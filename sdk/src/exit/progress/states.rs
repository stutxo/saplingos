use ark::vtxo::policy::signing::VtxoSigner;
use ark::VtxoId;
use log::{debug, error, info, trace, warn};

use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, P2TR_DUST, TxStatus};
use crate::chain::BroadcastError;
use crate::exit::models::{
	ExitError, ExitAwaitingDeltaState, ExitProcessingState, ExitClaimInProgressState, ExitClaimableState,
	ExitClaimedState, ExitState, ExitStartState, ExitTx, ExitTxStatus, ExitVtxoAlreadySpentState,
	ExitVtxoSweptState,
	ExitCanceledState,
};
use crate::exit::progress::{ExitProgressError, ExitStateProgress, ProgressContext};
use crate::exit::progress::util::{count_broadcast, count_confirmed, format_outpoints};
use crate::exit::transaction_manager::SPEND_CONFIRMATIONS;
use crate::vtxo::VtxoStateKind;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		// While the exit is still pre-broadcast another consumer (round forfeit, send, etc.)
		// can still take the VTXO out from under us. If we notice that's happened, bail to
		// the terminal `VtxoAlreadySpent` state so the caller can cancel the movement.
		// Once all exit txs are in mempool the underlying outpoint is committed to the
		// exit chain and a competing offchain spend would either lose in mempool or be
		// refused server-side, so we stop checking.
		if !self.warrants_exited_vtxo() && ctx.vtxo.state.kind() == VtxoStateKind::Spent {
			warn!("VTXO {} was spent before its exit chain was fully broadcast, aborting exit",
				ctx.vtxo.id());
			let tip = ctx.tip_height().await?;
			return Ok(ExitState::new_vtxo_already_spent(tip));
		}
		match self {
			ExitState::Start(s) => s.progress(ctx).await,
			ExitState::Processing(s) => s.progress(ctx).await,
			ExitState::AwaitingDelta(s) => s.progress(ctx).await,
			ExitState::Claimable(s) => s.progress(ctx).await,
			ExitState::ClaimInProgress(s) => s.progress(ctx).await,
			ExitState::Claimed(s) => s.progress(ctx).await,
			ExitState::VtxoAlreadySpent(s) => s.progress(ctx).await,
			ExitState::VtxoSwept(s) => s.progress(ctx).await,
			ExitState::Canceled(s) => s.progress(ctx).await,
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitStartState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let id = ctx.vtxo.id();
		info!("Checking if VTXO can be exited: {}", id);

		if ctx.vtxo.amount() < P2TR_DUST {
			return Err(ExitError::DustLimit { vtxo: id, amount: ctx.vtxo.amount(), dust: P2TR_DUST }.into());
		}

		info!("Validated VTXO {}, exit process can now begin", id);

		let tip = ctx.wallet.inner.chain.tip().await.unwrap_or(self.tip_height);
		Ok(ExitState::new_processing(tip, ctx.exit_txids.iter().cloned()))
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitProcessingState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		assert_eq!(self.transactions.len(), ctx.exit_txids.len());

		let tip = ctx.tip_height().await?;
		let mut transactions = self.transactions.clone();

		for i in 0..transactions.len() {
			match progress_exit_tx(&transactions[i], ctx).await {
				Ok(status) => transactions[i].status = status,
				Err(e) => {
					// We may need to commit any changes we have
					if self.transactions != transactions {
						let state = ExitState::new_processing_from_transactions(tip, transactions);
						return Err(ExitProgressError {
							state: Some(state),
							error: e,
						});
					}
					return Err(e.into());
				},
			}
		}

		// Check whether the vtxo was swept, or its exit chain otherwise spent, out from under us.
		// Only the frontier tx is worth checking: a confirmed tx proves its own inputs, and the
		// txs below the frontier spend outputs that aren't on chain yet. A frontier with a CPFP
		// in the mempool demonstrably still has unspent inputs, so only check it without one.
		// Runs after the pass above so it sees the statuses we just refreshed.
		if let Some(frontier) = transactions.iter().find(|tx| tx.status.confirmed_in().is_none()) {
			if matches!(frontier.status, ExitTxStatus::AwaitingCpfpBroadcast) {
				let spent_inputs = ctx.tx_manager.find_conflicting_spend(tip, frontier.txid).await?;
				if !spent_inputs.is_empty() {
					warn!("Exit tx {} for VTXO {} can never confirm: its inputs {} were spent, \
						aborting the exit",
						frontier.txid, ctx.vtxo.id(), format_outpoints(&spent_inputs),
					);
					return Ok(ExitState::new_vtxo_swept(tip, spent_inputs));
				}
			}
		}

		// Report the current status to the user
		let prev_confirmed = count_confirmed(&self.transactions);
		let now_confirmed = count_confirmed(&transactions);
		if now_confirmed == transactions.len() {
			info!("Exit for VTXO ({}) has been fully confirmed, waiting for funds to become \
				spendable...", ctx.vtxo.id(),
			);
			let conf_block = transactions
				.iter()
				.filter_map(|exit| exit.status.confirmed_in())
				.max_by(|a, b| a.height.cmp(&b.height))
				.unwrap();

			let clause = ctx.wallet.find_signable_clause(ctx.vtxo).await
				.ok_or_else(|| ExitError::ClaimMissingSignableClause { vtxo: ctx.vtxo.id() })?;

			let wait_delta = BlockDelta::new(clause.sequence().map_or(0, |csv| csv.0) as u16);
			return Ok(ExitState::new_awaiting_delta(tip, *conf_block, wait_delta));
		}
		if now_confirmed != prev_confirmed {
			info!("Exit for VTXO ({}) now has {} confirmed transactions with {} more required.",
				ctx.vtxo.id(), now_confirmed, transactions.len() - now_confirmed,
			);
		} else {
			let prev_broadcast = count_broadcast(&self.transactions);
			let now_broadcast = count_broadcast(&transactions);
			if now_broadcast == transactions.len() {
				info!("Exit for VTXO ({}) has been fully broadcast, waiting for {} transactions \
					to confirm...", ctx.vtxo.id(), transactions.len() - now_confirmed,
				);
			} else if prev_broadcast != now_broadcast {
				let remaining = transactions.len() - now_broadcast;
				if prev_broadcast > now_broadcast {
					warn!("An exit transaction for VTXO ({}) appears to have fallen out of the \
						mempool", ctx.vtxo.id(),
					);
				}
				info!("Exit for VTXO ({}) now has {} broadcast transactions with {} more required.",
					ctx.vtxo.id(), now_broadcast, remaining,
				);
			}
		}

		if self.transactions != transactions {
			debug!("VTXO exit transactions updated: {:?}", transactions);
			Ok(ExitState::new_processing_from_transactions(tip, transactions))
		} else {
			Ok(self.into())
		}
	}
}

async fn progress_exit_tx(
	exit: &ExitTx,
	ctx: &mut ProgressContext<'_>,
) -> anyhow::Result<ExitTxStatus, ExitError> {
	match &exit.status {
		ExitTxStatus::VerifyInputs => {
			debug!("Verifying inputs for exit tx {}", exit.txid);
			let inputs = ctx.get_unique_inputs(exit.txid).await?;
			ctx.check_status_from_inputs(exit, &inputs).await
		},
		ExitTxStatus::AwaitingInputConfirmation { txids } => {
			debug!("Checking if the {} remaining inputs for exit tx {} have confirmed",
				txids.len(), exit.txid,
			);
			ctx.check_status_from_inputs(exit, &txids).await
		}
		ExitTxStatus::AwaitingCpfpBroadcast => {
			// Check whether another party has already broadcast this transaction before
			// we pause and wait for the caller to provide a CPFP via provide_cpfp_tx.
			ctx.get_exit_tx_status(exit).await
		},
		ExitTxStatus::AwaitingConfirmation { child_txid, .. } => {
			let child_status = ctx.tx_manager.get_child_status(exit.txid).await?;
			match child_status {
				None => {
					error!("Exit CPFP tx {} for exit tx {} has disappeared", child_txid, exit.txid);
					Ok(ExitTxStatus::AwaitingCpfpBroadcast)
				},
				Some(ref c) if c.txid != *child_txid => {
					warn!("Exit CPFP tx {} for exit tx {} has been replaced by {}",
						child_txid, exit.txid, c.txid,
					);
					// Evict our dead CPFP immediately.
					// Unlike others we don't have to wait for the grace period
					if let Some(onchain) = ctx.wallet.inner.onchain.as_ref() {
						if let Err(e) = onchain.write().await.evict_tx(*child_txid).await {
							warn!("Failed to evict replaced CPFP {}: {:#}", child_txid, e);
						}
					}
					ctx.get_exit_tx_status(exit).await
				},
				Some(ref c) if c.status == TxStatus::NotFound => {
					debug!("Exit CPFP tx {} fell out of mempool, rebroadcasting", child_txid);
					let package = ctx.tx_manager.get_package(exit.txid)?;
					let guard = package.read().await;
					match ctx.tx_manager.broadcast_package(&*guard).await {
						Ok(_) => ctx.get_exit_tx_status(exit).await,
						// The stored CPFP can never confirm: one of its inputs is spent by a
						// confirmed tx — for our own child that's its fee input, consumed by a
						// sibling exit tx's CPFP that drew on the same wallet UTXO. Rebroadcasting
						// can only keep failing, so abandon it and go back to AwaitingCpfpBroadcast
						// to build a fresh CPFP from currently-spendable UTXOs. (A competing CPFP
						// spending the shared anchor is instead detected and adopted by
						// `update_package_from_network`, surfacing as the "replaced by" case above,
						// so it never reaches here.)
						Err(ExitError::ExitPackageBroadcastFailure {
							error: BroadcastError::MissingOrSpentInputs, ..
						}) => {
							warn!("Exit CPFP tx {} for exit tx {} can't be rebroadcast (inputs \
								already spent); requesting a fresh CPFP", child_txid, exit.txid,
							);
							Ok(ExitTxStatus::AwaitingCpfpBroadcast)
						},
						Err(e) => Err(e),
					}
				},
				Some(_) => {
					ctx.get_exit_tx_status(exit).await
				},
			}
		},
		ExitTxStatus::Confirmed { child_txid, block, .. } => {
			// Handle cases where we might get a block-reorg so our transaction may unconfirm
			let new_status = ctx.get_exit_tx_status(exit).await?;
			match &new_status {
				ExitTxStatus::Confirmed { child_txid: new_txid, block: new_block, .. } => {
					if new_block != block || new_txid != child_txid {
						warn!("Exit transaction {} was confirmed with block {} but it has been \
							replaced by {} in block {}",
							exit.txid, block.hash, new_txid, new_block.hash
						);
					}
				},
				_ => {
					warn!("Exit transaction {} was confirmed at height {} but it's now unconfirmed",
						exit.txid, block.height
					);
				},
			}
			Ok(new_status)
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitAwaitingDeltaState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let tip = ctx.tip_height().await?;

		// Ensure the exit transaction hasn't disappeared from the mempool due to a reorg
		if !ctx.check_confirmed(ctx.vtxo.point().txid).await {
			error!("Exit for VTXO ({}) is no longer confirmed, verifying all transactions...",
				ctx.vtxo.id(),
			);
			return Ok(ExitState::new_processing(
				tip, ctx.exit_txids.iter().cloned(),
			));
		}

		// Inform the user of any progress
		if tip >= self.claimable_height {
			info!("Exit for VTXO ({}) is spendable!", ctx.vtxo.id());
			let spendable_block = ctx.get_block_ref(self.claimable_height).await?;
			Ok(ExitState::new_claimable(tip, spendable_block, None))
		} else {
			info!("Waiting for {} more confirmations until exit for VTXO ({}) is spendable...",
				self.claimable_height.checked_blocks_since(tip).unwrap_or(0), ctx.vtxo.id(),
			);
			Ok(self.into())
		}
	}
}

/// The outcome of checking an exit's claim (drain) transaction against the chain: what the
/// state machine should do with the observed [TxStatus].
///
/// Both entry points to `Claimed` — the `Claimable` chain scan and the `ClaimInProgress`
/// status check — go through this, so the depth policy lives in exactly one place. It is pure
/// data in, data out: the async transitions below do the chain lookups and the logging, which
/// keeps the policy unit-testable without a chain connection or a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimObservation {
	/// The claim is confirmed but buried by fewer than [SPEND_CONFIRMATIONS] blocks: a reorg
	/// could still undo it, so keep the exit live and track this confirming block.
	Shallow(BlockRef),
	/// The claim is at least [SPEND_CONFIRMATIONS] confirmations deep: a reorg is not
	/// expected to undo it, so the exit may end as `Claimed`.
	Final(BlockRef),
	/// The claim is in the mempool but not confirmed yet.
	Mempool,
	/// The claim is nowhere on chain: evicted from the mempool or reorged out entirely.
	Gone,
}

/// Whether a claim confirmed in `height` is buried deep enough at `tip` to end the exit.
///
/// Ending an exit is irreversible — the movement is finalized as `Successful` and the exit
/// stops being tracked — so it must not latch on a spend a shallow reorg could still undo.
/// This is the claim-side twin of the gate [SPEND_CONFIRMATIONS] already applies to the
/// `VtxoAlreadySpent`/`VtxoSwept` endings.
fn claim_is_final(tip: BlockHeight, height: BlockHeight) -> bool {
	// Confirmations count the confirming block itself; a block above the tip counts as zero.
	tip.checked_blocks_since(height).map_or(0, |d| d.saturating_add(1)) >= SPEND_CONFIRMATIONS.to_u32()
}

fn observe_claim(tip: BlockHeight, status: TxStatus) -> ClaimObservation {
	match status {
		TxStatus::Confirmed(block) => if claim_is_final(tip, block.height) {
			ClaimObservation::Final(block)
		} else {
			ClaimObservation::Shallow(block)
		},
		TxStatus::Mempool => ClaimObservation::Mempool,
		TxStatus::NotFound => ClaimObservation::Gone,
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimableState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		let tip = ctx.tip_height().await?;

		// We should verify the current block hasn't been reorganized.
		let spendable_block = ctx.get_block_ref(self.claimable_since.height).await?;
		if spendable_block.hash != self.claimable_since.hash {
			return Ok(ExitState::new_claimable(tip, spendable_block, None));
		}

		// We can avoid scanning the whole chain provided there hasn't been a re-org
		let scan_height = if let Some(block) = &self.last_scanned_block {
			// Double check we haven't had a re-org since the last scan
			if ctx.get_block_ref(block.height).await?.hash == block.hash {
				block.height
			} else {
				self.claimable_since.height
			}
		} else {
			self.claimable_since.height
		};

		// Check if the VTXO exit has been spent
		let point = ctx.vtxo.point();
		#[allow(deprecated)]
		let result = ctx.wallet.inner.chain
			.txs_spending_inputs(
				vec![point],
				scan_height,
			).await
			.map_err(|e| ExitError::TransactionRetrievalFailure {
				txid: ctx.vtxo.point().txid, error: e.to_string(),
			})?;

		if let Some((txid, status)) = result.get(&point) {
			match observe_claim(tip, status.clone()) {
				ClaimObservation::Final(block) => {
					debug!("Tx {} has successfully claimed VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_claimed(tip, *txid, block))
				},
				ClaimObservation::Shallow(block) => {
					// Found the claim, but only confirmed under fewer than SPEND_CONFIRMATIONS
					// blocks: a reorg could still undo it. Track it in ClaimInProgress until it
					// is buried instead of finishing the exit here.
					let confirmations = tip.checked_blocks_since(block.height)
						.map_or(0, |d| d.saturating_add(1));
					debug!("Tx {} is claiming VTXO {} ({} of {} confirmations)",
						txid, ctx.vtxo.id(), confirmations, SPEND_CONFIRMATIONS,
					);
					Ok(ExitState::new_claim_in_progress(
						tip, self.claimable_since, *txid, Some(block),
					))
				},
				ClaimObservation::Mempool => {
					debug!("Tx {} is attempting to claim VTXO {}", txid, ctx.vtxo.id());
					Ok(ExitState::new_claim_in_progress(tip, self.claimable_since, *txid, None))
				},
				ClaimObservation::Gone => {
					unreachable!("the chain scan only reports spends it found")
				},
			}
		} else {
			// Make sure the wallet is aware of the exit
			debug!("VTXO is still spendable: {}", ctx.vtxo.id());
			let tip_block = Some(ctx.get_block_ref(tip).await?);
			Ok(ExitState::new_claimable(tip, self.claimable_since, tip_block))
		}
	}
}

impl ExitClaimInProgressState {
	/// The next state given the claim transaction's current chain status at `tip`.
	///
	/// Split out from the async [ExitStateProgress::progress] — which only does the chain
	/// lookups — so the transition policy is unit-testable without a chain connection or a
	/// wallet: finish only once the claim is buried under [SPEND_CONFIRMATIONS] blocks, and
	/// regress to `Claimable` if it disappears from the chain before that.
	fn advance(self, vtxo: VtxoId, tip: BlockHeight, status: TxStatus) -> ExitState {
		match observe_claim(tip, status) {
			ClaimObservation::Final(block) => {
				debug!("Tx {} is buried deep enough: exit for VTXO {} is complete",
					self.claim_txid, vtxo,
				);
				ExitState::new_claimed(tip, self.claim_txid, block)
			},
			ClaimObservation::Shallow(block) => {
				if let Some(prev) = self.claim_block {
					if prev != block {
						// The chain view reports the claim in a different block than we
						// recorded: a reorg replaced its confirmation. The depth count
						// restarts on the new block.
						warn!("Claim tx {} for VTXO {} moved from block {} to block {} across \
							a reorg", self.claim_txid, vtxo, prev, block,
						);
					}
				}
				let confirmations = tip.checked_blocks_since(block.height)
					.map_or(0, |d| d.saturating_add(1));
				trace!("Claim tx {} for VTXO {} has {} of {} confirmations",
					self.claim_txid, vtxo, confirmations, SPEND_CONFIRMATIONS,
				);
				ExitState::new_claim_in_progress(tip, self.claimable_since, self.claim_txid,
					Some(block),
				)
			},
			ClaimObservation::Mempool => {
				trace!("Still waiting for TX {} to be confirmed", self.claim_txid);
				self.into()
			},
			ClaimObservation::Gone => {
				warn!("TX {} is no longer on chain (evicted or reorged out), VTXO {} is \
					spendable again", self.claim_txid, vtxo,
				);
				ExitState::new_claimable(tip, self.claimable_since, None)
			},
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimInProgressState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		// Wait for the claim transaction to be buried deep enough to end the exit
		let tip = ctx.tip_height().await?;
		let status = ctx.tx_manager.tx_status(self.claim_txid).await?;
		Ok(self.advance(ctx.vtxo.id(), tip, status))
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitClaimedState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} is spent!", ctx.vtxo.id());
		Ok(self.into())
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitVtxoAlreadySpentState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} cannot proceed: VTXO was already spent.", ctx.vtxo.id());
		Ok(self.into())
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitVtxoSweptState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} cannot proceed: its chain was swept on inputs {}.",
			ctx.vtxo.id(), format_outpoints(&self.spent_inputs),
		);
		Ok(self.into())
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ExitStateProgress for ExitCanceledState {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError> {
		trace!("Exit for VTXO {} was canceled; nothing to progress.", ctx.vtxo.id());
		Ok(self.into())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::hashes::Hash;
	use bitcoin::{BlockHash, OutPoint, Txid};

	use crate::exit::models::ExitStateKind;
	use crate::exit::progress::ProgressStep;

	// The transitions under test are pure: `ProgressContext` needs a full `Wallet`, which no
	// in-crate test constructs, so the depth policy lives in `observe_claim` /
	// `ExitClaimInProgressState::advance` and is exercised here with bare chain statuses.

	fn txid(n: u8) -> Txid {
		Txid::from_byte_array([n; 32])
	}

	fn block(height: u32, seed: u8) -> BlockRef {
		BlockRef {
			height: BlockHeight::new(height),
			hash: BlockHash::from_byte_array([seed; 32]),
		}
	}

	fn vtxo() -> VtxoId {
		VtxoId::from(OutPoint::new(txid(1), 0))
	}

	/// A claim that was just spotted in the mempool.
	fn pending_claim() -> ExitClaimInProgressState {
		ExitClaimInProgressState {
			tip_height: BlockHeight::new(99),
			claimable_since: block(95, 1),
			claim_txid: txid(9),
			claim_block: None,
		}
	}

	#[test]
	fn first_claim_confirmation_keeps_exit_in_progress() {
		let state = pending_claim();
		let vtxo = vtxo();
		let claim = block(100, 7);

		// Confirmed in the tip block: 1 confirmation must not finish the exit, but the
		// confirming block is recorded so the depth count is anchored.
		let next = state.advance(vtxo, BlockHeight::new(100), TxStatus::Confirmed(claim));
		let ExitState::ClaimInProgress(next) = next else {
			panic!("a 1-conf claim must not finish the exit: {next:?}");
		};
		assert_eq!(next.claim_block, Some(claim));
		assert_eq!(next.claim_txid, state.claim_txid);

		// Depth `SPEND_CONFIRMATIONS - 1` is still too shallow.
		let shallow_tip = BlockHeight::new(100 + SPEND_CONFIRMATIONS.to_u32() - 2);
		let next = next.advance(vtxo, shallow_tip, TxStatus::Confirmed(claim));
		assert!(matches!(next, ExitState::ClaimInProgress(_)),
			"{} confirmations must not finish the exit: {next:?}", SPEND_CONFIRMATIONS.to_u32() - 1);

		// Still in the mempool: keep waiting without touching the state.
		let next = state.advance(vtxo, BlockHeight::new(100), TxStatus::Mempool);
		assert_eq!(next, ExitState::ClaimInProgress(state));
	}

	#[test]
	fn claim_finalizes_at_spend_confirmations() {
		let vtxo = vtxo();
		let claim = block(100, 7);
		let state = ExitClaimInProgressState { claim_block: Some(claim), ..pending_claim() };

		let tip = BlockHeight::new(100 + SPEND_CONFIRMATIONS.to_u32() - 1);
		let next = state.advance(vtxo, tip, TxStatus::Confirmed(claim));
		let ExitState::Claimed(next) = next else {
			panic!("{} confirmations must finish the exit: {next:?}", SPEND_CONFIRMATIONS);
		};
		assert_eq!(next.txid, state.claim_txid);
		assert_eq!(next.block, claim);
	}

	#[test]
	fn reorged_claim_regresses_and_is_redetected() {
		let vtxo = vtxo();
		let claim = block(100, 7);
		let state = ExitClaimInProgressState { claim_block: Some(claim), ..pending_claim() };

		// A reorg removed the claim before it was buried: the exit must not stay committed to
		// it and falls back to watching the chain from `Claimable` again.
		let next = state.advance(vtxo, BlockHeight::new(101), TxStatus::NotFound);
		let ExitState::Claimable(next) = next else {
			panic!("a reorged-out claim must regress the exit to Claimable: {next:?}");
		};
		assert_eq!(next.claimable_since, state.claimable_since);

		// On the replacement chain the scan finds the claim again, confirmed elsewhere at
		// depth 1: that is tracked, not finished.
		let reorged_claim = block(101, 3);
		assert_eq!(
			observe_claim(BlockHeight::new(101), TxStatus::Confirmed(reorged_claim)),
			ClaimObservation::Shallow(reorged_claim),
		);
		let state = ExitClaimInProgressState {
			claim_block: Some(reorged_claim), ..state
		};

		// The re-detection finalizes once the new confirmation is buried from the tip, not
		// from the old pre-reorg sighting.
		let tip = BlockHeight::new(101 + SPEND_CONFIRMATIONS.to_u32() - 1);
		let next = state.advance(vtxo, tip, TxStatus::Confirmed(reorged_claim));
		assert!(matches!(next, ExitState::Claimed(_)),
			"a buried re-detected claim must finish the exit: {next:?}");

		// A following reorg that re-confirms the same tx in yet another block moves the
		// recorded block, restarting the depth count on it.
		let moved_claim = block(103, 4);
		let next = state.advance(vtxo, tip, TxStatus::Confirmed(moved_claim));
		let ExitState::ClaimInProgress(next) = next else {
			panic!("a re-confirmed claim must restart the depth count: {next:?}");
		};
		assert_eq!(next.claim_block, Some(moved_claim));
	}

	#[test]
	fn claimed_stays_terminal() {
		// Finishing is one-way, including for `Claimed` states persisted by older versions
		// that entered at fewer than `SPEND_CONFIRMATIONS` confirmations: progress no longer
		// consults the chain for them and they are not re-tracked as live exits.
		let claimed = ExitState::new_claimed(BlockHeight::new(101), txid(9), block(100, 7));
		assert!(matches!(ProgressStep::from_exit_state(&claimed), ProgressStep::Done));
		assert!(ExitStateKind::FINISHED_STATES.contains(&ExitStateKind::Claimed));
		assert!(!ExitStateKind::LIVE_STATES.contains(&ExitStateKind::Claimed));
	}
}
