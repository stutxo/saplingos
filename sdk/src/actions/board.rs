//! Board wallet action.
//!
//! Boarding moves on-chain BTC into the Ark/VTXO world. Server cosign and exact
//! recovery preparation happen in [`crate::Wallet::board_psbt`] before funding
//! signatures are released. This action rechecks durable recovery on restart,
//! including externally funded detection, export and rebroadcast, then owns the
//! broadcast -> confirm -> register lifecycle and near-expiry salvage. Program
//! boards hand off durably to saved recovery; only native boards use native exit.
//! Identity (the funding tx, `id`, `vtxo_id`, `amount`,
//! `movement_id`) lives on [`Board`] as top-level fields; the mutable bit is the
//! [`Progress`] enum.

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Psbt, SignedAmount, Transaction, Txid};
use log::{error, info, warn};

use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::{Full, VtxoId};
use bitcoin_ext::{BlockDelta, TxStatus};
use server_rpc::protos;

use crate::Wallet;
use crate::actions::{Advance, AdvanceError, WalletAction, WalletActionId};
use crate::chain::BroadcastError;
use crate::movement::{MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::onchain::OnchainWalletTrait;
use crate::persist::models::recovery_action_key;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};

/// Whether every input has a final witness or scriptSig.
///
/// [Psbt::extract_tx] fills missing witnesses with empty ones rather than failing,
/// so finalisation has to be checked before extracting.
pub(crate) fn psbt_is_finalized(psbt: &Psbt) -> bool {
	psbt.inputs.iter().all(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some())
}

/// An in-flight board, persisted as a single checkpoint row and driven across
/// crashes by the executor.
///
/// The funding transaction is carried so (re-)broadcast is re-drivable without the
/// on-chain wallet, which isn't available inside `advance`. It sits in `funding_tx`
/// or `funding_psbt`, exactly one of which is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
	// Immutable state:
	pub id: WalletActionId,
	/// The funding transaction of a board checkpointed before `funding_psbt`
	/// existed. Read, never written: a transaction records its inputs' outpoints but
	/// not their values, so the `witness_utxo` a PSBT needs cannot be recovered.
	/// Always finalised, those boards having been broadcast on creation.
	#[serde(default, skip_serializing_if = "Option::is_none",
		with = "bitcoin_ext::serde::encodable::opt")]
	pub funding_tx: Option<Transaction>,
	/// The funding proposal. Broadcast once finalised, watched for until then.
	#[serde(default, skip_serializing_if = "Option::is_none",
		with = "bitcoin_ext::serde::psbt::opt")]
	pub funding_psbt: Option<Psbt>,
	/// The board vtxo produced by the cosign, built before this checkpoint
	/// exists. The full vtxo is reloaded from the db when needed.
	pub vtxo_id: VtxoId,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// Created up front in `board_psbt` so re-driving never duplicates a movement.
	pub movement_id: MovementId,

	// Mutable state:
	pub progress: Progress,
}

impl Board {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	/// The funding transaction, signed or not. For inspection only; broadcasting
	/// goes through [Board::to_broadcast].
	pub fn funding(&self) -> anyhow::Result<&Transaction> {
		self.funding_tx.as_ref()
			.or(self.funding_psbt.as_ref().map(|psbt| &psbt.unsigned_tx))
			.context("board checkpoint has no funding transaction")
	}

	/// The funding txid, which the board cosign commits to and is therefore fixed
	/// before the signatures exist.
	pub fn funding_txid(&self) -> anyhow::Result<Txid> {
		Ok(self.funding()?.compute_txid())
	}

	/// Export signed funding only after verifying durable recovery for the exact
	/// completed board. This barrier also applies to externally finalized PSBTs.
	pub async fn to_broadcast(&self, wallet: &Wallet) -> anyhow::Result<Option<Transaction>> {
		self.ensure_recovery(wallet).await?;
		self.extract_finalized_funding()
	}

	async fn ensure_recovery(&self, wallet: &Wallet) -> anyhow::Result<()> {
		let stored;
		let vtxo = match &self.progress {
			Progress::PreparingFunding { signed_vtxo, .. }
				| Progress::Broadcasting { signed_vtxo } => signed_vtxo,
			Progress::Confirming { .. } => {
				stored = wallet.get_full_vtxo(self.vtxo_id).await?;
				&stored
			},
		};
		ensure!(vtxo.id() == self.vtxo_id, "board checkpoint VTXO id mismatch");
		ensure!(vtxo.chain_anchor().txid == self.funding_txid()?,
			"funding transaction does not match the completed board");
		wallet.ensure_program_recoveries(std::slice::from_ref(vtxo)).await
	}

	/// Finish funding and its initial network handoff under the original
	/// coin-selection lock, or under a fresh lock on restart. A restarted signer
	/// must reject inputs already consumed by another wallet transaction, while
	/// allowing replay of this exact tx. Checkpoint network visibility before
	/// releasing the lock so the next send can safely spend the board's change.
	pub(crate) async fn complete_funding(
		&mut self,
		wallet: &Wallet,
		onchain: Option<&mut dyn OnchainWalletTrait>,
	) -> anyhow::Result<()> {
		let Progress::PreparingFunding { signed_vtxo, sign_funding } = &self.progress else {
			return Ok(());
		};
		self.ensure_recovery(wallet).await?;
		let sign_funding = *sign_funding;
		if sign_funding {
			let psbt = self.funding_psbt.take()
				.context("board awaiting funding has no PSBT")?;
			let txid = psbt.unsigned_tx.compute_txid();
			let signed = onchain.context("no onchain wallet configured")?
				.finish_psbt(psbt).await?;
			ensure!(signed.unsigned_tx.compute_txid() == txid,
				"funding signer changed the board transaction");
			ensure!(psbt_is_finalized(&signed), "funding signer did not finalize the PSBT");
			self.funding_psbt = Some(signed);
		}
		let seen = if sign_funding {
			// Persist the signed funding before network I/O. A failed handoff
			// must retain its inputs without making unpublished change spendable.
			wallet.inner.db.upsert_wallet_action_checkpoint(&self.id, &self.clone().into()).await?;
			matches!(run_broadcast(wallet, self, signed_vtxo).await?, BroadcastOutcome::Seen)
		} else {
			false
		};
		self.progress = if seen {
			Progress::Confirming { last_park_error: None }
		} else {
			Progress::Broadcasting { signed_vtxo: signed_vtxo.clone() }
		};
		if sign_funding {
			wallet.inner.db.upsert_wallet_action_checkpoint(&self.id, &self.clone().into()).await?;
		}
		Ok(())
	}

	/// Recovery owns the checkpoint permanently after takeover. Finish the
	/// movement idempotently without deleting the recovery continuation state.
	pub(crate) async fn record_recovery_handoff(&self, wallet: &Wallet) -> anyhow::Result<()> {
		if wallet.inner.db.get_movement_by_id(self.movement_id).await?.status == MovementStatus::Failed {
			return Ok(());
		}
		wallet.inner.movements.finish_movement_with_update(
			self.movement_id, MovementStatus::Failed,
			MovementUpdate::new().exited_vtxo(self.vtxo_id),
		).await.context("failed to finalize recovering board movement")
	}

	/// Raw PSBT extraction is private: every production caller must first pass
	/// through `to_broadcast` and its recovery readiness check.
	fn extract_finalized_funding(&self) -> anyhow::Result<Option<Transaction>> {
		if let Some(tx) = &self.funding_tx {
			return Ok(Some(tx.clone()));
		}
		let psbt = self.funding_psbt.as_ref()
			.context("board checkpoint has no funding transaction")?;
		if !psbt_is_finalized(psbt) {
			return Ok(None);
		}
		// `extract_tx` fee-checks, so it needs each input's value; a stored proposal
		// always carries `witness_utxo`.
		let tx = psbt.clone().extract_tx().context("failed to extract board funding tx")?;
		ensure!(tx.compute_txid() == psbt.unsigned_tx.compute_txid(),
			"finalized funding changes the board transaction id");
		Ok(Some(tx))
	}
}

/// The phases of an in-flight board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Exact completed output saved before recovery merges signed ancestors or
	/// the on-chain wallet releases funding signatures. Reuse these bytes after
	/// any interruption; never re-enter the board signer.
	PreparingFunding {
		#[serde(with = "ark::encode::serde")]
		signed_vtxo: Vtxo<Full>,
		sign_funding: bool,
	},
	/// Vtxo cosigned and built but not yet persisted, and the funding tx not yet
	/// seen on the network. Store the vtxo (locked under the action id), broadcast
	/// the funding tx if it is ours to broadcast, and stay here until it shows up.
	/// Carries the signed vtxo because it isn't in the vtxo table until this step
	/// stores it.
	Broadcasting {
		#[serde(with = "ark::encode::serde")]
		signed_vtxo: Vtxo<Full>,
	},
	/// Funding tx seen in the mempool or a block. Each pass waits for
	/// `required_board_confirmations`, registers with the server once confirmed, and
	/// kicks off an exit if the vtxo nears expiry unregistered (salvage). This
	/// mirrors the pre-action `sync_pending_boards` loop body so registration keeps
	/// being retried (with the vtxo left Locked) until it succeeds, the board exits,
	/// or it expires.
	Confirming {
		/// Most recent reason a registration attempt failed, for diagnostics.
		last_park_error: Option<String>,
	},
}

/// Stable action id derived from the funding outpoint. Known before broadcast
/// and unique because a given funding output can only board once.
///
/// Uses `.` rather than the `txid:vout` colon since action ids double as lock
/// keys, which only permit ASCII alphanumerics, `-`, `_` and `.`.
pub(crate) fn board_action_id(utxo: OutPoint) -> WalletActionId {
	format!("board.{}.{}", utxo.txid, utxo.vout)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for Board {
	fn id(&self) -> WalletActionId { Board::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		match self.progress.clone() {
			Progress::PreparingFunding { sign_funding, .. } => {
				let mut board = self;
				if sign_funding {
					let onchain = wallet.inner.onchain.as_ref()
						.context("no onchain wallet configured")?;
					let mut onchain = onchain.write().await;
					board.complete_funding(wallet, Some(&mut *onchain)).await?;
					if matches!(board.progress, Progress::Broadcasting { .. }) {
						// The initial handoff was attempted under the funding
						// lock. Leave further broadcasting to the next drive.
						return Ok(Advance::Park { state: board, wake_after: None, error: None });
					}
				} else {
					board.complete_funding(wallet, None).await?;
				}
				Ok(Advance::Next(board))
			},
			Progress::Broadcasting { signed_vtxo } => {
				match run_broadcast(wallet, &self, &signed_vtxo).await? {
					BroadcastOutcome::Seen => Ok(Advance::Next(Board {
						progress: Progress::Confirming { last_park_error: None },
						..self
					})),
					BroadcastOutcome::Conflicted => fail_dead_board(wallet, &self).await,
					// Not on the network yet, so there is nothing to confirm.
					BroadcastOutcome::Waiting =>
						Ok(Advance::Park { state: self, wake_after: None, error: None }),
				}
			},
			Progress::Confirming { .. } => run_confirm(wallet, self).await,
		}
	}

	/// The board VTXO once its funding transaction has been seen on the
	/// network; nothing has moved before that.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		match &self.progress {
			Progress::PreparingFunding { .. } | Progress::Broadcasting { .. } => Vec::new(),
			Progress::Confirming { .. } => vec![self.vtxo_id],
		}
	}

	async fn on_rejection(
		self,
		_wallet: &Wallet,
		error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		// The funding tx is already on-chain by the time the action runs, so we
		// can never safely fail-and-release. Registration failures are handled
		// inline in `Confirming` (kept retrying, vtxo left Locked), so a
		// rejection reaching here is unexpected; re-evaluate from `Confirming`
		// rather than tearing the board down.
		warn!("board {} hit an unexpected rejection, re-evaluating: {:#}", self.id, error);
		// Keep `Broadcasting` so its `signed_vtxo` survives for the next drive.
		let progress = match self.progress {
			preparing @ Progress::PreparingFunding { .. } => preparing,
			broadcasting @ Progress::Broadcasting { .. } => broadcasting,
			Progress::Confirming { .. } => Progress::Confirming { last_park_error: None },
		};
		Ok(Advance::Park {
			state: Board { progress, ..self },
			wake_after: None,
			error: None,
		})
	}
}

/// What a `Broadcasting` pass established about the funding tx.
enum BroadcastOutcome {
	/// In the mempool or a block.
	Seen,
	/// A funding input is spent by a confirmed tx, so it can never confirm.
	Conflicted,
	/// Absent, but still able to arrive.
	Waiting,
}

/// Store the cosigned vtxo locked under the action and get the funding tx onto the
/// network if we hold its signatures. Both steps are idempotent: the store no-ops if
/// the vtxo exists, and a tx already on the network is not pushed again.
async fn run_broadcast(
	wallet: &Wallet,
	board: &Board,
	signed_vtxo: &Vtxo<Full>,
) -> Result<BroadcastOutcome, AdvanceError> {
	// Do not bypass readiness merely because another party already funded the
	// board. Such a deposit is not retroactively made safe by observing it.
	board.ensure_recovery(wallet).await?;
	// The server doesn't know this vtxo until `register_board`, so skip the
	// recovery-mailbox post `store_locked_vtxos` would do (it would fail the
	// mailbox FK to `vtxo`); `register_board` posts it once accepted.
	wallet.store_vtxos(
		[signed_vtxo],
		&VtxoState::Locked {
			holder: Some(crate::vtxo::VtxoLockHolder::Movement { id: board.movement_id }),
		},
	).await?;

	// Leave on a positive "already on-chain" signal only. A not-yet-broadcast
	// funding tx is unknown to the chain source, and some backends report that by
	// erroring rather than returning `NotFound`, so treat anything but a
	// confirmed/mempool hit as "still needs broadcasting".
	if matches!(
		wallet.inner.chain.tx_status(board.funding_txid()?).await,
		Ok(TxStatus::Mempool) | Ok(TxStatus::Confirmed(_)),
	) {
		return Ok(BroadcastOutcome::Seen);
	}

	// Classify before pushing, the probe doubling as the push: a push that fails on a
	// spent input is retried rather than fatal, so classifying afterwards would never
	// reach the teardown. Only valid while the funding tx is absent, since a
	// confirmed one spends its own inputs.
	match funding_conflict(wallet, board).await? {
		// A confirmed funding tx spends its own inputs, which reads as a conflict, and
		// the probe above cannot rule that out when the chain source errors. Write the
		// board off on a positive "absent" answer only.
		FundingConflict::Fatal => match wallet.inner.chain.tx_status(board.funding_txid()?).await {
			Ok(TxStatus::Mempool) | Ok(TxStatus::Confirmed(_)) => Ok(BroadcastOutcome::Seen),
			Ok(TxStatus::NotFound) => Ok(BroadcastOutcome::Conflicted),
			Err(_) => Ok(BroadcastOutcome::Waiting),
		},
		// The probe pushed it for us.
		FundingConflict::None => {
			info!("Board {} funding tx broadcasted", board.id);
			Ok(BroadcastOutcome::Seen)
		},
		FundingConflict::Undecided(reason) => {
			info!("Board {} funding tx not on the network yet: {}", board.id, reason);
			Ok(BroadcastOutcome::Waiting)
		},
	}
}

/// `Confirming`. Mirrors the pre-action `sync_pending_boards` loop body, run
/// once per drive: tear down if the vtxo has exited, re-broadcast if the funding
/// tx dropped (or fail the board if it was double-spent), register once
/// sufficiently confirmed, and kick off an exit near expiry (keeping the board
/// around so registration can still win while the exit is abortable).
async fn run_confirm(wallet: &Wallet, board: Board) -> Result<Advance<Board>, AdvanceError> {
	let (_, ark_info) = wallet.require_server().await?;
	let current_height = wallet.inner.chain.tip().await?;
	let required = BlockDelta::new(ark_info.required_board_confirmations as u16);

	let vtxo = wallet.get_vtxo_by_id(board.vtxo_id).await?;

	// If an exit has progressed beyond the abortable stage, server-side
	// registration can no longer succeed: finish the movement and stop.
	if vtxo.state.kind() == VtxoStateKind::Exited {
		fail_board_movement(&wallet.inner.movements, board.movement_id).await
			.context("failed to finalize exited board movement")?;
		return Ok(Advance::Done);
	}

	// A previous drive already observed a confirmed double-spend of a funding
	// tx input and marked the vtxo spent (see the `Fatal` arm below), but was
	// interrupted before tearing the board down: finish the teardown.
	if vtxo.state.kind() == VtxoStateKind::Spent {
		wallet.inner.movements.finish_movement_with_update(
			board.movement_id, MovementStatus::Failed,
			MovementUpdate::new().effective_balance(SignedAmount::ZERO),
		).await.context("failed to finalize double-spent board movement")?;
		return Ok(Advance::Done);
	}

	board.ensure_recovery(wallet).await?;

	let mut last_park_error = None;
	let anchor = vtxo.chain_anchor();
	let confs = match wallet.inner.chain.tx_status(anchor.txid).await {
		Ok(TxStatus::Confirmed(block_ref)) =>
			Some(current_height.checked_blocks_since(block_ref.height).unwrap_or(0).saturating_add(1)),
		Ok(TxStatus::Mempool) => Some(0),
		// Dropped from the mempool before confirming. Probe for a conflicting
		// spend of the funding inputs: if one has confirmed the funding tx can
		// never confirm, so the board is dead and re-broadcasting would strand
		// it in a park-and-retry loop forever.
		Ok(TxStatus::NotFound) => {
			match funding_conflict(wallet, &board).await? {
				FundingConflict::Fatal => return fail_dead_board(wallet, &board).await,
				// The funding tx may still confirm: park and re-check next
				// drive.
				FundingConflict::Undecided(reason) => {
					return Ok(Advance::Park {
						state: Board {
							progress: Progress::Confirming {
								last_park_error: Some(reason),
							},
							..board
						},
						wake_after: None,
						error: None,
					});
				},
				// Nothing conflicts: the probe already put the funding tx back
				// in the mempool, so a single eviction doesn't strand the board
				// forever (the old flow never did).
				FundingConflict::None => Some(0),
			}
		},
		Err(_) => None,
	};

	if confs.is_some_and(|c| c >= required.to_u32()) {
		// Attempt registration inline. A failure here (the server can't see
		// enough confirmations yet, or refuses) is not terminal: leave the vtxo
		// Locked and retry next drive, exactly like the old loop. The funding tx
		// is already on-chain, so we must never fail-and-release.
		match run_register(wallet, &board).await {
			Ok(()) => return Ok(Advance::Done),
			Err(e) => {
				let reason = format!("{:#}", e);
				warn!("Failed to register board {}: {}", board.id, reason);
				last_park_error = Some(reason);
			},
		}
	}

	// Near expiry without registration: kick off an exit so the funds at least
	// come back on-chain, but keep retrying registration while the exit is still
	// abortable. The top-of-function `Exited` check tears the action down once
	// the exit commits.
	//
	// I know this if is collapsible, but it reads better like this...
	let exit_margin = wallet.config().vtxo_exit_margin;
	if vtxo.expiry_height() <= current_height + exit_margin {
		if wallet.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_some() {
			// The normal driver already holds this board's action guard. Recovery
			// tombstones it before chain I/O; no later registration may race the
			// saved recovery, even if this first ancestor cannot be broadcast.
			let result = wallet.recover_program_vtxos_with_action_guard(
				&[vtxo.id().to_point()], None, &board.id,
			).await;
			if wallet.inner.db.has_program_recovery_reservation(
				&recovery_action_key(&board.id),
			).await? {
				board.record_recovery_handoff(wallet).await?;
				if let Err(e) = result {
					warn!("Board {} recovery handed off; continuation will retry: {:#}", board.id, e);
				}
				return Ok(Advance::Park { state: board, wake_after: None, error: None });
			}
			result?;
			return Err(anyhow!("program board recovery did not reserve its action").into());
		}
		if !wallet.exit_mgr().is_exiting(vtxo.id()).await {
			warn!("Board {} expired before confirmation, marking VTXO for exit", board.id);
			wallet.inner.exit.start_exit_for_vtxos(&[vtxo.vtxo.clone()]).await?;
		}
		// Record unconditionally (idempotent): a crash after `start_exit_for_vtxos`
		// would otherwise leave `is_exiting` true and never record the exit.
		wallet.inner.movements.update_movement(
			board.movement_id, MovementUpdate::new().exited_vtxo(board.vtxo_id),
		).await.context("failed to record board exit on movement")?;
	}

	Ok(Advance::Park {
		state: Board { progress: Progress::Confirming { last_park_error }, ..board },
		wake_after: None,
		error: None,
	})
}

/// Register the board with the server, mark the vtxo spendable and finalize the
/// movement. All steps are idempotent: the server tolerates an already-registered
/// board and the state update is gated on the unspent states.
async fn run_register(wallet: &Wallet, board: &Board) -> anyhow::Result<()> {
	let (mut srv, _) = wallet.require_server().await?;

	// Get the full vtxo (including the genesis chain) since we send the
	// serialized bytes to the server.
	let vtxo = wallet.get_full_vtxo(board.vtxo_id).await
		.with_context(|| format!("board vtxo doesn't exist: {}", board.vtxo_id))?;
	wallet.ensure_program_recoveries(std::slice::from_ref(&vtxo)).await?;

	srv.client.register_board_vtxo(protos::BoardVtxoRequest {
		board_vtxo: vtxo.serialize(),
	}).await.context("error registering board with the Ark server")?;

	// Release only our own lock: an idempotent re-register must not steal a
	// lock that another operation has since acquired.
	wallet.unlock_vtxos(
		[vtxo.id()], Some(VtxoLockHolder::Movement { id: board.movement_id }),
	).await?;

	// Post vtxo ID for recovery (non-critical, just log errors). Done here
	// rather than in `store_locked_vtxos` because the server only has the
	// vtxo row after `register_board_vtxo` above, so the mailbox FK would
	// otherwise fail.
	if let Err(e) = wallet.post_recovery_vtxo_ids([vtxo.id()]).await {
		error!("Failed to post recovery vtxo ID to server: {:#}", e);
	}

	// TODO(pc): Cancel any pending exits for the VTXO once we support doing so.
	wallet.inner.movements.finish_movement(board.movement_id, MovementStatus::Successful).await
		.context("failed to finalize board movement")?;

	info!("Registered board {}", vtxo.id());
	Ok(())
}

/// How the board funding tx fares after being dropped from the mempool.
enum FundingConflict {
	/// Nothing conflicts: the re-broadcast probe put the funding tx back into
	/// the mempool.
	None,
	/// The outcome is still open (a parent tx isn't visible yet, a competing
	/// unconfirmed spend is in the way, or the node rejected the re-broadcast
	/// transiently), so the funding tx may still confirm. Carries the park
	/// reason.
	Undecided(String),
	/// A funding input was spent by a confirmed conflicting tx, so the funding
	/// tx can never confirm: the board is dead.
	Fatal,
}

/// Classify the board funding tx after it dropped out of the mempool, without
/// scanning the chain (a full block scan from the vtxo's creation height is
/// prohibitively slow against Bitcoin Core).
///
/// First confirm every funding input's parent tx is visible on-chain or in the
/// mempool. A missing parent is not fatal: an evicted ancestor can re-enter the
/// mempool once a cluster/package limit clears, so we park and wait. An input
/// whose parent is confirmed is then checked for a confirmed spend, which the
/// funding tx can never outrace. Finally, re-broadcasting the funding tx reveals
/// whether its inputs are still spendable: a `missing or spent inputs` rejection
/// means a confirmed conflict consumed one of them and the board is dead. Any
/// other rejection (a competing unconfirmed spend, an RBF fee shortfall, or a
/// transient node error) leaves the outcome open, so we park. A chain source
/// error on either probe is likewise left open rather than propagated: it says
/// nothing about the funding tx itself.
async fn funding_conflict(wallet: &Wallet, board: &Board) -> anyhow::Result<FundingConflict> {
	for input in &board.funding()?.input {
		let parent = input.previous_output.txid;
		match wallet.inner.chain.tx_status(parent).await {
			// The caller only reaches here while the funding tx itself is absent
			// from chain and mempool, so a confirmed spend of one of its inputs
			// belongs to another transaction and this board can never confirm.
			Ok(TxStatus::Confirmed(_)) => {
				match wallet.inner.chain.outpoint_spent_confirmed(input.previous_output).await {
					Ok(true) => return Ok(FundingConflict::Fatal),
					Ok(false) => {},
					Err(e) => return Ok(FundingConflict::Undecided(format!(
						"failed to check funding input parent tx {} for a confirmed spend: {:#}",
						parent, e,
					))),
				}
			},
			Ok(TxStatus::Mempool) => {},
			Ok(TxStatus::NotFound) => return Ok(FundingConflict::Undecided(format!(
				"funding input parent tx {} not yet visible on chain", parent,
			))),
			Err(e) => return Ok(FundingConflict::Undecided(format!(
				"failed to fetch status of funding input parent tx {}: {:#}", parent, e,
			))),
		}
	}

	let Some(tx) = board.to_broadcast(wallet).await? else {
		// Without the signatures there is nothing to probe with: a transaction we
		// cannot complete would be rejected on its own merits and tell us nothing
		// about its inputs. No input is spent by a confirmed tx, so the outcome is
		// still open and the party holding the signatures may yet broadcast.
		return Ok(FundingConflict::Undecided("awaiting external funding broadcast".into()));
	};
	match wallet.inner.chain.broadcast_package(std::slice::from_ref(&tx)).await {
		Ok(()) | Err(BroadcastError::AlreadyKnown) => Ok(FundingConflict::None),
		Err(BroadcastError::MissingOrSpentInputs) => Ok(FundingConflict::Fatal),
		Err(e) => Ok(FundingConflict::Undecided(
			format!("funding tx re-broadcast rejected: {}", e),
		)),
	}
}

#[cfg(test)]
mod test {
	use bitcoin::{ScriptBuf, Sequence, TxIn, TxOut, Witness, consensus};
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::transaction::Version;

	use super::*;

	fn unsigned_tx() -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(1_000_000),
				script_pubkey: ScriptBuf::new_op_return(&[0u8; 4]),
			}],
		}
	}

	/// An unfinalised PSBT for [unsigned_tx]. `witness_utxo` is set because
	/// [Psbt::extract_tx] fee-checks, so it fails without the input value.
	fn psbt() -> Psbt {
		let mut psbt = Psbt::from_unsigned_tx(unsigned_tx()).unwrap();
		psbt.inputs[0].witness_utxo = Some(TxOut {
			value: Amount::from_sat(1_001_000),
			script_pubkey: ScriptBuf::new_op_return(&[1u8; 4]),
		});
		psbt
	}

	fn finalized_psbt() -> Psbt {
		let mut psbt = psbt();
		psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[[0u8; 64]]));
		psbt
	}

	fn board(funding_tx: Option<Transaction>, funding_psbt: Option<Psbt>) -> Board {
		Board {
			id: "board.test.0".to_string(),
			funding_tx,
			funding_psbt,
			vtxo_id: VtxoId::from(OutPoint::null()),
			amount: Amount::from_sat(1_000_000),
			movement_id: MovementId(7),
			progress: Progress::Confirming { last_park_error: None },
		}
	}

	/// Finalized witness-only funding retains the board's committed txid.
	#[test]
	fn broadcast_follows_psbt_finalisation() {
		let unfinalized = board(None, Some(psbt()));
		assert!(unfinalized.extract_finalized_funding().unwrap().is_none());
		// Still knows which transaction to watch for.
		assert_eq!(unfinalized.funding_txid().unwrap(), psbt().unsigned_tx.compute_txid());

		let finalized = board(None, Some(finalized_psbt()));
		let tx = finalized.extract_finalized_funding().unwrap()
			.expect("finalised proposal is ours to send");
		assert_eq!(tx.compute_txid(), finalized.funding_txid().unwrap());
		assert!(!tx.input[0].witness.is_empty(), "extracted tx must carry the witness");
	}

	#[test]
	fn finalization_must_not_change_board_funding_txid() {
		let mut proposal = finalized_psbt();
		proposal.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
		let board = board(None, Some(proposal));
		let error = board.extract_finalized_funding().unwrap_err();
		assert!(error.to_string().contains("changes the board transaction id"));
	}

	/// A checkpoint with neither field has no funding transaction, so it errors
	/// rather than yielding a board that can never confirm.
	#[test]
	fn board_without_funding_is_an_error() {
		let board = board(None, None);
		assert!(board.funding().is_err());
		assert!(board.funding_txid().is_err());
		assert!(board.extract_finalized_funding().is_err());
	}

	/// A checkpoint predating `funding_psbt` stays readable and re-broadcastable.
	#[test]
	fn legacy_funding_tx_is_read_and_broadcastable() {
		let tx = {
			let mut tx = unsigned_tx();
			tx.input[0].witness = Witness::from_slice(&[[0u8; 64]]);
			tx
		};
		let legacy = serde_json::json!({
			"id": "board.test.0",
			"funding_tx": consensus::encode::serialize_hex(&tx),
			"vtxo_id": VtxoId::from(OutPoint::null()),
			"amount": 1_000_000,
			"movement_id": 7,
			"progress": { "Confirming": { "last_park_error": null } },
		});
		let board: Board = serde_json::from_value(legacy).unwrap();
		assert_eq!(board.funding_tx.as_ref(), Some(&tx));
		assert_eq!(board.funding_psbt, None);
		assert_eq!(board.extract_finalized_funding().unwrap(), Some(tx));
	}

	/// Boards are written with `funding_psbt` only, as BIP-174 hex.
	#[test]
	fn checkpoint_writes_only_funding_psbt() {
		let psbt = psbt();
		let json = serde_json::to_value(board(None, Some(psbt.clone()))).unwrap();
		assert_eq!(json["funding_psbt"], psbt.serialize_hex());
		assert!(json.get("funding_tx").is_none(), "funding_tx is never written: {json}");

		let board: Board = serde_json::from_value(json).unwrap();
		assert_eq!(board.funding_psbt, Some(psbt));
		assert_eq!(board.funding_tx, None);
	}

	/// Both on-disk shapes of a board checkpoint deserialise, into the field each
	/// names. This is what lets the two coexist without a migration: rows written
	/// while the funding transaction was a plain [Transaction] keep their `funding_tx`
	/// key, and rows written since carry `funding_psbt`.
	#[test]
	fn both_checkpoint_versions_deserialise() {
		fn payload(funding_key: &str, funding_hex: String) -> serde_json::Value {
			serde_json::json!({
				"id": "board.test.0",
				funding_key: funding_hex,
				"vtxo_id": VtxoId::from(OutPoint::null()),
				"amount": 1_000_000,
				"movement_id": 7,
				"progress": { "Confirming": { "last_park_error": null } },
			})
		}

		let tx = finalized_psbt().extract_tx().unwrap();
		let v1: Board = serde_json::from_value(
			payload("funding_tx", consensus::encode::serialize_hex(&tx)),
		).expect("a funding_tx checkpoint must still deserialise");
		assert_eq!(v1.funding_tx, Some(tx.clone()));
		assert_eq!(v1.funding_psbt, None);

		let psbt = psbt();
		let v2: Board = serde_json::from_value(
			payload("funding_psbt", psbt.serialize_hex()),
		).expect("a funding_psbt checkpoint must deserialise");
		assert_eq!(v2.funding_psbt, Some(psbt));
		assert_eq!(v2.funding_tx, None);

		// Both name the same funding transaction, so the rest of the action reads
		// them identically.
		assert_eq!(v1.funding_txid().unwrap(), v2.funding_txid().unwrap());
	}

	/// A board that exits before registration left through its own exit
	/// movement, so failing the board movement must zero the +amount
	/// effective balance committed at board start — same as the spent
	/// (double-spent funding) arm. Regression: the Exited arm finished
	/// the movement Failed without clearing it.
	#[tokio::test]
	async fn failed_board_movement_zeroes_effective_balance() {
		use std::sync::Arc;

		use crate::notification::NotificationDispatch;
		use crate::persist::WalletPersister;
		use crate::persist::adaptor::StorageAdaptorWrapper;
		use crate::subsystem::Subsystem;

		let db = Arc::new(StorageAdaptorWrapper::new_memory());
		let movements = crate::movement::manager::MovementManager::new(
			db.clone(), NotificationDispatch::new(),
		);
		movements.register_subsystem(Subsystem::BOARD).await.unwrap();
		// Mirror board start: the board's value committed as a positive
		// effective balance.
		let id = movements.new_movement_with_update(
			Subsystem::BOARD, "board",
			MovementUpdate::new()
				.effective_balance(Amount::from_sat(2_000).to_signed().unwrap()),
		).await.unwrap();

		fail_board_movement(&movements, id).await.unwrap();

		let movement = db.get_movement_by_id(id).await.unwrap();
		assert_eq!(movement.status, MovementStatus::Failed);
		assert_eq!(
			movement.effective_balance, SignedAmount::ZERO,
			"a failed board movement that never moved funds must report zero",
		);
	}
}

/// Fail a board movement whose funds never settled through the board:
/// either the funding never materialized (double-spend) or the vtxo
/// left through an exit, which its own exit movement already accounts.
/// In both cases the +amount effective balance committed at board
/// start must be zeroed — a failed movement with no value change
/// reports [SignedAmount::ZERO].
async fn fail_board_movement(
	movements: &crate::movement::manager::MovementManager,
	movement_id: MovementId,
) -> anyhow::Result<()> {
	movements.finish_movement_with_update(
		movement_id, MovementStatus::Failed,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await.context("failed to finalize failed board movement")
}

/// Fail a board whose funding tx can never confirm: mark its vtxo spent and close
/// the movement out at zero. Reached from either phase, since a funding input can
/// be spent before the transaction is ever seen as well as after.
async fn fail_dead_board(
	wallet: &Wallet,
	board: &Board,
) -> Result<Advance<Board>, AdvanceError> {
	warn!("Board {} funding input was spent by a confirmed conflicting tx, \
		failing the board", board.id);
	wallet.inner.db.update_vtxo_state_checked(
		board.vtxo_id, VtxoState::Spent, &[VtxoStateKind::Locked],
	).await.context("failed to mark double-spent board vtxo as spent")?;
	wallet.inner.movements.finish_movement_with_update(
		board.movement_id, MovementStatus::Failed,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await.context("failed to finalize double-spent board movement")?;
	Ok(Advance::Done)
}
