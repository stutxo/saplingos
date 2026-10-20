//!
//! Round State Machine
//!

use std::collections::HashMap;
use std::fmt;
use std::iter;
use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark::vtxo::{TransitionKind, VtxoValidationError};
use bdk_esplora::esplora_client::Amount;
use bip39::rand;
use bitcoin::{OutPoint, SignedAmount, Transaction, Txid};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::schnorr;
use futures::future::join_all;
use futures::{Stream, StreamExt};
use log::{debug, error, info, trace, warn};

use ark::{ArkInfo, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest};
use ark::vtxo::{Full, PubkeyVtxoPolicy, VtxoPolicy};
use ark::attestations::{DelegatedRoundParticipationAttestation, RoundAttemptAttestation};
use ark::fees::FeeValidationError;
use ark::forfeit::HarkForfeitSigningContext;
use ark::musig::{self, PublicNonce, SecretNonce};
use ark::rounds::{RoundAttempt, RoundEvent, RoundFinished, RoundSeq, ROUND_TX_VTXO_TREE_VOUT};
use ark::sapio::protocol::{OwnershipProof, OwnershipRequest};
use ark::tree::signed::{ExternalLeafVtxoCosignContext, LeafVtxoCosignResponse, UnlockHash, VtxoTreeSpec};
use bitcoin_ext::{BlockDelta, BlockHeight, TxStatus};
use server_rpc::{protos, ServerConnection, TryFromBytes, MAX_NB_FORFEIT_NONCE_IDS};

use crate::import::ImportVtxoArgs;
use crate::movement::manager::OnDropStatus;
use crate::{Wallet, WalletVtxo, SECP, SUBSCRIBE_REQUEST_TIMEOUT};
use crate::movement::{MovementId, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::persist::models::{RoundStateId, StoredRoundState, Unlocked};
use crate::subsystem::{RoundMovement, Subsystem};
use crate::vtxo::{validate_vtxo_tree_params, VtxoLockHolder, VtxoStateKind, VtxoState};

/// How long [`Wallet::lock_wait_round_state`] waits for a contended
/// round lock before giving up. Long enough to outlast a normal round.
const ROUND_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Blocks by which we let a round's VTXO expiry fall short of the full
/// advertised lifetime when doing interactive rounds.
const VTXO_EXPIRY_HEIGHT_BUFFER: BlockDelta = BlockDelta::new(6);

/// The most a recovered delegated round participation may lose to fees,
/// in percent of its input value. A hard-coded bound: the wallet that
/// created the participation is gone, so this is the only thing standing
/// between a recovered wallet and a server claiming excessive fees.
const MAX_RECOVERED_PARTICIPATION_FEE_PERCENT: u64 = 5;

/// The fee a recovered delegated participation claims to pay, if its totals
/// are sane enough to build a recovery on: both sides bounded by the money
/// supply (larger totals are necessarily forged, and the bound keeps the
/// percentage scaling below safely in-range), outputs never exceeding
/// inputs, and fees within [MAX_RECOVERED_PARTICIPATION_FEE_PERCENT].
///
/// A recovered participation's totals are rebuilt from server data, so this
/// is called before the participation is stored.
fn sane_recovered_participation_fee(
	total_in: Amount,
	total_out: Amount,
) -> anyhow::Result<Amount> {
	anyhow::ensure!(total_in <= Amount::MAX_MONEY && total_out <= Amount::MAX_MONEY,
		"value exceeds the money supply: {} in, {} out", total_in, total_out);
	let fee = total_in.checked_sub(total_out).with_context(||
		format!("outputs {} exceed inputs {}", total_out, total_in)
	)?;
	let in_scaled = total_in.checked_mul(MAX_RECOVERED_PARTICIPATION_FEE_PERCENT)
		.context("input fee-margin scaling overflow")?;
	let fee_scaled = fee.checked_mul(100)
		.context("fee scaling overflow")?;
	anyhow::ensure!(fee_scaled <= in_scaled,
		"it pays {} in fees, more than {}% of its {} input value",
		fee, MAX_RECOVERED_PARTICIPATION_FEE_PERCENT, total_in,
	);
	Ok(fee)
}

/// Sum the still-pending output balances of rounds, erroring rather than
/// panicking when they overflow.
///
/// Round outputs are normally wallet-authored, but recovered delegated
/// participations are rebuilt from server data, so a malicious server can
/// have stored forged over-valued outputs: enough of them would panic a
/// plain `+=`. No real wallet has more pending than the money supply, so
/// exceeding [Amount::MAX_MONEY] is an error, never a wrap.
fn sum_pending_round_balances<'a>(
	states: impl IntoIterator<Item = &'a RoundState>,
) -> anyhow::Result<Amount> {
	states.into_iter().try_fold(Amount::ZERO, |sum, state| {
		let pending = state.pending_balance()
			.context("pending outputs of a round overflow: forged recovered participation")?;
		sum.checked_add(pending)
			.filter(|sum| *sum <= Amount::MAX_MONEY)
			.context("pending round balance exceeds the money supply: forged recovered participations")
	})
}


/// Struct to communicate your specific participation for an Ark round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundParticipation {
	#[serde(with = "ark::encode::serde::vec")]
	pub inputs: Vec<Vtxo<Full>>,
	/// The output VTXOs that we request in the round,
	/// including change
	pub outputs: Vec<VtxoRequest>,
	/// Optional mailbox identifier for round completion notification
	#[serde(default, skip_serializing_if = "Option::is_none", with = "ark::encode::serde::opt")]
	pub unblinded_mailbox_id: Option<ark::mailbox::MailboxIdentifier>,
}

impl RoundParticipation {
	/// Total value of the input VTXOs
	///
	/// `None` on overflow: the amounts can come from an untrusted server.
	pub fn total_in(&self) -> Option<Amount> {
		self.inputs.iter().try_fold(Amount::ZERO, |acc, i| acc.checked_add(i.amount()))
	}

	/// Total value of the requested output VTXOs
	///
	/// `None` on overflow: the amounts can come from an untrusted server.
	pub fn total_out(&self) -> Option<Amount> {
		self.outputs.iter().try_fold(Amount::ZERO, |acc, r| acc.checked_add(r.amount))
	}

	pub fn to_movement_update(&self) -> anyhow::Result<MovementUpdate> {
		let input_amount = self.total_in().context("input value overflow")?;
		let output_amount = self.total_out().context("output value overflow")?;
		let fee = input_amount - output_amount;
		Ok(MovementUpdate::new()
			.consumed_vtxos(&self.inputs)
			.intended_balance(SignedAmount::ZERO)
			.effective_balance( - fee.to_signed()?)
			.fee(fee)
		)
	}
}

#[derive(Debug, Clone)]
pub enum RoundStatus {
	/// The round was successful and is fully confirmed
	Confirmed {
		funding_txid: Txid,
	},
	/// Round successful but not fully confirmed
	Unconfirmed {
		funding_txid: Txid,
	},
	/// Round didn't finish yet
	Pending,
	/// The round failed
	Failed {
		error: String,
	},
	/// User canceled the round
	Canceled,
}

impl RoundStatus {
	/// Whether this is the final state and it won't change anymore
	pub fn is_final(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => false,
			Self::Pending => false,
			Self::Failed { .. } => true,
			Self::Canceled => true,
		}
	}

	/// Whether it looks like the round succeeded
	pub fn is_success(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => true,
			Self::Pending => false,
			Self::Failed { .. } => false,
			Self::Canceled => false,
		}
	}
}

/// Type enum of [RoundFlowState].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoundFlowKind {
	/// Delegated participation waiting for its round
	DelegatedPending,
	/// Interactive participation waiting for its round
	Pending,
	/// The interactive part is being played out with the server
	Ongoing,
	/// The round finished and we are waiting for its funding tx to confirm
	AwaitingConfirmations,
	/// The participation failed
	Failed,
	/// The user canceled the participation
	Canceled,
}

impl fmt::Display for RoundFlowKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::DelegatedPending => f.write_str("delegated-pending"),
			Self::Pending => f.write_str("pending"),
			Self::Ongoing => f.write_str("ongoing"),
			Self::AwaitingConfirmations => f.write_str("awaiting-confirmations"),
			Self::Failed => f.write_str("failed"),
			Self::Canceled => f.write_str("canceled"),
		}
	}
}

/// State of the progress of a round participation
///
/// An instance of this struct is kept all the way from the intention of joining
/// the next round, until either the round fully confirms or it fails and we are
/// sure it won't have any effect on our wallet.
///
/// As soon as we have signed forfeit txs for the round, we keep track of this
/// round attempt until we see another attempt we participated in confirm or
/// we gain confidence that the failed attempt will never confirm.
pub struct RoundState {
	/// Round is fully done
	pub(crate) done: bool,

	/// Our participation in this round
	pub(crate) participation: RoundParticipation,

	/// The flow of the round in case it is still ongoing with the server
	pub(crate) flow: RoundFlowState,

	/// The new output vtxos of this round participation
	///
	/// After we finish the interactive part, we fill this with the uncompleted
	/// VTXOs which we then try to complete with the unlock preimage.
	pub(crate) new_vtxos: Vec<Vtxo<Full>>,

	/// Whether we sent our forfeit signatures to the server
	///
	/// If we did this and the server refused to reveal our new VTXOs,
	/// we will be forced to exit.
	//TODO(stevenroose) implement exit when this is true and we can't make progress
	// probably based on the input vtxos becoming close to expiry
	pub(crate) sent_forfeit_sigs: bool,

	/// Exact wire bundles, checkpointed before any share escapes. `None` is a
	/// legacy checkpoint whose earlier handoffs cannot be reconstructed safely.
	pub(crate) forfeit_bundles: Option<Vec<Vec<u8>>>,

	/// The ID of the [Movement] associated with this round
	pub(crate) movement_id: Option<MovementId>,
}

impl RoundState {
	fn new_interactive(
		participation: RoundParticipation,
		movement_id: Option<MovementId>,
	) -> Self {
		Self {
			participation,
			movement_id,
			flow: RoundFlowState::InteractivePending,
			new_vtxos: Vec::new(),
			sent_forfeit_sigs: false,
			forfeit_bundles: Some(Vec::new()),
			done: false,
		}
	}

	fn new_delegated(
		participation: RoundParticipation,
		unlock_hash: UnlockHash,
		scheduled_height: Option<BlockHeight>,
		movement_id: Option<MovementId>,
	) -> Self {
		Self {
			participation,
			movement_id,
			flow: RoundFlowState::NonInteractivePending { unlock_hash, scheduled_height },
			new_vtxos: Vec::new(),
			sent_forfeit_sigs: false,
			forfeit_bundles: Some(Vec::new()),
			done: false,
		}
	}

	/// Our participation in this round
	pub fn participation(&self) -> &RoundParticipation {
		&self.participation
	}

	/// The lifecycle phase this participation is in
	pub fn flow_kind(&self) -> RoundFlowKind {
		match self.flow {
			RoundFlowState::NonInteractivePending { .. } => RoundFlowKind::DelegatedPending,
			RoundFlowState::Redelegating { .. } => RoundFlowKind::DelegatedPending,
			RoundFlowState::InteractivePending => RoundFlowKind::Pending,
			RoundFlowState::InteractiveOngoing { .. } => RoundFlowKind::Ongoing,
			RoundFlowState::Finished { .. } => RoundFlowKind::AwaitingConfirmations,
			RoundFlowState::Failed { .. } => RoundFlowKind::Failed,
			RoundFlowState::Canceled => RoundFlowKind::Canceled,
		}
	}

	/// The block height a delegated participation is scheduled for, if any
	pub fn scheduled_height(&self) -> Option<BlockHeight> {
		match self.flow {
			RoundFlowState::NonInteractivePending { scheduled_height, .. } => scheduled_height,
			RoundFlowState::Redelegating { scheduled_height } => scheduled_height,
			_ => None,
		}
	}

	/// the unlock hash if already known
	pub fn unlock_hash(&self) -> Option<UnlockHash> {
		match self.flow {
			RoundFlowState::NonInteractivePending { unlock_hash, .. } => Some(unlock_hash),
			RoundFlowState::Redelegating { .. } => None,
			RoundFlowState::InteractivePending => None,
			RoundFlowState::InteractiveOngoing { .. } => None,
			RoundFlowState::Failed { .. } => None,
			RoundFlowState::Canceled => None,
			RoundFlowState::Finished { unlock_hash, .. } => Some(unlock_hash),
		}
	}

	pub fn funding_tx(&self) -> Option<&Transaction> {
		match self.flow {
			RoundFlowState::NonInteractivePending { .. } => None,
			RoundFlowState::Redelegating { .. } => None,
			RoundFlowState::InteractivePending => None,
			RoundFlowState::InteractiveOngoing { .. } => None,
			RoundFlowState::Failed { .. } => None,
			RoundFlowState::Canceled => None,
			RoundFlowState::Finished { ref funding_tx, .. } => Some(funding_tx),
		}
	}

	/// Whether the interactive part of the round is still ongoing
	///
	/// Includes the wait for the round to start. For an attempt in flight,
	/// use [RoundState::ongoing_attempt].
	pub fn ongoing_participation(&self) -> bool {
		match self.flow {
			RoundFlowState::NonInteractivePending { .. } => false,
			RoundFlowState::Redelegating { .. } => false,
			RoundFlowState::InteractivePending => true,
			RoundFlowState::InteractiveOngoing { .. } => true,
			RoundFlowState::Failed { .. } => false,
			RoundFlowState::Canceled => false,
			RoundFlowState::Finished { .. } => false,
		}
	}

	/// Whether an attempt is currently running with the server
	///
	/// Excludes a participation that only waits for its round, which a sync
	/// still has work to do on.
	pub fn ongoing_attempt(&self) -> bool {
		matches!(self.flow, RoundFlowState::InteractiveOngoing { .. })
	}

	/// Tries to cancel the round and returns whether it was succesfully canceled
	/// or if it was already canceled or failed
	pub async fn try_cancel(&mut self, wallet: &Wallet) -> anyhow::Result<bool> {
		ensure!(!self.sent_forfeit_sigs, "cannot cancel a round after committing forfeit shares");
		let ret = match self.flow {
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::Redelegating { .. }
			=> {
				//TODO(stevenroose) we have to cancel with server
				bail!("it is currently not yet possible to cancel pending delegated rounds");
			},
			RoundFlowState::Canceled => true,
			RoundFlowState::Failed { .. } => true,
			RoundFlowState::InteractivePending | RoundFlowState::InteractiveOngoing { .. } => {
				self.flow = RoundFlowState::Canceled;
				true
			},
			RoundFlowState::Finished { .. } => false,
		};
		if ret {
			persist_round_failure(wallet, &self.participation, self.movement_id).await
				.context("failed to persist round failure for cancelation")?;
		}
		Ok(ret)
	}

	/// Build this participation without the given inputs, and rebuild the
	/// refresh output from the ones that remain.
	///
	/// Nothing is mutated or persisted, so an already submitted
	/// participation can reach the server before the wallet commits to the
	/// new shape. Use [RoundState::adopt_participation] to take it on.
	///
	/// Returns `None` when the participation cannot be shrunk: too little
	/// value remains to pay the refresh fee and a non-dust output, or it pays
	/// an output this wallet does not own. Cancel or fail it instead.
	async fn try_shrink_participation(
		&self,
		wallet: &Wallet,
		remove: &[VtxoId],
	) -> anyhow::Result<Option<RoundParticipation>> {
		let remaining = self.participation.inputs.iter()
			.filter(|v| !remove.contains(&v.id()))
			.cloned()
			.collect::<Vec<_>>();
		if remaining.len() == self.participation.inputs.len() {
			return Ok(Some(self.participation.clone()));
		}
		if !self.is_self_refresh(wallet).await? {
			warn!("Round participation pays an output this wallet doesn't own; \
				refusing to shrink it, as that would redirect the payment",
			);
			return Ok(None);
		}

		let nb_remaining = remaining.len();
		let participation = match self.scheduled_height() {
			Some(scheduled_height) => {
				wallet.build_scheduled_refresh_participation(remaining, scheduled_height).await
			},
			None => {
				wallet.build_refresh_participation(remaining).await
			},
		};

		let built = match participation {
			Ok(p) => p,
			// A remainder that cannot pay the refresh fee and still leave a
			// non-dust output cannot be refreshed on its own.
			Err(e) if matches!(e.downcast_ref::<FeeValidationError>(),
				Some(FeeValidationError::AmountAfterFeeBelowDust { .. })
					| Some(FeeValidationError::FeeExceedsAmount { .. }),
			) => {
				info!("Round participation's {} remaining input(s) cannot cover the \
					refresh fee: {}", nb_remaining, e,
				);
				return Ok(None);
			},
			Err(e) => return Err(e),
		};

		// No inputs left to refresh, so there is nothing to shrink to.
		let Some(mut participation) = built else {
			debug!("Round participation lost every input; it cannot be shrunk");
			return Ok(None);
		};

		debug!("Shrinking round participation from {} to {} inputs",
			self.participation.inputs.len(), nb_remaining,
		);
		participation.unblinded_mailbox_id = self.participation.unblinded_mailbox_id.clone();
		Ok(Some(participation))
	}

	/// Whether every output of this participation pays back into this wallet,
	/// the only shape [RoundState::try_shrink_participation] can rebuild.
	async fn is_self_refresh(&self, wallet: &Wallet) -> anyhow::Result<bool> {
		for output in self.participation.outputs.iter() {
			let user_pubkey = match output.policy {
				VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => user_pubkey,
				VtxoPolicy::ServerHtlcSend(_) |
				VtxoPolicy::ServerHtlcSend_v0(_) |
				VtxoPolicy::ServerHtlcRecv(_) |
				VtxoPolicy::ServerHtlcRecv_v0(_) => return Ok(false),
			};
			if wallet.signing_key(&user_pubkey).await?.is_none() {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// Take on a participation built by
	/// [RoundState::try_shrink_participation], and keep the movement's
	/// consumed VTXOs and amounts in sync with it.
	///
	/// The caller must persist the updated state.
	async fn adopt_participation(
		&mut self,
		wallet: &Wallet,
		participation: RoundParticipation,
	) -> anyhow::Result<()> {
		if let Some(id) = self.movement_id {
			wallet.sync_movement_to_participation(id, &participation).await?;
		}
		self.participation = participation;
		Ok(())
	}

	/// Replace this participation with a fresh submission of the inputs it
	/// has left, and hand the movement over. It ends up canceled, not
	/// failed: it is replaced, not abandoned.
	///
	/// Runs from the persisted [RoundFlowState::Redelegating], so a crash can
	/// enter it twice. It then skips the submission when a replacement
	/// already holds our movement.
	async fn finish_redelegation(
		&mut self,
		wallet: &Wallet,
		scheduled_height: Option<BlockHeight>,
	) -> anyhow::Result<RoundStatus> {
		let submitted = match self.movement_id {
			Some(mid) => {
				// Check if the round participation was already replaced by a new one.
				// If so, we just need to drop the current one.
				let pending_rounds = wallet.pending_round_states().await?;
				pending_rounds.iter().any(|stored| {
					let state = stored.state();
					state.movement_id == Some(mid)
						&& matches!(state.flow, RoundFlowState::NonInteractivePending { .. })
				})
			},
			None => false,
		};

		if submitted {
			info!("Re-delegated round participation was already submitted; dropping the \
				participation it replaced",
			);
		} else {
			// Shrink against the inputs as they are now: more may have gone.
			// Read-only: the replacement locks at its own attempt start.
			let holder = self.movement_id.map(VtxoLockHolder::from);
			let lost = wallet.unavailable_vtxos(&self.participation.inputs, holder).await?;
			let shrunk = match self.try_shrink_participation(wallet, &lost).await? {
				Some(p) => p,
				None => {
					info!("Delegated round participation cannot be shrunk after losing \
						{} input(s); dropping it", lost.len(),
					);
					self.flow = RoundFlowState::Canceled;
					persist_round_failure(wallet, &self.participation, self.movement_id).await
						.context("failed to persist dropped delegated round failure")?;
					return Ok(RoundStatus::Canceled);
				},
			};

			let resubmitted = wallet.join_delegated_round_inner(
				shrunk, self.movement_id, scheduled_height,
			).await.context("failed to re-delegate round participation")?;
			info!("Re-delegated round participation as #{} without its {} lost input(s)",
				resubmitted.id(), lost.len(),
			);

			if let Some(mid) = self.movement_id {
				wallet.sync_movement_to_participation(
					mid, resubmitted.state().participation(),
				).await?;
			}
		}

		// The replacement owns the movement now, so drop our claim. A later
		// sync must not fail a movement that is no longer ours.
		self.movement_id = None;
		self.flow = RoundFlowState::Canceled;
		Ok(RoundStatus::Canceled)
	}

	/// Lock the inputs this participation can still claim for a starting round
	/// attempt, shrinking it to them when others took some.
	///
	/// Returns false when nothing usable remains.
	async fn lock_inputs_and_shrink(&mut self, wallet: &Wallet) -> anyhow::Result<bool> {
		let holder = self.movement_id.map(VtxoLockHolder::from);
		let unavailable = wallet.lock_available_vtxos(
			&self.participation.inputs, holder.clone(),
		).await?;
		if unavailable.is_empty() {
			return Ok(true);
		}

		// The shrunk participation only holds inputs we just locked.
		let res = match self.try_shrink_participation(wallet, &unavailable).await {
			Ok(Some(shrunk)) => self.adopt_participation(wallet, shrunk).await.map(|_| true),
			Ok(None) => Ok(false),
			Err(e) => Err(e),
		};

		// We locked above, so release on every way out but success without waiting for next sync.
		if !matches!(res, Ok(true)) {
			if let Err(e) = wallet.unlock_vtxos(&self.participation.inputs, holder).await {
				warn!("Failed to release round inputs after a failed shrink: {:#}", e);
			}
		}
		res
	}

	async fn try_start_attempt(
		&mut self,
		wallet: &Wallet,
		attempt: &RoundAttempt,
	) {
		// Drop the previous attempt's stashed nonces: the new attempt
		// regenerates cosign keys, so the old key becomes unreachable.
		if let RoundFlowState::InteractiveOngoing {
			state: AttemptState::AwaitingUnsignedVtxoTree { ref cosign_keys, .. },
			..
		} = self.flow {
			if let Some(k) = cosign_keys.first() {
				wallet.inner.round_secret_nonces.forget(&k.public_key());
			}
		}

		// Inputs are only locked from attempt start. A re-attempt re-locks
		// what this movement already holds.
		match self.lock_inputs_and_shrink(wallet).await {
			Ok(true) => {},
			Ok(false) => {
				warn!("No usable inputs left for round attempt {}:{}",
					attempt.round_seq, attempt.attempt_seq,
				);
				self.flow = RoundFlowState::Canceled;
				return;
			},
			Err(e) => {
				warn!("Failed to lock inputs for round attempt {}:{}: {:#}",
					attempt.round_seq, attempt.attempt_seq, e,
				);
				self.flow = RoundFlowState::Failed {
					error: format!("failed to lock input VTXOs: {:#}", e),
				};
				return;
			},
		}

		match start_attempt(wallet, &self.participation, attempt).await {
			Ok(state) => {
				self.flow = RoundFlowState::InteractiveOngoing {
					round_seq: attempt.round_seq,
					attempt_seq: attempt.attempt_seq,
					state: state,
				};
			},
			Err(e) => {
				self.flow = RoundFlowState::Failed {
					error: format!("{:#}", e),
				};
			},
		}
	}

	/// Processes the given event and returns true if some update was made to the state
	pub async fn process_event(
		&mut self,
		wallet: &Wallet,
		event: &RoundEvent,
	) -> bool {
		let _: Infallible = match self.flow {
			RoundFlowState::InteractivePending => {
				if let RoundEvent::Attempt(e) = event && e.attempt_seq == 0 {
					trace!("Joining round attempt {}:{}", e.round_seq, e.attempt_seq);
					self.try_start_attempt(wallet, e).await;
					return true;
				} else {
					trace!("Ignoring {} event (seq {}:{}), waiting for round to start",
						event.kind(), event.round_seq(), event.attempt_seq(),
					);
					return false;
				}
			},
			RoundFlowState::InteractiveOngoing { round_seq, attempt_seq, ref mut state } => {
				// here we catch the cases where we're in a wrong flow

				if let RoundEvent::Failed(e) = event && e.round_seq == round_seq {
					warn!("Round {} failed by server", round_seq);
					self.flow = RoundFlowState::Failed {
						error: format!("round {} failed by server", round_seq),
					};
					return true;
				}

				if event.round_seq() > round_seq {
					// new round started, we don't support multiple parallel rounds,
					// this means we failed
					self.flow = RoundFlowState::Failed {
						error: format!("round {} started while we were on {}",
							event.round_seq(), round_seq,
						),
					};
					return true;
				}

				if event.attempt_seq() < attempt_seq {
					trace!("ignoring replayed message from old attempt");
					return false;
				}

				if let RoundEvent::Attempt(e) = event && e.attempt_seq > attempt_seq {
					trace!("Joining new round attempt {}:{}", e.round_seq, e.attempt_seq);
					self.try_start_attempt(wallet, e).await;
					return true;
				}
				trace!("Processing event {} for round attempt {}:{} in state {}",
					event.kind(), round_seq, attempt_seq, state.kind(),
				);

				return match progress_attempt(state, wallet, &self.participation, event).await {
					AttemptProgressResult::NotUpdated => false,
					AttemptProgressResult::Updated { new_state } => {
						*state = new_state;
						true
					},
					AttemptProgressResult::Failed(e) => {
						warn!("Round failed with error: {:#}", e);
						self.flow = RoundFlowState::Failed {
							error: format!("{:#}", e),
						};
						true
					},
					AttemptProgressResult::Finished { funding_tx, vtxos, unlock_hash } => {
						// Interactive states cannot have released input forfeits yet.
						self.forfeit_bundles = Some(Vec::new());
						self.new_vtxos = vtxos;
						let funding_txid = funding_tx.compute_txid();
						self.flow = RoundFlowState::Finished { funding_tx, unlock_hash };
						if let Some(mid) = self.movement_id {
							if let Err(e) = update_funding_txid(wallet, mid, funding_txid).await {
								warn!("Error updating the round funding txid: {:#}", e);
							}
						}
						true
					},
				};
			},
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::Redelegating { .. }
				| RoundFlowState::Finished { .. }
				| RoundFlowState::Failed { .. }
				| RoundFlowState::Canceled => return false,
		};
	}

	/// Prepare the next transition; only `StoredRoundState::sync` may hand
	/// shares to the server, after checkpointing this state.
	async fn sync(&mut self, wallet: &Wallet) -> anyhow::Result<RoundStatus> {
		if self.forfeit_bundles.is_none() {
			let mut program_owned = false;
			for input in &self.participation.inputs {
				program_owned |= wallet.vtxo_signing_key(input).await?.program().is_some();
			}
			// Preserve native legacy replay. Program-owned positions must never
			// recreate a possibly released share from an ambiguous checkpoint.
			if !program_owned {
				self.forfeit_bundles = Some(Vec::new());
			} else if !matches!(self.flow,
				RoundFlowState::InteractivePending | RoundFlowState::InteractiveOngoing { .. },
			) {
				bail!("legacy program round lacks durable forfeit shares; retaining input locks");
			}
		}
		match self.flow {
			RoundFlowState::Finished { ref funding_tx, .. } if self.done => {
				Ok(RoundStatus::Confirmed {
					funding_txid: funding_tx.compute_txid(),
				})
			},

			RoundFlowState::InteractiveOngoing { .. } => Ok(RoundStatus::Pending),

			RoundFlowState::Redelegating { scheduled_height } => {
				self.finish_redelegation(wallet, scheduled_height).await
			},

			RoundFlowState::InteractivePending => {
				// A pending participation does not lock its inputs, so another
				// operation can have taken one while it waited. Read-only: it
				// only claims what is left once its attempt starts.
				let holder = self.movement_id.map(VtxoLockHolder::from);
				let lost = wallet.unavailable_vtxos(&self.participation.inputs, holder).await?;
				if !lost.is_empty() {
					match self.try_shrink_participation(wallet, &lost).await? {
						Some(shrunk) => self.adopt_participation(wallet, shrunk).await?,
						None => {
							info!("Pending round participation cannot be shrunk; canceling it");
							self.flow = RoundFlowState::Canceled;
							persist_round_failure(
								wallet, &self.participation, self.movement_id,
							).await.context("failed to persist round cancelation")?;
							return Ok(RoundStatus::Canceled);
						},
					}
				}

				Ok(RoundStatus::Pending)
			},
			RoundFlowState::Failed { ref error } => {
				persist_round_failure(wallet, &self.participation, self.movement_id).await
					.context("failed to persist round failure")?;
				Ok(RoundStatus::Failed { error: error.clone() })
			},
			RoundFlowState::Canceled => {
				persist_round_failure(wallet, &self.participation, self.movement_id).await
					.context("failed to persist round failure")?;
				Ok(RoundStatus::Canceled)
			},

			RoundFlowState::NonInteractivePending { unlock_hash, scheduled_height } => {
				// A pending participation does not lock its inputs either, and
				// the server drops one as soon as one input is consumed, which
				// kills the refresh of the others. Resubmit them before we ask
				// about a participation the server no longer holds.
				//
				// NB: only while some inputs remain. Losing every input is
				// indistinguishable from this participation's own round
				// consuming them, so progress_delegated handles that case.
				//
				// Only record the decision here; the next sync carries it out.
				// Read-only: a pending participation must not claim an input
				// an interactive registration can still take.
				let holder = self.movement_id.map(VtxoLockHolder::from);
				let lost = wallet.unavailable_vtxos(&self.participation.inputs, holder).await?;
				if !lost.is_empty() && lost.len() < self.participation.inputs.len() {
					info!("Delegated round participation lost {} of its {} input(s); \
						re-delegating the rest", lost.len(), self.participation.inputs.len(),
					);
					self.flow = RoundFlowState::Redelegating { scheduled_height };
					return Ok(RoundStatus::Pending);
				}

				match progress_delegated(
					wallet, &self.participation, self.movement_id, unlock_hash, scheduled_height,
					self.sent_forfeit_sigs || self.forfeit_bundles.is_none(),
				).await {
					Ok(HarkProgressResult::RoundPending) => Ok(RoundStatus::Pending),
					Ok(HarkProgressResult::RoundNotFound) => {
						// Inputs are only locked once the round is issued, so this
						// unlock is a no-op for a participation that never got that far.
						// TODO: if the funding tx never confirms and/or double spends, consider an
						//  auto-exit.
						info!("Server reports round participation not found (no forfeits sent)");
						wallet.unlock_vtxos(
							&self.participation.inputs, self.movement_id.map(|m| m.into()),
						).await.context("failed to unlock delegated round inputs")?;
						self.flow = RoundFlowState::Failed {
							error: "server reports round participation not found".into(),
						};
						if let Some(movement_id) = self.movement_id {
							wallet.inner.movements.finish_movement(movement_id, MovementStatus::Failed).await
								.context("failed to mark refresh movement as failed")?;
						}
						Ok(RoundStatus::Failed {
							error: "server reports round participation not found".into(),
						})
					},
					Ok(HarkProgressResult::Ok { funding_tx, new_vtxos }) => {
						self.new_vtxos = new_vtxos;
						self.flow = RoundFlowState::Finished { funding_tx, unlock_hash };
						Ok(RoundStatus::Pending)
					},
					Ok(HarkProgressResult::FundingTxUnconfirmed { funding_txid }) => {
						if let Some(mid) = self.movement_id {
							update_funding_txid(wallet, mid, funding_txid).await
								.context("failed to update funding txid in DB")?;
						}
						Ok(RoundStatus::Unconfirmed { funding_txid })
					},

					Err(e) => {
						Err(e.context("error progressing delegated round"))
					},
				}
			},
			// interactive part finished, but didn't forfeit yet
			RoundFlowState::Finished { ref funding_tx, unlock_hash } => {
				let funding_txid = funding_tx.compute_txid();
				let confirmed = check_funding_tx_confirmations(
					wallet, funding_txid, &funding_tx,
				).await.context("error checking funding tx confirmations")?;
				if !confirmed {
					trace!("Funding tx {} not yet deeply enough confirmed", funding_txid);
					return Ok(RoundStatus::Unconfirmed { funding_txid });
				}

				let bundles = self.forfeit_bundles.as_ref().context(
					"legacy round lacks durable forfeit shares; retaining the old recovery position",
				)?;
				if bundles.is_empty() {
					let (new_vtxos, bundles) = prepare_hark_swap(
						wallet, &self.participation, &self.new_vtxos,
						funding_tx, unlock_hash, self.sent_forfeit_sigs,
					).await.context("preparing recoverable hArk swap")?;
					self.new_vtxos = new_vtxos;
					self.forfeit_bundles = Some(bundles);
					// This flag is durable before send, so even an ambiguous network
					// failure cannot make the old inputs spendable again.
					self.sent_forfeit_sigs = true;
				}
				Ok(RoundStatus::Pending)
			},
		}
	}

	/// Once we know the signed round funding tx, this returns the output VTXOs
	/// for this round.
	pub fn output_vtxos(&self) -> Option<&[Vtxo<Full>]> {
		if self.new_vtxos.is_empty() {
			None
		} else {
			Some(&self.new_vtxos)
		}
	}

	/// The holder under which this round locks its inputs.
	pub fn lock_holder(&self) -> Option<VtxoLockHolder> {
		self.movement_id.map(|id| VtxoLockHolder::Movement { id })
	}

	/// Returns the input VTXOs that are locked in this round, but only
	/// if no output VTXOs were issued yet.
	pub fn locked_pending_inputs(&self) -> &[Vtxo<Full>] {
		//TODO(stevenroose) consider if we can't just drop the state after forfeit exchange
		match self.flow {
			// These are candidates, not a claim that the inputs are locked: a
			// participation awaiting its round holds no lock until an attempt
			// starts, or until the server issues a delegated round.
			// pending_round_input_vtxos keeps only the ones locked by this
			// round's movement.
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::Redelegating { .. }
				| RoundFlowState::InteractivePending
				| RoundFlowState::InteractiveOngoing { .. }
			=> {
				&self.participation.inputs
			},
			RoundFlowState::Finished { .. } => if self.done {
				// inputs already unlocked
				&[]
			} else {
				&self.participation.inputs
			},
			RoundFlowState::Failed { .. }
				| RoundFlowState::Canceled
			=> {
				// inputs already unlocked
				&[]
			},
		}
	}

	/// The balance pending in this round
	///
	/// This becomes zero once the new round VTXOs are unlocked.
	///
	/// `None` on overflow: a recovered participation's outputs are rebuilt
	/// from server data, whose amounts are untrusted.
	pub fn pending_balance(&self) -> Option<Amount> {
		if self.done {
			return Some(Amount::ZERO);
		}

		match self.flow {
			RoundFlowState::NonInteractivePending { .. }
				| RoundFlowState::Redelegating { .. }
				| RoundFlowState::InteractivePending
				| RoundFlowState::InteractiveOngoing { .. }
				| RoundFlowState::Finished { .. }
			=> {
				self.participation.total_out()
			},
			RoundFlowState::Failed { .. } | RoundFlowState::Canceled => {
				Some(Amount::ZERO)
			},
		}
	}

}

impl StoredRoundState {
	/// Progress a round while durably recording both sides of every handoff.
	/// No forfeit RPC runs until the exact leaves and user shares are on disk.
	pub async fn sync(&mut self, wallet: &Wallet) -> anyhow::Result<RoundStatus> {
		ensure!(!wallet.inner.db.has_program_recovery_reservation(
			&crate::persist::models::recovery_round_key(self.id()),
		).await?, "round {} was taken over by program recovery", self.id());
		let status = self.state_mut().sync(wallet).await?;
		wallet.inner.db.update_round_state(self).await
			.context("failed to checkpoint round before forfeit handoff")?;
		if self.state().done || !matches!(status, RoundStatus::Pending) {
			return Ok(status);
		}
		let state = self.state_mut();
		let RoundFlowState::Finished { funding_tx, unlock_hash } = &state.flow else {
			return Ok(status);
		};
		let Some(bundles) = state.forfeit_bundles.as_ref().filter(|b| !b.is_empty()) else {
			return Ok(status);
		};
		wallet.ensure_program_recoveries(&state.participation.inputs).await
			.context("old round recovery is not ready for forfeit handoff")?;
		for input in &state.participation.inputs {
			let ctx = HarkForfeitSigningContext::new(input, *unlock_hash)?;
			wallet.prepare_hark_recovery(input, &ctx).await?;
		}
		wallet.prepare_program_recoveries(&state.new_vtxos).await
			.context("failed to preserve signed hashlocked round recovery ancestors")?;
		wallet.preserve_hark_unlocks(&state.new_vtxos, &state.participation.inputs, *unlock_hash).await
			.context("failed to preserve authenticated round unlock dependencies")?;
		if !state.new_vtxos.iter().all(|v| v.has_all_witnesses()) {
			let (mut srv, _) = wallet.require_server().await?;
			let response = srv.client.forfeit_vtxos(protos::ForfeitVtxosRequest {
				forfeit_bundles: bundles.clone(),
			}).await;
			let response = match response {
				Ok(response) => response,
				Err(error) if error.code() == tonic::Code::InvalidArgument
					&& error.message().starts_with("no forfeit nonces generated for vtxo ") =>
				{
					// Only explicit nonce loss permits a new native signing session.
					// Keep the exact saved leaves and forfeit transaction identities.
					for vtxo in state.participation.inputs.iter().chain(&state.new_vtxos) {
						ensure!(wallet.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_none(),
							"program round forfeit nonce loss requires saved offline recovery");
					}
					state.forfeit_bundles = Some(prepare_hark_forfeits(
						wallet, &state.participation, *unlock_hash,
					).await?);
					wallet.inner.db.update_round_state(self).await
						.context("failed to checkpoint replacement native forfeit shares")?;
					return Ok(RoundStatus::Pending);
				},
				Err(error) => return Err(error).context("forfeit handoff failed; inputs remain locked"),
			};
			let preimage = response.into_inner().unlock_preimage.as_slice().try_into()
				.context("invalid round unlock preimage length")?;
			for vtxo in &mut state.new_vtxos {
				ensure!(vtxo.provide_unlock_preimage(preimage),
					"invalid unlock preimage for round output {}", vtxo.id(),
				);
			}
		}
		for vtxo in &state.new_vtxos {
			vtxo.validate(funding_tx).context("completed round output failed validation")?;
		}
		// Preserve completed bytes before recovery merging or registration: either
		// operation can fail, and neither may force another signature on retry.
		wallet.inner.db.update_round_state(self).await
			.context("failed to checkpoint completed round outputs")?;
		let state = self.state();
		let funding_tx = state.funding_tx().context("missing finished round transaction")?;
		wallet.ensure_program_recoveries(&state.new_vtxos).await
			.context("completed round recovery is not ready")?;
		wallet.register_vtxo_transactions_with_server(&state.new_vtxos).await
			.context("couldn't register completed round outputs")?;
		persist_round_success(
			wallet, &state.participation, state.movement_id, &state.new_vtxos, funding_tx,
		).await?;
		let funding_txid = funding_tx.compute_txid();
		self.state_mut().done = true;
		wallet.inner.db.update_round_state(self).await?;
		Ok(RoundStatus::Confirmed { funding_txid })
	}
}

/// The state of the process flow of a round
///
/// This tracks the progress of the interactive part of the round, from
/// waiting to start until finishing either succesfully or with a failure.
pub enum RoundFlowState {
	/// We don't do flow and we just wait for the round to finish
	NonInteractivePending {
		unlock_hash: UnlockHash,
		/// The block height we asked the server to schedule this participation
		/// for, if any. We use it to verify the server honoured our schedule:
		/// the new VTXOs must not expire before this height.
		scheduled_height: Option<BlockHeight>,
	},

	/// A delegated participation that lost inputs and replaces itself with a
	/// fresh submission of the ones it has left
	///
	/// Persisted before that submission, so a crash in between recovers:
	/// this record still owns the movement until it is done.
	Redelegating {
		/// The block height the replacement is scheduled for, if any
		scheduled_height: Option<BlockHeight>,
	},

	/// Waiting for round to happen
	InteractivePending,
	/// Interactive part ongoing
	InteractiveOngoing {
		round_seq: RoundSeq,
		attempt_seq: usize,
		state: AttemptState,
	},

	/// Interactive part finished, waiting for confirmation
	Finished {
		funding_tx: Transaction,
		unlock_hash: UnlockHash,
	},

	/// Failed during round
	Failed {
		error: String,
	},

	/// User canceled round
	Canceled,
}

/// The state of a single round attempt
///
/// For each attempt that we participate in, we keep the state of our concrete
/// participation.
pub enum AttemptState {
	AwaitingAttempt,
	AwaitingUnsignedVtxoTree {
		cosign_keys: Vec<Keypair>,
		unlock_hash: UnlockHash,
	},
	AwaitingFinishedRound {
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		unlock_hash: UnlockHash,
	},
}

impl AttemptState {
	/// The state kind represented as a string
	fn kind(&self) -> &'static str {
		match self {
			Self::AwaitingAttempt => "AwaitingAttempt",
			Self::AwaitingUnsignedVtxoTree { .. } => "AwaitingUnsignedVtxoTree",
			Self::AwaitingFinishedRound { .. } => "AwaitingFinishedRound",
		}
	}
}

/// Result from trying to progress an ongoing round attempt
enum AttemptProgressResult {
	Finished {
		funding_tx: Transaction,
		vtxos: Vec<Vtxo<Full>>,
		unlock_hash: UnlockHash,
	},
	Failed(anyhow::Error),
	/// When the state changes, this variant is returned
	///
	/// If during the processing, we have signed any forfeit txs and tried
	/// sending them to the server, the [UnconfirmedRound] instance is returned
	/// so that it can be stored in the state.
	Updated {
		new_state: AttemptState,
	},
	NotUpdated,
}

/// Participate in the new round attempt by submitting our round participation
async fn start_attempt(
	wallet: &Wallet,
	participation: &RoundParticipation,
	event: &RoundAttempt,
) -> anyhow::Result<AttemptState> {
	let (mut srv, ark_info) = wallet.require_server().await.context("server not available")?;

	// Assign cosign pubkeys to the payment requests.
	let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
		.take(participation.outputs.len())
		.collect::<Vec<_>>();

	// Prepare round participation info.
	// For each of our requested vtxo output, we need a set of public and secret nonces.
	let cosign_nonces = cosign_keys.iter()
		.map(|key| {
			let mut secs = Vec::with_capacity(ark_info.nb_round_nonces);
			let mut pubs = Vec::with_capacity(ark_info.nb_round_nonces);
			for _ in 0..ark_info.nb_round_nonces {
				let (s, p) = musig::nonce_pair(key);
				secs.push(s);
				pubs.push(p);
			}
			(secs, pubs)
		})
		.take(participation.outputs.len())
		.collect::<Vec<(Vec<SecretNonce>, Vec<PublicNonce>)>>();


	// The round has now started. We can submit our payment.
	debug!("Submitting payment request with {} inputs and {} vtxo outputs",
		participation.inputs.len(), participation.outputs.len(),
	);

	// Build signed requests with mailbox IDs
	let unblinded_mailbox_id = wallet.mailbox_identifier();
	let signed_reqs = participation.outputs.iter()
		.zip(cosign_keys.iter())
		.zip(cosign_nonces.iter())
		.map(|((req, cosign_key), (_sec, pub_nonces))| {
			SignedVtxoRequest {
				vtxo: req.clone(),
				cosign_pubkey: cosign_key.public_key(),
				nonces: pub_nonces.clone(),
			}
		})
		.collect::<Vec<_>>();

	let mut input_vtxos = Vec::with_capacity(participation.inputs.len());
	for vtxo in participation.inputs.iter() {
		let key = wallet.vtxo_signing_key(vtxo).await?;
		let signature = wallet.sign_vtxo_ownership(&key, OwnershipRequest {
			input: vtxo.clone(),
			proof: OwnershipProof::Round {
				challenge: event.challenge.inner(), outputs: signed_reqs.clone(),
			},
		}).await?;
		input_vtxos.push(protos::InputVtxo {
			vtxo_id: vtxo.id().to_bytes().to_vec(),
			attestation: {
				let attestation = RoundAttemptAttestation::from_signature(
					event.challenge, vtxo, &signed_reqs, signature,
				)?;
				attestation.serialize()
			},
		});
	}

	// Register VTXO transaction chains with server before round participation
	wallet.register_vtxo_transactions_with_server(&participation.inputs).await
		.context("failed to register round input transactions")?;

	let resp = srv.client.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: input_vtxos,
		vtxo_requests: signed_reqs.into_iter().map(Into::into).collect(),
		#[allow(deprecated)]
		offboard_requests: vec![],
		unblinded_mailbox_id: Some(unblinded_mailbox_id.serialize()),
	}).await.context("Ark server refused our payment submission")?;
	let unlock_hash = UnlockHash::from_bytes(&resp.into_inner().unlock_hash)?;

	// Stash nonces in memory only. Empty `cosign_keys` means no VTXO
	// outputs (offboard-only) — nothing to stash.
	if let Some(k) = cosign_keys.first() {
		wallet.inner.round_secret_nonces.stash(
			k.public_key(),
			cosign_nonces.into_iter().map(|(sec, _pub)| sec).collect(),
		);
	}

	Ok(AttemptState::AwaitingUnsignedVtxoTree { unlock_hash, cosign_keys })
}


async fn hark_cosign_leaf(
	wallet: &Wallet,
	srv: &mut ServerConnection,
	funding_tx: &Transaction,
	vtxo: &mut Vtxo<Full>,
) -> anyhow::Result<()> {
	let key = wallet.vtxo_signing_key(&*vtxo).await?;
	let ctx = ExternalLeafVtxoCosignContext::new(vtxo, funding_tx)
		.with_context(|| format!("can't cosign leaf of VTXO {}", vtxo.id()))?;
	let prepared = wallet.prepare_vtxo_signature(&key, ctx.signing_input().clone()).await
		.context("program rejected the round leaf transaction")?;
	let cosign_req = ctx.request(prepared.public_nonce());
	let cosign_resp: LeafVtxoCosignResponse = srv.client.request_leaf_vtxo_cosign(
		protos::LeafVtxoCosignRequest::from(cosign_req),
	).await
		.with_context(|| format!("error requesting leaf cosign for vtxo {}", vtxo.id()))?
		.into_inner().try_into()
		.context("bad leaf vtxo cosign response")?;
	let signature = prepared.finish(
		&key, Some(cosign_resp.public_nonce), Some(cosign_resp.partial_signature),
	).await?.signature.context("round leaf signature is incomplete")?;
	*vtxo = ctx.finalize(signature)
		.context("invalid externally signed round leaf")?;

	Ok(())
}

/// Prepare both sides of the swap before producing any input forfeit share.
/// The caller checkpoints the completed leaves and exact wire bundles before send.
async fn prepare_hark_swap(
	wallet: &Wallet,
	participation: &RoundParticipation,
	output_vtxos: &[Vtxo<Full>],
	funding_tx: &Transaction,
	unlock_hash: UnlockHash,
	sent_forfeit_sigs: bool,
) -> anyhow::Result<(Vec<Vtxo<Full>>, Vec<Vec<u8>>)> {
	let (mut srv, _) = wallet.require_server().await?;
	wallet.ensure_program_recoveries(&participation.inputs).await
		.context("old round position recovery is not ready")?;
	wallet.prepare_program_recoveries(output_vtxos).await
		.context("replacement round recovery preparation failed")?;
	wallet.register_vtxo_transactions_with_server(&participation.inputs).await
		.context("couldn't send our input vtxo transactions to server")?;
	let mut output_vtxos = output_vtxos.to_vec();

	// first get the leaves signed
	for vtxo in output_vtxos.iter_mut() {
		hark_cosign_leaf(wallet, &mut srv, funding_tx, vtxo).await?;
	}

	// Before we hand the server the forfeits of our inputs, check that the
	// new VTXOs still leave us enough room for a unilateral exit.
	if !sent_forfeit_sigs {
		// If we are refreshing only expired inputs, we don't care.
		// Our new VTXOs could have been prepared a long time ago as well.
		let tip = wallet.inner.chain.tip().await.context("chain source error")?;
		if participation.inputs.iter().any(|v| v.expiry_height() > tip) {
			let max_input_exit_delta = participation.inputs.iter().map(|v| v.exit_delta()).max()
				.expect("minimum one input");
			check_output_vtxos_exitable(
				&output_vtxos, tip, wallet.inner.config.vtxo_exit_margin, max_input_exit_delta,
			).context("refusing to forfeit our input VTXOs")?;
		}
	}

	let forfeit_bundles = prepare_hark_forfeits(wallet, participation, unlock_hash).await?;
	Ok((output_vtxos, forfeit_bundles))
}

/// Sign only the deterministic forfeit transactions, without obtaining fresh
/// leaf signatures or replacing checkpointed successor bytes.
async fn prepare_hark_forfeits(
	wallet: &Wallet, participation: &RoundParticipation, unlock_hash: UnlockHash,
) -> anyhow::Result<Vec<Vec<u8>>> {
	let (mut srv, _) = wallet.require_server().await?;

	// the server caps the number of vtxo ids per nonces request, so for
	// large participations we request the nonces in chunks
	let mut server_nonces = Vec::with_capacity(participation.inputs.len());
	for inputs in participation.inputs.chunks(MAX_NB_FORFEIT_NONCE_IDS) {
		let nonces = srv.client.request_forfeit_nonces(protos::ForfeitNoncesRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			vtxo_ids: inputs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
		}).await
			.context("request forfeits nonces call failed")?
			.into_inner().public_nonces.into_iter()
			.map(|b| musig::PublicNonce::from_bytes(b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid forfeit nonces")?;

		if nonces.len() != inputs.len() {
			bail!("server sent {} nonce pairs, expected {}", nonces.len(), inputs.len());
		}
		server_nonces.extend(nonces);
	}

	let mut forfeit_bundles = Vec::with_capacity(participation.inputs.len());
	for (input, nonces) in participation.inputs.iter().zip(server_nonces.into_iter()) {
		let ctx = HarkForfeitSigningContext::new(input, unlock_hash)?;
		wallet.prepare_hark_recovery(input, &ctx).await
			.context("hArk fallback recovery preparation failed")?;
		let key = wallet.vtxo_signing_key(input).await?;
		let prepared = wallet.prepare_vtxo_signature(&key, ctx.signing_input().clone()).await
			.context("program rejected the hArk forfeit transaction")?;
		let user_nonce = prepared.public_nonce();
		let share = prepared.finish(&key, Some(nonces.clone()), None).await?.user_partial;
		forfeit_bundles.push(ctx.assemble(user_nonce, share, &nonces)?.serialize());
	}

	Ok(forfeit_bundles)
}

fn check_vtxo_fails_hash_lock(funding_tx: &Transaction, vtxo: &Vtxo<Full>) -> anyhow::Result<()> {
	// validate() below short-circuits at the terminal hash-locked transition
	// before the point-vs-genesis checksum runs; call validate_unsigned first
	// so a forged point is caught before forfeit signatures are sent.
	vtxo.validate_unsigned(funding_tx).with_context(|| format!(
		"new VTXO {} failed unsigned validation", vtxo.id(),
	))?;

	match vtxo.validate(funding_tx) {
		// NB delegated participations from rounds that predate the v1
		// hashlock clauses have leaves with the v0 transition, so both
		// versions are acceptable here
		Err(VtxoValidationError::GenesisTransition {
			genesis_idx, genesis_len, transition_kind, ..
		}) if genesis_idx + 1 == genesis_len
			&& (transition_kind == TransitionKind::HashLockedCosigned.as_str()
				|| transition_kind == TransitionKind::HashLockedCosigned_v0.as_str()) => Ok(()),
		Ok(()) => Err(anyhow!("new un-unlocked VTXO should fail validation but doesn't: {}",
			vtxo.serialize_hex(),
		)),
		Err(e) => Err(anyhow!("new VTXO {} failed validation: {:#}", vtxo.id(), e)),
	}
}

/// The minimum expiry height that leaves us enough room for a unilateral
/// exit from the current chain tip.
///
/// The exit margin is counted twice: worst case the server withholds the
/// unlock preimage after we forfeit, so we first have to exit the old VTXOs
/// to force the preimage out through the forfeit claim (within exit_delta),
/// and then still exit the new VTXOs before they expire.
fn min_exitable_output_vtxo_expiry_height(
	tip: BlockHeight,
	exit_margin: BlockDelta,
	exit_delta: BlockDelta,
) -> BlockHeight {
	tip + exit_margin * 2 + exit_delta
}

/// Check that each VTXO's expiry leaves us enough room for a unilateral
/// exit from the current chain tip.
///
/// `input_exit_delta` is the exit delta of the input VTXOs
fn check_output_vtxos_exitable(
	vtxos: &[Vtxo<Full>],
	tip: BlockHeight,
	exit_margin: BlockDelta,
	max_input_exit_delta: BlockDelta,
) -> anyhow::Result<()> {
	let min_expiry_height = min_exitable_output_vtxo_expiry_height(tip, exit_margin, max_input_exit_delta);
	for vtxo in vtxos {
		ensure!(vtxo.expiry_height() >= min_expiry_height,
			"VTXO {} expires at height {}, which doesn't leave us room for a \
			unilateral exit (tip {}, exit margin {})",
			vtxo.id(), vtxo.expiry_height(), tip, exit_margin,
		);
	}
	Ok(())
}

fn check_round_matches_participation(
	part: &RoundParticipation,
	new_vtxos: &[Vtxo<Full>],
	funding_tx: &Transaction,
	ark_info: &ArkInfo,
	scheduled_height: Option<BlockHeight>,
	tip: BlockHeight,
	exit_margin: BlockDelta,
	unlock_hash: UnlockHash,
) -> anyhow::Result<()> {
	ensure!(new_vtxos.len() == part.outputs.len(),
		"unexpected number of VTXOs: got {}, expected {}", new_vtxos.len(), part.outputs.len(),
	);

	// Every output we forfeit inputs for must be a distinct VTXO: identical
	// requests are distinct leaves in the tree, so a duplicate here means the
	// server withheld one of our leaves.
	for (idx, vtxo) in new_vtxos.iter().enumerate() {
		ensure!(new_vtxos[idx + 1..].iter().all(|v| v.id() != vtxo.id()),
			"server delivered duplicate VTXO {}", vtxo.id(),
		);
	}

	// We have two requirements on the outputs:
	// - if we asked for a scheduled height, we want the server to respect it
	// - if our inputs are not expired yet, we want the output VTXOs to be exitable
	let expired_inputs = part.inputs.iter().all(|v| v.expiry_height() <= tip);
	let max_input_exit_delta = part.inputs.iter().map(|v| v.exit_delta()).max()
		.expect("min one input");
	let min_exitable = min_exitable_output_vtxo_expiry_height(tip, exit_margin, max_input_exit_delta);
	let min_scheduled = scheduled_height.map(|h| h + BlockDelta::new(1));
	let min_expiry_height = match (expired_inputs, min_scheduled) {
		(false, Some(h)) => h.max(min_exitable),
		(false, None) => min_exitable,
		(true, Some(h)) => h,
		(true, None) => BlockHeight::ZERO,
	};

	// The server returns leaves in no specified order. Count each request so
	// identical requests still require distinct leaves, without changing the
	// request order used by the participation attestation.
	let mut expected_outputs = HashMap::with_capacity(part.outputs.len());
	for req in &part.outputs {
		*expected_outputs.entry((req.amount, &req.policy)).or_insert(0usize) += 1;
	}

	for vtxo in new_vtxos {
		match expected_outputs.get_mut(&(vtxo.amount(), vtxo.policy())) {
			Some(remaining) if *remaining > 0 => *remaining -= 1,
			_ => bail!(
				"unexpected VTXO amount or policy: got {} with {:?}",
				vtxo.amount(), vtxo.policy(),
			),
		}

		// The server chose these tree-level parameters; make sure they match
		// what we expect before we forfeit our inputs in exchange.
		validate_vtxo_tree_params(
			vtxo.server_pubkey(), vtxo.exit_delta(), vtxo.expiry_height(),
			ark_info.server_pubkey, ark_info.vtxo_exit_delta, min_expiry_height,
		)?;

		// We accept the VTXO if only the hArk transition (last) failure happens
		check_vtxo_fails_hash_lock(funding_tx, vtxo)?;

		// The replacement output must be locked under exactly the hash our
		// forfeits commit to: the server earns the forfeit claim only by
		// revealing the preimage of the participation's unlock hash, and
		// that same preimage is the only way to unlock our new outputs. A
		// leaf locked under any other hash is unspendable by us yet the
		// forfeits stay claimable, so reject before any forfeit handoff.
		ensure!(vtxo.unlock_hash() == Some(unlock_hash),
			"round output {} is hash-locked under a foreign unlock hash",
			vtxo.id(),
		);
	}

	Ok(())
}

/// Check the confirmation status of a funding tx
///
/// Returns true if the funding tx is confirmed deeply enough for us to accept it.
/// The required number of confirmations depends on the wallet's configuration.
///
/// Returns false if the funding tx seems valid but not confirmed yet.
///
/// Returns an error if the chain source fails or if we can't submit the tx to the
/// mempool, suggesting it might be double spent.
async fn check_funding_tx_confirmations(
	wallet: &Wallet,
	funding_txid: Txid,
	funding_tx: &Transaction,
) -> anyhow::Result<bool> {
	let tip = wallet.inner.chain.tip().await.context("chain source error")?;
	let conf_height = tip.saturating_sub(wallet.inner.config.round_tx_required_confirmations) + BlockDelta::new(1);
	let tx_status = wallet.inner.chain.tx_status(funding_txid).await.context("chain source error")?;
	trace!("Round funding tx {} confirmation status: {:?} (tip={})",
		funding_txid, tx_status, tip,
	);
	match tx_status {
		TxStatus::Confirmed(b) if b.height <= conf_height => Ok(true),
		TxStatus::Mempool | TxStatus::Confirmed(_) => {
			if wallet.inner.config.round_tx_required_confirmations == BlockDelta::ZERO {
				debug!("Accepting round funding tx without confirmations because of configuration");
				Ok(true)
			} else {
				trace!("Hark round funding tx not confirmed (deep enough) yet: {:?}", tx_status);
				Ok(false)
			}
		},
		TxStatus::NotFound => {
			// let's try to submit it to our mempool
			//TODO(stevenroose) change this to an explicit "testmempoolaccept" so that we can
			// reliably distinguish the cases of our chain source having issues and the tx
			// actually being rejected which suggests the round was double-spent
			if let Err(e) = wallet.inner.chain.broadcast_tx(&funding_tx).await {
				Err(anyhow!("hark funding tx {} server sent us is rejected by mempool (hex={}): {:#}",
					funding_txid, serialize_hex(funding_tx), e,
				))
			} else {
				trace!("hark funding tx {} was not in mempool but we broadcast it", funding_txid);
				Ok(false)
			}
		},
	}
}

enum HarkProgressResult {
	RoundPending,
	RoundNotFound,
	FundingTxUnconfirmed {
		funding_txid: Txid,
	},
	Ok {
		funding_tx: Transaction,
		new_vtxos: Vec<Vtxo<Full>>,
	},
}

async fn progress_delegated(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
	unlock_hash: UnlockHash,
	scheduled_height: Option<BlockHeight>,
	sent_forfeit_sigs: bool,
) -> anyhow::Result<HarkProgressResult> {
	let (mut srv, ark_info) = wallet.require_server().await?;

	let resp = match srv.client.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unlock_hash.to_byte_array().to_vec(),
	}).await {
		Ok(resp) => resp.into_inner(),
		Err(err) if err.code() == tonic::Code::NotFound => {
			if sent_forfeit_sigs {
				bail!("round disappeared after a possible forfeit handoff; retaining input locks");
			}
			return Ok(HarkProgressResult::RoundNotFound);
		},
		Err(err) => {
			return Err(anyhow::Error::from(err).context("error checking round participation status"));
		},
	};
	let status = protos::RoundParticipationStatus::try_from(resp.status)
		.context("unknown status from server")?;

	if status == protos::RoundParticipationStatus::RoundPartPending {
		trace!("Hark round still pending");
		return Ok(HarkProgressResult::RoundPending);
	}

	// Since we got here, we clearly don't think we're finished.
	// So even if the server thinks we did the dance before, we need the
	// cosignature on the leaf tx so we need to do the dance again.
	// "Guilty feet have got no rhythm."
	if status == protos::RoundParticipationStatus::RoundPartReleased {
		let preimage = resp.unlock_preimage.as_ref().map(|p| p.as_hex());
		warn!("Server says preimage was already released for hArk participation \
			with unlock hash {}. Supposed preimage: {:?}", unlock_hash, preimage,
		);
	}

	let funding_tx_bytes = resp.round_funding_tx
		.context("funding transaction should be provided when status is not pending")?;
	let funding_tx = deserialize::<Transaction>(&funding_tx_bytes)
		.context("invalid funding transaction")?;
	let funding_txid = funding_tx.compute_txid();
	trace!("Funding tx for round participation with unlock hash {}: {} ({})",
		unlock_hash, funding_tx.compute_txid(), funding_tx_bytes.as_hex(),
	);

	// Check the confirmation status of the funding tx
	let confirmed = check_funding_tx_confirmations(wallet, funding_txid, &funding_tx).await
		.context("checking funding tx confirmations")?;

	// The server has issued the round and its funding tx is in our mempool or a
	// block: the server no longer accepts these inputs, so hold them like the
	// inputs of an interactive round before we forfeit them below. The lock
	// is forced: a recovered wallet can hold the inputs in any state, even
	// imported as Spent.
	let input_ids = participation.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
	wallet.inner.db.steal_lock(&input_ids, movement_id.map(|m| m.into())).await
		.context("failed to lock inputs of issued delegated round")?;

	if !confirmed {
		return Ok(HarkProgressResult::FundingTxUnconfirmed { funding_txid });
	}

	let new_vtxos = resp.output_vtxos.into_iter()
		.map(|v| <Vtxo<Full>>::deserialize(&v))
		.collect::<Result<Vec<_>, _>>()
		.context("invalid output VTXOs from server")?;

	// Check that the vtxos match our participation in the exact order, and that
	// the server-chosen tree parameters are safe, before we forfeit our inputs.
	let tip = wallet.inner.chain.tip().await.context("chain source error")?;
	check_round_matches_participation(
		participation, &new_vtxos, &funding_tx, &ark_info, scheduled_height,
		tip, wallet.inner.config.vtxo_exit_margin, unlock_hash,
	).context("new VTXOs received from server don't match our participation")?;

	// Discovery never forfeits. The StoredRoundState driver checkpoints these
	// exact outputs before preparing the swap and its durable wire shares.

	Ok(HarkProgressResult::Ok { funding_tx, new_vtxos })
}

async fn progress_attempt(
	state: &mut AttemptState,
	wallet: &Wallet,
	part: &RoundParticipation,
	event: &RoundEvent,
) -> AttemptProgressResult {
	// we will match only the states and messages required to make progress,
	// all else we ignore, except an unexpected finish

	match (state, event) {

		(
			AttemptState::AwaitingUnsignedVtxoTree { cosign_keys, unlock_hash },
			RoundEvent::VtxoProposal(e),
		) => {
			trace!("Received VtxoProposal: {:#?}", e);

			// Missing nonces means we restarted before signing —
			// abandon the attempt rather than reuse on retry.
			let secret_nonces = if let Some(first) = cosign_keys.first() {
				match wallet.inner.round_secret_nonces.take(&first.public_key()) {
					Some(n) => n,
					None => return AttemptProgressResult::Failed(anyhow!(
						"secret cosign nonces unavailable (likely after a restart); \
						 abandoning round attempt to avoid nonce reuse",
					)),
				}
			} else {
				vec![]
			};

			match sign_vtxo_tree(
				wallet,
				part,
				&cosign_keys,
				secret_nonces,
				&e.unsigned_round_tx,
				&e.vtxos_spec,
				&e.cosign_agg_nonces,
				*unlock_hash,
			).await {
				Ok(()) => {
					AttemptProgressResult::Updated {
						new_state: AttemptState::AwaitingFinishedRound {
							unsigned_round_tx: e.unsigned_round_tx.clone(),
							vtxos_spec: e.vtxos_spec.clone(),
							unlock_hash: *unlock_hash,
						},
					}
				},
				Err(e) => {
					trace!("Error signing VTXO tree: {:#}", e);
					AttemptProgressResult::Failed(e)
				},
			}
		},

		(
			AttemptState::AwaitingFinishedRound { unsigned_round_tx, vtxos_spec, unlock_hash },
			RoundEvent::Finished(RoundFinished { cosign_sigs, signed_round_tx, .. }),
		) => {
			if unsigned_round_tx.compute_txid() != signed_round_tx.compute_txid() {
				return AttemptProgressResult::Failed(anyhow!(
					"signed funding tx ({}) doesn't match tx received before ({})",
					signed_round_tx.compute_txid(), unsigned_round_tx.compute_txid(),
				));
			}

			if let Err(e) = wallet.inner.chain.broadcast_tx(&signed_round_tx).await {
				warn!("Failed to broadcast signed round tx: {:#}", e);
			}

			match construct_new_vtxos(
				part, unsigned_round_tx, vtxos_spec, cosign_sigs, *unlock_hash,
			).await {
				Ok(v) => AttemptProgressResult::Finished {
					funding_tx: signed_round_tx.clone(),
					vtxos: v,
					unlock_hash: *unlock_hash,
				},
				Err(e) => AttemptProgressResult::Failed(anyhow!(
					"failed to construct new VTXOs for round: {:#}", e,
				)),
			}
		},

		(state, RoundEvent::Finished(RoundFinished { .. })) => {
			AttemptProgressResult::Failed(anyhow!(
				"unexpectedly received a finished round while we were in state {}",
				state.kind(),
			))
		},

		(state, _) => {
			trace!("Ignoring round event {} in state {}", event.kind(), state.kind());
			AttemptProgressResult::NotUpdated
		},
	}
}

async fn sign_vtxo_tree(
	wallet: &Wallet,
	participation: &RoundParticipation,
	cosign_keys: &[Keypair],
	secret_nonces: Vec<Vec<SecretNonce>>,
	unsigned_round_tx: &Transaction,
	vtxo_tree: &VtxoTreeSpec,
	cosign_agg_nonces: &[musig::AggregatedNonce],
	unlock_hash: UnlockHash,
) -> anyhow::Result<()> {
	let (mut srv, ark_info) = wallet.require_server().await.context("server not available")?;

	let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), ROUND_TX_VTXO_TREE_VOUT);

	// Validate the tree. We expect new VTXOs to be within a buffer from
	// expected vtxo lifetime.
	let tip = wallet.inner.chain.tip().await.context("chain source error")?;
	let min_expiry_height = (tip + ark_info.vtxo_lifetime)
		.saturating_sub(VTXO_EXPIRY_HEIGHT_BUFFER);
	validate_vtxo_tree_params(
		vtxo_tree.server_pubkey, vtxo_tree.exit_delta, vtxo_tree.expiry_height,
		ark_info.server_pubkey, ark_info.vtxo_exit_delta, min_expiry_height,
	)?;

	// Check that the proposal contains our inputs.
	let mut my_vtxos = participation.outputs.iter().collect::<Vec<_>>();
	for vtxo_req in vtxo_tree.iter_vtxos() {
		if let Some(i) = my_vtxos.iter().position(|v| {
			v.policy == vtxo_req.vtxo.policy && v.amount == vtxo_req.vtxo.amount
		}) {
			my_vtxos.swap_remove(i);
		}
	}
	if !my_vtxos.is_empty() {
		bail!("server didn't include all of our vtxos, missing: {:?}", my_vtxos);
	}

	let unsigned_vtxos = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);
	trace!("Sending vtxo signatures to server...");
	let leaf_idxs = unsigned_vtxos.spec.leaf_idxs_for_participation(
		unlock_hash, participation.outputs.iter().map(|o| o),
	).context("our outputs not part of tree")?;
	// Sequential: SecretNonce is consume-once and not Clone, so we move
	// one Vec<SecretNonce> into cosign_branch per output. Going parallel
	// would require sharing the server connection across futures, which
	// isn't worth the complexity for a per-output RPC.
	for ((leaf_idx, key), sec) in leaf_idxs.into_iter().zip(cosign_keys).zip(secret_nonces) {
		let part_sigs = unsigned_vtxos.cosign_branch(
			&cosign_agg_nonces, leaf_idx, key, sec,
		).context("failed to cosign branch: our request not part of tree")?;

		info!("Sending {} partial vtxo cosign signatures for pk {}",
			part_sigs.len(), key.public_key(),
		);

		srv.client.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
			pubkey: key.public_key().serialize().to_vec(),
			signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
		}).await.context("error sending vtxo signatures")?;
	}
	trace!("Done sending vtxo signatures to server");

	Ok(())
}

async fn construct_new_vtxos(
	participation: &RoundParticipation,
	unsigned_round_tx: &Transaction,
	vtxo_tree: &VtxoTreeSpec,
	vtxo_cosign_sigs: &[schnorr::Signature],
	unlock_hash: UnlockHash,
) -> anyhow::Result<Vec<Vtxo<Full>>> {
	let round_txid = unsigned_round_tx.compute_txid();
	let vtxos_utxo = OutPoint::new(round_txid, ROUND_TX_VTXO_TREE_VOUT);
	let vtxo_tree = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);

	// Validate the vtxo tree and cosign signatures.
	if vtxo_tree.verify_cosign_sigs(&vtxo_cosign_sigs).is_err() {
		// bad server!
		bail!("Received incorrect vtxo cosign signatures from server");
	}

	let signed_vtxos = vtxo_tree
		.into_signed_tree(vtxo_cosign_sigs.to_vec())
		.into_cached_tree();

	let mut expected_vtxos = participation.outputs.iter().collect::<Vec<_>>();
	let total_nb_expected_vtxos = expected_vtxos.len();

	let mut new_vtxos = vec![];
	for (idx, req) in signed_vtxos.spec.spec.vtxos.iter().enumerate() {
		// Only leaves locked under the hash our forfeits commit to are
		// acceptable: a leaf matching our request under a foreign hash is
		// unspendable once the forfeit shares are handed over. The tree
		// order is server-chosen, so a forged duplicate ordered before the
		// genuine leaf must never be selected.
		if req.unlock_hash != unlock_hash {
			continue;
		}
		if let Some(expected_idx) = expected_vtxos.iter().position(|r| **r == req.vtxo) {
			let vtxo = signed_vtxos.build_vtxo(idx);

			// validate the received vtxos
			// This is more like a sanity check since we crafted them ourselves.
			check_vtxo_fails_hash_lock(unsigned_round_tx, &vtxo)
				.context("constructed invalid vtxo from tree")?;

			info!("New VTXO from round: {} ({}, {})",
				vtxo.id(), vtxo.amount(), vtxo.policy_type(),
			);

			new_vtxos.push(vtxo);
			expected_vtxos.swap_remove(expected_idx);
		}
	}

	if !expected_vtxos.is_empty() {
		if expected_vtxos.len() == total_nb_expected_vtxos {
			// we must have done something wrong
			bail!("None of our VTXOs were present in round!");
		} else {
			bail!("Server included some of our VTXOs but not all: {} missing: {:?}",
				expected_vtxos.len(), expected_vtxos,
			);
		}
	}
	Ok(new_vtxos)
}

//TODO(stevenroose) should be made idempotent
async fn persist_round_success(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
	new_vtxos: &[Vtxo<Full>],
	funding_tx: &Transaction,
) -> anyhow::Result<()> {
	debug!("Persisting newly finished round. {} new vtxos, movement ID {:?}",
		new_vtxos.len(), movement_id,
	);
	wallet.ensure_program_recoveries(new_vtxos).await
		.context("completed round recovery is not ready")?;

	// we first try all actions that need to happen and only afterwards return errors
	// so that we achieve maximum success

	// Spend the inputs before storing the outputs: in between, the balance
	// misses these sats for a moment rather than counting them twice.
	// The server completed the round, so the inputs are forfeited whatever
	// state the wallet has for them locally. A recovered wallet can hold
	// them in any state.
	let input_ids = participation.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
	let spent_result = wallet.inner.db.steal_lock_to_spent(&input_ids).await
		.context("failed to mark input VTXOs as spent");
	let store_result = wallet.store_spendable_vtxos(new_vtxos).await
		.context("failed to store new VTXOs");
	let update_result = if let Some(mid) = movement_id {
		wallet.inner.movements.finish_movement_with_update(
			mid,
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(new_vtxos)
				.metadata([("funding_txid".into(), serde_json::to_value(funding_tx.compute_txid())?)]),
		).await.context("failed to mark movement as finished")
	} else {
		Ok(())
	};

	store_result?;
	spent_result?;
	update_result?;

	Ok(())
}

async fn persist_round_failure(
	wallet: &Wallet,
	participation: &RoundParticipation,
	movement_id: Option<MovementId>,
) -> anyhow::Result<()> {
	debug!("Attempting to persist the failure of a round with the movement ID {:?}", movement_id);
	// Inputs the round never locked, or that another operation holds by now,
	// are skipped: `unlock_vtxos` only releases what this holder locked.
	let unlock_result = wallet.unlock_vtxos(
		&participation.inputs, movement_id.map(|m| m.into()),
	).await;
	let finish_result = if let Some(movement_id) = movement_id {
		wallet.inner.movements.finish_movement(movement_id, MovementStatus::Failed).await
	} else {
		Ok(())
	};
	if let Err(e) = &finish_result {
		error!("Failed to mark movement as failed: {:#}", e);
	}
	match (unlock_result, finish_result) {
		(Ok(()), Ok(())) => Ok(()),
		(Err(e), _) => Err(e),
		(_, Err(e)) => Err(anyhow!("Failed to mark movement as failed: {:#}", e)),
	}
}

async fn update_funding_txid(
	wallet: &Wallet,
	movement_id: MovementId,
	funding_txid: Txid,
) -> anyhow::Result<()> {
	wallet.inner.movements.update_movement(
		movement_id,
		MovementUpdate::new()
			.metadata([("funding_txid".into(), serde_json::to_value(&funding_txid)?)])
	).await.context("Unable to update funding txid of round")
}

/// In-memory store for MuSig2 secret cosign nonces used during round
/// signing. Entries are keyed by the first cosign pubkey of each round
/// attempt — that pubkey is freshly generated in `start_attempt`,
/// uniquely identifies the attempt within a process, and is reachable
/// from the persisted `AttemptState::AwaitingUnsignedVtxoTree`.
///
/// Nonces never touch disk: persisting them risks signing twice with
/// the same nonce, which is unsafe with MuSig2.
#[derive(Default)]
pub struct RoundSecretNonces {
	inner: parking_lot::Mutex<HashMap<bitcoin::secp256k1::PublicKey, Vec<Vec<SecretNonce>>>>,
}

impl RoundSecretNonces {
	pub fn new() -> Self {
		Self { inner: parking_lot::Mutex::new(HashMap::new()) }
	}

	/// Insert nonces under the given key, replacing any previous entry.
	pub fn stash(
		&self,
		first_cosign_pubkey: bitcoin::secp256k1::PublicKey,
		nonces: Vec<Vec<SecretNonce>>,
	) {
		self.inner.lock().insert(first_cosign_pubkey, nonces);
	}

	/// Remove and return the nonces stashed under the given key.
	/// `None` after a process restart or if the entry was never stashed.
	pub fn take(
		&self,
		first_cosign_pubkey: &bitcoin::secp256k1::PublicKey,
	) -> Option<Vec<Vec<SecretNonce>>> {
		self.inner.lock().remove(first_cosign_pubkey)
	}

	/// Drop the entry under the given key without returning its
	/// contents. Use when a stashed attempt is being replaced by a new
	/// one and its key would otherwise be unreachable.
	pub fn forget(&self, first_cosign_pubkey: &bitcoin::secp256k1::PublicKey) {
		self.inner.lock().remove(first_cosign_pubkey);
	}
}

impl Wallet {
	/// Load and lock a single given round state (by id), waiting for the lock.
	///
	/// Returns `Some(state)` if the round state is found and locked, `None`
	/// if it is not found after acquiring the lock.
	pub async fn lock_wait_round_state(&self, id: RoundStateId) -> anyhow::Result<Option<StoredRoundState>> {
		let guard = self.inner.lock_manager.lock(
			&format!("{}.round.{}", self.fingerprint(), id),
			ROUND_LOCK_TIMEOUT,
		).await.with_context(|| format!(
			"timed out waiting for lock on round state {} (wallet {})",
			id, self.fingerprint(),
		))?;
		ensure!(!self.inner.db.has_program_recovery_reservation(
			&crate::persist::models::recovery_round_key(id),
		).await?, "round {id} was taken over by program recovery");

		if let Some(state) = self.inner.db.get_round_state_by_id(id).await? {
			return Ok(Some(state.lock(guard)));
		}

		Ok(None)
	}

	/// Load and lock one round state by id, without waiting.
	///
	/// Returns `None` when the state is gone or another holder has it, which
	/// a caller making opportunistic progress skips.
	async fn try_lock_round_state(
		&self,
		id: RoundStateId,
	) -> anyhow::Result<Option<StoredRoundState>> {
		let guard = match self.inner.lock_manager.try_lock(
			&format!("{}.round.{}", self.fingerprint(), id),
		).await {
			Some(g) => g,
			None => return Ok(None),
		};
		if self.inner.db.has_program_recovery_reservation(
			&crate::persist::models::recovery_round_key(id),
		).await? {
			return Ok(None);
		}

		Ok(self.inner.db.get_round_state_by_id(id).await?.map(|s| s.lock(guard)))
	}

	/// Ask the server when the next round is scheduled to start
	pub async fn next_round_start_time(&self) -> anyhow::Result<SystemTime> {
		let (mut srv, _) = self.require_server().await?;
		let ts = srv.client.next_round_time(protos::Empty {}).await?.into_inner().timestamp;
		Ok(UNIX_EPOCH.checked_add(Duration::from_secs(ts)).context("invalid timestamp")?)
	}

	/// Point a round movement at the inputs and amounts of the participation
	/// it now stands for, after that participation was shrunk.
	async fn sync_movement_to_participation(
		&self,
		movement_id: MovementId,
		participation: &RoundParticipation,
	) -> anyhow::Result<()> {
		let update = participation.to_movement_update()?
			.replace_consumed_vtxos(&participation.inputs);
		self.inner.movements.update_movement(movement_id, update).await
			.context("failed to update movement after shrinking participation")?;
		Ok(())
	}

	async fn check_inputs_spendable(&self, inputs: &[VtxoId]) -> anyhow::Result<()> {
		for input in inputs.iter() {
			let vtxo = self.get_vtxo_by_id(*input).await
				.context("error loading round input VTXO")?;
			if vtxo.state.kind() != VtxoStateKind::Spendable {
				bail!("input VTXO {} is not spendable (state: {})",
					input, vtxo.state.kind(),
				);
			}
		}
		Ok(())
	}

	/// Start a new round participation
	///
	/// Stores the participation intent in the db. The input VTXOs are only
	/// locked once a round attempt starts, so an abandoned participation
	/// never leaves VTXOs locked.
	///
	/// ### Return
	///
	/// - By default, the returned state will be locked to prevent race conditions.
	/// To unlock the state, [StoredRoundState::unlock()] can be called.
	pub async fn join_next_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<StoredRoundState> {
		let input_ids = participation.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();

		// The inputs are only locked at attempt start; here they must just
		// be spendable.
		self.check_inputs_spendable(&input_ids).await?;

		let movement = if let Some(kind) = movement_kind {
			Some(self.inner.movements.new_guarded_movement_with_update(
				Subsystem::ROUND,
				kind.to_string(),
				OnDropStatus::Failed,
				participation.to_movement_update()?
			).await?)
		} else {
			None
		};
		let movement_id = movement.as_ref().map(|m| m.id());
		let state = RoundState::new_interactive(participation, movement_id);

		match (async || {
			let id = self.inner.db.store_round_state(&state).await?;
			Ok(self.lock_wait_round_state(id).await?
				.context("failed to lock fresh round state")?)
		})().await {
			Ok(state) => {
				if let Some(mut m) = movement {
					m.stop();
				}
				Ok(state)
			},
			Err(e) => {
				if let Some(mut m) = movement {
					m.fail().await.context("failed to mark movement as failed")?;
				}
				Err(e)
			},
		}
	}

	/// Join a round in delegated mode.
	///
	/// When `scheduled_height` is set, the server won't include the participation in a round
	/// before the chain tip reaches it. When `None`, it is eligible for the next round (see
	/// [Wallet::join_next_round_delegated]).
	pub async fn join_delegated_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
		scheduled_height: Option<BlockHeight>,
	) -> anyhow::Result<StoredRoundState<Unlocked>> {
		// The inputs are only locked once an attempt starts, so like an
		// interactive registration this one just needs them spendable.
		// Pending participations over the same inputs stand: the server drops
		// the ones it holds when it stores this submission, and they notice
		// on their next sync.
		let input_ids = participation.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.check_inputs_spendable(&input_ids).await?;

		let movement = if let Some(kind) = movement_kind {
			Some(self.inner.movements.new_guarded_movement_with_update(
				Subsystem::ROUND,
				kind.to_string(),
				OnDropStatus::Failed,
				participation.to_movement_update()?,
			).await?)
		} else {
			None
		};
		let movement_id = movement.as_ref().map(|m| m.id());

		match self.join_delegated_round_inner(participation, movement_id, scheduled_height).await {
			Ok(state) => {
				if let Some(mut m) = movement {
					m.stop();
				}
				Ok(state)
			},
			Err(e) => {
				if let Some(mut m) = movement {
					m.fail().await.context("error marking movement as failed")?;
				}
				Err(e)
			},
		}
	}

	/// Join the next delegated round, i.e. [Wallet::join_delegated_round] with no scheduled
	/// height, so the participation is eligible for the very next round.
	pub async fn join_next_round_delegated(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<StoredRoundState<Unlocked>> {
		self.join_delegated_round(participation, movement_kind, None).await
	}

	/// Join a round in delegated mode.
	///
	/// When `scheduled_height` is set, the server won't include the participation in a round
	/// before the chain tip reaches it. When `None`, it is eligible for the next round.
	async fn join_delegated_round_inner(
		&self,
		participation: RoundParticipation,
		movement_id: Option<MovementId>,
		scheduled_height: Option<BlockHeight>,
	) -> anyhow::Result<StoredRoundState<Unlocked>> {
		let (mut srv, _) = self.require_server().await?;

		// Get mailbox identifier for VTXO delivery
		let unblinded_mailbox_id = self.mailbox_identifier();

		// Register VTXO transaction chains with server before round participation
		self.register_vtxo_transactions_with_server(&participation.inputs).await
			.context("failed to register input vtxo transactions with server")?;

		// Generate attestations for input vtxos
		let mut input_vtxos = Vec::with_capacity(participation.inputs.len());
		for vtxo in participation.inputs.iter() {
			let key = self.vtxo_signing_key(vtxo).await?;
			let signature = self.sign_vtxo_ownership(&key, OwnershipRequest {
				input: vtxo.clone(),
				proof: OwnershipProof::DelegatedRound { outputs: participation.outputs.clone() },
			}).await?;
			input_vtxos.push(protos::InputVtxo {
				vtxo_id: vtxo.id().to_bytes().to_vec(),
				attestation: {
					let attestation = DelegatedRoundParticipationAttestation::from_signature(
						vtxo, &participation.outputs, signature,
					)?;
					attestation.serialize()
				},
			});
		}

		// Build proto VtxoRequests
		let vtxo_requests = participation.outputs.iter()
			.map(|req|
				protos::VtxoRequest {
					policy: req.policy.serialize(),
					amount: req.amount.to_sat(),
			})
			.collect::<Vec<_>>();

		// Submit participation to server and get unlock_hash
		let resp = srv.client.submit_round_participation(protos::RoundParticipationRequest {
			input_vtxos,
			vtxo_requests,
			unblinded_mailbox_id: Some(unblinded_mailbox_id.serialize()),
			scheduled_height: scheduled_height.map(|h| h.into()),
		}).await.context("error submitting round participation to server")?.into_inner();

		let unlock_hash = UnlockHash::from_bytes(resp.unlock_hash)
			.context("invalid unlock hash from server")?;

		let state = RoundState::new_delegated(
			participation, unlock_hash, scheduled_height, movement_id,
		);

		info!("Delegated round participation submitted, it will automatically execute \
			when you next sync your wallet after the round happened \
			(and has sufficient confirmations).",
		);

		// NB: the server dropped any older pending participation over one of
		// these inputs when it accepted this one. Those records stay in place
		// and settle on their own sync, which keeps this function callable
		// from a state that is itself being synced.
		let id = self.inner.db.store_round_state(&state).await?;
		Ok(StoredRoundState::new(id, state))
	}

	/// Rebuild a delegated round participation the wallet has no local state
	/// for, e.g. after a recovery from seed, and store it so the next sync
	/// continues it.
	///
	/// Only returns an error on transient failures (server, chain or
	/// database), so retrying can succeed. Invalid participation data from
	/// the server is logged and the recovery abandoned without error,
	/// because a retry would receive the same data again.
	pub(crate) async fn recover_delegated_participation(
		&self,
		unlock_hash: UnlockHash,
	) -> anyhow::Result<()> {
		for state in self.pending_round_states().await? {
			if state.state().unlock_hash() == Some(unlock_hash) {
				return Ok(());
			}
		}

		let (mut srv, ark_info) = self.require_server().await?;
		let resp = match srv.client.round_participation_status(
			protos::RoundParticipationStatusRequest {
				unlock_hash: unlock_hash.to_byte_array().to_vec(),
			},
		).await {
			Ok(resp) => resp.into_inner(),
			Err(err) if err.code() == tonic::Code::NotFound => {
				info!("Server has no round participation with unlock hash {}; \
					nothing to recover", unlock_hash);
				return Ok(());
			},
			Err(err) => return Err(anyhow::Error::from(err)
				.context("error fetching round participation from server")),
		};

		if resp.input_vtxo_ids.is_empty() {
			error!("Participation {} must have at least a single input", unlock_hash);
			return Ok(());
		}
		if resp.output_vtxos.is_empty() {
			error!("Participation {} must have at least a single output", unlock_hash);
			return Ok(());
		}

		let mut output_vtxos = Vec::with_capacity(resp.output_vtxos.len());
		for raw in resp.output_vtxos.iter() {
			match <Vtxo<Full>>::deserialize(raw) {
				Ok(vtxo) => output_vtxos.push(vtxo),
				Err(e) => {
					error!("Not recovering round participation {}: \
						invalid output vtxo from server: {}", unlock_hash, e,
					);
					return Ok(());
				},
			}
		}

		// The participation was already completed by an earlier sync: the
		// state is removed once its outputs are in the wallet, so a replayed
		// completion message must not resurrect it.
		for vtxo in output_vtxos.iter() {
			if self.inner.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
				return Ok(());
			}
		}

		info!("Recovering delegated round participation with unlock hash {}", unlock_hash);

		// The keys of the participation were derived by the wallet that
		// created it, so they may be past what this wallet has revealed.
		let mut undiscovered_pubkeys = Vec::new();
		for output in &output_vtxos {
			if self.signing_key(&output.user_pubkey()).await?.is_none() {
				undiscovered_pubkeys.push(output.user_pubkey());
			}
		}
		self.find_vtxo_keypairs(undiscovered_pubkeys, self.inner.config.vtxo_key_gap_limit).await?;
		for vtxo in output_vtxos.iter() {
			if self.signing_key(&vtxo.user_pubkey()).await?.is_none() {
				error!("Not recovering round participation {}: \
					output vtxo {} is not ours", unlock_hash, vtxo.id(),
				);
				return Ok(());
			}
			if vtxo.server_pubkey() != ark_info.server_pubkey {
				error!("Not recovering round participation {}: output vtxo {} \
					commits to a foreign server pubkey {}",
					unlock_hash, vtxo.id(), vtxo.server_pubkey(),
				);
				return Ok(());
			}
		}

		let mut inputs = Vec::with_capacity(resp.input_vtxo_ids.len());
		for raw in resp.input_vtxo_ids {
			let id = match VtxoId::from_bytes(raw) {
				Ok(id) => id,
				Err(e) => {
					error!("Not recovering round participation {}: \
						invalid input vtxo id from server: {}", unlock_hash, e,
					);
					return Ok(());
				},
			};
			if self.inner.db.get_wallet_vtxo(id).await?.is_none() {
				let vtxo = self.fetch_vtxo(id).await?;
				// The server holds the input already, so its reported spend
				// state says nothing useful here; the round state machine marks
				// it spent once the participation completes.
				self.import_vtxo(&vtxo, ImportVtxoArgs {
					skip_status_check: true,
					..Default::default()
				}).await.with_context(|| format!(
					"failed to import input vtxo {} of round participation {}", id, unlock_hash,
				))?;
			}
			inputs.push(self.get_full_vtxo(id).await?);
		}

		let outputs = output_vtxos.iter().map(|vtxo| VtxoRequest {
			amount: vtxo.amount(),
			policy: vtxo.policy().clone(),
		}).collect();

		let participation = RoundParticipation {
			inputs,
			outputs,
			unblinded_mailbox_id: Some(self.mailbox_identifier()),
		};

		// The participation is rebuilt from server data, so nothing else bounds
		// what the server claims we agreed to pay in fees.
		let (Some(total_in), Some(total_out)) =
			(participation.total_in(), participation.total_out())
		else {
			error!("Not recovering round participation {}: value overflow", unlock_hash);
			return Ok(());
		};
		if let Err(e) = sane_recovered_participation_fee(total_in, total_out) {
			error!("Not recovering round participation {}: {:#}", unlock_hash, e);
			return Ok(());
		}
		let state = RoundState::new_delegated(participation, unlock_hash, None, None);
		self.inner.db.store_round_state(&state).await?;
		Ok(())
	}

	/// Join an already-started round attempt interactively, submitting our
	/// participation synchronously.
	///
	/// Unlike [Wallet::join_next_round] — which stores a pending participation
	/// and waits for a round to start before submitting inside the round state
	/// machine — this submits to the in-flight `attempt` right away. This allows
	/// us to react to any unspendable VTXOs and exclude them from the refresh.
	pub(crate) async fn join_attempt_interactive(
		&self,
		participation: RoundParticipation,
		attempt: &RoundAttempt,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<StoredRoundState<Unlocked>> {
		// Publish a discoverable intent and take its ordinary round guard before
		// locking inputs or exporting an attestation. Recovery can now coordinate
		// even the first attempt, including movement-held and holder-less inputs.
		let mut state = self.join_next_round(participation, movement_kind).await?;
		let participation = &state.state().participation;
		let input_ids = participation.inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
		let movement_id = state.state().movement_id;
		let attempt_state = match self.lock_vtxos(&input_ids, state.state().lock_holder()).await {
			Ok(()) => start_attempt(self, participation, attempt).await,
			Err(error) => Err(error.context("error locking input VTXOs")),
		};
		match attempt_state {
			Ok(attempt_state) => {
				state.state_mut().flow = RoundFlowState::InteractiveOngoing {
					round_seq: attempt.round_seq,
					attempt_seq: attempt.attempt_seq,
					state: attempt_state,
				};
				self.inner.db.update_round_state(&state).await?;
				Ok(state.unlock())
			},
			Err(error) => {
				// Preserve tonic rejection identifiers for the caller's native
				// refresh/shrink behavior, after ownership-sensitive cleanup.
				persist_round_failure(self, participation, movement_id).await?;
				self.inner.db.remove_round_state(&state).await?;
				Err(error)
			},
		}
	}

	/// Get all pending round states
	pub async fn pending_round_state_ids(&self) -> anyhow::Result<Vec<RoundStateId>> {
		self.inner.db.get_pending_round_state_ids().await
	}

	/// Get all pending round states
	pub async fn pending_round_states(&self) -> anyhow::Result<Vec<StoredRoundState<Unlocked>>> {
		let ids = self.inner.db.get_pending_round_state_ids().await?;
		let mut states = Vec::with_capacity(ids.len());
		for id in ids {
			if let Some(state) = self.inner.db.get_round_state_by_id(id).await? {
				states.push(state);
			}
		}
		Ok(states)
	}

	/// The amount the pending rounds will produce as new VTXOs, including
	/// participations still awaiting their round.
	///
	/// This is not the amount locked in rounds: an interactive participation
	/// locks its inputs once a round attempt starts and a delegated one once
	/// the server has issued the round. Use [Wallet::balance] for the amount
	/// locked.
	pub async fn pending_round_balance(&self) -> anyhow::Result<Amount> {
		let mut states = Vec::new();
		for round in self.pending_round_states().await? {
			if self.inner.db.has_program_recovery_reservation(
				&crate::persist::models::recovery_round_key(round.id()),
			).await? { continue; }
			states.push(round);
		}
		sum_pending_round_balances(states.iter().map(|s| s.state()))
	}

	/// Returns all VTXOs that are locked in a pending round
	///
	/// This excludes all input VTXOs for which the output VTXOs have already
	/// been created, and inputs the round does not hold: those of a delegated
	/// participation the server has not issued yet, which are still spendable
	/// or locked by another operation.
	pub async fn pending_round_input_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut ret = Vec::new();
		for round in self.pending_round_states().await? {
			let holder = round.state().lock_holder();
			let inputs = round.state().locked_pending_inputs();
			ret.reserve(inputs.len());
			for input in inputs {
				let v = self.get_vtxo_by_id(input.id()).await
					.context("unknown round input VTXO")?;
				if matches!(&v.state, VtxoState::Locked { holder: h } if *h == holder) {
					ret.push(v);
				}
			}
		}
		Ok(ret)
	}

	/// Sync pending rounds that have finished but are waiting for confirmations
	pub async fn sync_pending_rounds(&self) -> anyhow::Result<HashMap<RoundStateId, RoundStatus>> {
		let states = self.pending_round_states().await?;
		if states.is_empty() {
			return Ok(HashMap::new());
		}

		debug!("Syncing {} pending round states...", states.len());

		let ret = Arc::new(parking_lot::Mutex::new(HashMap::with_capacity(states.len())));
		tokio_stream::iter(states).for_each_concurrent(10, |state| {
			let ret = ret.clone();
			async move {
				// Round events drive an attempt; one only waiting for its
				// round is ours to sync.
				if state.state().ongoing_attempt() {
					return;
				}

				// drive_round_state holds that one's lock for the whole wait,
				// so skip it when contended rather than time out. The rest is
				// held briefly and worth waiting for.
				let locked = if state.state().ongoing_participation() {
					self.try_lock_round_state(state.id()).await
				} else {
					self.lock_wait_round_state(state.id()).await
				};
				let mut state = match locked {
					Ok(Some(state)) => state,
					Ok(None) => return,
					Err(e) => {
						warn!("Error locking round state: {:#}", e);
						return;
					},
				};

				let status = match state.sync(self).await {
					Ok(s) => s,
					Err(e) => {
						warn!("Error syncing round: {:#}", e);
						return;
					},
				};
				trace!("Synced round #{}, status: {:?}", state.id(), status);
				match status {
					RoundStatus::Confirmed { funding_txid } => {
						info!("Round confirmed. Funding tx {}", funding_txid);
						if let Err(e) = self.inner.db.remove_round_state(&state).await {
							warn!("Error removing confirmed round state from db: {:#}", e);
						}
					},
					RoundStatus::Unconfirmed { funding_txid } => {
						info!("Waiting for confirmations for round funding tx {}", funding_txid);
						if let Err(e) = self.inner.db.update_round_state(&state).await {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					RoundStatus::Pending => {
						if let Err(e) = self.inner.db.update_round_state(&state).await {
							warn!("Error updating pending round state in db: {:#}", e);
						}
					},
					RoundStatus::Failed { ref error } => {
						error!("Round failed: {}", error);
						if let Err(e) = self.inner.db.remove_round_state(&state).await {
							warn!("Error removing failed round state from db: {:#}", e);
						}
					},
					RoundStatus::Canceled => {
						error!("Round canceled");
						if let Err(e) = self.inner.db.remove_round_state(&state).await {
							warn!("Error removing canceled round state from db: {:#}", e);
						}
					},
				}
				ret.lock().insert(state.id(), status);
			}
		}).await;

		Ok(Arc::into_inner(ret).expect("only ref left").into_inner())
	}

	/// Fetch last round event from server
	async fn get_last_round_event(&self) -> anyhow::Result<RoundEvent> {
		let (mut srv, _) = self.require_server().await?;
		let e = srv.client.last_round_event(protos::Empty {}).await?.into_inner();
		Ok(RoundEvent::try_from(e).context("invalid event format from server")?)
	}

	async fn inner_process_event(
		&self,
		state: &mut StoredRoundState,
		event: Option<&RoundEvent>,
	) {
		if let Some(event) = event && state.state().ongoing_participation() {
			let updated = state.state_mut().process_event(self, &event).await;
			if updated {
				if let Err(e) = self.inner.db.update_round_state(&state).await {
					error!("Error storing round state #{} after progress: {:#}", state.id(), e);
				}
			}
		}

		match state.sync(self).await {
			Err(e) => warn!("Error syncing round #{}: {:#}", state.id(), e),
			Ok(s) if s.is_final() => {
				info!("Round #{} finished with result: {:?}", state.id(), s);
				if let Err(e) = self.inner.db.remove_round_state(&state).await {
					warn!("Failed to remove finished round #{} from db: {:#}", state.id(), e);
				}
			},
			Ok(s) => {
				trace!("Round state #{} is now in state {:?}", state.id(), s);
				if let Err(e) = self.inner.db.update_round_state(&state).await {
					warn!("Error storing round state #{}: {:#}", state.id(), e);
				}
			},
		}
	}

	/// Try to make incremental progress on all pending round states
	///
	/// If the `last_round_event` argument is not provided, it will be fetched
	/// from the server.
	pub async fn progress_pending_rounds(
		&self,
		last_round_event: Option<&RoundEvent>,
	) -> anyhow::Result<()> {
		let states = self.pending_round_states().await?;
		if states.is_empty() {
			return Ok(());
		}

		info!("Processing {} rounds...", states.len());

		let mut last_round_event = last_round_event.map(|e| Cow::Borrowed(e));

		let has_ongoing_participation = states.iter()
			.any(|s| s.state().ongoing_participation());
		if has_ongoing_participation && last_round_event.is_none() {
			match self.get_last_round_event().await {
				Ok(e) => last_round_event = Some(Cow::Owned(e)),
				Err(e) => {
					warn!("Error fetching round event, \
						failed to progress ongoing rounds: {:#}", e);
				},
			}
		}

		let event = last_round_event.as_ref().map(|c| c.as_ref());

		let futs = states.into_iter().map(async |state| {
			let locked = self.lock_wait_round_state(state.id()).await?;
			if let Some(mut locked) = locked {
				self.inner_process_event(&mut locked, event).await;
			}
			Ok::<_, anyhow::Error>(())
		});

		futures::future::join_all(futs).await;

		Ok(())
	}

	pub async fn subscribe_round_events(&self)
		-> anyhow::Result<impl Stream<Item = anyhow::Result<RoundEvent>> + Unpin + use<>>
	{
		let (mut srv, _) = self.require_server().await?;
		let mut req = tonic::IntoRequest::into_request(protos::Empty {});
		req.set_timeout(SUBSCRIBE_REQUEST_TIMEOUT);
		let events = srv.client.subscribe_rounds(req).await?
			.into_inner().map(|m| {
				let m = m.context("received error on event stream")?;
				let e = RoundEvent::try_from(m.clone())
					.with_context(|| format!("error converting rpc round event: {:?}", m))?;
				trace!("Received round event: {}", e);
				Ok::<_, anyhow::Error>(e)
			});
		Ok(events)
	}

	/// A blocking call that will try to perform a full round participation
	/// for all ongoing rounds
	///
	/// Returns only once there is no ongoing rounds anymore.
	pub async fn participate_ongoing_rounds(&self) -> anyhow::Result<()> {
		let mut events = self.subscribe_round_events().await?;

		loop {
			// NB: we need to load all ongoing rounds on every iteration here
			// because some might be finished by another call
			let state_ids = self.pending_round_states().await?.iter()
				.filter(|s| s.state().ongoing_participation())
				.map(|s| s.id())
				.collect::<Vec<_>>();

			if state_ids.is_empty() {
				info!("All rounds handled");
				return Ok(());
			}

			let event = events.next().await
				.context("events stream broke")?
				.context("error on event stream")?;

			let futs = state_ids.into_iter().map(async |state| {
				let locked = self.lock_wait_round_state(state).await?;
				if let Some(mut locked) = locked {
					self.inner_process_event(&mut locked, Some(&event)).await;
				}
				Ok::<_, anyhow::Error>(())
			});

			futures::future::join_all(futs).await;
		}
	}

	/// Will cancel all pending rounds that can safely be canceled
	///
	/// All rounds that have not started yet can safely be canceled,
	/// as well as rounds where we have not yet signed any forfeit txs.
	pub async fn cancel_all_pending_rounds(&self) -> anyhow::Result<()> {
		// initial load to get all pending round states ids
		let state_ids = self.inner.db.get_pending_round_state_ids().await?;

		let futures = state_ids.into_iter().map(|state_id| {
			async move {
				// wait for lock and load again to ensure most recent state
				let mut state = match self.lock_wait_round_state(state_id).await {
					Ok(Some(s)) => s,
					Ok(None) => return,
					Err(e) => return warn!("Error loading round state #{}: {:#}", state_id, e),
				};

				match state.state_mut().try_cancel(self).await {
					Ok(true) => {
						if let Err(e) = self.inner.db.remove_round_state(&state).await {
							warn!("Error removing canceled round state from db: {:#}", e);
						}
					},
					Ok(false) => {},
					Err(e) => warn!("Error trying to cancel round #{}: {:#}", state_id, e),
				}
			}
		});

		join_all(futures).await;

		Ok(())
	}

	/// Try to cancel the given round
	pub async fn cancel_pending_round(&self, id: RoundStateId) -> anyhow::Result<()> {
		let mut state = self.lock_wait_round_state(id).await?
			.context("round state not found")?;

		if state.state_mut().try_cancel(self).await.context("failed to cancel round")? {
			self.inner.db.remove_round_state(&state).await
				.context("error removing canceled round state from db")?;
		} else {
			bail!("failed to cancel round");
		}

		Ok(())
	}

	/// Participate in a round
	///
	/// This function will start a new round participation and block until
	/// the round is finished.
	/// After this method returns the round state will be kept active until
	/// the round tx fully confirms.
	pub(crate) async fn participate_round(
		&self,
		participation: RoundParticipation,
		movement_kind: Option<RoundMovement>,
	) -> anyhow::Result<RoundStatus> {
		let state = self.join_next_round(participation, movement_kind).await?;

		info!("Waiting for a round start...");
		let mut events = self.subscribe_round_events().await?;

		self.drive_round_state(state, &mut events).await
	}

	/// Drive an already-joined round state to its final [RoundStatus], blocking
	/// on `events` and persisting each update.
	///
	/// Shared by [Wallet::participate_round] and the blocking maintenance
	/// refresh: the latter submits its participation up-front (against an
	/// in-flight attempt) and then drives the resulting round to completion
	/// here.
	pub(crate) async fn drive_round_state<S>(
		&self,
		mut state: StoredRoundState,
		events: &mut S,
	) -> anyhow::Result<RoundStatus>
	where
		S: Stream<Item = anyhow::Result<RoundEvent>> + Unpin,
	{
		loop {
			if !state.state().ongoing_participation() {
				let status = state.sync(self).await?;
				match status {
					RoundStatus::Failed { error } => bail!("round failed: {}", error),
					RoundStatus::Canceled => bail!("round canceled"),
					RoundStatus::Pending => continue,
					status => return Ok(status),
				}
			}

			let event = events.next().await
				.context("events stream broke")?
				.context("error on event stream")?;
			if state.state_mut().process_event(self, &event).await {
				self.inner.db.update_round_state(&state).await?;
			}
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::secp256k1::Secp256k1;

	use ark::VtxoPolicy;
	use ark::tree::signed::{CachedSignedVtxoTree, HashlockVersion, UnlockPreimage, VtxoLeafSpec};

	fn pubkey() -> bitcoin::secp256k1::PublicKey {
		let secp = Secp256k1::new();
		Keypair::new(&secp, &mut rand::thread_rng()).public_key()
	}

	fn nonces() -> Vec<Vec<SecretNonce>> {
		let secp = Secp256k1::new();
		let key = Keypair::new(&secp, &mut rand::thread_rng());
		// Shape mirrors what start_attempt produces: outer Vec is one
		// entry per cosign keypair, inner Vec is the tree-depth set of
		// pre-generated nonces.
		vec![vec![musig::nonce_pair(&key).0, musig::nonce_pair(&key).0]]
	}

	fn round_request(amount: u64, policy: &VtxoPolicy) -> VtxoRequest {
		VtxoRequest { amount: Amount::from_sat(amount), policy: policy.clone() }
	}

	/// A recovered participation built from forged server data — outputs
	/// exceeding inputs, or totals past the money supply — must fail the
	/// pre-store fee guard instead of being adopted as a zero-fee round.
	#[test]
	fn recovered_participation_totals_are_supply_checked() {
		let sane_in = Amount::from_sat(100_000);
		// Fees within the 5% bound pass, the boundary included.
		assert_eq!(
			sane_recovered_participation_fee(sane_in, Amount::from_sat(96_000)).unwrap(),
			Amount::from_sat(4_000),
		);
		sane_recovered_participation_fee(sane_in, Amount::from_sat(95_000)).unwrap();
		// A single sat over the fee bound is refused.
		sane_recovered_participation_fee(sane_in, Amount::from_sat(94_999)).unwrap_err();
		// Outputs exceeding the inputs are an error, not a free round.
		sane_recovered_participation_fee(sane_in, sane_in + Amount::ONE_SAT).unwrap_err();
		// Totals past the money supply are necessarily forged.
		sane_recovered_participation_fee(
			Amount::MAX_MONEY + Amount::ONE_SAT, Amount::ZERO,
		).unwrap_err();
		sane_recovered_participation_fee(
			Amount::MAX_MONEY, Amount::MAX_MONEY,
		).unwrap();
		sane_recovered_participation_fee(
			Amount::MAX_MONEY, Amount::MAX_MONEY + Amount::ONE_SAT,
		).unwrap_err();
	}

	/// Pending-round balances over recovered (server-rebuilt) participations
	/// with forged maximum-value outputs error instead of panicking.
	#[test]
	fn pending_round_balance_over_forged_recovered_states_errors() {
		let preimage: UnlockPreimage = rand::random();
		let state_with = |outputs: Vec<VtxoRequest>| RoundState::new_delegated(
			RoundParticipation {
				inputs: vec![],
				outputs,
				unblinded_mailbox_id: None,
			},
			UnlockHash::hash(&preimage), None, None,
		);
		let huge = || VtxoRequest {
			amount: Amount::MAX_MONEY,
			policy: VtxoPolicy::new_pubkey(pubkey()),
		};

		// One maximum-value round is still reportable.
		let a = state_with(vec![huge()]);
		assert_eq!(sum_pending_round_balances([&a]).unwrap(), Amount::MAX_MONEY);

		// Two exceed the money supply: error, not a panicking `+=`.
		let b = state_with(vec![huge()]);
		sum_pending_round_balances([&a, &b]).unwrap_err();

		// Outputs that overflow entirely surface as an error too.
		let c = state_with(vec![
			VtxoRequest { amount: Amount::MAX, policy: VtxoPolicy::new_pubkey(pubkey()) },
			VtxoRequest { amount: Amount::MAX, policy: VtxoPolicy::new_pubkey(pubkey()) },
		]);
		assert!(c.pending_balance().is_none());
		sum_pending_round_balances([&c]).unwrap_err();

		// Failed and canceled rounds contribute nothing, forged or not.
		let mut d = state_with(vec![huge()]);
		d.flow = RoundFlowState::Canceled;
		assert_eq!(sum_pending_round_balances([&d]).unwrap(), Amount::ZERO);
	}

	fn round_participation_fixture(
		version: HashlockVersion,
		outputs: Vec<VtxoRequest>,
	) -> (RoundParticipation, Vec<Vtxo<Full>>, Transaction, ArkInfo, UnlockHash) {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let user_cosign_key = Keypair::new(&secp, &mut rng);
		let server_key = Keypair::new(&secp, &mut rng);
		let server_cosign_key = Keypair::new(&secp, &mut rng);
		let preimage: UnlockPreimage = rand::random();
		let unlock_hash = UnlockHash::hash(&preimage);
		let (tree, funding_tx) = ark::test_util::build_signed_tree(
			version, outputs.iter().cloned(),
			&user_cosign_key, &server_key, &server_cosign_key, unlock_hash,
		);
		let vtxos = tree.into_cached_tree().output_vtxos().collect::<Vec<_>>();
		let part = RoundParticipation {
			// This check only uses the input expiry and exit delta.
			inputs: vec![vtxos[0].clone()],
			outputs,
			unblinded_mailbox_id: None,
		};
		#[allow(deprecated)]
		let ark_info = ArkInfo {
			network: bitcoin::Network::Regtest,
			server_pubkey: server_key.public_key(),
			mailbox_pubkey: server_key.public_key(),
			round_interval: Duration::from_secs(60),
			nb_round_nonces: 8,
			vtxo_exit_delta: vtxos[0].exit_delta(),
			vtxo_lifetime: BlockDelta::new(1000),
			htlc_send_expiry_delta: BlockDelta::new(100),
			htlc_expiry_delta: BlockDelta::new(100),
			max_vtxo_amount: None,
			required_board_confirmations: 6,
			max_user_invoice_cltv_delta: BlockDelta::new(100),
			min_board_amount: Amount::from_sat(1000),
			vtxo_expiry_delta: BlockDelta::new(1000),
			offboard_feerate: bitcoin::FeeRate::ZERO,
			max_offboard_inputs: 1,
			ln_receive_anti_dos_required: false,
			fees: Default::default(),
			max_vtxo_exit_depth: 10,
			tos_link: None,
		};
		(part, vtxos, funding_tx, ark_info, unlock_hash)
	}

	#[test]
	fn round_matches_reordered_amounts_and_policies() {
		let a = VtxoPolicy::new_pubkey(pubkey());
		let b = VtxoPolicy::new_pubkey(pubkey());
		let outputs = vec![
			round_request(10_000, &a), round_request(20_000, &b),
			round_request(20_000, &a), round_request(10_000, &b),
		];
		for version in [HashlockVersion::V0, HashlockVersion::V1] {
			let (part, mut vtxos, funding_tx, ark_info, unlock_hash) =
				round_participation_fixture(version, outputs.clone());
			vtxos.rotate_left(1);
			let saved_part = serde_json::to_vec(&part).unwrap();
			let saved_vtxos = vtxos.iter().map(|v| v.serialize()).collect::<Vec<_>>();
			check_round_matches_participation(
				&part, &vtxos, &funding_tx, &ark_info, None,
				BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
			).expect("valid leaves may arrive in any order");
			assert_eq!(serde_json::to_vec(&part).unwrap(), saved_part);
			assert_eq!(vtxos.iter().map(|v| v.serialize()).collect::<Vec<_>>(), saved_vtxos);
		}
	}

	#[test]
	fn round_matches_identical_requests_only_with_distinct_leaves() {
		let a = VtxoPolicy::new_pubkey(pubkey());
		let b = VtxoPolicy::new_pubkey(pubkey());
		let (part, mut vtxos, funding_tx, ark_info, unlock_hash) = round_participation_fixture(
			HashlockVersion::V1, vec![
				round_request(10_000, &a), round_request(10_000, &a),
				round_request(20_000, &b),
			],
		);
		vtxos.reverse();
		assert_ne!(vtxos[1].id(), vtxos[2].id());
		check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).expect("identical requests must accept distinct leaves");

		vtxos[2] = vtxos[1].clone();
		let err = check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).unwrap_err();
		assert!(err.to_string().contains("duplicate VTXO"), "{err:#}");
	}

	#[test]
	fn round_matches_rejects_substituted_output_multisets() {
		let a = VtxoPolicy::new_pubkey(pubkey());
		let b = VtxoPolicy::new_pubkey(pubkey());
		let (mut part, vtxos, funding_tx, ark_info, unlock_hash) = round_participation_fixture(
			HashlockVersion::V1, vec![
				round_request(10_000, &a), round_request(20_000, &b),
				round_request(10_000, &a),
			],
		);
		let total = part.total_out().unwrap();
		for (case, outputs) in [
			("substituted amounts", vec![
				round_request(15_000, &a), round_request(15_000, &b), round_request(10_000, &a),
			]),
			("substituted policy", vec![
				round_request(10_000, &a), round_request(20_000, &a), round_request(10_000, &a),
			]),
			("wrong multiplicity", vec![
				round_request(10_000, &a), round_request(20_000, &b), round_request(10_000, &b),
			]),
			("wrong amount-policy pairs", vec![
				round_request(20_000, &a), round_request(10_000, &b), round_request(10_000, &a),
			]),
		] {
			part.outputs = outputs;
			assert_eq!(part.total_out().unwrap(), total, "{case}");
			assert_eq!(part.outputs.len(), vtxos.len(), "{case}");
			let err = check_round_matches_participation(
				&part, &vtxos, &funding_tx, &ark_info, None,
				BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
			).expect_err(case);
			assert!(err.to_string().contains("unexpected VTXO amount or policy"), "{case}: {err:#}");
		}
	}

	#[test]
	fn round_matches_rejects_missing_or_extra_outputs() {
		let policy = VtxoPolicy::new_pubkey(pubkey());
		let (part, mut vtxos, funding_tx, ark_info, unlock_hash) = round_participation_fixture(
			HashlockVersion::V1, vec![round_request(10_000, &policy); 2],
		);
		let missing = check_round_matches_participation(
			&part, &vtxos[..1], &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).unwrap_err();
		assert!(missing.to_string().contains("unexpected number of VTXOs"), "{missing:#}");
		vtxos.push(vtxos[0].clone());
		let extra = check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).unwrap_err();
		assert!(extra.to_string().contains("unexpected number of VTXOs"), "{extra:#}");
	}

	#[test]
	fn round_matches_reordered_outputs_still_checks_tree_parameters() {
		let policy = VtxoPolicy::new_pubkey(pubkey());
		let (part, mut vtxos, funding_tx, ark_info, unlock_hash) = round_participation_fixture(
			HashlockVersion::V1, vec![
				round_request(10_000, &policy), round_request(20_000, &policy),
			],
		);
		vtxos.reverse();
		check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).unwrap();
		let mut wrong_server = ark_info.clone();
		wrong_server.server_pubkey = pubkey();
		let mut wrong_delta = ark_info.clone();
		wrong_delta.vtxo_exit_delta = ark_info.vtxo_exit_delta + BlockDelta::new(1);
		for info in [&wrong_server, &wrong_delta] {
			assert!(check_round_matches_participation(
				&part, &vtxos, &funding_tx, info, None,
				BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
			).is_err());
		}
		assert!(check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, Some(BlockHeight::new(101_000)),
			BlockHeight::new(100_000), BlockDelta::new(12), unlock_hash,
		).is_err(), "outputs must outlive the scheduled height");
		assert!(check_round_matches_participation(
			&part, &vtxos, &funding_tx, &ark_info, None,
			BlockHeight::new(100_953), BlockDelta::new(12), unlock_hash,
		).is_err(), "unexpired inputs require exitable outputs");
	}

	#[test]
	fn accepts_hash_locked_leaves_of_both_versions() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let user_key = Keypair::new(&secp, &mut rng);
		let user_cosign_key = Keypair::new(&secp, &mut rng);
		let server_key = Keypair::new(&secp, &mut rng);
		let server_cosign_key = Keypair::new(&secp, &mut rng);

		let preimage: UnlockPreimage = rand::random();
		let unlock_hash = UnlockHash::hash(&preimage);

		let outputs = (0..2u64).map(|i| VtxoRequest {
			amount: Amount::from_sat(10_000 + i),
			policy: VtxoPolicy::new_pubkey(user_key.public_key()),
		}).collect::<Vec<_>>();

		// Delegated participations from rounds that predate the v1 hashlock
		// clauses have leaves with the v0 policy and genesis transition, so
		// the check must accept the still-locked leaves of both versions.
		for version in [HashlockVersion::V0, HashlockVersion::V1] {
			let (tree, funding_tx) = ark::test_util::build_signed_tree(
				version, outputs.iter().cloned(),
				&user_cosign_key, &server_key, &server_cosign_key, unlock_hash,
			);
			for vtxo in tree.into_cached_tree().output_vtxos() {
				check_vtxo_fails_hash_lock(&funding_tx, &vtxo).unwrap_or_else(|e| panic!(
					"locked {:?} leaf vtxo should be accepted: {:#}", version, e,
				));
			}
		}
	}

	#[test]
	fn rejects_locked_round_vtxo_with_tampered_point() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let user_key = Keypair::new(&secp, &mut rng);
		let user_cosign_key = Keypair::new(&secp, &mut rng);
		let server_key = Keypair::new(&secp, &mut rng);
		let server_cosign_key = Keypair::new(&secp, &mut rng);
		let preimage: UnlockPreimage = rand::random();
		let unlock_hash = UnlockHash::hash(&preimage);
		let outputs = (0..2u64).map(|i| VtxoRequest {
			amount: Amount::from_sat(10_000 + i),
			policy: VtxoPolicy::new_pubkey(user_key.public_key()),
		}).collect::<Vec<_>>();

		let (tree, funding_tx) = ark::test_util::build_signed_tree(
			HashlockVersion::V1, outputs,
			&user_cosign_key, &server_key, &server_cosign_key, unlock_hash,
		);
		let vtxo = tree.into_cached_tree().output_vtxos().next().unwrap();

		// Bump the point's vout (last 4 bytes of the encoding) without touching
		// the genesis, so the leaf still validates up to the terminal transition.
		let mut encoded = vtxo.serialize();
		let vout_offset = encoded.len() - 4;
		encoded[vout_offset] = 1;
		let tampered = Vtxo::<Full>::deserialize(&encoded).unwrap();

		assert!(tampered.validate_unsigned(&funding_tx).is_err());
		assert!(check_vtxo_fails_hash_lock(&funding_tx, &tampered).is_err(),
			"tampered point must be rejected before forfeits are sent");
	}

	#[test]
	fn refuses_vtxos_without_room_for_unilateral_exit() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let user_key = Keypair::new(&secp, &mut rng);
		let user_cosign_key = Keypair::new(&secp, &mut rng);
		let server_key = Keypair::new(&secp, &mut rng);
		let server_cosign_key = Keypair::new(&secp, &mut rng);

		let preimage: UnlockPreimage = rand::random();
		let unlock_hash = UnlockHash::hash(&preimage);

		let outputs = (0..2u64).map(|i| VtxoRequest {
			amount: Amount::from_sat(10_000 + i),
			policy: VtxoPolicy::new_pubkey(user_key.public_key()),
		}).collect::<Vec<_>>();

		let (tree, _funding_tx) = ark::test_util::build_signed_tree(
			HashlockVersion::V1, outputs,
			&user_cosign_key, &server_key, &server_cosign_key, unlock_hash,
		);
		let vtxos = tree.into_cached_tree().output_vtxos().collect::<Vec<_>>();

		// The tree expires at height 101_000, so with an exit margin of 12
		// (counted twice, for the old and the new exit) plus the input exit
		// delta of 6, the last acceptable tip is 100_970.
		check_output_vtxos_exitable(&vtxos, BlockHeight::new(100_970), BlockDelta::new(12), BlockDelta::new(6))
			.expect("vtxos with room for a unilateral exit should be accepted");
		assert!(check_output_vtxos_exitable(&vtxos, BlockHeight::new(100_971), BlockDelta::new(12), BlockDelta::new(6)).is_err(),
			"vtxos without room for a unilateral exit must be rejected");
	}

	/// A server-built round tree whose forged leaf (identical VtxoRequest,
	/// foreign unlock hash H_B, first in server-chosen spec order) precedes
	/// the genuine leaf locked under the participation unlock hash H_A.
	#[allow(clippy::type_complexity)]
	fn mismatched_unlock_hash_fixture() -> (
		RoundParticipation, VtxoTreeSpec, Transaction, Vec<schnorr::Signature>,
		CachedSignedVtxoTree, UnlockPreimage, UnlockHash, UnlockHash, ArkInfo,
	) {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let user_key = Keypair::new(&secp, &mut rng);
		let server_key = Keypair::new(&secp, &mut rng);
		let server_cosign_key = Keypair::new(&secp, &mut rng);
		let user_cosign_key = Keypair::new(&secp, &mut rng);

		let preimage_a: UnlockPreimage = rand::random();
		let hash_a = UnlockHash::hash(&preimage_a);
		let preimage_b: UnlockPreimage = rand::random();
		let hash_b = UnlockHash::hash(&preimage_b);
		assert_ne!(hash_a, hash_b);

		let req = round_request(10_000, &VtxoPolicy::new_pubkey(user_key.public_key()));
		let spec = VtxoTreeSpec::new(
			vec![
				// forged leaf: identical request, foreign unlock hash, first
				// in server-chosen spec order
				VtxoLeafSpec { vtxo: req.clone(), cosign_pubkey: None, unlock_hash: hash_b },
				// genuine leaf under the participation's unlock hash
				VtxoLeafSpec { vtxo: req.clone(), cosign_pubkey: None, unlock_hash: hash_a },
			],
			server_key.public_key(),
			BlockHeight::new(101_000),
			BlockDelta::new(24),
			vec![user_cosign_key.public_key(), server_cosign_key.public_key()],
		);

		let funding_tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![spec.funding_tx_txout()],
		};
		let utxo = OutPoint::new(funding_tx.compute_txid(), ROUND_TX_VTXO_TREE_VOUT);
		let unsigned = spec.clone().into_unsigned_tree(utxo);

		let nonces = |key: &Keypair| -> (Vec<SecretNonce>, Vec<PublicNonce>) {
			unsigned.internal_sighashes.iter()
				.map(|sh| musig::nonce_pair_with_msg(key, &sh.to_byte_array()))
				.unzip()
		};
		let (user_secs, user_pubs) = nonces(&user_cosign_key);
		let (server_secs, server_pubs) = nonces(&server_cosign_key);
		let agg_nonces = user_pubs.iter().zip(&server_pubs)
			.map(|(u, s)| musig::AggregatedNonce::new(&[u, s]))
			.collect::<Vec<_>>();
		let user_sigs = unsigned.cosign_tree(&agg_nonces, &user_cosign_key, user_secs);
		let server_sigs = unsigned.cosign_tree(&agg_nonces, &server_cosign_key, server_secs);
		let sigs = unsigned.combine_partial_signatures(
			&agg_nonces, &HashMap::new(), &[&user_sigs, &server_sigs],
		).expect("valid partial signatures");
		let cached = unsigned.into_signed_tree(sigs.clone()).into_cached_tree();

		// The genuine leaf serves as a placeholder participation input; only
		// its exit_delta/expiry are read by the checks.
		let part = RoundParticipation {
			inputs: vec![cached.build_vtxo(1)],
			outputs: vec![req],
			unblinded_mailbox_id: None,
		};
		#[allow(deprecated)]
		let ark_info = ArkInfo {
			network: bitcoin::Network::Regtest,
			server_pubkey: server_key.public_key(),
			mailbox_pubkey: server_key.public_key(),
			round_interval: Duration::from_secs(60),
			nb_round_nonces: 8,
			vtxo_exit_delta: BlockDelta::new(24),
			vtxo_lifetime: BlockDelta::new(1000),
			htlc_send_expiry_delta: BlockDelta::new(100),
			htlc_expiry_delta: BlockDelta::new(100),
			max_vtxo_amount: None,
			required_board_confirmations: 6,
			max_user_invoice_cltv_delta: BlockDelta::new(100),
			min_board_amount: Amount::from_sat(1000),
			vtxo_expiry_delta: BlockDelta::new(1000),
			offboard_feerate: bitcoin::FeeRate::ZERO,
			max_offboard_inputs: 1,
			ln_receive_anti_dos_required: false,
			fees: Default::default(),
			max_vtxo_exit_depth: 10,
			tos_link: None,
		};
		(part, spec, funding_tx, sigs, cached, preimage_a, hash_a, hash_b, ark_info)
	}

	/// Delegated acceptance must reject a replacement VTXO locked under a
	/// foreign unlock hash: the server earns the forfeit claim by revealing
	/// only the preimage of the participation hash H_A, which cannot unlock
	/// an H_B-locked leaf.
	#[test]
	fn delegated_acceptance_rejects_foreign_unlock_hash() {
		let (part, _spec, funding_tx, _sigs, cached, preimage_a, hash_a, hash_b, ark_info) =
			mismatched_unlock_hash_fixture();
		let forged = cached.build_vtxo(0);
		assert_eq!(forged.unlock_hash(), Some(hash_b),
			"forged leaf carries the server's foreign unlock hash");

		let err = check_round_matches_participation(
			&part, &[forged.clone()], &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), hash_a,
		).expect_err("a leaf locked under a foreign unlock hash must be rejected");
		assert!(err.to_string().contains("foreign unlock hash"), "{err:#}");

		let mut accepted = forged;
		assert!(!accepted.provide_unlock_preimage(preimage_a),
			"preimage of the participation unlock hash {hash_a} cannot unlock the \
			foreign-hash output {hash_b}");
	}

	/// Control: the same acceptance check passes for the genuine leaf locked
	/// under the participation unlock hash.
	#[test]
	fn delegated_acceptance_accepts_matching_unlock_hash() {
		let (part, _spec, funding_tx, _sigs, cached, preimage_a, hash_a, _hash_b, ark_info) =
			mismatched_unlock_hash_fixture();
		let mut genuine = cached.build_vtxo(1);
		assert_eq!(genuine.unlock_hash(), Some(hash_a));

		check_round_matches_participation(
			&part, std::slice::from_ref(&genuine), &funding_tx, &ark_info, None,
			BlockHeight::new(100_000), BlockDelta::new(12), hash_a,
		).expect("the genuine leaf must be accepted");
		assert!(genuine.provide_unlock_preimage(preimage_a),
			"preimage of the participation unlock hash unlocks the accepted output");
	}

	/// Interactive construction must skip a request-matching duplicate leaf
	/// locked under a foreign hash, even when the server orders it before
	/// the genuine leaf, and select the genuine H_A leaf instead.
	#[tokio::test]
	async fn interactive_construction_skips_foreign_hash_leaf() {
		let (part, spec, funding_tx, sigs, _cached, preimage_a, hash_a, _hash_b, _ark_info) =
			mismatched_unlock_hash_fixture();

		let vtxos = construct_new_vtxos(&part, &funding_tx, &spec, &sigs, hash_a)
			.await.expect("a tree containing the genuine leaf passes acceptance");
		assert_eq!(vtxos.len(), 1);
		assert_eq!(vtxos[0].unlock_hash(), Some(hash_a),
			"the foreign-hash duplicate leaf must not be selected");

		let mut accepted = vtxos.into_iter().next().unwrap();
		assert!(accepted.provide_unlock_preimage(preimage_a),
			"preimage of the participation unlock hash unlocks the constructed output");
	}

	#[test]
	fn stash_and_take() {
		let store = RoundSecretNonces::new();
		let k = pubkey();
		store.stash(k, nonces());

		assert!(store.take(&k).is_some());
	}

	#[test]
	fn cannot_take_twice() {
		let store = RoundSecretNonces::new();
		let k = pubkey();
		store.stash(k, nonces());

		assert!(store.take(&k).is_some());
		assert!(store.take(&k).is_none());
	}

	#[test]
	fn cannot_take_after_forget() {
		let store = RoundSecretNonces::new();
		let k = pubkey();
		store.stash(k, nonces());
		store.forget(&k);

		assert!(store.take(&k).is_none());
	}

	#[test]
	fn stash_overrides_stash() {
		let secp = Secp256k1::new();
		let key = Keypair::new(&secp, &mut rand::thread_rng());
		let nonces_1 = vec![vec![musig::nonce_pair(&key).0]];
		let nonces_2 = vec![];

		let store = RoundSecretNonces::new();
		store.stash(key.public_key(), nonces_1);
		store.stash(key.public_key(), nonces_2);

		let taken = store.take(&key.public_key()).expect("nonces present");
		assert_eq!(taken.len(), 0);
	}
}
