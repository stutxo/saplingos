//! Wallet action infrastructure.
//!
//! A *wallet action* is a multi-step operation that moves vtxos (e.g. a
//! lightning send). Each step is small, persists its outcome to a
//! checkpoint, and is safe to re-drive after a crash.
//!
//! This module defines the generic vocabulary; per-kind machinery (state
//! machines, transition functions) lives in submodules.
//!
//! Manual cancellation holds the same per-action lock as the driver and reads
//! the durable checkpoint again. A saved signature, forfeit share or preimage
//! disclosure is not an undo point. Such actions must finish or transfer their
//! recovery to durable state before the executor removes the checkpoint.

pub mod arkoor_send;
pub mod board;
pub mod lightning;
pub mod offboard;

use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, SignedAmount};
use log::{debug, trace, warn};
use server_rpc::StatusExt;

use ark::VtxoId;

use crate::Wallet;
use crate::actions::arkoor_send::ArkoorSend;
use crate::actions::board::Board;
use crate::actions::lightning::pay::LightningSend;
use crate::actions::lightning::receive::LightningReceive;
use crate::actions::offboard::Offboard;
use crate::lock_manager::{LockGuard, LockManager};
use crate::movement::MovementStatus;
use crate::movement::update::MovementUpdate;
use crate::persist::BarkPersister;
use crate::subsystem::{ArkoorMovement, LightningReceiveMovement, OffboardMovement, Subsystem};
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind, VtxoValidationError};

pub(crate) const BASE_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Tagged union of every kind of checkpoint the wallet persists.
///
/// Used as the serialization boundary for the
/// `bark_wallet_action_checkpoint` table; per-kind logic lives on each
/// variant's payload type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletActionCheckpoint {
	LightningSend(LightningSend),
	LightningReceive(LightningReceive),
	ArkoorSend(ArkoorSend),
	Board(Board),
	Offboard(Offboard),
}

impl WalletActionCheckpoint {
	pub fn id(&self) -> WalletActionId {
		match self {
			WalletActionCheckpoint::LightningSend(s) => s.id(),
			WalletActionCheckpoint::LightningReceive(r) => r.id(),
			WalletActionCheckpoint::ArkoorSend(s) => s.id(),
			WalletActionCheckpoint::Board(s) => s.id(),
			WalletActionCheckpoint::Offboard(o) => o.id(),
		}
	}

	pub fn as_lightning_send(&self) -> Option<&LightningSend> {
		match self {
			WalletActionCheckpoint::LightningSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_lightning_send(self) -> Option<LightningSend> {
		match self {
			WalletActionCheckpoint::LightningSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_lightning_receive(&self) -> Option<&LightningReceive> {
		match self {
			WalletActionCheckpoint::LightningReceive(r) => Some(r),
			_ => None,
		}
	}

	pub fn into_lightning_receive(self) -> Option<LightningReceive> {
		match self {
			WalletActionCheckpoint::LightningReceive(r) => Some(r),
			_ => None,
		}
	}

	pub fn as_arkoor_send(&self) -> Option<&ArkoorSend> {
		match self {
			WalletActionCheckpoint::ArkoorSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_arkoor_send(self) -> Option<ArkoorSend> {
		match self {
			WalletActionCheckpoint::ArkoorSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_board(&self) -> Option<&Board> {
		match self {
			WalletActionCheckpoint::Board(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_board(self) -> Option<Board> {
		match self {
			WalletActionCheckpoint::Board(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_offboard(&self) -> Option<&Offboard> {
		match self {
			WalletActionCheckpoint::Offboard(o) => Some(o),
			_ => None,
		}
	}

	pub fn into_offboard(self) -> Option<Offboard> {
		match self {
			WalletActionCheckpoint::Offboard(o) => Some(o),
			_ => None,
		}
	}

	/// Inputs and saved successor bytes used to coordinate offline recovery.
	/// Include every stage: a signed checkpoint can precede inventory updates.
	pub(crate) fn recovery_positions(&self) -> (Vec<VtxoId>, Vec<&ark::Vtxo<ark::vtxo::Full>>) {
		let mut ids = Vec::new();
		let mut outputs = Vec::new();
		match self {
			Self::ArkoorSend(send) => {
				ids.extend_from_slice(&send.input_vtxo_ids);
				match &send.progress {
					arkoor_send::Progress::Cosigning => {},
					arkoor_send::Progress::Registration { signed_destination_vtxos, signed_change_vtxos, .. }
					| arkoor_send::Progress::Delivery { signed_destination_vtxos, signed_change_vtxos, .. } => {
						outputs.extend(signed_destination_vtxos);
						outputs.extend(signed_change_vtxos);
					},
					arkoor_send::Progress::Finalizing { signed_change_vtxos, .. } =>
						outputs.extend(signed_change_vtxos),
				}
			},
			Self::LightningSend(send) => {
				ids.extend_from_slice(&send.input_vtxo_ids);
				match &send.progress {
					lightning::pay::Progress::Start => {},
					lightning::pay::Progress::HtlcReceived(htlcs)
					| lightning::pay::Progress::PaymentInitiated(htlcs) => {
						ids.extend_from_slice(&htlcs.vtxo_ids);
						outputs.extend(&htlcs.vtxos);
					},
					lightning::pay::Progress::RevocableHtlcs { htlcs, revocation }
					| lightning::pay::Progress::RevocationStuck { htlcs, revocation } => {
						ids.extend_from_slice(&htlcs.vtxo_ids);
						outputs.extend(&htlcs.vtxos);
						outputs.extend(&revocation.vtxos);
					},
				}
			},
			Self::LightningReceive(recv) => match &recv.progress {
				lightning::receive::Progress::AwaitingPayment => {},
				lightning::receive::Progress::HtlcsReady(htlcs)
				| lightning::receive::Progress::PreimageRevealed(htlcs) =>
					ids.extend_from_slice(&htlcs.vtxo_ids),
				lightning::receive::Progress::Delivering(delivery) => {
					ids.extend_from_slice(&delivery.input_vtxo_ids);
					outputs.extend(&delivery.vtxos);
				},
			},
			Self::Board(board) => {
				ids.push(board.vtxo_id);
				match &board.progress {
					board::Progress::PreparingFunding { signed_vtxo, .. }
					| board::Progress::Broadcasting { signed_vtxo } => outputs.push(signed_vtxo),
					board::Progress::Confirming { .. } => {},
				}
			},
			Self::Offboard(offboard) => {
				match &offboard.kind {
					offboard::OffboardKind::OffboardWhole { input_vtxo_ids }
					| offboard::OffboardKind::SendOnchain { input_vtxo_ids, .. } =>
						ids.extend_from_slice(input_vtxo_ids),
				}
				match &offboard.progress {
					offboard::Progress::Start | offboard::Progress::SplitWithArkoor => {},
					offboard::Progress::ArkoorCreated { created, change } => {
						outputs.extend(created);
						outputs.extend(change);
					},
					offboard::Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids } => {
						ids.extend_from_slice(offboard_vtxo_ids);
						ids.extend_from_slice(change_vtxo_ids);
					},
					offboard::Progress::ReadyForOffboard { offboard_vtxo_ids, .. }
					| offboard::Progress::OffboardTxPrepared { offboard_vtxo_ids, .. }
					| offboard::Progress::ForfeitsPrepared { offboard_vtxo_ids, .. }
					| offboard::Progress::ReadyForBroadcast { offboard_vtxo_ids, .. }
					| offboard::Progress::AwaitingConfirmations { offboard_vtxo_ids, .. } =>
						ids.extend_from_slice(offboard_vtxo_ids),
				}
			},
		}
		ids.extend(outputs.iter().map(|v| v.id()));
		(ids, outputs)
	}

	pub(crate) fn recovery_movement_id(&self) -> Option<crate::movement::MovementId> {
		match self {
			Self::ArkoorSend(send) => match &send.progress {
				arkoor_send::Progress::Cosigning => None,
				arkoor_send::Progress::Registration { movement_id, .. }
				| arkoor_send::Progress::Delivery { movement_id, .. }
				| arkoor_send::Progress::Finalizing { movement_id, .. } => Some(*movement_id),
			},
			Self::LightningSend(send) => match &send.progress {
				lightning::pay::Progress::Start => send.movement_id,
				lightning::pay::Progress::HtlcReceived(htlcs)
				| lightning::pay::Progress::PaymentInitiated(htlcs)
				| lightning::pay::Progress::RevocableHtlcs { htlcs, .. }
				| lightning::pay::Progress::RevocationStuck { htlcs, .. } => Some(htlcs.movement_id),
			},
			Self::LightningReceive(recv) => match &recv.progress {
				lightning::receive::Progress::AwaitingPayment => None,
				lightning::receive::Progress::HtlcsReady(htlcs)
				| lightning::receive::Progress::PreimageRevealed(htlcs) => Some(htlcs.movement_id),
				lightning::receive::Progress::Delivering(delivery) => Some(delivery.movement_id),
			},
			Self::Board(board) => Some(board.movement_id),
			Self::Offboard(offboard) => match &offboard.progress {
				offboard::Progress::OffboardTxPrepared { movement_id, .. }
				| offboard::Progress::ForfeitsPrepared { movement_id, .. }
				| offboard::Progress::ReadyForBroadcast { movement_id, .. }
				| offboard::Progress::AwaitingConfirmations { movement_id, .. } => Some(*movement_id),
				_ => None,
			},
		}
	}

	/// A finalizing payment may already have discarded externally delivered
	/// output bytes. Its stage still proves the original inputs were transferred.
	pub(crate) fn recovery_consumed_inputs(&self) -> &[VtxoId] {
		match self {
			Self::ArkoorSend(send) if !matches!(send.progress, arkoor_send::Progress::Cosigning) =>
				&send.input_vtxo_ids,
			Self::LightningSend(send) if !matches!(send.progress, lightning::pay::Progress::Start) =>
				&send.input_vtxo_ids,
			Self::LightningReceive(recv) => match &recv.progress {
				lightning::receive::Progress::Delivering(delivery) => &delivery.input_vtxo_ids,
				_ => &[],
			},
			Self::Offboard(offboard) if !matches!(offboard.progress,
				offboard::Progress::Start | offboard::Progress::SplitWithArkoor,
			) => match &offboard.kind {
				offboard::OffboardKind::SendOnchain { input_vtxo_ids, .. } => input_vtxo_ids,
				offboard::OffboardKind::OffboardWhole { .. } => &[],
			},
			_ => &[],
		}
	}

	/// Reservations that may be released without abandoning a signed output.
	/// This is independent of key type: a native input can pay a program address.
	fn cancellable_input_ids(&self) -> anyhow::Result<&[VtxoId]> {
		match self {
			Self::ArkoorSend(send) => match &send.progress {
				arkoor_send::Progress::Cosigning => Ok(&send.input_vtxo_ids),
				arkoor_send::Progress::Registration { .. }
					| arkoor_send::Progress::Delivery { .. }
					| arkoor_send::Progress::Finalizing { .. }
				=> bail!("cannot cancel arkoor send: signed outputs must be retained"),
			},
			Self::LightningSend(send) => match &send.progress {
				lightning::pay::Progress::Start => Ok(&send.input_vtxo_ids),
				lightning::pay::Progress::HtlcReceived(_)
					| lightning::pay::Progress::PaymentInitiated(_)
					| lightning::pay::Progress::RevocableHtlcs { .. }
					| lightning::pay::Progress::RevocationStuck { .. }
				=> bail!("cannot cancel lightning send: HTLCs or signed claim outputs are committed"),
			},
			Self::LightningReceive(recv) => match &recv.progress {
				lightning::receive::Progress::AwaitingPayment => Ok(&[]),
				// Old HtlcsReady checkpoints can precede a crash after disclosure.
				// Unlocking these would also misclassify HTLCs as ordinary money.
				lightning::receive::Progress::HtlcsReady(_)
					| lightning::receive::Progress::PreimageRevealed(_)
					| lightning::receive::Progress::Delivering(_)
				=> bail!("cannot cancel lightning receive: granted HTLCs must complete or recover"),
			},
			// Even an unsigned funding proposal can be funded by another party.
			// The checkpoint may contain the only completed board and recovery link.
			Self::Board(_) => bail!("cannot cancel board: funding can still commit the signed board"),
			Self::Offboard(offboard) => match &offboard.progress {
				offboard::Progress::Start => match &offboard.kind {
					offboard::OffboardKind::OffboardWhole { input_vtxo_ids }
						| offboard::OffboardKind::SendOnchain { input_vtxo_ids, .. }
					=> Ok(input_vtxo_ids),
				},
				offboard::Progress::SplitWithArkoor => match &offboard.kind {
					offboard::OffboardKind::SendOnchain { input_vtxo_ids, .. } => Ok(input_vtxo_ids),
					offboard::OffboardKind::OffboardWhole { .. } =>
						bail!("cannot cancel offboard: inconsistent split checkpoint"),
				},
				offboard::Progress::ReadyForOffboard { offboard_vtxo_ids, prior_txid: None }
					| offboard::Progress::OffboardTxPrepared {
						offboard_vtxo_ids, forfeits_unsent: true, ..
					}
				=> Ok(offboard_vtxo_ids),
				// A missing server session or an unseen transaction does not
				// revoke a share. Legacy prepared states have no unsent proof.
				offboard::Progress::ArkoorCreated { .. }
					| offboard::Progress::ArkoorRegistrationRequired { .. }
					| offboard::Progress::ReadyForOffboard { prior_txid: Some(_), .. }
					| offboard::Progress::OffboardTxPrepared { forfeits_unsent: false, .. }
					| offboard::Progress::ForfeitsPrepared { .. }
					| offboard::Progress::ReadyForBroadcast { .. }
					| offboard::Progress::AwaitingConfirmations { .. }
				=> bail!("cannot cancel offboard: signed outputs or forfeits must be retained"),
			},
		}
	}
}

/// Acquire the driver lock before reading the checkpoint, not after inspecting
/// a caller's possibly stale snapshot. Keep the guard through all cleanup.
async fn lock_cancellable_checkpoint(
	db: &dyn BarkPersister,
	lock_manager: &dyn LockManager,
	action_id: &WalletActionId,
) -> anyhow::Result<(WalletActionCheckpoint, Box<dyn LockGuard>)> {
	let guard = lock_manager.try_lock(action_id).await
		.context("cannot cancel wallet action: action is already in progress")?;
	let checkpoint = cancellable_checkpoint(db, action_id, guard.as_ref()).await?;
	Ok((checkpoint, guard))
}

async fn cancellable_checkpoint(
	db: &dyn BarkPersister,
	action_id: &WalletActionId,
	_guard: &dyn LockGuard,
) -> anyhow::Result<WalletActionCheckpoint> {
	let checkpoint = db.get_wallet_action_checkpoint(action_id).await?
		.context("cannot cancel wallet action: no durable checkpoint")?;
	ensure!(checkpoint.id() == *action_id, "wallet action checkpoint identity mismatch");
	let inputs = checkpoint.cancellable_input_ids()?;

	// Initial stages do not export completed signatures. Inventory must still
	// agree: a legacy or interrupted transition may already have spent inputs
	// or stored new outputs while leaving an older checkpoint behind.
	for vtxo in db.get_wallet_vtxos(inputs).await? {
		ensure!(matches!(&vtxo.state, VtxoState::Spendable)
			|| matches!(&vtxo.state,
				VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id }) }
					if id == action_id),
			"cannot cancel wallet action: input {} is no longer an uncommitted reservation", vtxo.id());
	}
	for vtxo in db.get_vtxos_by_state(&[VtxoStateKind::Locked]).await? {
		if matches!(&vtxo.state,
			VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id }) }
				if id == action_id)
		{
			ensure!(inputs.contains(&vtxo.id()),
				"cannot cancel wallet action: checkpoint does not account for locked VTXO {}", vtxo.id());
		}
	}
	Ok(checkpoint)
}

async fn action_checkpoint_is_current<A>(db: &dyn BarkPersister, action: &A) -> anyhow::Result<bool>
where
	A: WalletAction + Into<WalletActionCheckpoint> + Clone,
{
	if db.has_program_recovery_reservation(
		&crate::persist::models::recovery_action_key(&action.id()),
	).await? {
		return Ok(false);
	}
	Ok(db.get_wallet_action_checkpoint(&action.id()).await?
		.as_ref() == Some(&action.clone().into()))
}

impl From<LightningSend> for WalletActionCheckpoint {
	fn from(s: LightningSend) -> Self {
		WalletActionCheckpoint::LightningSend(s)
	}
}

impl From<LightningReceive> for WalletActionCheckpoint {
	fn from(r: LightningReceive) -> Self {
		WalletActionCheckpoint::LightningReceive(r)
	}
}

impl From<ArkoorSend> for WalletActionCheckpoint {
	fn from(s: ArkoorSend) -> Self {
		WalletActionCheckpoint::ArkoorSend(s)
	}
}

impl From<Board> for WalletActionCheckpoint {
	fn from(s: Board) -> Self {
		WalletActionCheckpoint::Board(s)
	}
}

impl From<Offboard> for WalletActionCheckpoint {
	fn from(o: Offboard) -> Self {
		WalletActionCheckpoint::Offboard(o)
	}
}

/// Stable identifier for a wallet action.
///
/// The id must be derivable from the action's identity (e.g. the payment
/// hash for a lightning send) so that restarting the same action picks
/// up the same checkpoint row.
pub type WalletActionId = String;

/// Outcome of one `WalletAction::advance` call.
///
/// The executor uses these to decide whether to persist, loop, schedule
/// a wake-up or remove the checkpoint.
pub enum Advance<A> {
	/// Transition to a new state. Executor persists `state` and calls
	/// `advance` on it.
	Next(A),
	/// Pause until something external (notification, periodic sync) or
	/// `wake_after` (when set) re-drives the action. Executor persists
	/// `state` and returns.
	///
	/// `wake_after` is a hint, not a guarantee: it lives only in this
	/// process and is lost across restarts. `advance` MUST tolerate
	/// being called before the hint has elapsed.
	///
	/// `error` is the error that caused the park, if any.
	Park {
		state: A,
		wake_after: Option<Duration>,
		error: Option<AdvanceError>,
	},
	/// Terminal: executor removes the checkpoint row. Any permanent fact
	/// the action wants to retain (e.g. an "invoice paid" record) must
	/// be written to its own table before returning `Done`.
	Done,
	/// Terminal: executor removes the checkpoint row because of a fatal error.
	/// This advance should only be returned when no server change occured yet
	/// or when process has checked server status is expected one and it is
	/// safe to remove checkpoint
	Failed(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum AdvanceError {
	#[error("An error occurred while communicating with the server: {0}")]
	Server(tonic::Status),
	#[error("An error occurred while validating a VTXO: {0}")]
	Vtxo(VtxoValidationError),
	#[error("An error occurred while processing the action: {0}")]
	Other(#[from] anyhow::Error),
}

impl AdvanceError {
	pub fn is_server_rejection(&self) -> bool {
		match self {
			AdvanceError::Server(err) => err.is_rejection(),
			AdvanceError::Vtxo(_) => false,
			AdvanceError::Other(err) => err.downcast_ref::<tonic::Status>()
				.map(|s| s.is_rejection())
				.unwrap_or(false),
		}
	}
}

/// Park action with backoff
///
/// Pass the error when the caller should hear why it parked.
pub fn park_with_backoff<A: WalletAction>(
	state: A,
	attempts: u32,
	error: Option<AdvanceError>,
) -> Advance<A> {
	let delay = attempts.pow(2) * BASE_RETRY_BACKOFF;
	debug!("action {} retrying; sleeping {:?} before re-drive", state.id(), delay);
	Advance::Park { state, wake_after: Some(delay), error }
}

/// Whether to double-drive each action step to check reentrancy, set via the
/// `BARK_DOUBLE_DRIVE_ACTIONS` env var. Empty, `0` and `false` count as unset.
/// Debug-only, compiled out of release.
/// See `just int-bark-sdk-action-reentrancy`.
#[cfg(debug_assertions)]
fn double_drive_actions() -> bool {
	match std::env::var("BARK_DOUBLE_DRIVE_ACTIONS") {
		Ok(v) => !matches!(v.trim(), "" | "0" | "false"),
		Err(_) => false,
	}
}

/// Assert advancing the same state twice produced an equivalent outcome (same
/// [`Advance`] kind, same checkpoint for non-terminal kinds); a divergence is a
/// non-idempotency bug and panics, naming the offending step. Two errors count
/// as equivalent: [`AdvanceError`] isn't comparable.
#[cfg(debug_assertions)]
fn assert_reentrant<A>(
	first: &Result<Advance<A>, AdvanceError>,
	second: &Result<Advance<A>, AdvanceError>,
) where
	A: Into<WalletActionCheckpoint> + Clone,
{
	fn describe<A: Into<WalletActionCheckpoint> + Clone>(
		result: &Result<Advance<A>, AdvanceError>,
	) -> (&'static str, Option<WalletActionCheckpoint>) {
		match result {
			Ok(Advance::Next(state)) => ("Next", Some(state.clone().into())),
			Ok(Advance::Park { state, .. }) => ("Park", Some(state.clone().into())),
			Ok(Advance::Done) => ("Done", None),
			Ok(Advance::Failed(_)) => ("Failed", None),
			Err(_) => ("Err", None),
		}
	}

	assert_eq!(
		describe(first), describe(second),
		"wallet action is not reentrant: advancing the same state twice diverged",
	);
}

/// A wallet action that can be driven step-by-step.
///
/// Implementors define the per-kind state machine; the executor owns the
/// loop, persistence, retry tracking and wake scheduling.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait WalletAction: Sized + Send + Sync {
	/// Get an identifier for this action
	///
	/// The `id` returned MUST be stable across calls on the same logical
	/// action (different states of the same action share an id).
	fn id(&self) -> WalletActionId;

	/// The IDs of VTXOs which are currently in-use, either being spent or being
	/// created, by the action and should be included in the wallet's balance.
	/// The VTXOs should not be stored as spendable in the wallet, but they should
	/// be retrievable via [BarkPersister].
	///
	/// See [crate::Wallet::balance] for more information.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId>;

	/// Called to advance the action state
	///
	/// MUST be re-entrant: it may be called more than once for the same logical
	/// step (after a crash, after an early wake, after a notification arrives).
	/// All side effects it triggers must therefore be idempotent.
	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError>;

	/// Called when the action should be retried
	///
	/// `error` is the failure that triggered the retry; implementations can
	/// attach it to their park so callers driving [DriveMode::UntilParkOrDone]
	/// see why the action stopped.
	async fn on_retry(
		self,
		_wallet: &Wallet,
		attempts: u32,
		_error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		Ok(park_with_backoff(self, attempts, None))
	}

	/// Called when the server rejected one of our requests
	///
	/// MUST be re-entrant for the same reason as [WalletAction::advance]:
	/// it may run partially, crash, and be re-driven against the state the action
	/// subsequently lands in.
	async fn on_rejection(self, _wallet: &Wallet, _error: AdvanceError)
		-> anyhow::Result<Advance<Self>>;
}

/// How aggressively the executor should drive an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveMode {
	/// Drive until the action parks or completes, then return.
	UntilParkOrDone,
	/// Drive past parks, sleeping between iterations, until the action
	/// returns [`Advance::Done`].
	UntilDone,
}

impl Wallet {
	/// Cancel an action only while its durable checkpoint proves that no input
	/// commitment can escape. An active driver, an ambiguous checkpoint or an
	/// irreversible stage leaves both the checkpoint and reservations intact.
	///
	/// This does not undo an on-chain transaction, a disclosed preimage or a
	/// completed payment. Resume those actions or use their recovery path.
	pub async fn stop_wallet_action(&self, action_id: &WalletActionId) -> anyhow::Result<()> {
		let (checkpoint, guard) = lock_cancellable_checkpoint(
			self.inner.db.as_ref(), self.inner.lock_manager.as_ref(), action_id,
		).await?;
		self.cancel_action_checkpoint(&checkpoint, guard.as_ref()).await
	}

	/// Checked cancellation for callers that already hold this action's lock.
	/// `guard` must come from `lock_manager.try_lock(action_id)`.
	pub(crate) async fn stop_wallet_action_with_guard(
		&self,
		action_id: &WalletActionId,
		guard: &dyn LockGuard,
	) -> anyhow::Result<()> {
		let checkpoint = cancellable_checkpoint(self.inner.db.as_ref(), action_id, guard).await?;
		self.cancel_action_checkpoint(&checkpoint, guard).await
	}

	async fn cancel_action_checkpoint(
		&self,
		checkpoint: &WalletActionCheckpoint,
		guard: &dyn LockGuard,
	) -> anyhow::Result<()> {
		// A preparatory split can already have replaced the old inputs. Its new
		// position and change are in inventory before a cancellable stage. Retain
		// their recovery records, and verify readiness before releasing them.
		let inputs = self.inner.db.get_full_vtxos(checkpoint.cancellable_input_ids()?).await?;
		self.ensure_program_recoveries(&inputs).await?;
		self.cancel_action_movement(checkpoint).await?;
		self.finish_wallet_action_with_guard(&checkpoint.id(), guard).await
	}

	async fn cancel_action_movement(&self, checkpoint: &WalletActionCheckpoint) -> anyhow::Result<()> {
		let mut update = MovementUpdate::new()
			.effective_balance(SignedAmount::ZERO).fee(Amount::ZERO);
		let (subsystem, kind) = match checkpoint {
			WalletActionCheckpoint::LightningSend(send) => {
				if let Some(id) = send.movement_id {
					self.inner.movements.finish_movement_with_update(
						id, MovementStatus::Canceled, update,
					).await?;
				}
				return Ok(());
			},
			WalletActionCheckpoint::ArkoorSend(_) => (Subsystem::ARKOOR, ArkoorMovement::Send.to_string()),
			WalletActionCheckpoint::LightningReceive(_) =>
				(Subsystem::LIGHTNING_RECEIVE, LightningReceiveMovement::Receive.to_string()),
			WalletActionCheckpoint::Offboard(offboard) => {
				let kind = match &offboard.kind {
					offboard::OffboardKind::OffboardWhole { .. } => OffboardMovement::Offboard,
					offboard::OffboardKind::SendOnchain { .. } => {
						if matches!(offboard.progress,
							offboard::Progress::ReadyForOffboard { .. }
								| offboard::Progress::OffboardTxPrepared { .. })
						{
							// Keep the change already recorded and also account for
							// the split output that is no longer being offboarded.
							update = update.produced_vtxos(checkpoint.cancellable_input_ids()?);
						}
						OffboardMovement::SendOnchain
					},
				};
				(Subsystem::OFFBOARD, kind.to_string())
			},
			WalletActionCheckpoint::Board(_) => bail!("board cancellation is not safe"),
		};
		let id = self.inner.movements.get_or_create_movement_with_action(
			subsystem, kind, &checkpoint.id(), MovementUpdate::new(),
		).await?;
		self.inner.movements.finish_movement_with_update(id, MovementStatus::Canceled, update).await?;
		Ok(())
	}

	/// Complete a terminal action without acquiring its lock again.
	///
	/// Only the executor or an explicit exit may call this. They must first
	/// persist all signed outputs and recovery handoffs, and mark committed
	/// inputs spent or in exit. `guard` must hold this exact action's lock.
	/// Checkpoint deletion and lock release use one durable database commit.
	/// A failed commit cannot leave a resumable action with reusable inputs.
	pub(crate) async fn finish_wallet_action_with_guard(
		&self,
		action_id: &WalletActionId,
		_guard: &dyn LockGuard,
	) -> anyhow::Result<()> {
		self.inner.db.finish_wallet_action(action_id).await
	}

	/// Drive a wallet action to its next park or terminal state.
	///
	/// Holds a per-action-id in-flight guard so concurrent drives of
	/// the same action (e.g. the periodic sync racing a user call)
	/// don't step on each other.
	pub async fn drive_action<A>(&self, action: A, mode: DriveMode) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		let guard = match self.inner.lock_manager.try_lock(&action.id()).await {
			Some(g) => g,
			None => {
				trace!("action {} is already being driven, skipping", action.id());
				return Ok(());
			},
		};

		self.drive_action_with_guard(action, mode, guard).await
	}

	/// Drive an action assuming the caller already holds its per-id
	/// lock. `lock_guard` must come from `lock_manager.try_lock(&action.id())`.
	/// It is held for RAII and dropped when this function returns.
	pub(crate) async fn drive_action_with_guard<A>(
		&self,
		action: A,
		mode: DriveMode,
		lock_guard: Box<dyn LockGuard>,
	) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		ensure!(!self.inner.db.has_program_recovery_reservation(
			&crate::persist::models::recovery_action_key(&action.id()),
		).await?, "wallet action {} was taken over by program recovery", action.id());
		// A sync pass can load a snapshot before cancellation acquires the lock.
		// Never resurrect that deleted action, or drive an older signing stage.
		if !action_checkpoint_is_current(self.inner.db.as_ref(), &action).await? {
			trace!("action {} checkpoint changed or was removed, skipping stale drive", action.id());
			return Ok(());
		}

		// Box the driver so its state machine lives on the heap rather
		// than inline in the caller's future.
		Box::pin(self.run_action_loop(action, mode, lock_guard.as_ref())).await
	}

	/// Run one `advance` step.
	///
	/// In debug builds with `BARK_DOUBLE_DRIVE_ACTIONS` set (see
	/// [`double_drive_actions`]) the step runs twice from the same state and
	/// [`assert_reentrant`] checks both reach an equivalent checkpoint,
	/// exercising `advance`'s idempotency contract. Keep the second run; its
	/// side effects are the ones the persisted state references.
	async fn advance_step<A>(&self, action: A) -> Result<Advance<A>, AdvanceError>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		#[cfg(debug_assertions)]
		if double_drive_actions() {
			let snapshot = action.clone();
			let first = action.advance(self).await;
			if self.inner.db.has_program_recovery_reservation(
				&crate::persist::models::recovery_action_key(&snapshot.id()),
			).await? {
				return first;
			}
			let second = snapshot.advance(self).await;

			// A first run that parks made no committed progress: it is a
			// "nothing finished, re-drive me later" outcome (waiting on a
			// confirmation, polling for an incoming payment, retrying a
			// transient server rejection). The second run is that later
			// re-drive and may legitimately diverge once the awaited condition
			// clears, progressing to the next step or completing. So only
			// assert equivalence when the first run committed a step (Next),
			// finished (Done) or failed terminally.
			let first_parked = matches!(first, Ok(Advance::Park { .. }));
			if !first_parked {
				assert_reentrant(&first, &second);
			}
			return second;
		}

		action.advance(self).await
	}

	async fn run_action_loop<A>(
		&self,
		mut action: A,
		mode: DriveMode,
		lock_guard: &dyn LockGuard,
	) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		// In-memory counter for transient errors. Lives only for this
		// drive_action call so the backoff curve resets between drives.
		let mut retries: u32 = 0;

		loop {
			let id = action.id();
			// Snapshot for the error path: advance consumes self, and
			// on_rejection also takes self by value, so we need a
			// copy around if budget exhausts.
			let snapshot = action.clone();

			let result = self.advance_step(action).await;
			if self.inner.db.has_program_recovery_reservation(
				&crate::persist::models::recovery_action_key(&id),
			).await? {
				// Recovery owns the retained checkpoint and all its inputs now.
				// Never run a cooperative error callback after that handoff.
				return Ok(());
			}
			let advance = match result {
				Ok(advance) => Ok(advance),
				Err(e) if !action_checkpoint_is_current(self.inner.db.as_ref(), &snapshot).await? => {
					// A step can persist a signing boundary before a later error.
					// Its old retry/rejection handler must not replace that newer
					// checkpoint or release its committed inputs.
					return Err(e.into());
				},
				Err(e) if e.is_server_rejection() => {
					warn!("action {} got rejected by server: {:#}", id, e);
					snapshot.on_rejection(self, e).await.inspect_err(|err| {
						warn!("action {} on_rejection failed, leaving checkpoint for retry: {:#}", id, err);
					})
				}
				Err(e) => {
					retries = retries.saturating_add(1);
					log::error!("Got error {:?} from action {}, retrying", e, id);
					snapshot.on_retry(self, retries, e).await.inspect_err(|err| {
						warn!("action {} on_retry failed, leaving checkpoint for retry: {:#}", id, err);
					})
				},
			};

			if self.inner.db.has_program_recovery_reservation(
				&crate::persist::models::recovery_action_key(&id),
			).await? {
				// Retry/rejection handlers can hand off too. In particular,
				// keep their saved bytes instead of terminal action cleanup.
				return Ok(());
			}
			match advance? {
				Advance::Next(next) => {
					retries = 0;
					let checkpoint: WalletActionCheckpoint = next.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
					action = next;
				},
				Advance::Park { state, wake_after, error } => {
					let checkpoint: WalletActionCheckpoint = state.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
					match mode {
						DriveMode::UntilParkOrDone => {
							return match error {
								Some(error) => Err(error.into()),
								None => Ok(()),
							};
						},
						DriveMode::UntilDone => {
							if let Some(delay) = wake_after {
								debug!("action {} parked; sleeping {:?} before re-drive", id, delay);
								bark_runtime::sleep(delay).await;
								action = state;
							} else {
								return match error {
									Some(error) => Err(error.into()),
									None => Ok(()),
								};
							}
						},
					}
				},
				Advance::Done => {
					if let Err(e) = self.finish_wallet_action_with_guard(&id, lock_guard).await {
						warn!("action {} done but cleanup failed: {:#}", id, e);
					}
					return Ok(());
				},
				Advance::Failed(e) => {
					if let Err(e) = self.finish_wallet_action_with_guard(&id, lock_guard).await {
						warn!("action {} failed but cleanup failed: {:#}", id, e);
					}
					return Err(e);
				},
			}
		}
	}
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
	use std::str::FromStr;

	use bitcoin::{FeeRate, Network, Transaction};
	use bitcoin::secp256k1::Secp256k1;
	use lightning_invoice::Bolt11Invoice;

	use ark::lightning::{Invoice, Preimage};
	use ark::test_util::VTXO_VECTORS;
	use bitcoin_ext::{BlockDelta, BlockHeight};

	use crate::lock_manager::memory::MemoryLockManager;
	use crate::movement::{MovementId, PaymentMethod};
	use crate::persist::adaptor::StorageAdaptorWrapper;

	use super::*;

	const TEST_INVOICE: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

	fn transaction() -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![],
		}
	}

	fn send(progress: arkoor_send::Progress) -> ArkoorSend {
		ArkoorSend {
			id: "cancel.arkoor".into(),
			destination: ark::Address::from_str(
				"tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z",
			).unwrap(),
			amount: Amount::from_sat(10_000),
			input_vtxo_ids: vec![VTXO_VECTORS.board_vtxo.id()],
			change_key_index: 0,
			change_pieces: None,
			progress,
		}
	}

	fn offboard(progress: offboard::Progress) -> Offboard {
		let key = VTXO_VECTORS.board_vtxo.policy().user_pubkey();
		Offboard {
			id: "cancel.offboard".into(),
			destination: bitcoin::Address::p2tr(
				&Secp256k1::verification_only(), key.x_only_public_key().0, None, Network::Regtest,
			).into_unchecked(),
			onchain_output_amount: Amount::from_sat(1_000),
			committed_fee: Amount::ZERO,
			committed_fee_rate: FeeRate::BROADCAST_MIN,
			kind: offboard::OffboardKind::OffboardWhole {
				input_vtxo_ids: vec![VTXO_VECTORS.board_vtxo.id()],
			},
			progress,
		}
	}

	fn lightning_send(progress: lightning::pay::Progress) -> LightningSend {
		LightningSend {
			invoice: Invoice::Bolt11(TEST_INVOICE.parse().unwrap()),
			original_payment_method: PaymentMethod::Custom("test".into()),
			input_vtxo_ids: vec![VTXO_VECTORS.board_vtxo.id()],
			payment_amount: Amount::from_sat(1_000),
			fee: Amount::ZERO,
			change_pieces: None,
			htlc_key: VTXO_VECTORS.arkoor_htlc_out_vtxo.policy().user_pubkey(),
			htlc_expiry: BlockHeight::new(100),
			movement_id: None,
			revocation_key: None,
			retry_for: None,
			progress,
			allow_exit_of_htlcs: false,
		}
	}

	fn lightning_receive(progress: lightning::receive::Progress) -> LightningReceive {
		let invoice = Bolt11Invoice::from_str(TEST_INVOICE).unwrap();
		LightningReceive {
			payment_hash: (&invoice).into(),
			invoice,
			payment_preimage: Preimage::from_slice(&[3; 32]).unwrap(),
			htlc_recv_cltv_delta: BlockDelta::new(10),
			anti_dos_token: None,
			claim_destination: None,
			key_index: 0,
			progress,
		}
	}

	fn assert_not_cancellable(checkpoint: impl Into<WalletActionCheckpoint>) {
		let checkpoint = checkpoint.into();
		assert!(checkpoint.cancellable_input_ids().is_err(), "{checkpoint:?}");
	}

	#[test]
	fn signed_arkoor_and_board_checkpoints_are_not_cancellation_points() {
		let movement_id = MovementId::new(1);
		let signed = vec![VTXO_VECTORS.arkoor3_vtxo.clone()];
		for progress in [
			arkoor_send::Progress::Registration {
				movement_id, signed_destination_vtxos: signed.clone(), signed_change_vtxos: vec![],
			},
			arkoor_send::Progress::Delivery {
				movement_id, signed_destination_vtxos: signed.clone(), signed_change_vtxos: vec![],
				last_park_error: Some("recipient acknowledgement lost".into()),
			},
			arkoor_send::Progress::Finalizing {
				movement_id, signed_change_vtxos: signed, delivery_succeeded: false,
			},
		] {
			assert_not_cancellable(send(progress));
		}
		for progress in [
			board::Progress::PreparingFunding {
				signed_vtxo: VTXO_VECTORS.board_vtxo.clone(), sign_funding: false,
			},
			board::Progress::PreparingFunding {
				signed_vtxo: VTXO_VECTORS.board_vtxo.clone(), sign_funding: true,
			},
			board::Progress::Broadcasting { signed_vtxo: VTXO_VECTORS.board_vtxo.clone() },
			board::Progress::Confirming { last_park_error: None },
		] {
			assert_not_cancellable(Board {
				id: "cancel.board".into(),
				funding_tx: None,
				funding_psbt: Some(bitcoin::Psbt::from_unsigned_tx(transaction()).unwrap()),
				vtxo_id: VTXO_VECTORS.board_vtxo.id(),
				amount: Amount::from_sat(1_000),
				movement_id,
				progress,
			});
		}
	}

	#[test]
	fn legacy_and_saved_lightning_outputs_are_not_cancellation_points() {
		for vtxos in [vec![], vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.clone()]] {
			let htlcs = lightning::pay::Htlcs {
				vtxo_ids: vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.id()],
				mailbox_id: VTXO_VECTORS.board_vtxo.policy().user_pubkey().into(),
				movement_id: MovementId::new(1),
				vtxos,
			};
			assert_not_cancellable(lightning_send(lightning::pay::Progress::HtlcReceived(htlcs.clone())));
			assert_not_cancellable(lightning_send(lightning::pay::Progress::PaymentInitiated(htlcs.clone())));
			for revoked in [vec![], vec![VTXO_VECTORS.arkoor3_vtxo.clone()]] {
				let revocation = lightning::pay::Revocation {
					key: VTXO_VECTORS.board_vtxo.policy().user_pubkey(), vtxos: revoked,
				};
				assert_not_cancellable(lightning_send(lightning::pay::Progress::RevocableHtlcs {
					htlcs: htlcs.clone(), revocation: revocation.clone(),
				}));
				assert_not_cancellable(lightning_send(lightning::pay::Progress::RevocationStuck {
					htlcs: htlcs.clone(), revocation,
				}));
			}
		}
		let htlcs = lightning::receive::Htlcs {
			vtxo_ids: vec![VTXO_VECTORS.board_vtxo.id()], movement_id: MovementId::new(1),
		};
		assert_not_cancellable(lightning_receive(lightning::receive::Progress::HtlcsReady(htlcs.clone())));
		assert_not_cancellable(lightning_receive(lightning::receive::Progress::PreimageRevealed(htlcs)));
		assert_not_cancellable(lightning_receive(lightning::receive::Progress::Delivering(
			lightning::receive::Delivery {
				vtxos: vec![VTXO_VECTORS.arkoor3_vtxo.clone()],
				movement_id: MovementId::new(1),
				input_vtxo_ids: vec![VTXO_VECTORS.board_vtxo.id()],
			},
		)));
	}

	#[test]
	fn offboard_requires_positive_evidence_that_forfeits_are_unsent() {
		let input_ids = vec![VTXO_VECTORS.board_vtxo.id()];
		let prepared = offboard(offboard::Progress::OffboardTxPrepared {
			offboard_vtxo_ids: input_ids.clone(), offboard_tx: transaction(),
			forfeit_cosign_nonces: vec![], movement_id: MovementId::new(1), forfeits_unsent: true,
		});
		assert!(WalletActionCheckpoint::from(prepared.clone()).cancellable_input_ids().is_ok());
		let mut legacy = serde_json::to_value(prepared).unwrap();
		legacy["progress"]["OffboardTxPrepared"].as_object_mut().unwrap().remove("forfeits_unsent");
		assert_not_cancellable(serde_json::from_value::<Offboard>(legacy).unwrap());
		for progress in [
			offboard::Progress::ArkoorCreated {
				created: vec![VTXO_VECTORS.arkoor3_vtxo.clone()], change: vec![],
			},
			offboard::Progress::ArkoorRegistrationRequired {
				offboard_vtxo_ids: input_ids.clone(), change_vtxo_ids: vec![],
			},
			offboard::Progress::ReadyForOffboard {
				offboard_vtxo_ids: input_ids.clone(), prior_txid: Some(transaction().compute_txid()),
			},
			offboard::Progress::ForfeitsPrepared {
				offboard_vtxo_ids: input_ids.clone(), offboard_tx: transaction(),
				user_nonces: vec![], partial_signatures: vec![], movement_id: MovementId::new(1),
			},
			offboard::Progress::ReadyForBroadcast {
				offboard_vtxo_ids: input_ids.clone(), signed_offboard_tx: transaction(),
				movement_id: MovementId::new(1),
			},
			offboard::Progress::AwaitingConfirmations {
				offboard_vtxo_ids: input_ids, offboard_txid: transaction().compute_txid(),
				offboard_tx: transaction(), movement_id: MovementId::new(1),
				created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
			},
		] {
			assert_not_cancellable(offboard(progress));
		}
	}

	#[tokio::test]
	async fn cancellation_excludes_driver_and_reads_its_latest_checkpoint() {
		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let initial = ArkoorSend {
			id: "cancel.active-driver".into(), ..send(arkoor_send::Progress::Cosigning)
		};
		let id = initial.id();
		let holder = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: id.clone() }) };
		db.store_vtxos(&[(&VTXO_VECTORS.board_vtxo, &holder)]).await.unwrap();
		db.upsert_wallet_action_checkpoint(&id, &initial.clone().into()).await.unwrap();

		// Deterministic schedule: the signer owns the lock while cancellation
		// arrives, then publishes the signed checkpoint before releasing it.
		let driver = locks.try_lock(&id).await.unwrap();
		assert!(lock_cancellable_checkpoint(&db, &locks, &id).await.is_err());
		let committed: WalletActionCheckpoint = ArkoorSend {
			progress: arkoor_send::Progress::Registration {
				movement_id: MovementId::new(1),
				signed_destination_vtxos: vec![VTXO_VECTORS.arkoor3_vtxo.clone()],
				signed_change_vtxos: vec![],
			},
			..initial.clone()
		}.into();
		db.upsert_wallet_action_checkpoint(&id, &committed).await.unwrap();
		drop(driver);

		assert!(lock_cancellable_checkpoint(&db, &locks, &id).await.is_err());
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(committed));
		assert_eq!(db.get_wallet_vtxo(VTXO_VECTORS.board_vtxo.id()).await.unwrap().unwrap().state, holder);
		assert!(!action_checkpoint_is_current(&db, &initial).await.unwrap());
	}

	#[tokio::test]
	async fn safe_initial_native_actions_remain_cancellable() {
		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let vtxo = &VTXO_VECTORS.board_vtxo;
		db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.unwrap();
		for checkpoint in [
			WalletActionCheckpoint::from(send(arkoor_send::Progress::Cosigning)),
			lightning_send(lightning::pay::Progress::Start).into(),
			lightning_receive(lightning::receive::Progress::AwaitingPayment).into(),
			offboard(offboard::Progress::Start).into(),
			offboard(offboard::Progress::ReadyForOffboard {
				offboard_vtxo_ids: vec![vtxo.id()], prior_txid: None,
			}).into(),
		] {
			let id = checkpoint.id();
			db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
			let (loaded, guard) = lock_cancellable_checkpoint(&db, &locks, &id).await.unwrap();
			assert_eq!(loaded, checkpoint);
			assert!(locks.try_lock(&id).await.is_none(), "cleanup must still own the driver lock");
			drop(guard);
		}
	}

	#[tokio::test]
	async fn cancellation_rejects_missing_or_inconsistent_inventory_without_unlocking() {
		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let initial = ArkoorSend {
			id: "cancel.inconsistent-inventory".into(), ..send(arkoor_send::Progress::Cosigning)
		};
		let id = initial.id();
		let holder = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: id.clone() }) };
		db.store_vtxos(&[(&VTXO_VECTORS.board_vtxo, &holder)]).await.unwrap();
		assert!(lock_cancellable_checkpoint(&db, &locks, &id).await.is_err());
		db.upsert_wallet_action_checkpoint(&id, &initial.clone().into()).await.unwrap();
		let (_, guard) = lock_cancellable_checkpoint(&db, &locks, &id).await.unwrap();
		drop(guard);

		// A crash after storing new outputs but before advancing an old
		// checkpoint must not turn those outputs into spendable input money.
		db.store_vtxos(&[(&VTXO_VECTORS.arkoor3_vtxo, &holder)]).await.unwrap();
		assert!(lock_cancellable_checkpoint(&db, &locks, &id).await.is_err());
		assert_eq!(db.get_vtxos_by_state(&[VtxoStateKind::Locked]).await.unwrap().len(), 2);
		db.update_vtxo_state_checked(
			VTXO_VECTORS.board_vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Locked],
		).await.unwrap();
		assert!(lock_cancellable_checkpoint(&db, &locks, &id).await.is_err());
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(initial.into()));
	}

	#[tokio::test]
	async fn a_removed_checkpoint_cannot_be_resurrected_by_a_stale_driver() {
		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let initial = ArkoorSend {
			id: "cancel.stale-driver".into(), ..send(arkoor_send::Progress::Cosigning)
		};
		let id = initial.id();
		let holder = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: id.clone() }) };
		db.store_vtxos(&[(&VTXO_VECTORS.board_vtxo, &holder)]).await.unwrap();
		db.upsert_wallet_action_checkpoint(&id, &initial.clone().into()).await.unwrap();
		assert!(action_checkpoint_is_current(&db, &initial).await.unwrap());
		let (_, guard) = lock_cancellable_checkpoint(&db, &locks, &id).await.unwrap();
		db.finish_wallet_action(&id).await.unwrap();
		assert!(locks.try_lock(&id).await.is_none());
		assert_eq!(db.get_wallet_vtxo(VTXO_VECTORS.board_vtxo.id()).await.unwrap().unwrap().state,
			VtxoState::Spendable);
		drop(guard);
		let _stale_driver = locks.try_lock(&id).await.unwrap();
		assert!(!action_checkpoint_is_current(&db, &initial).await.unwrap());
	}

	#[tokio::test]
	async fn recovery_observes_signer_commit_and_permanently_stops_stale_drivers() {
		use crate::persist::models::recovery_action_key;
		use crate::sapio::recovery::lock_recovery_actors;

		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let initial = ArkoorSend {
			id: "recovery.signer-commit".into(), ..send(arkoor_send::Progress::Cosigning)
		};
		let id = initial.id();
		let actor = recovery_action_key(&id);
		let actors = std::collections::BTreeMap::from([(actor.clone(), id.clone())]);
		let holder = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: id.clone() }) };
		let vtxo = &VTXO_VECTORS.board_vtxo;
		db.store_vtxos(&[(vtxo, &holder)]).await.unwrap();
		db.upsert_wallet_action_checkpoint(&id, &initial.clone().into()).await.unwrap();

		// A driver has crossed its signing boundary while recovery is arriving.
		// Recovery cannot reserve/broadcast using the snapshot it read earlier.
		let signer = locks.try_lock(&id).await.unwrap();
		assert!(lock_recovery_actors(&locks, &actors, None).await.is_err());
		let committed = ArkoorSend {
			progress: arkoor_send::Progress::Registration {
				movement_id: MovementId::new(1),
				signed_destination_vtxos: vec![VTXO_VECTORS.arkoor3_vtxo.clone()],
				signed_change_vtxos: vec![],
			},
			..initial.clone()
		};
		db.upsert_wallet_action_checkpoint(&id, &committed.clone().into()).await.unwrap();
		drop(signer);

		let recovery = lock_recovery_actors(&locks, &actors, None).await.unwrap();
		let checkpoint = db.get_wallet_action_checkpoint(&id).await.unwrap().unwrap();
		let (_, saved_outputs) = checkpoint.recovery_positions();
		assert_eq!(saved_outputs, vec![&VTXO_VECTORS.arkoor3_vtxo]);
		assert!(action_checkpoint_is_current(&db, &committed).await.unwrap());
		db.reserve_program_recovery(&[(vtxo.id(), Some(holder))], &[actor]).await.unwrap();
		drop(recovery);

		// The latest checkpoint remains inspectable, but no saved stage can be
		// driven after restart/takeover. Generic unlock cannot undo it.
		let _next_driver = locks.try_lock(&id).await.unwrap();
		assert!(!action_checkpoint_is_current(&db, &initial).await.unwrap());
		assert!(!action_checkpoint_is_current(&db, &committed).await.unwrap());
		assert!(db.upsert_wallet_action_checkpoint(&id, &initial.into()).await.is_err());
		assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, VtxoState::Exited);
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(committed.into()));
	}

	#[tokio::test]
	async fn guarded_lightning_recovery_does_not_relock_or_block_unrelated_actions() {
		use crate::persist::models::recovery_action_key;
		use crate::sapio::recovery::lock_recovery_actors;

		let locks = MemoryLockManager::new();
		let id = "lightning.receive.recovery";
		let held = locks.try_lock(id).await.unwrap();
		let actors = std::collections::BTreeMap::from([(recovery_action_key(id), id.to_owned())]);
		assert!(lock_recovery_actors(&locks, &actors, None).await.is_err());
		let recovery = lock_recovery_actors(&locks, &actors, Some(id)).await.unwrap();
		assert!(recovery.is_empty(), "already-held action must not be recursively acquired");
		assert!(locks.try_lock("unrelated.native.action").await.is_some());
		assert!(locks.try_lock(id).await.is_none(), "caller retains its original guard");
		drop(recovery);
		drop(held);
		assert!(locks.try_lock(id).await.is_some());
	}

	#[test]
	fn delivered_payment_without_change_still_supersedes_its_old_claims() {
		let initial = send(arkoor_send::Progress::Cosigning);
		let inputs = initial.input_vtxo_ids.clone();
		assert!(WalletActionCheckpoint::from(initial.clone()).recovery_consumed_inputs().is_empty());
		let delivered: WalletActionCheckpoint = ArkoorSend {
			progress: arkoor_send::Progress::Finalizing {
				movement_id: MovementId::new(1),
				signed_change_vtxos: vec![],
				delivery_succeeded: true,
			},
			..initial
		}.into();
		assert!(delivered.recovery_positions().1.is_empty());
		assert_eq!(delivered.recovery_consumed_inputs(), inputs);
	}
}
