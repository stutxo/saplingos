//! State machine for outgoing offboards (offboard whole vtxos *and*
//! arkoor-prep-then-offboard for [`Wallet::send_onchain`]).
//!
//! Identity (`id`, `destination`, `fee_rate`, `kind`) and the parameters
//! fixed at the start (inputs, amounts) live on the action as top-level
//! fields; the mutable bit is [`Progress`], a small enum that names the
//! phases of the state machine and only carries the fields the phase
//! actually has.
//!
//! Both entry points share the same skeleton:
//! - `start_offboard` selects inputs and derives the offboard key (both
//!   for `SendOnchain` only), validates fee and dust constraints, and
//!   returns the action in [`Progress::Start`]; `lock_vtxos` then locks
//!   the inputs under the action id.
//! - For `SendOnchain` only, `arkoor_split_offboard` runs an arkoor to
//!   produce an exact-sized offboard vtxo plus change, which
//!   `register_arkoor_split` registers with the server.
//! - Both kinds converge in `prepare_offboard`, which has the server
//!   build the offboard tx and validates it
//!   ([`Progress::OffboardTxPrepared`]). `prepare_offboard_forfeits` signs
//!   and checkpoints the exact forfeits before `finish_offboard` trades
//!   those durable shares for the signed tx ([`Progress::ReadyForBroadcast`]).
//! - `broadcast_offboard` publishes the signed tx
//!   ([`Progress::AwaitingConfirmations`]).
//! - `settle_offboard` marks the vtxos spent and finalises the movement
//!   once the tx has enough confirmations.

use std::collections::HashSet;
use std::iter;
use std::time::Duration;

use anyhow::Context;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, FeeRate, SignedAmount, Transaction, Txid};
use bitcoin::hashes::Hash;
use log::{error, info, trace, warn};

use ark::{musig, ProtocolEncoding, Vtxo, VtxoPolicy, VtxoId, fees};
use ark::arkoor::ArkoorDestination;
use ark::attestations::OffboardRequestAttestation;
use ark::fees::VtxoFeeInfo;
use ark::offboard::{OffboardForfeitContext, OffboardForfeitError, OffboardRequest};
use ark::sapio::protocol::{OwnershipProof, OwnershipRequest};
use ark::vtxo::{Full, VtxoRef};
use bitcoin_ext::{BlockDelta, TxStatus};
use server_rpc::{protos, TryFromBytes};

use crate::{Wallet, WalletVtxo};
use crate::actions::{
	Advance, AdvanceError, WalletAction, WalletActionCheckpoint, WalletActionId, BASE_RETRY_BACKOFF,
};
use crate::arkoor::split_change_amount;
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::subsystem::{OffboardMovement, Subsystem};
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};

/// How long to sleep between confirmation polls while a tx is in
/// mempool or has too few confirmations.
pub(crate) const CONFIRMATION_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// An outgoing offboard, persisted as a single checkpoint row and
/// driven across crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offboard {
	// Set at start, immutable thereafter:
	pub id: WalletActionId,
	pub destination: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain_output_amount: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub committed_fee: Amount,
	pub committed_fee_rate: FeeRate,
	pub kind: OffboardKind,

	// Mutable state:
	pub progress: Progress,
}

impl Offboard {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	pub fn check_destination(&self, network: bitcoin::Network) -> anyhow::Result<bitcoin::Address> {
		Ok(self.destination.clone().require_network(network)?)
	}
}

/// Which flavour of offboard this action drives.
///
/// `OffboardWhole` is reached from [`Wallet::offboard_all`] or
/// [`Wallet::offboard_vtxos`]: the inputs are forfeited directly to
/// the offboard tx, fees come out of the gross amount.
///
/// `SendOnchain` is reached from [`Wallet::send_onchain`]: the user gives an
/// amount and the wallet must first arkoor-split its vtxos into an
/// exact-sized output (held by `offboard_pubkey`) plus change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffboardKind {
	/// Forfeit the listed vtxos as-is to the offboard tx.
	OffboardWhole {
		input_vtxo_ids: Vec<VtxoId>,
	},
	/// Run an arkoor first; offboard the resulting exact-sized vtxo.
	SendOnchain {
		input_vtxo_ids: Vec<VtxoId>,
		/// Holds the arkoor-output (offboard input) vtxo.
		arkoor_key_index: u32,
		/// Holds the arkoor change. Must differ from `arkoor_key_index`: the
		/// arkoor builder refuses a change output paying the destination.
		change_key_index: u32,
		/// Change piece amounts fixed at start. `None` when persisted by a
		/// pre-split bark, meaning one whole change output.
		#[serde(default, with = "crate::utils::serde::opt_amount_vec_sat")]
		change_pieces: Option<Vec<Amount>>,
	},
}

impl OffboardKind {
	fn deduct_fees_from_gross_amount(&self) -> bool {
		match self {
			OffboardKind::OffboardWhole { .. } => true,
			OffboardKind::SendOnchain { .. } => false,
		}
	}

	fn vtxo_ids(&self) -> &Vec<VtxoId> {
		match self {
			OffboardKind::OffboardWhole { input_vtxo_ids } => input_vtxo_ids,
			OffboardKind::SendOnchain { input_vtxo_ids, .. } => input_vtxo_ids,
		}
	}
}

/// The phases of offboarding.
///
/// `SplitWithArkoor` and `ArkoorRegistrationRequired` are only reached from
/// the `SendOnchain` kind; the `OffboardWhole` kind transitions directly
/// from `Start` to `ReadyForOffboard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs need locking, but we have selected VTXOs to offboard.
	Start,
	/// `SendOnchain` intermediate: We need to perform an arkoor to split the VTXOs so we can
	/// offboard the exact amount requested.
	SplitWithArkoor,
	/// Signed split outputs are durable before recovery merging or registration.
	ArkoorCreated {
		#[serde(with = "ark::encode::serde::vec")]
		created: Vec<Vtxo<Full>>,
		#[serde(with = "ark::encode::serde::vec")]
		change: Vec<Vtxo<Full>>,
	},
	/// `SendOnchain` intermediate: arkoor done, yet to be registered with the server.
	/// Both the offboard vtxos and the change are held locked until registration
	/// succeeds; only then is the change released as spendable.
	ArkoorRegistrationRequired {
		offboard_vtxo_ids: Vec<VtxoId>,
		change_vtxo_ids: Vec<VtxoId>,
	},
	/// VTXOs are locked, (potential) split is done, now we can start the actual offboard.
	ReadyForOffboard {
		/// In the case of `SendOnchain` this is the arkoor VTXOs we just created, in the case
		/// of `OffboardWhole` this is the VTXOs we selected to offboard.
		offboard_vtxo_ids: Vec<VtxoId>,
		/// Legacy checkpoints can carry an earlier offboard transaction whose
		/// forfeits may already have escaped. Such inputs must remain locked.
		#[serde(default)]
		prior_txid: Option<Txid>,
	},
	/// Validated offboard transaction, before authorizing its exact forfeits.
	OffboardTxPrepared {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		/// The server's forfeit cosign nonces from the prepare response;
		/// stable across prepare replays.
		forfeit_cosign_nonces: Vec<musig::PublicNonce>,
		movement_id: MovementId,
		/// False in legacy checkpoints, which did not record the signing boundary.
		#[serde(default)]
		forfeits_unsent: bool,
	},
	/// Exact public shares are durable before the server can receive them.
	/// A lost response must replay these bytes and never release the inputs.
	ForfeitsPrepared {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		user_nonces: Vec<musig::PublicNonce>,
		partial_signatures: Vec<[u8; 32]>,
		movement_id: MovementId,
	},
	ReadyForBroadcast {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		signed_offboard_tx: Transaction,
		movement_id: MovementId,
	},
	/// Offboard tx broadcast; waiting for confirmation.
	AwaitingConfirmations {
		offboard_vtxo_ids: Vec<VtxoId>,
		offboard_txid: Txid,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		movement_id: MovementId,
		created_at: chrono::DateTime<chrono::Utc>,
	},
}

/// Outcome of a single confirmation check on an `AwaitingConfirmations` offboard.
pub(crate) enum ConfirmationOutcome {
	Confirmed,
	Pending,
	/// The tx hasn't been seen on chain for over
	/// [Config::offboard_lost_tx_grace_period_secs](crate::Config::offboard_lost_tx_grace_period_secs).
	///
	/// We deliberately do NOT cancel the action and release its vtxos:
	/// after finish they are forfeited to the server, so treating them
	/// as spendable again would corrupt the wallet. The action parks
	/// with an error and keeps re-checking the chain on every drive.
	Lost,
}

/// User-level spec passed to `start_offboard` describing which
/// flavour of offboard is being launched.
pub enum StartOffboardSpec {
	/// Forfeit whole VTXOs as-is. Caller picks the vtxos; fees are
	/// deducted from the gross amount.
	OffboardWhole { vtxos: Vec<WalletVtxo> },
	/// Send a specific amount on-chain. The wallet picks inputs and
	/// runs an arkoor first to produce an exact-sized vtxo.
	SendOnchain { amount: Amount },
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for Offboard {
	fn id(&self) -> WalletActionId { Offboard::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let new_progress = match self.progress.clone() {
			Progress::Start => {
				lock_vtxos(wallet, &self).await?
			},
			Progress::SplitWithArkoor => {
				arkoor_split_offboard(wallet, &self).await?
			}
			Progress::ArkoorCreated { created, change } => {
				store_arkoor_split(wallet, &self, created, change).await?
			},
			Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids } => {
				register_arkoor_split(wallet, &self, offboard_vtxo_ids, change_vtxo_ids).await?
			},
			Progress::ReadyForOffboard { offboard_vtxo_ids, prior_txid } => {
				if prior_txid.is_some() {
					for id in &offboard_vtxo_ids {
						let input = wallet.get_vtxo_by_id(*id).await?;
						if wallet.vtxo_signing_key(&input).await?.program().is_some() {
							return Err(anyhow!(
								"legacy program offboard may have forfeited its inputs; refusing a conflicting session",
							).into());
						}
					}
				}
				prepare_offboard(wallet, &self, offboard_vtxo_ids).await?
			},
			Progress::OffboardTxPrepared {
				offboard_vtxo_ids, offboard_tx, forfeit_cosign_nonces, movement_id, forfeits_unsent,
			} => {
				if !forfeits_unsent {
					for id in &offboard_vtxo_ids {
						let input = wallet.get_vtxo_by_id(*id).await?;
						if wallet.vtxo_signing_key(&input).await?.program().is_some() {
							return Err(anyhow!(
								"legacy program offboard lacks durable forfeit shares; inputs remain locked",
							).into());
						}
					}
				}
				prepare_offboard_forfeits(
					wallet, &self, offboard_vtxo_ids, offboard_tx,
					forfeit_cosign_nonces, movement_id,
				).await?
			},
			Progress::ForfeitsPrepared {
				offboard_vtxo_ids, offboard_tx, user_nonces, partial_signatures, movement_id,
			} => {
				finish_offboard(
					wallet, offboard_vtxo_ids, offboard_tx,
					user_nonces, partial_signatures, movement_id,
				).await?
			},
			Progress::ReadyForBroadcast { offboard_vtxo_ids, signed_offboard_tx, movement_id } => {
				// Reaching `AwaitingConfirmations` is the user-observable boundary
				// (caller wants the txid back). Park here so the
				// orchestration layer can read the persisted checkpoint
				// without racing the executor past it.
				let progress = broadcast_offboard(
					wallet, offboard_vtxo_ids, signed_offboard_tx, movement_id,
				).await?;
				return Ok(Advance::Park {
					state: Offboard { progress, ..self },
					wake_after: Some(CONFIRMATION_POLL_INTERVAL),
					error: None,
				});
			},
			Progress::AwaitingConfirmations {
				ref offboard_vtxo_ids, offboard_txid, offboard_tx, movement_id, created_at,
			} => {
				return match check_offboard_confirmation(
					wallet, &offboard_tx, created_at,
				).await? {
					ConfirmationOutcome::Confirmed => {
						settle_offboard(
							wallet, offboard_vtxo_ids, movement_id, offboard_txid,
						).await?;
						Ok(Advance::Done)
					},
					ConfirmationOutcome::Pending => {
						Ok(Advance::Park {
							state: self,
							wake_after: Some(CONFIRMATION_POLL_INTERVAL),
							error: None,
						})
					},
					ConfirmationOutcome::Lost => {
						// The forfeits only become valid once the offboard tx
						// confirms (they spend one of its outputs), but the
						// server holds the fully signed tx and can commit it
						// at any time — so the inputs cannot be released.
						let error = anyhow!(
							"offboard tx {} has not been seen on chain since {}; \
							the server can still commit the signed tx, making the \
							forfeits valid, so the inputs stay locked; \
							will keep checking, but manual intervention may be needed",
							offboard_txid, created_at,
						);
						error!("{:#}", error);
						Ok(Advance::Park {
							state: self,
							wake_after: None,
							error: Some(error.into()),
						})
					},
				}
			},
		};

		Ok(Advance::Next(Offboard { progress: new_progress, ..self }))
	}

	/// The inputs, then the exact-sized VTXOs and their change while the
	/// split is being registered, then the VTXOs being offboarded. Nothing
	/// once the offboard transaction is on the network: the sats are the
	/// on-chain wallet's from then on.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		match &self.progress {
			Progress::Start | Progress::SplitWithArkoor | Progress::ArkoorCreated { .. } => {
				self.kind.vtxo_ids().clone()
			},
			Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids } => {
				offboard_vtxo_ids.iter().chain(change_vtxo_ids).copied().collect()
			},
			Progress::ReadyForOffboard { offboard_vtxo_ids, .. }
				| Progress::OffboardTxPrepared { offboard_vtxo_ids, .. }
				| Progress::ForfeitsPrepared { offboard_vtxo_ids, .. }
				| Progress::ReadyForBroadcast { offboard_vtxo_ids, .. }
			=> offboard_vtxo_ids.clone(),
			Progress::AwaitingConfirmations { .. } => Vec::new(),
		}
	}

	async fn on_retry(
		self,
		_wallet: &Wallet,
		attempts: u32,
		err: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		match self.progress {
			Progress::Start => {
				let error = anyhow::Error::from(err).context("Unable to lock VTXOs");
				return Ok(Advance::Failed(error));
			},
			Progress::SplitWithArkoor |
			Progress::ArkoorCreated { .. } |
			Progress::ArkoorRegistrationRequired { .. } |
			Progress::ReadyForOffboard { .. } |
			Progress::OffboardTxPrepared { .. } |
			Progress::ForfeitsPrepared { .. } |
			Progress::ReadyForBroadcast { .. } |
			Progress::AwaitingConfirmations { .. } => {},
		}
		// Park with backoff like the default, but surface the error: the
		// user-facing offboard call drives UntilParkOrDone and should report
		// what actually failed (e.g. the server being short on confirmed
		// funds), not a generic "parked" message. The checkpoint still
		// persists and the sync loop retries regardless.
		let delay = attempts.pow(2) * BASE_RETRY_BACKOFF;
		Ok(Advance::Park { state: self, wake_after: Some(delay), error: Some(err) })
	}

	async fn on_rejection(
		self,
		wallet: &Wallet,
		error: AdvanceError,
	) -> anyhow::Result<Advance<Self>> {
		match &self.progress {
			Progress::Start | Progress::AwaitingConfirmations { .. } => {
				debug_assert!(false, "server cannot reject here");
				error!("Rejection should be impossible here: {:#}", error);
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: None,
					error: Some(error.into())
				})
			},
			Progress::SplitWithArkoor | Progress::ArkoorCreated { .. } => {
				// A preparatory arkoor may have completed before persistence failed.
				// Keep its old position locked rather than risk a conflicting retry.
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: None,
					error: Some(error),
				})
			},
			Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, .. } |
			Progress::ReadyForBroadcast {  offboard_vtxo_ids, .. } => {
				// TODO: should we auto-exit here ?
				error!("Server rejected VTXOs, consider exiting: {:?}", offboard_vtxo_ids);
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: None,
					error: Some(error.into())
				})
			},
			Progress::ReadyForOffboard { offboard_vtxo_ids, prior_txid: Some(prior_txid) } => {
				// We already fell back here once from OffboardTxPrepared:
				// our finish session had disappeared and its tx wasn't
				// visible on chain. Now the fresh prepare got rejected too.
				if let Some(progress) = adopt_broadcast_offboard(
					wallet, &self, offboard_vtxo_ids, *prior_txid,
				).await? {
					return Ok(Advance::Next(Offboard { progress, ..self.clone() }));
				}
				// Any other rejection (typically: inputs already spent)
				// makes it likeliest that the prior finish DID go through
				// and our chain source simply lags the server's node. Keep
				// looking for the prior tx; failing here would wrongly
				// release forfeited vtxos as spendable.
				error!("Offboard inputs rejected but prior offboard tx {} is not on chain, \
					will keep looking for it: {:#}", prior_txid, error);
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: Some(CONFIRMATION_POLL_INTERVAL),
					error: Some(error.into()),
				})
			},
			Progress::ReadyForOffboard { prior_txid: None, .. } => {
				// Arkoor are spendable at this point, it is safe to fail here on rejection
				fail_offboard_movement(wallet, &self).await?;
				Ok(Advance::Failed(error.into()))
			},
			Progress::OffboardTxPrepared { offboard_vtxo_ids, offboard_tx, .. } |
			Progress::ForfeitsPrepared { offboard_vtxo_ids, offboard_tx, .. } => {
				// A missing session is not proof that a server discarded a share.
				// Legacy prepared checkpoints may already have sent forfeits.
				let offboard_txid = offboard_tx.compute_txid();
				if let Some(progress) = adopt_broadcast_offboard(
					wallet, &self, offboard_vtxo_ids, offboard_txid,
				).await? {
					return Ok(Advance::Next(Offboard { progress, ..self.clone() }));
				}
				warn!("Offboard session for tx {} is unavailable; retaining input locks: {:#}",
					offboard_txid, error,
				);
				Ok(Advance::Park {
					state: self.clone(),
					wake_after: Some(CONFIRMATION_POLL_INTERVAL),
					error: Some(error),
				})
			},
		}
	}
}

/// Build a fresh [`Offboard`] in [`Progress::Start`]: pick inputs (for
/// `SendOnchain`), derive the offboard key (for `SendOnchain`), validate fee/dust
/// constraints, and lock the inputs under the new action id.
///
/// The executor persists the returned state. Idempotent under re-run
/// only if no checkpoint exists yet for this offboard (the caller is
/// responsible for the existence check).
pub(crate) async fn start_offboard(
	wallet: &Wallet,
	destination: bitcoin::Address,
	spec: StartOffboardSpec,
) -> anyhow::Result<Offboard> {
	let (srv, ark) = wallet.require_server().await?;
	let offboard_feerate = srv.offboard_feerate().await?;
	let tip = wallet.inner.chain.tip().await?;
	let destination_spk = destination.script_pubkey();
	let dust = destination_spk.minimal_non_dust();
	let id = {
		let bytes: [u8; 16] = rand::random();
		bytes.as_hex().to_string()
	};

	let (net_amount, fee, kind) = match spec {
		StartOffboardSpec::OffboardWhole { vtxos } => {
			if vtxos.len() > srv.ark_info().await.max_offboard_inputs {
				bail!(
					"max inputs for offboard is {}, {} were provided",
					srv.ark_info().await.max_offboard_inputs, vtxos.len(),
				);
			}
			// The input VTXOs were issued by the server: never `sum`, which
			// panics on forged large amounts.
			let vtxos_amount = crate::utils::checked_sum_amounts(vtxos.iter().map(|v| v.amount()))
				.context("offboard input amounts overflow")?;
			let fee = ark.fees.offboard.calculate(
				&destination_spk, vtxos_amount, offboard_feerate,
				vtxos.iter().map(|v| VtxoFeeInfo::from_vtxo_and_tip(v, tip)),
			).context("error calculating offboard fee")?;
			let net_amount = fees::validate_and_subtract_fee_min_dust(vtxos_amount, fee, dust)
				.context("offboard fee leaves dust")?;

			(net_amount, fee, OffboardKind::OffboardWhole {
				input_vtxo_ids: vtxos.iter().map(|v| v.id()).collect(),
			})
		},
		StartOffboardSpec::SendOnchain { amount } => {
			if amount < dust {
				bail!("the minimum you can send to {} is {}", destination, dust);
			}
			let (vtxos, fee) = wallet.spend_input_selection().await?
				.max_inputs(srv.ark_info().await.max_offboard_inputs)
				.fee_scheme(wallet.chain().tip().await?, |a, v| {
					ark.fees.offboard.calculate(&destination_spk, a, offboard_feerate, v)
						.ok_or_else(|| anyhow!("failed to calculate offboard fee for {}", a))
				})
				.select(wallet.spendable_vtxos().await?, amount)?;

			let (_, arkoor_key_index) = wallet.derive_store_next_signing_key().await
				.context("failed to create offboard signing key")?;
			let (_, change_key_index) = wallet.derive_store_next_signing_key().await
				.context("failed to create change signing key")?;

			// The selected input VTXOs were issued by the server: never `sum`,
			// which panics on forged large amounts.
			let input_total = crate::utils::checked_sum_amounts(vtxos.iter().map(|v| v.amount()))
				.context("selected input amounts overflow")?;
			let change = input_total.checked_sub(amount + fee)
				.context("selected inputs don't cover amount plus fee")?;

			(amount, fee, OffboardKind::SendOnchain {
				input_vtxo_ids: vtxos.iter().map(|v| v.id()).collect(),
				arkoor_key_index,
				change_key_index,
				change_pieces: Some(split_change_amount(
					change, amount + fee, wallet.config().change_vtxo_split_factor,
				)),
			})
		},
	};

	// Duplicate inputs would break forfeit signing (one nonce per input) and
	// are rejected by the server; catch them before we lock anything.
	let input_vtxo_ids_len = kind.vtxo_ids().len();
	let unique = kind.vtxo_ids().iter().collect::<HashSet<_>>();
	if input_vtxo_ids_len != unique.len() {
		bail!("offboard inputs must not contain duplicates");
	}

	Ok(Offboard {
		id,
		kind,
		destination: destination.into_unchecked(),
		onchain_output_amount: net_amount,
		committed_fee: fee,
		committed_fee_rate: offboard_feerate,
		progress: Progress::Start,
	})
}

/// Locks the VTXOs, ready for the next step which differs based on the [OffboardKind].
async fn lock_vtxos(
	wallet: &Wallet,
	action: &Offboard,
) -> Result<Progress, AdvanceError> {
	wallet.lock_vtxos(
		action.kind.vtxo_ids(),
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await?;
	match &action.kind {
		OffboardKind::OffboardWhole { input_vtxo_ids } => {
			Ok(Progress::ReadyForOffboard {
				offboard_vtxo_ids: input_vtxo_ids.clone(),
				prior_txid: None,
			})
		},
		OffboardKind::SendOnchain { .. } => {
			Ok(Progress::SplitWithArkoor)
		},
	}
}

/// Split the inputs into an exact-sized offboard vtxo plus change and record the `SendOnchain`
/// movement.
async fn arkoor_split_offboard(
	wallet: &Wallet,
	action: &Offboard,
) -> Result<Progress, AdvanceError> {
	if let Some(WalletActionCheckpoint::Offboard(stored)) =
		wallet.inner.db.get_wallet_action_checkpoint(&action.id).await?
	{
		if matches!(stored.progress, Progress::ArkoorCreated { .. }) {
			return Ok(stored.progress);
		}
	}
	let OffboardKind::SendOnchain {
		input_vtxo_ids, arkoor_key_index, change_key_index, change_pieces,
	} = &action.kind
	else {
		return Err(anyhow!("arkoor_split_offboard called for non-SendOnchain kind").into());
	};

	let mut inputs = Vec::with_capacity(input_vtxo_ids.len());
	for id in input_vtxo_ids {
		inputs.push(wallet.get_vtxo_by_id(*id).await
			.context("failed to load offboard input vtxo")?);
	}

	// The persistent ownership keys fix the offboard and change destinations.
	let required_amount = action.onchain_output_amount + action.committed_fee;
	let key = wallet.peek_signing_key(*arkoor_key_index).await
		.context("failed to load signing key for offboard action")?;
	let change_key = wallet.peek_signing_key(*change_key_index).await
		.context("failed to load change signing key for offboard action")?;
	let split_destination = ArkoorDestination {
		total_amount: required_amount,
		policy: VtxoPolicy::new_pubkey(key.public_key()),
	};
	let arkoor = wallet
		.create_checkpointed_arkoor_with_vtxos(
			split_destination, inputs.into_iter(), change_key.public_key(), change_pieces.clone(),
		)
		.await
		.context("error preparing offboard vtxos with arkoor")?;
	let progress = Progress::ArkoorCreated { created: arkoor.created, change: arkoor.change };
	let checkpoint = WalletActionCheckpoint::Offboard(Offboard {
		progress: progress.clone(), ..action.clone()
	});
	wallet.inner.db.upsert_wallet_action_checkpoint(&action.id, &checkpoint).await?;
	Ok(progress)
}

/// Merge recovery witnesses and store only the already-checkpointed split bytes.
async fn store_arkoor_split(
	wallet: &Wallet,
	action: &Offboard,
	created: Vec<Vtxo<Full>>,
	change: Vec<Vtxo<Full>>,
) -> Result<Progress, AdvanceError> {
	wallet.ensure_program_recoveries(&created).await
		.context("offboard output recovery is not ready")?;
	wallet.ensure_program_recoveries(&change).await
		.context("offboard change recovery is not ready")?;

	// The server has marked our VTXOs as spent, so we must update accordingly.
	// Both the offboard vtxo and the change are held under the action until
	// the registration step registers their tx chains with the server; only
	// then is the change released as spendable (the offboard vtxo stays
	// locked until it is forfeited).
	wallet.store_locked_vtxos(
		&change,
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await.context("error storing change vtxos from preparatory arkoor")?;
	wallet.store_locked_vtxos(
		&created,
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await.context("error storing offboard vtxos from preparatory arkoor")?;
	wallet.mark_vtxos_as_spent(action.kind.vtxo_ids()).await
		.context("error marking offboard inputs as spent")?;

	// Create the movement early since we just performed an operation.
	let offboard_vtxo_ids = created.iter().map(|v| v.id()).collect::<Vec<_>>();
	let change_vtxo_ids = change.iter().map(|v| v.id()).collect::<Vec<_>>();
	get_or_create_movement(
		wallet, action, &offboard_vtxo_ids, change_vtxo_ids.iter().copied(),
	).await?;

	Ok(Progress::ArkoorRegistrationRequired { offboard_vtxo_ids, change_vtxo_ids })
}

/// Registers the new arkoor VTXOs (both the offboard vtxos and the change)
/// with the server, then releases the change as spendable. The offboard
/// vtxos stay locked until they are forfeited.
async fn register_arkoor_split(
	wallet: &Wallet,
	action: &Offboard,
	offboard_vtxo_ids: Vec<VtxoId>,
	change_vtxo_ids: Vec<VtxoId>,
) -> Result<Progress, AdvanceError> {
	let to_register = offboard_vtxo_ids.iter().chain(&change_vtxo_ids).copied().collect::<Vec<_>>();
	let full_vtxos = wallet.inner.db.get_full_vtxos(&to_register).await
		.context("failed to hydrate arkoor split vtxos")?;

	wallet.ensure_program_recoveries(&full_vtxos).await
		.context("offboard split recovery is not ready")?;
	wallet.register_vtxo_transactions_with_server(&full_vtxos).await
		.context("failed to register arkoor split vtxo transactions with server")?;

	// Registration succeeded, so the change is safe to spend now.
	wallet.unlock_vtxos(
		&change_vtxo_ids,
		Some(VtxoLockHolder::Action { id: action.id.clone() }),
	).await.context("failed to unlock change vtxos after registration")?;

	Ok(Progress::ReadyForOffboard { offboard_vtxo_ids, prior_txid: None })
}

/// `ReadyForOffboard -> OffboardTxPrepared`: have the server build the
/// offboard tx, validate it and record the movement (for `SendOnchain`
/// it already exists from the arkoor split).
///
/// Server-side `prepare_offboard` is idempotent as long as we re-send the exact same request
/// (inputs, amounts, fee rate): the server replays its pending session, returning the same
/// unsigned tx and the same cosign nonces.
async fn prepare_offboard(
	wallet: &Wallet,
	action: &Offboard,
	mut offboard_vtxo_ids: Vec<VtxoId>,
) -> Result<Progress, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;

	// Ensure the request remains deterministic and thus reentrant by sorting the offboard inputs.
	offboard_vtxo_ids.sort_unstable();
	debug_assert!(
		offboard_vtxo_ids.windows(2).all(|w| w[0] != w[1]),
		"offboard inputs must not contain duplicates",
	);
	let vtxos = wallet.inner.db.get_full_vtxos(&offboard_vtxo_ids).await
		.context("failed to load offboard input vtxos")?;
	debug_assert!(
		vtxos.iter().map(|v| v.id()).eq(offboard_vtxo_ids.iter().copied()),
		"get_full_vtxos should return inputs in the exact same order",
	);

	// Build the request, we can skip recalculating fees because the user already committed to a
	// fee structure, the server will reject invalid fees so we can safely unlock our inputs if
	// our numbers differ later on. This will fail the payment and the user can try again if they
	// find the new fees acceptable.
	let destination = action.check_destination(wallet.network().await?)?;
	let destination_spk = destination.script_pubkey();
	let req = OffboardRequest {
		script_pubkey: destination_spk,
		net_amount: action.onchain_output_amount,
		deduct_fees_from_gross_amount: action.kind.deduct_fees_from_gross_amount(),
		fee_rate: action.committed_fee_rate,
	};
	let attestation = {
		let mut attestations = Vec::with_capacity(vtxos.len());
		for v in &vtxos {
			let key = wallet.vtxo_signing_key(v).await?;
			let signature = wallet.sign_vtxo_ownership(&key, OwnershipRequest {
				input: v.clone(),
				proof: OwnershipProof::Offboard {
					request: req.clone(), inputs: offboard_vtxo_ids.clone(),
				},
			}).await?;
			let att = OffboardRequestAttestation::from_signature(
				&req, &offboard_vtxo_ids, v, signature,
			).context("invalid offboard ownership signature")?.serialize();
			attestations.push(att);
		}
		attestations
	};

	// Finally, we can make the request; this is idempotent ONLY if our request is deterministic. If
	// the server rejects this, we can safely unlock our funds.
	let prep_resp = srv.client.prepare_offboard(protos::PrepareOffboardRequest {
		offboard: Some(req.clone().into()),
		input_vtxo_ids: offboard_vtxo_ids.iter()
			.map(|id| id.to_bytes().to_vec())
			.collect(),
		attestation,
	}).await.map_err(AdvanceError::Server)?.into_inner();

	let unsigned_tx = bitcoin::consensus::deserialize::<Transaction>(&prep_resp.offboard_tx)
		.with_context(|| format!("received invalid unsigned offboard tx from server: {}",
			prep_resp.offboard_tx.as_hex(),
		))?;
	let offboard_txid = unsigned_tx.compute_txid();
	let ctx = OffboardForfeitContext::new(&vtxos, &unsigned_tx)
		.context("no offboard inputs")?;
	ctx.validate_offboard_tx(&req).context("received invalid offboard tx from server")?;
	info!("Received unsigned offboard tx {} from server", offboard_txid);

	// A replayed prepare returns the same cosign nonces, so this
	// checkpoint is identical no matter how often the step re-runs.
	let forfeit_cosign_nonces = prep_resp.forfeit_cosign_nonces.into_iter().map(|n| {
		musig::PublicNonce::from_bytes(&n)
			.context("received invalid public cosign nonce from server")
	}).collect::<anyhow::Result<Vec<_>>>()?;

	// Signing needs one nonce per input, so a response carrying any other
	// number is unusable. Reject it here, before the checkpoint below makes
	// it durable: a persisted mismatch would fail this action on every
	// re-drive, and taking the sync loop's offboard step down with it stops
	// the steps that run after it from ever being reached.
	OffboardForfeitError::check_count(
		"forfeit cosign nonces", vtxos.len(), forfeit_cosign_nonces.len(),
	).context("invalid prepare_offboard response from server")?;

	// We can safely ignore the change in the movement because `SendOnchain` has already had a
	// movement created for it.
	let movement_id = get_or_create_movement(
		wallet, action, &offboard_vtxo_ids, iter::empty::<VtxoId>(),
	).await?;
	Ok(Progress::OffboardTxPrepared {
		offboard_vtxo_ids,
		offboard_tx: unsigned_tx,
		forfeit_cosign_nonces,
		movement_id,
		forfeits_unsent: true,
	})
}

/// Authorize exact forfeits locally and checkpoint their public shares before send.
async fn prepare_offboard_forfeits(
	wallet: &Wallet,
	action: &Offboard,
	offboard_vtxo_ids: Vec<VtxoId>,
	offboard_tx: Transaction,
	server_forfeit_cosign_nonces: Vec<musig::PublicNonce>,
	movement_id: MovementId,
) -> Result<Progress, AdvanceError> {
	if let Some(WalletActionCheckpoint::Offboard(stored)) =
		wallet.inner.db.get_wallet_action_checkpoint(&action.id).await?
	{
		if matches!(stored.progress, Progress::ForfeitsPrepared { .. }) {
			return Ok(stored.progress);
		}
	}

	let full_inputs = wallet.inner.db.get_full_vtxos(&offboard_vtxo_ids).await
		.context("failed to hydrate offboard input vtxos")?;
	debug_assert!(
		full_inputs.iter().map(|v| v.id()).eq(offboard_vtxo_ids.iter().copied()),
		"get_full_vtxos should return inputs in the exact same order",
	);
	wallet.ensure_program_recoveries(&full_inputs).await
		.context("old offboard position recovery is not ready")?;
	let ctx = OffboardForfeitContext::new(&full_inputs, &offboard_tx)
		.context("no offboard inputs")?;
	ctx.validate_offboard_tx(&OffboardRequest {
		script_pubkey: action.check_destination(wallet.network().await?)?.script_pubkey(),
		net_amount: action.onchain_output_amount,
		deduct_fees_from_gross_amount: action.kind.deduct_fees_from_gross_amount(),
		fee_rate: action.committed_fee_rate,
	}).context("stored offboard transaction does not match the request")?;
	OffboardForfeitError::check_count(
		"forfeit cosign nonces", full_inputs.len(), server_forfeit_cosign_nonces.len(),
	).context("stored offboard has an unusable set of forfeit cosign nonces")?;
	let mut user_nonces = Vec::with_capacity(full_inputs.len());
	let mut user_shares = Vec::with_capacity(full_inputs.len());
	let contexts = ctx.signing_inputs().context("invalid offboard forfeit signing inputs")?;
	for ((vtxo, input), server_nonce) in full_inputs.iter().zip(contexts)
		.zip(server_forfeit_cosign_nonces.iter())
	{
		let key = wallet.vtxo_signing_key(vtxo).await?;
		let prepared = wallet.prepare_vtxo_signature(&key, input).await
			.context("program rejected the offboard forfeit transaction")?;
		user_nonces.push(prepared.public_nonce());
		user_shares.push(prepared.finish(&key, Some(server_nonce.clone()), None).await?
			.user_partial);
	}
	let sigs = ctx.assemble_external_forfeits(
		&server_forfeit_cosign_nonces, user_nonces, user_shares,
	).context("invalid externally signed offboard forfeits")?;
	let progress = Progress::ForfeitsPrepared {
		offboard_vtxo_ids, offboard_tx, movement_id,
		user_nonces: sigs.public_nonces,
		partial_signatures: sigs.partial_signatures.iter().map(|s| s.serialize()).collect(),
	};
	let checkpoint = WalletActionCheckpoint::Offboard(Offboard {
		progress: progress.clone(), ..action.clone()
	});
	wallet.inner.db.upsert_wallet_action_checkpoint(&action.id, &checkpoint).await?;
	Ok(progress)
}

/// Replay durable shares and trade them for the server-signed offboard transaction.
async fn finish_offboard(
	wallet: &Wallet,
	offboard_vtxo_ids: Vec<VtxoId>,
	offboard_tx: Transaction,
	user_nonces: Vec<musig::PublicNonce>,
	partial_signatures: Vec<[u8; 32]>,
	movement_id: MovementId,
) -> Result<Progress, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;
	let inputs = wallet.inner.db.get_full_vtxos(&offboard_vtxo_ids).await?;
	wallet.ensure_program_recoveries(&inputs).await
		.context("old offboard position recovery is not ready")?;

	let offboard_txid = offboard_tx.compute_txid();
	let finish_resp = srv.client.finish_offboard(protos::FinishOffboardRequest {
		offboard_txid: offboard_txid.as_byte_array().to_vec(),
		user_nonces: user_nonces.iter()
			.map(|n| n.serialize().to_vec())
			.collect(),
		partial_signatures: partial_signatures.iter().map(|s| s.to_vec()).collect(),
	}).await.map_err(AdvanceError::Server)?.into_inner();

	let signed_offboard_tx = bitcoin::consensus::deserialize::<Transaction>(
		&finish_resp.signed_offboard_tx,
	).with_context(|| format!(
		"received invalid offboard tx from server: {}", finish_resp.signed_offboard_tx.as_hex(),
	))?;
	if signed_offboard_tx.compute_txid() != offboard_txid {
		return Err(anyhow!("Signed offboard tx received from server is different from \
			unsigned tx we forfeited for: unsigned={}, signed={}",
			serialize_hex(&offboard_tx), finish_resp.signed_offboard_tx.as_hex(),
		).into());
	}
	// The txid pins everything except the witnesses, so checking every
	// input carries one is all that remains to prove the server signed
	// the tx. The signatures themselves can't be validated: the inputs
	// spend the server's own wallet utxos, whose prevouts we don't have.
	if signed_offboard_tx.input.iter().any(|i| i.witness.is_empty() && i.script_sig.is_empty()) {
		return Err(anyhow!("Signed offboard tx received from server has an unsigned input: {}",
			finish_resp.signed_offboard_tx.as_hex(),
		).into());
	}

	wallet.inner.movements.update_movement(
		movement_id,
		MovementUpdate::new().metadata(OffboardMovement::metadata(&signed_offboard_tx)),
	).await.context("failed to update movement with offboard tx")?;

	Ok(Progress::ReadyForBroadcast { offboard_vtxo_ids, signed_offboard_tx, movement_id })
}


/// Check whether the offboard tx made it to the mempool or chain even
/// though the server no longer holds a session for it (the server also
/// broadcasts the tx itself after a successful finish). If so, return an
/// [Progress::AwaitingConfirmations] adopting the broadcast tx.
///
/// Used by rejection recovery, so it must be re-entrant; it only reads
/// the chain and (re-)uses the movement keyed by the action id.
async fn adopt_broadcast_offboard(
	wallet: &Wallet,
	action: &Offboard,
	offboard_vtxo_ids: &Vec<VtxoId>,
	offboard_txid: Txid,
) -> anyhow::Result<Option<Progress>> {
	let tx = wallet.inner.chain.get_tx(&offboard_txid).await
		.with_context(|| format!("failed to look up offboard tx {} on chain", offboard_txid))?;
	let Some(offboard_tx) = tx else {
		return Ok(None);
	};

	info!("Found offboard tx {} on chain, adopting it", offboard_txid);
	let movement_id = get_or_create_movement(
		wallet, action, offboard_vtxo_ids, iter::empty::<VtxoId>(),
	).await?;
	Ok(Some(Progress::AwaitingConfirmations {
		offboard_vtxo_ids: offboard_vtxo_ids.to_vec(),
		offboard_txid,
		offboard_tx,
		movement_id,
		created_at: chrono::Utc::now(),
	}))
}

/// `ReadyForBroadcast -> AwaitingConfirmations`: publish the signed offboard tx to chain.
/// Idempotent: re-broadcasting a tx already in mempool/chain is a no-op.
async fn broadcast_offboard(
	wallet: &Wallet,
	offboard_vtxo_ids: Vec<VtxoId>,
	offboard_tx: Transaction,
	movement_id: MovementId,
) -> Result<Progress, AdvanceError> {
	let inputs = wallet.inner.db.get_full_vtxos(&offboard_vtxo_ids).await?;
	wallet.ensure_program_recoveries(&inputs).await
		.context("offboard recovery is not ready for broadcast")?;
	let offboard_txid = offboard_tx.compute_txid();
	wallet.inner.chain.broadcast_tx(&offboard_tx).await.with_context(|| format!(
		"error broadcasting offboard tx {}", offboard_txid,
	))?;
	Ok(Progress::AwaitingConfirmations {
		offboard_vtxo_ids,
		offboard_txid,
		offboard_tx,
		movement_id,
		created_at: chrono::Utc::now(),
	})
}

/// `AwaitingConfirmations -> Done`: mark the forfeited vtxos as spent and
/// finalise the movement. Only called once the caller has established that
/// the tx has enough confirmations (or zero confs are required and the tx
/// is in the mempool).
async fn settle_offboard(
	wallet: &Wallet,
	offboard_vtxo_ids: &[VtxoId],
	movement_id: MovementId,
	offboard_txid: Txid,
) -> anyhow::Result<()> {
	info!("Offboard tx {} confirmed, finalizing movement {}",
		offboard_txid, movement_id);

	// The vtxos MUST all be Spent before the executor sees Done: Done
	// releases anything still locked by the action back to Spendable, and
	// these vtxos are forfeited to the server. So a failure here has to
	// propagate and retry the step rather than fall through. Spent is
	// allowed as an old state so a re-driven settle is a no-op.
	wallet.inner.db.update_vtxo_states_checked(
		offboard_vtxo_ids,
		VtxoState::Spent,
		&[VtxoStateKind::Locked, VtxoStateKind::Spent],
	).await.context("failed to mark offboard vtxos as spent")?;

	wallet.inner.movements.finish_movement(movement_id, MovementStatus::Successful).await
		.context("failed to finish offboard movement")?;
	Ok(())
}

/// Look up the current confirmation status for an offboard tx and
/// collapse it to a `ConfirmationOutcome`.
async fn check_offboard_confirmation(
	wallet: &Wallet,
	offboard_tx: &Transaction,
	created_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<ConfirmationOutcome> {
	let offboard_txid = offboard_tx.compute_txid();
	let required_confs = wallet.inner.config.offboard_required_confirmations;
	let current_height = wallet.inner.chain.tip().await
		.context("error fetching chain tip")?;
	let status = wallet.inner.chain.tx_status(offboard_txid).await;

	match status {
		Ok(TxStatus::Confirmed(block_ref)) => {
			let confs = current_height.checked_blocks_since(block_ref.height)
				.map_or(0, |confs| confs + 1);
			if confs >= required_confs.to_u32() {
				Ok(ConfirmationOutcome::Confirmed)
			} else {
				trace!(
					"Offboard tx {} has {}/{} confirmations, waiting...",
					offboard_txid, confs, required_confs,
				);
				Ok(ConfirmationOutcome::Pending)
			}
		},
		Ok(TxStatus::Mempool) => {
			if required_confs == BlockDelta::ZERO {
				Ok(ConfirmationOutcome::Confirmed)
			} else {
				trace!("Offboard tx {} still in mempool, waiting...", offboard_txid);
				Ok(ConfirmationOutcome::Pending)
			}
		},
		Ok(TxStatus::NotFound) => {
			let age = chrono::Utc::now() - created_at;
			let grace_period = chrono::Duration::seconds(
				wallet.inner.config.offboard_lost_tx_grace_period_secs as i64,
			);
			if age > grace_period {
				return Ok(ConfirmationOutcome::Lost);
			}
			trace!("Offboard tx {} not found — re-broadcasting...", offboard_txid);
			wallet.inner.chain.broadcast_tx(&offboard_tx).await.with_context(|| format!(
				"error broadcasting offboard tx {}", offboard_txid,
			))?;
			Ok(ConfirmationOutcome::Pending)
		},
		Err(e) => {
			warn!("Failed to check status of offboard tx {}: {:#}", offboard_txid, e);
			Ok(ConfirmationOutcome::Pending)
		},
	}
}

/// Creates a movement for the offboard action based on the [OffboardKind].
async fn get_or_create_movement(
	wallet: &Wallet,
	action: &Offboard,
	offboard_vtxo_ids: &Vec<VtxoId>,
	change: impl IntoIterator<Item = impl VtxoRef>,
) -> anyhow::Result<MovementId> {
	let destination = action.check_destination(wallet.network().await?)?;
	let net = action.onchain_output_amount;
	let required = net.checked_add(action.committed_fee).context("overflow")?;
	match &action.kind {
		OffboardKind::OffboardWhole { .. } => {
			let effective_amt = -SignedAmount::try_from(required)
				.context("can't have this many vtxo sats")?;
			wallet.inner.movements.get_or_create_movement_with_action(
				Subsystem::OFFBOARD,
				OffboardMovement::Offboard.to_string(),
				&action.id,
				MovementUpdate::new()
					.intended_balance(effective_amt)
					.effective_balance(effective_amt)
					.fee(action.committed_fee)
					.consumed_vtxos(offboard_vtxo_ids)
					.sent_to([MovementDestination::bitcoin(destination, net)]),
			).await.context("failed to create offboard movement")
		},
		OffboardKind::SendOnchain { input_vtxo_ids, .. } => {
			wallet.inner.movements.get_or_create_movement_with_action(
				Subsystem::OFFBOARD,
				OffboardMovement::SendOnchain.to_string(),
				&action.id,
				MovementUpdate::new()
					.intended_balance(-net.to_signed().context("amount out of range")?)
					.effective_balance(-required.to_signed().context("required amount out of range")?)
					.fee(action.committed_fee)
					.consumed_vtxos(input_vtxo_ids)
					.produced_vtxos(change)
					.metadata([(
						"offboard_vtxos".into(),
						serde_json::to_value(offboard_vtxo_ids).expect("offboard_vtxos can serde"),
					)])
					.sent_to([MovementDestination::bitcoin(destination, net)]),
			).await.context("failed to create send-onchain movement")
		}
	}
}

/// Record the action's movement as failed before the action fails
/// terminally; without this, `Advance::Failed` removes the checkpoint but
/// leaves the movement pending forever.
///
/// The movement is keyed by the action id, so an attempt that had already
/// created one (`SendOnchain` after its arkoor, `OffboardWhole` after
/// prepare) finds it back; an attempt that hadn't gets a failed movement
/// recording what it tried to do. Both make this re-entrant.
async fn fail_offboard_movement(
	wallet: &Wallet,
	action: &Offboard,
) -> anyhow::Result<()> {
	let offboard_vtxo_ids = action.kind.vtxo_ids();
	let movement_id = get_or_create_movement(
		wallet, action, offboard_vtxo_ids, iter::empty::<VtxoId>(),
	).await?;
	// The balance didn't actually change: we only fail on paths where no
	// forfeit was signed and nothing was broadcast, so every vtxo the
	// action locked goes back to spendable.
	wallet.inner.movements.finish_movement_with_update(
		movement_id,
		MovementStatus::Failed,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await.context("failed to mark offboard movement as failed")
}
