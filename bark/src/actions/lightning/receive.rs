//! State machine for incoming lightning payments.
//!
//! Identity (`invoice`, `payment_hash`, `payment_preimage`) and the
//! parameters fixed at invoice creation (htlc claim cltv delta, anti-dos
//! token) live on the action as top-level fields; the mutable bit is
//! [`Progress`], representing the current phase of the state machine.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, SignedAmount};
use lightning_invoice::Bolt11Invoice;
use log::{debug, error, info, trace, warn};
use rand::seq::IteratorRandom;

use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::LightningReceiveAttestation;
use ark::fees::validate_and_subtract_fee;
use ark::lightning::{Bolt11InvoiceExt, PaymentHash, Preimage};
use ark::sapio::protocol::{OwnershipProof, OwnershipRequest};
use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_rpc::protos;
use server_rpc::protos::prepare_lightning_receive_claim_request::LightningReceiveAntiDos;

use crate::{Config, Wallet};
use crate::actions::{
	Advance, AdvanceError, BASE_RETRY_BACKOFF, WalletAction, WalletActionId, park_with_backoff,
};
use crate::arkoor::{DeliveryOutcome, post_arkoor_to_mailboxes};
use crate::movement::update::MovementUpdate;
use crate::movement::{MovementDestination, MovementId, MovementStatus};
use crate::persist::models::SettledLightningReceive;
use crate::subsystem::{LightningMovement, LightningReceiveMovement, Subsystem};
use crate::vtxo::{validate_vtxo_tree_params, VtxoLockHolder, VtxoState};

const LN_RECV_NAMESPACE: &str = "ln_recv";

/// Leniency delta to allow claim when blocks were mined between htlc
/// receive and claim preparation.
const LIGHTNING_PREPARE_CLAIM_DELTA: BlockDelta = BlockDelta::new(2);

/// How long to sleep between polls while waiting for an inbound payment
const AWAITING_PAYMENT_POLL_INTERVAL: Duration = Duration::from_secs(4);

/// Grace past the bolt11 invoice expiry before an unpaid receive is
/// reaped, to avoid racing a payment that lands right at the boundary.
const INVOICE_EXPIRY_GRACE: Duration = Duration::from_secs(60);

pub(crate) fn ln_recv_action_id(payment_hash: PaymentHash) -> WalletActionId {
	format!("{LN_RECV_NAMESPACE}.{payment_hash}")
}

fn validate_bolt11_payment_hash(
	invoice: &Bolt11Invoice,
	expected_payment_hash: PaymentHash,
) -> anyhow::Result<()> {
	let invoice_payment_hash = PaymentHash::from(invoice);
	ensure!(
		invoice_payment_hash == expected_payment_hash,
		"Ark server returned invoice with payment hash {}, expected {}",
		invoice_payment_hash,
		expected_payment_hash,
	);

	Ok(())
}

/// An incoming lightning payment, persisted as a single checkpoint row
/// stored at invoice creation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightningReceive {
	// Set at invoice creation, immutable thereafter:
	pub invoice: Bolt11Invoice,
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub htlc_recv_cltv_delta: BlockDelta,
	pub anti_dos_token: Option<String>,
	#[serde(default)]
	pub claim_destination: Option<ark::Address>,
	/// Index of the wallet key backing the HTLC-recv vtxo and, for local
	/// receives, the claim output.
	pub key_index: u32,

	// Mutable state:
	pub progress: Progress,
}

impl LightningReceive {
	pub fn id(&self) -> WalletActionId {
		ln_recv_action_id(self.payment_hash)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for LightningReceive {
	fn id(&self) -> WalletActionId { LightningReceive::id(self) }

	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let mut preimage_revealed = false;
		let new_progress = match self.progress.clone() {
			Progress::AwaitingPayment => {
				match check_incoming_lightning_payment(wallet, &self).await? {
					IncomingStatus::Pending => {
						if invoice_expired(&self.invoice) {
							info!("Removing unpaid expired lightning receive {}", self.payment_hash);
							return Ok(Advance::Done);
						}
						return Ok(Advance::Park {
							state: self,
							wake_after: Some(AWAITING_PAYMENT_POLL_INTERVAL),
							error: None,
						});
					},
					IncomingStatus::Canceled => {
						let err = anyhow!("Lightning receive {} canceled server-side", self.payment_hash);
						return Ok(Advance::Failed(err));
					},
					IncomingStatus::Ready => {
						match prepare_lightning_receive_htlcs(wallet, &self).await? {
							Grant::Accepted(htlcs) => Progress::HtlcsReady(htlcs),
							Grant::Rejected(err) => {
								error!("Rejecting the HTLC vtxos granted for lightning receive {}: {:#}",
									self.payment_hash, err);
								return Ok(Advance::Failed(err));
							},
						}
					},
				}
			},
			Progress::HtlcsReady(htlcs) => {
				// Preimage not revealed yet: if we can no longer finish a
				// unilateral claim in time, abandon rather than commit.
				if is_htlc_claim_window_closed(wallet, &htlcs).await? {
					abandon_lightning_receive(wallet, &self, &htlcs).await?;
					return Ok(Advance::Done);
				}

				match claim_lightning_receive_htlcs(wallet, &self, &htlcs, &mut preimage_revealed).await {
					Ok(delivery) => Progress::Delivering(delivery),
					Err(e) => {
						if preimage_revealed {
							// Preimage is out but a post-reveal step failed. Park
							// past the point of no return (PreimageRevealed never
							// abandons) and retry the idempotent claim later.
							warn!("lightning receive {} failed after revealing preimage, \
								retrying claim: {:#}", self.payment_hash, e);
							return Ok(Advance::Park {
								state: LightningReceive {
									progress: Progress::PreimageRevealed(htlcs),
									..self
								},
								wake_after: Some(BASE_RETRY_BACKOFF),
								error: None,
							});
						} else {
							return Err(e);
						}
					},
				}
			},
			Progress::PreimageRevealed(htlcs) => {
				Progress::Delivering(
					claim_lightning_receive_htlcs(wallet, &self, &htlcs, &mut preimage_revealed).await?,
				)
			},
			Progress::Delivering(delivery) => {
				deliver_lightning_receive(wallet, &self, &delivery).await?;
				return Ok(Advance::Done);
			},
		};

		Ok(Advance::Next(LightningReceive { progress: new_progress, ..self }))
	}

	/// The HTLCs once the preimage has been revealed. Completed claim outputs
	/// remain in the checkpoint until registration and local storage or delivery.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		match &self.progress {
			Progress::PreimageRevealed(htlcs) => htlcs.vtxo_ids.clone(),
			Progress::Delivering(delivery) => delivery.input_vtxo_ids.clone(),
			Progress::AwaitingPayment
				| Progress::HtlcsReady(_)
			=> Vec::new(),
		}
	}

	async fn on_retry(self, wallet: &Wallet, retries: u32, error: AdvanceError)
		-> anyhow::Result<Advance<Self>>
	{
		match self.progress.clone() {
			// No money committed; just back off. Expiry reaping happens in advance.
			Progress::AwaitingPayment => {
				Ok(park_with_backoff(self, retries, Some(error)))
			},
			Progress::HtlcsReady(htlcs) => {
				if is_htlc_claim_window_closed(wallet, &htlcs).await? {
					abandon_lightning_receive(wallet, &self, &htlcs).await?;
					let err = anyhow!("HTLC claim window closed, abandoning");
					return Ok(Advance::Failed(err));
				}
				Ok(park_with_backoff(self, retries, Some(error)))
			},
			Progress::PreimageRevealed(_) | Progress::Delivering(_) => {
				let budget = u32::from(wallet.config().lightning_receive_claim_retries);
				if retries >= budget {
					let err = anyhow!("lightning receive claim retry budget exhausted");
					return Ok(Advance::Park { state: self, wake_after: None, error: Some(err.into()) });
				}
				Ok(park_with_backoff(self, retries, None))
			},
		}
	}

	async fn on_rejection(self, wallet: &Wallet, error: AdvanceError) -> anyhow::Result<Advance<Self>> {
		match self.progress.clone() {
			// The executor removes the row under its existing action lock and
			// surfaces the original error.
			Progress::AwaitingPayment => {
				let id = self.id();
				error!("Could not start lightning receive {}: {:?}", id, error);
				Ok(Advance::Failed(error.into()))
			},
			// Preimage not revealed yet: abandon locally (the inbound HTLC
			// times out and the sender is refunded).
			Progress::HtlcsReady(htlcs) => {
				error!("Server rejected lightning receive claim before preimage disclosure, abandoning");
				abandon_lightning_receive(wallet, &self, &htlcs).await?;
				Ok(Advance::Failed(error.into()))
			},
			Progress::PreimageRevealed(_) | Progress::Delivering(_) => {
				Ok(Advance::Park { state: self, wake_after: None, error: Some(error) })
			},
		}
	}
}

/// The phases of an incoming lightning receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Invoice created, waiting for an inbound HTLC. No money yet.
	AwaitingPayment,
	/// Server prepared HTLC-recv vtxos; we hold them locked and the
	/// movement is created. The preimage has NOT been revealed yet, so the
	/// receive is still cancellable.
	HtlcsReady(Htlcs),
	/// The preimage has been revealed via the claim RPC in
	/// exchange of pubkey VTXOs.
	/// Past the point of no return — the receive can no longer be
	/// cancelled. On failure we leave it pending rather than auto-exit;
	/// the caller falls back to an on-chain exit via
	/// `Wallet::attempt_lightning_receive_exit`.
	PreimageRevealed(Htlcs),
	/// Exact signed claim outputs awaiting registration and local settlement or
	/// coordinated/mailbox delivery. Retries reuse these checkpointed signatures.
	Delivering(Delivery),
}

/// A handle for the HTLC-recv vtxos the server granted us
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Htlcs {
	/// The VTXO IDs of the HTLC-recv vtxos
	pub vtxo_ids: Vec<VtxoId>,
	/// The ID of the ongoing movement
	pub movement_id: MovementId,
}

/// The result of asking the server to grant HTLC-recv vtxos.
pub(crate) enum Grant {
	/// The server granted vtxos we're willing to claim against.
	Accepted(Htlcs),
	/// The granted vtxos don't match what we asked for, so we reject them
	/// instead of claiming against them.
	Rejected(anyhow::Error),
}

/// The exact cosigned claim outputs awaiting registration and settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
	/// Signed claim outputs, owned locally or by the requested destination.
	#[serde(with = "ark::encode::serde::vec")]
	pub vtxos: Vec<Vtxo<Full>>,
	/// The ID of the ongoing movement
	pub movement_id: MovementId,
	/// HTLC inputs consumed only after this signed-output checkpoint is durable.
	#[serde(default)]
	pub input_vtxo_ids: Vec<VtxoId>,
}

/// Triage of a payment hash on the receive side, mirroring
/// [`LightningSendState`](crate::actions::lightning::pay::LightningSendState):
/// settled (permanent record), in-progress (live checkpoint), or unknown.
#[derive(Debug, Clone)]
pub enum LightningReceiveState {
	InProgress(LightningReceive),
	Settled(SettledLightningReceive),
}

/// Outcome of polling the server for an inbound payment while in
/// [`Progress::AwaitingPayment`].
pub(crate) enum IncomingStatus {
	/// No inbound HTLC yet; keep waiting.
	Pending,
	/// The server is holding HTLCs ready for us to prepare and claim.
	Ready,
	/// The server canceled the hold invoice; nothing to claim.
	Canceled,
}

/// Mint a bolt11 invoice and build a fresh [`LightningReceive`] in
/// [`Progress::AwaitingPayment`]. The executor persists the returned
/// state; the caller is responsible for checkpoint existence checks.
pub(crate) async fn start_lightning_receive(
	wallet: &Wallet,
	amount: Amount,
	description: Option<String>,
	token: Option<String>,
	claim_destination: Option<ark::Address>,
) -> anyhow::Result<LightningReceive> {
	if amount == Amount::ZERO {
		bail!("Cannot create invoice for 0 sats (this would create an explicit 0 sat invoice, not an any-amount invoice)");
	}

	if let Some(destination) = claim_destination.as_ref() {
		wallet.validate_arkoor_address(destination).await
			.context("invalid arkoor address")?;
	}

	let (mut srv, ark_info) = wallet.require_server().await?;
	let config = wallet.config();

	let fee = ark_info.fees.lightning_receive.calculate(amount).context("fee overflowed")?;
	validate_and_subtract_fee(amount, fee)?;

	// User needs to enforce the following delta:
	// - vtxo exit delta + htlc expiry delta (time to exit the vtxo before the htlc expires)
	// - vtxo exit margin (time to exit the vtxo before the htlc expires)
	// - htlc recv claim delta (time to claim the htlc before it expires)
	let requested_min_cltv_delta = ark_info.vtxo_exit_delta
		.checked_add(ark_info.htlc_expiry_delta)
		.and_then(|v| v.checked_add(config.vtxo_exit_margin))
		.and_then(|v| v.checked_add(config.htlc_recv_claim_delta))
		.and_then(|v| v.checked_add(LIGHTNING_PREPARE_CLAIM_DELTA))
		.context("HTLC CLTV delta components sum overflows")?;

	if requested_min_cltv_delta > ark_info.max_user_invoice_cltv_delta {
		bail!("HTLC CLTV delta ({}) is greater than Server's max HTLC recv CLTV delta: {}",
			requested_min_cltv_delta,
			ark_info.max_user_invoice_cltv_delta,
		);
	}

	let (_, key_index) = wallet.derive_store_next_signing_key().await?;

	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	info!("Start bolt11 receive with payment hash: {}", payment_hash);

	let mailbox_kp = wallet.inner.seed.to_mailbox_keypair();
	let mailbox_id = ark::mailbox::MailboxIdentifier::from_pubkey(mailbox_kp.public_key());

	let req = protos::StartLightningReceiveRequest {
		payment_hash: payment_hash.to_vec(),
		amount_sat: amount.to_sat(),
		min_cltv_delta: requested_min_cltv_delta.into(),
		mailbox_id: Some(mailbox_id.serialize()),
		description,
	};

	let resp = srv.client.start_lightning_receive(req).await?.into_inner();
	info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

	let invoice = Bolt11Invoice::from_str(&resp.bolt11)
		.context("invalid bolt11 invoice returned by Ark server")?;
	validate_bolt11_payment_hash(&invoice, payment_hash)?;

	Ok(LightningReceive {
		invoice,
		payment_hash,
		payment_preimage: preimage,
		htlc_recv_cltv_delta: requested_min_cltv_delta,
		anti_dos_token: token,
		claim_destination,
		key_index,
		progress: Progress::AwaitingPayment,
	})
}

/// Build the anti-dos proof for a claim: an explicit token if the caller
/// supplied one, otherwise an attestation over an owned vtxo.
pub(crate) async fn compute_lightning_receive_anti_dos(
	wallet: &Wallet,
	payment_hash: PaymentHash,
	token: Option<&str>,
) -> anyhow::Result<LightningReceiveAntiDos> {
	Ok(if let Some(token) = token {
		LightningReceiveAntiDos::Token(token.to_string())
	} else {
		let tip = wallet.inner.chain.tip().await?;
		// The proof vtxo isn't spent, so any unexpired one will do; pick at
		// random but keep a 2-block margin: better no proof than one that
		// expires while the claim is in flight.
		let vtxo = wallet.spendable_vtxos().await?.into_iter()
			.filter(|v| v.expiry_height() > tip + BlockDelta::new(2))
			.choose(&mut rand::rng())
			.context("have no spendable vtxo with sufficient expiry margin to prove ownership of")?;
		let input = wallet.inner.db.get_full_vtxo(vtxo.id()).await?
			.context("owned proof vtxo is missing")?;
		let key = wallet.vtxo_signing_key(&input).await?;
		let proof_vtxo = input.to_bare();
		let signature = wallet.sign_vtxo_ownership(&key, OwnershipRequest {
			input,
			proof: OwnershipProof::LightningReceive { payment_hash },
		}).await?;
		let attestation = LightningReceiveAttestation::from_signature(
			payment_hash, &proof_vtxo, signature,
		).context("invalid lightning receive ownership signature")?;
		LightningReceiveAntiDos::InputVtxo(protos::InputVtxo {
			vtxo_id: vtxo.id().to_bytes().to_vec(),
			attestation: attestation.serialize(),
		})
	})
}

/// AwaitingPayment poll: ask the server whether an inbound payment has
/// arrived without waiting.
pub(crate) async fn check_incoming_lightning_payment(
	wallet: &Wallet,
	recv: &LightningReceive,
) -> Result<IncomingStatus, AdvanceError> {
	let (mut srv, _) = wallet.require_server().await?;
	let sub = srv.client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: recv.payment_hash.to_byte_array().to_vec(),
		wait: false,
	}).await.map_err(AdvanceError::Server)?.into_inner();

	let status = protos::LightningReceiveStatus::try_from(sub.status)
		.with_context(|| format!("unknown payment status: {}", sub.status))?;
	debug!("Received status {:?} for {}", status, recv.payment_hash);

	Ok(match status {
		protos::LightningReceiveStatus::Accepted |
		protos::LightningReceiveStatus::HtlcsReady => IncomingStatus::Ready,
		protos::LightningReceiveStatus::Created => IncomingStatus::Pending,
		protos::LightningReceiveStatus::Canceled => IncomingStatus::Canceled,
		protos::LightningReceiveStatus::Settled => {
			return Err(anyhow!("payment already settled").into());
		},
	})
}

/// The number of blocks we need, counted from now, to claim an HTLC-recv
/// vtxo unilaterally once the server refuses to cosign.
fn htlc_recv_exit_blocks_needed(
	exit_delta: BlockDelta,
	htlc_expiry_delta: BlockDelta,
	config: &Config,
) -> anyhow::Result<BlockDelta> {
	exit_delta
		.checked_add(htlc_expiry_delta)
		.and_then(|v| v.checked_add(config.vtxo_exit_margin))
		.and_then(|v| v.checked_add(config.htlc_recv_claim_delta))
		.context("HTLC recv exit delta components sum overflows")
}

/// The number of blocks of life we need, counted from now, on the tree
/// backing an HTLC-recv vtxo.
///
/// Much shorter than [htlc_recv_exit_blocks_needed]: the expiry height binds
/// the tree nodes above the leaf, not the HTLC leaf script itself (see
/// [VtxoPolicy::taproot]), so the tree only has to outlive confirmation of
/// our exit chain, which [Config::vtxo_exit_margin] bounds.
///
/// One margin covers the grant however it plays out. If the server refuses to
/// cosign the claim, we exit the HTLC-recv vtxo. If it does cosign, the claim
/// output inherits the tree's expiry and exits over the same branch. Only one
/// of the two ever happens, and [is_htlc_claim_window_closed] re-checks the
/// margin against the tip before we reveal the preimage.
fn htlc_recv_tree_blocks_needed(config: &Config) -> BlockDelta {
	config.vtxo_exit_margin
}

/// AwaitingPayment -> HtlcsReady. Asks the server to grant HTLC-recv
/// vtxos for the inbound payment, validates them, creates the receive
/// movement and stores the vtxos locked.
pub(crate) async fn prepare_lightning_receive_htlcs(
	wallet: &Wallet,
	recv: &LightningReceive,
) -> Result<Grant, AdvanceError> {
	let (mut srv, ark_info) = wallet.require_server().await?;
	let config = wallet.config();
	let current_height = wallet.inner.chain.tip().await?;
	let payment_hash = recv.payment_hash;

	let lightning_receive_anti_dos = match compute_lightning_receive_anti_dos(
		wallet, payment_hash, recv.anti_dos_token.as_deref(),
	).await {
		Ok(anti_dos) => Some(anti_dos),
		Err(e) => {
			info!("Could not compute anti-dos: {e:#}. Trying without");
			None
		},
	};

	let htlc_recv_expiry = current_height + recv.htlc_recv_cltv_delta;
	let key = wallet.peek_signing_key(recv.key_index).await?;
	let req = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: payment_hash.to_vec(),
		user_pubkey: key.public_key().serialize().to_vec(),
		htlc_recv_expiry: htlc_recv_expiry.into(),
		lightning_receive_anti_dos,
	};
	let res = srv.client.prepare_lightning_receive_claim(req).await
		.map_err(AdvanceError::Server)?.into_inner();
	let vtxos = res.htlc_vtxos.into_iter()
		.map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<_>, _>>()
		.context("invalid htlc vtxos from server")?;

	// Sanity-check the vtxos.
	let mut htlc_amount = Amount::ZERO;
	for vtxo in &vtxos {
		trace!("Received HTLC VTXO {} from server: {}", vtxo.id(), vtxo.serialize_hex());
		wallet.validate_vtxo(vtxo).await
			.context("received invalid HTLC VTXO from server")?;
		htlc_amount += vtxo.amount();

		if let VtxoPolicy::ServerHtlcRecv(p) = vtxo.policy() {
			if p.payment_hash != payment_hash {
				return Err(anyhow!("invalid payment hash on HTLC VTXOs received from server: {}",
					p.payment_hash).into());
			}
			if p.user_pubkey != key.public_key() {
				return Err(anyhow!("invalid pubkey on HTLC VTXOs received from server: {}",
					p.user_pubkey).into());
			}
			// NB: p.htlc_expiry isn't compared against the freshly computed
			// htlc_recv_expiry: the server hands back the first attempt's
			// grant, so any block mined since would fail on every retry. The
			// claim deadline check below covers the grant's headroom.

			// Ensure that the server didn't inflate the deltas for the client's
			// unilateral exit clauses. Don't retry on any failure here: the
			// server hands back these very same vtxos on every later request
			// for this payment hash.
			let claim_by = htlc_recv_exit_blocks_needed(
				vtxo.exit_delta(), p.htlc_expiry_delta, config,
			).and_then(|blocks_needed| {
				current_height.checked_add(blocks_needed)
					.context("HTLC VTXO claim deadline overflows")
			});
			let claim_by = match claim_by {
				Ok(claim_by) => claim_by,
				Err(e) => return Ok(Grant::Rejected(e)),
			};
			if claim_by > p.htlc_expiry {
				return Ok(Grant::Rejected(anyhow!(
					"HTLC VTXO timelocks leave no time to claim it unilaterally: we need \
					until height {} (exit delta {}, htlc expiry delta {}), but the server \
					can claim it from height {}",
					claim_by, vtxo.exit_delta(), p.htlc_expiry_delta, p.htlc_expiry,
				)));
			}

			// The server also chose the leaf's tree-level parameters, so validate
			// them against the advertised ones like round outputs.
			let blocks_needed = htlc_recv_tree_blocks_needed(config);
			let tree_expiry_by = match current_height.checked_add(blocks_needed) {
				Some(height) => height,
				None => return Ok(Grant::Rejected(
					anyhow!("HTLC VTXO tree expiry deadline overflows"),
				)),
			};
			if let Err(e) = validate_vtxo_tree_params(
				vtxo.server_pubkey(), vtxo.exit_delta(), vtxo.expiry_height(),
				ark_info.server_pubkey, ark_info.vtxo_exit_delta, tree_expiry_by,
			) {
				return Ok(Grant::Rejected(e));
			}
		} else {
			return Err(anyhow!("invalid HTLC VTXO policy: {:?}", vtxo.policy()).into());
		}
	}

	// We can't entirely trust the server-reported payment amount, so if there is a
	// discrepancy, fall back to checking the invoice amount.
	let invoice_amount = recv.invoice.get_payment_amount(None)
		.context("ln receive invoice should have amount")?;
	let server_received_amount = res.receive.map(|r| Amount::from_sat(r.amount_sat));
	let fee = {
		let fee = server_received_amount
			.and_then(|a| ark_info.fees.lightning_receive.calculate(a));
		match (server_received_amount, fee) {
			(Some(amount), Some(fee)) if htlc_amount + fee == amount => fee,
			_ => ark_info.fees.lightning_receive.calculate(invoice_amount)
				.expect("we previously validated this"),
		}
	};
	let received = htlc_amount + fee;
	if received < invoice_amount {
		return Err(anyhow!("Server didn't return enough VTXOs to cover invoice amount").into());
	}

	// No preimage leaves the wallet until the native HTLC claim clause has
	// a fully signed, program-authorized recovery on durable storage.
	wallet.prepare_program_recoveries(&vtxos).await?;
	wallet.ensure_program_recoveries(&vtxos).await?;
	if htlc_claim_window_closed(wallet, &vtxos).await? {
		return Ok(Grant::Rejected(anyhow!(
			"saved HTLC recovery cannot confirm before the granted deadlines",
		)));
	}

	let movement_id = wallet.inner.movements.get_or_create_movement_with_action(
		Subsystem::LIGHTNING_RECEIVE,
		LightningReceiveMovement::Receive.to_string(),
		&recv.id(),
		MovementUpdate::new()
			.intended_balance(invoice_amount.to_signed().context("invoice amount out of range")?)
			.effective_balance(htlc_amount.to_signed().context("htlc amount out of range")?)
			.fee(fee)
			.metadata(LightningMovement::metadata(
				payment_hash, &vtxos, Some(recv.payment_preimage),
			))
			.received_on([MovementDestination::new(recv.invoice.clone().into(), received)]),
	).await.context("failed to create lightning receive movement")?;
	wallet.store_locked_vtxos(
		&vtxos,
		Some(VtxoLockHolder::Action { id: recv.id() }),
	).await?;

	// Sort for a deterministic checkpoint (the server may return them in any order).
	let mut vtxo_ids = vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();
	vtxo_ids.sort();

	Ok(Grant::Accepted(Htlcs {
		vtxo_ids,
		movement_id,
	}))
}

/// Claim HTLCs without exporting the completed outputs. Recovery authorization
/// and recipient preparation precede the preimage RPC; the action checkpoints
/// its exact signed result before registration or delivery.
async fn claim_lightning_receive_htlcs(
	wallet: &Wallet,
	recv: &LightningReceive,
	htlcs: &Htlcs,
	preimage_revealed: &mut bool,
) -> Result<Delivery, AdvanceError> {
	if let Some(checkpoint) = wallet.inner.db.get_wallet_action_checkpoint(&recv.id()).await?
		.and_then(|cp| cp.into_lightning_receive())
	{
		if let Progress::Delivering(delivery) = checkpoint.progress {
			return Ok(delivery);
		}
	}
	let (mut srv, _) = wallet.require_server().await?;

	// Order inputs by vtxoid before generating nonces, then hydrate to
	// full so the arkoor builder has the genesis chain.
	let mut input_ids = htlcs.vtxo_ids.clone();
	input_ids.sort();
	let inputs = wallet.inner.db.get_full_vtxos(&input_ids).await
		.context("failed to hydrate htlc input vtxos")?;

	wallet.ensure_program_recoveries(&inputs).await?;

	let receive_policy = if let Some(destination) = recv.claim_destination.as_ref() {
		destination.policy().clone()
	} else {
		let claim_key = wallet.peek_signing_key(recv.key_index).await?.public_key();
		VtxoPolicy::new_pubkey(claim_key)
	};
	trace!("ln claim arkoor params: inputs: {:?}; policy: {:?}", input_ids, receive_policy);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		inputs, receive_policy,
	).context("creating claim arkoor builder failed")?;
	let candidates = builder.build_unsigned_vtxos().collect::<Vec<_>>();
	wallet.prepare_program_recoveries(&candidates).await?;
	if let Some(destination) = recv.claim_destination.as_ref() {
		wallet.prepare_program_receives(destination, &candidates).await?;
	}
	let (keys, prepared, attestations) = wallet.prepare_arkoor_signatures(&builder).await?;
	let builder = builder.with_external_nonces(prepared.iter().map(|part| {
		part.iter().map(|signature| signature.public_nonce()).collect()
	}).collect()).context("failed to install lightning receive nonces")?;
	let package_cosign_request = protos::ArkoorPackageCosignRequest::from(
		builder.cosign_request_with_attestations(attestations)
			.context("invalid lightning receive attestations")?,
	);

	// Preparation may contact a program or recipient; recheck chain timing
	// immediately before committing the payment.
	if !matches!(&recv.progress, Progress::PreimageRevealed(_))
		&& is_htlc_claim_window_closed(wallet, htlcs).await?
	{
		return Err(anyhow!("HTLC claim window closed before preimage disclosure").into());
	}
	let checkpoint = LightningReceive {
		progress: Progress::PreimageRevealed(htlcs.clone()),
		..recv.clone()
	};
	wallet.inner.db.upsert_wallet_action_checkpoint(&recv.id(), &checkpoint.into()).await?;
	info!("Claiming arkoor against payment preimage for {}", recv.payment_hash);
	*preimage_revealed = true;
	let resp = srv.client.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: recv.payment_hash.to_byte_array().to_vec(),
		payment_preimage: recv.payment_preimage.to_vec(),
		cosign_request: Some(package_cosign_request),
	}).await.map_err(AdvanceError::Server)?.into_inner();
	let cosign_resp = resp.try_into().context("invalid cosign response")?;

	builder.verify_cosign_response(&cosign_resp)
		.context("invalid lightning receive cosign response")?;
	let signatures = wallet.finish_arkoor_signatures(&keys, prepared, cosign_resp).await?;
	let mut outputs = builder.finish_external(signatures)
		.context("claim arkoor cosign failed with user response")?.build_signed_vtxos();

	for vtxo in &outputs {
		trace!("Validating Lightning receive claim VTXO {}: {}", vtxo.id(), vtxo.serialize_hex());
		wallet.validate_vtxo(vtxo).await
			.context("invalid arkoor from lightning receive")?;
	}

	info!("Got arkoors from lightning: {}",
		outputs.iter().map(|v| v.id().to_string()).collect::<Vec<_>>().join(", "));

	outputs.sort_unstable();
	let delivery = Delivery {
		vtxos: outputs,
		movement_id: htlcs.movement_id,
		input_vtxo_ids: input_ids,
	};
	let checkpoint = LightningReceive {
		progress: Progress::Delivering(delivery.clone()),
		..recv.clone()
	};
	wallet.inner.db.upsert_wallet_action_checkpoint(&recv.id(), &checkpoint.into()).await?;
	Ok(delivery)
}

/// Delivering -> done. Only checkpointed signed outputs reach registration,
/// coordinated recipients or mailboxes. Local claims are stored as spendable.
async fn deliver_lightning_receive(
	wallet: &Wallet,
	recv: &LightningReceive,
	delivery: &Delivery,
) -> Result<(), AdvanceError> {
	for vtxo in &delivery.vtxos {
		if wallet.inner.db.get_wallet_vtxo(vtxo.id()).await?
			.is_some_and(|v| v.state.kind() == crate::vtxo::VtxoStateKind::Exited)
		{
			wallet.exit_lightning_receive_with_guard(recv).await?;
			return Ok(());
		}
	}
	wallet.ensure_program_recoveries(&delivery.vtxos).await?;
	let external_destination = match recv.claim_destination.as_ref() {
		Some(destination) => wallet.signing_key(&destination.policy().user_pubkey())
			.await?.is_none(),
		None => false,
	};
	if let Some(destination) = recv.claim_destination.as_ref() {
		wallet.commit_program_receives(destination, &delivery.vtxos).await?;
	}
	wallet.register_vtxo_transactions_with_server(&delivery.vtxos).await?;
	wallet.mark_vtxos_as_spent(&delivery.input_vtxo_ids).await?;

	let received = delivery.vtxos.iter().map(|v| v.amount()).sum();
	let update = if external_destination {
		let destination = recv.claim_destination.as_ref()
			.context("external receive has no claim destination")?;
		deliver_vtxos_to_address(wallet, destination, &delivery.vtxos).await
			.context("failed to deliver lightning receive claim outputs")?;
		MovementUpdate::new()
			.effective_balance(SignedAmount::ZERO)
			.sent_to([MovementDestination::ark(destination.clone(), received)])
	} else {
		if let Err(e) = wallet.post_recovery_vtxo_ids(delivery.vtxos.iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}
		wallet.store_vtxos(&delivery.vtxos, &VtxoState::Spendable).await?;
		MovementUpdate::new()
			.effective_balance(received.to_signed().context("received amount out of range")?)
			.produced_vtxos(&delivery.vtxos)
	};
	wallet.inner.movements.finish_movement_with_update(
		delivery.movement_id, MovementStatus::Successful, update,
	).await.context("failed to finish lightning receive movement")?;

	let amount = recv.invoice.get_payment_amount(None).unwrap_or(received);
	wallet.inner.db.record_settled_lightning_receive(
		recv.payment_hash, recv.payment_preimage, &recv.invoice, amount,
	).await?;

	Ok(())
}

async fn deliver_vtxos_to_address(
	wallet: &Wallet,
	destination: &ark::Address,
	vtxos: &[Vtxo<ark::vtxo::Full>],
) -> anyhow::Result<()> {
	if crate::sapio::receive::is_coordinated_address(destination)? {
		// The checkpointed outputs were committed through the coordinator.
		return Ok(());
	}
	let (mut srv, _) = wallet.require_server().await?;

	match post_arkoor_to_mailboxes(&mut srv, destination.delivery(), vtxos).await {
		DeliveryOutcome::AnySucceeded => Ok(()),
		DeliveryOutcome::AllFailed { summary } => bail!(summary),
	}
}

/// HtlcsReady abandon: the preimage was never revealed, so we simply drop
/// the HTLC vtxos and finish the movement as canceled. The inbound HTLC
/// times out server-side and the sender is refunded.
pub(crate) async fn abandon_lightning_receive(
	wallet: &Wallet,
	recv: &LightningReceive,
	htlcs: &Htlcs,
) -> anyhow::Result<()> {
	warn!("Abandoning lightning receive {} before preimage disclosure", recv.payment_hash);
	wallet.mark_vtxos_as_spent(&htlcs.vtxo_ids).await?;
	wallet.inner.movements.finish_movement_with_update(
		htlcs.movement_id,
		MovementStatus::Canceled,
		MovementUpdate::new().effective_balance(SignedAmount::ZERO),
	).await?;
	Ok(())
}

/// Returns whether the claim window on the granted HTLC-recv vtxos has
/// closed, in which case the caller must abandon rather than reveal the
/// preimage.
///
/// Every granted vtxo is held to the two budgets
/// [prepare_lightning_receive_htlcs] accepted the grant against: the claim
/// must finish before the server can race us at the HTLC expiry, and our
/// exit chain must confirm before the server can sweep the tree at the VTXO
/// expiry. Both deadlines live on the stored vtxos, not the checkpoint.
pub(crate) async fn is_htlc_claim_window_closed(
	wallet: &Wallet,
	htlcs: &Htlcs,
) -> anyhow::Result<bool> {
	ensure!(!htlcs.vtxo_ids.is_empty(), "no HTLC vtxos on receive");

	// Revalidate the exact persisted claims, not the current configuration.
	// Bails if any id is missing, so every granted vtxo is checked.
	let vtxos = wallet.inner.db.get_full_vtxos(&htlcs.vtxo_ids).await
		.context("failed to hydrate htlc vtxos")?;
	wallet.ensure_program_recoveries(&vtxos).await?;
	htlc_claim_window_closed(wallet, &vtxos).await
}

async fn htlc_claim_window_closed(wallet: &Wallet, vtxos: &[Vtxo<Full>]) -> anyhow::Result<bool> {
	let config = wallet.config();
	let tip = wallet.inner.chain.tip().await?;
	let mut median_time = None;
	for vtxo in vtxos {
		let p = match vtxo.policy() {
			VtxoPolicy::ServerHtlcRecv(p) => p,
			other => bail!("HTLC receive vtxo has unexpected policy: {:?}", other),
		};

		let claim_by = tip.checked_add(htlc_recv_exit_blocks_needed(
			vtxo.exit_delta(), p.htlc_expiry_delta, config,
		)?).context("HTLC claim deadline overflows")?;
		if claim_by > p.htlc_expiry {
			debug!("HTLC vtxo {} needs until height {} to claim, but the server \
				can claim it from height {}", vtxo.id(), claim_by, p.htlc_expiry);
			return Ok(true);
		}

		let tree_expiry_by = tip.checked_add(htlc_recv_tree_blocks_needed(config))
			.context("HTLC tree deadline overflows")?;
		if tree_expiry_by > vtxo.expiry_height() {
			debug!("HTLC vtxo {} needs its backing tree until height {}, but it \
				expires at height {}", vtxo.id(), tree_expiry_by, vtxo.expiry_height());
			return Ok(true);
		}

		if wallet.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_some() {
			let record = wallet.inner.db.get_program_recovery(vtxo.point()).await?
				.context("missing persisted HTLC recovery claim")?;
			if !record.claim.lock_time.is_block_height() && median_time.is_none() {
				// Timestamp locks use Bitcoin's previous-block median time, not
				// wall clock. Do not predict its growth against a height deadline.
				let mut times = [0u32; 11];
				let mut count = 0;
				for height in tip.to_u32().saturating_sub(10)..=tip.to_u32() {
					let block_ref = wallet.inner.chain.block_ref(BlockHeight::new(height)).await?;
					let block = wallet.inner.chain.block(block_ref.hash).await?
						.context("missing block for HTLC recovery median time")?;
					times[count] = block.header.time;
					count += 1;
				}
				times[..count].sort_unstable();
				median_time = Some(times[count / 2]);
			}
			if !program_htlc_recovery_fits(
				&record.claim, record.ancestors.len(), tip, p.htlc_expiry,
				vtxo.expiry_height(), config, median_time,
			)? {
				return Ok(true);
			}
		}
	}

	Ok(false)
}

/// Bound the exact immutable recovery's parent publication, CSV, absolute
/// locktime and claim confirmations. Tree expiry only races the ancestry;
/// HTLC expiry races the claim itself.
fn program_htlc_recovery_fits(
	claim: &bitcoin::Transaction,
	ancestor_count: usize,
	tip: BlockHeight,
	htlc_expiry: BlockHeight,
	tree_expiry: BlockHeight,
	config: &Config,
	median_time: Option<u32>,
) -> anyhow::Result<bool> {
	ensure!(claim.input.len() == 1, "HTLC recovery must have one input");
	let sequence = claim.input[0].sequence.to_consensus_u32();
	ensure!(sequence <= u16::MAX as u32, "HTLC recovery requires block-based CSV");
	// Recovery publishes v3 ancestors one at a time. Include a potentially
	// unconfirmed root, even when the ordinary native margin is too small.
	let ancestry_blocks = u32::try_from(ancestor_count)?.checked_add(1)
		.context("HTLC recovery ancestry budget overflows")?
		.max(config.vtxo_exit_margin.to_u32());
	let parent_by = tip.to_u32().checked_add(ancestry_blocks)
		.context("HTLC recovery parent deadline overflows")?;
	if parent_by >= tree_expiry.to_u32() { return Ok(false); }
	let mut maturity = parent_by.checked_add(sequence)
		.context("HTLC recovery relative maturity overflows")?;
	let locktime = claim.lock_time.to_consensus_u32();
	if claim.lock_time.is_block_height() {
		maturity = maturity.max(locktime.checked_add(1).context("HTLC recovery locktime overflows")?);
	} else if median_time.context("missing HTLC recovery median time")? <= locktime {
		// Future timestamp plans cannot promise maturity before a block height.
		// Reject them rather than modifying or re-signing an authorized claim.
		return Ok(false);
	}
	let claim_by = maturity.checked_add(config.htlc_recv_claim_delta.to_u32().max(1))
		.context("HTLC recovery confirmation deadline overflows")?;
	Ok(claim_by < htlc_expiry.to_u32())
}

/// Whether an unpaid invoice has passed its bolt11 expiry plus a grace
/// margin and can be reaped.
pub(crate) fn invoice_expired(invoice: &Bolt11Invoice) -> bool {
	let now_secs = chrono::Utc::now().timestamp();
	if now_secs < 0 {
		return false;
	}
	let cutoff = Duration::from_secs(now_secs as u64).saturating_sub(INVOICE_EXPIRY_GRACE);
	invoice.would_expire(cutoff)
}

#[cfg(test)]
mod tests {
	use super::*;

	const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

	#[test]
	fn program_htlc_recovery_rejects_late_fixed_locktime_without_modifying_claim() {
		let mut config = Config::network_default(bitcoin::Network::Bitcoin);
		config.vtxo_exit_margin = BlockDelta::new(3);
		config.htlc_recv_claim_delta = BlockDelta::new(2);
		let mut claim = bitcoin::Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::from_height(120).unwrap(),
			input: vec![bitcoin::TxIn {
				sequence: bitcoin::Sequence::from_height(5),
				..Default::default()
			}],
			output: vec![],
		};
		let saved = claim.clone();
		let fits = |claim: &bitcoin::Transaction, tip, expiry, tree, ancestors, mtp| {
			program_htlc_recovery_fits(
				claim, ancestors, BlockHeight::new(tip), BlockHeight::new(expiry),
				BlockHeight::new(tree), &config, mtp,
			).unwrap()
		};
		// Native CSV could finish by 110, but the saved absolute lock cannot.
		assert!(!fits(&claim, 100, 120, 110, 2, None));
		assert!(!fits(&claim, 100, 123, 110, 2, None));
		assert!(fits(&claim, 100, 124, 110, 2, None));
		assert_eq!(claim, saved);
		claim.lock_time = bitcoin::absolute::LockTime::ZERO;
		assert!(fits(&claim, 100, 111, 110, 2, None));
		// Recheck immediately before disclosure: one block consumes the budget.
		assert!(!fits(&claim, 101, 111, 110, 2, None));
		assert!(!fits(&claim, 100, 140, 110, 9, None));
		claim.input[0].sequence = bitcoin::Sequence::from_height(35);
		assert!(!fits(&claim, 100, 140, 150, 2, None));
	}

	#[test]
	fn program_htlc_recovery_rejects_future_timestamp_even_with_height_headroom() {
		let mut config = Config::network_default(bitcoin::Network::Bitcoin);
		config.vtxo_exit_margin = BlockDelta::new(3);
		config.htlc_recv_claim_delta = BlockDelta::new(2);
		let claim = bitcoin::Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::from_time(1_800_000_000).unwrap(),
			input: vec![bitcoin::TxIn {
				sequence: bitcoin::Sequence::from_height(5),
				..Default::default()
			}],
			output: vec![],
		};
		for median in [1_799_999_999, 1_800_000_000, 1_800_000_001] {
			assert_eq!(program_htlc_recovery_fits(
				&claim, 2, BlockHeight::new(100), BlockHeight::new(1_000),
				BlockHeight::new(1_000), &config, Some(median),
			).unwrap(), median > 1_800_000_000);
		}
		assert_eq!(claim.lock_time.to_consensus_u32(), 1_800_000_000);
	}

	fn test_bolt11() -> Bolt11Invoice {
		Bolt11Invoice::from_str(TEST_INVOICE_STR).expect("valid test invoice")
	}

	#[test]
	fn validate_bolt11_payment_hash_accepts_matching_hash() {
		let invoice = test_bolt11();
		let payment_hash = PaymentHash::from(&invoice);

		validate_bolt11_payment_hash(&invoice, payment_hash).unwrap();
	}

	#[test]
	fn validate_bolt11_payment_hash_rejects_mismatched_hash() {
		let invoice = test_bolt11();
		let mismatched_payment_hash = PaymentHash::from_slice(&[0xabu8; 32]).unwrap();

		let err = validate_bolt11_payment_hash(&invoice, mismatched_payment_hash)
			.expect_err("mismatched payment hash should fail");

		assert!(
			err.to_string().contains("returned invoice with payment hash"),
			"{err:?}",
		);
	}

	/// The blocks we ask the server to put between the tip and `htlc_expiry`
	/// when creating the invoice, see [start_lightning_receive].
	fn requested_cltv_delta(
		exit_delta: BlockDelta,
		htlc_expiry_delta: BlockDelta,
		config: &Config,
	) -> BlockDelta {
		exit_delta + htlc_expiry_delta + config.vtxo_exit_margin
			+ config.htlc_recv_claim_delta + LIGHTNING_PREPARE_CLAIM_DELTA
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_fits_the_requested_cltv_delta() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);

		// A server granting the deltas it advertised leaves us
		// LIGHTNING_PREPARE_CLAIM_DELTA to spare.
		for (exit_delta, htlc_expiry_delta) in [(144, 6), (144, 40), (100, 0)] {
			let (exit_delta, htlc_expiry_delta) =
				(BlockDelta::new(exit_delta), BlockDelta::new(htlc_expiry_delta));
			let needed = htlc_recv_exit_blocks_needed(
				exit_delta, htlc_expiry_delta, &config,
			).unwrap();
			let requested = requested_cltv_delta(exit_delta, htlc_expiry_delta, &config);

			assert_eq!(requested.saturating_sub(needed), LIGHTNING_PREPARE_CLAIM_DELTA);
		}
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_exceeds_cltv_delta_when_server_inflates_a_delta() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);
		let requested = requested_cltv_delta(BlockDelta::new(144), BlockDelta::new(6), &config);

		// Inflating either delta past the leniency delta eats the whole window.
		let inflated_expiry_delta =
			htlc_recv_exit_blocks_needed(BlockDelta::new(144), BlockDelta::new(9), &config).unwrap();
		assert!(inflated_expiry_delta > requested);

		let inflated_exit_delta =
			htlc_recv_exit_blocks_needed(BlockDelta::new(147), BlockDelta::new(6), &config).unwrap();
		assert!(inflated_exit_delta > requested);
	}

	#[test]
	fn htlc_recv_exit_blocks_needed_rejects_overflowing_deltas() {
		let config = Config::network_default(bitcoin::Network::Bitcoin);

		htlc_recv_exit_blocks_needed(BlockDelta::MAX, BlockDelta::MAX, &config)
			.expect_err("summing the deltas should overflow");
	}

	/// The tree only has to outlive one exit margin, far less than the whole
	/// claim needs, so a tree bark can still exit from isn't refused.
	#[test]
	fn htlc_recv_tree_blocks_needed_stays_under_a_full_claim() {
		let mut config = Config::network_default(bitcoin::Network::Bitcoin);
		config.vtxo_exit_margin = BlockDelta::new(12);

		assert_eq!(htlc_recv_tree_blocks_needed(&config), BlockDelta::new(12));

		let needed = htlc_recv_exit_blocks_needed(
			BlockDelta::new(144), BlockDelta::new(40), &config,
		).unwrap();
		assert!(htlc_recv_tree_blocks_needed(&config) < needed);
	}
}
