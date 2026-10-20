
pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, Weak};

use anyhow::Context;
use ark::tree::signed::UnlockHash;
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use futures::{FutureExt, Stream, StreamExt};
use log::{debug, error, info, trace, warn};
use tokio_util::sync::CancellationToken;


use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use ark::vtxo::Full;
use server_rpc::{protos, MAX_NB_MAILBOX_RECOVERY_IDS};
use server_rpc::protos::mailbox_server::MailboxMessage;

use crate::{Wallet, WalletInner, SUBSCRIBE_REQUEST_TIMEOUT};
use crate::actions::DriveMode;
use crate::actions::lightning::pay::Progress;
use crate::movement::{MovementDestination, MovementStatus};
use crate::movement::update::MovementUpdate;
use crate::subsystem::{ArkoorMovement, Subsystem};
use crate::utils::ReconnectBackoff;
use crate::sapio::recovery::{verify_program_recovery, verify_program_recovery_template};
use crate::vtxo::VtxoValidationError;


/// The maximum number of times we will call the fetch mailbox endpoint in one go
///
/// We can't trust the server to honestly tell us to keep trying more forever.
/// A malicious server could send us empty messages or invalid messages and
/// lock up our resources forever. So we limit the number of times we will fetch.
/// If a user actually has more messages left, he will have to call sync again.
///
/// (Note that currently the server sends 100 messages per fetch, so this would
/// only happen for users with more than 1000 pending items.)
pub(crate) const MAX_MAILBOX_REQUEST_BURST: usize = 10;

/// Maximum VTXO bodies processed from one arkoor mailbox message.
///
/// A 64 MiB message can carry hundreds of thousands of minimal bodies, each
/// costing a chain-anchor lookup and persistence work. Honest packages are far
/// below this bound; excess is logged and the message checkpoint still advances
/// (a malicious server can withhold messages anyway, and refusing forever
/// would wedge the mailbox).
const MAX_ARKOOR_VTXOS_PER_MESSAGE: usize = 1024;

/// Maximum raw VTXO bytes retained in quarantine movement metadata.
const MAX_QUARANTINE_RAW_BYTES: usize = 4096;

/// Number of low bits in a server mailbox checkpoint that hold a
/// per-millisecond counter; the upper bits are milliseconds since the Unix
/// epoch.
///
/// The checkpoint shape is defined by the server: captaind's migrations
/// V21/V37 build `next_checkpoint()` as `(unix_ms << 20) | per_ms_counter`,
/// i.e. one global, time-shifted sequence — the "strictly ascending time
/// based number" of mailbox_server.proto. Two stamps taken a millisecond
/// apart already differ by 2^20, and a fresh wallet's first claim lands at
/// roughly time-now-shifted (~1.9e18) while its cursor is still 0, so no
/// fixed count-based advance bound can ever work against an honest server;
/// plausibility can only be judged against wall time.
pub(crate) const MAILBOX_CHECKPOINT_COUNTER_BITS: u32 = 20;

/// How far into the future a server-claimed checkpoint may be timestamped
/// before we refuse to persist it.
///
/// 24h absorbs clock drift and timezone misconfiguration on either side
/// while still rejecting far-future poison values (e.g. `u64::MAX - 7`),
/// which would black out every later message: all fetches request messages
/// strictly after the stored checkpoint.
pub(crate) const MAX_MAILBOX_CHECKPOINT_FUTURE_SKEW: std::time::Duration =
	std::time::Duration::from_secs(24 * 60 * 60);

/// Key for the lock that serializes the arkoor receive dedup within a wallet.
///
/// Several consumers of one wallet process the same mailbox messages: the
/// daemon's always-on stream ([`Wallet::subscribe_process_mailbox_messages`])
/// runs alongside the startup / periodic `sync()` (which calls
/// [`Wallet::sync_mailbox`]), and a REST deployment can fire concurrent
/// `/sync` and `/sync/mailbox` requests. The server hands each consumer the
/// same messages from its checkpoint, so without serialization the
/// peek-then-store dedup in arkoor processing races: every consumer that wins
/// the [`crate::persist::WalletPersister::get_wallet_vtxo`] check before the
/// others store records its own receive movement, double-counting the receive.
///
/// Holding this lock across that check-then-store (in
/// [`Wallet::process_received_arkoor_package`]) makes it atomic across
/// consumers. The VTXO row is `INSERT OR IGNORE`, so once one consumer has
/// stored the package the rest see the VTXO already present and skip the
/// movement.
const MAILBOX_PROCESSING_LOCK_KEY: &str = "mailbox.processing";

/// How long a consumer waits for the arkoor dedup lock before giving up.
///
/// The critical section is a couple of server round trips plus local DB
/// writes, normally well under a second. On timeout we error rather than
/// block, handled like any other arkoor processing error: this message's
/// checkpoint isn't advanced and processing halts (see
/// [`Wallet::process_mailbox_message`]) so a later message can't bury it. A
/// timeout only happens if a holder is stuck for the full duration; normally
/// waiters acquire the lock and dedup as usual.
const MAILBOX_PROCESSING_LOCK_TIMEOUT: std::time::Duration =
	std::time::Duration::from_secs(30);

/// Whether a structurally-valid arkoor vtxo is safe to store as a spendable
/// received payment.
///
/// [`Wallet::validate_vtxo`] only proves the vtxo's genesis chain was cosigned
/// by the server pubkey embedded in the vtxo. A received payment additionally
/// has to be a final, self-custodial coin, so we require that:
///
/// - the policy is [`VtxoPolicyKind::Pubkey`]: an in-flight HTLC (or any other
///   server contract) is not a payment, and the server refuses to let us spend
///   it as an arkoor/round/offboard input;
/// - the vtxo commits to *our* server's pubkey, not a foreign server's.
///
/// Expiry is not a reason to refuse. The sender paid with a vtxo that was
/// valid when the server cosigned it; if we only sync after it expired, the
/// payment is still ours and the coin needs a refresh, not a rejection.
/// Refusing would drop the payment, since the mailbox checkpoint advances.
///
/// Ownership (that the wallet holds a signable key) is checked by the caller,
/// which has async database access.
fn check_arkoor_receive_policy(
	vtxo: &Vtxo<Full>,
	server_pubkey: bitcoin::secp256k1::PublicKey,
) -> anyhow::Result<()> {
	let kind = vtxo.policy().policy_type();
	if kind != ark::vtxo::policy::VtxoPolicyKind::Pubkey {
		bail!("not a final payment VTXO (policy: {})", kind);
	}
	if vtxo.server_pubkey() != server_pubkey {
		bail!("VTXO commits to a foreign server pubkey {}", vtxo.server_pubkey());
	}
	Ok(())
}

/// Classify the outcome of [`Wallet::validate_vtxo`] for the arkoor-receive
/// path: `Ok(None)` for a valid VTXO, `Ok(Some(_))` for a provably invalid
/// one that must be absorbed and skipped, and `Err(_)` for a transient or
/// environmental failure, which must abort the whole message so its
/// checkpoint is not advanced and the server redelivers it.
///
/// Without this split, every validation failure was absorbed as if the
/// VTXO were provably invalid, while the checkpoint still advanced: a
/// chain-backend hiccup or an anchor the backend had not indexed yet
/// permanently dropped a genuine incoming payment.
///
/// The match must stay exhaustive: any new [VtxoValidationError] variant
/// forces a deliberate absorb-vs-abort decision here.
fn classify_arkoor_validation(
	result: Result<(), VtxoValidationError>,
) -> anyhow::Result<Option<ark::vtxo::VtxoValidationError>> {
	match result {
		Ok(()) => Ok(None),
		// Transient/environmental: not a property of the VTXO bytes.
		Err(VtxoValidationError::Chain(e)) => Err(e.context(
			"chain backend error vetting received arkoor VTXO; will retry on redelivery",
		)),
		Err(VtxoValidationError::AnchorNotFound) => Err(anyhow!(
			"chain anchor of received arkoor VTXO not visible to the backend yet; \
				will retry on redelivery",
		)),
		// Deterministic rejection: retrying can never credit these bytes.
		Err(VtxoValidationError::Invalid(e)) => Ok(Some(e)),
	}
}

/// Whether a vetted server-claimed checkpoint should be persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointVerdict {
	/// The claim advances the cursor and is within the plausibility bound.
	Advance,
	/// The stored cursor already covers this message, e.g. a racing
	/// consumer of the same wallet (sync and subscription run in parallel)
	/// advanced the cursor past it after this one started processing. Its
	/// position is durably covered, so there is nothing to persist.
	AlreadyCovered,
}

/// Vet a server-claimed mailbox checkpoint against the freshly read cursor
/// before it becomes the durable fetch position.
///
/// The claimed value is server-controlled input. Rejecting claims whose
/// embedded timestamp (see [MAILBOX_CHECKPOINT_COUNTER_BITS]) lies
/// implausibly far in the future (see [MAX_MAILBOX_CHECKPOINT_FUTURE_SKEW])
/// keeps one `MailboxMessage{checkpoint: huge, arkoor vtxos: []}` — fully
/// valid, unrefusable content — from poisoning the cursor and blacking out
/// every later message. Claims at or below the cursor are not errors: the
/// position is already covered (see [CheckpointVerdict::AlreadyCovered]),
/// and the persisters independently refuse non-increasing stores.
fn vet_server_checkpoint(
	current: u64,
	claimed: u64,
) -> anyhow::Result<CheckpointVerdict> {
	if claimed <= current {
		return Ok(CheckpointVerdict::AlreadyCovered);
	}
	let claimed_ms = claimed >> MAILBOX_CHECKPOINT_COUNTER_BITS;
	let limit_ms = chrono::Local::now().timestamp_millis() as u64
		+ MAX_MAILBOX_CHECKPOINT_FUTURE_SKEW.as_millis() as u64;
	anyhow::ensure!(
		claimed_ms <= limit_ms,
		"server-claimed mailbox checkpoint {claimed} is timestamped {} ms in the \
			future, beyond the allowed skew; refusing to persist a cursor the wallet \
			would never fetch past",
		claimed_ms.saturating_sub(limit_ms),
	);
	Ok(CheckpointVerdict::Advance)
}

impl Wallet {
	/// Get the keypair used for the server mailbox
	pub fn mailbox_keypair(&self) -> Keypair {
		self.inner.seed.to_mailbox_keypair()
	}

	/// Get the keypair used for the server recovery mailbox
	pub fn recovery_mailbox_keypair(&self) -> Keypair {
		self.inner.seed.to_recovery_mailbox_keypair()
	}

	/// Get this wallet's server mailbox ID
	pub fn mailbox_identifier(&self) -> MailboxIdentifier {
		let mailbox_kp = self.mailbox_keypair();
		MailboxIdentifier::from_pubkey(mailbox_kp.public_key())
	}

	/// Get this wallet's server recovery mailbox ID
	pub fn recovery_mailbox_identifier(&self) -> MailboxIdentifier {
		let mailbox_kp = self.recovery_mailbox_keypair();
		MailboxIdentifier::from_pubkey(mailbox_kp.public_key())
	}

	/// Create a mailbox authorization that is valid until the given expiry time
	///
	/// This authorization can be used by third parties to lookup your mailbox
	/// with the Ark server.
	pub fn mailbox_authorization(
		&self,
		authorization_expiry: chrono::DateTime<chrono::Local>,
	) -> MailboxAuthorization {
		MailboxAuthorization::new(&self.mailbox_keypair(), authorization_expiry)
	}

	/// Subscribe to mailbox message stream.
	///
	/// If `since` is `None`, the stream will start from the last checkpoint stored in the database.
	///
	/// Returns a stream of mailbox messages.
	pub async fn subscribe_mailbox_messages(
		&self,
		since_checkpoint: Option<u64>,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<MailboxMessage>> + Unpin + use<>> {
		let (mut srv, _) = self.require_server().await?;

		let checkpoint = if let Some(since) = since_checkpoint {
			since
		} else {
			self.get_mailbox_checkpoint().await?
		};

		// we just need a short authorization for the stream initialization
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10);
		let auth = self.mailbox_authorization(expiry);
		let mailbox_id = auth.mailbox();

		let mut req = tonic::IntoRequest::into_request(protos::mailbox_server::MailboxRequest {
			mailbox_id: mailbox_id.serialize(),
			authorization: Some(auth.serialize()),
			checkpoint: checkpoint,
		});
		req.set_timeout(SUBSCRIBE_REQUEST_TIMEOUT);
		trace!("Requesting mailbox stream from checkpoint {}", checkpoint);

		let stream = srv.mailbox_client.subscribe_mailbox(req).await?.into_inner().map(|m| {
			let m = m.context("received error on mailbox message stream")?;
			Ok::<_, anyhow::Error>(m)
		});

		Ok(stream)
	}

	/// Similar to [Wallet::subscribe_mailbox_messages] but it will also process each mailbox
	/// message indefinitely. This method won't stop until the given `shutdown` `CancellationToken`
	/// is triggered.
	///
	/// If `since_checkpoint` is `None`, the stream will start from the last checkpoint stored in
	/// the database.
	///
	/// Returns only once the stream is closed.
	pub async fn subscribe_process_mailbox_messages(
		&self,
		since_checkpoint: Option<u64>,
		shutdown: CancellationToken,
	) -> anyhow::Result<()> {
		Wallet::subscribe_process_mailbox_messages_weak(
			Arc::downgrade(&self.inner), since_checkpoint, shutdown,
		).await
	}

	/// The body of [Wallet::subscribe_process_mailbox_messages], holding the
	/// wallet only weakly.
	///
	/// The subscription is always-on, so this future must not own a strong
	/// wallet reference across its lifetime: the daemon relies on the wallet's
	/// strong count reaching zero — running [crate::WalletInner]'s drop glue —
	/// to learn that it should shut down. The weak reference is therefore only
	/// upgraded for one unit of work at a time (a resubscribe or a single
	/// message); between messages this future owns just the gRPC stream.
	///
	/// Returns cleanly when the wallet is dropped, like on shutdown.
	pub(crate) async fn subscribe_process_mailbox_messages_weak(
		wallet: Weak<WalletInner>,
		since_checkpoint: Option<u64>,
		shutdown: CancellationToken,
	) -> anyhow::Result<()> {
		let upgrade = || wallet.upgrade().map(|inner| Wallet { inner });

		// Count consecutive reconnects that made no progress. A delivered
		// message resets it (the connection is healthy); enough failures in a
		// row means the server is unreachable, so we bail and let the daemon
		// mark itself disconnected and back off a full sync interval.
		let mut reconnect_count = 0;
		const MAX_RECONNECT_ATTEMPTS: usize = 5;
		let mut backoff = ReconnectBackoff::new();

		loop {
			let mut stream = {
				let Some(wallet) = upgrade() else { return Ok(()) };
				futures::select! {
					res = wallet.subscribe_mailbox_messages(since_checkpoint).fuse()
						=> res?,
					_ = shutdown.cancelled().fuse() => return Ok(()),
				}
			};
			trace!("Connected to mailbox stream with server");

			'stream: loop {
				futures::select! {
					message = stream.next().fuse() => {
						match message {
							Some(Ok(message)) => {
								// A delivered message proves the connection is
								// healthy, so stop counting reconnects as failures.
								reconnect_count = 0;
								let Some(wallet) = upgrade() else { return Ok(()) };
								match wallet.process_mailbox_message(message).await {
									Ok(ControlFlow::Break(())) => {
										// A message failed without advancing its
										// checkpoint. Stop consuming this stream and
										// resubscribe from the unadvanced checkpoint
										// so it's redelivered before a later message
										// can bury it. We deliberately do NOT reset
										// the backoff here: if the same message keeps
										// failing, the growing delay keeps this from
										// becoming a tight redeliver loop.
										trace!("Halting mailbox stream after unadvanced message; resubscribing");
										break 'stream;
									},
									Err(e) => {
										// The message's checkpoint could not be
										// safely persisted (store failure or an
										// implausible server-claimed value). The
										// cursor was NOT advanced, so treat it
										// like the unadvanced case above and
										// resubscribe, keeping the backoff.
										error!("Halting mailbox stream after unadvanced message: {:#}", e);
										break 'stream;
									},
									Ok(ControlFlow::Continue(())) => {
										// Progress made: reconnect promptly next time.
										backoff.reset();
									},
								}
							},
							// A tonic h2 stream reset is almost always a
							// proxy- or server-side idle timeout rather than
							// a real failure; resubscribe quietly. Unlike before
							// we count it toward the reconnect cap, so a server
							// that keeps resetting us is treated as unreachable
							// rather than triggering an unbounded resubscribe.
							Some(Err(e)) if crate::utils::is_h2_stream_error(&e) => {
								reconnect_count += 1;
								trace!("Mailbox stream reset by server, reconnecting: {e:#}");
								break 'stream;
							},
							Some(Err(e)) => {
								return Err(e).context("error on mailbox message stream");
							},
							None => {
								reconnect_count += 1;
								warn!("Mailbox stream dropped by server, reconnecting");
								break 'stream;
							},
						}
					},
					_ = shutdown.cancelled().fuse() => {
						info!("Shutdown signal received! Shutting mailbox messages process...");
						return Ok(());
					},
				}
			}

			// Reached only by breaking out of 'stream to resubscribe.
			if reconnect_count >= MAX_RECONNECT_ATTEMPTS {
				bail!("Mailbox stream dropped by server, giving up to retry later");
			}

			// Back off before resubscribing so a fast-closing or rate-limited
			// stream can't become a tight reconnect loop that floods the server
			// with opened-then-reset streams.
			futures::select! {
				_ = backoff.wait().fuse() => {},
				_ = shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting mailbox messages process...");
					return Ok(());
				},
			}
		}
	}

	/// Sync with the mailbox on the Ark server and look for out-of-round received VTXOs.
	pub async fn sync_mailbox(&self) -> anyhow::Result<()> {
		let (mut srv, _) = self.require_server().await?;

		// we should be able to do all our syncing in 10 minutes
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
		let auth = self.mailbox_authorization(expiry);
		let mailbox_id = auth.mailbox();

		for _ in 0..MAX_MAILBOX_REQUEST_BURST {
			let checkpoint = self.get_mailbox_checkpoint().await?;
			let mailbox_req = protos::mailbox_server::MailboxRequest {
				mailbox_id: mailbox_id.serialize(),
				authorization: Some(auth.serialize()),
				checkpoint,
			};

			let mailbox_resp = srv.mailbox_client.read_mailbox(mailbox_req).await
				.context("error fetching mailbox")?.into_inner();
			debug!("Ark server has {} mailbox messages for us", mailbox_resp.messages.len());

			for mailbox_msg in mailbox_resp.messages {
				match self.process_mailbox_message(mailbox_msg).await? {
					ControlFlow::Continue(()) => {},
					// A message failed without advancing its checkpoint. Stop
					// so we don't advance past it; the next sync retries from
					// the same checkpoint.
					ControlFlow::Break(()) => return Ok(()),
				}
			}

			if !mailbox_resp.have_more {
				break;
			}
		}

		Ok(())
	}

	/// Turn raw byte arrays into VTXOs, then validate them.
	///
	/// Program deposits without a verified prepared recovery are durably
	/// quarantined, not discarded or made spendable. A storage failure leaves the
	/// mailbox checkpoint unchanged so the original message can be retried.
	async fn process_raw_vtxos(
		&self,
		raw_vtxos: Vec<Vec<u8>>,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let ark_info  = self.require_server().await
			.context("refuse_htlc_send_vtxo_posted_to_arkoor_mailbox")?.1;
		let tip = self.inner.chain.tip().await
			.context("cannot vet received arkoor VTXOs, no chain tip")?;

		if raw_vtxos.len() > MAX_ARKOOR_VTXOS_PER_MESSAGE {
			error!(
				"Arkoor mailbox message carries {} VTXOs; processing only the first {}",
				raw_vtxos.len(), MAX_ARKOOR_VTXOS_PER_MESSAGE,
			);
		}
		let mut invalid_vtxos = Vec::with_capacity(raw_vtxos.len());
		let mut valid_vtxos = Vec::with_capacity(raw_vtxos.len());

		for bytes in raw_vtxos.iter().take(MAX_ARKOOR_VTXOS_PER_MESSAGE) {
			let vtxo = match Vtxo::<Full>::deserialize(&bytes) {
				Ok(vtxo) => vtxo,
				Err(e) => {
					error!("Failed to deserialize arkoor VTXO: {}", e);
					invalid_vtxos.push(bytes);
					continue;
				}
			};

			let program = self.extension_program_key(&vtxo.user_pubkey()).await?;
			// Only deterministic rejections are absorbed; a transient
			// failure (chain backend error, anchor not yet indexed) aborts
			// here, leaving this message's checkpoint unadvanced so the
			// server redelivers it — like the require_server()/tip()
			// prologue above. Absorbing a transient failure would
			// permanently drop a genuine payment while advancing the
			// checkpoint past it.
			let invalid = classify_arkoor_validation(self.validate_vtxo(&vtxo).await)
				.with_context(|| format!("cannot vet received arkoor VTXO {}", vtxo.id()))?;
			if let Some(e) = invalid {
				if program.is_some() {
					self.extension_quarantine_receive(&vtxo, bytes, "invalid or unverifiable program deposit").await?;
					continue;
				}
				error!("Received invalid arkoor VTXO {} from server: {}", vtxo.id(), e);
				invalid_vtxos.push(bytes);
				continue;
			}

			if let Err(e) = check_arkoor_receive_policy(&vtxo, ark_info.server_pubkey) {
				if program.is_some() {
					self.extension_quarantine_receive(&vtxo, bytes, "program deposit has an unsupported payment policy or server").await?;
					continue;
				}
				error!("Refusing received arkoor VTXO {}: {}", vtxo.id(), e);
				invalid_vtxos.push(bytes);
				continue;
			}
			if let Some(key) = program {
				let prepared = match self.inner.db.get_program_recovery(vtxo.point()).await? {
					Some(record) => verify_program_recovery(&vtxo, &record, false)
						.and_then(|()| verify_program_recovery_template(&record, &key)),
					None => Err(anyhow!("program deposit was not prepared")),
				};
				if prepared.is_err() {
					self.extension_quarantine_receive(&vtxo, bytes, "program deposit has no verified prepared recovery").await?;
					continue;
				}
				if self.extension_ensure_recovery(std::slice::from_ref(&vtxo)).await.is_err() {
					self.extension_quarantine_receive(&vtxo, bytes, "program deposit recovery is not ready").await?;
					continue;
				}
			} else if self.find_signable_clause_strict(&vtxo).await?.is_none() {
				error!("Refusing received arkoor VTXO {}: not owned by this wallet", vtxo.id());
				invalid_vtxos.push(bytes);
				continue;
			}

			if vtxo.expiry_height() <= tip {
				warn!("Received arkoor VTXO {} that expired at height {} (tip {}); \
					keeping it, it needs a refresh", vtxo.id(), vtxo.expiry_height(), tip,
				);
			}

			valid_vtxos.push(vtxo);
		}

		// We log all invalid VTXOs to keep track
		if !invalid_vtxos.is_empty() {
			error!("Received {} invalid arkoor VTXOs out of {} from server",
				invalid_vtxos.len(), raw_vtxos.len(),
			);
		}

		Ok(valid_vtxos)
	}

	/// Process a single mailbox message and report whether the caller should
	/// keep consuming the mailbox.
	///
	/// Returns [`ControlFlow::Break`] when a message failed to process on a
	/// transient error and its checkpoint was therefore not advanced. Because
	/// checkpoints are monotonic, the caller must stop before a later message
	/// stores a higher checkpoint and buries the unprocessed one; the next
	/// sync/resubscribe re-fetches from the unadvanced checkpoint and retries.
	///
	/// # Errors
	///
	/// The server-claimed checkpoint is vetted and persisted only after the
	/// message was processed; a vetting rejection or a store failure is
	/// returned as an error with the cursor left unchanged, so processing
	/// halts and the message can be redelivered instead of silently
	/// advancing past a cursor that was never durably written.
	pub(crate) async fn process_mailbox_message(
		&self,
		mailbox_msg: MailboxMessage,
	) -> anyhow::Result<ControlFlow<()>> {
		use protos::mailbox_server::mailbox_message::Message;

		// Each arm returns whether the checkpoint should advance. Arkoor
		// and round participation return false on a transient processing
		// error so the server redelivers and we retry; their handlers
		// absorb invalid server data, since retrying can't fix that.
		// Every other arm advances regardless, either because the work is
		// idempotent and re-done on every wallet sync, or because the
		// message is informational/ignored.
		let advance = match mailbox_msg.message {
			Some(Message::Arkoor(msg)) => {
				match self.process_received_arkoor_package(msg.vtxos).await {
					Ok(()) => true,
					Err(e) => {
						error!("Error processing received arkoor package: {:#}", e);
						false
					}
				}
			}
			Some(Message::RoundParticipationCompleted(msg)) => {
				match self.handle_round_participation_completed(msg).await {
					Ok(()) => true,
					Err(e) => {
						error!("Error handling round participation completed \
							message: {:#}", e,
						);
						false
					}
				}
			},
			Some(Message::IncomingLightningPayment(msg)) => {
				if let Err(e) = self.handle_lightning_receive_notification(msg).await {
					error!("Error handling lightning receive notification: {:#}", e);
				}
				true
			},
			Some(Message::RecoveryVtxoIds(_)) => {
				trace!("Received recovery VTXO IDs, ignoring");
				true
			}
			Some(Message::LightningSendFinished(msg)) => {
				if let Err(e) = self.handle_lightning_send_finished(msg).await {
					error!("Error handling lightning send finished notification: {:#}", e);
				}
				true
			}
			None => {
				warn!("Received unknown mailbox message kind at checkpoint {}; bark may need to be upgraded",
					mailbox_msg.checkpoint);
				true
			}
		};

		if advance {
			self.advance_mailbox_checkpoint(mailbox_msg.checkpoint).await?;
			Ok(ControlFlow::Continue(()))
		} else {
			// The message didn't process and its checkpoint wasn't
			// advanced. Stop here so a later message can't store a higher
			// checkpoint and bury it.
			Ok(ControlFlow::Break(()))
		}
	}

	/// Vet the server-claimed checkpoint of a processed message and persist
	/// it as the new durable cursor.
	///
	/// The claim is server-controlled input: it is checked against the
	/// freshly read cursor (see [vet_server_checkpoint]) before anything is
	/// written, and read/store failures propagate so the caller halts with
	/// the cursor unchanged instead of logging and continuing past a cursor
	/// that was never durably written.
	async fn advance_mailbox_checkpoint(&self, claimed: u64) -> anyhow::Result<()> {
		let current = self.get_mailbox_checkpoint().await
			.context("failed to read mailbox checkpoint")?;
		match vet_server_checkpoint(current, claimed)? {
			CheckpointVerdict::Advance => {
				self.store_mailbox_checkpoint(claimed).await?;
			},
			CheckpointVerdict::AlreadyCovered => {
				trace!("Mailbox checkpoint {} already covered by stored cursor {}", claimed, current);
			},
		}
		Ok(())
	}

	async fn process_received_arkoor_package(
		&self,
		raw_vtxos: Vec<Vec<u8>>,
	) -> anyhow::Result<()> {
		let vtxos = self.process_raw_vtxos(raw_vtxos).await?;
		if let Err(e) = self.register_vtxo_transactions_with_server(&vtxos).await {
			warn!("Failed to register received arkoor vtxo transactions with server: {:#}", e);
		}
		self.store_received_arkoor_package(vtxos).await
	}

	/// Store a fully validated receive. Coordinated delivery calls this only after
	/// the recovery package is durable; it does not require the Ark server online.
	pub(crate) async fn store_received_arkoor_package(
		&self,
		vtxos: Vec<Vtxo<Full>>,
	) -> anyhow::Result<()> {

		// Serialize the receive dedup across all consumers of this wallet's
		// mailbox so two of them can't both record a movement for the same
		// package. See MAILBOX_PROCESSING_LOCK_KEY. On lock failure we
		// return like any other arkoor processing error, leaving this
		// message's checkpoint unadvanced.
		let _guard = self.inner.lock_manager.lock(
			MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
		).await.context("failed to acquire mailbox processing lock")?;

		// Everything works off of a deduplicated set. This is important to avoid accounting
		// mistakes in the movement and marking the entire package as spendable, even if it contains
		// VTXOs we already marked as spent.
		let mut new_vtxos = Vec::<Vtxo<Full>>::with_capacity(vtxos.len());
		for vtxo in vtxos {
			// Skip if the VTXO is already in the wallet or is in the VTXO list multiple times.
			let vtxo_id = vtxo.id();
			if new_vtxos.iter().any(|v| v.id() == vtxo_id) {
				debug!("Ignoring duplicate VTXO {} in arkoor package", vtxo_id);
			} else if self.inner.db.get_wallet_vtxo(vtxo_id).await?.is_some() {
				debug!("Ignoring already-known VTXO {} in arkoor package", vtxo_id);
			} else {
				trace!("Received VTXO {} for {} in arkoor package", vtxo_id, vtxo.amount());
				new_vtxos.push(vtxo);
			}
		}
		if new_vtxos.is_empty() {
			return Ok(());
		}

		// TODO: Make sure we don't effectively skip the entire package if the movement fails to
		//       be recorded due to bark getting killed after this point.
		//
		// The amounts come from the Ark server or a mailbox peer: checked
		// accumulation (never `sum::<Amount>`, which panics on overflow), so a
		// forged package is rejected with an error instead of crashing. See
		// [crate::utils::checked_sum_amounts].
		let balance = crate::utils::checked_sum_amounts(
			new_vtxos.iter().map(|vtxo| vtxo.amount()),
		).context("ignoring corrupt arkoor package")?.to_signed()?;
		self.store_spendable_vtxos(&new_vtxos).await?;

		// Build received_on destinations from received VTXOs, aggregated by address
		let mut received_by_address = HashMap::<ark::Address, Amount>::new();
		for vtxo in &new_vtxos {
			if let Ok(Some(index)) = self.inner.db.get_public_key_idx(&vtxo.user_pubkey()).await {
				if let Ok(address) = self.peek_address(index).await {
					// Cannot overflow: per-address sums are subsets of the
					// package total, which was bound-checked above.
					*received_by_address.entry(address).or_default() += vtxo.amount();
				}
			}
		}
		let received_on: Vec<_> = received_by_address
			.iter()
			.map(|(addr, amount)| MovementDestination::ark(addr.clone(), *amount))
			.collect();

		let movement_id = self.inner.movements.new_finished_movement(
			Subsystem::ARKOOR,
			ArkoorMovement::Receive.to_string(),
			MovementStatus::Successful,
			MovementUpdate::new()
				.produced_vtxos(&new_vtxos)
				.intended_and_effective_balance(balance)
				.received_on(received_on),
		).await?;

		info!("Received arkoor (movement {}) for {}", movement_id, balance);

		Ok(())
	}

	/// Retain rejected wire bytes only as diagnostic metadata. They must never
	/// establish a canonical VTXO row: a forged outpoint could otherwise prevent
	/// a later valid, prepared payment from being accepted.
	pub(crate) async fn quarantine_program_receive(
		&self,
		vtxo: &Vtxo<Full>,
		raw: &[u8],
		reason: &str,
	) -> anyhow::Result<()> {
		let _guard = self.inner.lock_manager.lock(
			MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
		).await?;
		if self.inner.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
			return Ok(());
		}
		// Diagnostic bytes are attacker-supplied; keep only a bounded prefix.
		let retained = &raw[..raw.len().min(MAX_QUARANTINE_RAW_BYTES)];
		let mut raw_hex = retained.as_hex().to_string();
		if retained.len() < raw.len() {
			raw_hex.push_str(&format!("... ({} bytes truncated)", raw.len() - retained.len()));
		}
		let movement = self.inner.movements.get_or_create_movement_with_action(
			Subsystem::ARKOOR,
			"program-receive-quarantine",
			&format!("program-quarantine.{}", vtxo.id()),
			MovementUpdate::new().metadata([
				("reason".into(), serde_json::Value::String(reason.to_owned())),
				("raw_vtxo".into(), serde_json::Value::String(raw_hex)),
			]),
		).await?;
		warn!("Quarantined unsafe program deposit {} (movement {}): {}", vtxo.id(), movement, reason);
		Ok(())
	}

	/// Handle a mailbox notice that a delegated round participation completed.
	///
	/// Only returns an error when the recovery failed on something transient,
	/// so the caller can leave the checkpoint unadvanced and retry on
	/// redelivery. Invalid message content is logged and dropped.
	async fn handle_round_participation_completed(
		&self,
		msg: protos::mailbox_server::RoundParticipationCompleted,
	) -> anyhow::Result<()> {
		match UnlockHash::from_slice(&msg.unlock_hash) {
			Ok(unlock_hash) => {
				info!("Server informed that round participation is ready, \
					unlock_hash: {}", unlock_hash,
				);
				self.recover_delegated_participation(unlock_hash).await.with_context(||
					format!("error recovering delegated round participation {}", unlock_hash),
				)?;
			},
			Err(e) => warn!("Received round participation completed message \
				with invalid unlock hash: {}", e,
			),
		}
		if let Err(e) = self.sync_pending_rounds().await {
			error!("Error syncing pending rounds: {:#}", e);
		}
		Ok(())
	}

	/// Handle a lightning receive notification from the mailbox.
	///
	/// This is a signal that the server has received a lightning payment for us
	/// and we should come online to claim it.
	async fn handle_lightning_receive_notification(
		&self,
		notif: protos::mailbox_server::IncomingLightningPaymentMessage,
	) -> anyhow::Result<()> {
		let payment_hash = PaymentHash::try_from(notif.payment_hash)
			.context("invalid payment hash in lightning receive notification")?;

		debug!("Lightning receive notification: payment_hash={}", payment_hash);

		match self.try_claim_lightning_receive(payment_hash, false).await {
			Ok(_) => info!("Lightning receive claimed via mailbox notification for {}", payment_hash),
			Err(e) => error!("Failed to claim lightning receive for {}: {:#}", payment_hash, e),
		}

		Ok(())
	}

	/// Handle a lightning send finished notification from the mailbox.
	///
	/// This notification indicates that the server has completed processing
	/// a lightning payment we initiated, either successfully or with failure.
	///
	/// The mailbox checkpoint is vetted and advanced by the caller; handler
	/// errors are logged but never propagated, because re-processing the
	/// same notification on the next poll is worse than dropping it.
	async fn handle_lightning_send_finished(
		&self,
		notif: protos::mailbox_server::LightningSendFinishedMessage,
	) -> anyhow::Result<()> {
		let payment_hash = PaymentHash::try_from(notif.payment_hash)
			.context("invalid payment hash in lightning send finished notification")?;

		let known_preimage = notif.preimage
			.and_then(|bytes| Preimage::try_from(bytes).ok());

		if known_preimage.is_some() {
			debug!("Lightning send finished notification (success): payment_hash={}", payment_hash);
		} else {
			debug!("Lightning send finished notification (failed): payment_hash={}", payment_hash);
		}

		// Errors are logged but not propagated: the caller always advances
		// the mailbox checkpoint to avoid re-processing the same
		// notification on the next poll.
		match self.is_invoice_paid(payment_hash).await {
			Ok(true) => {
				debug!("Lightning send {} already settled; ignoring notification", payment_hash);
			},
			Ok(false) => {
				let lookup = self.lightning_send_checkpoint(payment_hash).await;
				match lookup {
					Ok(Some(send)) => {
						let result = match (&send.progress, known_preimage) {
							(Progress::PaymentInitiated(_), Some(preimage)) => {
								self.settle_lightning_send_with_preimage(payment_hash, preimage).await
							},
							(Progress::PaymentInitiated(_), None) => {
								self.drive_action(send, DriveMode::UntilParkOrDone).await
							},
							_ => {
								debug!("Lightning send finished notification for {} but checkpoint is not PaymentInitiated; ignoring", payment_hash);
								Ok(())
							},
						};
						match result {
							Ok(()) => info!("Processed lightning send finished for {}", payment_hash),
							Err(e) => error!("Failed to process lightning send finished for {}: {:#}", payment_hash, e),
						}
					},
					Ok(None) => {
						warn!("Lightning send finished notification for unknown payment hash {}", payment_hash);
					},
					Err(e) => {
						error!("Failed to look up lightning send checkpoint for {}: {:#}", payment_hash, e);
					},
				}
			},
			Err(e) => {
				error!("Failed to look up paid_invoice for {}: {:#}", payment_hash, e);
			},
		}

		Ok(())
	}

	/// Post vtxo IDs to the server's recovery mailbox
	pub async fn post_recovery_vtxo_ids(
		&self,
		vtxo_ids: impl IntoIterator<Item = VtxoId>,
	) -> anyhow::Result<()> {
		let vtxo_ids = vtxo_ids.into_iter().map(|id| id.to_bytes().to_vec()).collect::<Vec<_>>();
		if vtxo_ids.is_empty() {
			return Ok(());
		}
		let nb_vtxos = vtxo_ids.len();

		// Prove ownership of the recovery mailbox; short validity is enough as
		// it's consumed by this single request.
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(60);
		let auth = MailboxAuthorization::new(&self.recovery_mailbox_keypair(), expiry);
		let mailbox_id = self.recovery_mailbox_identifier().serialize();

		let (mut srv, _) = self.require_server().await?;
		for chunk in vtxo_ids.chunks(MAX_NB_MAILBOX_RECOVERY_IDS) {
			let req = protos::mailbox_server::PostRecoveryVtxoIdsRequest {
				mailbox_id: mailbox_id.clone(),
				vtxo_ids: chunk.to_vec(),
				authorization: Some(auth.serialize()),
			};

			srv.mailbox_client.post_recovery_vtxo_ids(req).await
				.context("error posting recovery vtxo IDs to server")?;
		}

		debug!("Posted {} recovery vtxo IDs to server", nb_vtxos);
		Ok(())
	}

	/// Return the stored mailbox checkpoint — the tip position the wallet
	/// has consumed up to. After a successful [`Self::sync_mailbox`], this value
	/// reflects the server's latest advertised tip.
	pub async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		Ok(self.inner.db.get_mailbox_checkpoint().await?)
	}

	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()> {
		Ok(self.inner.db.store_mailbox_checkpoint(checkpoint).await?)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use ark::SECP;
	use ark::test_util::VTXO_VECTORS;
	use bitcoin::secp256k1::Keypair;

	/// The arkoor receive path must only store final, self-custodial coins for
	/// our own server. This pins the two ways a received vtxo can be unsafe.
	#[test]
	fn arkoor_receive_policy_gate() {
		let vectors = &*VTXO_VECTORS;
		let server_pubkey = vectors.server_key.public_key();

		// A final Pubkey payment vtxo committing to our server is acceptable.
		let good = &vectors.board_vtxo;
		check_arkoor_receive_policy(good, server_pubkey)
			.expect("a Pubkey vtxo must be accepted");

		// An HTLC-send vtxo is an in-flight contract, not a payment.
		let htlc = &vectors.arkoor_htlc_out_vtxo;
		check_arkoor_receive_policy(htlc, server_pubkey)
			.expect_err("an HTLC-send vtxo must be refused as a payment");

		// A vtxo committing to some other server's key is not ours to trust.
		let foreign_server = Keypair::from_seckey_slice(&SECP, &[0x11; 32])
			.unwrap().public_key();
		check_arkoor_receive_policy(good, foreign_server)
			.expect_err("a vtxo for a foreign server must be refused");
	}

	/// Arkoor-receive validation failures split into absorbed deterministic
	/// rejections and abort-the-message transient ones. Only the abort side
	/// is safe to leave the mailbox checkpoint unadvanced; absorbing a
	/// transient failure would advance the checkpoint past a genuine
	/// payment that was never credited.
	#[test]
	fn arkoor_validation_classification() {
		use crate::vtxo::VtxoValidationError as E;

		// Valid stays valid.
		assert!(classify_arkoor_validation(Ok(()))
			.expect("valid").is_none(), "a valid VTXO yields nothing to absorb");

		// A provably invalid VTXO is absorbed (Ok(Some)): retrying can't
		// fix bad bytes.
		let absorbed = classify_arkoor_validation(Err(E::Invalid(
			ark::vtxo::VtxoValidationError::Invalid("bad genesis signature"),
		))).expect("a deterministic rejection must be absorbable");
		assert!(absorbed.is_some());

		// A chain-backend error is transient: bubble it out so processing
		// aborts and the checkpoint is left unchanged.
		classify_arkoor_validation(Err(E::Chain(anyhow::anyhow!("backend 503"))))
			.expect_err("a chain backend error must abort, not be absorbed");

		// An anchor the backend has not indexed yet is transient for the
		// same reason.
		classify_arkoor_validation(Err(E::AnchorNotFound))
			.expect_err("a missing anchor must abort, not be absorbed");
	}

	/// The server-stamped checkpoint is untrusted input: persist only
	/// advances whose embedded timestamp is plausible (captaind stamps
	/// checkpoints as `(unix_ms << 20) | per_ms_counter`), and never rewind.
	#[test]
	fn server_checkpoint_vetting() {
		let shift = |ms: u64, counter: u64| (ms << MAILBOX_CHECKPOINT_COUNTER_BITS) | counter;
		let now_ms = chrono::Local::now().timestamp_millis() as u64;

		// A fresh wallet's cursor is 0 while the first honest claim is
		// time-now-shifted (~1.9e18): that jump over the cursor must pass.
		assert_eq!(
			vet_server_checkpoint(0, shift(now_ms, 0)).unwrap(),
			CheckpointVerdict::Advance,
		);

		// Two stamps a millisecond apart differ by 2^20 and both must
		// advance over the previous one.
		let first = shift(now_ms, 3);
		let second = shift(now_ms + 1, 0);
		assert!(second > first);
		assert_eq!(
			vet_server_checkpoint(first, second).unwrap(),
			CheckpointVerdict::Advance,
		);

		// A stamp slightly ahead of local time (clock skew both sides) is
		// accepted.
		assert_eq!(
			vet_server_checkpoint(0, shift(now_ms + 60_000, 7)).unwrap(),
			CheckpointVerdict::Advance,
		);

		// Far-future claims are refused as a server protocol violation,
		// including the u64-range poison values from the attack scenario.
		assert!(vet_server_checkpoint(first, u64::MAX - 7).is_err());
		assert!(vet_server_checkpoint(0, shift(now_ms, 0).wrapping_mul(2)).is_err());
		assert!(
			vet_server_checkpoint(0, shift(now_ms + 2 * 24 * 60 * 60 * 1000, 0)).is_err(),
			"a claim two days ahead exceeds the allowed skew",
		);

		// Equal or lower claims are already covered by the stored cursor
		// (a racing consumer stored them first): nothing to persist, no
		// error, and no rewind — also at the numeric edge.
		assert_eq!(vet_server_checkpoint(second, second).unwrap(), CheckpointVerdict::AlreadyCovered);
		assert_eq!(vet_server_checkpoint(second, first).unwrap(), CheckpointVerdict::AlreadyCovered);
		assert_eq!(vet_server_checkpoint(u64::MAX, u64::MAX).unwrap(), CheckpointVerdict::AlreadyCovered);
	}

	/// A forged package of repeated maximum-value VTXOs must be rejected with
	/// an error, never crash the receive path: the amounts are untrusted.
	#[test]
	fn received_package_amounts_never_panic() {
		use ark::test_util::dummy::DummyTestVtxoSpec;

		// The dummy spec takes its fee out of `amount`, leaving a VTXO just
		// under MAX_MONEY — large enough that any second one breaks the bound.
		let (_funding, vtxo) = DummyTestVtxoSpec {
			amount: Amount::MAX_MONEY, ..Default::default()
		}.build();

		// One huge VTXO is still accepted.
		assert_eq!(
			crate::utils::checked_sum_amounts([vtxo.amount()]).unwrap(),
			vtxo.amount(),
		);
		assert!(vtxo.amount().to_signed().is_ok());

		// Two exceed the money supply: error, not an overflowing panic.
		crate::utils::checked_sum_amounts([vtxo.amount(), vtxo.amount()]).unwrap_err();
		// Any number of maximum-value amounts behaves the same.
		crate::utils::checked_sum_amounts(
			std::iter::repeat(Amount::MAX_MONEY).take(9),
		).unwrap_err();
	}
}
