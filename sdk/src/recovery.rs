//! Wallet recovery from seed.
//!
//! As a wallet creates or receives VTXOs it posts their ids to a mailbox keyed
//! by a dedicated, seed-derived recovery key (see
//! [`Wallet::post_recovery_vtxo_ids`]). Recovering the seed re-derives that key
//! and reads back every posted id to rebuild the VTXO set. The regular
//! mailbox's arkoor messages are replayed too, since the recovery post is
//! best-effort and a VTXO can be missing there.
//!
//! Note that recovery is a trusted process. The server can withhold VTXOs
//! or may falsely represent spendable VTXOs as spent. Prefer to maintain
//! back-ups and use recovery from the mnemonic as a last resort.
//!
//! Mailbox content is server-controlled input, so the work it can force is
//! bounded: a run pays per-candidate processing work for at most
//! [`MAX_RECOVERY_CANDIDATES_PER_RUN`] unknown candidates, and the BIP32
//! gap-limit key scan is batched per mailbox page instead of running per
//! candidate. Candidates an earlier run already stored are classified without
//! spending budget — terminal states are mirrored into the report, while rows
//! that were never a decision (e.g. provisional `Spendable` after a failed
//! status request) are re-checked in full — so successive runs keep making
//! progress even when the mailbox re-reads from checkpoint 0 in the same
//! order. A flooded mailbox degrades a run to an incomplete [`RecoveryReport`]
//! (overflow counted, ids deliberately unrecorded) rather than stalling the
//! wallet.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::Keypair;
use log::{debug, info, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::MailboxAuthorization;
use ark::vtxo::Full;
use server_rpc::TryFromBytes;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use crate::Wallet;
use crate::mailbox::MAX_MAILBOX_REQUEST_BURST;
use crate::sapio::VtxoSigningKey;
use crate::vtxo::{ServerStatusAdoption, VtxoState};

/// Maximum number of distinct mailbox VTXO candidates a single recovery run
/// processes.
///
/// Classifying a candidate costs its owner-controlled body fetch, chain
/// validation, key-space scan share and spend-status request — all work the
/// server can multiply at tens of bytes per fabricated candidate. Capping the
/// count turns a mailbox flood into an incomplete report (overflow is counted
/// in [`RecoveryReport::budget_overflow`]) instead of an unbounded, synchronous
/// CPU and network burn during wallet open. Candidates an earlier run already
/// decided are accounted from the wallet's own records and do not consume this
/// budget, so successive runs keep making progress on the unprocessed tail.
/// The value is far above any plausible genuine wallet history.
const MAX_RECOVERY_CANDIDATES_PER_RUN: usize = 10_000;

/// Bookkeeping for the per-run candidate cap: how many distinct candidates
/// this run may still process. Overflow ids get no per-candidate bookkeeping
/// at all — a flood must not translate into unbounded memory either.
struct RecoveryCandidateBudget {
	remaining: usize,
}

impl RecoveryCandidateBudget {
	fn new(cap: usize) -> Self {
		Self { remaining: cap }
	}

	fn is_exhausted(&self) -> bool {
		self.remaining == 0
	}

	/// Spend one slot on a candidate about to be processed. Callers must gate
	/// on [`Self::is_exhausted`] first.
	fn consume(&mut self) {
		debug_assert!(!self.is_exhausted(), "budget gated by is_exhausted");
		self.remaining = self.remaining.saturating_sub(1);
	}
}

/// What the wallet's records conclude about a mailbox candidate id; see
/// [`Wallet::classify_stored_candidate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateRecord {
	/// No stored row: an unknown, adversarial candidate that spends budget.
	Unknown,
	/// Stored in a terminal state (`Spent`/`Exited`); mirrored into the report
	/// with no new work and no budget spend.
	Decided,
	/// Stored but not finally decided — a provisional `Spendable` row from a
	/// failed spend-status request, or `Locked` in an in-flight operation.
	/// Owned (only ownership-confirmed VTXOs are ever stored), so re-checked in
	/// full without spending budget.
	NeedsRecheck,
}

#[derive(Debug, Default, Clone)]
pub struct RecoveryReportEntry(HashMap<VtxoId, Option<Amount>>);

impl RecoveryReportEntry {
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn ids(&self) -> impl Iterator<Item = VtxoId> {
		self.0.keys().cloned()
	}

	pub fn total_amount(&self) -> Amount {
		self.0.values().filter_map(|a| *a).sum()
	}

	fn insert(&mut self, vtxo_id: VtxoId, amount: Option<Amount>) {
		if !self.0.contains_key(&vtxo_id) {
			self.0.insert(vtxo_id, amount);
		}
	}

	fn remove(&mut self, vtxo_id: VtxoId) {
		self.0.remove(&vtxo_id);
	}
}

/// Summary of a recovery scan over the mailboxes.
///
/// `skipped` vs `failed` is the load-bearing distinction: a `skipped` VTXO was
/// *decided* not to be spendable (spent, exited on-chain, or reported
/// non-spendable), whereas a `failed` VTXO could not be decided due to an error.
/// A non-empty `failed` or `foreign` set means funds may be missing, so it must
/// not be taken for a complete recovery. Ids are kept (not counted) so a caller
/// can log or retry the exact VTXOs.
#[derive(Debug, Default, Clone)]
pub struct RecoveryReport {
	/// Spendable VTXOs that were successfully re-imported.
	recovered: RecoveryReportEntry,
	/// VTXOs deliberately left out: reported spent or still in-flight by the
	/// server.
	skipped: RecoveryReportEntry,
	/// VTXOs recovery could not decide on: the fetch, validation, or status
	/// request failed.
	failed: RecoveryReportEntry,
	/// VTXOs found in the mailbox whose key we could not derive within the gap
	/// limit. Only the seed owner can post here, so these are most likely our own
	/// VTXOs whose key sits beyond the gap limit; their presence means funds may
	/// be missing and the scan can't be reported complete.
	foreign: RecoveryReportEntry,
	/// VTXOs that have been fully exited on-chain.
	exited: RecoveryReportEntry,
	/// Count of mailbox candidates never processed because the run hit its
	/// candidate budget. Their ids are deliberately not recorded — a flooded
	/// mailbox can deliver millions — but a nonzero value means funds may be
	/// missing just like `failed`/`foreign` do.
	budget_overflow: usize,
}

impl RecoveryReport {
	/// Whether the scan accounted for every VTXO in the mailbox.
	///
	/// A `failed` VTXO, a `foreign` id or any budget overflow all mean funds may
	/// be missing, so none may be present. `failed` is retryable; a `foreign` id
	/// instead needs a wider gap limit to be matched, and budget overflow needs
	/// further runs once this one has decided its candidates.
	pub fn is_complete(&self) -> bool {
		self.failed.is_empty() && self.foreign.is_empty() && self.budget_overflow == 0
	}

	pub fn recovered(&self) -> &RecoveryReportEntry {
		&self.recovered
	}

	pub fn push_recovered<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.recovered.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn skipped(&self) -> &RecoveryReportEntry {
		&self.skipped
	}

	pub fn push_skipped<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.skipped.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn foreign(&self) -> &RecoveryReportEntry {
		&self.foreign
	}

	pub fn push_foreign<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.foreign.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn failed(&self) -> &RecoveryReportEntry {
		&self.failed
	}

	pub fn push_failed(&mut self, id: VtxoId, amount: Option<Amount>) {
		self.failed.insert(id, amount);
	}

	pub fn exited(&self) -> &RecoveryReportEntry {
		&self.exited
	}

	/// How many mailbox candidates were left unprocessed because the run hit
	/// its candidate budget. See the `budget_overflow` field for why no ids
	/// are kept.
	pub fn budget_overflow(&self) -> usize {
		self.budget_overflow
	}

	fn push_budget_overflow(&mut self, n: usize) {
		self.budget_overflow += n;
	}

	pub fn push_exited<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.exited.insert(vtxo.id(), Some(vtxo.amount()));
	}
}

/// Outcome of the recovery scan on wallet open.
///
/// [`crate::OpenWalletArgs::on_recovery_finished`] is called exactly once per
/// successful open, with one of these. A caller never has to read meaning into
/// the callback staying silent: not running and failing are both stated.
#[derive(Debug)]
pub enum RecoveryStatus {
	/// No scan was attempted: the wallet already existed, or the caller set
	/// [`crate::OpenWalletArgs::skip_recovery`].
	NotRun,
	/// The scan errored before it could produce a report. Nothing is known about
	/// the mailbox's VTXOs, so funds may be missing until a retry succeeds.
	Failed(anyhow::Error),
	/// The scan ran to the end. Check [`RecoveryReport::is_complete`]: a finished
	/// scan can still leave individual VTXOs unaccounted for.
	Completed(RecoveryReport),
}

impl Wallet {
	/// Page a mailbox from checkpoint 0 and recover every VTXO it references.
	///
	/// Ids already in `seen` are skipped, so a VTXO both mailboxes know about is
	/// handled once. Each fetched page is recovered as a batch: fresh candidates
	/// are resolved to full bodies first, then validated and put through a
	/// single gap-limit key scan covering the whole page (see
	/// [`Wallet::recover_candidates`]), so a page of fabricated candidates pays
	/// one scan window, not one per candidate. `budget` caps how many unknown
	/// candidates the whole run processes, gated per id so a single oversized
	/// message cannot overrun it; candidates already stored are classified per
	/// [`Wallet::classify_stored_candidate`] without spending budget, and once
	/// the budget is exhausted overflow is only counted in the report — no
	/// per-id bookkeeping at all.
	///
	/// The paging cursor is never persisted: the server allocates checkpoints
	/// globally across all mailboxes, so storing it would make the next regular
	/// sync skip unrelated events. The regular sync still processes every message
	/// from its own stored checkpoint afterwards.
	async fn scan_mailbox_for_recovery(
		&self,
		report: &mut RecoveryReport,
		keypair: &Keypair,
		gap_limit: u32,
		seen: &mut HashSet<VtxoId>,
		budget: &mut RecoveryCandidateBudget,
	) -> anyhow::Result<()> {
		let (mut srv, _) = self.require_server().await?;

		// The paging burst should be done well within this window.
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
		let auth = MailboxAuthorization::new(keypair, expiry);
		let mailbox_id = auth.mailbox();

		let mut checkpoint = 0u64;
		for iteration in 1..=MAX_MAILBOX_REQUEST_BURST {
			let req = protos::mailbox_server::MailboxRequest {
				mailbox_id: mailbox_id.serialize(),
				authorization: Some(auth.serialize()),
				checkpoint,
			};
			let resp = srv.mailbox_client.read_mailbox(req).await
				.context("error reading the mailbox for recovery")?.into_inner();

			debug!("Mailbox returned {} messages on recovery iteration {iteration}",
				resp.messages.len());

			let prev_checkpoint = checkpoint;

			// Resolve this page's fresh candidates to full VTXO bodies first, so
			// the key scan below runs once for the whole page.
			let mut page: Vec<Vtxo<Full>> = Vec::new();
			for msg in &resp.messages {
				checkpoint = checkpoint.max(msg.checkpoint);

				// A message references its vtxos either by id or by full body.
				match &msg.message {
					Some(Message::RecoveryVtxoIds(m)) => {
						self.intake_id_refs(report, &m.vtxo_ids, seen, budget, &mut page).await?;
					},
					Some(Message::Arkoor(m)) => {
						self.intake_vtxo_bodies(report, &m.vtxos, seen, budget, &mut page).await?;
					},
					Some(Message::RoundParticipationCompleted(_)) |
					Some(Message::IncomingLightningPayment(_)) |
					Some(Message::LightningSendFinished(_)) => {},
					None => {
						warn!("Mailbox returned a message with no content: {msg:?}");
					},
				}
			}

			self.recover_candidates(report, page, gap_limit).await?;

			if !resp.have_more {
				break;
			}

			// The server wants us to keep paging, but the checkpoint didn't
			// advance, so the next request would be identical and we'd loop
			// forever. Stop rather than spin on the same page.
			if checkpoint == prev_checkpoint {
				warn!("Mailbox recovery iteration {iteration} made no progress \
					at checkpoint {checkpoint}; stopping");
				break;
			}
		}

		Ok(())
	}

	/// Fetch the full [`Vtxo<Full>`] for `id` from the server.
	///
	/// The recovery mailbox only stores ids, so we ask the server for the full
	/// VTXO data. The result is untrusted until validated by the caller.
	pub(crate) async fn fetch_vtxo(&self, id: VtxoId) -> anyhow::Result<Vtxo<Full>> {
		let (mut srv, _) = self.require_server().await?;
		let resp = srv.client.get_vtxo(protos::GetVtxoRequest {
			vtxo_id: id.to_bytes().to_vec(),
		}).await.with_context(|| format!("error fetching vtxo {id} from server"))?.into_inner();

		Vtxo::<Full>::deserialize(&resp.vtxo)
			.with_context(|| format!("server returned an undecodable vtxo for {id}"))
	}

	/// Check if a VTXO is confirmed on-chain.
	///
	/// If it is, we store it as exited and return `true`.
	/// If we could not confirm the exit status, we consider it is not exited yet and return `false`.
	async fn check_vtxo_onchain_status(
		&self,
		report: &mut RecoveryReport,
		vtxo: &Vtxo<Full>,
	) -> anyhow::Result<bool> {
		// An off-chain VTXO's tx is only confirmed once it has been exited,
		// so if we see it on-chain the funds live in the on-chain wallet and
		// it must not be recovered as spendable. The server's spend status
		// doesn't capture unilateral exits, so we check the chain ourselves.
		match self.inner.chain.tx_confirmed(vtxo.point().txid).await {
			Ok(Some(height)) => {
				// A row from an earlier, failed recovery attempt is forced along.
				self.store_vtxos([vtxo], &VtxoState::Exited).await?;
				self.mark_vtxos_as_exited(&[vtxo.id()]).await?;
				if self.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_none() {
					self.exit_mgr()
						.start_exit_for_vtxos_including_non_standard(&[vtxo.to_bare()]).await?;
				}
				report.push_exited(vtxo);
				debug!("Skipping recovery vtxo {}: confirmed on-chain at height {height} (exited)", vtxo.id());
				Ok(true)
			},
			// If we could not confirm the exit status, we consider it is not exited yet.
			// If it actually is, next wallet sync will handle it properly
			Ok(None) | Err(_) => Ok(false),
		}
	}

	/// Intake the id references of one mailbox message into the page batch.
	///
	/// The budget is gated per id, before any decode or other work, so a single
	/// message carrying more ids than the remaining budget can neither overrun
	/// the cap nor trip its assertion. Anything past the cap is counted in
	/// [`RecoveryReport::budget_overflow`] with no per-id records at all — not
	/// even `seen` — so a flood cannot fill memory. Ids already stored by an
	/// earlier run are classified per [`Wallet::classify_stored_candidate`];
	/// only unknown candidates spend budget.
	async fn intake_id_refs(
		&self,
		report: &mut RecoveryReport,
		refs: &[Vec<u8>],
		seen: &mut HashSet<VtxoId>,
		budget: &mut RecoveryCandidateBudget,
		page: &mut Vec<Vtxo<Full>>,
	) -> anyhow::Result<()> {
		for raw in refs {
			if budget.is_exhausted() {
				report.push_budget_overflow(1);
				continue;
			}
			let Ok(id) = VtxoId::from_bytes(raw.clone()) else {
				warn!("Ignoring undecodable recovery vtxo id: {raw:?}");
				continue;
			};
			if !seen.insert(id) {
				continue;
			}
			match self.classify_stored_candidate(report, id).await? {
				CandidateRecord::Decided => continue,
				// Only unknown candidates spend adversarial budget; stored
				// (hence ours) ones being re-checked do not.
				CandidateRecord::NeedsRecheck => {},
				CandidateRecord::Unknown => budget.consume(),
			}
			match self.fetch_vtxo(id).await {
				Ok(vtxo) => page.push(vtxo),
				Err(e) => {
					warn!("Could not fetch recovery vtxo {id}: {:#}", e);
					report.push_failed(id, None);
				},
			}
		}
		Ok(())
	}

	/// Intake the full VTXO bodies of one arkoor mailbox message into the page
	/// batch. Budget semantics are identical to [`Wallet::intake_id_refs`].
	async fn intake_vtxo_bodies(
		&self,
		report: &mut RecoveryReport,
		raws: &[Vec<u8>],
		seen: &mut HashSet<VtxoId>,
		budget: &mut RecoveryCandidateBudget,
		page: &mut Vec<Vtxo<Full>>,
	) -> anyhow::Result<()> {
		for raw in raws {
			if budget.is_exhausted() {
				report.push_budget_overflow(1);
				continue;
			}
			let Ok(vtxo) = Vtxo::<Full>::from_bytes(raw.clone()) else {
				warn!("Ignoring undecodable arkoor vtxo: {raw:?}");
				continue;
			};
			let id = vtxo.id();
			if !seen.insert(id) {
				continue;
			}
			match self.classify_stored_candidate(report, id).await? {
				CandidateRecord::Decided => continue,
				CandidateRecord::NeedsRecheck => {},
				CandidateRecord::Unknown => budget.consume(),
			}
			page.push(vtxo);
		}
		Ok(())
	}

	/// Classify a mailbox candidate against the wallet's own records, mirroring
	/// terminal decisions into `report`.
	///
	/// Mirroring decided VTXOs from stored state avoids re-paying
	/// attacker-rationed work (fetch, chain check, scan window) for no new
	/// decision on every re-run — the mailbox is always re-read from
	/// checkpoint 0 in the same server-chosen order, so without this fast path
	/// everything past the budget would be deferred by every run forever.
	///
	/// Crucially, only terminal states count as decided: a row stored as
	/// `Spendable` is not necessarily a decision — [`Wallet::store_candidate`]
	/// stores a provisional `Spendable` row precisely when the spend-status
	/// request failed, explicitly a non-decision. Such rows (and `Locked`
	/// in-flight ones) are re-checked in full instead of being mirrored, so a
	/// healthy run always re-queries their real spend status. The re-check is
	/// cheap (their key is already revealed, so no scan window is paid) and
	/// spends no budget, since only ownership-confirmed VTXOs are ever stored
	/// and an attacker cannot inflate this class; if a flood has exhausted the
	/// budget anyway, intake counts re-checks as overflow like anything else.
	async fn classify_stored_candidate(
		&self,
		report: &mut RecoveryReport,
		id: VtxoId,
	) -> anyhow::Result<CandidateRecord> {
		let Some(entry) = self.inner.db.get_wallet_vtxo(id).await? else {
			return Ok(CandidateRecord::Unknown);
		};
		Ok(match &entry.state {
			VtxoState::Spent => { report.push_skipped(&entry.vtxo); CandidateRecord::Decided },
			VtxoState::Exited => { report.push_exited(&entry.vtxo); CandidateRecord::Decided },
			VtxoState::Spendable | VtxoState::Locked { .. } => CandidateRecord::NeedsRecheck,
		})
	}

	/// Recover a batch of freshly seen VTXO candidates.
	///
	/// Ordering matters because the candidates are untrusted, server-controlled
	/// input: chain validation runs before the ownership key scan so fabricated
	/// garbage is rejected by a cheap chain lookup, and the scan itself runs
	/// once for the whole batch — one gap-limit window covers every candidate,
	/// so foreign candidates share the scan cost instead of each re-deriving
	/// `gap_limit` keys. A failure tied to a single candidate is recorded
	/// against that candidate alone and never aborts the rest of the batch.
	async fn recover_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<Vtxo<Full>>,
		gap_limit: u32,
	) -> anyhow::Result<()> {
		let valid = self.validate_candidates(report, candidates).await;
		self.scan_candidates(report, valid, gap_limit).await
	}

	/// Validate each candidate against its chain anchor. Running this before the
	/// ownership key scan means fabricated garbage is rejected by a cheap chain
	/// lookup instead of paying derivation cost. A validation error (anchor not
	/// yet visible, or invalid) is a non-decision, so it's a failure for that
	/// candidate alone, not a clean skip and never an abort of the batch.
	async fn validate_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<Vtxo<Full>>,
	) -> Vec<Vtxo<Full>> {
		let mut valid = Vec::with_capacity(candidates.len());
		for vtxo in candidates {
			if let Err(e) = self.validate_vtxo(&vtxo).await {
				warn!("Could not validate recovery vtxo {}: {:#}", vtxo.id(), e);
				report.push_failed(vtxo.id(), Some(vtxo.amount()));
			} else {
				valid.push(vtxo);
			}
		}
		valid
	}

	/// Batch the ownership scan over already-validated candidates: one
	/// gap-limit window covers the whole batch, so a candidate whose key we
	/// cannot derive is foreign for the price of this single scan instead of
	/// each re-deriving `gap_limit` keys. Native gap scanning persists revealed
	/// keys. Program positions require their independently backed-up
	/// descriptors and signed recovery records. Owned candidates go on to
	/// [`Wallet::store_candidate`]; a failure there is recorded against that
	/// candidate alone where possible.
	async fn scan_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<Vtxo<Full>>,
		gap_limit: u32,
	) -> anyhow::Result<()> {
		if candidates.is_empty() {
			return Ok(());
		}

		let keypairs = self.find_vtxo_signing_keys(
			candidates.iter().map(|v| v.user_pubkey()), gap_limit,
		).await.context("error scanning the vtxo key space")?;

		for vtxo in candidates {
			match keypairs.get(&vtxo.user_pubkey()) {
				None => report.push_foreign(&vtxo),
				Some(keypair) => self.store_candidate(report, vtxo, keypair).await?,
			}
		}

		Ok(())
	}

	/// Store a VTXO whose ownership scan matched one of our keys: complete its
	/// program recovery guard, then ask the chain and the server where it
	/// belongs and record it in that state.
	async fn store_candidate(
		&self,
		report: &mut RecoveryReport,
		vtxo: Vtxo<Full>,
		keypair: &VtxoSigningKey,
	) -> anyhow::Result<()> {
		let id = vtxo.id();

		if let Err(e) = self.ensure_program_recoveries(std::slice::from_ref(&vtxo)).await {
			warn!("Recovery vtxo {id} has no usable saved program recovery: {e:#}");
			self.quarantine_program_receive(
				&vtxo, &vtxo.serialize(), "program deposit has no verified complete recovery",
			).await?;
			report.push_failed(id, Some(vtxo.amount()));
			return Ok(());
		}

		if self.check_vtxo_onchain_status(report, &vtxo).await? {
			return Ok(());
		}

		// The server is the authority on whether it was spent elsewhere,
		// and recovery has nothing else to go on.
		let adoption = self.fetch_vtxo_spend_state(&vtxo, keypair).await
			.and_then(ServerStatusAdoption::from_spend_state);

		// NB we don't use store_spendable_vtxos to avoid posting the vtxo again
		match adoption {
			Ok(ServerStatusAdoption::Spendable) => {
				self.store_vtxos([&vtxo], &VtxoState::Spendable).await?;
				report.push_recovered(&vtxo);
				debug!("Recovered spendable vtxo {id} ({})", vtxo.amount());
			},
			// The spent row is what stops a later mailbox replay from storing
			// the vtxo as spendable again.
			Ok(ServerStatusAdoption::Spent) => {
				debug!("Recovery vtxo {id} already spent, skipping");
				// A spendable row from an earlier, failed attempt is forced along.
				self.store_vtxos([&vtxo], &VtxoState::Spent).await?;
				self.mark_vtxos_as_spent(&[id]).await?;
				report.push_skipped(&vtxo);
			},
			// Finishing the flow the VTXO is stuck in is what decides where it
			// belongs, so nothing is stored. Arkoor mailbox messages only carry
			// final Pubkey-policy VTXOs, so the replay cannot bring an in-flight
			// one back.
			Ok(ServerStatusAdoption::InFlight(state)) => {
				debug!("Recovery vtxo {id} not spendable ({state:?}), skipping");
				self.inner.db.remove_vtxo(id).await
					.context("Failed to drop in-flight recovery vtxo")?;
				report.push_skipped(&vtxo);
			},
			// No usable answer — a non-decision, so it's retried rather than taken
			// for a clean skip. The spendable row overstates the balance until the
			// retry, but no row at all would let a mailbox replay store the vtxo
			// spendable without ever asking the server.
			Err(e) => {
				warn!("Could not get status for recovery vtxo {id}: {:#}", e);
				self.store_vtxos([&vtxo], &VtxoState::Spendable).await?;
				report.push_failed(id, Some(vtxo.amount()));
			},
		}

		Ok(())
	}

	/// Recover the given VTXOs into this wallet's spendable set.
	///
	/// Bodies are fetched first, then the whole set is validated and put through
	/// a single batched key scan (see [`Wallet::recover_candidates`]). `gap_limit`
	/// overrides [`crate::Config::vtxo_key_gap_limit`] for that scan, which
	/// decides which of `ids` this wallet owns.
	pub async fn recover_vtxos(
		&self,
		ids: impl IntoIterator<Item = VtxoId>,
		gap_limit: Option<u32>,
	) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();
		let gap_limit = gap_limit.unwrap_or(self.inner.config.vtxo_key_gap_limit);
		let mut candidates = Vec::new();
		for id in ids {
			match self.fetch_vtxo(id).await {
				Ok(vtxo) => candidates.push(vtxo),
				Err(e) => {
					warn!("Could not fetch recovery vtxo {id}: {:#}", e);
					report.push_failed(id, None);
				},
			}
		}
		self.recover_candidates(&mut report, candidates, gap_limit).await?;
		Ok(report)
	}

	/// Rebuild the wallet's VTXO set from the seed-derived recovery mailbox and
	/// the arkoor messages in the regular mailbox.
	///
	/// Both mailboxes are read from checkpoint 0, and every VTXO they reference
	/// is resolved against the chain and the server as it is seen and stored
	/// accordingly. Mailbox content is untrusted, so the run processes at most
	/// [`MAX_RECOVERY_CANDIDATES_PER_RUN`] distinct candidates; overflow is
	/// counted in [`RecoveryReport::budget_overflow`], keeping the report
	/// incomplete without recording flood ids. Because candidates an earlier
	/// run already decided are counted from the wallet's own records, repeated
	/// runs keep spending their budget on the unprocessed tail and are the
	/// supported way to recover mailboxes larger than the cap. Returns a
	/// [`RecoveryReport`] (see it for why recovered/skipped/failed matters).
	pub(crate) async fn recover_from_mailbox(&self) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();
		let gap_limit = self.inner.config.vtxo_key_gap_limit;
		let mut seen = HashSet::new();
		let mut budget = RecoveryCandidateBudget::new(MAX_RECOVERY_CANDIDATES_PER_RUN);

		// The regular mailbox comes first: its arkoor messages carry full vtxos,
		// so a duplicate in the recovery mailbox needs no fetch.
		let keypair = self.mailbox_keypair();
		self.scan_mailbox_for_recovery(&mut report, &keypair, gap_limit, &mut seen, &mut budget).await?;

		let keypair = self.recovery_mailbox_keypair();
		self.scan_mailbox_for_recovery(&mut report, &keypair, gap_limit, &mut seen, &mut budget).await?;

		if report.budget_overflow() > 0 {
			warn!(
				"Recovery processed its maximum of {MAX_RECOVERY_CANDIDATES_PER_RUN} candidates \
				this run; {} further candidate(s) were delivered but left unprocessed, so the \
				run is incomplete — re-run recovery to continue",
				report.budget_overflow(),
			);
		}

		// Unmatched ids in our own seed-derived mailbox are suspicious: most
		// likely an owned VTXO whose key sits beyond the gap limit (funds may be
		// missing), not a stranger's id. Retrying won't help these — only a wider
		// gap limit can match them — so they get their own warning.
		if !report.foreign.is_empty() {
			warn!(
				"Recovery mailbox held {} vtxo(s) not derivable from this seed within the \
				gap limit ({gap_limit}); if any are ours they were not recovered. \
				First offenders: {:?}",
				report.foreign.len(),
				report.foreign.ids().take(8).collect::<Vec<_>>(),
			);
		}

		if report.is_complete() {
			info!(
				"Recovered {} spendable vtxos from the recovery mailbox ({} skipped)",
				report.recovered.len(), report.skipped.len(),
			);
		}

		// We retry 3 times to recover the failed VTXOs. Budget overflow is not
		// in `failed` (its ids are never recorded), so retries stay capped.
		for _ in 0..3 {
			if report.failed.is_empty() {
				break;
			}

			let ids = report.failed.ids().collect::<Vec<_>>();
			let mut candidates = Vec::with_capacity(ids.len());
			for id in ids {
				match self.fetch_vtxo(id).await {
					Ok(vtxo) => candidates.push(vtxo),
					Err(e) => {
						warn!("Could not fetch recovery vtxo {id}: {:#}", e);
						report.push_failed(id, None);
					},
				}
			}
			self.recover_candidates(&mut report, candidates, gap_limit).await?;
		}

		if !report.failed.is_empty() {
			warn!(
				"Recovery incomplete: recovered {} spendable vtxos, but {} could not be \
				checked due to errors; funds may be missing — retry recovery to recover \
				them ({} skipped). First failed vtxos: {:?}",
				report.recovered.len(), report.failed.len(),
				report.skipped.len(),
				report.failed.ids().take(8).collect::<Vec<_>>(),
			);
		}

		Ok(report)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::Amount;
	use bitcoin::hashes::Hash;

	fn dummy_id(vout: u32) -> VtxoId {
		bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), vout).into()
	}

	/// `is_complete` hinges on whether any VTXO went unaccounted for: a `skipped`
	/// VTXO is a clean decision, whereas a `failed` VTXO or a `foreign` id both
	/// mean funds may be missing and the scan is incomplete.
	#[test]
	fn recovery_report_completeness() {
		let clean = RecoveryReport {
			recovered: RecoveryReportEntry(HashMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			skipped: RecoveryReportEntry(HashMap::from([(dummy_id(1), Some(Amount::from_sat(1000)))])),
			foreign: RecoveryReportEntry(HashMap::new()),
			failed: RecoveryReportEntry(HashMap::new()),
			exited: RecoveryReportEntry(HashMap::new()),
			budget_overflow: 0,
		};
		assert!(clean.is_complete(),
			"recovered and skipped VTXOs are clean decisions, not failures");

		assert!(RecoveryReport::default().is_complete(),
			"an empty report is trivially complete");
		assert!(!RecoveryReport {
			failed: RecoveryReportEntry(HashMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a failed VTXO means recovery is incomplete");
		assert!(!RecoveryReport {
			foreign: RecoveryReportEntry(HashMap::from([(dummy_id(2), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a foreign id is likely an owned VTXO beyond the gap limit, so recovery is incomplete");
	}

	/// The per-run candidate cap processes exactly `cap` distinct candidates;
	/// past it, intake counts overflow in the report without recording any ids,
	/// and the overflow alone keeps the report incomplete.
	#[test]
	fn recovery_candidate_budget_caps_processing_and_counts_overflow() {
		let mut budget = RecoveryCandidateBudget::new(2);
		assert!(!budget.is_exhausted());
		budget.consume();
		budget.consume();
		assert!(budget.is_exhausted(), "the cap stays shut once hit");

		let mut report = RecoveryReport::default();
		report.push_budget_overflow(3);
		assert_eq!(report.budget_overflow(), 3);
		assert!(!report.is_complete(), "overflow alone means funds may be missing");
		assert!(report.failed().is_empty(),
			"overflow is counted, never recorded per id — a flood must not fill memory");
	}

	/// Wallet-backed tests for the batched ownership scan. The chain source is
	/// deliberately unroutable ([`ChainSource::offline_for_test`]), so these
	/// exercise [`Wallet::scan_candidates`] directly: validation is the stage
	/// before it and only needs the chain, not the seed.
	#[cfg(feature = "sqlite")]
	mod scan_batching {
		use std::collections::HashSet;
		use std::sync::Arc;

		use bitcoin::Network;
		use bitcoin::secp256k1::Keypair;

		use ark::{ProtocolEncoding, Vtxo};
		use ark::test_util::dummy::DummyTestVtxoSpec;
		use ark::vtxo::Full;

		use super::super::{CandidateRecord, RecoveryCandidateBudget, RecoveryReport};
		use crate::{Config, Wallet, WalletInner, WalletSeed, SECP};
		use crate::chain::ChainSource;
		use crate::exit::Exit;
		use crate::lock_manager::memory::MemoryLockManager;
		use crate::movement::manager::MovementManager;
		use crate::notification::NotificationDispatch;
		use crate::persist::WalletPersister;
		use crate::persist::adaptor::StorageAdaptorWrapper;
		use crate::round::RoundSecretNonces;
		use crate::vtxo::VtxoState;

		/// A wallet against an in-memory database with a chain source and
		/// server that are both unreachable. Enough to run the ownership scan
		/// and report classification; the owned-candidate store path dies at
		/// the spend-status request, which lands the VTXO in `failed`.
		async fn offline_wallet(seed_byte: u8) -> Wallet {
			let network = Network::Regtest;
			let seed = WalletSeed::new_from_seed(network, &[seed_byte; 64]);
			let db: Arc<dyn WalletPersister> = Arc::new(StorageAdaptorWrapper::new_memory());
			let chain = Arc::new(ChainSource::offline_for_test(network));
			let notifications = NotificationDispatch::new();
			let movements = Arc::new(MovementManager::new(db.clone(), notifications.clone()));
			let exit = Exit::new(db.clone(), chain.clone(), movements.clone()).await.unwrap();
			Wallet { inner: Arc::new(WalletInner {
				config: Config::network_default(network),
				db,
				lock_manager: Box::new(MemoryLockManager::new()),
				seed,
				exit,
				movements,
				notifications,
				server: tokio::sync::OnceCell::new(),
				chain,
				onchain: None,
				program_transport: tokio::sync::OnceCell::new(),
				daemon: parking_lot::Mutex::new(None),
				last_force_exit_scan_tip: tokio::sync::Mutex::new(None),
				round_secret_nonces: RoundSecretNonces::new(),
			})}
		}

		/// A fabricated mailbox candidate: structurally valid, but its user key
		/// is a fixed, seed-unrelated scalar, so it can never derive from the
		/// wallet's seed and each index yields a distinct candidate id.
		fn fabricated_candidate(n: u32) -> Vtxo<Full> {
			let mut sec = [0x11u8; 32];
			sec[28..32].copy_from_slice(&n.to_be_bytes());
			let user_keypair = Keypair::from_seckey_slice(&SECP, &sec).unwrap();
			DummyTestVtxoSpec { user_keypair, ..Default::default() }.build().1
		}

		/// A page of fabricated candidates must cost a single gap-limit scan
		/// window, not one scan per candidate: the derivation count stays at
		/// gap_limit + 1 no matter how many candidates the page carries, and
		/// every one of them is classified foreign.
		#[tokio::test]
		async fn foreign_candidates_share_one_scan_window() {
			let wallet = offline_wallet(1).await;
			let mut report = RecoveryReport::default();
			const GAP_LIMIT: u32 = 4;

			let n_foreign = 50;
			let candidates = (0..n_foreign as u32).map(fabricated_candidate).collect::<Vec<_>>();

			let before = wallet.inner.seed.vtxo_key_derivation_count();
			wallet.scan_candidates(&mut report, candidates, GAP_LIMIT).await.unwrap();
			let derivations = wallet.inner.seed.vtxo_key_derivation_count() - before;

			assert_eq!(derivations, GAP_LIMIT as usize + 1,
				"a page of foreign candidates must cost one gap window, not one scan each");
			assert_eq!(report.foreign().len(), n_foreign,
				"every unowned candidate is foreign, at shared scan cost");
			assert!(report.recovered().is_empty() && report.failed().is_empty());
			assert!(!report.is_complete());
		}

		/// In a mixed batch the owned candidate is still found: its key is
		/// revealed (from the database on the next lookup) while the fabricated
		/// candidates are foreign — and a bad candidate never aborts the good
		/// one's classification.
		#[tokio::test]
		async fn mixed_batch_finds_owned_key_and_isolates_foreign() {
			let wallet = offline_wallet(2).await;
			let mut report = RecoveryReport::default();
			const GAP_LIMIT: u32 = 1;

			// The owned candidate sits at derivation index 0, unseen so far: with
			// a gap limit of 1 the single window scans indices 0..=2 either way.
			let owned_keypair = wallet.inner.seed.derive_vtxo_keypair(0);
			let owned = DummyTestVtxoSpec {
				user_keypair: owned_keypair, ..Default::default()
			}.build().1;

			let mut candidates = vec![fabricated_candidate(0), fabricated_candidate(1)];
			let foreign_ids = candidates.iter().map(|v| v.id()).collect::<Vec<_>>();
			let owned_id = owned.id();
			candidates.push(owned);
			candidates.push(fabricated_candidate(2));

			let before = wallet.inner.seed.vtxo_key_derivation_count();
			wallet.scan_candidates(&mut report, candidates, GAP_LIMIT).await.unwrap();
			let derivations = wallet.inner.seed.vtxo_key_derivation_count() - before;

			// One window covering the whole batch, extended once by its only
			// match: indices 0 (match), 1 and 2.
			assert_eq!(derivations, 3,
				"the whole batch pays one gap window extended by its only match");
			for id in &foreign_ids {
				assert!(report.foreign().ids().any(|f| &f == id), "fabricated candidate is foreign");
			}
			assert!(!report.foreign().ids().any(|f| f == owned_id),
				"the owned candidate must never be classified foreign");
			assert_eq!(
				wallet.inner.db.get_public_key_idx(&owned_keypair.public_key()).await.unwrap(),
				Some(0),
				"the owned key is revealed by the shared scan, so the wallet owns the VTXO",
			);
			// With no reachable server the spend-status request fails, so the
			// owned VTXO lands in failed (a non-decision) rather than recovered.
			assert!(report.failed().ids().any(|f| f == owned_id));
		}

		/// Candidates an earlier run already stored with a terminal state are
		/// mirrored from the wallet's own records — no fetch, validation or key
		/// scan — so repeated runs spend the candidate budget only on the
		/// unprocessed tail and a flooded mailbox's tail is eventually reached.
		#[tokio::test]
		async fn decided_candidates_are_accounted_from_wallet_records() {
			let wallet = offline_wallet(3).await;

			let spent = fabricated_candidate(11);
			wallet.store_vtxos([&spent], &VtxoState::Spent).await.unwrap();
			let exited = fabricated_candidate(12);
			wallet.store_vtxos([&exited], &VtxoState::Exited).await.unwrap();
			let unknown = fabricated_candidate(13);

			let mut report = RecoveryReport::default();
			assert_eq!(
				wallet.classify_stored_candidate(&mut report, spent.id()).await.unwrap(),
				CandidateRecord::Decided,
			);
			assert_eq!(
				wallet.classify_stored_candidate(&mut report, exited.id()).await.unwrap(),
				CandidateRecord::Decided,
			);
			assert_eq!(
				wallet.classify_stored_candidate(&mut report, unknown.id()).await.unwrap(),
				CandidateRecord::Unknown,
				"an id the wallet never stored is an unknown candidate",
			);

			assert!(report.skipped().ids().any(|i| i == spent.id()));
			assert!(report.exited().ids().any(|i| i == exited.id()));
			assert_eq!(wallet.inner.seed.vtxo_key_derivation_count(), 0,
				"decided accounting performs no key scan at all");
		}

		/// A VTXO stored as `Spendable` may be a provisional row from a failed
		/// spend-status request — explicitly a non-decision. It must be
		/// re-checked, never mirrored as recovered: intake re-queries it
		/// (offline that surfaces as `failed`, preserving honest incomplete)
		/// without touching the candidate budget.
		#[tokio::test]
		async fn provisional_spendable_rows_are_rechecked_not_mirrored() {
			let wallet = offline_wallet(5).await;

			// A previous run stored this VTXO provisionally after its
			// spend-status request failed.
			let provisional = fabricated_candidate(20);
			wallet.store_vtxos([&provisional], &VtxoState::Spendable).await.unwrap();

			let mut report = RecoveryReport::default();
			assert_eq!(
				wallet.classify_stored_candidate(&mut report, provisional.id()).await.unwrap(),
				CandidateRecord::NeedsRecheck,
				"a stored Spendable row is not a final decision",
			);
			assert!(report.recovered().is_empty(),
				"must not be mirrored as recovered without a fresh status query");

			// Through intake the candidate is re-queried rather than mirrored:
			// offline the fetch fails, so it lands in failed... and crucially
			// the re-check is uncapped, leaving the whole budget untouched.
			let mut seen = HashSet::new();
			let mut budget = RecoveryCandidateBudget::new(10);
			let mut page = Vec::new();
			wallet.intake_id_refs(&mut report, std::slice::from_ref(&provisional.id().to_bytes().to_vec()),
				&mut seen, &mut budget, &mut page).await.unwrap();
			assert_eq!(budget.remaining, 10, "re-checking stored candidates costs no budget");
			assert!(report.recovered().is_empty());
			assert!(report.failed().ids().any(|i| i == provisional.id()),
				"the re-query happened (and its offline failure is a non-decision)");
		}

		/// One mailbox message may carry more candidates than the remaining
		/// budget. The per-id budget gate must hold in every build profile
		/// (before it, `consume` tripped its debug_assert in dev or overran the
		/// cap in release): the first `remaining` candidates are processed, the
		/// rest are overflow-counted with no per-id bookkeeping.
		#[tokio::test]
		async fn oversized_message_respects_budget_and_counts_overflow() {
			let wallet = offline_wallet(4).await;
			let mut report = RecoveryReport::default();
			let mut seen = HashSet::new();
			let mut budget = RecoveryCandidateBudget::new(2);

			let bodies = (0..5).map(fabricated_candidate)
				.map(|v| v.serialize())
				.collect::<Vec<_>>();
			let mut page = Vec::new();
			wallet.intake_vtxo_bodies(&mut report, &bodies, &mut seen, &mut budget, &mut page).await.unwrap();

			assert!(budget.is_exhausted());
			assert_eq!(page.len(), 2, "only the remaining budget is processed");
			assert_eq!(report.budget_overflow(), 3, "the excess is counted, not processed");
			assert_eq!(seen.len(), 2, "overflow ids get no per-id records");
		}
	}
}

