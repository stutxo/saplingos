use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use lightning::util::ser::Writeable;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::lnurl::LnUrl;
use log::{info, warn};
use server_rpc::protos;

use ark::lightning::{
	offer_request_amount, Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, PaymentHash, Preimage,
};

use crate::Wallet;
use crate::WalletVtxo;
use crate::actions::{DriveMode, WalletAction};
use crate::actions::lightning::pay::ln_pay_action_id;
use crate::actions::lightning::pay::{
	LightningSend, LightningSendState, Progress, settle_lightning_send_payment,
	start_lightning_send,
};
use crate::lightning::{lightning_wallet_proxy, lnaddr_invoice, lnurlp_invoice};
use crate::lock_manager::LockGuard;
use crate::movement::PaymentMethod;
use crate::persist::WalletPersister;
use crate::vtxo::VtxoStateKind;

/// Options for a lightning send, see [`Wallet::pay_lightning_invoice_with`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LightningSendOptions {
	/// Keep the call open until the payment settles or fails, instead of
	/// returning once it has been kicked off.
	pub wait: bool,
	/// How long the server keeps trying to pay, capped to the server's
	/// maximum. `None` leaves it to the server.
	pub retry_for: Option<Duration>,
}

impl LightningSendOptions {
	pub fn wait(mut self, wait: bool) -> Self {
		self.wait = wait;
		self
	}

	pub fn retry_for(mut self, retry_for: Option<Duration>) -> Self {
		self.retry_for = retry_for;
		self
	}
}

impl Wallet {
	/// Returns every in-progress lightning send checkpoint.
	pub async fn pending_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for cp in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if let Some(ls) = cp.into_lightning_send() {
				result.push(ls);
			}
		}
		Ok(result)
	}

	/// Returns failed payments whose revocation or signed-refund registration failed.
	/// Near expiry, an opted-in payment exits its saved signed refund successors,
	/// or the original HTLCs if no refund signatures were obtained.
	pub async fn stuck_failed_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		let mut result = Vec::new();
		for send in self.pending_lightning_sends().await? {
			if send.has_failed_revocation() {
				result.push(send);
			}
		}
		Ok(result)
	}

	/// Opts the Lightning send identified by `hash` into emergency exit near expiry.
	///
	/// After revocation or registration fails, exit the exact signed refund
	/// successors if present. Never exit HTLCs superseded by those successors.
	/// The flag is persisted on the action checkpoint. The next drive through
	/// [`Self::sync_pending_lightning_send_vtxos`] or [`Self::check_lightning_payment`]
	/// applies it. See [`LightningSend::has_failed_revocation`].
	pub async fn allow_lightning_send_to_exit(&self, hash: PaymentHash) -> anyhow::Result<()> {
		let key = ln_pay_action_id(hash);
		let _guard = self.inner.lock_manager.try_lock(&key).await
			.context("Payment operation already in progress for this invoice")?;

		let mut send = self.lightning_send_checkpoint(hash).await?
			.with_context(|| format!("no in-progress lightning send for payment hash {hash}"))?;
		send.allow_exit_of_htlcs = true;
		self.inner.db.upsert_wallet_action_checkpoint(&send.id(), &send.into()).await?;
		Ok(())
	}

	/// Returns the VTXOs currently held by any in-progress lightning send.
	pub async fn pending_lightning_send_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let ids = self.pending_lightning_sends().await?.into_iter()
			.flat_map(|send| send.pending_balance_vtxo_ids())
			.collect::<HashSet<_>>();
		if ids.is_empty() {
			return Ok(Vec::new());
		}
		// Signed HTLC snapshots may precede inventory hydration. Count whichever
		// side of that handover is still locked, not absent or already spent IDs.
		let mut vtxos = self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Locked]).await?;
		vtxos.retain(|vtxo| ids.contains(&vtxo.id()));
		Ok(vtxos)
	}

	/// Drives every pending lightning send forward by one step (or to
	/// completion if it's ready). Each action runs to its next park
	/// independently; errors on one don't stop the others.
	pub async fn sync_pending_lightning_send_vtxos(&self) -> anyhow::Result<()> {
		let pending = self.pending_lightning_sends().await?;
		if pending.is_empty() {
			return Ok(());
		}
		info!("Syncing {} pending lightning sends", pending.len());
		for send in pending {
			let id = send.id();
			if let Err(e) = self.drive_action(send, DriveMode::UntilParkOrDone).await {
				warn!("Failed to sync lightning send {}: {:#}", id, e);
			}
		}
		Ok(())
	}

	/// Fetches the current checkpoint for the given payment hash, if any.
	pub async fn lightning_send_checkpoint(&self, hash: PaymentHash)
		-> anyhow::Result<Option<LightningSend>>
	{
		Ok(self.inner.db.get_wallet_action_checkpoint(&ln_pay_action_id(hash)).await?
			.and_then(|cp| cp.into_lightning_send()))
	}

	/// Triage a payment hash: paid, in-progress, or unknown.
	pub async fn lightning_send_state(&self, hash: PaymentHash)
		-> anyhow::Result<LightningSendState>
	{
		if let Some(paid) = self.inner.db.get_paid_invoice(hash).await? {
			return Ok(LightningSendState::Paid(paid));
		}
		if let Some(cp) = self.lightning_send_checkpoint(hash).await? {
			return Ok(LightningSendState::InProgress(cp));
		}
		Ok(LightningSendState::Unknown)
	}

	/// Cheap "has this invoice ever been paid?" check.
	pub async fn is_invoice_paid(&self, hash: PaymentHash) -> anyhow::Result<bool> {
		Ok(self.inner.db.get_paid_invoice(hash).await?.is_some())
	}

	/// Drive a lightning send forward (e.g., to settle a pending one
	/// or revoke a failed one). `wait=true` keeps driving past parks
	/// until the action terminates. Returns the current state.
	pub async fn check_lightning_payment(&self, hash: PaymentHash, wait: bool)
		-> anyhow::Result<LightningSendState>
	{
		let send = match self.lightning_send_state(hash).await? {
			LightningSendState::InProgress(s) => s,
			s => return Ok(s),
		};

		let mode = if wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };
		self.drive_action(send, mode).await?;
		self.lightning_send_state(hash).await
	}

	/// Settle a payment using a preimage we already have (e.g. from a
	/// mailbox notification), skipping the server poll.
	///
	/// The notification carries no action snapshot. Reload the payment under
	/// the driver lock so a late notification cannot discard a newer revocation
	/// or signed-output checkpoint.
	pub(crate) async fn settle_lightning_send_with_preimage(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		if preimage.compute_payment_hash() != payment_hash {
			bail!("preimage mismatch for payment hash {}", payment_hash);
		}
		let id = ln_pay_action_id(payment_hash);
		let guard = self.inner.lock_manager.try_lock(&id).await
			.context("payment operation already in progress for this invoice")?;
		ensure!(!self.inner.db.has_program_recovery_reservation(
			&crate::persist::models::recovery_action_key(&id),
		).await?, "payment was taken over by program recovery");
		let Some(send) = payment_initiated_checkpoint(
			self.inner.db.as_ref(), payment_hash, guard.as_ref(),
		).await? else {
			// Another terminal drive already saved the paid record and removed
			// the action. There is no checkpoint to clean up again.
			return Ok(());
		};
		let Progress::PaymentInitiated(htlcs) = &send.progress else {
			unreachable!("payment_initiated_checkpoint checks the phase");
		};
		settle_lightning_send_payment(self, &send, htlcs, preimage).await?;
		// Settlement saves the preimage, marks the live HTLCs spent and finishes
		// the movement. Only then may the same guard authorize atomic cleanup.
		self.finish_wallet_action_with_guard(&id, guard.as_ref()).await
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs.
	///
	/// `wait=true` keeps the call open until the payment settles or
	/// fails; `wait=false` returns once the payment has been kicked off
	/// and lets the background sync drive it to completion. Returns the
	/// parsed [`Invoice`] in either case; callers wanting the preimage
	/// can look up the settled record via [`Self::lightning_send_state`].
	pub async fn pay_lightning_invoice<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_invoice_with(invoice, user_amount, opts).await
	}

	/// Same as [`Self::pay_lightning_invoice`], with [`LightningSendOptions`].
	pub async fn pay_lightning_invoice_with<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let invoice = invoice.try_into().context("failed to parse invoice")?;
		let amount = invoice.get_payment_amount(user_amount)?;
		info!("Sending bolt11 payment of {} to invoice {}", amount, invoice);
		self.make_lightning_payment_with(&invoice, invoice.clone().into(), user_amount, opts).await?;
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_invoice`] but resolves the invoice
	/// from a [`LightningAddress`] first.
	pub async fn pay_lightning_address(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_address_with(addr, amount, comment, opts).await
	}

	/// Same as [`Self::pay_lightning_address`], with [`LightningSendOptions`].
	pub async fn pay_lightning_address_with(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let comment = comment.as_ref();
		let invoice: Invoice = lnaddr_invoice(addr, amount, comment,
			lightning_wallet_proxy(self.config())).await
			.context("lightning address error")?.into();
		info!("Sending {} to lightning address {}", amount, addr);
		self.make_lightning_payment_with(&invoice, addr.clone().into(), None, opts).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Same as [`Self::pay_lightning_address`] but resolves the invoice from a
	/// raw LNURL-pay link (`lnurl1…`) first.
	///
	/// Errors if the link decodes to a non-pay LNURL (auth, withdraw, channel).
	pub async fn pay_lnurl(
		&self,
		lnurl: &LnUrl,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lnurl_with(lnurl, amount, comment, opts).await
	}

	/// Same as [`Self::pay_lnurl`], with [`LightningSendOptions`].
	pub async fn pay_lnurl_with(
		&self,
		lnurl: &LnUrl,
		amount: Amount,
		comment: Option<impl AsRef<str>>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let invoice: Invoice = lnurlp_invoice(&lnurl.url, amount, comment,
			lightning_wallet_proxy(self.config())).await
			.context("lnurl-pay error")?.into();
		info!("Sending {} to lnurl {}", amount, lnurl);
		self.make_lightning_payment_with(&invoice, lnurl.clone().into(), None, opts).await?;
		info!("Paid invoice {}", invoice);
		Ok(invoice)
	}

	/// Attempts to pay the given BOLT12 [`Offer`] using offchain funds.
	pub async fn pay_lightning_offer(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<Invoice> {
		let opts = LightningSendOptions::default().wait(wait);
		self.pay_lightning_offer_with(offer, user_amount, opts).await
	}

	/// Same as [`Self::pay_lightning_offer`], with [`LightningSendOptions`].
	pub async fn pay_lightning_offer_with(
		&self,
		offer: Offer,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<Invoice> {
		let (mut srv, _) = self.require_server().await?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).context("failed to serialize BOLT12 offer")?;
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: user_amount.map(|a| a.to_sat()),
		};

		// Since the server is the one fetching the invoice, it is the one building the
		// invoice request. We need to ensure that the amount we authorize here,
		// before the fetch, and the amount in the invoice we get back match during
		// validation below.
		let amount = offer_request_amount(&offer, user_amount)
			.context("cannot determine the amount to pay for this offer")?;
		if user_amount.is_some() {
			info!("Sending bolt12 payment of {} (user amount) to offer {}", amount, offer);
		} else {
			info!("Sending bolt12 payment of {} (offer amount) to offer {}", amount, offer);
		}

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();
		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|e| anyhow!("invalid invoice: {:?}", e))?;

		invoice.validate_issuance(&offer, amount)
			.context("invalid BOLT12 invoice received from offer")?;

		let invoice: Invoice = invoice.into();
		self.make_lightning_payment_with(&invoice, offer.into(), Some(amount), opts).await?;
		info!("Paid invoice: {}", invoice);
		Ok(invoice)
	}

	/// Low-level lightning payment primitive. Exposed for
	/// [`PaymentMethod::Custom`] use cases (e.g. LNURL-pay).
	pub async fn make_lightning_payment(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
		wait: bool,
	) -> anyhow::Result<()> {
		let opts = LightningSendOptions::default().wait(wait);
		self.make_lightning_payment_with(invoice, original_payment_method, user_amount, opts).await
	}

	/// Same as [`Self::make_lightning_payment`], with [`LightningSendOptions`].
	pub async fn make_lightning_payment_with(
		&self,
		invoice: &Invoice,
		original_payment_method: PaymentMethod,
		user_amount: Option<Amount>,
		opts: LightningSendOptions,
	) -> anyhow::Result<()> {
		if !original_payment_method.is_lightning() && !original_payment_method.is_custom() {
			bail!("Invalid original payment method for lightning payment");
		}

		let payment_hash = invoice.payment_hash();
		let mode = if opts.wait { DriveMode::UntilDone } else { DriveMode::UntilParkOrDone };

		if self.is_invoice_paid(payment_hash).await? {
			bail!("Invoice has already been paid");
		}

		let key = ln_pay_action_id(payment_hash);
		let guard = self.inner.lock_manager.try_lock(&key).await
			.context("Payment operation already in progress for this invoice")?;

		// Resume an existing checkpoint, or build a fresh send. A resumed
		// send keeps the retry time it was started with.
		let action = match self.lightning_send_checkpoint(payment_hash).await? {
			Some(existing) => existing,
			None => {
				let start = start_lightning_send(
					self, invoice.clone(), user_amount, original_payment_method, opts.retry_for,
				).await?;

				self.inner.db.upsert_wallet_action_checkpoint(
					&start.id(), &start.clone().into()
				).await?;

				start
			},
		};

		self.drive_action_with_guard(action, mode, guard).await
	}
}

/// Read terminal-notification state only while the caller holds the action lock.
/// A paid record can precede the remaining settlement writes, so its presence
/// must not bypass a checkpoint that still needs terminal accounting.
async fn payment_initiated_checkpoint(
	db: &dyn WalletPersister,
	hash: PaymentHash,
	_guard: &dyn LockGuard,
) -> anyhow::Result<Option<LightningSend>> {
	let id = ln_pay_action_id(hash);
	let Some(checkpoint) = db.get_wallet_action_checkpoint(&id).await? else {
		ensure!(db.get_paid_invoice(hash).await?.is_some(),
			"no pending or settled lightning send for payment hash {}", hash);
		return Ok(None);
	};
	let send = checkpoint.into_lightning_send().context("payment action is not a lightning send")?;
	ensure!(send.id() == id, "lightning send checkpoint identity mismatch");
	ensure!(matches!(send.progress, Progress::PaymentInitiated(_)),
		"lightning send phase changed before settlement; retaining the latest checkpoint");
	Ok(Some(send))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
	use ark::test_util::VTXO_VECTORS;

	use crate::actions::lightning::pay::{Htlcs, Revocation};
	use crate::lock_manager::{LockManager, memory::MemoryLockManager};
	use crate::movement::MovementId;
	use crate::persist::adaptor::StorageAdaptorWrapper;
	use crate::persist::test_suite::send_at_start;

	use super::*;

	fn initiated_send() -> LightningSend {
		LightningSend {
			// BOLT-11 example also used by payment_request.rs. Keep its hash
			// separate from other tests that share the memory lock manager.
			invoice: Invoice::Bolt11(
				"lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc"
					.parse().unwrap(),
			),
			progress: Progress::PaymentInitiated(Htlcs {
				vtxo_ids: vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.id()],
				mailbox_id: VTXO_VECTORS.board_vtxo.policy().user_pubkey().into(),
				movement_id: MovementId::new(1),
				vtxos: vec![VTXO_VECTORS.arkoor_htlc_out_vtxo.clone()],
			}),
			..send_at_start()
		}
	}

	#[tokio::test]
	async fn late_settlement_preserves_newer_signed_revocation_checkpoint() {
		let db = StorageAdaptorWrapper::new_memory();
		let locks = MemoryLockManager::new();
		let send = initiated_send();
		let id = send.id();
		let hash = send.invoice.payment_hash();
		let guard = locks.try_lock(&id).await.unwrap();
		db.upsert_wallet_action_checkpoint(&id, &send.clone().into()).await.unwrap();
		assert_eq!(payment_initiated_checkpoint(&db, hash, guard.as_ref()).await.unwrap(), Some(send.clone()));

		let Progress::PaymentInitiated(htlcs) = &send.progress else { unreachable!() };
		for signed_outputs in [vec![], vec![VTXO_VECTORS.arkoor3_vtxo.clone()]] {
			let revocation = Revocation {
				key: VTXO_VECTORS.board_vtxo.policy().user_pubkey(), vtxos: signed_outputs,
			};
			for progress in [
				Progress::RevocableHtlcs { htlcs: htlcs.clone(), revocation: revocation.clone() },
				Progress::RevocationStuck { htlcs: htlcs.clone(), revocation },
			] {
				let latest = LightningSend { progress, ..send.clone() };
				let checkpoint = latest.into();
				db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
				assert!(payment_initiated_checkpoint(&db, hash, guard.as_ref()).await.is_err());
				assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(checkpoint));
			}
		}

		// A paid record alone does not prove that a surviving checkpoint's
		// HTLCs and movement have completed their terminal writes.
		db.remove_wallet_action_checkpoint(&id).await.unwrap();
		assert!(payment_initiated_checkpoint(&db, hash, guard.as_ref()).await.is_err());
		db.record_paid_invoice(hash, Preimage::from_slice(&[3; 32]).unwrap()).await.unwrap();
		assert!(payment_initiated_checkpoint(&db, hash, guard.as_ref()).await.unwrap().is_none());
		db.upsert_wallet_action_checkpoint(&id, &send.clone().into()).await.unwrap();
		assert_eq!(payment_initiated_checkpoint(&db, hash, guard.as_ref()).await.unwrap(), Some(send));
	}

}
