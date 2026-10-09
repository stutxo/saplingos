use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;
use bitcoin::{Amount, FeeRate, Network};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};

use ark::lightning::{PaymentHash, Preimage};
use ark::{Vtxo, VtxoId, vtxo::Full};
use bitcoin_ext::BlockDelta;
use ark_testing::{TestContext, btc, sat, util::{FutureExt, poll_interval}};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::daemon::captaind::{proxy::ArkRpcProxy, ArkClient};

use bark::actions::lightning::pay::{LightningSendState, Progress as SendProgress};
use bark::actions::lightning::receive::{LightningReceiveState, Progress as ReceiveProgress};
use bark::exit::ExitState;
use bark::movement::MovementStatus;
use bark::onchain::OnchainWallet;
use bark::persist::{BarkPersister, sqlite::SqliteClient};
use bark::subsystem::Subsystem;
use bark::vtxo::VtxoState;
use bark::{LightningSendOptions, OpenWalletArgs, Wallet, WalletSeed};
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMsg;

/// Wait until the hold plugin holds the payment's HTLCs. The invoice turns
/// ACCEPTED only once every HTLC is irrevocably committed and handed to the
/// plugin; a settle before that fails with "no HTLCs to settle".
async fn wait_for_hold_invoice_accepted(
	hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>,
	payment_hash: PaymentHash,
) {
	async {
		loop {
			let invoices = hold_client.list(hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(
					payment_hash.as_ref().to_vec(),
				)),
			}).await.expect("list hold invoices").into_inner().invoices;
			let invoice = invoices.first().expect("hold invoice should exist");
			if invoice.state() == hold::InvoiceState::Accepted {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await
}

#[tokio::test]
async fn pay_hold_succeeds() {
	let ctx = TestContext::new("bark_sdk/pay_hold_succeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	// Build a hold invoice on the external CLN node. The HTLC won't be
	// settled until we hand the preimage to the hold plugin.
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"sdk_pay_lightning_hold_invoice".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	// Initiates the payment; HTLCs are now in flight but the external
	// node holds them. pay_lightning_invoice returns once the HTLCs are
	// sent, not once they settle.
	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// The payment is pending because the receiver hasn't claimed it yet
	// We report this correctly
	let status = wallet.check_lightning_payment(payment_hash, false).await .expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to get completed
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't settled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before settlement");

	// Settle the invoice
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	// ready()'s 2s bound is too tight under BARK_DOUBLE_DRIVE_ACTIONS: steps run twice and the send re-polls every 2s.
	let status = waiter.wait_millis(10_000).await.expect("join waiter");
	match &status {
		Ok(LightningSendState::Paid(invoice)) => {
			assert_eq!(invoice.payment_hash, payment_hash);
			assert_eq!(invoice.preimage, preimage);
		},
		err => panic!("Payment did not succeed: {:?}", err),
	}

	// A subsequent check should return the same cached result
	let new_status =  wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, status.unwrap());

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, board_amount - invoice_amount);
}

#[tokio::test]
async fn pay_hold_with_near_expiry_inputs_succeeds() {
	let ctx = TestContext::new("bark_sdk/pay_hold_with_near_expiry_inputs_succeeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	// Short vtxo lifetime keeps the block-advance cheap; absurdly long
	// round interval keeps any background refresh out of the picture.
	let srv = ctx.captaind("server").lightningd(&lightning.internal).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(100);
		cfg.round_interval = Duration::from_secs(86400);
	}).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	// Push the boarded VTXO past its expiry. An expired VTXO can still fund
	// a lightning payment; it and its change count as needs_refresh. The
	// lightning send used to spuriously fail this scenario because it
	// conflated input-VTXO expiry with HTLC expiry; the fresh HTLC's own
	// CLTV (htlc_send_expiry_delta blocks ahead) is still comfortably far
	// out, so the payment should still settle normally.
	ctx.generate_blocks(98).await;

	lightning.sync().await;

	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"pay_hold_with_expired_inputs_succeeds".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// The payment is pending because the receiver hasn't claimed it yet
	// We report this correctly
	let status = wallet.check_lightning_payment(payment_hash, false).await .expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.needs_refresh, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to get completed
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't settled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before settlement");

	// Settle the invoice
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	// ready()'s 2s bound is too tight under BARK_DOUBLE_DRIVE_ACTIONS: steps run twice and the send re-polls every 2s.
	let status = waiter.wait_millis(10_000).await.expect("join waiter");
	match &status {
		Ok(LightningSendState::Paid(invoice)) => {
			assert_eq!(invoice.payment_hash, payment_hash);
			assert_eq!(invoice.preimage, preimage);
		},
		err => panic!("Payment did not succeed: {:?}", err),
	}

	// A subsequent check should return the same cached result
	let new_status =  wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, status.unwrap());

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.needs_refresh, board_amount - invoice_amount);
}

#[tokio::test]
async fn pay_hold_refused() {
	let ctx = TestContext::new("bark_sdk/pay_hold_refused").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	// Build a hold invoice on the external CLN node. We never settle it
	// — instead we cancel, which makes the held HTLC fail back through
	// the route.
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"sdk_pay_lightning_hold_invoice_fail".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	// The payment is pending because the receiver hasn't claimed or
	// cancelled it yet; while the HTLC is in flight the locked amount
	// should be tracked as pending lightning send and excluded from
	// spendable.
	let status = wallet.check_lightning_payment(payment_hash, false).await.expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to resolve
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't cancelled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before cancel");

	// Cancel the hold invoice — the HTLC fails back to the server and
	// bark revokes the HTLC vtxos, restoring the funds.
	hold_client.cancel(hold::CancelRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
	}).await.expect("cancel hold invoice");

	// On failure the LightningSend record is removed once revocation completes, so the state
	// is Unknown. With CLN 26.06, xpay reports the destination failure before CLN's own sendpay
	// row transitions to failed, so captaind's immediate listpays reconciliation still sees
	// Pending and marks the attempt Submitted. It only flips to Failed on the next
	// process_payment_attempts tick past cln_xpay_timeout + XPAY_TIMEOUT_BUFFER (5s + 15s)
	// after the attempt was created. Wait long enough to clear that gate under
	// BARK_DOUBLE_DRIVE_ACTIONS + a couple of bark re-poll intervals.
	let status = waiter.wait_millis(40_000).await.expect("join waiter")
		.expect("waiting check errored");
	assert_eq!(status, LightningSendState::Unknown);

	// A subsequent check should also report Unknown
	let new_status = wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, LightningSendState::Unknown);

	// After revocation the HTLC vtxos come back as spendable
	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, board_amount);
	assert_eq!(balance.pending_lightning_send, btc(0));
}

/// Any integrator should be able to claim a lightning receive off the raw mailbox stream
/// alone, without depending on bark's own background sync loop or any particular sync method:
/// create an invoice, wait on the mailbox stream for the incoming-HTLC notification, then call
/// `try_claim_lightning_receive` once. No daemon and no background syncing runs, so that single
/// claim call has to complete the receive on its own.
#[tokio::test]
async fn receive_claim_on_mailbox_notification() {
	let ctx = TestContext::new("bark_sdk/receive_claim_on_mailbox_notification").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	// Subscribe to the mailbox stream before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// Wait for the server's incoming-payment notification.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(m)) = msg.message {
					assert_eq!(m.payment_hash, payment_hash.to_vec(),
						"notification for unexpected payment");
					break;
				}
			}
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let movements = wallet.history().await.expect("movements");
	let recv_mvt = movements.iter()
		.find(|m| m.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE))
		.expect("no lightning receive movement");
	assert_eq!(recv_mvt.status, MovementStatus::Successful,
		"lightning receive movement should be successful, got {:?}", recv_mvt.status);

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

/// The cooperative claim and the server's hold settler both settle the hold
/// invoice off the same preimage, so either can get there first. Settling the
/// invoice out of band before the claim forces the losing case: the claim
/// must still hand over the claim vtxos rather than fail on the hold plugin's
/// "no HTLCs to settle".
#[tokio::test]
async fn receive_claim_after_hold_invoice_already_settled() {
	let ctx = TestContext::new("bark_sdk/receive_claim_after_hold_invoice_already_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);
	let preimage = wallet.lightning_receive_checkpoint(payment_hash).await
		.expect("fetching receive checkpoint")
		.expect("receive checkpoint should exist")
		.payment_preimage;

	let mut hold_client = lightning.internal.hold_client().await;

	// Subscribe before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// The server posts the incoming-payment notification only after
			// it has registered the acceptance, so settling after it keeps
			// the server able to hand over the claim vtxos.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(_)) = msg.message {
					break;
				}
			}

			// Stand in for the hold settler getting there first.
			hold_client.settle(hold::SettleRequest {
				payment_preimage: preimage.as_ref().to_vec(),
			}).await.expect("settling the hold invoice out of band");

			wallet.try_claim_lightning_receive(payment_hash, true).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

#[tokio::test]
async fn pay_with_retry_for() {
	let ctx = TestContext::new("bark_sdk/pay_with_retry_for").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	let max = srv.config().cln_xpay_max_retry_for;

	// The server keeps the time on the attempt, which the xpay monitor waits
	// out before reconciling it. 0 makes a single attempt, and a time above
	// the maximum is capped to it.
	let db = Db::connect(&srv.config().postgres).await.expect("connect to server db");
	let one_sec = Duration::from_secs(1);
	for (retry_for, expected) in [
		(Duration::ZERO, Duration::ZERO),
		(max - one_sec, max - one_sec),
		(max + one_sec, max),
	] {
		let invoice = lightning.external.invoice(Some(btc(0.1)), format!("pay-{:?}", retry_for), "pay").await;
		let opts = LightningSendOptions::default().wait(true).retry_for(Some(retry_for));
		let invoice = wallet.pay_lightning_invoice_with(invoice, None, opts).await
			.expect("pay_lightning_invoice failed");

		let attempt = db.read(async |t|
			t.get_latest_payment_attempt_by_payment_hash(invoice.payment_hash()).await
		).await.expect("db read").expect("payment attempt");
		assert_eq!(attempt.retry_for, Some(expected));
	}
}

/// Only registration fails: every claim and revocation signature comes from
/// captaind. Count signing requests, including failures, to catch any attempt to
/// re-sign a superseded HTLC after restarting from the signed checkpoint.
#[derive(Clone)]
struct SignedSuccessorRegistrationFailure {
	claim_requests: Arc<AtomicUsize>,
	revocation_requests: Arc<AtomicUsize>,
	signed_responses: Arc<AtomicUsize>,
	registration_failures: Arc<AtomicUsize>,
	registration_error: tonic::Code,
}

impl SignedSuccessorRegistrationFailure {
	fn new(registration_error: tonic::Code) -> Self {
		Self {
			claim_requests: Arc::new(AtomicUsize::new(0)),
			revocation_requests: Arc::new(AtomicUsize::new(0)),
			signed_responses: Arc::new(AtomicUsize::new(0)),
			registration_failures: Arc::new(AtomicUsize::new(0)),
			registration_error,
		}
	}

	fn signing_requests(&self) -> (usize, usize) {
		(
			self.claim_requests.load(Ordering::SeqCst),
			self.revocation_requests.load(Ordering::SeqCst),
		)
	}
}

#[async_trait::async_trait]
impl ArkRpcProxy for SignedSuccessorRegistrationFailure {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.claim_requests.fetch_add(1, Ordering::SeqCst);
		let response = upstream.claim_lightning_receive(req).await?.into_inner();
		self.signed_responses.fetch_add(1, Ordering::SeqCst);
		Ok(response)
	}

	async fn request_lightning_pay_htlc_revocation(
		&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.revocation_requests.fetch_add(1, Ordering::SeqCst);
		let response = upstream.request_lightning_pay_htlc_revocation(req).await?.into_inner();
		self.signed_responses.fetch_add(1, Ordering::SeqCst);
		Ok(response)
	}

	async fn register_vtxo_transactions(
		&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		if self.signed_responses.load(Ordering::SeqCst) != 0 {
			self.registration_failures.fetch_add(1, Ordering::SeqCst);
			return Err(tonic::Status::new(
				self.registration_error, "registration unavailable after real cosigning",
			));
		}
		Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
	}
}

/// Open the same durable wallet, including its fee wallet, without a daemon
/// that could race the public fallback being exercised.
async fn reopen_signed_successor_wallet(ctx: &TestContext, name: &str) -> Wallet {
	let datadir = ctx.datadir.join(name);
	let mnemonic: bip39::Mnemonic = tokio::fs::read_to_string(datadir.join("mnemonic"))
		.await.unwrap().parse().unwrap();
	let config = toml::from_str(&tokio::fs::read_to_string(datadir.join("config.toml"))
		.await.unwrap()).unwrap();
	let db: Arc<dyn BarkPersister> = Arc::new(SqliteClient::open(datadir.join("db.sqlite")).unwrap());
	let onchain = OnchainWallet::load_or_create(
		Network::Regtest, mnemonic.to_seed(""), db.clone(),
	).await.unwrap();
	Wallet::open(
		Network::Regtest,
		WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic),
		config,
		OpenWalletArgs {
			persister: Some(db),
			onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
			run_daemon: false,
			..Default::default()
		},
	).await.expect("reopening the signed-successor checkpoint")
}

/// The signed branch, not just its amount, must survive inventory adoption,
/// publication, CSV maturity and the final on-chain claim.
async fn confirm_signed_successor_exit(
	ctx: &TestContext, wallet: &Wallet, saved: &[Vtxo<Full>], superseded: &[VtxoId],
) {
	assert!(!saved.is_empty());
	let ids = saved.iter().map(|v| v.id()).collect::<HashSet<_>>();
	assert_eq!(wallet.exit_mgr().get_exit_vtxo_ids().await.into_iter().collect::<HashSet<_>>(), ids);
	for vtxo in saved {
		assert_eq!(wallet.get_full_vtxo(vtxo.id()).await.unwrap(), *vtxo,
			"adoption must retain the complete saved genesis and signatures");
		assert_eq!(wallet.get_vtxo_by_id(vtxo.id()).await.unwrap().state, VtxoState::Exited);
	}
	for id in superseded {
		assert_eq!(wallet.get_vtxo_by_id(*id).await.unwrap().state, VtxoState::Spent);
		assert!(wallet.exit_mgr().get_exit_vtxo(*id).await.is_none(),
			"superseded HTLCs must not have their own exit");
	}

	for _ in 0..40 {
		wallet.sync_onchain().await.unwrap();
		wallet.progress_exits().await.expect("progressing exact signed successor exits");
		if wallet.exit_mgr().list_claimable().await.len() == saved.len() {
			break;
		}
		let tip = ctx.bitcoind().sync_client().tip().unwrap().height;
		let blocks = wallet.exit_mgr().all_claimable_at_height().await
			.and_then(|height| height.checked_blocks_since(tip)).unwrap_or(1).max(1);
		ctx.generate_blocks(blocks).await;
	}
	let claimable = wallet.exit_mgr().list_claimable().await;
	assert_eq!(claimable.iter().map(|v| v.id()).collect::<HashSet<_>>(), ids,
		"every saved successor must become claimable");
	for vtxo in saved {
		let exact_tx = vtxo.transactions().find(|item| item.tx.compute_txid() == vtxo.point().txid)
			.expect("saved successor transaction").tx;
		assert!(exact_tx.input.iter().all(|input| !input.witness.is_empty()));
		let confirmed = ctx.bitcoind().transaction_confirmation(exact_tx.compute_txid()).unwrap();
		assert!(confirmed.confirmations.unwrap_or(0) > 0);
		assert_eq!(ctx.bitcoind().sync_client().get_raw_transaction(&exact_tx.compute_txid(), None)
			.unwrap(), exact_tx, "the confirmed transaction must retain the saved signatures");
	}

	let amount = saved.iter().map(|v| v.amount()).sum::<Amount>();
	let payout = ctx.bitcoind().get_new_address();
	let claim = wallet.exit_mgr().drain_exits(
		&claimable, wallet, payout.clone(), Some(FeeRate::from_sat_per_vb(2).unwrap()),
	).await.unwrap();
	let fee = claim.fee().expect("claim PSBT has all prevouts");
	assert!(fee > Amount::ZERO && fee < amount);
	let claim = claim.extract_tx().unwrap();
	assert_eq!(claim.input.iter().map(|i| i.previous_output).collect::<HashSet<_>>(),
		saved.iter().map(|v| v.point()).collect::<HashSet<_>>(),
		"claim must consume the refund/receive successors, never the old HTLCs");
	assert_eq!(claim.output.len(), 1);
	assert_eq!(claim.output[0].value, amount - fee);
	assert_eq!(claim.output[0].script_pubkey, payout.script_pubkey());
	let claim_txid = ctx.bitcoind().sync_client().send_raw_transaction(&claim).unwrap();
	ctx.generate_blocks(1).await;
	wallet.progress_exits().await.unwrap();
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), amount - fee);
	assert!(ctx.bitcoind().transaction_confirmation(claim_txid)
		.unwrap().confirmations.unwrap_or(0) > 0);
	for id in ids {
		assert!(matches!(wallet.exit_mgr().get_exit_vtxo(id).await.unwrap().state(),
			ExitState::Claimed(state) if state.txid == claim_txid));
	}
	let spendable = wallet.spendable_vtxos().await.unwrap();
	assert!(spendable.iter().all(|v| !superseded.contains(&v.id())
		&& saved.iter().all(|successor| successor.id() != v.id())),
		"neither spent inputs nor exited successors may become reusable");
}

/// A locally owned Delivering checkpoint predates inventory insertion. Its
/// public fallback must adopt those exact signatures after a wallet restart.
#[tokio::test]
async fn receive_signed_successor_exit_after_registration_failure() {
	let ctx = TestContext::new("bark_sdk/receive_signed_successor_exit_after_registration_failure").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let fault = SignedSuccessorRegistrationFailure::new(tonic::Code::InvalidArgument);
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let wallet = ctx.bark_sdk("bark", &proxy.address).funded(sat(1_000_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	lightning.sync().await;

	let invoice_amount = sat(100_000);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await.unwrap();
	let payment_hash = PaymentHash::from(&invoice);
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await.unwrap();
	let (paid, claimed) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			loop {
				let message = mailbox.next().wait_millis(30_000).await.unwrap().unwrap();
				if let Some(MailboxMsg::IncomingLightningPayment(incoming)) = message.message {
					assert_eq!(incoming.payment_hash, payment_hash.to_vec());
					break;
				}
			}
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);
	paid.expect("real Lightning payment must settle before fallback");
	claimed.expect_err("registration must reject the signed local claim");
	drop(mailbox);

	let checkpoint = wallet.lightning_receive_checkpoint(payment_hash).await.unwrap().unwrap();
	assert!(checkpoint.claim_destination.is_none());
	let ReceiveProgress::Delivering(delivery) = &checkpoint.progress else {
		panic!("receive must retain its signed Delivering checkpoint: {:?}", checkpoint.progress);
	};
	assert!(!delivery.vtxos.is_empty());
	assert!(!delivery.input_vtxo_ids.is_empty());
	assert_eq!(delivery.vtxos.iter().map(|v| v.amount()).sum::<Amount>(), invoice_amount);
	for vtxo in &delivery.vtxos {
		wallet.validate_vtxo(vtxo).await.unwrap();
		assert!(wallet.get_vtxo_by_id(vtxo.id()).await.is_err(),
			"the fault must precede local successor inventory insertion");
	}
	assert!(fault.registration_failures.load(Ordering::SeqCst) > 0);
	let signed_requests = fault.signing_requests();
	assert!(signed_requests.0 > 0);
	assert_eq!(signed_requests.1, 0);
	drop(wallet);

	let wallet = reopen_signed_successor_wallet(&ctx, "bark").await;
	assert_eq!(wallet.lightning_receive_checkpoint(payment_hash).await.unwrap(), Some(checkpoint.clone()));
	assert!(wallet.exit_mgr().get_exit_vtxo_ids().await.is_empty());
	wallet.attempt_lightning_receive_exit(payment_hash).await
		.expect("public fallback must exit saved local Delivering successors");
	assert!(wallet.lightning_receive_checkpoint(payment_hash).await.unwrap().is_none());
	assert_eq!(fault.signing_requests(), signed_requests, "fallback must not re-sign old HTLCs");
	srv.stop().await.unwrap();
	confirm_signed_successor_exit(&ctx, &wallet, &delivery.vtxos, &delivery.input_vtxo_ids).await;
	assert_eq!(fault.signing_requests(), signed_requests);
	assert_eq!(wallet.spendable_vtxos().await.unwrap().len(), 0);
	drop(wallet);
	proxy.stop.send(()).unwrap();
	lightning.internal.stop().await.unwrap();
	lightning.external.stop().await.unwrap();
}

/// Signed revocation outputs are still a stuck send when registration fails.
/// Opting into exit must recover the refund branch rather than its old HTLCs.
#[tokio::test]
async fn send_signed_successor_exit_after_registration_failure() {
	let ctx = TestContext::new("bark_sdk/send_signed_successor_exit_after_registration_failure").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.htlc_send_expiry_delta = BlockDelta::new(96)).create().await;
	let fault = SignedSuccessorRegistrationFailure::new(tonic::Code::Unavailable);
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let board_amount = sat(500_000);
	let wallet = ctx.bark_sdk("bark", &proxy.address).funded(sat(1_000_000)).boarded(board_amount)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	wallet.stop_daemon_wait().await.unwrap();
	lightning.sync().await;
	let original_ids = wallet.spendable_vtxos().await.unwrap().iter().map(|v| v.id()).collect::<Vec<_>>();
	let invoice_amount = sat(100_000);
	let payment_hash = Preimage::random().compute_payment_hash();
	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo("signed refund exit".into())),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11;
	wallet.pay_lightning_invoice(invoice, None, false).await.unwrap();
	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;
	hold_client.cancel(hold::CancelRequest { payment_hash: payment_hash.to_vec() })
		.await.unwrap();

	// CLN reconciliation can lag xpay's failure. Only stop once the genuine
	// refund signatures have reached the durable, publicly reported stuck state.
	async {
		loop {
			let _ = wallet.check_lightning_payment(payment_hash, false).await;
			if wallet.stuck_failed_lightning_sends().await.unwrap().iter().any(|send|
				send.invoice.payment_hash() == payment_hash
					&& matches!(&send.progress, SendProgress::RevocationStuck { revocation, .. }
						if !revocation.vtxos.is_empty())
			) {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await;
	let checkpoint = wallet.lightning_send_checkpoint(payment_hash).await.unwrap().unwrap();
	let SendProgress::RevocationStuck { htlcs, revocation } = &checkpoint.progress else {
		panic!("signed refunds must be reported as stuck: {:?}", checkpoint.progress);
	};
	assert!(!checkpoint.allow_exit_of_htlcs);
	assert!(!revocation.vtxos.is_empty());
	assert_eq!(revocation.vtxos.iter().map(|v| v.amount()).sum::<Amount>(), checkpoint.total_amount());
	for vtxo in &revocation.vtxos {
		wallet.validate_vtxo(vtxo).await.unwrap();
		assert!(wallet.get_vtxo_by_id(vtxo.id()).await.is_err(),
			"registration must fail before refund inventory insertion");
	}
	assert!(fault.registration_failures.load(Ordering::SeqCst) > 0);
	let signed_requests = fault.signing_requests();
	assert_eq!(signed_requests.0, 0);
	assert!(signed_requests.1 > 0);
	drop(wallet);

	let wallet = reopen_signed_successor_wallet(&ctx, "bark").await;
	assert_eq!(wallet.lightning_send_checkpoint(payment_hash).await.unwrap(), Some(checkpoint.clone()));
	assert_eq!(wallet.stuck_failed_lightning_sends().await.unwrap(), vec![checkpoint.clone()]);
	let tip = ctx.bitcoind().sync_client().tip().unwrap().height;
	let near_expiry = checkpoint.htlc_expiry
		.saturating_sub(wallet.config().vtxo_refresh_expiry_threshold) + BlockDelta::new(1);
	if let Some(blocks) = near_expiry.checked_blocks_since(tip) {
		if blocks > 0 {
			ctx.generate_blocks(blocks).await;
		}
	}
	assert!(checkpoint.is_htlc_near_expiry(&wallet).await.unwrap());
	let _ = wallet.check_lightning_payment(payment_hash, false).await;
	assert!(wallet.exit_mgr().get_exit_vtxo_ids().await.is_empty(),
		"saved refunds must not bypass explicit exit opt-in");
	assert_eq!(wallet.stuck_failed_lightning_sends().await.unwrap(), vec![checkpoint.clone()]);

	wallet.allow_lightning_send_to_exit(payment_hash).await.unwrap();
	wallet.check_lightning_payment(payment_hash, false).await.unwrap();
	assert!(wallet.lightning_send_checkpoint(payment_hash).await.unwrap().is_none());
	assert!(wallet.stuck_failed_lightning_sends().await.unwrap().is_empty());
	assert_eq!(fault.signing_requests(), signed_requests, "exit must not request another refund signature");
	let change = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(change.iter().map(|v| v.amount()).sum::<Amount>(), board_amount - checkpoint.total_amount());
	assert!(change.iter().all(|v| !original_ids.contains(&v.id()) && !htlcs.vtxo_ids.contains(&v.id())));
	let mut superseded = original_ids;
	superseded.extend_from_slice(&htlcs.vtxo_ids);
	srv.stop().await.unwrap();
	confirm_signed_successor_exit(&ctx, &wallet, &revocation.vtxos, &superseded).await;
	assert_eq!(fault.signing_requests(), signed_requests);
	assert_eq!(wallet.spendable_vtxos().await.unwrap(), change,
		"exiting the refunds must neither reuse inputs nor consume unrelated change");
	drop(wallet);
	proxy.stop.send(()).unwrap();
	lightning.internal.stop().await.unwrap();
	lightning.external.stop().await.unwrap();
}
