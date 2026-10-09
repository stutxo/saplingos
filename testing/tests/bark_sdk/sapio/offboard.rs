use super::*;

use bark::actions::offboard::Progress;

#[derive(Clone)]
struct OffboardBoundary {
	drop_request: bool,
	lose_reply: Arc<AtomicBool>,
	requests: Arc<Mutex<Vec<protos::FinishOffboardRequest>>>,
	signed: Arc<Mutex<Option<Transaction>>>,
}

impl OffboardBoundary {
	fn new(drop_request: bool) -> Self {
		Self {
			drop_request,
			lose_reply: Arc::new(AtomicBool::new(!drop_request)),
			requests: Arc::new(Mutex::new(Vec::new())),
			signed: Arc::new(Mutex::new(None)),
		}
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for OffboardBoundary {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, request: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		self.requests.lock().push(request.clone());
		if self.drop_request {
			return Err(tonic::Status::unavailable("test: forfeit handoff interrupted"));
		}
		let response = upstream.finish_offboard(request).await?.into_inner();
		*self.signed.lock() = Some(bitcoin::consensus::deserialize(&response.signed_offboard_tx).unwrap());
		if self.lose_reply.swap(false, Ordering::SeqCst) {
			return Err(tonic::Status::unavailable("test: signed offboard response lost"));
		}
		Ok(response)
	}
}

#[tokio::test]
async fn sapio_generic_offboard_outages_preserve_old_offline_recovery() {
	let _exclusive = TEE_LOCK.lock().await;
	for after_handoff in [false, true] {
		let ctx = TestContext::new(if after_handoff {
			"bark_sdk/sapio_generic_offboard_after_handoff_recovery"
		} else {
			"bark_sdk/sapio_generic_offboard_before_handoff_recovery"
		}).await;
		let tee = SapioTee::launch(&ctx).await;
		let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1)).create().await;
		let boundary = OffboardBoundary::new(true);
		let proxy = srv.start_proxy_no_mailbox(boundary.clone()).await;
		let payout = ctx.bitcoind().get_new_address();
		let destination = ctx.bitcoind().get_new_address();
		let mnemonic = bip39::Mnemonic::generate(12).unwrap();
		let evidence_seed = mnemonic.clone();
		let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
		let wallet = ctx.bark_sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(900_000)).boarded(sat(400_000))
			.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
		let old = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
		let original = wallet.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap();
		if !after_handoff { tee.stop().await.unwrap(); }

		wallet.offboard_all(destination.clone()).await.expect_err("offboard must stop at the injected outage");
		let pending = wallet.pending_offboards().await.unwrap();
		assert_eq!(pending.len(), 1);
		if after_handoff {
			let Progress::ForfeitsPrepared { user_nonces, partial_signatures, .. } = &pending[0].progress else {
				panic!("forfeit shares were not checkpointed before handoff");
			};
			let requests = boundary.requests.lock();
			let request = requests.first().expect("no forfeit share reached the handoff");
			assert_eq!(request.user_nonces, user_nonces.iter().map(|n| n.serialize().to_vec()).collect::<Vec<_>>());
			assert_eq!(request.partial_signatures, partial_signatures.iter().map(|s| s.to_vec()).collect::<Vec<_>>());
		} else {
			assert!(boundary.requests.lock().is_empty(), "forfeits escaped without program authorization");
		}
		let retained = wallet.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap();
		assert_eq!(retained.recoveries, original.recoveries);
		assert_eq!(retained.readiness(old.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
		wallet.stop_daemon_wait().await.unwrap();
		drop(wallet);
		if after_handoff { tee.stop().await.unwrap(); }
		srv.stop().await.unwrap();
		let (_, bundle) = export(&ctx, "wallet").await;
		recover_offline(&ctx, "wallet", None, &bundle).await;
		assert_eq!(ctx.bitcoind().get_received_by_address(&payout), sat(400_000));
		assert_eq!(ctx.bitcoind().get_received_by_address(&destination), Amount::ZERO);
	}
}

#[tokio::test]
async fn sapio_generic_offboard_lost_response_replays_shares_and_recovers_change() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("bark_sdk/sapio_generic_offboard_lost_response_replays_shares_and_recovers_change").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1)).create().await;
	let boundary = OffboardBoundary::new(false);
	let proxy = srv.start_proxy_no_mailbox(boundary.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let destination = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let wallet = ctx.bark_sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(800_000)).boarded(sat(300_000))
		.cfg(move |c| {
			configure_wallet(c, sapio, &evidence_seed);
			c.offboard_required_confirmations = bitcoin_ext::BlockDelta::new(1);
		}).create().await;

	wallet.send_onchain(destination.clone(), sat(100_000)).await.expect_err("finish response must be lost");
	let pending = wallet.pending_offboards().await.unwrap();
	assert_eq!(pending.len(), 1);
	assert!(matches!(pending[0].progress, Progress::ForfeitsPrepared { .. }));
	let change = wallet.spendable_vtxos().await.unwrap();
	let change_value = sat(300_000) - sat(100_000) - pending[0].committed_fee;
	assert_eq!(change.iter().map(|v| v.amount()).sum::<Amount>(), change_value);
	for vtxo in &change {
		let bundle = wallet.program_recovery_bundle(&[vtxo.vtxo.point()]).await.unwrap();
		assert_eq!(bundle.readiness(vtxo.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
		assert!(bundle.keys.iter().any(|key| key.program.public_key().unwrap() == vtxo.user_pubkey()));
	}
	let signed = boundary.signed.lock().clone().expect("real server did not sign the offboard");
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);
	tee.stop().await.unwrap();

	// A fresh CLI process must use the checkpointed shares, not ask S again.
	cli(&ctx, "wallet", "resume-offboard", &["balance"]).await;
	{
		let requests = boundary.requests.lock();
		assert!(requests.len() >= 2, "restart did not retry the lost finish response");
		assert!(requests.iter().all(|request| request == &requests[0]), "restart changed a nonce or forfeit share");
	}
	ctx.generate_blocks(1).await;
	cli(&ctx, "wallet", "settle-offboard", &["balance"]).await;
	assert_eq!(ctx.bitcoind().sync_client().get_raw_transaction(&signed.compute_txid(), None).unwrap(), signed);
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), sat(100_000));

	srv.stop().await.unwrap();
	let (_, bundle) = export(&ctx, "wallet").await;
	assert_eq!(bundle.targets.len(), change.len(), "offboarded inputs remained recovery targets");
	recover_offline(&ctx, "wallet", None, &bundle).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), change_value);
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), sat(100_000));
}
