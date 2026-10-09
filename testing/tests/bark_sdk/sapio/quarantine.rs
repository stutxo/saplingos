use super::*;

use ark_testing::daemon::captaind::MailboxClient;
use server_rpc::protos::mailbox_server::{ArkoorMessage, MailboxMessage, MailboxMessages, MailboxRequest};
use server_rpc::protos::mailbox_server::mailbox_message::Message;

#[derive(Clone, Default)]
struct PoisonedMailbox {
	message: Arc<Mutex<Option<MailboxMessage>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for PoisonedMailbox {
	async fn read_mailbox(
		&self, upstream: &mut MailboxClient, request: MailboxRequest,
	) -> Result<MailboxMessages, tonic::Status> {
		let message = self.message.lock().take();
		if let Some(message) = message {
			return Ok(MailboxMessages { messages: vec![message], have_more: false });
		}
		Ok(upstream.read_mailbox(request).await?.into_inner())
	}
}

#[derive(Clone)]
struct ReceivingWallet {
	wallet: bark::Wallet,
	db: Arc<SqliteClient>,
	mailbox: PoisonedMailbox,
	checked: Arc<AtomicBool>,
}

async fn prepare(
	State(state): State<ReceivingWallet>, Json(request): Json<ProgramReceiveRequest>,
) -> Result<Json<ProgramReceiveReceipt>, (StatusCode, String)> {
	state.wallet.prepare_program_receive(request).await.map(Json).map_err(http_error)
}

async fn commit(
	State(state): State<ReceivingWallet>, Json(request): Json<ProgramReceiveRequest>,
) -> Result<Json<ProgramReceiveCommit>, (StatusCode, String)> {
	let genuine = ark::Vtxo::deserialize_hex(&request.vtxos[0]).unwrap();
	if !state.checked.load(Ordering::SeqCst) {
		let mut forged = genuine.clone();
		forged.invalidate_final_sig();
		assert_eq!(forged.id(), genuine.id());
		assert_ne!(forged.serialize(), genuine.serialize());

		// Inject before the first commit. Later calls replay the genuine
		// commit and must retain the already accepted canonical bytes.
		let checkpoint = state.wallet.get_mailbox_checkpoint().await.unwrap() + 1;
		*state.mailbox.message.lock() = Some(MailboxMessage {
			checkpoint,
			message: Some(Message::Arkoor(ArkoorMessage { vtxos: vec![forged.serialize()] })),
		});
		state.wallet.sync_mailbox().await.unwrap();
		assert!(state.mailbox.message.lock().is_none());
		assert!(state.db.get_wallet_vtxo(genuine.id()).await.unwrap().is_none(),
			"unverified bytes established a canonical VTXO row");
		let movements = state.wallet.history().await.unwrap();
		let quarantine = movements.iter().find(|m|
			m.metadata.get("raw_vtxo") == Some(&serde_json::Value::String(forged.serialize_hex()))
		).expect("rejected wire bytes were not quarantined");
		assert!(quarantine.output_vtxos.is_empty(), "quarantine reported an owned output");
	}

	let receipt = state.wallet.commit_program_receive(request).await.map_err(http_error)?;
	let stored = state.wallet.get_full_vtxos(state.wallet.vtxos().await.unwrap()).await.unwrap();
	assert_eq!(stored, vec![genuine], "forged genesis poisoned the genuine prepared payment");
	state.checked.store(true, Ordering::SeqCst);
	Ok(Json(receipt))
}

#[tokio::test]
async fn sapio_generic_quarantine_cannot_poison_prepared_same_outpoint() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("bark_sdk/sapio_generic_quarantine_cannot_poison_prepared_same_outpoint").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(400_000)).create().await;
	let mailbox = PoisonedMailbox::default();
	let proxy = srv.start_proxy_with_mailbox((), mailbox.clone()).await;
	let (socket, url) = listener().await;
	let payout = ctx.bitcoind().get_new_address();
	let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), Some(url));
	let receiver = ctx.bark_sdk("receiver", &proxy)
		.cfg(move |c| { c.sapio = Some(sapio); c.daemon_manual_sync = true; }).create().await;
	receiver.stop_daemon_wait().await.unwrap();
	let state = ReceivingWallet {
		wallet: receiver.clone(), mailbox,
		db: Arc::new(SqliteClient::open(ctx.datadir.join("receiver/db.sqlite")).unwrap()),
		checked: Arc::new(AtomicBool::new(false)),
	};
	let router = Router::new().route("/prepare", post(prepare)).route("/commit", post(commit))
		.layer(DefaultBodyLimit::max(bark::sapio::receive::MAX_RECEIVE_BODY_BYTES))
		.with_state(state.clone());
	let task = tokio::spawn(async move { axum::serve(socket, router).await.unwrap(); });
	let address = receiver.new_address().await.unwrap();
	sender.send_arkoor_payment(&address, sat(100_000)).await.unwrap();
	assert!(state.checked.load(Ordering::SeqCst));
	assert_eq!(receiver.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(100_000));
	task.abort();
	sender.stop_daemon_wait().await.unwrap();
	tee.stop().await.unwrap();
	drop(state); drop(receiver); drop(sender); drop(proxy);
	srv.stop().await.unwrap();
}
