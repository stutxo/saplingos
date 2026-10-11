//! Real Sapio/Ark/Bitcoin integration, never an approval-server simulation.
//!
//! Run `just int-sapio` in a private network namespace with:
//! - `SAPIO_TEE_EXEC`: real sapio-tee built with the `local-dev` feature;
//! - `SAPIO_TEMPLATEHASH_WASM`: sapio_tee/examples/templatehash/templatehash.wasm
//!   (the v1 artifact, not the newer v2 evaluator);
//! - `SAPIO_LIFECYCLE_WASM`: build testing/fixtures/sapio/output_value_floor.wat
//!   with `wat2wasm`, and supply its absolute output path.
//! Normal `just int` Bitcoin Core, captaind and Lightning prerequisites apply.
//! Missing fixtures fail the test, rather than silently skipping it. TEE ports
//! 8000/8367 are fixed upstream; the daemon harness holds a cross-process port lock.
//!
//! The lifecycle predicate requires an evidence-selected output to pay at least
//! one satoshi. It permits ordinary Ark transitions *and* recovery by the same
//! rule, not by an implicit recovery exception. It is intentionally not a fixed
//! beneficiary policy. Exact BIP446 has separate coverage: it permits its saved
//! recovery transaction but correctly refuses unrelated outgoing transitions.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::{Json, Router};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{StatusCode, Uri};
use axum::routing::post;
use bitcoin::{absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{TapLeafHash, TapSighashType};
use bitcoin_ext::rpc::{BitcoinRpcErrorExt, RpcApi};
use futures::StreamExt;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use ark::encode::ProtocolEncoding;
use ark::lightning::{PaymentHash, Preimage};
use ark::sapio::program::{Program, ProgramKey};
use ark::vtxo::policy::clause::TapScriptClause;
use ark::vtxo::policy::HarkForfeitVtxoPolicy;
use sapling::persist::models::ProgramRecoveryTemplate;
use sapling::persist::{WalletPersister, sqlite::SqliteClient};
use sapling::onchain::MakeCpfpFees;
use sapling::sapio::SapioConfig;
use sapling::sapio::receive::{ProgramReceiveRequest, ProgramReceiveReceipt, ProgramReceiveCommit};
use sapling::sapio::recovery::{ProgramRecoveryBundle, ProgramRecoveryProgress, ProgramRecoveryReadiness, ProgramRecoveryState};
use sapling::vtxo::VtxoState;
use sapling::actions::lightning::pay::LightningSendState;
use sapling::actions::lightning::receive::LightningReceiveState;
use cln_rpc::plugins::hold;
use sapling_testing::{btc, sat, TestContext};
use sapling_testing::daemon::captaind::{self, ArkClient};
use sapling_testing::daemon::BitcoindExt;
use sapling_testing::util::FutureExt;
use server_rpc::protos;
use server::database::Db;
use server_log::RoundFinished;
use sapling_testing::daemon::sapio::{SapioTee, ENDPOINT};

mod offboard;
mod quarantine;
mod process;

use process::Request;

static TEE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn artifact(variable: &str) -> Vec<u8> {
	let path = std::env::var_os(variable).unwrap_or_else(|| panic!("{variable} must name the real WASM artifact; see module instructions"));
	let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {variable}: {e}"));
	assert!(bytes.starts_with(b"\0asm"), "{variable} is not a WASM binary");
	bytes
}

fn lifecycle_program() -> Program {
	Program::new(sha256::Hash::all_zeros(), artifact("SAPIO_LIFECYCLE_WASM"), 1u64.to_le_bytes().to_vec()).unwrap()
}

fn template_hash(tx: &Transaction) -> Vec<u8> {
	let mut sequences = sha256::Hash::engine();
	for input in &tx.input { sequences.input(&input.sequence.to_consensus_u32().to_le_bytes()); }
	let mut outputs = sha256::Hash::engine();
	for output in &tx.output { outputs.input(&serialize(output)); }
	let tag = sha256::Hash::hash(b"TemplateHash");
	let mut hash = sha256::Hash::engine();
	hash.input(tag.as_byte_array());
	hash.input(tag.as_byte_array());
	hash.input(&tx.version.0.to_le_bytes());
	hash.input(&tx.lock_time.to_consensus_u32().to_le_bytes());
	hash.input(sha256::Hash::from_engine(sequences).as_byte_array());
	hash.input(sha256::Hash::from_engine(outputs).as_byte_array());
	hash.input(&[0]);
	hash.input(&0u32.to_le_bytes());
	sha256::Hash::from_engine(hash).to_byte_array().to_vec()
}

fn recovery(script: ScriptBuf, witness: Vec<u8>) -> ProgramRecoveryTemplate {
	ProgramRecoveryTemplate {
		outputs: vec![TxOut { value: Amount::ZERO, script_pubkey: script }],
		remainder_output: Some(0), lock_time: absolute::LockTime::ZERO, witness,
	}
}

fn config(tee: &SapioTee, program: Program, recovery: ProgramRecoveryTemplate, url: Option<String>) -> SapioConfig {
	SapioConfig { endpoint: ENDPOINT.into(), root: tee.public_root(), program, recovery,
		coordinator_url: url, receive_bind: None }
}

/// Configure ordinary evidence for exactly this wallet's derivation branch.
/// This computes only U and public C; the fixture never has the service secret S.
fn configure_wallet(c: &mut sapling::Config, sapio: SapioConfig, mnemonic: &bip39::Mnemonic) {
	let master = Xpriv::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();
	let branch = master.derive_priv(&ark::SECP, &[
		ChildNumber::from_hardened_idx(350).unwrap(),
		ChildNumber::from_hardened_idx(0).unwrap(),
	]).unwrap();
	for index in 0..128 {
		let user = branch.derive_priv(&ark::SECP, &[ChildNumber::from_normal_idx(index).unwrap()]).unwrap();
		let key = ProgramKey { root: sapio.root, program: sapio.program.clone(),
			user_pubkey: user.to_keypair(&ark::SECP).public_key() };
		c.sapio_witnesses.insert(key.public_key().unwrap(), 0u32.to_le_bytes().to_vec());
	}
	c.sapio = Some(sapio);
	c.daemon_manual_sync = true;
	c.change_vtxo_split_factor = 1;
}

/// A transport fault injector around the real receiving wallet, not an approval
/// service. Every acknowledgement is generated by the production SDK after real
/// program evaluation, Bitcoin ancestry validation and persistence.
#[derive(Clone)]
struct ReceiveState {
	wallet: sapling::Wallet,
	refuse_prepare: Arc<AtomicBool>,
	lose_commit: Arc<AtomicBool>,
	prepares: Arc<AtomicUsize>,
	commits: Arc<AtomicUsize>,
	last_commit: Arc<Mutex<Option<ProgramReceiveRequest>>>,
}

async fn receive_prepare(State(s): State<ReceiveState>, Json(request): Json<ProgramReceiveRequest>)
	-> Result<Json<ProgramReceiveReceipt>, (StatusCode, String)>
{
	s.prepares.fetch_add(1, Ordering::SeqCst);
	if s.refuse_prepare.load(Ordering::SeqCst) {
		return Err((StatusCode::SERVICE_UNAVAILABLE, "test: preparation outage".into()));
	}
	let first = s.wallet.prepare_program_receive(request.clone()).await.map_err(http_error)?;
	let retry = s.wallet.prepare_program_receive(request).await.map_err(http_error)?;
	assert_eq!(serde_json::to_value(&first).unwrap(), serde_json::to_value(&retry).unwrap(), "prepare retry changed durable claim bytes");
	Ok(Json(retry))
}

async fn receive_commit(State(s): State<ReceiveState>, Json(request): Json<ProgramReceiveRequest>)
	-> Result<Json<ProgramReceiveCommit>, (StatusCode, String)>
{
	s.commits.fetch_add(1, Ordering::SeqCst);
	*s.last_commit.lock() = Some(request.clone());
	let first = s.wallet.commit_program_receive(request.clone()).await.map_err(http_error)?;
	let retry = s.wallet.commit_program_receive(request).await.map_err(http_error)?;
	assert_eq!(serde_json::to_value(&first).unwrap(), serde_json::to_value(&retry).unwrap(), "commit retry changed signed output bytes");
	if s.lose_commit.load(Ordering::SeqCst) {
		return Err((StatusCode::SERVICE_UNAVAILABLE, "test: lost durable commit acknowledgement".into()));
	}
	Ok(Json(retry))
}

fn http_error(error: anyhow::Error) -> (StatusCode, String) {
	(StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}"))
}

struct Receiver {
	state: ReceiveState,
	task: JoinHandle<()>,
}

impl Receiver {
	fn start(listener: TcpListener, wallet: &sapling::Wallet) -> Self {
		let state = ReceiveState { wallet: wallet.clone(),
			refuse_prepare: Arc::new(AtomicBool::new(false)), lose_commit: Arc::new(AtomicBool::new(false)),
			prepares: Arc::new(AtomicUsize::new(0)), commits: Arc::new(AtomicUsize::new(0)),
			last_commit: Arc::new(Mutex::new(None)) };
		let router = Router::new().route("/prepare", post(receive_prepare))
			.route("/commit", post(receive_commit))
			.layer(DefaultBodyLimit::max(sapling::sapio::receive::MAX_RECEIVE_BODY_BYTES))
			.with_state(state.clone());
		let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
		Self { state, task }
	}
}

impl Drop for Receiver {
	fn drop(&mut self) { self.task.abort(); }
}

async fn listener() -> (TcpListener, String) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap());
	(listener, url)
}

/// Only forwards actual TEE responses. The one-shot gate holds a successful
/// preparation response while the board still owns its unsigned funding PSBT.
#[derive(Clone)]
struct TeeGateState {
	client: reqwest::Client,
	armed: Arc<AtomicBool>,
	reached: Arc<tokio::sync::Semaphore>,
	release: Arc<tokio::sync::Semaphore>,
}

struct TeeGate {
	url: String,
	state: TeeGateState,
	task: JoinHandle<()>,
}

async fn forward_tee(
	State(state): State<TeeGateState>, uri: Uri, body: Bytes,
) -> Result<(StatusCode, Bytes), (StatusCode, String)> {
	let response = state.client.post(format!("{ENDPOINT}{}", uri.path()))
		.header("content-type", "application/json").body(body)
		.send().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
	let status = response.status();
	let bytes = response.bytes().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
	if uri.path() == "/ark/prepare" && status.is_success() && state.armed.swap(false, Ordering::SeqCst) {
		state.reached.add_permits(1);
		tokio::time::timeout(Duration::from_secs(20), state.release.acquire()).await
			.expect("test did not release genuine TEE response").unwrap().forget();
	}
	Ok((status, bytes))
}

impl TeeGate {
	async fn start() -> Self {
		let (socket, url) = listener().await;
		let state = TeeGateState {
			client: reqwest::Client::builder().timeout(Duration::from_secs(15)).build().unwrap(),
			armed: Arc::new(AtomicBool::new(false)),
			reached: Arc::new(tokio::sync::Semaphore::new(0)),
			release: Arc::new(tokio::sync::Semaphore::new(0)),
		};
		let router = Router::new().route("/ark/prepare", post(forward_tee))
			.route("/ark/finish", post(forward_tee))
			.layer(DefaultBodyLimit::max(16 * 1024 * 1024)).with_state(state.clone());
		let task = tokio::spawn(async move { axum::serve(socket, router).await.unwrap(); });
		Self { url, state, task }
	}

	async fn reached(&self) {
		tokio::time::timeout(Duration::from_secs(20), self.state.reached.acquire()).await
			.expect("board never reached real TEE preparation").unwrap().forget();
	}
}

impl Drop for TeeGate {
	fn drop(&mut self) { self.task.abort(); }
}

/// A genuinely fresh process runs the production daemon; no recovery command or
/// explicit wallet-sync call drives continuation after takeover.
fn watch(ctx: &TestContext, wallet: &str, label: &str) -> tokio::process::Child {
	let stdout = std::fs::File::create(ctx.datadir.join(format!("{wallet}-{label}.stdout"))).unwrap();
	let stderr = std::fs::File::create(ctx.datadir.join(format!("{wallet}-{label}.stderr"))).unwrap();
	process::command(ctx.datadir.join(wallet), ctx.datadir.join(format!("{wallet}-{label}.json")), Request::Watch)
		.stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr))
		.spawn().expect("start fresh offline wallet daemon")
}

async fn wait_for_chain_tx(ctx: &TestContext, txid: bitcoin::Txid) {
	tokio::time::timeout(Duration::from_secs(60), async {
		loop {
			if ctx.bitcoind().sync_client().get_raw_transaction(&txid, None).is_ok() { break; }
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}).await.expect("daemon did not publish saved transaction");
}

async fn finish_automatic_recovery(
	ctx: &TestContext, daemon: &mut tokio::process::Child, records: &[sapling::persist::models::ProgramRecoveryRecord],
) {
	let rpc = ctx.bitcoind().sync_client();
	for _ in 0..120 {
		assert!(daemon.try_wait().unwrap().is_none(), "offline recovery daemon exited");
		if records.iter().all(|r| ctx.bitcoind().transaction_confirmation(r.claim.compute_txid())
			.is_ok_and(|info| info.confirmations.unwrap_or(0) > 0))
		{
			for record in records {
				assert_eq!(rpc.get_raw_transaction(&record.claim.compute_txid(), None).unwrap(), record.claim,
					"automatic recovery changed saved signed bytes");
				assert_eq!(record.claim.output.iter().map(|o| o.value).sum::<Amount>(), record.prevout.value,
					"automatic recovery deducted fees from its immutable beneficiary");
				let claim = ctx.bitcoind().transaction_confirmation(record.claim.compute_txid()).unwrap();
				let parent = ctx.bitcoind().transaction_confirmation(record.controlled_outpoint.txid).unwrap();
				let claim_height = rpc.get_block_header_info(&claim.blockhash.unwrap()).unwrap().height;
				let parent_height = rpc.get_block_header_info(&parent.blockhash.unwrap()).unwrap().height;
				assert!(claim_height >= parent_height + record.claim.input[0].sequence.to_consensus_u32() as usize);
				if record.claim.lock_time.is_block_height() {
					assert!(claim_height > record.claim.lock_time.to_consensus_u32() as usize);
				}
			}
			return;
		}
		ctx.bitcoind().generate(1).await;
		tokio::time::sleep(Duration::from_millis(1100)).await;
	}
	panic!("daemon failed to finish saved claims without manual recovery");
}

/// Each call is a fresh SDK process opening saved SQLite/config/seed bytes.
/// A bounded subprocess also ensures a dead service cannot hang offline recovery.
async fn sdk_process(ctx: &TestContext, wallet: &str, label: &str, request: Request) -> serde_json::Value {
	let response = ctx.datadir.join(format!("{wallet}-{label}.json"));
	let mut command = process::command(ctx.datadir.join(wallet), response.clone(), request);
	let result = tokio::time::timeout(Duration::from_secs(60), command.output()).await
		.expect("offline SDK fixture timed out").expect("run SDK fixture");
	tokio::fs::write(ctx.datadir.join(format!("{wallet}-{label}.stderr")), &result.stderr).await.unwrap();
	tokio::fs::write(ctx.datadir.join(format!("{wallet}-{label}.stdout")), &result.stdout).await.unwrap();
	assert!(result.status.success(), "SDK fixture: {}\n{}",
		String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
	serde_json::from_slice(&tokio::fs::read(response).await.unwrap()).expect("SDK fixture JSON")
}

async fn export(ctx: &TestContext, wallet: &str) -> (PathBuf, ProgramRecoveryBundle) {
	let path = ctx.datadir.join(format!("{wallet}-recovery.json"));
	let value = sdk_process(ctx, wallet, "export", Request::Export).await;
	tokio::fs::write(&path, serde_json::to_vec(&value).unwrap()).await.unwrap();
	let bundle = serde_json::from_value(value).unwrap();
	(path, bundle)
}

async fn recover_offline(ctx: &TestContext, wallet: &str, imported: Option<&Path>, bundle: &ProgramRecoveryBundle) -> bool {
	assert!(!bundle.targets.is_empty());
	let mut saw_maturity = false;
	let rpc = ctx.bitcoind().sync_client();
	for step in 0..100 {
		let progress: Vec<ProgramRecoveryProgress> = serde_json::from_value(
			sdk_process(ctx, wallet, &format!("recover-{step}"), Request::Recover {
				outpoints: vec![], bundle: imported.map(Path::to_path_buf),
			}).await,
		).unwrap();
		assert!(!progress.is_empty());
		for position in &progress {
			assert!(!matches!(position.state, ProgramRecoveryState::Prepared | ProgramRecoveryState::Conflicted { .. }), "{position:?}");
			if matches!(position.state, ProgramRecoveryState::AwaitingMaturity { .. }) {
				saw_maturity = true;
				assert!(rpc.get_raw_transaction(&position.claim_txid, None).is_err(), "immature claim was published");
			}
		}
		if progress.iter().all(|p| p.state == ProgramRecoveryState::Confirmed) {
			for point in &bundle.targets {
				let record = bundle.recoveries.iter().find(|r| r.controlled_outpoint == *point).unwrap();
				let txid = record.claim.compute_txid();
				assert_eq!(rpc.get_raw_transaction(&txid, None).unwrap(), record.claim, "recovery re-signed or mutated the immutable claim");
				assert_eq!(record.claim.output.iter().map(|o| o.value).sum::<Amount>(), record.prevout.value, "claim deducted fees from beneficiary");
				let info = ctx.bitcoind().transaction_confirmation(txid).unwrap();
				assert!(info.confirmations.unwrap_or(0) > 0);
				let claim_height = rpc.get_block_header_info(&info.blockhash.unwrap()).unwrap().height;
				let parent_info = ctx.bitcoind().transaction_confirmation(record.controlled_outpoint.txid).unwrap();
				let parent_height = rpc.get_block_header_info(&parent_info.blockhash.unwrap()).unwrap().height;
				assert!(claim_height >= parent_height + record.claim.input[0].sequence.to_consensus_u32() as usize,
					"Bitcoin confirmed a claim before native CSV maturity");
				if record.claim.lock_time.is_block_height() {
					assert!(claim_height > record.claim.lock_time.to_consensus_u32() as usize,
						"Bitcoin confirmed a claim before its authorized absolute locktime");
				}
				let block = rpc.get_block(&info.blockhash.unwrap()).unwrap();
				let anchor = OutPoint::new(txid, (record.claim.output.len() - 1) as u32);
				let child = block.txdata.iter().find(|tx| tx.input.iter().any(|i| i.previous_output == anchor))
					.expect("zero-fee claim must confirm with a real P2A fee child");
				let input_value: Amount = child.input.iter().map(|i| {
					let parent = rpc.get_raw_transaction(&i.previous_output.txid, None).unwrap();
					parent.output[i.previous_output.vout as usize].value
				}).sum();
				assert!(input_value > child.output.iter().map(|o| o.value).sum::<Amount>(), "fee child paid no mining fee");
			}
			return saw_maturity;
		}
		// Jump only a known, Core-enforced delay, after observing the immature
		// claim absent. Ancestor publication still advances one block at a time.
		let only_maturity = progress.iter().all(|p| matches!(p.state,
			ProgramRecoveryState::Confirmed | ProgramRecoveryState::AwaitingMaturity { .. }));
		let blocks = if only_maturity {
			let height = progress.iter().filter_map(|p| match p.state {
				ProgramRecoveryState::AwaitingMaturity { height } => Some(height),
				_ => None,
			}).min().unwrap();
			height.saturating_sub(1).saturating_sub(rpc.get_block_count().unwrap() as u32).max(1)
		} else { 1 };
		// Do not call wallet sync or captaind after shutdown.
		ctx.bitcoind().generate(blocks).await;
	}
	panic!("saved recovery did not confirm within its bounded chain progression");
}

#[tokio::test]
async fn sapio_bip446_receive_exact_payout_and_offline_sdk_recovery() {
	let _exclusive = TEE_LOCK.lock().await;
	let wasm = artifact("SAPIO_TEMPLATEHASH_WASM");
	assert_eq!(sha256::Hash::hash(&wasm).to_string(), "0fbc4e2cc68722474e3a708ffb934c0784990806ea1fb4a3dda64805fdd340a1", "use the reviewed real BIP446 v1 artifact");
	let ctx = TestContext::new("sapling_sdk/sapio_bip446_receive_exact_payout_and_offline_sdk_recovery").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let sender = ctx.sdk("sender", &srv).boarded(sat(400_000)).create().await;
	let payout = ctx.bitcoind().get_new_address();
	let forbidden = ctx.bitcoind().get_new_address();
	let amount = sat(100_000);
	let exact_claim = Transaction { version: transaction::Version(3), lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn { previous_output: OutPoint::null(), sequence: Sequence::from_height(srv.config().vtxo_exit_delta.to_u32().try_into().unwrap()), ..TxIn::default() }],
		output: vec![TxOut { value: amount, script_pubkey: payout.script_pubkey() }, bitcoin_ext::fee::fee_anchor()] };
	let program = Program::new(sha256::Hash::all_zeros(), wasm, template_hash(&exact_claim)).unwrap();
	let (socket, url) = listener().await;
	let sapio = config(&tee, program, recovery(payout.script_pubkey(), vec![]), Some(url));
	let receiver = ctx.sdk("receiver", &srv).funded(sat(500_000))
		.cfg(move |c| { c.sapio = Some(sapio); c.daemon_manual_sync = true; }).create().await;
	let coordinator = Receiver::start(socket, &receiver);
	let address = receiver.new_address().await.unwrap();
	sender.send_arkoor_payment(&address, amount).await.expect("native sender creates genuine BIP446-backed position");
	let received = receiver.spendable_vtxos().await.unwrap();
	assert_eq!(received.len(), 1);
	assert_eq!(received[0].amount(), amount);
	let point = received[0].vtxo.point();
	let saved = receiver.program_recovery_bundle(&[point]).await.unwrap();
	let claim = &saved.recoveries.iter().find(|r| r.controlled_outpoint == point).unwrap().claim;
	assert_eq!(template_hash(claim), template_hash(&exact_claim));
	assert_eq!(claim.output, exact_claim.output);
	let mut redirected = saved.clone();
	redirected.recoveries.iter_mut().find(|r| r.controlled_outpoint == point).unwrap().claim.output[0].script_pubkey = forbidden.script_pubkey();
	assert!(redirected.verify().is_err(), "mutated saved destination must invalidate authorization");
	let (bad_socket, bad_url) = listener().await;
	let wrong_plan = config(&tee, saved.keys[0].program.program.clone(),
		recovery(forbidden.script_pubkey(), vec![]), Some(bad_url));
	let bad_receiver = ctx.sdk("forbidden-recipient", &srv)
		.cfg(move |c| { c.sapio = Some(wrong_plan); c.daemon_manual_sync = true; }).create().await;
	let bad_coordinator = Receiver::start(bad_socket, &bad_receiver);
	let bad_address = bad_receiver.new_address().await.unwrap();
	sender.send_arkoor_payment(&bad_address, amount).await
		.expect_err("real BIP446 evaluation rejects a recovery construction with a forbidden destination");
	assert!(bad_receiver.spendable_vtxos().await.unwrap().is_empty());
	assert_eq!(bad_coordinator.state.commits.load(Ordering::SeqCst), 0);
	drop(bad_coordinator);
	bad_receiver.stop_daemon_wait().await.unwrap();
	drop(bad_receiver);
	let native_address = sender.new_address().await.unwrap();
	receiver.send_arkoor_payment(&native_address, sat(10_000)).await
		.expect_err("exact BIP446 policy must not receive an implicit Ark transition exception");
	assert_eq!(receiver.get_vtxo_by_id(received[0].id()).await.unwrap().amount(), amount);
	let retained = receiver.program_recovery_bundle(&[point]).await.unwrap();
	assert_eq!(retained.readiness(point).unwrap(), ProgramRecoveryReadiness::Complete);
	assert_eq!(retained.recoveries, saved.recoveries, "unsupported transition lost the old position");
	drop(coordinator);
	receiver.stop_daemon_wait().await.unwrap(); sender.stop_daemon_wait().await.unwrap();
	drop(receiver); drop(sender);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	let (path, exported) = export(&ctx, "receiver").await;
	assert_eq!(exported.readiness(point).unwrap(), ProgramRecoveryReadiness::Complete);
	// The same datadir is opened afresh for every SDK process, with both services dead.
	assert!(recover_offline(&ctx, "receiver", Some(&path), &exported).await,
		"fresh BIP446 position must exercise the native CSV delay against Bitcoin Core");
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), amount);
	assert_eq!(ctx.bitcoind().get_received_by_address(&forbidden), Amount::ZERO);
}

#[tokio::test]
async fn sapio_generic_board_receive_checkpoint_commit_crash_and_recovery() {
	let _exclusive = TEE_LOCK.lock().await;
	let program = lifecycle_program();
	let ctx = TestContext::new("sapling_sdk/sapio_generic_board_receive_checkpoint_commit_crash_and_recovery").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let sapio = config(&tee, program.clone(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let evidence_seed = mnemonic.clone();
	let sender = ctx.sdk("sender", &srv).mnemonic(mnemonic).funded(sat(1_500_000)).boarded(sat(400_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let native = ctx.sdk("native", &srv).create().await;
	let native_address = native.new_address().await.unwrap();
	sender.send_arkoor_payment(&native_address, sat(50_000)).await.unwrap();
	native.sync().await;
	assert_eq!(native.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(50_000));
	assert_eq!(sender.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(350_000));
	native.stop_daemon_wait().await.unwrap();
	drop(native);
	let old = sender.spendable_vtxos().await.unwrap()[0].clone();
	assert_eq!(sender.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap().readiness(old.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
	let recipient_payout = ctx.bitcoind().get_new_address();
	let (socket, url) = listener().await;
	let sapio = config(&tee, program.clone(), recovery(recipient_payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), Some(url));
	let receiver = ctx.sdk("receiver", &srv).funded(sat(500_000))
		.cfg(move |c| { c.sapio = Some(sapio); c.daemon_manual_sync = true; }).create().await;
	let coordinator = Receiver::start(socket, &receiver);
	let address = receiver.new_address().await.unwrap();
	coordinator.state.refuse_prepare.store(true, Ordering::SeqCst);
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect_err("preparation outage refuses irreversible commitment");
	assert_eq!(sender.get_vtxo_by_id(old.id()).await.unwrap().amount(), old.amount());
	assert_eq!(sender.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap().readiness(old.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
	assert!(receiver.spendable_vtxos().await.unwrap().is_empty());
	assert_eq!(coordinator.state.commits.load(Ordering::SeqCst), 0);
	coordinator.state.refuse_prepare.store(false, Ordering::SeqCst);
	coordinator.state.lose_commit.store(true, Ordering::SeqCst);
	sender.sync_pending_arkoor_sends().await.unwrap();
	assert!(coordinator.state.commits.load(Ordering::SeqCst) > 0);
	assert!(sender.spendable_vtxos().await.unwrap().iter().all(|v| v.id() != old.id()), "completed signatures must lock the old input");
	assert!(!sender.pending_arkoor_sends().await.unwrap().is_empty(), "signed transition checkpoint must survive delivery failure");
	let received = receiver.spendable_vtxos().await.unwrap();
	assert_eq!(received.iter().map(|v| v.amount()).sum::<Amount>(), sat(100_000));
	let bundle = sender.program_recovery_bundle(&[]).await.unwrap();
	assert!(bundle.recoveries.iter().any(|r| r.ancestors.len() >= 3 && bundle.targets.contains(&r.controlled_outpoint)), "checkpointed outgoing ancestry was not durably saved");
	let request = coordinator.state.last_commit.lock().clone().unwrap();
	let receiver_before = receiver.program_recovery_bundle(&[]).await.unwrap();
	tee.stop().await.unwrap();
	// Retrying both recipient phases reuses saved claims, without a live TEE.
	let prepared = receiver.prepare_program_receive(request.clone()).await.unwrap();
	let committed = receiver.commit_program_receive(request.clone()).await.unwrap();
	assert_eq!(prepared.recoveries.len(), request.vtxos.len());
	assert_eq!(serde_json::to_value(&committed).unwrap(), serde_json::to_value(receiver.commit_program_receive(request).await.unwrap()).unwrap());
	assert_eq!(serde_json::to_value(receiver.program_recovery_bundle(&[]).await.unwrap()).unwrap(), serde_json::to_value(receiver_before).unwrap());
	drop(coordinator);
	sender.stop_daemon_wait().await.unwrap(); receiver.stop_daemon_wait().await.unwrap();
	drop(sender); drop(receiver); srv.stop().await.unwrap();
	let (_, sender_bundle) = export(&ctx, "sender").await;
	let expected = sender_bundle.targets.iter().map(|p| sender_bundle.recoveries.iter().find(|r| r.controlled_outpoint == *p).unwrap().claim.output[0].value).sum::<Amount>();
	assert_eq!(expected, sat(250_000), "offline export must choose signed change, not reuse its committed input");
	recover_offline(&ctx, "sender", None, &sender_bundle).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), sat(250_000));
	let db = SqliteClient::open(ctx.datadir.join("sender/db.sqlite")).unwrap();
	let retained = db.get_wallet_vtxo(old.id()).await.unwrap().unwrap();
	assert!(matches!(retained.state, VtxoState::Spent | VtxoState::Exited),
		"restart must not resurrect a committed input after offline takeover");
	let (_, recipient_bundle) = export(&ctx, "receiver").await;
	recover_offline(&ctx, "receiver", None, &recipient_bundle).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&recipient_payout), sat(100_000));
}

#[derive(Clone, Default)]
struct CaptureRegistration {
	vtxos: Arc<Mutex<Vec<ark::Vtxo<ark::vtxo::Full>>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for CaptureRegistration {
	async fn register_vtxo_transactions(
		&self, upstream: &mut ArkClient, request: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		let response = upstream.register_vtxo_transactions(request.clone()).await?.into_inner();
		for bytes in &request.vtxos {
			self.vtxos.lock().push(ark::Vtxo::<ark::vtxo::Full>::deserialize(bytes).unwrap());
		}
		Ok(response)
	}
}

#[tokio::test]
async fn sapio_generic_evidence_rejection_and_unprepared_raw_deposit() {
	let _exclusive = TEE_LOCK.lock().await;
	let program = lifecycle_program();
	let ctx = TestContext::new("sapling_sdk/sapio_generic_evidence_rejection_and_unprepared_raw_deposit").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let payout = ctx.bitcoind().get_new_address();
	for (name, witness, minimum) in [
		("anchor-evidence", 1u32, 1u64),
		("missing-output-evidence", u32::MAX, 1),
		("insufficient-value", 0, 500_000),
	] {
		let predicate = Program::new(program.evaluator(), program.program().to_vec(), minimum.to_le_bytes().to_vec()).unwrap();
		let sapio = config(&tee, predicate, recovery(payout.script_pubkey(), witness.to_le_bytes().to_vec()), None);
		let mnemonic = bip39::Mnemonic::generate(12).unwrap();
		let evidence_seed = mnemonic.clone();
		let wallet = ctx.sdk(name, &srv).mnemonic(mnemonic).funded(sat(600_000))
			.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
		let mempool = ctx.bitcoind().sync_client().get_raw_mempool().unwrap();
		let error = wallet.board_amount(sat(100_000)).await.expect_err("real evaluator must reject invalid recovery evidence/value");
		assert!(format!("{error:#}").contains("Sapio") || format!("{error:#}").contains("program"), "{error:#}");
		assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
		assert_eq!(ctx.bitcoind().sync_client().get_raw_mempool().unwrap(), mempool, "rejected recovery must not broadcast board funding");
		wallet.stop_daemon_wait().await.unwrap();
	}

	let capture = CaptureRegistration::default();
	let proxy = srv.start_proxy_no_mailbox(capture.clone()).await;
	let sender = ctx.sdk("native-sender", &proxy).boarded(sat(400_000)).create().await;
	let (_socket, url) = listener().await;
	let sapio = config(&tee, program.clone(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), Some(url));
	let receiver = ctx.sdk("raw-receiver", &srv)
		.cfg(move |c| { c.sapio = Some(sapio); c.daemon_manual_sync = true; }).create().await;
	let coordinated = receiver.new_address().await.unwrap();
	// An unsolicited sender can strip delivery metadata. This is not a managed
	// receive: the recipient must quarantine it even though C and signatures match.
	let raw = ark::Address::new(coordinated.is_testnet(), coordinated.ark_id(),
		coordinated.policy().clone(), vec![]);
	sender.send_arkoor_payment(&raw, sat(100_000)).await.unwrap();
	let vtxo = capture.vtxos.lock().iter().find(|v|
		v.user_pubkey() == coordinated.policy().user_pubkey()
	).expect("captured real registered raw deposit").clone();
	let request = ProgramReceiveRequest { address: coordinated.to_string(), vtxos: vec![vtxo.serialize_hex()] };
	receiver.commit_program_receive(request).await.expect_err("commit cannot prepare an unsolicited deposit after commitment");
	receiver.import_vtxo(&vtxo, sapling::ImportVtxoArgs::default()).await
		.expect_err("unprepared raw deposit must not enter the spendable wallet");
	assert!(receiver.spendable_vtxos().await.unwrap().is_empty());
	// A live genuine evaluator still authorizes a properly prepared board.
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, program, recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let managed = ctx.sdk("managed", &srv).mnemonic(mnemonic).funded(sat(800_000)).boarded(sat(100_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let old = managed.spendable_vtxos().await.unwrap()[0].clone();
	let saved = managed.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap();
	tee.stop().await.unwrap();
	let mempool = ctx.bitcoind().sync_client().get_raw_mempool().unwrap();
	managed.board_amount(sat(100_000)).await.expect_err("TEE outage before preparation refuses funding");
	assert_eq!(ctx.bitcoind().sync_client().get_raw_mempool().unwrap(), mempool);
	assert_eq!(managed.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap().recoveries, saved.recoveries);
	managed.stop_daemon_wait().await.unwrap(); receiver.stop_daemon_wait().await.unwrap(); sender.stop_daemon_wait().await.unwrap();
	drop(managed); drop(receiver); drop(sender); drop(proxy);
	srv.stop().await.unwrap();
	let (_, bundle) = export(&ctx, "managed").await;
	recover_offline(&ctx, "managed", None, &bundle).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), sat(100_000));
}

#[derive(Clone, Default)]
struct LoseForfeitResponse {
	armed: Arc<AtomicBool>,
	saved: Arc<Mutex<Option<protos::ForfeitVtxosRequest>>>,
	calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for LoseForfeitResponse {
	async fn forfeit_vtxos(
		&self, upstream: &mut ArkClient, request: protos::ForfeitVtxosRequest,
	) -> Result<protos::ForfeitVtxosResponse, tonic::Status> {
		let response = upstream.forfeit_vtxos(request.clone()).await?.into_inner();
		if self.armed.load(Ordering::SeqCst) {
			self.calls.fetch_add(1, Ordering::SeqCst);
			let mut saved = self.saved.lock();
			if let Some(first) = saved.as_ref() {
				assert_eq!(first, &request, "forfeit response-loss retry regenerated signatures");
			} else {
				*saved = Some(request);
			}
			return Err(tonic::Status::unavailable("test: lost real forfeit response"));
		}
		Ok(response)
	}
}

/// Publish only previously signed parent bytes. The extra signature here belongs
/// to an ordinary fee wallet, never to a Sapio key or an Ark ownership key.
async fn publish_saved_parent(ctx: &TestContext, fee_wallet: &sapling::Wallet, tx: &Transaction) {
	let txid = tx.compute_txid();
	let rpc = ctx.bitcoind().sync_client();
	match ctx.bitcoind().transaction_confirmation(txid) {
		Ok(info) => {
			assert_eq!(rpc.get_raw_transaction(&txid, None).unwrap(), *tx,
				"previously published parent changed its saved signed bytes");
			if info.confirmations.unwrap_or(0) > 0 { return; }
			// The first offline recovery may already have sponsored this old
			// branch. Mine that package, rather than replace its fee child
			// with an unrelated publisher's equal-fee spend of the anchor.
		},
		Err(e) if e.is_not_found() => {
			let onchain = fee_wallet.onchain().unwrap();
			let mut onchain = onchain.write().await;
			onchain.sync(fee_wallet.chain()).await.unwrap();
			let child = onchain.make_signed_p2a_cpfp(tx,
				MakeCpfpFees::Effective(bitcoin::FeeRate::from_sat_per_vb_u32(2))).await.unwrap();
			onchain.store_signed_p2a_cpfp(&child).await.unwrap();
			fee_wallet.chain().broadcast_package(&[tx, &child]).await.unwrap();
		},
		Err(e) => panic!("query saved parent {txid}: {e}"),
	}
	ctx.bitcoind().generate(1).await;
	assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap().confirmations.unwrap_or(0) > 0);
	assert_eq!(rpc.get_raw_transaction(&txid, None).unwrap(), *tx,
		"confirmed parent changed its saved signed bytes");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HarkPublication { None, Forfeit, ClaimedForfeit }

async fn hark_recovery(publication: HarkPublication) {
	let publish_forfeit = publication != HarkPublication::None;
	let _exclusive = TEE_LOCK.lock().await;
	let program = lifecycle_program();
	let ctx = TestContext::new(match publication {
		HarkPublication::None => "sapling_sdk/sapio_generic_hark_unpublished_forfeit_old_branch_recovery",
		HarkPublication::Forfeit => "sapling_sdk/sapio_generic_refresh_hark_published_forfeit_recovery",
		HarkPublication::ClaimedForfeit => "sapling_sdk/sapio_generic_hark_claimed_forfeit_chain_unlock_recovery",
	}).await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(2)).create().await;
	let fault = LoseForfeitResponse::default();
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, program, recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let wallet = ctx.sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(1_500_000)).boarded(sat(800_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let fee_wallet = ctx.sdk("publisher-fees", &srv).funded(sat(1_000_000))
		.cfg(|c| c.daemon_manual_sync = true).create().await;
	if publish_forfeit {
		let before = wallet.spendable_vtxos().await.unwrap()[0].id();
		let (result, _) = tokio::join!(
			wallet.refresh_vtxos(vec![before]),
			async {
				tokio::time::sleep(Duration::from_secs(2)).await;
				srv.trigger_round().await;
			},
		);
		assert!(result.unwrap().is_some(), "generic program did not join interactive refresh");
		ctx.generate_blocks(sapling_testing::constants::ROUND_CONFIRMATIONS).await;
		wallet.sync().await;
		let fresh = wallet.spendable_vtxos().await.unwrap();
		assert!(!fresh.is_empty());
		assert!(fresh.iter().all(|v| v.id() != before), "refresh reused its committed input");
		assert_eq!(wallet.get_vtxo_by_id(before).await.unwrap().state, VtxoState::Spent);
		for vtxo in fresh {
			let saved = wallet.program_recovery_bundle(&[vtxo.vtxo.point()]).await.unwrap();
			assert_eq!(saved.readiness(vtxo.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
			assert!(saved.keys.iter().any(|k| k.program.public_key().unwrap() == vtxo.user_pubkey()),
				"refresh silently changed program ownership into a native key");
		}
	}
	let old = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(old.len(), 1);
	let old = old[0].clone();
	fault.armed.store(true, Ordering::SeqCst);
	let round = wallet.refresh_vtxos_delegated(vec![old.id()]).await.unwrap().unwrap();
	let unlock_hash = round.state().unlock_hash().unwrap();
	drop(round);
	let mut finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(60)).await.expect("real hArk round finished");
	ctx.generate_blocks(sapling_testing::constants::ROUND_CONFIRMATIONS).await;
	for _ in 0..30 {
		wallet.progress_pending_rounds(None).await.unwrap();
		wallet.sync_pending_rounds().await.unwrap();
		if fault.saved.lock().is_some() { break; }
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert!(fault.saved.lock().is_some(), "forfeit handoff was not reached");
	wallet.sync_pending_rounds().await.unwrap();
	assert!(fault.calls.load(Ordering::SeqCst) >= 2,
		"lost forfeit acknowledgement must exercise an actual same-byte retry");
	assert!(wallet.spendable_vtxos().await.unwrap().iter().all(|v| v.id() != old.id()));
	let bundle = wallet.program_recovery_bundle(&[]).await.unwrap();
	let conditional = bundle.recoveries.iter().find(|record|
		matches!(bundle.readiness(record.controlled_outpoint), Ok(ProgramRecoveryReadiness::Conditional { old_position, .. }) if old_position == old.vtxo.point())
	).expect("hArk claim must retain its real unsigned publication dependency and old branch").clone();
	assert_eq!(bundle.readiness(old.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
	// Obtain the genuine completed transaction the unchanged server already
	// persisted. Do not finish or manufacture a forfeit signature in the test.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let participation = db.read(async |t|
		t.get_round_participation_by_unlock_hash(unlock_hash).await
	).await.unwrap().unwrap();
	let signed_forfeit = participation.inputs.iter().find(|input| input.vtxo_id == old.id())
		.unwrap().signed_forfeit_tx.clone().expect("server persisted its actual forfeit");
	assert_eq!(signed_forfeit.compute_txid(), conditional.controlled_outpoint.txid);
	let saved_forfeit = ctx.datadir.join("published-forfeit.bin");
	tokio::fs::write(&saved_forfeit, serialize(&signed_forfeit)).await.unwrap();
	let replacement = bundle.recoveries.iter().find(|record| record.unlocks.iter()
		.any(|unlock| unlock.hash == unlock_hash && unlock.disclosures.iter()
			.any(|d| d.outpoint == conditional.controlled_outpoint)))
		.expect("replacement signature and authenticated disclosure dependency must survive before preimage disclosure").clone();
	let unlock = replacement.unlocks.iter().find(|u| u.hash == unlock_hash).unwrap();
	assert_eq!(unlock.witness.len(), 3, "export must contain signature/script/control, not the undisclosed preimage");
	assert_eq!(unlock.witness.iter().next().unwrap().len(), 64);
	let old_leaf = replacement.ancestors.iter().find(|tx| tx.compute_txid() == unlock.ancestor).unwrap();
	assert!(old_leaf.input[0].witness.is_empty(), "test must lose the actual unlock response");
	let attack_claim = if publication == HarkPublication::ClaimedForfeit {
		// Only the ordinary test-owned server A signs its own hashlock branch.
		// Replacement C+A signatures above were obtained from the real protocol.
		let seed = server::wallet::read_mnemonic_from_datadir(&srv.config().data_dir).unwrap().to_seed("");
		let master = Xpriv::new_master(Network::Regtest, &seed).unwrap();
		let server_key = master.derive_priv(&ark::SECP, &[
			ChildNumber::from_hardened_idx(2).unwrap(), ChildNumber::from_hardened_idx(0).unwrap(),
		]).unwrap().to_keypair(&ark::SECP);
		assert_eq!(server_key.public_key(), old.server_pubkey());
		let policy = HarkForfeitVtxoPolicy { user_pubkey: old.user_pubkey(), unlock_hash };
		let clause = policy.server_claim_clause(server_key.public_key());
		let taproot = policy.taproot(server_key.public_key(), old.exit_delta());
		let script = clause.tapscript();
		let control = taproot.control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript)).unwrap();
		assert_eq!(conditional.prevout.script_pubkey, ScriptBuf::new_p2tr_tweaked(taproot.output_key()));
		let mut tx = Transaction { version: transaction::Version(3), lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn { previous_output: conditional.controlled_outpoint, sequence: Sequence::MAX, ..TxIn::default() }],
			output: vec![TxOut { value: conditional.prevout.value, script_pubkey: ctx.bitcoind().get_new_address().script_pubkey() },
				bitcoin_ext::fee::fee_anchor()] };
		let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(0,
			&Prevouts::All(&[conditional.prevout.clone()]), TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript),
			TapSighashType::Default).unwrap();
		let signature = ark::SECP.sign_schnorr(&sighash.into(), &server_key);
		tx.input[0].witness = clause.witness(&(signature, *participation.unlock_preimage.leak_ref()), &control);
		Some(tx)
	} else { None };
	wallet.stop_daemon_wait().await.unwrap(); fee_wallet.stop_daemon_wait().await.unwrap();
	drop(wallet); drop(proxy); drop(db);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	let (_, mut exported) = export(&ctx, "wallet").await;
	assert_eq!(exported.readiness(conditional.controlled_outpoint).unwrap(),
		ProgramRecoveryReadiness::Conditional { publication: signed_forfeit.compute_txid(), old_position: old.vtxo.point() });
	let replacement_export = exported.recoveries.iter().find(|r| r.controlled_outpoint == replacement.controlled_outpoint).unwrap();
	assert_eq!(replacement_export, &replacement, "fresh-process export lost pre-disclosure signature material");
	let before_disclosure = ctx.datadir.join("before-disclosure.json");
	tokio::fs::write(&before_disclosure, serde_json::to_vec(&exported).unwrap()).await.unwrap();
	// This first offline invocation must report the unknown parent honestly; it
	// can begin the old branch but cannot sign or fabricate the forfeit parent.
	let progress: Vec<ProgramRecoveryProgress> = serde_json::from_value(sdk_process(&ctx, "wallet", "conditional",
		Request::Recover { outpoints: vec![conditional.controlled_outpoint], bundle: None }).await).unwrap();
	assert!(progress.iter().any(|p| matches!(p.state,
		ProgramRecoveryState::AwaitingPublication { txid } if txid == signed_forfeit.compute_txid())));
	if publish_forfeit {
		let actual: Transaction = bitcoin::consensus::deserialize(&tokio::fs::read(saved_forfeit).await.unwrap()).unwrap();
		for parent in &conditional.ancestors {
			if parent.compute_txid() == actual.compute_txid() { break; }
			publish_saved_parent(&ctx, &fee_wallet, parent).await;
		}
		publish_saved_parent(&ctx, &fee_wallet, &actual).await;
		if let Some(attack) = &attack_claim {
			let rpc = ctx.bitcoind().sync_client();
			assert!(rpc.get_raw_transaction(&replacement.controlled_outpoint.txid, None).is_err(),
				"server must not publish the replacement for the wallet");
			publish_saved_parent(&ctx, &fee_wallet, attack).await;
			assert!(rpc.get_tx_out(&conditional.controlled_outpoint.txid, conditional.controlled_outpoint.vout, Some(true)).unwrap().is_none(),
				"immediate server claim must consume the delayed fallback");
			let forfeit_info = ctx.bitcoind().transaction_confirmation(actual.compute_txid()).unwrap();
			let attack_info = ctx.bitcoind().transaction_confirmation(attack.compute_txid()).unwrap();
			let forfeit_height = rpc.get_block_header_info(&forfeit_info.blockhash.unwrap()).unwrap().height;
			let attack_height = rpc.get_block_header_info(&attack_info.blockhash.unwrap()).unwrap().height;
			assert!(attack_height < forfeit_height + old.exit_delta().to_u32() as usize,
				"attack did not exercise the immediate hashlock branch before user CSV");
			// Reload only the exported pre-disclosure bytes. No server or enclave
			// can hydrate them; the sole new information is Bitcoin's witness.
			exported = serde_json::from_slice(&tokio::fs::read(&before_disclosure).await.unwrap()).unwrap();
			exported.targets = vec![replacement.controlled_outpoint];
		} else {
			exported.targets = vec![conditional.controlled_outpoint];
		}
	} else {
		assert!(ctx.bitcoind().sync_client().get_raw_transaction(&signed_forfeit.compute_txid(), None).is_err());
		exported.targets = vec![old.vtxo.point()];
	}
	drop(fee_wallet);
	exported.verify().unwrap();
	let selected = ctx.datadir.join("selected-branch.json");
	tokio::fs::write(&selected, serde_json::to_vec(&exported).unwrap()).await.unwrap();
	recover_offline(&ctx, "wallet", Some(&selected), &exported).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), old.amount());
	if let Some(attack) = &attack_claim {
		let actual = ctx.bitcoind().sync_client().get_raw_transaction(&unlock.ancestor, None).unwrap();
		let witness: Vec<_> = actual.input[0].witness.iter().collect();
		let saved: Vec<_> = unlock.witness.iter().collect();
		assert_eq!(witness[0], saved[0], "replacement signature changed after S/A shutdown");
		assert_eq!(witness[1], attack.input[0].witness.iter().nth(1).unwrap());
		assert_eq!(&witness[2..], &saved[1..]);
		assert_eq!(actual.compute_txid(), old_leaf.compute_txid());
	}
}

#[tokio::test]
async fn sapio_generic_refresh_hark_published_forfeit_recovery() {
	hark_recovery(HarkPublication::Forfeit).await;
}

#[tokio::test]
async fn sapio_generic_hark_unpublished_forfeit_old_branch_recovery() {
	hark_recovery(HarkPublication::None).await;
}

#[tokio::test]
async fn sapio_generic_hark_claimed_forfeit_chain_unlock_recovery() {
	hark_recovery(HarkPublication::ClaimedForfeit).await;
}

async fn hold_invoice(node: &sapling_testing::Lightningd, preimage: Preimage, amount: Amount) -> String {
	node.hold_client().await.invoice(hold::InvoiceRequest {
		payment_hash: preimage.compute_payment_hash().as_ref().to_vec(),
		amount_msat: amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo("real Sapio lifecycle".into())),
		min_final_cltv_expiry: Some(18), expiry: Some(3600), routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11
}

#[tokio::test]
async fn sapio_generic_lightning_send_receive_revoke_and_offline_timeout() {
	let _exclusive = TEE_LOCK.lock().await;
	let program = lifecycle_program();
	let ctx = TestContext::new("sapling_sdk/sapio_generic_lightning_send_receive_revoke_and_offline_timeout").await;
	let tee = SapioTee::launch(&ctx).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc())
		.lightningd(&lightning.internal).funded(btc(10))
		.cfg(|c| {
			c.htlc_send_expiry_delta = bitcoin_ext::BlockDelta::new(96);
			c.max_user_invoice_cltv_delta = bitcoin_ext::BlockDelta::new(300);
		})
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let payout = ctx.bitcoind().get_new_address();
	let mut plan = recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec());
	// An explicit, policy-authorized height beyond this test's outgoing HTLC expiries.
	// A zero-height construction cannot satisfy native HTLC refund CLTV. The
	// wallet must reject that plan, never silently change its authorized locktime.
	plan.lock_time = absolute::LockTime::from_height(ctx.bitcoind().get_block_count().await as u32 + 200).unwrap();
	let sapio = config(&tee, program, plan, None);
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let wallet = ctx.sdk("wallet", &srv).mnemonic(mnemonic).funded(sat(2_000_000)).boarded(sat(500_000))
		.cfg(move |c| {
			configure_wallet(c, sapio, &evidence_seed);
			// Request a genuine inbound deadline with room for the immutable
			// height-locked claim, rather than weakening its program or lock.
			c.vtxo_exit_margin = bitcoin_ext::BlockDelta::new(220);
		}).create().await;
	lightning.sync().await;
	let invoice = lightning.external.invoice(Some(sat(25_000)), "sapio-paid", "real program payment").await;
	wallet.pay_lightning_invoice(invoice, None, true).wait_millis(60_000).await.unwrap();
	lightning.external.wait_invoice_paid("sapio-paid").await;
	assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(475_000));

	let invoice = wallet.bolt11_invoice(sat(15_000), None, None).await.unwrap();
	let receive_hash = PaymentHash::from(&invoice);
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await.unwrap();
	let (paid, claimed) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			loop {
				let msg = mailbox.next().wait_millis(30_000).await.unwrap().unwrap();
				if let Some(protos::mailbox_server::mailbox_message::Message::IncomingLightningPayment(incoming)) = msg.message {
					assert_eq!(incoming.payment_hash, receive_hash.as_ref().to_vec());
					break;
				}
			}
			wallet.try_claim_lightning_receive(receive_hash, true).await
		},
	);
	paid.unwrap();
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
	drop(mailbox);
	assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(490_000));

	let cancelled_preimage = Preimage::random();
	let cancelled_hash = cancelled_preimage.compute_payment_hash();
	let cancelled = hold_invoice(&lightning.external, cancelled_preimage, sat(10_000)).await;
	wallet.pay_lightning_invoice(cancelled, None, false).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(cancelled_hash).await;
	lightning.external.hold_client().await.cancel(hold::CancelRequest {
		payment_hash: cancelled_hash.as_ref().to_vec(),
	}).await.unwrap();
	assert_eq!(wallet.check_lightning_payment(cancelled_hash, true).wait_millis(60_000).await.unwrap(), LightningSendState::Unknown);
	assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(), sat(490_000));

	let held_preimage = Preimage::random();
	let held_hash = held_preimage.compute_payment_hash();
	let held = hold_invoice(&lightning.external, held_preimage, sat(20_000)).await;
	let before = wallet.spendable_vtxos().await.unwrap();
	wallet.pay_lightning_invoice(held, None, false).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(held_hash).await;
	assert!(matches!(wallet.check_lightning_payment(held_hash, false).await.unwrap(), LightningSendState::InProgress(_)));
	let pending = wallet.pending_lightning_send_vtxos().await.unwrap();
	assert!(!pending.is_empty());
	for htlc in &pending {
		let recovery = wallet.program_recovery_bundle(&[htlc.vtxo.point()]).await.unwrap();
		assert_eq!(recovery.readiness(htlc.vtxo.point()).unwrap(), ProgramRecoveryReadiness::Complete);
	}
	let after = wallet.spendable_vtxos().await.unwrap();
	assert!(before.iter().any(|v| after.iter().all(|a| a.id() != v.id())), "payment reused its committed input");
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	lightning.internal.stop().await.unwrap(); lightning.external.stop().await.unwrap();
	let (_, bundle) = export(&ctx, "wallet").await;
	let total = bundle.targets.iter().map(|point| bundle.recoveries.iter().find(|r| r.controlled_outpoint == *point).unwrap().claim.output[0].value).sum::<Amount>();
	assert_eq!(total, sat(490_000), "recover held timeout plus current change, never already-paid or revoked inputs");
	// The first package consumes the sole confirmed fee UTXO. Other positions
	// must report fee starvation without losing that successful publication or
	// treating its unconfirmed v3 change as a new confirmed fee input.
	let first: Vec<ProgramRecoveryProgress> = serde_json::from_value(sdk_process(&ctx, "wallet", "first-fee-pass",
		Request::Recover { outpoints: vec![], bundle: None }).await).unwrap();
	let mempool = ctx.bitcoind().sync_client().get_raw_mempool().unwrap();
	assert!(first.iter().any(|p| matches!(p.state,
		ProgramRecoveryState::AwaitingConfirmation { txid } if mempool.contains(&txid))),
		"first recovery package must remain published when a later position lacks fees");
	let fee_waits = first.iter().filter_map(|p| match p.state {
		ProgramRecoveryState::AwaitingFees { txid, available, needed } => Some((txid, available, needed)),
		_ => None,
	}).collect::<Vec<_>>();
	assert!(!fee_waits.is_empty(), "fixture must exhaust its single confirmed external-fee input");
	for (txid, available, needed) in fee_waits {
		assert_eq!(available, Amount::ZERO);
		assert!(needed > available);
		if let Ok(published) = ctx.bitcoind().sync_client().get_raw_transaction(&txid, None) {
			// Positions may share the ancestor funded earlier in this pass.
			// A later fee-bump shortage must preserve that exact publication.
			assert!(first.iter().any(|p| matches!(p.state,
				ProgramRecoveryState::AwaitingConfirmation { txid: funded } if funded == txid)));
			let saved = bundle.recoveries.iter().flat_map(|r| &r.ancestors)
				.find(|tx| tx.compute_txid() == txid).unwrap();
			assert_eq!(&published, saved);
		}
	}
	// Confirmation replenishes fee-wallet change; fresh SDK processes must
	// resume every position and retain the exact claims and payouts below.
	ctx.bitcoind().generate(1).await;
	recover_offline(&ctx, "wallet", None, &bundle).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), total);
}

#[tokio::test]
async fn sapio_generic_board_serializes_funding_with_board_and_onchain_send() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_board_serializes_funding_with_board_and_onchain_send").await;
	let tee = SapioTee::launch(&ctx).await;
	let gate = TeeGate::start().await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	for (name, second_is_board, independent_funds) in [
		("two-boards", true, false),
		("board-and-send", false, false),
		("two-boards-independent", true, true),
		("board-and-send-independent", false, true),
	] {
		let mnemonic = bip39::Mnemonic::generate(12).unwrap();
		let evidence_seed = mnemonic.clone();
		let payout = ctx.bitcoind().get_new_address();
		let mut sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
		sapio.endpoint = gate.url.clone();
		let wallet = ctx.sdk(name, &srv).mnemonic(mnemonic)
			.funded(sat(if independent_funds { 225_000 } else { 700_000 }))
			.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
		if independent_funds {
			// Each confirmed output covers one operation, but its change
			// cannot cover the other. Retain the one-UTXO cases above to
			// exercise spending a parent's change before any block is mined.
			let onchain = wallet.onchain().unwrap();
			let mut onchain = onchain.write().await;
			let address = onchain.address().await.unwrap();
			ctx.bitcoind().fund_addr(address, sat(225_000)).await;
			ctx.bitcoind().generate(1).await;
			onchain.sync(wallet.chain()).await.unwrap();
		}
		let funding = {
			let onchain = wallet.onchain().unwrap();
			let onchain = onchain.read().await;
			let bdk = (&*onchain as &dyn std::any::Any)
				.downcast_ref::<sapling::onchain::OnchainWallet>().unwrap();
			bdk.list_unspent().into_iter().map(|utxo| utxo.outpoint).collect::<Vec<_>>()
		};
		assert_eq!(funding.len(), if independent_funds { 2 } else { 1 });
		let mempool = ctx.bitcoind().sync_client().get_raw_mempool().unwrap();
		gate.state.armed.store(true, Ordering::SeqCst);
		let first_wallet = wallet.clone();
		let first = tokio::spawn(async move { first_wallet.board_amount(sat(200_000)).await });
		gate.reached().await;
		assert!(!first.is_finished());
		assert_eq!(ctx.bitcoind().sync_client().get_raw_mempool().unwrap(), mempool,
			"board funding escaped before recovery authorization was returned");
		let sent_to = ctx.bitcoind().get_new_address();
		let destination = sent_to.clone();
		let second_wallet = wallet.clone();
		let started = Arc::new(tokio::sync::Semaphore::new(0));
		let started_in_task = started.clone();
		let second = tokio::spawn(async move {
			started_in_task.add_permits(1);
			if second_is_board {
				Ok::<_, anyhow::Error>(second_wallet.board_amount(sat(200_000)).await?.funding_tx)
			} else {
				let onchain = second_wallet.onchain().unwrap();
				let mut onchain = onchain.write().await;
				let psbt = onchain.prepare_tx(&[(destination, sat(200_000))],
					bitcoin::FeeRate::from_sat_per_vb_u32(2)).await?;
				let tx = onchain.finish_psbt(psbt).await?.extract_tx()?;
				second_wallet.chain().broadcast_tx(&tx).await?;
				Ok(tx)
			}
		});
		started.acquire().await.unwrap().forget();
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(!second.is_finished(), "competing funding operation bypassed the board's onchain guard");
		assert_eq!(ctx.bitcoind().sync_client().get_raw_mempool().unwrap(), mempool);
		gate.state.release.add_permits(1);
		let first = first.wait(Duration::from_secs(30)).await.unwrap().unwrap().funding_tx;
		let second = second.wait(Duration::from_secs(30)).await.unwrap().unwrap();
		assert_eq!(first.input.len(), 1, "first board must spend exactly one funding UTXO");
		assert!(funding.contains(&first.input[0].previous_output));
		assert!(first.input.iter().all(|a| second.input.iter().all(|b| a.previous_output != b.previous_output)),
			"concurrent board/send signed the same funding outpoint");
		if independent_funds {
			assert!(second.input.iter().any(|i| funding.contains(&i.previous_output)),
				"second operation must use a distinct originally funded UTXO");
		} else {
			assert!(second.input.iter().any(|i| i.previous_output.txid == first.compute_txid()),
				"second operation must use first funding's real change, not the spent original UTXO");
		}
		// PendingBoard exposes an inspection transaction, possibly unsigned.
		// Pin the actual signed bytes from the local wallet before confirmation.
		let signed_funding = {
			let onchain = wallet.onchain().unwrap();
			let onchain = onchain.read().await;
			let bdk = (&*onchain as &dyn std::any::Any)
				.downcast_ref::<sapling::onchain::OnchainWallet>().unwrap();
			bdk.list_transactions()
		};
		ctx.generate_blocks(sapling_testing::constants::BOARD_CONFIRMATIONS).await;
		wallet.sync().await;
		let rpc = ctx.bitcoind().sync_client();
		for tx in [&first, &second] {
			let txid = tx.compute_txid();
			let signed = signed_funding.iter().find(|saved| saved.compute_txid() == txid).unwrap();
			assert_eq!(rpc.get_raw_transaction(&txid, None).unwrap(), **signed,
				"confirmed funding must retain its exact signed bytes");
			assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap().confirmations.unwrap_or(0)
				>= u32::from(sapling_testing::constants::BOARD_CONFIRMATIONS));
		}
		assert_eq!(wallet.spendable_vtxos().await.unwrap().iter().map(|v| v.amount()).sum::<Amount>(),
			if second_is_board { sat(400_000) } else { sat(200_000) });
		if !second_is_board { assert_eq!(ctx.bitcoind().get_received_by_address(&sent_to), sat(200_000)); }
		wallet.stop_daemon_wait().await.unwrap();
		let persisted = tokio::fs::read(ctx.datadir.join(name).join("config.toml")).await.unwrap();
		let private: sapling::Config = toml::from_str(std::str::from_utf8(&persisted).unwrap()).unwrap();
		assert!(!private.sapio_witnesses.is_empty());
		assert!(!private.sapio.as_ref().unwrap().recovery.witness.is_empty());
		let diagnostic = sdk_process(&ctx, name, "redacted-config", Request::Config).await;
		assert_eq!(diagnostic["sapio_witnesses"], serde_json::json!({}));
		assert_eq!(diagnostic["sapio"]["recovery"]["witness"], serde_json::json!([]));
		let _: sapling::Config = serde_json::from_value(diagnostic).unwrap();
		assert_eq!(tokio::fs::read(ctx.datadir.join(name).join("config.toml")).await.unwrap(), persisted,
			"diagnostic redaction mutated authorization evidence in private persisted configuration");
	}
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
}

#[derive(Clone, Default)]
struct RefuseBoardRegistration {
	attempts: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RefuseBoardRegistration {
	async fn register_board_vtxo(
		&self, _upstream: &mut ArkClient, _request: protos::BoardVtxoRequest,
	) -> Result<protos::Empty, tonic::Status> {
		self.attempts.fetch_add(1, Ordering::SeqCst);
		Err(tonic::Status::unavailable("test: board registration unavailable"))
	}
}

#[tokio::test]
async fn sapio_generic_unregistered_board_expiry_daemon_recovery_survives_restart() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_unregistered_board_expiry_daemon_recovery_survives_restart").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let fault = RefuseBoardRegistration::default();
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let wallet = ctx.sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(1_000_000))
		.cfg(move |c| {
			configure_wallet(c, sapio, &evidence_seed);
			c.daemon_manual_sync = false;
			c.daemon_sync_interval_secs = 1;
		}).create().await;
	let board = wallet.board_amount(sat(200_000)).await.unwrap();
	ctx.generate_blocks(sapling_testing::constants::BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert!(fault.attempts.load(Ordering::SeqCst) > 0);
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	let vtxo = wallet.get_vtxo_by_id(board.vtxos[0]).await.unwrap();
	let saved = wallet.program_recovery_bundle(&[vtxo.vtxo.point()]).await.unwrap();
	let record = saved.recoveries.iter().find(|r| r.controlled_outpoint == vtxo.vtxo.point()).unwrap().clone();
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let takeover_height = vtxo.expiry_height().to_u32() - wallet.config().vtxo_exit_margin.to_u32();
	ctx.generate_blocks(takeover_height.saturating_sub(tip)).await;
	let first = record.ancestors.iter().find(|tx| tx.compute_txid() != board.funding_tx.compute_txid()).unwrap();
	wait_for_chain_tx(&ctx, first.compute_txid()).await;
	let db = SqliteClient::open(ctx.datadir.join("wallet/db.sqlite")).unwrap();
	assert!(db.has_program_recovery_reservation(
		&sapling::persist::models::recovery_vtxo_key(vtxo.id())).await.unwrap());
	assert!(ctx.bitcoind().sync_client().get_raw_transaction(&record.claim.compute_txid(), None).is_err(),
		"test must restart after the first ancestor, before claim maturity");
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet); drop(proxy);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	let mut daemon = watch(&ctx, "wallet", "offline-board-first");
	ctx.bitcoind().generate(1).await;
	tokio::time::sleep(Duration::from_millis(1100)).await;
	daemon.kill().await.unwrap(); daemon.wait().await.unwrap();
	let mut daemon = watch(&ctx, "wallet", "offline-board-restarted");
	finish_automatic_recovery(&ctx, &mut daemon, &[record]).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), sat(200_000));
	assert!(matches!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, VtxoState::Exited));
	daemon.kill().await.unwrap(); daemon.wait().await.unwrap();
}

#[tokio::test]
async fn sapio_generic_uncommitted_round_candidate_keeps_old_offline_recovery() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_uncommitted_round_candidate_keeps_old_offline_recovery").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let fault = LoseForfeitResponse::default();
	fault.armed.store(true, Ordering::SeqCst);
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), None);
	let wallet = ctx.sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(1_000_000)).boarded(sat(250_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let old = wallet.spendable_vtxos().await.unwrap()[0].clone();
	let original = wallet.program_recovery_bundle(&[old.vtxo.point()]).await.unwrap();
	let round = wallet.refresh_vtxos_delegated(vec![old.id()]).await.unwrap().unwrap();
	drop(round);
	let mut finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	finished.recv().wait(Duration::from_secs(60)).await.unwrap();
	ctx.generate_blocks(sapling_testing::constants::ROUND_CONFIRMATIONS).await;
	// Exactly one sync installs Finished/new_vtxos, but must not authorize the
	// replacement or hand over old-input shares during the same checkpoint.
	wallet.sync_pending_rounds().await.unwrap();
	let rounds = wallet.pending_round_states().await.unwrap();
	assert_eq!(rounds.len(), 1);
	let candidates = rounds[0].state().output_vtxos().expect("delegated candidate was not checkpointed").to_vec();
	assert!(!candidates.is_empty());
	let db = SqliteClient::open(ctx.datadir.join("wallet/db.sqlite")).unwrap();
	for candidate in &candidates {
		assert!(db.get_program_key(&candidate.user_pubkey()).await.unwrap().is_some());
		assert!(db.get_program_recovery(candidate.point()).await.unwrap().is_none(),
			"test crossed the uncommitted candidate recovery barrier");
	}
	assert!(fault.saved.lock().is_none(), "old forfeit escaped before replacement preparation");
	drop(rounds);
	tee.stop().await.unwrap();
	wallet.sync_pending_rounds().await.unwrap();
	assert!(fault.saved.lock().is_none(), "TEE outage must prevent forfeit commitment");
	let saved = wallet.program_recovery_bundle(&[old.vtxo.point()]).await
		.expect("an uncommitted missing claim must not poison old-position export");
	assert_eq!(saved.targets, vec![old.vtxo.point()]);
	assert_eq!(saved.recoveries.iter().find(|r| r.controlled_outpoint == old.vtxo.point()),
		original.recoveries.iter().find(|r| r.controlled_outpoint == old.vtxo.point()));
	assert!(candidates.iter().all(|v| !saved.targets.contains(&v.point())));
	wallet.recover_program_vtxos(&[old.vtxo.point()], None).await
		.expect("old-position recovery must work without replacement authorization");
	wallet.stop_daemon_wait().await.unwrap(); drop(wallet); drop(proxy);
	srv.stop().await.unwrap();
	let path = ctx.datadir.join("old-uncommitted-round.json");
	tokio::fs::write(&path, serde_json::to_vec(&saved).unwrap()).await.unwrap();
	recover_offline(&ctx, "wallet", Some(&path), &saved).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), old.amount());
	for candidate in candidates {
		assert!(ctx.bitcoind().sync_client().get_raw_transaction(&candidate.point().txid, None).is_err());
	}
}

#[tokio::test]
async fn sapio_generic_selected_sibling_recovery_does_not_take_parked_sibling() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_selected_sibling_recovery_does_not_take_parked_sibling").await;
	let tee = SapioTee::launch(&ctx).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).funded(btc(1)).create().await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let (socket, url) = listener().await;
	let sapio = config(&tee, lifecycle_program(), recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec()), Some(url));
	let wallet = ctx.sdk("wallet", &srv).mnemonic(mnemonic).funded(sat(1_000_000)).boarded(sat(400_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let old = wallet.spendable_vtxos().await.unwrap()[0].clone();
	let coordinator = Receiver::start(socket, &wallet);
	let own_address = wallet.new_address().await.unwrap();
	wallet.send_arkoor_payment(&own_address, sat(150_000)).await.unwrap();
	let siblings = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(siblings.len(), 2);
	let p = siblings.iter().find(|v| v.amount() == sat(150_000)).unwrap().clone();
	let q = siblings.iter().find(|v| v.amount() == sat(250_000)).unwrap().clone();
	assert_eq!(wallet.get_vtxo_by_id(old.id()).await.unwrap().state, VtxoState::Spent);
	let parked = wallet.refresh_vtxos_delegated(vec![q.id()]).await.unwrap().unwrap();
	let q_round = parked.id();
	let q_checkpoint = serde_json::to_value(sapling::persist::models::SerdeRoundState::from(parked.state())).unwrap();
	drop(parked);
	let before = wallet.program_recovery_bundle(&[p.vtxo.point()]).await.unwrap();
	assert_eq!(before.targets, vec![p.vtxo.point()], "historical common input promoted unrelated sibling Q");
	drop(coordinator);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	wallet.recover_program_vtxos(&[p.vtxo.point()], None).await.unwrap();
	let db = SqliteClient::open(ctx.datadir.join("wallet/db.sqlite")).unwrap();
	assert!(!db.has_program_recovery_reservation(&sapling::persist::models::recovery_vtxo_key(q.id())).await.unwrap());
	assert!(!db.has_program_recovery_reservation(&sapling::persist::models::recovery_round_key(q_round)).await.unwrap());
	let rounds = wallet.pending_round_states().await.unwrap();
	assert_eq!(serde_json::to_value(sapling::persist::models::SerdeRoundState::from(
		rounds.iter().find(|r| r.id() == q_round).unwrap().state(),
	)).unwrap(), q_checkpoint);
	assert_eq!(wallet.get_vtxo_by_id(q.id()).await.unwrap().vtxo.serialize(), q.vtxo.serialize());
	drop(rounds);
	let saved = wallet.program_recovery_bundle(&[p.vtxo.point()]).await.unwrap();
	assert_eq!(saved.targets, vec![p.vtxo.point()]);
	wallet.stop_daemon_wait().await.unwrap(); drop(wallet);
	let path = ctx.datadir.join("selected-p-only.json");
	tokio::fs::write(&path, serde_json::to_vec(&saved).unwrap()).await.unwrap();
	recover_offline(&ctx, "wallet", Some(&path), &saved).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), p.amount());
	assert_eq!(db.get_wallet_vtxo(q.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
	let q_claim = db.get_program_recovery(q.vtxo.point()).await.unwrap().unwrap().claim;
	assert!(ctx.bitcoind().sync_client().get_raw_transaction(&q_claim.compute_txid(), None).is_err());
	assert!(!db.has_program_recovery_reservation(&sapling::persist::models::recovery_vtxo_key(q.id())).await.unwrap());
}

#[derive(Clone, Default)]
struct CountReceiveDisclosures {
	claims: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for CountReceiveDisclosures {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, request: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.claims.fetch_add(1, Ordering::SeqCst);
		Ok(upstream.claim_lightning_receive(request).await?.into_inner())
	}
}

#[tokio::test]
async fn sapio_generic_inbound_late_fixed_lock_rejects_before_disclosure() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_inbound_late_fixed_lock_rejects_before_disclosure").await;
	let tee = SapioTee::launch(&ctx).await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let fault = CountReceiveDisclosures::default();
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let mut plan = recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec());
	let fixed_lock = absolute::LockTime::from_height(ctx.bitcoind().get_block_count().await as u32 + 10_000).unwrap();
	plan.lock_time = fixed_lock;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let sapio = config(&tee, lifecycle_program(), plan, None);
	let wallet = ctx.sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(500_000))
		.cfg(move |c| configure_wallet(c, sapio, &evidence_seed)).create().await;
	let invoice = wallet.bolt11_invoice(sat(20_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await.unwrap();
	lightning.sync().await;
	let payment = lightning.external.try_pay_bolt11(invoice.to_string());
	tokio::pin!(payment);
	let rejection = async {
		loop {
			let msg = mailbox.next().wait(Duration::from_secs(60)).await.unwrap().unwrap();
			if let Some(protos::mailbox_server::mailbox_message::Message::IncomingLightningPayment(incoming)) = msg.message {
				if incoming.payment_hash == hash.as_ref().to_vec() { break; }
			}
		}
		wallet.try_claim_lightning_receive(hash, true).await
			.expect_err("authorized but too-late immutable recovery must reject the grant")
	};
	let error = tokio::select! {
		result = &mut payment => panic!("payer completed before safe receive admission: {result:?}"),
		error = rejection => error,
	};
	assert!(format!("{error:#}").contains("recover") || format!("{error:#}").contains("deadline"), "{error:#}");
	assert_eq!(fault.claims.load(Ordering::SeqCst), 0, "late recovery disclosed the Lightning preimage");
	assert!(!matches!(wallet.lightning_receive_state(hash).await, Ok(LightningReceiveState::Settled(_))));
	assert!(wallet.spendable_vtxos().await.unwrap().is_empty());
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), Amount::ZERO);
	let db = SqliteClient::open(ctx.datadir.join("wallet/db.sqlite")).unwrap();
	let records = db.list_program_recoveries().await.unwrap();
	assert!(!records.is_empty(), "real program claim was not prepared before deadline rejection");
	assert!(records.iter().all(|r| r.claim.lock_time == fixed_lock),
		"wallet worked around the policy by silently lowering the authorized locktime");
	if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), &mut payment).await {
		assert!(result.is_err(), "payer settled despite rejected inbound recovery");
	}
	drop(mailbox);
	wallet.stop_daemon_wait().await.unwrap();
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
}

#[derive(Clone, Default)]
struct RefuseOutgoingCompletion {
	revocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RefuseOutgoingCompletion {
	async fn initiate_lightning_payment(
		&self, _upstream: &mut ArkClient, _request: protos::InitiateLightningPaymentRequest,
	) -> Result<protos::Empty, tonic::Status> {
		Err(tonic::Status::invalid_argument("test: payment initiation rejected after real HTLC signing"))
	}

	async fn request_lightning_pay_htlc_revocation(
		&self, _upstream: &mut ArkClient, _request: protos::ArkoorPackageCosignRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.revocations.fetch_add(1, Ordering::SeqCst);
		Err(tonic::Status::invalid_argument("test: genuine refund signatures unavailable"))
	}
}

#[tokio::test]
async fn sapio_generic_reserved_htlc_daemon_continues_without_cooperative_services() {
	let _exclusive = TEE_LOCK.lock().await;
	let ctx = TestContext::new("sapling_sdk/sapio_generic_reserved_htlc_daemon_continues_without_cooperative_services").await;
	let tee = SapioTee::launch(&ctx).await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(btc(10)).cfg(|c| c.htlc_send_expiry_delta = bitcoin_ext::BlockDelta::new(96)).create().await;
	let fault = RefuseOutgoingCompletion::default();
	let proxy = srv.start_proxy_no_mailbox(fault.clone()).await;
	let payout = ctx.bitcoind().get_new_address();
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let evidence_seed = mnemonic.clone();
	let mut plan = recovery(payout.script_pubkey(), 0u32.to_le_bytes().to_vec());
	plan.lock_time = absolute::LockTime::from_height(ctx.bitcoind().get_block_count().await as u32 + 120).unwrap();
	let sapio = config(&tee, lifecycle_program(), plan, None);
	let wallet = ctx.sdk("wallet", &proxy).mnemonic(mnemonic).funded(sat(1_500_000)).boarded(sat(400_000))
		.cfg(move |c| {
			configure_wallet(c, sapio, &evidence_seed);
			c.daemon_manual_sync = false;
			c.daemon_sync_interval_secs = 1;
			c.vtxo_refresh_expiry_threshold = bitcoin_ext::BlockDelta::new(12);
		}).create().await;
	// Drive the cooperative failure deterministically; fresh processes below
	// restart with background continuation enabled in the saved configuration.
	wallet.stop_daemon_wait().await.unwrap();
	let invoice = lightning.external.invoice(Some(sat(30_000)), "unpaid", "reserved program timeout").await;
	wallet.pay_lightning_invoice(invoice, None, false).await.expect_err("real HTLC is signed, payment and revocation then fail");
	let sends = wallet.stuck_failed_lightning_sends().await.unwrap();
	assert_eq!(sends.len(), 1);
	let send = &sends[0];
	let hash = send.invoice.payment_hash();
	let pending = wallet.pending_lightning_send_vtxos().await.unwrap();
	assert!(!pending.is_empty());
	let db = SqliteClient::open(ctx.datadir.join("wallet/db.sqlite")).unwrap();
	let mut records = Vec::new();
	for vtxo in &pending {
		let record = db.get_program_recovery(vtxo.vtxo.point()).await.unwrap().unwrap();
		assert!(record.claim.lock_time.to_consensus_u32() >= send.htlc_expiry.to_u32());
		records.push(record);
	}
	let amount = records.iter().map(|r| r.prevout.value).sum::<Amount>();
	assert_eq!(amount, send.total_amount());
	let change = wallet.spendable_vtxos().await.unwrap();
	assert_eq!(change.iter().map(|v| v.amount()).sum::<Amount>() + amount, sat(400_000));
	let tip = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(send.htlc_expiry.to_u32().saturating_sub(11).saturating_sub(tip)).await;
	wallet.allow_lightning_send_to_exit(hash).await.unwrap();
	wallet.sync_pending_lightning_send_vtxos().await.unwrap();
	assert!(db.has_program_recovery_reservation(&sapling::persist::models::recovery_action_key(&send.id())).await.unwrap(),
		"opted-in timeout did not durably take the action over");
	assert!(wallet.pending_lightning_send_vtxos().await.unwrap().is_empty(),
		"continuation test requires the reserved targets, not still-live HTLC inventory");
	for record in &records {
		assert!(db.has_program_recovery_reservation(
			&sapling::persist::models::recovery_target_key(record.controlled_outpoint.into())).await.unwrap());
		assert!(ctx.bitcoind().sync_client().get_raw_transaction(&record.claim.compute_txid(), None).is_err());
	}
	let retries = fault.revocations.load(Ordering::SeqCst);
	wallet.sync_pending_lightning_send_vtxos().await.unwrap();
	assert_eq!(fault.revocations.load(Ordering::SeqCst), retries, "stale cooperative driver crossed recovery takeover");
	assert_eq!(wallet.balance().await.unwrap().pending_program_recovery, amount);
	wallet.stop_daemon_wait().await.unwrap(); drop(wallet); drop(proxy);
	tee.stop().await.unwrap(); srv.stop().await.unwrap();
	lightning.internal.stop().await.unwrap(); lightning.external.stop().await.unwrap();
	let mut daemon = watch(&ctx, "wallet", "offline-htlc-first");
	let first = records[0].ancestors.iter().find(|tx|
		!ctx.bitcoind().transaction_confirmation(tx.compute_txid())
			.is_ok_and(|info| info.confirmations.unwrap_or(0) > 0)
	).unwrap();
	wait_for_chain_tx(&ctx, first.compute_txid()).await;
	daemon.kill().await.unwrap(); daemon.wait().await.unwrap();
	let mut daemon = watch(&ctx, "wallet", "offline-htlc-restarted");
	finish_automatic_recovery(&ctx, &mut daemon, &records).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&payout), amount);
	for vtxo in change {
		assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
		let record = db.get_program_recovery(vtxo.vtxo.point()).await.unwrap().unwrap();
		assert!(ctx.bitcoind().sync_client().get_raw_transaction(&record.claim.compute_txid(), None).is_err(),
			"reserved-only daemon recovered unrelated unreserved change");
	}
	daemon.kill().await.unwrap(); daemon.wait().await.unwrap();
}
