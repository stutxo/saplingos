//! Internal libtest subprocess protocol, not a wallet command-line interface.
//! Every invocation reopens the real SDK from persisted seed/config/SQLite bytes.

use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::{FeeRate, Network, OutPoint};
use sapling::{OpenWalletArgs, WalletSeed};
use sapling::onchain::OnchainWallet;
use sapling::persist::{WalletPersister, sqlite::SqliteClient};
use sapling::sapio::recovery::{ProgramRecoveryBundle, recover_program_bundle};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Serialize, Deserialize)]
pub(super) enum Request {
	Watch,
	Export,
	Recover { outpoints: Vec<OutPoint>, bundle: Option<PathBuf> },
	Balance,
	Config,
}

pub(super) fn command(datadir: PathBuf, response: PathBuf, request: Request) -> Command {
	let mut command = Command::new(std::env::current_exe().expect("integration test executable"));
	command.args(["--exact", "sapio::process::sdk_process", "--ignored", "--nocapture"])
		.env("SAPLING_TEST_DATADIR", datadir)
		.env("SAPLING_TEST_RESPONSE", response)
		.env("SAPLING_TEST_REQUEST", serde_json::to_string(&request).unwrap())
		.kill_on_drop(true);
	command
}

#[tokio::test]
#[ignore = "internal subprocess entry point; requires a serialized fixture request"]
async fn sdk_process() {
	let request: Request = serde_json::from_str(&std::env::var("SAPLING_TEST_REQUEST")
		.expect("SDK fixture request is required")).unwrap();
	let datadir = PathBuf::from(std::env::var_os("SAPLING_TEST_DATADIR").expect("fixture datadir"));
	let response = PathBuf::from(std::env::var_os("SAPLING_TEST_RESPONSE").expect("fixture response"));
	let config: sapling::Config = toml::from_str(&tokio::fs::read_to_string(datadir.join("config.toml")).await.unwrap()).unwrap();
	if matches!(request, Request::Config) {
		tokio::fs::write(response, serde_json::to_vec(&config.redacted()).unwrap()).await.unwrap();
		return;
	}
	let mnemonic: bip39::Mnemonic = tokio::fs::read_to_string(datadir.join("mnemonic")).await.unwrap().trim().parse().unwrap();
	let db: Arc<dyn WalletPersister> = Arc::new(SqliteClient::open(datadir.join("db.sqlite")).unwrap());
	let onchain = Arc::new(tokio::sync::RwLock::new(OnchainWallet::load_or_create(
		Network::Regtest, mnemonic.to_seed(""), db.clone(),
	).await.unwrap()));
	let wallet = sapling::Wallet::open(Network::Regtest,
		WalletSeed::new_from_mnemonic(Network::Regtest, &mnemonic), config,
		OpenWalletArgs {
			datadir: Some(datadir), persister: Some(db), onchain: Some(onchain.clone()),
			create_if_not_exists: false, skip_recovery: true,
			run_daemon: matches!(request, Request::Watch),
			..Default::default()
		},
	).await.expect("reopen persisted SDK wallet");
	let result = match request {
		Request::Watch => {
			// Only the production SDK daemon advances recovery. The parent kills
			// and restarts this OS process between Bitcoin publication checkpoints.
			std::future::pending::<()>().await;
			unreachable!()
		},
		Request::Export => serde_json::to_value(wallet.program_recovery_bundle(&[]).await.unwrap()).unwrap(),
		Request::Recover { outpoints, bundle } => {
			let fee_rate = FeeRate::from_sat_per_kwu(2000);
			let progress = if let Some(path) = bundle {
				let bundle: ProgramRecoveryBundle = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
				recover_program_bundle(&bundle, wallet.chain(), &mut *onchain.write().await, fee_rate).await.unwrap()
			} else {
				wallet.recover_program_vtxos(&outpoints, Some(fee_rate)).await.unwrap()
			};
			serde_json::to_value(progress).unwrap()
		},
		Request::Balance => {
			wallet.sync().await;
			serde_json::json!({ "spendable": wallet.balance().await.unwrap().spendable.to_sat() })
		},
		Request::Config => unreachable!("configuration diagnostics do not open a wallet"),
	};
	tokio::fs::write(response, serde_json::to_vec(&result).unwrap()).await.unwrap();
}
