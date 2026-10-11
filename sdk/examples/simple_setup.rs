use std::path::PathBuf;

use anyhow::Context;
use bitcoin::Network;
use sapling::{Config, OpenWalletArgs, Wallet, WalletSeed};

// Run against a configured signet server. The application owns seed storage;
// this example reads a seed phrase from the environment and never prints it.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
	let datadir = PathBuf::from(std::env::var_os("SAPLING_DATADIR")
		.context("set SAPLING_DATADIR to the wallet directory")?);
	let mnemonic = std::env::var("SAPLING_MNEMONIC")
		.context("set SAPLING_MNEMONIC to the wallet's seed phrase")?.parse()?;
	let network = Network::Signet;
	let config = Config::load(network, datadir.join("config.toml"))?;
	let wallet = Wallet::open(
		network,
		WalletSeed::new_from_mnemonic(network, &mnemonic),
		config,
		OpenWalletArgs { datadir: Some(datadir), ..Default::default() },
	).await?;

	println!("Receive address: {}", wallet.new_address().await?);
	println!("Spendable balance: {}", wallet.balance().await?.spendable);
	wallet.stop_daemon_wait().await?;
	Ok(())
}
