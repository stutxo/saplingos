//! Upstream process fixtures and SDK-specific chain assertions.
pub use ark_testing::daemon::{captaind, Daemon, DaemonHelper};

#[cfg(feature = "sapio-integration")]
pub mod sapio;

use bitcoin::{BlockHash, Txid};
use bitcoin_ext::rpc::{self, RpcApi};

/// Only chain metadata is needed when checking the confirmations of exact raw
/// transactions. Core's output-script classifications can change independently.
#[derive(Debug, serde::Deserialize)]
pub struct TransactionConfirmation {
	pub confirmations: Option<u32>,
	pub blockhash: Option<BlockHash>,
}

pub trait BitcoindExt {
	fn transaction_confirmation(&self, txid: Txid) -> Result<TransactionConfirmation, rpc::Error>;
}

impl BitcoindExt for ark_testing::Bitcoind {
	fn transaction_confirmation(&self, txid: Txid) -> Result<TransactionConfirmation, rpc::Error> {
		self.sync_client().call("getrawtransaction", &[txid.to_string().into(), true.into()])
	}
}
