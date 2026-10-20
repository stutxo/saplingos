//! Onchain wallet integration interfaces.
//!
//! This module defines the traits and types that an external onchain wallet must
//! implement to be used by the library. The goal is to let integrators plug in
//! their own wallet implementation, so features like boarding (moving onchain funds
//! into Ark) and unilateral exit (claiming VTXOs onchain without server cooperation)
//! are supported.
//!
//! Key concepts exposed here:
//! - [Utxo], [LocalUtxo] & [SpendableExit]: lightweight types representing wallet UTXOs and
//!   spendable exit outputs.
//! - [OnchainWalletTrait]: unified interface covering balance, address, PSBT construction and signing,
//!   transaction lookups, and CPFP fee-bumping for unilateral exits.
//!
//! A reference implementation based on BDK is available behind the `onchain-bdk`
//! cargo feature. Enable it to use the provided [OnchainWallet] implementation.
//! You can use all features from BDK because [bdk_wallet] is re-exported.

#[cfg(feature = "onchain-bdk")]
mod bdk;

#[cfg(feature = "onchain-bdk")]
pub use bdk_wallet;

pub use bitcoin_ext::cpfp::{CpfpError, MakeCpfpFees};

/// The largest share of rescued value a chain-backend-reported package fee may claim:
/// a reported `current_package_fee` above one tenth of [cap_backend_package_fee]'s
/// `value_at_stake` (bounded below by [MIN_CPFP_FEE_CAP]) is treated as fabricated.
///
/// `MakeCpfpFees::Rbf::current_package_fee` is the absolute fee floor a replacement CPFP
/// child must pay. When it comes from `ChainSource::mempool_ancestor_info` it is
/// unverified data from a configured but potentially adversarial chain backend: esplora
/// sums raw JSON `fee` fields of claimed unconfirmed ancestors and bitcoind relays
/// `getmempoolentry`, so either can invent a package fee of arbitrary size (the audited
/// reproduction passed 99 BTC straight through to the signer's `fee_absolute`, bounded
/// only by the wallet's entire confirmed balance).
const MAX_CPFP_FEE_DIVISOR: u64 = 10;

/// Floor for [cap_backend_package_fee]'s cap so that exits and program recoveries of
/// near-dust value remain bumpable at ordinary fee rates.
const MIN_CPFP_FEE_CAP: Amount = Amount::from_sat(10_000);

/// Bounds a chain-backend-reported total package fee before it may become an RBF fee
/// floor for a package rescuing `value_at_stake`.
///
/// Returns `Some(reported)` when the claim is plausible, and `None` — the caller must
/// skip the bump, warning, and never sign — when it exceeds one tenth of the rescued
/// value (see [MAX_CPFP_FEE_DIVISOR]), which honest mempool data cannot produce.
pub(crate) fn cap_backend_package_fee(value_at_stake: Amount, reported: Amount) -> Option<Amount> {
	let cap = Amount::from_sat(
		(value_at_stake.to_sat() / MAX_CPFP_FEE_DIVISOR).max(MIN_CPFP_FEE_CAP.to_sat()),
	);
	if reported > cap { None } else { Some(reported) }
}

/// BDK-backed onchain wallet implementation.
///
/// Available only when the `onchain-bdk` feature is enabled.
#[cfg(feature = "onchain-bdk")]
pub use crate::onchain::bdk::{OnchainWallet, TxBuilderExt};

use std::sync::Arc;

use bitcoin::{
	Address, Amount, FeeRate, OutPoint, Psbt, Script, SignedAmount, Transaction, Txid,
};

use ark::Vtxo;
use ark::vtxo::Full;
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::chain::ChainSource;


/// Summary of a wallet transaction produced by [OnchainWallet::list_transaction_infos].
#[derive(Debug, Clone)]
pub struct WalletTxInfo {
	pub txid: Txid,
	pub tx: Arc<Transaction>,
	/// Total fee paid by the transaction, when computable. `None` for inbound or
	/// collaboratively-funded txs whose foreign prevouts BDK has not indexed
	/// (e.g. after a bitcoind-rpc sync — esplora syncs populate prevouts).
	pub onchain_fees: Option<Amount>,
	/// Net change to the wallet's balance: `received - sent` over wallet-owned outputs.
	pub balance_change: SignedAmount,
	/// `Some` if the transaction is confirmed in a block, `None` if still in the mempool.
	pub confirmation: Option<BlockRef>,
	/// `true` when this tx spends a P2A fee anchor — i.e. it is a CPFP child
	/// bumping the parent that created the anchor.
	pub is_cpfp: bool,
}

/// Represents an onchain UTXO known to the wallet.
///
/// This can be either:
/// - `Local`: a standard wallet UTXO
/// - `Exit`: a spendable exit output produced by the Ark exit mechanism
#[derive(Debug, Clone)]
pub enum Utxo {
	Local(LocalUtxo),
	Exit(SpendableExit),
}

/// A standard wallet [Utxo] owned by the local wallet implementation.
#[derive(Debug, Clone)]
pub struct LocalUtxo {
	/// The outpoint referencing the UTXO.
	pub outpoint: OutPoint,
	/// The amount contained in the UTXO.
	pub amount: Amount,
	/// Optional confirmation height; `None` if unconfirmed.
	pub confirmation_height: Option<BlockHeight>,
}

/// A spendable unilateral exit of a [Vtxo] which can be claimed onchain.
///
/// When exiting unilaterally, the wallet will end up with onchain outputs that correspond to
/// previously-held VTXOs. These can be claimed and used for further spending.
#[derive(Debug, Clone)]
pub struct SpendableExit {
	/// The VTXO being exited.
	pub vtxo: Vtxo<Full>,
	/// The block height associated with the exits' validity window.
	pub height: BlockHeight,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait OnchainWalletTrait: std::any::Any + Send + Sync {
	/// Get the total balance of the wallet
	async fn balance(&self) -> Amount;

	/// Get an onchain receive address from the wallet
	async fn address(&mut self) -> anyhow::Result<Address>;

	/// Sync the wallet with the onchain network.
	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()>;

	/// Returns `true` if the given script pubkey belongs to the wallet's keychains.
	async fn is_mine(&self, spk: &Script) -> anyhow::Result<bool>;

	/// Register an unconfirmed transaction relevant to the wallet
	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()>;

	/// Mark a wallet-known transaction as evicted from the mempool.
	///
	/// Frees its inputs for coin selection immediately, without waiting for the
	/// sync eviction grace period. Callers must only invoke this on a tx that
	/// has definitively been superseded on-chain (e.g. an exit CPFP that was
	/// RBF-replaced by a competing party); evicting a still-in-flight tx
	/// causes the same self-inflicted double-spend the grace period exists to
	/// avoid.
	async fn evict_tx(&mut self, txid: Txid) -> anyhow::Result<()>;

	/// Prepare a [Transaction] which will send to the given destinations
	async fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Prepare a [Transaction] for sending all wallet funds to the given destination
	async fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Consume a [Psbt] and return a fully signed [Psbt] with all witnesses filled in
	///
	/// Useful when the signed [Psbt] is needed after signing, e.g. to compute fees
	/// via [Psbt::fee] before extracting the final [Transaction].
	///
	/// Wallets should apply all necessary signatures and finalize inputs according
	/// to their internal key management and policies.
	///
	/// Reject inputs already consumed by another wallet-known transaction,
	/// including locally signed transactions not yet broadcast. An unsigned
	/// board checkpoint can be resumed after its original coin-selection lock
	/// was lost. Re-signing the exact same transaction remains allowed.
	/// Before returning, durably record the completed spend so subsequent coin
	/// selection cannot reuse its inputs.
	async fn finish_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt>;

	/// Creates a signed Child Pays for Parent (CPFP) transaction using a Pay-to-Anchor (P2A) output
	/// to broadcast unilateral exits and other TRUC transactions.
	///
	/// For more information please see [BIP431](https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki#topologically-restricted-until-confirmation).
	///
	/// # Arguments
	///
	/// * `tx` - A parent `Transaction` that is guaranteed to have one P2A output which
	///          implementations must spend so that both the parent and child transactions can be
	///          broadcast to the network as a v3 transaction package.
	/// * `fees` - Informs the implementation how fees should be paid by the child transaction. Note
	///            that an effective fee rate should be calculated using the weight of both the
	///            parent and child transactions.
	///
	/// # Returns
	///
	/// Returns a `Result` containing:
	/// * `Transaction` - The signed CPFP transaction ready to be broadcasted to the network with
	///                   the given parent transaction if construction and signing were successful.
	/// * `CpfpError` - An error indicating the reason for failure in constructing the CPFP
	///                 transaction (e.g., insufficient funds, invalid parent transaction, or
	///                 signing failure).
	async fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError>;

	/// Persist the signed CPFP transaction so it can be rebroadcast or retrieved as needed.
	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError>;
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn cap_backend_package_fee_rejects_implausible_claims() {
		// Regression for a lying chain backend claiming a 99 BTC package fee; such a
		// floor must never reach a signed CPFP child.
		let one_btc = Amount::from_sat(100_000_000);
		assert_eq!(cap_backend_package_fee(one_btc, Amount::from_sat(99_000_000_000)), None);
		// Even just above the cap (one tenth of the rescued value) is refused.
		assert_eq!(cap_backend_package_fee(one_btc, Amount::from_sat(10_000_001)), None);
	}

	#[test]
	fn cap_backend_package_fee_passes_plausible_claims() {
		let one_btc = Amount::from_sat(100_000_000);
		// Sane package fees pass through bit-for-bit.
		let sane = Amount::from_sat(5_000);
		assert_eq!(cap_backend_package_fee(one_btc, sane), Some(sane));
		// Boundary: exactly one tenth of the rescued value stays permissible.
		assert_eq!(cap_backend_package_fee(one_btc, one_btc / 10), Some(one_btc / 10));
	}

	#[test]
	fn cap_backend_package_fee_floors_near_dust_rescues() {
		// The 10k-sat floor keeps near-dust exits/recoveries bumpable at ordinary rates.
		let dust = Amount::from_sat(5_000);
		let floor = Amount::from_sat(10_000);
		assert_eq!(cap_backend_package_fee(dust, floor), Some(floor));
		assert_eq!(cap_backend_package_fee(dust, floor + Amount::from_sat(1)), None);
	}
}
