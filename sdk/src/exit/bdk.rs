
use anyhow::Context;
use bitcoin::{FeeRate, Transaction};
use bitcoin_ext::FeeRateExt;
use log::warn;

use crate::Wallet;
use crate::exit::{Exit, ExitProgressStatus, FeeInfo};
use crate::onchain::{CpfpError, MakeCpfpFees};

/// Exit transactions should only be RBF'ed if the new requested fee rate
/// is strictly greater than the current package rate.
pub (crate) fn should_rbf(new_fee_rate: FeeRate, old_fee_rate: FeeRate) -> bool {
	new_fee_rate > old_fee_rate
}

/// Derives the committed [FeeInfo] of a CPFP child this wallet has just built for
/// `exit_tx`, without consulting the chain backend.
///
/// The child pays exactly `fees.package_fee(parent weight, child weight)`:
/// `make_signed_p2a_cpfp` signs with `fee_absolute` equal to that value for the child's
/// final weight, and the exit parent is zero-fee by construction. Recording the fee we
/// signed — instead of letting the backend tell us later — means fabricated mempool
/// `fee`/`weight` fields can never raise the committed fee of our own package.
pub(crate) fn wallet_child_fee_info(
	exit_tx: &Transaction,
	child_tx: &Transaction,
	fees: MakeCpfpFees,
) -> FeeInfo {
	let parent_weight = exit_tx.weight();
	let package_weight = parent_weight + child_tx.weight();
	let total_fee = fees.package_fee(parent_weight, child_tx.weight());
	let fee_rate = FeeRate::from_amount_and_weight_ceil(total_fee, package_weight)
		// `total_fee` comes straight from this very division, so it always yields a rate.
		.unwrap_or_else(|| fees.effective());
	FeeInfo { fee_rate, total_fee }
}

impl Exit {
	/// Advance ongoing exits by one step, handling CPFP fee-bumping via the wallet's
	/// internal onchain wallet.
	///
	/// This makes progress on each exit but does not run an exit to completion — exits
	/// span many blocks (broadcasting, confirmations, CSV timelocks, claim spends), so
	/// this must be called repeatedly (e.g. once per block) until all exits reach a
	/// terminal state.
	///
	/// It calls [Exit::progress_exits], creates CPFP transactions for any exits in
	/// [crate::exit::ExitTxStatus::AwaitingCpfpBroadcast], then calls [Exit::progress_exits] again
	/// so those exits advance to [crate::exit::ExitTxStatus::AwaitingConfirmation].
	///
	/// Callers with external or hardware wallets should use [Exit::exits_needing_cpfp]
	/// and [Exit::provide_cpfp_tx] directly instead.
	///
	/// Returns an error if the wallet has no onchain wallet configured.
	pub async fn progress_exits_with_cpfp(
		&self,
		wallet: &Wallet,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		let onchain_arc = wallet.inner.onchain.as_ref()
			.context("no onchain wallet configured; cannot progress exits")?;

		self.progress_exits(wallet).await?;

		let fee_rate = match fee_rate_override {
			Some(fr) => fr,
			None => wallet.exit_mgr().default_exit_fee_rate().await,
		};

		for req in self.exits_needing_cpfp().await {
			let fees = match req.rbf_requirement {
				None => MakeCpfpFees::Effective(fee_rate),
				Some(rbf) => {
					// Only RBF if we can improve the fee rate; equal or lower rates are rejected
					// by Bitcoin Core's RBF policy ("new feerate must be strictly greater").
					if !should_rbf(fee_rate, rbf.min_fee_rate) {
						warn!(
							"Skipping exit CPFP RBF: requested fee rate {} is not above current package rate {}",
							fee_rate, rbf.min_fee_rate,
						);
						continue;
					}
					MakeCpfpFees::Rbf {
						min_effective_fee_rate: fee_rate,
						current_package_fee: rbf.current_package_fee,
					}
				},
			};
			let child_tx = {
				let mut onchain = onchain_arc.write().await;
				let tx = match onchain.make_signed_p2a_cpfp(&req.exit_tx, fees).await {
					Ok(tx) => tx,
					Err(CpfpError::InsufficientConfirmedFunds { needed, available }) => {
						warn!("Insufficient funds for exit CPFP: needed {} available {}", needed, available);
						continue;
					},
					Err(e) => return Err(e.into()),
				};
				onchain.store_signed_p2a_cpfp(&tx).await?;
				tx
			};
			// We built this child ourselves: derive its committed fee locally so a lying
			// chain backend can never re-report our own package at a fabricated fee.
			let fee_info = wallet_child_fee_info(&req.exit_tx, &child_tx, fees);
			let exit_txid = req.exit_tx.compute_txid();
			self.provide_cpfp_tx_with_fee_info(wallet, exit_txid, child_tx, Some(fee_info)).await?;
		}

		self.progress_exits(wallet).await
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::{Amount, ScriptBuf, TxIn, TxOut, absolute::LockTime, transaction::Version};

	fn dummy_exit_tx() -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn::default()],
			output: vec![
				TxOut { value: Amount::from_sat(330), script_pubkey: ScriptBuf::new() },
				TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::new() },
			],
		}
	}

	fn dummy_child_tx() -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn::default(), TxIn::default()],
			output: vec![TxOut { value: Amount::from_sat(45_000), script_pubkey: ScriptBuf::new() }],
		}
	}

	#[test]
	fn wallet_child_fee_info_is_derived_not_backend_supplied() {
		// The committed fee of a wallet-built child must equal exactly what the pinned
		// builder signs as `fee_absolute` — never whatever the chain backend claims later.
		let rate = FeeRate::from_sat_per_kwu(2_500); // 10 sat/vB
		let parent = dummy_exit_tx();
		let child = dummy_child_tx();
		let fees = MakeCpfpFees::Effective(rate);
		let fi = wallet_child_fee_info(&parent, &child, fees);
		assert_eq!(fi.total_fee, fees.package_fee(parent.weight(), child.weight()));
		// The derived effective rate covers the requested one (up to unit rounding).
		assert!(fi.fee_rate >= rate);
		// And the committed package fee stays in ordinary-fee territory.
		assert!(fi.total_fee < Amount::from_sat(10_000));
	}

	#[test]
	fn wallet_child_fee_info_honors_rbf_floor() {
		let rate = FeeRate::from_sat_per_kwu(2_500);
		let parent = dummy_exit_tx();
		let child = dummy_child_tx();
		// A plausible, already-capped prior package fee.
		let prior = Amount::from_sat(2_000);
		let fees = MakeCpfpFees::Rbf { min_effective_fee_rate: rate, current_package_fee: prior };
		let fi = wallet_child_fee_info(&parent, &child, fees);
		assert_eq!(fi.total_fee, fees.package_fee(parent.weight(), child.weight()));
		// A replacement always commits strictly more than the replaced package (BIP125).
		assert!(fi.total_fee > prior);
	}
}
