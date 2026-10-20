
use bitcoin::{Amount, FeeRate, OutPoint, Weight};

use crate::exit::models::{ExitTx, ExitTxStatus};
use crate::WalletVtxo;

/// Renders outpoints as a comma-separated `txid:vout` list, for log lines.
pub(crate) fn format_outpoints(outpoints: &[OutPoint]) -> String {
	outpoints.iter().map(|o| o.to_string()).collect::<Vec<_>>().join(", ")
}

/// Counts how many of the given ExitTx objects exist in either the mempool or the blockchain
pub(crate) fn count_broadcast(status: &[ExitTx]) -> usize {
	status.iter().filter(|s| match s.status {
		ExitTxStatus::AwaitingConfirmation { .. } => true,
		ExitTxStatus::Confirmed { .. } => true,
		_ => false,
	}).count()
}


/// Counts how many of the given ExitTx objects are confirmed in the blockchain
pub(crate) fn count_confirmed(status: &[ExitTx]) -> usize {
	status.iter().filter(|s| match s.status {
		ExitTxStatus::Confirmed { .. } => true,
		_ => false,
	}).count()
}

/// Do a rudimentary check of the total exit cost for a set of vtxos.
/// We estimate the CPFP part by multiplying the exit tx weight by 2.
pub(crate) fn estimate_exit_cost<'a, I>(vtxos: I, fee_rate: FeeRate) -> Amount
where
	I: IntoIterator<Item = &'a WalletVtxo>
{
	// we multiply by two as a rough upper bound of all the CPFP tx
	let total_weight = vtxos.into_iter().map(|vtxo| vtxo.exit_tx_weight).sum::<Weight>();
	rough_cpfp_cost(total_weight, fee_rate)
}

/// Rough CPFP cost of a package of `total_weight` at `fee_rate`, saturating instead of
/// ever panicking or wrapping. Used only to filter out VTXOs too small to be worth
/// exiting, so an over-estimate merely excludes the VTXO (the conservative direction).
fn rough_cpfp_cost(total_weight: Weight, fee_rate: FeeRate) -> Amount {
	// Backend-supplied rates are clamped at ingestion; clamp again here so no caller can
	// ever make the multiplication overflow (a wrapped fee would *include* worthless VTXOs).
	let fee_rate = fee_rate.min(crate::chain::MAX_PLAUSIBLE_FEE_RATE);
	fee_rate.checked_mul_by_weight(total_weight)
		.and_then(|fee| fee.checked_mul(2))
		.unwrap_or(Amount::MAX_MONEY)
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn rough_cpfp_cost_matches_plain_math_for_sane_values() {
		let rate = FeeRate::from_sat_per_vb_unchecked(10);
		let weight = Weight::from_wu(2_048);
		assert_eq!(rough_cpfp_cost(weight, rate), rate * weight * 2);
	}

	#[test]
	fn rough_cpfp_cost_never_panics_on_backend_admissible_rates() {
		// The 2^54 sat/kwu rate an esplora backend can feed us used to panic
		// (overflow-checks) or silently wrap here; it must now clamp to the ceiling.
		let absurd = FeeRate::from_sat_per_kwu(1 << 54);
		let expected = crate::chain::MAX_PLAUSIBLE_FEE_RATE
			.checked_mul_by_weight(Weight::from_wu(2_048)).unwrap()
			.checked_mul(2).unwrap();
		assert_eq!(rough_cpfp_cost(Weight::from_wu(2_048), absurd), expected);
	}

	#[test]
	fn rough_cpfp_cost_saturates_instead_of_wrapping() {
		// An absurd weight combined with the (already ceiling-clamped) rate must
		// saturate to MAX_MONEY — the direction that excludes the VTXO — never wrap.
		assert_eq!(
			rough_cpfp_cost(Weight::MAX, crate::chain::MAX_PLAUSIBLE_FEE_RATE),
			Amount::MAX_MONEY,
		);
	}
}
