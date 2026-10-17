use bitcoin::{Amount, FeeRate, Transaction, Txid};

use ark::VtxoId;

use crate::exit::models::states::ExitTxOrigin;

/// Describes an exit transaction that needs a CPFP child to be confirmed.
///
/// Returned by [crate::exit::Exit::exits_needing_cpfp]. The caller creates a child
/// transaction spending the P2A anchor of [ExitCpfpRequest::exit_tx] and submits it
/// via [crate::exit::Exit::provide_cpfp_tx].
#[derive(Clone, Debug)]
pub struct ExitCpfpRequest {
	/// The VTXO being exited.
	pub vtxo_id: VtxoId,
	/// The exit transaction whose P2A anchor output must be spent by the CPFP child.
	pub exit_tx: Transaction,
	/// If set, a third-party CPFP is already in the mempool and the child must replace it
	/// via RBF. `None` means no CPFP exists yet and any valid fee is acceptable.
	pub rbf_requirement: Option<RbfRequirement>,
}

/// Constraints a CPFP replacement transaction must satisfy to evict an existing one via RBF.
///
/// When the values originate from chain-backend mempool data (rather than from a child the
/// wallet built and signed itself) they are unverified; producers clamp the rate to the
/// fee-rate ingestion ceiling and cap `current_package_fee` against the rescued VTXO
/// value before exposing them, dropping implausible reports entirely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RbfRequirement {
	/// The effective fee rate of the existing package. A replacement must exceed this.
	pub min_fee_rate: FeeRate,
	/// The total fee paid by the existing package. A replacement must pay strictly more.
	/// For backend-derived reports this is capped to at most one tenth of the rescued
	/// value (with a 10,000 sat floor for near-dust exits).
	pub current_package_fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitTransactionPackage {
	/// The actual unilateral exit transaction containing an anchor output and a spendable amount
	pub exit: TransactionInfo,
	/// The child transaction used to spend, and thus confirm, the exit anchor output
	pub child: Option<ChildTransactionInfo>,
}

/// An information struct used to pair the ID of a transaction with the full transaction for ease
/// of use and readability for the user
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionInfo {
	pub txid: Txid,
	pub tx: Transaction,
}

/// Represents a child transaction for an exit transaction package with information about the origin
/// of the transaction
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildTransactionInfo {
	pub info: TransactionInfo,
	pub fee_info: Option<FeeInfo>,
	pub origin: ExitTxOrigin,
}

/// Contains the data required to bump the fee for a given transaction (including ancestors).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct FeeInfo {
	/// The effective fee rate of the transaction (including unconfirmed CPFP ancestors).
	#[serde(rename = "fee_rate_kwu")]
	pub fee_rate: FeeRate,
	/// Sum of the transaction's own fee plus the fee of each of its unconfirmed ancestors.
	/// To replace this transaction via RBF, a replacement must add `mintxrelayfee` (typically
	/// 0.1 sat/vB) multiplied by the replacement weight on top of this amount.
	#[serde(rename = "total_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	pub total_fee: Amount,
	/// Provenance: `true` when the fee was derived locally from a child the wallet (or its
	/// operator, via the CPFP API) built and signed itself — we know what we signed. `false`
	/// when read from the configured chain backend's mempool data: both the fee and the
	/// weights behind `fee_rate` are then unverified, server-supplied fields, and consumers
	/// must sanitize them (rate ceiling, package-fee cap against the rescued value) before
	/// they may steer RBF decisions or signing.
	#[serde(default)]
	pub trusted: bool,
}

impl FeeInfo {
	/// Marks the fee info as locally derived; called on any fee info provided at child
	/// registration time ([crate::exit::Exit::provide_cpfp_tx_with_fee_info]), where the
	/// registrant asserts it knows what it signed.
	///
	/// Registration-time values are bounded too (`None` on absurd input): a buggy caller
	/// could otherwise hand us a `total_fee` above [Amount::MAX_MONEY] — which overflows
	/// the pinned CPFP builder's panicking relay-floor addition — or a `fee_rate` above
	/// the ingestion ceiling, whose weight multiplication cannot be represented.
	pub(crate) fn try_into_trusted(self) -> Option<FeeInfo> {
		if self.total_fee > Amount::MAX_MONEY
			|| self.fee_rate > crate::chain::MAX_PLAUSIBLE_FEE_RATE
		{
			return None;
		}
		Some(FeeInfo { trusted: true, ..self })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn plausible() -> FeeInfo {
		FeeInfo {
			fee_rate: FeeRate::from_sat_per_kwu(2_500),
			total_fee: Amount::from_sat(3_000),
			trusted: false,
		}
	}

	#[test]
	fn try_into_trusted_rejects_absurd_registration_time_info() {
		// Registration-time fee info feeds the pinned CPFP builder verbatim once trusted:
		// a total_fee above representable money would overflow its panicking relay-floor
		// addition, and an above-ceiling rate overflows its weight multiplication. Neither
		// describes a real signed child, so both are refused at the chokepoint.
		let absurd_fee = FeeInfo { total_fee: Amount::from_sat(u64::MAX), ..plausible() };
		assert_eq!(absurd_fee.try_into_trusted(), None);
		let absurd_rate = FeeInfo { fee_rate: FeeRate::from_sat_per_kwu(1 << 54), ..plausible() };
		assert_eq!(absurd_rate.try_into_trusted(), None);
	}

	#[test]
	fn try_into_trusted_tags_plausible_info() {
		let fi = plausible();
		assert_eq!(fi.try_into_trusted(), Some(FeeInfo { trusted: true, ..fi }));
		// Boundary values remain usable.
		let max_fee = FeeInfo { total_fee: Amount::MAX_MONEY, ..fi };
		assert!(max_fee.try_into_trusted().is_some());
		let max_rate = FeeInfo { fee_rate: crate::chain::MAX_PLAUSIBLE_FEE_RATE, ..fi };
		assert!(max_rate.try_into_trusted().is_some());
	}
}
