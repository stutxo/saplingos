use std::collections::HashSet;
use std::fmt;

use bitcoin::{OutPoint, Txid};

use bitcoin_ext::{BlockHeight, BlockRef};

use crate::exit::models::ExitState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitTx {
	pub txid: Txid,
	pub status: ExitTxStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxStatus {
	#[default]
	VerifyInputs,
	AwaitingInputConfirmation {
		txids: HashSet<Txid>
	},
	AwaitingCpfpBroadcast,
	AwaitingConfirmation {
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	Confirmed {
		child_txid: Txid,
		block: BlockRef,
		origin: ExitTxOrigin,
	},
}

impl ExitTxStatus {
	pub fn child_txid(&self) -> Option<&Txid> {
		match self {
			ExitTxStatus::AwaitingConfirmation { child_txid, .. } => Some(child_txid),
			ExitTxStatus::Confirmed { child_txid, .. } => Some(child_txid),
			_ => None,
		}
	}

	pub fn confirmed_in(&self) -> Option<&BlockRef> {
		match self {
			ExitTxStatus::Confirmed { block, .. } => Some(block),
			_ => None,
		}
	}
}

impl fmt::Display for ExitTxStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxOrigin {
	Wallet {
		confirmed_in: Option<BlockRef>
	},
	Mempool,
	Block {
		confirmed_in: BlockRef
	},
}

impl ExitTxOrigin {
	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			ExitTxOrigin::Wallet { confirmed_in } => *confirmed_in,
			ExitTxOrigin::Mempool => None,
			ExitTxOrigin::Block { confirmed_in } => Some(*confirmed_in),
		}
	}

	/// Returns a copy of this origin reflecting the given confirmation state, preserving the
	/// origin kind where it makes sense. A `Wallet` origin keeps its kind (we still know it's
	/// ours) and updates its `confirmed_in`; mempool/block origins become `Block` once confirmed
	/// and `Mempool` otherwise.
	pub fn with_confirmed_in(self, confirmed_in: Option<BlockRef>) -> ExitTxOrigin {
		match (self, confirmed_in) {
			(ExitTxOrigin::Wallet { .. }, _) => ExitTxOrigin::Wallet { confirmed_in },
			(_, Some(confirmed_in)) => ExitTxOrigin::Block { confirmed_in },
			(_, None) => ExitTxOrigin::Mempool,
		}
	}
}

impl fmt::Display for ExitTxOrigin {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitStartState {
	pub tip_height: BlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitProcessingState {
	pub tip_height: BlockHeight,
	pub transactions: Vec<ExitTx>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitAwaitingDeltaState {
	pub tip_height: BlockHeight,
	pub confirmed_block: BlockRef,
	pub claimable_height: BlockHeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimableState {
	pub tip_height: BlockHeight,
	pub claimable_since: BlockRef,
	pub last_scanned_block: Option<BlockRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimInProgressState {
	pub tip_height: BlockHeight,
	pub claimable_since: BlockRef,
	pub claim_txid: Txid,
	/// The block the claim transaction was last seen confirmed in, once it has confirmed.
	///
	/// The exit only finishes (as `Claimed`) once this block is buried under
	/// `SPEND_CONFIRMATIONS` blocks; until then a shallow reorg can still remove the claim,
	/// in which case the exit falls back to `Claimable` to detect the spend again. Recording
	/// the block also lets progression detect a reorg that re-confirmed the claim somewhere
	/// else: the confirming block changed, so the depth count restarts.
	///
	/// `None` until the claim confirms, and for states persisted by versions that finished
	/// the exit at the claim's first confirmation — serde defaults keep those rows loading.
	#[serde(default)]
	pub claim_block: Option<BlockRef>,
}

/// Terminal state: the claim transaction is buried under `SPEND_CONFIRMATIONS` blocks, deep
/// enough that a reorg is not expected to undo it; the movement was finalized at that point
/// and the exit is no longer tracked.
///
/// Exits stored as `Claimed` by versions before the depth gate existed may be shallower, but
/// are deliberately still treated as final: their movement was already finished as
/// `Successful` and their VTXO marked `Exited`, so there is no consistent state to regress
/// them to. Reorg safety has to come from the gate before entry, not from undoing `Claimed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimedState {
	pub tip_height: BlockHeight,
	pub txid: Txid,
	pub block: BlockRef,
}

/// Terminal state reached when the exit cannot proceed because the VTXO has already been
/// consumed by something other than this exit (e.g. the server forfeited it in a round).
/// No exit transactions can be broadcast at this point; the caller should cancel the
/// associated movement and remove the exit from active tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitVtxoAlreadySpentState {
	pub tip_height: BlockHeight,
}

/// Terminal state for an exit whose chain was spent on chain by someone else, in practice the
/// server sweeping a VTXO that expired mid-exit. No exit transaction can confirm any more; a
/// refresh may still be possible, depending on what took the output.
///
/// `spent_inputs` records which of the exit transaction's inputs were taken. The exit only
/// reaches this state once those spends are buried deep enough that a reorg is not expected to
/// undo them, so the spending transactions themselves aren't kept.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitVtxoSweptState {
	pub tip_height: BlockHeight,
	pub spent_inputs: Vec<OutPoint>,
}

/// Resumable state for the current exit attempt: the user explicitly canceled the exit while
/// it was still in its abortable window (before any exit transaction was broadcast).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitCanceledState {
	pub tip_height: BlockHeight,
}

impl Into<ExitState> for ExitStartState {
	fn into(self) -> ExitState {
		ExitState::Start(self)
	}
}

impl Into<ExitState> for ExitProcessingState {
	fn into(self) -> ExitState {
		ExitState::Processing(self)
	}
}

impl Into<ExitState> for ExitAwaitingDeltaState {
	fn into(self) -> ExitState {
		ExitState::AwaitingDelta(self)
	}
}

impl Into<ExitState> for ExitClaimableState {
	fn into(self) -> ExitState {
		ExitState::Claimable(self)
	}
}

impl Into<ExitState> for ExitClaimInProgressState {
	fn into(self) -> ExitState {
		ExitState::ClaimInProgress(self)
	}
}

impl Into<ExitState> for ExitClaimedState {
	fn into(self) -> ExitState {
		ExitState::Claimed(self)
	}
}

impl Into<ExitState> for ExitVtxoAlreadySpentState {
	fn into(self) -> ExitState {
		ExitState::VtxoAlreadySpent(self)
	}
}

impl Into<ExitState> for ExitVtxoSweptState {
	fn into(self) -> ExitState {
		ExitState::VtxoSwept(self)
	}
}

impl Into<ExitState> for ExitCanceledState {
	fn into(self) -> ExitState {
		ExitState::Canceled(self)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	/// States persisted by versions that finished the exit at the claim's first
	/// confirmation have no `claim_block`; they must still deserialize, as unconfirmed.
	#[test]
	fn claim_in_progress_without_claim_block_still_deserializes() {
		let old = r#"{"type":"claim-in-progress","tip_height":134,
			"claimable_since":"134:6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a",
			"claim_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		let ExitState::ClaimInProgress(state) = serde_json::from_str::<ExitState>(old).unwrap()
		else {
			panic!("old claim-in-progress blob must deserialize as ClaimInProgress");
		};
		assert_eq!(state.claim_block, None);
	}

	#[test]
	fn claim_block_roundtrips_through_serde() {
		let claimable_since = "134:6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a"
			.parse().unwrap();
		let claim_block = "136:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"
			.parse().unwrap();
		let state = ExitClaimInProgressState {
			tip_height: BlockHeight::new(136),
			claimable_since,
			claim_txid: "599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"
				.parse().unwrap(),
			claim_block: Some(claim_block),
		};
		let json = serde_json::to_string(&state).unwrap();
		assert_eq!(serde_json::from_str::<ExitClaimInProgressState>(&json).unwrap(), state);
	}
}
