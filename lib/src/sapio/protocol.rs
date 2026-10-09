//! Versioned client–enclave messages. There is deliberately no raw-digest request.
//!
//! Spending authorizations contain the actual PSBT. Ownership proofs use Ark's
//! existing domain-separated messages and bind their complete native request;
//! they cannot substitute for a transaction signature. The user never sends its
//! partial signature to this service: it signs last, after recovery is durable.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::taproot::{TapLeafHash, TapTweakHash};

use crate::{musig, SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest};
use crate::arkoor::ArkoorDestination;
use crate::attestations::{
	ArkoorCosignAttestation, Challenge, DelegatedRoundParticipationAttestation,
	LightningReceiveAttestation, OffboardRequestAttestation, RoundAttemptAttestation,
	VtxoStatusAttestation,
};
use crate::lightning::PaymentHash;
use crate::musig::context::{SigningContextError, SigningInput};
use crate::musig::nested::Intent;
use crate::offboard::OffboardRequest;
use crate::vtxo::Full;

use super::program::{ProgramError, ProgramKey};

pub const SIGNING_PROTOCOL: &str = "sapio-ark/nested-signing/1";
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PSBT_BYTES: usize = 512 * 1024;
pub const MAX_REQUEST_OUTPUTS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
	#[error("invalid program identity: {0}")]
	Program(#[from] ProgramError),
	#[error("invalid signing context: {0}")]
	Context(#[from] SigningContextError),
	#[error("invalid nested signing intent: {0}")]
	Intent(#[from] musig::nested::Error),
	#[error("invalid signing request encoding: {0}")]
	Encoding(String),
	#[error("request exceeds the signing protocol bounds")]
	TooLarge,
	#[error("program key does not own the requested VTXO")]
	WrongOwner,
	#[error("PSBT lacks the authenticated Taproot internal key")]
	MissingInternalKey,
	#[error("signing participants do not match the Taproot internal key")]
	WrongInternalKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SpendPath {
	KeyPath,
	ScriptPath { leaf: TapLeafHash },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendRequest {
	/// Hexadecimal PSBT, with every previous output and the actual Taproot proof.
	pub psbt: String,
	pub input_index: u32,
	pub path: SpendPath,
	/// The outer co-signer. None signs only the joint user/program key.
	pub server: Option<PublicKey>,
	/// Auxiliary program evidence; never interpreted as a privileged recovery flag.
	pub witness: Vec<u8>,
}

impl SpendRequest {
	pub fn from_input(input: &SigningInput, server: Option<PublicKey>, witness: Vec<u8>)
		-> Result<Self, ProtocolError>
	{
		let input_index = u32::try_from(input.input_index).map_err(|_| ProtocolError::TooLarge)?;
		Ok(Self {
			psbt: input.psbt.serialize().to_lower_hex_string(),
			input_index,
			path: match input.script_leaf {
				Some(leaf) => SpendPath::ScriptPath { leaf },
				None => SpendPath::KeyPath,
			},
			server,
			witness,
		})
	}

	pub fn signing_input(&self, key: &ProgramKey) -> Result<SigningInput, ProtocolError> {
		if self.psbt.len() > MAX_PSBT_BYTES * 2 || self.witness.len() > 65_536 {
			return Err(ProtocolError::TooLarge);
		}
		let bytes = Vec::<u8>::from_hex(&self.psbt)
			.map_err(|e| ProtocolError::Encoding(e.to_string()))?;
		let psbt = Psbt::deserialize(&bytes)
			.map_err(|e| ProtocolError::Encoding(e.to_string()))?;
		let index = self.input_index as usize;
		let input = psbt.inputs.get(index)
			.ok_or_else(|| ProtocolError::Encoding("input index out of range".into()))?;
		let group = key.public_key()?;
		let participants = match self.server {
			Some(server) => vec![group, server],
			None => vec![key.user_pubkey, key.program_pubkey()?],
		};
		let (script_leaf, tweak) = match self.path {
			SpendPath::KeyPath => {
				let internal = input.tap_internal_key.ok_or(ProtocolError::MissingInternalKey)?;
				let expected = musig::combine_keys(participants.iter().copied()).x_only_public_key().0;
				if internal != expected {
					return Err(ProtocolError::WrongInternalKey);
				}
				(None, Some(TapTweakHash::from_key_and_tweak(internal, input.tap_merkle_root).to_byte_array()))
			},
			SpendPath::ScriptPath { leaf } => (Some(leaf), None),
		};
		let ret = SigningInput { psbt, input_index: index, script_leaf, participants, tweak };
		ret.sighash()?;
		Ok(ret)
	}

	pub fn intent(&self, key: &ProgramKey) -> Result<Intent, ProtocolError> {
		let input = self.signing_input(key)?;
		let intent = Intent {
			members: [key.user_pubkey, key.program_pubkey()?],
			server: self.server,
			message: input.sighash()?,
			tweak: input.tweak,
		};
		intent.output_key()?;
		Ok(intent)
	}
}

/// Only native ownership protocols are permitted. None is a Bitcoin spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OwnershipProof {
	Status,
	Arkoor { outputs: Vec<ArkoorDestination> },
	Round { challenge: [u8; 32], outputs: Vec<SignedVtxoRequest> },
	DelegatedRound { outputs: Vec<VtxoRequest> },
	Offboard { request: OffboardRequest, inputs: Vec<VtxoId> },
	LightningReceive { payment_hash: PaymentHash },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRequest {
	#[serde(with = "crate::encode::serde")]
	pub input: Vtxo<Full>,
	pub proof: OwnershipProof,
}

impl OwnershipRequest {
	pub fn message(&self, key: &ProgramKey) -> Result<Message, ProtocolError> {
		self.message_for_owner(key.public_key()?)
	}

	/// Reconstruct the identical native message for a locally owned key.
	pub fn message_for_owner(&self, owner: PublicKey) -> Result<Message, ProtocolError> {
		if self.input.user_pubkey() != owner {
			return Err(ProtocolError::WrongOwner);
		}
		let id = self.input.id();
		Ok(match &self.proof {
			OwnershipProof::Status => VtxoStatusAttestation::compute_message(id),
			OwnershipProof::Arkoor { outputs } => {
				check_count(outputs.len())?;
				ArkoorCosignAttestation::compute_message(id, &outputs.iter().collect::<Vec<_>>())
			},
			OwnershipProof::Round { challenge, outputs } => {
				check_count(outputs.len())?;
				RoundAttemptAttestation::compute_message(Challenge::new(*challenge), id, outputs)
			},
			OwnershipProof::DelegatedRound { outputs } => {
				check_count(outputs.len())?;
				DelegatedRoundParticipationAttestation::compute_message(id, outputs)
			},
			OwnershipProof::Offboard { request, inputs } => {
				check_count(inputs.len())?;
				if !inputs.contains(&id) {
					return Err(ProtocolError::WrongOwner);
				}
				request.validate().map_err(|e| ProtocolError::Encoding(e.to_string()))?;
				OffboardRequestAttestation::compute_message(request, inputs)
			},
			OwnershipProof::LightningReceive { payment_hash } =>
				LightningReceiveAttestation::compute_message(*payment_hash, id),
		})
	}
}

fn check_count(count: usize) -> Result<(), ProtocolError> {
	if count == 0 || count > MAX_REQUEST_OUTPUTS { Err(ProtocolError::TooLarge) } else { Ok(()) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SigningAction {
	Spend { request: SpendRequest },
	Ownership { request: OwnershipRequest },
}

impl SigningAction {
	pub fn intent(&self, key: &ProgramKey) -> Result<Intent, ProtocolError> {
		match self {
			Self::Spend { request } => request.intent(key),
			Self::Ownership { request } => {
				let intent = Intent {
					members: [key.user_pubkey, key.program_pubkey()?],
					server: None,
					message: *request.message(key)?.as_ref(),
					tweak: None,
				};
				intent.output_key()?;
				Ok(intent)
			},
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
	pub protocol: String,
	pub key: ProgramKey,
	pub action: SigningAction,
	pub user_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareResponse {
	pub protocol: String,
	pub session: sha256::Hash,
	pub program_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishRequest {
	pub protocol: String,
	pub session: sha256::Hash,
	pub server_nonce: Option<String>,
	/// Some protocols reveal the server share first; forfeits reveal it later.
	pub server_partial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishResponse {
	pub protocol: String,
	pub program_partial: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
	pub protocol: String,
	pub session: sha256::Hash,
}

pub fn parse_nonce(encoded: &str) -> Result<musig::PublicNonce, ProtocolError> {
	let bytes = <[u8; 66]>::from_hex(encoded).map_err(|e| ProtocolError::Encoding(e.to_string()))?;
	musig::PublicNonce::from_byte_array(&bytes).map_err(|e| ProtocolError::Encoding(e.to_string()))
}

pub fn parse_partial(encoded: &str) -> Result<musig::PartialSignature, ProtocolError> {
	let bytes = <[u8; 32]>::from_hex(encoded).map_err(|e| ProtocolError::Encoding(e.to_string()))?;
	musig::PartialSignature::from_byte_array(&bytes).map_err(|e| ProtocolError::Encoding(e.to_string()))
}
