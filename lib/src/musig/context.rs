//! Owned, authenticated transaction contexts for external MuSig signers.

use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{schnorr, Message, PublicKey, Scalar, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{TapLeafHash, TapNodeHash, TaprootSpendInfo};
use bitcoin::{Transaction, TxOut};
use bitcoin_ext::TaprootSpendInfoExt;

use crate::{musig, SECP};
use self::SigningContextError::InvalidContext;

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SigningContextError {
	#[error("invalid signing context: {0}")]
	InvalidContext(&'static str),
	#[error("invalid completed signature")]
	InvalidSignature,
}

/// An owned signing request. Nonces and signatures use the caller's context order;
/// participants retain their full point parity and are aggregated in native sorted order.
/// Prevouts must come from authenticated funding transactions or validated VTXOs.
#[derive(Debug, Clone)]
pub struct SigningInput {
	pub psbt: Psbt,
	pub input_index: usize,
	pub script_leaf: Option<TapLeafHash>,
	pub participants: Vec<PublicKey>,
	pub tweak: Option<[u8; 32]>,
}

impl SigningInput {
	/// Construct a DEFAULT key-spend context with all prevouts and the actual tree.
	pub fn key_spend(
		tx: Transaction,
		input_index: usize,
		prevouts: Vec<TxOut>,
		taproot: &TaprootSpendInfo,
		participants: Vec<PublicKey>,
	) -> Result<Self, SigningContextError> {
		let mut psbt = Psbt::from_unsigned_tx(tx)
			.map_err(|_| SigningContextError::InvalidContext("transaction is not unsigned"))?;
		if psbt.inputs.len() != prevouts.len() {
			return Err(SigningContextError::InvalidContext("prevout count mismatch"));
		}
		for (input, prevout) in psbt.inputs.iter_mut().zip(prevouts) {
			input.witness_utxo = Some(prevout);
		}
		let input = psbt.inputs.get_mut(input_index)
			.ok_or(SigningContextError::InvalidContext("input index out of bounds"))?;
		input.tap_internal_key = Some(taproot.internal_key());
		input.tap_merkle_root = taproot.merkle_root();
		input.tap_scripts = taproot.psbt_tap_scripts();
		let ret = Self {
			psbt, input_index, script_leaf: None, participants,
			tweak: Some(taproot.tap_tweak().to_byte_array()),
		};
		ret.sighash()?;
		Ok(ret)
	}

	fn authenticated(&self) -> Result<(Vec<&TxOut>, XOnlyPublicKey), SigningContextError> {
		let tx = &self.psbt.unsigned_tx;
		if tx.input.len() != self.psbt.inputs.len() || tx.output.len() != self.psbt.outputs.len() {
			return Err(InvalidContext("PSBT transaction map count mismatch"));
		}
		if tx.input.iter().any(|i| !i.script_sig.is_empty() || !i.witness.is_empty()) {
			return Err(InvalidContext("transaction is not unsigned"));
		}
		let input = self.psbt.inputs.get(self.input_index)
			.ok_or(InvalidContext("input index out of bounds"))?;
		if input.sighash_type.map(|s| s != TapSighashType::Default.into()).unwrap_or(false) {
			return Err(InvalidContext("only DEFAULT sighash is supported"));
		}
		if self.participants.is_empty() {
			return Err(InvalidContext("no signing participants"));
		}
		let mut prevouts = Vec::with_capacity(tx.input.len());
		for (txin, map) in tx.input.iter().zip(&self.psbt.inputs) {
			let prevout = map.witness_utxo.as_ref().ok_or(InvalidContext("missing prevout"))?;
			if let Some(parent) = &map.non_witness_utxo {
				if parent.compute_txid() != txin.previous_output.txid
					|| parent.output.get(txin.previous_output.vout as usize) != Some(prevout)
				{
					return Err(InvalidContext("funding transaction does not match prevout"));
				}
			}
			prevouts.push(prevout);
		}
		let prevout = &prevouts[self.input_index];
		let internal = input.tap_internal_key.ok_or(InvalidContext("missing taproot internal key"))?;
		let tree = TaprootSpendInfo::new_key_spend(&SECP, internal, input.tap_merkle_root);
		if tree.script_pubkey() != prevout.script_pubkey {
			return Err(InvalidContext("taproot tree does not match prevout"));
		}
		let aggregate = musig::combine_keys(self.participants.iter().copied());
		let (aggregate_xonly, _) = aggregate.x_only_public_key();
		if let Some(leaf) = self.script_leaf {
			let signing_key = if let Some(tweak) = self.tweak {
				let scalar = Scalar::from_be_bytes(tweak).map_err(|_| InvalidContext("invalid tweak"))?;
				aggregate_xonly.add_tweak(&SECP, &scalar)
					.map_err(|_| InvalidContext("invalid tweaked signing key"))?.0
			} else {
				aggregate_xonly
			};
			// A script-path context must prove both the leaf and its signing key.
			// Bark's aggregate-key leaves use a direct push followed by CHECKSIG.
			let key_bytes = signing_key.serialize();
			let valid = input.tap_scripts.iter().any(|(control, (script, version))| {
				let mut previous_is_key = false;
				let mut ends_in_checksig = false;
				for instruction in script.instructions() {
					match instruction {
						Ok(bitcoin::script::Instruction::Op(bitcoin::opcodes::all::OP_CODESEPARATOR)) | Err(_) => return false,
						Ok(bitcoin::script::Instruction::Op(op)) => {
							ends_in_checksig = previous_is_key && op == bitcoin::opcodes::all::OP_CHECKSIG;
							previous_is_key = false;
						},
						Ok(bitcoin::script::Instruction::PushBytes(bytes)) => {
							previous_is_key = bytes.as_bytes() == key_bytes;
							ends_in_checksig = false;
						},
					}
				}
				let mut root = TapNodeHash::from_script(script, *version);
				for branch in &control.merkle_branch {
					root = TapNodeHash::from_node_hashes(root, *branch);
				}
				*version == bitcoin::taproot::LeafVersion::TapScript
					&& control.internal_key == internal && control.leaf_version == *version
					&& input.tap_merkle_root == Some(root)
					&& TapLeafHash::from_script(script, *version) == leaf
					&& control.verify_taproot_commitment(&SECP, tree.output_key().to_x_only_public_key(), script)
					&& ends_in_checksig
			});
			if !valid {
				return Err(InvalidContext("missing authenticated signing leaf"));
			}
			Ok((prevouts, signing_key))
		} else {
			if aggregate_xonly != internal || self.tweak != Some(tree.tap_tweak().to_byte_array()) {
				return Err(InvalidContext("aggregate key or tweak does not match taproot tree"));
			}
			Ok((prevouts, tree.output_key().to_x_only_public_key()))
		}
	}

	/// Authenticate the context and compute the exact DEFAULT sighash with full prevouts.
	pub fn sighash(&self) -> Result<[u8; 32], SigningContextError> {
		let (prevouts, _) = self.authenticated()?;
		self.sighash_with_prevouts(&prevouts)
	}

	fn sighash_with_prevouts(&self, prevouts: &[&TxOut]) -> Result<[u8; 32], SigningContextError> {
		let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
		let prevouts = Prevouts::All(prevouts);
		let hash = if let Some(leaf) = self.script_leaf {
			cache.taproot_script_spend_signature_hash(self.input_index, &prevouts, leaf, TapSighashType::Default)
		} else {
			cache.taproot_key_spend_signature_hash(self.input_index, &prevouts, TapSighashType::Default)
		}.map_err(|_| SigningContextError::InvalidContext("cannot compute sighash"))?;
		Ok(hash.to_byte_array())
	}

	/// Verify a completed signature against this exact message and authenticated signing key.
	pub fn verify_signature(&self, signature: &schnorr::Signature) -> Result<(), SigningContextError> {
		let (prevouts, key) = self.authenticated()?;
		SECP.verify_schnorr(signature, &Message::from_digest(self.sighash_with_prevouts(&prevouts)?), &key)
			.map_err(|_| SigningContextError::InvalidSignature)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::secp256k1::{Keypair, SecretKey};
	use bitcoin::taproot::{LeafVersion, TaprootBuilder};
	use bitcoin::{absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, Witness};

	#[test]
	fn authenticated_script_context_rejects_missing_proofs_and_wrong_signatures() {
		let user = Keypair::from_secret_key(&SECP, &SecretKey::from_slice(&[1; 32]).unwrap());
		let server = Keypair::from_secret_key(&SECP, &SecretKey::from_slice(&[2; 32]).unwrap());
		let participants = vec![user.public_key(), server.public_key()];
		let aggregate = musig::combine_keys(participants.iter().copied()).x_only_public_key().0;
		let script = ScriptBuf::builder().push_x_only_key(&aggregate)
			.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG).into_script();
		let tree = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap()
			.finalize(&SECP, aggregate).unwrap();
		let parent = Transaction {
			version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
			input: vec![],
			output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: tree.script_pubkey() }],
		};
		let tx = Transaction {
			version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(parent.compute_txid(), 0),
				script_sig: ScriptBuf::new(), sequence: Sequence::ZERO, witness: Witness::new(),
			}],
			output: vec![TxOut { value: Amount::from_sat(900), script_pubkey: tree.script_pubkey() }],
		};
		assert!(SigningInput::key_spend(
			tx.clone(), 0, vec![], &tree, participants.clone(),
		).is_err());
		let mut context = SigningInput::key_spend(
			tx, 0, parent.output.clone(), &tree, participants,
		).unwrap();
		context.psbt.inputs[0].non_witness_utxo = Some(parent);
		context.script_leaf = Some(TapLeafHash::from_script(&script, LeafVersion::TapScript));
		context.tweak = None;
		let signature = musig::cosign_both(&user, &server, context.sighash().unwrap(), None);
		context.verify_signature(&signature).unwrap();
		let mut missing = context.clone();
		missing.psbt.inputs[0].tap_scripts.clear();
		assert!(missing.sighash().is_err());
		let mut wrong = context.clone();
		wrong.psbt.inputs[0].tap_internal_key = Some(user.x_only_public_key().0);
		assert!(wrong.sighash().is_err());
		let mut wrong = context.clone();
		wrong.psbt.unsigned_tx.output[0].value += Amount::ONE_SAT;
		assert_eq!(wrong.verify_signature(&signature), Err(SigningContextError::InvalidSignature));
		let mut wrong = context;
		wrong.psbt.inputs[0].non_witness_utxo.as_mut().unwrap().output[0].value += Amount::ONE_SAT;
		assert!(wrong.sighash().is_err());
	}
}
