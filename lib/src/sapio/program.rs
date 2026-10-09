//! Portable Sapio v1 program identities, not an evaluator.
//!
//! The JSON fields, tagged commitment and public derivation match
//! `sapio_base::ProgramInstance`. Evaluator bytes select exact semantics; this
//! descriptor neither executes them nor attests that a signer enforces them.

use std::fmt;

use bitcoin::bip32::{self, ChildNumber, Xpub};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Parity, PublicKey, XOnlyPublicKey};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::musig::nested;

pub const MAX_PROGRAM_BYTES: usize = 65_536;
pub const MAX_PARAMETER_BYTES: usize = 65_536;
pub const MAX_PROGRAM_ROOT_DEPTH: u8 = u8::MAX - 10;

/// Exact, immutable evaluator, program and preset-parameter bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Program {
	evaluator: sha256::Hash,
	program: Vec<u8>,
	parameters: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProgramError {
	#[error("program has {size} bytes; maximum is {MAX_PROGRAM_BYTES}")]
	ProgramTooLarge { size: usize },
	#[error("parameters have {size} bytes; maximum is {MAX_PARAMETER_BYTES}")]
	ParametersTooLarge { size: usize },
	#[error("program signer root has depth {depth}; maximum is {MAX_PROGRAM_ROOT_DEPTH}")]
	RootDepth { depth: u8 },
	#[error("program key derivation failed: {0}")]
	Derivation(#[from] bip32::Error),
	#[error("program ownership key aggregation failed: {0}")]
	Aggregation(#[from] nested::Error),
}

impl Program {
	pub fn new(
		evaluator: sha256::Hash, program: Vec<u8>, parameters: Vec<u8>,
	) -> Result<Self, ProgramError> {
		if program.len() > MAX_PROGRAM_BYTES {
			return Err(ProgramError::ProgramTooLarge { size: program.len() });
		}
		if parameters.len() > MAX_PARAMETER_BYTES {
			return Err(ProgramError::ParametersTooLarge { size: parameters.len() });
		}
		Ok(Self { evaluator, program, parameters })
	}

	pub fn evaluator(&self) -> sha256::Hash { self.evaluator }
	pub fn program(&self) -> &[u8] { &self.program }
	pub fn parameters(&self) -> &[u8] { &self.parameters }

	/// SHA256(tag || tag || evaluator || len_le32(program) || program ||
	/// len_le32(parameters) || parameters), with tag = SHA256 of the v1 tag.
	pub fn id(&self) -> sha256::Hash {
		let tag = sha256::Hash::hash(b"Sapio/Emulation/Program/v1");
		let mut engine = sha256::Hash::engine();
		engine.input(tag.as_byte_array());
		engine.input(tag.as_byte_array());
		engine.input(self.evaluator.as_byte_array());
		engine.input(&(self.program.len() as u32).to_le_bytes());
		engine.input(&self.program);
		engine.input(&(self.parameters.len() as u32).to_le_bytes());
		engine.input(&self.parameters);
		sha256::Hash::from_engine(engine)
	}

	/// Derive the exact ten-child key, never retrying with an alternate path.
	pub fn derive_public_key(&self, root: &Xpub) -> Result<XOnlyPublicKey, ProgramError> {
		if root.depth > MAX_PROGRAM_ROOT_DEPTH {
			return Err(ProgramError::RootDepth { depth: root.depth });
		}
		let child = root.derive_pub(&crate::SECP, &program_derivation_path(self.id()))?;
		Ok(child.public_key.x_only_public_key().0)
	}
}

impl<'de> Deserialize<'de> for Program {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		#[derive(Deserialize)]
		#[serde(deny_unknown_fields)]
		struct Fields {
			evaluator: sha256::Hash,
			#[serde(deserialize_with = "bounded_program")]
			program: Vec<u8>,
			#[serde(deserialize_with = "bounded_parameters")]
			parameters: Vec<u8>,
		}
		let fields = Fields::deserialize(deserializer)?;
		Self::new(fields.evaluator, fields.program, fields.parameters).map_err(D::Error::custom)
	}
}

fn bounded_program<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
	bounded_bytes::<D, MAX_PROGRAM_BYTES>(deserializer)
}

fn bounded_parameters<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
	bounded_bytes::<D, MAX_PARAMETER_BYTES>(deserializer)
}

fn bounded_bytes<'de, D: Deserializer<'de>, const MAX: usize>(
	deserializer: D,
) -> Result<Vec<u8>, D::Error> {
	struct Bytes<const MAX: usize>;
	impl<'de, const MAX: usize> Visitor<'de> for Bytes<MAX> {
		type Value = Vec<u8>;

		fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
			write!(formatter, "an array of at most {MAX} bytes")
		}

		fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
			let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
			while let Some(byte) = seq.next_element()? {
				if bytes.len() == MAX {
					return Err(A::Error::custom(format!("byte array exceeds {MAX} bytes")));
				}
				bytes.push(byte);
			}
			Ok(bytes)
		}
	}
	deserializer.deserialize_seq(Bytes::<MAX>)
}

/// `SAPI`, eight big-endian words' low 31 bits, then their high bits.
/// All 256 hash bits survive, and every child is non-hardened.
pub fn program_derivation_path(id: sha256::Hash) -> [ChildNumber; 10] {
	let mut path = [ChildNumber::Normal { index: 0 }; 10];
	path[0] = ChildNumber::Normal { index: 0x5341_5049 };
	let mut high_bits = 0;
	for (index, (child, chunk)) in path[1..].iter_mut().zip(id.as_byte_array().chunks_exact(4)).enumerate() {
		let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
		*child = ChildNumber::Normal { index: word & 0x7fff_ffff };
		high_bits |= (word >> 31) << index;
	}
	path[9] = ChildNumber::Normal { index: high_bits };
	path
}

/// Public ownership descriptor for C = sorted KeyAgg(U, S).
/// Neither this descriptor nor its serialization contains a private group key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramKey {
	pub program: Program,
	pub root: Xpub,
	pub user_pubkey: PublicKey,
}

impl ProgramKey {
	/// Sapio signs the x-only derived key: S is its canonical even lift.
	pub fn program_pubkey(&self) -> Result<PublicKey, ProgramError> {
		Ok(self.program.derive_public_key(&self.root)?.public_key(Parity::Even))
	}

	/// Retain the aggregate's full point parity for outer KeyAgg(C, A).
	pub fn public_key(&self) -> Result<PublicKey, ProgramError> {
		// group_key only uses members. The message/server/tweak fields are not
		// part of identity; no signing session is constructed here.
		Ok(nested::Intent {
			members: [self.user_pubkey, self.program_pubkey()?],
			server: None,
			message: [0; 32],
			tweak: None,
		}.group_key()?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::BTreeSet;
	use bitcoin::bip32::Xpriv;
	use bitcoin::Network;
	use serde_json::json;

	fn instance() -> Program {
		Program::new(
			sha256::Hash::hash(b"test evaluator v1"),
			b"payment".to_vec(), b"recipient and minimum".to_vec(),
		).unwrap()
	}

	#[test]
	fn sapio_commitment_vectors() {
		// Exact fixtures from sapio-base/tests/program.rs.
		assert_eq!(instance().evaluator().to_string(),
			"c8f9fd14473d8d0bc63e497ff1ab455a54ea2be63bd8e4f560ca871c180e9ac3");
		assert_eq!(instance().id().to_string(),
			"609d3c0765d9092356f0345863c28398291401d6f50bae2d541ec6dda5c40a12");
		let empty = Program::new(sha256::Hash::all_zeros(), vec![], vec![]).unwrap();
		assert_eq!(empty.id().to_string(),
			"67a574489f81a569a969df673af1e620ce798def9e49d5349cbac171be3b567d");
	}

	#[test]
	fn identity_commits_every_component_and_boundary() {
		let base = instance();
		let variants = [
			base.clone(),
			Program::new(sha256::Hash::hash(b"other"), base.program.clone(), base.parameters.clone()).unwrap(),
			Program::new(base.evaluator, b"Payment".to_vec(), base.parameters.clone()).unwrap(),
			Program::new(base.evaluator, base.program.clone(), b"other".to_vec()).unwrap(),
			Program::new(base.evaluator, b"ab".to_vec(), b"c".to_vec()).unwrap(),
			Program::new(base.evaluator, b"a".to_vec(), b"bc".to_vec()).unwrap(),
			Program::new(base.evaluator, vec![], b"abc".to_vec()).unwrap(),
			Program::new(base.evaluator, b"abc".to_vec(), vec![]).unwrap(),
		];
		assert_eq!(variants.iter().map(Program::id).collect::<BTreeSet<_>>().len(), variants.len());
	}

	#[test]
	fn sapio_path_vector_and_all_hash_bits() {
		// Word/high-bit fixture from sapio-base/src/covenant.rs.
		let words: [u32; 8] = [0x8000_0000, 0x7fff_ffff, 0x1234_5678,
			0xabcd_ef01, 0xffff_fff0, 0, 1, 0x8000_00ff];
		let bytes: Vec<_> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
		let path = program_derivation_path(sha256::Hash::from_slice(&bytes).unwrap());
		assert_eq!(path.map(u32::from), [0x5341_5049, 0, 0x7fff_ffff,
			0x1234_5678, 0x2bcd_ef01, 0x7fff_fff0, 0, 1, 0xff, 0x99]);
		for bit in 0..256 {
			let mut bytes = [0; 32];
			bytes[bit / 8] = 1 << (bit % 8);
			let path = program_derivation_path(sha256::Hash::from_byte_array(bytes));
			assert!(path.iter().all(ChildNumber::is_normal));
			let mut restored = [0; 32];
			for index in 0..8 {
				let word = u32::from(path[index + 1]) | (((u32::from(path[9]) >> index) & 1) << 31);
				restored[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
			}
			assert_eq!(restored, bytes);
		}
	}

	#[test]
	fn public_private_derivation_and_depth_bounds() {
		let program = instance();
		for byte in [7, 8] {
			let private = Xpriv::new_master(Network::Testnet, &[byte; 32]).unwrap();
			let mut public = Xpub::from_priv(&crate::SECP, &private);
			let child = private.derive_priv(&crate::SECP, &program_derivation_path(program.id())).unwrap();
			assert_eq!(program.derive_public_key(&public).unwrap(), child.to_keypair(&crate::SECP).x_only_public_key().0);
			public.depth = MAX_PROGRAM_ROOT_DEPTH;
			assert!(program.derive_public_key(&public).is_ok());
			public.depth += 1;
			assert!(matches!(program.derive_public_key(&public), Err(ProgramError::RootDepth { .. })));
		}
	}

	#[test]
	fn byte_bounds_and_exact_json() {
		let evaluator = sha256::Hash::all_zeros();
		let maximum = Program::new(evaluator, vec![1; MAX_PROGRAM_BYTES], vec![2; MAX_PARAMETER_BYTES]).unwrap();
		assert_eq!(serde_json::from_str::<Program>(&serde_json::to_string(&maximum).unwrap()).unwrap(), maximum);
		assert!(matches!(Program::new(evaluator, vec![0; MAX_PROGRAM_BYTES + 1], vec![]), Err(ProgramError::ProgramTooLarge { .. })));
		assert!(matches!(Program::new(evaluator, vec![], vec![0; MAX_PARAMETER_BYTES + 1]), Err(ProgramError::ParametersTooLarge { .. })));
		for field in ["program", "parameters"] {
			let mut value = serde_json::to_value(&maximum).unwrap();
			value[field] = json!(vec![0; MAX_PROGRAM_BYTES + 1]);
			assert!(serde_json::from_str::<Program>(&value.to_string()).is_err());
		}
		let program = Program::new(evaluator, vec![1, 2], vec![3]).unwrap();
		assert_eq!(serde_json::to_value(&program).unwrap(), json!({
			"evaluator": evaluator.to_string(), "program": [1, 2], "parameters": [3],
		}));
		let mut value = serde_json::to_value(program).unwrap();
		value["name"] = json!("not an identity");
		assert!(serde_json::from_value::<Program>(value).is_err());
	}

	#[test]
	fn ownership_uses_even_program_key_and_native_full_aggregate() {
		let private = Xpriv::new_master(Network::Testnet, &[7; 32]).unwrap();
		let mut descriptor = ProgramKey {
			program: instance(),
			root: Xpub::from_priv(&crate::SECP, &private),
			user_pubkey: private.to_keypair(&crate::SECP).public_key(),
		};
		let program_key = descriptor.program_pubkey().unwrap();
		assert_eq!(program_key.x_only_public_key().1, Parity::Even);
		assert_eq!(descriptor.public_key().unwrap(), crate::musig::combine_keys([descriptor.user_pubkey, program_key]));
		assert_eq!(serde_json::from_str::<ProgramKey>(&serde_json::to_string(&descriptor).unwrap()).unwrap(), descriptor);
		descriptor.user_pubkey = program_key;
		assert!(matches!(descriptor.public_key(), Err(ProgramError::Aggregation(nested::Error::DuplicateParticipant))));
	}
}
