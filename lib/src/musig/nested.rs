//! Two-member signing for `KeyAgg(KeyAgg(U, S), A)`, or just `KeyAgg(U, S)`.
//!
//! # Safety boundaries
//!
//! Keys are sorted by their full compressed encoding at each aggregation level. The
//! inner key is never x-only normalized before it enters the outer aggregation. An
//! optional x-only tweak belongs to the root only; native MuSig aggregation adds its
//! correction exactly once. Duplicate member keys, or a server equal to the inner
//! aggregate, are rejected: the independent user/program veto must not collapse.
//!
//! Secret arithmetic uses k256, not public-data secp scalar helpers. Nonces come from
//! a CSPRNG, cannot be cloned or serialized, and signing consumes them even on error.
//! Owned nonce scalars, key conversion buffers and named secret intermediates are
//! zeroized on drop. This does not promise erasure of compiler-created copies or
//! protect against process snapshots, rollback, forks or a compromised RNG. Never
//! restore a process containing a live nonce or reuse a seeded RNG in production.
//!
//! Public nonce context labels are checked, not authenticated. The transport must
//! authenticate participants and their approved intent. This module is a cryptographic
//! primitive, not a program evaluator or a raw-digest authorization service: its caller
//! must enforce the program, transaction and recovery policy before releasing a share.
//! Do not treat this custom nested protocol as production-reviewed cryptography.

use std::ops::{Add, Mul, Neg};

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{schnorr, Keypair, Parity, PublicKey};
use k256::elliptic_curve::bigint::{U256, U512};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::{Reduce, ReduceNonZero};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::zeroize::Zeroizing;
use k256::{EncodedPoint, ProjectivePoint, Scalar, WideBytes};
use rand::{CryptoRng, RngCore};

use super::secpm::musig::KeyAggCache;
use super::{secpm, AggregatedNonce, PartialSignature, PublicNonce};

/// Failures are terminal for a nonce passed to [`Nonce::sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	#[error("malformed or infinite public point")]
	InvalidPoint,
	#[error("participant does not match the signing intent")]
	ParticipantMismatch,
	#[error("signing principals must have distinct public keys")]
	DuplicateParticipant,
	#[error("nonce belongs to a different signing intent")]
	ContextMismatch,
	#[error("nonce does not match its participant or was repeated")]
	NonceMismatch,
	#[error("server nonce or share presence does not match the signing intent")]
	ServerMismatch,
	#[error("invalid x-only root tweak")]
	InvalidTweak,
	#[error("key or nonce aggregation cancels to infinity")]
	Cancellation,
	#[error("expected exactly two member shares")]
	ShareCount,
	#[error("invalid partial signature")]
	InvalidPartialSignature,
	#[error("invalid final signature")]
	InvalidSignature,
	#[error("native and RustCrypto public-key aggregation disagree")]
	BackendMismatch,
}

/// The exact approved signing context. Member order identifies share/nonce slots;
/// it does not change sorted key aggregation. `None` server is ordinary joint signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
	pub members: [PublicKey; 2],
	pub server: Option<PublicKey>,
	pub message: [u8; 32],
	pub tweak: Option<[u8; 32]>,
}

impl Intent {
	/// The full, parity-preserving inner aggregate key.
	pub fn group_key(&self) -> Result<PublicKey, Error> {
		Ok(super::pubkey_from(checked_key_agg(self.members)?.0.agg_pk_full()))
	}

	/// The full root key after the optional x-only tweak. Signatures verify against
	/// its x-only form. Rejects invalid tweaks and cancelling key aggregates.
	pub fn output_key(&self) -> Result<PublicKey, Error> {
		Ok(KeyContext::new(self)?.output)
	}
}

/// A public nonce with its participant and exact intent label. Labels must be
/// authenticated by the caller; re-labelling received bytes is not authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberNonce {
	intent: Intent,
	member: PublicKey,
	nonce: PublicNonce,
}

impl MemberNonce {
	/// Import a peer's two compressed nonce points and authenticated context label.
	pub fn from_bytes(intent: Intent, member: PublicKey, bytes: [u8; 66]) -> Result<Self, Error> {
		intent.output_key()?;
		if !intent.members.contains(&member) {
			return Err(Error::ParticipantMismatch);
		}
		let nonce = PublicNonce::from_byte_array(&bytes).map_err(|_| Error::InvalidPoint)?;
		Ok(Self { intent, member, nonce })
	}

	pub fn serialize(&self) -> [u8; 66] { self.nonce.serialize() }

	/// The ordinary MuSig wire nonce, without its authenticated application context.
	pub fn native(&self) -> PublicNonce { self.nonce }

	pub fn member(&self) -> PublicKey { self.member }

	pub fn intent(&self) -> &Intent { &self.intent }
}

/// One-use, in-memory secret nonces. Intentionally no `Clone`, `Debug`, or encoding.
#[must_use]
pub struct Nonce {
	secret: Zeroizing<[Scalar; 2]>,
	public: MemberNonce,
}

impl Nonce {
	/// Generate fresh nonces using the operating-system-seeded thread CSPRNG.
	pub fn new(intent: Intent, member: PublicKey) -> Result<Self, Error> {
		Self::generate(intent, member, &mut rand::rng())
	}

	/// Generate using a caller-owned CSPRNG. The RNG must remain unpredictable and
	/// must never be reset, cloned, or rolled back between calls. Seeded RNGs are for
	/// public fixtures only. Each scalar reduces 512 random bits modulo `n - 1`,
	/// then adds one: nonzero, constant-time, with negligible distribution bias.
	pub fn generate<R: CryptoRng + RngCore>(
		intent: Intent, member: PublicKey, rng: &mut R,
	) -> Result<Self, Error> {
		intent.output_key()?;
		if !intent.members.contains(&member) {
			return Err(Error::ParticipantMismatch);
		}
		let mut secret = Zeroizing::new([Scalar::ZERO; 2]);
		let mut entropy = Zeroizing::new(WideBytes::default());
		let mut bytes = [0u8; 66];
		for (scalar, encoded) in secret.iter_mut().zip(bytes.chunks_exact_mut(33)) {
			rng.fill_bytes(&mut entropy[..]);
			*scalar = <Scalar as ReduceNonZero<U512>>::reduce_nonzero_bytes(&entropy);
			let point = ProjectivePoint::GENERATOR.mul(&*scalar);
			encoded.copy_from_slice(point.to_encoded_point(true).as_bytes());
		}
		let nonce = PublicNonce::from_byte_array(&bytes).map_err(|_| Error::InvalidPoint)?;
		Ok(Self { secret, public: MemberNonce { intent, member, nonce } })
	}

	pub fn public(&self) -> MemberNonce { self.public }

	/// Consume this nonce on success AND failure. The session must contain exactly
	/// this member's nonce and intent. Private key bytes never leave this API.
	pub fn sign(self, keypair: &Keypair, session: &Session) -> Result<PartialSignature, Error> {
		if self.public.intent != session.intent {
			return Err(Error::ContextMismatch);
		}
		if keypair.public_key() != self.public.member {
			return Err(Error::ParticipantMismatch);
		}
		let index = session.members.iter().position(|nonce| *nonce == self.public)
			.ok_or(Error::NonceMismatch)?;
		let key_bytes = Zeroizing::new(keypair.secret_bytes());
		let key = Zeroizing::new(
			Option::<Scalar>::from(Scalar::from_repr((*key_bytes).into()))
				.ok_or(Error::ParticipantMismatch)?,
		);
		let mut nonce_term = Zeroizing::new(Scalar::mul(&self.secret[1], &session.nonce_coefficient));
		*nonce_term = Scalar::add(&nonce_term, &self.secret[0]);
		if session.negate_nonce {
			*nonce_term = Scalar::negate(&nonce_term);
		}
		let mut key_term = Zeroizing::new(Scalar::mul(&key, &session.key_factors[index]));
		*key_term = Scalar::mul(&key_term, &session.challenge);
		*nonce_term = Scalar::add(&nonce_term, &key_term);
		let encoded = Zeroizing::new(nonce_term.to_bytes());
		let signature = PartialSignature::from_byte_array(encoded.as_ref())
			.map_err(|_| Error::InvalidPartialSignature)?;
		// Faults must not cause an unchecked share to escape the signer.
		session.verify_member(index, &signature)?;
		Ok(signature)
	}
}

/// An immutable, fully validated public session. All arrays/slices of member shares
/// use `Intent::members` order, not sorted-key order. No secret key is reconstructed.
pub struct Session {
	intent: Intent,
	members: [MemberNonce; 2],
	member_points: [[ProjectivePoint; 2]; 2],
	group: PublicKey,
	group_nonce: PublicNonce,
	server_nonce: Option<PublicNonce>,
	aggregate_nonce: AggregatedNonce,
	cache: KeyAggCache,
	native: super::Session,
	key_factors: [Scalar; 2],
	nonce_coefficient: Scalar,
	challenge: Scalar,
	negate_nonce: bool,
}

impl Session {
	pub fn new(
		intent: Intent, members: [MemberNonce; 2], server_nonce: Option<PublicNonce>,
	) -> Result<Self, Error> {
		if intent.server.is_some() != server_nonce.is_some() {
			return Err(Error::ServerMismatch);
		}
		let group_nonce = aggregate_member_nonces(&intent, &members)?;
		let keys = KeyContext::new(&intent)?;
		let member_points = [nonce_points(&members[0].serialize())?, nonce_points(&members[1].serialize())?];
		let aggregate_nonce = match server_nonce.as_ref() {
			Some(server) => AggregatedNonce::new(&[&group_nonce, server]),
			None => AggregatedNonce::new(&[&group_nonce]),
		};
		let nonce_bytes = aggregate_nonce.serialize();
		let output_xonly = keys.output.x_only_public_key().0.serialize();
		let nonce_coefficient = reduce(tagged_hash(b"MuSig/noncecoef", &[
			&nonce_bytes, &output_xonly, &intent.message,
		]));
		let [first, second] = nonce_points(&nonce_bytes).map_err(|_| Error::Cancellation)?;
		let effective = effective_nonce(first, second, nonce_coefficient)?;
		let effective_key = point_key(effective)?;
		let challenge = reduce(tagged_hash(b"BIP0340/challenge", &[
			&effective_key.x_only_public_key().0.serialize(), &output_xonly, &intent.message,
		]));
		let native = super::Session::new(&keys.cache, aggregate_nonce, &intent.message);
		Ok(Self {
			intent, members, member_points, group: keys.group, group_nonce, server_nonce,
			aggregate_nonce, cache: keys.cache, native, key_factors: keys.factors,
			nonce_coefficient, challenge,
			negate_nonce: effective_key.x_only_public_key().1 == Parity::Odd,
		})
	}

	pub fn intent(&self) -> &Intent { &self.intent }

	/// Present this as the client's ordinary public nonce to the outer server.
	pub fn group_nonce(&self) -> PublicNonce { self.group_nonce }

	pub fn aggregate_nonce(&self) -> AggregatedNonce { self.aggregate_nonce }

	pub fn key_agg_cache(&self) -> &KeyAggCache { &self.cache }

	pub fn native_session(&self) -> &super::Session { &self.native }

	/// Verify the leaf share against its original full public key and nonce points.
	pub fn verify_member(&self, index: usize, signature: &PartialSignature) -> Result<(), Error> {
		let member = self.intent.members.get(index).ok_or(Error::ParticipantMismatch)?;
		let [first, second] = self.member_points[index];
		let mut nonce = first.add(&second.mul(&self.nonce_coefficient));
		if self.negate_nonce {
			nonce = nonce.neg();
		}
		let expected = nonce.add(&point(member)?.mul(&Scalar::mul(&self.challenge, &self.key_factors[index])));
		let actual = ProjectivePoint::GENERATOR.mul(&partial_scalar(signature)?);
		if actual != expected {
			return Err(Error::InvalidPartialSignature);
		}
		// In ordinary mode the leaf share must also match native BIP327 directly.
		if self.intent.server.is_none() && !self.native.partial_verify(
			&self.cache, signature, &self.members[index].nonce, super::pubkey_to(*member),
		) {
			return Err(Error::InvalidPartialSignature);
		}
		Ok(())
	}

	/// Verify both leaves and combine them into the ordinary native outer group
	/// share. In server-free mode this is the untweaked sum of the ordinary shares.
	pub fn combine_members(&self, signatures: &[PartialSignature]) -> Result<PartialSignature, Error> {
		if signatures.len() != 2 {
			return Err(Error::ShareCount);
		}
		self.verify_member(0, &signatures[0])?;
		self.verify_member(1, &signatures[1])?;
		let sum = Scalar::add(&partial_scalar(&signatures[0])?, &partial_scalar(&signatures[1])?);
		let combined = PartialSignature::from_byte_array(sum.to_bytes().as_ref())
			.map_err(|_| Error::InvalidPartialSignature)?;
		if self.intent.server.is_some() && !self.native.partial_verify(
			&self.cache, &combined, &self.group_nonce, super::pubkey_to(self.group),
		) {
			return Err(Error::InvalidPartialSignature);
		}
		Ok(combined)
	}

	pub fn verify_server(&self, signature: &PartialSignature) -> Result<(), Error> {
		let server = self.intent.server.ok_or(Error::ServerMismatch)?;
		let nonce = self.server_nonce.as_ref().ok_or(Error::ServerMismatch)?;
		if !self.native.partial_verify(&self.cache, signature, nonce, super::pubkey_to(server)) {
			return Err(Error::InvalidPartialSignature);
		}
		Ok(())
	}

	/// Verify every share, apply the root tweak correction once using the native
	/// aggregator, and verify the final BIP340 signature before returning it.
	pub fn aggregate(
		&self, members: &[PartialSignature], server: Option<&PartialSignature>,
	) -> Result<schnorr::Signature, Error> {
		if self.intent.server.is_some() != server.is_some() {
			return Err(Error::ServerMismatch);
		}
		let group = self.combine_members(members)?;
		let signature = match server {
			Some(server) => {
				self.verify_server(server)?;
				self.native.partial_sig_agg(&[&group, server])
			},
			None => self.native.partial_sig_agg(&[&group]),
		};
		let verified = signature.verify(&self.cache.agg_pk(), &self.intent.message)
			.map_err(|_| Error::InvalidSignature)?;
		Ok(super::sig_from(verified))
	}
}

/// Aggregate the two authenticated member nonces before contacting the server.
/// This lets an unchanged server receive an ordinary client nonce before its own
/// nonce is available. Cancellation cannot be represented as a native public nonce.
pub fn aggregate_member_nonces(
	intent: &Intent, members: &[MemberNonce; 2],
) -> Result<PublicNonce, Error> {
	if intent.members[0] == intent.members[1] {
		return Err(Error::DuplicateParticipant);
	}
	for (nonce, member) in members.iter().zip(intent.members) {
		if nonce.intent != *intent {
			return Err(Error::ContextMismatch);
		}
		if nonce.member != member {
			return Err(Error::ParticipantMismatch);
		}
	}
	if members[0].nonce == members[1].nonce {
		return Err(Error::NonceMismatch);
	}
	let aggregate = AggregatedNonce::new(&[&members[0].nonce, &members[1].nonce]);
	PublicNonce::from_byte_array(&aggregate.serialize()).map_err(|_| Error::Cancellation)
}

struct KeyContext {
	group: PublicKey,
	output: PublicKey,
	cache: KeyAggCache,
	factors: [Scalar; 2],
}

impl KeyContext {
	fn new(intent: &Intent) -> Result<Self, Error> {
		let (inner, mut factors) = checked_key_agg(intent.members)?;
		let group = super::pubkey_from(inner.agg_pk_full());
		let mut cache = match intent.server {
			Some(server) => {
				let (outer, coefficients) = checked_key_agg([group, server])?;
				for factor in &mut factors {
					*factor = Scalar::mul(factor, &coefficients[0]);
				}
				outer
			},
			None => inner,
		};
		let internal = super::pubkey_from(cache.agg_pk_full());
		let output = match intent.tweak {
			Some(bytes) => {
				let tweak = secpm::Scalar::from_be_bytes(bytes).map_err(|_| Error::InvalidTweak)?;
				super::pubkey_from(cache.pubkey_xonly_tweak_add(&tweak).map_err(|_| Error::InvalidTweak)?)
			},
			None => internal,
		};
		// No inner normalization. With a tweak, the root is normalized before
		// tweaking; without one, only the final BIP340 normalization applies.
		let negate = (output.x_only_public_key().1 == Parity::Odd)
			^ (intent.tweak.is_some() && internal.x_only_public_key().1 == Parity::Odd);
		if negate {
			for factor in &mut factors {
				*factor = Scalar::negate(factor);
			}
		}
		Ok(Self { group, output, cache, factors })
	}
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
	let tag_hash = sha256::Hash::hash(tag);
	let mut engine = sha256::Hash::engine();
	engine.input(tag_hash.as_byte_array());
	engine.input(tag_hash.as_byte_array());
	for part in parts {
		engine.input(part);
	}
	sha256::Hash::from_engine(engine).to_byte_array()
}

fn reduce(bytes: [u8; 32]) -> Scalar {
	<Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

fn key_coefficients(keys: [PublicKey; 2]) -> [Scalar; 2] {
	let mut sorted = keys.map(|key| key.serialize());
	sorted.sort();
	let list = tagged_hash(b"KeyAgg list", &[&sorted[0], &sorted[1]]);
	keys.map(|key| {
		// BIP327: pk2 is the second DISTINCT key, or an impossible all-zero
		// encoding when all keys are equal. Equal keys therefore both hash.
		if sorted[0] != sorted[1] && key.serialize() == sorted[1] {
			Scalar::ONE
		} else {
			reduce(tagged_hash(b"KeyAgg coefficient", &[&list, &key.serialize()]))
		}
	})
}

fn checked_key_agg(keys: [PublicKey; 2]) -> Result<(KeyAggCache, [Scalar; 2]), Error> {
	if keys[0] == keys[1] {
		return Err(Error::DuplicateParticipant);
	}
	let coefficients = key_coefficients(keys);
	let sum = point(&keys[0])?.mul(&coefficients[0]).add(&point(&keys[1])?.mul(&coefficients[1]));
	let expected = point_key(sum)?;
	let mut native_keys = keys.map(super::pubkey_to);
	native_keys.sort_by_key(secpm::PublicKey::serialize);
	let cache = KeyAggCache::new(&[&native_keys[0], &native_keys[1]]);
	if cache.agg_pk_full().serialize() != expected.serialize() {
		return Err(Error::BackendMismatch);
	}
	Ok((cache, coefficients))
}

fn point(key: &PublicKey) -> Result<ProjectivePoint, Error> {
	let encoded = EncodedPoint::from_bytes(key.serialize()).map_err(|_| Error::InvalidPoint)?;
	Option::<ProjectivePoint>::from(ProjectivePoint::from_encoded_point(&encoded))
		.ok_or(Error::InvalidPoint)
}

fn point_key(point: ProjectivePoint) -> Result<PublicKey, Error> {
	if bool::from(point.is_identity()) {
		return Err(Error::Cancellation);
	}
	PublicKey::from_slice(point.to_encoded_point(true).as_bytes()).map_err(|_| Error::InvalidPoint)
}

fn nonce_points(bytes: &[u8; 66]) -> Result<[ProjectivePoint; 2], Error> {
	Ok([
		point(&PublicKey::from_slice(&bytes[..33]).map_err(|_| Error::InvalidPoint)?)?,
		point(&PublicKey::from_slice(&bytes[33..]).map_err(|_| Error::InvalidPoint)?)?,
	])
}

fn effective_nonce(first: ProjectivePoint, second: ProjectivePoint, coefficient: Scalar)
	-> Result<ProjectivePoint, Error>
{
	let effective = first.add(&second.mul(&coefficient));
	if bool::from(effective.is_identity()) {
		return Err(Error::Cancellation);
	}
	Ok(effective)
}

fn partial_scalar(signature: &PartialSignature) -> Result<Scalar, Error> {
	Option::<Scalar>::from(Scalar::from_repr(signature.serialize().into()))
		.ok_or(Error::InvalidPartialSignature)
}

#[cfg(test)]
mod tests {
	use bitcoin::secp256k1::Message;
	use rand::{rngs::StdRng, SeedableRng};

	use super::*;
	use crate::{musig, SECP};

	fn key(index: u8) -> Keypair {
		// Public fixture keys, never production key material.
		Keypair::from_seckey_slice(&SECP, &[index; 32]).unwrap()
	}

	fn intent(keys: &[Keypair; 2], server: Option<&Keypair>, tweak: Option<[u8; 32]>) -> Intent {
		Intent {
			members: keys.each_ref().map(|key| key.public_key()),
			server: server.map(|key| key.public_key()),
			message: [42; 32], tweak,
		}
	}

	fn nonces(intent: Intent, rng: &mut StdRng) -> [Nonce; 2] {
		intent.members.map(|member| Nonce::generate(intent, member, rng).unwrap())
	}

	fn native_nonce(
		key: &Keypair, intent: &Intent, rng: &mut StdRng,
	) -> (musig::SecretNonce, PublicNonce) {
		let key = musig::keypair_to(key);
		let mut seed = [0u8; 32];
		rng.fill_bytes(&mut seed);
		secpm::musig::new_nonce_pair(
			musig::SessionSecretRand::assume_unique_per_nonce_gen(seed, &key.secret_key()),
			None, Some(key.secret_key()), key.public_key(), Some(&intent.message), None,
		)
	}

	fn shares(nonces: [Nonce; 2], keys: &[Keypair; 2], session: &Session) -> [PartialSignature; 2] {
		let [first, second] = nonces;
		[
			first.sign(&keys[0], session).unwrap(),
			second.sign(&keys[1], session).unwrap(),
		]
	}

	fn verify_final(intent: &Intent, signature: &schnorr::Signature) {
		SECP.verify_schnorr(
			signature, &Message::from_digest(intent.message),
			&intent.output_key().unwrap().x_only_public_key().0,
		).unwrap();
	}

	fn changed_share(share: &PartialSignature) -> PartialSignature {
		let value = Scalar::add(&partial_scalar(share).unwrap(), &Scalar::ONE);
		PartialSignature::from_byte_array(value.to_bytes().as_ref()).unwrap()
	}

	#[test]
	fn nested_native_server_and_all_parities() {
		let program = key(2);
		let server = key(3);
		let mut rng = StdRng::from_seed([0x71; 32]);
		let mut parities = [false; 16];
		let mut coefficient_cases = [false; 2];
		for fixture in 4..=160u8 {
			let keys = [key(fixture), program];
			let mut intent = intent(&keys, Some(&server), Some([11; 32]));
			intent.message = [fixture; 32];
			let nonces = nonces(intent, &mut rng);
			let public = nonces.each_ref().map(Nonce::public);
			let group_nonce = aggregate_member_nonces(&intent, &public).unwrap();
			let (server_secret, server_public) = native_nonce(&server, &intent, &mut rng);
			let session = Session::new(intent, public, Some(server_public)).unwrap();
			assert_eq!(session.group_nonce(), group_nonce);
			let group = intent.group_key().unwrap();
			assert_eq!(group, musig::combine_keys(intent.members));
			let (cache, output) = musig::tweaked_key_agg(
				[group, server.public_key()], intent.tweak.unwrap(),
			);
			assert_eq!(output, intent.output_key().unwrap());
			// An unchanged native server has no knowledge of the two leaf keys.
			let native = musig::Session::new(
				&cache, musig::nonce_agg(&[&group_nonce, &server_public]), &intent.message,
			);
			let server_share = native.partial_sign(server_secret, &musig::keypair_to(&server), &cache);
			let members = shares(nonces, &keys, &session);
			let joint = session.combine_members(&members).unwrap();
			assert!(native.partial_verify(&cache, &joint, &group_nonce, musig::pubkey_to(group)));
			session.verify_server(&server_share).unwrap();
			let signature = session.aggregate(&members, Some(&server_share)).unwrap();
			verify_final(&intent, &signature);
			let ordinary = native.partial_sig_agg(&[&joint, &server_share])
				.verify(&cache.agg_pk(), &intent.message).unwrap();
			assert_eq!(signature, musig::sig_from(ordinary));
			let root = musig::combine_keys([group, server.public_key()]);
			let bits = usize::from(group.x_only_public_key().1 == Parity::Odd) * 8
				+ usize::from(root.x_only_public_key().1 == Parity::Odd) * 4
				+ usize::from(output.x_only_public_key().1 == Parity::Odd) * 2
				+ usize::from(session.negate_nonce);
			parities[bits] = true;
			coefficient_cases[usize::from(key_coefficients([group, server.public_key()])[0] == Scalar::ONE)] = true;
		}
		assert_eq!(parities, [true; 16]);
		assert_eq!(coefficient_cases, [true; 2]);
	}

	#[test]
	fn ordinary_native_member_interoperability() {
		let mut rng = StdRng::from_seed([0x39; 32]);
		for keys in [[key(1), key(2)], [key(2), key(1)]] {
			for tweak in [None, Some([0; 32]), Some([7; 32])] {
				let intent = intent(&keys, None, tweak);
				let ours = Nonce::generate(intent, keys[0].public_key(), &mut rng).unwrap();
				let (native_secret, native_public) = native_nonce(&keys[1], &intent, &mut rng);
				let peer = MemberNonce::from_bytes(intent, keys[1].public_key(), native_public.serialize()).unwrap();
				let session = Session::new(intent, [ours.public(), peer], None).unwrap();
				let native = musig::Session::new(session.key_agg_cache(), session.aggregate_nonce(), &intent.message);
				let native_share = native.partial_sign(
					native_secret, &musig::keypair_to(&keys[1]), session.key_agg_cache(),
				);
				session.verify_member(1, &native_share).unwrap();
				let our_share = ours.sign(&keys[0], &session).unwrap();
				assert!(native.partial_verify(
					session.key_agg_cache(), &our_share, &session.members[0].native(),
					musig::pubkey_to(keys[0].public_key()),
				));
				let signature = session.aggregate(&[our_share, native_share], None).unwrap();
				verify_final(&intent, &signature);
				assert_eq!(signature, musig::sig_from(
					native.partial_sig_agg(&[&our_share, &native_share])
						.verify(&session.key_agg_cache().agg_pk(), &intent.message).unwrap(),
				));
			}
		}
	}

	#[test]
	fn both_modes_and_optional_tweak() {
		let keys = [key(1), key(2)];
		let server = key(3);
		let mut rng = StdRng::from_seed([0x28; 32]);
		for server in [None, Some(&server)] {
			for tweak in [None, Some([0; 32]), Some([9; 32])] {
				let intent = intent(&keys, server, tweak);
				let members = nonces(intent, &mut rng);
				let (server_secret, server_public) = match server {
					Some(server) => {
						let (secret, public) = native_nonce(server, &intent, &mut rng);
						(Some(secret), Some(public))
					},
					None => (None, None),
				};
				let session = Session::new(intent, members.each_ref().map(Nonce::public), server_public).unwrap();
				let server_share = server_secret.map(|secret| {
					session.native_session().partial_sign(
						secret, &musig::keypair_to(server.unwrap()), session.key_agg_cache(),
					)
				});
				let members = shares(members, &keys, &session);
				let signature = session.aggregate(&members, server_share.as_ref()).unwrap();
				verify_final(&intent, &signature);
			}
		}
	}

	#[test]
	fn bip327_coefficients_and_duplicate_principal_rejection() {
		let member = key(2).public_key();
		let duplicate = [member, member];
		let coefficients = key_coefficients(duplicate);
		assert_eq!(coefficients[0], coefficients[1]);
		let encoded = member.serialize();
		let list = tagged_hash(b"KeyAgg list", &[&encoded, &encoded]);
		assert_eq!(coefficients[0], reduce(tagged_hash(b"KeyAgg coefficient", &[&list, &encoded])));
		assert_eq!(checked_key_agg(duplicate).err(), Some(Error::DuplicateParticipant));
		let duplicate_intent = Intent {
			members: duplicate, server: None, message: [8; 32], tweak: None,
		};
		assert_eq!(duplicate_intent.group_key(), Err(Error::DuplicateParticipant));
		assert_eq!(duplicate_intent.output_key(), Err(Error::DuplicateParticipant));

		let keys = [key(1), key(2)];
		let group = musig::combine_keys(keys.each_ref().map(|key| key.public_key()));
		let intent = Intent {
			members: keys.each_ref().map(|key| key.public_key()),
			server: Some(group), message: [8; 32], tweak: None,
		};
		assert_eq!(intent.output_key(), Err(Error::DuplicateParticipant));
		let mut rng = StdRng::from_seed([0x55; 32]);
		assert_eq!(Nonce::generate(intent, intent.members[0], &mut rng).err(), Some(Error::DuplicateParticipant));
		assert_eq!(Nonce::generate(duplicate_intent, member, &mut rng).err(), Some(Error::DuplicateParticipant));

		let coefficients = key_coefficients(intent.members);
		let mut sorted = intent.members;
		sorted.sort_by_key(PublicKey::serialize);
		let second = intent.members.iter().position(|key| *key == sorted[1]).unwrap();
		assert_eq!(coefficients[second], Scalar::ONE);
		let reverse = key_coefficients([intent.members[1], intent.members[0]]);
		assert_eq!(coefficients, [reverse[1], reverse[0]]);
	}

	#[test]
	fn rejects_wrong_tampered_missing_and_swapped_shares() {
		let keys = [key(1), key(2)];
		let server = key(3);
		let intent = intent(&keys, Some(&server), Some([7; 32]));
		let mut rng = StdRng::from_seed([0x64; 32]);
		let members = nonces(intent, &mut rng);
		let (server_secret, server_public) = native_nonce(&server, &intent, &mut rng);
		let session = Session::new(intent, members.each_ref().map(Nonce::public), Some(server_public)).unwrap();
		let server_share = session.native_session().partial_sign(
			server_secret, &musig::keypair_to(&server), session.key_agg_cache(),
		);
		let members = shares(members, &keys, &session);
		assert_eq!(session.verify_member(2, &members[0]), Err(Error::ParticipantMismatch));
		assert_eq!(session.verify_member(0, &changed_share(&members[0])), Err(Error::InvalidPartialSignature));
		assert_eq!(session.combine_members(&members[..1]), Err(Error::ShareCount));
		assert_eq!(session.combine_members(&[]), Err(Error::ShareCount));
		assert_eq!(session.combine_members(&[members[0], members[1], members[0]]), Err(Error::ShareCount));
		assert_eq!(session.combine_members(&[members[1], members[0]]), Err(Error::InvalidPartialSignature));
		assert_eq!(session.combine_members(&[members[0], members[0]]), Err(Error::InvalidPartialSignature));
		assert_eq!(session.aggregate(&members, None), Err(Error::ServerMismatch));
		assert_eq!(session.verify_server(&members[0]), Err(Error::InvalidPartialSignature));
		assert_eq!(session.aggregate(&members, Some(&changed_share(&server_share))), Err(Error::InvalidPartialSignature));
		let good = session.aggregate(&members, Some(&server_share)).unwrap();
		verify_final(&intent, &good);
		let mut wrong_message = intent.message;
		wrong_message[0] ^= 1;
		assert!(SECP.verify_schnorr(
			&good, &Message::from_digest(wrong_message), &intent.output_key().unwrap().x_only_public_key().0,
		).is_err());
	}

	#[test]
	fn rejects_nonce_context_member_and_point_mismatches() {
		let keys = [key(1), key(2)];
		let intent = intent(&keys, None, None);
		let mut rng = StdRng::from_seed([0x17; 32]);
		let members = nonces(intent, &mut rng);
		let public = members.each_ref().map(Nonce::public);
		assert_eq!(MemberNonce::from_bytes(intent, intent.members[0], [0; 66]), Err(Error::InvalidPoint));
		assert_eq!(MemberNonce::from_bytes(intent, key(3).public_key(), public[0].serialize()), Err(Error::ParticipantMismatch));
		assert_eq!(Nonce::generate(intent, key(3).public_key(), &mut rng).err(), Some(Error::ParticipantMismatch));
		assert_eq!(Session::new(intent, [public[1], public[0]], None).err(), Some(Error::ParticipantMismatch));
		assert_eq!(Session::new(intent, public, Some(public[0].native())).err(), Some(Error::ServerMismatch));
		let mut with_server = intent;
		with_server.server = Some(key(3).public_key());
		assert_eq!(Session::new(with_server, public, None).err(), Some(Error::ServerMismatch));
		// Each binding dimension is checked before using a nonce, even when
		// x-only output keys might coincide (e.g. absent versus zero tweak).
		for changed in [
			Intent { message: [99; 32], ..intent },
			Intent { tweak: Some([0; 32]), ..intent },
			Intent { members: [intent.members[1], intent.members[0]], ..intent },
		] {
			assert_eq!(Session::new(changed, public, None).err(), Some(Error::ContextMismatch));
		}
		let substituted = nonces(intent, &mut rng);
		let session = Session::new(intent, substituted.each_ref().map(Nonce::public), None).unwrap();
		let [old, other] = members;
		assert_eq!(old.sign(&keys[0], &session), Err(Error::NonceMismatch));
		assert_eq!(other.sign(&keys[0], &session), Err(Error::ParticipantMismatch));
		let changed = Intent { message: [99; 32], ..intent };
		let changed_nonces = nonces(changed, &mut rng);
		let changed_session = Session::new(changed, changed_nonces.each_ref().map(Nonce::public), None).unwrap();
		let [old, _] = substituted;
		assert_eq!(old.sign(&keys[0], &changed_session), Err(Error::ContextMismatch));
	}

	#[test]
	fn rejects_invalid_tweaks_and_repeated_nonce_slots() {
		let keys = [key(1), key(2)];
		let intent = intent(&keys, None, None);
		let invalid = Intent { tweak: Some([0xff; 32]), ..intent };
		assert_eq!(invalid.output_key(), Err(Error::InvalidTweak));
		let mut rng = StdRng::from_seed([0x22; 32]);
		assert_eq!(Nonce::generate(invalid, intent.members[0], &mut rng).err(), Some(Error::InvalidTweak));
		let nonce = Nonce::generate(intent, intent.members[0], &mut rng).unwrap();
		let repeated = MemberNonce::from_bytes(intent, intent.members[1], nonce.public().serialize()).unwrap();
		assert_eq!(Session::new(intent, [nonce.public(), repeated], None).err(), Some(Error::NonceMismatch));
	}

	fn negated_nonce(nonce: PublicNonce) -> [u8; 66] {
		let mut bytes = nonce.serialize();
		for encoded in bytes.chunks_exact_mut(33) {
			let key = PublicKey::from_slice(encoded).unwrap().negate(&SECP);
			encoded.copy_from_slice(&key.serialize());
		}
		bytes
	}

	#[test]
	fn rejects_inner_outer_and_effective_nonce_cancellation() {
		let keys = [key(1), key(2)];
		let server = key(3);
		let intent = intent(&keys, Some(&server), None);
		let mut rng = StdRng::from_seed([0x43; 32]);
		let members = nonces(intent, &mut rng);
		let public = members.each_ref().map(Nonce::public);
		let negative = MemberNonce::from_bytes(
			intent, intent.members[1], negated_nonce(public[0].native()),
		).unwrap();
		let (_, server_nonce) = native_nonce(&server, &intent, &mut rng);
		assert_eq!(aggregate_member_nonces(&intent, &[public[0], negative]), Err(Error::Cancellation));
		assert_eq!(Session::new(intent, [public[0], negative], Some(server_nonce)).err(), Some(Error::Cancellation));
		let group = aggregate_member_nonces(&intent, &public).unwrap();
		let negative_server = PublicNonce::from_byte_array(&negated_nonce(group)).unwrap();
		assert_eq!(Session::new(intent, public, Some(negative_server)).err(), Some(Error::Cancellation));
		let generator = ProjectivePoint::GENERATOR;
		assert_eq!(effective_nonce(generator, -generator, Scalar::ONE), Err(Error::Cancellation));
		assert_eq!(effective_nonce(generator, -generator, Scalar::ZERO), Ok(generator));
		assert_eq!(point_key(generator + -generator), Err(Error::Cancellation));
	}

	#[test]
	fn scalar_reduction_and_seeded_nonce_generation() {
		let order = [
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
			0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
			0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
		];
		assert_eq!(reduce(order), Scalar::ZERO);
		assert_eq!(reduce([0; 32]), Scalar::ZERO);
		let mut one = [0; 32];
		one[31] = 1;
		assert_eq!(reduce(one), Scalar::ONE);
		let keys = [key(1), key(2)];
		let intent = intent(&keys, None, None);
		let mut first = StdRng::from_seed([0x59; 32]);
		let mut repeat = StdRng::from_seed([0x59; 32]);
		let a = Nonce::generate(intent, intent.members[0], &mut first).unwrap();
		let b = Nonce::generate(intent, intent.members[0], &mut repeat).unwrap();
		assert_eq!(a.public(), b.public());
		let c = Nonce::generate(intent, intent.members[0], &mut first).unwrap();
		assert_ne!(a.public().serialize(), c.public().serialize());
		assert_eq!(
			MemberNonce::from_bytes(intent, intent.members[0], a.public().serialize()).unwrap(),
			a.public(),
		);
	}
}
