

use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, Keypair, PublicKey};
use bitcoin::sighash::{self, SighashCache, TapSighash, TapSighashType};

use bitcoin_ext::{fee, TaprootSpendInfoExt, P2TR_DUST};

use crate::{musig, ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId, SECP};
use crate::connectors::ConnectorChain;
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::musig::context::{SigningContextError, SigningInput};
use crate::tree::signed::UnlockHash;
use crate::vtxo::{Full, GenesisItem, GenesisTransition, TapScriptClause};
use crate::vtxo::policy::HarkForfeitVtxoPolicy;
use crate::vtxo::policy::clause::DelayedSignClause;
use crate::vtxo::genesis::ArkoorGenesis;


/// Construct the forfeit tx in the hArk forfeit protocol
#[inline]
pub fn create_hark_forfeit_tx<G>(
	vtxo: &Vtxo<G>,
	unlock_hash: UnlockHash,
	signature: Option<&schnorr::Signature>,
) -> Transaction {
	let claim_policy = HarkForfeitVtxoPolicy {
		user_pubkey: vtxo.user_pubkey(),
		unlock_hash: unlock_hash,
	};
	debug_assert_eq!(
		musig::combine_keys([vtxo.user_pubkey(), vtxo.server_pubkey()]).x_only_public_key().0,
		vtxo.output_taproot().internal_key(),
	);

	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::MAX,
				script_sig: ScriptBuf::new(),
				witness: signature.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: claim_policy
					.taproot(vtxo.server_pubkey(), vtxo.exit_delta())
					.script_pubkey(),
			},
			fee::fee_anchor(),
		],
	}
}

#[inline]
fn hark_forfeit_sighash<G>(
	vtxo: &Vtxo<G>,
	unlock_hash: UnlockHash,
) -> (TapSighash, Transaction) {
	let exit_prevout = vtxo.txout();
	let tx = create_hark_forfeit_tx(vtxo, unlock_hash, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		0, &sighash::Prevouts::All(&[exit_prevout]), TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

/// Construct the internal VTXO that represents the forfeit output
///
/// The `forfeit_txid` argument is optional and will be calculated if not present.
#[inline]
fn build_internal_forfeit_vtxo(
	vtxo: &Vtxo<Full>,
	unlock_hash: UnlockHash,
	forfeit_tx_sig: schnorr::Signature,
	forfeit_txid: Option<Txid>,
) -> ServerVtxo<Full> {
	let ff_txid = forfeit_txid.unwrap_or_else(|| {
		create_hark_forfeit_tx(vtxo, unlock_hash, None).compute_txid()
	});
	debug_assert_eq!(ff_txid, create_hark_forfeit_tx(vtxo, unlock_hash, None).compute_txid());

	Vtxo {
		point: OutPoint::new(ff_txid, 0),
		policy: ServerVtxoPolicy::new_hark_forfeit(vtxo.user_pubkey(), unlock_hash),
		genesis: Full {
			items: vtxo.genesis.items.iter().cloned().chain([
				GenesisItem {
					transition: GenesisTransition::Arkoor(ArkoorGenesis {
						client_cosigners: vec![vtxo.user_pubkey()],
						tap_tweak: vtxo.output_taproot().tap_tweak(),
						signature: Some(forfeit_tx_sig),
					}),
					output_idx: 0,
					other_outputs: vec![],
					fee_amount: Amount::ZERO,
				}
			]).collect(),
		},

		amount: vtxo.amount,
		expiry_height: vtxo.expiry_height,
		server_pubkey: vtxo.server_pubkey,
		exit_delta: vtxo.exit_delta,
		anchor_point: vtxo.anchor_point,
	}
}

/// Authenticated hArk forfeit signing data and the exact output a fallback claim spends.
///
/// The parent is deliberately unsigned: the server need not disclose its complete
/// forfeit signature. A presigned fallback can therefore have to wait for this
/// known parent to appear on chain; it is not a fully signed VTXO ancestor.
pub struct HarkForfeitSigningContext {
	vtxo_id: VtxoId,
	user_pubkey: PublicKey,
	unlock_hash: UnlockHash,
	signing_input: SigningInput,
	recovery_outpoint: OutPoint,
	recovery_taproot: bitcoin::taproot::TaprootSpendInfo,
	recovery_clause: DelayedSignClause,
}

impl HarkForfeitSigningContext {
	/// Build this context before authorizing or releasing the external user share.
	pub fn new<G>(
		vtxo: &Vtxo<G>,
		unlock_hash: UnlockHash,
	) -> Result<Self, SigningContextError> {
		let tx = create_hark_forfeit_tx(vtxo, unlock_hash, None);
		let recovery_outpoint = OutPoint::new(tx.compute_txid(), 0);
		let signing_input = SigningInput::key_spend(
			tx, 0, vec![vtxo.txout()], &vtxo.output_taproot(),
			vec![vtxo.user_pubkey(), vtxo.server_pubkey()],
		)?;
		let policy = HarkForfeitVtxoPolicy { user_pubkey: vtxo.user_pubkey(), unlock_hash };
		Ok(Self {
			vtxo_id: vtxo.id(),
			user_pubkey: vtxo.user_pubkey(),
			unlock_hash,
			signing_input,
			recovery_outpoint,
			recovery_taproot: policy.taproot(vtxo.server_pubkey(), vtxo.exit_delta()),
			recovery_clause: policy.user_exit_clause(vtxo.exit_delta()),
		})
	}

	pub fn signing_input(&self) -> &SigningInput {
		&self.signing_input
	}

	/// The exact parent transaction, without the server's unknown final signature.
	pub fn unsigned_parent(&self) -> &Transaction {
		&self.signing_input.psbt.unsigned_tx
	}

	pub fn recovery_outpoint(&self) -> OutPoint {
		self.recovery_outpoint
	}

	pub fn recovery_txout(&self) -> &TxOut {
		&self.unsigned_parent().output[0]
	}

	pub fn recovery_taproot(&self) -> &bitcoin::taproot::TaprootSpendInfo {
		&self.recovery_taproot
	}

	pub fn recovery_clause(&self) -> &DelayedSignClause {
		&self.recovery_clause
	}

	/// Authenticate a delayed fallback claim against the unsigned forfeit parent.
	///
	/// `participants` are the untweaked signers of the user's ownership key
	/// (for program ownership, U and S), not the server's forfeit cosigners.
	pub fn recovery_signing_input(
		&self,
		tx: Transaction,
		mut participants: Vec<PublicKey>,
	) -> Result<SigningInput, SigningContextError> {
		if tx.input.len() != 1 || tx.input[0].previous_output != self.recovery_outpoint
			|| tx.input[0].sequence != self.recovery_clause.sequence() || tx.version.0 < 2
		{
			return Err(SigningContextError::InvalidContext("incorrect hArk fallback input"));
		}
		if participants.is_empty()
			|| musig::combine_keys(participants.iter().copied()).x_only_public_key().0
				!= self.user_pubkey.x_only_public_key().0
		{
			return Err(SigningContextError::InvalidContext("incorrect hArk fallback signing keys"));
		}
		let script = self.recovery_clause.tapscript();
		let version = bitcoin::taproot::LeafVersion::TapScript;
		let control = self.recovery_taproot.control_block(&(script.clone(), version))
			.ok_or(SigningContextError::InvalidContext("missing hArk fallback control block"))?;
		let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx)
			.map_err(|_| SigningContextError::InvalidContext("invalid unsigned hArk fallback"))?;
		psbt.inputs[0].witness_utxo = Some(self.recovery_txout().clone());
		psbt.inputs[0].non_witness_utxo = Some(self.unsigned_parent().clone());
		psbt.inputs[0].tap_internal_key = Some(self.recovery_taproot.internal_key());
		psbt.inputs[0].tap_merkle_root = self.recovery_taproot.merkle_root();
		psbt.inputs[0].tap_scripts.insert(control, (script.clone(), version));
		participants.sort_by_key(|key| key.serialize());
		let input = SigningInput {
			psbt, input_index: 0,
			script_leaf: Some(bitcoin::taproot::TapLeafHash::from_script(&script, version)),
			participants, tweak: None,
		};
		input.sighash()?;
		Ok(input)
	}

	/// Complete a fallback claim; its unsigned parent may still need to appear on chain.
	pub fn finalize_recovery(
		&self,
		tx: Transaction,
		participants: Vec<PublicKey>,
		signature: schnorr::Signature,
	) -> Result<Transaction, SigningContextError> {
		let input = self.recovery_signing_input(tx, participants)?;
		input.verify_signature(&signature)?;
		let script = self.recovery_clause.tapscript();
		let control = self.recovery_taproot
			.control_block(&(script, bitcoin::taproot::LeafVersion::TapScript))
			.ok_or(SigningContextError::InvalidContext("missing hArk fallback control block"))?;
		let mut tx = input.psbt.unsigned_tx;
		tx.input[0].witness = self.recovery_clause.witness(&signature, &control);
		Ok(tx)
	}

	/// Validate an external aggregate user share before constructing the wire bundle.
	pub fn assemble(
		&self,
		user_nonce: musig::PublicNonce,
		user_share: musig::PartialSignature,
		server_nonce: &musig::PublicNonce,
	) -> Result<HashLockedForfeitBundle, SigningContextError> {
		let tweak = self.signing_input.tweak
			.ok_or(SigningContextError::InvalidContext("missing forfeit taproot tweak"))?;
		let (key_agg, _) = musig::tweaked_key_agg(
			self.signing_input.participants.iter().copied(), tweak,
		);
		let session = musig::Session::new(
			&key_agg, musig::nonce_agg(&[&user_nonce, server_nonce]),
			&self.signing_input.sighash()?,
		);
		if !session.partial_verify(
			&key_agg, &user_share, &user_nonce, musig::pubkey_to(self.user_pubkey),
		) {
			return Err(SigningContextError::InvalidSignature);
		}
		Ok(HashLockedForfeitBundle {
			vtxo_id: self.vtxo_id, unlock_hash: self.unlock_hash,
			user_nonce, part_sig: user_share,
		})
	}

	/// Attach a known, verified final signature without inventing a signed ancestor.
	pub fn signed_parent(
		&self,
		signature: schnorr::Signature,
	) -> Result<Transaction, SigningContextError> {
		self.signing_input.verify_signature(&signature)?;
		let mut tx = self.unsigned_parent().clone();
		tx.input[0].witness = Witness::from_slice(&[&signature[..]]);
		Ok(tx)
	}
}

/// A bundle of a signature and metadata that forfeits a user's VTXO
/// conditional on the server revealing a secret preimage
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLockedForfeitBundle {
	pub vtxo_id: VtxoId,
	pub unlock_hash: UnlockHash,
	pub user_nonce: musig::PublicNonce,
	/// User's partial signature on the forfeit tx
	pub part_sig: musig::PartialSignature,
}

impl HashLockedForfeitBundle {
	/// Create a new [HashLockedForfeitBundle] for the given VTXO
	///
	/// This is used to forfeit the VTXO to the server conditional on receiving
	/// the unlock preimage corresponding to the given unlock hash.
	pub fn new<G>(
		vtxo: &Vtxo<G>,
		unlock_hash: UnlockHash,
		user_key: &Keypair,
		server_nonce: &musig::PublicNonce,
	) -> Self {
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, _) = hark_forfeit_sighash(vtxo, unlock_hash);
		let (ff_sec_nonce, ff_pub_nonce) = musig::nonce_pair_with_msg(
			user_key, &ff_sighash.to_byte_array(),
		);
		let ff_agg_nonce = musig::nonce_agg(&[&ff_pub_nonce, &server_nonce]);
		let (ff_part_sig, _sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			user_key,
			ff_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			None,
		);

		Self {
			vtxo_id: vtxo.id(),
			unlock_hash: unlock_hash,
			user_nonce: ff_pub_nonce,
			part_sig: ff_part_sig,
		}
	}

	/// Used by the server to verify if the partial signature in the bundle
	/// is valid
	pub fn verify<G>(
		&self,
		vtxo: &Vtxo<G>,
		server_nonce: &musig::PublicNonce,
	) -> Result<(), &'static str> {
		if vtxo.id() != self.vtxo_id {
			return Err("VTXO mismatch");
		}

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonce, &server_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, _) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let (ff_key_agg, _) = musig::tweaked_key_agg(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			vtxo_exit_taproot.tap_tweak().to_byte_array(),
		);
		let ff_session = musig::Session::new(
			&ff_key_agg,
			ff_agg_nonce,
			&ff_sighash.to_byte_array(),
		);
		let success = ff_session.partial_verify(
			&ff_key_agg, &self.part_sig, &self.user_nonce, musig::pubkey_to(vtxo.user_pubkey()),
		);
		if !success {
			return Err("invalid partial sig for forfeit tx");
		}
		Ok(())
	}

	/// Used by the server to finish the forfeit signature using its own
	/// nonce
	///
	/// NB users don't need to know this signature
	pub fn finish(
		&self,
		vtxo: &Vtxo<Full>,
		server_pub_nonce: &musig::PublicNonce,
		server_sec_nonce: musig::SecretNonce,
		server_key: &Keypair,
	) -> (schnorr::Signature, Transaction, ServerVtxo<Full>) {
		assert_eq!(vtxo.id(), self.vtxo_id);

		let ff_agg_nonce = musig::nonce_agg(
			&[&self.user_nonce, &server_pub_nonce],
		);
		let vtxo_exit_taproot = vtxo.output_taproot();
		let (ff_sighash, mut ff_tx) = hark_forfeit_sighash(vtxo, self.unlock_hash);
		let (_ff_part_sig, ff_sig) = musig::partial_sign(
			[vtxo.user_pubkey(), vtxo.server_pubkey()],
			ff_agg_nonce,
			server_key,
			server_sec_nonce,
			ff_sighash.to_byte_array(),
			Some(vtxo_exit_taproot.tap_tweak().to_byte_array()),
			Some(&[&self.part_sig]),
		);
		let ff_sig = ff_sig.expect("forfeit tx sig error");
		debug_assert!({
			let (ff_key_agg, _) = musig::tweaked_key_agg(
				[vtxo.user_pubkey(), vtxo.server_pubkey()],
				vtxo_exit_taproot.tap_tweak().to_byte_array(),
			);
			let ff_session = musig::Session::new(
				&ff_key_agg,
				ff_agg_nonce,
				&ff_sighash.to_byte_array(),
			);
			ff_session.partial_verify(
				&ff_key_agg,
				&_ff_part_sig,
				&server_pub_nonce,
				musig::pubkey_to(vtxo.server_pubkey()),
			)
		});
		debug_assert_eq!(Ok(()), SECP.verify_schnorr(
			&ff_sig, &ff_sighash.into(), &vtxo_exit_taproot.output_key().to_x_only_public_key(),
		));

		// fill in the signature in the tx
		ff_tx.input[0].witness = Witness::from_slice(&[&ff_sig[..]]);
		debug_assert_eq!(ff_tx, create_hark_forfeit_tx(vtxo, self.unlock_hash, Some(&ff_sig)));

		let ff_txid = ff_tx.compute_txid();
		let ff_vtxo = build_internal_forfeit_vtxo(vtxo, self.unlock_hash, ff_sig, Some(ff_txid));

		(ff_sig, ff_tx, ff_vtxo)
	}
}

/// The serialization version of [HashLockedForfeitBundle].
const HASH_LOCKED_FORFEIT_BUNDLE_VERSION: u8 = 0x01;

impl ProtocolEncoding for HashLockedForfeitBundle {
	fn encode<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
		w.emit_u8(HASH_LOCKED_FORFEIT_BUNDLE_VERSION)?;
		self.vtxo_id.encode(w)?;
		self.unlock_hash.encode(w)?;
		self.user_nonce.encode(w)?;
		self.part_sig.encode(w)?;
		Ok(())
	}

	fn decode<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let ver = r.read_u8()?;
		if ver != HASH_LOCKED_FORFEIT_BUNDLE_VERSION {
			return Err(ProtocolDecodingError::invalid("unknown encoding version"));
		}
		Ok(Self {
			vtxo_id: ProtocolEncoding::decode(r)?,
			unlock_hash: ProtocolEncoding::decode(r)?,
			user_nonce: ProtocolEncoding::decode(r)?,
			part_sig: ProtocolEncoding::decode(r)?,
		})
	}
}

#[inline]
pub fn create_connector_forfeit_tx<G>(
	vtxo: &Vtxo<G>,
	connector: OutPoint,
	forfeit_sig: Option<&schnorr::Signature>,
	connector_sig: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![
			TxIn {
				previous_output: vtxo.point(),
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: forfeit_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
			TxIn {
				previous_output: connector,
				sequence: Sequence::ZERO,
				script_sig: ScriptBuf::new(),
				witness: connector_sig.map(|s| Witness::from_slice(&[&s[..]])).unwrap_or_default(),
			},
		],
		output: vec![
			TxOut {
				value: vtxo.amount(),
				script_pubkey: ScriptBuf::new_p2tr(&SECP, vtxo.server_pubkey().into(), None),
			},
			// We throw the connector dust value into the fee anchor
			// because we can't have zero-value anchors and a non-zero fee.
			fee::fee_anchor_with_amount(P2TR_DUST),
		],
	}
}

#[inline]
fn connector_forfeit_input_sighash<G>(
	vtxo: &Vtxo<G>,
	connector: OutPoint,
	connector_pk: PublicKey,
	input_idx: usize,
) -> (TapSighash, Transaction) {
	let exit_prevout = vtxo.txout();
	let connector_prevout = TxOut {
		script_pubkey: ConnectorChain::output_script(connector_pk),
		value: P2TR_DUST,
	};
	let tx = create_connector_forfeit_tx(vtxo, connector, None, None);
	let sighash = SighashCache::new(&tx).taproot_key_spend_signature_hash(
		input_idx,
		&sighash::Prevouts::All(&[exit_prevout, connector_prevout]),
		TapSighashType::Default,
	).expect("sighash error");
	(sighash, tx)
}

/// The sighash of the exit tx input of a forfeit tx.
#[inline]
pub fn connector_forfeit_sighash_exit<G>(
	vtxo: &Vtxo<G>,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	connector_forfeit_input_sighash(vtxo, connector, connector_pk, 0)
}

/// The sighash of the connector input of a forfeit tx.
#[inline]
pub fn connector_forfeit_sighash_connector<G>(
	vtxo: &Vtxo<G>,
	connector: OutPoint,
	connector_pk: PublicKey,
) -> (TapSighash, Transaction) {
	connector_forfeit_input_sighash(vtxo, connector, connector_pk, 1)
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use bitcoin::hex::{DisplayHex, FromHex};
	use crate::test_util::{verify_tx, VTXO_VECTORS};
	use crate::tree::signed::UnlockPreimage;
	use super::*;

	fn verify_hark_forfeits(
		vtxo: &Vtxo<Full>,
		unlock_preimage: UnlockPreimage,
		server_sec_nonce: musig::SecretNonce,
		server_pub_nonce: &musig::PublicNonce,
		bundle: HashLockedForfeitBundle,
	) {
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		assert_eq!(Ok(()), bundle.verify(vtxo, server_pub_nonce));
		let external = HarkForfeitSigningContext::new(vtxo, unlock_hash).unwrap();
		assert_eq!(
			external.signing_input().sighash().unwrap(),
			hark_forfeit_sighash(vtxo, unlock_hash).0.to_byte_array(),
		);
		assert_eq!(external.unsigned_parent(), &create_hark_forfeit_tx(vtxo, unlock_hash, None));
		assert_eq!(external.recovery_outpoint(), OutPoint::new(external.unsigned_parent().compute_txid(), 0));
		assert_eq!(external.recovery_txout(), &external.unsigned_parent().output[0]);
		assert!(external.unsigned_parent().input[0].witness.is_empty());
		assert_eq!(
			external.assemble(bundle.user_nonce, bundle.part_sig, server_pub_nonce).unwrap(),
			bundle,
		);
		let (_, wrong_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		assert_eq!(
			external.assemble(bundle.user_nonce, bundle.part_sig, &wrong_nonce).err(),
			Some(SigningContextError::InvalidSignature),
		);

		// finish it which triggers debug asserts on partial sigs
		let (sig, tx, _vtxo) = bundle.finish(vtxo, server_pub_nonce, server_sec_nonce, &VTXO_VECTORS.server_key);

		let (ff_sighash, ff_tx) = hark_forfeit_sighash(vtxo, unlock_hash);
		SECP.verify_schnorr(
			&sig,
			&ff_sighash.into(),
			&vtxo.output_taproot().output_key().to_x_only_public_key(),
		).expect("forfeit tx sig check failed");
		let ff_point = OutPoint::new(ff_tx.compute_txid(), 0);

		// validate the actual txs
		let ff_input = vtxo.txout();
		let ff_tx_expected = create_hark_forfeit_tx(vtxo, unlock_hash, Some(&sig));
		assert_eq!(ff_tx_expected, tx);
		assert_eq!(external.signed_parent(sig).unwrap(), tx);
		verify_tx(&[ff_input], 0, &ff_tx_expected).expect("forfeit tx error");
		assert_eq!(ff_tx_expected.compute_txid(), ff_point.txid);
	}

	#[test]
	fn test_hark_forfeits() {
		let (server_sec_nonce, server_pub_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		// we need to go through some hoops to print the secret nonces
		let server_sec_bytes = server_sec_nonce.dangerous_into_bytes();
		println!("server ff sec nonce: {}", server_sec_bytes.as_hex());
		let server_sec_nonce = musig::SecretNonce::dangerous_from_bytes(server_sec_bytes);
		println!("server pub nonces: {}", server_pub_nonce.serialize_hex());

		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
		let unlock_preimage = UnlockPreimage::from_hex("c65f29e65dbc6cbad3e7f35c41986487c74ed513aeb37778354d42f3b0714645").unwrap();
		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		let bundle = HashLockedForfeitBundle::new(
			vtxo,
			unlock_hash,
			&VTXO_VECTORS.arkoor3_user_key,
			&server_pub_nonce,
		);

		// test encoding round trip
		let encoded = bundle.serialize();
		println!("bundle: {}", encoded.as_hex());
		let decoded = HashLockedForfeitBundle::deserialize(&encoded).unwrap();
		assert_eq!(bundle, decoded);
		let bundle = decoded;

		println!("verifying generated forfeits");
		verify_hark_forfeits(
			vtxo, unlock_preimage, server_sec_nonce, &server_pub_nonce, bundle.clone(),
		);

		let (_sec, bad_nonce) = musig::nonce_pair(&VTXO_VECTORS.server_key);
		assert_eq!(
			bundle.verify(vtxo, &bad_nonce),
			Err("invalid partial sig for forfeit tx"),
		);


		// verify a hard-coded example from a previous run of this test
		let server_sec_nonce = musig::SecretNonce::dangerous_from_bytes(FromHex::from_hex(
			"220edcf1e0025bafa93c541763eb869fb7325c235fea6f0b9e9b32ae7de3aa416a798bd0c1deecbd2b61bac43ca683c296631e1e555fec9fd200ce973e62f6f387a85e47622bf70a8243580d1879746ffe940588c5ad9d478d1b46e2bb9318743312a8657f684b47f963f7a0e95927b2c71005112d8edc5821a3f6f0f7bd6354947ff8ac",
		).unwrap());
		let server_pub_nonce = musig::PublicNonce::from_str("03b4d5711322b73c8c412d0d6a6bce0af1eb98662c6fac8faeab3d6979d77c7430034ff4c184887f764d00af812a1c155ca8be4d18a6c012fea0d6b4a819b451414e").unwrap();
		let bundle = HashLockedForfeitBundle::deserialize_hex("0167754b5920d282ad276e8c80e1088f09238698bb674906fe47a0bfe2e9855912000000003d5491373df6a016f78b3f46d65a4fc6948824c43a59620404e8719cfee05d1a02afcb2341f8ff179d12fe0bf586653dc1ae91f97df02ab25958ecc37675b611bd0225697fa9181018d4a8b2130d4464df40beb48b80534dec43662b0115ac5dad95a102613bd646bceb9afbd895e8092ec504e5b4a419c027114445dff521569bf5").unwrap();

		println!("verifying hard-coded forfeits");
		verify_hark_forfeits(vtxo, unlock_preimage, server_sec_nonce, &server_pub_nonce, bundle);
	}

	#[test]
	fn external_hark_recovery_keeps_unknown_parent_unsigned() {
		let user_key = &VTXO_VECTORS.arkoor3_user_key;
		let program_key = Keypair::from_seckey_slice(&SECP, &[3; 32]).unwrap();
		let participants = vec![user_key.public_key(), program_key.public_key()];
		// A bare fixture needs no alleged signed history for the group-owned output.
		let mut vtxo = VTXO_VECTORS.arkoor3_vtxo.to_bare();
		vtxo.policy = crate::VtxoPolicy::new_pubkey(musig::combine_keys(participants.iter().copied()));
		let ctx = HarkForfeitSigningContext::new(&vtxo, UnlockHash::hash(&[42; 32])).unwrap();
		let claim = Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: ctx.recovery_outpoint(),
				sequence: ctx.recovery_clause().sequence(),
				script_sig: ScriptBuf::new(),
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: vtxo.amount() - Amount::from_sat(1_000),
				script_pubkey: ScriptBuf::new_p2tr(&SECP, user_key.x_only_public_key().0, None),
			}],
		};
		let input = ctx.recovery_signing_input(claim.clone(), participants.clone()).unwrap();
		assert_eq!(input.psbt.inputs[0].non_witness_utxo.as_ref(), Some(ctx.unsigned_parent()));
		let signature = musig::cosign_both(user_key, &program_key, input.sighash().unwrap(), None);
		let signed = ctx.finalize_recovery(claim.clone(), participants.clone(), signature).unwrap();
		verify_tx(&[ctx.recovery_txout().clone()], 0, &signed).unwrap();
		assert!(ctx.unsigned_parent().input[0].witness.is_empty());

		let mut wrong_parent = claim.clone();
		wrong_parent.input[0].previous_output.vout = 1;
		assert!(ctx.recovery_signing_input(wrong_parent, participants.clone()).is_err());
		let mut premature = claim.clone();
		premature.input[0].sequence = Sequence::ZERO;
		assert!(ctx.recovery_signing_input(premature, participants.clone()).is_err());
		let mut redirected = claim;
		redirected.output[0].value -= Amount::ONE_SAT;
		assert!(ctx.finalize_recovery(redirected, participants, signature).is_err());
	}
}
