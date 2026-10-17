//! Immutable, program-authorized Bitcoin recovery.
//!
//! Preparation authorizes the actual transaction through the generic program. A saved
//! claim is never redirected, batched, or re-signed to pay fees. Its zero-value P2A
//! output is spent by an ordinary fee wallet. Beneficiaries are explicitly configured
//! Bitcoin scripts; they are not a claim that this wallet owns those scripts.
//!
//! Export a [`ProgramRecoveryBundle`] before taking the cosigner offline. Repeatedly
//! call [`recover_program_bundle`] with a chain source and funded ordinary fee wallet
//! until the claims confirm. No Ark server or program service is used by that path.
//!
//! Exports retain signed hashlocked leaves separately from their incomplete
//! transaction witnesses, with authenticated forfeit-output disclosure paths.
//! Bitcoin can reveal the missing preimage; it never supplies a new authorization.
//! Wallet takeovers distinguish selected actor positions from shared historical
//! ancestors. The daemon resumes only those durable selections, and balance
//! accounting chooses one old/forfeit/replacement branch until payout confirms.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, ensure};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootSpendInfo};
use bitcoin::{transaction, Amount, FeeRate, Network, OutPoint, Psbt, Script, ScriptBuf,
	Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_ext::{fee, BlockDelta, BlockHeight, TransactionExt, TxOutExt};

use ark::forfeit::HarkForfeitSigningContext;
use ark::musig::context::SigningInput;
use ark::vtxo::{Full, TapScriptClause, VtxoClause};
use ark::{scripts, Vtxo, SECP};

use crate::chain::ChainSource;
use crate::onchain::{CpfpError, MakeCpfpFees, OnchainWalletTrait};
use crate::persist::models::{ProgramRecoveryDisclosure, ProgramRecoveryRecord, ProgramRecoveryTemplate,
	ProgramRecoveryUnlock, SerdeProgramKey, recovery_action_key, recovery_round_key,
	recovery_superseded_key, recovery_target_key, recovery_vtxo_key};
use crate::sapio::VtxoSigningKey;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};
use crate::Wallet;

/// A self-contained export. Endpoints in descriptors are informational only during recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramRecoveryBundle {
	pub version: u32,
	pub network: Network,
	/// Positions deliberately selected for recovery, not every historical proof in the export.
	pub targets: Vec<OutPoint>,
	pub keys: Vec<SerdeProgramKey>,
	pub recoveries: Vec<ProgramRecoveryRecord>,
}

/// Cryptographic completeness of saved bytes, independent of chain confirmation or maturity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramRecoveryReadiness {
	Prepared,
	Complete,
	Conditional { publication: Txid, old_position: OutPoint },
}

/// Readiness and chain progress are deliberately distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramRecoveryState {
	/// At least one ordinary ancestor still lacks its signature or unlock preimage.
	Prepared,
	/// A known unsigned hArk forfeit can only be used after the server publishes it.
	AwaitingPublication { txid: Txid },
	AwaitingConfirmation { txid: Txid },
	/// Confirmed ordinary funds cannot currently fund this transaction's CPFP.
	/// Other packages may need to confirm, or the fee wallet may need funding.
	/// These are coin-selection amounts, including the required change output.
	AwaitingFees { txid: Txid, available: Amount, needed: Amount },
	AwaitingMaturity { height: u32 },
	AwaitingTime { timestamp: u32 },
	Broadcast,
	Confirmed,
	Conflicted { spending_txid: Txid },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramRecoveryProgress {
	pub controlled_outpoint: OutPoint,
	pub claim_txid: Txid,
	pub state: ProgramRecoveryState,
}

fn outputs(template: &ProgramRecoveryTemplate, amount: Amount) -> anyhow::Result<Vec<TxOut>> {
	ensure!(!template.outputs.is_empty(), "recovery requires explicitly configured beneficiaries");
	let mut outputs = template.outputs.clone();
	let total = outputs.iter().try_fold(Amount::ZERO, |sum, out| {
		sum.checked_add(out.value).context("recovery output value overflow")
	})?;
	let remainder = amount.checked_sub(total).context("recovery outputs exceed input value")?;
	if let Some(index) = template.remainder_output {
		let output = outputs.get_mut(index).context("recovery remainder index out of range")?;
		ensure!(!output.is_p2a_fee_anchor(), "recovery remainder cannot pay the fee anchor");
		output.value = output.value.checked_add(remainder).context("recovery remainder overflow")?;
	} else {
		ensure!(remainder == Amount::ZERO, "recovery template must allocate the complete input value");
	}
	// The construction plan never substitutes a recipient or deducts a fee from it.
	if !outputs.iter().any(|out| out.is_p2a_fee_anchor()) {
		outputs.push(fee::fee_anchor());
	}
	ensure!(outputs.iter().filter(|out| out.is_p2a_fee_anchor()).count() == 1,
		"recovery requires exactly one P2A anchor");
	for output in &outputs {
		if output.is_p2a_fee_anchor() {
			ensure!(output.value == Amount::ZERO, "recovery P2A anchor must have zero value");
		} else {
			output.check_standard().context("nonstandard recovery beneficiary")?;
		}
	}
	ensure!(outputs.iter().any(|out| out.value > Amount::ZERO && !out.script_pubkey.is_op_return()),
		"recovery has no spendable beneficiary");
	Ok(outputs)
}

fn reject_key_outputs(outputs: &[TxOut], program_key: PublicKey) -> anyhow::Result<()> {
	let key = program_key.x_only_public_key().0;
	let raw = ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(key));
	let tweaked = ScriptBuf::new_p2tr(&SECP, key, None);
	let bitcoin_key = bitcoin::PublicKey::new(program_key);
	let p2pkh = ScriptBuf::new_p2pkh(&bitcoin_key.pubkey_hash());
	let p2wpkh = ScriptBuf::new_p2wpkh(&bitcoin_key.wpubkey_hash()?);
	let wrapped = p2wpkh.to_p2sh();
	for output in outputs {
		ensure!(output.script_pubkey != raw && output.script_pubkey != tweaked
			&& output.script_pubkey != p2pkh && output.script_pubkey != p2wpkh && output.script_pubkey != wrapped,
			"recovery beneficiary retains a known program-controlled key");
		for instruction in output.script_pubkey.instructions() {
			if let Instruction::PushBytes(bytes) = instruction? {
				ensure!(bytes.as_bytes() != key.serialize() && bytes.as_bytes() != program_key.serialize(),
					"recovery beneficiary directly retains a known program-controlled key");
			}
		}
	}
	Ok(())
}

fn reject_program_outputs(record: &ProgramRecoveryRecord) -> anyhow::Result<()> {
	ensure!(!record.claim.output.iter().any(|output| output.script_pubkey == record.prevout.script_pubkey),
		"recovery beneficiary retains the original program-controlled output");
	reject_key_outputs(&record.claim.output, record.program_key)
}

/// Verify exact persisted construction data, including the explicitly chosen beneficiaries.
/// This establishes authorization and immutability, not ownership of an external beneficiary.
pub fn verify_program_recovery_template(
	record: &ProgramRecoveryRecord,
	key: &SerdeProgramKey,
) -> anyhow::Result<()> {
	ensure!(key.program.public_key()? == record.program_key, "recovery descriptor key mismatch");
	ensure!(record.claim.output == outputs(&key.recovery, record.prevout.value)?,
		"recovery outputs differ from the persisted construction plan");
	ensure!(record.claim.lock_time == key.recovery.lock_time,
		"recovery locktime differs from the persisted construction plan");
	reject_program_outputs(record)
}

fn output_key(prevout: &TxOut) -> anyhow::Result<XOnlyPublicKey> {
	ensure!(prevout.script_pubkey.is_p2tr(), "recovery dependency is not Taproot");
	Ok(XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..])?)
}

fn script_number(instruction: Instruction<'_>) -> Option<u32> {
	match instruction {
		Instruction::Op(op) if (0x51..=0x60).contains(&op.to_u8()) => Some((op.to_u8() - 0x50) as u32),
		Instruction::PushBytes(bytes) => {
			let bytes = bytes.as_bytes();
			if bytes.len() > 5 || bytes.last().is_some_and(|b| b & 0x80 != 0) { return None; }
			let mut number = 0u64;
			for (i, byte) in bytes.iter().enumerate() { number |= (*byte as u64) << (8 * i); }
			u32::try_from(number).ok()
		},
		_ => None,
	}
}

/// Recognize only the native signature clauses, rebuilding their exact script bytes.
/// No general script interpreter or assumed satisfaction is involved.
fn verify_script_shape(tx: &Transaction, script: &Script, stack: &[&[u8]], key: XOnlyPublicKey)
	-> anyhow::Result<()>
{
	let sequence = tx.input[0].sequence.to_consensus_u32();
	let delta = u16::try_from(sequence).ok().map(BlockDelta::new);
	let first = script.instructions().next().transpose()?.and_then(script_number);
	let height = first.filter(|height| *height < 500_000_000).map(BlockHeight::new);
	let valid = match stack {
		[_signature] => {
			let delayed = delta.is_some_and(|delta| scripts::delayed_sign(delta, key).as_script() == script);
			let timed = height.is_some_and(|height| {
				let lock = tx.lock_time.to_consensus_u32();
				if !tx.lock_time.is_block_height() || lock < height.to_u32()
					|| tx.input[0].sequence == Sequence::MAX { return false; }
				scripts::timelock_sign(height, key).as_script() == script
					|| delta.is_some_and(|delta| scripts::delay_timelock_sign(delta, height, key).as_script() == script)
			});
			tx.version.0 >= 2 && (delayed || timed)
		},
		[_signature, preimage] if preimage.len() == 32 => {
			let hash = sha256::Hash::hash(preimage);
			scripts::hash_and_sign(hash, key).as_script() == script || scripts::hash_and_sign_v0(hash, key).as_script() == script
				|| (tx.version.0 >= 2 && delta.is_some_and(|delta| {
					scripts::hash_delay_sign(hash, delta, key).as_script() == script
						|| scripts::hash_delay_sign_v0(hash, delta, key).as_script() == script
				}))
		},
		_ => false,
	};
	ensure!(valid, "unsupported or unsatisfied recovery tapscript");
	Ok(())
}

fn verify_spend(tx: &Transaction, prevout: &TxOut, claim_key: Option<PublicKey>) -> anyhow::Result<()> {
	verify_spend_inner(tx, prevout, claim_key, None)
}

fn verify_spend_inner(tx: &Transaction, prevout: &TxOut, claim_key: Option<PublicKey>,
	unlock_hash: Option<sha256::Hash>) -> anyhow::Result<()>
{
	ensure!(tx.input.len() == 1 && tx.input[0].script_sig.is_empty(), "invalid recovery input shape");
	let stack = tx.input[0].witness.iter().collect::<Vec<_>>();
	ensure!(unlock_hash.is_none() || stack.len() == 3, "invalid saved hashlocked witness shape");
	let prevouts = [prevout];
	let mut cache = SighashCache::new(tx);
	let (signature, hash, key) = if stack.len() == 1 {
		ensure!(claim_key.is_none(), "recovery claim must use its native unilateral clause");
		ensure!(stack[0].len() == 64, "ancestor must use DEFAULT sighash");
		(schnorr::Signature::from_slice(stack[0])?,
			cache.taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)?,
			output_key(prevout)?)
	} else {
		ensure!(stack.len() == 3 || stack.len() == 4, "incomplete recovery script witness");
		ensure!(stack[0].len() == 64, "recovery must use DEFAULT sighash");
		let script = Script::from_bytes(stack[stack.len() - 2]);
		let control = ControlBlock::decode(stack[stack.len() - 1])?;
		ensure!(control.leaf_version == LeafVersion::TapScript
			&& control.verify_taproot_commitment(&SECP, output_key(prevout)?, script),
			"invalid recovery control block");
		let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
		let key = match instructions.get(instructions.len().saturating_sub(2)) {
			Some(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes())?,
			_ => bail!("missing native tapscript signing key"),
		};
		if let Some(expected) = claim_key {
			ensure!(key == expected.x_only_public_key().0, "incorrect recovery signing key");
		}
		if let Some(hash) = unlock_hash {
			ensure!(stack.len() == 3 && (script == scripts::hash_and_sign(hash, key).as_script()
				|| script == scripts::hash_and_sign_v0(hash, key).as_script()),
				"saved unlock does not match its authenticated hashlock");
		} else {
			verify_script_shape(tx, script, &stack[..stack.len() - 2], key)?;
		}
		(schnorr::Signature::from_slice(stack[0])?, cache.taproot_script_spend_signature_hash(
			0, &Prevouts::All(&prevouts), TapLeafHash::from_script(script, LeafVersion::TapScript),
			TapSighashType::Default,
		)?, key)
	};
	SECP.verify_schnorr(&signature, &hash.into(), &key).context("invalid recovery signature")?;
	Ok(())
}

fn verify_disclosure_dependency(source: &ProgramRecoveryDisclosure, hash: sha256::Hash) -> anyhow::Result<()> {
	let stack = source.hashlock.iter().collect::<Vec<_>>();
	ensure!(stack.len() == 2, "missing disclosure hashlock commitment");
	let script = Script::from_bytes(stack[0]);
	let control = ControlBlock::decode(stack[1])?;
	ensure!(control.leaf_version == LeafVersion::TapScript
		&& control.verify_taproot_commitment(&SECP, output_key(&source.prevout)?, script),
		"invalid disclosure hashlock commitment");
	let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
	let key = match instructions.get(instructions.len().saturating_sub(2)) {
		Some(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes())?,
		_ => bail!("missing disclosure signing key"),
	};
	ensure!(script == scripts::hash_and_sign(hash, key).as_script()
		|| script == scripts::hash_and_sign_v0(hash, key).as_script(),
		"disclosure dependency has a different unlock hash");
	Ok(())
}

fn recovery_disclosures(inputs: &[Vtxo<Full>], hash: sha256::Hash)
	-> anyhow::Result<Vec<ProgramRecoveryDisclosure>>
{
	inputs.iter().map(|input| {
		let context = HarkForfeitSigningContext::new(input, hash)?;
		let script = scripts::hash_and_sign(hash, input.server_pubkey().x_only_public_key().0);
		let control = context.recovery_taproot().control_block(&(script.clone(), LeafVersion::TapScript))
			.context("missing forfeit disclosure clause")?;
		Ok(ProgramRecoveryDisclosure { outpoint: context.recovery_outpoint(),
			prevout: context.recovery_txout().clone(),
			hashlock: Witness::from_slice(&[script.as_bytes(), &control.serialize()]) })
	}).collect()
}

fn verify_record(record: &ProgramRecoveryRecord, require_complete: bool) -> anyhow::Result<()> {
	ensure!(record.claim.version == transaction::Version(3), "recovery claim must be v3");
	ensure!(record.claim.input.len() == 1
		&& record.claim.input[0].previous_output == record.controlled_outpoint,
		"recovery claim outpoint mismatch");
	ensure!(record.claim.input[0].sequence.to_consensus_u32() <= u16::MAX as u32,
		"recovery requires native block-based CSV");
	let total = record.claim.output.iter().try_fold(Amount::ZERO, |sum, out| {
		sum.checked_add(out.value).context("recovery value overflow")
	})?;
	ensure!(total == record.prevout.value && total <= Amount::MAX_MONEY,
		"recovery claim must preserve the configured value and use external fees");
	ensure!(record.claim.output.iter().filter(|out| out.is_p2a_fee_anchor()).count() == 1,
		"recovery claim needs one external-fee anchor");
	for output in &record.claim.output {
		if output.is_p2a_fee_anchor() {
			ensure!(output.value == Amount::ZERO, "nonzero recovery anchor");
		} else {
			output.check_standard().context("nonstandard recovery output")?;
		}
	}
	reject_program_outputs(record)?;
	verify_spend(&record.claim, &record.prevout, Some(record.program_key))?;
	let mut point = record.chain_anchor;
	let mut prevout = &record.chain_anchor_prevout;
	let mut seen = HashSet::new();
	for (index, ancestor) in record.ancestors.iter().enumerate() {
		let txid = ancestor.compute_txid();
		ensure!(seen.insert(txid), "duplicate recovery ancestor");
		ensure!(ancestor.version == transaction::Version(3) && ancestor.input.len() == 1
			&& ancestor.input[0].previous_output == point && ancestor.input[0].script_sig.is_empty()
			&& ancestor.lock_time == bitcoin::absolute::LockTime::ZERO
			&& (ancestor.input[0].sequence == Sequence::ZERO || ancestor.input[0].sequence == Sequence::MAX),
			"missing or out-of-order native recovery ancestor");
		if ancestor.input[0].witness.is_empty() {
			ensure!(!require_complete, "recovery ancestor {txid} is incomplete");
		} else {
			verify_spend(ancestor, prevout, None)?;
		}
		let amount = ancestor.output.iter().try_fold(Amount::ZERO, |sum, out| {
			sum.checked_add(out.value).context("ancestor output value overflow")
		})?;
		ensure!(amount <= prevout.value, "ancestor creates value");
		ensure!(ancestor.output.iter().filter(|out| out.is_p2a_fee_anchor()).count() == 1,
			"recovery ancestor needs one external-fee anchor");
		for output in &ancestor.output {
			if !output.is_p2a_fee_anchor() {
				output.check_standard().context("nonstandard recovery ancestor output")?;
			}
		}
		point = match record.ancestors.get(index + 1) {
			Some(next) => next.input.first().context("empty recovery ancestor")?.previous_output,
			None => record.controlled_outpoint,
		};
		ensure!(point.txid == txid, "unrelated transaction in recovery ancestry");
		prevout = ancestor.output.get(point.vout as usize).context("recovery ancestor output missing")?;
	}
	ensure!(point == record.controlled_outpoint && prevout == &record.prevout,
		"recovery ancestry does not produce the claim prevout");
	let mut unlocks = HashSet::new();
	for unlock in &record.unlocks {
		ensure!(unlocks.insert(unlock.ancestor), "duplicate recovery unlock");
		let (index, ancestor) = record.ancestors.iter().enumerate()
			.find(|(_, tx)| tx.compute_txid() == unlock.ancestor).context("unrelated recovery unlock")?;
		let prevout = ancestor_prevout(record, index)?;
		let mut signed = ancestor.clone();
		signed.input[0].witness = unlock.witness.clone();
		verify_spend_inner(&signed, prevout, None, Some(unlock.hash))?;
		for disclosure in &unlock.disclosures {
			verify_disclosure_dependency(disclosure, unlock.hash)?;
		}
	}
	Ok(())
}

/// Independently verify a recipient's exact recovery claim and its native VTXO ancestry.
/// `false` permits unsigned ancestor templates, never an unsigned terminal claim.
pub fn verify_program_recovery(
	vtxo: &Vtxo<Full>, record: &ProgramRecoveryRecord, require_complete: bool,
) -> anyhow::Result<()> {
	verify_record(record, require_complete)?;
	ensure!(record.controlled_outpoint == vtxo.point() && record.program_key == vtxo.user_pubkey()
		&& record.prevout == vtxo.txout() && record.chain_anchor == vtxo.chain_anchor()
		&& record.chain_anchor_prevout == vtxo.chain_anchor_txout().context("invalid chain anchor")?,
		"recovery does not match VTXO");
	let expected = vtxo.transactions().collect::<Vec<_>>();
	ensure!(expected.len() == record.ancestors.len(), "incomplete VTXO recovery ancestry");
	for (expected, saved) in expected.iter().zip(&record.ancestors) {
		ensure!(expected.tx.compute_txid() == saved.compute_txid(), "incorrect VTXO recovery ancestor");
		// Commit first checks the saved unsigned template against the now-signed
		// VTXO, then persists its verified witnesses. Never replace a saved signature.
		if !expected.tx.input[0].witness.is_empty() && !saved.input[0].witness.is_empty() {
			ensure!(expected.tx.input[0].witness == saved.input[0].witness,
				"recovery ancestor differs from completed VTXO");
		}
	}
	let leaf = record.claim.input.first().and_then(|input| input.witness.taproot_leaf_script())
		.context("missing recovery tapscript")?;
	ensure!(leaf.version == LeafVersion::TapScript, "unsupported recovery leaf version");
	let script = leaf.script;
	let clause = vtxo.policy().clauses(vtxo.exit_delta(), vtxo.expiry_height(), vtxo.server_pubkey())
		.into_iter().find(|clause| clause.pubkey() == vtxo.user_pubkey() && clause.tapscript().as_script() == script)
		.context("recovery does not use the VTXO user's unilateral clause")?;
	ensure!(record.claim.input[0].sequence == clause.sequence().unwrap_or(Sequence::ZERO),
		"recovery claim sequence differs from native clause");
	Ok(())
}

fn claim_transaction(point: OutPoint, amount: Amount, clause: &VtxoClause, template: &ProgramRecoveryTemplate)
	-> anyhow::Result<Transaction>
{
	Ok(Transaction {
		version: transaction::Version(3), lock_time: template.lock_time,
		input: vec![TxIn { previous_output: point, script_sig: ScriptBuf::new(),
			sequence: clause.sequence().unwrap_or(Sequence::ZERO), witness: Witness::new() }],
		output: outputs(template, amount)?,
	})
}

fn signing_input(tx: Transaction, prevout: TxOut, tree: &TaprootSpendInfo,
	clause: &VtxoClause, key: &SerdeProgramKey) -> anyhow::Result<SigningInput>
{
	let script = clause.tapscript();
	let control = tree.control_block(&(script.clone(), LeafVersion::TapScript))
		.context("recovery clause not in native Taproot tree")?;
	let mut psbt = Psbt::from_unsigned_tx(tx)?;
	psbt.inputs[0].witness_utxo = Some(prevout);
	psbt.inputs[0].tap_internal_key = Some(tree.internal_key());
	psbt.inputs[0].tap_merkle_root = tree.merkle_root();
	psbt.inputs[0].tap_scripts.insert(control, (script.clone(), LeafVersion::TapScript));
	let input = SigningInput { psbt, input_index: 0,
		script_leaf: Some(TapLeafHash::from_script(&script, LeafVersion::TapScript)),
		participants: vec![key.program.user_pubkey, key.program.program_pubkey()?], tweak: None };
	input.sighash()?;
	Ok(input)
}

/// Acquire only the existing actors' guards. Nonblocking acquisition means
/// cross-actor dependency cycles cannot deadlock: a contended recovery retries
/// from a fresh snapshot instead of waiting while retaining another actor.
pub(crate) async fn lock_recovery_actors(
	locks: &dyn crate::lock_manager::LockManager,
	actors: &BTreeMap<String, String>,
	already_guarded_action: Option<&str>,
) -> anyhow::Result<Vec<Box<dyn crate::lock_manager::LockGuard>>> {
	let mut guards = Vec::with_capacity(actors.len());
	for (actor, lock) in actors {
		if already_guarded_action.is_some_and(|id| *actor == recovery_action_key(id)) { continue; }
		guards.push(locks.try_lock(lock).await
			.with_context(|| format!("recovery actor {lock} is active; retry after it parks"))?);
	}
	Ok(guards)
}

impl Wallet {
	/// Reload saved successor bytes while holding the owning actors' ordinary
	/// guards. This is deliberately not preparation: missing authorization stays
	/// missing, and neither the Ark server nor the program service is contacted.
	async fn merge_saved_recovery_outputs(&self, outputs: &[&Vtxo<Full>], committed: bool) -> anyhow::Result<()> {
		let mut records = Vec::new();
		for vtxo in outputs {
			let Some(mut record) = self.inner.db.get_program_recovery(vtxo.point()).await? else {
				ensure!(!committed || self.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_none(),
					"saved program successor has no authorized recovery claim");
				continue;
			};
			record.ancestors = vtxo.transactions().map(|item| item.tx).collect();
			retain_unlock_witness(vtxo, &mut record);
			verify_program_recovery(vtxo, &record, false)?;
			records.push(record);
		}
		self.inner.db.store_program_recoveries(&records).await
	}

	async fn retain_native_recovery(
		&self, vtxo: &Vtxo<Full>, native: &mut HashMap<OutPoint, Vtxo<Full>>,
	) -> anyhow::Result<()> {
		if vtxo.has_all_witnesses()
			&& self.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_none()
			&& self.inner.db.get_public_key_idx(&vtxo.user_pubkey()).await?.is_some()
		{
			native.entry(vtxo.point()).or_insert_with(|| vtxo.clone());
		}
		Ok(())
	}

	/// A checkpoint is not ownership of outputs it already released. Historical
	/// inputs remain ancestry guards, not a route into their other successors.
	async fn recovery_position_is_pending(
		&self, point: OutPoint, actor: &str, action: Option<&str>,
		movement: Option<crate::movement::MovementId>,
	) -> anyhow::Result<bool> {
		Ok(match self.inner.db.get_wallet_vtxo(point.into()).await?.map(|v| v.state) {
			None | Some(VtxoState::Locked { holder: None }) => true,
			Some(VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id }) }) =>
				action == Some(id.as_str()),
			Some(VtxoState::Locked { holder: Some(VtxoLockHolder::Movement { id }) }) =>
				movement == Some(id),
			Some(VtxoState::Exited) =>
				self.inner.db.has_program_recovery_reservation(actor).await?
					&& self.inner.db.has_program_recovery_reservation(&recovery_target_key(point.into())).await?,
			Some(VtxoState::Spent | VtxoState::Spendable) => false,
		})
	}

	/// Discover only actors touching the selected branches. The second discovery
	/// after acquisition detects an actor introduced while guards were acquired;
	/// the final exact-state transaction closes the remaining coin-selection race.
	async fn recovery_actors(&self, points: &mut HashSet<OutPoint>)
		-> anyhow::Result<BTreeMap<String, String>>
	{
		let mut actors = BTreeMap::new();
		let checkpoints = self.inner.db.get_all_wallet_action_checkpoints().await?;
		let records = self.inner.db.list_program_recoveries().await?;
		let mut receive_keys = HashMap::new();
		for checkpoint in &checkpoints {
			if let crate::actions::WalletActionCheckpoint::LightningReceive(recv) = checkpoint {
				if let Some(key) = self.inner.db.get_program_key_by_index(recv.key_index).await? {
					receive_keys.insert(checkpoint.id(), key.program.public_key()?);
				}
			}
		}
		let mut rounds = Vec::new();
		for id in self.inner.db.get_pending_round_state_ids().await? {
			if let Some(round) = self.inner.db.get_round_state_by_id(id).await? { rounds.push(round); }
		}
		loop {
			let before = points.len();
			let keys = records.iter().filter(|r| points.contains(&r.controlled_outpoint))
				.map(|r| r.program_key).collect::<HashSet<_>>();
			for checkpoint in &checkpoints {
				let (ids, _) = checkpoint.recovery_positions();
				let id = checkpoint.id();
				let actor = recovery_action_key(&id);
				let mut active = Vec::new();
				for point in ids.iter().map(|id| id.to_point()) {
					if self.recovery_position_is_pending(point, &actor, Some(&id),
						checkpoint.recovery_movement_id()).await?
					{ active.push(point); }
				}
				if active.iter().any(|point| points.contains(point))
					|| receive_keys.get(&id).is_some_and(|key| keys.contains(key))
				{
					actors.insert(actor, id);
					points.extend(active);
				}
			}
			for round in &rounds {
				let state = round.state();
				let id = round.id();
				let actor = recovery_round_key(id);
				let mut active = Vec::new();
				for vtxo in state.participation.inputs.iter().chain(&state.new_vtxos) {
					if self.recovery_position_is_pending(vtxo.point(), &actor, None, state.movement_id).await? {
						active.push(vtxo.point());
					}
				}
				if active.iter().any(|point| points.contains(point))
					|| state.participation.outputs.iter().any(|output| keys.contains(&output.policy.user_pubkey()))
				{
					actors.insert(actor, format!("{}.round.{}", self.fingerprint(), id));
					points.extend(active);
				}
			}
			if points.len() == before { break; }
		}
		// Board preparation already holds this exact guard before its first
		// recovery record exists, but the board checkpoint is written only after
		// cosigning. The authenticated funding outpoint bridges that crash gap.
		for record in &records {
			if points.contains(&record.controlled_outpoint) {
				let id = crate::actions::board::board_action_id(record.chain_anchor);
				actors.insert(recovery_action_key(&id), id);
			}
		}
		for point in points.iter() {
			if let Some(vtxo) = self.inner.db.get_wallet_vtxo((*point).into()).await? {
				if let VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id }) } = vtxo.state {
					actors.insert(recovery_action_key(&id), id);
				}
			}
		}
		Ok(actors)
	}

	async fn guarded_recovery_bundle(
		&self,
		outpoints: &[OutPoint],
		already_guarded_action: Option<&str>,
		reserve: bool,
	) -> anyhow::Result<ProgramRecoveryBundle> {
		// Include incomplete candidates and their old inputs during discovery.
		// An unsigned candidate is not a reason to abandon an otherwise usable
		// old position in a process that cannot reach either cosigner.
		let initial = self.select_program_recovery_bundle(
			(!outpoints.is_empty()).then_some(outpoints), &HashSet::new(),
		).await?;
		let mut points = initial.targets.iter().copied().collect::<HashSet<_>>();
		points.extend(outpoints.iter().copied());
		if outpoints.is_empty() {
			// Resume takeover cleanup even when its only program input has been
			// superseded by a saved native output in the same stopped actor.
			for record in self.inner.db.list_program_recoveries().await? {
				if self.inner.db.has_program_recovery_reservation(
					&recovery_vtxo_key(record.controlled_outpoint.into()),
				).await? {
					points.insert(record.controlled_outpoint);
				}
			}
		}
		let actors = self.recovery_actors(&mut points).await?;
		let _guards = lock_recovery_actors(
			self.inner.lock_manager.as_ref(), &actors, already_guarded_action,
		).await?;

		let mut superseded = HashSet::new();
		let mut legacy_locks = HashMap::<OutPoint, HashSet<Option<crate::movement::MovementId>>>::new();
		let mut native = HashMap::new();
		for checkpoint in self.inner.db.get_all_wallet_action_checkpoints().await? {
			let id = checkpoint.id();
			let actor = recovery_action_key(&id);
			if !actors.contains_key(&actor) { continue; }
			let (ids, outputs) = checkpoint.recovery_positions();
			self.merge_saved_recovery_outputs(&outputs, true).await?;
			superseded.extend(checkpoint.recovery_consumed_inputs().iter().map(|id| id.to_point()));
			if let Some(movement) = checkpoint.recovery_movement_id() {
				for id in &ids { legacy_locks.entry(id.to_point()).or_default().insert(Some(movement)); }
			}
			for output in &outputs { legacy_locks.entry(output.point()).or_default().insert(None); }
			for point in ids.iter().map(|id| id.to_point()) {
				if self.recovery_position_is_pending(point, &actor,
					Some(&id), checkpoint.recovery_movement_id()).await?
				{ points.insert(point); }
			}
			// Complete successors (including somebody else's payment) win over
			// historical input claims even before inventory marks inputs Spent.
			for vtxo in outputs.iter() {
				if !vtxo.has_all_witnesses() { continue; }
				if reserve && points.contains(&vtxo.point()) {
					self.retain_native_recovery(vtxo, &mut native).await?;
				}
				for item in vtxo.transactions() {
					superseded.extend(item.tx.input.iter().map(|i| i.previous_output));
				}
			}
		}
		for id in self.inner.db.get_pending_round_state_ids().await? {
			let actor = recovery_round_key(id);
			if !actors.contains_key(&actor) { continue; }
			let Some(round) = self.inner.db.get_round_state_by_id(id).await? else { continue; };
			let state = round.state();
			for vtxo in state.participation.inputs.iter().chain(&state.new_vtxos) {
				legacy_locks.entry(vtxo.point()).or_default().insert(state.movement_id);
				if self.recovery_position_is_pending(vtxo.point(), &actor, None, state.movement_id).await? {
					points.insert(vtxo.point());
				}
				if reserve && points.contains(&vtxo.point()) {
					self.retain_native_recovery(vtxo, &mut native).await?;
				}
			}
			let committed = state.sent_forfeit_sigs || state.forfeit_bundles.is_none()
				|| state.forfeit_bundles.as_ref().is_some_and(|bundles| !bundles.is_empty());
			self.merge_saved_recovery_outputs(&state.new_vtxos.iter().collect::<Vec<_>>(), committed).await?;
			if !state.new_vtxos.is_empty() && state.new_vtxos.iter().all(|v| v.has_all_witnesses()) {
				superseded.extend(state.participation.inputs.iter().map(|v| v.point()));
			}
		}
		// Expand explicit in-flight selection to its actor's saved recovery
		// positions. This preserves old/conditional fallback and signed change.
		let selection = if outpoints.is_empty() { Vec::new() } else {
			self.inner.db.list_program_recoveries().await?.into_iter()
				.filter(|r| points.contains(&r.controlled_outpoint))
				.map(|r| r.controlled_outpoint).collect()
		};
		let bundle = self.select_program_recovery_bundle(
			(!outpoints.is_empty()).then_some(selection.as_slice()), &superseded,
		).await?;
		// Ancestry is reserved below, never promoted into actor selection. Shared
		// spent history must not select an unrelated live sibling.
		let current_actors = self.recovery_actors(&mut points).await?;
		ensure!(current_actors.keys().all(|actor| actors.contains_key(actor)),
			"recovery ownership changed while acquiring guards; retry");
		let target_reservations = points.iter().map(|point| recovery_target_key((*point).into())).collect::<Vec<_>>();
		points.extend(recovery_points(&bundle));
		if reserve {
			// A round's old inputs are not ancestors of its new funding root.
			// Reserve the complete affected actor scope, not only claim ancestry.
			let mut expected = Vec::with_capacity(points.len());
			for point in points {
				let state = self.inner.db.get_wallet_vtxo(point.into()).await?.map(|v| v.state);
				if bundle.targets.contains(&point) {
					ensure!(state != Some(VtxoState::Spent) || self.inner.db.has_program_recovery_reservation(
						&recovery_vtxo_key(point.into()),
					).await?,
						"refusing to recover a position already transferred by this wallet");
				}
				if let Some(VtxoState::Locked { holder }) = &state {
					let covered = match holder {
						Some(VtxoLockHolder::Action { id }) => actors.contains_key(&recovery_action_key(id)),
						Some(VtxoLockHolder::Movement { id }) =>
							legacy_locks.get(&point).is_some_and(|owners| owners.contains(&Some(*id))),
						None => legacy_locks.get(&point).is_some_and(|owners| owners.contains(&None)),
					};
					ensure!(covered, "recovery input {point} has an unaccounted reservation");
				}
				if state != Some(VtxoState::Spent) && !superseded.contains(&point) {
					if let Some(vtxo) = self.inner.db.get_full_vtxo(point.into()).await? {
						self.retain_native_recovery(&vtxo, &mut native).await?;
					}
				}
				expected.push((point.into(), state));
			}
			let mut reservations = actors.keys().cloned().collect::<Vec<_>>();
			reservations.extend(target_reservations);
			reservations.extend(superseded.iter().map(|point| recovery_superseded_key((*point).into())));
			self.inner.db.reserve_program_recovery(&expected, &reservations).await?;
			// Mixed actors retain their ordinary native recovery instead of
			// stranding native change behind a permanently stopped checkpoint.
			// No program position ever enters the native signing fallback.
			native.retain(|point, _| !superseded.contains(point));
			for vtxo in native.values() {
				self.inner.db.store_vtxos(&[(vtxo, &VtxoState::Exited)]).await?;
			}
			if !native.is_empty() {
				self.inner.exit.start_exit_for_vtxos(
					&native.values().map(|v| v.to_bare()).collect::<Vec<_>>(),
				).await?;
			}
		}
		// Actor tombstones now prevent every future drive, including a snapshot
		// loaded before this takeover. Guards may be released before chain I/O.
		Ok(bundle)
	}

	async fn verify_recovery_terminals(&self, records: &[ProgramRecoveryRecord]) -> anyhow::Result<()> {
		if records.is_empty() { return Ok(()); }
		let keys = self.inner.db.list_program_keys().await?;
		let saved = self.inner.db.list_program_recoveries().await?;
		for record in records {
			for key in &keys {
				reject_key_outputs(&record.claim.output, key.program.public_key()?)?;
			}
			for output in &record.claim.output {
				ensure!(!saved.iter().chain(records).any(|known| known.prevout.script_pubkey == output.script_pubkey),
					"terminal recovery pays a known program-controlled output");
			}
		}
		Ok(())
	}

	/// Preauthorize immutable claims before releasing any irreversible transition signature.
	pub async fn prepare_program_recoveries(&self, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		let mut records = Vec::new();
		for vtxo in vtxos {
			let Some(key) = self.signing_key(&vtxo.user_pubkey()).await? else { continue; };
			let Some(program) = key.program() else { continue; };
			let mut record = if let Some(record) = self.inner.db.get_program_recovery(vtxo.point()).await? {
				verify_program_recovery_template(&record, program)?;
				verify_record(&record, false)?;
				record
			} else {
				let clause = vtxo.policy().clauses(vtxo.exit_delta(), vtxo.expiry_height(), vtxo.server_pubkey())
					.into_iter().find(|clause| clause.pubkey() == vtxo.user_pubkey())
					.context("program output has no unilateral recovery clause")?;
				let tx = claim_transaction(vtxo.point(), vtxo.amount(), &clause, &program.recovery)?;
				let claim = self.authorize_recovery_claim(&key, tx, vtxo.txout(), &vtxo.output_taproot(), &clause).await?;
				ProgramRecoveryRecord { controlled_outpoint: vtxo.point(), program_key: vtxo.user_pubkey(),
					claim, prevout: vtxo.txout(), ancestors: Vec::new(), chain_anchor: vtxo.chain_anchor(),
					chain_anchor_prevout: vtxo.chain_anchor_txout().context("invalid recovery root")?,
					unlocks: Vec::new() }
			};
			record.ancestors = vtxo.transactions().map(|item| item.tx).collect();
			retain_unlock_witness(vtxo, &mut record);
			verify_program_recovery_template(&record, program)?;
			verify_program_recovery(vtxo, &record, false)?;
			records.push(record);
		}
		if records.is_empty() { return Ok(()); }
		self.verify_recovery_terminals(&records).await?;
		self.inner.db.store_program_recoveries(&records).await
	}

	async fn authorize_recovery_claim(&self, key: &VtxoSigningKey, tx: Transaction, prevout: TxOut,
		tree: &TaprootSpendInfo, clause: &VtxoClause) -> anyhow::Result<Transaction>
	{
		let program = key.program().context("not a program key")?;
		let input = signing_input(tx, prevout, tree, clause, program)?;
		let control = tree.control_block(&(clause.tapscript(), LeafVersion::TapScript))
			.context("missing recovery control block")?;
		let preimage_hash = match clause {
			VtxoClause::HashDelaySign(c) => Some(c.hash),
			VtxoClause::HashDelaySign_v0(c) => Some(c.hash),
			_ => None,
		};
		let preimage = match preimage_hash {
			Some(hash) => Some(self.lightning_receive_preimage(hash.into()).await?
				.context("missing Lightning recovery preimage")?.to_byte_array()),
			None => None,
		};
		// Fail local timelock constraints before asking the generic program to authorize.
		let mut shape = vec![&[][..]];
		if let Some(preimage) = &preimage { shape.push(&preimage[..]); }
		verify_script_shape(&input.psbt.unsigned_tx, &clause.tapscript(), &shape,
			key.public_key().x_only_public_key().0)?;
		let mut tx = input.psbt.unsigned_tx.clone();
		let signature = self.sign_program_claim(key, input, program.recovery.witness.clone()).await?;
		tx.input[0].witness = match clause {
			VtxoClause::DelayedSign(c) => c.witness(&signature, &control),
			VtxoClause::DelayedTimelockSign(c) => c.witness(&signature, &control),
			VtxoClause::TimelockSign(c) => c.witness(&signature, &control),
			VtxoClause::HashDelaySign(c) => c.witness(&(signature, preimage.context("missing preimage")?), &control),
			VtxoClause::HashDelaySign_v0(c) => c.witness(&(signature, preimage.context("missing preimage")?), &control),
			_ => bail!("unsupported program recovery clause"),
		};
		Ok(tx)
	}

	/// Complete the durable guard. This never creates or re-signs a missing claim.
	pub async fn ensure_program_recoveries(&self, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		let mut records = Vec::new();
		for vtxo in vtxos {
			let Some(program) = self.inner.db.get_program_key(&vtxo.user_pubkey()).await? else { continue; };
			let mut record = self.inner.db.get_program_recovery(vtxo.point()).await?
				.context("program recovery must be prepared before commitment")?;
			verify_program_recovery_template(&record, &program)?;
			verify_record(&record, false)?;
			record.ancestors = vtxo.transactions().map(|item| item.tx).collect();
			retain_unlock_witness(vtxo, &mut record);
			verify_program_recovery(vtxo, &record, true)?;
			records.push(record);
		}
		if records.is_empty() { return Ok(()); }
		self.verify_recovery_terminals(&records).await?;
		self.inner.db.store_program_recoveries(&records).await?;
		for record in records {
			let saved = self.inner.db.get_program_recovery(record.controlled_outpoint).await?
				.context("durable recovery disappeared")?;
			verify_record(&saved, true)?;
			ensure!(saved == record, "durable recovery differs from verified final chain");
		}
		Ok(())
	}

	/// Save a conditional hArk branch while retaining the complete old position.
	pub async fn prepare_hark_recovery(&self, vtxo: &Vtxo<Full>, context: &HarkForfeitSigningContext)
		-> anyhow::Result<()>
	{
		let Some(key) = self.signing_key(&vtxo.user_pubkey()).await? else { return Ok(()); };
		let Some(program) = key.program() else { return Ok(()); };
		self.ensure_program_recoveries(std::slice::from_ref(vtxo)).await?;
		ensure!(context.unsigned_parent().input.len() == 1
			&& context.unsigned_parent().input[0].previous_output == vtxo.point()
			&& context.recovery_clause().pubkey == vtxo.user_pubkey()
			&& context.signing_input().psbt.inputs.first().and_then(|input| input.witness_utxo.as_ref()) == Some(&vtxo.txout())
			&& context.recovery_txout().value == vtxo.amount(), "hArk recovery context mismatch");
		context.signing_input().sighash()?;
		let mut record = if let Some(record) = self.inner.db.get_program_recovery(context.recovery_outpoint()).await? {
			verify_program_recovery_template(&record, program)?;
			verify_record(&record, false)?;
			record
		} else {
			let clause = VtxoClause::DelayedSign(context.recovery_clause().clone());
			let tx = claim_transaction(context.recovery_outpoint(), context.recovery_txout().value,
				&clause, &program.recovery)?;
			let claim = self.authorize_recovery_claim(&key, tx, context.recovery_txout().clone(),
				context.recovery_taproot(), &clause).await?;
			ProgramRecoveryRecord { controlled_outpoint: context.recovery_outpoint(), program_key: key.public_key(),
				claim, prevout: context.recovery_txout().clone(), ancestors: Vec::new(),
				chain_anchor: vtxo.chain_anchor(),
				chain_anchor_prevout: vtxo.chain_anchor_txout().context("invalid hArk recovery root")?,
				unlocks: Vec::new() }
		};
		ensure!(record.prevout == *context.recovery_txout(), "changed hArk fallback prevout");
		record.ancestors = vtxo.transactions().map(|item| item.tx).collect();
		record.ancestors.push(context.unsigned_parent().clone());
		verify_program_recovery_template(&record, program)?;
		verify_record(&record, false)?;
		self.verify_recovery_terminals(std::slice::from_ref(&record)).await?;
		self.inner.db.store_program_recoveries(&[record]).await
	}

	/// Persist disclosure links before sending any forfeit share. The signed
	/// replacement witness itself is authenticated against its native ancestry.
	///
	/// Every replacement output, native leaf or program-bound, must be locked
	/// under the same unlock hash the input forfeits commit to. The server
	/// earns the forfeit claim only by revealing that hash's preimage, and
	/// the same preimage is the only way to unlock the replacement. This is
	/// the last check before any forfeit share escapes, so it is enforced
	/// even for native outputs that carry no program recovery record.
	pub(crate) async fn preserve_hark_unlocks(
		&self, outputs: &[Vtxo<Full>], inputs: &[Vtxo<Full>], hash: sha256::Hash,
	) -> anyhow::Result<()> {
		let disclosures = recovery_disclosures(inputs, hash)?;
		let mut records = Vec::new();
		for vtxo in outputs {
			ensure!(vtxo.unlock_hash() == Some(hash),
				"replacement VTXO {} is not locked under the forfeit unlock hash",
				vtxo.id(),
			);
			let Some(mut record) = self.inner.db.get_program_recovery(vtxo.point()).await? else { continue; };
			retain_unlock_witness(vtxo, &mut record);
			let unlock = record.unlocks.iter_mut().find(|unlock| unlock.ancestor == vtxo.point().txid)
				.context("signed replacement is missing its recovery unlock")?;
			ensure!(unlock.hash == hash, "replacement unlock hash differs from input forfeits");
			unlock.disclosures = disclosures.clone();
			verify_program_recovery(vtxo, &record, false)?;
			records.push(record);
		}
		self.inner.db.store_program_recoveries(&records).await
	}

	/// Export verified claims and saved ancestors under the affected actors' guards.
	/// Empty selection chooses live or already-taken-over positions, including
	/// durable crash-gap outputs. Explicit selection expands to the affected
	/// actor's successor/fallback positions; it never selects a superseded claim.
	/// Prepared records remain explicitly incomplete; exporting does not make them
	/// ready or stop future signing. Stop other wallets before standalone replay.
	pub async fn program_recovery_bundle(&self, outpoints: &[OutPoint]) -> anyhow::Result<ProgramRecoveryBundle> {
		self.guarded_recovery_bundle(outpoints, None, false).await
	}

	async fn select_program_recovery_bundle(&self, selection: Option<&[OutPoint]>, handed_off: &HashSet<OutPoint>)
		-> anyhow::Result<ProgramRecoveryBundle>
	{
		let records = self.inner.db.list_program_recoveries().await?;
		let outpoints = selection.unwrap_or_default();
		let mut targets = outpoints.iter().copied().collect::<HashSet<_>>();
		ensure!(targets.iter().all(|point| records.iter().any(|r| r.controlled_outpoint == *point)),
			"unknown program recovery outpoint");
		let states = self.inner.db.get_all_vtxos().await?.into_iter()
			.map(|vtxo| (vtxo.point(), vtxo.state.kind())).collect::<HashMap<_, _>>();
		let mut unavailable = HashSet::new();
		for record in &records {
			let point = record.controlled_outpoint;
			if states.get(&point) == Some(&VtxoStateKind::Spent)
				&& !self.inner.db.has_program_recovery_reservation(&recovery_vtxo_key(point.into())).await?
			{
				unavailable.insert(point);
			}
			if self.inner.db.has_program_recovery_reservation(&recovery_superseded_key(point.into())).await? {
				unavailable.insert(point);
			}
		}
		if selection.is_none() {
			targets.extend(records.iter().map(|r| r.controlled_outpoint));
		}
		let complete = records.iter().filter(|r| verify_record(r, true).is_ok()).collect::<Vec<_>>();
		let conditional_parents = records.iter().filter_map(|record| {
			conditional_old(record, &records).map(|old| (record.controlled_outpoint, old.controlled_outpoint))
		}).collect::<HashMap<_, _>>();
		// Explicit requests also follow fully signed successors. A caller naming
		// an old point must never cause recovery to replay a stale conflicting claim.
		loop {
			let before = targets.len();
			for record in &complete {
				if record.ancestors.iter()
					.any(|tx| tx.input.iter().any(|i| targets.contains(&i.previous_output)))
				{
					targets.insert(record.controlled_outpoint);
				}
			}
			for (point, old) in &conditional_parents {
				if targets.contains(old) { targets.insert(*point); }
			}
			if targets.len() == before { break; }
		}
		let superseded = complete.iter()
			.flat_map(|r| r.ancestors.iter().flat_map(|tx| tx.input.iter().map(|i| i.previous_output)))
			.chain(handed_off.iter().copied()).collect::<HashSet<_>>();
		targets.retain(|point| !superseded.contains(point) && !unavailable.contains(point));
		for (point, old) in &conditional_parents {
			if superseded.contains(old) || unavailable.contains(old) {
				targets.remove(point);
			}
		}
		let mut wanted = targets.clone();
		loop {
			let before = wanted.len();
			for (point, old) in &conditional_parents {
				if wanted.contains(point) {
					wanted.insert(*old);
					// The old branch remains the actual recovery until publication.
					targets.insert(*old);
				}
			}
			if wanted.len() == before { break; }
		}
		let recoveries = records.into_iter().filter(|record| wanted.contains(&record.controlled_outpoint))
			.collect::<Vec<_>>();
		let targets = recoveries.iter().filter(|record| targets.contains(&record.controlled_outpoint))
			.map(|record| record.controlled_outpoint).collect();
		let bundle = ProgramRecoveryBundle { version: 1, network: self.chain().network(), targets,
			keys: self.inner.db.list_program_keys().await?, recoveries };
		bundle.verify()?;
		Ok(bundle)
	}

	/// Advance saved immutable recovery by one chain step without contacting either cosigner.
	pub async fn recover_program_vtxos(&self, outpoints: &[OutPoint], fee_rate: Option<FeeRate>)
		-> anyhow::Result<Vec<ProgramRecoveryProgress>>
	{
		self.recover_program_vtxos_inner(outpoints, fee_rate, None).await
	}

	/// The caller holds this exact action's normal driver guard. This separate
	/// entry point avoids trying to acquire it recursively during HTLC fallback.
	/// Takeover still tombstones the action: subsequent drives cannot sign again.
	pub(crate) async fn recover_program_vtxos_with_action_guard(
		&self, outpoints: &[OutPoint], fee_rate: Option<FeeRate>, action_id: &str,
	) -> anyhow::Result<Vec<ProgramRecoveryProgress>> {
		self.recover_program_vtxos_inner(outpoints, fee_rate, Some(action_id)).await
	}

	/// Resume only permanent recovery takeovers, never select fresh spendable
	/// inventory. Actor checkpoints remain available for native crash-gap exits.
	pub(crate) async fn continue_program_recovery(&self) -> anyhow::Result<()> {
		let points = self.reserved_program_recovery_points().await?;
		for point in points {
			match self.recover_program_vtxos(&[point], None).await {
				Ok(progress) => for position in progress {
					if let ProgramRecoveryState::AwaitingFees { txid, available, needed } = position.state {
						log::warn!("Program recovery for {} needs confirmed external fees for {txid}: \
							{available} available, {needed} needed", position.controlled_outpoint);
					} else {
						log::debug!("Program recovery for {}: {:?}", position.controlled_outpoint, position.state);
					}
				},
				Err(error) => log::warn!("Unable to continue program recovery for {point}: {error:#}"),
			}
		}
		Ok(())
	}

	pub(crate) async fn reserved_program_recovery_points(&self) -> anyhow::Result<Vec<OutPoint>> {
		let mut points = Vec::new();
		for record in self.inner.db.list_program_recoveries().await? {
			if self.inner.db.has_program_recovery_reservation(
				&recovery_target_key(record.controlled_outpoint.into()),
			).await? {
				points.push(record.controlled_outpoint);
			}
		}
		Ok(points)
	}

	/// Chain-only accounting for already selected recovery branches. Unsigned
	/// alternatives do not add value; a confirmed payout has left this balance.
	pub(crate) async fn pending_program_recovery_balance(&self) -> anyhow::Result<Amount> {
		let selection = self.reserved_program_recovery_points().await?;
		if selection.is_empty() { return Ok(Amount::ZERO); }
		let mut superseded = HashSet::new();
		let records = self.inner.db.list_program_recoveries().await?;
		let mut native = HashMap::new();
		for id in self.inner.db.get_pending_round_state_ids().await? {
			if !self.inner.db.has_program_recovery_reservation(&recovery_round_key(id)).await? { continue; }
			let Some(round) = self.inner.db.get_round_state_by_id(id).await? else { continue; };
			let state = round.state();
			let mut ready = !state.new_vtxos.is_empty();
			for vtxo in &state.new_vtxos {
				let available = if vtxo.has_all_witnesses() {
					true
				} else if let Some(record) = records.iter().find(|r| r.controlled_outpoint == vtxo.point()) {
					recovery_witnesses_available(record, self.chain()).await?
				} else if let Some((hash, witness)) = vtxo.recovery_unlock_witness() {
					let unlock = ProgramRecoveryUnlock { ancestor: vtxo.point().txid, hash, witness,
						disclosures: recovery_disclosures(&state.participation.inputs, hash)? };
					find_disclosed_preimage(&unlock, self.chain()).await?.is_some()
				} else {
					false
				};
				ready &= available;
			}
			if ready {
				superseded.extend(state.participation.inputs.iter().map(|v| v.point()));
				for vtxo in &state.new_vtxos {
					self.retain_native_recovery_amount(vtxo.point(), vtxo.user_pubkey(), vtxo.amount(), &mut native).await?;
				}
			} else {
				// Until the complete replacement branch is usable, account for
				// the old/forfeit branch, not a sum of competing alternatives.
				superseded.extend(state.new_vtxos.iter().map(|v| v.point()));
			}
		}
		let bundle = self.select_program_recovery_bundle(Some(&selection), &superseded).await?;
		let mut amount = Amount::ZERO;
		for record in &bundle.recoveries {
			if !bundle.targets.contains(&record.controlled_outpoint) { continue; }
			if pending_recovery_record(record, self.chain()).await? {
				amount = amount.checked_add(record.prevout.value).context("pending recovery balance overflow")?;
			}
		}
		// Native successors are part of the same takeover. Until their ordinary
		// exit commits, account for them here rather than losing the crash gap.
		for vtxo in self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Exited]).await? {
			self.retain_native_recovery_amount(vtxo.point(), vtxo.user_pubkey(), vtxo.amount(), &mut native).await?;
		}
		for checkpoint in self.inner.db.get_all_wallet_action_checkpoints().await? {
			if !self.inner.db.has_program_recovery_reservation(&recovery_action_key(&checkpoint.id())).await? { continue; }
			for vtxo in checkpoint.recovery_positions().1 {
				if vtxo.has_all_witnesses() {
					self.retain_native_recovery_amount(vtxo.point(), vtxo.user_pubkey(), vtxo.amount(), &mut native).await?;
				}
			}
		}
		for (point, value) in native {
			if !superseded.contains(&point)
				&& !self.inner.db.has_program_recovery_reservation(&recovery_superseded_key(point.into())).await?
			{
				amount = amount.checked_add(value).context("pending native recovery balance overflow")?;
			}
		}
		Ok(amount)
	}

	async fn retain_native_recovery_amount(
		&self, point: OutPoint, key: PublicKey, amount: Amount, native: &mut HashMap<OutPoint, Amount>,
	) -> anyhow::Result<()> {
		if !self.inner.db.has_program_recovery_reservation(&recovery_target_key(point.into())).await?
			|| self.inner.db.get_program_key(&key).await?.is_some()
			|| self.inner.db.get_public_key_idx(&key).await?.is_none()
			|| self.inner.db.get_wallet_vtxo(point.into()).await?.is_some_and(|v| v.state == VtxoState::Spent)
		{ return Ok(()); }
		if let Some(exit) = self.inner.db.get_exit_vtxo_entry(&point.into()).await? {
			if exit.state.warrants_exited_vtxo()
				|| crate::exit::ExitStateKind::FINISHED_STATES.contains(&exit.state.kind())
			{ return Ok(()); }
		}
		native.insert(point, amount);
		Ok(())
	}

	/// A mixed round can have ordinary native replacements. Their saved leaf
	/// signatures need the same on-chain unlock, but never a program fallback.
	async fn continue_native_round_recovery(
		&self, outpoints: &[OutPoint], bundle: &ProgramRecoveryBundle,
	) -> anyhow::Result<()> {
		for id in self.inner.db.get_pending_round_state_ids().await? {
			if !self.inner.db.has_program_recovery_reservation(&recovery_round_key(id)).await? { continue; }
			let Some(round) = self.inner.db.get_round_state_by_id(id).await? else { continue; };
			let state = round.state();
			if !outpoints.is_empty() && !state.participation.inputs.iter().chain(&state.new_vtxos)
				.any(|v| outpoints.contains(&v.point()) || bundle.targets.contains(&v.point()))
			{ continue; }
			for saved in &state.new_vtxos {
				if !self.inner.db.has_program_recovery_reservation(&recovery_target_key(saved.id())).await? {
					continue;
				}
				if saved.has_all_witnesses()
					|| self.inner.db.get_program_key(&saved.user_pubkey()).await?.is_some()
					|| self.inner.db.get_public_key_idx(&saved.user_pubkey()).await?.is_none()
				{ continue; }
				if self.inner.db.get_wallet_vtxo(saved.id()).await?.is_some_and(|v| v.state == VtxoState::Spent) {
					continue;
				}
				let Some((hash, witness)) = saved.recovery_unlock_witness() else { continue; };
				let unlock = ProgramRecoveryUnlock { ancestor: saved.point().txid, hash, witness,
					disclosures: recovery_disclosures(&state.participation.inputs, hash)? };
				let Some(preimage) = find_disclosed_preimage(&unlock, self.chain()).await? else { continue; };
				let mut vtxo = saved.clone();
				ensure!(vtxo.provide_unlock_preimage(preimage), "native round unlock differs from saved leaf");
				let root = self.chain().get_tx(&vtxo.chain_anchor().txid).await?
					.context("native round recovery funding is unavailable")?;
				vtxo.validate(&root).context("invalid native round recovery ancestry")?;
				self.inner.db.store_vtxos(&[(&vtxo, &VtxoState::Exited)]).await?;
				self.inner.exit.start_exit_for_vtxos(&[vtxo.to_bare()]).await?;
			}
		}
		Ok(())
	}

	async fn recover_program_vtxos_inner(
		&self, outpoints: &[OutPoint], fee_rate: Option<FeeRate>, action_id: Option<&str>,
	) -> anyhow::Result<Vec<ProgramRecoveryProgress>> {
		// Do not reserve anything if a required local fee-wallet dependency is absent.
		let onchain = self.inner.onchain.as_ref().context("program recovery requires an ordinary fee wallet")?;
		let bundle = self.guarded_recovery_bundle(outpoints, action_id, true).await?;
		self.continue_native_round_recovery(outpoints, &bundle).await?;
		let fee_rate = fee_rate.unwrap_or(self.chain().fee_rates().await.fast);
		let mut onchain = onchain.write().await;
		let results = recover_program_bundle(&bundle, self.chain(), &mut *onchain, fee_rate).await?;
		Ok(results)
	}
}

fn retain_unlock_witness(vtxo: &Vtxo<Full>, record: &mut ProgramRecoveryRecord) {
	if let Some((hash, witness)) = vtxo.recovery_unlock_witness() {
		if !record.unlocks.iter().any(|unlock| unlock.ancestor == vtxo.point().txid) {
			record.unlocks.push(ProgramRecoveryUnlock {
				ancestor: vtxo.point().txid, hash, witness, disclosures: Vec::new(),
			});
		}
	}
}

fn ancestor_prevout(record: &ProgramRecoveryRecord, index: usize) -> anyhow::Result<&TxOut> {
	if index == 0 {
		Ok(&record.chain_anchor_prevout)
	} else {
		record.ancestors[index - 1].output.get(
			record.ancestors[index].input[0].previous_output.vout as usize,
		).context("missing authenticated recovery ancestor prevout")
	}
}

fn recovery_points(bundle: &ProgramRecoveryBundle) -> HashSet<OutPoint> {
	bundle.recoveries.iter().flat_map(|record| {
		std::iter::once(record.controlled_outpoint).chain(
			record.ancestors.iter().flat_map(|tx| tx.input.iter().map(|input| input.previous_output)),
		)
	}).collect()
}

impl ProgramRecoveryBundle {
	/// Classify saved recovery without conflating an unsigned future parent with readiness.
	pub fn readiness(&self, point: OutPoint) -> anyhow::Result<ProgramRecoveryReadiness> {
		self.verify()?;
		let record = self.recoveries.iter().find(|record| record.controlled_outpoint == point)
			.context("unknown program recovery outpoint")?;
		if verify_record(record, true).is_ok() {
			Ok(ProgramRecoveryReadiness::Complete)
		} else if let Some(old) = conditional_old(record, &self.recoveries) {
			Ok(ProgramRecoveryReadiness::Conditional {
				publication: record.controlled_outpoint.txid, old_position: old.controlled_outpoint,
			})
		} else {
			Ok(ProgramRecoveryReadiness::Prepared)
		}
	}

	/// Validate every signature and construction plan, without a network or private keys.
	pub fn verify(&self) -> anyhow::Result<()> {
		ensure!(self.version == 1, "unsupported program recovery bundle version");
		let mut keys = HashMap::new();
		for key in &self.keys {
			ensure!(keys.insert(key.program.public_key()?, key).is_none(), "duplicate program descriptor");
		}
		let mut points = HashSet::new();
		for record in &self.recoveries {
			ensure!(points.insert(record.controlled_outpoint), "duplicate recovery claim");
			let key = keys.get(&record.program_key).context("missing program recovery descriptor")?;
			verify_program_recovery_template(record, key)?;
			verify_record(record, false)?;
			for key in keys.keys() {
				reject_key_outputs(&record.claim.output, *key)?;
			}
			for output in &record.claim.output {
				ensure!(!self.recoveries.iter().any(|known| known.prevout.script_pubkey == output.script_pubkey),
					"terminal recovery pays a known program-controlled output");
			}
		}
		let targets = self.targets.iter().copied().collect::<HashSet<_>>();
		ensure!(targets.len() == self.targets.len() && targets.iter().all(|point| points.contains(point)),
			"invalid or duplicate recovery target");
		Ok(())
	}
}

/// Recover from saved bytes using only Bitcoin and an ordinary external-fee wallet.
/// Ancestors are confirmed one at a time to respect v3 package limits; the claim is
/// not broadcast until CSV and the configured height or median-time lock are satisfied.
/// The fee wallet is synchronized first. A lack of confirmed fee inputs is reported
/// per position as [`ProgramRecoveryState::AwaitingFees`], without hiding progress
/// made by another package or spending unconfirmed v3 change.
/// Repeat after each block. A standalone bundle has no access to the wallets
/// that exported it: the caller MUST stop all other wallets and signing actors
/// controlling these positions, including wallets using another database.
/// The [`Wallet::recover_program_vtxos`] wrapper coordinates its own database's
/// actors and reserves known and not-yet-imported positions durably first.
pub async fn recover_program_bundle(bundle: &ProgramRecoveryBundle, chain: &ChainSource,
	fee_wallet: &mut dyn OnchainWalletTrait, fee_rate: FeeRate) -> anyhow::Result<Vec<ProgramRecoveryProgress>>
{
	bundle.verify()?;
	ensure!(bundle.network == chain.network(), "recovery bundle network mismatch");
	chain.require_version().await?;
	fee_wallet.sync(chain).await.context("failed to sync program recovery fee wallet")?;
	let tip = chain.tip().await?.to_u32();
	let mut results = Vec::with_capacity(bundle.targets.len());
	for record in bundle.recoveries.iter().filter(|record| bundle.targets.contains(&record.controlled_outpoint)) {
		let state = progress_record(record, bundle, chain, fee_wallet, fee_rate, tip).await?;
		results.push(ProgramRecoveryProgress { controlled_outpoint: record.controlled_outpoint,
			claim_txid: record.claim.compute_txid(), state });
	}
	Ok(results)
}

async fn broadcast_with_fees(tx: &Transaction, chain: &ChainSource,
	fee_wallet: &mut dyn OnchainWalletTrait, fee_rate: FeeRate, funded_state: ProgramRecoveryState)
	-> anyhow::Result<ProgramRecoveryState>
{
	let (anchor, _) = tx.fee_anchor().context("recovery transaction has no external-fee anchor")?;
	#[allow(deprecated)]
	let spending = chain.txs_spending_inputs([anchor], chain.tip().await?).await?;
	let fees = if let Some((child, _)) = spending.get(&anchor) {
		let info = chain.mempool_ancestor_info(*child).await?;
		if info.effective_fee_rate().is_some_and(|rate| rate >= fee_rate) { return Ok(funded_state); }
		MakeCpfpFees::Rbf { min_effective_fee_rate: fee_rate, current_package_fee: info.total_fee }
	} else {
		MakeCpfpFees::Effective(fee_rate)
	};
	let child = match fee_wallet.make_signed_p2a_cpfp(tx, fees).await {
		Ok(child) => child,
		Err(CpfpError::InsufficientConfirmedFunds { needed, available }) =>
			return Ok(ProgramRecoveryState::AwaitingFees { txid: tx.compute_txid(), available, needed }),
		Err(error) => return Err(error.into()),
	};
	ensure!(child.version == transaction::Version(3) && child.input.len() >= 2
		&& child.input.iter().filter(|input| input.previous_output == anchor).count() == 1
		&& child.input.iter().any(|input| input.previous_output == anchor
			&& input.witness.is_empty() && input.script_sig.is_empty())
		&& child.input.iter().all(|input| input.previous_output.txid != anchor.txid
			|| input.previous_output == anchor),
		"fee wallet must spend only the P2A anchor and ordinary external funding, never a recovery beneficiary");
	fee_wallet.store_signed_p2a_cpfp(&child).await?;
	chain.broadcast_package(&[tx, &child]).await?;
	Ok(funded_state)
}

/// An unsigned dependency is conditional only for the exact known forfeit shape,
/// with a fully verified old branch and identical signed prefix still available.
fn conditional_old<'a>(record: &ProgramRecoveryRecord, records: &'a [ProgramRecoveryRecord])
	-> Option<&'a ProgramRecoveryRecord>
{
	let parent = record.ancestors.last()?;
	if parent.input.len() != 1 || !parent.input[0].witness.is_empty()
		|| parent.input[0].sequence != Sequence::MAX
		|| parent.lock_time != bitcoin::absolute::LockTime::ZERO
		|| record.controlled_outpoint != OutPoint::new(parent.compute_txid(), 0)
		|| parent.output.len() != 2 || parent.output[0] != record.prevout
		|| parent.output[1] != fee::fee_anchor()
	{
		return None;
	}
	let claim_input = record.claim.input.first()?;
	let delta = BlockDelta::new(u16::try_from(claim_input.sequence.0).ok()?);
	let leaf = claim_input.witness.taproot_leaf_script()?;
	if leaf.version != LeafVersion::TapScript || leaf.script != scripts::delayed_sign(
		delta, record.program_key.x_only_public_key().0,
	).as_script() { return None; }
	records.iter().find(|old| old.controlled_outpoint == parent.input[0].previous_output
		&& old.program_key == record.program_key && old.prevout.value == record.prevout.value
		&& old.chain_anchor == record.chain_anchor && old.chain_anchor_prevout == record.chain_anchor_prevout
		&& old.ancestors == record.ancestors[..record.ancestors.len() - 1]
		&& verify_record(old, true).is_ok())
}

/// Chain retrieval is not an authorization oracle: only the exact saved
/// transaction with a valid witness against the authenticated prevout is usable.
fn verify_published_ancestor(
	expected: &Transaction, published: &Transaction, prevout: &TxOut,
) -> anyhow::Result<()> {
	ensure!(published.compute_txid() == expected.compute_txid(),
		"published recovery ancestor txid mismatch");
	verify_spend(published, prevout, None)
}

/// Authenticate the disclosed preimage against the exact saved forfeit output.
fn disclosed_preimage(
	tx: &Transaction, input_index: usize, prevouts: &[TxOut], hash: sha256::Hash,
) -> anyhow::Result<[u8; 32]> {
	let stack = tx.input[input_index].witness.iter().collect::<Vec<_>>();
	ensure!(stack.len() == 4, "forfeit disclosure has no hashlock witness");
	let preimage: [u8; 32] = stack[1].try_into().context("invalid disclosed preimage length")?;
	ensure!(sha256::Hash::hash(&preimage) == hash, "disclosed preimage does not unlock saved leaf");
	let script = Script::from_bytes(stack[2]);
	let control = ControlBlock::decode(stack[3])?;
	ensure!(control.leaf_version == LeafVersion::TapScript
		&& control.verify_taproot_commitment(&SECP, output_key(&prevouts[input_index])?, script),
		"forfeit disclosure does not satisfy saved prevout");
	let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
	let key = match instructions.get(instructions.len().saturating_sub(2)) {
		Some(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes())?,
		_ => bail!("missing forfeit disclosure key"),
	};
	ensure!(script == scripts::hash_and_sign(hash, key).as_script()
		|| script == scripts::hash_and_sign_v0(hash, key).as_script(), "invalid forfeit disclosure script");
	let signature = bitcoin::taproot::Signature::from_slice(stack[0])?;
	let sighash = SighashCache::new(tx).taproot_script_spend_signature_hash(
		input_index, &Prevouts::All(prevouts), TapLeafHash::from_script(script, LeafVersion::TapScript),
		signature.sighash_type,
	)?;
	SECP.verify_schnorr(&signature.signature, &sighash.into(), &key)
		.context("invalid forfeit disclosure signature")?;
	Ok(preimage)
}

async fn hydrate_unlock(
	record: &ProgramRecoveryRecord, index: usize, chain: &ChainSource,
) -> anyhow::Result<Option<Transaction>> {
	let ancestor = &record.ancestors[index];
	let Some(unlock) = record.unlocks.iter().find(|unlock| unlock.ancestor == ancestor.compute_txid())
		else { return Ok(None); };
	let Some(preimage) = find_disclosed_preimage(unlock, chain).await? else { return Ok(None); };
	complete_unlock(ancestor, ancestor_prevout(record, index)?, unlock, preimage).map(Some)
}

async fn find_disclosed_preimage(
	unlock: &ProgramRecoveryUnlock, chain: &ChainSource,
) -> anyhow::Result<Option<[u8; 32]>> {
	for disclosure in &unlock.disclosures {
		verify_disclosure_dependency(disclosure, unlock.hash)?;
		let Some(parent) = chain.get_tx(&disclosure.outpoint.txid).await? else { continue; };
		ensure!(parent.output.get(disclosure.outpoint.vout as usize) == Some(&disclosure.prevout),
			"published forfeit output differs from saved disclosure dependency");
		let height = chain.tx_confirmed(disclosure.outpoint.txid).await?.unwrap_or(BlockHeight::ZERO);
		#[allow(deprecated)]
		let spends = chain.txs_spending_inputs([disclosure.outpoint], height).await?;
		let Some((txid, _)) = spends.get(&disclosure.outpoint) else { continue; };
		let tx = chain.get_tx(txid).await?.context("missing forfeit disclosure transaction")?;
		let input_index = tx.input.iter().position(|input| input.previous_output == disclosure.outpoint)
			.context("unrelated forfeit disclosure transaction")?;
		// The user's delayed recovery has no preimage and is not a disclosure.
		if tx.input[input_index].witness.len() != 4 { continue; }
		let mut prevouts = Vec::with_capacity(tx.input.len());
		for input in &tx.input {
			let parent = chain.get_tx(&input.previous_output.txid).await?
				.context("missing disclosure signing prevout transaction")?;
			prevouts.push(parent.output.get(input.previous_output.vout as usize)
				.context("missing disclosure signing prevout")?.clone());
		}
		ensure!(prevouts[input_index] == disclosure.prevout, "changed disclosure prevout");
		let preimage = disclosed_preimage(&tx, input_index, &prevouts, unlock.hash)?;
		return Ok(Some(preimage));
	}
	Ok(None)
}

fn complete_unlock(
	ancestor: &Transaction, prevout: &TxOut, unlock: &ProgramRecoveryUnlock, preimage: [u8; 32],
) -> anyhow::Result<Transaction> {
	ensure!(ancestor.compute_txid() == unlock.ancestor && sha256::Hash::hash(&preimage) == unlock.hash,
		"unlock preimage or ancestor differs from saved authorization");
	let parts = unlock.witness.iter().collect::<Vec<_>>();
	ensure!(parts.len() == 3, "invalid saved unlock witness");
	let mut completed = ancestor.clone();
	completed.input[0].witness = Witness::from_slice(&[parts[0], &preimage, parts[1], parts[2]]);
	verify_published_ancestor(ancestor, &completed, prevout)?;
	Ok(completed)
}

async fn recovery_witnesses_available(record: &ProgramRecoveryRecord, chain: &ChainSource) -> anyhow::Result<bool> {
	verify_record(record, false)?;
	for (index, ancestor) in record.ancestors.iter().enumerate() {
		if ancestor.input[0].witness.is_empty() {
			let completed = match chain.get_tx(&ancestor.compute_txid()).await? {
				Some(tx) => Some(tx),
				None => hydrate_unlock(record, index, chain).await?,
			};
			let Some(completed) = completed else { return Ok(false); };
			verify_published_ancestor(ancestor, &completed, ancestor_prevout(record, index)?)?;
		}
	}
	Ok(true)
}

async fn pending_recovery_record(record: &ProgramRecoveryRecord, chain: &ChainSource) -> anyhow::Result<bool> {
	if chain.tx_confirmed(record.claim.compute_txid()).await?.is_some() { return Ok(false); }
	let Some(root) = chain.get_tx(&record.chain_anchor.txid).await? else { return Ok(false); };
	ensure!(root.output.get(record.chain_anchor.vout as usize) == Some(&record.chain_anchor_prevout),
		"recovery accounting root differs from authenticated prevout");
	let height = chain.tx_confirmed(record.chain_anchor.txid).await?.unwrap_or(BlockHeight::ZERO);
	if !recovery_witnesses_available(record, chain).await? { return Ok(false); }
	for tx in record.ancestors.iter().chain(std::iter::once(&record.claim)) {
		#[allow(deprecated)]
		let spends = chain.txs_spending_inputs([tx.input[0].previous_output], height).await?;
		if spends.get(&tx.input[0].previous_output).is_some_and(|(id, _)| *id != tx.compute_txid()) {
			return Ok(false);
		}
	}
	Ok(true)
}

async fn progress_record(record: &ProgramRecoveryRecord, bundle: &ProgramRecoveryBundle,
	chain: &ChainSource, fee_wallet: &mut dyn OnchainWalletTrait, fee_rate: FeeRate, tip: u32)
	-> anyhow::Result<ProgramRecoveryState>
{
	let claim_txid = record.claim.compute_txid();
	if chain.tx_confirmed(claim_txid).await?.is_some() { return Ok(ProgramRecoveryState::Confirmed); }
	// A committed receive can lose the local commit acknowledgement while its
	// sender publishes the exact signed ancestry. Bitcoin may supply missing
	// witnesses, never a new transaction or fresh signature. Authenticate the
	// complete hydrated chain before publishing even one saved prefix.
	let mut hydrated = None;
	for (index, ancestor) in record.ancestors.iter().enumerate() {
		if !ancestor.input[0].witness.is_empty() { continue; }
		let txid = ancestor.compute_txid();
		let published = match chain.get_tx(&txid).await? {
			Some(published) => Some(published),
			None => hydrate_unlock(record, index, chain).await?,
		};
		let Some(published) = published else {
			return Ok(if conditional_old(record, &bundle.recoveries).is_some() {
				ProgramRecoveryState::AwaitingPublication { txid }
			} else {
				ProgramRecoveryState::Prepared
			});
		};
		let prevout = if index == 0 {
			&record.chain_anchor_prevout
		} else {
			record.ancestors[index - 1].output.get(ancestor.input[0].previous_output.vout as usize)
				.context("missing authenticated recovery ancestor prevout")?
		};
		verify_published_ancestor(ancestor, &published, prevout)?;
		hydrated.get_or_insert_with(|| record.clone()).ancestors[index] = published;
	}
	let record = hydrated.as_ref().unwrap_or(record);
	verify_record(record, true).context("published recovery ancestors failed authentication")?;
	let root = match chain.get_tx(&record.chain_anchor.txid).await? {
		Some(root) => root,
		None => return Ok(ProgramRecoveryState::AwaitingPublication { txid: record.chain_anchor.txid }),
	};
	ensure!(root.output.get(record.chain_anchor.vout as usize) == Some(&record.chain_anchor_prevout),
		"published recovery root differs from authenticated prevout");
	let root_height = match chain.tx_confirmed(record.chain_anchor.txid).await? {
		Some(height) => height,
		None => return Ok(ProgramRecoveryState::AwaitingConfirmation { txid: record.chain_anchor.txid }),
	};
	for ancestor in &record.ancestors {
		let txid = ancestor.compute_txid();
		if chain.tx_confirmed(txid).await?.is_some() { continue; }
		#[allow(deprecated)]
		let spending = chain.txs_spending_inputs([ancestor.input[0].previous_output], root_height).await?;
		if let Some((spending_txid, _)) = spending.get(&ancestor.input[0].previous_output) {
			if *spending_txid != txid { return Ok(ProgramRecoveryState::Conflicted { spending_txid: *spending_txid }); }
		}
		return broadcast_with_fees(ancestor, chain, fee_wallet, fee_rate,
			ProgramRecoveryState::AwaitingConfirmation { txid }).await;
	}
	#[allow(deprecated)]
	let spending = chain.txs_spending_inputs([record.controlled_outpoint], root_height).await?;
	if let Some((spending_txid, _)) = spending.get(&record.controlled_outpoint) {
		if *spending_txid != claim_txid { return Ok(ProgramRecoveryState::Conflicted { spending_txid: *spending_txid }); }
	}
	let height = chain.tx_confirmed(record.controlled_outpoint.txid).await?
		.context("recovery parent confirmation disappeared")?.to_u32();
	let sequence = record.claim.input[0].sequence.to_consensus_u32();
	ensure!(sequence <= u16::MAX as u32, "recovery only supports native block-based CSV");
	let locktime = record.claim.lock_time.to_consensus_u32();
	let mut maturity = height.checked_add(sequence).context("recovery maturity overflow")?;
	if record.claim.lock_time.is_block_height() {
		maturity = maturity.max(locktime.saturating_add(1));
	} else {
		// Bitcoin compares timestamp locktimes against the previous block's MTP,
		// not local wall clock or the last block's timestamp.
		let mut times = [0u32; 11];
		let mut count = 0;
		for height in tip.saturating_sub(10)..=tip {
			let block_ref = chain.block_ref(BlockHeight::new(height)).await?;
			let block = chain.block(block_ref.hash).await?.context("missing block for recovery median time")?;
			times[count] = block.header.time;
			count += 1;
		}
		times[..count].sort_unstable();
		if times[count / 2] <= locktime {
			return Ok(ProgramRecoveryState::AwaitingTime { timestamp: locktime.saturating_add(1) });
		}
	}
	if tip.saturating_add(1) < maturity {
		return Ok(ProgramRecoveryState::AwaitingMaturity { height: maturity });
	}
	broadcast_with_fees(&record.claim, chain, fee_wallet, fee_rate, ProgramRecoveryState::Broadcast).await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod recovery_tests {
	use ark::test_util::VTXO_VECTORS;

	use super::*;

	#[test]
	fn prepared_ancestor_accepts_only_the_exact_published_signed_transaction() {
		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
		let signed = vtxo.transactions().next().unwrap().tx;
		let prevout = vtxo.chain_anchor_txout().unwrap();
		assert!(!signed.input[0].witness.is_empty());
		let mut prepared = signed.clone();
		prepared.input[0].witness = Witness::new();

		verify_published_ancestor(&prepared, &signed, &prevout).unwrap();
		assert!(prepared.input[0].witness.is_empty(), "authentication must not alter saved templates");
		assert!(verify_published_ancestor(&prepared, &prepared, &prevout).is_err());

		let mut wrong_transaction = signed.clone();
		wrong_transaction.output[0].value += Amount::from_sat(1);
		assert!(verify_published_ancestor(&prepared, &wrong_transaction, &prevout).is_err());

		let mut invalid_signature = signed.clone();
		let mut witness = invalid_signature.input[0].witness.to_vec();
		witness[0][0] ^= 1;
		invalid_signature.input[0].witness = Witness::from_slice(&witness);
		assert_eq!(invalid_signature.compute_txid(), prepared.compute_txid());
		assert!(verify_published_ancestor(&prepared, &invalid_signature, &prevout).is_err());
	}

	#[test]
	fn disclosed_forfeit_preimage_reconstructs_exported_leaf_without_new_signature() {
		let vtxo = &VTXO_VECTORS.round1_vtxo;
		let ancestors = vtxo.transactions().map(|item| item.tx).collect::<Vec<_>>();
		let signed = ancestors.last().unwrap();
		let prevout = &ancestors[ancestors.len() - 2].output[signed.input[0].previous_output.vout as usize];
		let preimage: [u8; 32] = signed.input[0].witness.iter().nth(1).unwrap().try_into().unwrap();
		let (hash, witness) = vtxo.recovery_unlock_witness().unwrap();
		let disclosures = recovery_disclosures(&[VTXO_VECTORS.arkoor3_vtxo.clone()], hash).unwrap();
		let unlock = ProgramRecoveryUnlock { ancestor: signed.compute_txid(), hash, witness, disclosures };
		let unlock: ProgramRecoveryUnlock = serde_json::from_slice(&serde_json::to_vec(&unlock).unwrap()).unwrap();
		let disclosure = &unlock.disclosures[0];
		verify_disclosure_dependency(disclosure, hash).unwrap();
		assert!(verify_disclosure_dependency(disclosure, sha256::Hash::hash(&[1; 32])).is_err());

		let parts = disclosure.hashlock.iter().collect::<Vec<_>>();
		let script = Script::from_bytes(parts[0]);
		let mut claim = Transaction {
			version: transaction::Version(3), lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn { previous_output: disclosure.outpoint, script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO, witness: Witness::new() }],
			output: vec![fee::fee_anchor()],
		};
		let prevouts = [disclosure.prevout.clone()];
		let sighash = SighashCache::new(&claim).taproot_script_spend_signature_hash(
			0, &Prevouts::All(&prevouts), TapLeafHash::from_script(script, LeafVersion::TapScript),
			TapSighashType::Default,
		).unwrap();
		let signature = SECP.sign_schnorr_no_aux_rand(&sighash.into(), &VTXO_VECTORS.server_key);
		claim.input[0].witness = Witness::from_slice(&[&signature.serialize()[..], &preimage, parts[0], parts[1]]);
		let recovered = disclosed_preimage(&claim, 0, &prevouts, hash).unwrap();
		let mut prepared = signed.clone();
		prepared.input[0].witness = Witness::new();
		assert_eq!(complete_unlock(&prepared, prevout, &unlock, recovered).unwrap(), *signed);
		assert!(prepared.input[0].witness.is_empty());
		assert!(complete_unlock(&prepared, prevout, &unlock, [0; 32]).is_err());
		let mut tampered = claim.input[0].witness.to_vec();
		tampered[0][0] ^= 1;
		claim.input[0].witness = Witness::from_slice(&tampered);
		assert!(disclosed_preimage(&claim, 0, &prevouts, hash).is_err());
		let mut tampered = unlock.clone();
		let mut witness = tampered.witness.to_vec();
		witness[0][0] ^= 1;
		tampered.witness = Witness::from_slice(&witness);
		assert!(complete_unlock(&prepared, prevout, &tampered, recovered).is_err());
	}
}
