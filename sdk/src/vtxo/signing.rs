
use bitcoin::secp256k1::schnorr;
use bitcoin::{taproot, TapSighash, Witness};
use bitcoin::key::Keypair;
use log::error;

use ark::VtxoPolicy;
use ark::vtxo::{Full, TapScriptClause, Vtxo, VtxoClause};
use ark::vtxo::policy::signing::VtxoSigner;

use crate::{SECP, Wallet};

impl Wallet {
	/// Build the clause witness with an already-resolved keypair. Shared by
	/// the native signer and the generic [`crate::vtxo::VtxoKeySigner`] path.
	pub(crate) async fn clause_witness_with_key(
		&self,
		keypair: &Keypair,
		clause: &VtxoClause,
		control_block: &taproot::ControlBlock,
		sighash: TapSighash,
	) -> anyhow::Result<Option<Witness>> {
		let signature = SECP.sign_schnorr_with_aux_rand(&sighash.into(), keypair, &rand::random());
		Ok(match clause {
			VtxoClause::DelayedSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedTimelockSign(c) => Some(c.witness(&signature, &control_block)),
			VtxoClause::TimelockSign(c) => Some(c.witness(&signature, &control_block)),
			VtxoClause::HashDelaySign(c) => {
				let preimage = self.lightning_receive_preimage(c.hash.into()).await?;
				preimage.map(|p| c.witness(
					&(signature, p.to_byte_array()), &control_block,
				))
			},
			VtxoClause::HashDelaySign_v0(c) => {
				let preimage = self.lightning_receive_preimage(c.hash.into()).await?;
				preimage.map(|p| c.witness(
					&(signature, p.to_byte_array()), &control_block,
				))
			},
			VtxoClause::HashSign(_) | VtxoClause::HashSign_v0(_) => None,
		})
	}

	/// Variant of [`VtxoSigner::find_signable_clause`] that propagates
	/// transient errors instead of collapsing them into "not signable".
	///
	/// [`VtxoSigner::find_signable_clause`] decides signability through
	/// [`VtxoSigner::witness`], which can only answer "yes or no": a
	/// database failure while looking up the key or preimage is
	/// indistinguishable from the wallet not owning the clause. Callers
	/// that treat "not signable" as a final verdict — like the
	/// arkoor-receive path refusing a payment — must use this variant so a
	/// transient failure aborts and retries instead of dropping an owned
	/// payment.
	pub(crate) async fn find_signable_clause_strict(
		&self,
		vtxo: &Vtxo<Full>,
	) -> anyhow::Result<Option<VtxoClause>> {
		let clauses = vtxo.policy().clauses(
			vtxo.exit_delta(), vtxo.expiry_height(), vtxo.server_pubkey(),
		);
		for clause in clauses {
			if self.can_sign_clause_strict(&clause).await? {
				return Ok(Some(clause));
			}
		}
		Ok(None)
	}

	/// Mirror of the signability decision in [`VtxoSigner::witness`], but
	/// propagating the underlying lookups' errors. See
	/// [`Wallet::find_signable_clause_strict`].
	async fn can_sign_clause_strict(&self, clause: &VtxoClause) -> anyhow::Result<bool> {
		let Some(signer) = self.signer_for_pubkey(&clause.pubkey()).await? else {
			return Ok(false);
		};
		if signer.is_external() {
			// An external signer owns the key and decides at signing time.
			// Key-possession clauses are the ones it can satisfy; program
			// exit paths use their saved recovery authorization instead.
			return Ok(matches!(
				clause,
				VtxoClause::DelayedSign(_)
					| VtxoClause::DelayedTimelockSign(_)
					| VtxoClause::TimelockSign(_)
			));
		}
		Ok(match clause {
			// Key-possession clauses sign with the wallet key alone.
			VtxoClause::DelayedSign(_)
			| VtxoClause::DelayedTimelockSign(_)
			| VtxoClause::TimelockSign(_) => true,
			// Hash-delay clauses additionally need the receive preimage.
			VtxoClause::HashDelaySign(c) =>
				self.lightning_receive_preimage(c.hash.into()).await?.is_some(),
			VtxoClause::HashDelaySign_v0(c) =>
				self.lightning_receive_preimage(c.hash.into()).await?.is_some(),
			// The wallet never signs these (see witness()).
			VtxoClause::HashSign(_) | VtxoClause::HashSign_v0(_) => false,
		})
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl VtxoSigner for Wallet {
	async fn sign_keyspend<G: Sync + Send>(
		&self,
		vtxo: &Vtxo<G, VtxoPolicy>,
		_sighash: TapSighash,
	) -> Option<schnorr::Signature> {
		error!(
			"CODE BUG: wallet was asked to sign a keyspend clause but that should never happen \
				(VTXO ID: {}; policy type: {})", vtxo.id(), vtxo.policy_type(),
		);
		None
	}

	async fn witness(
		&self,
		clause: &VtxoClause,
		control_block: &taproot::ControlBlock,
		sighash: TapSighash,
	) -> Option<Witness> {
		let signer = match self.signer_for_pubkey(&clause.pubkey()).await {
			Ok(Some(signer)) => signer,
			Ok(None) => return None,
			// The [VtxoSigner] trait cannot propagate errors, so a transient
			// database failure is reported as unsignable here. Callers whose
			// verdict is final must use the strict variants instead (see
			// [Wallet::find_signable_clause_strict]).
			Err(e) => {
				error!("Failed to look up clause signer, treating clause as unsignable: {:#}", e);
				return None;
			},
		};

		match signer.sign_clause(self, clause, control_block, sighash).await {
			Ok(witness) => witness,
			Err(e) => {
				error!("Failed to build clause witness: {:#}", e);
				None
			},
		}
	}
}
