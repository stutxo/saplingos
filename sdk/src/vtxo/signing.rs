
use bitcoin::secp256k1::schnorr;
use bitcoin::{taproot, TapSighash, Witness};
use bitcoin::key::Keypair;
use log::error;

use ark::VtxoPolicy;
use ark::vtxo::{Full, TapScriptClause, Vtxo, VtxoClause};
use ark::vtxo::policy::signing::VtxoSigner;

use crate::{SECP, Wallet};

impl Wallet {
	/// Get the keypair for the given clause, if the wallet owns it.
	///
	/// Database errors are propagated: collapsing them into `None` would
	/// make a transient persister failure indistinguishable from "no key",
	/// letting an ownership probe permanently drop a payment the wallet in
	/// fact owns. Callers that need the [`VtxoSigner::witness`] contract of
	/// a plain `Option` handle the error at their boundary.
	pub (crate) async fn clause_keypair(&self, clause: &VtxoClause) -> anyhow::Result<Option<Keypair>> {
		let clause_pubkey = clause.pubkey();
		Ok(self.pubkey_keypair(&clause_pubkey).await?.map(|(_, keypair)| keypair))
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
		if self.clause_keypair(clause).await?.is_none() {
			return Ok(false);
		}
		Ok(match clause {
			// Hash-delay clauses additionally need the receive preimage.
			VtxoClause::HashDelaySign(c) =>
				self.lightning_receive_preimage(c.hash.into()).await?.is_some(),
			VtxoClause::HashDelaySign_v0(c) =>
				self.lightning_receive_preimage(c.hash.into()).await?.is_some(),
			// The wallet never signs these (see witness()).
			VtxoClause::HashSign(_) | VtxoClause::HashSign_v0(_) => false,
			_ => true,
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
		let signature = match self.clause_keypair(clause).await {
			Ok(Some(keypair)) => {
				SECP.sign_schnorr_with_aux_rand(&sighash.into(), &keypair, &rand::random())
			},
			Ok(None) => return None,
			// The [VtxoSigner] trait cannot propagate errors, so a transient
			// database failure is reported as unsignable here. Callers whose
			// verdict is final must use the strict variants instead (see
			// [Wallet::find_signable_clause_strict]).
			Err(e) => {
				error!("Failed to look up clause keypair, treating clause as unsignable: {:#}", e);
				return None;
			},
		};

		match clause {
			VtxoClause::DelayedSign(c) => Some(c.witness(&signature, control_block)),
			VtxoClause::DelayedTimelockSign(c) => Some(c.witness(&signature, &control_block)),
			VtxoClause::TimelockSign(c) => Some(c.witness(&signature, &control_block)),
			VtxoClause::HashDelaySign(c) => {
				let preimage = self.lightning_receive_preimage(c.hash.into())
					.await.ok().flatten();

				preimage.map(|p| c.witness(
					&(signature, p.to_byte_array()), &control_block,
				))
			},
			VtxoClause::HashDelaySign_v0(c) => {
				let preimage = self.lightning_receive_preimage(c.hash.into())
					.await.ok().flatten();

				preimage.map(|p| c.witness(
					&(signature, p.to_byte_array()), &control_block,
				))
			},
			VtxoClause::HashSign(_) => None, // Not used by bark
			VtxoClause::HashSign_v0(_) => None, // Not used by bark
		}
	}
}
