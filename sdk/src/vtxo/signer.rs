//! Generic signing interface for VTXO policy keys.
//!
//! Most wallets sign with a seed-derived keypair. Program-backed wallets use
//! the same interface for keys whose private material is split with a local
//! co-signer: bark sees one public key and asks the signer to prepare nonces
//! and finish the MuSig session.

use bitcoin::key::Keypair;
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::Witness;

use ark::musig::{PartialSignature, PublicNonce};
use ark::musig::context::SigningInput;
use ark::sapio::protocol::OwnershipRequest;
use ark::vtxo::VtxoClause;

use crate::Wallet;

/// A signing key for one VTXO policy public key.
///
/// `local_keypair()` is `Some` only when the wallet can sign without help.
/// Callers use it for operations that are intentionally native-only (raw
/// keypair export, address mailbox binding, specialized protocol paths).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait VtxoKeySigner: Send + Sync {
	/// The public key this signer controls.
	fn public_key(&self) -> PublicKey;

	/// The local keypair, when this is a seed-derived native key.
	fn local_keypair(&self) -> Option<&Keypair>;

	/// Whether signing requires a local co-signer.
	fn is_external(&self) -> bool {
		self.local_keypair().is_none()
	}

	/// Prepare one MuSig signing context. The returned object holds any
	/// secret nonce state until `finish`.
	async fn prepare(
		&self,
		wallet: &Wallet,
		input: SigningInput,
	) -> anyhow::Result<Box<dyn PreparedVtxoSignature>>;

	/// Sign an ownership challenge for this key.
	async fn sign_ownership(
		&self,
		wallet: &Wallet,
		request: OwnershipRequest,
	) -> anyhow::Result<schnorr::Signature>;

	/// Sign a tapscript clause when the wallet owns the clause key.
	async fn sign_clause(
		&self,
		wallet: &Wallet,
		clause: &VtxoClause,
		control_block: &bitcoin::taproot::ControlBlock,
		sighash: bitcoin::TapSighash,
	) -> anyhow::Result<Option<Witness>>;
}

/// A prepared MuSig session for one VTXO signing context.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait PreparedVtxoSignature: Send {
	/// The public nonce to send to the server.
	fn public_nonce(&self) -> PublicNonce;

	/// Finish the session with the server's nonce/partial signature.
	async fn finish(
		self: Box<Self>,
		server_nonce: Option<PublicNonce>,
		server_partial: Option<PartialSignature>,
	) -> anyhow::Result<SignatureResult>;
}

/// Result of finishing a MuSig signing context.
#[derive(Debug, Clone)]
pub struct SignatureResult {
	/// The wallet's own partial signature, before aggregation.
	pub user_partial: PartialSignature,
	/// The aggregated signature when the context includes the server.
	pub signature: Option<schnorr::Signature>,
}
