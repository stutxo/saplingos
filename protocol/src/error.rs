
use std::fmt;

use bitcoin::secp256k1::PublicKey;



/// Incorrect signing secret key was provided.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("incorrect signing key: required={required:?}, provided={provided}")]
pub struct IncorrectSigningKeyError {
	/// The public key of the key that was required the sign.
	pub required: Option<PublicKey>,
	/// The public key we got.
	pub provided: PublicKey,
}

impl fmt::Debug for IncorrectSigningKeyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("IncorrectSigningKeyError")
			.field("required", &self.required.map(|pk| pk.to_string()).unwrap_or("None".into()))
			.field("provided", &self.provided.to_string())
			.finish()
	}
}

/// An error cosigning a branch of a VTXO tree.
#[derive(Debug, thiserror::Error)]
pub enum CosignBranchError {
	/// The provided keypair doesn't match the leaf's cosign pubkey.
	#[error(transparent)]
	IncorrectSigningKey(#[from] IncorrectSigningKeyError),
	/// The provided number of aggregate cosign nonces doesn't match the
	/// number of internal nodes in the tree.
	#[error("expected {expected} aggregate cosign nonces, got {provided}")]
	InvalidNonceCount {
		/// The number of internal nodes in the tree.
		expected: usize,
		/// The number of aggregate cosign nonces provided.
		provided: usize,
	},
	/// The branch being signed needs a secret nonce at an internal level the
	/// caller did not provide. The server controls the tree shape, so this is
	/// caller input that must fail rather than index out of bounds.
	#[error("branch needs a cosign secret nonce at internal level {required_level}, but only {provided} were provided")]
	InsufficientSecretNonces {
		/// The internal level (leaves-to-root) of the node being signed.
		required_level: usize,
		/// The number of secret nonces provided for the branch.
		provided: usize,
	},
}
