//! Generic Sapio-backed VTXOs with independent user ownership and saved recovery.
//!
//! captaind sees the ordinary public key C = KeyAgg(U, S). The wallet stores U's
//! derivation index and the exact attested-root/program descriptor, never C's
//! private key. Construction templates do not override program authorization.

pub(crate) mod client;
pub mod receive;
pub mod recovery;

use std::borrow::Cow;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bitcoin::bip32::Xpub;
use bitcoin::secp256k1::{Keypair, PublicKey};

use ark::sapio::program::{Program, ProgramKey};
use ark::vtxo::VtxoRef;

use crate::persist::models::{ProgramRecoveryTemplate, SerdeProgramKey};
use crate::Wallet;

pub(crate) use client::PreparedSignature;

/// Complete policy and recovery construction for newly issued program keys.
/// Obtain `root` from independently verified attestation of the expected image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SapioConfig {
	pub endpoint: String,
	pub root: Xpub,
	pub program: Program,
	pub recovery: ProgramRecoveryTemplate,
	#[serde(default)]
	pub coordinator_url: Option<String>,
	/// Separate receiving-only REST listener; never exposes wallet admin routes.
	#[serde(default)]
	pub receive_bind: Option<SocketAddr>,
}

impl SapioConfig {
	pub fn validate(&self) -> Result<()> {
		client::endpoint_url(&self.endpoint)?;
		self.program.derive_public_key(&self.root)?;
		ensure!(!self.recovery.outputs.is_empty(), "program recovery needs explicit outputs");
		ensure!(self.recovery.witness.len() <= 65_536, "program evidence exceeds size limit");
		if let Some(index) = self.recovery.remainder_output {
			ensure!(index < self.recovery.outputs.len(), "recovery remainder output is out of range");
		}
		if let Some(url) = &self.coordinator_url { client::endpoint_url(url)?; }
		ensure!(self.receive_bind.is_none() || self.coordinator_url.is_some(),
			"program receiving listener requires its advertised coordinator URL");
		Ok(())
	}
}

/// A native key or the user's private participant in an immutable joint key.
/// No conversion from a program handle to a native C keypair exists.
pub(crate) struct VtxoSigningKey {
	pub(super) user: Keypair,
	public: PublicKey,
	program: Option<SerdeProgramKey>,
}

impl From<Keypair> for VtxoSigningKey {
	fn from(user: Keypair) -> Self {
		Self { public: user.public_key(), user, program: None }
	}
}

impl VtxoSigningKey {
	pub fn public_key(&self) -> PublicKey { self.public }

	pub fn local_keypair(&self) -> Option<&Keypair> {
		if self.program.is_none() { Some(&self.user) } else { None }
	}

	pub fn program(&self) -> Option<&SerdeProgramKey> { self.program.as_ref() }

	fn from_program(user: Keypair, program: SerdeProgramKey) -> Result<Self> {
		ensure!(user.public_key() == program.program.user_pubkey,
			"program descriptor does not match the wallet's user key");
		let public = program.program.public_key()?;
		Ok(Self { user, public, program: Some(program) })
	}
}

impl Wallet {
	pub(crate) async fn signing_key(&self, public: &PublicKey) -> Result<Option<VtxoSigningKey>> {
		if let Some(program) = self.inner.db.get_program_key(public).await? {
			ensure!(self.inner.db.get_public_key_idx(public).await? == Some(program.index),
				"program key index mapping is inconsistent");
			let user = self.inner.seed.derive_vtxo_keypair(program.index);
			let key = VtxoSigningKey::from_program(user, program)?;
			ensure!(key.public_key() == *public, "program key mapping is inconsistent");
			Ok(Some(key))
		} else {
			Ok(self.pubkey_keypair(public).await?.map(|(_, key)| key.into()))
		}
	}

	pub(crate) async fn vtxo_signing_key(&self, vtxo: impl VtxoRef) -> Result<VtxoSigningKey> {
		let bare = match vtxo.as_bare_vtxo() {
			Some(bare) => bare,
			None => Cow::Owned(self.get_vtxo_by_id(vtxo.vtxo_id()).await?.vtxo),
		};
		self.signing_key(&bare.user_pubkey()).await?.context("VTXO ownership key not found")
	}

	pub(crate) async fn peek_signing_key(&self, index: u32) -> Result<VtxoSigningKey> {
		if let Some(program) = self.inner.db.get_program_key_by_index(index).await? {
			ensure!(program.index == index, "program derivation index mismatch");
			VtxoSigningKey::from_program(self.inner.seed.derive_vtxo_keypair(index), program)
		} else {
			Ok(self.peek_keypair(index).await?.into())
		}
	}

	pub(crate) async fn derive_store_next_signing_key(&self) -> Result<(VtxoSigningKey, u32)> {
		let Some(config) = self.inner.config.sapio.as_ref() else {
			let (key, index) = self.derive_store_next_keypair().await?;
			return Ok((key.into(), index));
		};
		config.validate()?;
		let (user, index) = self.peek_next_keypair().await?;
		let program = SerdeProgramKey {
			index,
			program: ProgramKey { program: config.program.clone(), root: config.root,
				user_pubkey: user.public_key() },
			endpoint: config.endpoint.clone(),
			recovery: config.recovery.clone(),
		};
		let key = VtxoSigningKey::from_program(user, program)?;
		self.inner.db.store_program_key(key.program().expect("constructed program handle")).await?;
		Ok((key, index))
	}

	pub(crate) async fn find_vtxo_signing_keys(
		&self,
		wanted: impl IntoIterator<Item = PublicKey>,
		gap_limit: u32,
	) -> Result<std::collections::HashMap<PublicKey, VtxoSigningKey>> {
		let mut found = std::collections::HashMap::new();
		let mut unknown = Vec::new();
		for public in wanted {
			if let Some(key) = self.signing_key(&public).await? {
				found.insert(public, key);
			} else {
				unknown.push(public);
			}
		}
		// Program descriptors and claims are mandatory backup material. Unknown
		// raw aggregate keys cannot be reconstructed by a seed-only gap scan.
		found.extend(self.find_vtxo_keypairs(unknown, gap_limit).await?
			.into_iter().map(|(public, key)| (public, key.into())));
		Ok(found)
	}
}
