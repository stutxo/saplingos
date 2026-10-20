//! Optional wallet extensions for policy-controlled VTXOs.
//!
//! The core wallet owns native Ark transfers and exits. Features that need
//! extra state around a VTXO (for example a local co-signer and its saved
//! recovery records) implement this trait. Core call sites go through the
//! helpers below so they never depend on a concrete program implementation.

use std::sync::Arc;

use anyhow::Result;
use bitcoin::secp256k1::PublicKey;

use ark::{Address, Vtxo};
use ark::vtxo::Full;

use crate::Wallet;

/// Lifecycle hooks for policy-controlled VTXOs.
///
/// Implementations must be idempotent: core calls these at crash-replay
/// boundaries as well as on first execution.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait WalletExtension: Send + Sync {
	/// Ensure every program-backed VTXO has a usable saved recovery.
	async fn ensure_recovery(&self, wallet: &Wallet, vtxos: &[Vtxo<Full>]) -> Result<()>;

	/// Prepare and save recovery for candidate outputs before they commit.
	async fn prepare_recovery(&self, wallet: &Wallet, vtxos: &[Vtxo<Full>]) -> Result<()>;

	/// Prepare a coordinated receive for an address before acknowledging it.
	async fn prepare_receive(
		&self,
		wallet: &Wallet,
		address: &Address,
		vtxos: &[Vtxo<Full>],
	) -> Result<()>;

	/// Retain a rejected program deposit as bounded diagnostic metadata.
	async fn quarantine_receive(
		&self,
		wallet: &Wallet,
		vtxo: &Vtxo<Full>,
		raw: &[u8],
		reason: &str,
	) -> Result<()>;

	/// Whether this key belongs to the extension (program-backed or a
	/// registered external signer).
	async fn is_program_key(&self, wallet: &Wallet, public: &PublicKey) -> Result<bool>;

	/// The stored program descriptor for a key, when present.
	async fn program_key(
		&self,
		wallet: &Wallet,
		public: &PublicKey,
	) -> Result<Option<crate::persist::models::SerdeProgramKey>>;
}

impl Wallet {
	pub(crate) fn wallet_extension(&self) -> Option<&Arc<dyn WalletExtension>> {
		self.inner.extension.as_ref()
	}

	pub(crate) async fn extension_ensure_recovery(
		&self,
		vtxos: &[Vtxo<Full>],
	) -> Result<()> {
		match self.wallet_extension() {
			Some(extension) => extension.ensure_recovery(self, vtxos).await,
			None => Ok(()),
		}
	}

	pub(crate) async fn extension_prepare_recovery(
		&self,
		vtxos: &[Vtxo<Full>],
	) -> Result<()> {
		match self.wallet_extension() {
			Some(extension) => extension.prepare_recovery(self, vtxos).await,
			None => Ok(()),
		}
	}

	pub(crate) async fn extension_prepare_receive(
		&self,
		address: &Address,
		vtxos: &[Vtxo<Full>],
	) -> Result<()> {
		match self.wallet_extension() {
			Some(extension) => extension.prepare_receive(self, address, vtxos).await,
			None => Ok(()),
		}
	}

	pub(crate) async fn extension_quarantine_receive(
		&self,
		vtxo: &Vtxo<Full>,
		raw: &[u8],
		reason: &str,
	) -> Result<()> {
		match self.wallet_extension() {
			Some(extension) => extension.quarantine_receive(self, vtxo, raw, reason).await,
			None => Ok(()),
		}
	}

	pub(crate) async fn extension_is_program_key(&self, public: &PublicKey) -> Result<bool> {
		match self.wallet_extension() {
			Some(extension) => extension.is_program_key(self, public).await,
			None => Ok(false),
		}
	}

	pub(crate) async fn extension_program_key(
		&self,
		public: &PublicKey,
	) -> Result<Option<crate::persist::models::SerdeProgramKey>> {
		match self.wallet_extension() {
			Some(extension) => extension.program_key(self, public).await,
			None => Ok(None),
		}
	}
}
