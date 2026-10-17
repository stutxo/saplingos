
pub mod selection;
mod signing;
mod state;

pub use self::selection::{FilterVtxos, RefreshStrategy, VtxoFilter};
pub use self::state::{VtxoLockHolder, VtxoState, VtxoStateKind, WalletVtxo};

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use log::{debug, error, info, trace, warn};
use ark::{Vtxo, VtxoId};
use ark::vtxo::{Full, VtxoRef};
use bitcoin_ext::{BlockDelta, BlockHeight};
use server_rpc::protos::VtxoSpendState;

use crate::Wallet;

/// Validate the tree-level security parameters the server chose for the VTXOs
/// we're about to accept in a round.
///
/// Checks that server pubkey and exit delta match.
/// Checks that expiry height is above minimum threshold.
pub(crate) fn validate_vtxo_tree_params(
	server_pubkey: PublicKey,
	exit_delta: BlockDelta,
	expiry_height: BlockHeight,
	expected_server_pubkey: PublicKey,
	expected_exit_delta: BlockDelta,
	min_expiry_height: BlockHeight,
) -> anyhow::Result<()> {
	ensure!(server_pubkey == expected_server_pubkey,
		"round VTXO tree uses an unexpected server pubkey: got {}, expected {}",
		server_pubkey, expected_server_pubkey,
	);

	ensure!(exit_delta == expected_exit_delta,
		"round VTXO tree uses an unexpected exit delta: got {}, expected {}",
		exit_delta, expected_exit_delta,
	);

	ensure!(expiry_height >= min_expiry_height,
		"round VTXO tree expiry height {} is below the required minimum {}; \
		server may be trying to sweep before we can exit",
		expiry_height, min_expiry_height,
	);

	Ok(())
}

/// Where the server's spend state puts a VTXO in this wallet.
///
/// The single translation of a [VtxoSpendState] into wallet terms, shared by
/// the import and recovery paths so they cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatusAdoption {
	/// The server will let us spend the VTXO.
	Spendable,
	/// The server considers the VTXO spent.
	Spent,
	/// Neither spendable nor spent: the server is still waiting on a preimage
	/// or on the VTXO's transaction chain. No wallet state describes this, and
	/// finishing that flow is what decides where the VTXO belongs.
	InFlight(VtxoSpendState),
}

impl ServerStatusAdoption {
	/// Errors when the server gave no usable answer.
	///
	/// Matched exhaustively (no catch-all) so a new spend state forces an
	/// explicit decision rather than being silently skipped.
	pub fn from_spend_state(spend_state: VtxoSpendState) -> anyhow::Result<Self> {
		Ok(match spend_state {
			VtxoSpendState::Spendable => ServerStatusAdoption::Spendable,
			VtxoSpendState::Spent => ServerStatusAdoption::Spent,
			state @ (
				VtxoSpendState::Unclaimed
				| VtxoSpendState::Unregistered
				| VtxoSpendState::HtlcRecvUnclaimed
			) => ServerStatusAdoption::InFlight(state),
			VtxoSpendState::Unspecified => bail!("server returned an unspecified spend state"),
		})
	}
}

#[derive(Debug, thiserror::Error)]
pub enum VtxoValidationError {
	#[error("chain error: {0:#}")]
	Chain(anyhow::Error),
	#[error("anchor not found")]
	AnchorNotFound,
	#[error("invalid: {0}")]
	Invalid(#[from] ark::vtxo::VtxoValidationError),
}

impl Wallet {
	/// Attempts to lock VTXOs with the given [VtxoId] values.
	///
	/// Only [VtxoStateKind::Spendable] vtxos can be locked; re-locking a
	/// vtxo that is already in the exact target state (same holder) is a
	/// no-op success, but any other prior state — including a Locked vtxo
	/// owned by a different holder — fails. The whole batch is atomic:
	/// if any vtxo fails the check, no vtxo's state changes.
	///
	/// `holder` records which operation is reserving the vtxos so
	/// "who holds this vtxo?" is a typed lookup. Pass `None` only for
	/// the narrow window before the operation's holder identity is
	/// known (e.g. offboard's preparatory arkoor).
	///
	/// # Errors
	/// - If any VTXO is not Spendable (and not already locked by the same holder).
	/// - If a VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn lock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.set_vtxo_states(
			vtxos, &VtxoState::Locked { holder }, &[VtxoStateKind::Spendable],
		).await
	}

	/// Whether `holder` can still use this VTXO: it is spendable, or already
	/// locked by `holder` itself. Anything else — locked by someone else,
	/// spent, exited, or absent from the wallet — is unavailable.
	///
	/// The shared predicate behind [Wallet::unavailable_vtxos] and
	/// [Wallet::lock_available_vtxos], so the two cannot disagree.
	///
	/// # Errors
	/// - If a database error occurs.
	async fn vtxo_available_for(
		&self,
		vtxo: &Vtxo<Full>,
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<bool> {
		let stored = self.inner.db.get_wallet_vtxo(vtxo.id()).await
			.with_context(|| format!("error querying vtxo {}", vtxo.id()))?;
		Ok(match stored {
			Some(v) => match v.state {
				VtxoState::Spendable => true,
				VtxoState::Locked { holder: ref h } => h == holder,
				_ => false,
			},
			None => false,
		})
	}

	/// The VTXOs of `vtxos` that are no longer available to `holder`, without
	/// touching any of them.
	///
	/// The read-only counterpart of [Wallet::lock_available_vtxos]: use this
	/// to find out what an operation lost while it held no lock, and
	/// [Wallet::lock_available_vtxos] when it is time to claim what is left.
	///
	/// # Errors
	/// - If a database error occurs.
	pub async fn unavailable_vtxos(
		&self,
		vtxos: &[Vtxo<Full>],
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<Vec<VtxoId>> {
		let mut unavailable = Vec::new();
		for vtxo in vtxos.iter() {
			if !self.vtxo_available_for(vtxo, &holder).await? {
				unavailable.push(vtxo.id());
			}
		}
		Ok(unavailable)
	}

	/// Locks the VTXOs still available to `holder` as one atomic batch, and
	/// returns the ones that are not.
	///
	/// The locking counterpart of [Wallet::unavailable_vtxos].
	/// [Wallet::lock_vtxos] is all-or-nothing; this is for operations that
	/// can continue with fewer VTXOs than they started with.
	///
	/// # Errors
	/// - If an available VTXO stopped being available before it was locked.
	/// - If a database error occurs.
	pub async fn lock_available_vtxos(
		&self,
		vtxos: &[Vtxo<Full>],
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<Vec<VtxoId>> {
		let mut available = Vec::with_capacity(vtxos.len());
		let mut unavailable = Vec::new();
		for vtxo in vtxos.iter() {
			if self.vtxo_available_for(vtxo, &holder).await? {
				available.push(vtxo.id());
			} else {
				unavailable.push(vtxo.id());
			}
		}

		self.lock_vtxos(&available, holder).await?;
		Ok(unavailable)
	}

	/// Marks VTXOs as [VtxoState::Spent].
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Spent] will
	/// remain spent without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_spent(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Spent,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Spent, ALLOWED).await
	}

	/// Marks VTXOs as [VtxoState::Exited]. Called from the unilateral exit progression once
	/// every exit transaction has been broadcast — at that point the VTXO is effectively gone
	/// from the protocol's view, but it shouldn't be confused with a forfeited VTXO.
	///
	/// This operation is idempotent: VTXOs already in [VtxoState::Exited] will remain exited
	/// without inserting a redundant state entry.
	///
	/// # Errors
	/// - If the VTXO is in a state other than `Spendable`, `Locked`, or `Exited`.
	/// - If the VTXO doesn't exist.
	/// - If a database error occurs.
	pub async fn mark_vtxos_as_exited(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<()> {
		const ALLOWED: &[VtxoStateKind] = &[
			VtxoStateKind::Spendable,
			VtxoStateKind::Locked,
			VtxoStateKind::Exited,
		];
		self.set_vtxo_states(vtxos, &VtxoState::Exited, ALLOWED).await
	}

	/// Updates the state set the [VtxoState] of VTXOs corresponding to each given
	/// [VtxoId] while validating if the transition is allowed based
	/// on the current state and allowed transitions.
	///
	/// # Parameters
	/// - `vtxos`: The [VtxoId] of each [Vtxo] to update.
	/// - `state`: A reference to the new [VtxoState] that the VTXOs should be transitioned to.
	/// - `allowed_states`: A slice of [VtxoStateKind] representing the permissible current states
	///   from which the VTXOs are allowed to transition to the given `state`. If an empty
	///   slice is passed, all states are allowed.
	///
	/// # Errors
	/// - The database operation to update the states fails.
	/// - The state transition is invalid or does not match the allowed transitions.
	pub async fn set_vtxo_states(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		state: &VtxoState,
		mut allowed_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		if allowed_states.is_empty() {
			allowed_states = VtxoStateKind::ALL;
		}

		let ids: Vec<_> = vtxos.into_iter().map(|v| v.vtxo_id()).collect();
		self.inner.db.update_vtxo_states_checked(&ids, state.clone(), allowed_states).await
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Locked].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_locked_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos.clone(), &VtxoState::Locked { holder }).await?;

		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spendable].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// Also posts the vtxo IDs to the server's recovery mailbox (non-critical, errors are logged).
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spendable_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>> + Clone,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos.clone(), &VtxoState::Spendable).await?;

		// Post vtxo IDs to server for recovery (non-critical, just log errors)
		if let Err(e) = self.post_recovery_vtxo_ids(vtxos.into_iter().map(|v| v.id())).await {
			error!("Failed to post recovery vtxo IDs to server: {:#}", e);
		}

		Ok(())
	}

	/// Stores the given collection of VTXOs in the wallet with an initial state of
	/// [VtxoState::Spent].
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	pub async fn store_spent_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
	) -> anyhow::Result<()> {
		self.store_vtxos(vtxos, &VtxoState::Spent).await
	}

	/// Stores the given collection of VTXOs in the wallet with the given initial state.
	///
	/// It does nothing if the VTXOs already exist.
	///
	/// # Parameters
	/// - `vtxos`: The VTXOs to store in the wallet.
	/// - `state`: The initial state of the VTXOs.
	pub async fn store_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo<Full>>,
		state: &VtxoState,
	) -> anyhow::Result<()> {
		let vtxos = vtxos.into_iter().map(|v| (v, state)).collect::<Vec<_>>();
		if state.kind() == VtxoStateKind::Spendable {
			for (vtxo, _) in &vtxos {
				self.ensure_program_recoveries(std::slice::from_ref(*vtxo)).await?;
			}
		}
		if let Err(e) = self.inner.db.store_vtxos(&vtxos).await {
			error!("An error occurred while storing {} VTXOs: {:#}", vtxos.len(), e);
			Err(e)
		} else {
			debug!("Stored {} VTXOs", vtxos.len());
			trace!("New VTXO IDs: {:?}", vtxos.into_iter().map(|(v, _)| v.id()).collect::<Vec<_>>());
			Ok(())
		}
	}

	/// Ask the server for the status of `vtxo_id` and move the wallet's vtxo along
	/// with it. Adoption only ever moves a vtxo towards spent or in-flight
	/// resolution: a vtxo the wallet has as spent stays spent, even when the server
	/// reports it spendable.
	///
	/// A locked vtxo is left alone and the server isn't asked at all: returns
	/// `Ok(None)`. Unlock the vtxo first if you want its status adopted.
	///
	/// NOTE: Only call this method if you can trust the server.
	pub async fn trust_and_adopt_server_vtxo_status(
		&self,
		vtxo_id: VtxoId,
	) -> anyhow::Result<Option<ServerStatusAdoption>> {
		let stored = self.inner.db.get_wallet_vtxo(vtxo_id).await
			.with_context(|| format!("error querying vtxo {vtxo_id}"))?
			.with_context(|| format!("vtxo {vtxo_id} is not in this wallet"))?;

		if stored.state.kind() == VtxoStateKind::Locked {
			warn!("Cannot trust and adopt server state for {vtxo_id}. \
				The vtxo must be unlocked first");
			return Ok(None);
		}

		let keypair = self.signing_key(&stored.vtxo.user_pubkey()).await?
			.with_context(|| format!("no key for vtxo {vtxo_id} in this wallet"))?;

		let spend_state = self.fetch_vtxo_spend_state(&stored.vtxo, &keypair).await?;
		let adoption = ServerStatusAdoption::from_spend_state(spend_state)
			.with_context(|| format!("cannot decide the state of vtxo {vtxo_id}"))?;

		match adoption {
			ServerStatusAdoption::Spendable => {
				if stored.state.kind() == VtxoStateKind::Spent {
					info!("Server reports vtxo {vtxo_id} spendable, but the wallet has it \
						spent; keeping it spent");
				}
			},
			ServerStatusAdoption::Spent => {
				self.mark_vtxos_as_spent(&[vtxo_id]).await?;
			},
			ServerStatusAdoption::InFlight(_) => {},
		}

		Ok(Some(adoption))
	}

	/// Release `holder`'s lock on the given VTXOs, transitioning each one
	/// to [VtxoState::Spendable]. `holder` must match the value passed to
	/// [Self::lock_vtxos] when the lock was taken; a mismatch (including
	/// `None` vs `Some`) leaves the vtxo untouched. VTXOs not currently
	/// locked by `holder` are silently skipped, so calling this
	/// repeatedly is equivalent to calling it once and can safely be
	/// retried after a crash mid-batch.
	pub async fn unlock_vtxos(
		&self,
		vtxos: impl IntoIterator<Item = impl VtxoRef>,
		holder: Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		for v in vtxos {
			self.inner.db.release_vtxo_lock(v.vtxo_id(), holder.as_ref()).await?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bip39::rand;
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::Secp256k1;

	use ark::vtxo::policy::MAX_BLOCK_DELTA;

	#[test]
	fn vtxo_tree_params_accepts_honest_and_rejects_hostile() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let server = Keypair::new(&secp, &mut rng).public_key();
		let other = Keypair::new(&secp, &mut rng).public_key();

		let exit_delta = BlockDelta::new(144);
		let min_expiry = BlockHeight::new(100_000);

		// Expiry at or above the minimum, with matching pubkey and delta, passes.
		validate_vtxo_tree_params(server, exit_delta, min_expiry, server, exit_delta, min_expiry)
			.expect("expiry exactly at the minimum should validate");
		validate_vtxo_tree_params(
			server, exit_delta, min_expiry + BlockDelta::new(5_000), server, exit_delta, min_expiry,
		).expect("expiry above the minimum should validate");

		// A wrong server pubkey is rejected.
		assert!(validate_vtxo_tree_params(
			other, exit_delta, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "wrong server pubkey must be rejected");

		// An inflated exit delta (hostage) is rejected.
		assert!(validate_vtxo_tree_params(
			server, MAX_BLOCK_DELTA, min_expiry, server, exit_delta, min_expiry,
		).is_err(), "inflated exit delta must be rejected");

		// An expiry below the minimum (e.g. the short-expiry sweep attack) is
		// rejected, right down to a single block short.
		assert!(validate_vtxo_tree_params(
			server, exit_delta, min_expiry.saturating_sub(BlockDelta::new(1)), server, exit_delta, min_expiry,
		).is_err(), "expiry one block below the minimum must be rejected");
	}

	use ark::ProtocolEncoding;
	use ark::tree::signed::{HashlockVersion, VtxoLeafSpec, VtxoTreeSpec};
	use bitcoin::Amount;
	use bitcoin::hashes::{sha256, Hash};
	use bitcoin::secp256k1::PublicKey;

	fn hostile_leaf(
		pk: PublicKey,
		amount: Amount,
		cosign_pubkey: Option<PublicKey>,
	) -> VtxoLeafSpec {
		VtxoLeafSpec {
			vtxo: ark::VtxoRequest {
				amount,
				policy: ark::VtxoPolicy::new_pubkey(pk),
			},
			cosign_pubkey,
			unlock_hash: sha256::Hash::hash(&amount.to_sat().to_le_bytes()),
		}
	}

	fn hostile_spec(
		server: PublicKey,
		vtxos: Vec<VtxoLeafSpec>,
		globals: Vec<PublicKey>,
	) -> VtxoTreeSpec {
		VtxoTreeSpec {
			vtxos,
			expiry_height: BlockHeight::new(100_000),
			server_pubkey: server,
			exit_delta: BlockDelta::new(2016),
			global_cosign_pubkeys: globals,
			hashlock_version: HashlockVersion::V1,
		}
	}

	/// A server-supplied [VtxoTreeSpec] is decoded straight from the wire in
	/// the round flow; tree shapes that can never be cosigned must be
	/// rejected with decoding errors instead of panicking the wallet while
	/// building the tree.
	#[test]
	fn vtxo_tree_spec_rejects_missing_cosign_pubkeys() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let server = Keypair::new(&secp, &mut rng).public_key();
		let cosigner = Keypair::new(&secp, &mut rng).public_key();

		// no cosign pubkeys at all: such a tree can never be signed or spent
		let spec = hostile_spec(server,
			vec![hostile_leaf(server, Amount::from_sat(100_000), None),
				hostile_leaf(server, Amount::from_sat(50_000), None)],
			vec![],
		).serialize();
		let err = VtxoTreeSpec::deserialize(&spec)
			.expect_err("tree without any cosign pubkey must be rejected");
		assert!(err.to_string().contains("at least one cosign pubkey"),
			"unexpected error: {err}");

		// without global cosigners, an internal node whose leaves all lack
		// a cosign pubkey can never be signed either
		let mut vtxos = vec![hostile_leaf(server, Amount::from_sat(5_000), Some(cosigner))];
		vtxos.extend((0..7).map(|i| hostile_leaf(server, Amount::from_sat(5_000 + i), None)));
		let spec = hostile_spec(server, vtxos.clone(), vec![]).serialize();
		let err = VtxoTreeSpec::deserialize(&spec)
			.expect_err("tree with an internal node without cosign pubkeys must be rejected");
		assert!(err.to_string().contains("internal node without cosign pubkeys"),
			"unexpected error: {err}");

		// control: a global cosigner rescues the same leaves
		let spec = hostile_spec(server, vtxos, vec![cosigner]);
		assert_eq!(VtxoTreeSpec::deserialize(&spec.serialize()).unwrap(), spec);
	}

	/// Attackers control the leaf amounts of the trees we sign; amounts must
	/// be bounded so tree building cannot overflow its value sums.
	#[test]
	fn vtxo_tree_spec_rejects_invalid_leaf_amounts() {
		let secp = Secp256k1::new();
		let mut rng = rand::thread_rng();
		let server = Keypair::new(&secp, &mut rng).public_key();
		let cosigner = Keypair::new(&secp, &mut rng).public_key();

		// zero and above-money-supply leaf amounts
		for amount in [Amount::ZERO, Amount::MAX_MONEY + Amount::from_sat(1), Amount::from_sat(u64::MAX)] {
			let spec = hostile_spec(server, vec![hostile_leaf(server, amount, None)], vec![cosigner]).serialize();
			let err = VtxoTreeSpec::deserialize(&spec)
				.expect_err("tree with out-of-range leaf amount must be rejected");
			assert!(err.to_string().contains("leaf amount out of range"),
				"unexpected error: {err}");
		}

		// a total exceeding the money supply used to overflow the panicking
		// leaf-amount sum while building the unsigned tree
		let spec = hostile_spec(server, vec![
			hostile_leaf(server, Amount::MAX_MONEY, Some(cosigner)),
			hostile_leaf(server, Amount::MAX_MONEY, None),
		], vec![cosigner]).serialize();
		let err = VtxoTreeSpec::deserialize(&spec)
			.expect_err("tree with excessive total value must be rejected");
		assert!(err.to_string().contains("total value exceeds maximum money"),
			"unexpected error: {err}");

		// control: the decoded valid spec builds an unsigned tree fine
		let good = hostile_spec(server, vec![
			hostile_leaf(server, Amount::from_int_btc(10_500_000), Some(cosigner)),
			hostile_leaf(server, Amount::from_int_btc(10_500_000), None),
		], vec![cosigner]);
		let decoded = VtxoTreeSpec::deserialize(&good.serialize()).unwrap();
		assert_eq!(decoded, good);
		decoded.into_unsigned_tree(bitcoin::OutPoint::null());
	}
}
