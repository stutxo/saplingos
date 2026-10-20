//! SQLite persistence backend for Bark.
//!
//! This module provides a concrete implementation of the `WalletPersister` trait
//! backed by a local SQLite database. It encapsulates schema creation and
//! migrations, typed query helpers, and conversions between in-memory models
//! and their stored representations. Operations are performed using explicit
//! connections and transactions to ensure atomic updates across related tables,
//! covering wallet properties, movements, vtxos and their states, round
//! lifecycle data, Lightning receives, exit tracking, and sync metadata.

mod convert;
mod migrations;
mod query;


use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::secp256k1::PublicKey;
use chrono::DateTime;
use lightning_invoice::Bolt11Invoice;
use log::debug;
use rusqlite::{Connection, TransactionBehavior};

use ark::{Vtxo, VtxoId};
use ark::lightning::{PaymentHash, Preimage};
use ark::vtxo::Full;

use crate::WalletProperties;
use crate::actions::{WalletActionCheckpoint, WalletActionId};
use crate::exit::{ExitStateKind, ExitTxOrigin};
use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem, PaymentMethod};
use crate::movement::update::MovementUpdate;
use crate::persist::{WalletPersister, RoundStateId, StoredRoundState, Unlocked};
use crate::persist::models::{
	PaidInvoice, ProgramRecoveryRecord, SerdeProgramKey, SettledLightningReceive, StoredExit,
};
use crate::round::RoundState;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind, WalletVtxo};


/// The default sqlite db file for when no file path was provided
pub const DEFAULT_DB_FILE: &str = "db.sqlite";

/// An implementation of the WalletPersister using rusqlite. Changes are persisted using the given
/// [PathBuf].
#[derive(Debug, Clone)]
pub struct SqliteClient {
	connection_string: PathBuf,
}

/// Pre-create a missing db file owner-only.
///
/// The db holds wallet state (movements, vtxos, unrevealed lightning
/// preimages) and SQLite applies `0666 & ~umask` to files it creates itself,
/// so the file must exist with restricted mode before SQLite ever opens it.
/// A pre-existing file is left untouched: [crate::fs_perms::warn_if_loose]
/// nudges rather than overriding a deliberate setup. Rollback-journal
/// sidecars (this codebase never enables WAL) inherit the db file's mode.
#[cfg(unix)]
fn create_owner_only_if_missing(path: &Path) -> anyhow::Result<()> {
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

	// In-memory and URI connection strings are not filesystem paths here.
	let Some(name) = path.as_os_str().to_str() else {
		return Ok(());
	};
	if name == ":memory:" || name.starts_with("file:") {
		return Ok(());
	}

	let check_existing = |meta: &std::fs::Metadata| -> anyhow::Result<()> {
		anyhow::ensure!(!meta.file_type().is_symlink(),
			"refusing symlinked database path {}", path.display());
		anyhow::ensure!(meta.is_file(),
			"database path {} is not a regular file", path.display());
		anyhow::ensure!(meta.nlink() == 1,
			"database path {} has multiple hard links", path.display());
		Ok(())
	};
	match std::fs::symlink_metadata(path) {
		Ok(meta) => return check_existing(&meta),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
		Err(e) => return Err(e)
			.with_context(|| format!("failed to inspect database {}", path.display())),
	}

	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true).mode(0o600)
		// Do not follow a symlink planted in the creation race.
		.custom_flags(libc::O_NOFOLLOW);
	match options.open(path) {
		Ok(file) => {
			let meta = file.metadata()
				.with_context(|| format!("failed to inspect database {}", path.display()))?;
			check_existing(&meta)
		},
		// Another process won the creation race; re-check what appeared.
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
			let meta = std::fs::symlink_metadata(path)
				.with_context(|| format!("failed to inspect database {}", path.display()))?;
			check_existing(&meta)
		},
		Err(e) => Err(e)
			.with_context(|| format!("failed to create database {}", path.display())),
	}
}

#[cfg(not(unix))]
fn create_owner_only_if_missing(_path: &Path) -> anyhow::Result<()> {
	Ok(())
}

impl SqliteClient {
	/// Open a new [SqliteClient] with the given file path
	pub fn open(db_file: impl AsRef<Path>) -> anyhow::Result<SqliteClient> {
		let path = db_file.as_ref().to_path_buf();

		debug!("Opening database at {}", path.display());
		create_owner_only_if_missing(&path)?;
		// SQLITE_OPEN_NOFOLLOW closes the remaining check/open race: a
		// symlink planted after the pre-check is still refused.
		let flags = rusqlite::OpenFlags::default()
			| rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
		let mut conn = rusqlite::Connection::open_with_flags(&path, flags)
			.with_context(|| format!("Error connecting to database {}", path.display()))?;

		// Defense in depth for older or externally-created dbs: warn rather
		// than chmod on every open, which would override a deliberate setup.
		crate::fs_perms::warn_if_loose(&path, 0o600);

		let migrations = migrations::MigrationContext::new();
		migrations.do_all_migrations(&mut conn)?;

		Ok( Self { connection_string: path })
	}

	fn connect(&self) -> anyhow::Result<Connection> {
		rusqlite::Connection::open(&self.connection_string)
			.with_context(|| format!("Error connecting to database {}", self.connection_string.display()))
	}
}

#[async_trait]
impl WalletPersister for SqliteClient {
	async fn init_wallet(&self, properties: &WalletProperties) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		query::set_properties(&tx, properties)?;

		tx.commit()?;
		Ok(())
	}

	#[cfg(feature = "onchain-bdk")]
	async fn initialize_bdk_wallet(&self) -> anyhow::Result<bdk_wallet::ChangeSet> {
	    let mut conn = self.connect()?;
		Ok(bdk_wallet::WalletPersister::initialize(&mut conn)?)
	}

	#[cfg(feature = "onchain-bdk")]
	async fn store_bdk_wallet_changeset(&self, changeset: &bdk_wallet::ChangeSet) -> anyhow::Result<()> {
	    let mut conn = self.connect()?;
		bdk_wallet::WalletPersister::persist(&mut conn, changeset)?;
		Ok(())
	}

	async fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		let conn = self.connect()?;
		Ok(query::fetch_properties(&conn)?)
	}

	async fn set_server_pubkey(&self, server_pubkey: PublicKey) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_server_pubkey(&conn, &server_pubkey)?;
		Ok(())
	}

	async fn set_server_mailbox_pubkey(&self, server_mailbox_pubkey: PublicKey) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_server_mailbox_pubkey(&conn, &server_mailbox_pubkey)?;
		Ok(())
	}

	async fn set_recovery_incomplete(&self, incomplete: bool) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_recovery_incomplete(&conn, incomplete)?;
		Ok(())
	}

	async fn create_new_movement(&self,
		status: MovementStatus,
		subsystem: &MovementSubsystem,
		time: DateTime<chrono::Local>,
		action_id: Option<&str>,
	) -> anyhow::Result<MovementId> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		let movement_id = query::create_new_movement(&tx, status, subsystem, time, action_id)?;
		tx.commit()?;
		Ok(movement_id)
	}

	async fn get_or_create_movement_for_action(
		&self,
		subsystem: &MovementSubsystem,
		time: DateTime<chrono::Local>,
		action_id: &str,
		update: MovementUpdate,
	) -> anyhow::Result<(MovementId, bool)> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		let result = match query::get_movement_id_by_action(&tx, action_id)? {
			Some(id) => (id, false),
			None => {
				let id = query::create_new_movement(
					&tx, MovementStatus::Pending, subsystem, time, Some(action_id))?;
				let mut movement = query::get_movement_by_id(&tx, id)?;
				update.apply_to(&mut movement, time);
				query::update_movement(&tx, &movement)?;
				(id, true)
			},
		};
		tx.commit()?;
		Ok(result)
	}

	async fn update_movement(&self, movement: &Movement) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::update_movement(&tx, movement)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_movement_by_id(&self, movement_id: MovementId) -> anyhow::Result<Movement> {
		let conn = self.connect()?;
		query::get_movement_by_id(&conn, movement_id)
	}

	async fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>> {
		let conn = self.connect()?;
		query::get_all_movements(&conn)
	}

	async fn get_movements_by_payment_method(
		&self,
		payment_method: &PaymentMethod,
	) -> anyhow::Result<Vec<Movement>> {
		let conn = self.connect()?;
		query::get_movements_by_payment_method(&conn, payment_method)
	}

	async fn store_round_state(&self, round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		let conn = self.connect()?;
		query::store_round_state(&conn, round_state)
	}

	async fn update_round_state(&self, state: &StoredRoundState) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::update_round_state(&tx, state)?;
		tx.commit()?;
		Ok(())
	}

	async fn remove_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::remove_round_state(&tx, round_state.id())?;
		tx.commit()?;
		Ok(())
	}

	async fn get_round_state_by_id(&self, id: RoundStateId) -> anyhow::Result<Option<StoredRoundState<Unlocked>>> {
		let conn = self.connect()?;
		query::get_round_state_by_id(&conn, id)
	}

	async fn get_pending_round_state_ids(&self) -> anyhow::Result<Vec<RoundStateId>> {
		let conn = self.connect()?;
		query::get_pending_round_state_ids(&conn)
	}

	async fn store_vtxos(
		&self,
		vtxos: &[(&Vtxo<Full>, &VtxoState)],
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

		for (vtxo, state) in vtxos {
			query::store_vtxo_with_initial_state(&tx, vtxo, state)?;
		}
		tx.commit()?;
		Ok(())
	}

	async fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_wallet_vtxo_by_id(&conn, id)
	}

	async fn get_wallet_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_wallet_vtxos_by_ids(&conn, ids)
	}

	async fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_all_vtxos(&conn)
	}

	/// Get all VTXOs that are in one of the provided states
	async fn get_vtxos_by_state(&self, state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_vtxos_by_state(&conn, state)
	}

	async fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		let conn = self.connect()?;
		let state : Option<VtxoState> = query::get_vtxo_state(&conn, id)?;
		let result = state.map(|s| s == VtxoState::Spent).unwrap_or(false);
		Ok(result)
	}

	async fn get_full_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		let conn = self.connect()?;
		query::get_full_vtxo_by_id(&conn, id)
	}

	async fn get_full_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let conn = self.connect()?;
		query::get_full_vtxos_by_ids(&conn, ids)
	}

	async fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		let mut conn = self.connect()?;
		let tx = conn.transaction().context("Failed to start transaction")?;
		let result = query::delete_vtxo(&tx, id);
		tx.commit().context("Failed to commit transaction")?;
		result
	}

	async fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_vtxo_key(&conn, index, public_key)
	}

	async fn store_program_key(&self, record: &SerdeProgramKey) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		conn.pragma_update(None, "synchronous", "FULL")?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::store_program_key(&tx, record)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_program_key(&self, public_key: &PublicKey)
		-> anyhow::Result<Option<SerdeProgramKey>>
	{
		query::get_program_key(&self.connect()?, public_key)
	}

	async fn get_program_key_by_index(&self, index: u32)
		-> anyhow::Result<Option<SerdeProgramKey>>
	{
		query::get_program_key_by_index(&self.connect()?, index)
	}

	async fn list_program_keys(&self) -> anyhow::Result<Vec<SerdeProgramKey>> {
		query::list_program_keys(&self.connect()?)
	}

	async fn store_program_recoveries(&self, records: &[ProgramRecoveryRecord])
		-> anyhow::Result<()>
	{
		let mut conn = self.connect()?;
		conn.pragma_update(None, "synchronous", "FULL")?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::store_program_recoveries(&tx, records)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_program_recovery(&self, outpoint: OutPoint)
		-> anyhow::Result<Option<ProgramRecoveryRecord>>
	{
		query::get_program_recovery(&self.connect()?, outpoint)
	}

	async fn list_program_recoveries(&self) -> anyhow::Result<Vec<ProgramRecoveryRecord>> {
		query::list_program_recoveries(&self.connect()?)
	}

	async fn reserve_program_recovery(
		&self,
		inputs: &[(VtxoId, Option<VtxoState>)],
		actors: &[String],
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		conn.pragma_update(None, "synchronous", "FULL")?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::reserve_program_recovery(&tx, inputs, actors)?;
		tx.commit()?;
		Ok(())
	}

	async fn has_program_recovery_reservation(&self, key: &str) -> anyhow::Result<bool> {
		let mut conn = self.connect()?;
		conn.pragma_update(None, "synchronous", "FULL")?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		let reserved = query::has_program_recovery_reservation(&tx, key)?;
		tx.commit()?;
		Ok(reserved)
	}

	async fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>> {
		let conn = self.connect()?;
		query::get_last_vtxo_key_index(&conn)
	}

	async fn get_public_key_idx(&self, public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
		let conn = self.connect()?;
		query::get_public_key_idx(&conn, public_key)
	}

	async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		let conn = self.connect()?;
		query::get_mailbox_checkpoint(&conn)
	}

	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_mailbox_checkpoint(&conn, checkpoint)?;
		Ok(())
	}

	async fn upsert_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
		checkpoint: &WalletActionCheckpoint,
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::upsert_wallet_action_checkpoint(&tx, id, checkpoint)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<Option<WalletActionCheckpoint>> {
		let conn = self.connect()?;
		query::get_wallet_action_checkpoint(&conn, id)
	}

	async fn get_all_wallet_action_checkpoints(
		&self,
	) -> anyhow::Result<Vec<WalletActionCheckpoint>> {
		let conn = self.connect()?;
		query::get_all_wallet_action_checkpoints(&conn)
	}

	async fn remove_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::remove_wallet_action_checkpoint(&tx, id)?;
		tx.commit()?;
		Ok(())
	}

	async fn finish_wallet_action(&self, id: &WalletActionId) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		conn.pragma_update(None, "synchronous", "FULL")?;
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
		query::finish_wallet_action(&tx, id)?;
		tx.commit()?;
		Ok(())
	}

	async fn record_paid_invoice(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::record_paid_invoice(&conn, payment_hash, preimage)
	}

	async fn get_paid_invoice(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<PaidInvoice>> {
		let conn = self.connect()?;
		query::get_paid_invoice(&conn, payment_hash)
	}

	async fn record_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
		invoice: &Bolt11Invoice,
		amount: Amount,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::record_settled_lightning_receive(&conn, payment_hash, preimage, invoice, amount)
	}

	async fn get_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<SettledLightningReceive>> {
		let conn = self.connect()?;
		query::get_settled_lightning_receive(&conn, payment_hash)
	}

	async fn store_exit_vtxo_entry(&self, exit: &StoredExit) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit_vtxo_entry(&tx, exit)?;
		tx.commit()?;
		Ok(())
	}

	async fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::remove_exit_vtxo_entry(&tx, &id)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>> {
		let conn = self.connect()?;
		query::get_exit_vtxo_entries(&conn)
	}

	async fn get_exit_vtxo_entries_with_states(
		&self,
		states: &[ExitStateKind],
	) -> anyhow::Result<Vec<StoredExit>> {
		let conn = self.connect()?;
		query::get_exit_vtxo_entries_with_states(&conn, states)
	}

	async fn get_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<Option<StoredExit>> {
		let conn = self.connect()?;
		query::get_exit_vtxo_entry(&conn, id)
	}

	async fn store_exit_child_tx(
		&self,
		exit_txid: Txid,
		child_tx: &bitcoin::Transaction,
		origin: ExitTxOrigin,
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit_child_tx(&tx, exit_txid, child_tx, origin)?;
		tx.commit()?;
		Ok(())
	}

	async fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(bitcoin::Transaction, ExitTxOrigin)>> {
		let conn = self.connect()?;
		query::get_exit_child_tx(&conn, exit_txid)
	}

	async fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind]
	) -> anyhow::Result<WalletVtxo> {
		let conn = self.connect()?;
		query::update_vtxo_state_checked(&conn, vtxo_id, new_state, allowed_old_states)
	}

	async fn release_vtxo_lock(
		&self,
		vtxo_id: VtxoId,
		holder: Option<&VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::release_vtxo_lock(&conn, vtxo_id, holder)
	}

	async fn update_vtxo_states_checked(
		&self,
		vtxo_ids: &[VtxoId],
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::update_vtxo_states_checked(&tx, vtxo_ids, new_state, allowed_old_states)?;
		tx.commit()?;
		Ok(())
	}

	async fn mark_vtxos_registered(&self, vtxo_ids: &[VtxoId]) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::mark_vtxos_registered(&conn, vtxo_ids)
	}

	async fn get_unregistered_vtxo_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		let conn = self.connect()?;
		query::get_unregistered_vtxo_ids(&conn)
	}

}

#[cfg(any(test, doc))]
pub mod helpers {
	use std::path::PathBuf;
	use std::str::FromStr;

	use rusqlite::Connection;

	/// Creates an in-memory sqlite connection.
	///
	/// It returns a [PathBuf] and a [Connection].
	/// The user should ensure the [Connection] isn't dropped
	/// until the test completes. If all connections are dropped during
	/// the test the entire database might be cleared.
	#[cfg(any(test, feature = "rand"))]
	pub fn in_memory_db() -> (PathBuf, Connection) {
		use rand::{distr, RngExt};

		// All tests run in the same process and share the same
		// cache. To ensure that each call to `in_memory` results
		// in a new database a random file-name is generated.
		//
		// This database is deleted once all connections are dropped
		let mut rng = rand::rng();
		let filename: String = (&mut rng).sample_iter(distr::Alphanumeric)
			.take(16).map(char::from).collect();

		let connection_string = format!("file:{}?mode=memory&cache=shared", filename);
		let pathbuf = PathBuf::from_str(&connection_string).unwrap();

		let conn = Connection::open(pathbuf.clone()).unwrap();
		(pathbuf.clone(), conn)
	}
}

#[cfg(test)]
mod test {
	use ark::ProtocolEncoding;
	use ark::test_util::VTXO_VECTORS;

	use crate::{persist::sqlite::helpers::in_memory_db, vtxo::VtxoState};
	use crate::persist::test_suite::bark_persister_tests;
	use crate::persist::models::{recovery_action_key, recovery_round_key, recovery_vtxo_key};

	use super::*;

	#[tokio::test]
	async fn test_add_and_retrieve_vtxos() {
		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let (cs, conn) = in_memory_db();
		let db = SqliteClient::open(cs).unwrap();

		db.store_vtxos(&[
			(vtxo_1, &VtxoState::Spendable), (vtxo_2, &VtxoState::Spendable)
		]).await.unwrap();

		// Check that vtxo-1 can be retrieved from the database. Listings
		// return the bare form, so compare against `to_bare()`.
		let vtxo_1_db = db.get_wallet_vtxo(vtxo_1.id()).await.expect("No error").expect("A vtxo was found");
		assert_eq!(vtxo_1_db.vtxo, vtxo_1.to_bare());

		// Hydrating to full should round-trip back to the original bytes.
		let vtxo_1_full = db.get_full_vtxo(vtxo_1.id()).await.unwrap().unwrap();
		assert_eq!(vtxo_1_full.serialize(), vtxo_1.serialize());

		// Verify that vtxo 3 is not in the database
		assert!(db.get_wallet_vtxo(vtxo_3.id()).await.expect("No error").is_none());

		// Verify that we have two entries in the database
		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await.unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.iter().any(|v| v.vtxo == vtxo_1.to_bare()));
		assert!(vtxos.iter().any(|v| v.vtxo == vtxo_2.to_bare()));
		assert!(!vtxos.iter().any(|v| v.vtxo == vtxo_3.to_bare()));

		// Verify that we can mark a vtxo as spent
		db.update_vtxo_state_checked(
			vtxo_1.id(), VtxoState::Spent, &VtxoStateKind::UNSPENT_STATES,
		).await.unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await.unwrap();
		assert_eq!(vtxos.len(), 1);

		// Add the third entry to the database
		db.store_vtxos(&[(vtxo_3, &VtxoState::Spendable)]).await.unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await.unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.iter().any(|v| v.vtxo == vtxo_2.to_bare()));
		assert!(vtxos.iter().any(|v| v.vtxo == vtxo_3.to_bare()));

		conn.close().unwrap();
	}

	#[tokio::test]
	#[cfg(feature = "onchain-bdk")]
	async fn test_create_wallet_then_load() {
		use bdk_wallet::chain::DescriptorExt;

		let (connection_string, conn) = in_memory_db();

		let db = SqliteClient::open(connection_string).unwrap();
		let network = bitcoin::Network::Testnet;

		let seed = bip39::Mnemonic::generate(12).unwrap().to_seed("");
		let xpriv = bitcoin::bip32::Xpriv::new_master(network, &seed).unwrap();

		let desc = format!("tr({}/84'/0'/0'/*)", xpriv);

		// need to call init before we call store
		let _ = db.initialize_bdk_wallet().await.unwrap();
		let mut created = bdk_wallet::Wallet::create_single(desc.clone())
			.network(network)
			.create_wallet_no_persist()
			.unwrap();
		db.store_bdk_wallet_changeset(&created.take_staged().unwrap()).await.unwrap();

		let loaded = {
			let changeset = db.initialize_bdk_wallet().await.unwrap();
			bdk_wallet::Wallet::load()
				.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
				.extract_keys()
				.check_network(network)
				.load_wallet_no_persist(changeset)
				.unwrap()
		};

		assert!(loaded.is_some());
		assert_eq!(
			created.public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id(),
			loaded.unwrap().public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id()
		);

		// Explicitly close the connection here
		// This ensures the database isn't dropped during the test
		conn.close().unwrap();
	}

	async fn setup(_test: &str) -> (Connection, SqliteClient) {
		let (path, conn) = helpers::in_memory_db();
		(conn, SqliteClient::open(path).unwrap())
	}

	bark_persister_tests!(setup);

	#[tokio::test]
	async fn test_finish_wallet_action_write_failure_rolls_back() {
		// FAIL deliberately leaves the statement's earlier writes in the
		// transaction. Only rolling back the entire transaction restores both
		// the deleted checkpoint and any newly appended state history.
		for trigger in [
			"CREATE TRIGGER fail_finish AFTER DELETE ON bark_wallet_action_checkpoint
			BEGIN SELECT RAISE(FAIL, 'forced completion write failure'); END;",
			"CREATE TRIGGER fail_finish AFTER INSERT ON bark_vtxo_state
			BEGIN SELECT RAISE(FAIL, 'forced completion write failure'); END;",
		] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("wallet.sqlite");
			let db = SqliteClient::open(&path).unwrap();
			let checkpoint: WalletActionCheckpoint =
				crate::persist::test_suite::send_at_start().into();
			let id = checkpoint.id();
			let owned = VtxoState::Locked {
				holder: Some(VtxoLockHolder::Action { id: id.clone() }),
			};
			let vtxos = [&VTXO_VECTORS.board_vtxo, &VTXO_VECTORS.round1_vtxo];
			db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
			for vtxo in vtxos {
				db.store_vtxos(&[(vtxo, &owned)]).await.unwrap();
			}
			db.connect().unwrap().execute_batch(trigger).unwrap();

			let error = db.finish_wallet_action(&id).await.unwrap_err();
			assert!(format!("{error:#}").contains("forced completion write failure"));
			drop(db);
			let db = SqliteClient::open(&path).unwrap();
			assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(),
				Some(checkpoint));
			for vtxo in vtxos {
				assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, owned);
				assert_eq!(db.get_full_vtxo(vtxo.id()).await.unwrap().as_ref(), Some(vtxo));
			}
			let history_count: u64 = db.connect().unwrap().query_row(
				"SELECT COUNT(*) FROM bark_vtxo_state", [], |row| row.get(0),
			).unwrap();
			assert_eq!(history_count, 2, "failed writes must not leave partial state history");
			db.connect().unwrap().execute_batch("DROP TRIGGER fail_finish").unwrap();

			db.finish_wallet_action(&id).await.unwrap();
			drop(db);
			let db = SqliteClient::open(&path).unwrap();
			db.finish_wallet_action(&id).await.unwrap();
			assert!(db.get_wallet_action_checkpoint(&id).await.unwrap().is_none());
			for vtxo in vtxos {
				assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state,
					VtxoState::Spendable);
			}
			let history_count: u64 = db.connect().unwrap().query_row(
				"SELECT COUNT(*) FROM bark_vtxo_state", [], |row| row.get(0),
			).unwrap();
			assert_eq!(history_count, 4, "retry must not append redundant unlocks");
		}
	}

	#[tokio::test]
	async fn program_records_survive_migration_and_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.sqlite");
		let key = crate::persist::test_suite::program_key_fixture();
		let recovery = crate::persist::test_suite::program_recovery_fixture();
		let ordinary_key = key.program.user_pubkey;
		let db = SqliteClient::open(&path).unwrap();
		db.store_vtxo_key(0, ordinary_key).await.unwrap();
		// Removing the additive program tables and their version markers
		// reconstructs the schema immediately before program persistence.
		// The recovery_incomplete column is additive too, so it must go for
		// its migration to replay cleanly.
		db.connect().unwrap().execute_batch(
			"DROP TABLE bark_program_key;
			DROP TABLE bark_program_recovery;
			DROP TABLE bark_program_recovery_reservation;
			ALTER TABLE bark_properties DROP COLUMN recovery_incomplete;
			DELETE FROM migrations WHERE value >= 43;"
		).unwrap();
		drop(db);

		let db = SqliteClient::open(&path).unwrap();
		assert_eq!(db.get_public_key_idx(&ordinary_key).await.unwrap(), Some(0));
		assert!(db.list_program_keys().await.unwrap().is_empty());
		assert!(db.list_program_recoveries().await.unwrap().is_empty());
		db.store_program_key(&key).await.unwrap();
		db.store_program_recoveries(&[recovery.clone()]).await.unwrap();
		drop(db);

		let db = SqliteClient::open(&path).unwrap();
		assert_eq!(db.get_program_key(&key.program.public_key().unwrap()).await.unwrap(), Some(key.clone()));
		assert_eq!(db.get_public_key_idx(&key.program.public_key().unwrap()).await.unwrap(), Some(key.index));
		assert_eq!(db.get_public_key_idx(&ordinary_key).await.unwrap(), Some(0));
		assert_eq!(db.get_program_recovery(recovery.controlled_outpoint).await.unwrap(), Some(recovery.clone()));
		assert_eq!(db.list_program_recoveries().await.unwrap(), vec![recovery]);
	}

	#[tokio::test]
	async fn program_recovery_rejects_stale_snapshots_without_partial_reservations() {
		// Force the competing writer to commit between snapshot and takeover:
		// no scheduling or timestamp assumptions are needed.
		for expected in [
			None,
			Some(VtxoState::Spendable),
			Some(VtxoState::Locked { holder: None }),
			Some(VtxoState::Locked {
				holder: Some(VtxoLockHolder::Movement { id: MovementId::new(1) }),
			}),
		] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("wallet.sqlite");
			let db = SqliteClient::open(&path).unwrap();
			let competitor = SqliteClient::open(&path).unwrap();
			let first = &VTXO_VECTORS.board_vtxo;
			let raced = &VTXO_VECTORS.round1_vtxo;
			db.store_vtxos(&[(first, &VtxoState::Spendable)]).await.unwrap();
			if let Some(state) = &expected {
				db.store_vtxos(&[(raced, state)]).await.unwrap();
			}
			let inputs = [(first.id(), Some(VtxoState::Spendable)), (raced.id(), expected.clone())];
			let new_state = VtxoState::Locked {
				holder: Some(VtxoLockHolder::Movement { id: MovementId::new(2) }),
			};
			if expected.is_some() {
				competitor.update_vtxo_state_checked(
					raced.id(), new_state.clone(), &VtxoStateKind::UNSPENT_STATES,
				).await.unwrap();
			} else {
				competitor.store_vtxos(&[(raced, &new_state)]).await.unwrap();
			}
			let actor = recovery_action_key("stale-actor");
			assert!(db.reserve_program_recovery(&inputs, &[actor.clone()]).await.is_err());
			for key in [recovery_vtxo_key(first.id()), recovery_vtxo_key(raced.id()), actor] {
				assert!(!db.has_program_recovery_reservation(&key).await.unwrap());
			}
			assert_eq!(db.get_wallet_vtxo(first.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
			assert_eq!(db.get_wallet_vtxo(raced.id()).await.unwrap().unwrap().state, new_state);
		}
	}

	#[tokio::test]
	async fn program_recovery_write_failure_rolls_back_every_reservation_and_state() {
		for trigger in [
			"CREATE TRIGGER fail_recovery AFTER INSERT ON bark_program_recovery_reservation
			WHEN NEW.key LIKE 'action/%'
			BEGIN SELECT RAISE(FAIL, 'forced recovery write failure'); END;",
			"CREATE TRIGGER fail_recovery AFTER INSERT ON bark_vtxo_state
			BEGIN SELECT RAISE(FAIL, 'forced recovery write failure'); END;",
		] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("wallet.sqlite");
			let db = SqliteClient::open(&path).unwrap();
			let first = &VTXO_VECTORS.board_vtxo;
			let second = &VTXO_VECTORS.round1_vtxo;
			let absent = VTXO_VECTORS.round2_vtxo.id();
			db.store_vtxos(&[(first, &VtxoState::Spendable), (second, &VtxoState::Spendable)])
				.await.unwrap();
			let inputs = [
				(first.id(), Some(VtxoState::Spendable)),
				(second.id(), Some(VtxoState::Spendable)),
				(absent, None),
			];
			let actor = recovery_action_key("rollback-actor");
			db.connect().unwrap().execute_batch(trigger).unwrap();
			let error = db.reserve_program_recovery(&inputs, &[actor.clone()]).await.unwrap_err();
			assert!(format!("{error:#}").contains("forced recovery write failure"));
			drop(db);
			let db = SqliteClient::open(&path).unwrap();
			for (id, expected) in &inputs {
				assert!(!db.has_program_recovery_reservation(&recovery_vtxo_key(*id)).await.unwrap());
				assert_eq!(db.get_wallet_vtxo(*id).await.unwrap().map(|v| v.state), *expected);
			}
			assert!(!db.has_program_recovery_reservation(&actor).await.unwrap());
			let history_count: u64 = db.connect().unwrap().query_row(
				"SELECT COUNT(*) FROM bark_vtxo_state", [], |row| row.get(0),
			).unwrap();
			assert_eq!(history_count, 2);
			db.connect().unwrap().execute_batch("DROP TRIGGER fail_recovery").unwrap();
			db.reserve_program_recovery(&inputs, &[actor.clone()]).await.unwrap();
			assert!(db.has_program_recovery_reservation(&actor).await.unwrap());
			for (id, expected) in &inputs {
				assert!(db.has_program_recovery_reservation(&recovery_vtxo_key(*id)).await.unwrap());
				assert_eq!(db.get_wallet_vtxo(*id).await.unwrap().map(|v| v.state),
					expected.as_ref().map(|_| VtxoState::Exited));
			}
		}
	}

	#[tokio::test]
	async fn program_recovery_tombstones_preserve_checkpoints_and_unselected_locks() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.sqlite");
		let db = SqliteClient::open(&path).unwrap();
		let checkpoint: WalletActionCheckpoint = crate::persist::test_suite::send_at_start().into();
		let id = checkpoint.id();
		let actor = recovery_action_key(&id);
		let owned = VtxoState::Locked {
			holder: Some(VtxoLockHolder::Action { id: id.clone() }),
		};
		let selected = &VTXO_VECTORS.board_vtxo;
		let unselected = &VTXO_VECTORS.round1_vtxo;
		let spent = &VTXO_VECTORS.round2_vtxo;
		let exited = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let absent = VtxoId::from_slice(&[0xedu8; 36]).unwrap();
		db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
		db.store_vtxos(&[
			(selected, &owned), (unselected, &owned),
			(spent, &VtxoState::Spent), (exited, &VtxoState::Exited),
		]).await.unwrap();
		let record = crate::persist::test_suite::program_recovery_fixture();
		db.store_program_recoveries(&[record.clone()]).await.unwrap();
		// Reconstruct version 43 with real actor and recovery data, then
		// migrate forward before taking over. The new table is purely additive.
		db.connect().unwrap().execute_batch(
			"DROP TABLE bark_program_recovery_reservation;
			ALTER TABLE bark_properties DROP COLUMN recovery_incomplete;
			DELETE FROM migrations WHERE value >= 44;"
		).unwrap();
		drop(db);
		let db = SqliteClient::open(&path).unwrap();
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(checkpoint.clone()));
		assert_eq!(db.get_program_recovery(record.controlled_outpoint).await.unwrap(), Some(record.clone()));
		assert!(!db.has_program_recovery_reservation(&actor).await.unwrap());
		db.reserve_program_recovery(&[
			(selected.id(), Some(owned.clone())), (spent.id(), Some(VtxoState::Spent)),
			(exited.id(), Some(VtxoState::Exited)), (absent, None),
		], &[actor.clone()]).await.unwrap();
		drop(db);

		let db = SqliteClient::open(&path).unwrap();
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert!(db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.is_err());
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(checkpoint.clone()));
		assert!(db.get_all_wallet_action_checkpoints().await.unwrap().contains(&checkpoint));
		assert_eq!(db.get_wallet_vtxo(unselected.id()).await.unwrap().unwrap().state, owned);
		for (vtxo, state) in [(selected, VtxoState::Exited), (spent, VtxoState::Spent), (exited, VtxoState::Exited)] {
			assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, state);
			assert_eq!(db.get_full_vtxo(vtxo.id()).await.unwrap().as_ref(), Some(vtxo));
			assert!(db.has_program_recovery_reservation(&recovery_vtxo_key(vtxo.id())).await.unwrap());
		}
		assert!(db.has_program_recovery_reservation(&recovery_vtxo_key(absent)).await.unwrap());
		assert!(db.get_wallet_vtxo(absent).await.unwrap().is_none());
		assert_eq!(db.get_program_recovery(record.controlled_outpoint).await.unwrap(), Some(record));
		let history_count: u64 = db.connect().unwrap().query_row(
			"SELECT COUNT(*) FROM bark_vtxo_state", [], |row| row.get(0),
		).unwrap();
		assert_eq!(history_count, 5, "terminal states must not append history");

		// Actor checkpoints may be the only source of signed recovery data.
		// Neither removing an input nor attempting cleanup can discard them.
		assert!(db.remove_wallet_action_checkpoint(&id).await.is_err());
		db.remove_vtxo(selected.id()).await.unwrap();
		drop(db);
		let db = SqliteClient::open(&path).unwrap();
		assert!(db.has_program_recovery_reservation(&actor).await.unwrap());
		assert!(db.has_program_recovery_reservation(&recovery_vtxo_key(selected.id())).await.unwrap());
		assert_eq!(db.get_wallet_action_checkpoint(&id).await.unwrap(), Some(checkpoint.clone()));
		assert!(db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.is_err());
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert_eq!(db.get_wallet_vtxo(unselected.id()).await.unwrap().unwrap().state, owned);
	}

	#[tokio::test]
	async fn program_recovery_serializes_actor_writes_and_blocks_round_restart() {
		use crate::lock_manager::LockManager;
		use crate::lock_manager::memory::MemoryLockManager;
		use crate::round::{RoundFlowState, RoundParticipation};

		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.sqlite");
		let db = SqliteClient::open(&path).unwrap();
		let round = RoundState {
			done: false,
			participation: RoundParticipation {
				inputs: vec![], outputs: vec![], unblinded_mailbox_id: None,
			},
			flow: RoundFlowState::InteractivePending,
			new_vtxos: vec![],
			sent_forfeit_sigs: false,
			forfeit_bundles: Some(Vec::new()),
			movement_id: None,
		};
		let id = db.store_round_state(&round).await.unwrap();
		let manager = MemoryLockManager::new();
		let guard = manager.try_lock("test.recovery.round").await.unwrap();
		let mut stored = db.get_round_state_by_id(id).await.unwrap().unwrap().lock(guard);
		db.update_round_state(&stored).await.unwrap();
		let checkpoint: WalletActionCheckpoint = crate::persist::test_suite::send_at_start().into();
		let action = checkpoint.id();
		db.upsert_wallet_action_checkpoint(&action, &checkpoint).await.unwrap();

		let mut conn = db.connect().unwrap();
		conn.pragma_update(None, "synchronous", "FULL").unwrap();
		let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
		query::reserve_program_recovery(
			&tx, &[], &[recovery_round_key(id), recovery_action_key(&action)],
		).unwrap();
		let mut competitor = db.connect().unwrap();
		competitor.busy_timeout(std::time::Duration::ZERO).unwrap();
		// A normal actor writer cannot acquire its transaction while takeover
		// is uncommitted, so there is no check/write interleaving window.
		let error = competitor.transaction_with_behavior(TransactionBehavior::Immediate).unwrap_err();
		assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
		tx.commit().unwrap();

		let tx = competitor.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
		stored.state_mut().done = true;
		assert!(query::update_round_state(&tx, &stored).is_err());
		assert!(query::upsert_wallet_action_checkpoint(&tx, &action, &checkpoint).is_err());
		assert!(query::finish_wallet_action(&tx, &action).is_err());
		assert!(query::remove_round_state(&tx, id).is_err());
		assert!(query::remove_wallet_action_checkpoint(&tx, &action).is_err());
		tx.commit().unwrap();
		assert!(db.update_round_state(&stored).await.is_err());
		assert!(!db.get_round_state_by_id(id).await.unwrap().unwrap().state().done);
		assert!(db.remove_round_state(&stored).await.is_err());
		assert!(!db.get_round_state_by_id(id).await.unwrap().unwrap().state().done);
		assert!(db.has_program_recovery_reservation(&recovery_round_key(id)).await.unwrap());
		assert!(db.update_round_state(&stored).await.is_err());
	}

	#[tokio::test]
	async fn program_recovery_wins_against_new_locks_and_live_reimports() {
		for initial in [VtxoState::Spendable, VtxoState::Locked { holder: None }, VtxoState::Spent] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("wallet.sqlite");
			let db = SqliteClient::open(&path).unwrap();
			let competitor = SqliteClient::open(&path).unwrap();
			let vtxo = &VTXO_VECTORS.board_vtxo;
			db.store_vtxos(&[(vtxo, &initial)]).await.unwrap();
			db.reserve_program_recovery(&[(vtxo.id(), Some(initial.clone()))], &[]).await.unwrap();
			let final_state = if initial == VtxoState::Spent { VtxoState::Spent } else { VtxoState::Exited };
			for live in [VtxoState::Spendable, VtxoState::Locked { holder: None }] {
				assert!(competitor.update_vtxo_state_checked(
					vtxo.id(), live.clone(), VtxoStateKind::ALL,
				).await.is_err());
				assert!(competitor.update_vtxo_states_checked(
					&[vtxo.id()], live.clone(), VtxoStateKind::ALL,
				).await.is_err());
				assert!(competitor.store_vtxos(&[(vtxo, &live)]).await.is_err());
			}
			competitor.release_vtxo_lock(vtxo.id(), None).await.unwrap();
			assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, final_state);
			competitor.update_vtxo_state_checked(vtxo.id(), final_state.clone(), &[]).await.unwrap();
			competitor.store_vtxos(&[(vtxo, &final_state)]).await.unwrap();
			db.remove_vtxo(vtxo.id()).await.unwrap();
			assert!(competitor.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.is_err());
			assert!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().is_none());
		}
	}

	#[tokio::test]
	async fn program_recovery_blocks_future_outputs_and_unspent_ancestor_imports() {
		let ancestor = &VTXO_VECTORS.board_vtxo;
		let successor = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		assert!(successor.transactions().any(|item|
			item.tx.input.iter().any(|input| input.previous_output == ancestor.id().to_point())));
		for initial in [
			None, Some(VtxoState::Locked { holder: None }), Some(VtxoState::Exited),
			Some(VtxoState::Spent),
		] {
			let directory = tempfile::tempdir().unwrap();
			let path = directory.path().join("wallet.sqlite");
			let db = SqliteClient::open(&path).unwrap();
			let competitor = SqliteClient::open(&path).unwrap();
			if let Some(state) = &initial {
				db.store_vtxos(&[(ancestor, state)]).await.unwrap();
			}
			db.reserve_program_recovery(&[(ancestor.id(), initial.clone())], &[]).await.unwrap();
			let historical_spend = initial == Some(VtxoState::Spent);
			for live in [VtxoState::Spendable, VtxoState::Locked { holder: None }] {
				// An unrelated first row must roll back when the successor fails.
				let unrelated = &VTXO_VECTORS.round1_vtxo;
				let result = competitor.store_vtxos(&[(unrelated, &live), (successor, &live)]).await;
				assert_eq!(result.is_ok(), historical_spend);
				assert_eq!(db.get_wallet_vtxo(unrelated.id()).await.unwrap().is_some(), historical_spend);
				assert_eq!(db.get_wallet_vtxo(successor.id()).await.unwrap().is_some(), historical_spend);
			}
			// Terminal imports remain available to preserve recovery history.
			competitor.store_vtxos(&[(successor, &VtxoState::Exited)]).await.unwrap();
		}

		let directory = tempfile::tempdir().unwrap();
		let db = SqliteClient::open(directory.path().join("wallet.sqlite")).unwrap();
		db.reserve_program_recovery(&[(successor.id(), None)], &[]).await.unwrap();
		assert!(db.store_vtxos(&[(successor, &VtxoState::Spendable)]).await.is_err());
		assert!(db.get_wallet_vtxo(successor.id()).await.unwrap().is_none());
		db.store_vtxos(&[(successor, &VtxoState::Exited)]).await.unwrap();
		assert_eq!(db.get_wallet_vtxo(successor.id()).await.unwrap().unwrap().state, VtxoState::Exited);
	}

	/// A freshly created wallet db must be owner-only even under the
	/// widespread default umask 022, under which SQLite alone would apply
	/// 0644.
	#[cfg(unix)]
	#[test]
	fn fresh_db_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt;

		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.sqlite");

		// umask is process-global state shared with parallel tests; change
		// it only around the creation.
		let previous = unsafe { libc::umask(0o022) };
		let db = SqliteClient::open(&path).unwrap();
		unsafe { libc::umask(previous) };

		let mode = std::fs::metadata(&path).unwrap().permissions().mode();
		assert_eq!(mode & 0o777, 0o600,
			"fresh wallet db must be owner-only, got {:o}", mode & 0o777);

		// The pre-created file must behave like a normal database.
		let one: i64 = db.connect().unwrap()
			.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
		assert_eq!(one, 1);
	}

	/// A symlink planted where the wallet database belongs must be refused,
	/// not followed: SQLite would create/overwrite the link target.
	#[cfg(unix)]
	#[test]
	fn symlinked_db_path_is_refused() {
		use std::os::unix::fs::symlink;

		let directory = tempfile::tempdir().unwrap();
		let victim = directory.path().join("victim");
		std::fs::write(&victim, b"do not touch").unwrap();
		let link = directory.path().join("wallet.sqlite");
		symlink(&victim, &link).unwrap();

		let err = SqliteClient::open(&link).unwrap_err();
		assert!(format!("{err:#}").contains("symlink"), "unexpected error: {err:#}");
		assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
	}

	/// A pre-existing loose db keeps working and keeps its mode:
	/// [crate::fs_perms::warn_if_loose] only nudges and must never silently
	/// re-chmod a deliberate setup.
	#[cfg(unix)]
	#[test]
	fn existing_world_readable_db_still_opens_and_keeps_its_mode() {
		use std::os::unix::fs::PermissionsExt;

		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.sqlite");
		std::fs::write(&path, b"").unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

		let db = SqliteClient::open(&path).unwrap();
		let one: i64 = db.connect().unwrap()
			.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
		assert_eq!(one, 1);

		let mode = std::fs::metadata(&path).unwrap().permissions().mode();
		assert_eq!(mode & 0o777, 0o644,
			"opening must not override an existing file's mode, got {:o}", mode & 0o777);
	}
}
