//! Storage adaptor module providing the [StorageAdaptor] trait and blanket
//! implementation of [WalletPersister] for any type implementing [StorageAdaptor].
//!
//! This module provides an optimized single-table storage abstraction that can be
//! efficiently implemented on various backends (SQLite, Postgres, MongoDB, Firebase,
//! in-memory, etc.).
//!
//! The design uses structured keys:
//! - **Primary key (`pk`)**: Unique identifier for each record
//! - **Partition key**: Groups related records for efficient querying
//! - **Sort key**: Enables ordered iteration and range queries
//!
//! # Example
//!
//! ```rust
//! # use sapling::persist::adaptor::memory::MemoryStorageAdaptor;
//! # use sapling::persist::adaptor::{Query, Record, StorageAdaptor, SortKey};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create an in-memory storage adaptor
//! let mut storage = MemoryStorageAdaptor::new();
//!
//! // Store a record sorted by a numeric field (ascending)
//! let record = Record {
//!     partition: 0,
//!     pk: "item:1".into(),
//!     sort_key: Some(SortKey::u32_asc(42)),
//!     data: b"hello world".to_vec(),
//! };
//! storage.put(record).await?;
//!
//! // Query with efficient index scan
//! let query = Query::new_full_range(0).limit(10);
//! let records = storage.query_sorted(query).await?;
//! # Ok(())
//! # }
//! ```

mod sort;

#[cfg(feature = "filestore")]
pub mod filestore;
pub mod memory;
pub use self::sort::{SortKey, SortKeyBuilder};

#[cfg(feature = "indexed-db")]
pub mod indexed_db;

use std::collections::BTreeMap;
use std::ops::RangeBounds;

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::Hash;
#[cfg(feature = "onchain-bdk")]
use bdk_core::Merge;
#[cfg(feature = "onchain-bdk")]
use bdk_wallet::ChangeSet;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;
use serde::{de::DeserializeOwned, Serialize};

use ark::lightning::{PaymentHash, Preimage};
use ark::{Vtxo, VtxoId};
use ark::vtxo::Full;

use crate::actions::{WalletActionCheckpoint, WalletActionId};
use crate::exit::{ExitStateKind, ExitTxOrigin};
use crate::movement::{
	Movement, MovementId, MovementStatus, MovementSubsystem, PaymentMethod,
};
use crate::movement::update::MovementUpdate;
use crate::persist::WalletPersister;
use crate::persist::models::{
	merge_program_recovery, PaidInvoice, ProgramRecoveryRecord, RoundStateId, SerdeExitChildTx,
	recovery_action_key, recovery_round_key, recovery_vtxo_key,
	SerdeProgramKey, SerdeRoundState, SerdeVtxo, SerdeVtxoKey,
	SettledLightningReceive, StoredExit, StoredRoundState, Unlocked, wallet_vtxo_from_full,
};
use crate::round::RoundState;
use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};
use crate::{WalletProperties, WalletVtxo};


pub mod partition {
	pub const PROPERTIES: u8 = 0;
	#[allow(unused)]
	pub const BDK_CHANGESET: u8 = 1;
	pub const VTXO: u8 = 2;
	pub const PUBLIC_KEY: u8 = 3;
	pub const PENDING_BOARD: u8 = 4;
	pub const ROUND_STATE: u8 = 5;
	pub const MOVEMENT: u8 = 6;
	/// was used by the now-removed `bark_lightning_send`. Do not reuse.
	#[allow(unused)]
	pub const LEGACY_LIGHTNING_SEND: u8 = 7;
	/// was used by the now-removed legacy `bark_pending_lightning_receive`.
	/// Do not reuse. In-flight receives now live in WALLET_ACTION_CHECKPOINT
	/// and settled ones in SETTLED_LIGHTNING_RECEIVE.
	#[allow(unused)]
	pub const LEGACY_LIGHTNING_RECEIVE: u8 = 8;
	pub const EXIT_VTXO: u8 = 9;
	pub const EXIT_CHILD_TX: u8 = 10;
	pub const MAILBOX_CHECKPOINT: u8 = 11;
	/// was used by the now-removed `PENDING_OFFBOARD`; superseded by
	/// [`WALLET_ACTION_CHECKPOINT`]. Do not reuse.
	#[allow(unused)]
	pub const LEGACY_PENDING_OFFBOARD: u8 = 12;
	/// An index table for payment method to movement
	pub const MOVEMENT_PAYMENT_METHOD: u8 = 13;
	/// Per-action checkpoint payloads keyed by [crate::actions::WalletActionId].
	pub const WALLET_ACTION_CHECKPOINT: u8 = 14;
	/// Permanent record of every settled outgoing lightning payment,
	/// keyed by payment hash.
	pub const PAID_INVOICE: u8 = 15;
	/// Permanent record of every settled incoming lightning receive,
	/// keyed by payment hash.
	pub const SETTLED_LIGHTNING_RECEIVE: u8 = 16;
	/// An index from [crate::actions::WalletActionId] to the movement that action owns, so a
	/// re-driven action step reuses its movement instead of duplicating it.
	pub const MOVEMENT_ACTION: u8 = 17;
	/// Immutable program descriptors keyed by their aggregate public key.
	pub const PROGRAM_KEY: u8 = 18;
	/// Raw, wallet-verified recovery records keyed by controlled outpoint.
	pub const PROGRAM_RECOVERY: u8 = 19;
	/// Uniquely reserves a derivation index, including ordinary VTXO keys.
	pub const PUBLIC_KEY_INDEX: u8 = 20;
	/// Permanent recovery ownership tombstones, keyed by actor or VTXO key.
	pub const PROGRAM_RECOVERY_RESERVATION: u8 = 21;

	pub const LAST_IDS: u8 = u8::MAX;
}

/// A storage record with structured keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
	/// Partition key for grouping related records (e.g., "vtxo", "movement").
	///
	/// Queries always filter by partition.
	pub partition: u8,

	/// Unique primary key
	pub pk: Vec<u8>,

	/// Optional sort key for ordered iteration within a partition.
	///
	/// Use [`SortKey::builder()`] to construct composite keys with
	/// mixed sort directions.
	///
	/// This field may be set or changed after record insertion.
	/// Implementation should support updating the sort key of a
	/// record post-insert if needed.
	pub sort_key: Option<SortKey>,

	/// The record data encoded as JSON.
	pub data: Vec<u8>,
}

impl Record {
	/// Converts the record data to a typed value.
	fn to_data<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
		serde_json::from_slice(&self.data).map_err(Into::into)
	}

	/// Creates a new record from a typed value.
	fn from_data<T: Serialize>(
		partition: u8,
		pk: &[u8],
		sort_key: Option<SortKey>,
		data: &T,
	) -> anyhow::Result<Record> {
		Ok(Record {
			partition,
			pk: pk.to_vec(),
			sort_key,
			data: serde_json::to_vec(data)?,
		})
	}
}

/// One compare-and-swap in an atomic batch.
///
/// `previous` is the exact record read by the caller, or `None` for an absent
/// key. `updated` is the replacement, or `None` to delete the previous record.
/// At least one record must be present. When both are present, their partition
/// and primary key must agree. Duplicate keys in a batch are rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordUpdate {
	pub previous: Option<Record>,
	pub updated: Option<Record>,
}

impl RecordUpdate {
	fn record(&self) -> anyhow::Result<&Record> {
		self.updated.as_ref().or(self.previous.as_ref())
			.context("atomic update has neither a previous nor an updated record")
	}
}

fn validate_record_updates(updates: &[RecordUpdate]) -> anyhow::Result<()> {
	let mut keys = std::collections::HashSet::with_capacity(updates.len());
	for update in updates {
		let record = update.record()?;
		anyhow::ensure!(keys.insert((record.partition, &record.pk)),
			"duplicate record in atomic batch");
		if let Some(previous) = &update.previous {
			anyhow::ensure!(previous.partition == record.partition && previous.pk == record.pk,
				"atomic update changes its record key");
		}
	}
	Ok(())
}

/// A range of sort keys.
pub trait QueryRange: RangeBounds<SortKey> + Send {}

impl<R: RangeBounds<SortKey> + Send> QueryRange for R {}

/// Query specification for retrieving sorted records from a partition.
#[derive(Debug, Clone)]
pub struct Query<R: QueryRange> {
	/// Partition to query (required).
	pub partition: u8,

	/// Range of sort keys to query.
	pub range: R,

	/// Maximum number of records to return.
	pub limit: Option<usize>,
}

impl<R: QueryRange> Query<R> {
	/// Creates a new query for the given partition.
	pub fn new(partition: u8, range: R) -> Self {
		Self {
			partition,
			range,
			limit: None,
		}
	}

	/// Sets the maximum number of records to return.
	///
	/// If the range is greater than the limit, the query will
	/// return the first `limit` records.
	pub fn limit(mut self, limit: usize) -> Self {
		self.limit = Some(limit);
		self
	}
}

impl Query<std::ops::RangeFull> {
	pub fn new_full_range(partition: u8) -> Self {
		Self::new(partition, ..)
	}
}

fn serialize_payment_method(pm: &PaymentMethod) -> Vec<u8> {
	let body = pm.value_string();

	let mut buf = Vec::with_capacity(pm.type_str().len() + 1 + body.len());
	buf.extend(pm.type_str().as_bytes().iter().copied());
	// nb we need to separate with a non-utf8 byte
	// we use 0xfe so that we can easily query on prefix from <type>0xfe .. <type>0xff
	buf.push(0xfe);
	buf.extend(body.into_bytes());
	buf
}

/// Write a movement record and its payment-method index records through the
/// given adaptor guard. Shared by the plain update path and the atomic
/// action-owned create path.
async fn write_movement_records<S: StorageAdaptor>(
	guard: &mut S,
	movement: &Movement,
) -> anyhow::Result<()> {
	let record = Record::from_data(
		partition::MOVEMENT,
		&movement.id.to_bytes(),
		Some(sort::movement_sort_key(&movement.time.created_at)),
		movement,
	)?;
	guard.put(record).await?;

	// then add records for each payment method
	let sent = movement.sent_to.iter().map(|d| &d.destination);
	let rcvd = movement.received_on.iter().map(|d| &d.destination);
	for pm in sent.chain(rcvd) {
		let pm_bytes = serialize_payment_method(pm);
		let primary_key = {
			// We just need a unique key, but we will never query using this
			let mut buf = Vec::with_capacity(pm_bytes.len() + 4);
			buf.extend(pm_bytes.iter().copied());
			buf.extend(movement.id.to_bytes());
			buf
		};
		let record = Record::from_data(
			partition::MOVEMENT_PAYMENT_METHOD,
			&primary_key,
			Some(SortKey::from_bytes(pm_bytes)),
			&movement.id.0,
		)?;
		guard.put(record).await?;
	}
	Ok(())
}

/// Storage adaptor trait for persistence backends.
///
/// This trait provides a minimal interface (5 methods) that can be efficiently
/// implemented on various storage backends while enabling query optimization.
///
/// # Implementor's Guide
///
/// ## Simple backends (memory, file-based)
///
/// Store records in a map/list keyed by `(partition, pk)`.
///
/// - `query_sorted`: query sorted records by partition, excluding those without
///	  a sort key defined.
/// - `get_all`: return every record in the partition regardless of whether it
///   has a sort key. No ordering is guaranteed.
///
/// ## Database backends (Postgres, MongoDB, Firebase, IndexedDB, etc.)
///
/// Create a single table with indexes:
///
/// ```sql
/// CREATE TABLE storage (
///     pk TEXT PRIMARY KEY,
///     partition TEXT NOT NULL,
///     sort_key BLOB,
///     data BLOB NOT NULL
/// );
/// CREATE INDEX idx_partition_sort ON storage(partition, sort_key);
/// ```
///
/// Translate [`Query`] to SQL:
///
/// ```sql
/// -- query_sorted: only returns records with a sort key
/// SELECT * FROM storage
/// WHERE partition = :partition AND sort_key IS NOT NULL
/// ORDER BY sort_key DESC
/// ```
///
/// Translate [`get_all`](StorageAdaptor::get_all) to SQL:
///
/// ```sql
/// -- get_all: returns all records in the partition, no ordering
/// SELECT * FROM storage
/// WHERE partition = :partition
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageAdaptor: Send + Sync + 'static {
	/// Stores a record, inserting or updating by primary key.
	async fn put(&mut self, record: Record) -> anyhow::Result<()>;

	/// Atomically compare every previous record, then commit all replacements
	/// and deletions.
	///
	/// Validate every previous record before any mutation. Conflicts or write
	/// failures must never commit only part of the batch. Persistent
	/// implementations must complete a durable write transaction or flush before
	/// success. There is deliberately no sequential-write default.
	async fn put_batch(&mut self, updates: Vec<RecordUpdate>) -> anyhow::Result<()> {
		self.put_batch_checked(updates, &[]).await
	}

	/// Assert absent keys inside the same transaction without creating them.
	async fn put_batch_checked(
		&mut self, updates: Vec<RecordUpdate>, absent: &[(u8, Vec<u8>)],
	) -> anyhow::Result<()>;

	/// Retrieves a record by primary key.
	///
	/// Returns `None` if the record doesn't exist.
	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>>;

	/// Deletes a record by primary key.
	///
	/// Returns the deleted record if it existed, `None` otherwise.
	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>>;

	/// Queries sorted records from a partition.
	///
	/// Results are ordered by sort key.
	/// Records without a sort key must not be returned, to query all
	/// records use [`StorageAdaptor::get_all`].
	async fn query_sorted<R: QueryRange>(&self, query: Query<R>)
		-> anyhow::Result<Vec<Record>>;

	/// Get all records in a partition.
	///
	/// No ordering guarantees are made.
	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>>;

	/// Increments the last partition id, then stores and returns the new id.
	///
	/// The read-modify-write runs through the backend's atomic
	/// compare-and-commit batch so that two concurrently opened contexts on
	/// one shared database (e.g. two same-origin tabs on IndexedDB, which
	/// commits each adaptor request as its own transaction) cannot allocate
	/// the same id: `put_batch_checked` compares `previous` inside a single
	/// transaction and fails when another context moved the counter first,
	/// in which case the counter is re-read and the allocation retried.
	async fn incremental_id(&mut self, partition: u8) -> anyhow::Result<u32> {
		// A failed compare-and-commit on a contended counter costs one extra
		// read to tell "another context moved it" from a real backend error,
		// so the budget is sized for the two reads per attempt under the
		// IndexedDB-style per-request auto-commit model.
		const MAX_RETRIES: usize = 128;
		for _ in 0..MAX_RETRIES {
			let previous = self.get(partition::LAST_IDS, &[partition]).await?;
			let next_partition_id = previous.as_ref()
				.map(|r| r.to_data::<u32>()).transpose()?.unwrap_or(0) + 1;
			let updated = Record::from_data(
				partition::LAST_IDS,
				&[partition],
				None,
				&next_partition_id,
			)?;

			let update = RecordUpdate { previous: previous.clone(), updated: Some(updated) };
			let Err(e) = self.put_batch_checked(vec![update], &[]).await else {
				return Ok(next_partition_id);
			};
			// Only a counter moved by another context is retried: an
			// unchanged counter means the batch failed for another reason
			// (I/O, validation), which retrying cannot fix.
			if self.get(partition::LAST_IDS, &[partition]).await? == previous {
				return Err(e.context(format!(
					"incremental_id for partition {partition}: compare-and-commit failed"
				)));
			}
			// Another context committed the counter first; retry.
		}
		anyhow::bail!("incremental_id for partition {partition}: counter contention after {MAX_RETRIES} retries")
	}
}

async fn get_vtxo<S: StorageAdaptor>(adaptor: &S, id: VtxoId) -> anyhow::Result<Option<SerdeVtxo>> {
	match adaptor.get(partition::VTXO, &id.to_bytes()).await? {
		Some(record) => Ok(Some(record.to_data::<SerdeVtxo>()?)),
		None => Ok(None),
	}
}

/// Whether a checked state update still has anything to write.
enum StateTransition {
	/// The vtxo already carries the exact target state; re-appending it
	/// would only grow the state history.
	AlreadyApplied,
	/// The vtxo is in an allowed old state and must be moved.
	Apply,
}

/// Fetch `vtxo_id` and decide whether it may move to `new_state`.
///
/// A vtxo that already carries `new_state` is accepted regardless of
/// `allowed_states`, so repeating a transition is a no-op rather than an
/// error. Any other vtxo must currently be in one of `allowed_states`.
async fn get_check_vtxo_state<S: StorageAdaptor>(
	adaptor: &S,
	vtxo_id: VtxoId,
	new_state: &VtxoState,
	allowed_states: &[VtxoStateKind],
) -> anyhow::Result<(Record, SerdeVtxo, StateTransition)> {
	let previous = adaptor.get(partition::VTXO, &vtxo_id.to_bytes()).await?
		.context("vtxo not found")?;
	let vtxo = previous.to_data::<SerdeVtxo>()?;

	let current_state = vtxo.current_state().context("vtxo has no state")?;
	let transition = if current_state == new_state {
		StateTransition::AlreadyApplied
	} else if allowed_states.contains(&current_state.kind()) {
		StateTransition::Apply
	} else {
		bail!("current state {:?} not in allowed states {:?}",
			current_state.kind(), allowed_states
		);
	};

	Ok((previous, vtxo, transition))
}

async fn update_vtxo_state_checked<S: StorageAdaptor>(
	adaptor: &mut S,
	vtxo_id: VtxoId,
	new_state: VtxoState,
	allowed_old_states: &[VtxoStateKind],
) -> anyhow::Result<WalletVtxo> {
	let (previous, mut serde_vtxo, transition) =
		get_check_vtxo_state(adaptor, vtxo_id, &new_state, allowed_old_states).await?;
	let absent = if matches!(new_state, VtxoState::Spendable | VtxoState::Locked { .. }) {
		vec![(partition::PROGRAM_RECOVERY_RESERVATION, recovery_vtxo_key(vtxo_id).into_bytes())]
	} else {
		Vec::new()
	};

	if let StateTransition::Apply = transition {
		let sk = sort::vtxo_sort_key(
			new_state.kind(), serde_vtxo.vtxo.expiry_height().to_u32(), serde_vtxo.vtxo.amount()
		);

		serde_vtxo.states.push(new_state.clone());
		let updated_record = Record::from_data(
			partition::VTXO,
			&vtxo_id.to_bytes(),
			Some(sk),
			&serde_vtxo,
		)?;

		// The tombstone and exact previous VTXO are checked by one transaction.
		adaptor.put_batch_checked(vec![
			RecordUpdate { previous: Some(previous), updated: Some(updated_record) },
		], &absent).await?;
	} else if !absent.is_empty() {
		adaptor.put_batch_checked(Vec::new(), &absent).await?;
	}

	Ok(wallet_vtxo_from_full(&serde_vtxo.vtxo, new_state, serde_vtxo.registered))
}

/// Check legacy mappings as well as the index reservation introduced for
/// atomic program descriptor writes. Existing stores need no eager rewrite.
async fn vtxo_key_updates<S: StorageAdaptor>(
	adaptor: &S,
	index: u32,
	public_key: PublicKey,
) -> anyhow::Result<Vec<RecordUpdate>> {
	let sort_key = SortKey::u64_desc(index as u64);
	let query = Query::new(partition::PUBLIC_KEY, sort_key.clone()..=sort_key.clone());
	for record in adaptor.query_sorted(query).await? {
		let existing = record.to_data::<SerdeVtxoKey>()?;
		anyhow::ensure!(existing.index == index && existing.public_key == public_key,
			"vtxo key index {index} already stored under a different public key");
	}
	let previous = adaptor.get(partition::PUBLIC_KEY, &public_key.serialize()).await?;
	if let Some(record) = &previous {
		anyhow::ensure!(record.to_data::<SerdeVtxoKey>()?.index == index,
			"vtxo public key already stored under a different index");
	}
	let updated = Record::from_data(
		partition::PUBLIC_KEY, &public_key.serialize(), Some(sort_key),
		&SerdeVtxoKey { index, public_key },
	)?;
	let index_previous = adaptor.get(partition::PUBLIC_KEY_INDEX, &index.to_be_bytes()).await?;
	if let Some(record) = &index_previous {
		anyhow::ensure!(record.to_data::<PublicKey>()? == public_key,
			"vtxo key index {index} already reserved under a different public key");
	}
	let index_updated = Record::from_data(
		partition::PUBLIC_KEY_INDEX, &index.to_be_bytes(), None, &public_key,
	)?;
	Ok(vec![
		RecordUpdate { previous, updated: Some(updated) },
		RecordUpdate { previous: index_previous, updated: Some(index_updated) },
	])
}

pub struct StorageAdaptorWrapper<S: StorageAdaptor> {
	inner: tokio::sync::RwLock<S>,
}

impl<S: StorageAdaptor> StorageAdaptorWrapper<S> {
	pub fn new(inner: S) -> Self {
		Self {
			inner: tokio::sync::RwLock::new(inner),
		}
	}

	/// Read-modify-write the properties record through the backend's atomic
	/// compare-and-commit, so two wallet contexts sharing one database cannot
	/// lose each other's field updates (e.g. reset a pinned server key or the
	/// recovery-incomplete marker).
	async fn update_properties(
		&self,
		update: impl Fn(&mut WalletProperties) -> anyhow::Result<()>,
	) -> anyhow::Result<()> {
		const MAX_RETRIES: usize = 32;
		for _ in 0..MAX_RETRIES {
			let mut lock = self.inner.write().await;
			let previous = lock.get(partition::PROPERTIES, &[]).await?
				.context("wallet not initialized")?;
			let mut properties = previous.to_data::<WalletProperties>()?;
			update(&mut properties)?;
			let updated = Record::from_data(
				partition::PROPERTIES, &[], None, &properties,
			)?;
			let Err(e) = lock.put_batch_checked(
				vec![RecordUpdate {
					previous: Some(previous.clone()),
					updated: Some(updated),
				}],
				&[],
			).await else {
				return Ok(());
			};
			// Only a properties record changed by another context is
			// retried; an unchanged record means the write failed for a
			// reason a retry cannot fix.
			if lock.get(partition::PROPERTIES, &[]).await?.as_ref() == Some(&previous) {
				return Err(e.context("failed to update wallet properties"));
			}
		}
		anyhow::bail!("wallet properties update conflicted after {MAX_RETRIES} retries")
	}
}

/// Blanket implementation of `WalletPersister` for any type implementing `StorageAdaptor`.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl <S: StorageAdaptor> WalletPersister for StorageAdaptorWrapper<S> {
	async fn init_wallet(&self, properties: &WalletProperties) -> anyhow::Result<()> {
		let record = Record::from_data(
			partition::PROPERTIES,
			// NB: a single set of properties is stored, so no need for primary key
			&[],
			None,
			properties,
		)?;
		// A CAS with no previous record refuses to overwrite an existing
		// wallet even when two contexts race the initialization check.
		let mut lock = self.inner.write().await;
		anyhow::ensure!(lock.get(partition::PROPERTIES, &[]).await?.is_none(),
			"cannot overwrite already existing config");
		lock.put_batch_checked(
			vec![RecordUpdate { previous: None, updated: Some(record) }],
			&[],
		).await
	}

	async fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		match self.inner.read().await.get(partition::PROPERTIES, &[]).await? {
			Some(record) => Ok(Some(record.to_data()?)),
			None => Ok(None),
		}
	}

	async fn set_server_pubkey(&self, server_pubkey: PublicKey) -> anyhow::Result<()> {
		self.update_properties(|properties| {
			anyhow::ensure!(properties.server_pubkey.is_none(),
				"server pubkey is already set and cannot be changed");
			properties.server_pubkey = Some(server_pubkey);
			Ok(())
		}).await
	}

	async fn set_server_mailbox_pubkey(&self, server_mailbox_pubkey: PublicKey) -> anyhow::Result<()> {
		self.update_properties(|properties| {
			anyhow::ensure!(properties.server_mailbox_pubkey.is_none(),
				"server mailbox pubkey is already set and cannot be changed");
			properties.server_mailbox_pubkey = Some(server_mailbox_pubkey);
			Ok(())
		}).await
	}

	async fn set_recovery_incomplete(&self, incomplete: bool) -> anyhow::Result<()> {
		self.update_properties(|properties| {
			properties.recovery_incomplete = incomplete;
			Ok(())
		}).await
	}

	#[cfg(feature = "onchain-bdk")]
	async fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet> {
		match self.inner.read().await.get(partition::BDK_CHANGESET, &[]).await? {
			Some(record) => record.to_data(),
			None => Ok(ChangeSet::default()),
		}
	}

	#[cfg(feature = "onchain-bdk")]
	async fn store_bdk_wallet_changeset(&self, changeset: &ChangeSet) -> anyhow::Result<()> {
		let mut current = self.initialize_bdk_wallet().await?;
		current.merge(changeset.clone());

		let record = Record::from_data(
			partition::BDK_CHANGESET,
			// NB: a single changeset is stored, so no need for primary key
			&[],
			None,
			&current,
		)?;
		self.inner.write().await.put(record).await
	}

	async fn create_new_movement(
		&self,
		status: MovementStatus,
		subsystem: &MovementSubsystem,
		time: DateTime<Local>,
		action_id: Option<&str>,
	) -> anyhow::Result<MovementId> {
		let mut lock = self.inner.write().await;

		let id = MovementId(lock.incremental_id(partition::MOVEMENT).await?);
		let movement = Movement::new(id, status, subsystem, time);

		let record = Record::from_data(
			partition::MOVEMENT,
			&id.to_bytes(),
			Some(sort::movement_sort_key(&time)),
			&movement,
		)?;
		lock.put(record).await?;

		// Index by owning action so the movement can be reused on re-drive.
		if let Some(action_id) = action_id {
			let idx = Record::from_data(
				partition::MOVEMENT_ACTION,
				action_id.as_bytes(),
				None,
				&id.0,
			)?;
			lock.put(idx).await?;
		}

		Ok(id)
	}

	async fn get_or_create_movement_for_action(
		&self,
		subsystem: &MovementSubsystem,
		time: DateTime<Local>,
		action_id: &str,
		update: MovementUpdate,
	) -> anyhow::Result<(MovementId, bool)> {
		let mut guard = self.inner.write().await;

		// Reuse the movement already owned by this action, if any.
		if let Some(rec) = guard.get(partition::MOVEMENT_ACTION, action_id.as_bytes()).await? {
			let id = MovementId::new(
				rec.to_data::<u32>().context("corrupt db: movement action index value")?);
			return Ok((id, false));
		}

		let id = MovementId(guard.incremental_id(partition::MOVEMENT).await?);
		let mut movement = Movement::new(id, MovementStatus::Pending, subsystem, time);
		update.apply_to(&mut movement, time);
		write_movement_records(&mut *guard, &movement).await?;

		// Index by owning action so the movement can be reused on re-drive.
		let idx = Record::from_data(
			partition::MOVEMENT_ACTION,
			action_id.as_bytes(),
			None,
			&id.0,
		)?;
		guard.put(idx).await?;

		Ok((id, true))
	}

	async fn update_movement(&self, movement: &Movement) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		write_movement_records(&mut *guard, movement).await
	}

	async fn get_movement_by_id(&self, movement_id: MovementId) -> anyhow::Result<Movement> {
		self.inner.read().await.get(partition::MOVEMENT, &movement_id.to_bytes())
			.await?
			.context("movement not found")?
			.to_data()
	}

	async fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>> {
		let records = self.inner.read().await
			.query_sorted(Query::new_full_range(partition::MOVEMENT)).await?;
		records.into_iter().map(|r| r.to_data()).collect()
	}

	async fn get_movements_by_payment_method(
		&self,
		payment_method: &PaymentMethod,
	) -> anyhow::Result<Vec<Movement>> {
		let pm_bytes = serialize_payment_method(payment_method);
		let sort_key = SortKey::from_bytes(pm_bytes);

		let guard = self.inner.read().await;
		let idx_recs = guard.query_sorted(Query::new(
			partition::MOVEMENT_PAYMENT_METHOD,
			sort_key.clone()..=sort_key,
		)).await?;

		let mut ret = Vec::with_capacity(idx_recs.len());
		for idx_rec in idx_recs {
			let id = MovementId::new(idx_rec.to_data::<u32>()
				.context("corrupt db: movement payment method index value")?);

			ret.push(
				guard.get(partition::MOVEMENT, &id.to_bytes()).await?
					.context("corrupt db: movement payment method entry for unknown movement")?
					.to_data()
					.context("corrupt db: invalid movement record")?
			);
		}
		Ok(ret)
	}

	async fn store_round_state(&self, round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		let mut lock = self.inner.write().await;

		let id = RoundStateId(lock.incremental_id(partition::ROUND_STATE).await?);
		let serde_state = SerdeRoundState::from(round_state);
		let record = Record::from_data(
			partition::ROUND_STATE,
			&id.to_bytes(),
			Some(sort::SortKey::u32_asc(id.0)),
			&serde_state,
		)?;
		lock.put(record).await?;

		Ok(id)
	}

	async fn update_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()> {
		let serde_state = SerdeRoundState::from(round_state.state());
		let record = Record::from_data(
			partition::ROUND_STATE,
			&round_state.id().to_bytes(),
			Some(sort::SortKey::u32_asc(round_state.id().0)),
			&serde_state,
		)?;
		let mut lock = self.inner.write().await;
		anyhow::ensure!(lock.get(
			partition::PROGRAM_RECOVERY_RESERVATION,
			recovery_round_key(round_state.id()).as_bytes(),
		).await?.is_none(), "round reserved for program recovery");
		let previous = lock.get(partition::ROUND_STATE, &record.pk).await?;
		lock.put_batch_checked(vec![RecordUpdate { previous, updated: Some(record) }], &[
			(partition::PROGRAM_RECOVERY_RESERVATION, recovery_round_key(round_state.id()).into_bytes()),
		]).await
	}

	async fn remove_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let previous = lock.get(partition::ROUND_STATE, &round_state.id().to_bytes()).await?;
		let updates = previous.into_iter().map(|record| RecordUpdate {
			previous: Some(record), updated: None,
		}).collect();
		lock.put_batch_checked(updates, &[
			(partition::PROGRAM_RECOVERY_RESERVATION, recovery_round_key(round_state.id()).into_bytes()),
		]).await
	}

	async fn get_round_state_by_id(&self, _id: RoundStateId) -> anyhow::Result<Option<StoredRoundState<Unlocked>>> {
		let record = self.inner.read().await
			.get(partition::ROUND_STATE, &_id.to_bytes()).await?;
		match record {
			Some(r) => {
				let pk_slice: [u8; 4] = r.pk[..4].try_into().expect("4 bytes shouldn't fail");
				let id = RoundStateId(u32::from_be_bytes(pk_slice));
				let state = r.to_data::<SerdeRoundState>()?.into();
				Ok(Some(StoredRoundState::new(id, state)))
			},
			None => Ok(None),
		}
	}

	async fn get_pending_round_state_ids(&self) -> anyhow::Result<Vec<RoundStateId>> {
		let records = self.inner.read().await
			.get_all(partition::ROUND_STATE).await?;
		records.into_iter()
			.map(|r| {
				let pk_slice: [u8; 4] = r.pk[..4].try_into().expect("4 bytes shouldn't fail");
				Ok(RoundStateId(u32::from_be_bytes(pk_slice)))
			})
			.collect()
	}

	async fn store_vtxos(&self, vtxos: &[(&Vtxo<Full>, &VtxoState)]) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let mut updates = BTreeMap::new();
		let mut absent = std::collections::BTreeSet::new();

		for (vtxo, state) in vtxos {
			let previous = lock.get(partition::VTXO, &vtxo.id().to_bytes()).await?;
			if !matches!(state, VtxoState::Spent | VtxoState::Exited) {
				absent.insert((partition::PROGRAM_RECOVERY_RESERVATION,
					recovery_vtxo_key(vtxo.id()).into_bytes()));
				for item in vtxo.transactions() {
					for input in &item.tx.input {
						let ancestor = VtxoId::from(input.previous_output);
						if let Some(record) = lock.get(partition::VTXO, &ancestor.to_bytes()).await? {
							if record.to_data::<SerdeVtxo>()?.current_state() == Some(&VtxoState::Spent) {
								updates.entry(ancestor).or_insert_with(|| RecordUpdate {
									previous: Some(record.clone()), updated: Some(record),
								});
								continue;
							}
						}
						absent.insert((partition::PROGRAM_RECOVERY_RESERVATION,
							recovery_vtxo_key(ancestor).into_bytes()));
					}
				}
			}
			// Contract: 'For each VTXO that already exists: no-op for that
			// VTXO.' The reservation guard above still ran for live states,
			// mirroring SQLite's unconditional guard before INSERT OR IGNORE.
			// An existing record keeps its current state, full state history,
			// registered flag and signed bytes; in particular a live retry
			// landing on a terminal record is a silent no-op, never an error
			// or a resurrection.
			if previous.is_some() {
				continue;
			}
			let serde_vtxo = SerdeVtxo {
				vtxo: (*vtxo).clone(),
				states: vec![(*state).clone()],
				registered: false,
			};

			let sk = sort::vtxo_sort_key(
				state.kind(), vtxo.expiry_height().to_u32(), vtxo.amount(),
			);
			let record = Record::from_data(
				partition::VTXO,
				&vtxo.id().to_bytes(),
				Some(sk),
				&serde_vtxo,
			)?;
			updates.insert(vtxo.id(), RecordUpdate { previous, updated: Some(record) });
		}
		lock.put_batch_checked(updates.into_values().collect(), &absent.into_iter().collect::<Vec<_>>()).await
	}

	async fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		let lock = self.inner.read().await;
		match get_vtxo(&*lock, id).await? {
			Some(serde_vtxo) => {
				let state = serde_vtxo.current_state()
					.context("vtxo has no state")?.clone();
				Ok(Some(wallet_vtxo_from_full(
					&serde_vtxo.vtxo, state, serde_vtxo.registered,
				)))
			},
			None => Ok(None),
		}
	}

	async fn get_wallet_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<WalletVtxo>> {
		let lock = self.inner.read().await;
		let mut out = Vec::with_capacity(ids.len());
		for id in ids {
			let serde_vtxo = get_vtxo(&*lock, *id).await?
				.with_context(|| format!("vtxo {id} not found"))?;
			let state = serde_vtxo.current_state()
				.context("vtxo has no state")?.clone();
			out.push(wallet_vtxo_from_full(
				&serde_vtxo.vtxo, state, serde_vtxo.registered,
			));
		}
		Ok(out)
	}

	async fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let records = self.inner.read().await
			.query_sorted(Query::new_full_range(partition::VTXO)).await?;

		records
			.into_iter()
			.map(|r| {
				let serde_vtxo = r.to_data::<SerdeVtxo>()?;
				let state = serde_vtxo
					.current_state()
					.cloned()
					.context("vtxo has no state")?;
				Ok(wallet_vtxo_from_full(
					&serde_vtxo.vtxo, state, serde_vtxo.registered,
				))
			})
			.collect()
	}

	async fn get_vtxos_by_state(
		&self,
		states: &[VtxoStateKind],
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let lock = self.inner.read().await;

		let range = |state: VtxoStateKind| {
			let start = sort::vtxo_sort_key(state, u32::MIN, Amount::ZERO);
			let end = sort::vtxo_sort_key(state, u32::MAX, Amount::MAX);
			(start, end)
		};

		let mut records = Vec::new();
		for state in states {
			let (start, end) = range(*state);
			let query = Query::new(partition::VTXO, start..=end);

			for record in lock.query_sorted(query).await? {
				let serde_vtxo = record.to_data::<SerdeVtxo>()?;
				let current_state = serde_vtxo.current_state()
					.context("vtxo has no current state")?.clone();
				debug_assert_eq!(current_state.kind(), *state);
				records.push(wallet_vtxo_from_full(
					&serde_vtxo.vtxo, current_state, serde_vtxo.registered,
				));
			}
		}

		// Each per-state range comes back in sort-key order, but
		// concatenating the ranges groups results by state. Re-sort to the
		// order the trait documents: expiry height ASC, amount DESC.
		records.sort_by(|a, b| {
			a.vtxo.expiry_height().cmp(&b.vtxo.expiry_height())
				.then(b.vtxo.amount().cmp(&a.vtxo.amount()))
		});

		Ok(records)
	}

	async fn get_full_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		let lock = self.inner.read().await;
		Ok(get_vtxo(&*lock, id).await?.map(|s| s.vtxo))
	}

	async fn get_full_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let lock = self.inner.read().await;
		let mut out = Vec::with_capacity(ids.len());
		for id in ids {
			let serde_vtxo = get_vtxo(&*lock, *id).await?
				.with_context(|| format!("vtxo {id} not found"))?;
			out.push(serde_vtxo.vtxo);
		}
		Ok(out)
	}

	async fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>> {
		match self.inner.write().await.delete(partition::VTXO, &id.to_bytes()).await? {
			Some(record) => Ok(Some(record.to_data::<SerdeVtxo>()?.vtxo)),
			None => Ok(None),
		}
	}

	async fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		match self.get_wallet_vtxo(id).await? {
			Some(vtxo) => Ok(vtxo.state.kind() == VtxoStateKind::Spent),
			None => Ok(false),
		}
	}

	async fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo> {
		let mut lock = self.inner.write().await;
		update_vtxo_state_checked(&mut *lock, vtxo_id, new_state, allowed_old_states).await
	}

	async fn release_vtxo_lock(
		&self,
		vtxo_id: VtxoId,
		holder: Option<&VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let Some(previous) = lock.get(partition::VTXO, &vtxo_id.to_bytes()).await? else {
			return Ok(());
		};
		let mut serde_vtxo = previous.to_data::<SerdeVtxo>()?;
		let expected = VtxoState::Locked { holder: holder.cloned() };
		let current_state = serde_vtxo.current_state()
			.context("vtxo has no state")?;
		if current_state != &expected {
			return Ok(());
		}
		let new_state = VtxoState::Spendable;
		let sk = sort::vtxo_sort_key(
			new_state.kind(), serde_vtxo.vtxo.expiry_height().to_u32(), serde_vtxo.vtxo.amount(),
		);
		serde_vtxo.states.push(new_state);
		let updated_record = Record::from_data(
			partition::VTXO,
			&vtxo_id.to_bytes(),
			Some(sk),
			&serde_vtxo,
		)?;
		lock.put_batch_checked(vec![
			RecordUpdate { previous: Some(previous), updated: Some(updated_record) },
		], &[(partition::PROGRAM_RECOVERY_RESERVATION, recovery_vtxo_key(vtxo_id).into_bytes())]).await?;
		Ok(())
	}

	async fn update_vtxo_states_checked(
		&self,
		vtxo_ids: &[VtxoId],
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let mut updates = Vec::new();
		let mut absent = Vec::new();
		let mut seen = std::collections::HashSet::new();
		for id in vtxo_ids {
			if !seen.insert(*id) {
				continue;
			}
			let (previous, mut vtxo, transition) =
				get_check_vtxo_state(&*lock, *id, &new_state, allowed_old_states).await?;
			if matches!(new_state, VtxoState::Spendable | VtxoState::Locked { .. }) {
				absent.push((partition::PROGRAM_RECOVERY_RESERVATION, recovery_vtxo_key(*id).into_bytes()));
			}
			if let StateTransition::Apply = transition {
				vtxo.states.push(new_state.clone());
				let sk = sort::vtxo_sort_key(
					new_state.kind(), vtxo.vtxo.expiry_height().to_u32(), vtxo.vtxo.amount(),
				);
				let updated = Record::from_data(partition::VTXO, &id.to_bytes(), Some(sk), &vtxo)?;
				updates.push(RecordUpdate { previous: Some(previous), updated: Some(updated) });
			}
		}
		lock.put_batch_checked(updates, &absent).await
	}

	async fn mark_vtxos_registered(&self, vtxo_ids: &[VtxoId]) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		for id in vtxo_ids {
			let previous = lock.get(partition::VTXO, &id.to_bytes()).await?
				.with_context(|| format!("vtxo {id} not found"))?;
			let mut serde_vtxo = previous.to_data::<SerdeVtxo>()?;
			if serde_vtxo.registered {
				continue;
			}
			serde_vtxo.registered = true;

			// Keep the record's sort key unchanged: it is derived from the
			// current state, which this update doesn't touch.
			let state = serde_vtxo.current_state().context("vtxo has no state")?;
			let sk = sort::vtxo_sort_key(
				state.kind(), serde_vtxo.vtxo.expiry_height().to_u32(), serde_vtxo.vtxo.amount(),
			);
			let record = Record::from_data(
				partition::VTXO,
				&id.to_bytes(),
				Some(sk),
				&serde_vtxo,
			)?;
			lock.put_batch(vec![RecordUpdate { previous: Some(previous), updated: Some(record) }]).await?;
		}
		Ok(())
	}

	async fn get_unregistered_vtxo_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		let records = self.inner.read().await
			.query_sorted(Query::new_full_range(partition::VTXO)).await?;

		let mut ids = Vec::new();
		for record in records {
			let serde_vtxo = record.to_data::<SerdeVtxo>()?;
			if serde_vtxo.registered {
				continue;
			}
			let state = serde_vtxo.current_state()
				.context("vtxo has no state")?;
			if state.kind() != VtxoStateKind::Spent {
				ids.push(serde_vtxo.vtxo.id());
			}
		}
		Ok(ids)
	}

	async fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let updates = vtxo_key_updates(&*lock, index, public_key).await?;
		lock.put_batch(updates).await
	}

	async fn store_program_key(&self, record: &SerdeProgramKey) -> anyhow::Result<()> {
		let public_key = record.program.public_key()?;
		let mut lock = self.inner.write().await;
		let previous = lock.get(partition::PROGRAM_KEY, &public_key.serialize()).await?;
		if let Some(existing) = &previous {
			anyhow::ensure!(existing.to_data::<SerdeProgramKey>()? == *record,
				"conflicting program descriptor for {public_key}");
		}
		let mut updates = vtxo_key_updates(&*lock, record.index, public_key).await?;
		updates.push(RecordUpdate {
			previous,
			updated: Some(Record::from_data(
				partition::PROGRAM_KEY, &public_key.serialize(), None, record,
			)?),
		});
		lock.put_batch(updates).await
	}

	async fn get_program_key(&self, public_key: &PublicKey)
		-> anyhow::Result<Option<SerdeProgramKey>>
	{
		self.inner.read().await.get(partition::PROGRAM_KEY, &public_key.serialize()).await?
			.map(|record| record.to_data()).transpose()
	}

	async fn get_program_key_by_index(&self, index: u32)
		-> anyhow::Result<Option<SerdeProgramKey>>
	{
		let lock = self.inner.read().await;
		let Some(record) = lock.get(partition::PUBLIC_KEY_INDEX, &index.to_be_bytes()).await? else {
			return Ok(None);
		};
		let public_key = record.to_data::<PublicKey>()?;
		lock.get(partition::PROGRAM_KEY, &public_key.serialize()).await?
			.map(|record| record.to_data()).transpose()
	}

	async fn list_program_keys(&self) -> anyhow::Result<Vec<SerdeProgramKey>> {
		self.inner.read().await.get_all(partition::PROGRAM_KEY).await?
			.into_iter().map(|record| record.to_data()).collect()
	}

	async fn store_program_recoveries(&self, records: &[ProgramRecoveryRecord])
		-> anyhow::Result<()>
	{
		let mut lock = self.inner.write().await;
		let mut staged = BTreeMap::<OutPoint, (Option<Record>, ProgramRecoveryRecord)>::new();
		for record in records {
			let outpoint = record.controlled_outpoint;
			let (previous, existing) = match staged.remove(&outpoint) {
				Some((previous, existing)) => (previous, Some(existing)),
				None => {
					let previous = lock.get(
						partition::PROGRAM_RECOVERY, &bitcoin::consensus::serialize(&outpoint),
					).await?;
					let existing = previous.as_ref().map(|row| row.to_data()).transpose()?;
					(previous, existing)
				},
			};
			staged.insert(outpoint, (previous, merge_program_recovery(existing, record)?));
		}
		let updates = staged.into_iter().map(|(outpoint, (previous, record))| {
			Ok(RecordUpdate {
				previous,
				updated: Some(Record::from_data(
					partition::PROGRAM_RECOVERY, &bitcoin::consensus::serialize(&outpoint),
					None, &record,
				)?),
			})
		}).collect::<anyhow::Result<Vec<_>>>()?;
		lock.put_batch(updates).await
	}

	async fn get_program_recovery(&self, outpoint: OutPoint)
		-> anyhow::Result<Option<ProgramRecoveryRecord>>
	{
		self.inner.read().await.get(
			partition::PROGRAM_RECOVERY, &bitcoin::consensus::serialize(&outpoint),
		).await?.map(|record| record.to_data()).transpose()
	}

	async fn list_program_recoveries(&self) -> anyhow::Result<Vec<ProgramRecoveryRecord>> {
		self.inner.read().await.get_all(partition::PROGRAM_RECOVERY).await?
			.into_iter().map(|record| record.to_data()).collect()
	}

	async fn reserve_program_recovery(
		&self,
		inputs: &[(VtxoId, Option<VtxoState>)],
		actors: &[String],
	) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let mut updates = Vec::new();
		let mut absent = Vec::new();
		let mut keys = std::collections::BTreeSet::new();
		let mut seen = std::collections::HashSet::new();
		for (id, expected) in inputs {
			let previous = lock.get(partition::VTXO, &id.to_bytes()).await?;
			let mut vtxo = previous.as_ref().map(|r| r.to_data::<SerdeVtxo>()).transpose()?;
			let current = vtxo.as_ref().map(|v| v.current_state().context("vtxo has no state"))
				.transpose()?;
			anyhow::ensure!(current == expected.as_ref(),
				"vtxo {id} changed before program recovery reservation");
			keys.insert(recovery_vtxo_key(*id));
			if !seen.insert(*id) {
				continue;
			}
			if previous.is_none() {
				absent.push((partition::VTXO, id.to_bytes().to_vec()));
			}
			if let Some(vtxo) = vtxo.as_mut() {
				let updated = if matches!(vtxo.current_state(),
					Some(VtxoState::Spendable | VtxoState::Locked { .. }))
				{
					vtxo.states.push(VtxoState::Exited);
					let sk = sort::vtxo_sort_key(
						VtxoStateKind::Exited, vtxo.vtxo.expiry_height().to_u32(), vtxo.vtxo.amount(),
					);
					Some(Record::from_data(partition::VTXO, &id.to_bytes(), Some(sk), vtxo)?)
				} else {
					previous.clone()
				};
				updates.push(RecordUpdate { previous, updated });
			}
		}
		keys.extend(actors.iter().cloned());
		for key in keys {
			let previous = lock.get(partition::PROGRAM_RECOVERY_RESERVATION, key.as_bytes()).await?;
			let updated = Record::from_data(
				partition::PROGRAM_RECOVERY_RESERVATION, key.as_bytes(), None, &true,
			)?;
			updates.push(RecordUpdate { previous, updated: Some(updated) });
		}
		lock.put_batch_checked(updates, &absent).await
	}

	async fn has_program_recovery_reservation(&self, key: &str) -> anyhow::Result<bool> {
		Ok(self.inner.read().await.get(
			partition::PROGRAM_RECOVERY_RESERVATION, key.as_bytes(),
		).await?.is_some())
	}

	async fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>> {
		// pks are sorted descending, so the first one is the highest index
		let query = Query::new_full_range(partition::PUBLIC_KEY).limit(1);
		let records = self.inner.read().await.query_sorted(query).await?;

		match records.into_iter().next() {
			Some(record) => {
				let vtxo_key = record.to_data::<SerdeVtxoKey>()?;
				Ok(Some(vtxo_key.index))
			}
			None => Ok(None),
		}
	}

	async fn get_public_key_idx(&self, public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
		match self.inner.read().await
			.get(partition::PUBLIC_KEY, &public_key.serialize()[..]).await?
		{
			Some(record) => {
				let vtxo_key = record.to_data::<SerdeVtxoKey>()?;
				Ok(Some(vtxo_key.index))
			}
			None => Ok(None),
		}
	}

	async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64> {
		match self.inner.read().await
			.get(partition::MAILBOX_CHECKPOINT, &[]).await?
		{
			Some(record) => Ok(record.to_data::<u64>()?),
			None => Ok(0),
		}
	}

	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()> {
		// Read-compare-write under the write lock, mirroring the SQLite
		// backend and the WalletPersister contract: the mailbox cursor must
		// never rewind. A stale or replayed lower value would re-serve
		// already-processed messages and invalidate the monotone-cursor
		// assumption the mailbox no-bury logic relies on.
		let mut lock = self.inner.write().await;
		let current = match lock.get(partition::MAILBOX_CHECKPOINT, &[]).await? {
			Some(record) => record.to_data::<u64>()?,
			None => 0,
		};
		anyhow::ensure!(
			checkpoint > current,
			"mailbox checkpoint not advanced: refusing to store {checkpoint} \
				over the current cursor {current}",
		);
		let record = Record::from_data(
			partition::MAILBOX_CHECKPOINT,
			&[],
			None,
			&checkpoint,
		)?;
		lock.put(record).await?;
		Ok(())
	}

	async fn upsert_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
		checkpoint: &WalletActionCheckpoint,
	) -> anyhow::Result<()> {
		let record = Record::from_data(
			partition::WALLET_ACTION_CHECKPOINT,
			id.as_bytes(),
			None,
			checkpoint,
		)?;
		let mut lock = self.inner.write().await;
		anyhow::ensure!(lock.get(
			partition::PROGRAM_RECOVERY_RESERVATION, recovery_action_key(id).as_bytes(),
		).await?.is_none(), "wallet action reserved for program recovery");
		let previous = lock.get(partition::WALLET_ACTION_CHECKPOINT, id.as_bytes()).await?;
		lock.put_batch_checked(vec![RecordUpdate { previous, updated: Some(record) }], &[
			(partition::PROGRAM_RECOVERY_RESERVATION, recovery_action_key(id).into_bytes()),
		]).await
	}

	async fn get_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<Option<WalletActionCheckpoint>> {
		match self.inner.read().await
			.get(partition::WALLET_ACTION_CHECKPOINT, id.as_bytes()).await?
		{
			Some(record) => Ok(Some(record.to_data()?)),
			None => Ok(None),
		}
	}

	async fn get_all_wallet_action_checkpoints(
		&self,
	) -> anyhow::Result<Vec<WalletActionCheckpoint>> {
		let records = self.inner.read().await
			.get_all(partition::WALLET_ACTION_CHECKPOINT).await?;
		records.into_iter().map(|r| r.to_data()).collect()
	}

	async fn remove_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		let previous = lock.get(partition::WALLET_ACTION_CHECKPOINT, id.as_bytes()).await?;
		let updates = previous.into_iter().map(|record| RecordUpdate {
			previous: Some(record), updated: None,
		}).collect();
		lock.put_batch_checked(updates, &[
			(partition::PROGRAM_RECOVERY_RESERVATION, recovery_action_key(id).into_bytes()),
		]).await
	}

	async fn finish_wallet_action(&self, id: &WalletActionId) -> anyhow::Result<()> {
		let mut lock = self.inner.write().await;
		anyhow::ensure!(lock.get(
			partition::PROGRAM_RECOVERY_RESERVATION, recovery_action_key(id).as_bytes(),
		).await?.is_none(), "wallet action reserved for program recovery");
		let checkpoint = lock.get(partition::WALLET_ACTION_CHECKPOINT, id.as_bytes()).await?;
		let mut updates = Vec::new();
		// Amounts sort in descending order. Include both boundary heights
		// without loading signed VTXOs whose current state is not locked.
		let start = sort::vtxo_sort_key(
			VtxoStateKind::Locked, u32::MIN, Amount::from_sat(u64::MAX),
		);
		let end = sort::vtxo_sort_key(VtxoStateKind::Locked, u32::MAX, Amount::ZERO);
		for previous in lock.query_sorted(Query::new(partition::VTXO, start..=end)).await? {
			let mut vtxo = previous.to_data::<SerdeVtxo>()?;
			if !matches!(
				vtxo.current_state().context("vtxo has no state")?,
				VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: holder }) }
					if holder == id
			) {
				continue;
			}
			anyhow::ensure!(checkpoint.is_some(),
				"wallet action {id} has locked vtxos but no checkpoint");

			// Retain the signed VTXO, registration flag, and complete state
			// history. Only the current lock and its sort key change.
			vtxo.states.push(VtxoState::Spendable);
			let sk = sort::vtxo_sort_key(
				VtxoStateKind::Spendable, vtxo.vtxo.expiry_height().to_u32(), vtxo.vtxo.amount(),
			);
			let updated = Record::from_data(
				partition::VTXO, &previous.pk, Some(sk), &vtxo,
			)?;
			updates.push(RecordUpdate { previous: Some(previous), updated: Some(updated) });
		}
		if let Some(checkpoint) = checkpoint {
			// The checkpoint and every owned lock share one conditional commit.
			// A retry after a lost acknowledgement has no records left to change.
			updates.push(RecordUpdate { previous: Some(checkpoint), updated: None });
			lock.put_batch_checked(updates, &[
				(partition::PROGRAM_RECOVERY_RESERVATION, recovery_action_key(id).into_bytes()),
			]).await?;
		}
		Ok(())
	}

	async fn record_paid_invoice(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let key = payment_hash.to_byte_array();
		// Idempotent: preserve the original paid_at across retries.
		let mut lock = self.inner.write().await;
		if lock.get(partition::PAID_INVOICE, &key).await?.is_some() {
			return Ok(());
		}
		let paid = PaidInvoice {
			payment_hash,
			preimage,
			paid_at: chrono::Local::now(),
		};
		let record = Record::from_data(partition::PAID_INVOICE, &key, None, &paid)?;
		lock.put(record).await
	}

	async fn get_paid_invoice(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<PaidInvoice>> {
		match self.inner.read().await
			.get(partition::PAID_INVOICE, &payment_hash.to_byte_array()).await?
		{
			Some(record) => Ok(Some(record.to_data()?)),
			None => Ok(None),
		}
	}

	async fn record_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
		invoice: &Bolt11Invoice,
		amount: Amount,
	) -> anyhow::Result<()> {
		let key = payment_hash.to_byte_array();

		let mut lock = self.inner.write().await;
		if lock.get(partition::SETTLED_LIGHTNING_RECEIVE, &key).await?.is_some() {
			return Ok(());
		}
		let settled = SettledLightningReceive {
			payment_hash,
			preimage,
			invoice: invoice.clone(),
			amount,
			settled_at: chrono::Local::now(),
		};
		let record = Record::from_data(partition::SETTLED_LIGHTNING_RECEIVE, &key, None, &settled)?;
		lock.put(record).await
	}

	async fn get_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<SettledLightningReceive>> {
		match self.inner.read().await
			.get(partition::SETTLED_LIGHTNING_RECEIVE, &payment_hash.to_byte_array()).await?
		{
			Some(record) => Ok(Some(record.to_data()?)),
			None => Ok(None),
		}
	}


	async fn store_exit_vtxo_entry(&self, exit: &StoredExit) -> anyhow::Result<()> {
		let record = Record::from_data(
			partition::EXIT_VTXO,
			&exit.vtxo_id.to_bytes(),
			None,
			exit,
		)?;
		self.inner.write().await.put(record).await
	}

	async fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()> {
		self.inner.write().await.delete(partition::EXIT_VTXO, &id.to_bytes()).await?;
		Ok(())
	}

	async fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>> {
		let records = self.inner.read().await.get_all(partition::EXIT_VTXO).await?;
		records.into_iter().map(|r| r.to_data()).collect()
	}

	async fn get_exit_vtxo_entries_with_states(
		&self,
		states: &[ExitStateKind],
	) -> anyhow::Result<Vec<StoredExit>> {
		// The state lives inside the serialized record and adaptors only key by primary/sort key,
		// so there's no filter to push down — read the partition and filter here.
		let records = self.inner.read().await.get_all(partition::EXIT_VTXO).await?;
		records.into_iter()
			.map(|r| r.to_data::<StoredExit>())
			.filter(|e| e.as_ref().map_or(true, |e| states.contains(&e.state.kind())))
			.collect()
	}

	async fn get_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<Option<StoredExit>> {
		match self.inner.read().await.get(partition::EXIT_VTXO, &id.to_bytes()).await? {
			Some(record) => Ok(Some(record.to_data::<StoredExit>()?)),
			None => Ok(None),
		}
	}

	async fn store_exit_child_tx(
		&self,
		exit_txid: Txid,
		child_tx: &Transaction,
		origin: ExitTxOrigin,
	) -> anyhow::Result<()> {
		let exit_child = SerdeExitChildTx {
			child_tx: child_tx.clone(),
			origin,
		};
		let record = Record::from_data(
			partition::EXIT_CHILD_TX,
			&exit_txid.to_byte_array(),
			None,
			&exit_child,
		)?;
		self.inner.write().await.put(record).await
	}

	async fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>> {
		match self.inner.read().await
			.get(partition::EXIT_CHILD_TX, &exit_txid.to_byte_array()).await?
		{
			Some(record) => {
				let exit_child = record.to_data::<SerdeExitChildTx>()?;
				Ok(Some((exit_child.child_tx, exit_child.origin)))
			}
			None => Ok(None),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	#[cfg(not(target_arch = "wasm32"))]
	use std::sync::Arc;

	use ark::test_util::VTXO_VECTORS;

	use super::*;
	use crate::persist::adaptor::memory::MemoryStorageAdaptor;
	use crate::persist::test_suite::{
		bark_persister_tests, program_key_fixture, program_recovery_fixture, send_at_start,
	};

	#[test]
	fn storage_query_builder() {
		let query = Query::new_full_range(0).limit(10);

		assert_eq!(query.partition, 0);
		assert_eq!(query.limit, Some(10));
		assert_eq!(query.range, ..);
	}

	async fn setup(_test: &str) -> ((), StorageAdaptorWrapper<MemoryStorageAdaptor>) {
		((), StorageAdaptorWrapper::new(MemoryStorageAdaptor::new()))
	}

	bark_persister_tests!(setup);

	/// Shares one backing store between independently constructed adaptors,
	/// committing every request separately the way IndexedDB auto-commit
	/// transactions do: nothing spans the read and the write of one logical
	/// operation, so a parallel context can always interleave between them.
	/// This is the layout `persist::platform_default` produces on wasm32,
	/// where each open wallet context gets its own wrapper (and its own
	/// wrapper lock) over one shared database.
	#[cfg(not(target_arch = "wasm32"))]
	#[derive(Clone, Default)]
	struct SharedAutoCommitAdaptor {
		store: Arc<std::sync::Mutex<HashMap<u8, BTreeMap<Vec<u8>, Record>>>>,
	}

	#[cfg(not(target_arch = "wasm32"))]
	#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
	impl StorageAdaptor for SharedAutoCommitAdaptor {
		async fn put(&mut self, record: Record) -> anyhow::Result<()> {
			let mut store = self.store.lock().unwrap();
			store.entry(record.partition).or_default().insert(record.pk.clone(), record);
			Ok(())
		}

		async fn put_batch_checked(
			&mut self, updates: Vec<RecordUpdate>, absent: &[(u8, Vec<u8>)],
		) -> anyhow::Result<()> {
			validate_record_updates(&updates)?;
			let mut store = self.store.lock().unwrap();
			for (partition, pk) in absent {
				anyhow::ensure!(store.get(partition).and_then(|p| p.get(pk)).is_none(),
					"record inserted during atomic update");
			}
			for update in &updates {
				let record = update.record()?;
				anyhow::ensure!(
					store.get(&record.partition).and_then(|p| p.get(&record.pk))
						== update.previous.as_ref(),
					"record changed during atomic update",
				);
			}
			for update in updates {
				if let Some(record) = update.updated {
					store.entry(record.partition).or_default().insert(record.pk.clone(), record);
				} else if let Some(previous) = update.previous {
					if let Some(partition) = store.get_mut(&previous.partition) {
						partition.remove(&previous.pk);
					}
				}
			}
			Ok(())
		}

		async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
			// The read is its own committed transaction; yielding before
			// returning the snapshot lets a parallel context commit between
			// this read and the caller's follow-up write, as IndexedDB's
			// per-request auto-commit always allows.
			let value = self.store.lock().unwrap().get(&partition).and_then(|p| p.get(pk).cloned());
			tokio::task::yield_now().await;
			Ok(value)
		}

		async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
			Ok(self.store.lock().unwrap().get_mut(&partition).and_then(|p| p.remove(pk)))
		}

		async fn query_sorted<R: QueryRange>(&self, query: Query<R>)
			-> anyhow::Result<Vec<Record>>
		{
			let store = self.store.lock().unwrap();
			let Some(partition) = store.get(&query.partition) else {
				return Ok(Vec::new());
			};
			let mut results: Vec<_> = partition.values()
				.filter(|r| r.sort_key.as_ref().is_some_and(|sk| query.range.contains(sk)))
				.cloned()
				.collect();
			results.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
			if let Some(limit) = query.limit {
				results.truncate(limit);
			}
			Ok(results)
		}

		async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
			let store = self.store.lock().unwrap();
			Ok(store.get(&partition)
				.map(|p| p.values().cloned().collect()).unwrap_or_default())
		}
	}

	/// Two wallet contexts over one shared store must never allocate the
	/// same MovementId/RoundStateId: movement records are keyed by id, so a
	/// duplicate silently overwrites the first context's ledger entry. The
	/// yield inside [`SharedAutoCommitAdaptor::get`] makes a non-atomic
	/// read-then-write allocator collide deterministically here (~196/400
	/// in the finding's reproduction); only the atomic compare-and-commit
	/// batch keeps the ids unique.
	#[cfg(not(target_arch = "wasm32"))]
	#[tokio::test]
	async fn incremental_id_allocates_unique_ids_across_contexts() {
		const ALLOCATIONS: usize = 100;

		async fn allocate(
			context: StorageAdaptorWrapper<SharedAutoCommitAdaptor>,
			barrier: Arc<tokio::sync::Barrier>,
		) -> Vec<u32> {
			let mut ids = Vec::with_capacity(ALLOCATIONS);
			barrier.wait().await;
			for _ in 0..ALLOCATIONS {
				let mut guard = context.inner.write().await;
				ids.push(guard.incremental_id(partition::MOVEMENT).await
					.expect("id allocation must survive contention"));
			}
			ids
		}

		let adaptor = SharedAutoCommitAdaptor::default();
		// Two independently opened contexts on one shared database, each
		// with its own wrapper lock: only the store can serialize them.
		let context_a = StorageAdaptorWrapper::new(adaptor.clone());
		let context_b = StorageAdaptorWrapper::new(adaptor.clone());
		let barrier = Arc::new(tokio::sync::Barrier::new(2));

		let a = tokio::spawn(allocate(context_a, barrier.clone()));
		let b = tokio::spawn(allocate(context_b, barrier));
		let ids_a = a.await.unwrap();
		let ids_b = b.await.unwrap();

		let unique: std::collections::BTreeSet<u32> =
			ids_a.iter().chain(&ids_b).copied().collect();
		assert_eq!(unique.len(), 2 * ALLOCATIONS,
			"concurrent contexts allocated duplicate ids");

		// Every allocation committed exactly once: the counter reaches the
		// total and no commit was lost.
		let counter = adaptor.get(partition::LAST_IDS, &[partition::MOVEMENT])
			.await.unwrap().expect("counter exists after allocations");
		assert_eq!(counter.to_data::<u32>().unwrap(), (2 * ALLOCATIONS) as u32);
	}

	/// Two contexts sharing one database must not lose each other's property
	/// field: the updates are CAS-checked and retried, not whole-record
	/// read-modify-writes.
	#[cfg(not(target_arch = "wasm32"))]
	#[tokio::test]
	async fn property_updates_survive_concurrent_contexts() {
		use std::str::FromStr;

		let adaptor = SharedAutoCommitAdaptor::default();
		let context_a = StorageAdaptorWrapper::new(adaptor.clone());
		let context_b = StorageAdaptorWrapper::new(adaptor.clone());
		let properties = WalletProperties {
			network: bitcoin::Network::Regtest,
			fingerprint: Default::default(),
			server_pubkey: None,
			server_mailbox_pubkey: None,
			recovery_incomplete: false,
		};
		context_a.init_wallet(&properties).await.unwrap();

		let pk = PublicKey::from_str(
			"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		).unwrap();
		let (pin, marker) = tokio::join!(
			context_a.set_server_pubkey(pk),
			context_b.set_recovery_incomplete(true),
		);
		pin.unwrap();
		marker.unwrap();

		let properties = context_a.read_properties().await.unwrap().unwrap();
		assert_eq!(properties.server_pubkey, Some(pk));
		assert!(properties.recovery_incomplete);
	}

	#[derive(Clone, Copy)]
	enum BatchFailure {
		BeforeCommit,
		LostAcknowledgement,
	}

	/// Only the atomic batch may mutate storage once a failure is armed.
	/// This also detects a sequential-write fallback in action completion.
	#[derive(Default)]
	struct FailingBatchAdaptor {
		storage: MemoryStorageAdaptor,
		failure: Option<BatchFailure>,
		batch_calls: usize,
	}

	#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
	#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
	impl StorageAdaptor for FailingBatchAdaptor {
		async fn put(&mut self, record: Record) -> anyhow::Result<()> {
			assert!(self.failure.is_none(), "action completion must use an atomic batch");
			self.storage.put(record).await
		}

		async fn put_batch_checked(
			&mut self, updates: Vec<RecordUpdate>, absent: &[(u8, Vec<u8>)],
		) -> anyhow::Result<()> {
			self.batch_calls += 1;
			let failure = self.failure.take();
			if matches!(failure, Some(BatchFailure::BeforeCommit)) {
				bail!("injected batch commit failure");
			}
			self.storage.put_batch_checked(updates, absent).await?;
			if matches!(failure, Some(BatchFailure::LostAcknowledgement)) {
				bail!("injected lost batch acknowledgement");
			}
			Ok(())
		}

		async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
			self.storage.get(partition, pk).await
		}

		async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
			assert!(self.failure.is_none(), "action completion must use an atomic batch");
			self.storage.delete(partition, pk).await
		}

		async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> {
			self.storage.query_sorted(query).await
		}

		async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
			self.storage.get_all(partition).await
		}
	}

	async fn action_failure_fixture() -> (StorageAdaptorWrapper<FailingBatchAdaptor>, WalletActionId) {
		let db = StorageAdaptorWrapper::new(FailingBatchAdaptor::default());
		let checkpoint: WalletActionCheckpoint = send_at_start().into();
		let id = checkpoint.id();
		let state = VtxoState::Locked {
			holder: Some(VtxoLockHolder::Action { id: id.clone() }),
		};
		db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
		db.store_vtxos(&[
			(&VTXO_VECTORS.board_vtxo, &state),
			(&VTXO_VECTORS.round1_vtxo, &state),
			(&VTXO_VECTORS.arkoor3_vtxo, &state),
		]).await.unwrap();
		db.update_vtxo_state_checked(
			VTXO_VECTORS.arkoor3_vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Locked],
		).await.unwrap();
		db.mark_vtxos_registered(&[VTXO_VECTORS.board_vtxo.id()]).await.unwrap();
		db.store_program_key(&program_key_fixture()).await.unwrap();
		db.store_program_recoveries(&[program_recovery_fixture()]).await.unwrap();
		(db, id)
	}

	async fn assert_finished_records(
		db: &StorageAdaptorWrapper<FailingBatchAdaptor>,
		id: &WalletActionId,
		before: &HashMap<u8, BTreeMap<Vec<u8>, Record>>,
	) {
		let guard = db.inner.read().await;
		let after = guard.storage.partitions();
		assert!(after[&partition::WALLET_ACTION_CHECKPOINT].get(id.as_bytes()).is_none());
		assert_eq!(
			after.values().map(|p| p.len()).sum::<usize>() + 1,
			before.values().map(|p| p.len()).sum::<usize>(),
		);
		let mut unlocked = 0;
		for (partition, records) in before {
			for (pk, record) in records {
				if *partition == partition::WALLET_ACTION_CHECKPOINT && pk.as_slice() == id.as_bytes() {
					continue;
				}
				let current = &after[partition][pk];
				if *partition == partition::VTXO {
					let mut original = record.to_data::<SerdeVtxo>().unwrap();
					if matches!(original.current_state(),
						Some(VtxoState::Locked {
							holder: Some(VtxoLockHolder::Action { id: holder }),
						}) if holder == id
					) {
						let finished = current.to_data::<SerdeVtxo>().unwrap();
						original.states.push(VtxoState::Spendable);
						assert_eq!(finished.states, original.states);
						assert_eq!(finished.vtxo, original.vtxo, "signed VTXO changed");
						assert_eq!(finished.registered, original.registered);
						assert_eq!(current.sort_key, Some(sort::vtxo_sort_key(
							VtxoStateKind::Spendable, original.vtxo.expiry_height().to_u32(),
							original.vtxo.amount(),
						)));
						unlocked += 1;
						continue;
					}
				}
				assert_eq!(current, record, "unrelated or recovery record changed");
			}
		}
		assert_eq!(unlocked, 2);
	}

	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
	async fn recovery_reservation_batch_failure_and_retry_preserve_records() {
		let (db, id) = action_failure_fixture().await;
		let selected = VTXO_VECTORS.board_vtxo.id();
		let future = VTXO_VECTORS.round2_vtxo.id();
		let owned = VtxoState::Locked { holder: Some(VtxoLockHolder::Action { id: id.clone() }) };
		let actors = [recovery_action_key(&id)];
		let before = {
			let mut guard = db.inner.write().await;
			guard.failure = Some(BatchFailure::BeforeCommit);
			guard.storage.partitions().clone()
		};
		assert!(db.reserve_program_recovery(&[
			(selected, Some(owned.clone())), (future, None),
		], &actors).await.is_err());
		assert_eq!(*db.inner.read().await.storage.partitions(), before);
		db.inner.write().await.failure = Some(BatchFailure::LostAcknowledgement);
		assert!(db.reserve_program_recovery(&[
			(selected, Some(owned)), (future, None),
		], &actors).await.is_err());
		let committed = db.inner.read().await.storage.partitions().clone();
		for (partition, records) in &before {
			for (pk, original) in records {
				let current = &committed[partition][pk];
				if *partition == partition::VTXO && *pk == selected.to_bytes().to_vec() {
					let mut expected = original.to_data::<SerdeVtxo>().unwrap();
					expected.states.push(VtxoState::Exited);
					let actual = current.to_data::<SerdeVtxo>().unwrap();
					assert_eq!(actual.states, expected.states);
					assert_eq!(actual.vtxo, expected.vtxo);
					assert_eq!(actual.registered, expected.registered);
					assert_eq!(current.sort_key, Some(sort::vtxo_sort_key(
						VtxoStateKind::Exited, expected.vtxo.expiry_height().to_u32(),
						expected.vtxo.amount(),
					)));
				} else {
					assert_eq!(current, original, "recovery changed unrelated data");
				}
			}
		}
		db.reserve_program_recovery(&[
			(selected, Some(VtxoState::Exited)), (future, None),
		], &actors).await.unwrap();
		assert_eq!(*db.inner.read().await.storage.partitions(), committed);
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert_eq!(*db.inner.read().await.storage.partitions(), committed);
	}

	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
	async fn finish_wallet_action_batch_failure_preserves_checkpoint_and_locks() {
		let (db, id) = action_failure_fixture().await;
		let before = {
			let mut guard = db.inner.write().await;
			guard.failure = Some(BatchFailure::BeforeCommit);
			guard.batch_calls = 0;
			guard.storage.partitions().clone()
		};
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert_eq!(*db.inner.read().await.storage.partitions(), before);
		db.finish_wallet_action(&id).await.unwrap();
		assert_finished_records(&db, &id, &before).await;
		let finished = db.inner.read().await.storage.partitions().clone();
		db.finish_wallet_action(&id).await.unwrap();
		let guard = db.inner.read().await;
		assert_eq!(*guard.storage.partitions(), finished, "retry appended VTXO state history");
		assert_eq!(guard.batch_calls, 2, "retry of a completed action must not write");
	}

	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
	async fn finish_wallet_action_lost_acknowledgement_is_idempotent() {
		let (db, id) = action_failure_fixture().await;
		let before = {
			let mut guard = db.inner.write().await;
			guard.failure = Some(BatchFailure::LostAcknowledgement);
			guard.batch_calls = 0;
			guard.storage.partitions().clone()
		};
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert_finished_records(&db, &id, &before).await;
		let finished = db.inner.read().await.storage.partitions().clone();
		db.finish_wallet_action(&id).await.unwrap();
		let guard = db.inner.read().await;
		assert_eq!(*guard.storage.partitions(), finished, "retry appended VTXO state history");
		assert_eq!(guard.batch_calls, 1, "retry must accept the committed batch");
	}
}

/// This module provides comprehensive tests for all four methods of the
/// `StorageAdaptor` trait. Use these functions to validate custom implementations.
///
/// # Example
///
/// ```rust
/// use sapling::persist::adaptor::memory::test_suite;
///
/// #[tokio::test]
/// async fn test_my_custom_adaptor() {
///     let storage = MyCustomStorageAdaptor::new();
///     test_suite::run_all(&storage).await;
/// }
/// ```
#[cfg(test)]
pub mod test_suite {
	use super::*;
	use super::partition::LAST_IDS;
	use super::sort::SortKey;

	async fn clear_partitions<S: StorageAdaptor>(storage: &mut S, partitions: &[u8]) -> anyhow::Result<()> {
		for partition in partitions {
			let records = storage.get_all(*partition).await?;
			for record in records {
				storage.delete(record.partition, &record.pk).await?;
			}
		}
		Ok(())
	}

	/// Absence assertions participate in the commit, but never create records.
	pub async fn test_put_batch_absent_atomic<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[90, 91]).await.unwrap();
		let existing = Record { partition: 90, pk: vec![1], sort_key: None, data: vec![2] };
		let inserted = Record { partition: 91, pk: vec![3], sort_key: None, data: vec![4] };
		storage.put(existing.clone()).await.unwrap();
		assert!(storage.put_batch_checked(vec![
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
		], &[(90, existing.pk.clone())]).await.is_err());
		assert_eq!(storage.get(91, &inserted.pk).await.unwrap(), None);
		assert_eq!(storage.get(90, &existing.pk).await.unwrap(), Some(existing));
		storage.put_batch_checked(vec![
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
		], &[(90, vec![9])]).await.unwrap();
		assert_eq!(storage.get(91, &inserted.pk).await.unwrap(), Some(inserted));
		assert_eq!(storage.get(90, &[9]).await.unwrap(), None);
	}

	/// A late conflict must roll back earlier replacements and insertions.
	pub async fn test_put_batch_atomic<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[90, 91]).await.unwrap();
		let existing = Record { partition: 90, pk: vec![1], sort_key: None, data: vec![2] };
		storage.put(existing.clone()).await.unwrap();
		let inserted = Record { partition: 91, pk: vec![3], sort_key: None, data: vec![4] };
		let changed = Record { data: vec![5], ..existing.clone() };
		let wrong = Record { data: vec![6], ..existing.clone() };
		assert!(storage.put_batch(vec![
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
			RecordUpdate { previous: Some(wrong), updated: Some(changed.clone()) },
		]).await.is_err());
		assert!(storage.get(inserted.partition, &inserted.pk).await.unwrap().is_none());
		assert_eq!(storage.get(existing.partition, &existing.pk).await.unwrap(), Some(existing.clone()));
		storage.put_batch(vec![
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
			RecordUpdate { previous: Some(existing), updated: Some(changed.clone()) },
		]).await.unwrap();
		assert_eq!(storage.get(inserted.partition, &inserted.pk).await.unwrap(), Some(inserted));
		assert_eq!(storage.get(changed.partition, &changed.pk).await.unwrap(), Some(changed));
		clear_partitions(storage, &[90, 91]).await.unwrap();
	}

	/// Deletes, replacements, and inserts must share one conditional commit.
	pub async fn test_put_batch_delete_atomic<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[90, 91]).await.unwrap();
		let deleted = Record {
			partition: 90, pk: vec![1], sort_key: Some(SortKey::u32_asc(1)), data: vec![2],
		};
		let existing = Record { partition: 91, pk: vec![3], sort_key: None, data: vec![4] };
		let inserted = Record { partition: 90, pk: vec![5], sort_key: None, data: vec![6] };
		let changed = Record {
			sort_key: Some(SortKey::u32_asc(7)), data: vec![8], ..existing.clone()
		};
		storage.put(deleted.clone()).await.unwrap();
		storage.put(existing.clone()).await.unwrap();

		let stale = Record { data: vec![9], ..existing.clone() };
		assert!(storage.put_batch(vec![
			RecordUpdate { previous: Some(deleted.clone()), updated: None },
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
			RecordUpdate { previous: Some(stale), updated: Some(changed.clone()) },
		]).await.is_err());
		assert_eq!(storage.get(deleted.partition, &deleted.pk).await.unwrap(), Some(deleted.clone()));
		assert_eq!(storage.get(existing.partition, &existing.pk).await.unwrap(), Some(existing.clone()));
		assert!(storage.get(inserted.partition, &inserted.pk).await.unwrap().is_none());

		// A delete must compare the sort key as well as the payload.
		let stale = Record { sort_key: None, ..deleted.clone() };
		assert!(storage.put_batch(vec![
			RecordUpdate { previous: Some(existing.clone()), updated: Some(changed.clone()) },
			RecordUpdate { previous: Some(stale), updated: None },
		]).await.is_err());
		assert_eq!(storage.get(deleted.partition, &deleted.pk).await.unwrap(), Some(deleted.clone()));
		assert_eq!(storage.get(existing.partition, &existing.pk).await.unwrap(), Some(existing.clone()));

		storage.put_batch(vec![
			RecordUpdate { previous: Some(deleted.clone()), updated: None },
			RecordUpdate { previous: Some(existing), updated: Some(changed.clone()) },
			RecordUpdate { previous: None, updated: Some(inserted.clone()) },
		]).await.unwrap();
		assert!(storage.get(deleted.partition, &deleted.pk).await.unwrap().is_none());
		assert_eq!(storage.get(changed.partition, &changed.pk).await.unwrap(), Some(changed.clone()));
		assert_eq!(storage.get(inserted.partition, &inserted.pk).await.unwrap(), Some(inserted.clone()));

		// A stale delete of an absent record must not apply earlier updates.
		assert!(storage.put_batch(vec![
			RecordUpdate {
				previous: Some(inserted.clone()),
				updated: Some(Record { data: vec![10], ..inserted.clone() }),
			},
			RecordUpdate { previous: Some(deleted), updated: None },
		]).await.is_err());
		assert_eq!(storage.get(inserted.partition, &inserted.pk).await.unwrap(), Some(inserted));
		clear_partitions(storage, &[90, 91]).await.unwrap();
	}

	/// Invalid identities and duplicate keys must not apply earlier updates.
	pub async fn test_put_batch_invalid_updates<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[90, 91]).await.unwrap();
		let first = Record { partition: 90, pk: vec![1], sort_key: None, data: vec![2] };
		let second = Record { partition: 91, pk: vec![3], sort_key: None, data: vec![4] };
		storage.put(first.clone()).await.unwrap();
		storage.put(second.clone()).await.unwrap();
		for invalid in [
			vec![RecordUpdate { previous: None, updated: None }],
			vec![RecordUpdate {
				previous: Some(second.clone()),
				updated: Some(Record { pk: vec![5], ..second.clone() }),
			}],
			vec![RecordUpdate {
				previous: Some(second.clone()),
				updated: Some(Record { partition: 90, ..second.clone() }),
			}],
			vec![
				RecordUpdate { previous: Some(second.clone()), updated: None },
				RecordUpdate { previous: Some(second.clone()), updated: None },
			],
			vec![
				RecordUpdate { previous: Some(second.clone()), updated: None },
				RecordUpdate { previous: None, updated: Some(second.clone()) },
			],
		] {
			let mut updates = vec![RecordUpdate {
				previous: Some(first.clone()),
				updated: Some(Record { data: vec![6], ..first.clone() }),
			}];
			updates.extend(invalid);
			assert!(storage.put_batch(updates).await.is_err());
			assert_eq!(storage.get(first.partition, &first.pk).await.unwrap(), Some(first.clone()));
			assert_eq!(storage.get_all(second.partition).await.unwrap(), vec![second.clone()]);
			assert_eq!(storage.get_all(first.partition).await.unwrap(), vec![first.clone()]);
		}
		clear_partitions(storage, &[90, 91]).await.unwrap();
	}

	/// Runs all test suites against the given storage adaptor.
	pub async fn run_all<S: StorageAdaptor>(storage: &mut S) {
		// put tests
		test_put_insert(storage).await;
		test_put_upsert(storage).await;
		test_put_with_sort_key(storage).await;
		test_put_without_sort_key(storage).await;
		test_put_multiple_partitions(storage).await;
		test_put_batch_atomic(storage).await;
		test_put_batch_delete_atomic(storage).await;
		test_put_batch_invalid_updates(storage).await;
		test_put_batch_absent_atomic(storage).await;

		// get tests
		test_get_existing(storage).await;
		test_get_after_update(storage).await;

		// delete tests
		test_delete_existing(storage).await;
		test_delete_nonexistent(storage).await;
		test_delete_idempotent(storage).await;

		// query tests
		test_query_empty_partition(storage).await;
		test_query_returns_partition_records(storage).await;
		test_query_ordering(storage).await;
		test_query_with_limit(storage).await;
		test_query_null_sort_key_excluded(storage).await;
		test_query_partition_isolation(storage).await;
		test_query_range(storage).await;
		test_query_exclusive_end_range(storage).await;
		test_query_full_range_limit_one(storage).await;

		// get_all tests
		test_get_all_empty_partition(storage).await;
		test_get_all_returns_all_records(storage).await;
		test_get_all_includes_records_without_sort_key(storage).await;
		test_get_all_partition_isolation(storage).await;
		test_get_all_after_delete(storage).await;

		// incremental_id tests
		test_incremental_id_starts_at_one(storage).await;
		test_incremental_id_increments(storage).await;
		test_incremental_id_partition_isolation(storage).await;
		test_incremental_id_persists_across_operations(storage).await;
	}

	/// Tests that put inserts a new record.
	pub async fn test_put_insert<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: "put_insert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"test data".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_insert_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.pk, b"put_insert_1");
		assert_eq!(retrieved.partition, 0);
		assert_eq!(retrieved.data, b"test data");
	}

	/// Tests that put updates an existing record (upsert behavior).
	pub async fn test_put_upsert<S: StorageAdaptor>(storage: &mut S) {
		let record1 = Record {
			pk: b"put_upsert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"original".to_vec(),
		};
		storage.put(record1).await.expect("first put should succeed");

		let record2 = Record {
			pk: "put_upsert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"updated".to_vec(),
		};
		storage
			.put(record2)
			.await
			.expect("second put should succeed");

		let retrieved = storage
			.get(0, b"put_upsert_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.data, b"updated", "data should be updated");
	}

	/// Tests that put correctly stores the sort key.
	pub async fn test_put_with_sort_key<S: StorageAdaptor>(storage: &mut S) {
		let sort_key = SortKey::u32_asc(42);
		let record = Record {
			pk: b"put_sort_key_1".into(),
			partition: 0,
			sort_key: Some(sort_key.clone()),
			data: b"with sort key".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_sort_key_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.sort_key, Some(sort_key));
	}

	/// Tests that put correctly handles records without sort keys.
	pub async fn test_put_without_sort_key<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"put_no_sort_key_1".into(),
			partition: 0,
			sort_key: None,
			data: b"no sort key".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_no_sort_key_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert!(retrieved.sort_key.is_none());
	}

	/// Tests that put correctly handles multiple partitions.
	pub async fn test_put_multiple_partitions<S: StorageAdaptor>(storage: &mut S) {
		let record_a = Record {
			pk: "put_multi_a".into(),
			partition: 0,
			sort_key: None,
			data: b"in partition a".to_vec(),
		};
		let record_b = Record {
			pk: "put_multi_b".into(),
			partition: 1,
			sort_key: None,
			data: b"in partition b".to_vec(),
		};

		storage.put(record_a).await.expect("put a should succeed");
		storage.put(record_b).await.expect("put b should succeed");

		let retrieved_a = storage
			.get(0, b"put_multi_a")
			.await
			.expect("get should succeed")
			.expect("record a should exist");
		let retrieved_b = storage
			.get(1, b"put_multi_b")
			.await
			.expect("get should succeed")
			.expect("record b should exist");

		assert_eq!(retrieved_a.partition, 0);
		assert_eq!(retrieved_b.partition, 1);
	}

	/// Tests that get returns an existing record.
	pub async fn test_get_existing<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"get_existing_1".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(100)),
			data: b"test".to_vec(),
		};
		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"get_existing_1")
			.await
			.expect("get should succeed");

		assert!(retrieved.is_some());
		let retrieved = retrieved.unwrap();
		assert_eq!(retrieved.pk, b"get_existing_1");
		assert_eq!(retrieved.partition, 0);
		assert_eq!(retrieved.data, b"test");

		// superset of the key
		assert!(storage.get(0, b"get_existing_1_").await.unwrap().is_none());
		// subset of the key
		assert!(storage.get(0, b"get_existing_").await.unwrap().is_none());

		// non-existent key
		assert!(storage.get(0, b"get_nonexistent_does_not_exist").await.unwrap().is_none());
	}

	/// Tests that get returns updated data after put.
	pub async fn test_get_after_update<S: StorageAdaptor>(storage: &mut S) {
		let record1 = Record {
			pk: b"get_after_update_1".into(),
			partition: 0,
			sort_key: None,
			data: b"version1".to_vec(),
		};
		storage.put(record1).await.expect("put should succeed");

		let record2 = Record {
			pk: b"get_after_update_1".into(),
			partition: 0,
			sort_key: None,
			data: b"version2".to_vec(),
		};
		storage.put(record2).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"get_after_update_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.data, b"version2");
	}

	/// Tests that delete removes an existing record and returns it.
	pub async fn test_delete_existing<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"delete_existing_1".into(),
			partition: 0,
			sort_key: None,
			data: b"to delete".to_vec(),
		};
		storage.put(record.clone()).await.expect("put should succeed");

		let deleted_record = storage
			.delete(0, b"delete_existing_1")
			.await
			.expect("delete should succeed");

		assert_eq!(deleted_record, Some(record));

		let retrieved = storage
			.get(0, b"delete_existing_1")
			.await
			.expect("get should succeed");
		assert!(retrieved.is_none(), "record should no longer exist");
	}

	/// Tests that delete returns None for non-existent records.
	pub async fn test_delete_nonexistent<S: StorageAdaptor>(storage: &mut S) {
		let deleted_record = storage
			.delete(0, b"delete_nonexistent_does_not_exist")
			.await
			.expect("delete should succeed");

		assert!(
			deleted_record.is_none(),
			"delete should return None for non-existent record"
		);
	}

	/// Tests that delete is idempotent (second delete returns None).
	pub async fn test_delete_idempotent<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"delete_idempotent_1".into(),
			partition: 0,
			sort_key: None,
			data: b"delete twice".to_vec(),
		};
		storage.put(record.clone()).await.expect("put should succeed");

		let first_delete = storage
			.delete(0, b"delete_idempotent_1")
			.await
			.expect("first delete should succeed");
		let second_delete = storage
			.delete(0, b"delete_idempotent_1")
			.await
			.expect("second delete should succeed");

		assert_eq!(first_delete, Some(record), "first delete should return the record");
		assert_eq!(second_delete, None, "second delete should return None");
	}

	/// Tests that query returns empty results for empty partition.
	pub async fn test_query_empty_partition<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		let results = storage
			.query_sorted(Query::new_full_range(0))
			.await
			.expect("query should succeed");

		assert!(results.is_empty());
	}

	/// Tests that query returns all records in a partition.
	pub async fn test_query_returns_partition_records<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		for i in 0..3 {
			let record = Record {
				pk: format!("query_partition_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query_sorted(Query::new_full_range(0))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 3);
	}

	/// Tests that query returns records in ascending sort key order by default.
	pub async fn test_query_ordering<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		// Insert in non-sequential order
		for i in [5, 2, 8, 1, 9] {
			let record = Record {
				pk: format!("query_asc_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query_sorted(Query::new_full_range(0))
			.await
			.expect("query should succeed");

		let values = results.iter().map(|r| r.data.clone()).collect::<Vec<_>>();
		assert_eq!(
			values,
			vec![b"record_1".to_vec(), b"record_2".to_vec(), b"record_5".to_vec(), b"record_8".to_vec(), b"record_9".to_vec()],
			"should be in ascending order"
		);
	}

	/// Tests that query with limit returns at most N records.
	pub async fn test_query_with_limit<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		for i in 0..10 {
			let record = Record {
				pk: format!("query_limit_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query_sorted(Query::new_full_range(0).limit(3))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 3);
		let values = results.iter().map(|r| r.data.clone()).collect::<Vec<_>>();
		assert_eq!(
			values,
			vec![b"record_0".to_vec(), b"record_1".to_vec(), b"record_2".to_vec()],
			"should return first 3 records"
		);
	}

	/// Tests that records without sort keys don't appear in query
	pub async fn test_query_null_sort_key_excluded<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		// Records with sort keys
		let with_key_1 = Record {
			pk: "query_null_with_1".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(1)),
			data: b"with_key_1".to_vec(),
		};
		let with_key_2 = Record {
			pk: "query_null_with_2".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(2)),
			data: b"with_key_2".to_vec(),
		};

		// Record without sort key
		let without_key = Record {
			pk: "query_null_without".into(),
			partition: 0,
			sort_key: None,
			data: b"no_key".to_vec(),
		};

		storage.put(with_key_1).await.expect("put should succeed");
		storage.put(without_key).await.expect("put should succeed");
		storage.put(with_key_2).await.expect("put should succeed");

		// query should only return records with sort keys
		let results_query = storage.query_sorted(Query::new_full_range(0)).await
			.expect("query should succeed");
		assert_eq!(results_query.len(), 2, "query should only return records with sort keys");
		assert_eq!(results_query[0].data, b"with_key_1");
		assert_eq!(results_query[1].data, b"with_key_2");

		// get_all should return all records
		let results_all = storage.get_all(0).await
			.expect("get_all should succeed");
		assert_eq!(results_all.len(), 3, "get_all should return all records including those without sort keys");

		// Verify all three records are present (order not guaranteed for get_all)
		let has_with_key_1 = results_all.iter().any(|r| r.data == b"with_key_1");
		let has_with_key_2 = results_all.iter().any(|r| r.data == b"with_key_2");
		let has_without_key = results_all.iter().any(|r| r.data == b"no_key");
		assert!(has_with_key_1, "get_all should include with_key_1");
		assert!(has_with_key_2, "get_all should include with_key_2");
		assert!(has_without_key, "get_all should include record without sort key");
	}

	/// Tests that query only returns records from the specified partition.
	pub async fn test_query_partition_isolation<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1]).await.unwrap();
		// Records in partition A
		for i in 0..3 {
			let record = Record {
				pk: format!("query_iso_a_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Records in partition B
		for i in 0..5 {
			let record = Record {
				pk: format!("query_iso_b_{}", i).into(),
				partition: 1,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i + 100).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results_a = storage
			.query_sorted(Query::new_full_range(0))
			.await
			.expect("query should succeed");

		let results_b = storage
			.query_sorted(Query::new_full_range(1))
			.await
			.expect("query should succeed");

		assert_eq!(results_a.len(), 3, "partition A should have 3 records");
		assert_eq!(results_b.len(), 5, "partition B should have 5 records");

		// Verify all results_a are from partition A
		assert!(results_a
			.iter()
			.all(|r| r.partition == 0));

		// Verify all results_b are from partition B
		assert!(results_b
			.iter()
			.all(|r| r.partition == 1));
	}

	/// Tests that query with start and end keys returns only records within the range.
	pub async fn test_query_range<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		// Insert records with sort keys 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
		for i in 1..=10u32 {
			let record = Record {
				pk: format!("query_range_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Query with start key only (>= 5)
		let results_start = storage
			.query_sorted(Query::new(0, SortKey::u32_asc(5)..))
			.await
			.expect("query should succeed");

		assert_eq!(results_start.len(), 6, "should return records 5-10");
		let values: Vec<_> = results_start.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_5".to_vec(),
				b"record_6".to_vec(),
				b"record_7".to_vec(),
				b"record_8".to_vec(),
				b"record_9".to_vec(),
				b"record_10".to_vec(),
			],
			"should return records from 5 onwards"
		);

		// Query with end key only (<= 3)
		let results_end = storage
			.query_sorted(Query::new(0, ..=SortKey::u32_asc(3)))
			.await
			.expect("query should succeed");

		assert_eq!(results_end.len(), 3, "should return records 1-3");
		let values: Vec<_> = results_end.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_1".to_vec(),
				b"record_2".to_vec(),
				b"record_3".to_vec(),
			],
			"should return records up to 3"
		);

		// Query with both start and end keys (3 <= x <= 7)
		let results_range = storage
			.query_sorted(Query::new(0, SortKey::u32_asc(3)..=SortKey::u32_asc(7)))
			.await
			.expect("query should succeed");

		assert_eq!(results_range.len(), 5, "should return records 3-7");
		let values: Vec<_> = results_range.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_3".to_vec(),
				b"record_4".to_vec(),
				b"record_5".to_vec(),
				b"record_6".to_vec(),
				b"record_7".to_vec(),
			],
			"should return records in range 3-7"
		);

		// Query range with limit
		let results_range_limit = storage
			.query_sorted(Query::new(0, SortKey::u32_asc(2)..=SortKey::u32_asc(8)).limit(3))
			.await
			.expect("query should succeed");

		assert_eq!(results_range_limit.len(), 3, "should return only 3 records due to limit");
		let values: Vec<_> = results_range_limit.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_2".to_vec(),
				b"record_3".to_vec(),
				b"record_4".to_vec(),
			],
			"should return first 3 records in range"
		);

		// Query range that matches no records
		let results_empty = storage
			.query_sorted(Query::new(0, SortKey::u32_asc(100)..=SortKey::u32_asc(200)))
			.await
			.expect("query should succeed");

		assert!(results_empty.is_empty(), "should return no records for out-of-range query");
	}

	/// Tests that exclusive end ranges (start..end) exclude the end bound.
	pub async fn test_query_exclusive_end_range<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		for i in 1..=10u32 {
			let record = Record {
				pk: format!("query_excl_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Exclusive end: 3 <= x < 7 (should return records 3, 4, 5, 6)
		let results = storage
			.query_sorted(Query::new(0, SortKey::u32_asc(3)..SortKey::u32_asc(7)))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 4, "exclusive end should not include record_7");
		let values: Vec<_> = results.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_3".to_vec(),
				b"record_4".to_vec(),
				b"record_5".to_vec(),
				b"record_6".to_vec(),
			],
		);

		// Exclusive end only: x < 4 (should return records 1, 2, 3)
		let results = storage
			.query_sorted(Query::new(0, ..SortKey::u32_asc(4)))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 3, "exclusive upper bound should not include record_4");
		let values: Vec<_> = results.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_1".to_vec(),
				b"record_2".to_vec(),
				b"record_3".to_vec(),
			],
		);
	}

	/// Tests that full-range query with limit 1 returns the first sorted record.
	pub async fn test_query_full_range_limit_one<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		for i in [5u32, 2, 8, 1, 9] {
			let record = Record {
				pk: format!("query_limit1_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query_sorted(Query::new_full_range(0).limit(1))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 1);
		assert_eq!(results[0].data, b"record_1".to_vec(), "limit 1 should return the first record in sort order");
	}

	/// Tests that incremental_id returns 1 for the first call on a partition.
	pub async fn test_incremental_id_starts_at_one<S: StorageAdaptor>(storage: &mut S) {
		// Clear the LAST_IDS entry for partition 0
		storage.delete(LAST_IDS, b"0").await.unwrap();
		let id = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		assert_eq!(id, 1, "first id should be 1");
	}

	/// Tests that incremental_id increments on subsequent calls.
	pub async fn test_incremental_id_increments<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, LAST_IDS]).await.unwrap();

		let id1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id3 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		assert_eq!(id1, 1, "first id should be 1");
		assert_eq!(id2, 2, "second id should be 2");
		assert_eq!(id3, 3, "third id should be 3");
	}

	/// Tests that incremental_id maintains separate sequences for different partitions.
	pub async fn test_incremental_id_partition_isolation<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1, LAST_IDS]).await.unwrap();

		// Generate IDs for partition A
		let a1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let a2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let a3 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		// Generate IDs for partition B
		let b1 = storage.incremental_id(1).await
			.expect("incremental_id should succeed");
		let b2 = storage.incremental_id(1).await
			.expect("incremental_id should succeed");

		// Partition A should have 1, 2, 3
		assert_eq!(a1, 1);
		assert_eq!(a2, 2);
		assert_eq!(a3, 3);

		// Partition B should have its own sequence starting at 1
		assert_eq!(b1, 1);
		assert_eq!(b2, 2);

		// Generate more for A - should continue from 3
		let a4 = storage.incremental_id(0).await.expect("incremental_id should succeed");
		assert_eq!(a4, 4);
	}

	/// Tests that incremental_id persists its state correctly.
	pub async fn test_incremental_id_persists_across_operations<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1, LAST_IDS]).await.unwrap();

		// Generate some IDs
		let id1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		assert_eq!(id1, 1);
		assert_eq!(id2, 2);

		// Verify the stored value can be retrieved directly
		let stored = storage
			.get(LAST_IDS, &[0])
			.await
			.expect("get should succeed")
			.expect("id record should exist");
		let stored_id: u32 = serde_json::from_slice(&stored.data).expect("should deserialize");
		assert_eq!(stored_id, 2, "stored id should be 2");

		// Continue generating - should pick up where we left off
		let id3 = storage.incremental_id(0).await.expect("incremental_id should succeed");
		assert_eq!(id3, 3);
	}

	/// Tests that get_all returns empty results for empty partition.
	pub async fn test_get_all_empty_partition<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		let results = storage
			.get_all(0)
			.await
			.expect("get_all should succeed");

		assert!(results.is_empty(), "get_all should return empty for empty partition");
	}

	/// Tests that get_all returns all records in a partition.
	pub async fn test_get_all_returns_all_records<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		// Insert records with sort keys
		for i in 0..5 {
			let record = Record {
				pk: format!("get_all_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.get_all(0)
			.await
			.expect("get_all should succeed");

		assert_eq!(results.len(), 5, "get_all should return all 5 records");

		// Verify all records are present (order not guaranteed)
		for i in 0..5 {
			let expected_data = format!("record_{}", i).as_bytes().to_vec();
			let found = results.iter().any(|r| r.data == expected_data);
			assert!(found, "get_all should include record_{}", i);
		}
	}

	/// Tests that get_all includes records without sort keys.
	pub async fn test_get_all_includes_records_without_sort_key<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		// Insert records with sort keys
		let with_key_1 = Record {
			pk: "get_all_with_1".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(1)),
			data: b"with_key_1".to_vec(),
		};
		let with_key_2 = Record {
			pk: "get_all_with_2".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(2)),
			data: b"with_key_2".to_vec(),
		};

		// Insert records without sort keys
		let without_key_1 = Record {
			pk: "get_all_without_1".into(),
			partition: 0,
			sort_key: None,
			data: b"without_key_1".to_vec(),
		};
		let without_key_2 = Record {
			pk: "get_all_without_2".into(),
			partition: 0,
			sort_key: None,
			data: b"without_key_2".to_vec(),
		};

		storage.put(with_key_1).await.expect("put should succeed");
		storage.put(without_key_1).await.expect("put should succeed");
		storage.put(with_key_2).await.expect("put should succeed");
		storage.put(without_key_2).await.expect("put should succeed");

		let results = storage
			.get_all(0)
			.await
			.expect("get_all should succeed");

		assert_eq!(results.len(), 4, "get_all should return all 4 records");

		// Verify all records are present
		let has_with_1 = results.iter().any(|r| r.data == b"with_key_1");
		let has_with_2 = results.iter().any(|r| r.data == b"with_key_2");
		let has_without_1 = results.iter().any(|r| r.data == b"without_key_1");
		let has_without_2 = results.iter().any(|r| r.data == b"without_key_2");

		assert!(has_with_1, "get_all should include with_key_1");
		assert!(has_with_2, "get_all should include with_key_2");
		assert!(has_without_1, "get_all should include without_key_1");
		assert!(has_without_2, "get_all should include without_key_2");

		// Verify that query excludes records without sort keys
		let query_results = storage
			.query_sorted(Query::new_full_range(0))
			.await
			.expect("query should succeed");

		assert_eq!(query_results.len(), 2, "query should only return records with sort keys");
		let query_has_without = query_results.iter().any(|r| r.sort_key.is_none());
		assert!(!query_has_without, "query should not include records without sort keys");
	}

	/// Tests that get_all only returns records from the specified partition.
	pub async fn test_get_all_partition_isolation<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1]).await.unwrap();

		// Insert records in partition 0
		for i in 0..3 {
			let record = Record {
				pk: format!("partition_0_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("p0_record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Insert records in partition 1
		for i in 0..2 {
			let record = Record {
				pk: format!("partition_1_{}", i).into(),
				partition: 1,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("p1_record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// get_all partition 0
		let results_0 = storage.get_all(0).await.expect("get_all should succeed");
		assert_eq!(results_0.len(), 3, "partition 0 should have 3 records");
		assert!(results_0.iter().all(|r| r.partition == 0), "all records should be from partition 0");

		// get_all partition 1
		let results_1 = storage.get_all(1).await.expect("get_all should succeed");
		assert_eq!(results_1.len(), 2, "partition 1 should have 2 records");
		assert!(results_1.iter().all(|r| r.partition == 1), "all records should be from partition 1");
	}

	/// Tests that get_all reflects deletions.
	pub async fn test_get_all_after_delete<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		for i in 0..3u32 {
			let record = Record {
				pk: format!("get_all_del_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		storage.delete(0, b"get_all_del_1").await.expect("delete should succeed");

		let results = storage.get_all(0).await.expect("get_all should succeed");
		assert_eq!(results.len(), 2, "get_all should reflect the deletion");

		let has_deleted = results.iter().any(|r| r.data == b"record_1".to_vec());
		assert!(!has_deleted, "deleted record should not appear");
	}
}

