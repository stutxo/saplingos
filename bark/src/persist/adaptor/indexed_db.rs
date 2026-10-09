use std::collections::HashSet;
use std::ops::Bound;

use anyhow::Context;
use bitcoin::hex::DisplayHex;
use indexed_db::{Database, Factory, TransactionBuilder};
use tokio::sync::{Mutex, MutexGuard};
use web_sys::js_sys::JsString;
use web_sys::wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::persist::adaptor::{
	validate_record_updates, Query, QueryRange, Record, RecordUpdate, SortKey, StorageAdaptor,
};

const OBJECT_STORE_PREFIX: &str = "bark.v1.";

fn partition_name(partition: u8) -> String {
	format!("{OBJECT_STORE_PREFIX}{partition}")
}

struct IndexedDbInner {
	db: String,
	version: u32,
	partitions: HashSet<String>,
	conn: Option<Database<std::io::Error>>,
}

impl IndexedDbInner {
	fn factory() -> anyhow::Result<Factory<std::io::Error>> {
		Ok(Factory::<std::io::Error>::get().context("opening IndexedDB")?)
	}

	pub async fn new(db: &str) -> anyhow::Result<Self> {
		let conn = Self::factory()?.open_latest_version(db).await
			.context("opening the IndexedDB")?;

		let version = conn.version();
		let partitions = HashSet::from_iter(conn.object_store_names());

		Ok(Self {
			db: db.to_string(),
			version,
			partitions,
			conn: Some(conn),
		})
	}

	/// Adds a new partition to the database.
	///
	/// Fails if the database already contains the partition.
	async fn add_partition(&mut self, partition: &str) -> anyhow::Result<()> {
		self.conn.take().context("database connection already closed")?.close();

		let version = self.version + 1;

		let partition_name = partition.to_string();
		let conn = Self::factory()?.open(&self.db, version, move |evt| async move {
			let db = evt.database();
			let store = db.build_object_store(&partition_name).create()?;
			store.build_index("sort_key", "sort_key").create()?;
			Ok(())
		}).await?;

		self.version = version;
		self.partitions.insert(partition.to_string());
		self.conn = Some(conn);

		Ok(())
	}

	/// Opens a database connection and ensures the requested partition exists.
	///
	/// Returns a transaction builder, to execute any subsequent operations on the database
	async fn ensure_partition(&mut self, partition: &str)
		-> anyhow::Result<TransactionBuilder<std::io::Error>>
	{
		if !self.partitions.contains(partition) {
			self.add_partition(partition).await?;
		}

		let conn = self.conn.as_ref()
			.context("database connection already closed")?;

		debug_assert_eq!(conn.version(), self.version);
		Ok(conn.transaction(&[partition]))
	}
}

impl Drop for IndexedDbInner {
	fn drop(&mut self) {
		if let Some(conn) = self.conn.take() {
			conn.close();
		}
	}
}

pub struct IndexedDbClient {
	inner: Mutex<Option<IndexedDbInner>>,
}

impl IndexedDbClient {
	pub async fn open(db_name: &str) -> anyhow::Result<IndexedDbClient> {
		Ok(IndexedDbClient {
			inner: Mutex::new(Some(IndexedDbInner::new(db_name).await?)),
		})
	}

	async fn inner(&self) -> anyhow::Result<MutexGuard<'_, Option<IndexedDbInner>>> {
		let guard = self.inner.lock().await;
		if guard.is_none() {
			bail!("database connection already closed");
		}
		Ok(guard)
	}
}

fn sort_key_to_js(sk: &SortKey) -> JsValue {
	serde_wasm_bindgen::to_value(sk).expect("sortkey should be serializable")
}

/// IndexedDbClient is single-threaded, so it is safe to send and sync.
unsafe impl Sync for IndexedDbClient {}

// indexed-db 0.4 does not expose transaction completion or strict durability.
// Keep the ordinary query wrapper, but make conditional batches acknowledge the
// browser's actual commit event, not merely the last successful request.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = r#"
export function barkPutBatch(name, version, partitions, updates, absent) {
	return new Promise((resolve, reject) => {
		let rejected = false;
		const opening = indexedDB.open(name, version);
		opening.onerror = () => reject(opening.error);
		opening.onblocked = () => {
			rejected = true;
			reject(new Error("program storage database open is blocked"));
		};
		opening.onupgradeneeded = () => {
			rejected = true;
			opening.transaction.abort();
			reject(new Error("program storage database version changed"));
		};
		opening.onsuccess = () => {
			const db = opening.result;
			if (rejected) { db.close(); return; }
			let tx;
			let failure;
			try {
				tx = db.transaction(partitions, "readwrite", { durability: "strict" });
				tx.oncomplete = () => { db.close(); resolve(); };
				tx.onabort = () => {
					db.close();
					reject(failure || tx.error || new Error("program storage transaction aborted"));
				};
				if (tx.durability !== "strict") {
					throw new Error("strict IndexedDB durability is unavailable");
				}
				const bytesEqual = (a, b) =>
					a.length === b.length && Array.from(a).every((v, i) => v === b[i]);
				const sameRecord = (a, b) => a == null || b == null ? a == null && b == null :
					a.partition === b.partition && bytesEqual(a.pk, b.pk) &&
					bytesEqual(a.data, b.data) &&
					JSON.stringify(a.sort_key ?? null) === JSON.stringify(b.sort_key ?? null);
				let remaining = updates.length + absent.length;
				const writes = updates.map(update => {
					const record = update.updated ?? update.previous;
					return {
						store: tx.objectStore("bark.v1." + record.partition),
						key: Array.from(record.pk, b => b.toString(16).padStart(2, "0")).join(""),
						update,
					};
				});
				for (const [partition, pk] of absent) {
					writes.push({
						store: tx.objectStore("bark.v1." + partition),
						key: Array.from(pk, b => b.toString(16).padStart(2, "0")).join(""),
						update: { previous: null, assertion: true },
					});
				}
				for (const { store, key, update } of writes) {
					const request = store.get(key);
					request.onsuccess = () => {
						try {
							if (!sameRecord(request.result, update.previous)) {
								throw new Error("record changed during atomic update");
							}
							// Keep the transaction active, but do not mutate any
							// record until every comparison succeeds.
							if (--remaining === 0) {
								for (const write of writes) {
									if (write.update.assertion) continue;
									if (write.update.updated == null) {
										write.store.delete(write.key);
									} else {
										write.store.put(write.update.updated, write.key);
									}
								}
							}
						} catch (error) {
							failure = error;
							tx.abort();
						}
					};
				}
			} catch (error) {
				failure = error;
				if (tx) { tx.abort(); }
				else { db.close(); reject(error); }
			}
		};
	});
}
"#)]
extern "C" {
	#[wasm_bindgen(js_name = barkPutBatch)]
	fn put_batch_committed(
		name: &str,
		version: u32,
		partitions: JsValue,
		updates: JsValue,
		absent: JsValue,
	) -> web_sys::js_sys::Promise;
}

#[cfg(target_arch = "wasm32")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl StorageAdaptor for IndexedDbClient {
	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let pk = pk.to_lower_hex_string();
		let partition_name = partition_name(partition);

		let conn = self.inner().await?.as_mut().unwrap()
			.ensure_partition(&partition_name).await?;
		let value = conn.run(move |t| async move {
			let store = t.object_store(&partition_name)?;
			let key = JsString::from(pk);
			store.get(&key).await
		}).await?;

		match value {
			Some(v) => {
				let record: Record = serde_wasm_bindgen::from_value(v)
					.context("failed to deserialize record")?;
				Ok(Some(record))
			}
			None => Ok(None),
		}
	}

	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		let pk = record.pk.to_lower_hex_string();
		let partition_name = partition_name(record.partition);

		let value = serde_wasm_bindgen::to_value(&record)
			.context("failed to serialize record")?;

		let conn = self.inner().await?.as_mut().unwrap()
			.ensure_partition(&partition_name).await?;
		conn.rw().run(move |t| async move {
			let store = t.object_store(&partition_name)?;
			let key = JsString::from(pk);
			store.put_kv(&key, &value).await
		}).await?;

		Ok(())
	}

	async fn put_batch_checked(
		&mut self, updates: Vec<RecordUpdate>, absent: &[(u8, Vec<u8>)],
	) -> anyhow::Result<()> {
		validate_record_updates(&updates)?;
		if updates.is_empty() && absent.is_empty() {
			return Ok(());
		}
		let mut partitions = updates.iter().map(|u| Ok(partition_name(u.record()?.partition)))
			.collect::<anyhow::Result<HashSet<_>>>()?;
		partitions.extend(absent.iter().map(|(partition, _)| partition_name(*partition)));
		let mut guard = self.inner().await?;
		let inner = guard.as_mut().unwrap();
		for partition in &partitions {
			if !inner.partitions.contains(partition) {
				inner.add_partition(partition).await?;
			}
		}
		let promise = put_batch_committed(
			&inner.db,
			inner.version,
			serde_wasm_bindgen::to_value(&partitions)?,
			serde_wasm_bindgen::to_value(&updates)?,
			serde_wasm_bindgen::to_value(absent)?,
		);
		wasm_bindgen_futures::JsFuture::from(promise).await
			.map_err(|e| anyhow!("durable IndexedDB batch failed: {e:?}"))?;
		Ok(())
	}

	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let pk = pk.to_lower_hex_string();
		let partition_name = partition_name(partition);

		let conn = self.inner().await?.as_mut().unwrap()
			.ensure_partition(&partition_name).await?;
		let value = conn.rw().run(move |t| async move {
			let store = t.object_store(&partition_name)?;
			let key = JsString::from(pk);
			let existed = store.get(&key).await?;
			if let Some(value) = existed {
				store.delete(&key).await?;
				Ok(Some(value))
			} else {
				Ok(None)
			}
		}).await?;

		match value {
			Some(v) => {
				let record = serde_wasm_bindgen::from_value::<Record>(v)
					.context("deleted record but failed to deserialize")?;
				Ok(Some(record))
			}
			None => Ok(None),
		}
	}

	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> {
		let limit = query.limit.unwrap_or(usize::MAX) as u32;

		// Convert range bounds to JS values for the index query.
		// Records without a sort_key are excluded from the index by
		// IndexedDB (null keys are not indexed), matching our contract.
		let start_bound = query.range.start_bound().map(sort_key_to_js);
		let end_bound = query.range.end_bound().map(sort_key_to_js);

		let partition_name = partition_name(query.partition);
		let conn = self.inner().await?.as_mut().unwrap()
			.ensure_partition(&partition_name).await?;

		let values = conn.run(move |t| async move {
			let store = t.object_store(&partition_name)?;
			let index = store.index("sort_key")?;

			let values = match (start_bound, end_bound) {
				(Bound::Unbounded, Bound::Unbounded) => {
					index.get_all(Some(limit)).await?
				}
				(start, end) => {
					// Default lower bound to 0 so IndexedDB doesn't reject
					// an unbounded start (it requires a valid key range).
					let start = match start {
						Bound::Unbounded => Bound::Included(JsValue::from(0)),
						b => b,
					};
					index.get_all_in((start, end), Some(limit)).await?
				}
			};

			Ok(values)
		}).await
		.context("failed to query sorted records")?;

		let mut records = Vec::with_capacity(values.len());
		for value in values {
			let record = serde_wasm_bindgen::from_value::<Record>(value)
				.context("failed to deserialize record")?;
			records.push(record);
		}

		Ok(records)
	}

	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
		let partition_name = partition_name(partition);

		let conn = self.inner().await?.as_mut().unwrap()
			.ensure_partition(&partition_name).await?;
		let values = conn.run(move |t| async move {
			let store = t.object_store(&partition_name)?;
			let mut cursor = store.cursor().open().await?;

			let mut values = vec![];
			while let Some(value) = cursor.value() {
				values.push(value);
				cursor.advance(1).await?;
			}

			Ok(values)
		}).await
		.context("failed to get all records")?;

		let mut records = Vec::with_capacity(values.len());
		for value in values {
			let record = serde_wasm_bindgen::from_value::<Record>(value)
				.context("failed to deserialize record")?;
			records.push(record);
		}

		Ok(records)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::persist::adaptor::StorageAdaptorWrapper;
	use crate::persist::adaptor::test_suite;
	use crate::persist::BarkPersister;
	use crate::persist::test_suite::{
		bark_persister_tests, program_key_fixture, program_recovery_fixture,
	};
	use wasm_bindgen_test::wasm_bindgen_test;

	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	async fn setup(test: &str) -> ((), StorageAdaptorWrapper<IndexedDbClient>) {
		// IndexedDB databases are named and persistent, so every test
		// gets its own database.
		let client = IndexedDbClient::open(&format!("bark_persister_{}", test)).await
			.expect("failed to open IndexedDB");
		((), StorageAdaptorWrapper::new(client))
	}

	bark_persister_tests!(setup);

	#[wasm_bindgen_test]
	async fn program_records_survive_reopen() {
		let name = "bark_program_records_reopen";
		let key = program_key_fixture();
		let recovery = program_recovery_fixture();
		let db = StorageAdaptorWrapper::new(IndexedDbClient::open(name).await.unwrap());
		db.store_program_key(&key).await.unwrap();
		db.store_program_recoveries(&[recovery.clone()]).await.unwrap();
		drop(db);

		let db = StorageAdaptorWrapper::new(IndexedDbClient::open(name).await.unwrap());
		assert_eq!(db.get_program_key(&key.program.public_key().unwrap()).await.unwrap(), Some(key.clone()));
		assert_eq!(db.get_public_key_idx(&key.program.public_key().unwrap()).await.unwrap(), Some(key.index));
		assert_eq!(db.get_program_recovery(recovery.controlled_outpoint).await.unwrap(), Some(recovery.clone()));
		assert_eq!(db.list_program_recoveries().await.unwrap(), vec![recovery]);
	}

	/// Run the full test suite against IndexedDbClient.
	#[wasm_bindgen_test]
	async fn indexed_db_adaptor_full_test_suite() {
		let _ = console_log::init_with_level(log::Level::Debug);
		let mut storage = IndexedDbClient::open("test_db").await
			.expect("failed to open IndexedDB");
		test_suite::run_all(&mut storage).await;
	}

	/// Extracts the byte array from a JS sort key for comparison. This
	/// mirrors how IndexedDB compares Array keys: element-by-element.
	fn js_sort_key_bytes(js: &JsValue) -> Vec<u8> {
		let arr = web_sys::js_sys::Array::from(js);
		(0..arr.length())
			.map(|i| arr.get(i).as_f64().expect("element should be a number") as u8)
			.collect()
	}

	/// sort_key_to_js must preserve ascending u32 ordering so that
	/// IndexedDB range scans return records in the correct order.
	#[wasm_bindgen_test]
	fn sort_key_to_js_preserves_u32_ascending_order() {
		let keys: Vec<SortKey> = (0u32..5).map(SortKey::u32_asc).collect();

		for pair in keys.windows(2) {
			let a = js_sort_key_bytes(&sort_key_to_js(&pair[0]));
			let b = js_sort_key_bytes(&sort_key_to_js(&pair[1]));
			assert!(a < b, "u32_asc: expected {a:?} < {b:?}");
		}
	}

	/// sort_key_to_js must preserve descending u64 ordering so that
	/// higher values sort before lower ones in IndexedDB.
	#[wasm_bindgen_test]
	fn sort_key_to_js_preserves_u64_descending_order() {
		let keys: Vec<SortKey> = (1u64..6).map(SortKey::u64_desc).collect();

		for pair in keys.windows(2) {
			let a = js_sort_key_bytes(&sort_key_to_js(&pair[0]));
			let b = js_sort_key_bytes(&sort_key_to_js(&pair[1]));
			assert!(a > b, "u64_desc: expected {a:?} > {b:?}");
		}
	}

	/// sort_key_to_js must preserve composite key ordering: primary
	/// field (u32 asc) dominates, secondary field (u64 desc) breaks ties.
	#[wasm_bindgen_test]
	fn sort_key_to_js_preserves_composite_order() {
		let make = |height: u32, amount: u64| {
			SortKey::builder().u32_asc(height).u64_desc(amount).build()
		};

		// Same height, higher amount should sort first (desc)
		let a = sort_key_to_js(&make(100, 1000));
		let b = sort_key_to_js(&make(100, 500));
		assert!(js_sort_key_bytes(&a) < js_sort_key_bytes(&b),
			"same height: higher amount should sort first in desc");

		// Lower height always sorts before higher, regardless of amount
		let low = sort_key_to_js(&make(50, 1));
		let high = sort_key_to_js(&make(150, u64::MAX));
		assert!(js_sort_key_bytes(&low) < js_sort_key_bytes(&high),
			"lower height should sort before higher height");
	}

	/// Verifies the partition management lifecycle: a fresh database starts
	/// with no partitions, adding a partition bumps the version and creates
	/// the object store, and requesting an already-existing partition does
	/// not bump the version again.
	#[wasm_bindgen_test]
	async fn partition_management_lifecycle() {
		let _ = console_log::init_with_level(log::Level::Debug);

		// Fresh database: no partitions, version 0.
		let mut inner = IndexedDbInner::new("test_partition_lifecycle").await
			.expect("failed to open fresh IndexedDB");
		assert!(inner.partitions.is_empty(), "fresh db should have no partitions");
		let initial_version = inner.version;

		// Add a new partition — version must increase.
		inner.add_partition(&partition_name(1)).await.expect("add_partition(1) should succeed");
		assert!(inner.partitions.contains(&partition_name(1)));
		assert_eq!(inner.version, initial_version + 1);
		// ensure_partition for the same partition should not bump version.
		let version_before = inner.version;
		inner.ensure_partition(&partition_name(1)).await
			.expect("ensure_partition for existing partition should succeed");
		assert_eq!(inner.version, version_before, "version should not change for existing partition");
		// ensure_partition for a new partition should bump version.
		inner.ensure_partition(&partition_name(2)).await
			.expect("ensure_partition for new partition should succeed");
		assert_eq!(inner.version, version_before + 1);
		assert!(inner.partitions.contains(&partition_name(2)));
		// Re-open the database and confirm partitions persisted.
		let reopened = IndexedDbInner::new("test_partition_lifecycle").await
			.expect("failed to re-open IndexedDB");
		assert!(reopened.partitions.contains(&partition_name(1)));
		assert!(reopened.partitions.contains(&partition_name(2)));
		assert_eq!(reopened.version, inner.version);
	}

	/// sort_key_to_js must handle boundary values without losing order.
	#[wasm_bindgen_test]
	fn sort_key_to_js_preserves_order_at_boundaries() {
		let zero = sort_key_to_js(&SortKey::u32_asc(0));
		let one = sort_key_to_js(&SortKey::u32_asc(1));
		let max = sort_key_to_js(&SortKey::u32_asc(u32::MAX));

		assert!(js_sort_key_bytes(&zero) < js_sort_key_bytes(&one),
			"0 should sort before 1");
		assert!(js_sort_key_bytes(&one) < js_sort_key_bytes(&max),
			"1 should sort before u32::MAX");

		let desc_zero = sort_key_to_js(&SortKey::u64_desc(0));
		let desc_max = sort_key_to_js(&SortKey::u64_desc(u64::MAX));

		assert!(js_sort_key_bytes(&desc_zero) > js_sort_key_bytes(&desc_max),
			"u64_desc(0) should sort after u64_desc(MAX)");
	}
}
