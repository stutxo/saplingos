//! Simple file-based storage for testing, built on top of the memory storage adaptor.

use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use tokio::fs;

use crate::persist::adaptor::{Query, QueryRange, Record, RecordUpdate, StorageAdaptor};

use super::memory::MemoryStorageAdaptor;

#[derive(Debug)]
pub struct FileStorageAdaptor {
	file_path: PathBuf,
}

impl FileStorageAdaptor {
	pub async fn open(file_path: impl AsRef<Path>) -> anyhow::Result<Self> {
		let file_path = file_path.as_ref().to_path_buf();

		crate::fs_perms::warn_if_loose(&file_path, 0o600);

		Ok(Self { file_path })
	}

	pub async fn read(&self) -> anyhow::Result<MemoryStorageAdaptor> {
		let data = match fs::read_to_string(&self.file_path).await {
			Ok(contents) => {
				let records = serde_json::from_str::<Vec<Record>>(&contents)?;

				let mut data = MemoryStorageAdaptor::new();
				for record in records {
					data.put(record).await?;
				}
				data
			}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => MemoryStorageAdaptor::new(),
			Err(e) => return Err(e.into()),
		};

		Ok(data)
	}

	/// Serialize read/modify/replace across separately opened adaptors. A busy
	/// writer fails rather than blocking an async executor while holding a lock.
	fn write_lock(&self) -> anyhow::Result<std::fs::File> {
		let mut path = self.file_path.as_os_str().to_owned();
		path.push(".lock");
		let mut options = std::fs::OpenOptions::new();
		options.read(true).write(true).create(true).truncate(false);
		#[cfg(unix)]
		options.mode(0o600);
		let file = options.open(PathBuf::from(path))?;
		file.try_lock()?;
		Ok(file)
	}

	async fn persist(&self, data: &MemoryStorageAdaptor) -> anyhow::Result<()> {
		let records = data.partitions().values()
			.map(|p| p.values())
			.flatten().collect::<Vec<_>>();
		let json = serde_json::to_vec(&records)?;

		let parent = self.file_path.parent()
			.filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
		let name = self.file_path.file_name()
			.ok_or_else(|| anyhow::anyhow!("storage path has no file name"))?.to_string_lossy();
		let nonce = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?.as_nanos();
		for attempt in 0..16 {
			let temp = parent.join(format!(".{name}.{nonce}.{attempt}.tmp"));
			let mut options = std::fs::OpenOptions::new();
			options.write(true).create_new(true);
			#[cfg(unix)]
			options.mode(0o600);
			let mut file = match options.open(&temp) {
				Ok(file) => file,
				Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
				Err(e) => return Err(e.into()),
			};
			let result = (|| -> anyhow::Result<()> {
				file.write_all(&json)?;
				file.sync_all()?;
				std::fs::rename(&temp, &self.file_path)?;
				#[cfg(unix)]
				std::fs::File::open(parent)?.sync_all()?;
				Ok(())
			})();
			if result.is_err() {
				let _ = std::fs::remove_file(&temp);
			}
			return result;
		}
		bail!("unable to create an atomic storage file")
	}
}

#[async_trait]
impl StorageAdaptor for FileStorageAdaptor {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		let _guard = self.write_lock()?;
		let mut data = self.read().await?;
		data.put(record).await?;
		self.persist(&data).await
	}

	async fn put_batch_checked(
		&mut self, updates: Vec<RecordUpdate>, absent: &[(u8, Vec<u8>)],
	) -> anyhow::Result<()> {
		// Keep validation, deletions, and replacements under the same file lock.
		// Only the complete new snapshot can replace the durable file.
		let _guard = self.write_lock()?;
		let mut data = self.read().await?;
		data.put_batch_checked(updates, absent).await?;
		self.persist(&data).await
	}

	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let data = self.read().await?;
		data.get(partition, pk).await
	}

	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		let _guard = self.write_lock()?;
		let mut data = self.read().await?;
		let deleted_record = data.delete(partition, pk).await?;
		self.persist(&data).await?;
		Ok(deleted_record)
	}

	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> {
		let data = self.read().await?;
		data.query_sorted(query).await
	}

	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
		let data = self.read().await?;
		data.get_all(partition).await
	}
}

#[cfg(test)]
mod tests {
	use ark::test_util::VTXO_VECTORS;
	use ark::encode::ProtocolEncoding;

	use super::*;
	use crate::actions::WalletActionCheckpoint;
	use crate::persist::adaptor::test_suite;
	use crate::persist::adaptor::StorageAdaptorWrapper;
	use crate::persist::BarkPersister;
	use crate::persist::test_suite::{
		bark_persister_tests, program_key_fixture, program_recovery_fixture, send_at_start,
	};
	use crate::vtxo::{VtxoLockHolder, VtxoState};

	async fn setup(_test: &str) -> (tempfile::TempDir, StorageAdaptorWrapper<FileStorageAdaptor>) {
		let directory = tempfile::tempdir().unwrap();
		let storage = FileStorageAdaptor::open(directory.path().join("wallet.json")).await.unwrap();
		(directory, StorageAdaptorWrapper::new(storage))
	}

	bark_persister_tests!(setup);

	#[tokio::test]
	async fn program_records_survive_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.json");
		let key = program_key_fixture();
		let recovery = program_recovery_fixture();
		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		db.store_program_key(&key).await.unwrap();
		db.store_program_recoveries(&[recovery.clone()]).await.unwrap();
		drop(db);

		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		assert_eq!(db.get_program_key(&key.program.public_key().unwrap()).await.unwrap(), Some(key.clone()));
		assert_eq!(db.get_public_key_idx(&key.program.public_key().unwrap()).await.unwrap(), Some(key.index));
		assert_eq!(db.get_program_recovery(recovery.controlled_outpoint).await.unwrap(), Some(recovery.clone()));
		assert_eq!(db.list_program_recoveries().await.unwrap(), vec![recovery]);
	}

	#[tokio::test]
	async fn absent_recovery_successor_adoption_survives_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.json");
		let successor = &VTXO_VECTORS.round1_vtxo;
		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		db.reserve_program_recovery(&[(successor.id(), None)], &[]).await.unwrap();
		drop(db);
		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		db.store_vtxos(&[(successor, &VtxoState::Exited)]).await.unwrap();
		drop(db);
		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		db.store_vtxos(&[(successor, &VtxoState::Exited)]).await.unwrap();
		assert_eq!(db.get_full_vtxo(successor.id()).await.unwrap().unwrap().serialize(), successor.serialize());
		assert_eq!(db.get_wallet_vtxo(successor.id()).await.unwrap().unwrap().state, VtxoState::Exited);
		assert!(db.store_vtxos(&[(successor, &VtxoState::Spendable)]).await.is_err());
	}

	#[tokio::test]
	async fn file_adaptor_test_suite() {
		let temp_dir = tempfile::tempdir().unwrap();
		let mut storage = FileStorageAdaptor::open(temp_dir.path().join("test.json")).await.unwrap();
		test_suite::run_all(&mut storage).await;
	}

	#[tokio::test]
	async fn file_batch_delete_conflict_and_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.json");
		let mut storage = FileStorageAdaptor::open(&path).await.unwrap();
		let deleted = Record { partition: 0, pk: vec![1], sort_key: None, data: vec![2] };
		let existing = Record { partition: 1, pk: vec![3], sort_key: None, data: vec![4] };
		let updated = Record { data: vec![5], ..existing.clone() };
		storage.put(deleted.clone()).await.unwrap();
		storage.put(existing.clone()).await.unwrap();
		let before = fs::read(&path).await.unwrap();

		// A separately opened writer makes the pending replacement stale.
		let mut other = FileStorageAdaptor::open(&path).await.unwrap();
		other.put(updated.clone()).await.unwrap();
		let concurrent = fs::read(&path).await.unwrap();
		assert_ne!(before, concurrent);
		assert!(storage.put_batch(vec![
			RecordUpdate { previous: Some(deleted.clone()), updated: None },
			RecordUpdate { previous: Some(existing.clone()), updated: Some(updated.clone()) },
		]).await.is_err());
		assert_eq!(fs::read(&path).await.unwrap(), concurrent);

		storage.put_batch(vec![
			RecordUpdate { previous: Some(deleted.clone()), updated: None },
			RecordUpdate { previous: Some(updated), updated: Some(existing.clone()) },
		]).await.unwrap();
		drop(storage);
		drop(other);
		let reopened = FileStorageAdaptor::open(&path).await.unwrap();
		assert!(reopened.get(deleted.partition, &deleted.pk).await.unwrap().is_none());
		assert_eq!(reopened.get(existing.partition, &existing.pk).await.unwrap(), Some(existing));
	}

	#[tokio::test]
	async fn finish_wallet_action_write_failure_and_retry_survive_reopen() {
		let directory = tempfile::tempdir().unwrap();
		let path = directory.path().join("wallet.json");
		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		let checkpoint: WalletActionCheckpoint = send_at_start().into();
		let id = checkpoint.id();
		let owned = VtxoState::Locked {
			holder: Some(VtxoLockHolder::Action { id: id.clone() }),
		};
		let vtxos = [&VTXO_VECTORS.board_vtxo, &VTXO_VECTORS.round1_vtxo];
		db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.unwrap();
		for vtxo in vtxos {
			db.store_vtxos(&[(vtxo, &owned)]).await.unwrap();
		}
		let key = program_key_fixture();
		let recovery = program_recovery_fixture();
		db.store_program_key(&key).await.unwrap();
		db.store_program_recoveries(&[recovery.clone()]).await.unwrap();
		let before = fs::read(&path).await.unwrap();

		// An independent writer owns the file lock. Completion must not
		// delete the checkpoint or release any lock when its batch fails.
		let writer = db.inner.read().await.write_lock().unwrap();
		assert!(db.finish_wallet_action(&id).await.is_err());
		assert_eq!(fs::read(&path).await.unwrap(), before);
		drop(writer);
		drop(db);

		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		assert!(db.get_wallet_action_checkpoint(&id).await.unwrap().is_some());
		for vtxo in vtxos {
			assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, owned);
		}
		db.finish_wallet_action(&id).await.unwrap();
		drop(db);

		let db = StorageAdaptorWrapper::new(FileStorageAdaptor::open(&path).await.unwrap());
		assert!(db.get_wallet_action_checkpoint(&id).await.unwrap().is_none());
		for vtxo in vtxos {
			assert_eq!(db.get_wallet_vtxo(vtxo.id()).await.unwrap().unwrap().state, VtxoState::Spendable);
			assert_eq!(db.get_full_vtxo(vtxo.id()).await.unwrap().as_ref(), Some(vtxo));
		}
		assert_eq!(db.get_program_key(&key.program.public_key().unwrap()).await.unwrap(), Some(key));
		assert_eq!(db.get_program_recovery(recovery.controlled_outpoint).await.unwrap(), Some(recovery));
		let finished = fs::read(&path).await.unwrap();
		db.finish_wallet_action(&id).await.unwrap();
		assert_eq!(fs::read(&path).await.unwrap(), finished, "retry must not rewrite state history");
	}

	#[cfg(unix)]
	#[tokio::test]
	async fn persisted_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = tempfile::tempdir().unwrap();
		let path = temp_dir.path().join("wallet.json");
		let mut storage = FileStorageAdaptor::open(&path).await.unwrap();

		storage.put(Record {
			partition: 0,
			pk: b"k".to_vec(),
			sort_key: None,
			data: b"v".to_vec(),
		}).await.unwrap();

		let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600, "wallet state file must be owner-only");
	}
}
