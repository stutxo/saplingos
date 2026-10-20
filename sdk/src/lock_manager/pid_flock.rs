//! Named locks for a single-process-per-datadir deployment.
//!
//! # Safety scope
//!
//! Prevents concurrent access by callers within the **current OS
//! process**. Construction additionally **refuses to start a second
//! process** holding the same datadir: an exclusive OS-level lock is
//! acquired on `<datadir>/LOCK` via `std::fs::File::try_lock`
//! (`flock(2)` on Unix, `LockFileEx` on Windows). The OS releases that
//! lock when the process exits, even on SIGKILL or a crash.
//!
//! From that point on, all per-key locking is in-memory: by
//! construction, this is the only process touching `datadir`, so the
//! cross-process semantics of file-based per-key locking would be
//! redundant. The in-memory map is **per manager instance**
//! ([`super::internal_memory::InternalMemoryLockManager`]) — unlike
//! the process-wide [`super::memory::MemoryLockManager`] — so keys of
//! managers guarding unrelated directories never falsely contend.
//!
//! # Platform support
//!
//! Linux, macOS, Android, Windows. Not available on `wasm32`.
//!
//! # When to use
//!
//! - You run a single-process-per-datadir deployment (CLIs, daemons).
//! - You want that constraint expressed as a type rather than as a
//!   separate setup step that callers might forget.

use std::fs::{self, File, TryLockError};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;

use super::{LockGuard, LockManager, PidLockError};
use super::internal_memory::InternalMemoryLockManager;

/// File name used for the datadir-level PID lock.
pub const LOCK_FILE: &str = "LOCK";

fn open_lock_file(path: &Path) -> anyhow::Result<File> {
	let mut options = File::options();
	options.read(true).write(true).create(true).truncate(false);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		// Never follow a symlink planted where the lock belongs: the holder
		// truncates and writes this file.
		options.custom_flags(libc::O_NOFOLLOW);
	}
	let file = options.open(path)
		.with_context(|| format!("failed to open lock file {}", path.display()))?;
	let metadata = file.metadata()
		.with_context(|| format!("failed to inspect lock file {}", path.display()))?;
	anyhow::ensure!(metadata.is_file(),
		"lock path {} is not a regular file", path.display());
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		anyhow::ensure!(metadata.nlink() == 1,
			"lock path {} has multiple hard links", path.display());
	}
	Ok(file)
}

/// Reject a caller-chosen lock file name that is not a single normal path
/// component (absolute paths and `..` would escape the datadir).
fn validate_lock_file(lock_file: &str) -> anyhow::Result<()> {
	use std::path::Component;
	let mut components = Path::new(lock_file).components();
	anyhow::ensure!(
		matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none(),
		"invalid lock file name {lock_file:?}: expected a single path component",
	);
	Ok(())
}


pub struct FlockPidLockManager {
	// Holds the OS lock for the lifetime of the manager. Dropped on
	// drop of the manager — at which point the OS releases the lock.
	_pid_file: File,
	datadir: PathBuf,
	in_process: InternalMemoryLockManager,
}

impl FlockPidLockManager {
	/// Take the pid lock on `datadir` and construct a manager. Fails
	/// with [`PidLockError::AlreadyHeld`] if another process already
	/// holds the lock, or [`PidLockError::SetupFailed`] for any other
	/// I/O failure.
	pub fn new(datadir: impl Into<PathBuf>) -> Result<Self, PidLockError> {
		Self::new_with_lock_file(datadir, LOCK_FILE)
	}

	/// Like [`new`](Self::new), but locking a caller-chosen file name
	pub fn new_with_lock_file(
		datadir: impl Into<PathBuf>,
		lock_file: &str,
	) -> Result<Self, PidLockError> {
		let datadir = datadir.into();
		let setup = |source: anyhow::Error| PidLockError::SetupFailed {
			datadir: datadir.clone(),
			source,
		};
		validate_lock_file(lock_file).map_err(&setup)?;

		fs::create_dir_all(&datadir)
			.with_context(|| format!("failed to create datadir {}", datadir.display()))
			.map_err(setup)?;

		let path = datadir.join(lock_file);
		let mut file = open_lock_file(&path).map_err(setup)?;

		match file.try_lock() {
			Ok(()) => {}
			Err(TryLockError::WouldBlock) => {
				let mut holder = String::new();
				// The file is attacker-influenced; bound the diagnostic read.
				let _ = (&file).take(64).read_to_string(&mut holder);
				let pid = holder.trim().parse::<u32>().ok();
				return Err(PidLockError::AlreadyHeld { datadir, pid });
			}
			Err(TryLockError::Error(e)) => {
				return Err(setup(anyhow::Error::from(e)
					.context(format!("failed to acquire pid lock at {}", path.display()))));
			}
		}

		// Stamp the holder PID for diagnostics. Truncate first to drop
		// any stale content left by a previous holder.
		file.set_len(0).context("failed to truncate pid lock").map_err(setup)?;
		write!(file, "{}", std::process::id())
			.context("failed to write pid lock").map_err(&setup)?;
		file.flush().context("failed to flush pid lock").map_err(setup)?;

		Ok(Self {
			_pid_file: file,
			datadir,
			in_process: InternalMemoryLockManager::new(),
		})
	}

	pub fn datadir(&self) -> &Path {
		&self.datadir
	}
}

impl std::fmt::Debug for FlockPidLockManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("FlockPidLockManager").field("datadir", &self.datadir).finish()
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl LockManager for FlockPidLockManager {
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>> {
		self.in_process.try_lock(key).await
	}

	async fn lock(
		&self,
		key: &str,
		timeout: std::time::Duration,
	) -> anyhow::Result<Box<dyn LockGuard>> {
		self.in_process.lock(key, timeout).await
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn tmp_dir() -> PathBuf {
		let dir = std::env::temp_dir()
			.join(format!("bark-pid-lockmgr-{}", std::process::id()))
			.join(format!("{}", std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[tokio::test]
	async fn acquire_writes_holder_pid() {
		let dir = tmp_dir();
		let mgr = FlockPidLockManager::new(&dir).unwrap();
		let contents = fs::read_to_string(dir.join(LOCK_FILE)).unwrap();
		assert_eq!(contents, std::process::id().to_string());
		drop(mgr);
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn second_acquire_in_same_process_is_refused() {
		let dir = tmp_dir();
		let _held = FlockPidLockManager::new(&dir).unwrap();
		let err = FlockPidLockManager::new(&dir).unwrap_err();
		assert!(
			err.to_string().contains("another process is already using datadir"),
			"unexpected error: {}", err,
		);
		drop(_held);
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn distinct_lock_files_dont_conflict() {
		let dir = tmp_dir();
		let _default = FlockPidLockManager::new(&dir).unwrap();
		let _custom = FlockPidLockManager::new_with_lock_file(&dir, "other.lock").unwrap();
		let err = FlockPidLockManager::new_with_lock_file(&dir, "other.lock").unwrap_err();
		assert!(matches!(err, PidLockError::AlreadyHeld { .. }));
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn reacquire_after_drop_succeeds() {
		let dir = tmp_dir();
		let first = FlockPidLockManager::new(&dir).unwrap();
		drop(first);
		let _second = FlockPidLockManager::new(&dir).unwrap();
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn per_key_locking_works_in_process() {
		let dir = tmp_dir();
		let mgr = FlockPidLockManager::new(&dir).unwrap();

		let g = mgr.try_lock("foo").await;
		assert!(g.is_some());

		let busy = mgr.try_lock("foo").await;
		assert!(busy.is_none(), "same key should be blocked");

		let g2 = mgr.try_lock("bar").await;
		assert!(g2.is_some(), "different key should be free");

		let _ = fs::remove_dir_all(&dir);
	}

	/// Regression test for the per-key locking flake. The in-process
	/// map was once the process-wide [`MemoryLockManager`] shared
	/// static, so this test and its `pid_fcntl` twin — running
	/// concurrently in the same test process with the same keys —
	/// spuriously blocked each other (`g.is_some()` failed
	/// intermittently under parallel load). With a per-instance map,
	/// two managers can hold the same key without contending.
	#[tokio::test]
	async fn managers_for_distinct_datadirs_dont_contend() {
		let dir_a = tmp_dir();
		let dir_b = tmp_dir();
		let mgr_a = FlockPidLockManager::new(&dir_a).unwrap();
		let mgr_b = FlockPidLockManager::new(&dir_b).unwrap();

		let ga = mgr_a.try_lock("foo").await;
		assert!(ga.is_some());
		let gb = mgr_b.try_lock("foo").await;
		assert!(gb.is_some(), "unrelated datadirs must not share keys");

		let _ = fs::remove_dir_all(&dir_a);
		let _ = fs::remove_dir_all(&dir_b);
	}

	#[cfg(unix)]
	#[test]
	fn symlinked_lock_file_is_refused() {
		use std::os::unix::fs::symlink;

		let dir = tmp_dir();
		fs::create_dir_all(&dir).unwrap();
		let victim = dir.join("victim");
		fs::write(&victim, b"do not touch").unwrap();
		symlink(&victim, dir.join(LOCK_FILE)).unwrap();

		let err = FlockPidLockManager::new(&dir).unwrap_err();
		assert!(matches!(err, PidLockError::SetupFailed { .. }), "{err:?}");
		assert_eq!(fs::read(&victim).unwrap(), b"do not touch");

		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn lock_file_name_must_be_a_single_component() {
		let dir = tmp_dir();
		for bad in ["../escape", "/tmp/escape", "a/b", "."] {
			let err = FlockPidLockManager::new_with_lock_file(&dir, bad).unwrap_err();
			assert!(matches!(err, PidLockError::SetupFailed { .. }), "{bad}: {err:?}");
		}
		let _ = fs::remove_dir_all(&dir);
	}
}
