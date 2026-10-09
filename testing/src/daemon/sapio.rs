//! Real local-development Sapio TEE process. Never connects to an existing service.
//!
//! `SAPIO_TEE_EXEC` must name a binary built with `local-dev`. The upstream service
//! owns fixed loopback ports 8000 and 8367. A cross-process file lock serializes
//! nextest workers; run the test binary in a private network namespace. Its root
//! is ephemeral.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, ensure};
use bitcoin::bip32::Xpub;
use serde::Deserialize;
use tokio::process::Command;

use super::{Daemon, DaemonHelper};
use crate::TestContext;

pub const ENDPOINT: &str = "http://127.0.0.1:8000";

pub type SapioTee = Daemon<SapioTeeHelper>;

pub struct SapioTeeHelper {
	name: String,
	datadir: PathBuf,
	executable: PathBuf,
	root: OnceLock<Xpub>,
	_exclusive_ports: std::fs::File,
}

#[derive(Deserialize)]
struct Identity {
	mode: String,
	xpub: Xpub,
}

impl SapioTee {
	pub async fn launch(ctx: &TestContext) -> Self {
		let executable = PathBuf::from(std::env::var_os("SAPIO_TEE_EXEC")
			.expect("SAPIO_TEE_EXEC must name the real sapio-tee binary built with local-dev"));
		assert!(executable.is_file(), "SAPIO_TEE_EXEC does not name a file");
		let exclusive_ports = tokio::task::spawn_blocking(|| {
			let file = std::fs::OpenOptions::new().read(true).write(true).create(true)
				.truncate(false).open(std::env::temp_dir().join("sapio-tee-integration.lock"))
				.expect("open Sapio fixture port lock");
			file.lock().expect("lock fixed Sapio fixture ports");
			file
		}).await.expect("join Sapio fixture port reservation");
		// Refuse to accidentally use another test's or an operator's service.
		let api = std::net::TcpListener::bind("127.0.0.1:8000")
			.expect("Sapio tests require exclusive port 8000 in a private network namespace");
		let oracle = std::net::TcpListener::bind("127.0.0.1:8367")
			.expect("Sapio tests require exclusive port 8367 in a private network namespace");
		let daemon = Self::wrap(SapioTeeHelper {
			name: "sapio-tee".into(), datadir: ctx.datadir.join("sapio-tee"),
			executable, root: OnceLock::new(), _exclusive_ports: exclusive_ports,
		});
		drop((api, oracle));
		daemon.start().await.expect("start real Sapio TEE");
		daemon
	}

	pub fn public_root(&self) -> Xpub {
		*self.inner.root.get().expect("Sapio TEE initialized")
	}
}

#[async_trait]
impl DaemonHelper for SapioTeeHelper {
	fn name(&self) -> &str { &self.name }
	fn datadir(&self) -> PathBuf { self.datadir.clone() }
	async fn make_reservations(&self) -> anyhow::Result<()> { Ok(()) }
	async fn prepare(&self) -> anyhow::Result<()> {
		tokio::fs::create_dir_all(&self.datadir).await?;
		Ok(())
	}
	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut command = Command::new(&self.executable);
		command.arg("--local-dev");
		Ok(command)
	}
	async fn wait_for_init(&self) -> anyhow::Result<()> {
		let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build()?;
		loop {
			if let Ok(response) = client.get(format!("{ENDPOINT}/public-key")).send().await {
				if response.status().is_success() {
					let identity: Identity = response.json().await.context("Sapio identity")?;
					ensure!(identity.mode == "local-dev", "test fixture is not local-dev");
					self.root.set(identity.xpub).map_err(|_| anyhow!("fixture cannot change root"))?;
					return Ok(());
				}
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}
