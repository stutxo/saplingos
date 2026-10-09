//! Preserve program descriptors and wallet-verified recovery claims without
//! changing existing VTXO key mappings or ordinary wallet records.

use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0043 {}

impl Migration for Migration0043 {
	fn name(&self) -> &str { "Persist program ownership and recovery claims" }

	fn to_version(&self) -> i64 { 43 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute_batch(
			"CREATE TABLE bark_program_key (
				public_key TEXT PRIMARY KEY REFERENCES bark_vtxo_key(public_key),
				descriptor BLOB NOT NULL
			);
			CREATE TABLE bark_program_recovery (
				controlled_outpoint TEXT PRIMARY KEY,
				record BLOB NOT NULL
			);"
		).context("failed to create program ownership tables")?;
		Ok(())
	}
}
