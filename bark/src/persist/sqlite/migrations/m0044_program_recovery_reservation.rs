//! Permanent takeover keys are independent of removable actor checkpoints and
//! recovery records, so deleting either cannot restart a recovered actor.

use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0044 {}

impl Migration for Migration0044 {
	fn name(&self) -> &str { "Persist permanent program recovery reservations" }

	fn to_version(&self) -> i64 { 44 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute_batch(
			"CREATE TABLE bark_program_recovery_reservation (
				key TEXT PRIMARY KEY NOT NULL
			);"
		).context("failed to create program recovery reservation table")?;
		Ok(())
	}
}
