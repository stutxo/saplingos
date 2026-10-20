//! A wallet whose recovery scan ended incomplete must resume it on the next
//! open; that requires a durable flag, since the scan is capped per run.

use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0045 {}

impl Migration for Migration0045 {
	fn name(&self) -> &str { "Add recovery-incomplete flag to properties" }

	fn to_version(&self) -> i64 { 45 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			// Fail safe: wallets created before this flag existed have no
			// record that their recovery scan completed, so the next open
			// scans once and clears the flag on completion.
			"ALTER TABLE bark_properties ADD COLUMN recovery_incomplete INTEGER NOT NULL DEFAULT 1;",
			(),
		).context("failed to add recovery_incomplete column")?;

		Ok(())
	}
}
