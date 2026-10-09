//! Configure generic programs with `bark create --sapio-config FILE` and the usual
//! chain/server flags. FILE is a JSON `bark::sapio::SapioConfig`: `endpoint`, an
//! explicitly attestation-pinned `root` xpub, `program`, `recovery`, and optional
//! `coordinator_url` / `receive_bind`. `program` contains the evaluator SHA256 hex
//! string and the exact `program` / `parameters` byte arrays. `recovery` contains
//! consensus-encoded TxOut hex strings in `outputs`, an optional zero-based
//! `remainder_output`, the consensus `lock_time`, and a `witness` byte array.
//! These are construction inputs, not an exemption from program authorization.
//! Existing wallets use the corresponding `[sapio]` tables in config.toml.
//!
//! Save recovery with `bark sapio recovery-export --all --output recovery.json`,
//! or select positions with repeated `--outpoint TXID:VOUT`. Keep the file private
//! and back it up separately from the seed phrase. Export does not reserve VTXOs.
//! Run `bark sapio recover --all` to reserve local positions and advance recovery.
//! Alternatively, `bark sapio recover --bundle recovery.json` uses only the saved
//! transactions and this datadir's ordinary on-chain fee wallet. Stop all other
//! spending of imported positions first; another wallet's state cannot be locked.
//! Neither path starts maintenance or contacts the Ark server or the enclave.
//! Fund the ordinary on-chain wallet for fees and repeat recovery after each block.
//! Claims retain their exact signed outputs, which need not belong to this wallet.

use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::{FeeRate, OutPoint};
use bitcoin_ext::FeeRateExt;
use serde::Serialize;

use bark::fs_perms;
use bark::sapio::recovery::{
	ProgramRecoveryBundle, ProgramRecoveryReadiness, recover_program_bundle,
};
use bark_cli::util::output_json;
use bark_cli::wallet::{open_wallet_for_recovery, read_bounded_json};

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;

#[derive(clap::Args)]
#[group(multiple = false)]
pub struct Selection {
	/// Select a saved controlled outpoint. Repeat for multiple positions.
	#[arg(long = "outpoint", value_name = "TXID:VOUT")]
	outpoints: Vec<OutPoint>,
	/// Select all recoverable live positions, including saved crash-gap outputs.
	#[arg(long)]
	all: bool,
}

impl Selection {
	fn validate(&self) -> anyhow::Result<()> {
		ensure!(self.all != !self.outpoints.is_empty(), "provide --all or --outpoint");
		Ok(())
	}
}

#[derive(clap::Subcommand)]
pub enum SapioCommand {
	/// Export verified complete or conditional recovery with its exact signed bytes.
	RecoveryExport {
		#[command(flatten)]
		selection: Selection,
		/// Write a private JSON bundle here. Existing files are replaced atomically.
		#[arg(long, value_name = "FILE")]
		output: PathBuf,
	},
	/// Advance recovery once using Bitcoin and an ordinary on-chain fee wallet only.
	Recover {
		#[command(flatten)]
		selection: Selection,
		/// Import a JSON bundle (maximum 16 MiB) instead of using this wallet's positions.
		/// Stop concurrent Ark spending of the imported positions before recovery.
		#[arg(long, value_name = "FILE", conflicts_with_all = ["outpoints", "all"])]
		bundle: Option<PathBuf>,
		/// Feerate in sats/kvB. Defaults to the chain source's fast estimate.
		#[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
		fee_rate: Option<u64>,
	},
}

#[derive(Serialize)]
struct ExportPosition {
	controlled_outpoint: OutPoint,
	readiness: ProgramRecoveryReadiness,
}

#[derive(Serialize)]
struct ExportResult {
	output: PathBuf,
	positions: Vec<ExportPosition>,
}

fn export_positions(bundle: &mut ProgramRecoveryBundle, all: bool) -> anyhow::Result<Vec<ExportPosition>> {
	bundle.verify()?;
	let mut positions = Vec::with_capacity(bundle.targets.len());
	for &point in &bundle.targets {
		let readiness = bundle.readiness(point)?;
		if readiness == ProgramRecoveryReadiness::Prepared {
			ensure!(all, "recovery for {} still lacks signed ancestors", point);
			continue;
		}
		positions.push(ExportPosition { controlled_outpoint: point, readiness });
	}
	ensure!(!positions.is_empty(), "no complete or conditional recovery positions found");
	bundle.targets = positions.iter().map(|position| position.controlled_outpoint).collect();
	Ok(positions)
}

pub async fn execute(cmd: SapioCommand, datadir: &Path, user_agent: &str) -> anyhow::Result<()> {
	// Parse and verify imported bytes before opening a wallet or making a chain request.
	let imported: Option<ProgramRecoveryBundle> = match &cmd {
		SapioCommand::Recover { bundle: Some(path), .. } => {
			let bundle: ProgramRecoveryBundle = read_bounded_json(path, MAX_BUNDLE_BYTES)?;
			bundle.verify().context("invalid recovery bundle")?;
			ensure!(!bundle.targets.is_empty(), "recovery bundle has no selected positions");
			Some(bundle)
		},
		SapioCommand::Recover { selection, .. } | SapioCommand::RecoveryExport { selection, .. } => {
			selection.validate()?;
			None
		},
	};
	let wallet = open_wallet_for_recovery(datadir, user_agent).await
		.context("error opening recovery wallet")?.context("No wallet found")?;

	match cmd {
		SapioCommand::RecoveryExport { selection, output } => {
			let mut bundle = wallet.program_recovery_bundle(&selection.outpoints).await?;
			let positions = export_positions(&mut bundle, selection.all)?;
			let bytes = serde_json::to_vec_pretty(&bundle).context("failed to encode recovery bundle")?;
			ensure!(bytes.len() <= MAX_BUNDLE_BYTES,
				"bundle exceeds 16 MiB; export smaller selections with --outpoint");
			fs_perms::write_atomic_owner_only(&output, &bytes)
				.with_context(|| format!("failed to save recovery to {}", output.display()))?;
			output_json(&ExportResult { output, positions });
		},
		SapioCommand::Recover { selection, fee_rate, .. } => {
			if let Some(bundle) = &imported {
				ensure!(bundle.network == wallet.network().await?, "recovery bundle network mismatch");
			}
			// Do not call wallet.sync(): it includes Ark synchronization and maintenance.
			let onchain = wallet.onchain().context("recovery requires an ordinary on-chain fee wallet")?;
			onchain.write().await.sync(wallet.chain()).await.context("failed to sync the fee wallet")?;
			let fee_rate = fee_rate.map(FeeRate::from_sat_per_kvb_ceil);
			let progress = if let Some(bundle) = &imported {
				let rate = match fee_rate {
					Some(rate) => rate,
					None => wallet.chain().fee_rates().await.fast,
				};
				recover_program_bundle(bundle, wallet.chain(), &mut *onchain.write().await, rate).await?
			} else {
				wallet.recover_program_vtxos(&selection.outpoints, fee_rate).await?
			};
			output_json(&progress);
		},
	}
	Ok(())
}
