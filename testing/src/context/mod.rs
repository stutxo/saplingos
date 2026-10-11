//! SDK wallet construction over the pinned upstream service fixtures.

use std::collections::HashSet;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bitcoin::{Amount, FeeRate};
use bitcoin_ext::BlockDelta;
use futures::StreamExt;
use sapling::{WalletNetwork, OpenWalletArgs, WalletSeed};
use sapling::movement::{MovementId, MovementStatus};
use sapling::onchain::{OnchainWallet, OnchainWalletTrait};
use sapling::persist::{WalletPersister, sqlite::SqliteClient};
use tokio::fs;

pub use ark_testing::context::ToArkUrl;
use ark_testing::Bitcoind;
use crate::constants::{self, BOARD_CONFIRMATIONS};
use crate::util::FutureExt;

const BOARD_ONCHAIN_FEE_BUFFER: Amount = Amount::from_sat(100_000);

/// Service lifecycle stays upstream; wallets always use this repository's SDK.
pub struct TestContext(ark_testing::TestContext);

impl Deref for TestContext {
	type Target = ark_testing::TestContext;
	fn deref(&self) -> &Self::Target { &self.0 }
}

impl TestContext {
	pub async fn new(name: impl AsRef<str>) -> Self {
		Self(ark_testing::TestContext::new(name).await)
	}

	pub fn sdk<'a>(&'a self, name: impl AsRef<str>, srv: &'a dyn ToArkUrl) -> SdkBuilder<'a> {
		SdkBuilder::new(self, name, srv)
	}

	pub fn sdk_default_cfg(
		&self,
		srv: &dyn ToArkUrl,
		bitcoind: Option<&Bitcoind>,
	) -> sapling::Config {
		#[allow(deprecated)]
		sapling::Config {
			server_address: srv.ark_url(),
			server_access_token: None,
			user_agent: None,
			esplora_address: if bitcoind.is_none() {
				Some(self.electrs.as_ref().expect("need either bitcoind or electrs").rest_url())
			} else {
				None
			},
			bitcoind_address: bitcoind.map(|b| b.rpc_url()),
			bitcoind_cookiefile: bitcoind.map(|b| b.rpc_cookie()),
			bitcoind_user: None,
			bitcoind_pass: None,
			bitcoind_zmq_address: bitcoind.map(|b| b.zmq_url()),
			socks5_proxy: None,
			sapio: None,
			sapio_witnesses: Default::default(),

			vtxo_refresh_expiry_threshold: BlockDelta::new(24),
			vtxo_exit_margin: BlockDelta::new(12),
			htlc_recv_claim_delta: BlockDelta::new(18),
			lightning_receive_claim_retries: 5,
			fallback_fee_rate: Some(FeeRate::from_sat_per_vb_u32(5)),
			round_tx_required_confirmations: constants::ROUND_CONFIRMATIONS.try_into().unwrap(),
			offboard_required_confirmations: constants::OFFBOARD_CONFIRMATIONS.try_into().unwrap(),
			offboard_lost_tx_grace_period_secs: 3600,
			daemon_sync_interval_secs: 3,
			daemon_manual_sync: false,
			change_vtxo_split_factor: 2,
			vtxo_key_gap_limit: sapling::DEFAULT_VTXO_KEY_GAP_LIMIT,
		}
	}
}

/// Creates and funds an in-process Sapling wallet with a persisted seed and database.
pub struct SdkBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	srv: &'a dyn ToArkUrl,
	fund_amount: Option<Amount>,
	board_amounts: Vec<Amount>,
	mod_cfg: Option<Box<dyn FnOnce(&mut sapling::Config)>>,
	mnemonic: Option<bip39::Mnemonic>,
}

impl<'a> SdkBuilder<'a> {
	fn new(
		ctx: &'a TestContext,
		name: impl AsRef<str>,
		srv: &'a dyn ToArkUrl,
	) -> Self {
		SdkBuilder {
			ctx,
			name: name.as_ref().to_string(),
			srv,
			fund_amount: None,
			board_amounts: Vec::new(),
			mod_cfg: None,
			mnemonic: None,
		}
	}

	/// Use the given BIP-39 mnemonic instead of generating a fresh one.
	/// Lets a test recover into a new wallet from another wallet's seed.
	pub fn mnemonic(mut self, mnemonic: bip39::Mnemonic) -> Self {
		self.mnemonic = Some(mnemonic);
		self
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut sapling::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	/// Send `amount` to a fresh onchain address of the wallet before
	/// returning it. If unset and [`Self::boarded`] is set, enough
	/// onchain funds are sent automatically to cover all boards plus
	/// fees.
	pub fn funded(mut self, amount: Amount) -> Self {
		self.fund_amount = Some(amount);
		self
	}

	/// Board `amount` from the onchain wallet into Ark, wait for the
	/// configured number of board confirmations, and sync the wallet so
	/// the resulting VTXO is registered with the Ark server.
	///
	/// May be called multiple times to produce multiple distinct VTXOs;
	/// each call appends a separate board.
	pub fn boarded(mut self, amount: Amount) -> Self {
		self.board_amounts.push(amount);
		self
	}

	pub async fn create(self) -> sapling::Wallet {
		self.try_create().await.unwrap()
	}

	pub async fn try_create(self) -> anyhow::Result<sapling::Wallet> {
		let bitcoind = if self.ctx.electrs.is_some() {
			None
		} else {
			Some(self.ctx.bitcoind_arc())
		};

		let mut cfg = self.ctx.sdk_default_cfg(self.srv, bitcoind.as_deref());
		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		let datadir = self.ctx.datadir.join(&self.name);
		fs::create_dir_all(&datadir).await
			.with_context(|| format!("creating sapling-sdk datadir at {}", datadir.display()))?;

		let network = WalletNetwork::Regtest.as_bitcoin();
		let mnemonic = if let Some(m) = self.mnemonic {
			m
		} else {
			bip39::Mnemonic::generate(12).context("mnemonic")?
		};
		fs::write(datadir.join("mnemonic"), mnemonic.to_string()).await
			.context("writing mnemonic file")?;
		fs::write(
			datadir.join("config.toml"),
			toml::to_string_pretty(&cfg).unwrap(),
		).await.context("writing config.toml")?;

		let db: Arc<dyn WalletPersister> = Arc::new(
			SqliteClient::open(datadir.join("db.sqlite")).context("opening sqlite db")?,
		);

		let onchain = Arc::new(tokio::sync::RwLock::new(OnchainWallet::load_or_create(
			network, mnemonic.to_seed(""), db.clone(),
		).await.context("creating onchain wallet")?));

		let seed = WalletSeed::new_from_mnemonic(network, &mnemonic);
		let wallet = sapling::Wallet::open(network, seed, cfg, OpenWalletArgs {
			datadir: Some(datadir),
			persister: Some(db),
			create_if_not_exists: true,
			onchain: Some(onchain.clone()),
			..Default::default()
		}).await.context("creating Sapling wallet")?;

		let fund_amount = self.fund_amount.or_else(|| {
			if self.board_amounts.is_empty() {
				None
			} else {
				Some(self.board_amounts.iter().copied().sum::<Amount>() + BOARD_ONCHAIN_FEE_BUFFER)
			}
		});
		if let Some(amount) = fund_amount {
			let mut onchain = onchain.write().await;
			let address = onchain.address().await.context("onchain address")?;
			self.ctx.bitcoind().fund_addr(address, amount).await;
			self.ctx.bitcoind().generate(1).await;
			self.ctx.await_block_count_sync().await;
			onchain.sync(wallet.chain()).await.context("onchain sync after funding")?;
		}

		if !self.board_amounts.is_empty() {
			// Subscribe before issuing so we can watch each board's terminal
			// transition. Match on the specific `movement_id` each board
			// returned so we don't count an unrelated Board movement's
			// notification as one of ours.
			let mut movements = wallet.subscribe_notifications().movements();

			let mut pending: HashSet<MovementId> = HashSet::new();
			for amount in &self.board_amounts {
				let b = wallet.board_amount(*amount).await.context("board_amount")?;
				self.ctx.await_transaction(b.funding_tx.compute_txid()).await;
				pending.insert(b.movement_id);
			}
			self.ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

			wallet.sync().await;

			// One deadline for the whole wait — a per-`next()` timeout would
			// be reset by unrelated movements and never fire.
			let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
			while !pending.is_empty() {
				let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
				let m = movements.next()
					.try_wait(remaining).await
					.context("boards did not all complete before deadline")?
					.context("wallet notification stream ended before all boards completed")?;
				if !pending.contains(&m.id) {
					continue;
				}
				match m.status {
					MovementStatus::Pending => continue,
					MovementStatus::Successful => { pending.remove(&m.id); },
					other => bail!("board movement {} entered terminal status {:?}", m.id, other),
				}
			}
		}

		Ok(wallet)
	}
}
