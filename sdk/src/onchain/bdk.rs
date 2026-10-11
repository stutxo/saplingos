use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::Context;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::chain::{Anchor, ChainPosition, CheckPoint};
use bdk_wallet::Wallet as BdkWallet;
use bdk_wallet::coin_selection::DefaultCoinSelectionAlgorithm;
use bdk_wallet::{Balance, KeychainKind, LocalOutput, TxBuilder, TxOrdering};
use bitcoin::{
	Address, Amount, FeeRate, Network, OutPoint, Psbt, Script, Sequence, Transaction, TxOut,
	Txid, Weight, bip32, psbt,
};
use log::{debug, error, info, trace, warn};

use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockDelta, BlockHeight, DEEPLY_CONFIRMED};
use bitcoin_ext::bdk::{CpfpInternalError, WalletExt};
use bitcoin_ext::cpfp::CpfpError;

use crate::Wallet;
use crate::actions::board::{Progress as BoardProgress, psbt_is_finalized};
use crate::chain::{ChainSource, ChainSourceClient};
use crate::exit::{ExitVtxo, ExitState};
use crate::onchain::{LocalUtxo, MakeCpfpFees, Utxo, OnchainWalletTrait, WalletTxInfo};
use crate::persist::WalletPersister;
use crate::psbtext::PsbtInputExt;

const STOP_GAP: usize = 50;
const PARALLEL_REQS: usize = 4;
const GENESIS_HEIGHT: BlockHeight = BlockHeight::ZERO;
/// Minimum age (by `last_seen`) a locally-unconfirmed tx must reach before a
/// sync is allowed to evict it for being absent from the node's mempool.
///
/// A tx is marked seen (`apply_unconfirmed_txs`) as soon as it's signed, not
/// once it's actually reached the node: e.g. a board's funding tx is applied
/// locally in `finish_psbt` after durable recovery preparation and before its
/// action broadcasts it. Without this grace period, a sync landing in that gap
/// would see the tx as absent from the node's mempool and evict it, handing
/// its inputs back to the next coin selection while the "evicted" tx is still
/// in flight and about to land in the mempool anyway -- a self-inflicted
/// double-spend. A tx that's genuinely gone just gets evicted one sync later.
const ONCHAIN_EVICTION_GRACE_SECS: u64 = 30;

impl From<LocalOutput> for LocalUtxo {
	fn from(value: LocalOutput) -> Self {
		LocalUtxo {
			outpoint: value.outpoint,
			amount: value.txout.value,
			confirmation_height: value.chain_position.confirmation_height_upper_bound()
				.map(BlockHeight::new),
		}
	}
}

/// Trait extension for TxBuilder to add exit outputs
///
/// When used, the resulting PSBT should be signed using
/// [crate::exit::Exit::sign_exit_claim_inputs].
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TxBuilderExt: Send + Sync {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<Cs: Send + Sync> TxBuilderExt for TxBuilder<'_, Cs> {
	async fn add_exit_claim_inputs(
		&mut self,
		wallet: &Wallet,
		exit_outputs: &[&ExitVtxo],
	) -> anyhow::Result<()> {
		self.version(2);

		for input in exit_outputs {
			if !matches!(input.state(), ExitState::Claimable(..)) {
				bail!("VTXO exit is not spendable");
			}

			// Claiming an exit needs the full vtxo: the PSBT input embeds the
			// serialized full bytes (including the genesis chain) so the
			// claim signer can reconstruct the spend.
			let vtxo = wallet.inner.db.get_full_vtxo(input.id()).await?
				.context(format!("Unable to load VTXO for exit: {}", input.id()))?;
			ensure!(wallet.inner.db.get_program_key(&vtxo.user_pubkey()).await?.is_none(),
				"program recovery cannot be added to a dynamic fee transaction; use Wallet::recover_program_vtxos");
			let mut psbt_in = psbt::Input::default();
			psbt_in.set_exit_claim_input(&vtxo);
			psbt_in.witness_utxo = Some(TxOut {
				script_pubkey: vtxo.output_script_pubkey(),
				value: vtxo.amount(),
			});

			let clause = wallet.find_signable_clause(&vtxo).await
				.context("Cannot sign vtxo")?;

			let witness_weight = {
				let witness_size = clause.witness_size(&vtxo);
				Weight::from_witness_data_size(witness_size as u64)
			};

			self.add_foreign_utxo_with_sequence(
				vtxo.point(),
				psbt_in,
				witness_weight,
				clause.sequence().unwrap_or(Sequence::ZERO),
			).expect("error adding foreign utxo for claim input");
		}

		Ok(())
	}
}

/// Map the internal BDK CPFP error onto the public [CpfpError] surface.
fn cpfp_internal_to_error(e: CpfpInternalError) -> CpfpError {
	match e {
		CpfpInternalError::General(s) => CpfpError::InternalError(s),
		CpfpInternalError::Create(e) => CpfpError::CreateError(e.to_string()),
		CpfpInternalError::Extract(e) => CpfpError::FinalizeError(e.to_string()),
		CpfpInternalError::Fee() => CpfpError::InternalError(CpfpInternalError::Fee().to_string()),
		CpfpInternalError::FinalizeError(s) => CpfpError::FinalizeError(s),
		CpfpInternalError::InsufficientConfirmedFunds(f) => {
			CpfpError::InsufficientConfirmedFunds {
				needed: f.needed, available: f.available,
			}
		},
		CpfpInternalError::NoFeeAnchor(txid) => CpfpError::NoFeeAnchor(txid),
		CpfpInternalError::Signer(e) => CpfpError::SigningError(e.to_string()),
	}
}

/// A basic wrapper around the bdk wallet to showcase
/// how to use bark with an external onchain wallet.
///
/// Note: BDK wallet already implements all the traits
/// to be used as an onboard and exit wallet, so that
/// wrapper only needs to proxy the methods.
pub struct OnchainWallet {
	pub inner: BdkWallet,
	db: Arc<dyn WalletPersister>,
}

impl Deref for OnchainWallet {
	type Target = BdkWallet;

	fn deref(&self) -> &Self::Target {
		&self.inner
	}
}

impl DerefMut for OnchainWallet {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.inner
	}
}

impl OnchainWallet {
	pub async fn load_or_create(network: Network, seed: [u8; 64], db: Arc<dyn WalletPersister>) -> anyhow::Result<Self> {
		let xpriv = bip32::Xpriv::new_master(network, &seed).expect("valid seed");
		let desc = bdk_wallet::template::Bip86(xpriv, KeychainKind::External);

		let changeset = db.initialize_bdk_wallet().await.context("error reading bdk wallet state")?;
		let wallet_opt = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet_no_persist(changeset)?;

		let wallet = match wallet_opt {
			Some(wallet) => wallet,
			None => bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()?,
		};

		Ok(Self { inner: wallet, db })
	}

	/// Coin selection must distinguish signed funding from a published parent.
	/// The checkpoint also reserves signed inputs if BDK evicts the transaction.
	/// An unsigned checkpoint alone does not consume the original safe coins.
	async fn unavailable_board_funding(&self) -> anyhow::Result<Vec<OutPoint>> {
		let mut unavailable = Vec::new();
		for checkpoint in self.db.get_all_wallet_action_checkpoints().await? {
			let Some(board) = checkpoint.into_board() else { continue };
			let funding = board.funding()?;
			let txid = funding.compute_txid();
			if !matches!(board.progress, BoardProgress::Confirming { .. }) {
				unavailable.extend(funding.output.iter().enumerate()
					.map(|(vout, _)| OutPoint::new(txid, vout as u32)));
			}
			// Signing may have reached BDK's durable graph before the signed
			// checkpoint was saved. Use the graph, not only canonical txs, so
			// an eviction cannot free those committed inputs for another send.
			if board.funding_tx.is_some()
				|| board.funding_psbt.as_ref().is_some_and(psbt_is_finalized)
				|| self.inner.tx_graph().get_tx(txid).is_some()
			{
				unavailable.extend(funding.input.iter().map(|input| input.previous_output));
			}
		}
		Ok(unavailable)
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl OnchainWalletTrait for OnchainWallet {
	async fn balance(&self) -> Amount {
		self.inner.balance().total()
	}

	async fn address(&mut self) -> anyhow::Result<Address> {
		let ret = self.inner.reveal_next_address(bdk_wallet::KeychainKind::External).address;
		self.persist().await?;
		Ok(ret)
	}

	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		OnchainWallet::sync(self, chain).await
	}

	async fn is_mine(&self, spk: &Script) -> anyhow::Result<bool> {
		Ok(self.inner.is_mine(spk.to_owned()))
	}

	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	async fn evict_tx(&mut self, txid: Txid) -> anyhow::Result<()> {
		self.inner.apply_evicted_txs([(txid, bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	async fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let unavailable = self.unavailable_board_funding().await?;
		let mut b = self.inner.build_tx();
		b.unspendable(unavailable);
		b.ordering(TxOrdering::Untouched);
		for (dest, amount) in destinations {
			b.add_recipient(dest.script_pubkey(), *amount);
		}
		b.fee_rate(fee_rate);
		b.finish().context("error building tx")
	}

	async fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt> {
		let unavailable = self.unavailable_board_funding().await?;
		let mut b = self.inner.build_tx();
		b.unspendable(unavailable);
		b.drain_to(destination.script_pubkey());
		b.fee_rate(fee_rate);
		b.drain_wallet();
		b.finish().context("error building tx")
	}

	async fn finish_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		// An unsigned board checkpoint may resume after the selection lock was
		// lost in a crash. Never sign it over a newer locally signed spend, even
		// when that spend has not reached the chain yet. Replaying this exact
		// transaction after signing succeeded but checkpointing failed is safe.
		let txid = psbt.unsigned_tx.compute_txid();
		for input in &psbt.unsigned_tx.input {
			for spend in self.inner.tx_graph().outspends(input.previous_output) {
				ensure!(*spend == txid || self.inner.get_tx(*spend).is_none(),
					"funding input {} is already spent by wallet transaction {}",
					input.previous_output, spend);
			}
		}
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign(&mut psbt, opts).context("signing error")?;
		ensure!(finalized, "failed to succesfully sign the tx");
		let tx = psbt.clone().extract_tx()?;
		self.inner.apply_unconfirmed_txs([(tx, bark_runtime::timestamp_secs())]);
		self.persist().await?;
		Ok(psbt)
	}

	async fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError> {
		WalletExt::make_signed_p2a_cpfp(&mut self.inner, tx, fees)
			.inspect_err(|e| error!("Error creating signed P2A CPFP: {}", e))
			.map_err(cpfp_internal_to_error)
	}

	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError> {
		self.inner.apply_unconfirmed_txs([(tx.clone(), bark_runtime::timestamp_secs())]);
		trace!("Unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.persist().await
			.map_err(|e| CpfpError::StoreError(e.to_string()))
	}
}

impl OnchainWallet {
	pub async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()> {
		debug!("Starting wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());
		trace!("Starting unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { sync, .. } => {
				let prev_tip = self.inner.latest_checkpoint();
				self.inner_sync_bitcoind(sync, prev_tip).await?;
			},
			ChainSourceClient::Esplora(client) => {
				debug!("Syncing with esplora...");

				// Don't sync the entire transaction history of the wallet. We can safely filter out
				// anything deeply confirmed.
				let min_height = self.inner.latest_checkpoint()
					.height()
					.checked_sub(DEEPLY_CONFIRMED.to_u32())
					.unwrap_or(0);

				let request = self.inner.start_sync_with_revealed_spks_at(bark_runtime::timestamp_secs())
					.outpoints(self.list_unspent().iter().map(|o| o.outpoint))
					.txids(self.inner.transactions().filter_map(|tx| {
						let fresh = match tx.chain_position {
							ChainPosition::Unconfirmed { .. } => true,
							ChainPosition::Confirmed { anchor, .. } => {
								anchor.anchor_block().height >= min_height
							},
						};
						if fresh {
							Some(tx.tx_node.txid)
						} else {
							None
						}
					}));

				let mut update = client.sync(request, PARALLEL_REQS).await?;

				// Esplora's indexer runs behind the mempool: a tx broadcast
				// moments ago can still be absent from its response and BDK
				// will report it as evicted. Drop such evictions here so we
				// don't hand a freshly-spent UTXO back to coin selection
				// before the tx actually confirms; see ONCHAIN_EVICTION_GRACE_SECS.
				let now = bark_runtime::timestamp_secs();
				let recently_seen: HashSet<Txid> = self.inner.transactions()
					.filter_map(|tx| match tx.chain_position {
						ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
							if now.saturating_sub(seen) < ONCHAIN_EVICTION_GRACE_SECS => {
							Some(tx.tx_node.txid)
						},
						_ => None,
					})
					.collect();
				update.tx_update.evicted_ats.retain(|(txid, _)| {
					if recently_seen.contains(txid) {
						debug!("Not evicting recently-seen tx {} still within grace period", txid);
						false
					} else {
						true
					}
				});

				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished syncing with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		trace!("Current unconfirmed txs: {:?}", self.unconfirmed_txids().collect::<Vec<_>>());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await?;

		Ok(())
	}

	pub fn balance(&self) -> Balance {
		self.inner.balance()
	}

	pub fn list_unspent(&self) -> Vec<LocalOutput> {
		self.inner.list_unspent().collect()
	}

	pub fn list_transactions(&self) -> Vec<Arc<Transaction>> {
		self.inner.transactions().map(|tx| tx.tx_node.tx).collect()
	}

	/// List every wallet transaction with fee, balance change, and confirmation.
	///
	/// Fees are `None` for txs whose foreign prevouts BDK has not indexed: see
	/// [`WalletTxInfo::onchain_fees`].
	pub fn list_transaction_infos(&self) -> anyhow::Result<Vec<WalletTxInfo>> {
		let mut out = Vec::new();
		for canon in self.inner.transactions() {
			let txid = canon.tx_node.txid;
			let tx = canon.tx_node.tx.clone();

			let confirmation = match canon.chain_position {
				ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.into()),
				ChainPosition::Unconfirmed { .. } => None,
			};

			let (sent, received) = self.inner.sent_and_received(&tx);
			let balance_change = received.to_signed().context("received overflow")?
				- sent.to_signed().context("sent overflow")?;

			let onchain_fees = self.inner.calculate_fee(&tx).ok();

			// A P2A fee anchor is anyone-can-spend (BIP-431), so its spend
			// carries no signature: both witness and script_sig are empty.
			let is_cpfp = tx.input.iter()
				.any(|i| i.witness.is_empty() && i.script_sig.is_empty());

			out.push(WalletTxInfo {
				txid,
				tx,
				onchain_fees,
				balance_change,
				confirmation,
				is_cpfp,
			});
		}
		Ok(out)
	}

	pub fn utxos(&self) -> Vec<Utxo> {
		self.list_unspent().into_iter().map(|o| Utxo::Local(o.into())).collect()
	}

	/// Sign a psbt. Wallet-graph application is deferred to
	/// [`Self::record_broadcast_tx`].
	async fn sign_psbt(&mut self, mut psbt: Psbt) -> anyhow::Result<Psbt> {
		#[allow(deprecated)]
		let opts = bdk_wallet::SignOptions {
			trust_witness_utxo: true,
			..Default::default()
		};
		let finalized = self.inner.sign(&mut psbt, opts).context("signing error")?;
		ensure!(finalized, "failed to succesfully sign the tx");
		Ok(psbt)
	}

	async fn record_broadcast_tx(&mut self, tx: Transaction) -> anyhow::Result<()> {
		self.inner.apply_unconfirmed_txs([(tx, bark_runtime::timestamp_secs())]);
		self.persist().await
	}

	pub async fn send(&mut self, chain: &ChainSource, dest: Address, amount: Amount, fee_rate: FeeRate
	)	-> anyhow::Result<Txid> {
		let psbt = self.prepare_tx(&[(dest, amount)], fee_rate).await?;
		let tx = self.sign_psbt(psbt).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
	}

	pub async fn send_many(
		&mut self,
		chain: &ChainSource,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let pbst = self.prepare_tx(destinations, fee_rate).await?;
		let tx = self.sign_psbt(pbst).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
	}


	pub async fn drain(
		&mut self,
		chain: &ChainSource,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Txid> {
		let psbt = self.prepare_drain_tx(destination, fee_rate).await?;
		let tx = self.sign_psbt(psbt).await?.extract_tx()?;
		let txid = tx.compute_txid();
		self.record_broadcast_tx(tx.clone()).await?;
		if let Err(e) = chain.broadcast_tx(&tx).await {
			warn!("broadcast for {txid} returned error, will retry on next sync: {e:#}");
		}
		Ok(txid)
	}

	pub fn build_tx(&mut self) -> TxBuilder<'_, DefaultCoinSelectionAlgorithm> {
		self.inner.build_tx()
	}

	#[cfg(feature = "bitcoind-rpc")]
	async fn inner_sync_bitcoind(
		&mut self,
		bitcoind_sync: &bitcoin_ext::rpc::BitcoinRpcClient,
		prev_tip: CheckPoint,
	) -> anyhow::Result<()> {
		debug!("Syncing with bitcoind, starting at block height {}...", prev_tip.height());
		// `bdk_bitcoind_rpc::Emitter` is sync-only upstream. Run it on a
		// blocking thread and stream blocks back over a channel so we can
		// persist progress incrementally and yield to the runtime.
		// NB We pass start_height=0 so the Emitter never skips blocks.
		// Using prev_tip.height() would cause the Emitter to jump from the
		// agreement point directly to prev_tip on the new chain after a deep
		// reorg, producing a gap that BDK cannot merge.
		let sync_rpc = bitcoind_sync.clone();
		let prev_tip_clone = prev_tip.clone();
		// Materialize the unconfirmed-tx iterator before crossing the thread
		// boundary; bdk's iterator borrows wallet state and is not Send.
		let unconfirmed: Vec<_> = self.unconfirmed_txs().collect();
		let (block_tx, mut block_rx) =
			tokio::sync::mpsc::channel::<bdk_bitcoind_rpc::BlockEvent<bitcoin::Block>>(8);
		let (mempool_tx, mempool_rx) =
			tokio::sync::oneshot::channel::<bdk_bitcoind_rpc::MempoolEvent>();
		let emitter_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
			let mut emitter = bdk_bitcoind_rpc::Emitter::new(
				&sync_rpc, prev_tip_clone, 0, unconfirmed,
			);
			while let Some(em) = emitter.next_block()? {
				if block_tx.blocking_send(em).is_err() {
					return Ok(());
				}
			}
			drop(block_tx);
			let _ = mempool_tx.send(emitter.mempool()?);
			Ok(())
		});

		let mut count = 0;
		while let Some(em) = block_rx.recv().await {
			self.inner.apply_block_connected_to(
				&em.block, em.block_height(), em.connected_to(),
			)?;
			count += 1;

			if count % 10_000 == 0 {
				self.persist().await?;
				info!("Synced until block height {}", em.block_height());
			}
		}
		emitter_handle.await.context("wallet sync blocking task panicked")??;

		if let Ok(mempool) = mempool_rx.await {
			let now = bark_runtime::timestamp_secs();
			let recently_seen: HashSet<Txid> = self.inner.transactions()
				.filter_map(|tx| match tx.chain_position {
					ChainPosition::Unconfirmed { last_seen: Some(seen), .. }
						if now.saturating_sub(seen) < ONCHAIN_EVICTION_GRACE_SECS => {
						Some(tx.tx_node.txid)
					},
					_ => None,
				})
				.collect();
			let evicted = mempool.evicted.into_iter().filter(|(txid, _)| {
				if recently_seen.contains(txid) {
					debug!("Not evicting recently-seen tx {} still within grace period", txid);
					false
				} else {
					true
				}
			});
			self.inner.apply_evicted_txs(evicted);
			self.inner.apply_unconfirmed_txs(mempool.update);
		}
		self.persist().await?;
		debug!("Finished syncing with bitcoind");

		Ok(())
	}

	async fn rebroadcast_txs(&mut self, chain: &ChainSource, sync_start: u64) -> anyhow::Result<Amount> {
		let balance = self.inner.balance();

		// Ultimately, let's try to rebroadcast all our unconfirmed txs.
		let transactions = self.inner.transactions().filter(|tx| {
			if let ChainPosition::Unconfirmed { last_seen, .. } = tx.chain_position {
				match last_seen {
					Some(last_seen) => last_seen < sync_start,
					None => true,
				}
			} else {
				false
			}
		}).collect::<Vec<_>>();

		for tx in transactions {
			if let Err(e) = chain.broadcast_tx(&tx.tx_node.tx).await {
				warn!("Error broadcasting tx {}: {}", tx.tx_node.txid, e);
			}
		}

		Ok(balance.total())
	}

	pub async fn initial_wallet_scan(
		&mut self,
		chain: &ChainSource,
		start_height: Option<BlockHeight>,
	) -> anyhow::Result<Amount> {
		info!("Starting initial wallet sync...");
		debug!("Starting balance: {}", self.inner.balance());

		match chain.inner() {
			#[cfg(feature = "bitcoind-rpc")]
			ChainSourceClient::Bitcoind { rpc, sync } => {
				use bitcoind_async_client::traits::Reader;
				// Make sure we include the given start_height in the scan
				let height = start_height.unwrap_or(GENESIS_HEIGHT).saturating_sub(BlockDelta::new(1));
				let block_hash = rpc.get_block_hash(height.into()).await?;
				self.inner.set_checkpoint(height.into(), block_hash);
				self.inner_sync_bitcoind(sync, self.inner.latest_checkpoint()).await?;
			},
			// Esplora can't do a full scan from a given block height, so we can ignore start_height
			ChainSourceClient::Esplora(client) => {
				debug!("Starting full scan with esplora...");
				let request = self.inner.start_full_scan_at(bark_runtime::timestamp_secs());
				let update = client.full_scan(request, STOP_GAP, PARALLEL_REQS).await?;
				self.inner.apply_update(update)?;
				self.persist().await?;
				debug!("Finished scanning with esplora");
			},
		}

		debug!("Current balance: {}", self.inner.balance());
		self.rebroadcast_txs(chain, bark_runtime::timestamp_secs()).await
	}


	async fn persist(&mut self) -> anyhow::Result<()> {
		if let Some(stage) = self.inner.staged() {
			self.db.store_bdk_wallet_changeset(&*stage).await?;
			let _ = self.inner.take_staged();
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use bitcoin::{OutPoint, ScriptBuf, TxIn, Witness};
	use bitcoin::hashes::Hash;
	use bitcoin::locktime::absolute::LockTime;
	use bitcoin::transaction::Version;

	use ark::test_util::dummy::DummyTestVtxoSpec;

	use crate::actions::board::Board;
	use crate::movement::MovementId;
	use crate::persist::adaptor::StorageAdaptorWrapper;

	use super::*;

	#[tokio::test]
	async fn resumed_board_funding_rejects_newer_spend_but_allows_exact_replay() {
		let db = Arc::new(StorageAdaptorWrapper::new_memory());
		let mut wallet = OnchainWallet::load_or_create(Network::Regtest, [42; 64], db.clone())
			.await.unwrap();
		let address = wallet.address().await.unwrap();
		let funding = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(Txid::all_zeros(), 0),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(100_000),
				script_pubkey: address.script_pubkey(),
			}],
		};
		wallet.register_tx(&funding).await.unwrap();
		let board = wallet.prepare_tx(
			&[(address.clone(), Amount::from_sat(40_000))], FeeRate::from_sat_per_vb(1).unwrap(),
		).await.unwrap();

		// A crash leaves only the unsigned checkpoint: its old on-chain position
		// is still spendable, and a later ordinary send may validly consume it.
		drop(wallet);
		let mut wallet = OnchainWallet::load_or_create(Network::Regtest, [42; 64], db.clone())
			.await.unwrap();
		let competing = wallet.prepare_drain_tx(address, FeeRate::from_sat_per_vb(1).unwrap())
			.await.unwrap();
		let signed = wallet.finish_psbt(competing.clone()).await.unwrap();
		drop(wallet);

		// Resumption sees the persisted local spend before any broadcast/sync.
		let mut wallet = OnchainWallet::load_or_create(Network::Regtest, [42; 64], db)
			.await.unwrap();
		let error = wallet.finish_psbt(board).await.unwrap_err();
		assert!(error.to_string().contains("already spent by wallet transaction"));
		let replay = wallet.finish_psbt(competing).await.unwrap();
		assert_eq!(replay.unsigned_tx, signed.unsigned_tx);
		assert!(replay.inputs.iter().all(|input| input.final_script_witness.is_some()));
	}

	#[tokio::test]
	async fn unpublished_board_funding_keeps_change_unavailable_and_signed_inputs_reserved() {
		let db = Arc::new(StorageAdaptorWrapper::new_memory());
		let mut wallet = OnchainWallet::load_or_create(Network::Regtest, [43; 64], db.clone())
			.await.unwrap();
		let address = wallet.address().await.unwrap();
		let funding = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(Txid::all_zeros(), 0),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(100_000),
				script_pubkey: address.script_pubkey(),
			}],
		};
		wallet.register_tx(&funding).await.unwrap();
		let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
		let psbt = wallet.prepare_tx(
			&[(address.clone(), Amount::from_sat(40_000))], fee_rate,
		).await.unwrap();
		let txid = psbt.unsigned_tx.compute_txid();
		let original = psbt.unsigned_tx.input[0].previous_output;
		let (_, signed_vtxo) = DummyTestVtxoSpec::default().build();
		let mut board = Board {
			id: format!("board.{}.0", txid),
			funding_tx: None,
			funding_psbt: Some(psbt.clone()),
			vtxo_id: signed_vtxo.id(),
			amount: signed_vtxo.amount(),
			movement_id: MovementId(1),
			progress: BoardProgress::PreparingFunding { signed_vtxo, sign_funding: true },
		};
		db.upsert_wallet_action_checkpoint(&board.id, &board.clone().into()).await.unwrap();

		// Recovery preparation has not committed the original coins.
		let safe = wallet.prepare_drain_tx(address.clone(), fee_rate).await.unwrap();
		assert_eq!(safe.unsigned_tx.input[0].previous_output, original);

		// Simulate a crash after BDK saved the signature, before the board
		// checkpoint recorded it or the parent reached the network.
		let signed = wallet.finish_psbt(psbt).await.unwrap();
		drop(wallet);
		let mut wallet = OnchainWallet::load_or_create(Network::Regtest, [43; 64], db.clone())
			.await.unwrap();
		assert!(wallet.prepare_tx(
			&[(address.clone(), Amount::from_sat(10_000))], fee_rate,
		).await.is_err(), "unpublished board change must not fund another send");
		assert!(wallet.prepare_drain_tx(address.clone(), fee_rate).await.is_err());

		// Even after the sync grace period, eviction must not let a send
		// compete with funding whose signatures have already been released.
		let eviction_time = bark_runtime::timestamp_secs() + ONCHAIN_EVICTION_GRACE_SECS;
		wallet.inner.apply_evicted_txs([(txid, eviction_time)]);
		wallet.persist().await.unwrap();
		assert!(wallet.inner.list_unspent().any(|utxo| utxo.outpoint == original));
		assert!(wallet.prepare_drain_tx(address.clone(), fee_rate).await.is_err(),
			"evicted signed funding must keep its original inputs reserved");

		// Independent coins remain usable while board publication is pending.
		let mut independent = funding.clone();
		independent.input[0].previous_output = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
		wallet.register_tx(&independent).await.unwrap();
		let independent_psbt = wallet.prepare_tx(
			&[(address.clone(), Amount::from_sat(40_000))], fee_rate,
		).await.unwrap();
		assert_eq!(independent_psbt.unsigned_tx.input.len(), 1);
		assert_eq!(independent_psbt.unsigned_tx.input[0].previous_output,
			OutPoint::new(independent.compute_txid(), 0));

		// The publication checkpoint, not merely a signature, releases change.
		wallet.inner.apply_unconfirmed_txs([(signed.clone().extract_tx().unwrap(), eviction_time + 1)]);
		wallet.persist().await.unwrap();
		board.funding_psbt = Some(signed);
		board.progress = BoardProgress::Confirming { last_park_error: None };
		db.upsert_wallet_action_checkpoint(&board.id, &board.clone().into()).await.unwrap();
		let drain = wallet.prepare_drain_tx(address, fee_rate).await.unwrap();
		assert!(drain.unsigned_tx.input.iter().any(|input| input.previous_output.txid == txid));
		assert!(drain.unsigned_tx.input.iter().all(|input| input.previous_output != original));
	}
}
