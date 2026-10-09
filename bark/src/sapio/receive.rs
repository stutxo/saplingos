//! Coordinated delivery for program-backed addresses.
//!
//! The address has no mailbox fallback. Prepare persists an authorized recovery
//! claim before the sender signs; commit accepts only that same claim and the
//! complete signed VTXO. Receipts use U, never an arbitrary-message S signature.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{schnorr, Message, PublicKey};
use bitcoin::Network;
use serde::{Deserialize, Serialize};

use ark::address::VtxoDelivery;
use ark::sapio::program::ProgramKey;
use ark::vtxo::{policy::VtxoPolicyKind, Full};
use ark::{Address, ProtocolEncoding, Vtxo};

use crate::persist::models::{ProgramRecoveryRecord, SerdeProgramKey};
use crate::sapio::recovery::{verify_program_recovery, verify_program_recovery_template};
use crate::Wallet;

const DELIVERY_TYPE: u8 = 0x53;
const DELIVERY_MARKER: &[u8] = b"sapio-receive\0";
const VERSION: u8 = 1;
const MAX_URL_BYTES: usize = 2048;
const MAX_PREPARED_PER_KEY: usize = 128;
const RECEIVE_LOCK: &str = "sapio.receive";

pub const MAX_RECEIVE_BODY_BYTES: usize = 1_048_576;
pub const MAX_RECEIVE_VTXOS: usize = 16;
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The HTTP wire request. VTXOs use the canonical protocol hex encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramReceiveRequest {
	pub address: String,
	pub vtxos: Vec<String>,
}

/// A durable preparation acknowledgement. The descriptor proves U and S aggregate
/// to the address key. Each claim is independently checked, then U authenticates
/// its binding to this address and these exact candidate outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramReceiveReceipt {
	pub version: u8,
	pub address: String,
	pub candidates: Vec<String>,
	pub program: ProgramKey,
	pub recoveries: Vec<ProgramRecoveryRecord>,
	pub signature: schnorr::Signature,
}

/// A commit acknowledgement binds the final signed bytes, not only their txids.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramReceiveCommit {
	pub version: u8,
	pub address: String,
	pub vtxos_hash: sha256::Hash,
	pub program: ProgramKey,
	pub signature: schnorr::Signature,
}

fn coordinator_url(value: &str) -> anyhow::Result<reqwest::Url> {
	ensure!(value.len() <= MAX_URL_BYTES, "coordinator URL is too long");
	let url = reqwest::Url::parse(value).context("invalid coordinator URL")?;
	ensure!(url.host_str().is_some(), "coordinator URL needs a host");
	ensure!(url.username().is_empty() && url.password().is_none()
		&& url.query().is_none() && url.fragment().is_none(),
		"coordinator URL must not contain credentials, a query or a fragment");
	// Plain HTTP is restricted to literal loopback addresses for local listeners.
	// A hostname such as localhost is not trusted to retain its DNS resolution.
	let loopback = url.host_str().and_then(|s| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
		.is_some_and(|ip| ip.is_loopback());
	ensure!(url.scheme() == "https" || (url.scheme() == "http" && loopback),
		"coordinator URL requires HTTPS (HTTP is allowed only on loopback)");
	Ok(url)
}

fn delivery_url(address: &Address) -> anyhow::Result<Option<reqwest::Url>> {
	let Some(data) = address.delivery().iter().find_map(|delivery| match delivery {
		VtxoDelivery::Unknown { delivery_type: DELIVERY_TYPE, data } => Some(data),
		_ => None,
	}) else { return Ok(None) };
	ensure!(address.delivery().len() == 1, "coordinated address must have no other delivery method");
	ensure!(address.policy().policy_type() == VtxoPolicyKind::Pubkey,
		"coordinated address must use a final pubkey policy");
	let payload = data.strip_prefix(DELIVERY_MARKER).context("invalid coordinated delivery marker")?;
	ensure!(payload.first() == Some(&VERSION), "unsupported coordinated delivery version");
	let value = std::str::from_utf8(&payload[1..]).context("invalid coordinator URL encoding")?;
	Ok(Some(coordinator_url(value)?))
}

pub fn is_coordinated_address(address: &Address) -> anyhow::Result<bool> {
	Ok(delivery_url(address)?.is_some())
}

fn candidate_bytes(vtxos: &[Vtxo<Full>]) -> Vec<String> {
	vtxos.iter().map(|v| v.to_bare().serialize_hex()).collect()
}

fn validate_candidates(address: &Address, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
	ensure!(!vtxos.is_empty() && vtxos.len() <= MAX_RECEIVE_VTXOS,
		"receive requires between 1 and {MAX_RECEIVE_VTXOS} VTXOs");
	let mut seen = HashSet::with_capacity(vtxos.len());
	for vtxo in vtxos {
		ensure!(vtxo.policy() == address.policy(), "candidate policy differs from receive address");
		ensure!(address.is_for_server(vtxo.server_pubkey()), "candidate belongs to another Ark server");
		ensure!(vtxo.amount() > bitcoin::Amount::ZERO, "candidate amount must be positive");
		ensure!(seen.insert(vtxo.point()), "duplicate receive candidate");
	}
	Ok(())
}

fn receipt_message(
	address: &str,
	candidates: &[String],
	program: &ProgramKey,
	recoveries: &[ProgramRecoveryRecord],
) -> anyhow::Result<Message> {
	// Serialize an explicit typed tuple. Ancestor witnesses are excluded because
	// preparation intentionally precedes the sender's signatures. The claim and
	// prevout are immutable; the candidate commits to the exact ancestry txids.
	let claims = recoveries.iter().map(|r|
		(r.controlled_outpoint, r.program_key, &r.claim, &r.prevout)
	).collect::<Vec<_>>();
	let bytes = serde_json::to_vec(&(VERSION, address, candidates, program, claims))?;
	Ok(tagged_message(b"bark/sapio/receive/prepare/v1", &bytes))
}

fn tagged_message(tag: &[u8], bytes: &[u8]) -> Message {
	let tag = sha256::Hash::hash(tag);
	let mut engine = sha256::Hash::engine();
	engine.input(tag.as_byte_array());
	engine.input(tag.as_byte_array());
	engine.input(bytes);
	Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array())
}

fn final_hash(vtxos: &[Vtxo<Full>]) -> sha256::Hash {
	let mut engine = sha256::Hash::engine();
	engine.input(&(vtxos.len() as u64).to_le_bytes());
	for vtxo in vtxos {
		let bytes = vtxo.serialize();
		engine.input(&(bytes.len() as u64).to_le_bytes());
		engine.input(&bytes);
	}
	sha256::Hash::from_engine(engine)
}

fn commit_message(address: &str, hash: sha256::Hash, program: &ProgramKey) -> anyhow::Result<Message> {
	Ok(tagged_message(b"bark/sapio/receive/commit/v1",
		&serde_json::to_vec(&(VERSION, address, hash, program))?))
}

impl ProgramReceiveRequest {
	fn decode(&self) -> anyhow::Result<(Address, Vec<Vtxo<Full>>)> {
		ensure!(self.address.len() <= 8192, "receive address is too long");
		ensure!(!self.vtxos.is_empty() && self.vtxos.len() <= MAX_RECEIVE_VTXOS,
			"invalid receive VTXO count");
		let size = self.vtxos.iter().try_fold(self.address.len(), |size, v|
			size.checked_add(v.len()).context("receive size overflow"))?;
		ensure!(size <= MAX_RECEIVE_BODY_BYTES, "receive request is too large");
		let address = self.address.parse::<Address>().context("invalid receive address")?;
		ensure!(is_coordinated_address(&address)?, "address does not use coordinated delivery");
		let vtxos = self.vtxos.iter().map(|hex| Vtxo::<Full>::deserialize_hex(hex)
			.context("invalid receive VTXO encoding")).collect::<anyhow::Result<Vec<_>>>()?;
		validate_candidates(&address, &vtxos)?;
		Ok((address, vtxos))
	}

	fn new(address: &Address, vtxos: &[Vtxo<Full>]) -> Self {
		Self { address: address.to_string(), vtxos: vtxos.iter().map(|v| v.serialize_hex()).collect() }
	}
}

impl ProgramReceiveReceipt {
	pub fn verify(&self, address: &Address, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		validate_candidates(address, vtxos)?;
		ensure!(self.version == VERSION && self.address == address.to_string(), "receipt address/version mismatch");
		ensure!(self.program.public_key()? == address.policy().user_pubkey(),
			"receipt U and S do not aggregate to address key");
		ensure!(self.candidates == candidate_bytes(vtxos) && self.recoveries.len() == vtxos.len(),
			"receipt candidate mismatch");
		for (vtxo, recovery) in vtxos.iter().zip(&self.recoveries) {
			verify_program_recovery(vtxo, recovery, false).context("invalid receipt recovery claim")?;
		}
		let message = receipt_message(&self.address, &self.candidates, &self.program, &self.recoveries)?;
		ark::SECP.verify_schnorr(&self.signature, &message, &self.program.user_pubkey.x_only_public_key().0)
			.context("invalid receive preparation signature")
	}
}

impl ProgramReceiveCommit {
	pub fn verify(&self, address: &Address, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		ensure!(self.version == VERSION && self.address == address.to_string(), "commit address/version mismatch");
		ensure!(self.program.public_key()? == address.policy().user_pubkey(), "commit ownership descriptor mismatch");
		ensure!(self.vtxos_hash == final_hash(vtxos), "commit signed VTXO bytes mismatch");
		ark::SECP.verify_schnorr(&self.signature,
			&commit_message(&self.address, self.vtxos_hash, &self.program)?,
			&self.program.user_pubkey.x_only_public_key().0,
		).context("invalid receive commit signature")
	}
}

impl Wallet {
	/// Build an address from an already persisted program descriptor. The only
	/// delivery option is the coordinated endpoint; no private C is needed.
	pub(crate) fn coordinated_address(
		&self, key: &SerdeProgramKey, network: Network, server_pubkey: PublicKey,
	) -> anyhow::Result<Address> {
		let url = self.inner.config.sapio.as_ref().and_then(|s| s.coordinator_url.as_deref())
			.context("program addresses require sapio.coordinator_url")?;
		let url = coordinator_url(url)?;
		let mut data = Vec::with_capacity(DELIVERY_MARKER.len() + 1 + url.as_str().len());
		data.extend_from_slice(DELIVERY_MARKER);
		data.push(VERSION);
		data.extend_from_slice(url.as_str().as_bytes());
		Address::builder().testnet(network != Network::Bitcoin).server_pubkey(server_pubkey)
			.pubkey_policy(key.program.public_key()?)
			.delivery(VtxoDelivery::Unknown { delivery_type: DELIVERY_TYPE, data })
			.into_address().context("failed to build coordinated address")
	}

	async fn receive_key(&self, address: &Address) -> anyhow::Result<SerdeProgramKey> {
		let key = self.inner.db.get_program_key(&address.policy().user_pubkey()).await?
			.context("receive address is not a stored program key")?;
		let properties = self.properties().await?;
		let server = properties.server_pubkey.context("wallet has no stored Ark server key")?;
		ensure!(address.is_for_server(server) && address.is_testnet() == (properties.network != Network::Bitcoin),
			"receive address belongs to another network or server");
		ensure!(key.program.public_key()? == address.policy().user_pubkey(), "invalid stored program descriptor");
		let user = self.inner.seed.derive_vtxo_keypair(key.index);
		ensure!(user.public_key() == key.program.user_pubkey, "stored program user key differs from wallet key");
		Ok(key)
	}

	async fn prepared_receive_records(
		&self, key: &SerdeProgramKey, vtxos: &[Vtxo<Full>],
	) -> anyhow::Result<Vec<ProgramRecoveryRecord>> {
		let mut records = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			let record = self.inner.db.get_program_recovery(vtxo.point()).await?
				.context("program receive was not prepared; refusing unsafe deposit")?;
			verify_program_recovery(vtxo, &record, false)?;
			verify_program_recovery_template(&record, key)?;
			records.push(record);
		}
		Ok(records)
	}

	/// Prepare only exact future payments to stored program addresses. This API
	/// exposes no balance, arbitrary digest, input signing, or administrative call.
	pub async fn prepare_program_receive(
		&self, request: ProgramReceiveRequest,
	) -> anyhow::Result<ProgramReceiveReceipt> {
		let (address, vtxos) = request.decode()?;
		let _guard = self.inner.lock_manager.lock(RECEIVE_LOCK, RECEIVE_TIMEOUT).await?;
		let key = self.receive_key(&address).await?;
		let existing = self.inner.db.list_program_recoveries().await?;
		let count = existing.iter().filter(|r| r.program_key == address.policy().user_pubkey()).count();
		let new_count = vtxos.iter().filter(|v| !existing.iter().any(|r| r.controlled_outpoint == v.point())).count();
		ensure!(new_count == 0 || count.saturating_add(new_count) <= MAX_PREPARED_PER_KEY,
			"receive address preparation limit reached; use a new address");
		for vtxo in &vtxos {
			let anchor = self.inner.chain.get_tx(&vtxo.chain_anchor().txid).await?
				.context("receive candidate chain anchor not found")?;
			vtxo.validate_unsigned(&anchor).context("invalid receive candidate chain")?;
		}
		self.prepare_program_recoveries(&vtxos).await?;
		let records = self.prepared_receive_records(&key, &vtxos).await?;
		let candidates = candidate_bytes(&vtxos);
		let address = address.to_string();
		let message = receipt_message(&address, &candidates, &key.program, &records)?;
		let user = self.inner.seed.derive_vtxo_keypair(key.index);
		let signature = ark::SECP.sign_schnorr_no_aux_rand(&message, &user);
		Ok(ProgramReceiveReceipt { version: VERSION, address, candidates,
			program: key.program, recoveries: records, signature })
	}

	/// Commit a prepared receive without consulting Sapio or requesting another
	/// signature. A lost response can be retried with identical signed VTXOs.
	pub async fn commit_program_receive(
		&self, request: ProgramReceiveRequest,
	) -> anyhow::Result<ProgramReceiveCommit> {
		let (address, vtxos) = request.decode()?;
		let _guard = self.inner.lock_manager.lock(RECEIVE_LOCK, RECEIVE_TIMEOUT).await?;
		let key = self.receive_key(&address).await?;
		self.prepared_receive_records(&key, &vtxos).await?;
		for vtxo in &vtxos {
			self.validate_vtxo(vtxo).await.context("invalid final receive VTXO")?;
			if let Some(stored) = self.inner.db.get_full_vtxo(vtxo.id()).await? {
				ensure!(stored.serialize() == vtxo.serialize(), "receive retry differs from saved signed bytes");
			}
		}
		self.ensure_program_recoveries(&vtxos).await?;
		let hash = final_hash(&vtxos);
		self.store_received_arkoor_package(vtxos).await?;
		let address = address.to_string();
		let user = self.inner.seed.derive_vtxo_keypair(key.index);
		let signature = ark::SECP.sign_schnorr_no_aux_rand(&commit_message(&address, hash, &key.program)?, &user);
		Ok(ProgramReceiveCommit { version: VERSION, address, vtxos_hash: hash, program: key.program, signature })
	}

	/// Require a verified, durable recipient recovery before the sender releases
	/// its completed input signature. Native addresses need no handshake.
	pub async fn prepare_program_receives(&self, address: &Address, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		let Some(url) = delivery_url(address)? else { return Ok(()) };
		validate_candidates(address, vtxos)?;
		let receipt: ProgramReceiveReceipt = receive_request(self, url, "prepare", &ProgramReceiveRequest::new(address, vtxos)).await?;
		receipt.verify(address, vtxos)
	}

	/// Call only after the sender checkpoints the final signed VTXOs, before
	/// registration/export. A rejected or unavailable commit never unlocks inputs.
	pub async fn commit_program_receives(&self, address: &Address, vtxos: &[Vtxo<Full>]) -> anyhow::Result<()> {
		let Some(url) = delivery_url(address)? else { return Ok(()) };
		validate_candidates(address, vtxos)?;
		let receipt: ProgramReceiveCommit = receive_request(self, url, "commit", &ProgramReceiveRequest::new(address, vtxos)).await?;
		receipt.verify(address, vtxos)
	}
}

async fn receive_request<T: serde::de::DeserializeOwned>(
	wallet: &Wallet, mut url: reqwest::Url, phase: &str, request: &ProgramReceiveRequest,
) -> anyhow::Result<T> {
	let path = format!("{}/{}", url.path().trim_end_matches('/'), phase);
	url.set_path(&path);
	wallet.post_program_json(url.as_str(), request).await
		.with_context(|| format!("receive coordinator {phase} failed"))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn address_with_deliveries(delivery: Vec<VtxoDelivery>) -> Address {
		let key: PublicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
		Address::new(true, key, ark::VtxoPolicy::new_pubkey(key), delivery)
	}

	fn coordinated_delivery(version: u8, url: &str) -> VtxoDelivery {
		let mut data = DELIVERY_MARKER.to_vec();
		data.push(version);
		data.extend_from_slice(url.as_bytes());
		VtxoDelivery::Unknown { delivery_type: DELIVERY_TYPE, data }
	}

	#[test]
	fn coordinated_addresses_fail_closed_without_exclusive_supported_delivery() {
		let delivery = coordinated_delivery(VERSION, "https://recipient.example/api/v1/receive/program");
		let address = address_with_deliveries(vec![delivery.clone()]);
		assert!(is_coordinated_address(&address).unwrap());
		assert!(address.delivery().iter().all(VtxoDelivery::is_unknown));
		let decoded: Address = address.to_string().parse().unwrap();
		assert_eq!(delivery_url(&decoded).unwrap(), delivery_url(&address).unwrap());
		assert!(is_coordinated_address(&address_with_deliveries(vec![delivery.clone(), delivery])).is_err());
		assert!(is_coordinated_address(&address_with_deliveries(vec![
			coordinated_delivery(VERSION + 1, "https://recipient.example"),
		])).is_err());
		assert!(!is_coordinated_address(&address_with_deliveries(Vec::new())).unwrap());
	}

	#[test]
	fn coordinated_delivery_rejects_unsafe_url_authority() {
		for url in [
			"file:///etc/passwd", "ftp://recipient.example/receive",
			"http://recipient.example/receive", "http://localhost/receive",
			"https://user:secret@recipient.example/receive",
			"https://recipient.example/receive?admin=true",
			"https://recipient.example/receive#commit",
		] {
			assert!(coordinator_url(url).is_err(), "{url}");
		}
		assert!(coordinator_url("https://recipient.example/api/v1/receive/program").is_ok());
		assert!(coordinator_url("http://127.0.0.1:8081/api/v1/receive/program").is_ok());
		assert!(coordinator_url("http://[::1]:8081/api/v1/receive/program").is_ok());
	}
}
