//! One-use client signing sessions and bounded, non-redirecting JSON transport.

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{schnorr, PublicKey};
use serde::{de::DeserializeOwned, Serialize};

use ark::musig::{self, nested};
use ark::musig::context::SigningInput;
use ark::sapio::protocol::{
	parse_nonce, parse_partial, FinishRequest, FinishResponse, OwnershipRequest,
	PrepareRequest, PrepareResponse, SigningAction, SpendRequest, MAX_REQUEST_BYTES, SIGNING_PROTOCOL,
};

use crate::{Config, Wallet};
use crate::vtxo::SignatureResult;
use super::VtxoSigningKey;

const HTTP_TIMEOUT_SECS: u64 = 30;

pub(crate) fn endpoint_url(value: &str) -> Result<reqwest::Url> {
	let url = reqwest::Url::parse(value).context("invalid program endpoint URL")?;
	ensure!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
		"program endpoint must not contain credentials or a fragment");
	let loopback = url.host_str()
		.and_then(|s| s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
		.is_some_and(|ip| ip.is_loopback());
	ensure!(url.scheme() == "https" || (url.scheme() == "http" && loopback),
		"program endpoint requires HTTPS, except literal loopback HTTP");
	Ok(url)
}

pub(crate) struct ProgramTransport {
	#[cfg(not(target_arch = "wasm32"))]
	direct: reqwest::Client,
	#[cfg(all(not(target_arch = "wasm32"), feature = "socks5-proxy"))]
	proxied: Option<reqwest::Client>,
}

impl ProgramTransport {
	pub(crate) fn new(config: &Config) -> Result<Self> {
		#[cfg(not(target_arch = "wasm32"))]
		let direct = reqwest::Client::builder()
			.no_proxy()
			.redirect(reqwest::redirect::Policy::none())
			.timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
			.build().context("building program HTTP client")?;
		#[cfg(all(not(target_arch = "wasm32"), feature = "socks5-proxy"))]
		let proxied = config.socks5_proxy.as_ref().map(|proxy| {
			reqwest::Client::builder().no_proxy()
				.proxy(reqwest::Proxy::all(proxy)?)
				.redirect(reqwest::redirect::Policy::none())
				.timeout(Duration::from_secs(HTTP_TIMEOUT_SECS)).build()
		}).transpose().context("building proxied program HTTP client")?;
		let _ = config;
		Ok(Self {
			#[cfg(not(target_arch = "wasm32"))]
			direct,
			#[cfg(all(not(target_arch = "wasm32"), feature = "socks5-proxy"))]
			proxied,
		})
	}

	async fn post<T: Serialize + ?Sized, R: DeserializeOwned>(
		&self, config: &Config, url: &str, request: &T,
	) -> Result<R> {
		let url = endpoint_url(url)?;
		let body = serde_json::to_vec(request)?;
		ensure!(body.len() <= MAX_REQUEST_BYTES, "program request exceeds size limit");
		#[cfg(not(target_arch = "wasm32"))]
		{
			let client = &self.direct;
			#[cfg(feature = "socks5-proxy")]
			let client = if crate::proxy::proxy_for_url(&config.socks5_proxy, url.as_str())?.is_some() {
				self.proxied.as_ref().context("program proxy client unavailable")?
			} else { client };
			let _ = config;
			let mut response = client.post(url).header("Content-Type", "application/json")
				.body(body).send().await.context("contacting program service")?;
			let status = response.status();
			let mut bytes = Vec::new();
			while let Some(chunk) = response.chunk().await? {
				ensure!(bytes.len().saturating_add(chunk.len()) <= MAX_REQUEST_BYTES,
					"program response exceeds size limit");
				bytes.extend_from_slice(&chunk);
			}
			ensure!(status.is_success(), "program service rejected request ({status}): {}",
				String::from_utf8_lossy(&bytes[..bytes.len().min(8192)]));
			Ok(serde_json::from_slice(&bytes).context("invalid program service response")?)
		}
		#[cfg(all(target_arch = "wasm32", feature = "wasm-web"))]
		{
			let _ = config;
			let body = String::from_utf8(body).expect("JSON serialization is UTF-8");
			let text = browser_post(url.as_str(), &body, MAX_REQUEST_BYTES as u32,
				(HTTP_TIMEOUT_SECS * 1000) as u32).await
				.map_err(|error| anyhow!("program HTTP request failed: {error:?}"))?;
			Ok(serde_json::from_str(&text).context("invalid program service response")?)
		}
		#[cfg(all(target_arch = "wasm32", not(feature = "wasm-web")))]
		{
			let _ = (config, url, body);
			bail!("browser program transport requires the wasm-web feature")
		}
	}
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-web"))]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = "
export async function barkProgramPost(url, body, limit, timeout) {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeout);
	try {
		const response = await fetch(url, {method: 'POST', body,
			headers: {'Content-Type': 'application/json'}, credentials: 'omit',
			redirect: 'error', signal: controller.signal, cache: 'no-store'});
		const chunks = []; let size = 0;
		if (response.body) {
			const reader = response.body.getReader();
			for (;;) {
				const {done, value} = await reader.read();
				if (done) break;
				size += value.byteLength;
				if (size > limit) { controller.abort(); throw new Error('program response exceeds size limit'); }
				chunks.push(value);
			}
		}
		const bytes = new Uint8Array(size); let offset = 0;
		for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
		const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
		if (!response.ok) throw new Error('program service rejected request (' + response.status + '): ' + text.slice(0, 8192));
		return text;
	} finally { clearTimeout(timer); }
}
")]
extern "C" {
	#[wasm_bindgen::prelude::wasm_bindgen(catch, js_name = barkProgramPost)]
	async fn browser_post(url: &str, body: &str, limit: u32, timeout: u32)
		-> std::result::Result<String, wasm_bindgen::JsValue>;
}

pub(crate) struct PreparedSignature {
	wallet: Wallet,
	key: VtxoSigningKey,
	input: Option<SigningInput>,
	state: PreparedState,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl crate::vtxo::PreparedVtxoSignature for PreparedSignature {
	fn public_nonce(&self) -> musig::PublicNonce {
		self.public_nonce()
	}

	async fn finish(
		self: Box<Self>,
		server_nonce: Option<musig::PublicNonce>,
		server_partial: Option<musig::PartialSignature>,
	) -> Result<crate::vtxo::SignatureResult> {
		PreparedSignature::finish(*self, server_nonce, server_partial).await
	}
}

enum PreparedState {
	Local {
		nonce: musig::SecretNonce,
		public: musig::PublicNonce,
		message: [u8; 32],
		participants: Vec<PublicKey>,
		tweak: Option<[u8; 32]>,
	},
	Program {
		nonce: nested::Nonce,
		peer: nested::MemberNonce,
		intent: nested::Intent,
		session: bitcoin::hashes::sha256::Hash,
		endpoint: String,
	},
}

impl PreparedSignature {
	pub fn public_nonce(&self) -> musig::PublicNonce {
		match &self.state {
			PreparedState::Local { public, .. } => *public,
			PreparedState::Program { nonce, peer, intent, .. } =>
				nested::aggregate_member_nonces(intent, &[nonce.public(), *peer])
					.expect("member nonce aggregation was checked during preparation"),
		}
	}

	pub async fn finish(
		self,
		server_nonce: Option<musig::PublicNonce>,
		server_partial: Option<musig::PartialSignature>,
	) -> Result<crate::vtxo::SignatureResult> {
		let key = &self.key;
		let ret = match self.state {
			PreparedState::Program { nonce, peer, intent, session, endpoint } => {
				let request = FinishRequest {
					protocol: SIGNING_PROTOCOL.into(), session,
					server_nonce: server_nonce.map(|n| n.serialize().to_lower_hex_string()),
					server_partial: server_partial.map(|s| s.serialize().to_lower_hex_string()),
				};
				let response: FinishResponse = self.wallet.post_program_json(
					&format!("{}/ark/finish", endpoint.trim_end_matches('/')), &request,
				).await?;
				ensure!(response.protocol == SIGNING_PROTOCOL, "unexpected program signing protocol");
				let session = nested::Session::new(intent, [nonce.public(), peer], server_nonce)?;
				if let Some(partial) = server_partial.as_ref() { session.verify_server(partial)?; }
				let peer_partial = parse_partial(&response.program_partial)?;
				session.verify_member(1, &peer_partial)?;
				// U is last. The enclave has never received this share.
				let user = nonce.sign(&key.user, &session)?;
				let shares = [user, peer_partial];
				let user_partial = session.combine_members(&shares)?;
				let signature = if intent.server.is_none() || server_partial.is_some() {
					Some(session.aggregate(&shares, server_partial.as_ref())?)
				} else { None };
				SignatureResult { user_partial, signature }
			},
			PreparedState::Local { nonce, public, message, participants, tweak } => {
				let native = key.local_keypair().context("native nonce supplied to program signer")?;
				let server_nonce = server_nonce.context("missing server nonce")?;
				ensure!(participants.len() == 2, "unsupported native participant count");
				let server = participants.iter().copied()
					.find(|p| *p != key.public_key())
					.context("missing distinct server participant")?;
				let cache = match tweak {
					Some(tweak) => musig::tweaked_key_agg(participants.iter().copied(), tweak).0,
					None => musig::key_agg(participants.iter().copied()),
				};
				let aggregate = musig::nonce_agg(&[&public, &server_nonce]);
				let session = musig::Session::new(&cache, aggregate, &message);
				if let Some(partial) = server_partial.as_ref() {
					ensure!(session.partial_verify(&cache, partial, &server_nonce, musig::pubkey_to(server)),
						"invalid server partial signature");
				}
				let user_partial = session.partial_sign(nonce, &musig::keypair_to(native), &cache);
				ensure!(session.partial_verify(&cache, &user_partial, &public,
					musig::pubkey_to(key.public_key())),
					"invalid local partial signature");
				let signature = server_partial.as_ref().map(|server| {
					musig::sig_from(session.partial_sig_agg(&[&user_partial, server]).assume_valid())
				});
				SignatureResult { user_partial, signature }
			},
		};
		if let (Some(input), Some(signature)) = (&self.input, &ret.signature) {
			input.verify_signature(signature)?;
		}
		Ok(ret)
	}
}

impl Wallet {
	pub(crate) async fn post_program_json<T: Serialize + ?Sized, R: DeserializeOwned>(
		&self, url: &str, request: &T,
	) -> Result<R> {
		let transport = self.inner.program_transport.get_or_try_init(|| async {
			ProgramTransport::new(&self.inner.config)
		}).await?;
		transport.post(&self.inner.config, url, request).await
	}

	async fn prepare_program_signature(
		&self, key: &VtxoSigningKey, action: SigningAction, input: Option<SigningInput>,
	) -> Result<PreparedSignature> {
		let descriptor = key.program().context("program signer required")?;
		let intent = action.intent(&descriptor.program)?;
		let nonce = nested::Nonce::new(intent, descriptor.program.user_pubkey)?;
		let request = PrepareRequest {
			protocol: SIGNING_PROTOCOL.into(), key: descriptor.program.clone(), action,
			user_nonce: nonce.public().serialize().to_lower_hex_string(),
		};
		let response: PrepareResponse = self.post_program_json(
			&format!("{}/ark/prepare", descriptor.endpoint.trim_end_matches('/')), &request,
		).await?;
		ensure!(response.protocol == SIGNING_PROTOCOL, "unexpected program signing protocol");
		let peer = nested::MemberNonce::from_bytes(
			intent, intent.members[1], parse_nonce(&response.program_nonce)?.serialize(),
		)?;
		nested::aggregate_member_nonces(&intent, &[nonce.public(), peer])?;
		Ok(PreparedSignature {
			wallet: self.clone(), key: key.clone(), input,
			state: PreparedState::Program { nonce, peer, intent, session: response.session,
				endpoint: descriptor.endpoint.clone() },
		})
	}

	pub(crate) async fn prepare_vtxo_signature(
		&self, key: &VtxoSigningKey, input: SigningInput,
	) -> Result<PreparedSignature> {
		let message = input.sighash()?;
		ensure!(input.participants.contains(&key.public_key()), "key is not a signing participant");
		if key.program().is_some() {
			ensure!(input.participants.len() == 2, "program outer signing needs exactly two participants");
			let server = input.participants.iter().copied().find(|p| *p != key.public_key())
				.context("missing distinct outer server")?;
			let witness = self.inner.config.sapio_witnesses.get(&key.public_key())
				.cloned().unwrap_or_default();
			let request = SpendRequest::from_input(&input, Some(server), witness)?;
			self.prepare_program_signature(key, SigningAction::Spend { request }, Some(input)).await
		} else {
			let native = key.local_keypair().context("native signing key required")?;
			let (nonce, public) = musig::nonce_pair_with_msg(native, &message);
			let state = PreparedState::Local { nonce, public, message,
				participants: input.participants.clone(), tweak: input.tweak };
			Ok(PreparedSignature {
				wallet: self.clone(), key: key.clone(), input: Some(input), state,
			})
		}
	}

	pub(crate) async fn sign_program_claim(
		&self, key: &VtxoSigningKey, input: SigningInput, witness: Vec<u8>,
	) -> Result<schnorr::Signature> {
		ensure!(key.program().is_some(), "program claim requires a program key");
		let request = SpendRequest::from_input(&input, None, witness)?;
		self.prepare_program_signature(key, SigningAction::Spend { request }, Some(input)).await?
			.finish(None, None).await?.signature.context("missing joint recovery signature")
	}

	pub(crate) async fn sign_vtxo_ownership(
		&self, key: &VtxoSigningKey, request: OwnershipRequest,
	) -> Result<schnorr::Signature> {
		if let Some(program) = key.program() {
			request.message(&program.program)?;
			self.prepare_program_signature(key, SigningAction::Ownership { request }, None).await?
				.finish(None, None).await?.signature.context("missing joint ownership signature")
		} else {
			ensure!(request.input.user_pubkey() == key.public_key(), "ownership key mismatch");
			let message = request.message_for_owner(key.public_key())?;
			Ok(ark::SECP.sign_schnorr_with_aux_rand(&message, &key.user, &rand::random()))
		}
	}
}
