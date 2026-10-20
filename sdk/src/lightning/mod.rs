
mod pay;
mod receive;

pub use self::pay::LightningSendOptions;

use std::net::IpAddr;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hashes::Hash;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use lnurllib::LnUrlResponse;
use lnurllib::lightning_address::LightningAddress;
use lnurllib::pay::PayResponse;
use log::warn;

use bitcoin_ext::AmountExt;

/// Returns the wallet's configured socks5h proxy for LNURL fetches, if any.
///
/// Always `None` when built without the `socks5-proxy` feature, so call
/// sites stay feature-agnostic; without a proxy `.onion` and cleartext
/// destinations remain rejected by [`validate_lnurl_destination`].
#[allow(unused_variables)]
pub(crate) fn lightning_wallet_proxy(config: &crate::Config) -> Option<&str> {
	#[cfg(feature = "socks5-proxy")]
	{ config.socks5_proxy.as_deref() }
	#[cfg(not(feature = "socks5-proxy"))]
	{ None }
}

/// Per-request timeout for LNURL-pay HTTP exchanges (initial resolution and
/// invoice callback), matching the wallet's other bounded HTTP transports
/// (`sapio::client::HTTP_TIMEOUT_SECS`). A payee endpoint must not be able
/// to stall a payment task indefinitely. Native targets only: the wasm32
/// fetch path cannot enforce it (see the wasm32 lnurl_pay_resolve).
#[cfg(not(target_arch = "wasm32"))]
const LNURL_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard cap on LNURL-pay response bodies, read incrementally before any
/// JSON decode. Pay/invoice responses are single-digit KiB in practice;
/// without a cap a payee endpoint can exhaust the wallet's memory
/// (a 96 MiB body was buffered whole in audit reproductions).
#[cfg(not(target_arch = "wasm32"))]
const LNURL_MAX_BODY: usize = 64 * 1024;

/// Validates a payee-controlled URL before it is fetched.
///
/// LNURL endpoints are untrusted: the initial URL comes from a user-pasted
/// bech32 string and the invoice callback is payee-chosen metadata, so
/// fetching them verbatim would hand the payee unrestricted outbound-request
/// authority over the wallet host. The policy here is:
///
/// - https only, except `.onion` over http, which is permitted only when the
///   request is routed through the wallet's configured socks5h proxy (the
///   hidden-service handshake authenticates the endpoint);
/// - no credentials embedded in the URL;
/// - no loopback, private, link-local or unspecified literal IP destinations
///   (proxied or not), so resolution cannot be abused as a blind GET oracle
///   against internal services of the wallet host.
///
/// Only literal IPs are filtered here: an unproxied *hostname* that
/// resolves (via DNS) to a private or internal address is NOT mitigated,
/// because no name resolution happens at validation time. When the socks5h
/// proxy is configured it resolves names remotely from the proxy's vantage
/// point, which keeps the wallet host's internal names unreachable from
/// this path; operators paying arbitrary LNURLs from hosts with internal
/// reachability should therefore configure the proxy.
fn validate_lnurl_destination(url: &str, has_proxy: bool) -> anyhow::Result<()> {
	let url = reqwest::Url::parse(url).context("invalid lnurl url")?;
	ensure!(url.username().is_empty() && url.password().is_none(),
		"lnurl url must not contain credentials");
	let host = url.host_str().context("lnurl url has no host")?;
	let is_onion = host.ends_with(".onion");
	// `Url::host_str` keeps the brackets on IPv6 literals ([::1]).
	let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
	match url.scheme() {
		"https" => {},
		"http" if is_onion && has_proxy => {},
		scheme => bail!(
			"lnurl url scheme '{}' is not allowed; only https \
			(or .onion via the configured socks5 proxy) is fetched", scheme,
		),
	}
	if let Ok(ip) = host.parse::<IpAddr>() {
		// Normalize IPv4-mapped IPv6 literals so that, e.g.,
		// ::ffff:127.0.0.1 cannot smuggle a loopback past the IPv4 checks.
		let ip = match ip {
			IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
			v4 => v4,
		};
		let non_public = match ip {
			IpAddr::V4(v4) => v4.is_private() || v4.is_loopback()
				|| v4.is_link_local() || v4.is_unspecified(),
			IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified()
				|| v6.is_unique_local() || v6.is_unicast_link_local(),
		};
		ensure!(!non_public, "lnurl url targets a non-public address");
	}
	Ok(())
}

/// Builds the HTTP client used for LNURL-pay fetches.
///
/// Unlike `lnurllib::Builder::default()` this binds the request to the
/// wallet's network policy: a hard per-request timeout, no redirect
/// following (a redirect would silently hand request authority to a third
/// origin), and the wallet's configured socks5h proxy -- the same posture as
/// the chain, server and sapio clients, so payee endpoints never learn the
/// wallet's real egress address.
#[cfg(not(target_arch = "wasm32"))]
fn lnurl_http_client(
	url: &str,
	timeout: Duration,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<reqwest::Client> {
	// The proxy applies per request URL: local destinations bypass it through
	// proxy_for_url, and only socks5h proxy URLs are accepted (DNS must be
	// resolved remotely to avoid leaks).
	#[cfg(feature = "socks5-proxy")]
	let proxy = crate::proxy::proxy_for_url(&wallet_proxy.map(str::to_owned), url)?;
	#[cfg(not(feature = "socks5-proxy"))]
	let proxy: Option<String> = { let _ = (url, wallet_proxy); None };

	let mut builder = reqwest::Client::builder()
		.no_proxy()
		.redirect(reqwest::redirect::Policy::none())
		.timeout(timeout);
	if let Some(proxy) = proxy {
		builder = builder.proxy(reqwest::Proxy::all(proxy).context("invalid socks5 proxy url")?);
	}
	Ok(builder.build().context("building lnurl http client")?)
}

/// Performs a single bounded GET against a payee-controlled LNURL URL and
/// returns the raw response body.
///
/// The body is read incrementally with the [`LNURL_MAX_BODY`] hard cap
/// before any JSON decode, and non-success statuses (including redirects,
/// which are never followed) are reported as errors.
#[cfg(not(target_arch = "wasm32"))]
async fn lnurl_get(
	url: &str,
	timeout: Duration,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
	let client = lnurl_http_client(url, timeout, wallet_proxy)?;
	let mut response = client.get(url).send().await.context("lnurl http request failed")?;
	let status = response.status();
	let mut body = Vec::new();
	while let Some(chunk) = response.chunk().await.context("reading lnurl response body")? {
		ensure!(body.len() + chunk.len() <= LNURL_MAX_BODY,
			"lnurl response exceeds {} byte limit", LNURL_MAX_BODY);
		body.extend_from_slice(&chunk);
	}
	ensure!(status.is_success(),
		"lnurl endpoint returned http status {} (redirects are not followed): {}",
		status, String::from_utf8_lossy(&body[..body.len().min(1024)]));
	Ok(body)
}

/// Runs the two LNURL-pay HTTP exchanges (pay request, then invoice
/// callback) and returns the [`PayResponse`] together with the raw BOLT11
/// invoice string.
///
/// lnurl-rs 0.10 cannot express the wallet's network policy its
/// `make_request`/`get_invoice` buffer the whole body unbounded, follow
/// reqwest's default cross-origin redirects and know nothing of the
/// configured socks5h proxy, so the fetches run through our own bounded
/// client ([`lnurl_get`]). The request/response handling below mirrors
/// lnurl-rs' `AsyncClient::make_request`/`get_invoice` exactly, so
/// well-behaved endpoints observe identical behavior.
#[cfg(not(target_arch = "wasm32"))]
async fn lnurl_pay_resolve(
	lnurlp: &str,
	amount_msats: u64,
	comment: Option<&str>,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<(PayResponse, String)> {
	let body = lnurl_get(lnurlp, LNURL_TIMEOUT, wallet_proxy).await
		.context("failed to make lnurl request")?;
	let text = String::from_utf8(body).context("lnurl response was not utf-8")?;
	let resp = match lnurllib::api::decode_ln_url_response(&text).context("invalid lnurl response")? {
		LnUrlResponse::LnUrlPayResponse(v) => v,
		LnUrlResponse::LnUrlWithdrawResponse(_) => bail!("received lnurl withdraw"),
		LnUrlResponse::LnUrlChannelResponse(_) => bail!("received lnurl channel"),
	};

	// The callback is payee-chosen metadata; re-validate it against the same
	// destination policy as the initial URL before fetching it verbatim.
	validate_lnurl_destination(&resp.callback, wallet_proxy.is_some())?;

	// Mirror lnurl-rs' `get_invoice`: amount and comment checks and the
	// callback query string are built exactly as upstream.
	ensure!(amount_msats >= resp.min_sendable && amount_msats <= resp.max_sendable,
		"amount {} msat is outside the endpoint's sendable range", amount_msats);
	if let Some(comment) = comment {
		if let Some(max_length) = resp.comment_allowed {
			ensure!(comment.len() <= max_length as usize, "lnurl-pay comment too long");
		}
	}
	let symbol = if resp.callback.contains('?') { "&" } else { "?" };
	let url = match comment {
		Some(comment) => format!(
			"{}{}amount={}&comment={}", resp.callback, symbol, amount_msats, comment,
		),
		None => format!("{}{}amount={}", resp.callback, symbol, amount_msats),
	};
	let body = lnurl_get(&url, LNURL_TIMEOUT, wallet_proxy).await
		.context("failed to fetch invoice from lnurlpay")?;
	let invoice: lnurllib::pay::LnURLPayInvoice = serde_json::from_slice(&body)
		.context("invalid lnurlpay invoice response")?;
	// LUD-06: the invoice amount must equal the requested amount.
	invoice.verify_amount(amount_msats).context("lnurlpay invoice amount mismatch")?;
	Ok((resp, invoice.pr))
}

/// wasm32 counterpart of the native lnurl_pay_resolve. WEAKER THAN THE
/// NATIVE PATH.
///
/// The fetch still goes through lnurl-rs because reqwest's wasm builder
/// exposes no timeout/redirect/proxy controls: on wasm32 lnurl-rs 0.10
/// honors neither `Builder::timeout` nor `Builder::proxy` (they are only
/// applied on native targets), payee response bodies are buffered
/// unbounded, and cross-origin redirects are followed by the browser's own
/// fetch machinery (which does mediate mixed content and cross-origin
/// requests per browser policy). What is enforced on every target,
/// including this one, is the destination policy in
/// [`validate_lnurl_destination`] for both the initial URL and the
/// payee-chosen callback. Do not widen the doc language of the callers
/// beyond this.
#[cfg(target_arch = "wasm32")]
async fn lnurl_pay_resolve(
	lnurlp: &str,
	amount_msats: u64,
	comment: Option<&str>,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<(PayResponse, String)> {
	let _ = wallet_proxy;
	let client = lnurllib::Builder::default().build_async().context("lnurl client error")?;
	let resp = match client.make_request(lnurlp).await.context("failed to make lnurl request")? {
		LnUrlResponse::LnUrlPayResponse(v) => v,
		LnUrlResponse::LnUrlWithdrawResponse(_) => bail!("received lnurl withdraw"),
		LnUrlResponse::LnUrlChannelResponse(_) => bail!("received lnurl channel"),
	};
	validate_lnurl_destination(&resp.callback, wallet_proxy.is_some())?;
	let invoice = client.get_invoice(&resp, amount_msats, None, comment).await
		.context("failed to fetch invoice from lnurlpay")?;
	Ok((resp, invoice.pr))
}

/// Verifies that a BOLT11 invoice returned by an LNURL-pay endpoint
/// matches the request we made, since the endpoint is untrusted.
fn verify_lnurlp_invoice(
	invoice: &Bolt11Invoice,
	amount: Amount,
	resp: &PayResponse,
) -> anyhow::Result<()> {
	match invoice.amount_milli_satoshis() {
		Some(msat) if msat == amount.to_msat() => {},
		Some(msat) => bail!(
			"lnurl-pay endpoint returned an invoice for {} msat, \
			but we requested {} ({} msat)",
			msat, amount, amount.to_msat(),
		),
		None => bail!(
			"lnurl-pay endpoint returned an amountless invoice, \
			but we requested {}", amount,
		),
	}

	// nb this is no longer a hard requirement in LUD-06 spec
	let metadata_bound = match invoice.description() {
		Bolt11InvoiceDescriptionRef::Hash(h) => h.0.to_byte_array() == resp.metadata_hash(),
		Bolt11InvoiceDescriptionRef::Direct(_) => false,
	};
	if !metadata_bound {
		warn!("lnurl-pay invoice description hash does not commit to the endpoint metadata");
	}

	Ok(())
}

/// Performs an LNURL-Pay request against `lnurlp` and returns the BOLT11
/// invoice the endpoint issues for the requested amount.
///
/// `comment` is forwarded as the LNURL-Pay `comment` field when present; the
/// endpoint may reject or truncate it according to its own `commentAllowed`
/// limit.
///
/// `wallet_proxy` is the wallet's configured socks5h proxy
/// ([`Config::socks5_proxy`]); when set, both LNURL fetches are routed
/// through it like the wallet's other network traffic (native targets only;
/// the wasm32 fetch path cannot honor it).
///
/// Both the initial URL and the payee-chosen invoice callback are validated
/// against [`validate_lnurl_destination`] (https-only except `.onion` via
/// the proxy, no credentials, no non-public IP destinations). On native
/// targets both are then fetched with a bounded, non-redirecting client —
/// hard per-request timeout, incremental body cap before JSON decode, no
/// redirect following — before any invoice is returned. On wasm32 only the
/// destination policy is enforced: the fetch uses the browser's own
/// networking, which mediates redirects and mixed content itself but gets
/// no LNURL-specific timeout, body cap or proxy (see the wasm32
/// `lnurl_pay_resolve`).
///
/// Returns an error if the endpoint resolves to a non-pay LNURL response
/// (withdraw, channel), if a URL fails the destination policy, if the HTTP
/// request fails, if the returned bolt11 string is not a valid invoice, or
/// if the invoice's amount doesn't match the requested amount.
pub(crate) async fn lnurlp_invoice(
	lnurlp: &str,
	amount: Amount,
	comment: Option<impl AsRef<str>>,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<Bolt11Invoice> {
	validate_lnurl_destination(lnurlp, wallet_proxy.is_some())?;
	let comment = comment.as_ref().map(|s| s.as_ref());
	let (resp, invoice) = lnurl_pay_resolve(lnurlp, amount.to_msat(), comment, wallet_proxy).await?;

	let invoice: Bolt11Invoice = invoice.parse()
		.with_context(|| format!("received invalid invoice: {}", invoice))?;
	verify_lnurlp_invoice(&invoice, amount, &resp)?;

	Ok(invoice)
}

/// Resolves a Lightning Address (`user@domain`) to its LNURL-Pay endpoint and
/// returns a BOLT11 invoice issued by that endpoint for the requested amount.
///
/// Thin wrapper over [`lnurlp_invoice`]; see it for the meaning of `comment`
/// and `wallet_proxy`, and for the set of conditions under which this call
/// can fail.
pub(crate) async fn lnaddr_invoice(
	addr: &LightningAddress,
	amount: Amount,
	comment: Option<impl AsRef<str>>,
	wallet_proxy: Option<&str>,
) -> anyhow::Result<Bolt11Invoice> {
	let lnurl = addr.lnurlp_url();
	Ok(lnurlp_invoice(&lnurl, amount, comment, wallet_proxy).await?)
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use std::sync::Arc;

	#[test]
	fn lnurl_destination_policy() {
		// cleartext http is rejected for the initial url and callback alike,
		// except .onion when a proxy routes the traffic
		assert!(validate_lnurl_destination("http://example.com/lnurl", false).is_err());
		assert!(validate_lnurl_destination("http://example.com/callback", true).is_err());
		assert!(validate_lnurl_destination("http://eai6gz7zvme2x6dja5kwsu5lxnz6r5xcpacgq4vqnu4qjbd5g6ywqzad.onion/pay", false).is_err());
		assert!(validate_lnurl_destination("http://eai6gz7zvme2x6dja5kwsu5lxnz6r5xcpacgq4vqnu4qjbd5g6ywqzad.onion/pay", true).is_ok());

		// credentials embedded in the url are rejected
		assert!(validate_lnurl_destination("https://user:pass@example.com/lnurl", false).is_err());
		assert!(validate_lnurl_destination("https://user@example.com/lnurl", false).is_err());

		// loopback, private and link-local literal destinations are rejected,
		// whether a proxy is configured or not
		for url in [
			"https://127.0.0.1/callback",
			"https://10.0.0.8/internal/secrets",
			"https://192.168.1.1/",
			"https://169.254.169.254/latest/meta-data",
			"https://0.0.0.0/",
			"https://[::1]/callback",
			"https://[::]/callback",
			// IPv6 ULA and link-local literals are equally internal
			"https://[fd00::1]/internal",
			"https://[fe80::1]/",
			// IPv4-mapped IPv6 forms must not bypass the IPv4 checks
			"https://[::ffff:127.0.0.1]/callback",
			"https://[::ffff:169.254.169.254]/",
		] {
			assert!(validate_lnurl_destination(url, false).is_err(), "{url}");
			assert!(validate_lnurl_destination(url, true).is_err(), "{url}");
		}

		// public https endpoints are fine
		assert!(validate_lnurl_destination("https://example.com/lnurl", false).is_ok());
		assert!(validate_lnurl_destination("https://example.com:8443/lnurl", true).is_ok());
	}

	#[cfg(not(target_arch = "wasm32"))]
	mod http_policy {
		use std::sync::{Arc, Mutex};
		use std::time::{Duration, Instant};

		use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
		use tokio::net::TcpListener;

		use bitcoin::Amount;

		use super::super::{lnurlp_invoice, lnurl_get, LNURL_MAX_BODY, LNURL_TIMEOUT};

		struct MockServer {
			url: String,
			requests: Arc<Mutex<Vec<String>>>,
			task: tokio::task::JoinHandle<()>,
		}

		impl MockServer {
			fn requests(&self) -> Vec<String> {
				self.requests.lock().unwrap().clone()
			}
		}

		impl Drop for MockServer {
			fn drop(&mut self) {
				self.task.abort();
			}
		}

		/// Starts a loopback HTTP server that records request lines and, per
		/// connection, either replies with `(status, headers, body)` or, when
		/// the handler returns `None`, silently holds the connection open
		/// (simulating a stalled endpoint).
		async fn mock_server(
			respond: impl Fn(&str) -> Option<(u16, Vec<(String, String)>, Vec<u8>)>
				+ Send + Sync + 'static,
		) -> MockServer {
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let url = format!("http://{}", listener.local_addr().unwrap());
			let requests = Arc::new(Mutex::new(Vec::new()));
			let recorded = requests.clone();
			let respond = Arc::new(respond);
			let task = tokio::spawn(async move {
				loop {
					let (socket, _) = listener.accept().await.unwrap();
					let recorded = recorded.clone();
					let respond = respond.clone();
					tokio::spawn(async move {
						let mut socket = BufReader::new(socket);
						let mut line = String::new();
						socket.read_line(&mut line).await.unwrap();
						let request = line.trim_end().to_owned();
						recorded.lock().unwrap().push(request.clone());
						// drain the headers without inspecting them
						loop {
							line.clear();
							assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
							if line == "\r\n" {
								break;
							}
						}
						let Some((status, headers, body)) = respond(&request) else {
							// a stalled endpoint: never answer
							std::future::pending::<()>().await;
							unreachable!();
						};
						let mut head = format!(
							"HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
							status, body.len(),
						);
						for (name, value) in headers {
							head += &format!("{}: {}\r\n", name, value);
						}
						socket.write_all(head.as_bytes()).await.unwrap();
						socket.write_all(b"\r\n").await.unwrap();
						socket.write_all(&body).await.unwrap();
						socket.shutdown().await.unwrap();
					});
				}
			});
			MockServer { url, requests, task }
		}

		#[tokio::test]
		async fn lnurlp_rejects_cleartext_before_fetching() {
			let server = mock_server(|_| unreachable!("must not be contacted")).await;
			let err = lnurlp_invoice(
				&server.url, Amount::from_sat(10_000), None::<&str>, None,
			).await.unwrap_err();
			assert!(err.to_string().contains("scheme"), "err: {:#}", err);
			assert!(server.requests().is_empty());
		}

		#[tokio::test]
		async fn lnurlp_rejects_private_ip_initial_url() {
			let server = mock_server(|_| unreachable!("must not be contacted")).await;
			// the mock server itself is loopback, so this exercises the
			// private-destination rejection on the initial url
			let url = server.url.replace("http://", "https://");
			let err = lnurlp_invoice(&url, Amount::from_sat(10_000), None::<&str>, None)
				.await.unwrap_err();
			assert!(err.to_string().contains("non-public address"), "err: {:#}", err);
			assert!(server.requests().is_empty());
		}

		#[tokio::test]
		async fn lnurl_get_caps_response_body() {
			let body = vec![b' '; LNURL_MAX_BODY + 1];
			let server = mock_server(move |_| Some((200, vec![], body.clone()))).await;
			let err = lnurl_get(&server.url, LNURL_TIMEOUT, None).await.unwrap_err();
			assert!(err.to_string().contains("byte limit"), "err: {:#}", err);
		}

		#[tokio::test]
		async fn lnurl_get_accepts_response_at_limit() {
			let body = vec![b' '; LNURL_MAX_BODY];
			let server = mock_server(move |_| Some((200, vec![], body.clone()))).await;
			let received = lnurl_get(&server.url, LNURL_TIMEOUT, None).await.unwrap();
			assert_eq!(received.len(), LNURL_MAX_BODY);
		}

		#[tokio::test]
		async fn lnurl_get_times_out_stalled_endpoint() {
			let server = mock_server(|_| None).await;
			let timeout = Duration::from_millis(200);
			let start = Instant::now();
			// bound the test itself so a missing client timeout hangs loudly
			let result = tokio::time::timeout(
				Duration::from_secs(5), lnurl_get(&server.url, timeout, None),
			).await.expect("lnurl fetch hung past the client timeout");
			let err = result.unwrap_err();
			let reqwest_err = err.downcast_ref::<reqwest::Error>()
				.expect("expected an underlying reqwest error");
			assert!(reqwest_err.is_timeout(), "err: {:#}", err);
			assert!(start.elapsed() < Duration::from_secs(2));
		}

		#[tokio::test]
		async fn lnurl_get_never_follows_redirects() {
			let target = mock_server(|_| unreachable!("redirect target must not be contacted")).await;
			let location = target.url.clone();
			let server = mock_server(move |_| Some(
				(302, vec![("Location".into(), location.clone())], vec![]),
			)).await;
			let err = lnurl_get(&server.url, LNURL_TIMEOUT, None).await.unwrap_err();
			assert!(err.to_string().contains("http status 302"), "err: {:#}", err);
			assert_eq!(server.requests().len(), 1);
			assert!(target.requests().is_empty());
		}
	}

	use bitcoin::Network;
	use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice};
	use lightning_invoice::Bolt11Invoice;
	use lnurllib::Tag;

	use crate::{Config, OpenWalletArgs, Wallet, WalletSeed};
	use crate::lock_manager::memory::MemoryLockManager;
	use crate::persist::adaptor::StorageAdaptorWrapper;

	use super::*;

	/// A known-valid BOLT11 invoice on signet for 100u (10,000 sat).
	const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

	fn dummy_pay_response() -> PayResponse {
		PayResponse {
			callback: "https://example.com/callback".into(),
			max_sendable: 100_000_000_000,
			min_sendable: 1_000,
			tag: Tag::PayRequest,
			metadata: "[[\"text/plain\",\"test\"]]".into(),
			comment_allowed: None,
			allows_nostr: None,
			nostr_pubkey: None,
		}
	}

	#[test]
	fn lnurlp_invoice_amount_verification() {
		let invoice = Bolt11Invoice::from_str(TEST_INVOICE_STR).unwrap();
		let resp = dummy_pay_response();

		// the invoice is for exactly 10,000 sat
		verify_lnurlp_invoice(&invoice, Amount::from_sat(10_000), &resp).unwrap();

		// an invoice for any other amount must be rejected
		let err = verify_lnurlp_invoice(&invoice, Amount::from_sat(9_000), &resp).unwrap_err();
		assert!(err.to_string().contains("10000000 msat"), "err: {}", err);
		verify_lnurlp_invoice(&invoice, Amount::from_sat(11_000), &resp).unwrap_err();
	}

	#[allow(unused)] // just exists for compile check
	async fn pay_lightning_invoice_argument() {
		//! Check the different possible argument for pay_lightning_invoice

		let db = Arc::new(StorageAdaptorWrapper::new_memory());
		let w = Wallet::open(
			Network::Regtest,
			WalletSeed::new_from_seed(Network::Regtest, &[1; 64]),
			Config::network_default(Network::Regtest),
			OpenWalletArgs {
				lock_manager: Some(Box::new(MemoryLockManager::new())),
				persister: Some(db),
				..Default::default()
			},
		).await.unwrap();

		let bolt11 = Bolt11Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt11, None, false).await.unwrap();

		let bolt12 = Bolt12Invoice::from_str("").unwrap();
		w.pay_lightning_invoice(bolt12, None, false).await.unwrap();

		let string = format!("lnbc1..");
		w.pay_lightning_invoice(string, None, false).await.unwrap();

		let strr = "lnbc1..";
		w.pay_lightning_invoice(strr, None, false).await.unwrap();

		let invoice = Invoice::Bolt11("".parse().unwrap());
		w.pay_lightning_invoice(invoice, None, false).await.unwrap();
	}
}
