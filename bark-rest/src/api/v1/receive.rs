//! Public, receiving-only API. This router is mounted on its own listener, not
//! on the administrative API. Possession of an address does not grant spending,
//! balance, mnemonic, or arbitrary-message signing authority.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tower_http::cors::{Any, CorsLayer};
use utoipa::{OpenApi, ToSchema};

use bark::sapio::receive::{
	ProgramReceiveCommit, ProgramReceiveReceipt, ProgramReceiveRequest,
	MAX_RECEIVE_BODY_BYTES, RECEIVE_TIMEOUT,
};

use crate::ServerState;

// Admission precedes JSON extraction. Busy requests fail rather than joining an
// unbounded queue; the deadline also bounds slow request-body uploads.
static ADMISSION: Semaphore = Semaphore::const_new(4);

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiveRequest {
	/// Coordinated Ark address advertised by the recipient.
	pub address: String,
	/// Canonical full VTXO protocol encodings, as hex. Maximum 16 per request.
	pub vtxos: Vec<String>,
}

impl From<ReceiveRequest> for ProgramReceiveRequest {
	fn from(request: ReceiveRequest) -> Self {
		Self { address: request.address, vtxos: request.vtxos }
	}
}

#[derive(OpenApi)]
#[openapi(
	paths(prepare, commit),
	components(schemas(ReceiveRequest)),
	tags((name = "program-receive", description = "Coordinated receiving on the dedicated receiving-only listener.")),
)]
pub struct ReceiveApiDoc;

pub fn router() -> Router<Arc<ServerState>> {
	Router::new()
		.route("/prepare", post(prepare))
		.route("/commit", post(commit))
		.layer(DefaultBodyLimit::max(MAX_RECEIVE_BODY_BYTES))
		.layer(middleware::from_fn(admit))
		// Browser senders use public receive authority, never cookies or a bearer
		// token. This CORS policy exists only on the receiving-only listener.
		.layer(CorsLayer::new().allow_origin(Any)
			.allow_methods([Method::POST]).allow_headers([header::CONTENT_TYPE]))
}

async fn admit(request: Request<Body>, next: Next) -> Response {
	let Ok(_permit) = ADMISSION.try_acquire() else {
		return (StatusCode::TOO_MANY_REQUESTS, "receive coordinator is busy").into_response();
	};
	match tokio::time::timeout(RECEIVE_TIMEOUT, next.run(request)).await {
		Ok(response) => response,
		Err(_) => (StatusCode::REQUEST_TIMEOUT, "receive request timed out; retry the same bytes").into_response(),
	}
}

// Public callers do not receive internal database, chain-source or Sapio error
// details. The operator gets the error; the sender gets an unambiguous rejection.
fn rejected(error: anyhow::Error) -> Response {
	log::warn!("Program receive rejected: {:#}", error);
	(StatusCode::UNPROCESSABLE_ENTITY, "program receive rejected; no acknowledgement issued").into_response()
}

#[utoipa::path(
	post,
	path = "/prepare",
	summary = "Prepare a program receive",
	description = "Validates unsigned candidate VTXOs for a stored program address and durably saves authorized recovery claims. Returns a versioned receipt with address, candidate encodings, ProgramKey descriptor, recovery records and a U signature. The sender must verify the descriptor aggregates U and S to the address key, each claim, and the receipt signature before it signs its inputs. Requests are limited to 1 MiB and 16 VTXOs. Each address admits at most 128 distinct prepared outputs. This endpoint exists only on the configured receiving-only listener; it does not grant administrative authority.",
	request_body = ReceiveRequest,
	security(),
	responses(
		(status = 200, description = "Cryptographically bound durable preparation receipt", body = Object),
		(status = 408, description = "Request timed out; retry identical candidates"),
		(status = 413, description = "Request body too large"),
		(status = 422, description = "Preparation rejected"),
		(status = 429, description = "Coordinator busy"),
	),
	tag = "program-receive",
)]
pub async fn prepare(State(state): State<Arc<ServerState>>, Json(body): Json<ReceiveRequest>) -> Response {
	let wallet = match state.require_wallet() {
		Ok(wallet) => wallet,
		Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "receive wallet unavailable").into_response(),
	};
	match wallet.prepare_program_receive(body.into()).await {
		Ok(receipt) => bounded_receipt::<ProgramReceiveReceipt>(&receipt),
		Err(error) => rejected(error),
	}
}

#[utoipa::path(
	post,
	path = "/commit",
	summary = "Commit a program receive",
	description = "Accepts only complete signed VTXOs whose exact recovery claims were already prepared. Verifies the complete chain, durably merges signed ancestors, and stores the received position before it acknowledges delivery. Returns a U-signed acknowledgement over the final signed VTXO bytes. The sender must checkpoint those bytes before calling this endpoint and must retry exactly those bytes after interruption. No new Sapio signature is requested. Requests are limited to 1 MiB and 16 VTXOs. This endpoint exists only on the configured receiving-only listener.",
	request_body = ReceiveRequest,
	security(),
	responses(
		(status = 200, description = "Signed durable delivery acknowledgement", body = Object),
		(status = 408, description = "Request timed out; retry identical signed VTXOs"),
		(status = 413, description = "Request body too large"),
		(status = 422, description = "Commit rejected; keep the sender checkpoint"),
		(status = 429, description = "Coordinator busy"),
	),
	tag = "program-receive",
)]
pub async fn commit(State(state): State<Arc<ServerState>>, Json(body): Json<ReceiveRequest>) -> Response {
	let wallet = match state.require_wallet() {
		Ok(wallet) => wallet,
		Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "receive wallet unavailable").into_response(),
	};
	match wallet.commit_program_receive(body.into()).await {
		Ok(receipt) => bounded_receipt::<ProgramReceiveCommit>(&receipt),
		Err(error) => rejected(error),
	}
}

fn bounded_receipt<T: serde::Serialize>(receipt: &T) -> Response {
	match serde_json::to_vec(receipt) {
		Ok(bytes) if bytes.len() <= MAX_RECEIVE_BODY_BYTES => (
			[(axum::http::header::CONTENT_TYPE, "application/json")], bytes,
		).into_response(),
		_ => (StatusCode::UNPROCESSABLE_ENTITY, "receive receipt exceeds the response limit").into_response(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tower::Service;
	use tokio_util::sync::CancellationToken;

	#[tokio::test]
	async fn receive_listener_never_mounts_administrative_authority() {
		// No bearer token is configured. Unlike the administrative router, this
		// public router still has no route to wallet or signing authority.
		let state = Arc::new(ServerState::builder().build(CancellationToken::new()));
		let mut public = Router::new()
			.nest("/api/v1/receive/program", router())
			.with_state(state);
		for path in [
			"/api/v1/wallet/balance", "/api/v1/wallet/mnemonic",
			"/api/v1/message/sign", "/api/v1/onchain/send",
		] {
			let response = public.call(Request::builder().method("POST").uri(path)
				.body(Body::empty()).unwrap()).await.unwrap();
			assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
		}
	}

	#[tokio::test]
	async fn receive_listener_bounds_untrusted_bodies_before_wallet_access() {
		let state = Arc::new(ServerState::builder().build(CancellationToken::new()));
		let mut public = router().with_state(state);
		let response = public.call(Request::builder().method("POST").uri("/prepare")
			.header("content-type", "application/json")
			.body(Body::from(vec![b' '; MAX_RECEIVE_BODY_BYTES + 1])).unwrap()).await.unwrap();
		assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
	}

	#[tokio::test]
	async fn browser_receives_allow_public_json_without_credentials() {
		let state = Arc::new(ServerState::builder().build(CancellationToken::new()));
		let mut public = router().with_state(state);
		let response = public.call(Request::builder().method("OPTIONS").uri("/prepare")
			.header(header::ORIGIN, "https://sender.example")
			.header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
			.header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
			.body(Body::empty()).unwrap()).await.unwrap();
		assert!(response.status().is_success());
		assert_eq!(response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
		assert!(!response.headers().contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
	}
}
