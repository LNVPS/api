//! The inbound control API: HTTPS, bound to the tunnel address, every request
//! authenticated with NIP-98 against the LNVPS key compiled into the binary.
//!
//! Decision 13 says the tunnel is not by itself a trust boundary — guests can
//! route to the node's tunnel address — so there are two independent defences,
//! and neither is documentation:
//!
//! 1. The listener binds **only** the tunnel interface address, checked against
//!    the interface's real addresses at startup ([`crate::config`]).
//! 2. Every request is authenticated ([`crate::control_auth`]). The middleware
//!    is layered over the whole router rather than per-route, so a route added
//!    later cannot forget it. The tests prove this by hitting a path that does
//!    not exist and getting 401 rather than 404.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::{Body, to_bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use nostr::PublicKey;
use serde::Serialize;

use crate::control_auth::{self, ReplayGuard};
use crate::tls::NodeTls;

/// Commands are small JSON documents. Anything larger is not a command this
/// node knows how to run, and should not be read into memory before deciding
/// that.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// How long a used request id is remembered. Must exceed the clock window, or
/// a request could age out of the replay cache while still inside the window
/// that makes it acceptable.
const REPLAY_WINDOW: Duration = Duration::from_secs(600);

/// Bound on the replay cache, so a flood of signed requests cannot grow it
/// without limit. Only LNVPS can add entries, but a bug on their side should
/// not be able to exhaust a node's memory.
const REPLAY_CAPACITY: usize = 10_000;

/// Shared control-plane state.
pub struct ControlState {
    /// The only key permitted to command this node.
    pub control_pubkey: PublicKey,
    /// Seen request ids, so a captured request cannot be run twice.
    pub replay: Mutex<ReplayGuard>,
    /// The node's own base URL (`https://<tunnel-ip>:<port>`).
    ///
    /// Deliberately **not** derived from the `Host` header. The NIP-98 `u` tag
    /// is compared against this, so a request signed for one node cannot be
    /// replayed against another by setting `Host` to the first node's address.
    pub base_url: String,
}

impl ControlState {
    /// Build state for a node serving on `addr`.
    pub fn new(control_pubkey: PublicKey, addr: SocketAddr) -> Self {
        Self {
            control_pubkey,
            replay: Mutex::new(ReplayGuard::new(REPLAY_WINDOW, REPLAY_CAPACITY)),
            base_url: format!("https://{addr}"),
        }
    }
}

/// What the node reports about itself.
#[derive(Debug, Serialize)]
pub struct NodeStatus {
    /// Daemon version, so LNVPS can tell what a node is running.
    pub version: &'static str,
    /// Host inventory, the same view `lnvps-node inventory` prints.
    pub inventory: crate::inventory::Inventory,
}

/// The control router, with authentication layered over everything.
pub fn router(state: Arc<ControlState>) -> Router {
    Router::new()
        .route("/api/v1/status", get(get_status))
        // Order matters: the body limit is outermost so an oversized body is
        // rejected before authentication reads it into memory.
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Serve the control API over HTTPS until the process exits.
pub async fn serve(state: Arc<ControlState>, addr: SocketAddr, tls: NodeTls) -> Result<()> {
    // rustls needs a process-wide crypto provider; installing twice is not an
    // error worth failing a startup over.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem, tls.key_pem)
        .await
        .context("Control API TLS configuration is invalid")?;

    log::info!(
        "Control API listening on https://{addr} (certificate fingerprint {})",
        tls.fingerprint
    );
    axum_server::bind_rustls(addr, cfg)
        .serve(router(state).into_make_service())
        .await
        .context("Control API server stopped")
}

/// Reject anything not signed by LNVPS for exactly this request.
///
/// The body is buffered so its hash can be bound into the signature check, then
/// handed on to the handler unchanged.
async fn authenticate(
    State(state): State<Arc<ControlState>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return unauthorized("Request body could not be read"),
    };

    // Built from the node's own address, never from the request's Host header.
    let url = format!("{}{}", state.base_url, parts.uri.path());
    let verified = {
        let mut replay = match state.replay.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        control_auth::verify(
            &control_auth::Request {
                authorization: &authorization,
                url: &url,
                method: parts.method.as_str(),
                body: &bytes,
            },
            &state.control_pubkey,
            &mut replay,
            control_auth::now_unix(),
        )
    };

    match verified {
        Ok(id) => {
            log::debug!("Control request {} {} authorised ({id})", parts.method, url);
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Err(e) => {
            // Logged at warn: on a healthy node every control request is from
            // LNVPS and valid, so a failure is either a bug or someone probing.
            log::warn!("Rejected control request {} {url}: {e:#}", parts.method);
            unauthorized(&format!("{e:#}"))
        }
    }
}

fn unauthorized(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": reason })),
    )
        .into_response()
}

/// Report what this node is and what it is running.
async fn get_status() -> Json<NodeStatus> {
    Json(NodeStatus {
        version: env!("CARGO_PKG_VERSION"),
        inventory: crate::inventory::Inventory::collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request as HttpRequest};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use nostr::{EventBuilder, Keys, Kind, Tag, TagKind};
    use tower::ServiceExt;

    const ADDR: &str = "10.66.0.7:8890";

    fn state_for(keys: &Keys, addr: &str) -> Arc<ControlState> {
        Arc::new(ControlState::new(keys.public_key(), addr.parse().unwrap()))
    }

    /// A NIP-98 header, with every field overridable so tests can tamper with
    /// exactly one thing at a time.
    fn auth_header(keys: &Keys, url: &str, method: &str, body: &[u8]) -> String {
        let mut tags = vec![
            Tag::custom(TagKind::custom("u"), [url.to_string()]),
            Tag::custom(TagKind::custom("method"), [method.to_string()]),
        ];
        if !body.is_empty() {
            tags.push(Tag::custom(
                TagKind::custom("payload"),
                [control_auth::sha256_hex(body)],
            ));
        }
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap();
        format!(
            "Nostr {}",
            BASE64.encode(serde_json::to_vec(&event).unwrap())
        )
    }

    fn get(path: &str, auth: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::builder().method(Method::GET).uri(path);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        b.body(Body::empty()).unwrap()
    }

    async fn status_of(state: Arc<ControlState>, req: HttpRequest<Body>) -> StatusCode {
        router(state).oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_signed_request_from_lnvps_is_served() {
        let keys = Keys::generate();
        let url = format!("https://{ADDR}/api/v1/status");
        let auth = auth_header(&keys, &url, "GET", b"");

        let code = status_of(state_for(&keys, ADDR), get("/api/v1/status", Some(&auth))).await;
        assert_eq!(code, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unsigned_request_is_refused() {
        let keys = Keys::generate();
        let code = status_of(state_for(&keys, ADDR), get("/api/v1/status", None)).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    /// A guest on this machine can reach the tunnel address (decision 13). It
    /// holds no LNVPS key, and that must be the end of it.
    #[tokio::test]
    async fn a_request_signed_by_anyone_else_is_refused() {
        let lnvps = Keys::generate();
        let attacker = Keys::generate();
        let url = format!("https://{ADDR}/api/v1/status");
        let auth = auth_header(&attacker, &url, "GET", b"");

        let code = status_of(state_for(&lnvps, ADDR), get("/api/v1/status", Some(&auth))).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    /// The `u` tag is checked against the node's own address, not the Host
    /// header. Otherwise a request captured from node A could be sent to node B
    /// with `Host: <node A>`, and node B would authorise it.
    #[tokio::test]
    async fn a_request_for_another_node_is_refused_here() {
        let keys = Keys::generate();
        let other_node = "10.66.0.9:8890";
        let signed_for_other = auth_header(
            &keys,
            &format!("https://{other_node}/api/v1/status"),
            "GET",
            b"",
        );

        // Same operator key, same path, and the attacker sets Host to the node
        // the request was signed for.
        let mut req = get("/api/v1/status", Some(&signed_for_other));
        req.headers_mut()
            .insert(header::HOST, other_node.parse().unwrap());

        let code = status_of(state_for(&keys, ADDR), req).await;
        assert_eq!(
            code,
            StatusCode::UNAUTHORIZED,
            "a request signed for {other_node} must not be accepted by {ADDR}"
        );
    }

    /// Signed for one path, sent to another.
    #[tokio::test]
    async fn a_request_signed_for_a_different_path_is_refused() {
        let keys = Keys::generate();
        let auth = auth_header(
            &keys,
            &format!("https://{ADDR}/api/v1/harmless"),
            "GET",
            b"",
        );
        let code = status_of(state_for(&keys, ADDR), get("/api/v1/status", Some(&auth))).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_replayed_request_is_refused() {
        let keys = Keys::generate();
        let state = state_for(&keys, ADDR);
        let auth = auth_header(&keys, &format!("https://{ADDR}/api/v1/status"), "GET", b"");

        let first = status_of(state.clone(), get("/api/v1/status", Some(&auth))).await;
        let second = status_of(state, get("/api/v1/status", Some(&auth))).await;

        assert_eq!(first, StatusCode::OK);
        assert_eq!(
            second,
            StatusCode::UNAUTHORIZED,
            "the same signed request must not run twice"
        );
    }

    /// The single most valuable test here: authentication is layered over the
    /// router, not attached per route, so a route added tomorrow is covered
    /// without anyone remembering to cover it. An unknown path returning 401
    /// rather than 404 is what demonstrates that.
    #[tokio::test]
    async fn authentication_covers_paths_that_do_not_exist_yet() {
        let keys = Keys::generate();
        let code = status_of(state_for(&keys, ADDR), get("/api/v1/vm/1/destroy", None)).await;
        assert_eq!(
            code,
            StatusCode::UNAUTHORIZED,
            "an unauthenticated request reached routing; a future route would be exposed"
        );
    }

    #[tokio::test]
    async fn the_status_report_names_the_daemon_version() {
        let keys = Keys::generate();
        let url = format!("https://{ADDR}/api/v1/status");
        let auth = auth_header(&keys, &url, "GET", b"");

        let response = router(state_for(&keys, ADDR))
            .oneshot(get("/api/v1/status", Some(&auth)))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
        assert!(json["inventory"]["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(
            !json["inventory"]["cpu"]["arch"]
                .as_str()
                .unwrap()
                .is_empty()
        );
    }

    /// A rejection must say why, or a node that stops accepting commands is
    /// debugged by guesswork.
    #[tokio::test]
    async fn a_rejection_explains_itself() {
        let keys = Keys::generate();
        let response = router(state_for(&keys, ADDR))
            .oneshot(get("/api/v1/status", None))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json["error"].as_str().unwrap().contains("Nostr scheme"),
            "unhelpful rejection: {json}"
        );
    }

    /// The base URL is the node's own address, which is what makes the cross
    /// node replay test above meaningful.
    #[test]
    fn state_takes_its_base_url_from_its_own_address() {
        let keys = Keys::generate();
        assert_eq!(state_for(&keys, ADDR).base_url, format!("https://{ADDR}"));
    }

    /// The replay cache must outlive the window in which a request is still
    /// considered fresh, or a request could age out of the cache and be
    /// accepted a second time.
    #[test]
    fn the_replay_window_outlives_the_clock_window() {
        assert!(
            REPLAY_WINDOW > control_auth::MAX_CLOCK_SKEW,
            "a request could leave the replay cache while still inside the clock window"
        );
    }
}
