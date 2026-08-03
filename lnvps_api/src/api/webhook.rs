use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::routing::any;
use futures::StreamExt;
use payments_rs::webhook::{WEBHOOK_BRIDGE, WebhookMessage};
use std::collections::HashMap;
use tower_http::limit::RequestBodyLimitLayer;

use crate::api::RouterState;

/// Largest webhook body we will buffer, in bytes.
///
/// Payment-provider webhooks are small JSON documents (a few KB at most). The
/// handler consumes the raw request body, which bypasses axum's
/// `DefaultBodyLimit` (that only applies to body *extractors*), so without an
/// explicit cap an unauthenticated caller could stream an unbounded body
/// straight into memory. 256 KB is orders of magnitude above any real payload.
const MAX_WEBHOOK_BODY: usize = 256 * 1024;

pub fn router() -> Router<RouterState> {
    let mut router = Router::new();

    #[cfg(feature = "bitvora")]
    {
        router = router.route("/api/v1/webhook/bitvora", any(send_webhook));
    }

    #[cfg(feature = "revolut")]
    {
        router = router.route("/api/v1/webhook/revolut", any(send_webhook));
    }

    #[cfg(feature = "stripe")]
    {
        router = router.route("/api/v1/webhook/stripe", any(send_webhook));
    }

    // Belt and braces: the layer rejects an oversized body before it reaches the
    // handler (and caps the stream the handler reads), while the handler keeps
    // its own accounting so the limit holds even if the layer is ever dropped.
    router.layer(RequestBodyLimitLayer::new(MAX_WEBHOOK_BODY))
}

/// Collect a header map into the `(name, value)` pairs the webhook bridge wants.
///
/// A header value that is not valid UTF-8 is lossily converted rather than
/// unwrapped: hyper accepts `obs-text` bytes (`0x80..=0xFF`) in header values,
/// so `HeaderValue::to_str` fails on input an unauthenticated caller fully
/// controls. This used to `unwrap()`, which panicked the handler — and, under
/// the release profile's `panic = "abort"`, took the whole process down.
fn collect_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

async fn send_webhook(req: Request) -> StatusCode {
    let mut msg = WebhookMessage {
        endpoint: req.uri().path().to_string(),
        body: Vec::new(),
        headers: collect_headers(req.headers()),
    };

    let mut s = req.into_body().into_data_stream();
    while let Some(chunk) = s.next().await {
        let Ok(chunk) = chunk else {
            // A read error (including the body-limit layer tripping) means we
            // never saw the whole payload. Forwarding a truncated body would
            // only fail signature verification downstream, so drop it here.
            return StatusCode::BAD_REQUEST;
        };
        if msg.body.len() + chunk.len() > MAX_WEBHOOK_BODY {
            return StatusCode::PAYLOAD_TOO_LARGE;
        }
        msg.body.extend_from_slice(&chunk);
    }

    WEBHOOK_BRIDGE.send(msg);
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    /// Regression (F-01): a header value carrying a non-UTF-8 `obs-text` byte
    /// must not panic. `HeaderValue::to_str()` returns `Err` for these, and the
    /// previous `.unwrap()` aborted the process under `panic = "abort"`.
    #[test]
    fn non_utf8_header_value_does_not_panic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-evil"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );

        let collected = collect_headers(&headers);

        assert_eq!(collected.len(), 1);
        // Lossy conversion yields replacement characters rather than panicking.
        assert!(collected["x-evil"].contains('\u{fffd}'));
    }

    /// Ordinary ASCII header values still round-trip unchanged.
    #[test]
    fn ascii_header_values_round_trip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("stripe-signature"),
            HeaderValue::from_static("t=1,v1=abc"),
        );

        assert_eq!(
            collect_headers(&headers),
            HashMap::from([("stripe-signature".to_string(), "t=1,v1=abc".to_string())])
        );
    }
}
