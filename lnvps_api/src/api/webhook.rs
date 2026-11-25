use crate::payments::gateway::handle_gateway_event;
use axum::Router;
use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::routing::{any, post};
use futures::StreamExt;
use lnvps_api_common::{GATEWAY_WEBHOOK_PATH, parse_gateway_event, parse_gateway_event_with};
use log::{error, warn};
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
    let mut router = Router::new().route(GATEWAY_WEBHOOK_PATH, post(gateway_webhook));

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

pub(crate) async fn verify_gateway_webhook(
    state: &RouterState,
    body: &[u8],
    signature: Option<&str>,
) -> anyhow::Result<Option<lnvps_api_common::GatewayEvent>> {
    let rows: Vec<_> = state
        .db
        .list_payment_method_configs()
        .await?
        .iter()
        .filter_map(lnvps_api_common::gateway_row)
        .collect();
    if !rows.is_empty() {
        let mut last_err = None;
        for row in rows.iter() {
            match parse_gateway_event_with(
                body,
                signature,
                &row.config.webhook_secret,
                row.config.tolerance_seconds,
            ) {
                Ok(e) => return Ok(Some(e)),
                Err(e) => last_err = Some(e),
            }
        }
        return match last_err {
            Some(e) => Err(e),
            None => Ok(None),
        };
    }
    match state.settings.gateway.as_ref() {
        Some(config) => Ok(Some(parse_gateway_event(body, signature, config)?)),
        None => Ok(None),
    }
}

async fn gateway_webhook(
    State(state): State<RouterState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let signature = headers
        .get(payment_gateway_client::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok());
    let event = match verify_gateway_webhook(&state, &body, signature).await {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(e) => {
            warn!("{}", e);
            return StatusCode::UNAUTHORIZED;
        }
    };
    match handle_gateway_event(&state.db, &state.sub_handler, &event).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            error!("gateway event {} failed: {}", event.event_id, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
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
    use lnvps_api_common::{MockDb, MockExchangeRate, VatClient};
    use lnvps_db::{
        GatewayOffSession, GatewayProviderConfig, LNVpsDb, LNVpsDbBase, PaymentMethod,
        PaymentMethodConfig, ProviderConfig,
    };
    use std::sync::Arc;

    async fn webhook_state(db: Arc<MockDb>, yaml_secret: Option<&str>) -> RouterState {
        use crate::mocks::{MockNode, MockOnChainProvider};
        let rates = Arc::new(MockExchangeRate::new());
        let commander: Arc<dyn lnvps_api_common::WorkCommander> =
            Arc::new(lnvps_api_common::ChannelWorkCommander::new());
        let sub_handler = crate::subscription::SubscriptionHandler::new(
            crate::settings::mock_settings(),
            db.clone(),
            Arc::new(MockNode::default()),
            Arc::new(MockOnChainProvider::default()),
            None,
            rates.clone(),
            VatClient::new(),
            commander.clone(),
            lnvps_api_common::VmStateCache::new(),
        )
        .unwrap();
        let mut settings = crate::settings::mock_settings();
        settings.gateway = yaml_secret.map(|s| lnvps_api_common::GatewayConfig {
            url: "http://yaml".into(),
            api_key: "k".into(),
            webhook_secret: s.into(),
            methods: vec![],
            webhook_tolerance_seconds: 0,
            off_session_renewals: Default::default(),
        });
        RouterState {
            db: db.clone(),
            state: lnvps_api_common::VmStateCache::new(),
            sub_handler,
            history: lnvps_api_common::VmHistoryLogger::new(db),
            settings,
            rates,
            work_sender: commander,
            feedback: None,
            geoip: None,
            screener: None,
        }
    }

    fn row(company: u64, secret: &str, enabled: bool) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(
            company,
            PaymentMethod::Gateway,
            "Gateway".into(),
            enabled,
            ProviderConfig::Gateway(GatewayProviderConfig {
                url: "http://gw".into(),
                api_key: "k".into(),
                webhook_secret: secret.into(),
                tolerance_seconds: 0,
                off_session_renewals: GatewayOffSession::Off,
                handles: vec![PaymentMethod::Lightning],
            }),
        )
    }

    const BODY: &str = r#"{"id":"e1","type":"payment.paid","data":{"payment":{"reference":"ab","status":"paid"}}}"#;

    fn signed(secret: &str) -> String {
        format!(
            "t=1700000000,v1={}",
            payment_gateway_client::sign_webhook(BODY.as_bytes(), secret, 1700000000)
        )
    }

    #[tokio::test]
    async fn webhook_is_verified_with_the_secret_of_the_enabled_row() {
        let db = Arc::new(MockDb::default());
        db.insert_payment_method_config(&row(1, "row-secret", true))
            .await
            .unwrap();
        let state = webhook_state(db, Some("yaml-secret")).await;

        let event = verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("row-secret")))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event.kind, "payment.paid");
    }

    #[tokio::test]
    async fn webhook_with_a_wrong_secret_is_refused() {
        let db = Arc::new(MockDb::default());
        db.insert_payment_method_config(&row(1, "row-secret", true))
            .await
            .unwrap();
        let state = webhook_state(db, None).await;

        let res = verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("wrong"))).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn yaml_secret_is_not_accepted_once_a_row_exists() {
        let db = Arc::new(MockDb::default());
        db.insert_payment_method_config(&row(1, "row-secret", true))
            .await
            .unwrap();
        let state = webhook_state(db, Some("yaml-secret")).await;

        let res =
            verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("yaml-secret"))).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn webhook_falls_back_to_the_yaml_secret_without_a_row() {
        let db = Arc::new(MockDb::default());
        let state = webhook_state(db, Some("yaml-secret")).await;

        let ok = verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("yaml-secret")))
            .await
            .unwrap();

        assert!(ok.is_some());
    }

    #[tokio::test]
    async fn webhook_is_not_found_with_no_row_and_no_yaml() {
        let db = Arc::new(MockDb::default());
        let state = webhook_state(db, None).await;

        let res = verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("x")))
            .await
            .unwrap();

        assert!(res.is_none());
    }

    #[tokio::test]
    async fn webhook_still_verifies_with_a_disabled_row_so_in_flight_payments_settle() {
        let db = Arc::new(MockDb::default());
        db.insert_payment_method_config(&row(1, "row-secret", false))
            .await
            .unwrap();
        let state = webhook_state(db, Some("yaml-secret")).await;

        let ok = verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("row-secret")))
            .await
            .unwrap();
        let bad =
            verify_gateway_webhook(&state, BODY.as_bytes(), Some(&signed("yaml-secret"))).await;

        assert!(ok.is_some());
        assert!(bad.is_err());
    }

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
