//! Control-API tests: exercise the router via `tower::oneshot` (no TLS / no
//! network / no root), covering auth, the rules round-trip, event polling, and
//! the unauthenticated dashboard.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{StatusCode, header};
use http_body_util::BodyExt;
use lnvps_fw_service::api::{
    Event, EventKind, EventsResponse, LearnedPort, Override, PortsPage, RuleSet, SharedState,
    Status, router,
};
use tower::ServiceExt;

fn state() -> Arc<SharedState> {
    SharedState::new(
        "tok".into(),
        vec![],
        vec!["eth0".into()],
        RuleSet::default(),
        16,
    )
}

fn req(
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<String>,
) -> axum::http::Request<Body> {
    let mut b = axum::http::Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = match body {
        Some(s) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(s)
        }
        None => Body::empty(),
    };
    b.body(body).unwrap()
}

async fn body_json<T: serde::de::DeserializeOwned>(res: axum::response::Response) -> T {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn rejects_missing_or_wrong_token() {
    let app = router(state());
    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/status", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = app
        .oneshot(req("GET", "/api/v1/status", Some("nope"), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_ok_with_token() {
    let res = router(state())
        .oneshot(req("GET", "/api/v1/status", Some("tok"), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let st: Status = body_json(res).await;
    assert_eq!(st.interfaces, vec!["eth0".to_string()]);
}

#[tokio::test]
async fn rules_round_trip_and_bad_cidr_rejected() {
    let st = state();
    let app = router(st.clone());
    let good = serde_json::to_string(&RuleSet {
        protected: vec!["203.0.113.0/24".into()],
        overrides: vec![Override {
            cidr: "10.0.0.5/32".into(),
            flags: 1,
        }],
    })
    .unwrap();
    let res = app
        .clone()
        .oneshot(req("PUT", "/api/v1/rules", Some("tok"), Some(good)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(st.rules_version() > 1, "version bumped on push");

    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/rules", Some("tok"), None))
        .await
        .unwrap();
    let rs: RuleSet = body_json(res).await;
    assert_eq!(rs.protected, vec!["203.0.113.0/24".to_string()]);
    assert_eq!(rs.overrides.len(), 1);

    // Malformed CIDR is rejected.
    let bad = r#"{"protected":["not-a-cidr"],"overrides":[]}"#.to_string();
    let res = app
        .oneshot(req("PUT", "/api/v1/rules", Some("tok"), Some(bad)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn manual_override_add_and_delete() {
    let st = state();
    let app = router(st.clone());
    let ov = r#"{"cidr":"192.0.2.9/32","flags":3}"#.to_string();
    let res = app
        .clone()
        .oneshot(req("POST", "/api/v1/mitigations", Some("tok"), Some(ov)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(st.rules().overrides.len(), 1);

    let res = app
        .clone()
        .oneshot(req(
            "DELETE",
            "/api/v1/mitigations?cidr=192.0.2.9/32",
            Some("tok"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(st.rules().overrides.is_empty());

    // Deleting again -> 404.
    let res = app
        .oneshot(req(
            "DELETE",
            "/api/v1/mitigations?cidr=192.0.2.9/32",
            Some("tok"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_poll_incrementally() {
    let st = state();
    let app = router(st.clone());
    st.record_event(EventKind::Start, "203.0.113.0/24".into(), 1, 100, 200, 5);
    st.record_event(EventKind::Stop, "203.0.113.0/24".into(), 1, 0, 0, 0);

    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/events?since=0", Some("tok"), None))
        .await
        .unwrap();
    let ev: EventsResponse = body_json(res).await;
    assert_eq!(ev.events.len(), 2);
    assert_eq!(ev.cursor, 2);
    let first: &Event = &ev.events[0];
    assert_eq!(first.kind, EventKind::Start);

    // Poll from the returned cursor -> nothing new.
    let res = app
        .oneshot(req("GET", "/api/v1/events?since=2", Some("tok"), None))
        .await
        .unwrap();
    let ev: EventsResponse = body_json(res).await;
    assert!(ev.events.is_empty());
}

#[tokio::test]
async fn learned_ports_endpoint() {
    let st = state();
    let app = router(st.clone());
    st.set_ports(vec![
        LearnedPort {
            ip: "185.18.221.87".into(),
            port: 443,
            proto: "tcp".into(),
            age_secs: 5,
        },
        LearnedPort {
            ip: "185.18.221.140".into(),
            port: 51820,
            proto: "udp".into(),
            age_secs: 12,
        },
    ]);
    // Paginated: limit=1 returns 1 of 2, with total.
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            "/api/v1/ports?offset=0&limit=1",
            Some("tok"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let page: PortsPage = body_json(res).await;
    assert_eq!(page.total, 2);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].port, 443);

    // Filter by proto.
    let res = app
        .oneshot(req("GET", "/api/v1/ports?q=udp", Some("tok"), None))
        .await
        .unwrap();
    let page: PortsPage = body_json(res).await;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].proto, "udp");
}

#[tokio::test]
async fn dashboard_served_without_token() {
    let res = router(state())
        .oneshot(req("GET", "/", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(ct.starts_with("text/html"));
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains("lnvps_fw dashboard"));
}
