//! Control-API tests: exercise the router via `tower::oneshot` (no TLS / no
//! network / no root), covering auth, the rules round-trip, event polling, and
//! the unauthenticated dashboard.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{StatusCode, header};
use http_body_util::BodyExt;
use lnvps_fw_service::api::{
    BlocksPage, Event, EventKind, EventsResponse, LearnedPort, Limits, Override, PortsPage,
    RuleSet, SharedState, SourceBlock, SourcesPage, Status, TrackedSource, router,
};
use tower::ServiceExt;

fn state() -> Arc<SharedState> {
    SharedState::new(
        "tok".into(),
        vec![],
        vec!["eth0".into()],
        RuleSet::default(),
        16,
        "LNVPS/api".into(),
        false,
        None,
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
        source_blocks: vec![],
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
async fn limits_put_get_roundtrip_and_validation() {
    let st = state();
    let app = router(st.clone());
    let good = serde_json::to_string(&Limits {
        pps: 50_000,
        syn_pps: 5_000,
        bps: 500_000_000,
        net_pps: 400_000,
        net_syn_pps: 40_000,
        net_bps: 4_000_000_000,
        exit_pct: 60,
        cooldown_secs: 45,
        src_rate_pps: 20_000,
        src_exit_pct: 40,
        src_cooldown_secs: 15,
    })
    .unwrap();
    let res = app
        .clone()
        .oneshot(req("PUT", "/api/v1/limits", Some("tok"), Some(good)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(st.limits_version() > 1);
    assert_eq!(st.limits().pps, 50_000);

    // GET reflects it.
    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/limits", Some("tok"), None))
        .await
        .unwrap();
    let got: Limits = body_json(res).await;
    assert_eq!(got.exit_pct, 60);
    assert_eq!(got.src_rate_pps, 20_000);
    assert_eq!(got.src_exit_pct, 40);
    assert_eq!(got.src_cooldown_secs, 15);

    // Zero threshold rejected.
    let bad = r#"{"pps":0,"syn_pps":1,"bps":1,"net_pps":1,"net_syn_pps":1,"net_bps":1,"exit_pct":50,"cooldown_secs":30}"#.to_string();
    let res = app
        .clone()
        .oneshot(req("PUT", "/api/v1/limits", Some("tok"), Some(bad)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Zero src_rate_pps rejected; omitted source fields fall back to defaults
    // (backward compat with pre-src-limit clients).
    let bad_src = r#"{"pps":1,"syn_pps":1,"bps":1,"net_pps":1,"net_syn_pps":1,"net_bps":1,"exit_pct":50,"cooldown_secs":30,"src_rate_pps":0}"#.to_string();
    let res = app
        .clone()
        .oneshot(req("PUT", "/api/v1/limits", Some("tok"), Some(bad_src)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let legacy = r#"{"pps":1,"syn_pps":1,"bps":1,"net_pps":1,"net_syn_pps":1,"net_bps":1,"exit_pct":50,"cooldown_secs":30}"#.to_string();
    let res = app
        .oneshot(req("PUT", "/api/v1/limits", Some("tok"), Some(legacy)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(st.limits().src_rate_pps, 10_000, "serde default applied");
}

#[tokio::test]
async fn blocks_endpoint() {
    let st = state();
    let app = router(st.clone());
    st.set_blocks(vec![SourceBlock {
        cidr: "203.0.113.0/24".into(),
        age_secs: 12,
        pps: 5000,
        manual: false,
        cooling: false,
    }]);
    // Add a manual block via the API.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/blocks",
            Some("tok"),
            Some(r#"{"cidr":"45.0.0.0/8"}"#.into()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/blocks", Some("tok"), None))
        .await
        .unwrap();
    let page: BlocksPage = body_json(res).await;
    // Paginated: total counts both, items holds the (bounded) slice.
    assert_eq!(page.total, 2);
    assert!(
        page.items
            .iter()
            .any(|b| b.cidr == "45.0.0.0/8" && b.manual)
    );
    assert!(
        page.items
            .iter()
            .any(|b| b.cidr == "203.0.113.0/24" && !b.manual)
    );

    // Delete the manual block.
    let res = app
        .oneshot(req(
            "DELETE",
            "/api/v1/blocks?cidr=45.0.0.0/8",
            Some("tok"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
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

#[tokio::test]
async fn dashboard_sets_strict_csp() {
    let res = router(state())
        .oneshot(req("GET", "/", None, None))
        .await
        .unwrap();
    let csp = res
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    // No external origins may be contacted from the token-entry page.
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("connect-src 'self'"));
}

#[tokio::test]
async fn dashboard_is_a_self_contained_single_file() {
    // The Vite single-file build inlines all JS + CSS; the served page must not
    // reference any external asset/CDN, so a token typed into it can't leak.
    let res = router(state())
        .oneshot(req("GET", "/", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(!body.contains("esm.sh"), "no external CDN");
    assert!(!body.contains("/assets/"), "no external asset references");
    assert!(body.contains("id=\"app\""), "app root present");
    assert!(body.contains("<script"), "inlined script present");
}

#[tokio::test]
async fn blocks_paginated_sorted_by_pps_and_filtered() {
    let st = state();
    let app = router(st.clone());
    st.set_blocks(vec![
        SourceBlock {
            cidr: "10.0.0.1/32".into(),
            age_secs: 1,
            pps: 100,
            manual: false,
            cooling: false,
        },
        SourceBlock {
            cidr: "10.0.0.2/32".into(),
            age_secs: 1,
            pps: 9000,
            manual: false,
            cooling: false,
        },
        SourceBlock {
            cidr: "10.0.0.3/32".into(),
            age_secs: 1,
            pps: 500,
            manual: false,
            cooling: true,
        },
    ]);
    // First page, limit 2: highest pps first.
    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/blocks?limit=2", Some("tok"), None))
        .await
        .unwrap();
    let page: BlocksPage = body_json(res).await;
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].cidr, "10.0.0.2/32"); // 9000 pps
    assert_eq!(page.items[1].cidr, "10.0.0.3/32"); // 500 pps
    assert!(page.items[1].cooling);
    // Filter narrows to one.
    let res = app
        .oneshot(req("GET", "/api/v1/blocks?q=0.0.1", Some("tok"), None))
        .await
        .unwrap();
    let page: BlocksPage = body_json(res).await;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].cidr, "10.0.0.1/32");
}

#[tokio::test]
async fn sources_unified_list_manual_pinned_then_by_pps() {
    let st = state();
    let app = router(st.clone());
    // A manual block, added via the public block API (updates the ruleset).
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/blocks",
            Some("tok"),
            Some("{\"cidr\":\"45.0.0.0/24\"}".into()),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    // Auto-tracked sources in every state.
    st.set_sources(vec![
        TrackedSource {
            ip: "10.0.0.1".into(),
            pps: 100,
            state: "normal".into(),
            manual: false,
            age_secs: 0,
        },
        TrackedSource {
            ip: "10.0.0.2".into(),
            pps: 9000,
            state: "dropping".into(),
            manual: false,
            age_secs: 1,
        },
        TrackedSource {
            ip: "10.0.0.3".into(),
            pps: 200,
            state: "cooling".into(),
            manual: false,
            age_secs: 2,
        },
    ]);
    let res = app
        .clone()
        .oneshot(req("GET", "/api/v1/sources", Some("tok"), None))
        .await
        .unwrap();
    let page: SourcesPage = body_json(res).await;
    // Manual block pinned first; then auto sources most-active first.
    assert_eq!(page.total, 4);
    assert_eq!(page.items[0].ip, "45.0.0.0/24");
    assert!(page.items[0].manual);
    assert_eq!(page.items[1].ip, "10.0.0.2"); // 9000 pps, dropping
    assert_eq!(page.items[1].state, "dropping");
    assert_eq!(page.items[2].ip, "10.0.0.3"); // 200 pps, cooling
    assert_eq!(page.items[3].ip, "10.0.0.1"); // 100 pps, normal (still in the list)
    assert_eq!(page.items[3].state, "normal");
    // Filtering narrows to the auto sources only.
    let res = app
        .oneshot(req("GET", "/api/v1/sources?q=10.0.0.1", Some("tok"), None))
        .await
        .unwrap();
    let page: SourcesPage = body_json(res).await;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].ip, "10.0.0.1");
}

#[tokio::test]
async fn unknown_asset_404() {
    let res = router(state())
        .oneshot(req("GET", "/assets/evil.js", None, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upgrade_forbidden_when_disabled() {
    // state() constructs with allow_remote_upgrade = false.
    let res = router(state())
        .oneshot(req("POST", "/api/v1/upgrade", Some("tok"), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
