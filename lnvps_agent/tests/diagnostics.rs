//! End-to-end tests for the diagnostic tools through the HTTP-backed executor.
//!
//! The point of exercising the tool *arms* rather than the probe helpers is
//! the target-resolution path: a probe must aim only at an address the admin
//! API says belongs to the requesting user, and must refuse otherwise. Both
//! the admin API and the looking glass are mocked, so no packet leaves the
//! test and no public service is driven by CI.

use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::{LnvpsToolExecutor, PublicToolExecutor, ToolExecutor};
use lnvps_agent::api_client::ApiClient;
use lnvps_agent::diag::{Diagnostics, LookingGlass, PolicyDocs};
use lnvps_agent::settings::{OpenAiConfig, Settings};

/// A throwaway nsec so `ApiClient` can be constructed.
const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

const MTR: &str = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- 185.18.221.87  0.0%     5    0.2   0.2   0.2   0.2   0.0\n";

fn settings(admin_url: String) -> Settings {
    Settings {
        listen: None,
        admin_api_url: admin_url,
        user_api_url: "http://127.0.0.1:1".to_string(),
        nsec: TEST_NSEC.to_string(),
        openai: OpenAiConfig {
            base_url: "http://127.0.0.1:1/v1".to_string(),
            api_key: Some("test".to_string()),
            model: "test-model".to_string(),
            max_tokens: Some(256),
        },
        system_prompt: None,
        email: None,
        kind1: None,
        conversation_history_path: None,
    }
}

/// Admin API + looking glass + website, all served by one mock server.
///
/// `vm_ip` is what the admin API reports for VM 7; tests that actually connect
/// pass a loopback address so no test opens a socket to the internet.
async fn stack(vm_owner: u64, vm_ip: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/admin/v1/vms/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": 7,
                "user_id": vm_owner,
                "ip_addresses": [{ "id": 1, "ip": vm_ip, "range_id": 1 }],
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/traceroute/edge1/{vm_ip}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("<pre>{MTR}</pre>")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/tos"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<body><h1>Terms of Service</h1><p>{}</p></body>",
            "No port scanning. ".repeat(50)
        )))
        .mount(&server)
        .await;
    server
}

fn executor(server: &MockServer, user_id: u64) -> LnvpsToolExecutor {
    let api = Arc::new(ApiClient::new(&settings(server.uri())).expect("api client"));
    LnvpsToolExecutor::new(api, user_id).with_diagnostics(Diagnostics::new(
        LookingGlass::new(server.uri(), "edge1"),
        PolicyDocs::new(server.uri()),
    ))
}

#[tokio::test]
async fn ping_vm_resolves_the_owned_vms_address() {
    let server = stack(1, "185.18.221.87").await;
    let out = executor(&server, 1)
        .execute("ping_vm", r#"{"vm_id":7}"#)
        .await
        .expect("ping");
    assert!(out.contains("\"reachable\": true"));
    assert!(out.contains("185.18.221.87"));
    // The condensed answer must not carry the whole path.
    assert!(!out.contains("10.0.0.1"));
}

#[tokio::test]
async fn traceroute_vm_returns_the_full_path() {
    let server = stack(1, "185.18.221.87").await;
    let out = executor(&server, 1)
        .execute("traceroute_vm", r#"{"vm_id":7}"#)
        .await
        .expect("traceroute");
    assert!(out.contains("10.0.0.1"));
    assert!(out.contains("\"hop\": 2"));
}

/// The probe target comes from the VM record, so a VM owned by someone else
/// must be refused before the looking glass is touched.
#[tokio::test]
async fn probes_refuse_another_users_vm() {
    let server = stack(99, "185.18.221.87").await;
    let exec = executor(&server, 1);
    for tool in ["ping_vm", "traceroute_vm"] {
        let err = exec
            .execute(tool, r#"{"vm_id":7}"#)
            .await
            .expect_err("must refuse");
        assert!(err.to_string().contains("does not belong"), "{tool}");
    }
    let err = exec
        .execute("check_vm_port", r#"{"vm_id":7,"port":22}"#)
        .await
        .expect_err("must refuse");
    assert!(err.to_string().contains("does not belong"));
}

#[tokio::test]
async fn check_vm_port_reports_an_open_port() {
    // Bind a real socket and tell the admin API the VM owns that address, so
    // the connect stays on loopback.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = stack(1, "127.0.0.1").await;
    let out = executor(&server, 1)
        .execute("check_vm_port", &format!(r#"{{"vm_id":7,"port":{port}}}"#))
        .await
        .expect("port check");
    assert!(out.contains("\"open\": true"));
    // The vantage-point caveat must always ride along with the result.
    assert!(out.contains("not the public internet"));
}

#[tokio::test]
async fn check_vm_port_rejects_an_invalid_port() {
    let server = stack(1, "127.0.0.1").await;
    let err = executor(&server, 1)
        .execute("check_vm_port", r#"{"vm_id":7,"port":0}"#)
        .await
        .expect_err("port 0 is not probeable");
    assert!(err.to_string().contains("between 1 and 65535"));
}

#[tokio::test]
async fn terms_of_service_is_available_to_customers_and_anonymous_askers() {
    let server = stack(1, "185.18.221.87").await;
    let out = executor(&server, 1)
        .execute("get_terms_of_service", "{}")
        .await
        .expect("tos");
    assert!(out.contains("No port scanning."));

    let api = Arc::new(ApiClient::new(&settings(server.uri())).expect("api client"));
    let public = PublicToolExecutor::new(api).with_diagnostics(Diagnostics::new(
        LookingGlass::new(server.uri(), "edge1"),
        PolicyDocs::new(server.uri()),
    ));
    let out = public
        .execute("get_terms_of_service", "{}")
        .await
        .expect("tos");
    assert!(out.contains("Terms of Service"));
}

/// An anonymous requester has no VM to resolve a target from, so the probes
/// must not be executable even if the model invents a call.
#[tokio::test]
async fn public_executor_refuses_probes() {
    let server = stack(1, "185.18.221.87").await;
    let api = Arc::new(ApiClient::new(&settings(server.uri())).expect("api client"));
    let public = PublicToolExecutor::new(api);
    for tool in ["ping_vm", "traceroute_vm", "check_vm_port"] {
        assert!(
            public
                .execute(tool, r#"{"vm_id":7,"port":22}"#)
                .await
                .is_err(),
            "{tool} must be unavailable anonymously"
        );
    }
}
