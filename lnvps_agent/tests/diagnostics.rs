//! End-to-end tests for the diagnostic tools through the executor.
//!
//! The point of exercising the tool *arms* rather than the probe helpers is
//! the target-resolution path: a probe must aim only at an address the
//! database says belongs to the requesting user, and must refuse otherwise.
//! The VM records come from `MockDb` and the looking glass is mocked, so no
//! packet leaves the test and no public service is driven by CI.

use std::sync::Arc;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::{DbToolExecutor, ToolExecutor};
use lnvps_agent::diag::{Diagnostics, LookingGlass, PolicyDocs};
use lnvps_api_common::MockDb;
use lnvps_db::{LNVpsDb, Vm, VmIpAssignment};

const MTR: &str = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- 185.18.221.87  0.0%     5    0.2   0.2   0.2   0.2   0.0\n";

/// Looking glass + website, served by one mock server, plus a database holding
/// VM 7 owned by `vm_owner` at `vm_ip`.
///
/// Tests that actually connect pass a loopback address, so no test opens a
/// socket to the internet.
async fn stack(vm_owner: u64, vm_ip: &str) -> (MockServer, Arc<MockDb>) {
    let db = Arc::new(MockDb::default());
    db.vms.lock().await.insert(
        7,
        Vm {
            id: 7,
            user_id: vm_owner,
            ..MockDb::mock_vm()
        },
    );
    db.ip_assignments.lock().await.insert(
        1,
        VmIpAssignment {
            id: 1,
            vm_id: 7,
            ip: vm_ip.to_string(),
            ..Default::default()
        },
    );

    let server = MockServer::start().await;
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
    (server, db)
}

/// Probe clients pointed at the mock server, for a given user.
fn diagnostics(server: &MockServer) -> Diagnostics {
    Diagnostics::new(
        LookingGlass::new(server.uri(), "edge1"),
        PolicyDocs::new(server.uri()),
    )
}

fn executor(stack: &(MockServer, Arc<MockDb>), user_id: u64) -> DbToolExecutor {
    let db: Arc<dyn LNVpsDb> = stack.1.clone();
    DbToolExecutor::new(db, user_id).with_diagnostics(diagnostics(&stack.0))
}

#[tokio::test]
async fn ping_vm_resolves_the_owned_vms_address() {
    let stack = stack(1, "185.18.221.87").await;
    let out = executor(&stack, 1)
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
    let stack = stack(1, "185.18.221.87").await;
    let out = executor(&stack, 1)
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
    let stack = stack(99, "185.18.221.87").await;
    let exec = executor(&stack, 1);
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
    let stack = stack(1, "127.0.0.1").await;
    let out = executor(&stack, 1)
        .execute("check_vm_port", &format!(r#"{{"vm_id":7,"port":{port}}}"#))
        .await
        .expect("port check");
    assert!(out.contains("\"open\": true"));
    // The vantage-point caveat must always ride along with the result.
    assert!(out.contains("not the public internet"));
}

#[tokio::test]
async fn check_vm_port_rejects_an_invalid_port() {
    let stack = stack(1, "127.0.0.1").await;
    let err = executor(&stack, 1)
        .execute("check_vm_port", r#"{"vm_id":7,"port":0}"#)
        .await
        .expect_err("port 0 is not probeable");
    assert!(err.to_string().contains("between 1 and 65535"));
}

#[tokio::test]
async fn terms_of_service_is_available_to_customers_and_anonymous_askers() {
    let stack = stack(1, "185.18.221.87").await;
    let out = executor(&stack, 1)
        .execute("get_terms_of_service", "{}")
        .await
        .expect("tos");
    assert!(out.contains("No port scanning."));

    let db: Arc<dyn LNVpsDb> = stack.1.clone();
    let public = DbToolExecutor::public(db).with_diagnostics(diagnostics(&stack.0));
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
    let stack = stack(1, "185.18.221.87").await;
    let db: Arc<dyn LNVpsDb> = stack.1.clone();
    let public = DbToolExecutor::public(db).with_diagnostics(diagnostics(&stack.0));
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
