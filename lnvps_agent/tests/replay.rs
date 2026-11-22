use std::sync::Arc;

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::{DbToolExecutor, ToolExecutor};
use lnvps_agent::diag::{Diagnostics, LookingGlass, PolicyDocs};
use lnvps_agent::tools::errors::customer_safe;
use lnvps_api_common::MockDb;
use lnvps_db::{LNVpsDb, Vm, VmIpAssignment};

const DEAD_VM_PATH: &str = "  1.|-- 10.95.0.2   0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- vm-7.lnvps.cloud 100.0%     5    1.0   1.0   1.0   1.0   0.0\n";

async fn stack(vm_ip: &str, disabled: bool) -> (MockServer, DbToolExecutor, Arc<MockDb>) {
    let db = Arc::new(MockDb::default());
    db.vms.lock().await.insert(
        7,
        Vm {
            id: 7,
            user_id: 1,
            disabled,
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
        .and(path_regex("^/traceroute/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(format!("<pre>{DEAD_VM_PATH}</pre>")),
        )
        .mount(&server)
        .await;
    let dyn_db: Arc<dyn LNVpsDb> = db.clone();
    let exec = DbToolExecutor::new(dyn_db, 1).with_diagnostics(Diagnostics::new(
        LookingGlass::new(server.uri(), "edge1"),
        PolicyDocs::new(server.uri()),
    ));
    (server, exec, db)
}

#[tokio::test]
async fn replay_ssh_on_a_moved_port_conv_886() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let moved = listener.local_addr().unwrap().port();
    let unused = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let (_server, exec, _db) = stack("127.0.0.1", false).await;

    let ping = exec.execute("ping_vm", r#"{"vm_id":7}"#).await.unwrap();
    assert!(ping.contains("\"reachable\": false"));
    println!("AFTER ping_vm: {ping}");

    let scan = exec
        .execute(
            "scan_vm_ports",
            &format!(r#"{{"vm_id":7,"ports":[{unused},{moved}]}}"#),
        )
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&scan).unwrap();
    assert_eq!(parsed["open_ports"], serde_json::json!([moved]));
    println!("AFTER scan_vm_ports: {scan}");
}

#[tokio::test]
async fn replay_no_route_port_check_is_not_read_as_vm_down_conv_880() {
    let (_server, exec, _db) = stack("127.0.0.1", false).await;
    let out = exec
        .execute("check_vm_port", r#"{"vm_id":7,"port":1}"#)
        .await
        .unwrap();
    assert!(out.contains("meaning"));
    println!("AFTER check_vm_port: {out}");
}

#[tokio::test]
async fn replay_restart_of_a_staff_disabled_vm_conv_763() {
    let (_server, exec, _db) = stack("127.0.0.1", true).await;
    let err = exec
        .execute("restart_vm", r#"{"vm_id":7}"#)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("disabled by LNVPS staff"));
    println!("AFTER restart_vm: {err}");
}

#[test]
fn replay_hypervisor_error_text_conv_264_and_not_found_conv_344() {
    let hypervisor = customer_safe(
        "transient error: Request failed: error sending request for url (https://10.97.0.6:8006/api2/json/nodes/pve2/qemu/1506/status/reset) (No route to host)",
    );
    assert!(!hypervisor.contains("10.97") && !hypervisor.contains("pve2"));
    println!("AFTER hypervisor error: {hypervisor}");
    let missing =
        customer_safe("sqlx: no rows returned by a query that expected to return at least one row");
    assert!(!missing.contains("sqlx"));
    println!("AFTER missing vm: {missing}");
}

#[tokio::test]
async fn replay_ssh_key_that_cannot_be_deleted_conv_395() {
    let (_server, exec, db) = stack("127.0.0.1", false).await;
    db.user_ssh_keys.lock().await.insert(
        1,
        lnvps_db::UserSshKey {
            id: 1,
            name: "old".to_string(),
            user_id: 1,
            created: chrono::Utc::now(),
            key_data: "ssh-ed25519 K".to_string().into(),
        },
    );
    let out = exec.execute("list_my_ssh_keys", "{}").await.unwrap();
    assert!(out.contains("\"deletable\": false"));
    println!("AFTER list_my_ssh_keys: {out}");
}

const HEADER_ONLY: &str = "<pre>Start: 2026-11-19T16:37:07+0000\nHOST: router Loss%   Snt   Last   Avg  Best  Wrst StDev\n</pre>";

#[tokio::test]
async fn replay_silent_vm_is_not_a_looking_glass_outage_conv_283() {
    let (server, exec, _db) = stack("185.18.221.221", false).await;
    server.reset().await;
    Mock::given(method("GET"))
        .and(path_regex("^/traceroute/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(HEADER_ONLY))
        .mount(&server)
        .await;

    let ping = exec.execute("ping_vm", r#"{"vm_id":7}"#).await.unwrap();
    assert!(ping.contains("\"status\": \"no_reply_from_vm\""));
    assert!(ping.contains("no reply from this VM"));
    assert!(!ping.contains("unavailable"));
    println!("BEFORE ping_vm: Error: looking glass returned no traceroute output for 185.18.221.221 - the probe tool on the edge may be unavailable");
    println!("AFTER ping_vm: {ping}");

    let trace = exec
        .execute("traceroute_vm", r#"{"vm_id":7}"#)
        .await
        .unwrap();
    assert!(trace.contains("no_reply_from_vm"));

    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let err = exec
        .execute("ping_vm", r#"{"vm_id":7}"#)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("looking glass unavailable"));
}
