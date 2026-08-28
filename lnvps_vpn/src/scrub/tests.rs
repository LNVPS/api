//! Forgetting where a customer was.

use super::*;
use crate::apply::apply;
use crate::apply::tests::{FakeKernel, a_document, a_peer};

const QUIET: u64 = 600;

#[tokio::test]
async fn a_peer_that_has_gone_quiet_has_its_address_forgotten() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);
    apply(&kernel, &doc).await.unwrap();
    kernel.peer_spoke("wgln7", "cGVlcjE=", "203.0.113.9:41414", QUIET + 1);

    let scrubbed = scrub_quiet_peers(&kernel, &doc, QUIET).await.unwrap();

    assert_eq!(scrubbed, vec!["cGVlcjE=".to_string()]);
    let peer = &kernel.peers_of("wgln7")[0];
    assert_eq!(peer.endpoint, None, "the customer's address is still here");
    // Re-added, not dropped: a client that comes back must find its key
    // configured, or the scrub would be a disconnection.
    assert_eq!(peer.allowed_ips.len(), 1);
}

#[tokio::test]
async fn a_peer_that_is_still_talking_is_left_alone() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);
    apply(&kernel, &doc).await.unwrap();
    kernel.peer_spoke("wgln7", "cGVlcjE=", "203.0.113.9:41414", QUIET - 1);
    kernel.calls.lock().unwrap().clear();

    let scrubbed = scrub_quiet_peers(&kernel, &doc, QUIET).await.unwrap();

    assert!(scrubbed.is_empty());
    // Scrubbing a live peer would cost it a handshake for nothing.
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_peer_that_never_connected_is_not_churned() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);
    apply(&kernel, &doc).await.unwrap();
    kernel.calls.lock().unwrap().clear();

    // Nothing was ever recorded, so there is nothing to forget, and removing
    // and re-adding it on every pass would be churn for its own sake.
    assert!(
        scrub_quiet_peers(&kernel, &doc, QUIET)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(kernel.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_peer_lnvps_did_not_ask_for_is_not_touched() {
    let kernel = FakeKernel::default();
    let doc = a_document(vec![a_peer("cGVlcjE=", &["10.64.0.7/32"])]);
    apply(&kernel, &doc).await.unwrap();
    // Something the operator put on the interface themselves.
    kernel
        .set_wireguard_peer(
            "wgln7",
            &WgPeer {
                public_key: "b3RoZXI=".to_string(),
                allowed_ips: vec!["192.0.2.0/24".parse().unwrap()],
                endpoint: None,
                persistent_keepalive: None,
            },
        )
        .await
        .unwrap();
    kernel.peer_spoke("wgln7", "b3RoZXI=", "203.0.113.9:41414", QUIET + 1);

    let scrubbed = scrub_quiet_peers(&kernel, &doc, QUIET).await.unwrap();

    // Removing and re-adding it would be this daemon rebuilding a peer from a
    // document that never described it.
    assert!(scrubbed.is_empty());
    assert_eq!(kernel.peers_of("wgln7").len(), 2);
}
