//! LNVPS calling a node, with both halves real.
//!
//! `lnvps_api_common::node_control` signs and pins; `lnvps_node::control`
//! verifies and serves. Each side is unit-tested against its own idea of the
//! other, which is exactly the arrangement in which two correct-looking halves
//! fail to interoperate: a tag named differently, a URL built with a port on
//! one side and without on the other, a fingerprint hex on one side and bytes
//! on the other. This is the test that would catch it.
//!
//! No root, no network namespaces — a loopback socket is enough.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use lnvps_api_common::node_control::{CONTROL_PORT, NodeControl};
use lnvps_db::{MarketplaceNode, MarketplaceNodeStatus, MarketplaceTrustTier, VmHost, VmHostKind};
use nostr::Keys;

/// A node serving its control API on loopback, with a freshly generated
/// identity, and the fingerprint LNVPS would have pinned at registration.
struct Node {
    addr: SocketAddr,
    fingerprint: Vec<u8>,
    _state_dir: tempfile::TempDir,
}

/// Each test gets its own loopback address rather than its own port: the port
/// is the one LNVPS dials fleet-wide, and a test that picked a free port would
/// pass while production called the wrong one. In production the same
/// separation comes for free — every node has a tunnel address to itself.
async fn start_node(control_pubkey: nostr::PublicKey, address: &str) -> Result<Node> {
    let state_dir = tempfile::tempdir()?;
    let addr: SocketAddr = format!("{address}:{CONTROL_PORT}").parse()?;

    let tls = lnvps_node::tls::load_or_generate(state_dir.path(), Some(addr.ip()))?;
    let fingerprint = hex::decode(&tls.fingerprint)?;

    let state = Arc::new(lnvps_node::control::ControlState::new(
        control_pubkey,
        addr,
        // This test is about who may call the node and whether its answer can
        // be trusted, not about what it reports, so an unconfigured machine is
        // the honest thing to report.
        Arc::new(lnvps_node::net::UnavailableKernel),
        Arc::new(lnvps_node::fw::UnavailableFirewall),
    ));
    tokio::spawn(async move { lnvps_node::control::serve(state, addr, tls).await });

    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(Node {
        addr,
        fingerprint,
        _state_dir: state_dir,
    })
}

fn node_row(fingerprint: Vec<u8>) -> MarketplaceNode {
    MarketplaceNode {
        libvirt_cert: None,
        id: 1,
        operator_id: 1,
        name: "a node".to_string(),
        token_version: 1,
        status: MarketplaceNodeStatus::Approved,
        trust_tier: MarketplaceTrustTier::Untrusted,
        tls_fingerprint: Some(fingerprint),
        tunnel_id: Some(1),
        last_seen: None,
        subscription_line_item_id: None,
        created: chrono::Utc::now(),
    }
}

fn host_row(addr: SocketAddr) -> VmHost {
    VmHost {
        id: 1,
        kind: VmHostKind::MarketplaceNode,
        // What the tunnel allocator writes: the node's inner address, which is
        // where its control API is bound.
        ip: addr.ip().to_string(),
        ..Default::default()
    }
}

/// The whole round trip: LNVPS signs with its control key, the node verifies it
/// against the key it was built with, LNVPS verifies the certificate against
/// the fingerprint the node registered, and a status comes back.
#[tokio::test]
async fn lnvps_can_read_a_nodes_status() -> Result<()> {
    let lnvps = Keys::generate();
    let node = start_node(lnvps.public_key(), "127.0.0.1").await?;

    let control = NodeControl::new(&lnvps.secret_key().to_secret_hex())?;
    let status = control
        .status(&node_row(node.fingerprint.clone()), &host_row(node.addr))
        .await?;

    assert!(
        !status.version.is_empty(),
        "a node names its daemon version"
    );
    // An unconfigured machine, reported as one rather than as an error.
    assert!(!status.dataplane.tunnel_up);
    assert!(!status.dataplane.firewall.available);
    Ok(())
}

/// A second call in the same second succeeds. The node remembers event ids to
/// stop replays, and a nostr id is the hash of its own contents — so without a
/// nonce the second call would be rejected as a replay of the first, which is
/// precisely what a health gate that polls does.
#[tokio::test]
async fn a_node_can_be_polled_twice_in_a_second() -> Result<()> {
    let lnvps = Keys::generate();
    let node = start_node(lnvps.public_key(), "127.0.0.2").await?;
    let control = NodeControl::new(&lnvps.secret_key().to_secret_hex())?;

    let (row, host) = (node_row(node.fingerprint.clone()), host_row(node.addr));
    control.status(&row, &host).await?;
    control
        .status(&row, &host)
        .await
        .expect("a second call in the same second is not a replay");
    Ok(())
}

/// Somebody else's key does not work, even holding a valid certificate and a
/// well-formed request. This is the property the whole scheme exists for.
#[tokio::test]
async fn another_key_cannot_command_a_node() -> Result<()> {
    let lnvps = Keys::generate();
    let node = start_node(lnvps.public_key(), "127.0.0.3").await?;

    let impostor = NodeControl::new(&Keys::generate().secret_key().to_secret_hex())?;
    let err = impostor
        .status(&node_row(node.fingerprint.clone()), &host_row(node.addr))
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("401") || format!("{err:#}").contains("refused"),
        "{err:#}"
    );
    Ok(())
}

/// A node presenting a certificate LNVPS did not pin is refused, however
/// correct the rest of the exchange is. Without this, anything that could
/// answer on the node's tunnel address — a guest that grabbed the IP, a mistake
/// on the route server — could report that a VM is running when it is not.
#[tokio::test]
async fn a_node_that_is_not_the_pinned_one_is_refused() -> Result<()> {
    let lnvps = Keys::generate();
    let node = start_node(lnvps.public_key(), "127.0.0.4").await?;

    let control = NodeControl::new(&lnvps.secret_key().to_secret_hex())?;
    let err = control
        .status(&node_row(vec![9u8; 32]), &host_row(node.addr))
        .await
        .unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("not the pinned") || message.contains("certificate"),
        "{message}"
    );
    Ok(())
}
