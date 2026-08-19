//! What the control client decides, without a network.
//!
//! That the signature this produces is one a node actually accepts, and that
//! the pin rejects a real certificate that is not the pinned one, is proved in
//! `lnvps_e2e/tests/node_control.rs` — which stands up the node's own control
//! server and calls it with this client. Both halves have to agree, and only
//! one of them lives in this repository's `lnvps_api` crate.

use lnvps_db::{MarketplaceNode, MarketplaceNodeStatus, MarketplaceTrustTier, VmHost, VmHostKind};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use super::*;

/// A key that is not LNVPS's, for asserting a node would refuse it.
const OTHER_KEY: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

fn node(fingerprint: Option<Vec<u8>>) -> MarketplaceNode {
    MarketplaceNode {
        libvirt_cert: None,
        id: 7,
        operator_id: 1,
        name: "a node".to_string(),
        token_version: 1,
        status: MarketplaceNodeStatus::Approved,
        trust_tier: MarketplaceTrustTier::Untrusted,
        tls_fingerprint: fingerprint,
        tunnel_id: Some(1),
        last_seen: None,
        subscription_line_item_id: None,
        created: chrono::Utc::now(),
    }
}

fn host(ip: &str) -> VmHost {
    VmHost {
        id: 3,
        kind: VmHostKind::MarketplaceNode,
        ip: ip.to_string(),
        ..Default::default()
    }
}

fn control() -> NodeControl {
    NodeControl::new(&Keys::generate().secret_key().to_secret_hex()).unwrap()
}

/// A node is dialled at its tunnel address on the fleet's control port.
#[test]
fn a_node_is_called_inside_its_tunnel() {
    assert_eq!(
        endpoint(&host("10.66.0.2"), "/api/v1/status").unwrap(),
        "https://10.66.0.2:8890/api/v1/status"
    );
    // IPv6 arrives already bracketed, because that is how the tunnel allocator
    // writes a control address — a URL cannot hold a bare v6 address.
    assert_eq!(
        endpoint(&host("[fd00:66::2]"), "/api/v1/status").unwrap(),
        "https://[fd00:66::2]:8890/api/v1/status"
    );
}

/// A host with no control address is a hard error, never a default. Dialling
/// something else would mean calling another machine and believing its answer.
#[test]
fn a_node_with_no_tunnel_yet_is_not_dialled() {
    let err = endpoint(&host("  "), "/api/v1/status").unwrap_err();
    assert!(
        err.to_string().contains("tunnel has not been allocated"),
        "{err}"
    );
}

/// A node with no pinned certificate cannot be called at all: there would be no
/// way to tell its answers from anyone else's.
#[tokio::test]
async fn a_node_with_no_pin_is_not_called() {
    let err = control()
        .status(&node(None), &host("10.66.0.2"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("re-register"), "{err}");
}

/// The key is parsed once, at construction, so a deployment configured with
/// rubbish fails immediately rather than on whichever call runs first.
#[test]
fn a_bad_control_key_is_refused_up_front() {
    assert!(NodeControl::new("not-a-key").is_err());
    assert!(NodeControl::new(OTHER_KEY).is_ok());
    // Whitespace from a config file is not a different key.
    let padded = format!("  {OTHER_KEY}\n");
    assert_eq!(
        NodeControl::new(&padded).unwrap().public_key(),
        NodeControl::new(OTHER_KEY).unwrap().public_key()
    );
}

/// The authorisation is bound to the method and the full URL. The node checks
/// both, so a signature that authorised reading status cannot be replayed
/// against an endpoint that stops a guest.
#[test]
fn the_signature_names_the_request_it_authorises() {
    let control = control();
    let header = control
        .authorization("GET", "https://10.66.0.2:8890/api/v1/status", &[])
        .unwrap();

    let encoded = header.strip_prefix("Nostr ").expect("the Nostr scheme");
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
    let event: Event = serde_json::from_slice(&json).unwrap();

    event.verify().expect("a node verifies this first");
    assert_eq!(event.kind, Kind::HttpAuth);
    assert_eq!(event.pubkey, control.public_key());

    let tag = |name: &str| {
        event
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
            .and_then(|t| t.as_slice().get(1).cloned())
    };
    assert_eq!(
        tag("u").as_deref(),
        Some("https://10.66.0.2:8890/api/v1/status")
    );
    assert_eq!(tag("method").as_deref(), Some("GET"));
    // No body, no payload tag: the node only requires one when there is a body,
    // and sending a hash of nothing would be a hash of nothing.
    assert_eq!(tag("payload"), None);
}

/// A body is bound to the signature, so the arguments of a command cannot be
/// swapped after it was signed.
#[test]
fn a_body_is_bound_to_the_signature() {
    let header = control()
        .authorization("POST", "https://10.66.0.2:8890/api/v1/probe", b"{\"a\":1}")
        .unwrap();
    let encoded = header.strip_prefix("Nostr ").unwrap();
    let json = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
    let event: Event = serde_json::from_slice(&json).unwrap();

    let payload = event
        .tags
        .iter()
        .find(|t| t.as_slice().first().map(String::as_str) == Some("payload"))
        .and_then(|t| t.as_slice().get(1).cloned())
        .expect("a bodied request carries a payload tag");
    use nostr::hashes::{Hash, sha256};
    assert_eq!(payload, sha256::Hash::hash(b"{\"a\":1}").to_string());
}

/// Two identical requests are two events. A nostr event id is the hash of its
/// own contents and `created_at` has one-second resolution, so without a nonce
/// the second call in a second would be rejected by the node as a replay of the
/// first — which is exactly what a health gate that polls does.
#[test]
fn two_identical_requests_are_not_the_same_event() {
    let control = control();
    let one = control
        .authorization("GET", "https://n/api/v1/status", &[])
        .unwrap();
    let two = control
        .authorization("GET", "https://n/api/v1/status", &[])
        .unwrap();
    assert_ne!(one, two);
}

/// The pin accepts the certificate the node registered.
#[test]
fn the_pinned_certificate_is_accepted() {
    let der = b"a certificate, as far as this test is concerned".to_vec();
    use nostr::hashes::{Hash, sha256};
    let fingerprint = sha256::Hash::hash(&der).to_byte_array();

    let verifier = pin::PinnedCertificate::new(fingerprint);
    assert!(
        verifier
            .verify_server_cert(
                &CertificateDer::from(der),
                &[],
                &ServerName::try_from("10.66.0.2").unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    );
}

/// ...and refuses anything else, however well-signed. The usual cause is a node
/// that regenerated its certificate without re-registering, so the error names
/// both values rather than saying the handshake failed.
#[test]
fn an_unpinned_certificate_is_refused() {
    let verifier = pin::PinnedCertificate::new([0u8; 32]);
    let err = verifier
        .verify_server_cert(
            &CertificateDer::from(b"somebody else's certificate".to_vec()),
            &[],
            &ServerName::try_from("10.66.0.2").unwrap(),
            &[],
            UnixTime::now(),
        )
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("not the pinned"), "{message}");
    assert!(message.contains(&"0".repeat(64)), "{message}");
}

/// A fingerprint that is not 32 bytes is refused before any connection is made.
/// It can only come from a corrupt row, and connecting with a truncated pin
/// would be connecting with a weaker one.
#[test]
fn a_malformed_pin_is_refused() {
    assert!(pinned_client(&[1, 2, 3], TIMEOUT).is_err());
    assert!(pinned_client(&[0u8; 32], TIMEOUT).is_ok());
}

/// A node running a newer daemon is still readable: fields this LNVPS does not
/// know are ignored, and fields it knows that are missing take their defaults.
/// The alternative is a fleet that has to be upgraded in lockstep.
#[test]
fn a_newer_node_is_still_readable() {
    let status: NodeStatus = serde_json::from_str(
        r#"{
            "version": "0.9.0",
            "something_new": {"a": 1},
            "dataplane": {
                "tunnel_up": true,
                "last_handshake_secs": 3,
                "firewall": {"available": true, "present": true, "unknown": 1}
            }
        }"#,
    )
    .unwrap();

    assert_eq!(status.version, "0.9.0");
    assert!(status.dataplane.tunnel_up);
    assert_eq!(status.dataplane.last_handshake_secs, Some(3));
    assert!(status.dataplane.firewall.present);
    assert!(!status.dataplane.bridge_up, "absent means not claimed");
}

/// An older node that reports nothing at all still parses, as a node with
/// nothing working. A status that failed to parse would be indistinguishable
/// from a node that is down, and those need different answers.
#[test]
fn an_empty_status_is_a_node_with_nothing_working() {
    let status: NodeStatus = serde_json::from_str("{}").unwrap();
    assert_eq!(status.dataplane, NodeDataPlaneState::default());
    assert!(!status.dataplane.firewall.present);
}

/// The control key is LNVPS's own nostr identity — the account customers DM for
/// support — not a secret of its own. A key that cannot be parsed is caught when
/// the process starts rather than when the first node is called, which may be
/// days later.
#[test]
fn a_deployment_builds_its_client_from_config() {
    let config = NostrConfig {
        relays: vec![],
        nsec: OTHER_KEY.to_string(),
    };
    assert_eq!(
        config.control().unwrap().public_key(),
        NodeControl::new(OTHER_KEY).unwrap().public_key()
    );

    let broken = NostrConfig {
        relays: vec![],
        nsec: "nsec1-nonsense".to_string(),
    };
    // `NodeControl` has no `Debug` on purpose — it holds a secret key — so the
    // error is matched out rather than unwrapped.
    let err = match broken.control() {
        Ok(_) => panic!("nonsense was accepted as a control key"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("not a valid nostr secret key"),
        "{err}"
    );
}

/// The identity nodes are built to obey is LNVPS's published account, so the
/// constant recording it must actually be that account — a typo here would be a
/// documented value that no node trusts, discovered by an operator when their
/// node refuses every command.
#[test]
fn the_published_identity_is_a_real_key() {
    let key = PublicKey::parse(LNVPS_NPUB).expect("LNVPS_NPUB is a nostr public key");
    assert_eq!(
        key.to_hex(),
        "fcd818454002a6c47a980393f0549ac6e629d28d5688114bb60d831b5c1832a7",
        "this is the value compiled into node binaries as LNVPS_CONTROL_PUBKEY"
    );
}
