//! End-to-end checks of the control API over a real socket.
//!
//! The unit tests in `control` drive the router directly, which proves the
//! authentication logic but says nothing about whether the daemon actually
//! serves HTTPS, or whether the certificate it presents is the one whose
//! fingerprint LNVPS pinned. Both of those are the sort of thing that can be
//! wrong while every unit test passes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use lnvps_node::control::{ControlState, serve};
use lnvps_node::control_auth::sha256_hex;
use lnvps_node::tls;
use nostr::{EventBuilder, Keys, Kind, Tag, TagKind};

/// Start a control API on a free loopback port, returning its address, the
/// certificate it serves and its fingerprint.
async fn start_node(keys: &Keys, state_dir: &std::path::Path) -> (SocketAddr, Vec<u8>, String) {
    // Ask the OS for a free port, then release it: axum_server binds by
    // address, and a hardcoded port makes the suite fail when something else
    // happens to hold it.
    let port = {
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        sock.local_addr().unwrap().port()
    };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let node_tls = tls::load_or_generate(state_dir, Some(addr.ip())).unwrap();
    let (cert, fingerprint) = (node_tls.cert_pem.clone(), node_tls.fingerprint.clone());

    // The data plane this reports on is the machine's; these tests are about
    // TLS and authentication, so an unconfigured machine is the honest answer.
    let state = Arc::new(ControlState::new(
        keys.public_key(),
        addr,
        Arc::new(lnvps_node::net::UnavailableKernel),
        Arc::new(lnvps_node::fw::UnavailableFirewall),
    ));
    tokio::spawn(async move { serve(state, addr, node_tls).await });

    // Wait for the listener rather than sleeping a fixed time.
    for _ in 0..100 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (addr, cert, fingerprint)
}

fn auth_header(keys: &Keys, url: &str, method: &str, body: &[u8]) -> String {
    let mut tags = vec![
        Tag::custom(TagKind::custom("u"), [url.to_string()]),
        Tag::custom(TagKind::custom("method"), [method.to_string()]),
    ];
    if !body.is_empty() {
        tags.push(Tag::custom(TagKind::custom("payload"), [sha256_hex(body)]));
    }
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap();
    format!(
        "Nostr {}",
        BASE64.encode(serde_json::to_vec(&event).unwrap())
    )
}

/// A client that trusts exactly one certificate — the same shape of trust
/// LNVPS uses once it has pinned this node.
fn pinned_client(cert_pem: &[u8]) -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem).unwrap())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

#[tokio::test]
async fn the_daemon_serves_https_and_authorises_lnvps() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let (addr, cert, _) = start_node(&keys, dir.path()).await;

    let url = format!("https://{addr}/api/v1/status");
    let response = pinned_client(&cert)
        .get(&url)
        .header("Authorization", auth_header(&keys, &url, "GET", b""))
        .send()
        .await
        .expect("control API did not answer over HTTPS");

    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["inventory"]["memory"]["total_bytes"].as_u64().unwrap() > 0);
}

/// Plain HTTP must not be served: the pin only means something if the
/// connection is TLS in the first place.
#[tokio::test]
async fn the_control_api_is_not_reachable_over_plain_http() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let (addr, _, _) = start_node(&keys, dir.path()).await;

    let result = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{addr}/api/v1/status"))
        .send()
        .await;

    assert!(
        result.is_err(),
        "the control API answered an unencrypted request: {result:?}"
    );
}

/// The certificate presented on the wire must be the one whose fingerprint was
/// registered. If these can differ, the pin protects nothing.
#[tokio::test]
async fn the_served_certificate_is_the_one_that_was_pinned() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let (addr, cert_pem, fingerprint) = start_node(&keys, dir.path()).await;

    // Take the certificate from the live TLS session, not from disk.
    let presented = fetch_peer_certificate(addr).await;
    assert_eq!(
        tls::fingerprint_sha256(&presented),
        fingerprint,
        "the certificate served differs from the one whose fingerprint is registered"
    );
    assert_eq!(presented, tls::pem_to_der(&cert_pem).unwrap());
}

/// A client trusting some other certificate must fail the handshake — the
/// negative half of the pinning claim.
#[tokio::test]
async fn a_client_pinned_to_a_different_certificate_is_rejected() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let (addr, _, _) = start_node(&keys, dir.path()).await;

    let someone_else = tls::generate(Some(addr.ip())).unwrap().cert_pem;
    let url = format!("https://{addr}/api/v1/status");
    let result = pinned_client(&someone_else)
        .get(&url)
        .header("Authorization", auth_header(&keys, &url, "GET", b""))
        .send()
        .await;

    assert!(
        result.is_err(),
        "a client pinned to a different certificate completed the handshake"
    );
}

/// Reaching the node over TLS is not authorisation. A guest that can route to
/// the tunnel address gets exactly this far (decision 13).
#[tokio::test]
async fn tls_alone_does_not_authorise_a_request() {
    let keys = Keys::generate();
    let dir = tempfile::tempdir().unwrap();
    let (addr, cert, _) = start_node(&keys, dir.path()).await;

    let response = pinned_client(&cert)
        .get(format!("https://{addr}/api/v1/status"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
}

/// Read the peer certificate from a real handshake, accepting whatever is
/// presented, so the test observes the server rather than trusting it.
async fn fetch_peer_certificate(addr: SocketAddr) -> Vec<u8> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use std::sync::Mutex;
    use tokio_rustls::TlsConnector;

    /// Records the certificate and accepts it. Test-only: the point is to
    /// observe what the server actually sends.
    #[derive(Debug)]
    struct Capture(Arc<Mutex<Option<Vec<u8>>>>);

    impl ServerCertVerifier for Capture {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            *self.0.lock().unwrap() = Some(end_entity.to_vec());
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let seen = Arc::new(Mutex::new(None));
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Capture(seen.clone())))
        .with_no_client_auth();

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = TlsConnector::from(Arc::new(config))
        .connect(ServerName::IpAddress(addr.ip().into()), stream)
        .await
        .unwrap();

    let captured = seen.lock().unwrap().clone();
    captured.expect("no certificate was presented")
}
