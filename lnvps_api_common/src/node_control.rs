//! Calling a marketplace node's control API.
//!
//! The other half of a mutual pin. The node already verifies that a request
//! came from LNVPS, against a public key compiled into its binary; this
//! verifies that the answer came from the node, against the certificate
//! fingerprint it registered. Neither side trusts the tunnel to establish who
//! is at the other end of it — a guest that got hold of the node's address, or
//! a mistake on the route server, could otherwise answer for a node and report
//! that a VM is running when it is not.
//!
//! Two decisions are worth stating, because they look like omissions:
//!
//! - **The node's status is not modelled by depending on `lnvps_node`.** That
//!   would pull netlink, nftables and WireGuard into the API binary to describe
//!   a JSON document. The wire format is the contract; the structs here are
//!   this side's reading of it, and unknown fields are ignored so a node
//!   running a newer daemon is still readable.
//! - **The port is not stored per node.** The control API exists only inside
//!   the tunnel, where every node has an address to itself and nothing competes
//!   for a port. An operator who changes it makes their own node unreachable,
//!   which the health gate reports as unreachable — self-correcting, and
//!   cheaper than a column that can disagree with the node's own config.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use lnvps_db::{MarketplaceNode, VmHost};
use nostr::prelude::*;
use serde::{Deserialize, Serialize};

/// The port every node's control API listens on.
pub const CONTROL_PORT: u16 = 8890;

/// LNVPS's published nostr identity, for reference.
///
/// Not enforced here — self-hosted deployments sign with their own key and
/// build their nodes with its public half — but recorded so the value an
/// operator is asked to trust is written down somewhere authoritative.
pub const LNVPS_NPUB: &str = "npub1lnvps32qq2nvg75cqwflq4y6cmnzn55d26ypzjakpkp3khqcx2ns7t7vjj";

/// LNVPS's nostr identity.
///
/// The same key throughout: the account customers DM for support, the key legal
/// agreements are signed with, and — its public half — the key every
/// marketplace node is built to obey. One identity rather than a control key of
/// its own, because a separate secret would have to be generated, distributed
/// to whoever builds the node binaries, and kept in step with the value
/// compiled into them, while this one is already published. An operator can
/// check the key their node was built with against the account LNVPS answers
/// support DMs from, which is not a check they could make against a key that
/// existed only in LNVPS's config file.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NostrConfig {
    /// Relays for outbound messages. Not needed to sign a control request,
    /// hence defaulted: the admin API holds this identity to call nodes and
    /// speaks to no relay at all.
    #[serde(default)]
    pub relays: Vec<String>,
    /// The secret key, `nsec…` or hex.
    pub nsec: String,
}

impl NostrConfig {
    /// The control client this identity signs with.
    pub fn control(&self) -> Result<NodeControl> {
        NodeControl::new(&self.nsec)
    }
}

/// How long a node has to answer.
///
/// Short: a node is one WireGuard hop away and answering from memory. The
/// health gate is the main caller and a hung call there stalls an approval, so
/// "not answering" is a more useful result than a long wait.
const TIMEOUT: Duration = Duration::from_secs(10);

/// What a node reports about itself.
///
/// Everything here is the node's own word. It is worth having — a node that
/// says its tunnel is down is telling the truth about a real problem — but the
/// health gate does not stop here, because the failure worth catching is the
/// node that believes it is fine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeStatus {
    /// Daemon version, so LNVPS can tell what a node is running.
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub dataplane: NodeDataPlaneState,
}

/// The node's view of its own network, as `lnvps_node::net::DataPlaneState`
/// states it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeDataPlaneState {
    #[serde(default)]
    pub tunnel_up: bool,
    /// Seconds since the last handshake with the route server. `None` when
    /// there has never been one — the difference between "configured" and
    /// "working", and the reason a node cannot be gated on `tunnel_up` alone.
    #[serde(default)]
    pub last_handshake_secs: Option<u64>,
    #[serde(default)]
    pub tunnel_mtu: Option<u32>,
    #[serde(default)]
    pub bridge_up: bool,
    #[serde(default)]
    pub forwarding4: bool,
    #[serde(default)]
    pub forwarding6: bool,
    /// Guest addresses actually routed to the bridge.
    #[serde(default)]
    pub routed_guests: usize,
    #[serde(default)]
    pub firewall: NodeFirewallState,
}

/// The node's packet filter, as `lnvps_node::fw::FirewallState` states it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeFirewallState {
    #[serde(default)]
    pub available: bool,
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub isolated: bool,
    #[serde(default)]
    pub bindings: usize,
    #[serde(default)]
    pub ruleset: Option<String>,
    /// Packets dropped for claiming an address the guest was not assigned.
    #[serde(default)]
    pub spoofed_packets: u64,
}

/// Calling a node, as the health gate needs it.
///
/// A trait so the gate's decisions can be tested against a node that answers in
/// a chosen way. Every interesting case here is a node behaving badly —
/// claiming a tunnel it does not have, refusing to apply a document, answering
/// slowly — and none of those are states a real node can be asked to be in on
/// demand.
#[async_trait::async_trait]
pub trait NodeControlApi: Send + Sync {
    async fn status(&self, node: &MarketplaceNode, host: &VmHost) -> Result<NodeStatus>;
    async fn refresh_dataplane(&self, node: &MarketplaceNode, host: &VmHost)
    -> Result<Vec<String>>;
}

#[async_trait::async_trait]
impl NodeControlApi for NodeControl {
    async fn status(&self, node: &MarketplaceNode, host: &VmHost) -> Result<NodeStatus> {
        NodeControl::status(self, node, host).await
    }

    async fn refresh_dataplane(
        &self,
        node: &MarketplaceNode,
        host: &VmHost,
    ) -> Result<Vec<String>> {
        NodeControl::refresh_dataplane(self, node, host).await
    }
}

/// Signs and sends control requests.
///
/// Holds the key rather than taking it per call so that a deployment without a
/// control key fails once, at construction, instead of at whichever call
/// happens to run first.
/// Deliberately no `Debug`: the struct holds LNVPS's control secret key, and a
/// derived `Debug` is how a secret ends up in a log line nobody meant to write.
#[derive(Clone)]
pub struct NodeControl {
    keys: Keys,
    timeout: Duration,
}

impl NodeControl {
    /// Build a client from LNVPS's control secret key (`nsec…` or hex).
    pub fn new(secret: &str) -> Result<Self> {
        let keys = Keys::parse(secret.trim())
            .context("The marketplace control key is not a valid nostr secret key")?;
        Ok(Self {
            keys,
            timeout: TIMEOUT,
        })
    }

    /// The public half, which is what operators build their node binaries with.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Read a node's self-reported status.
    pub async fn status(&self, node: &MarketplaceNode, host: &VmHost) -> Result<NodeStatus> {
        let body = self.get(node, host, "/api/v1/status").await?;
        serde_json::from_str(&body)
            .with_context(|| format!("Node {} returned a status this LNVPS cannot read", node.id))
    }

    /// Ask a node to re-fetch and apply its data plane now.
    ///
    /// Nothing about the document is sent: the node fetches it itself, from
    /// LNVPS, with its own credential. This only says *when*, so that a change
    /// LNVPS has just made — a probe address, a new guest — does not have to
    /// wait out the node's heartbeat before it can be tested.
    pub async fn refresh_dataplane(
        &self,
        node: &MarketplaceNode,
        host: &VmHost,
    ) -> Result<Vec<String>> {
        let body = self
            .send(node, host, "POST", "/api/v1/dataplane/refresh")
            .await?;
        #[derive(Deserialize, Default)]
        struct RefreshResult {
            #[serde(default)]
            changed: Vec<String>,
        }
        let result: RefreshResult = serde_json::from_str(&body).unwrap_or_default();
        Ok(result.changed)
    }

    /// `GET path` against a node, signed and pinned.
    async fn get(&self, node: &MarketplaceNode, host: &VmHost, path: &str) -> Result<String> {
        self.send(node, host, "GET", path).await
    }

    /// One signed, pinned request.
    async fn send(
        &self,
        node: &MarketplaceNode,
        host: &VmHost,
        method: &str,
        path: &str,
    ) -> Result<String> {
        let url = endpoint(host, path)?;
        let fingerprint = node.tls_fingerprint.clone().context(
            "This node has no pinned certificate, so there is no way to tell its answers \
             from anyone else's; it must re-register",
        )?;

        let auth = self.authorization(method, &url, &[])?;
        let client = pinned_client(&fingerprint, self.timeout)?;
        let request = match method {
            "POST" => client.post(&url),
            _ => client.get(&url),
        };
        let response = request
            .header("Authorization", auth)
            .send()
            .await
            .with_context(|| format!("Cannot reach node {} at {url}", node.id))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // The node's own message, which says *why* it refused — a stale
            // clock, a key it does not recognise — where a status code alone
            // would send an operator to read our source.
            bail!(
                "Node {} refused the request ({status}): {}",
                node.id,
                body.trim()
            );
        }
        Ok(body)
    }

    /// A NIP-98 event authorising exactly this request.
    ///
    /// Bound to the method and the full URL, because the node checks both: a
    /// signature that authorised reading status must not be replayable against
    /// an endpoint that stops a guest.
    fn authorization(&self, method: &str, url: &str, body: &[u8]) -> Result<String> {
        let mut tags = vec![
            Tag::parse(["u", url])?,
            Tag::parse(["method", method])?,
            // A nonce, because the node remembers event ids to stop replays and
            // an id is the hash of its own contents: two identical requests in
            // the same second would otherwise be the same event, and the second
            // would be rejected as a replay of the first.
            Tag::parse(["nonce", &nonce()])?,
        ];
        if !body.is_empty() {
            use nostr::hashes::{Hash, sha256};
            tags.push(Tag::parse([
                "payload",
                &sha256::Hash::hash(body).to_string(),
            ])?);
        }

        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(&self.keys)
            .context("Cannot sign a control request")?;
        Ok(format!(
            "Nostr {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, event.as_json())
        ))
    }
}

/// A random nonce, so two identical requests are two events.
///
/// A nostr event id is the hash of its own contents and `created_at` has
/// one-second resolution, so two identical requests in the same second would
/// otherwise be the *same* event — and the node, which remembers ids to stop
/// replays, would reject the second as a replay of the first.
fn nonce() -> String {
    use ::rand::Rng;
    hex::encode(::rand::rng().random::<[u8; 8]>())
}

/// Where a node's control API lives.
///
/// `host.ip` is blank until the node's tunnel is allocated, and a blank address
/// is a hard error here rather than a fallback to anything: dialling a default
/// would mean calling *some other machine* and believing its answer.
pub fn endpoint(host: &VmHost, path: &str) -> Result<String> {
    let address = host.ip.trim();
    if address.is_empty() {
        bail!(
            "Host {} has no control address yet, which means its tunnel has not been \
             allocated; there is nothing to call",
            host.id
        );
    }
    Ok(format!("https://{address}:{CONTROL_PORT}{path}"))
}

/// An HTTPS client that accepts exactly one certificate.
///
/// No CA, no name checking: the node's certificate is self-signed and its
/// "name" is an address inside a tunnel. What is checked is the one thing that
/// identifies the node — the fingerprint it registered — and a certificate that
/// does not match is refused however well-signed it is.
fn pinned_client(fingerprint: &[u8], timeout: Duration) -> Result<reqwest::Client> {
    let mut pinned = [0u8; 32];
    if fingerprint.len() != pinned.len() {
        bail!("A pinned certificate fingerprint must be 32 bytes");
    }
    pinned.copy_from_slice(fingerprint);

    // The provider is named rather than taken from process-wide state: reqwest
    // is built without one on purpose (so a deployment can choose), and a
    // client that panicked because nobody had installed one would take the API
    // down the first time a node was polled.
    let config = rustls::ClientConfig::builder_with_provider(pin::provider())
        .with_safe_default_protocol_versions()
        .context("Cannot configure TLS for a control call")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pin::PinnedCertificate::new(pinned)))
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .timeout(timeout)
        .build()
        .context("Cannot build a pinned HTTPS client")
}

mod pin {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    /// The crypto provider control calls use.
    ///
    /// Whatever the process installed, when it installed one, so a deployment
    /// that chose a provider keeps it — and ring otherwise, rather than the
    /// panic rustls raises when it cannot decide for itself.
    pub fn provider() -> Arc<CryptoProvider> {
        CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
    }

    /// Accepts one certificate, by its SHA-256, and nothing else.
    #[derive(Debug)]
    pub struct PinnedCertificate {
        expected: [u8; 32],
        provider: Arc<CryptoProvider>,
    }

    impl PinnedCertificate {
        pub fn new(expected: [u8; 32]) -> Self {
            Self {
                expected,
                provider: provider(),
            }
        }
    }

    impl ServerCertVerifier for PinnedCertificate {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let presented: [u8; 32] = {
                use nostr::hashes::{Hash, sha256};
                sha256::Hash::hash(end_entity.as_ref()).to_byte_array()
            };
            if presented == self.expected {
                Ok(ServerCertVerified::assertion())
            } else {
                // Named in full: the usual cause is a node that regenerated its
                // certificate and has not re-registered, and the operator needs
                // to know which value to compare against which.
                Err(Error::General(format!(
                    "Node presented certificate {}, not the pinned {}",
                    hex::encode(presented),
                    hex::encode(self.expected)
                )))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests;
