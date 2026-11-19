//! Asking LNVPS what this route server should be.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::VpnConfig;

/// The desired data plane, as LNVPS states it.
///
/// Mirrors `GET /api/v1/routeserver/dataplane`. Defined here rather than shared
/// with the API crate because the route server must not compile the database
/// and the payment stack to parse four structs, and because a daemon that
/// tolerates a field it does not know about is one that can be upgraded in
/// either order.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredDataPlane {
    pub generation: u64,
    pub interfaces: Vec<DesiredInterface>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredInterface {
    /// The pool this realises. The interface is named from it.
    pub pool_id: u64,
    pub private_key: String,
    pub listen_port: u16,
    pub mtu: u16,
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub peers: Vec<DesiredPeer>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DesiredPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

impl DesiredInterface {
    /// The interface this becomes.
    ///
    /// Derived from the pool id rather than carried in the document, and the
    /// same rule LNVPS uses: a name that arrived over the wire could be edited
    /// to point at an interface this pool does not own, and the next apply
    /// would rewrite somebody else's tunnel. The `wgln` prefix also keeps a
    /// managed interface from ever being confused with one the operator built.
    pub fn interface(&self) -> String {
        format!("wgln{}", self.pool_id)
    }
}

/// The shape of every LNVPS API response.
#[derive(Deserialize)]
struct ApiEnvelope<T> {
    data: Option<T>,
    error: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    #[cfg_attr(not(test), allow(dead_code))]
    api_url: String,
    token: String,
}

impl Client {
    pub fn new(config: &VpnConfig) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                // Comfortably longer than the longest wait LNVPS will hold a
                // request for. Too short and every held fetch looks like a
                // network failure; too long and a connection a NAT dropped
                // silently is one the daemon sits on instead of reconnecting.
                .timeout(config.wait() + std::time::Duration::from_secs(30))
                .build()
                .context("Cannot build an HTTP client")?,
            api_url: config.api_url.trim_end_matches('/').to_string(),
            token: config.token.clone(),
        })
    }

    /// Fetch the desired data plane, asking LNVPS to hold the request until it
    /// differs from `generation`.
    ///
    /// Returns whatever LNVPS says, including an unchanged document when the
    /// wait expired: the caller compares generations rather than being told
    /// separately, so there is one answer to "what should this machine be"
    /// instead of two that can disagree.
    pub async fn dataplane(&self, generation: u64, wait_secs: u64) -> Result<DesiredDataPlane> {
        let url = format!(
            "{}/api/v1/routeserver/dataplane?generation={generation}&wait={wait_secs}",
            self.api_url
        );
        let response = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("Cannot reach LNVPS")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Cannot read the response from LNVPS")?;

        if status == reqwest::StatusCode::UNAUTHORIZED {
            // Named, because it is the one failure that will never fix itself
            // and the one an operator can act on immediately.
            bail!("LNVPS rejected this route server's token");
        }
        if !status.is_success() {
            bail!("LNVPS answered {status}: {body}");
        }

        let envelope: ApiEnvelope<DesiredDataPlane> =
            serde_json::from_str(&body).context("Cannot parse the data plane LNVPS sent")?;
        match (envelope.data, envelope.error) {
            (Some(data), _) => Ok(data),
            (None, Some(e)) => bail!("LNVPS refused: {e}"),
            (None, None) => bail!("LNVPS sent neither a data plane nor a reason"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_is_named_from_its_pool() {
        let iface = DesiredInterface {
            pool_id: 7,
            private_key: String::new(),
            listen_port: 51820,
            mtu: 1420,
            addresses: vec![],
            routes: vec![],
            peers: vec![],
        };
        assert_eq!(iface.interface(), "wgln7");
    }

    /// Answer exactly one request with `status` and `body`, and report what was
    /// asked for. Enough to assert the daemon's half of the conversation
    /// without standing up the API.
    async fn one_shot(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            request
        });
        (format!("http://{addr}"), handle)
    }

    fn a_config(api_url: &str) -> crate::config::VpnConfig {
        crate::config::VpnConfig {
            api_url: api_url.to_string(),
            token: "7.s3cret".to_string(),
            wait_secs: 25,
            retry_secs: 5,
            scrub_after_secs: 600,
        }
    }

    #[tokio::test]
    async fn a_fetch_sends_the_generation_the_wait_and_the_token() {
        let body = r#"{"data":{"generation":9,"interfaces":[]}}"#;
        let (url, server) = one_shot("200 OK", body).await;

        let doc = Client::new(&a_config(&url))
            .unwrap()
            .dataplane(4, 25)
            .await
            .unwrap();

        assert_eq!(doc.generation, 9);
        let request = server.await.unwrap();
        assert!(request.contains("generation=4"), "{request}");
        assert!(request.contains("wait=25"), "{request}");
        // The whole credential, id included: LNVPS cannot look a router up by
        // its secret, because the column is encrypted per row.
        assert!(
            request.contains("authorization: Bearer 7.s3cret"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_rejected_token_says_so_plainly() {
        let (url, _server) = one_shot("401 Unauthorized", "nope").await;

        let err = Client::new(&a_config(&url))
            .unwrap()
            .dataplane(0, 0)
            .await
            .unwrap_err();

        // The one failure that will never fix itself, and the one an operator
        // can act on immediately. It must not read as a network problem.
        assert!(
            format!("{err:#}").contains("rejected this route server's token"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_refusal_carries_its_reason() {
        let body = r#"{"error":"Tunnel pool 7 has no block"}"#;
        let (url, _server) = one_shot("200 OK", body).await;

        let err = Client::new(&a_config(&url))
            .unwrap()
            .dataplane(0, 0)
            .await
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("Tunnel pool 7 has no block"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_a_document_is_not_silently_an_empty_one() {
        let (url, _server) = one_shot("200 OK", "<html>proxy error</html>").await;

        // An empty document would mean removing every peer on the machine,
        // which is what a captive portal or a misconfigured proxy would cause.
        let err = Client::new(&a_config(&url))
            .unwrap()
            .dataplane(0, 0)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("Cannot parse"), "{err:#}");
    }

    #[test]
    fn a_client_trims_a_trailing_slash_off_the_api_url() {
        // Otherwise every request would be built with a double slash, which
        // some proxies redirect and some reject.
        let config = crate::config::VpnConfig {
            api_url: "https://api.lnvps.net/".to_string(),
            token: "7.s3cret".to_string(),
            wait_secs: 25,
            retry_secs: 5,
            scrub_after_secs: 600,
        };
        assert_eq!(
            Client::new(&config).unwrap().api_url,
            "https://api.lnvps.net"
        );
    }

    #[test]
    fn a_document_with_fields_this_build_does_not_know_still_parses() {
        // Otherwise the API could never gain a field without every route
        // server having to be upgraded first, in lockstep, worldwide.
        let json = r#"{
            "generation": 3,
            "something_new": true,
            "interfaces": [{
                "pool_id": 1,
                "private_key": "k",
                "listen_port": 51820,
                "mtu": 1420,
                "addresses": ["10.64.0.1/24"],
                "routes": [],
                "peers": [{"public_key": "p", "allowed_ips": ["10.64.0.7/32"]}],
                "future_field": 9
            }]
        }"#;
        let doc: DesiredDataPlane = serde_json::from_str(json).unwrap();
        assert_eq!(doc.generation, 3);
        assert_eq!(doc.interfaces[0].peers[0].public_key, "p");
        // Absent optional fields are absent, not an error: a device has no
        // endpoint, because it is found by where it last spoke from.
        assert_eq!(doc.interfaces[0].peers[0].endpoint, None);
    }
}
