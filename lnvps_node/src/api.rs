//! Outbound calls to LNVPS.
//!
//! This is the only direction that works before a tunnel exists, which is why
//! the node fetches its data plane rather than being handed it: the control API
//! LNVPS would push it over is reachable *through* the tunnel it describes.
//!
//! Every call carries the node's own token. A node authenticates as itself,
//! never as its operator, so a compromised machine costs the operator that node
//! and nothing else.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::credential::Credential;
use crate::net::DesiredDataPlane;

/// A client for the LNVPS node API.
pub struct LnvpsApi {
    base_url: String,
    authorization: String,
    http: reqwest::Client,
}

/// The envelope every LNVPS response comes in.
#[derive(Deserialize)]
struct ApiResponse<T> {
    data: Option<T>,
    error: Option<String>,
}

impl LnvpsApi {
    pub fn new(base_url: &str, credential: &Credential) -> Result<Self> {
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            authorization: credential.authorization_header(),
            http: reqwest::Client::builder()
                // A node that cannot reach LNVPS must find out in seconds. The
                // default is no timeout at all, which turns an unreachable API
                // into a daemon that never finishes starting.
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .context("Cannot build an HTTP client")?,
        })
    }

    /// Present the node's public key and receive its tunnel allocation.
    ///
    /// Idempotent at the far end: a node that asks twice gets the allocation it
    /// already has, and one presenting a new key is re-pinned in place.
    pub async fn request_tunnel(&self, public_key: &[u8; 32]) -> Result<()> {
        let url = format!("{}/api/v1/node/tunnel", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("Authorization", &self.authorization)
            .json(&serde_json::json!({ "public_key": hex::encode(public_key) }))
            .send()
            .await
            .with_context(|| format!("Cannot reach LNVPS at {url}"))?;
        let _: serde_json::Value = decode(response, &url).await?;
        Ok(())
    }

    /// Fetch the data plane this node should be running.
    pub async fn dataplane(&self) -> Result<DesiredDataPlane> {
        let url = format!("{}/api/v1/node/dataplane", self.base_url);
        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.authorization)
            .send()
            .await
            .with_context(|| format!("Cannot reach LNVPS at {url}"))?;
        decode(response, &url).await
    }

    /// Present the certificate LNVPS should trust when driving this node's
    /// libvirtd.
    ///
    /// Sent on every apply rather than once. It is cheap and idempotent, and it
    /// means an LNVPS that lost its per-node trust directory — a fresh
    /// container, a moved volume — recovers on the next poll instead of leaving
    /// the node undialable until somebody notices.
    pub async fn register_libvirt_cert(&self, cert_pem: &str) -> Result<()> {
        let url = format!("{}/api/v1/node/libvirt", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("Authorization", &self.authorization)
            .json(&serde_json::json!({ "cert_pem": cert_pem }))
            .send()
            .await
            .with_context(|| format!("Cannot reach LNVPS at {url}"))?;
        let _: serde_json::Value = decode(response, &url).await?;
        Ok(())
    }
}

/// Unwrap an LNVPS response, preferring its own error message to the status.
///
/// The API reports failure in the body as often as in the status, and "500
/// Internal Server Error" tells an operator nothing they can act on where
/// "This node has no tunnel allocated yet" tells them exactly what to do.
async fn decode<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    url: &str,
) -> Result<T> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("Cannot read the response from {url}"))?;

    match serde_json::from_str::<ApiResponse<T>>(&body) {
        Ok(parsed) => {
            if let Some(error) = parsed.error {
                bail!("{url}: {error}");
            }
            match parsed.data {
                Some(data) => Ok(data),
                None => bail!("{url}: response carried neither data nor an error"),
            }
        }
        // Not an LNVPS envelope at all: a proxy error page, or the wrong URL.
        // Reporting the status and a bounded slice of the body beats a serde
        // message about a missing field.
        Err(e) => bail!(
            "{url}: {status}, and the response is not an LNVPS response ({e}): {}",
            body.chars().take(200).collect::<String>()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Deserialize, Debug, PartialEq)]
    struct Thing {
        value: u32,
    }

    fn response(status: u16, body: &str) -> reqwest::Response {
        reqwest::Response::from(
            http::Response::builder()
                .status(status)
                .body(body.to_string())
                .unwrap(),
        )
    }

    /// The ordinary case: the envelope's data is what the caller wanted.
    #[tokio::test]
    async fn a_successful_response_is_unwrapped() {
        let got: Thing = decode(response(200, r#"{"data":{"value":7}}"#), "u")
            .await
            .unwrap();
        assert_eq!(got, Thing { value: 7 });
    }

    /// The API reports failure in the body as often as in the status, and its
    /// message is the one an operator can act on.
    #[tokio::test]
    async fn the_apis_own_error_is_preferred_to_the_status() {
        let err = decode::<Thing>(
            response(404, r#"{"error":"This node has no tunnel allocated yet"}"#),
            "u",
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("no tunnel allocated"), "{err}");
    }

    /// A proxy error page is not an LNVPS response; saying so beats a serde
    /// message about a missing field.
    #[tokio::test]
    async fn a_non_lnvps_response_is_reported_with_its_status() {
        let err = decode::<Thing>(response(502, "<html>bad gateway</html>"), "u")
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("502"), "{text}");
        assert!(text.contains("bad gateway"), "{text}");
    }

    /// An envelope carrying neither half is a bug at the far end, and a node
    /// that treated it as success would apply an empty data plane.
    #[tokio::test]
    async fn an_empty_envelope_is_an_error() {
        assert!(decode::<Thing>(response(200, "{}"), "u").await.is_err());
    }

    fn credential() -> Credential {
        Credential::parse(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuaWQiOjd9.c2ln",
            std::path::Path::new("/etc/lnvps-node/token"),
        )
        .unwrap()
    }

    /// A real server on a real socket, because what is worth proving is the
    /// request that goes out: the node's token on every call, the public key
    /// presented before the document is asked for, and the document parsed as
    /// the node will actually apply it.
    #[tokio::test]
    async fn the_node_presents_its_key_and_fetches_its_document() {
        use axum::routing::{get, post};
        use std::sync::Arc;

        let seen: Arc<Mutex<Vec<(String, String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = axum::Router::new()
            .route(
                "/api/v1/node/tunnel",
                post(|headers: axum::http::HeaderMap, body: String| async move {
                    recorder.lock().unwrap().push((
                        "POST /api/v1/node/tunnel".to_string(),
                        headers
                            .get("authorization")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or_default()
                            .to_string(),
                        body,
                    ));
                    axum::Json(serde_json::json!({ "data": {} }))
                }),
            )
            .route(
                "/api/v1/node/dataplane",
                get(|| async {
                    axum::Json(serde_json::json!({ "data": {
                        "tunnel": {
                            "address4": "10.66.0.2/32",
                            "address6": null,
                            "gateway4": "10.66.0.1",
                            "gateway6": null,
                            "server_public_key": "ab".repeat(32),
                            "endpoint": "rs1.example:51820",
                            "keepalive": 25,
                            "mtu": 1420
                        },
                        "gateways": ["203.0.113.1"],
                        "guests": [
                            {"address": "203.0.113.5/32", "gateway": "203.0.113.1", "mac": null}
                        ]
                    }}))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let api = LnvpsApi::new(&format!("http://{addr}"), &credential()).unwrap();
        api.request_tunnel(&[0x11; 32]).await.unwrap();
        let plane = api.dataplane().await.unwrap();

        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1.starts_with("Bearer "), "{:?}", calls[0]);
        // Hex, as the rest of the node API states keys.
        assert!(
            calls[0].2.contains(&hex::encode([0x11u8; 32])),
            "{:?}",
            calls[0]
        );

        assert_eq!(plane.tunnel.mtu, 1420);
        assert_eq!(plane.guests.len(), 1);
        assert_eq!(plane.gateways, vec!["203.0.113.1".to_string()]);
    }

    /// An unreachable API is a message naming the URL, not a bare connection
    /// error: an operator reading a node's log has to know what it was dialling.
    #[tokio::test]
    async fn an_unreachable_api_names_what_it_was_dialling() {
        // Port 1 on localhost: nothing listens there, and nothing can.
        let api = LnvpsApi::new("http://127.0.0.1:1", &credential()).unwrap();
        let err = api.dataplane().await.unwrap_err();
        assert!(format!("{err:#}").contains("127.0.0.1:1"), "{err:#}");
        let err = api.request_tunnel(&[0x11; 32]).await.unwrap_err();
        assert!(format!("{err:#}").contains("node/tunnel"), "{err:#}");
    }

    /// The base URL is normalised so a trailing slash in the config file does
    /// not produce `//api/v1/...`, which some proxies redirect and others 404.
    #[test]
    fn the_base_url_is_normalised() {
        let credential = Credential::parse(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuaWQiOjd9.c2ln",
            std::path::Path::new("/etc/lnvps-node/token"),
        )
        .unwrap();
        let api = LnvpsApi::new("https://api.lnvps.net/", &credential).unwrap();
        assert_eq!(api.base_url, "https://api.lnvps.net");
        assert!(api.authorization.starts_with("Bearer "));
    }
}
