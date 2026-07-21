//! [Krill](https://www.nlnetlabs.nl/projects/routing/krill/) delegated-RPKI
//! client for issuing/withdrawing ROAs.
//!
//! We run our own RPKI CA (Krill) rather than using RIPE's hosted RPKI service,
//! because the hosted service's API is limited to LIR members and cannot sign
//! ROAs for sponsored / sub-allocated space. Krill lets us author ROAs for any
//! resource delegated to our CA.
//!
//! ROA management uses Krill's route-authorisation endpoints
//! (`/api/v1/cas/{ca}/routes`), authorised with the Krill admin bearer token:
//!
//! * list — `GET /api/v1/cas/{ca}/routes`;
//! * update — `POST /api/v1/cas/{ca}/routes` with `{ "added": [...], "removed": [...] }`.

use crate::json_api::JsonApi;
use crate::registry::{RoaDefinition, RpkiProvider};
use crate::retry::OpResult;
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::info;
use serde::{Deserialize, Serialize};

/// Krill REST client bound to a single CA handle.
pub struct Krill {
    api: JsonApi,
    /// The CA handle (Krill "child"/CA name) that owns the ROAs.
    ca: String,
}

impl Krill {
    /// Build a client for `base` (e.g. `https://krill.example.com`) authorised
    /// with the Krill admin `token`, managing ROAs under CA `ca`.
    pub fn new(base: &str, token: &str, ca: &str) -> anyhow::Result<Self> {
        Ok(Self {
            api: JsonApi::token(base, &format!("Bearer {}", token), false)?,
            ca: ca.to_string(),
        })
    }

    fn routes_path(&self) -> String {
        format!("/api/v1/cas/{}/routes", self.ca)
    }

    async fn update(&self, updates: RoaUpdates) -> OpResult<()> {
        let _: serde_json::Value = self.api.post(&self.routes_path(), updates).await?;
        Ok(())
    }
}

#[async_trait]
impl RpkiProvider for Krill {
    async fn add_roa(&self, roa: &RoaDefinition) -> OpResult<()> {
        info!(
            "Adding ROA {} max {} for {}",
            roa.prefix,
            roa.effective_max_length(),
            format_asn(roa.origin_asn)
        );
        self.update(RoaUpdates {
            added: vec![KrillRoa::from(roa)],
            removed: vec![],
        })
        .await
    }

    async fn remove_roa(&self, roa: &RoaDefinition) -> OpResult<()> {
        info!(
            "Removing ROA {} for {}",
            roa.prefix,
            format_asn(roa.origin_asn)
        );
        self.update(RoaUpdates {
            added: vec![],
            removed: vec![KrillRoa::from(roa)],
        })
        .await
    }

    async fn list_roas(&self) -> OpResult<Vec<RoaDefinition>> {
        let roas: Vec<KrillRoa> = self.api.get(&self.routes_path()).await?;
        Ok(roas.iter().filter_map(KrillRoa::to_definition).collect())
    }
}

/// Format a bare ASN as Krill expects, e.g. `AS3333`.
fn format_asn(asn: u32) -> String {
    format!("AS{}", asn)
}

/// Parse a Krill ASN string (`AS3333` or `3333`) back to a bare number.
fn parse_asn(s: &str) -> Option<u32> {
    s.trim()
        .strip_prefix("AS")
        .or_else(|| s.trim().strip_prefix("as"))
        .unwrap_or(s.trim())
        .parse()
        .ok()
}

#[derive(Debug, Serialize)]
struct RoaUpdates {
    added: Vec<KrillRoa>,
    removed: Vec<KrillRoa>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KrillRoa {
    asn: String,
    prefix: String,
    max_length: u8,
}

impl KrillRoa {
    fn from(roa: &RoaDefinition) -> Self {
        Self {
            asn: format_asn(roa.origin_asn),
            prefix: roa.prefix.to_string(),
            max_length: roa.effective_max_length(),
        }
    }

    fn to_definition(&self) -> Option<RoaDefinition> {
        let prefix: IpNetwork = self.prefix.parse().ok()?;
        Some(RoaDefinition {
            origin_asn: parse_asn(&self.asn)?,
            prefix,
            max_length: Some(self.max_length),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn roa() -> RoaDefinition {
        RoaDefinition {
            origin_asn: 3333,
            prefix: "193.0.0.0/24".parse().unwrap(),
            max_length: None,
        }
    }

    #[test]
    fn test_asn_format_and_parse() {
        assert_eq!(format_asn(3333), "AS3333");
        assert_eq!(parse_asn("AS3333"), Some(3333));
        assert_eq!(parse_asn("as64500"), Some(64500));
        assert_eq!(parse_asn("64500"), Some(64500));
        assert_eq!(parse_asn("bogus"), None);
    }

    #[test]
    fn test_krill_roa_roundtrip() {
        let k = KrillRoa::from(&roa());
        assert_eq!(k.asn, "AS3333");
        assert_eq!(k.prefix, "193.0.0.0/24");
        assert_eq!(k.max_length, 24); // falls back to prefix length
        let d = k.to_definition().unwrap();
        assert_eq!(d.origin_asn, 3333);
        assert_eq!(d.max_length, Some(24));
    }

    #[tokio::test]
    async fn test_add_roa_posts_update() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cas/lnvps/routes"))
            .and(body_partial_json(serde_json::json!({
                "added": [ { "asn": "AS3333", "prefix": "193.0.0.0/24", "max_length": 24 } ],
                "removed": []
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let k = Krill::new(&server.uri(), "secret", "lnvps")?;
        k.add_roa(&roa()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_remove_roa_posts_update() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/cas/lnvps/routes"))
            .and(body_partial_json(serde_json::json!({
                "added": [],
                "removed": [ { "asn": "AS3333", "prefix": "193.0.0.0/24", "max_length": 24 } ]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let k = Krill::new(&server.uri(), "secret", "lnvps")?;
        k.remove_roa(&roa()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_list_roas_parses() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/cas/lnvps/routes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "asn": "AS3333", "prefix": "193.0.0.0/24", "max_length": 24 },
                { "asn": "AS64500", "prefix": "2001:db8::/48", "max_length": 48 },
                { "asn": "bad", "prefix": "garbage", "max_length": 0 }
            ])))
            .mount(&server)
            .await;

        let k = Krill::new(&server.uri(), "secret", "lnvps")?;
        let roas = k.list_roas().await?;
        // The unparseable entry is skipped.
        assert_eq!(roas.len(), 2);
        assert_eq!(roas[0].origin_asn, 3333);
        assert_eq!(roas[1].prefix.to_string(), "2001:db8::/48");
        Ok(())
    }
}
