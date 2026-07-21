//! RIPE Database (whois) REST client for IRR `route`/`route6` objects.
//!
//! Uses the [RIPE Database RESTful API](https://docs.db.ripe.net/Update-Methods/RESTful-API):
//!
//! * create — `POST /{source}/{type}` with a *whois resources* JSON document;
//! * delete — `DELETE /{source}/{type}/{primary-key}`.
//!
//! Write operations are authorised with a maintainer password supplied as the
//! `password` query parameter. (RIPE is migrating to API keys; this prototype
//! targets the long-stable password method and keeps the key opaque so the auth
//! mechanism can be swapped without touching the object mapping.)
//!
//! Note on authorisation: creating a `route` object requires *three-tier*
//! authorisation in RIPE — the object's own `mnt-by`, the covering address
//! space maintainer, and the origin `aut-num` maintainer. This client passes a
//! single maintainer password; multi-maintainer setups pass the relevant
//! password(s) via configuration on the space itself.

use crate::json_api::JsonApi;
use crate::op_transient;
use crate::registry::{RegistryProvider, RegistryRef, RouteObject};
use crate::retry::OpResult;
use async_trait::async_trait;
use log::info;
use serde::{Deserialize, Serialize};

/// RIPE whois REST client bound to a single source (`ripe`, `test`, ...).
pub struct RipeDb {
    api: JsonApi,
    /// Whois source, e.g. `ripe` (upper-cased in object bodies as `RIPE`).
    source: String,
    /// Maintainer password used to authorise writes.
    password: String,
}

impl RipeDb {
    /// Production RIPE database client.
    pub fn new(source: &str, password: &str) -> anyhow::Result<Self> {
        Self::with_base("https://rest.db.ripe.net", source, password)
    }

    /// Client pointed at an arbitrary base URL (tests / the RIPE TEST db).
    pub fn with_base(base: &str, source: &str, password: &str) -> anyhow::Result<Self> {
        Ok(Self {
            api: JsonApi::new(base)?,
            source: source.to_string(),
            password: password.to_string(),
        })
    }

    /// Build the whois-resources document for creating a route object.
    fn build_body(&self, obj: &RouteObject) -> WhoisResources {
        let src = self.source.to_uppercase();
        let attribute = vec![
            Attribute::new(obj.object_type(), &obj.prefix.to_string()),
            Attribute::new("descr", &obj.description),
            Attribute::new("origin", &obj.origin()),
            Attribute::new("mnt-by", &obj.maintainer),
            Attribute::new("source", &src),
        ];
        WhoisResources {
            objects: WhoisObjects {
                object: vec![WhoisObject {
                    attributes: Attributes { attribute },
                }],
            },
        }
    }

    /// Surface RIPE `errormessages` (validation / auth failures) as errors.
    fn bail_error(rsp: &WhoisResponse) -> OpResult<()> {
        if let Some(errs) = &rsp.errormessages
            && !errs.errormessage.is_empty()
        {
            let msg = errs
                .errormessage
                .iter()
                .map(|e| e.render())
                .collect::<Vec<_>>()
                .join("; ");
            op_transient!("RIPE error: {}", msg);
        }
        Ok(())
    }
}

#[async_trait]
impl RegistryProvider for RipeDb {
    async fn create_route_object(&self, obj: &RouteObject) -> OpResult<RegistryRef> {
        info!(
            "Creating RIPE {} object {} origin {}",
            obj.object_type(),
            obj.prefix,
            obj.origin()
        );
        let path = format!(
            "/{}/{}?password={}",
            self.source,
            obj.object_type(),
            urlencoding_min(&self.password)
        );
        let rsp: WhoisResponse = self.api.post(&path, self.build_body(obj)).await?;
        Self::bail_error(&rsp)?;
        Ok(RegistryRef(obj.primary_key()))
    }

    async fn delete_route_object(&self, obj: &RouteObject) -> OpResult<()> {
        info!(
            "Deleting RIPE {} object {}",
            obj.object_type(),
            obj.primary_key()
        );
        let path = format!(
            "/{}/{}/{}?password={}",
            self.source,
            obj.object_type(),
            obj.primary_key(),
            urlencoding_min(&self.password)
        );
        let rsp: WhoisResponse = self
            .api
            .req(reqwest::Method::DELETE, &path, None::<()>)
            .await?;
        Self::bail_error(&rsp)?;
        Ok(())
    }
}

/// Minimal percent-encoding for the handful of characters that can appear in a
/// maintainer password and would otherwise break the query string. Avoids
/// pulling in a dependency for a prototype.
fn urlencoding_min(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// RIPE whois "resources" JSON model (subset)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct WhoisResources {
    objects: WhoisObjects,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WhoisObjects {
    object: Vec<WhoisObject>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WhoisObject {
    attributes: Attributes,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Attributes {
    attribute: Vec<Attribute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attribute {
    name: String,
    value: String,
}

impl Attribute {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// Response envelope; only `errormessages` is meaningful for our purposes.
#[derive(Debug, Default, Deserialize)]
struct WhoisResponse {
    #[serde(default)]
    errormessages: Option<ErrorMessages>,
}

#[derive(Debug, Default, Deserialize)]
struct ErrorMessages {
    #[serde(default)]
    errormessage: Vec<ErrorMessage>,
}

#[derive(Debug, Deserialize)]
struct ErrorMessage {
    #[serde(default)]
    text: String,
    #[serde(default)]
    args: Vec<ErrorArg>,
}

#[derive(Debug, Deserialize)]
struct ErrorArg {
    #[serde(default)]
    value: String,
}

impl ErrorMessage {
    /// RIPE error text uses `%s` placeholders filled from `args`.
    fn render(&self) -> String {
        let mut out = self.text.clone();
        for a in &self.args {
            out = out.replacen("%s", &a.value, 1);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn obj() -> RouteObject {
        RouteObject {
            prefix: "193.0.0.0/24".parse().unwrap(),
            origin_asn: 3333,
            description: "LNVPS customer".to_string(),
            maintainer: "LNVPS-MNT".to_string(),
        }
    }

    #[test]
    fn test_build_body_attributes() {
        let db = RipeDb::with_base("http://localhost", "ripe", "pw").unwrap();
        let body = db.build_body(&obj());
        let attrs = &body.objects.object[0].attributes.attribute;
        let get = |n: &str| attrs.iter().find(|a| a.name == n).map(|a| a.value.clone());
        assert_eq!(get("route").as_deref(), Some("193.0.0.0/24"));
        assert_eq!(get("origin").as_deref(), Some("AS3333"));
        assert_eq!(get("mnt-by").as_deref(), Some("LNVPS-MNT"));
        assert_eq!(get("source").as_deref(), Some("RIPE"));
    }

    #[test]
    fn test_error_message_render() {
        let e = ErrorMessage {
            text: "Unknown object %s referenced from %s".to_string(),
            args: vec![
                ErrorArg {
                    value: "AS3333".to_string(),
                },
                ErrorArg {
                    value: "origin".to_string(),
                },
            ],
        };
        assert_eq!(e.render(), "Unknown object AS3333 referenced from origin");
    }

    #[test]
    fn test_urlencoding_min() {
        assert_eq!(urlencoding_min("abcXYZ09-_.~"), "abcXYZ09-_.~");
        assert_eq!(urlencoding_min("a b&c"), "a%20b%26c");
    }

    #[tokio::test]
    async fn test_create_route_object_ok() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ripe/route"))
            .and(query_param("password", "pw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": { "object": [ { "attributes": { "attribute": [] } } ] }
            })))
            .mount(&server)
            .await;

        let db = RipeDb::with_base(&server.uri(), "ripe", "pw")?;
        let r = db.create_route_object(&obj()).await?;
        assert_eq!(r, RegistryRef("193.0.0.0/24AS3333".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn test_create_route_object_error() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/ripe/route"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errormessages": { "errormessage": [
                    { "text": "Authorisation for %s failed", "args": [ { "value": "route" } ] }
                ] }
            })))
            .mount(&server)
            .await;

        let db = RipeDb::with_base(&server.uri(), "ripe", "pw")?;
        let err = db.create_route_object(&obj()).await.unwrap_err();
        assert!(err.to_string().contains("Authorisation for route failed"));
        Ok(())
    }

    #[tokio::test]
    async fn test_delete_route_object_ok() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/ripe/route/193.0.0.0/24AS3333"))
            .and(query_param("password", "pw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let db = RipeDb::with_base(&server.uri(), "ripe", "pw")?;
        db.delete_route_object(&obj()).await?;
        Ok(())
    }
}
