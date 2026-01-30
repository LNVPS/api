use anyhow::bail;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, Uri, request::Parts},
};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::debug;
use nostr::{Event, JsonUtil, Kind, Timestamp};

pub struct Nip98Auth {
    pub event: Event,
}

impl Nip98Auth {
    pub fn check(&self, path: &str, method: &str) -> anyhow::Result<()> {
        if self.event.kind != Kind::HttpAuth {
            bail!("Wrong event kind");
        }
        if self
            .event
            .created_at
            .as_u64()
            .abs_diff(Timestamp::now().as_u64())
            > 600
        {
            bail!("Created timestamp is out of range");
        }

        // check url tag
        if let Some(url) = self.event.tags.iter().find_map(|t| {
            let vec = t.as_slice();
            if vec[0] == "u" {
                Some(vec[1].clone())
            } else {
                None
            }
        }) {
            // Simple path comparison - extract path from URL
            if let Ok(parsed_uri) = url.parse::<Uri>() {
                if path != parsed_uri.path() {
                    bail!("U tag does not match");
                }
            } else {
                bail!("Invalid U tag");
            }
        } else {
            bail!("Missing url tag");
        }

        // check method tag
        if let Some(t_method) = self.event.tags.iter().find_map(|t| {
            let vec = t.as_slice();
            if vec[0] == "method" {
                Some(vec[1].clone())
            } else {
                None
            }
        }) {
            if method != t_method {
                bail!("Method tag incorrect")
            }
        } else {
            bail!("Missing method tag")
        }

        if let Err(_err) = self.event.verify() {
            bail!("Event signature invalid");
        }

        debug!("{}", self.event.as_json());
        Ok(())
    }

    pub fn from_base64(i: &str) -> anyhow::Result<Self> {
        if let Ok(j) = BASE64_STANDARD.decode(i) {
            if let Ok(ev) = Event::from_json(j) {
                Ok(Self { event: ev })
            } else {
                bail!("Invalid nostr event")
            }
        } else {
            bail!("Invalid auth string");
        }
    }
}

impl<S> FromRequestParts<S> for Nip98Auth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        Box::pin(async {
            let auth_header = parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .ok_or((StatusCode::FORBIDDEN, "Auth header not found".to_string()))?;

            if !auth_header.starts_with("Nostr ") {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Auth scheme must be Nostr".to_string(),
                ));
            }

            let auth = Nip98Auth::from_base64(&auth_header[6..])
                .map_err(|e| (StatusCode::UNAUTHORIZED, format!("Invalid auth: {}", e)))?;

            let path = parts.uri.path();
            let method = parts.method.as_str();

            auth.check(path, method).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("Auth check failed: {}", e),
                )
            })?;

            Ok(auth)
        })
    }
}
