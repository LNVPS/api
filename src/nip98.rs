use anyhow::bail;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use log::debug;
use nostr::{Event, JsonUtil, Kind, Timestamp};
use reqwest::Url;
use rocket::http::uri::{Absolute, Uri};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::{async_trait, Request};

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
            if let Ok(u_req) = Uri::parse::<Absolute>(&url) {
                if path != u_req.absolute().unwrap().path() {
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

#[async_trait]
impl<'r> FromRequest<'r> for Nip98Auth {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(auth) = request.headers().get_one("authorization") {
            if !auth.starts_with("Nostr ") {
                return Outcome::Error((Status::new(403), "Auth scheme must be Nostr".to_string()));
            }
            let auth = Nip98Auth::from_base64(&auth[6..]).unwrap();
            match auth.check(
                request.uri().to_string().as_str(),
                request.method().as_str(),
            ) {
                Ok(_) => Outcome::Success(auth),
                Err(e) => Outcome::Error((Status::new(401), e.to_string())),
            }
        } else {
            Outcome::Error((Status::new(403), "Auth header not found".to_string()))
        }
    }
}
