use lnvps_db::nostr::LNVPSNostrDb;
use log::info;
use rocket::http::ContentType;
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::{Request, Route, State, routes};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

pub fn routes() -> Vec<Route> {
    routes![get_index, nostr_address]
}

#[derive(Serialize)]
struct NostrJson {
    pub names: HashMap<String, String>,
    pub relays: HashMap<String, Vec<String>>,
}

struct HostInfo<'r> {
    pub host: Option<&'r str>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for HostInfo<'r> {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(HostInfo {
            host: request.host().map(|h| h.domain().as_str()),
        })
    }
}

#[rocket::get("/", format = "html")]
fn get_index() -> (ContentType, &'static str) {
    const HTML: &str = include_str!("../index.html");
    (ContentType::HTML, HTML)
}

#[rocket::get("/.well-known/nostr.json?<name>")]
async fn nostr_address(
    host: HostInfo<'_>,
    db: &State<Arc<dyn LNVPSNostrDb>>,
    name: Option<&str>,
) -> Result<Json<NostrJson>, &'static str> {
    let name = name.unwrap_or("_");
    let host = host.host.unwrap_or("lnvps.net");
    info!("Got request for {} on host {}", name, host);
    let domain = db
        .get_domain_by_name(host)
        .await
        .map_err(|_| "Domain not found")?;
    let handle = db
        .get_handle_by_name(domain.id, name)
        .await
        .map_err(|_| "Handle not found")?;

    let pubkey_hex = hex::encode(handle.pubkey);
    let relays = if let Some(r) = handle.relays {
        r.split(",").map(|x| x.to_string()).collect()
    } else if let Some(r) = domain.relays {
        r.split(",").map(|x| x.to_string()).collect()
    } else {
        vec![]
    };
    Ok(Json(NostrJson {
        names: HashMap::from([(name.to_string(), pubkey_hex.clone())]),
        relays: HashMap::from([(pubkey_hex, relays)]),
    }))
}
