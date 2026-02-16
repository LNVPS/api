use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use lnvps_db::nostr::LNVPSNostrDb;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
struct RouterState {
    db: Arc<dyn LNVPSNostrDb>,
}

pub fn routes(db: Arc<dyn LNVPSNostrDb>) -> Router {
    Router::new()
        .route("/", get(async || Html(include_str!("../index.html"))))
        .route("/.well-known/nostr.json", get(nostr_address))
        .with_state(RouterState { db })
}

#[derive(Serialize)]
struct NostrJson {
    pub names: HashMap<String, String>,
    pub relays: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct NostrAddressQuery {
    name: Option<String>,
}

async fn nostr_address(
    State(this): State<RouterState>,
    headers: HeaderMap,
    Query(q): Query<NostrAddressQuery>,
) -> Result<Json<NostrJson>, &'static str> {
    let name = q.name.clone().unwrap_or("_".to_string());
    let host = headers
        .get("host")
        .and_then(|s| s.to_str().ok())
        .unwrap_or("lnvps.net");
    info!("Got request for {} on host {}", name, host);
    
    // First, try to get domain by hostname
    let domain = match this.db.get_domain_by_name(host).await {
        Ok(d) => d,
        Err(_) => {
            // If domain not found by hostname, check if name parameter is an activation hash
            // This supports the activation check: /.well-known/nostr.json?name=<hash>
            info!("Domain not found by hostname, checking if name is activation hash");
            this.db
                .get_domain_by_activation_hash(&name)
                .await
                .map_err(|_| "Domain not found")?
        }
    };
    
    // If we found domain by activation hash, return a simple success response
    // This allows the activation check to verify the path is reachable
    if q.name.is_some() && domain.activation_hash.as_ref() == Some(&name) {
        info!("Activation hash matched for domain {}", domain.name);
        return Ok(Json(NostrJson {
            names: HashMap::new(),
            relays: HashMap::new(),
        }));
    }
    
    let handle = this
        .db
        .get_handle_by_name(domain.id, &name)
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
