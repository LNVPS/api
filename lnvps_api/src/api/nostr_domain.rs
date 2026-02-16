use crate::Nip98Auth;
use crate::api::RouterState;
use axum::extract::{Path, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiData, ApiError, ApiResult};
use lnvps_db::{NostrDomain, NostrDomainHandle};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/nostr/domain",
            get(v1_nostr_domains).post(v1_create_nostr_domain),
        )
        .route(
            "/api/v1/nostr/domain/<dom>/handle",
            get(v1_list_nostr_domain_handles).post(v1_create_nostr_domain_handle),
        )
        .route(
            "/api/v1/nostr/domain/<dom>/handle/<handle>",
            delete(v1_delete_nostr_domain_handle),
        )
}

async fn v1_nostr_domains(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<ApiDomainsResponse> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domains = this.db.list_domains(uid).await?;
    ApiData::ok(ApiDomainsResponse {
        domains: domains.into_iter().map(|d| d.into()).collect(),
        cname: this.settings.nostr_address_host.clone().unwrap_or_default(),
    })
}

async fn v1_create_nostr_domain(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(data): Json<NameRequest>,
) -> ApiResult<ApiNostrDomain> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let mut dom = NostrDomain {
        owner_id: uid,
        name: data.name.clone(),
        activation_hash: Some(uuid::Uuid::new_v4().to_string()),
        ..Default::default()
    };
    let dom_id = this.db.insert_domain(&dom).await?;
    dom.id = dom_id;

    ApiData::ok(dom.into())
}

async fn v1_list_nostr_domain_handles(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(dom): Path<u64>,
) -> ApiResult<Vec<ApiNostrDomainHandle>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return ApiData::err("Access denied");
    }

    let handles = this.db.list_handles(domain.id).await?;
    ApiData::ok(handles.into_iter().map(|h| h.into()).collect())
}

async fn v1_create_nostr_domain_handle(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(dom): Path<u64>,
    data: Json<HandleRequest>,
) -> ApiResult<ApiNostrDomainHandle> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return ApiData::err("Access denied");
    }

    let h_pubkey = hex::decode(&data.pubkey)
        .map_err(|_| ApiError::new("Invalid public key hex encoding"))?;
    if h_pubkey.len() != 32 {
        return ApiData::err("Invalid public key");
    }

    let mut handle = NostrDomainHandle {
        domain_id: domain.id,
        handle: data.name.clone(),
        pubkey: h_pubkey,
        ..Default::default()
    };
    let id = this.db.insert_handle(&handle).await?;
    handle.id = id;

    ApiData::ok(handle.into())
}

async fn v1_delete_nostr_domain_handle(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(dom): Path<u64>,
    Path(handle): Path<u64>,
) -> ApiResult<()> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return ApiData::err("Access denied");
    }
    this.db.delete_handle(handle).await?;
    ApiData::ok(())
}

#[derive(Deserialize)]
struct NameRequest {
    pub name: String,
}

#[derive(Deserialize)]
struct HandleRequest {
    pub pubkey: String,
    pub name: String,
}

#[derive(Serialize)]
struct ApiNostrDomain {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub handles: u64,
    pub created: DateTime<Utc>,
    pub relays: Vec<String>,
}

impl From<NostrDomain> for ApiNostrDomain {
    fn from(value: NostrDomain) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enabled: value.enabled,
            handles: value.handles as u64,
            created: value.created,
            relays: if let Some(r) = value.relays {
                r.split(',').map(|s| s.to_string()).collect()
            } else {
                vec![]
            },
        }
    }
}

#[derive(Serialize)]
struct ApiNostrDomainHandle {
    pub id: u64,
    pub domain_id: u64,
    pub handle: String,
    pub created: DateTime<Utc>,
    pub pubkey: String,
    pub relays: Vec<String>,
}

impl From<NostrDomainHandle> for ApiNostrDomainHandle {
    fn from(value: NostrDomainHandle) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            created: value.created,
            handle: value.handle,
            pubkey: hex::encode(value.pubkey),
            relays: if let Some(r) = value.relays {
                r.split(',').map(|s| s.to_string()).collect()
            } else {
                vec![]
            },
        }
    }
}

#[derive(Serialize)]
struct ApiDomainsResponse {
    pub domains: Vec<ApiNostrDomain>,
    pub cname: String,
}
