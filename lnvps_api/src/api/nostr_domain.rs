use axum::extract::{Path, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{ApiData, ApiError, ApiResult, dns_name};
use lnvps_db::{NostrDomain, NostrDomainHandle};

use crate::Nip98Auth;
use crate::api::RouterState;
use crate::settings::Settings;

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
    let pubkey = auth.pubkey();
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
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let name = validate_domain(&this.settings, &data.name)?;
    let mut dom = NostrDomain {
        owner_id: uid,
        name,
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
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return Err(ApiError::forbidden("Access denied"));
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
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return Err(ApiError::forbidden("Access denied"));
    }

    let h_pubkey =
        hex::decode(&data.pubkey).map_err(|_| ApiError::new("Invalid public key hex encoding"))?;
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
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let domain = this.db.get_domain(dom).await?;
    if domain.owner_id != uid {
        return Err(ApiError::forbidden("Access denied"));
    }
    this.db.delete_handle(handle).await?;
    ApiData::ok(())
}

/// Check a customer-supplied NIP-05 domain before it becomes a row.
///
/// Two failures were reaching the database: names that are not domains at all
/// (a pasted URL, a host with a port, `localhost`), which can never be pointed
/// at us and leave an Ingress rule that serves nothing, and the operator's own
/// hostnames. The second is the one that matters: the name becomes an Ingress
/// rule in LNVPS's cluster claiming that host, and the unique index means
/// whoever registers it also denies it to everyone else.
fn validate_domain(settings: &Settings, name: &str) -> Result<String, ApiError> {
    let name =
        dns_name::validate_public_domain(name).map_err(|e| ApiError::bad_request(e.to_string()))?;

    for suffix in reserved_domains(settings) {
        if dns_name::is_under(&name, &suffix) {
            return Err(ApiError::bad_request(format!(
                "'{name}' is not available: '{suffix}' is reserved"
            )));
        }
    }
    Ok(name)
}

/// Everything this deployment refuses to serve a customer's NIP-05 document
/// from: its own hostnames and their parent domain, plus the operator's list.
pub(crate) fn reserved_domains(settings: &Settings) -> Vec<String> {
    let configured: Vec<String> = [
        dns_name::host_of(&settings.public_url),
        settings
            .nostr_address_host
            .as_deref()
            .and_then(dns_name::host_of),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut out = dns_name::reserved_suffixes(configured.iter().map(String::as_str));
    for extra in &settings.reserved_domains {
        if let Ok(d) = dns_name::validate_public_domain(extra)
            && !out.contains(&d)
        {
            out.push(d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::mock_settings;

    fn settings() -> Settings {
        let mut s = mock_settings();
        s.public_url = "https://api.lnvps.net".to_string();
        s.nostr_address_host = Some("nostr.lnvps.net".to_string());
        s
    }

    #[test]
    fn a_customer_domain_is_stored_in_its_canonical_form() {
        assert_eq!(
            validate_domain(&settings(), " Nostr.MyRelay.COM. ").unwrap(),
            "nostr.myrelay.com"
        );
    }

    /// Regression test: `api.lnvps.net` was accepted. The row becomes an
    /// Ingress rule claiming that host in LNVPS's own cluster, and the unique
    /// index on the name means registering it also denies it to everyone else.
    #[test]
    fn an_internal_domain_is_refused() {
        let s = settings();
        for internal in [
            "api.lnvps.net",
            "API.LNVPS.NET",
            "nostr.lnvps.net",
            "lnvps.net",
            "anything.at.all.lnvps.net",
        ] {
            let err = validate_domain(&s, internal)
                .err()
                .unwrap_or_else(|| panic!("'{internal}' was accepted"));
            assert_eq!(err.code.as_u16(), 400, "{}", err.error);
            assert!(err.error.contains("reserved"), "{}", err.error);
        }
        // A name that merely looks similar is still the customer's to register.
        assert!(validate_domain(&s, "notlnvps.net").is_ok());
    }

    /// The operator's list covers hostnames that are not in the config, which
    /// is most of them.
    #[test]
    fn the_operator_can_reserve_more() {
        let mut s = settings();
        s.reserved_domains = vec!["lnvps.com".to_string()];
        assert!(validate_domain(&s, "shop.lnvps.com").is_err());
        assert!(validate_domain(&s, "shop.lnvps.cloud").is_ok());
    }

    /// Regression test: a pasted URL, a host with a port and `localhost` were
    /// all stored verbatim, leaving an Ingress rule that can never serve.
    #[test]
    fn a_name_that_is_not_a_domain_is_refused() {
        let s = settings();
        for bad in [
            "https://nostr.myrelay.com",
            "nostr.myrelay.com:8080",
            "user@myrelay.com",
            "localhost",
            "myrelay",
            "192.168.1.1",
            "",
        ] {
            let err = validate_domain(&s, bad)
                .err()
                .unwrap_or_else(|| panic!("'{bad}' was accepted"));
            assert_eq!(err.code.as_u16(), 400, "{}", err.error);
        }
    }
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
