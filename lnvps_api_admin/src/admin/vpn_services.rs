//! VPN services: the product an account subscribes to, and the interfaces that
//! terminate it.
//!
//! A service is one price, one device allowance, and a set of regions. What a
//! customer buys is the whole set: a device holds one key and one address that
//! is valid on every interface linked here, and picking a region is a
//! client-side choice of which endpoint to dial. That is why linking an
//! interface is an operation on the service rather than an edit to the pool --
//! the pool does not record what it is for, and adding one to a service changes
//! what every existing device can reach.
//!
//! Under its own `vpn_service` resource rather than `router`, because the price
//! and the device allowance are pricing decisions that everyone who has already
//! bought the service is subject to. Revoking one customer's device is not; see
//! [`super::vpn_subscriptions`].

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, WorkJob,
    deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource, IntervalType, LNVpsDb, VpnService};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vpn_services",
            get(admin_list_vpn_services).post(admin_create_vpn_service),
        )
        .route(
            "/api/admin/v1/vpn_services/{id}",
            get(admin_get_vpn_service)
                .patch(admin_update_vpn_service)
                .delete(admin_delete_vpn_service),
        )
        .route(
            "/api/admin/v1/vpn_services/{id}/pools/{pool_id}",
            post(admin_link_vpn_service_pool).delete(admin_unlink_vpn_service_pool),
        )
}

/// One region a service is sold in, which is one interface a device may dial.
#[derive(serde::Serialize, Debug)]
pub struct AdminVpnServiceRegion {
    pub tunnel_pool_id: u64,
    pub region_id: u64,
    pub region_name: String,
    /// What a client dials for this region.
    pub endpoint: String,
    /// The interface's public key, hex.
    pub public_key: String,
    /// False while the interface is administratively down: the region stays
    /// linked and its devices keep their addresses, but nothing terminates
    /// there until it is back.
    pub enabled: bool,
}

#[derive(serde::Serialize, Debug)]
pub struct AdminVpnServiceInfo {
    pub id: u64,
    pub company_id: u64,
    pub name: String,
    pub currency: String,
    /// Recurring price, in the currency's smallest unit.
    pub amount: u64,
    pub interval_amount: u64,
    pub interval_type: IntervalType,
    /// One-off charge on the first payment, in the same unit as `amount`.
    pub setup_amount: u64,
    /// Resolvers handed to clients, comma-separated as stored.
    pub dns: Option<String>,
    /// Devices a plan may register. Enforced by the allocator against
    /// `vpn_device.slot`, so lowering it does not disconnect anyone already
    /// over the new limit -- it stops them adding more.
    pub default_device_limit: u8,
    /// False takes the service off sale without touching plans already paid
    /// for. This is how a service is retired; deleting one with subscribers is
    /// refused.
    pub enabled: bool,
    /// The regions it is sold in.
    pub regions: Vec<AdminVpnServiceRegion>,
    /// Plans currently sold against it. Deleting the service is refused while
    /// this is non-zero.
    pub subscriptions: u64,
    pub created: DateTime<Utc>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ListServicesQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    /// Include services that are off sale. Defaults to true, because an admin
    /// listing exists precisely to show what a customer cannot see.
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    include_disabled: Option<bool>,
}

#[derive(serde::Deserialize, Debug)]
pub struct CreateVpnServiceRequest {
    pub company_id: u64,
    pub name: String,
    pub currency: String,
    pub amount: u64,
    /// Defaults to 1 with `interval_type` month.
    pub interval_amount: Option<u64>,
    pub interval_type: Option<IntervalType>,
    pub setup_amount: Option<u64>,
    pub dns: Option<String>,
    /// Defaults to 5.
    pub default_device_limit: Option<u8>,
    /// Defaults to false: a service with no interfaces linked yet cannot serve
    /// anybody, so it is created off sale and enabled once its regions exist.
    pub enabled: Option<bool>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct UpdateVpnServiceRequest {
    /// `company_id` is deliberately absent: it decides who is billing, and
    /// moving a service between companies would leave existing plans invoiced
    /// by one and priced by another.
    pub name: Option<String>,
    pub currency: Option<String>,
    pub amount: Option<u64>,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<IntervalType>,
    pub setup_amount: Option<u64>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub dns: Option<Option<String>>,
    pub default_device_limit: Option<u8>,
    pub enabled: Option<bool>,
}

/// The default device allowance, matching the schema default. Five is a phone,
/// a laptop, a tablet and two spare.
const DEFAULT_DEVICE_LIMIT: u8 = 5;

async fn service_info(
    db: &std::sync::Arc<dyn LNVpsDb>,
    service: VpnService,
) -> Result<AdminVpnServiceInfo, ApiError> {
    let mut regions = Vec::new();
    for pool in db.list_vpn_service_pools(service.id).await? {
        let region = db.get_host_region(pool.region_id).await?;
        regions.push(AdminVpnServiceRegion {
            tunnel_pool_id: pool.id,
            region_id: pool.region_id,
            region_name: region.name,
            // Derived, so what a client is told to dial cannot disagree with
            // the socket that was configured.
            endpoint: pool.endpoint(),
            public_key: hex::encode(&pool.public_key),
            enabled: pool.enabled,
        });
    }

    let (_, subscriptions) = db
        .admin_list_vpn_subscriptions_filtered(1, 0, None, Some(service.id))
        .await?;

    Ok(AdminVpnServiceInfo {
        id: service.id,
        company_id: service.company_id,
        name: service.name,
        currency: service.currency,
        amount: service.amount,
        interval_amount: service.interval_amount,
        interval_type: service.interval_type,
        setup_amount: service.setup_amount,
        dns: service.dns,
        default_device_limit: service.default_device_limit,
        enabled: service.enabled,
        regions,
        subscriptions,
        created: service.created,
    })
}

async fn admin_list_vpn_services(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListServicesQuery>,
) -> ApiPaginatedResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let enabled_only = !params.include_disabled.unwrap_or(true);

    // Services are few -- one per product, not one per customer -- so this
    // pages in memory rather than earning a filtered query of its own.
    let all = this.db.list_vpn_services(enabled_only).await?;
    let total = all.len() as u64;

    let mut out = Vec::new();
    for service in all.into_iter().skip(offset as usize).take(limit as usize) {
        out.push(service_info(&this.db, service).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_vpn_service(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::View)?;
    let service = this.db.get_vpn_service(id).await?;
    ApiData::ok(service_info(&this.db, service).await?)
}

async fn admin_create_vpn_service(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVpnServiceRequest>,
) -> ApiResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::Create)?;

    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    // The company decides who bills and in what base currency, so a bad id here
    // surfaces now rather than at the first invoice.
    this.db.get_company(req.company_id).await?;

    let id = this
        .db
        .insert_vpn_service(&VpnService {
            id: 0,
            company_id: req.company_id,
            name: req.name.trim().to_string(),
            currency: req.currency.to_uppercase(),
            amount: req.amount,
            interval_amount: req.interval_amount.unwrap_or(1),
            interval_type: req.interval_type.unwrap_or(IntervalType::Month),
            setup_amount: req.setup_amount.unwrap_or(0),
            dns: req.dns.filter(|d| !d.trim().is_empty()),
            default_device_limit: req.default_device_limit.unwrap_or(DEFAULT_DEVICE_LIMIT),
            // Off sale by default: a service with no interfaces linked has no
            // region to connect to, so selling it would be selling nothing.
            enabled: req.enabled.unwrap_or(false),
            created: Utc::now(),
        })
        .await?;

    let service = this.db.get_vpn_service(id).await?;
    ApiData::ok(service_info(&this.db, service).await?)
}

async fn admin_update_vpn_service(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateVpnServiceRequest>,
) -> ApiResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::Update)?;

    let mut service = this.db.get_vpn_service(id).await?;
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("name cannot be blank"));
        }
        service.name = name.trim().to_string();
    }
    if let Some(currency) = req.currency {
        service.currency = currency.to_uppercase();
    }
    if let Some(amount) = req.amount {
        service.amount = amount;
    }
    if let Some(interval_amount) = req.interval_amount {
        service.interval_amount = interval_amount;
    }
    if let Some(interval_type) = req.interval_type {
        service.interval_type = interval_type;
    }
    if let Some(setup_amount) = req.setup_amount {
        service.setup_amount = setup_amount;
    }
    if let Some(dns) = req.dns {
        service.dns = dns.filter(|d| !d.trim().is_empty());
    }
    if let Some(limit) = req.default_device_limit {
        service.default_device_limit = limit;
    }
    if let Some(enabled) = req.enabled {
        service.enabled = enabled;
    }
    this.db.update_vpn_service(&service).await?;

    // A changed price or allowance does not touch any interface, but the DNS
    // servers are handed to clients in the configuration they download, so a
    // pushed peer set is not what changes -- the client's next fetch is.
    let service = this.db.get_vpn_service(id).await?;
    ApiData::ok(service_info(&this.db, service).await?)
}

/// Delete a service.
///
/// Refused while it has subscribers, by the foreign key: what is owed to
/// somebody cannot be deleted to tidy up. Taking a service off sale is
/// `enabled = false`, which stops new plans without touching paid ones.
///
/// The links to its interfaces cascade away; the interfaces themselves survive
/// and simply stop terminating anything.
async fn admin_delete_vpn_service(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::VpnService, AdminAction::Delete)?;

    let pools: Vec<u64> = this
        .db
        .list_vpn_service_pools(id)
        .await?
        .into_iter()
        .map(|p| p.id)
        .collect();

    this.db.delete_vpn_service(id).await?;

    // Each interface just lost its peers, so each has to be re-pushed or it
    // keeps serving devices whose service no longer exists.
    for pool_id in pools {
        dispatch_sync(&this, pool_id).await;
    }
    ApiData::ok(())
}

/// Link an interface to a service, making its region available to every device
/// on it.
///
/// The interface must carry the same address block as the service's others,
/// which the database enforces: a device holds one address in every region, so
/// an interface with a different block would route some devices and black-hole
/// the rest.
async fn admin_link_vpn_service_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, pool_id)): Path<(u64, u64)>,
) -> ApiResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::Update)?;

    // Both sides checked before the link, so a bad id is a 404 naming what is
    // missing rather than a foreign key error.
    this.db.get_vpn_service(id).await?;
    this.db.get_tunnel_pool(pool_id).await?;

    if let Some(existing) = this.db.get_vpn_service_for_pool(pool_id).await?
        && existing.id != id
    {
        return Err(ApiError::bad_request(format!(
            "Tunnel pool {pool_id} already terminates VPN service {} ({}). \
             An interface carries one peer set, so unlink it first.",
            existing.id, existing.name
        )));
    }

    this.db.link_vpn_service_pool(id, pool_id).await?;

    // The interface's peer set just changed from nothing to every device on the
    // service, so it has to be pushed before the region works.
    dispatch_sync(&this, pool_id).await;

    let service = this.db.get_vpn_service(id).await?;
    ApiData::ok(service_info(&this.db, service).await?)
}

/// Unlink an interface, withdrawing its region.
///
/// Devices keep their addresses and every other region: the address belongs to
/// the service, and this only stops one endpoint terminating them.
async fn admin_unlink_vpn_service_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, pool_id)): Path<(u64, u64)>,
) -> ApiResult<AdminVpnServiceInfo> {
    auth.require_permission(AdminResource::VpnService, AdminAction::Update)?;

    match this.db.get_vpn_service_for_pool(pool_id).await? {
        Some(linked) if linked.id == id => {}
        _ => {
            return Err(ApiError::bad_request(format!(
                "Tunnel pool {pool_id} does not terminate VPN service {id}"
            )));
        }
    }

    this.db.unlink_vpn_service_pool(pool_id).await?;

    // Without this the interface keeps every device configured on it, and
    // withdrawing a region would withdraw nothing.
    dispatch_sync(&this, pool_id).await;

    let service = this.db.get_vpn_service(id).await?;
    ApiData::ok(service_info(&this.db, service).await?)
}

async fn dispatch_sync(this: &RouterState, pool_id: u64) {
    if let Err(e) = this
        .work_commander
        .send(WorkJob::SyncTunnelPool { pool_id })
        .await
    {
        log::error!("Failed to queue tunnel pool sync for pool {pool_id}: {e}");
    }
}
