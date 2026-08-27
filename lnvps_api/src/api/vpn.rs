//! Customer-facing VPN endpoints.
//!
//! A customer buys one plan, registers up to their device allowance of public
//! keys, and downloads one config per region. Region is a client-side choice:
//! every config a device gets shares an identical `[Interface]` block and
//! differs only in the `[Peer]` endpoint and public key, which is what makes
//! switching regions instant and stateless here.

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth, wireguard_key_to_base64};
use lnvps_db::{VpnDevice, VpnSubscription};
use serde::{Deserialize, Serialize};

use crate::api::RouterState;
use crate::provisioner::register_vpn_device;
use crate::subscription::create_vpn_plan;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/vpn/services", get(v1_list_vpn_services))
        .route("/api/v1/vpn", get(v1_get_vpn_plan).post(v1_create_vpn_plan))
        .route(
            "/api/v1/vpn/devices",
            get(v1_list_vpn_devices).post(v1_add_vpn_device),
        )
        .route("/api/v1/vpn/devices/{id}", delete(v1_delete_vpn_device))
        .route(
            "/api/v1/vpn/devices/{id}/configs",
            get(v1_vpn_device_configs),
        )
        .route(
            "/api/v1/vpn/devices/{id}/enabled",
            post(v1_set_vpn_device_enabled),
        )
}

/// A VPN plan offered for sale.
#[derive(Serialize)]
pub struct ApiVpnService {
    pub id: u64,
    pub name: String,
    /// Recurring price, in cents / milli-sats of [`currency`](Self::currency).
    pub amount: u64,
    /// One-off amount charged on the first payment.
    pub setup_amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: lnvps_api_common::ApiIntervalType,
    /// How many devices a plan on this service may register.
    pub device_limit: u8,
    /// Whether the service hands out IPv4 addresses, IPv6, or both. A client
    /// needs this to know what its tunnel will actually carry.
    pub ipv4: bool,
    pub ipv6: bool,
    /// The regions a device on this service can connect through. Every one of
    /// them accepts every device, so this is a menu, not an allocation.
    pub regions: Vec<ApiVpnRegion>,
}

/// One place a device can connect through.
#[derive(Serialize)]
pub struct ApiVpnRegion {
    pub region_id: u64,
    pub name: String,
    /// Two-letter country code of the exit, when the region records one.
    pub country_code: Option<String>,
}

/// A customer's plan.
#[derive(Serialize)]
pub struct ApiVpnPlan {
    pub id: u64,
    pub service_id: u64,
    /// Devices this plan may register.
    pub device_limit: u8,
    /// Devices registered so far, so a client can show "3 of 5" without
    /// fetching the list.
    pub device_count: u8,
    /// The subscription to pay. Until it is paid the plan configures nothing.
    pub subscription_id: u64,
    /// `unpaid`, `active` or `expired`.
    pub billing_state: lnvps_db::BillingState,
    pub expires: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
}

/// A registered device.
#[derive(Serialize)]
pub struct ApiVpnDevice {
    pub id: u64,
    pub name: String,
    /// The public key the customer registered, base64 as `wg` writes it.
    pub public_key: String,
    /// The device's addresses, identical in every region.
    pub address4: Option<String>,
    pub address6: Option<String>,
    pub enabled: bool,
    pub created: DateTime<Utc>,
}

impl From<VpnDevice> for ApiVpnDevice {
    fn from(d: VpnDevice) -> Self {
        Self {
            id: d.id,
            name: d.name,
            public_key: wireguard_key_to_base64(&d.peer_pubkey),
            address4: d.address4,
            address6: d.address6,
            enabled: d.enabled,
            created: d.created,
        }
    }
}

/// One region's configuration for one device.
///
/// The fields and the rendered file say the same thing twice on purpose: an app
/// building its own tunnel wants the fields, and a customer running `wg-quick`
/// wants a file. Rendering it here rather than in each client is also what stops
/// three clients disagreeing about the MTU.
#[derive(Serialize)]
pub struct ApiVpnDeviceConfig {
    pub region_id: u64,
    pub region_name: String,
    /// `host:port` the client dials.
    pub endpoint: String,
    /// The route server's public key for this region.
    pub public_key: String,
    /// The device's own addresses. The same in every region: that is the point.
    pub address: Vec<String>,
    pub dns: Vec<String>,
    /// Not 1500. WireGuard's overhead comes off the inside of the tunnel, and
    /// getting this wrong hangs large transfers rather than failing outright.
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
    /// Everything routed into the tunnel: a full tunnel, per family, for the
    /// families this device actually has.
    pub allowed_ips: Vec<String>,
    /// A ready-to-use `wg-quick` file.
    ///
    /// `PrivateKey` is a placeholder. The customer generated the keypair and
    /// only ever sent the public half, so LNVPS cannot fill it in — which is
    /// the property that makes the private key worth having.
    pub config: String,
}

/// The placeholder a client replaces with the private key it kept.
pub const PRIVATE_KEY_PLACEHOLDER: &str = "<your private key>";

impl ApiVpnDeviceConfig {
    /// Render the `wg-quick` file for these settings.
    fn render(&self) -> String {
        let mut out = String::from("[Interface]\n");
        out.push_str(&format!("PrivateKey = {PRIVATE_KEY_PLACEHOLDER}\n"));
        out.push_str(&format!("Address = {}\n", self.address.join(", ")));
        if !self.dns.is_empty() {
            out.push_str(&format!("DNS = {}\n", self.dns.join(", ")));
        }
        out.push_str(&format!("MTU = {}\n", self.mtu));
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", self.public_key));
        out.push_str(&format!("AllowedIPs = {}\n", self.allowed_ips.join(", ")));
        out.push_str(&format!("Endpoint = {}\n", self.endpoint));
        if let Some(k) = self.persistent_keepalive {
            out.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
        out
    }
}

/// Register a device by presenting its public key.
#[derive(Deserialize)]
pub struct AddVpnDeviceRequest {
    /// The customer's label for it. Never leaves LNVPS.
    pub name: String,
    /// The device's WireGuard public key, base64.
    ///
    /// The client generates the pair and sends only this half. LNVPS never
    /// holds a private key belonging to a machine it does not own.
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct CreateVpnPlanRequest {
    pub service_id: u64,
}

#[derive(Deserialize)]
pub struct SetVpnDeviceEnabledRequest {
    pub enabled: bool,
}

/// What is for sale, and where it exits.
async fn v1_list_vpn_services(State(this): State<RouterState>) -> ApiResult<Vec<ApiVpnService>> {
    let mut out = Vec::new();
    for service in this.db.list_vpn_services(true).await? {
        let mut regions = Vec::new();
        for pool in this.db.list_vpn_service_pools(service.id).await? {
            // A disabled interface is one that is not carrying anybody, so
            // advertising it would sell a region that does not answer.
            if !pool.enabled {
                continue;
            }
            let region = this.db.get_host_region(pool.region_id).await?;
            if !region.enabled {
                continue;
            }
            regions.push(ApiVpnRegion {
                region_id: region.id,
                name: region.name,
                country_code: region.country_code,
            });
        }
        regions.sort_by(|a, b| a.name.cmp(&b.name));
        regions.dedup_by_key(|r| r.region_id);

        out.push(ApiVpnService {
            id: service.id,
            name: service.name.clone(),
            amount: service.amount,
            setup_amount: service.setup_amount,
            currency: service.currency.clone(),
            interval_amount: service.interval_amount,
            interval_type: service.interval_type.into(),
            device_limit: service.default_device_limit,
            ipv4: service.device_cidr4.is_some(),
            ipv6: service.device_cidr6.is_some(),
            regions,
        });
    }
    ApiData::ok(out)
}

/// The caller's plan, or 404 if they have never bought one.
async fn v1_get_vpn_plan(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<ApiVpnPlan> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    ApiData::ok(to_api_plan(&this, &plan).await?)
}

/// Buy a plan, or restart a lapsed one.
///
/// Returns the plan with the subscription to pay. Nothing is configured on a
/// route server until that payment lands.
async fn v1_create_vpn_plan(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVpnPlanRequest>,
) -> ApiResult<ApiVpnPlan> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let service = this
        .db
        .get_vpn_service(req.service_id)
        .await
        .map_err(|_| ApiError::not_found("No such VPN service"))?;

    let plan = create_vpn_plan(&this.db, uid, &service)
        .await
        .map_err(ApiError::bad_request)?;
    ApiData::ok(to_api_plan(&this, &plan).await?)
}

async fn v1_list_vpn_devices(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiVpnDevice>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    let devices = this.db.list_vpn_devices(plan.id).await?;
    ApiData::ok(devices.into_iter().map(Into::into).collect())
}

/// Register a device.
///
/// Idempotent on the key: sending the same one twice returns the device it
/// already made, so a client that retries a request whose response it lost does
/// not burn a slot.
async fn v1_add_vpn_device(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<AddVpnDeviceRequest>,
) -> ApiResult<ApiVpnDevice> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    require_paid(&this, &plan).await?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("A device needs a name"));
    }
    let key = BASE64_STANDARD
        .decode(req.public_key.trim())
        .map_err(|_| ApiError::bad_request("A WireGuard public key must be base64"))?;

    let device = register_vpn_device(&this.db, &plan, name, &key)
        .await
        .map_err(ApiError::bad_request)?;

    // The peer has to reach every route server the service terminates on, or
    // the customer holds a config for a region that will not answer.
    push_service(&this, plan.vpn_service_id).await;

    ApiData::ok(device.into())
}

/// Turn a device off without giving up its slot, key or address.
async fn v1_set_vpn_device_enabled(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<SetVpnDeviceEnabledRequest>,
) -> ApiResult<ApiVpnDevice> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    let device = my_device(&this, &plan, id).await?;

    this.db
        .update_vpn_device(&VpnDevice {
            enabled: req.enabled,
            ..device
        })
        .await?;
    push_service(&this, plan.vpn_service_id).await;

    ApiData::ok(this.db.get_vpn_device(id).await?.into())
}

/// Remove a device, releasing its slot and its addresses.
async fn v1_delete_vpn_device(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    my_device(&this, &plan, id).await?;

    this.db.delete_vpn_device(id).await?;
    // Removal is the direction that matters most: until the route servers are
    // told, a revoked key still authenticates.
    push_service(&this, plan.vpn_service_id).await;

    ApiData::ok(())
}

/// One config per region, all sharing this device's `[Interface]`.
async fn v1_vpn_device_configs(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiVpnDeviceConfig>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let plan = my_plan(&this, uid).await?;
    let device = my_device(&this, &plan, id).await?;
    let service = this.db.get_vpn_service(plan.vpn_service_id).await?;

    // A full tunnel, for the families this device actually holds. Offering
    // `::/0` to a v4-only device would black-hole its IPv6 rather than leaving
    // it alone.
    let mut allowed_ips = Vec::new();
    if device.address4.is_some() {
        allowed_ips.push("0.0.0.0/0".to_string());
    }
    if device.address6.is_some() {
        allowed_ips.push("::/0".to_string());
    }
    let address: Vec<String> = [device.address4.clone(), device.address6.clone()]
        .into_iter()
        .flatten()
        .collect();

    let mut out = Vec::new();
    for pool in this.db.list_vpn_service_pools(service.id).await? {
        if !pool.enabled {
            continue;
        }
        let region = this.db.get_host_region(pool.region_id).await?;
        if !region.enabled {
            continue;
        }
        let mut cfg = ApiVpnDeviceConfig {
            region_id: region.id,
            region_name: region.name,
            endpoint: pool.endpoint(),
            public_key: wireguard_key_to_base64(&pool.public_key),
            address: address.clone(),
            dns: service.dns_servers(),
            mtu: pool.mtu,
            persistent_keepalive: pool.keepalive,
            allowed_ips: allowed_ips.clone(),
            config: String::new(),
        };
        cfg.config = cfg.render();
        out.push(cfg);
    }
    out.sort_by(|a, b| a.region_name.cmp(&b.region_name));
    ApiData::ok(out)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The caller's plan, or a 404 that says how to get one.
async fn my_plan(this: &RouterState, uid: u64) -> Result<VpnSubscription, ApiError> {
    this.db
        .get_vpn_subscription_for_user(uid)
        .await?
        .ok_or_else(|| ApiError::not_found("You do not have a VPN plan"))
}

/// A device on the caller's plan.
///
/// Not-found rather than forbidden for somebody else's device, so the endpoint
/// does not confirm that an id exists to anyone who guesses it.
async fn my_device(
    this: &RouterState,
    plan: &VpnSubscription,
    id: u64,
) -> Result<VpnDevice, ApiError> {
    let device = this
        .db
        .get_vpn_device(id)
        .await
        .map_err(|_| ApiError::not_found("No such device"))?;
    if device.vpn_subscription_id != plan.id {
        return Err(ApiError::not_found("No such device"));
    }
    Ok(device)
}

/// Refuse to register devices on a plan that has not been paid for.
///
/// The planner would ignore them anyway, so this exists to say why rather than
/// to let a customer register five devices that silently never connect.
async fn require_paid(this: &RouterState, plan: &VpnSubscription) -> Result<(), ApiError> {
    let sub = this
        .db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    match sub.billing_state(Utc::now()) {
        lnvps_db::BillingState::Active => Ok(()),
        lnvps_db::BillingState::Unpaid => Err(ApiError::bad_request(
            "Pay for your VPN plan before registering devices",
        )),
        lnvps_db::BillingState::Expired => Err(ApiError::bad_request(
            "Your VPN plan has expired; renew it before registering devices",
        )),
    }
}

/// Push every interface on a service, so a change lands now rather than at the
/// next scheduled reconcile.
///
/// Failures are logged, not returned: the change is already recorded, the
/// scheduled reconcile will apply it, and failing the request would tell a
/// customer their device was not registered when it was.
async fn push_service(this: &RouterState, service_id: u64) {
    let pools = match this.db.list_vpn_service_pools(service_id).await {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Could not list interfaces for VPN service {service_id}: {e}");
            return;
        }
    };
    for pool in pools {
        if let Err(e) = this
            .work_sender
            .send(lnvps_api_common::WorkJob::ReconcileTunnelPeers { pool_id: pool.id })
            .await
        {
            log::warn!(
                "Could not queue a reconcile of tunnel pool {}: {e}",
                pool.id
            );
        }
    }
}

async fn to_api_plan(this: &RouterState, plan: &VpnSubscription) -> Result<ApiVpnPlan, ApiError> {
    let sub = this
        .db
        .get_subscription_by_line_item_id(plan.subscription_line_item_id)
        .await?;
    let device_count = this.db.list_vpn_devices(plan.id).await?.len() as u8;
    Ok(ApiVpnPlan {
        id: plan.id,
        service_id: plan.vpn_service_id,
        device_limit: plan.device_limit,
        device_count,
        subscription_id: sub.id,
        billing_state: sub.billing_state(Utc::now()),
        expires: sub.expires,
        created: plan.created,
    })
}

#[cfg(test)]
mod tests;
