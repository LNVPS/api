//! Customer VPN plans and the devices registered against them.
//!
//! Read, and revoke. There is deliberately no way to create a plan here: a plan
//! exists because a line item was paid for, and one conjured by an admin would
//! be a subscription nobody is billed for. Nor is there a way to register a
//! device, because a device is a keypair whose private half never leaves the
//! customer's machine -- an admin-created one would be a key the customer does
//! not hold.
//!
//! Under its own `vpn_subscription` resource: revoking a lost phone is support
//! work, and should not require the ability to reprice the product that
//! everyone else has already bought. See [`super::vpn_services`].

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::{DateTime, Utc};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, WorkJob,
    deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VpnSubscription};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vpn_subscriptions",
            get(admin_list_vpn_subscriptions),
        )
        .route(
            "/api/admin/v1/vpn_subscriptions/{id}",
            get(admin_get_vpn_subscription),
        )
        .route(
            "/api/admin/v1/vpn_subscriptions/{id}/devices/{device_id}",
            delete(admin_revoke_vpn_device),
        )
}

#[derive(serde::Serialize, Debug)]
pub struct AdminVpnDeviceInfo {
    pub id: u64,
    /// Which of the plan's slots it occupies, counted from zero.
    pub slot: u8,
    /// The customer's label for it. Not an identifier.
    pub name: String,
    /// Its peers, one per region it is carried in. A device is a peer on every
    /// interface of its service, so this is a list rather than one id.
    pub tunnel_ids: Vec<u64>,
    /// The device's public key, hex. The private half is generated on the
    /// customer's machine and has never been seen here.
    ///
    /// Optional because `tunnel` is shared with peers that are configured
    /// before the far side has a key. A registered device always has one.
    pub public_key: Option<String>,
    /// The address it holds in every region.
    pub address4: Option<String>,
    pub address6: Option<String>,
    /// False while the peer is administratively down: it stays allocated and
    /// keeps its address, but no interface terminates it.
    pub enabled: bool,
    pub created: DateTime<Utc>,
}

#[derive(serde::Serialize, Debug)]
pub struct AdminVpnSubscriptionInfo {
    pub id: u64,
    pub user_id: u64,
    pub vpn_service_id: u64,
    pub vpn_service_name: String,
    /// The line item billing for it. Stable for the plan's life, so a customer
    /// who lapses and comes back renews this rather than getting a new plan.
    pub subscription_line_item_id: u64,
    /// Whether the plan is currently paid for. Devices on an unpaid plan stay
    /// allocated and keep their addresses -- they are simply not configured on
    /// any interface, so the customer gets them all back on payment rather than
    /// having to re-register each one.
    pub active: bool,
    /// When the billing period ends, if the subscription has an expiry.
    pub expires: Option<DateTime<Utc>>,
    /// Devices this plan may register, from the service.
    pub device_limit: u8,
    pub devices: Vec<AdminVpnDeviceInfo>,
    pub created: DateTime<Utc>,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ListSubscriptionsQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    user_id: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    vpn_service_id: Option<u64>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct RevokeVpnDeviceRequest {
    /// Why the device was revoked, for the audit trail. Optional, but the
    /// reason is the whole point of doing this from an admin console rather
    /// than letting the customer do it themselves.
    pub reason: Option<String>,
}

async fn subscription_info(
    db: &std::sync::Arc<dyn LNVpsDb>,
    plan: VpnSubscription,
) -> Result<AdminVpnSubscriptionInfo, ApiError> {
    let service = db.get_vpn_service(plan.vpn_service_id).await?;

    // Billing lives on the subscription, not here: a plan has no `active`
    // column because lapsing and paying should not need a write.
    let line_item = db
        .get_subscription_line_item(plan.subscription_line_item_id)
        .await?;
    let subscription = db.get_subscription(line_item.subscription_id).await?;
    let active = subscription.is_active && subscription.is_setup;

    let mut devices = Vec::new();
    for device in db.list_vpn_devices(plan.id).await? {
        // A device has one peer per region, identical in everything shown
        // here, so the first is as good as any.
        let peers = db.list_vpn_device_tunnels(device.id).await?;
        let tunnel = peers.first();
        devices.push(AdminVpnDeviceInfo {
            id: device.id,
            slot: device.slot,
            name: device.name,
            tunnel_ids: peers.iter().map(|t| t.id).collect(),
            public_key: tunnel
                .and_then(|t| t.peer_pubkey.as_deref())
                .map(hex::encode),
            address4: tunnel.and_then(|t| t.address4.clone()),
            address6: tunnel.and_then(|t| t.address6.clone()),
            // A device with no peers has no interface to be enabled on.
            enabled: tunnel.is_some_and(|t| t.enabled),
            created: device.created,
        });
    }

    Ok(AdminVpnSubscriptionInfo {
        id: plan.id,
        user_id: plan.user_id,
        vpn_service_id: plan.vpn_service_id,
        vpn_service_name: service.name,
        subscription_line_item_id: plan.subscription_line_item_id,
        active,
        expires: subscription.expires,
        device_limit: service.default_device_limit,
        devices,
        created: plan.created,
    })
}

async fn admin_list_vpn_subscriptions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListSubscriptionsQuery>,
) -> ApiPaginatedResult<AdminVpnSubscriptionInfo> {
    auth.require_permission(AdminResource::VpnSubscription, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .admin_list_vpn_subscriptions_filtered(limit, offset, params.user_id, params.vpn_service_id)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for plan in rows {
        out.push(subscription_info(&this.db, plan).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_vpn_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVpnSubscriptionInfo> {
    auth.require_permission(AdminResource::VpnSubscription, AdminAction::View)?;
    let plan = this.db.get_vpn_subscription(id).await?;
    ApiData::ok(subscription_info(&this.db, plan).await?)
}

/// Revoke a device: delete its keypair and free its slot.
///
/// This is what a stolen laptop needs. The device's tunnel goes with it, so the
/// key stops being configured anywhere, and every interface on the service is
/// re-pushed -- a peer removed from the database but left on a route server
/// would keep working, which is the one failure mode that matters here.
///
/// The slot is freed, so the customer can register a replacement immediately.
async fn admin_revoke_vpn_device(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((id, device_id)): Path<(u64, u64)>,
    Json(req): Json<RevokeVpnDeviceRequest>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::VpnSubscription, AdminAction::Delete)?;

    let plan = this.db.get_vpn_subscription(id).await?;
    let device = this.db.get_vpn_device(device_id).await?;
    // Checked rather than assumed: without this, a device id from one plan
    // could be revoked through another customer's plan.
    if device.vpn_subscription_id != plan.id {
        return Err(ApiError::bad_request(format!(
            "Device {device_id} does not belong to VPN plan {id}"
        )));
    }

    log::info!(
        "Admin revoking VPN device {device_id} (slot {}, {:?}) on plan {id} for user {}: {}",
        device.slot,
        device.name,
        plan.user_id,
        req.reason.as_deref().unwrap_or("no reason given")
    );

    this.db.delete_vpn_device(device_id).await?;

    // Every region, not just one: the device was a peer on all of them, and a
    // revoked key left configured on any single route server still works.
    for pool in this.db.list_vpn_service_pools(plan.vpn_service_id).await? {
        if let Err(e) = this
            .work_commander
            .send(WorkJob::SyncTunnelPool { pool_id: pool.id })
            .await
        {
            log::error!(
                "Failed to queue tunnel pool sync for pool {} after revoking device {device_id}: {e}",
                pool.id
            );
        }
    }

    ApiData::ok(())
}
