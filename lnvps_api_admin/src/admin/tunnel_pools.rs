//! Tunnel pools: where inner tunnel addresses are allocated from.
//!
//! A pool is to tunnels what an `ip_range` is to guest addresses — a block to
//! carve links out of, scoped to a region, attached to the route server that
//! terminates them. Marketplace nodes are the first consumer: a node's guests
//! use LNVPS addresses, so their traffic has to reach an LNVPS route server
//! before it reaches the internet, and that is a peer on one of these pools.
//!
//! Under the `router` resource, because a pool is part of a route server's
//! configuration and anyone who can edit the router can already reconfigure the
//! same interface by hand.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult,
    deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, TunnelPool};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/tunnel_pools",
            get(admin_list_tunnel_pools).post(admin_create_tunnel_pool),
        )
        .route(
            "/api/admin/v1/tunnel_pools/{id}",
            get(admin_get_tunnel_pool)
                .patch(admin_update_tunnel_pool)
                .delete(admin_delete_tunnel_pool),
        )
}

/// Point-to-point prefix lengths, matching the allocator. A pool's capacity is
/// counted in links, not addresses, because a link is what a node consumes.
const LINK_PREFIX_V4: u8 = 31;
const LINK_PREFIX_V6: u8 = 127;

#[derive(Serialize, Debug)]
pub struct AdminTunnelPoolInfo {
    pub id: u64,
    pub router_id: u64,
    pub router_name: String,
    pub region_id: u64,
    pub region_name: String,
    pub name: String,
    /// The WireGuard interface peers are added to on the route server.
    pub interface: String,
    /// `host:port` peers dial. Not the router's management URL.
    pub endpoint: String,
    /// The interface's public key, hex. This is public by construction — the
    /// private half is on the route server and is never stored here.
    pub public_key: String,
    pub cidr4: Option<String>,
    pub cidr6: Option<String>,
    pub keepalive: Option<u16>,
    pub mtu: u16,
    pub enabled: bool,
    /// Links already carved out of this pool.
    pub links_used: u64,
    /// Links the smaller of the two blocks can supply. A dual-stack pool hands
    /// out one link of each family together, so the v4 block running out ends
    /// allocation even with v6 space left — reporting the larger number would
    /// promise capacity that cannot be handed out.
    pub links_total: u64,
    pub created: DateTime<Utc>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListPoolsQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    region_id: Option<u64>,
}

#[derive(Deserialize, Debug)]
pub struct CreateTunnelPoolRequest {
    /// The route server that will terminate peers from this pool.
    pub router_id: u64,
    /// The region whose nodes may be allocated from it.
    pub region_id: u64,
    pub name: String,
    /// WireGuard interface on the route server, e.g. `wg-mkt0`.
    pub interface: String,
    /// `host:port` that peers dial.
    pub endpoint: String,
    /// The interface's public key, 64 hex characters.
    pub public_key: String,
    /// Inner IPv4 block, e.g. `10.66.0.0/16`. At least one of the two blocks
    /// is required.
    pub cidr4: Option<String>,
    /// Inner IPv6 block, e.g. `fd00:66::/48`.
    pub cidr6: Option<String>,
    pub keepalive: Option<u16>,
    /// Defaults to 1420 — 1500 less WireGuard's overhead.
    pub mtu: Option<u16>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
pub struct UpdateTunnelPoolRequest {
    /// The pool's `router_id` is deliberately absent: moving a pool to another
    /// route server would leave every tunnel carved from it pointing at an
    /// interface that does not exist there.
    pub region_id: Option<u64>,
    pub name: Option<String>,
    pub interface: Option<String>,
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cidr4: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cidr6: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub keepalive: Option<Option<u16>>,
    pub mtu: Option<u16>,
    pub enabled: Option<bool>,
}

/// How many point-to-point links `cidr` can supply, saturating: a /48 of IPv6
/// holds more /127s than a `u64` can count, and the exact figure is not the
/// point once it is that large.
fn link_capacity(cidr: Option<&str>) -> Option<u64> {
    let net: IpNetwork = cidr?.parse().ok()?;
    let link_prefix = if net.is_ipv4() {
        LINK_PREFIX_V4
    } else {
        LINK_PREFIX_V6
    };
    if net.prefix() > link_prefix {
        return Some(0);
    }
    let bits = link_prefix - net.prefix();
    Some(if bits >= 64 { u64::MAX } else { 1u64 << bits })
}

async fn pool_info(
    db: &std::sync::Arc<dyn LNVpsDb>,
    pool: TunnelPool,
) -> Result<AdminTunnelPoolInfo, ApiError> {
    let router = db.get_router(pool.router_id).await?;
    let region = db.get_host_region(pool.region_id).await?;
    let links_used = db.list_tunnels_in_pool(pool.id).await?.len() as u64;

    // The binding constraint, not the roomier block: a dual-stack pool hands
    // out both families together.
    let links_total = [
        link_capacity(pool.cidr4.as_deref()),
        link_capacity(pool.cidr6.as_deref()),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(0);

    Ok(AdminTunnelPoolInfo {
        id: pool.id,
        router_id: pool.router_id,
        router_name: router.name,
        region_id: pool.region_id,
        region_name: region.name,
        name: pool.name,
        interface: pool.interface,
        endpoint: pool.endpoint,
        public_key: hex::encode(pool.public_key),
        cidr4: pool.cidr4,
        cidr6: pool.cidr6,
        keepalive: pool.keepalive,
        mtu: pool.mtu,
        enabled: pool.enabled,
        links_used,
        links_total,
        created: pool.created,
    })
}

async fn admin_list_tunnel_pools(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListPoolsQuery>,
) -> ApiPaginatedResult<AdminTunnelPoolInfo> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .admin_list_tunnel_pools_paginated(limit, offset, params.region_id)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for pool in rows {
        out.push(pool_info(&this.db, pool).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_tunnel_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminTunnelPoolInfo> {
    auth.require_permission(AdminResource::Router, AdminAction::View)?;
    let pool = this.db.get_tunnel_pool(id).await?;
    ApiData::ok(pool_info(&this.db, pool).await?)
}

async fn admin_create_tunnel_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateTunnelPoolRequest>,
) -> ApiResult<AdminTunnelPoolInfo> {
    auth.require_permission(AdminResource::Router, AdminAction::Create)?;
    let pool = create_tunnel_pool(&this.db, &req).await?;
    ApiData::ok(pool_info(&this.db, pool).await?)
}

pub(crate) async fn create_tunnel_pool(
    db: &std::sync::Arc<dyn LNVpsDb>,
    req: &CreateTunnelPoolRequest,
) -> Result<TunnelPool, ApiError> {
    let public_key = parse_public_key(&req.public_key)?;
    let cidr4 = parse_block(req.cidr4.as_deref(), "cidr4", true)?;
    let cidr6 = parse_block(req.cidr6.as_deref(), "cidr6", false)?;
    if cidr4.is_none() && cidr6.is_none() {
        return Err(ApiError::bad_request(
            "A pool needs at least one address block, or it can allocate nothing",
        ));
    }
    let name = required(&req.name, "name")?;
    let interface = required(&req.interface, "interface")?;
    let endpoint = parse_endpoint(&req.endpoint)?;

    let id = db
        .insert_tunnel_pool(&TunnelPool {
            id: 0,
            router_id: req.router_id,
            region_id: req.region_id,
            name,
            interface,
            endpoint,
            public_key,
            cidr4,
            cidr6,
            keepalive: req.keepalive,
            mtu: req.mtu.unwrap_or(1420),
            enabled: req.enabled.unwrap_or(true),
            created: Utc::now(),
        })
        .await?;
    Ok(db.get_tunnel_pool(id).await?)
}

async fn admin_update_tunnel_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateTunnelPoolRequest>,
) -> ApiResult<AdminTunnelPoolInfo> {
    auth.require_permission(AdminResource::Router, AdminAction::Update)?;
    let pool = update_tunnel_pool(&this.db, id, &req).await?;
    ApiData::ok(pool_info(&this.db, pool).await?)
}

pub(crate) async fn update_tunnel_pool(
    db: &std::sync::Arc<dyn LNVpsDb>,
    id: u64,
    req: &UpdateTunnelPoolRequest,
) -> Result<TunnelPool, ApiError> {
    let mut pool = db.get_tunnel_pool(id).await?;

    if let Some(region_id) = req.region_id {
        pool.region_id = region_id;
    }
    if let Some(name) = &req.name {
        pool.name = required(name, "name")?;
    }
    if let Some(interface) = &req.interface {
        pool.interface = required(interface, "interface")?;
    }
    if let Some(endpoint) = &req.endpoint {
        pool.endpoint = parse_endpoint(endpoint)?;
    }
    if let Some(key) = &req.public_key {
        pool.public_key = parse_public_key(key)?;
    }
    if let Some(cidr4) = &req.cidr4 {
        pool.cidr4 = parse_block(cidr4.as_deref(), "cidr4", true)?;
    }
    if let Some(cidr6) = &req.cidr6 {
        pool.cidr6 = parse_block(cidr6.as_deref(), "cidr6", false)?;
    }
    if let Some(keepalive) = req.keepalive {
        pool.keepalive = keepalive;
    }
    if let Some(mtu) = req.mtu {
        pool.mtu = mtu;
    }
    if let Some(enabled) = req.enabled {
        pool.enabled = enabled;
    }

    // Shrinking a block below what is already handed out would leave live
    // tunnels outside their own pool, which the allocator would then hand to
    // somebody else.
    let allocated = db.list_tunnels_in_pool(id).await?;
    for tunnel in &allocated {
        for (addr, block, field) in [
            (tunnel.address4.as_deref(), pool.cidr4.as_deref(), "cidr4"),
            (tunnel.address6.as_deref(), pool.cidr6.as_deref(), "cidr6"),
        ] {
            let Some(addr) = addr else { continue };
            let parsed: IpNetwork = addr.parse().map_err(|_| {
                ApiError::new(format!("Tunnel {} has an unparseable address", tunnel.id))
            })?;
            let contained = block
                .and_then(|b| b.parse::<IpNetwork>().ok())
                .is_some_and(|b| b.contains(parsed.ip()));
            if !contained {
                return Err(ApiError::bad_request(format!(
                    "{field} would no longer contain {addr}, which is allocated to tunnel {}. \
                     Move that tunnel before shrinking the block.",
                    tunnel.id
                )));
            }
        }
    }

    db.update_tunnel_pool(&pool).await?;
    Ok(db.get_tunnel_pool(id).await?)
}

async fn admin_delete_tunnel_pool(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::Router, AdminAction::Delete)?;
    // Fetch first so a missing pool is a 404 rather than a silent success.
    let _ = this.db.get_tunnel_pool(id).await?;
    this.db.delete_tunnel_pool(id).await?;
    ApiData::ok(())
}

fn required(value: &str, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(format!("{field} cannot be empty")));
    }
    Ok(trimmed.to_string())
}

/// A WireGuard public key is 32 bytes. Accepted as hex to match every other key
/// and digest on the admin API; the daemon's `wg` output is base64, so this is
/// the one place a conversion is expected.
fn parse_public_key(value: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| ApiError::bad_request("public_key is not valid hex"))?;
    if bytes.len() != 32 {
        return Err(ApiError::bad_request(format!(
            "public_key must be 32 bytes (64 hex characters), got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parse and normalise a block, rejecting the wrong family.
///
/// A v6 block in `cidr4` would be handed out as an IPv4 link by an allocator
/// that trusts the column, so the family is checked here rather than at
/// allocation time on somebody's first node.
fn parse_block(
    value: Option<&str>,
    field: &str,
    want_v4: bool,
) -> Result<Option<String>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let net: IpNetwork = value
        .parse()
        .map_err(|_| ApiError::bad_request(format!("{field} is not a valid CIDR")))?;
    if net.is_ipv4() != want_v4 {
        return Err(ApiError::bad_request(format!(
            "{field} must be an IPv{} block",
            if want_v4 { 4 } else { 6 }
        )));
    }
    let link_prefix = if want_v4 {
        LINK_PREFIX_V4
    } else {
        LINK_PREFIX_V6
    };
    if net.prefix() > link_prefix {
        return Err(ApiError::bad_request(format!(
            "{field} is smaller than a single /{link_prefix} link"
        )));
    }
    // Store the network address, so two pools written as `10.0.0.5/24` and
    // `10.0.0.0/24` are recognisably the same block.
    Ok(Some(format!("{}/{}", net.network(), net.prefix())))
}

/// A peer dials `host:port`. A bare host would leave the node guessing a port,
/// and 51820 is a default, not a promise.
fn parse_endpoint(value: &str) -> Result<String, ApiError> {
    let endpoint = required(value, "endpoint")?;
    let port = endpoint.rsplit(':').next().unwrap_or_default();
    if port.is_empty() || port.parse::<u16>().is_err() || !endpoint.contains(':') {
        return Err(ApiError::bad_request(
            "endpoint must be host:port, e.g. rs1.example.com:51820",
        ));
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{Router as DbRouter, RouterKind, Tunnel};
    use std::sync::Arc;

    const KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    async fn db() -> (Arc<dyn LNVpsDb>, u64) {
        let mock = MockDb::default();
        let router_id = {
            let mut routers = mock.router.lock().await;
            routers.insert(
                1,
                DbRouter {
                    id: 1,
                    name: "rs1".to_string(),
                    enabled: true,
                    kind: RouterKind::MockRouter,
                    url: "mock://rs".to_string(),
                    token: "t".into(),
                },
            );
            1
        };
        (Arc::new(mock), router_id)
    }

    fn create(router_id: u64) -> CreateTunnelPoolRequest {
        CreateTunnelPoolRequest {
            router_id,
            region_id: 1,
            name: "lon marketplace".to_string(),
            interface: "wg-mkt0".to_string(),
            endpoint: "rs1.example.com:51820".to_string(),
            public_key: KEY.to_string(),
            cidr4: Some("10.66.0.0/24".to_string()),
            cidr6: Some("fd00:66::/64".to_string()),
            keepalive: Some(25),
            mtu: None,
            enabled: None,
        }
    }

    #[tokio::test]
    async fn a_pool_is_created_with_sane_defaults() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(&db, &create(router_id)).await.unwrap();

        assert_eq!(pool.router_id, router_id);
        assert_eq!(pool.interface, "wg-mkt0");
        assert_eq!(pool.public_key, hex::decode(KEY).unwrap());
        assert_eq!(
            pool.mtu, 1420,
            "a pool must not default to 1500: WireGuard's overhead comes off it"
        );
        assert!(pool.enabled);

        let info = pool_info(&db, pool).await.unwrap();
        assert_eq!(info.router_name, "rs1");
        assert_eq!(info.links_used, 0);
        // A /24 holds 128 /31 links; the /64 holds far more, so the v4 block is
        // what actually limits the pool.
        assert_eq!(info.links_total, 128);
    }

    /// Capacity has to reflect what can be handed out, not the roomier of the
    /// two blocks: a dual-stack pool allocates both families together.
    #[tokio::test]
    async fn capacity_is_reported_from_the_binding_block() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(
            &db,
            &CreateTunnelPoolRequest {
                cidr4: Some("10.66.0.0/28".to_string()),
                cidr6: Some("fd00:66::/64".to_string()),
                ..create(router_id)
            },
        )
        .await
        .unwrap();

        let info = pool_info(&db, pool).await.unwrap();
        assert_eq!(info.links_total, 8, "the /28 limits the pool to 8 links");
    }

    /// A block exactly one link wide is not a rounding error, and one that
    /// cannot hold a link reports no capacity rather than shifting negatively.
    #[test]
    fn capacity_counts_links_not_addresses() {
        assert_eq!(link_capacity(Some("10.0.0.0/31")), Some(1));
        assert_eq!(link_capacity(Some("10.0.0.0/24")), Some(128));
        assert_eq!(link_capacity(Some("fd00::/127")), Some(1));
        // Saturated rather than overflowed: the exact number of /127s in a /48
        // is not a figure anyone needs.
        assert_eq!(link_capacity(Some("fd00::/48")), Some(u64::MAX));
        // Smaller than one link. Creation refuses these, but an older row or a
        // direct database edit must not panic the listing.
        assert_eq!(link_capacity(Some("10.0.0.1/32")), Some(0));
        assert_eq!(link_capacity(Some("not-a-cidr")), None);
        assert_eq!(link_capacity(None), None);
    }

    /// A v6 block in the v4 column would be handed out as an IPv4 link by an
    /// allocator that trusts the column.
    #[tokio::test]
    async fn blocks_must_match_their_family_and_hold_a_link() {
        let (db, router_id) = db().await;
        for (cidr4, cidr6) in [
            (Some("fd00::/64"), None),
            (Some("not-a-cidr"), None),
            // A /32 cannot hold a /31, and a /128 cannot hold a /127.
            (Some("10.0.0.1/32"), None),
            (None, Some("fd00::1/128")),
            (None, Some("10.0.0.0/24")),
        ] {
            assert!(
                create_tunnel_pool(
                    &db,
                    &CreateTunnelPoolRequest {
                        cidr4: cidr4.map(str::to_string),
                        cidr6: cidr6.map(str::to_string),
                        ..create(router_id)
                    },
                )
                .await
                .is_err(),
                "accepted cidr4={cidr4:?} cidr6={cidr6:?}"
            );
        }
    }

    /// A pool with no block can allocate nothing, and would only be discovered
    /// when a node asked for a tunnel.
    #[tokio::test]
    async fn a_pool_without_a_block_is_refused() {
        let (db, router_id) = db().await;
        let err = create_tunnel_pool(
            &db,
            &CreateTunnelPoolRequest {
                cidr4: None,
                cidr6: None,
                ..create(router_id)
            },
        )
        .await
        .expect_err("a pool with nothing to allocate was created");
        assert!(
            format!("{err:?}").contains("at least one address block"),
            "{err:?}"
        );
    }

    /// The block is stored as its network address, so the same block written
    /// two ways is recognisably the same block.
    #[tokio::test]
    async fn blocks_are_normalised_to_their_network_address() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(
            &db,
            &CreateTunnelPoolRequest {
                cidr4: Some("10.66.0.37/24".to_string()),
                ..create(router_id)
            },
        )
        .await
        .unwrap();
        assert_eq!(pool.cidr4.as_deref(), Some("10.66.0.0/24"));
    }

    /// A peer dials host:port. A bare host leaves the node guessing.
    #[tokio::test]
    async fn an_endpoint_without_a_port_is_refused() {
        let (db, router_id) = db().await;
        for endpoint in [
            "rs1.example.com",
            "rs1.example.com:",
            "rs1.example.com:http",
        ] {
            assert!(
                create_tunnel_pool(
                    &db,
                    &CreateTunnelPoolRequest {
                        endpoint: endpoint.to_string(),
                        ..create(router_id)
                    },
                )
                .await
                .is_err(),
                "accepted endpoint {endpoint}"
            );
        }
    }

    /// A key of the wrong length is not a WireGuard key; every handshake would
    /// fail later with nothing to point at.
    #[tokio::test]
    async fn a_malformed_public_key_is_refused() {
        let (db, router_id) = db().await;
        for key in ["zz", "1122"] {
            assert!(
                create_tunnel_pool(
                    &db,
                    &CreateTunnelPoolRequest {
                        public_key: key.to_string(),
                        ..create(router_id)
                    },
                )
                .await
                .is_err()
            );
        }
    }

    /// Two pools on one interface would each carve addresses the other does not
    /// know about, onto the same link.
    #[tokio::test]
    async fn one_interface_holds_one_pool() {
        let (db, router_id) = db().await;
        create_tunnel_pool(&db, &create(router_id)).await.unwrap();
        assert!(create_tunnel_pool(&db, &create(router_id)).await.is_err());
    }

    #[tokio::test]
    async fn a_pool_can_be_retuned_but_not_moved_off_its_router() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(&db, &create(router_id)).await.unwrap();

        let updated = update_tunnel_pool(
            &db,
            pool.id,
            &UpdateTunnelPoolRequest {
                enabled: Some(false),
                mtu: Some(1380),
                keepalive: Some(None),
                endpoint: Some("rs1.example.com:51821".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.mtu, 1380);
        assert_eq!(updated.keepalive, None);
        assert_eq!(updated.endpoint, "rs1.example.com:51821");

        // Every remaining field, including the ones only touched when a route
        // server is re-keyed or an interface renamed.
        let retuned = update_tunnel_pool(
            &db,
            pool.id,
            &UpdateTunnelPoolRequest {
                region_id: Some(1),
                name: Some("lon marketplace 2".to_string()),
                interface: Some("wg-mkt1".to_string()),
                public_key: Some("44".repeat(32)),
                cidr6: Some(Some("fd00:67::/64".to_string())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(retuned.name, "lon marketplace 2");
        assert_eq!(retuned.interface, "wg-mkt1");
        assert_eq!(retuned.public_key, hex::decode("44".repeat(32)).unwrap());
        assert_eq!(retuned.cidr6.as_deref(), Some("fd00:67::/64"));

        // Blank is not a rename.
        for req in [
            UpdateTunnelPoolRequest {
                name: Some("  ".to_string()),
                ..Default::default()
            },
            UpdateTunnelPoolRequest {
                interface: Some("".to_string()),
                ..Default::default()
            },
        ] {
            assert!(update_tunnel_pool(&db, pool.id, &req).await.is_err());
        }
        assert_eq!(
            updated.router_id, router_id,
            "there is no way to move a pool between route servers, by design"
        );
        // An omitted field is left alone.
        assert_eq!(updated.cidr4.as_deref(), Some("10.66.0.0/24"));
    }

    /// Shrinking a block under a live allocation would leave that tunnel
    /// outside its own pool, and the allocator would hand its addresses to
    /// somebody else.
    #[tokio::test]
    async fn a_block_cannot_be_shrunk_out_from_under_an_allocation() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(&db, &create(router_id)).await.unwrap();
        let user_id = db.upsert_user(&[4u8; 32]).await.unwrap();
        db.insert_tunnel(&Tunnel {
            user_id,
            router_id: Some(router_id),
            pool_id: Some(pool.id),
            name: "mkt-node-1".to_string(),
            address4: Some("10.66.0.129/31".to_string()),
            address6: Some("fd00:66::1/127".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        let err = update_tunnel_pool(
            &db,
            pool.id,
            &UpdateTunnelPoolRequest {
                cidr4: Some(Some("10.66.0.0/25".to_string())),
                ..Default::default()
            },
        )
        .await
        .expect_err("a block was shrunk under a live tunnel");
        assert!(
            format!("{err:?}").contains("allocated to tunnel"),
            "{err:?}"
        );

        // A stored address that cannot be parsed is reported rather than
        // treated as "not in the block", which would blame the wrong thing.
        let mut broken = db.list_tunnels_in_pool(pool.id).await.unwrap().remove(0);
        broken.address4 = Some("not-an-address".to_string());
        db.update_tunnel(&broken).await.unwrap();
        let err = update_tunnel_pool(
            &db,
            pool.id,
            &UpdateTunnelPoolRequest {
                cidr4: Some(Some("10.66.0.0/25".to_string())),
                ..Default::default()
            },
        )
        .await
        .expect_err("an unparseable allocation was ignored");
        assert!(
            format!("{err:?}").contains("unparseable address"),
            "{err:?}"
        );
        broken.address4 = Some("10.66.0.129/31".to_string());
        db.update_tunnel(&broken).await.unwrap();

        // Growing it is fine.
        let grown = update_tunnel_pool(
            &db,
            pool.id,
            &UpdateTunnelPoolRequest {
                cidr4: Some(Some("10.66.0.0/16".to_string())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(grown.cidr4.as_deref(), Some("10.66.0.0/16"));

        // And the pool now reports the allocation.
        let info = pool_info(&db, grown).await.unwrap();
        assert_eq!(info.links_used, 1);
    }

    /// Dropping a block a live tunnel sits in is the same mistake as shrinking
    /// one.
    #[tokio::test]
    async fn a_block_cannot_be_removed_out_from_under_an_allocation() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(&db, &create(router_id)).await.unwrap();
        let user_id = db.upsert_user(&[4u8; 32]).await.unwrap();
        db.insert_tunnel(&Tunnel {
            user_id,
            router_id: Some(router_id),
            pool_id: Some(pool.id),
            name: "mkt-node-1".to_string(),
            address4: Some("10.66.0.1/31".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        assert!(
            update_tunnel_pool(
                &db,
                pool.id,
                &UpdateTunnelPoolRequest {
                    cidr4: Some(None),
                    ..Default::default()
                },
            )
            .await
            .is_err()
        );
    }

    /// The handlers, through the extractors and the routes they are mounted
    /// on, including the permission they sit behind.
    #[tokio::test]
    async fn the_endpoints_serve_pool_administration() {
        use crate::admin::model::Permission;
        use lnvps_api_common::{ChannelWorkCommander, MockExchangeRate, VmStateCache};

        let (db, router_id) = db().await;
        let this = RouterState {
            db: db.clone(),
            work_commander: Arc::new(ChannelWorkCommander::new()),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: Arc::new(MockExchangeRate::default()),
        };
        let auth = |resource: AdminResource| AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: [
                AdminAction::View,
                AdminAction::Create,
                AdminAction::Update,
                AdminAction::Delete,
            ]
            .into_iter()
            .map(|action| Permission { resource, action })
            .collect(),
            nip98_auth: None,
        };
        let admin = || auth(AdminResource::Router);

        // A handler nothing routes to is not an endpoint.
        let _: Router<RouterState> = router();

        let created =
            admin_create_tunnel_pool(admin(), State(this.clone()), Json(create(router_id)))
                .await
                .unwrap();
        let pool_id = created.data.id;
        assert_eq!(created.data.region_name, "Mock");
        assert_eq!(created.data.public_key, KEY);

        let listed = admin_list_tunnel_pools(
            admin(),
            State(this.clone()),
            Query(ListPoolsQuery::default()),
        )
        .await
        .unwrap();
        assert_eq!(listed.total, 1);

        // Filtering by a region with no pool must return nothing, not
        // everything — an ignored filter would show an admin capacity that
        // cannot serve the region they are looking at.
        let elsewhere = admin_list_tunnel_pools(
            admin(),
            State(this.clone()),
            Query(ListPoolsQuery {
                region_id: Some(999),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(elsewhere.total, 0);

        let got = admin_get_tunnel_pool(admin(), State(this.clone()), Path(pool_id))
            .await
            .unwrap();
        assert_eq!(got.data.interface, "wg-mkt0");

        let updated = admin_update_tunnel_pool(
            admin(),
            State(this.clone()),
            Path(pool_id),
            Json(UpdateTunnelPoolRequest {
                enabled: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(!updated.data.enabled);

        // Pools are route-server configuration, so they sit behind the same
        // permission as the router itself and nothing else grants them.
        let outsider = || auth(AdminResource::MarketplaceNode);
        assert!(
            admin_list_tunnel_pools(
                outsider(),
                State(this.clone()),
                Query(ListPoolsQuery::default())
            )
            .await
            .is_err()
        );
        assert!(
            admin_get_tunnel_pool(outsider(), State(this.clone()), Path(pool_id))
                .await
                .is_err()
        );
        assert!(
            admin_create_tunnel_pool(outsider(), State(this.clone()), Json(create(router_id)))
                .await
                .is_err()
        );
        assert!(
            admin_update_tunnel_pool(
                outsider(),
                State(this.clone()),
                Path(pool_id),
                Json(UpdateTunnelPoolRequest::default()),
            )
            .await
            .is_err()
        );
        assert!(
            admin_delete_tunnel_pool(outsider(), State(this.clone()), Path(pool_id))
                .await
                .is_err()
        );

        let _ = admin_delete_tunnel_pool(admin(), State(this.clone()), Path(pool_id))
            .await
            .unwrap();
        assert!(db.get_tunnel_pool(pool_id).await.is_err());

        // A pool that never existed is a 404, not a silent success.
        assert!(
            admin_delete_tunnel_pool(admin(), State(this.clone()), Path(pool_id))
                .await
                .is_err()
        );
    }

    /// A pool still carrying allocations cannot be deleted: those tunnels are
    /// live guest traffic.
    #[tokio::test]
    async fn a_pool_with_allocations_cannot_be_deleted() {
        let (db, router_id) = db().await;
        let pool = create_tunnel_pool(&db, &create(router_id)).await.unwrap();
        let user_id = db.upsert_user(&[4u8; 32]).await.unwrap();
        db.insert_tunnel(&Tunnel {
            user_id,
            router_id: Some(router_id),
            pool_id: Some(pool.id),
            name: "mkt-node-1".to_string(),
            address4: Some("10.66.0.1/31".to_string()),
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();

        assert!(db.delete_tunnel_pool(pool.id).await.is_err());
    }
}
