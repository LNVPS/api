use crate::api::RouterState;
use crate::api::model::{ApiAvailableIpSpace, ApiIpRangeSubscription, ApiUpdateIpRangeRequest};
use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/ip_space", get(v1_list_ip_space))
        .route("/api/v1/ip_space/{id}", get(v1_get_ip_space))
        .route(
            "/api/v1/ip_range/{id}",
            get(v1_get_ip_range).patch(v1_update_ip_range),
        )
}

// ============================================================================
// IP Range Allocation Endpoints (Owner - Auth Required)
// ============================================================================

/// Resolve an IP-range allocation, enforcing that `uid` owns it.
async fn owned_ip_range(
    this: &RouterState,
    uid: u64,
    id: u64,
) -> Result<lnvps_db::IpRangeSubscription, ApiError> {
    let sub = this.db.get_ip_range_subscription(id).await?;
    let li = this
        .db
        .get_subscription_line_item(sub.subscription_line_item_id)
        .await?;
    let parent = this.db.get_subscription(li.subscription_id).await?;
    if parent.user_id != uid {
        return Err(ApiError::forbidden("Access denied: not your IP range"));
    }
    Ok(sub)
}

/// Get one of the caller's IP-range allocations.
async fn v1_get_ip_range(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiIpRangeSubscription> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let sub = owned_ip_range(&this, uid, id).await?;
    ApiData::ok(ApiIpRangeSubscription::from_subscription_with_space(this.db.as_ref(), sub).await?)
}

/// Update one of the caller's IP-range allocations.
///
/// Currently supports setting/clearing the origin ASN, which reconciles the
/// prefix's IRR route object and RPKI ROA.
async fn v1_update_ip_range(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<ApiUpdateIpRangeRequest>,
) -> ApiResult<ApiIpRangeSubscription> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    // Ownership check (also 404s unknown ids).
    owned_ip_range(&this, uid, id).await?;

    if let Some(origin_asn) = req.origin_asn {
        this.sub_handler
            .configure_ip_range_origin_asn(id, origin_asn)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to configure origin ASN: {}", e))?;
    }

    let updated = this.db.get_ip_range_subscription(id).await?;
    ApiData::ok(
        ApiIpRangeSubscription::from_subscription_with_space(this.db.as_ref(), updated).await?,
    )
}

// ============================================================================
// IP Space Browsing Endpoints (Public - No Auth Required)
// ============================================================================

/// List all available IP spaces with their pricing
async fn v1_list_ip_space(
    State(this): State<RouterState>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiAvailableIpSpace> {
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);

    let (paginated_spaces, total) = this
        .db
        .list_available_ip_space_paginated(
            Some(true),  // is_available = true
            Some(false), // is_reserved = false
            None,
            limit,
            offset,
        )
        .await?;

    // Convert to API format with pricing
    let mut ip_spaces = Vec::new();
    for space in paginated_spaces {
        match ApiAvailableIpSpace::from_ip_space_with_pricing(this.db.as_ref(), space).await {
            Ok(mut api_space) => {
                // Expand pricing with alternative currencies
                if let Err(_) = api_space.expand_pricing(&this.rates).await {
                    // If expansion fails, continue with base pricing
                }
                ip_spaces.push(api_space);
            }
            Err(_) => continue, // Skip if we can't load pricing
        }
    }

    ApiPaginatedData::ok(ip_spaces, total, limit, offset)
}

/// Get detailed information about a specific IP space
async fn v1_get_ip_space(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAvailableIpSpace> {
    let space = this.db.get_available_ip_space(id).await?;

    // Only show if available and not reserved
    if !space.is_available || space.is_reserved {
        return ApiData::err("IP space not available");
    }

    let mut api_space =
        ApiAvailableIpSpace::from_ip_space_with_pricing(this.db.as_ref(), space).await?;

    // Expand pricing with alternative currencies
    if let Err(_) = api_space.expand_pricing(&this.rates).await {
        // If expansion fails, continue with base pricing
    }

    ApiData::ok(api_space)
}

// ============================================================================
// Helper Functions
// ============================================================================

// Helper function to find an available subnet
pub(super) async fn find_available_subnet(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    parent_network: &ipnetwork::IpNetwork,
    prefix_size: u16,
    available_ip_space_id: u64,
) -> anyhow::Result<String> {
    use ipnetwork::{Ipv4Network, Ipv6Network};
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Get all existing allocations from this IP space
    // Note: We need to get ALL allocations, not filtered by user
    // So we'll query by space ID directly
    let all_subs = db.list_ip_range_subscriptions_by_user(0).await?;

    let existing_allocations: Vec<_> = all_subs
        .into_iter()
        .filter(|sub| sub.available_ip_space_id == available_ip_space_id && sub.is_active)
        .collect();

    // Parse existing CIDRs
    let mut allocated_networks: Vec<ipnetwork::IpNetwork> = Vec::new();
    for allocation in existing_allocations {
        if let Ok(network) = allocation.cidr.parse::<ipnetwork::IpNetwork>() {
            allocated_networks.push(network);
        }
    }

    match parent_network {
        ipnetwork::IpNetwork::V4(v4_network) => {
            let parent_prefix = v4_network.prefix();
            let target_prefix = prefix_size as u8;

            if target_prefix < parent_prefix {
                return Err(anyhow::anyhow!(
                    "Requested prefix /{} is larger than parent network /{}",
                    target_prefix,
                    parent_prefix
                ));
            }

            // Calculate number of subnets
            let subnet_count = 1u64 << (target_prefix - parent_prefix);
            let subnet_size = 1u64 << (32 - target_prefix);

            // Iterate through possible subnets
            let network_addr = u32::from(v4_network.network());

            for i in 0..subnet_count {
                let subnet_addr = network_addr + (i * subnet_size) as u32;
                let subnet = match Ipv4Network::new(Ipv4Addr::from(subnet_addr), target_prefix) {
                    Ok(net) => net,
                    Err(_) => continue,
                };

                let subnet_network = ipnetwork::IpNetwork::V4(subnet);

                // Check if this subnet overlaps with any existing allocation
                let is_available = !allocated_networks
                    .iter()
                    .any(|allocated| subnets_overlap(&subnet_network, allocated));

                if is_available {
                    return Ok(subnet.to_string());
                }
            }
        }
        ipnetwork::IpNetwork::V6(v6_network) => {
            let parent_prefix = v6_network.prefix();
            let target_prefix = prefix_size as u8;

            if target_prefix < parent_prefix {
                return Err(anyhow::anyhow!(
                    "Requested prefix /{} is larger than parent network /{}",
                    target_prefix,
                    parent_prefix
                ));
            }

            // For IPv6, we use similar logic but with u128 addresses
            let subnet_bits = target_prefix - parent_prefix;
            let subnet_count = if subnet_bits < 64 {
                1u64 << subnet_bits
            } else {
                u64::MAX
            };
            let subnet_size = 1u128 << (128 - target_prefix);

            let network_addr = u128::from(v6_network.network());

            // Limit iteration to prevent excessive loops
            let max_iterations = std::cmp::min(subnet_count, 10000);

            for i in 0..max_iterations {
                let subnet_addr = network_addr + (i as u128 * subnet_size);
                let subnet = match Ipv6Network::new(Ipv6Addr::from(subnet_addr), target_prefix) {
                    Ok(net) => net,
                    Err(_) => continue,
                };

                let subnet_network = ipnetwork::IpNetwork::V6(subnet);

                let is_available = !allocated_networks
                    .iter()
                    .any(|allocated| subnets_overlap(&subnet_network, allocated));

                if is_available {
                    return Ok(subnet.to_string());
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "No available subnets of size /{} in the IP space",
        prefix_size
    ))
}

fn subnets_overlap(a: &ipnetwork::IpNetwork, b: &ipnetwork::IpNetwork) -> bool {
    a.contains(b.network()) || b.contains(a.network())
}
