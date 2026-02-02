use crate::api::model::{ApiAvailableIpSpace, ApiIpRangeSubscription};
use crate::api::{PageQuery, RouterState};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/ip_space", get(v1_list_ip_space))
        .route("/api/v1/ip_space/{id}", get(v1_get_ip_space))
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

    // Get all available IP spaces
    let all_spaces = this.db.list_available_ip_space().await?;

    // Filter to only show available ones (not reserved)
    let available_spaces: Vec<_> = all_spaces
        .into_iter()
        .filter(|space| space.is_available && !space.is_reserved)
        .collect();

    let total = available_spaces.len() as u64;

    // Paginate
    let paginated_spaces: Vec<_> = available_spaces
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Convert to API format with pricing
    let mut ip_spaces = Vec::new();
    for space in paginated_spaces {
        match ApiAvailableIpSpace::from_ip_space_with_pricing(this.db.as_ref(), space).await {
            Ok(api_space) => ip_spaces.push(api_space),
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

    let api_space = ApiAvailableIpSpace::from_ip_space_with_pricing(this.db.as_ref(), space).await?;

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
            let subnet_count = if subnet_bits < 64 { 1u64 << subnet_bits } else { u64::MAX };
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
