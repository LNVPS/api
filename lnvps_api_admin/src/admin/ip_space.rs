use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminAvailableIpSpaceInfo, AdminIpRangeSubscriptionInfo, AdminIpSpacePricingInfo,
    CreateAvailableIpSpaceRequest, CreateIpSpacePricingRequest, UpdateAvailableIpSpaceRequest,
    UpdateIpSpacePricingRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, InternetRegistry};
use serde::Deserialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/ip_space",
            get(admin_list_ip_space).post(admin_create_ip_space),
        )
        .route(
            "/api/admin/v1/ip_space/{id}",
            get(admin_get_ip_space)
                .patch(admin_update_ip_space)
                .delete(admin_delete_ip_space),
        )
        .route(
            "/api/admin/v1/ip_space/{id}/pricing",
            get(admin_list_ip_space_pricing).post(admin_create_ip_space_pricing),
        )
        .route(
            "/api/admin/v1/ip_space/{space_id}/pricing/{pricing_id}",
            get(admin_get_ip_space_pricing)
                .patch(admin_update_ip_space_pricing)
                .delete(admin_delete_ip_space_pricing),
        )
        .route(
            "/api/admin/v1/ip_space/{id}/subscriptions",
            get(admin_list_ip_space_subscriptions),
        )
}

#[derive(Deserialize)]
struct IpSpaceQuery {
    limit: Option<u64>,
    offset: Option<u64>,
    is_available: Option<bool>,
    registry: Option<u8>,
}

/// List all available IP space with pagination and filtering
async fn admin_list_ip_space(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<IpSpaceQuery>,
) -> ApiPaginatedResult<AdminAvailableIpSpaceInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = params.offset.unwrap_or(0);

    // Get all IP spaces (we'll filter in memory for now)
    let all_spaces = this.db.list_available_ip_space().await?;

    // Filter based on query params
    let filtered_spaces: Vec<_> = all_spaces
        .into_iter()
        .filter(|space| {
            if let Some(is_available) = params.is_available {
                if space.is_available != is_available {
                    return false;
                }
            }
            if let Some(registry) = params.registry {
                if (space.registry as u8) != registry {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered_spaces.len() as u64;

    // Paginate
    let paginated_spaces: Vec<_> = filtered_spaces
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Convert to API format with enriched data
    let mut ip_spaces = Vec::new();
    for space in paginated_spaces {
        let pricing_count = this
            .db
            .list_ip_space_pricing_by_space(space.id)
            .await
            .unwrap_or_default()
            .len() as u64;

        let mut admin_ip_space = AdminAvailableIpSpaceInfo::from(space);
        admin_ip_space.pricing_count = pricing_count;
        ip_spaces.push(admin_ip_space);
    }

    ApiPaginatedData::ok(ip_spaces, total, limit, offset)
}

/// Get a specific IP space by ID
async fn admin_get_ip_space(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAvailableIpSpaceInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::View)?;

    let space = this.db.get_available_ip_space(id).await?;

    let pricing_count = this
        .db
        .list_ip_space_pricing_by_space(id)
        .await
        .unwrap_or_default()
        .len() as u64;

    let mut admin_ip_space = AdminAvailableIpSpaceInfo::from(space);
    admin_ip_space.pricing_count = pricing_count;

    ApiData::ok(admin_ip_space)
}

/// Create a new IP space
async fn admin_create_ip_space(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateAvailableIpSpaceRequest>,
) -> ApiResult<AdminAvailableIpSpaceInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Create)?;

    // Validate required fields
    if req.cidr.trim().is_empty() {
        return ApiData::err("CIDR is required");
    }

    // Validate CIDR format
    if req.cidr.trim().parse::<ipnetwork::IpNetwork>().is_err() {
        return ApiData::err("Invalid CIDR format");
    }

    // Create IP space object
    let ip_space = req.to_available_ip_space()?;

    let ip_space_id = this.db.insert_available_ip_space(&ip_space).await?;

    // Fetch the created IP space to return
    let created_ip_space = this.db.get_available_ip_space(ip_space_id).await?;

    let mut admin_ip_space = AdminAvailableIpSpaceInfo::from(created_ip_space);
    admin_ip_space.pricing_count = 0; // New space has no pricing yet

    ApiData::ok(admin_ip_space)
}

/// Update IP space information
async fn admin_update_ip_space(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateAvailableIpSpaceRequest>,
) -> ApiResult<AdminAvailableIpSpaceInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Update)?;

    let mut space = this.db.get_available_ip_space(id).await?;

    // Update fields if provided
    if let Some(cidr) = &req.cidr {
        if cidr.trim().is_empty() {
            return ApiData::err("CIDR cannot be empty");
        }
        // Validate CIDR format
        if cidr.trim().parse::<ipnetwork::IpNetwork>().is_err() {
            return ApiData::err("Invalid CIDR format");
        }
        space.cidr = cidr.trim().to_string();
    }

    if let Some(min_prefix_size) = req.min_prefix_size {
        space.min_prefix_size = min_prefix_size;
    }

    if let Some(max_prefix_size) = req.max_prefix_size {
        space.max_prefix_size = max_prefix_size;
    }

    // Validate min >= max (remember: larger prefix number = smaller block)
    if space.min_prefix_size < space.max_prefix_size {
        return ApiData::err(
            "min_prefix_size must be greater than or equal to max_prefix_size (smaller prefix number = larger block)",
        );
    }

    if let Some(registry) = req.registry {
        space.registry = match registry {
            0 => InternetRegistry::ARIN,
            1 => InternetRegistry::RIPE,
            2 => InternetRegistry::APNIC,
            3 => InternetRegistry::LACNIC,
            4 => InternetRegistry::AFRINIC,
            _ => return ApiData::err("Invalid registry value"),
        };
    }

    // Validate max prefix size against RIR limits and parent CIDR
    let network: ipnetwork::IpNetwork = space
        .cidr
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid CIDR format"))?;
    let is_ipv6 = network.is_ipv6();
    let parent_prefix = network.prefix() as u16;

    let rir_min = if is_ipv6 {
        space.registry.min_ipv6_prefix_size()
    } else {
        space.registry.min_ipv4_prefix_size()
    };

    if space.max_prefix_size > rir_min {
        return ApiData::err(&format!(
            "max_prefix_size /{} is too small for BGP announcement (RIR minimum: /{})",
            space.max_prefix_size, rir_min
        ));
    }

    if space.max_prefix_size < parent_prefix {
        return ApiData::err(&format!(
            "max_prefix_size /{} cannot be larger than parent CIDR /{}",
            space.max_prefix_size, parent_prefix
        ));
    }

    if let Some(external_id) = &req.external_id {
        space.external_id = external_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    if let Some(is_available) = req.is_available {
        space.is_available = is_available;
    }

    if let Some(is_reserved) = req.is_reserved {
        space.is_reserved = is_reserved;
    }

    if let Some(metadata) = &req.metadata {
        space.metadata = metadata.clone();
    }

    // Update in database
    this.db.update_available_ip_space(&space).await?;

    // Return updated IP space
    let pricing_count = this
        .db
        .list_ip_space_pricing_by_space(id)
        .await
        .unwrap_or_default()
        .len() as u64;

    let mut admin_ip_space = AdminAvailableIpSpaceInfo::from(space);
    admin_ip_space.pricing_count = pricing_count;

    ApiData::ok(admin_ip_space)
}

/// Delete an IP space
async fn admin_delete_ip_space(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Delete)?;

    // Check if there are any subscriptions using this space
    let subscriptions = this.db.list_ip_range_subscriptions_by_user(0).await?; // Get all
    let has_active_subscriptions = subscriptions
        .iter()
        .any(|sub| sub.available_ip_space_id == id && sub.is_active);

    if has_active_subscriptions {
        return ApiData::err(
            "Cannot delete IP space with active subscriptions. Please cancel subscriptions first.",
        );
    }

    this.db.delete_available_ip_space(id).await?;

    ApiData::ok(())
}

// ============================================================================
// IP Space Pricing Endpoints
// ============================================================================

#[derive(Deserialize)]
struct IpSpacePricingQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

/// List all pricing tiers for an IP space
async fn admin_list_ip_space_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(params): Query<IpSpacePricingQuery>,
) -> ApiPaginatedResult<AdminIpSpacePricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::View)?;

    // Verify IP space exists
    let space = this.db.get_available_ip_space(id).await?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let all_pricing = this.db.list_ip_space_pricing_by_space(id).await?;
    let total = all_pricing.len() as u64;

    // Paginate
    let paginated_pricing: Vec<_> = all_pricing
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Convert to API format
    let pricing_infos: Vec<_> = paginated_pricing
        .into_iter()
        .map(|p| {
            let mut info = AdminIpSpacePricingInfo::from(p);
            info.cidr = Some(space.cidr.clone());
            info
        })
        .collect();

    ApiPaginatedData::ok(pricing_infos, total, limit, offset)
}

/// Get a specific pricing tier
async fn admin_get_ip_space_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((space_id, pricing_id)): Path<(u64, u64)>,
) -> ApiResult<AdminIpSpacePricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::View)?;

    let space = this.db.get_available_ip_space(space_id).await?;
    let pricing = this.db.get_ip_space_pricing(pricing_id).await?;

    // Verify the pricing belongs to this space
    if pricing.available_ip_space_id != space_id {
        return ApiData::err("Pricing does not belong to the specified IP space");
    }

    let mut info = AdminIpSpacePricingInfo::from(pricing);
    info.cidr = Some(space.cidr);

    ApiData::ok(info)
}

/// Create a new pricing tier for an IP space
async fn admin_create_ip_space_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<CreateIpSpacePricingRequest>,
) -> ApiResult<AdminIpSpacePricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Create)?;

    // Verify IP space exists
    let space = this.db.get_available_ip_space(id).await?;

    // Validate prefix size is within space's min/max bounds
    // Remember: min_prefix_size = largest number (smallest block)
    //           max_prefix_size = smallest number (largest block)
    // Valid range: max_prefix_size <= prefix_size <= min_prefix_size
    if req.prefix_size < space.max_prefix_size || req.prefix_size > space.min_prefix_size {
        return ApiData::err(&format!(
            "Prefix size must be between /{} and /{}",
            space.max_prefix_size, space.min_prefix_size
        ));
    }

    // Check if pricing already exists for this prefix size
    let existing_pricing = this.db.list_ip_space_pricing_by_space(id).await?;
    if existing_pricing
        .iter()
        .any(|p| p.prefix_size == req.prefix_size)
    {
        return ApiData::err(&format!(
            "Pricing already exists for prefix size /{}",
            req.prefix_size
        ));
    }

    // Create pricing object
    let pricing = req.to_ip_space_pricing(id)?;

    let pricing_id = this.db.insert_ip_space_pricing(&pricing).await?;

    // Fetch the created pricing to return
    let created_pricing = this.db.get_ip_space_pricing(pricing_id).await?;

    let mut info = AdminIpSpacePricingInfo::from(created_pricing);
    info.cidr = Some(space.cidr);

    ApiData::ok(info)
}

/// Update pricing tier information
async fn admin_update_ip_space_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((space_id, pricing_id)): Path<(u64, u64)>,
    Json(req): Json<UpdateIpSpacePricingRequest>,
) -> ApiResult<AdminIpSpacePricingInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Update)?;

    let space = this.db.get_available_ip_space(space_id).await?;
    let mut pricing = this.db.get_ip_space_pricing(pricing_id).await?;

    // Verify the pricing belongs to this space
    if pricing.available_ip_space_id != space_id {
        return ApiData::err("Pricing does not belong to the specified IP space");
    }

    // Update fields if provided
    if let Some(prefix_size) = req.prefix_size {
        // Validate prefix size is within space's min/max bounds
        // Remember: min_prefix_size = largest number (smallest block)
        //           max_prefix_size = smallest number (largest block)
        // Valid range: max_prefix_size <= prefix_size <= min_prefix_size
        if prefix_size < space.max_prefix_size || prefix_size > space.min_prefix_size {
            return ApiData::err(&format!(
                "Prefix size must be between /{} and /{}",
                space.max_prefix_size, space.min_prefix_size
            ));
        }

        // Check if pricing already exists for this prefix size (excluding current)
        let existing_pricing = this.db.list_ip_space_pricing_by_space(space_id).await?;
        if existing_pricing
            .iter()
            .any(|p| p.prefix_size == prefix_size && p.id != pricing_id)
        {
            return ApiData::err(&format!(
                "Pricing already exists for prefix size /{}",
                prefix_size
            ));
        }

        pricing.prefix_size = prefix_size;
    }

    if let Some(price_per_month) = req.price_per_month {
        if price_per_month == 0 {
            return ApiData::err("price_per_month cannot be 0");
        }
        pricing.price_per_month = price_per_month;
    }

    if let Some(currency) = &req.currency {
        if currency.trim().is_empty() {
            return ApiData::err("Currency cannot be empty");
        }
        pricing.currency = currency.trim().to_uppercase();
    }

    if let Some(setup_fee) = req.setup_fee {
        pricing.setup_fee = setup_fee;
    }

    // Update in database
    this.db.update_ip_space_pricing(&pricing).await?;

    let mut info = AdminIpSpacePricingInfo::from(pricing);
    info.cidr = Some(space.cidr);

    ApiData::ok(info)
}

/// Delete a pricing tier
async fn admin_delete_ip_space_pricing(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path((_space_id, pricing_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::IpSpace, AdminAction::Delete)?;

    this.db.delete_ip_space_pricing(pricing_id).await?;

    ApiData::ok(())
}

// ============================================================================
// IP Range Subscription Endpoints (read-only for admin)
// ============================================================================

#[derive(Deserialize)]
struct IpRangeSubscriptionQuery {
    limit: Option<u64>,
    offset: Option<u64>,
    user_id: Option<u64>,
    is_active: Option<bool>,
}

/// List all subscriptions for an IP space
async fn admin_list_ip_space_subscriptions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(params): Query<IpRangeSubscriptionQuery>,
) -> ApiPaginatedResult<AdminIpRangeSubscriptionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Subscriptions, AdminAction::View)?;

    // Verify IP space exists
    let _space = this.db.get_available_ip_space(id).await?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Get all subscriptions for this IP space
    // We need to get all subscriptions and filter by available_ip_space_id
    let all_subscriptions = if let Some(user_id) = params.user_id {
        this.db.list_ip_range_subscriptions_by_user(user_id).await?
    } else {
        // Get all subscriptions (use user_id 0 as sentinel for all)
        // This is a limitation - we may need to add a new DB method for this
        this.db.list_ip_range_subscriptions_by_user(0).await?
    };

    // Filter by space_id and optionally by is_active
    let filtered_subs: Vec<_> = all_subscriptions
        .into_iter()
        .filter(|sub| {
            if sub.available_ip_space_id != id {
                return false;
            }
            if let Some(is_active) = params.is_active {
                if sub.is_active != is_active {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered_subs.len() as u64;

    // Paginate
    let paginated_subs: Vec<_> = filtered_subs
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    // Convert to API format with enriched data
    let mut sub_infos = Vec::new();
    for sub in paginated_subs {
        match AdminIpRangeSubscriptionInfo::from_subscription_with_admin_data(&this.db, sub).await {
            Ok(info) => sub_infos.push(info),
            Err(_) => continue, // Skip if we can't enrich the data
        }
    }

    ApiPaginatedData::ok(sub_infos, total, limit, offset)
}
