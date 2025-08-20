use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminIpRangeAllocationMode, AdminIpRangeInfo, CreateIpRangeRequest, UpdateIpRangeRequest,
};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, IpRangeAllocationMode, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// List all IP ranges with pagination and optional region filtering
#[get("/api/admin/v1/ip_ranges?<limit>&<offset>&<region_id>")]
pub async fn admin_list_ip_ranges(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    region_id: Option<u64>,
) -> ApiPaginatedResult<AdminIpRangeInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    let (db_ip_ranges, total) = db.admin_list_ip_ranges(limit, offset, region_id).await?;

    // Convert to API format with enriched data
    let mut ip_ranges = Vec::new();
    for ip_range in db_ip_ranges {
        let assignment_count = db
            .admin_count_ip_range_assignments(ip_range.id)
            .await
            .unwrap_or(0);

        // Get region name
        let region_name = match db.get_host_region(ip_range.region_id).await {
            Ok(region) => Some(region.name),
            Err(_) => None,
        };

        // Get access policy name if set
        let access_policy_name = if let Some(policy_id) = ip_range.access_policy_id {
            match db.get_access_policy(policy_id).await {
                Ok(policy) => Some(policy.name),
                Err(_) => None,
            }
        } else {
            None
        };

        let mut admin_ip_range = AdminIpRangeInfo::from(ip_range);
        admin_ip_range.assignment_count = assignment_count;
        admin_ip_range.region_name = region_name;
        admin_ip_range.access_policy_name = access_policy_name;
        ip_ranges.push(admin_ip_range);
    }

    ApiPaginatedData::ok(ip_ranges, total, limit, offset)
}

/// Get a specific IP range by ID
#[get("/api/admin/v1/ip_ranges/<id>")]
pub async fn admin_get_ip_range(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminIpRangeInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let ip_range = db.admin_get_ip_range(id).await?;
    let assignment_count = db.admin_count_ip_range_assignments(id).await.unwrap_or(0);

    // Get region name
    let region_name = match db.get_host_region(ip_range.region_id).await {
        Ok(region) => Some(region.name),
        Err(_) => None,
    };

    // Get access policy name if set
    let access_policy_name = if let Some(policy_id) = ip_range.access_policy_id {
        match db.get_access_policy(policy_id).await {
            Ok(policy) => Some(policy.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_ip_range = AdminIpRangeInfo::from(ip_range);
    admin_ip_range.assignment_count = assignment_count;
    admin_ip_range.region_name = region_name;
    admin_ip_range.access_policy_name = access_policy_name;

    ApiData::ok(admin_ip_range)
}

/// Create a new IP range
#[post("/api/admin/v1/ip_ranges", data = "<req>")]
pub async fn admin_create_ip_range(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<CreateIpRangeRequest>,
) -> ApiResult<AdminIpRangeInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::Create)?;

    // Validate required fields
    if req.cidr.trim().is_empty() {
        return ApiData::err("CIDR is required");
    }
    if req.gateway.trim().is_empty() {
        return ApiData::err("Gateway is required");
    }

    // Validate CIDR format
    if req.cidr.trim().parse::<ipnetwork::IpNetwork>().is_err() {
        return ApiData::err("Invalid CIDR format");
    }

    // Validate gateway IP format
    if req.gateway.trim().parse::<IpAddr>().is_err() {
        return ApiData::err("Invalid gateway IP address format");
    }

    // Validate region exists
    if let Err(_) = db.get_host_region(req.region_id).await {
        return ApiData::err("Specified region does not exist");
    }

    // Validate access policy if provided
    if let Some(policy_id) = req.access_policy_id {
        if let Err(_) = db.get_access_policy(policy_id).await {
            return ApiData::err("Specified access policy does not exist");
        }
    }

    // Create IP range object
    let ip_range = req.to_ip_range()?;

    let ip_range_id = db.admin_create_ip_range(&ip_range).await?;

    // Fetch the created IP range to return
    let created_ip_range = db.admin_get_ip_range(ip_range_id).await?;

    // Get region name
    let region_name = match db.get_host_region(created_ip_range.region_id).await {
        Ok(region) => Some(region.name),
        Err(_) => None,
    };

    // Get access policy name if set
    let access_policy_name = if let Some(policy_id) = created_ip_range.access_policy_id {
        match db.get_access_policy(policy_id).await {
            Ok(policy) => Some(policy.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_ip_range = AdminIpRangeInfo::from(created_ip_range);
    admin_ip_range.region_name = region_name;
    admin_ip_range.access_policy_name = access_policy_name;
    admin_ip_range.assignment_count = 0; // New range has no assignments

    ApiData::ok(admin_ip_range)
}

/// Update IP range information
#[patch("/api/admin/v1/ip_ranges/<id>", data = "<req>")]
pub async fn admin_update_ip_range(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<UpdateIpRangeRequest>,
) -> ApiResult<AdminIpRangeInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::Update)?;

    let mut ip_range = db.admin_get_ip_range(id).await?;

    // Update IP range fields if provided
    if let Some(cidr) = &req.cidr {
        if cidr.trim().is_empty() {
            return ApiData::err("CIDR cannot be empty");
        }
        // Validate CIDR format
        if cidr.trim().parse::<ipnetwork::IpNetwork>().is_err() {
            return ApiData::err("Invalid CIDR format");
        }
        ip_range.cidr = cidr.trim().to_string();
    }

    if let Some(gateway) = &req.gateway {
        if gateway.trim().is_empty() {
            return ApiData::err("Gateway cannot be empty");
        }
        // Validate gateway IP format
        if gateway.trim().parse::<IpAddr>().is_err() {
            return ApiData::err("Invalid gateway IP address format");
        }
        ip_range.gateway = gateway.trim().to_string();
    }

    if let Some(enabled) = req.enabled {
        ip_range.enabled = enabled;
    }

    if let Some(region_id) = req.region_id {
        // Validate region exists
        if let Err(_) = db.get_host_region(region_id).await {
            return ApiData::err("Specified region does not exist");
        }
        ip_range.region_id = region_id;
    }

    if let Some(reverse_zone_id) = &req.reverse_zone_id {
        ip_range.reverse_zone_id = reverse_zone_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    if let Some(access_policy_id) = &req.access_policy_id {
        if let Some(policy_id) = access_policy_id {
            // Validate access policy exists
            if let Err(_) = db.get_access_policy(*policy_id).await {
                return ApiData::err("Specified access policy does not exist");
            }
        }
        ip_range.access_policy_id = *access_policy_id;
    }

    if let Some(allocation_mode) = &req.allocation_mode {
        let db_allocation_mode = match allocation_mode {
            AdminIpRangeAllocationMode::Random => IpRangeAllocationMode::Random,
            AdminIpRangeAllocationMode::Sequential => IpRangeAllocationMode::Sequential,
            AdminIpRangeAllocationMode::SlaacEui64 => IpRangeAllocationMode::SlaacEui64,
        };
        ip_range.allocation_mode = db_allocation_mode;
    }

    if let Some(use_full_range) = req.use_full_range {
        ip_range.use_full_range = use_full_range;
    }

    // Update IP range in database
    db.admin_update_ip_range(&ip_range).await?;

    // Return updated IP range
    let assignment_count = db.admin_count_ip_range_assignments(id).await.unwrap_or(0);

    // Get region name
    let region_name = match db.get_host_region(ip_range.region_id).await {
        Ok(region) => Some(region.name),
        Err(_) => None,
    };

    // Get access policy name if set
    let access_policy_name = if let Some(policy_id) = ip_range.access_policy_id {
        match db.get_access_policy(policy_id).await {
            Ok(policy) => Some(policy.name),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut admin_ip_range = AdminIpRangeInfo::from(ip_range);
    admin_ip_range.assignment_count = assignment_count;
    admin_ip_range.region_name = region_name;
    admin_ip_range.access_policy_name = access_policy_name;

    ApiData::ok(admin_ip_range)
}

/// Delete an IP range
#[delete("/api/admin/v1/ip_ranges/<id>")]
pub async fn admin_delete_ip_range(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::Delete)?;

    // This will fail if there are active IP assignments in the range
    db.admin_delete_ip_range(id).await?;

    ApiData::ok(())
}
