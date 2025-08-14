use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminRegionInfo, CreateRegionRequest, UpdateRegionRequest};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use serde::Serialize;
use std::sync::Arc;

/// List all regions with pagination
#[get("/api/admin/v1/regions?<limit>&<offset>")]
pub async fn admin_list_regions(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    // Get paginated regions from database
    let (regions, total) = db.admin_list_regions(limit, offset).await?;

    // Convert to API model with comprehensive statistics
    let mut region_infos = Vec::new();
    for region in regions {
        let stats = db.admin_get_region_stats(region.id).await?;
        region_infos.push(AdminRegionInfo {
            id: region.id,
            name: region.name,
            enabled: region.enabled,
            company_id: region.company_id,
            host_count: stats.host_count,
            total_vms: stats.total_vms,
            total_cpu_cores: stats.total_cpu_cores,
            total_memory_bytes: stats.total_memory_bytes,
            total_ip_assignments: stats.total_ip_assignments,
        });
    }

    ApiPaginatedData::ok(region_infos, total, limit, offset)
}

/// Get detailed information about a specific region
#[get("/api/admin/v1/regions/<id>")]
pub async fn admin_get_region(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let region = db.get_host_region(id).await?;
    let stats = db.admin_get_region_stats(id).await?;

    let region_info = AdminRegionInfo {
        id: region.id,
        name: region.name,
        enabled: region.enabled,
        company_id: region.company_id,
        host_count: stats.host_count,
        total_vms: stats.total_vms,
        total_cpu_cores: stats.total_cpu_cores,
        total_memory_bytes: stats.total_memory_bytes,
        total_ip_assignments: stats.total_ip_assignments,
    };

    ApiData::ok(region_info)
}

/// Create a new region
#[post("/api/admin/v1/regions", data = "<req>")]
pub async fn admin_create_region(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<CreateRegionRequest>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Create)?;

    let region_id = db.admin_create_region(&req.name, req.enabled, req.company_id).await?;

    // Get the created region
    let region = db.get_host_region(region_id).await?;
    let region_info = AdminRegionInfo {
        id: region.id,
        name: region.name,
        enabled: region.enabled,
        company_id: region.company_id,
        host_count: 0, // New region has no hosts
        total_vms: 0,
        total_cpu_cores: 0,
        total_memory_bytes: 0,
        total_ip_assignments: 0,
    };

    ApiData::ok(region_info)
}

/// Update region information
#[patch("/api/admin/v1/regions/<id>", data = "<req>")]
pub async fn admin_update_region(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<UpdateRegionRequest>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Update)?;

    // Get existing region
    let mut region = db.get_host_region(id).await?;

    // Update fields if provided
    if let Some(name) = &req.name {
        region.name = name.clone();
    }
    if let Some(enabled) = req.enabled {
        region.enabled = enabled;
    }
    if req.company_id.is_some() {
        region.company_id = req.company_id;
    }

    // Save changes
    db.admin_update_region(&region).await?;

    // Return updated region
    let stats = db.admin_get_region_stats(id).await?;
    let region_info = AdminRegionInfo {
        id: region.id,
        name: region.name,
        enabled: region.enabled,
        company_id: region.company_id,
        host_count: stats.host_count,
        total_vms: stats.total_vms,
        total_cpu_cores: stats.total_cpu_cores,
        total_memory_bytes: stats.total_memory_bytes,
        total_ip_assignments: stats.total_ip_assignments,
    };

    ApiData::ok(region_info)
}

/// Delete/disable region
#[delete("/api/admin/v1/regions/<id>")]
pub async fn admin_delete_region(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<RegionDeleteResponse> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Delete)?;

    db.admin_delete_region(id).await?;

    ApiData::ok(RegionDeleteResponse {
        success: true,
        message: "Region disabled successfully".to_string(),
    })
}

#[derive(Serialize)]
pub struct RegionDeleteResponse {
    pub success: bool,
    pub message: String,
}
