use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminRegionInfo, CreateRegionRequest, UpdateRegionRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource};
use serde::Serialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/regions",
            get(admin_list_regions).post(admin_create_region),
        )
        .route(
            "/api/admin/v1/regions/{id}",
            get(admin_get_region)
                .patch(admin_update_region)
                .delete(admin_delete_region),
        )
}

/// List all regions with pagination
async fn admin_list_regions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(page): Query<PageQuery>,
) -> ApiPaginatedResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let limit = page.limit.unwrap_or(50).min(100);
    let offset = page.offset.unwrap_or(0);

    // Get paginated regions from database
    let (regions, total) = this.db.admin_list_regions(limit, offset).await?;

    // Convert to API model with comprehensive statistics
    let mut region_infos = Vec::new();
    for region in regions {
        let stats = this.db.admin_get_region_stats(region.id).await?;
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
async fn admin_get_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let region = this.db.get_host_region(id).await?;
    let stats = this.db.admin_get_region_stats(id).await?;

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
async fn admin_create_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateRegionRequest>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Create)?;

    let region_id = this
        .db
        .admin_create_region(&req.name, req.enabled, req.company_id)
        .await?;

    // Get the created region
    let region = this.db.get_host_region(region_id).await?;
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
async fn admin_update_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateRegionRequest>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Update)?;

    // Get existing region
    let mut region = this.db.get_host_region(id).await?;

    // Update fields if provided
    if let Some(name) = &req.name {
        region.name = name.clone();
    }
    if let Some(enabled) = req.enabled {
        region.enabled = enabled;
    }
    if let Some(company_id) = req.company_id {
        region.company_id = company_id;
    }

    // Save changes
    this.db.admin_update_region(&region).await?;

    // Return updated region
    let stats = this.db.admin_get_region_stats(id).await?;
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
async fn admin_delete_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<RegionDeleteResponse> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Delete)?;

    this.db.admin_delete_region(id).await?;

    ApiData::ok(RegionDeleteResponse {
        success: true,
        message: "Region disabled successfully".to_string(),
    })
}

#[derive(Serialize)]
struct RegionDeleteResponse {
    success: bool,
    message: String,
}
