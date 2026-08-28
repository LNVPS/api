use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminRegionInfo, CreateRegionRequest, UpdateRegionRequest};
use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use isocountry::CountryCode;
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, IPRangeCapacity, PageQuery,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, Region};
use serde::Serialize;
use std::sync::Arc;

/// Validate and normalise an ISO 3166-1 alpha-2 country code.
///
/// Accepts any case and surrounding whitespace, returning the upper-case form.
/// An empty (or whitespace-only) input means "no country", i.e. clear the value.
/// Note this is alpha-2 (what flag rendering needs), whereas `user.country_code`
/// is alpha-3.
fn normalize_country_code(input: &str) -> Result<Option<String>, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let upper = trimmed.to_ascii_uppercase();
    if CountryCode::for_alpha2(&upper).is_err() {
        return Err("Invalid country code, expected ISO 3166-1 alpha-2 (e.g. \"NL\")");
    }
    Ok(Some(upper))
}

/// Build the API view of a region, including its resource and IP statistics.
async fn region_info(db: &Arc<dyn LNVpsDb>, region: Region) -> Result<AdminRegionInfo> {
    let stats = db.admin_get_region_stats(region.id).await?;
    let ipv4_available = region_ipv4_available(db, region.id).await?;

    Ok(AdminRegionInfo {
        id: region.id,
        name: region.name,
        enabled: region.enabled,
        company_id: region.company_id,
        country_code: region.country_code,
        host_count: stats.host_count,
        total_vms: stats.total_vms,
        total_cpu_cores: stats.total_cpu_cores,
        total_memory_bytes: stats.total_memory_bytes,
        total_ip_assignments: stats.total_ip_assignments,
        ipv4_assignments: stats.ipv4_assignments,
        ipv4_available,
        ipv6_assignments: stats.ipv6_assignments,
        ip_ranges: stats.ip_ranges,
        vm_templates: stats.vm_templates,
        app_clusters: stats.app_clusters,
        app_deployments: stats.app_deployments,
        tunnel_pools: stats.tunnel_pools,
        vpn_services: stats.vpn_services,
        routers: stats.routers,
    })
}

/// Count the IPv4 addresses still free for allocation in a region.
///
/// Only **enabled** ranges are counted: a disabled range is not available to the
/// allocator, so including it would report free addresses that can never be
/// handed out. Reserved addresses (gateway, network/broadcast unless the range
/// is `use_full_range`) are excluded by [`IPRangeCapacity::available_capacity`],
/// so this matches what the allocator can actually assign.
async fn region_ipv4_available(db: &Arc<dyn LNVpsDb>, region_id: u64) -> Result<u64> {
    let ranges = db.list_ip_range_in_region(region_id).await?;

    let mut available: u128 = 0;
    for range in ranges.into_iter().filter(|r| r.enabled) {
        let mut capacity = IPRangeCapacity { range, usage: 0 };
        if !capacity.is_ipv4() {
            continue;
        }
        capacity.usage = db
            .list_vm_ip_assignments_in_range(capacity.range.id)
            .await?
            .len() as u128;
        available = available.saturating_add(capacity.available_capacity());
    }

    Ok(available.min(u64::MAX as u128) as u64)
}

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
        region_infos.push(region_info(&this.db, region).await?);
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

    ApiData::ok(region_info(&this.db, region).await?)
}

/// Create a new region
async fn admin_create_region(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateRegionRequest>,
) -> ApiResult<AdminRegionInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Create)?;

    let country_code = match req.country_code.as_deref().map(normalize_country_code) {
        Some(Ok(cc)) => cc,
        Some(Err(err)) => return ApiData::err(err),
        None => None,
    };

    let region_id = this
        .db
        .admin_create_region(
            &req.name,
            req.enabled,
            req.company_id,
            country_code.as_deref(),
        )
        .await?;

    // Get the created region. Everything hangs off it, so a region that was
    // created a moment ago has none of it and the counts are all zero.
    let region = this.db.get_host_region(region_id).await?;
    let region_info = AdminRegionInfo {
        id: region.id,
        name: region.name,
        enabled: region.enabled,
        company_id: region.company_id,
        country_code: region.country_code,
        host_count: 0,
        total_vms: 0,
        total_cpu_cores: 0,
        total_memory_bytes: 0,
        total_ip_assignments: 0,
        ipv4_assignments: 0,
        ipv4_available: 0,
        ipv6_assignments: 0,
        ip_ranges: 0,
        vm_templates: 0,
        app_clusters: 0,
        app_deployments: 0,
        tunnel_pools: 0,
        vpn_services: 0,
        routers: 0,
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
    if let Some(country_code) = &req.country_code {
        match normalize_country_code(country_code) {
            Ok(cc) => region.country_code = cc,
            Err(err) => return ApiData::err(err),
        }
    }

    // Save changes
    this.db.admin_update_region(&region).await?;

    // Return updated region
    ApiData::ok(region_info(&this.db, region).await?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lnvps_api_common::MockDb;
    use lnvps_db::{AdminDb, VmIpAssignment};

    /// The mock region 1 has one enabled IPv4 /24 (gateway inside the range,
    /// `use_full_range = false`) and one IPv6 range: 256 - 1 gateway - 2
    /// boundary addresses = 253 usable IPv4 addresses, and no IPv6 capacity
    /// reported at all.
    const MOCK_REGION_IPV4_USABLE: u64 = 253;

    async fn mock_db() -> (MockDb, Arc<dyn LNVpsDb>) {
        let db = MockDb::default();
        let dyn_db: Arc<dyn LNVpsDb> = Arc::new(db.clone());
        (db, dyn_db)
    }

    #[test]
    fn country_code_is_normalized_and_validated() {
        assert_eq!(normalize_country_code("nl").unwrap().as_deref(), Some("NL"));
        assert_eq!(
            normalize_country_code(" ie ").unwrap().as_deref(),
            Some("IE")
        );
        // An empty value clears the country
        assert_eq!(normalize_country_code("").unwrap(), None);
        assert_eq!(normalize_country_code("   ").unwrap(), None);
        // Anything that is not two ASCII letters is rejected
        assert!(normalize_country_code("NLD").is_err());
        assert!(normalize_country_code("N").is_err());
        assert!(normalize_country_code("N1").is_err());
        // Two letters that are not a real country are rejected too
        assert!(normalize_country_code("ZZ").is_err());
    }

    #[tokio::test]
    async fn region_country_code_round_trips_through_create_and_update() {
        let (_db, dyn_db) = mock_db().await;
        let id = dyn_db
            .admin_create_region("Amsterdam", true, 1, Some("NL"))
            .await
            .unwrap();

        let mut region = dyn_db.get_host_region(id).await.unwrap();
        assert_eq!(region.country_code.as_deref(), Some("NL"));
        assert_eq!(
            region_info(&dyn_db, region.clone())
                .await
                .unwrap()
                .country_code
                .as_deref(),
            Some("NL")
        );

        region.country_code = None;
        dyn_db.admin_update_region(&region).await.unwrap();
        assert_eq!(dyn_db.get_host_region(id).await.unwrap().country_code, None);
    }

    #[tokio::test]
    async fn ipv4_available_counts_only_enabled_v4_ranges() {
        let (db, dyn_db) = mock_db().await;
        assert_eq!(
            region_ipv4_available(&dyn_db, 1).await.unwrap(),
            MOCK_REGION_IPV4_USABLE
        );

        // An assignment consumes one address from its range
        db.ip_assignments.lock().await.insert(
            1,
            VmIpAssignment {
                id: 1,
                vm_id: 1,
                ip_range_id: 1,
                ip: "10.0.0.5".to_string(),
                ..Default::default()
            },
        );
        assert_eq!(
            region_ipv4_available(&dyn_db, 1).await.unwrap(),
            MOCK_REGION_IPV4_USABLE - 1
        );

        // A disabled range offers no capacity: it cannot be allocated from
        db.ip_range.lock().await.get_mut(&1).unwrap().enabled = false;
        assert_eq!(region_ipv4_available(&dyn_db, 1).await.unwrap(), 0);

        // A region with no ranges at all has no IPv4 capacity
        assert_eq!(region_ipv4_available(&dyn_db, 999).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn region_info_splits_assignments_by_address_family() {
        let (db, dyn_db) = mock_db().await;
        db.vms.lock().await.insert(
            1,
            lnvps_db::Vm {
                id: 1,
                host_id: 1,
                user_id: 1,
                ..Default::default()
            },
        );
        {
            let mut assignments = db.ip_assignments.lock().await;
            assignments.insert(
                1,
                VmIpAssignment {
                    id: 1,
                    vm_id: 1,
                    ip_range_id: 1,
                    ip: "10.0.0.5".to_string(),
                    ..Default::default()
                },
            );
            assignments.insert(
                2,
                VmIpAssignment {
                    id: 2,
                    vm_id: 1,
                    ip_range_id: 2,
                    ip: "fd00::5".to_string(),
                    ..Default::default()
                },
            );
        }

        let region = dyn_db.get_host_region(1).await.unwrap();
        let info = region_info(&dyn_db, region).await.unwrap();

        assert_eq!(info.id, 1);
        assert_eq!(info.total_ip_assignments, 2);
        assert_eq!(info.ipv4_assignments, 1);
        assert_eq!(info.ipv6_assignments, 1);
        assert_eq!(info.ipv4_available, MOCK_REGION_IPV4_USABLE - 1);
    }

    /// The related-resource counts, which are what an operator reads to answer
    /// "what else is in this region" before touching it.
    #[tokio::test]
    async fn region_info_counts_related_resources() {
        let (db, dyn_db) = mock_db().await;

        let cluster_id = dyn_db
            .insert_app_cluster(&lnvps_db::AppCluster {
                id: 0,
                name: "eu-1".to_string(),
                region_id: 1,
                ingress_domain: "apps.example.com".to_string(),
                enabled: true,
                capacity_cpu_milli: 1000,
                capacity_memory_bytes: 1024,
                capacity_storage_bytes: 1024,
                created: Utc::now(),
            })
            .await
            .unwrap();

        {
            let mut deployments = db.app_deployments.lock().await;
            for (id, deleted) in [(1u64, false), (2, false), (3, true)] {
                deployments.insert(
                    id,
                    lnvps_db::AppDeployment {
                        id,
                        user_id: 1,
                        app_id: 1,
                        cluster_id,
                        resource_multiplier: 1,
                        subscription_line_item_id: 0,
                        name: format!("d{id}"),
                        namespace: format!("app-d{id}"),
                        hostname: None,
                        custom_domain: None,
                        custom_domain_verified: false,
                        config: None,
                        desired_state: Default::default(),
                        status: Default::default(),
                        status_message: None,
                        usage_cpu_milli: None,
                        usage_memory_bytes: None,
                        usage_storage_bytes: None,
                        usage_collected: None,
                        created: Utc::now(),
                        deleted,
                    },
                );
            }
        }

        {
            // Two interfaces on one route server, both in region 1, so the pool
            // count is two but the router count is one.
            let mut pools = db.tunnel_pools.lock().await;
            for id in [1u64, 2] {
                pools.insert(
                    id,
                    lnvps_db::TunnelPool {
                        id,
                        router_id: 7,
                        region_id: 1,
                        name: format!("pool{id}"),
                        ..Default::default()
                    },
                );
            }
            // One service terminating on both of them is still one service.
            let mut links = db.vpn_service_pools.lock().await;
            links.insert(1, 42);
            links.insert(2, 42);
        }

        let info = region_info(&dyn_db, dyn_db.get_host_region(1).await.unwrap())
            .await
            .unwrap();

        assert_eq!(info.app_clusters, 1);
        // The soft-deleted deployment is not running anywhere, so it is not counted
        assert_eq!(info.app_deployments, 2);
        assert_eq!(info.tunnel_pools, 2);
        assert_eq!(info.vpn_services, 1);
        assert_eq!(info.routers, 1);
        assert_eq!(
            info.ip_ranges,
            dyn_db.list_ip_range_in_region(1).await.unwrap().len() as u64
        );

        // A region with nothing attached reports zero rather than the totals
        let empty_id = dyn_db
            .admin_create_region("Nowhere", true, 1, None)
            .await
            .unwrap();
        let empty = region_info(&dyn_db, dyn_db.get_host_region(empty_id).await.unwrap())
            .await
            .unwrap();
        assert_eq!(empty.app_clusters, 0);
        assert_eq!(empty.app_deployments, 0);
        assert_eq!(empty.tunnel_pools, 0);
        assert_eq!(empty.vpn_services, 0);
        assert_eq!(empty.routers, 0);
        assert_eq!(empty.ip_ranges, 0);
    }
}
