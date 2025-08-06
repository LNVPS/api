use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminHostDisk, AdminHostInfo};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{get, patch, State};
use rocket_okapi::openapi;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// List all VM hosts with pagination
#[openapi(tag = "Admin - Hosts")]
#[get("/api/admin/v1/hosts?<limit>&<offset>")]
pub async fn admin_list_hosts(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminHostInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    // Get paginated hosts with region info from database (including disabled hosts for admin)
    let (hosts_data, total) = db
        .admin_list_hosts_with_regions_paginated(limit, offset)
        .await?;

    // Convert to API model with disk information
    let mut hosts = Vec::new();
    for (host, region) in hosts_data {
        let disks = db.list_host_disks(host.id).await?;
        hosts.push(AdminHostInfo::from_host_region_and_disks(
            host, region, disks,
        ));
    }

    ApiPaginatedData::ok(hosts, total, limit, offset)
}

/// Get detailed information about a specific host
#[openapi(tag = "Admin - Hosts")]
#[get("/api/admin/v1/hosts/<id>")]
pub async fn admin_get_host(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminHostInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    let host = db.get_host(id).await?;
    let region = db.get_host_region(host.region_id).await?;
    let disks = db.list_host_disks(id).await?;
    ApiData::ok(AdminHostInfo::from_host_region_and_disks(
        host, region, disks,
    ))
}

/// Update host configuration
#[openapi(tag = "Admin - Hosts")]
#[patch("/api/admin/v1/hosts/<id>", data = "<req>")]
pub async fn admin_update_host(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: Json<AdminHostUpdateRequest>,
) -> ApiResult<AdminHostInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Update)?;

    // Get existing host
    let mut host = db.get_host(id).await?;

    // Update fields if provided
    if let Some(name) = &req.name {
        host.name = name.clone();
    }
    if let Some(enabled) = req.enabled {
        host.enabled = enabled;
    }
    if let Some(load_cpu) = req.load_cpu {
        host.load_cpu = load_cpu;
    }
    if let Some(load_memory) = req.load_memory {
        host.load_memory = load_memory;
    }
    if let Some(load_disk) = req.load_disk {
        host.load_disk = load_disk;
    }

    // Save changes
    db.update_host(&host).await?;

    // Return updated host
    let updated_host = db.get_host(id).await?;
    let region = db.get_host_region(updated_host.region_id).await?;
    let disks = db.list_host_disks(id).await?;
    ApiData::ok(AdminHostInfo::from_host_region_and_disks(
        updated_host,
        region,
        disks,
    ))
}

/// Host statistics
#[openapi(tag = "Admin - Hosts")]
#[get("/api/admin/v1/hosts/<id>/stats")]
pub async fn admin_get_host_stats(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminHostStats> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    // Check that host exists
    let _host = db.get_host(id).await?;

    // Get VM counts by status - get all VMs and filter by host
    let all_vms = db.list_vms().await?;
    let vms: Vec<_> = all_vms.into_iter().filter(|vm| vm.host_id == id).collect();
    let total_vms = vms.len() as u64;
    let active_vms = vms.iter().filter(|vm| !vm.deleted).count() as u64;

    let stats = AdminHostStats {
        total_vms,
        active_vms,
        deleted_vms: total_vms - active_vms,
        cpu_usage: None,    // TODO: Get from monitoring system
        memory_usage: None, // TODO: Get from monitoring system
        disk_usage: None,   // TODO: Get from monitoring system
    };

    ApiData::ok(stats)
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminHostUpdateRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub load_cpu: Option<f32>,
    pub load_memory: Option<f32>,
    pub load_disk: Option<f32>,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminHostStats {
    pub total_vms: u64,
    pub active_vms: u64,
    pub deleted_vms: u64,
    pub cpu_usage: Option<f32>,
    pub memory_usage: Option<f32>,
    pub disk_usage: Option<f32>,
}

/// List host disks
#[openapi(tag = "Admin - Host Disks")]
#[get("/api/admin/v1/hosts/<host_id>/disks")]
pub async fn admin_list_host_disks(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    host_id: u64,
) -> ApiResult<Vec<AdminHostDisk>> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    // Check that host exists
    let _host = db.get_host(host_id).await?;

    // Get host disks
    let disks = db.list_host_disks(host_id).await?;
    let admin_disks: Vec<AdminHostDisk> = disks
        .into_iter()
        .map(|disk| AdminHostDisk {
            id: disk.id,
            name: disk.name,
            size: disk.size,
            kind: disk.kind.into(),
            interface: disk.interface.into(),
            enabled: disk.enabled,
        })
        .collect();

    ApiData::ok(admin_disks)
}

/// Get specific host disk details
#[openapi(tag = "Admin - Host Disks")]
#[get("/api/admin/v1/hosts/<host_id>/disks/<disk_id>")]
pub async fn admin_get_host_disk(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    host_id: u64,
    disk_id: u64,
) -> ApiResult<AdminHostDisk> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::View)?;

    // Check that host exists
    let _host = db.get_host(host_id).await?;

    // Get disk details
    let disk = db.get_host_disk(disk_id).await?;

    // Verify disk belongs to this host
    if disk.host_id != host_id {
        return Err(anyhow::anyhow!("Disk {} does not belong to host {}", disk_id, host_id).into());
    }

    let admin_disk = AdminHostDisk {
        id: disk.id,
        name: disk.name,
        size: disk.size,
        kind: disk.kind.into(),
        interface: disk.interface.into(),
        enabled: disk.enabled,
    };

    ApiData::ok(admin_disk)
}

/// Update host disk configuration
#[openapi(tag = "Admin - Host Disks")]
#[patch("/api/admin/v1/hosts/<host_id>/disks/<disk_id>", data = "<req>")]
pub async fn admin_update_host_disk(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    host_id: u64,
    disk_id: u64,
    req: Json<AdminHostDiskUpdateRequest>,
) -> ApiResult<AdminHostDisk> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Update)?;

    // Check that host exists
    let _host = db.get_host(host_id).await?;

    // Get existing disk
    let mut disk = db.get_host_disk(disk_id).await?;

    // Verify disk belongs to this host
    if disk.host_id != host_id {
        return Err(anyhow::anyhow!("Disk {} does not belong to host {}", disk_id, host_id).into());
    }

    // Update fields if provided
    if let Some(enabled) = req.enabled {
        disk.enabled = enabled;
    }

    // Save changes
    db.update_host_disk(&disk).await?;

    // Return updated disk
    let admin_disk = AdminHostDisk {
        id: disk.id,
        name: disk.name,
        size: disk.size,
        kind: disk.kind.into(),
        interface: disk.interface.into(),
        enabled: disk.enabled,
    };

    ApiData::ok(admin_disk)
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminHostDiskUpdateRequest {
    pub enabled: Option<bool>,
}
