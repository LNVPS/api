use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminHostDisk, AdminHostInfo, AdminVmHostKind};
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, HostCapacityService,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{get, patch, post, State};
use serde::Deserialize;
use std::sync::Arc;

/// Create AdminHostInfo with calculated load data from host, region, and disks
async fn create_admin_host_info_with_capacity(
    db: &Arc<dyn LNVpsDb>,
    host: lnvps_db::VmHost,
    region: lnvps_db::VmHostRegion,
    disks: Vec<lnvps_db::VmHostDisk>,
) -> AdminHostInfo {
    // Create capacity service to calculate load data
    let capacity_service = HostCapacityService::new(db.clone());

    // Calculate host capacity/load
    match capacity_service.get_host_capacity(&host, None, None).await {
        Ok(capacity) => {
            // Count active VMs on this host - more efficient than listing all VMs
            let active_vms = db.count_active_vms_on_host(host.id).await.unwrap_or(0);

            AdminHostInfo::from_host_capacity(&capacity, region, disks, active_vms)
        }
        Err(_) => {
            // If capacity calculation fails, use the fallback method
            AdminHostInfo::from_host_region_and_disks(host, region, disks)
        }
    }
}

/// List all VM hosts with pagination
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

    // Convert to API model with disk information and calculated load data
    let mut hosts = Vec::new();
    for (host, region) in hosts_data {
        let disks = db.list_host_disks(host.id).await?;
        hosts.push(create_admin_host_info_with_capacity(db.inner(), host, region, disks).await);
    }

    ApiPaginatedData::ok(hosts, total, limit, offset)
}

/// Get detailed information about a specific host
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

    let host_info = create_admin_host_info_with_capacity(db.inner(), host, region, disks).await;
    ApiData::ok(host_info)
}

/// Update host configuration
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
    if let Some(ip) = &req.ip {
        host.ip = ip.clone();
    }
    if let Some(api_token) = &req.api_token {
        host.api_token = api_token.clone();
    }
    if let Some(region_id) = req.region_id {
        host.region_id = region_id;
    }
    if let Some(kind) = &req.kind {
        host.kind = kind.clone().into();
    }
    if let Some(vlan_id) = req.vlan_id {
        host.vlan_id = vlan_id;
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

    // Return updated host with calculated load data
    let updated_host = db.get_host(id).await?;
    let region = db.get_host_region(updated_host.region_id).await?;
    let disks = db.list_host_disks(id).await?;

    let host_info =
        create_admin_host_info_with_capacity(db.inner(), updated_host, region, disks).await;
    ApiData::ok(host_info)
}

/// Create a new host
#[post("/api/admin/v1/hosts", data = "<req>")]
pub async fn admin_create_host(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    req: Json<AdminHostCreateRequest>,
) -> ApiResult<AdminHostInfo> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Create)?;

    // Validate region exists
    let _region = db.get_host_region(req.region_id).await?;

    // Create new host object
    let new_host = lnvps_db::VmHost {
        id: 0, // Will be set by database
        kind: req.kind.clone().into(),
        region_id: req.region_id,
        name: req.name.clone(),
        ip: req.ip.clone(),
        cpu: req.cpu,
        memory: req.memory,
        enabled: req.enabled.unwrap_or(true),
        api_token: req.api_token.clone(),
        load_cpu: req.load_cpu.unwrap_or(1.0),
        load_memory: req.load_memory.unwrap_or(1.0),
        load_disk: req.load_disk.unwrap_or(1.0),
        vlan_id: req.vlan_id,
    };

    // Create host in database
    let host_id = db.create_host(&new_host).await?;

    // Return the created host with calculated load data
    let created_host = db.get_host(host_id).await?;
    let region = db.get_host_region(created_host.region_id).await?;
    let disks = db.list_host_disks(host_id).await?;

    let host_info =
        create_admin_host_info_with_capacity(db.inner(), created_host, region, disks).await;
    ApiData::ok(host_info)
}

#[derive(Deserialize)]
pub struct AdminHostUpdateRequest {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub api_token: Option<String>,
    pub region_id: Option<u64>,
    pub kind: Option<AdminVmHostKind>,
    pub vlan_id: Option<Option<u64>>,
    pub enabled: Option<bool>,
    pub load_cpu: Option<f32>,
    pub load_memory: Option<f32>,
    pub load_disk: Option<f32>,
}

#[derive(Deserialize)]
pub struct AdminHostCreateRequest {
    pub name: String,
    pub ip: String,
    pub api_token: String,
    pub region_id: u64,
    pub kind: AdminVmHostKind,
    pub vlan_id: Option<u64>,
    pub cpu: u16,
    pub memory: u64,
    pub enabled: Option<bool>,
    pub load_cpu: Option<f32>,
    pub load_memory: Option<f32>,
    pub load_disk: Option<f32>,
}

/// List host disks
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

#[derive(Deserialize)]
pub struct AdminHostDiskUpdateRequest {
    pub enabled: Option<bool>,
}
