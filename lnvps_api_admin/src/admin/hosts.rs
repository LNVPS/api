use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminHostDisk, AdminHostInfo, AdminVmHostKind};
use lnvps_api_common::{
    ApiData, ApiDiskInterface, ApiDiskType, ApiPaginatedData, ApiPaginatedResult, ApiResult,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{get, patch, post, State};
use serde::Deserialize;
use std::sync::Arc;


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

    // Get paginated hosts with all data from database (including disabled hosts for admin)
    let (admin_hosts, total) = db
        .admin_list_hosts_with_regions_paginated(limit, offset)
        .await?;

    // Convert to API model with calculated load data
    let mut hosts = Vec::new();
    for admin_host in admin_hosts {
        hosts.push(AdminHostInfo::from_admin_vm_host_with_capacity(db.inner(), admin_host).await);
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

    // Create admin host manually since we don't have the unified query for a single host
    let admin_host = lnvps_db::AdminVmHost {
        host,
        region_id: region.id,
        region_name: region.name.clone(),
        region_enabled: region.enabled,
        region_company_id: region.company_id,
        disks,
        active_vm_count: db.count_active_vms_on_host(id).await.unwrap_or(0) as _,
    };
    let host_info = AdminHostInfo::from_admin_vm_host_with_capacity(db.inner(), admin_host).await;
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
        host.api_token = api_token.clone().into();
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

    // Create admin host manually
    let admin_host = lnvps_db::AdminVmHost {
        host: updated_host,
        region_id: region.id,
        region_name: region.name.clone(),
        region_enabled: region.enabled,
        region_company_id: region.company_id,
        disks,
        active_vm_count: db.count_active_vms_on_host(id).await.unwrap_or(0) as _,
    };
    let host_info = AdminHostInfo::from_admin_vm_host_with_capacity(db.inner(), admin_host).await;
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
        api_token: req.api_token.clone().into(),
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

    // Create admin host manually
    let admin_host = lnvps_db::AdminVmHost {
        host: created_host,
        region_id: region.id,
        region_name: region.name.clone(),
        region_enabled: region.enabled,
        region_company_id: region.company_id,
        disks,
        active_vm_count: 0, // New host has no VMs
    };
    let host_info = AdminHostInfo::from_admin_vm_host_with_capacity(db.inner(), admin_host).await;
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
        .map(|disk| disk.into())
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

    ApiData::ok(disk.into())
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
    if let Some(name) = &req.name {
        disk.name = name.clone();
    }
    if let Some(size) = req.size {
        disk.size = size;
    }
    if let Some(kind) = &req.kind {
        disk.kind = (*kind).into();
    }
    if let Some(interface) = &req.interface {
        disk.interface = (*interface).into();
    }
    if let Some(enabled) = req.enabled {
        disk.enabled = enabled;
    }

    // Save changes
    db.update_host_disk(&disk).await?;

    // Return updated disk
    ApiData::ok(disk.into())
}

/// Create a new host disk
#[post("/api/admin/v1/hosts/<host_id>/disks", data = "<req>")]
pub async fn admin_create_host_disk(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    host_id: u64,
    req: Json<AdminHostDiskCreateRequest>,
) -> ApiResult<AdminHostDisk> {
    // Check permission
    auth.require_permission(AdminResource::Hosts, AdminAction::Update)?;

    // Check that host exists
    let _host = db.get_host(host_id).await?;

    // Create new host disk object
    let new_disk = lnvps_db::VmHostDisk {
        id: 0, // Will be set by database
        host_id,
        name: req.name.clone(),
        size: req.size,
        kind: req.kind.into(),
        interface: req.interface.into(),
        enabled: req.enabled.unwrap_or(true),
    };

    // Create disk in database
    let disk_id = db.create_host_disk(&new_disk).await?;

    // Return the created disk
    let created_disk = db.get_host_disk(disk_id).await?;
    ApiData::ok(created_disk.into())
}

#[derive(Deserialize)]
pub struct AdminHostDiskCreateRequest {
    pub name: String,
    pub size: u64,
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct AdminHostDiskUpdateRequest {
    pub name: Option<String>,
    pub size: Option<u64>,
    pub kind: Option<ApiDiskType>,
    pub interface: Option<ApiDiskInterface>,
    pub enabled: Option<bool>,
}
