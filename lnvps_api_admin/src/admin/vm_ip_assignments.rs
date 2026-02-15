use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminVmIpAssignmentInfo, CreateVmIpAssignmentRequest, JobResponse, UpdateVmIpAssignmentRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, NetworkProvisioner, WorkJob,
};
use lnvps_db::{AdminAction, AdminResource};
use serde::Deserialize;
use std::net::IpAddr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/vm_ip_assignments",
            get(admin_list_vm_ip_assignments).post(admin_create_vm_ip_assignment),
        )
        .route(
            "/api/admin/v1/vm_ip_assignments/{id}",
            get(admin_get_vm_ip_assignment)
                .patch(admin_update_vm_ip_assignment)
                .delete(admin_delete_vm_ip_assignment),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VmIpAssignmentQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    vm_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    ip_range_id: Option<u64>,
    ip: Option<String>,
    include_deleted: Option<bool>,
}

/// List all VM IP assignments with pagination and optional filtering
async fn admin_list_vm_ip_assignments(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<VmIpAssignmentQuery>,
) -> ApiPaginatedResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = params.offset.unwrap_or(0);

    let (db_assignments, total) = this
        .db
        .admin_list_vm_ip_assignments(
            limit,
            offset,
            params.vm_id,
            params.ip_range_id,
            params.ip.as_deref(),
            params.include_deleted,
        )
        .await?;

    // Convert to API format with enriched data
    let mut assignments = Vec::new();
    for assignment in db_assignments {
        let admin_assignment =
            AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment)
                .await?;
        assignments.push(admin_assignment);
    }

    ApiPaginatedData::ok(assignments, total, limit, offset)
}

/// Get a specific VM IP assignment by ID
async fn admin_get_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let assignment = this.db.admin_get_vm_ip_assignment(id).await?;
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment).await?;

    ApiData::ok(admin_assignment)
}

/// Create a new VM IP assignment
async fn admin_create_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Validate VM exists
    let vm = this.db.get_vm(req.vm_id).await?;
    if vm.deleted {
        return ApiData::err("Cannot assign IP to a deleted VM");
    }

    if vm.expires == vm.created {
        return ApiData::err("Cannot assign IP to a new VM");
    }

    if vm.expires < Utc::now() {
        return ApiData::err("Cannot assign IP to an expired VM");
    }

    // Validate IP range exists and is enabled
    let ip_range = this.db.admin_get_ip_range(req.ip_range_id).await?;
    if !ip_range.enabled {
        return ApiData::err("Cannot assign IP from a disabled IP range");
    }

    // If IP is provided, validate it's within the range
    let assigned_ip = if let Some(ip) = &req.ip {
        // Validate IP format
        if ip.trim().parse::<IpAddr>().is_err() {
            return ApiData::err("Invalid IP address format");
        }

        // Parse the CIDR to validate the IP is within the range
        let cidr = ip_range
            .cidr
            .parse::<ipnetwork::IpNetwork>()
            .map_err(|_| "Invalid CIDR format in IP range")?;
        let provided_ip = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Invalid IP address format")?;

        if !cidr.contains(provided_ip) {
            return ApiData::err("IP address is not within the specified IP range");
        }

        ip.trim().to_string()
    } else {
        // Auto-assign IP from the range using NetworkProvisioner
        let network_provisioner = NetworkProvisioner::new(this.db.clone());
        match network_provisioner.pick_ip_from_range(&ip_range).await {
            Ok(available_ip) => available_ip.ip.to_string(),
            Err(e) => {
                return ApiData::err(&format!("Failed to auto-assign IP from range: {}", e));
            }
        }
    };

    // Send AssignVmIp job to handle the assignment using the provisioner
    // This will create the IP assignment and handle all additional setup
    if let Err(e) = this
        .work_commander
        .send(WorkJob::AssignVmIp {
            vm_id: req.vm_id,
            ip_range_id: req.ip_range_id,
            ip: Some(assigned_ip.clone()),
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        log::error!(
            "Failed to queue IP assignment job for VM {}: {}",
            req.vm_id,
            e
        );
        return ApiData::err("Failed to queue IP assignment job");
    }

    // Return a success response indicating the job has been queued
    ApiData::ok(AdminVmIpAssignmentInfo {
        id: 0, // Will be assigned by worker
        vm_id: req.vm_id,
        ip_range_id: req.ip_range_id,
        region_id: 0, // Will be filled by worker
        user_id: 0,   // Will be filled by worker
        ip: assigned_ip,
        deleted: false,
        arp_ref: None,
        dns_forward: None,
        dns_forward_ref: None,
        dns_reverse: None,
        dns_reverse_ref: None,
        ip_range_cidr: None,
        region_name: None,
    })
}

/// Update VM IP assignment information
async fn admin_update_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    let mut assignment = this.db.admin_get_vm_ip_assignment(id).await?;

    // Update IP if provided
    if let Some(ip) = &req.ip {
        if ip.trim().is_empty() {
            return ApiData::err("IP cannot be empty");
        }
        // Validate IP format
        if ip.trim().parse::<IpAddr>().is_err() {
            return ApiData::err("Invalid IP address format");
        }

        // Validate IP is within the range
        let ip_range = this.db.admin_get_ip_range(assignment.ip_range_id).await?;
        let cidr = ip_range
            .cidr
            .parse::<ipnetwork::IpNetwork>()
            .map_err(|_| "Invalid CIDR format in IP range")?;
        let provided_ip = ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| "Invalid IP address format")?;

        if !cidr.contains(provided_ip) {
            return ApiData::err("IP address is not within the IP range");
        }

        assignment.ip = ip.trim().to_string();
    }

    // Update ARP ref if provided
    if let Some(arp_ref) = &req.arp_ref {
        assignment.arp_ref = arp_ref.clone();
    }

    // Update DNS forward if provided
    if let Some(dns_forward) = &req.dns_forward {
        assignment.dns_forward = dns_forward.clone();
    }

    // Update DNS reverse if provided
    if let Some(dns_reverse) = &req.dns_reverse {
        assignment.dns_reverse = dns_reverse.clone();
    }

    // Update assignment in database
    this.db.admin_update_vm_ip_assignment(&assignment).await?;

    // Return updated assignment
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(&this.db, &assignment).await?;

    // Send ConfigureVm job to update VM network configuration
    if let Err(e) = this
        .work_commander
        .send(WorkJob::UpdateVmIp {
            assignment_id: assignment.id,
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        // Log error but don't fail the API call
        log::warn!(
            "Failed to queue update vm ip job for VM {} after IP assignment update: {}",
            assignment.vm_id,
            e
        );
    }
    ApiData::ok(admin_assignment)
}

/// Delete a VM IP assignment (soft delete)
async fn admin_delete_vm_ip_assignment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<JobResponse> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify assignment exists
    let _assignment = this.db.admin_get_vm_ip_assignment(id).await?;

    // Send UnassignVmIp job to handle the unassignment using the provisioner
    // This will handle all cleanup (ARP, DNS, access policies) and then delete the assignment
    match this
        .work_commander
        .send(WorkJob::UnassignVmIp {
            assignment_id: id,
            admin_user_id: Some(auth.user_id),
        })
        .await
    {
        Ok(stream_id) => {
            log::info!("IP unassignment job queued with stream ID: {}", stream_id);
            ApiData::ok(JobResponse { job_id: stream_id })
        }
        Err(e) => {
            log::error!(
                "Failed to queue IP unassignment job for assignment {}: {}",
                id,
                e
            );
            ApiData::err("Failed to queue IP unassignment job")
        }
    }
}
