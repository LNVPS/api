use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminVmIpAssignmentInfo, CreateVmIpAssignmentRequest, UpdateVmIpAssignmentRequest,
};
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, NetworkProvisioner, WorkCommander,
    WorkJob,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, VmIpAssignment};
use rocket::serde::json::Json;
use rocket::{State, delete, get, patch, post};
use std::net::IpAddr;
use std::sync::Arc;

/// List all VM IP assignments with pagination and optional filtering
#[get(
    "/api/admin/v1/vm_ip_assignments?<limit>&<offset>&<vm_id>&<ip_range_id>&<ip>&<include_deleted>"
)]
pub async fn admin_list_vm_ip_assignments(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    vm_id: Option<u64>,
    ip_range_id: Option<u64>,
    ip: Option<String>,
    include_deleted: Option<bool>,
) -> ApiPaginatedResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    let (db_assignments, total) = db
        .admin_list_vm_ip_assignments(
            limit,
            offset,
            vm_id,
            ip_range_id,
            ip.as_deref(),
            include_deleted,
        )
        .await?;

    // Convert to API format with enriched data
    let mut assignments = Vec::new();
    for assignment in db_assignments {
        let admin_assignment =
            AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(db, &assignment).await?;
        assignments.push(admin_assignment);
    }

    ApiPaginatedData::ok(assignments, total, limit, offset)
}

/// Get a specific VM IP assignment by ID
#[get("/api/admin/v1/vm_ip_assignments/<id>")]
pub async fn admin_get_vm_ip_assignment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::IpRange, AdminAction::View)?;

    let assignment = db.admin_get_vm_ip_assignment(id).await?;
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(db, &assignment).await?;

    ApiData::ok(admin_assignment)
}

/// Create a new VM IP assignment
#[post("/api/admin/v1/vm_ip_assignments", data = "<req>")]
pub async fn admin_create_vm_ip_assignment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    req: Json<CreateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Validate VM exists
    let vm = db.get_vm(req.vm_id).await?;
    if vm.deleted {
        return ApiData::err("Cannot assign IP to a deleted VM");
    }

    // Validate IP range exists and is enabled
    let ip_range = db.admin_get_ip_range(req.ip_range_id).await?;
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
        let network_provisioner = NetworkProvisioner::new(db.inner().clone());
        match network_provisioner.pick_ip_from_range(&ip_range).await {
            Ok(available_ip) => available_ip.ip.ip().to_string(),
            Err(e) => {
                return ApiData::err(&format!("Failed to auto-assign IP from range: {}", e));
            }
        }
    };

    // Create the assignment
    let assignment = VmIpAssignment {
        id: 0, // Will be set by database
        vm_id: req.vm_id,
        ip_range_id: req.ip_range_id,
        ip: assigned_ip,
        deleted: false,
        arp_ref: req.arp_ref.clone(),
        dns_forward: req.dns_forward.clone(),
        dns_forward_ref: None,
        dns_reverse: req.dns_reverse.clone(),
        dns_reverse_ref: None,
    };

    let assignment_id = db.admin_create_vm_ip_assignment(&assignment).await?;

    // Fetch the created assignment to return
    let created_assignment = db.admin_get_vm_ip_assignment(assignment_id).await?;
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(db, &created_assignment)
            .await?;

    // Send ConfigureVm job to update VM network configuration
    if let Some(work_commander) = work_commander.inner() {
        if let Err(e) = work_commander
            .send_job(WorkJob::ConfigureVm {
                vm_id: req.vm_id,
                admin_user_id: Some(auth.user_id),
            })
            .await
        {
            // Log error but don't fail the API call
            log::warn!(
                "Failed to queue VM configuration job for VM {} after IP assignment: {}",
                req.vm_id,
                e
            );
        }
    }

    ApiData::ok(admin_assignment)
}

/// Update VM IP assignment information
#[patch("/api/admin/v1/vm_ip_assignments/<id>", data = "<req>")]
pub async fn admin_update_vm_ip_assignment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    id: u64,
    req: Json<UpdateVmIpAssignmentRequest>,
) -> ApiResult<AdminVmIpAssignmentInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    let mut assignment = db.admin_get_vm_ip_assignment(id).await?;

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
        let ip_range = db.admin_get_ip_range(assignment.ip_range_id).await?;
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
    db.admin_update_vm_ip_assignment(&assignment).await?;

    // Return updated assignment
    let admin_assignment =
        AdminVmIpAssignmentInfo::from_ip_assignment_with_admin_data(db, &assignment).await?;

    // Send ConfigureVm job to update VM network configuration
    if let Some(work_commander) = work_commander.inner() {
        if let Err(e) = work_commander
            .send_job(WorkJob::ConfigureVm {
                vm_id: assignment.vm_id,
                admin_user_id: Some(auth.user_id),
            })
            .await
        {
            // Log error but don't fail the API call
            log::warn!(
                "Failed to queue VM configuration job for VM {} after IP assignment update: {}",
                assignment.vm_id,
                e
            );
        }
    }
    ApiData::ok(admin_assignment)
}

/// Delete a VM IP assignment (soft delete)
#[delete("/api/admin/v1/vm_ip_assignments/<id>")]
pub async fn admin_delete_vm_ip_assignment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify assignment exists and get VM ID for later configuration
    let assignment = db.admin_get_vm_ip_assignment(id).await?;
    let vm_id = assignment.vm_id;

    // Soft delete the assignment
    db.admin_delete_vm_ip_assignment(id).await?;

    // Send ConfigureVm job to update VM network configuration
    if let Some(work_commander) = work_commander.inner() {
        if let Err(e) = work_commander
            .send_job(WorkJob::ConfigureVm {
                vm_id,
                admin_user_id: Some(auth.user_id),
            })
            .await
        {
            // Log error but don't fail the API call
            log::warn!(
                "Failed to queue VM configuration job for VM {} after IP assignment deletion: {}",
                vm_id,
                e
            );
        }
    }

    ApiData::ok(())
}