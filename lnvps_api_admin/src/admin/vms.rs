use crate::admin::auth::AdminAuth;
use crate::admin::model::AdminVmInfo;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::{delete, get, post, State};
use std::sync::Arc;

/// List all VMs with pagination and filtering
#[get("/api/admin/v1/vms?<limit>&<offset>&<user_id>&<host_id>&<pubkey>&<region_id>&<include_deleted>")]
pub async fn admin_list_vms(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    user_id: Option<u64>,
    host_id: Option<u64>,
    pubkey: Option<String>,
    region_id: Option<u64>,
    include_deleted: Option<bool>,
) -> ApiPaginatedResult<AdminVmInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    // Use the new filtered database method
    let (vms, total) = db
        .admin_list_vms_filtered(
            limit,
            offset,
            user_id,
            host_id,
            pubkey.as_deref(), // Convert Option<String> to Option<&str>
            region_id,
            include_deleted,
        )
        .await?;

    let mut admin_vms = Vec::new();
    for vm in vms {
        // Get user info for this VM
        let user = db.get_user(vm.user_id).await?;

        // Get host info
        let host = db.get_host(vm.host_id).await.ok();
        let host_name = host.as_ref().map(|h| h.name.clone());

        // Get region info if host is available
        let region_name = if let Some(host) = &host {
            db.get_host_region(host.region_id)
                .await
                .ok()
                .map(|r| r.name)
        } else {
            None
        };

        // Build the AdminVmInfo with all data
        let admin_vm = AdminVmInfo::from_vm_with_admin_data(
            db,
            &vm,
            None,
            vm.host_id,
            vm.user_id,
            hex::encode(&user.pubkey),
            user.email,
            host_name,
            region_name,
            vm.deleted,
            vm.ref_code.clone(),
        )
        .await?;

        admin_vms.push(admin_vm);
    }

    ApiPaginatedData::ok(admin_vms, total, limit, offset)
}

/// Get detailed information about a specific VM
#[get("/api/admin/v1/vms/<id>")]
pub async fn admin_get_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminVmInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;

    let vm = db.get_vm(id).await?;
    let user = db.get_user(vm.user_id).await?;

    // Get host info
    let host = db.get_host(vm.host_id).await.ok();
    let host_name = host.as_ref().map(|h| h.name.clone());

    // Get region info if host is available
    let region_name = if let Some(host) = &host {
        db.get_host_region(host.region_id)
            .await
            .ok()
            .map(|r| r.name)
    } else {
        None
    };

    // Build the AdminVmInfo with all data
    let admin_vm = AdminVmInfo::from_vm_with_admin_data(
        db,
        &vm,
        None,
        vm.host_id,
        vm.user_id,
        hex::encode(&user.pubkey),
        user.email,
        host_name,
        region_name,
        vm.deleted,
        vm.ref_code.clone(),
    )
    .await?;

    ApiData::ok(admin_vm)
}

/// Start a VM
#[post("/api/admin/v1/vms/<id>/start")]
pub async fn admin_start_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("Cannot start a deleted VM");
    }

    // TODO: Implement actual VM start logic with hypervisor
    // This would typically involve calling Proxmox API or similar

    // For now, just return success
    // In real implementation, you would:
    // 1. Get the host information
    // 2. Connect to the hypervisor (Proxmox)
    // 3. Send start command
    // 4. Handle any errors

    ApiData::ok(())
}

/// Stop a VM
#[post("/api/admin/v1/vms/<id>/stop")]
pub async fn admin_stop_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("Cannot stop a deleted VM");
    }

    // TODO: Implement actual VM stop logic with hypervisor
    // This would typically involve calling Proxmox API or similar

    ApiData::ok(())
}

/// Delete a VM
#[delete("/api/admin/v1/vms/<id>")]
pub async fn admin_delete_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Delete)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("VM is already deleted");
    }

    // TODO: Implement proper VM deletion
    // In a real implementation, you would:
    // 1. Stop the VM if it's running
    // 2. Delete VM from hypervisor
    // 3. Clean up disk storage
    // 4. Update network configurations
    // 5. Mark VM as deleted in database

    // For now, just mark as deleted in database
    db.delete_vm(id).await?;

    // TODO: Log admin action for audit trail
    // audit_log.log_vm_deleted(auth.user_id, id).await?;

    ApiData::ok(())
}
