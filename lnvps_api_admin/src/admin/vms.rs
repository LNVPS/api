use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminVmInfo, AdminVmHistoryInfo, AdminVmPaymentInfo};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, VmStateCache};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::{delete, get, post, State};
use std::sync::Arc;

/// List all VMs with pagination and filtering
#[get("/api/admin/v1/vms?<limit>&<offset>&<user_id>&<host_id>&<pubkey>&<region_id>&<include_deleted>")]
pub async fn admin_list_vms(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_state_cache: &State<VmStateCache>,
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

        // Get VM running state from cache
        let vm_running_state = vm_state_cache.get_state(vm.id).await;

        // Build the AdminVmInfo with all data
        let admin_vm = AdminVmInfo::from_vm_with_admin_data(
            db,
            &vm,
            vm_running_state,
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
    vm_state_cache: &State<VmStateCache>,
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

    // Get VM running state from cache
    let vm_running_state = vm_state_cache.get_state(id).await;

    // Build the AdminVmInfo with all data
    let admin_vm = AdminVmInfo::from_vm_with_admin_data(
        db,
        &vm,
        vm_running_state,
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
    // db.delete_vm(id).await?;

    // TODO: Log admin action for audit trail
    // audit_log.log_vm_deleted(auth.user_id, id).await?;

    ApiData::ok(())
}

/// List VM history with pagination
#[get("/api/admin/v1/vms/<vm_id>/history?<limit>&<offset>")]
pub async fn admin_list_vm_history(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_id: u64,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminVmHistoryInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;

    // Verify VM exists
    let _vm = db.get_vm(vm_id).await?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    // Get VM history with pagination
    let history_entries = db.list_vm_history_paginated(vm_id, limit, offset).await?;
    
    // For total count, we'll get all history entries and count them
    // This is not ideal for large datasets, but works for now
    let all_history = db.list_vm_history(vm_id).await?;
    let total = all_history.len() as u64;

    let mut admin_history = Vec::new();
    for history in history_entries {
        let admin_history_info = AdminVmHistoryInfo::from_vm_history_with_admin_data(db, &history).await?;
        admin_history.push(admin_history_info);
    }

    ApiPaginatedData::ok(admin_history, total, limit, offset)
}

/// Get specific VM history entry
#[get("/api/admin/v1/vms/<vm_id>/history/<history_id>")]
pub async fn admin_get_vm_history(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_id: u64,
    history_id: u64,
) -> ApiResult<AdminVmHistoryInfo> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;

    // Verify VM exists
    let _vm = db.get_vm(vm_id).await?;

    // Get history entry
    let history = db.get_vm_history(history_id).await?;

    // Verify history entry belongs to this VM
    if history.vm_id != vm_id {
        return ApiData::err("History entry does not belong to this VM");
    }

    let admin_history_info = AdminVmHistoryInfo::from_vm_history_with_admin_data(db, &history).await?;
    
    ApiData::ok(admin_history_info)
}

/// List VM payments with pagination
#[get("/api/admin/v1/vms/<vm_id>/payments?<limit>&<offset>")]
pub async fn admin_list_vm_payments(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_id: u64,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminVmPaymentInfo> {
    // Check permission
    auth.require_permission(AdminResource::Payments, AdminAction::View)?;

    // Verify VM exists
    let _vm = db.get_vm(vm_id).await?;

    let limit = limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = offset.unwrap_or(0);

    // Get VM payments with pagination
    let payments = db.list_vm_payment_paginated(vm_id, limit, offset).await?;

    // For total count, we'll get all payments and count them
    // This is not ideal for large datasets, but works for now
    let all_payments = db.list_vm_payment(vm_id).await?;
    let total = all_payments.len() as u64;

    let admin_payments: Vec<AdminVmPaymentInfo> = payments
        .iter()
        .map(|payment| AdminVmPaymentInfo::from_vm_payment(payment))
        .collect();

    ApiPaginatedData::ok(admin_payments, total, limit, offset)
}

/// Get specific VM payment
#[get("/api/admin/v1/vms/<vm_id>/payments/<payment_id>")]
pub async fn admin_get_vm_payment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    vm_id: u64,
    payment_id: String,
) -> ApiResult<AdminVmPaymentInfo> {
    // Check permission
    auth.require_permission(AdminResource::Payments, AdminAction::View)?;

    // Verify VM exists
    let _vm = db.get_vm(vm_id).await?;

    // Decode payment ID from hex
    let payment_id_bytes = hex::decode(&payment_id)
        .map_err(|_| "Invalid payment ID format")?;

    // Get payment
    let payment = db.get_vm_payment(&payment_id_bytes).await?;

    // Verify payment belongs to this VM
    if payment.vm_id != vm_id {
        return ApiData::err("Payment does not belong to this VM");
    }

    let admin_payment_info = AdminVmPaymentInfo::from_vm_payment(&payment);
    
    ApiData::ok(admin_payment_info)
}
