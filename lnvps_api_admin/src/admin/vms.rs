use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminVmHistoryInfo, AdminVmInfo, AdminVmPaymentInfo};
use chrono::Days;
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, VmHistoryLogger, VmRunningState,
    VmStateCache, WorkCommander, WorkJob,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use log::{error, info};
use rocket::{delete, get, post, put, State};
use serde::Deserialize;
use std::sync::Arc;

async fn get_vm_state(vm_state_cache: &VmStateCache, vm_id: u64) -> Option<VmRunningState> {
    #[cfg(feature = "demo")]
    let vm_running_state = Some(VmRunningState {
        timestamp: chrono::Utc::now().timestamp() as _,
        state: match rand::random::<f32>() {
            n if n >= 0.0 && n < 0.75 => lnvps_api_common::VmRunningStates::Running,
            _ => lnvps_api_common::VmRunningStates::Stopped,
        },
        cpu_usage: rand::random(),
        mem_usage: rand::random(),
        uptime: rand::random::<u16>() as _,
        net_in: 1024 * 1024 * rand::random::<u8>() as u64,
        net_out: 1024 * 1024 * rand::random::<u8>() as u64,
        disk_write: 1024 * rand::random::<u8>() as u64,
        disk_read: 1024 * rand::random::<u8>() as u64,
    });

    #[cfg(not(feature = "demo"))]
    let vm_running_state = vm_state_cache.get_state(vm_id).await;

    vm_running_state
}

/// List all VMs with pagination and filtering
#[get(
    "/api/admin/v1/vms?<limit>&<offset>&<user_id>&<host_id>&<pubkey>&<region_id>&<include_deleted>"
)]
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

    // Load all hosts and regions upfront to avoid N+1 queries
    let hosts = db.list_hosts().await?;
    let mut host_map = std::collections::HashMap::new();
    for host in hosts {
        host_map.insert(host.id, host);
    }

    let regions = db.list_host_region().await?;
    let mut region_map = std::collections::HashMap::new();
    for region in regions {
        region_map.insert(region.id, region);
    }

    let mut admin_vms = Vec::new();
    for vm in vms {
        // Get user info for this VM
        let user = db.get_user(vm.user_id).await?;

        // Get host info from pre-loaded map
        let host = host_map.get(&vm.host_id)
            .ok_or_else(|| anyhow::anyhow!("VM {} references non-existent host {}", vm.id, vm.host_id))?;

        // Get region info from pre-loaded map
        let region = region_map.get(&host.region_id)
            .ok_or_else(|| anyhow::anyhow!("Host {} references non-existent region {}", host.id, host.region_id))?;

        // Get VM running state from cache
        let vm_running_state = get_vm_state(vm_state_cache, vm.id).await;

        // Build the AdminVmInfo with all data
        let admin_vm = AdminVmInfo::from_vm_with_admin_data(
            db,
            &vm,
            vm_running_state,
            vm.host_id,
            vm.user_id,
            hex::encode(&user.pubkey),
            user.email.map(|e| e.into()),
            host.name.clone(),
            region.id,
            region.name.clone(),
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

    // Load all hosts and regions upfront for consistency
    let hosts = db.list_hosts().await?;
    let mut host_map = std::collections::HashMap::new();
    for host in hosts {
        host_map.insert(host.id, host);
    }

    let regions = db.list_host_region().await?;
    let mut region_map = std::collections::HashMap::new();
    for region in regions {
        region_map.insert(region.id, region);
    }

    // Get host info from pre-loaded map
    let host = host_map.get(&vm.host_id)
        .ok_or_else(|| anyhow::anyhow!("VM {} references non-existent host {}", vm.id, vm.host_id))?;
    
    let host_name = host.name.clone();

    // Get region info from pre-loaded map
    let region = region_map.get(&host.region_id)
        .ok_or_else(|| anyhow::anyhow!("Host {} references non-existent region {}", host.id, host.region_id))?;
    
    let region_id = region.id;
    let region_name = region.name.clone();

    // Get VM running state from cache
    let vm_running_state = get_vm_state(vm_state_cache, vm.id).await;

    // Build the AdminVmInfo with all data
    let admin_vm = AdminVmInfo::from_vm_with_admin_data(
        db,
        &vm,
        vm_running_state,
        vm.host_id,
        vm.user_id,
        hex::encode(&user.pubkey),
        user.email.map(|e| e.into()),
        host_name,
        region_id,
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
    work_commander: &State<Option<WorkCommander>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("Cannot start a deleted VM");
    }

    // Check if WorkCommander is available for distributed processing
    if let Some(commander) = work_commander.as_ref() {
        // Send start job via Redis stream for distributed processing
        let start_job = WorkJob::StartVm {
            vm_id: id,
            admin_user_id: Some(auth.user_id),
        };

        match commander.send_job(start_job).await {
            Ok(stream_id) => {
                info!("VM start job queued with stream ID: {}", stream_id);
                ApiData::ok(())
            }
            Err(e) => {
                error!("Failed to queue VM start job: {}", e);
                ApiData::err("Failed to queue VM start job")
            }
        }
    } else {
        // WorkCommander not available - cannot process start
        error!("WorkCommander not configured - cannot process VM start");
        ApiData::err("VM start service is not available")
    }
}

/// Stop a VM
#[post("/api/admin/v1/vms/<id>/stop")]
pub async fn admin_stop_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    id: u64,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("Cannot stop a deleted VM");
    }

    // Check if WorkCommander is available for distributed processing
    if let Some(commander) = work_commander.as_ref() {
        // Send stop job via Redis stream for distributed processing
        let stop_job = WorkJob::StopVm {
            vm_id: id,
            admin_user_id: Some(auth.user_id),
        };

        match commander.send_job(stop_job).await {
            Ok(stream_id) => {
                info!("VM stop job queued with stream ID: {}", stream_id);
                ApiData::ok(())
            }
            Err(e) => {
                error!("Failed to queue VM stop job: {}", e);
                ApiData::err("Failed to queue VM stop job")
            }
        }
    } else {
        // WorkCommander not available - cannot process stop
        error!("WorkCommander not configured - cannot process VM stop");
        ApiData::err("VM stop service is not available")
    }
}

#[derive(Deserialize)]
pub struct AdminDeleteVmRequest {
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminExtendVmRequest {
    pub days: u32,
    pub reason: Option<String>,
}

/// Delete a VM
#[delete("/api/admin/v1/vms/<id>", data = "<req>")]
pub async fn admin_delete_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    id: u64,
    req: Option<rocket::serde::json::Json<AdminDeleteVmRequest>>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Delete)?;

    // Verify VM exists
    let vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("VM is already deleted");
    }

    // Extract reason from request
    let reason = req.and_then(|r| r.reason.clone());

    // Check if WorkCommander is available for distributed processing
    if let Some(commander) = work_commander.as_ref() {
        // Send delete job via Redis stream for distributed processing
        let delete_job = WorkJob::DeleteVm {
            vm_id: id,
            reason,
            admin_user_id: Some(auth.user_id),
        };

        match commander.send_job(delete_job).await {
            Ok(stream_id) => {
                info!("VM deletion job queued with stream ID: {}", stream_id);
                ApiData::ok(())
            }
            Err(e) => {
                error!("Failed to queue VM deletion job: {}", e);
                ApiData::err("Failed to queue VM deletion job")
            }
        }
    } else {
        // WorkCommander not available - cannot process deletion
        error!("WorkCommander not configured - cannot process VM deletion");
        ApiData::err("VM deletion service is not available")
    }
}

/// Extend a VM's expiration date
#[put("/api/admin/v1/vms/<id>/extend", data = "<req>")]
pub async fn admin_extend_vm(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    req: rocket::serde::json::Json<AdminExtendVmRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::Update)?;

    // Verify VM exists
    let mut vm = db.get_vm(id).await?;

    if vm.deleted {
        return ApiData::err("Cannot extend a deleted VM");
    }

    // Validate days (reasonable limits)
    if req.days == 0 {
        return ApiData::err("Must extend by at least 1 day");
    }
    if req.days > 365 {
        return ApiData::err("Cannot extend by more than 365 days");
    }

    let old_expires = vm.expires;
    let new_expires = vm.expires + Days::new(req.days as u64);

    // Update VM expiration date in database
    vm.expires = new_expires;
    db.update_vm(&vm).await?;

    // Log the extension in VM history
    let vm_history_logger = VmHistoryLogger::new(db.inner().clone());
    let metadata = Some(serde_json::json!({
        "admin_user_id": auth.user_id,
        "admin_action": true
    }));

    if let Err(e) = vm_history_logger
        .log_vm_extended(
            id,
            Some(auth.user_id),
            old_expires,
            new_expires,
            req.days,
            req.reason.clone(),
            metadata,
        )
        .await
    {
        error!("Failed to log VM {} extension: {}", id, e);
    }

    info!(
        "Admin {} extended VM {} by {} days until {}",
        auth.user_id, id, req.days, new_expires
    );

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
        let admin_history_info =
            AdminVmHistoryInfo::from_vm_history_with_admin_data(db, &history).await?;
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

    let admin_history_info =
        AdminVmHistoryInfo::from_vm_history_with_admin_data(db, &history).await?;

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
    let payment_id_bytes = hex::decode(&payment_id).map_err(|_| "Invalid payment ID format")?;

    // Get payment
    let payment = db.get_vm_payment(&payment_id_bytes).await?;

    // Verify payment belongs to this VM
    if payment.vm_id != vm_id {
        return ApiData::err("Payment does not belong to this VM");
    }

    let admin_payment_info = AdminVmPaymentInfo::from_vm_payment(&payment);

    ApiData::ok(admin_payment_info)
}

