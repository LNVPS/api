use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCustomTemplateInfo, AdminCustomTemplateUpdateResult, UpdateCustomTemplateRequest,
};
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiDiskInterface, ApiDiskType, ApiError, ApiResult, PricingEngine, UpgradeConfig,
    VmHistoryLogger, WorkJob,
};
use lnvps_db::{
    AdminAction, AdminResource, CpuArch, CpuFeature, CpuMfg, DiskInterface, DiskType, LNVpsDb, Vm,
    VmCustomTemplate,
};
use log::{error, info, warn};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;

pub fn router() -> Router<RouterState> {
    Router::new().route(
        "/api/admin/v1/custom_templates/{id}",
        get(admin_get_custom_template).patch(admin_update_custom_template),
    )
}

impl AdminCustomTemplateInfo {
    /// Present a stored template together with what it currently costs and
    /// which VMs it governs, because both are the reason an admin opens it.
    pub async fn from_template(
        db: &Arc<dyn LNVpsDb>,
        template: &VmCustomTemplate,
    ) -> Result<Self, ApiError> {
        let pricing = db.get_custom_pricing(template.pricing_id).await?;
        let region = db.get_host_region(pricing.region_id).await.ok();
        // Pricing must not be fatal here: a grandfathered spec that no current
        // plan can quote still has to be viewable, and editable back into range.
        let price = PricingEngine::get_custom_vm_cost_amount(db, template)
            .await
            .map(|p| p.total())
            .unwrap_or(0);
        let vm_ids = db
            .list_vms_by_custom_template(template.id)
            .await?
            .into_iter()
            .map(|vm| vm.id)
            .collect();

        Ok(AdminCustomTemplateInfo {
            id: template.id,
            cpu: template.cpu,
            memory: template.memory,
            disk_size: template.disk_size,
            disk_type: ApiDiskType::from(template.disk_type),
            disk_interface: ApiDiskInterface::from(template.disk_interface),
            pricing_id: pricing.id,
            pricing_name: pricing.name,
            region_id: pricing.region_id,
            region_name: region.map(|r| r.name),
            currency: pricing.currency,
            price,
            ip4_count: template.ip4_count,
            ip6_count: template.ip6_count,
            cpu_mfg: match template.cpu_mfg {
                CpuMfg::Unknown => None,
                ref v => Some(v.to_string()),
            },
            cpu_arch: match template.cpu_arch {
                CpuArch::Unknown => None,
                ref v => Some(v.to_string()),
            },
            cpu_features: template
                .cpu_features
                .iter()
                .map(|f| f.to_string())
                .collect(),
            disk_iops_read: template.disk_iops_read,
            disk_iops_write: template.disk_iops_write,
            disk_mbps_read: template.disk_mbps_read,
            disk_mbps_write: template.disk_mbps_write,
            network_mbps: template.network_mbps,
            cpu_limit: template.cpu_limit,
            firewall_rule_limit: template.firewall_rule_limit,
            transfer_gb: template.transfer_gb,
            vm_ids,
        })
    }
}

/// Get a single VM's custom spec.
async fn admin_get_custom_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminCustomTemplateInfo> {
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::View)?;

    let template = this.db.get_custom_vm_template(id).await?;
    ApiData::ok(AdminCustomTemplateInfo::from_template(&this.db, &template).await?)
}

/// Edit a VM's custom spec.
///
/// The row is the VM's hardware *and* its price, so a successful patch does
/// three things: stores the new spec, rewrites the subscription line item so the
/// next renewal bills for what the customer now has, and queues the host work
/// that makes the running machine match. A spec that grows CPU, memory or disk
/// goes through the same upgrade pipeline a paid upgrade uses (stop, resize,
/// reconfigure, start); anything else only needs a reconfigure.
async fn admin_update_custom_template(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateCustomTemplateRequest>,
) -> ApiResult<AdminCustomTemplateUpdateResult> {
    auth.require_permission(AdminResource::VmCustomPricing, AdminAction::Update)?;

    let old = this.db.get_custom_vm_template(id).await?;
    let new = apply_template_patch(&old, req)?;
    reject_downgrade(&old, &new)?;

    // Validate against the (possibly new) plan's limits before writing, so an
    // out-of-range spec is a 400 rather than a VM the pricing engine cannot quote.
    PricingEngine::validate_custom_vm_spec(&this.db, &new)
        .await
        .map_err(|e| ApiError::bad_request(format!("Invalid custom template: {e}")))?;
    let renewal_amount = PricingEngine::get_custom_vm_cost_amount(&this.db, &new)
        .await
        .map_err(|e| ApiError::bad_request(format!("Cannot price custom template: {e}")))?
        .total();

    this.db.update_custom_vm_template(&new).await?;
    info!(
        "Admin {} updated custom template {}: cpu={} memory={} disk={}",
        auth.user_id, id, new.cpu, new.memory, new.disk_size
    );

    let vms = this.db.list_vms_by_custom_template(id).await?;
    if vms.len() > 1 {
        // The schema does not enforce it, so say so loudly rather than
        // silently re-pricing several customers from one request.
        warn!(
            "Custom template {} is shared by {} VMs; all were repriced and reconfigured",
            id,
            vms.len()
        );
    }

    let history = VmHistoryLogger::new(this.db.clone());
    let mut job_ids = Vec::with_capacity(vms.len());
    for vm in &vms {
        reprice_vm(&this.db, vm, renewal_amount).await?;

        if let Err(e) = history
            .log_vm_configuration_changed(
                vm.id,
                Some(auth.user_id),
                vm,
                vm, // the VM row is unchanged; the spec it points at is what moved
                Some(json!({
                    "change": "admin_custom_template_update",
                    "custom_template_id": id,
                    "old_specs": spec_json(&old),
                    "new_specs": spec_json(&new),
                    "renewal_amount": renewal_amount,
                })),
            )
            .await
        {
            warn!("Failed to log history for VM {}: {}", vm.id, e);
        }

        if let Some(job) = host_job_for(vm, &old, &new, auth.user_id)
            && let Some(job_id) = queue(&this, job).await
        {
            job_ids.push(job_id);
        }
    }

    let template = this.db.get_custom_vm_template(id).await?;
    ApiData::ok(AdminCustomTemplateUpdateResult {
        template: AdminCustomTemplateInfo::from_template(&this.db, &template).await?,
        renewal_amount,
        job_ids,
    })
}

/// Apply the patch to a copy of the stored template.
///
/// Unknown enum spellings are rejected rather than defaulted: a silently
/// downgraded disk interface or architecture is worse than a 400.
fn apply_template_patch(
    old: &VmCustomTemplate,
    req: UpdateCustomTemplateRequest,
) -> Result<VmCustomTemplate, ApiError> {
    let mut new = old.clone();

    if let Some(v) = req.cpu {
        if v == 0 {
            return Err(ApiError::bad_request("cpu must be at least 1"));
        }
        new.cpu = v;
    }
    if let Some(v) = req.memory {
        new.memory = v;
    }
    if let Some(v) = req.disk_size {
        new.disk_size = v;
    }
    if let Some(v) = &req.disk_type {
        new.disk_type =
            DiskType::from_str(v).map_err(|_| ApiError::bad_request("unknown disk type"))?;
    }
    if let Some(v) = &req.disk_interface {
        new.disk_interface = DiskInterface::from_str(v)
            .map_err(|_| ApiError::bad_request("unknown disk interface"))?;
    }
    if let Some(v) = req.pricing_id {
        new.pricing_id = v;
    }
    if let Some(v) = req.ip4_count {
        new.ip4_count = v;
    }
    if let Some(v) = req.ip6_count {
        new.ip6_count = v;
    }
    if let Some(v) = req.cpu_mfg {
        new.cpu_mfg = match v {
            Some(s) => CpuMfg::from_str(&s)
                .map_err(|_| ApiError::bad_request("unknown cpu manufacturer"))?,
            None => CpuMfg::Unknown,
        };
    }
    if let Some(v) = req.cpu_arch {
        new.cpu_arch = match v {
            Some(s) => CpuArch::from_str(&s)
                .map_err(|_| ApiError::bad_request("unknown cpu architecture"))?,
            None => CpuArch::Unknown,
        };
    }
    if let Some(v) = req.cpu_features {
        let mut features = Vec::new();
        for f in v.unwrap_or_default() {
            features.push(
                CpuFeature::from_str(&f)
                    .map_err(|_| ApiError::bad_request(format!("unknown cpu feature {f}")))?,
            );
        }
        new.cpu_features = features.into();
    }
    if let Some(v) = req.disk_iops_read {
        new.disk_iops_read = v;
    }
    if let Some(v) = req.disk_iops_write {
        new.disk_iops_write = v;
    }
    if let Some(v) = req.disk_mbps_read {
        new.disk_mbps_read = v;
    }
    if let Some(v) = req.disk_mbps_write {
        new.disk_mbps_write = v;
    }
    if let Some(v) = req.network_mbps {
        new.network_mbps = v;
    }
    if let Some(v) = req.cpu_limit {
        new.cpu_limit = v;
    }
    if let Some(v) = req.firewall_rule_limit {
        new.firewall_rule_limit = v;
    }
    if let Some(v) = req.transfer_gb {
        new.transfer_gb = v;
    }

    Ok(new)
}

/// CPU, memory and disk may only grow.
///
/// Shrinking a virtual disk destroys the filesystem living on the removed
/// blocks, and the customer upgrade path refuses downgrades for the same
/// reason. To give a customer less, delete the VM and re-create it.
fn reject_downgrade(old: &VmCustomTemplate, new: &VmCustomTemplate) -> Result<(), ApiError> {
    if new.cpu < old.cpu {
        return Err(ApiError::bad_request(format!(
            "Cannot downgrade CPU ({} -> {})",
            old.cpu, new.cpu
        )));
    }
    if new.memory < old.memory {
        return Err(ApiError::bad_request(format!(
            "Cannot downgrade memory ({} -> {})",
            old.memory, new.memory
        )));
    }
    if new.disk_size < old.disk_size {
        return Err(ApiError::bad_request(format!(
            "Cannot downgrade disk size ({} -> {})",
            old.disk_size, new.disk_size
        )));
    }
    Ok(())
}

/// The work needed on the host, if any.
///
/// Growing CPU/memory/disk needs the upgrade pipeline (stop, resize the disk,
/// reconfigure, start). Everything else the host cares about — IO/network caps,
/// CPU pinning hints — is applied by a plain reconfigure. A change the API
/// enforces on its own (`pricing_id`, IP counts, transfer quota, the firewall
/// rule allowance) touches nothing on the hypervisor, so no job is queued.
fn host_job_for(
    vm: &Vm,
    old: &VmCustomTemplate,
    new: &VmCustomTemplate,
    admin_user_id: u64,
) -> Option<WorkJob> {
    let cpu = (new.cpu != old.cpu).then_some(new.cpu);
    let memory = (new.memory != old.memory).then_some(new.memory);
    let disk = (new.disk_size != old.disk_size).then_some(new.disk_size);

    if cpu.is_some() || memory.is_some() || disk.is_some() {
        return Some(WorkJob::ProcessVmUpgrade {
            vm_id: vm.id,
            config: UpgradeConfig::new(cpu, memory, disk),
        });
    }

    let reconfigure = new.disk_type != old.disk_type
        || new.disk_interface != old.disk_interface
        || new.disk_iops_read != old.disk_iops_read
        || new.disk_iops_write != old.disk_iops_write
        || new.disk_mbps_read != old.disk_mbps_read
        || new.disk_mbps_write != old.disk_mbps_write
        || new.network_mbps != old.network_mbps
        || new.cpu_limit != old.cpu_limit;

    reconfigure.then_some(WorkJob::ConfigureVm {
        vm_id: vm.id,
        admin_user_id: Some(admin_user_id),
    })
}

/// Point the VM's subscription line item at the new monthly cost, so the next
/// renewal charges for the spec the customer now has.
async fn reprice_vm(db: &Arc<dyn LNVpsDb>, vm: &Vm, amount: u64) -> Result<(), ApiError> {
    let mut line_item = db
        .get_subscription_line_item(vm.subscription_line_item_id)
        .await?;
    if line_item.amount != amount {
        line_item.amount = amount;
        db.update_subscription_line_item(&line_item).await?;
    }
    Ok(())
}

/// Queue a job, logging rather than failing: the spec and the price are already
/// committed, and reporting the whole request as failed would invite a retry
/// that re-prices nothing but confuses the admin.
async fn queue(this: &RouterState, job: WorkJob) -> Option<String> {
    match this.work_commander.send(job).await {
        Ok(stream_id) => Some(stream_id),
        Err(e) => {
            error!("Failed to queue job after custom template update: {e}");
            None
        }
    }
}

fn spec_json(template: &VmCustomTemplate) -> serde_json::Value {
    json!({
        "cpu": template.cpu,
        "memory": template.memory,
        "disk_size": template.disk_size,
        "disk_type": template.disk_type.to_string(),
        "disk_interface": template.disk_interface.to_string(),
        "pricing_id": template.pricing_id,
        "ip4_count": template.ip4_count,
        "ip6_count": template.ip6_count,
    })
}

#[cfg(test)]
mod tests;
