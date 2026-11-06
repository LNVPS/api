use crate::host::{DiskStream, FullVmInfo, HashingReader, VmHostClient};
use crate::provisioner::VmProvisioner;
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use lnvps_api_common::{
    IpPolicy, MigrationMethod, MigrationOptions, MigrationPlan, NetworkProvisioner,
    VmHistoryLogger, VmRunningStates, load_migration_plan,
};
use lnvps_db::{Vm, VmHost, VmIpAssignment, VmMigration, VmMigrationState};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const STALE_MIGRATION_GRACE_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReassignedIp {
    pub old_ip: String,
    pub new_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    pub vm: Vm,
    pub migration_id: Option<u64>,
    pub method: MigrationMethod,
    pub reassigned: Vec<ReassignedIp>,
    pub source_retained: bool,
    pub needs_attention: Option<String>,
}

struct Ctx {
    migration: VmMigration,
    vm: Vm,
    source_host: VmHost,
    target_host: VmHost,
    source: Arc<dyn VmHostClient>,
    target: Arc<dyn VmHostClient>,
    options: MigrationOptions,
    plan: MigrationPlan,
    initiated_by: Option<u64>,
    inherited_running: bool,
    old_ips: Vec<VmIpAssignment>,
    new_ip_ids: Vec<u64>,
    target_created: bool,
}

impl VmProvisioner {
    pub async fn plan_vm_migration(
        &self,
        vm_id: u64,
        target_host_id: u64,
        options: &MigrationOptions,
    ) -> Result<MigrationPlan> {
        load_migration_plan(self.db(), vm_id, target_host_id, options).await
    }

    pub async fn migrate_vm_with(
        &self,
        vm_id: u64,
        target_host_id: u64,
        live: bool,
        options: &MigrationOptions,
        initiated_by: Option<u64>,
    ) -> Result<MigrationOutcome> {
        if self.read_only() {
            bail!("Cant migrate VM's in read-only mode");
        }
        let inherited_running = self.expire_stale_migration(vm_id).await?;
        let plan = self
            .plan_vm_migration(vm_id, target_host_id, options)
            .await?;
        if !plan.allowed() {
            bail!("Migration refused: {}", plan.refusals.join("; "));
        }
        match plan.method {
            Some(MigrationMethod::Hypervisor) => {
                let db = self.get_db();
                let vm = db.get_vm(vm_id).await?;
                let mut lock = VmMigration {
                    vm_id,
                    source_host_id: vm.host_id,
                    source_disk_id: vm.disk_id,
                    target_host_id,
                    target_disk_id: plan.target_disk_id.unwrap_or_default(),
                    phase: "hypervisor".to_string(),
                    options: serde_json::to_string(options)?,
                    initiated_by,
                    ..Default::default()
                };
                lock.id = db
                    .insert_vm_migration(&lock)
                    .await
                    .context("VM is already being migrated")?;
                let res = self
                    .migrate_vm(vm_id, target_host_id, live, initiated_by)
                    .await;
                lock.state = if res.is_ok() {
                    VmMigrationState::Completed
                } else {
                    VmMigrationState::Failed
                };
                lock.flipped = res.is_ok();
                lock.error = res.as_ref().err().map(|e| format!("{e:#}"));
                lock.finished = Some(Utc::now());
                db.update_vm_migration(&lock).await?;
                let vm = res?;
                Ok(MigrationOutcome {
                    vm,
                    migration_id: Some(lock.id),
                    method: MigrationMethod::Hypervisor,
                    reassigned: vec![],
                    source_retained: false,
                    needs_attention: None,
                })
            }
            _ => {
                self.copy_and_adopt(plan, options.clone(), initiated_by, inherited_running)
                    .await
            }
        }
    }

    async fn expire_stale_migration(&self, vm_id: u64) -> Result<bool> {
        let db = self.get_db();
        let Some(mut active) = db.get_active_vm_migration(vm_id).await? else {
            return Ok(false);
        };
        let options: MigrationOptions = serde_json::from_str(&active.options).unwrap_or_default();
        let disk = FullVmInfo::vm_resources(vm_id, db.clone())
            .await
            .map(|r| r.disk_size)
            .unwrap_or(0);
        let limit = chrono::TimeDelta::seconds(
            (options.transfer_timeout_secs(disk) + STALE_MIGRATION_GRACE_SECS) as i64,
        );
        if Utc::now() - active.created < limit {
            return Ok(false);
        }
        warn!(
            "Migration {} of VM {} has been in phase {} since {}; treating it as abandoned",
            active.id, vm_id, active.phase, active.created
        );
        let inherit = active.source_was_running && !active.flipped;
        active.state = VmMigrationState::Failed;
        active.needs_attention = true;
        active.error = Some(format!(
            "abandoned in phase {} (worker stopped?); check host {} for a partial copy",
            active.phase, active.target_host_id
        ));
        active.finished = Some(Utc::now());
        db.update_vm_migration(&active).await?;
        Ok(inherit)
    }

    async fn copy_and_adopt(
        &self,
        plan: MigrationPlan,
        options: MigrationOptions,
        initiated_by: Option<u64>,
        inherited_running: bool,
    ) -> Result<MigrationOutcome> {
        let db = self.get_db();
        let vm = db.get_vm(plan.vm_id).await?;
        let source_host = db.get_host(plan.source_host_id).await?;
        let target_host = db.get_host(plan.target_host_id).await?;
        let target_disk_id = plan
            .target_disk_id
            .ok_or_else(|| anyhow!("plan has no target disk"))?;

        let mut migration = VmMigration {
            vm_id: vm.id,
            source_host_id: source_host.id,
            source_disk_id: vm.disk_id,
            target_host_id: target_host.id,
            target_disk_id,
            state: VmMigrationState::InProgress,
            phase: "planned".to_string(),
            options: serde_json::to_string(&options)?,
            initiated_by,
            ..Default::default()
        };
        migration.id = db
            .insert_vm_migration(&migration)
            .await
            .context("VM is already being migrated")?;

        let mut ctx = Ctx {
            migration,
            vm,
            source: self.host_client(&source_host).await?,
            target: self.host_client(&target_host).await?,
            source_host,
            target_host,
            options,
            plan,
            initiated_by,
            inherited_running,
            old_ips: vec![],
            new_ip_ids: vec![],
            target_created: false,
        };

        if let Err(e) = self.before_flip(&mut ctx).await {
            let rollback = self.rollback_before_flip(&mut ctx).await;
            let msg = match &rollback {
                Ok(()) => format!("{e:#}"),
                Err(r) => format!("{e:#}; rollback also failed: {r:#}"),
            };
            ctx.migration.state = if rollback.is_ok() {
                VmMigrationState::RolledBack
            } else {
                VmMigrationState::Failed
            };
            ctx.migration.needs_attention = rollback.is_err();
            ctx.migration.error = Some(msg.clone());
            ctx.migration.finished = Some(Utc::now());
            self.phase(
                &mut ctx,
                "rolled_back",
                format!("Migration failed and was rolled back: {msg}"),
            )
            .await;
            bail!(
                "Migration of VM {} failed before the switch-over: {msg}",
                ctx.vm.id
            );
        }

        self.after_flip(&mut ctx).await
    }

    async fn phase(&self, ctx: &mut Ctx, phase: &str, description: String) {
        ctx.migration.phase = phase.to_string();
        let db = self.get_db();
        if let Err(e) = db.update_vm_migration(&ctx.migration).await {
            warn!(
                "Failed to record migration {} phase {}: {}",
                ctx.migration.id, phase, e
            );
        }
        if let Err(e) = VmHistoryLogger::new(db)
            .log_vm_migration_phase(
                ctx.vm.id,
                ctx.initiated_by,
                ctx.migration.id,
                phase,
                description,
                Some(json!({
                    "source_host_id": ctx.source_host.id,
                    "target_host_id": ctx.target_host.id,
                    "bytes_copied": ctx.migration.bytes_copied,
                })),
            )
            .await
        {
            warn!("Failed to log migration phase for VM {}: {}", ctx.vm.id, e);
        }
    }

    async fn before_flip(&self, ctx: &mut Ctx) -> Result<()> {
        let db = self.get_db();
        self.phase(
            ctx,
            "started",
            format!(
                "Copying VM from {} host {} to {} host {} ({} bytes, ip_policy {:?})",
                ctx.source_host.kind,
                ctx.source_host.name,
                ctx.target_host.kind,
                ctx.target_host.name,
                ctx.plan.disk_bytes,
                ctx.options.ip_policy
            ),
        )
        .await;

        let earlier_attempt = db.list_vm_migrations(ctx.vm.id).await?.iter().any(|m| {
            m.id != ctx.migration.id
                && m.target_host_id == ctx.target_host.id
                && !m.flipped
                && m.state != VmMigrationState::Completed
        });
        clear_stale_target(ctx, earlier_attempt).await?;

        let running = matches!(
            ctx.source.get_vm_state(&ctx.vm).await.map(|s| s.state),
            Ok(VmRunningStates::Running)
        );
        ctx.migration.source_was_running = running || ctx.inherited_running;
        if running {
            ctx.source.stop_vm(&ctx.vm).await?;
        }
        self.phase(
            ctx,
            "source_stopped",
            "VM stopped on the source host".to_string(),
        )
        .await;

        ctx.old_ips = db
            .list_vm_ip_assignments(ctx.vm.id)
            .await?
            .into_iter()
            .filter(|i| !i.deleted)
            .collect();
        if ctx.options.ip_policy == IpPolicy::Reassign {
            self.allocate_new_ips(ctx).await?;
            self.phase(
                ctx,
                "ips_allocated",
                format!("Allocated {} new addresses", ctx.new_ip_ids.len()),
            )
            .await;
        }

        let mut info = FullVmInfo::load(ctx.vm.id, db.clone()).await?;
        info.host = ctx.target_host.clone();
        info.disk = db.get_host_disk(ctx.migration.target_disk_id).await?;
        info.vm.host_id = ctx.target_host.id;
        info.vm.disk_id = ctx.migration.target_disk_id;
        if ctx.options.ip_policy == IpPolicy::Reassign {
            info.ips = db
                .list_vm_ip_assignments(ctx.vm.id)
                .await?
                .into_iter()
                .filter(|i| ctx.new_ip_ids.contains(&i.id))
                .collect();
            info.ranges.clear();
            for ip in &info.ips {
                if !info.ranges.iter().any(|r| r.id == ip.ip_range_id) {
                    info.ranges.push(db.get_ip_range(ip.ip_range_id).await?);
                }
            }
        }

        self.phase(ctx, "copying", "Copying the disk".to_string())
            .await;
        let export = ctx.source.export_primary_disk(&ctx.vm).await?;
        let expected = export.size;
        let (reader, probe) = HashingReader::wrap(export.reader);
        let stream = DiskStream {
            size: expected,
            format: export.format,
            reader,
        };
        let timeout = Duration::from_secs(ctx.options.transfer_timeout_secs(expected));
        ctx.target_created = true;
        let imported = tokio::time::timeout(timeout, ctx.target.create_vm_from_disk(&info, stream))
            .await
            .map_err(|_| anyhow!("disk copy did not finish within {}s", timeout.as_secs()))??;
        let (sent, sent_sha) = probe.finish();
        ctx.migration.bytes_copied = sent;
        ctx.migration.checksum = Some(sent_sha.clone());
        if sent != expected {
            bail!("source sent {sent} bytes, expected {expected}");
        }
        if imported.bytes != sent || imported.sha256 != sent_sha {
            bail!(
                "checksum mismatch: sent {sent} bytes sha256 {sent_sha}, destination wrote {} bytes sha256 {}",
                imported.bytes,
                imported.sha256
            );
        }
        if matches!(
            ctx.source.get_vm_state(&ctx.vm).await.map(|s| s.state),
            Ok(VmRunningStates::Running)
        ) {
            bail!(
                "the VM was started during the copy on source host {}; the copy is stale",
                ctx.source_host.id
            );
        }
        self.phase(
            ctx,
            "verified",
            format!("Disk copied and verified ({sent} bytes, sha256 {sent_sha})"),
        )
        .await;
        Ok(())
    }

    async fn allocate_new_ips(&self, ctx: &mut Ctx) -> Result<()> {
        let db = self.get_db();
        let v4 = ctx
            .old_ips
            .iter()
            .filter(|i| i.ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_ipv4()))
            .count() as u16;
        let v6 = ctx.old_ips.len() as u16 - v4;
        let picked = NetworkProvisioner::new(db.clone())
            .pick_ips_for_region(ctx.target_host.region_id, v4, v6)
            .await?;
        let mut fresh = Vec::new();
        for ip in picked.ip4 {
            fresh.push(VmIpAssignment {
                vm_id: ctx.vm.id,
                ip_range_id: ip.range_id,
                ip: ip.ip.ip().to_string(),
                ..Default::default()
            });
        }
        for mut ip in picked.ip6 {
            fresh.push(VmProvisioner::v6_to_allocation(
                &mut ip,
                ctx.vm.id,
                &ctx.vm.mac_address,
            )?);
        }
        for mut a in fresh {
            let range = db.get_ip_range(a.ip_range_id).await?;
            self.network.validate_ip_assignment(&a, &range)?;
            self.network.persist_ip_assignment(&mut a).await?;
            ctx.new_ip_ids.push(a.id);
        }
        Ok(())
    }

    async fn rollback_before_flip(&self, ctx: &mut Ctx) -> Result<()> {
        let db = self.get_db();
        let mut errors = Vec::new();
        if ctx.target_created
            && let Err(e) = ctx.target.delete_vm(&ctx.vm).await
        {
            errors.push(format!("remove destination copy: {e}"));
        }
        for id in ctx.new_ip_ids.drain(..) {
            if let Err(e) = db.hard_delete_vm_ip_assignment(id).await {
                errors.push(format!("remove new address {id}: {e}"));
            }
        }
        if ctx.migration.source_was_running
            && let Err(e) = ctx.source.start_vm(&ctx.vm).await
        {
            errors.push(format!("restart on source: {e}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(errors.join("; ")))
        }
    }

    async fn after_flip(&self, ctx: &mut Ctx) -> Result<MigrationOutcome> {
        let db = self.get_db();
        db.update_vm_host(ctx.vm.id, ctx.target_host.id, ctx.migration.target_disk_id)
            .await?;
        let old_disk = ctx.vm.disk_id;
        ctx.vm.host_id = ctx.target_host.id;
        ctx.vm.disk_id = ctx.migration.target_disk_id;
        ctx.migration.flipped = true;
        ctx.migration.source_retained = true;
        self.phase(
            ctx,
            "switched",
            "Database now points at the destination host".to_string(),
        )
        .await;

        let mut problems: Vec<String> = Vec::new();
        let mut reassigned = Vec::new();

        if let Err(e) = ctx.source.retire_vm(&ctx.vm).await {
            problems.push(format!("could not disable the source copy: {e}"));
        }

        if ctx.options.ip_policy == IpPolicy::Reassign {
            match self.switch_ips(ctx).await {
                Ok(r) => reassigned = r,
                Err(e) => problems.push(format!("address switch-over incomplete: {e:#}")),
            }
        } else {
            for ip in &mut ctx.old_ips {
                if let Err(e) = self.refresh_ip_policy(ip).await {
                    problems.push(format!("ARP/DNS refresh for {}: {e:#}", ip.ip));
                }
            }
        }

        match FullVmInfo::load(ctx.vm.id, db.clone()).await {
            Ok(info) => {
                if let Err(e) = ctx.target.patch_firewall(&info).await {
                    problems.push(format!("firewall: {e}"));
                }
            }
            Err(e) => problems.push(format!("reload VM: {e}")),
        }

        if ctx.migration.source_was_running
            && let Err(e) = ctx.target.start_vm(&ctx.vm).await
        {
            problems.push(format!("start on destination: {e}"));
        }

        if !ctx.options.keep_source && problems.is_empty() {
            match ctx.source.delete_vm(&ctx.vm).await {
                Ok(()) => ctx.migration.source_retained = false,
                Err(e) => problems.push(format!("could not delete the source copy: {e}")),
            }
        }

        if let Err(e) = VmHistoryLogger::new(db.clone())
            .log_vm_migrated(
                ctx.vm.id,
                ctx.initiated_by,
                ctx.source_host.id,
                ctx.target_host.id,
                false,
                Some((old_disk, ctx.migration.target_disk_id)),
                Some(json!({
                    "method": "copy_and_adopt",
                    "migration_id": ctx.migration.id,
                    "source_host": ctx.source_host.name,
                    "target_host": ctx.target_host.name,
                    "ip_policy": ctx.options.ip_policy,
                    "reassigned": reassigned,
                    "bytes": ctx.migration.bytes_copied,
                    "sha256": ctx.migration.checksum,
                    "source_retained": ctx.migration.source_retained,
                })),
            )
            .await
        {
            warn!("Failed to log migration of VM {}: {}", ctx.vm.id, e);
        }

        ctx.migration.old_ips = Some(serde_json::to_string(&reassigned)?);
        ctx.migration.state = VmMigrationState::Completed;
        ctx.migration.finished = Some(Utc::now());
        let attention = (!problems.is_empty()).then(|| problems.join("; "));
        ctx.migration.needs_attention = attention.is_some();
        ctx.migration.error = attention.clone();
        let summary = match &attention {
            Some(p) => format!("Migration finished on the destination with follow-up needed: {p}"),
            None if ctx.migration.source_retained => {
                "Migration finished; the stopped source copy is kept for manual deletion"
                    .to_string()
            }
            None => "Migration finished; the source copy was deleted".to_string(),
        };
        self.phase(ctx, "completed", summary).await;
        info!(
            "VM {} copy-and-adopt migration {} done",
            ctx.vm.id, ctx.migration.id
        );

        Ok(MigrationOutcome {
            vm: db.get_vm(ctx.vm.id).await?,
            migration_id: Some(ctx.migration.id),
            method: MigrationMethod::CopyAndAdopt,
            reassigned,
            source_retained: ctx.migration.source_retained,
            needs_attention: attention,
        })
    }

    async fn refresh_ip_policy(&self, ip: &mut VmIpAssignment) -> Result<()> {
        let range = self.get_db().get_ip_range(ip.ip_range_id).await?;
        self.network.update_ip_assignment_policy(ip, &range).await?;
        self.get_db().update_vm_ip_assignment(ip).await?;
        Ok(())
    }

    async fn switch_ips(&self, ctx: &mut Ctx) -> Result<Vec<ReassignedIp>> {
        let db = self.get_db();
        let mut errors = Vec::new();
        for old in &mut ctx.old_ips {
            let range = db.get_ip_range(old.ip_range_id).await?;
            if let Err(e) = self.network.delete_ip_assignment(old, &range).await {
                errors.push(format!("release {}: {e}", old.ip));
            }
        }
        let mut fresh = Vec::new();
        for id in &ctx.new_ip_ids {
            let mut a = db.get_vm_ip_assignment(*id).await?;
            if let Err(e) = self.refresh_ip_policy(&mut a).await {
                errors.push(format!("ARP/DNS for {}: {e:#}", a.ip));
            }
            fresh.push(a);
        }
        let mut out = Vec::new();
        for old in &ctx.old_ips {
            let is_v4 = old
                .ip
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_ipv4());
            let pos = fresh
                .iter()
                .position(|n| n.ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_ipv4()) == is_v4);
            out.push(ReassignedIp {
                old_ip: old.ip.clone(),
                new_ip: pos.map(|p| fresh.remove(p).ip),
            });
        }
        if errors.is_empty() {
            Ok(out)
        } else {
            Err(anyhow!(errors.join("; ")))
        }
    }
}

async fn clear_stale_target(ctx: &Ctx, earlier_attempt: bool) -> Result<()> {
    if ctx.target.get_vm_state(&ctx.vm).await.is_err() {
        return Ok(());
    }
    if !earlier_attempt {
        bail!(
            "Target host {} already has a VM with id {} that no earlier migration left there; \
             refusing to overwrite it",
            ctx.target_host.id,
            ctx.vm.id
        );
    }
    warn!(
        "VM {} has a leftover copy on target host {} from an earlier attempt, removing it",
        ctx.vm.id, ctx.target_host.id
    );
    ctx.target.delete_vm(&ctx.vm).await?;
    Ok(())
}

#[cfg(test)]
#[path = "adopt_tests.rs"]
mod tests;
