//! Moving a VM between hosts, and noticing when someone already did (issue #66).
//!
//! Two halves that share one rule: **the host is the source of truth for where
//! a VM lives.** [`VmProvisioner::migrate_vm`] asks the hypervisor to move a VM
//! and only then updates `vm.host_id`; [`VmProvisioner::reconcile_vm_hosts`]
//! polls the hosts and updates `vm.host_id` when a VM turns up somewhere the
//! database did not expect (a hand-run migration in the Proxmox UI, for
//! instance). A VM whose `host_id` is wrong is not a cosmetic problem: every
//! lifecycle operation — start, stop, reinstall, firewall sync, state polling —
//! is aimed at the host in that column, so a stale value silently points all of
//! them at a node that no longer has the VM.

use crate::host::{MigrateVmRequest, VmResources, get_host_client};
use crate::provisioner::VmProvisioner;
use anyhow::{Result, anyhow, bail};
use lnvps_api_common::{
    HostCapacity, HostCapacityService, HostVmSpec, VmHistoryLogger, VmRunningStates,
};
use lnvps_db::{Vm, VmHost, VmHostDisk};
use log::{info, warn};
use serde_json::json;
use std::collections::HashMap;

/// Where a migration should put the VM on the destination host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationTarget {
    /// Database id of the destination host disk.
    pub disk_id: u64,
    /// Storage pool to copy the disk into, or `None` when a pool of the same
    /// name exists on the destination.
    ///
    /// `None` hands the copy decision to the hypervisor layer rather than
    /// deciding it here: a same-named pool is the *same* storage only when it
    /// is shared, and only the host knows that. On shared storage the disk
    /// stays put (asking for a copy would turn a seconds-long migration into a
    /// full disk transfer); on node-local storage of the same name — `local-zfs`
    /// on every node — the disk is copied into that name on the far side.
    pub target_storage: Option<String>,
}

/// A VM found running somewhere other than where the database says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmHostDrift {
    pub vm_id: u64,
    /// Host the database has recorded.
    pub from_host_id: u64,
    /// Host the VM was actually found on.
    pub to_host_id: u64,
    /// Storage pool backing the VM's disk on the host it was found on.
    pub storage: Option<String>,
}

/// Decide whether `vm_resources` can move onto `target_host`, and where its
/// disk goes.
///
/// Kept separate from the IO so the refusal rules are testable: a migration
/// that oversubscribes the destination or lands a VM in a region whose VLANs
/// its IPs do not exist on is worse than no migration at all — the VM comes up
/// on the far side unreachable, and the customer sees it as an outage.
pub fn plan_migration(
    resources: &VmResources,
    source_host: &VmHost,
    source_disk: &VmHostDisk,
    target_host: &VmHost,
    target_capacity: &HostCapacity,
) -> Result<MigrationTarget> {
    if target_host.id == source_host.id {
        bail!("VM is already on host {}", target_host.id);
    }
    if !target_host.enabled {
        bail!("Target host {} is disabled", target_host.id);
    }
    if target_host.kind != source_host.kind {
        bail!(
            "Cannot migrate between host kinds ({} -> {})",
            source_host.kind,
            target_host.kind
        );
    }
    // IP assignments are not rewritten by a migration, so the destination must
    // sit on the same VLANs/ranges — which in this schema means the same region.
    if target_host.region_id != source_host.region_id {
        bail!(
            "Target host {} is in region {}, VM is in region {}; migration would strand its IPs",
            target_host.id,
            target_host.region_id,
            source_host.region_id
        );
    }
    if target_host.cpu_arch != source_host.cpu_arch {
        bail!(
            "Target host CPU architecture ({}) does not match the source ({})",
            target_host.cpu_arch,
            source_host.cpu_arch
        );
    }

    if target_capacity.available_cpu() < resources.cpu {
        bail!(
            "Target host {} has {} free cores, VM needs {}",
            target_host.id,
            target_capacity.available_cpu(),
            resources.cpu
        );
    }
    if target_capacity.available_memory() < resources.memory {
        bail!(
            "Target host {} has {} bytes of free memory, VM needs {}",
            target_host.id,
            target_capacity.available_memory(),
            resources.memory
        );
    }

    // Prefer the pool with the same name as the source: on shared storage that
    // is the same storage, so the VM moves without copying a byte, and on
    // node-local storage it at least keeps the VM's disk layout unchanged.
    // Whether a copy is needed is settled by the host client, which can see
    // the pool's `shared` flag.
    let same_name = target_capacity
        .disks
        .iter()
        .find(|d| d.disk.name == source_disk.name && d.disk.enabled);
    if let Some(d) = same_name
        && d.available_capacity() >= resources.disk_size
    {
        return Ok(MigrationTarget {
            disk_id: d.disk.id,
            target_storage: None,
        });
    }

    let fallback = target_capacity
        .disks
        .iter()
        .filter(|d| d.disk.enabled && d.available_capacity() >= resources.disk_size)
        // Most free space first, so a migration does not fill the tightest pool.
        .max_by_key(|d| d.available_capacity())
        .ok_or_else(|| {
            anyhow!(
                "No enabled disk on host {} has {} bytes free for the VM",
                target_host.id,
                resources.disk_size
            )
        })?;

    Ok(MigrationTarget {
        disk_id: fallback.disk.id,
        target_storage: Some(fallback.disk.name.clone()),
    })
}

/// Compare recorded VM placement against what the hosts actually report.
///
/// `db_placement` is `vm_id -> host_id` for live VMs; `observed` is the VM list
/// each **reachable** host returned. Hosts that could not be polled must be left
/// out entirely rather than passed as an empty list, or every VM on an
/// unreachable host looks like it vanished.
///
/// A VM seen on more than one host is reported as ambiguous and never
/// reconciled: that is the signature of a leftover copy on the source node
/// after a migration, and picking one of the two at random would flap the
/// database between them on every poll.
pub fn plan_host_drift(
    db_placement: &HashMap<u64, u64>,
    observed: &HashMap<u64, Vec<HostVmSpec>>,
) -> (Vec<VmHostDrift>, Vec<u64>) {
    // vm_id -> [(host_id, storage)]
    let mut seen: HashMap<u64, Vec<(u64, Option<String>)>> = HashMap::new();
    for (host_id, specs) in observed {
        for spec in specs {
            if let Some(vm_id) = spec.mapped_vm_id {
                seen.entry(vm_id)
                    .or_default()
                    .push((*host_id, spec.disk_storage.clone()));
            }
        }
    }

    let mut drift = Vec::new();
    let mut ambiguous = Vec::new();
    for (vm_id, recorded_host) in db_placement {
        let Some(hosts) = seen.get(vm_id) else {
            // Not on any polled host: could be an unreachable host we skipped,
            // or a VM that was never spawned. Not evidence of a migration.
            continue;
        };
        if hosts.len() > 1 {
            ambiguous.push(*vm_id);
            continue;
        }
        let (found_host, storage) = &hosts[0];
        if found_host != recorded_host {
            drift.push(VmHostDrift {
                vm_id: *vm_id,
                from_host_id: *recorded_host,
                to_host_id: *found_host,
                storage: storage.clone(),
            });
        }
    }

    drift.sort_by_key(|d| d.vm_id);
    ambiguous.sort_unstable();
    (drift, ambiguous)
}

impl VmProvisioner {
    /// Migrate a VM to another host.
    ///
    /// `live` attempts an online migration (the VM keeps running); otherwise a
    /// running VM is stopped first and started again on the destination. The
    /// database is only updated after the hypervisor reports success, so a
    /// failed migration leaves the VM on — and pointed at — the source host.
    pub async fn migrate_vm(
        &self,
        vm_id: u64,
        target_host_id: u64,
        live: bool,
        initiated_by_user: Option<u64>,
    ) -> Result<Vm> {
        if self.read_only() {
            bail!("Cant migrate VM's in read-only mode");
        }

        let db = self.get_db();
        let mut vm = db.get_vm(vm_id).await?;
        if vm.deleted {
            bail!("Cannot migrate a deleted VM");
        }

        let source_host = db.get_host(vm.host_id).await?;
        let target_host = db.get_host(target_host_id).await?;
        let source_disk = db.get_host_disk(vm.disk_id).await?;

        let resources = Self::vm_resources(&db, &vm).await?;
        let capacity = HostCapacityService::new(db.clone())
            .get_host_capacity(&target_host, None, None)
            .await?;
        let target = plan_migration(
            &resources,
            &source_host,
            &source_disk,
            &target_host,
            &capacity,
        )?;

        let source_client = get_host_client(&source_host, self.config())?;
        let was_running = matches!(
            source_client.get_vm_state(&vm).await.map(|s| s.state),
            Ok(VmRunningStates::Running)
        );

        // An offline migration of a running VM is refused by the hypervisor, so
        // stop it here rather than surfacing that as a migration failure.
        if was_running && !live {
            info!("Stopping VM {} for offline migration", vm.id);
            source_client.stop_vm(&vm).await?;
        }

        info!(
            "Migrating VM {} from host {} to host {} ({})",
            vm.id,
            source_host.id,
            target_host.id,
            if live { "online" } else { "offline" }
        );
        source_client
            .migrate_vm(
                &vm,
                &MigrateVmRequest {
                    target_node: target_host.name.clone(),
                    online: live && was_running,
                    target_storage: target.target_storage.clone(),
                },
            )
            .await?;

        let old_host_id = vm.host_id;
        db.update_vm_host(vm.id, target_host.id, target.disk_id)
            .await?;
        vm.host_id = target_host.id;
        vm.disk_id = target.disk_id;

        // Start it again where it now lives; an online migration never stopped.
        if was_running && !live {
            let target_client = get_host_client(&target_host, self.config())?;
            if let Err(e) = target_client.start_vm(&vm).await {
                warn!(
                    "VM {} migrated to host {} but failed to start: {}",
                    vm.id, target_host.id, e
                );
            }
        }

        VmHistoryLogger::new(db.clone())
            .log_vm_migrated(
                vm.id,
                initiated_by_user,
                old_host_id,
                target_host.id,
                false,
                Some(json!({
                    "live": live,
                    "source_host": source_host.name,
                    "target_host": target_host.name,
                    "target_storage": target.target_storage,
                })),
            )
            .await?;

        Ok(vm)
    }

    /// Poll every enabled host and re-point `vm.host_id` at whichever host is
    /// actually running the VM.
    ///
    /// Returns the reconciled drifts. Migrations performed outside this API —
    /// a `qm migrate` on the node, a hand-run migration in the Proxmox UI —
    /// leave the database pointing at the old host, which breaks every
    /// subsequent lifecycle operation for that VM until someone notices.
    pub async fn reconcile_vm_hosts(&self) -> Result<Vec<VmHostDrift>> {
        let db = self.get_db();
        let hosts = db.list_hosts().await?;

        let mut observed: HashMap<u64, Vec<HostVmSpec>> = HashMap::new();
        for host in &hosts {
            let client = match get_host_client(host, self.config()) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Skipping host {} in placement check: {}", host.id, e);
                    continue;
                }
            };
            match client.list_host_vms().await {
                // Only hosts that answered are considered: a host we could not
                // reach must not make its VMs look like they moved away.
                Ok(vms) => {
                    observed.insert(host.id, vms);
                }
                Err(e) => warn!("Failed to list VMs on host {}: {}", host.id, e),
            }
        }

        let db_placement: HashMap<u64, u64> = db
            .list_vms()
            .await?
            .into_iter()
            .filter(|v| !v.deleted)
            .map(|v| (v.id, v.host_id))
            .collect();

        let (drifts, ambiguous) = plan_host_drift(&db_placement, &observed);
        for vm_id in ambiguous {
            warn!(
                "VM {} exists on more than one host; not reconciling placement \
                 (a leftover copy on the source host?)",
                vm_id
            );
        }

        let logger = VmHistoryLogger::new(db.clone());
        let mut applied = Vec::new();
        for drift in drifts {
            let vm = match db.get_vm(drift.vm_id).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to load VM {} for placement fix: {}", drift.vm_id, e);
                    continue;
                }
            };
            // The VM's disk row belongs to the old host; move it to the pool it
            // is actually on, else capacity accounting keeps charging the disk
            // to a host that no longer stores it.
            let target_disks = db
                .list_host_disks(drift.to_host_id)
                .await
                .unwrap_or_default();
            let disk = drift
                .storage
                .as_ref()
                .and_then(|s| target_disks.iter().find(|d| &d.name == s))
                .or_else(|| target_disks.iter().find(|d| d.enabled))
                .or_else(|| target_disks.first());
            let Some(disk) = disk else {
                warn!(
                    "VM {} appears on host {} which has no disks recorded; leaving placement alone",
                    drift.vm_id, drift.to_host_id
                );
                continue;
            };

            info!(
                "VM {} found on host {} but recorded on host {}; updating database",
                drift.vm_id, drift.to_host_id, drift.from_host_id
            );
            if let Err(e) = db.update_vm_host(vm.id, drift.to_host_id, disk.id).await {
                warn!("Failed to fix placement of VM {}: {}", drift.vm_id, e);
                continue;
            }

            if let Err(e) = logger
                .log_vm_migrated(
                    drift.vm_id,
                    None,
                    drift.from_host_id,
                    drift.to_host_id,
                    true,
                    Some(json!({ "storage": drift.storage })),
                )
                .await
            {
                warn!("Failed to log placement fix for VM {}: {}", drift.vm_id, e);
            }
            applied.push(drift);
        }

        Ok(applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::{DiskCapacity, GB, LoadFactors};
    use lnvps_db::{CpuArch, VmHostKind};

    fn host(id: u64, region: u64, enabled: bool) -> VmHost {
        VmHost {
            id,
            kind: VmHostKind::Proxmox,
            region_id: region,
            name: format!("node-{id}"),
            cpu: 16,
            memory: 64 * GB,
            enabled,
            load_cpu: 1.0,
            load_memory: 1.0,
            load_disk: 1.0,
            ..Default::default()
        }
    }

    fn disk(id: u64, host_id: u64, name: &str, size: u64) -> VmHostDisk {
        VmHostDisk {
            id,
            host_id,
            name: name.to_string(),
            size,
            enabled: true,
            ..Default::default()
        }
    }

    /// Capacity for `host` with `disks` and the given already-consumed amounts.
    fn capacity(
        host: &VmHost,
        disks: Vec<(VmHostDisk, u64)>,
        cpu: u16,
        memory: u64,
    ) -> HostCapacity {
        HostCapacity {
            load_factor: LoadFactors {
                cpu: 1.0,
                memory: 1.0,
                disk: 1.0,
            },
            host: host.clone(),
            cpu,
            memory,
            disks: disks
                .into_iter()
                .map(|(disk, usage)| DiskCapacity {
                    load_factor: 1.0,
                    disk,
                    usage,
                })
                .collect(),
            ranges: vec![],
        }
    }

    fn resources() -> VmResources {
        VmResources {
            cpu: 4,
            memory: 8 * GB,
            disk_size: 100 * GB,
        }
    }

    #[test]
    fn test_migration_prefers_same_named_pool_without_copying_disk() {
        let src = host(1, 1, true);
        let dst = host(2, 1, true);
        let src_disk = disk(10, 1, "local-lvm", 4000 * GB);
        let cap = capacity(
            &dst,
            vec![
                (disk(20, 2, "slow", 4000 * GB), 0),
                (disk(21, 2, "local-lvm", 1000 * GB), 0),
            ],
            0,
            0,
        );

        let plan = plan_migration(&resources(), &src, &src_disk, &dst, &cap).expect("should plan");
        // Same pool name on both nodes: keep the disk where it is, even though
        // the other pool has more free space.
        assert_eq!(plan.disk_id, 21);
        assert_eq!(plan.target_storage, None);
    }

    #[test]
    fn test_migration_falls_back_to_emptiest_pool_and_copies_disk() {
        let src = host(1, 1, true);
        let dst = host(2, 1, true);
        let src_disk = disk(10, 1, "local-lvm", 4000 * GB);
        let cap = capacity(
            &dst,
            vec![
                (disk(20, 2, "nvme-a", 1000 * GB), 900 * GB),
                (disk(21, 2, "nvme-b", 1000 * GB), 100 * GB),
            ],
            0,
            0,
        );

        let plan = plan_migration(&resources(), &src, &src_disk, &dst, &cap).expect("should plan");
        assert_eq!(plan.disk_id, 21);
        assert_eq!(plan.target_storage, Some("nvme-b".to_string()));
    }

    #[test]
    fn test_migration_refuses_oversubscribed_or_incompatible_targets() {
        let src = host(1, 1, true);
        let src_disk = disk(10, 1, "local-lvm", 4000 * GB);
        let ok_disks = || vec![(disk(20, 2, "local-lvm", 4000 * GB), 0)];

        // Same host
        let dst = host(1, 1, true);
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 0, 0)
            )
            .is_err()
        );

        // Disabled host
        let dst = host(2, 1, false);
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 0, 0)
            )
            .is_err()
        );

        // Different region: the VM's IPs live on the source region's ranges, so
        // the VM would come up unreachable.
        let dst = host(2, 2, true);
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 0, 0)
            )
            .is_err()
        );

        // Different CPU architecture
        let mut dst = host(2, 1, true);
        dst.cpu_arch = CpuArch::ARM64;
        let mut src_arm = src.clone();
        src_arm.cpu_arch = CpuArch::X86_64;
        assert!(
            plan_migration(
                &resources(),
                &src_arm,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 0, 0)
            )
            .is_err()
        );

        // No CPU left
        let dst = host(2, 1, true);
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 16, 0)
            )
            .is_err()
        );

        // No memory left
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, ok_disks(), 0, 64 * GB)
            )
            .is_err()
        );

        // No disk with room
        assert!(
            plan_migration(
                &resources(),
                &src,
                &src_disk,
                &dst,
                &capacity(&dst, vec![(disk(20, 2, "local-lvm", 50 * GB), 0)], 0, 0)
            )
            .is_err()
        );
    }

    fn spec(vm_id: u64, storage: &str) -> HostVmSpec {
        HostVmSpec {
            host_vm_id: vm_id as i64 + 100,
            mapped_vm_id: Some(vm_id),
            name: None,
            cpu: 4,
            memory: 8 * GB,
            disk_size: 100 * GB,
            disk_storage: Some(storage.to_string()),
            mac_address: None,
            running: true,
        }
    }

    /// Regression for the reason this exists: a VM migrated by hand on the
    /// hypervisor leaves `vm.host_id` pointing at the old host, and every
    /// lifecycle operation then targets a node that no longer has the VM.
    #[test]
    fn test_detects_vm_moved_to_another_host() {
        let db: HashMap<u64, u64> = HashMap::from([(1, 10), (2, 10)]);
        let observed = HashMap::from([
            (10, vec![spec(2, "local-lvm")]),
            (11, vec![spec(1, "nvme-b")]),
        ]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(ambiguous.is_empty());
        assert_eq!(
            drift,
            vec![VmHostDrift {
                vm_id: 1,
                from_host_id: 10,
                to_host_id: 11,
                storage: Some("nvme-b".to_string()),
            }]
        );
    }

    #[test]
    fn test_vm_on_two_hosts_is_ambiguous_not_reconciled() {
        // A leftover copy on the source node after a migration. Choosing either
        // host would flap the database between them on every poll.
        let db: HashMap<u64, u64> = HashMap::from([(1, 10)]);
        let observed = HashMap::from([
            (10, vec![spec(1, "local-lvm")]),
            (11, vec![spec(1, "local-lvm")]),
        ]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(drift.is_empty());
        assert_eq!(ambiguous, vec![1]);
    }

    #[test]
    fn test_unreachable_host_does_not_look_like_a_migration() {
        // Host 10 could not be polled, so it is absent from `observed`
        // entirely; its VMs must not be treated as having moved or vanished.
        let db: HashMap<u64, u64> = HashMap::from([(1, 10), (2, 11)]);
        let observed = HashMap::from([(11, vec![spec(2, "local-lvm")])]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(drift.is_empty(), "{drift:?}");
        assert!(ambiguous.is_empty());
    }

    #[test]
    fn test_host_vms_outside_managed_range_are_ignored() {
        // Proxmox vmid < 100 has no database id; it must never be matched
        // against a VM row.
        let db: HashMap<u64, u64> = HashMap::from([(1, 10)]);
        let mut unmanaged = spec(1, "local-lvm");
        unmanaged.mapped_vm_id = None;
        let observed = HashMap::from([(10, vec![spec(1, "local-lvm")]), (11, vec![unmanaged])]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(drift.is_empty());
        assert!(ambiguous.is_empty());
    }

    // ---- end-to-end over the mock database and dummy hypervisor ----

    use crate::host::dummy_host::DummyVmHost;
    use crate::settings::mock_settings;
    use lnvps_api_common::MockDb;
    use lnvps_db::{LNVpsDbBase, Vm};
    use std::sync::Arc;

    /// Second host in region 1 of the mock database, with its own storage pool.
    async fn add_second_host(db: &Arc<MockDb>) {
        db.hosts.lock().await.insert(
            2,
            VmHost {
                id: 2,
                kind: VmHostKind::Dummy,
                region_id: 1,
                name: "mock-host-2".to_string(),
                ip: "https://localhost".to_string(),
                cpu: 64,
                cpu_arch: CpuArch::X86_64,
                memory: 512 * GB,
                enabled: true,
                load_cpu: 1.0,
                load_memory: 1.0,
                load_disk: 1.0,
                ..Default::default()
            },
        );
        db.host_disks.lock().await.insert(
            2,
            VmHostDisk {
                id: 2,
                host_id: 2,
                name: "mock-disk-2".to_string(),
                size: 10_000 * GB,
                enabled: true,
                ..Default::default()
            },
        );
    }

    async fn add_vm(db: &Arc<MockDb>) -> u64 {
        let pubkey: [u8; 32] = rand::random();
        let user_id = db.upsert_user(&pubkey).await.expect("user");
        db.insert_vm(&Vm {
            id: 0,
            host_id: 1,
            user_id,
            image_id: 1,
            template_id: Some(1),
            disk_id: 1,
            mac_address: "ff:ff:ff:ff:ff:ff".to_string(),
            ..Default::default()
        })
        .await
        .expect("vm")
    }

    #[tokio::test]
    async fn test_migrate_vm_updates_placement_after_the_host_agrees() {
        let db = Arc::new(MockDb::default());
        add_second_host(&db).await;
        let vm_id = add_vm(&db).await;
        DummyVmHost::clear_migrations().await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        let vm = provisioner
            .migrate_vm(vm_id, 2, true, Some(7))
            .await
            .expect("migration should succeed");

        assert_eq!(vm.host_id, 2);
        // The disk row must follow the VM: capacity accounting otherwise keeps
        // charging the disk to a host that no longer stores it.
        assert_eq!(vm.disk_id, 2);
        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 2);
        assert_eq!(stored.disk_id, 2);

        let migrations = DummyVmHost::migrations().await;
        let (migrated_vm, req) = migrations.last().expect("host was asked to migrate");
        assert_eq!(*migrated_vm, vm_id);
        assert_eq!(req.target_node, "mock-host-2");
        // Pool names differ between the two mock hosts, so the disk is copied.
        assert_eq!(req.target_storage, Some("mock-disk-2".to_string()));

        let history = db.list_vm_history(vm_id).await.expect("history");
        assert!(
            history
                .iter()
                .any(|h| matches!(h.action_type, lnvps_db::VmHistoryActionType::Migrated)),
            "migration must be recorded in VM history"
        );
    }

    #[tokio::test]
    async fn test_migrate_vm_rejects_unknown_or_unfit_target() {
        let db = Arc::new(MockDb::default());
        let vm_id = add_vm(&db).await;
        let provisioner = VmProvisioner::new(mock_settings(), db.clone());

        // Same host
        assert!(provisioner.migrate_vm(vm_id, 1, true, None).await.is_err());
        // Unknown host
        assert!(provisioner.migrate_vm(vm_id, 99, true, None).await.is_err());

        // Nothing was written on a refusal.
        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 1);
    }

    /// Regression for the case that motivated this: a VM migrated by hand on
    /// the hypervisor, leaving `vm.host_id` pointing at the host it left.
    #[tokio::test]
    async fn test_reconcile_moves_database_to_match_the_hosts() {
        let db = Arc::new(MockDb::default());
        add_second_host(&db).await;
        let vm_id = add_vm(&db).await;

        DummyVmHost::clear_host_vms().await;
        // Host 1 no longer has it; host 2 does.
        DummyVmHost::set_host_vms_for(1, vec![]).await;
        let mut moved = spec(vm_id, "mock-disk-2");
        moved.mapped_vm_id = Some(vm_id);
        DummyVmHost::set_host_vms_for(2, vec![moved]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        let drifts = provisioner.reconcile_vm_hosts().await.expect("reconcile");

        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].vm_id, vm_id);
        assert_eq!(drifts[0].from_host_id, 1);
        assert_eq!(drifts[0].to_host_id, 2);

        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 2);
        assert_eq!(stored.disk_id, 2);

        // Second pass is a no-op now the database agrees with the hosts.
        let drifts = provisioner.reconcile_vm_hosts().await.expect("reconcile");
        assert!(drifts.is_empty());
        DummyVmHost::clear_host_vms().await;
    }
}
