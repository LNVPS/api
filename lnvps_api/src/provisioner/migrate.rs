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
use crate::provisioner::{UNASSIGNED_MAC, VmProvisioner};
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

/// Where the hosts say a VM is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmLocation {
    /// Exactly one host has it. The database has been corrected if it disagreed.
    Host(u64),
    /// Every enabled host answered and none of them has this VM.
    Nowhere,
    /// More than one host has it — a leftover copy after a migration. Picking
    /// one would flap the database, and acting on it could delete the wrong copy.
    Ambiguous(Vec<u64>),
    /// At least one enabled host could not be polled, so absence proves nothing.
    Unknown,
}

/// What the database records about where a VM lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmPlacement {
    /// Host the VM is recorded on.
    pub host_id: u64,
    /// Name of the storage pool the VM's disk row points at, or `None` when
    /// that row could not be read. `None` disables the storage comparison for
    /// this VM rather than treating the pool as changed: a disk row we cannot
    /// name is not evidence that the disk moved.
    pub disk_name: Option<String>,
}

/// A VM found somewhere other than where the database says it is — on another
/// host, on another storage pool, or both.
///
/// `from_host_id == to_host_id` is a disk-only move: the VM stayed put and its
/// disk was moved between pools (`qm move-disk`, or the Proxmox UI's "Move
/// Storage"). That leaves `vm.disk_id` pointing at a pool that no longer holds
/// the disk, which charges the space to the wrong pool in capacity planning and
/// aims the next reinstall's import at the wrong storage.
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

impl VmHostDrift {
    /// Whether the VM changed host, as opposed to only changing storage pool.
    pub fn is_host_move(&self) -> bool {
        self.from_host_id != self.to_host_id
    }
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
/// `db_placement` is `vm_id -> `[`VmPlacement`] for live VMs; `observed` is the
/// VM list each **reachable** host returned. Hosts that could not be polled must
/// be left out entirely rather than passed as an empty list, or every VM on an
/// unreachable host looks like it vanished.
///
/// Both halves of a placement are compared, because both are acted on: the host
/// aims every lifecycle operation, and the disk row names the pool. A VM that
/// never left its host but whose disk was moved between pools by hand is
/// therefore reported too — the earlier version only compared hosts, so a
/// `qm move-disk` was invisible.
///
/// A VM seen on more than one host is reported as ambiguous and never
/// reconciled: that is the signature of a leftover copy on the source node
/// after a migration, and picking one of the two at random would flap the
/// database between them on every poll.
pub fn plan_host_drift(
    db_placement: &HashMap<u64, VmPlacement>,
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
    for (vm_id, recorded) in db_placement {
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
        let host_moved = *found_host != recorded.host_id;
        // Only a pool the host actually named can contradict the disk row. A
        // host client that could not read the VM's config reports `None`, which
        // is missing information, not a move.
        let disk_moved = match (storage.as_deref(), recorded.disk_name.as_deref()) {
            (Some(found), Some(recorded)) => found != recorded,
            _ => false,
        };
        if host_moved || disk_moved {
            drift.push(VmHostDrift {
                vm_id: *vm_id,
                from_host_id: recorded.host_id,
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

    /// Ask every host what it is running.
    ///
    /// Returns the VM lists of the hosts that **answered**, plus the number of
    /// enabled hosts that did not. A host we could not reach is left out of the
    /// map entirely rather than recorded as empty: its VMs have not vanished,
    /// we simply cannot see them, and treating silence as absence is how a
    /// network blip turns into a placement rewrite or a duplicate VM.
    async fn observe_hosts(&self) -> Result<(HashMap<u64, Vec<HostVmSpec>>, usize)> {
        let db = self.get_db();
        let hosts = db.list_hosts().await?;

        let mut observed: HashMap<u64, Vec<HostVmSpec>> = HashMap::new();
        let mut unreachable = 0;
        for host in &hosts {
            let client = match get_host_client(host, self.config()) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Skipping host {} in placement check: {}", host.id, e);
                    if host.enabled {
                        unreachable += 1;
                    }
                    continue;
                }
            };
            match client.list_host_vms().await {
                Ok(vms) => {
                    observed.insert(host.id, vms);
                }
                Err(e) => {
                    warn!("Failed to list VMs on host {}: {}", host.id, e);
                    if host.enabled {
                        unreachable += 1;
                    }
                }
            }
        }
        Ok((observed, unreachable))
    }

    /// Find out where a single VM actually lives, and correct the database if
    /// that is not where it was recorded.
    ///
    /// Used before the worker concludes that a VM is missing and rebuilds it:
    /// a VM absent from the host the database names is far more often one that
    /// moved than one that was destroyed, and re-creating it would leave the
    /// customer with two copies of their machine (or, when the ids collide as
    /// they do on Proxmox, a failed spawn whose rollback damages the live VM).
    pub async fn locate_vm(&self, vm: &Vm) -> Result<VmLocation> {
        let (observed, unreachable) = self.observe_hosts().await?;

        let mut found: Vec<(u64, Option<String>)> = observed
            .iter()
            .filter_map(|(host_id, specs)| {
                specs
                    .iter()
                    .find(|s| s.mapped_vm_id == Some(vm.id))
                    .map(|s| (*host_id, s.disk_storage.clone()))
            })
            .collect();
        found.sort_by_key(|(host_id, _)| *host_id);

        match found.len() {
            0 if unreachable > 0 => Ok(VmLocation::Unknown),
            0 => Ok(VmLocation::Nowhere),
            1 => {
                let (host_id, storage) = found.remove(0);
                if host_id != vm.host_id {
                    self.apply_drift(&VmHostDrift {
                        vm_id: vm.id,
                        from_host_id: vm.host_id,
                        to_host_id: host_id,
                        storage,
                    })
                    .await?;
                }
                Ok(VmLocation::Host(host_id))
            }
            _ => Ok(VmLocation::Ambiguous(
                found.into_iter().map(|(h, _)| h).collect(),
            )),
        }
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
        let (observed, _) = self.observe_hosts().await?;

        self.heal_unassigned_macs(&observed).await;

        // Disk rows are looked up once per host rather than once per VM: the
        // storage comparison needs the *name* of the pool each VM's disk row
        // points at, and a per-VM `get_host_disk` would be a query per VM on
        // every pass.
        let mut disk_names: HashMap<u64, String> = HashMap::new();
        for host in db.list_hosts().await? {
            for disk in db.list_host_disks(host.id).await.unwrap_or_default() {
                disk_names.insert(disk.id, disk.name);
            }
        }

        let db_placement: HashMap<u64, VmPlacement> = db
            .list_vms()
            .await?
            .into_iter()
            .filter(|v| !v.deleted)
            .map(|v| {
                (
                    v.id,
                    VmPlacement {
                        host_id: v.host_id,
                        disk_name: disk_names.get(&v.disk_id).cloned(),
                    },
                )
            })
            .collect();

        let (drifts, ambiguous) = plan_host_drift(&db_placement, &observed);
        for vm_id in ambiguous {
            warn!(
                "VM {} exists on more than one host; not reconciling placement \
                 (a leftover copy on the source host?)",
                vm_id
            );
        }

        let mut applied = Vec::new();
        for drift in drifts {
            match self.apply_drift(&drift).await {
                // Nothing changed: a drift we could not act on (an unrecorded
                // pool on a VM that never left its host) must not be reported,
                // or every pass would raise the same alert forever.
                Ok(false) => continue,
                Ok(true) => applied.push(drift),
                Err(e) => {
                    warn!("Failed to fix placement of VM {}: {}", drift.vm_id, e);
                    continue;
                }
            }
        }

        Ok(applied)
    }

    /// Re-point one VM's `host_id`/`disk_id` at the host and pool it was found
    /// on. Returns whether anything was actually written.
    async fn apply_drift(&self, drift: &VmHostDrift) -> Result<bool> {
        let db = self.get_db();
        let vm = db.get_vm(drift.vm_id).await?;

        // The VM's disk row belongs to the old host; move it to the pool the
        // host says the disk is on, else capacity accounting keeps charging the
        // disk to a host that no longer stores it.
        //
        // Matched by name and by name only. A pool we cannot name is not a pool
        // we can substitute for: every candidate is a guess about where a
        // customer's disk physically is, and recording the wrong one charges the
        // space to a pool that does not hold it and points the next reinstall's
        // `qm set <storage>:0` at a name that may not even exist on the node.
        // The VM's storage class does not come into it — a VM found on a
        // different kind of pool keeps its price either way, since billing
        // follows the template and never the disk row.
        let target_disks = db
            .list_host_disks(drift.to_host_id)
            .await
            .unwrap_or_default();
        let disk_id = drift
            .storage
            .as_ref()
            .and_then(|s| target_disks.iter().find(|d| &d.name == s))
            .map(|d| d.id);

        // Correcting `host_id` matters more than `disk_id` and is independently
        // right: every lifecycle operation is aimed at `host_id`, so leaving it
        // stale breaks the VM outright, whereas a stale `disk_id` only misplaces
        // capacity accounting until an admin records the missing pool.
        let disk_id = disk_id.unwrap_or_else(|| {
            warn!(
                "VM {} is on storage {:?} of host {}, which has no matching disk record; \
                 fixing the host but leaving disk {} in place — add the disk to host {}",
                drift.vm_id, drift.storage, drift.to_host_id, vm.disk_id, drift.to_host_id
            );
            vm.disk_id
        });

        if disk_id == vm.disk_id && drift.to_host_id == vm.host_id {
            // The only thing this drift could have fixed was the disk row, and
            // the pool it names is one we have no record of.
            return Ok(false);
        }

        if drift.is_host_move() {
            info!(
                "VM {} found on host {} but recorded on host {}; updating database",
                drift.vm_id, drift.to_host_id, drift.from_host_id
            );
        } else {
            info!(
                "VM {} disk was moved to storage {:?} on host {}; re-pointing disk {} at {}",
                drift.vm_id, drift.storage, drift.to_host_id, vm.disk_id, disk_id
            );
        }
        db.update_vm_host(vm.id, drift.to_host_id, disk_id).await?;

        let logger = VmHistoryLogger::new(db.clone());
        let logged = if drift.is_host_move() {
            logger
                .log_vm_migrated(
                    drift.vm_id,
                    None,
                    drift.from_host_id,
                    drift.to_host_id,
                    true,
                    Some(json!({ "storage": drift.storage })),
                )
                .await
        } else {
            // Not a migration: the VM never left the host, so recording it as
            // one would put a move that never happened in the customer's
            // history. It is a configuration change, which is what it is.
            let mut moved = vm.clone();
            moved.disk_id = disk_id;
            logger
                .log_vm_configuration_changed(
                    drift.vm_id,
                    None,
                    &vm,
                    &moved,
                    Some(json!({ "reason": "disk moved on host", "storage": drift.storage })),
                )
                .await
        };
        if let Err(e) = logged {
            warn!("Failed to log placement fix for VM {}: {}", drift.vm_id, e);
        }
        Ok(true)
    }

    /// Put back a MAC address the database has lost.
    ///
    /// The placeholder `ff:ff:ff:ff:ff:ff` means "never provisioned", and every
    /// check that asks whether a VM exists yet reads it that way. A running VM
    /// carrying the placeholder is therefore not a cosmetic error: it is also
    /// the address the router's static ARP, the firewall and SLAAC address
    /// derivation depend on. The host's `net0` is the truth, so take it back
    /// from there. Only the placeholder is overwritten — a disagreement between
    /// two real addresses is a different problem and is left alone.
    async fn heal_unassigned_macs(&self, observed: &HashMap<u64, Vec<HostVmSpec>>) {
        let db = self.get_db();
        for specs in observed.values() {
            for spec in specs {
                let (Some(vm_id), Some(mac)) = (spec.mapped_vm_id, spec.mac_address.as_ref())
                else {
                    continue;
                };
                if mac.is_empty() || mac.eq_ignore_ascii_case(UNASSIGNED_MAC) {
                    continue;
                }
                let Ok(mut vm) = db.get_vm(vm_id).await else {
                    continue;
                };
                if vm.deleted || !vm.mac_address.eq_ignore_ascii_case(UNASSIGNED_MAC) {
                    continue;
                }
                warn!(
                    "VM {} has no MAC recorded but the host reports {}; restoring it",
                    vm_id, mac
                );
                vm.mac_address = mac.clone();
                if let Err(e) = db.update_vm(&vm).await {
                    warn!("Failed to restore MAC of VM {}: {}", vm_id, e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::{DiskCapacity, GB, LoadFactors};
    use lnvps_db::{CpuArch, DiskType, VmHostKind};

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
    /// Recorded placement helper: host `host_id`, disk row naming `storage`.
    fn placed(host_id: u64, storage: &str) -> VmPlacement {
        VmPlacement {
            host_id,
            disk_name: Some(storage.to_string()),
        }
    }

    #[test]
    fn test_detects_vm_moved_to_another_host() {
        let db = HashMap::from([(1, placed(10, "local-lvm")), (2, placed(10, "local-lvm"))]);
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

    /// Regression for the drift this pass used to miss entirely: a disk moved
    /// between pools on the host the VM already lives on (`qm move-disk`).
    /// Only hosts were compared, so `vm.disk_id` kept naming the pool the disk
    /// had left.
    #[test]
    fn test_detects_disk_moved_to_another_pool_on_the_same_host() {
        let db = HashMap::from([(1, placed(10, "local-lvm")), (2, placed(10, "local-lvm"))]);
        let observed = HashMap::from([(10, vec![spec(1, "nvme-b"), spec(2, "local-lvm")])]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(ambiguous.is_empty());
        assert_eq!(
            drift,
            vec![VmHostDrift {
                vm_id: 1,
                from_host_id: 10,
                to_host_id: 10,
                storage: Some("nvme-b".to_string()),
            }]
        );
        assert!(!drift[0].is_host_move());
    }

    /// A pool the host did not name, or a disk row we could not read, is
    /// missing information rather than a move: reporting it would re-"fix" the
    /// same VM on every pass.
    #[test]
    fn test_unknown_storage_on_either_side_is_not_a_disk_move() {
        let mut unnamed = spec(1, "local-lvm");
        unnamed.disk_storage = None;
        let observed = HashMap::from([(10, vec![unnamed])]);
        let db = HashMap::from([(1, placed(10, "local-lvm"))]);
        assert!(plan_host_drift(&db, &observed).0.is_empty());

        let observed = HashMap::from([(10, vec![spec(1, "nvme-b")])]);
        let db = HashMap::from([(
            1,
            VmPlacement {
                host_id: 10,
                disk_name: None,
            },
        )]);
        assert!(plan_host_drift(&db, &observed).0.is_empty());
    }

    #[test]
    fn test_vm_on_two_hosts_is_ambiguous_not_reconciled() {
        // A leftover copy on the source node after a migration. Choosing either
        // host would flap the database between them on every poll.
        let db = HashMap::from([(1, placed(10, "local-lvm"))]);
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
        let db = HashMap::from([(1, placed(10, "local-lvm")), (2, placed(11, "local-lvm"))]);
        let observed = HashMap::from([(11, vec![spec(2, "local-lvm")])]);

        let (drift, ambiguous) = plan_host_drift(&db, &observed);
        assert!(drift.is_empty(), "{drift:?}");
        assert!(ambiguous.is_empty());
    }

    #[test]
    fn test_host_vms_outside_managed_range_are_ignored() {
        // Proxmox vmid < 100 has no database id; it must never be matched
        // against a VM row.
        let db = HashMap::from([(1, placed(10, "local-lvm"))]);
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

    /// Regression for the check that rebuilt a VM which had merely moved:
    /// locating one must correct its placement, and must only report "nowhere"
    /// when every host answered and none of them had it.
    #[tokio::test]
    async fn test_locate_vm_reconciles_instead_of_reporting_it_missing() {
        let db = Arc::new(MockDb::default());
        add_second_host(&db).await;
        let vm_id = add_vm(&db).await;
        let provisioner = VmProvisioner::new(mock_settings(), db.clone());

        // Recorded on host 1, actually on host 2.
        DummyVmHost::clear_host_vms().await;
        DummyVmHost::set_host_vms_for(1, vec![]).await;
        DummyVmHost::set_host_vms_for(2, vec![spec(vm_id, "mock-disk-2")]).await;

        let vm = db.get_vm(vm_id).await.expect("vm");
        let found = provisioner.locate_vm(&vm).await.expect("locate");
        assert_eq!(found, VmLocation::Host(2));
        // The database follows the host, so the next lifecycle operation is
        // aimed at the node that has the VM.
        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 2);
        assert_eq!(stored.disk_id, 2);

        // Gone from every host: the only case in which rebuilding it is right.
        DummyVmHost::set_host_vms_for(1, vec![]).await;
        DummyVmHost::set_host_vms_for(2, vec![]).await;
        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(
            provisioner.locate_vm(&stored).await.expect("locate"),
            VmLocation::Nowhere
        );

        // On two hosts at once (a leftover copy after a migration): never a
        // rebuild, and never a placement rewrite.
        DummyVmHost::set_host_vms_for(1, vec![spec(vm_id, "mock-disk")]).await;
        DummyVmHost::set_host_vms_for(2, vec![spec(vm_id, "mock-disk-2")]).await;
        assert!(matches!(
            provisioner.locate_vm(&stored).await.expect("locate"),
            VmLocation::Ambiguous(_)
        ));
        DummyVmHost::clear_host_vms().await;
    }

    /// The disk row is matched on the reported pool name alone, whatever its
    /// storage class: a VM found on an SSD pool it was not sold is re-pointed at
    /// that pool, and keeps its price, which comes from its template.
    #[tokio::test]
    async fn test_reconcile_maps_the_reported_pool_regardless_of_its_class() {
        let db = Arc::new(MockDb::default());
        add_second_host(&db).await;
        let vm_id = add_vm(&db).await;

        // The VM was provisioned on an SSD pool and is now on an HDD one.
        assert_eq!(db.get_host_disk(1).await.expect("disk").kind, DiskType::SSD);
        {
            let mut disks = db.host_disks.lock().await;
            disks.get_mut(&2).expect("disk 2").kind = DiskType::HDD;
        }
        let template_id = db.get_vm(vm_id).await.expect("vm").template_id;

        DummyVmHost::clear_host_vms().await;
        DummyVmHost::set_host_vms_for(1, vec![]).await;
        DummyVmHost::set_host_vms_for(2, vec![spec(vm_id, "mock-disk-2")]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        provisioner.reconcile_vm_hosts().await.expect("reconcile");

        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 2);
        assert_eq!(stored.disk_id, 2);
        // Price follows the template, so the plan the customer pays for is
        // untouched by the class of pool they were found on.
        assert_eq!(stored.template_id, template_id);
        DummyVmHost::clear_host_vms().await;
    }

    /// A pool we have no record of is never substituted for another one: the
    /// host is corrected (every lifecycle operation depends on it) and the disk
    /// mapping is left alone rather than guessed at, since a wrong disk row
    /// charges the space to a pool that does not hold it and aims the next
    /// reinstall's import at a name that may not exist on the node.
    #[tokio::test]
    async fn test_reconcile_never_guesses_an_unrecognised_pool() {
        let db = Arc::new(MockDb::default());
        add_second_host(&db).await;
        let vm_id = add_vm(&db).await;
        let original_disk = db.get_vm(vm_id).await.expect("vm").disk_id;

        DummyVmHost::clear_host_vms().await;
        DummyVmHost::set_host_vms_for(1, vec![]).await;
        // Host 2 reports a pool nobody recorded against it.
        DummyVmHost::set_host_vms_for(2, vec![spec(vm_id, "pool-nobody-recorded")]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        let drifts = provisioner.reconcile_vm_hosts().await.expect("reconcile");
        assert_eq!(drifts.len(), 1);

        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 2, "the host must still be corrected");
        assert_eq!(
            stored.disk_id, original_disk,
            "an unknown pool must not be swapped for an arbitrary disk row"
        );
        DummyVmHost::clear_host_vms().await;
    }

    /// Regression for a VM whose disk was moved between pools *on the host it
    /// already lived on*: nothing about its placement changed except the pool,
    /// so the host-only comparison saw no drift and `vm.disk_id` kept charging
    /// the space to a pool that no longer held the disk.
    #[tokio::test]
    async fn test_reconcile_follows_a_disk_moved_between_pools_on_one_host() {
        let db = Arc::new(MockDb::default());
        // A second pool on the same host, which is where the disk was moved to.
        db.host_disks.lock().await.insert(
            3,
            VmHostDisk {
                id: 3,
                host_id: 1,
                name: "mock-disk-1b".to_string(),
                size: 10_000 * GB,
                enabled: true,
                ..Default::default()
            },
        );
        let vm_id = add_vm(&db).await;
        assert_eq!(db.get_vm(vm_id).await.expect("vm").disk_id, 1);

        DummyVmHost::clear_host_vms().await;
        DummyVmHost::set_host_vms_for(1, vec![spec(vm_id, "mock-disk-1b")]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        let drifts = provisioner.reconcile_vm_hosts().await.expect("reconcile");
        assert_eq!(drifts.len(), 1);
        assert!(!drifts[0].is_host_move(), "the VM never left host 1");

        let stored = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(stored.host_id, 1);
        assert_eq!(stored.disk_id, 3);

        // A disk move is not a migration, so it must not be written into the
        // VM's history as one.
        let history = db.list_vm_history(vm_id).await.expect("history");
        assert!(
            !history
                .iter()
                .any(|h| matches!(h.action_type, lnvps_db::VmHistoryActionType::Migrated))
        );
        assert!(history.iter().any(|h| matches!(
            h.action_type,
            lnvps_db::VmHistoryActionType::ConfigurationChanged
        )));

        // Second pass is a no-op now the database agrees with the host.
        assert!(
            provisioner
                .reconcile_vm_hosts()
                .await
                .expect("reconcile")
                .is_empty()
        );
        DummyVmHost::clear_host_vms().await;
    }

    /// A pool nobody recorded against the host cannot be substituted for the
    /// disk row, and on a VM that never moved host there is then nothing to
    /// write — so it must not be reported, or the same alert would be raised on
    /// every pass forever.
    #[tokio::test]
    async fn test_reconcile_ignores_a_disk_move_to_an_unrecorded_pool() {
        let db = Arc::new(MockDb::default());
        let vm_id = add_vm(&db).await;

        DummyVmHost::clear_host_vms().await;
        DummyVmHost::set_host_vms_for(1, vec![spec(vm_id, "pool-nobody-recorded")]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        assert!(
            provisioner
                .reconcile_vm_hosts()
                .await
                .expect("reconcile")
                .is_empty()
        );
        assert_eq!(db.get_vm(vm_id).await.expect("vm").disk_id, 1);
        DummyVmHost::clear_host_vms().await;
    }

    /// Regression: a VM left holding the "never provisioned" placeholder MAC
    /// (a failed re-spawn used to overwrite the real one) has it restored from
    /// the host, which is the only place the truth survives. Without it the VM
    /// keeps a MAC that its static ARP, firewall and SLAAC address do not
    /// match, and every "has this been provisioned?" check answers no.
    #[tokio::test]
    async fn test_reconcile_restores_a_wiped_mac_from_the_host() {
        let db = Arc::new(MockDb::default());
        let vm_id = add_vm(&db).await;

        let mut vm = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(vm.mac_address, "ff:ff:ff:ff:ff:ff");

        DummyVmHost::clear_host_vms().await;
        let mut running = spec(vm_id, "mock-disk");
        running.mac_address = Some("bc:24:11:4e:8f:d1".to_string());
        DummyVmHost::set_host_vms_for(1, vec![running]).await;

        let provisioner = VmProvisioner::new(mock_settings(), db.clone());
        provisioner.reconcile_vm_hosts().await.expect("reconcile");

        vm = db.get_vm(vm_id).await.expect("vm");
        assert_eq!(vm.mac_address, "bc:24:11:4e:8f:d1");

        // A real MAC that disagrees with the host is a different problem and is
        // left alone: the database is authoritative for a provisioned VM.
        let mut other = spec(vm_id, "mock-disk");
        other.mac_address = Some("02:00:00:00:00:99".to_string());
        DummyVmHost::set_host_vms_for(1, vec![other]).await;
        provisioner.reconcile_vm_hosts().await.expect("reconcile");
        assert_eq!(
            db.get_vm(vm_id).await.expect("vm").mac_address,
            "bc:24:11:4e:8f:d1"
        );
        DummyVmHost::clear_host_vms().await;
    }
}
