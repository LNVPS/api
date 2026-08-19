//! A VM LNVPS builds on an operator's node to find out whether it works.
//!
//! Everything before this proves a node is *configured*: its tunnel carries
//! packets, its filter loads, its libvirtd answers. None of it proves the
//! machine can carry a customer, and the difference is not academic — an
//! operator can present a perfectly configured node backed by an oversubscribed
//! VPS, a failing disk, or memory that is mostly somebody else's.
//!
//! So LNVPS builds a real VM through the ordinary customer path, logs into it,
//! measures what a customer would actually get, and destroys it.
//!
//! Three properties keep this from becoming its own liability:
//!
//! - **Nothing is stored about the VM.** It exists in this process's memory and
//!   in the node's libvirt. It is destroyed inline on the ordinary paths and by
//!   a `Drop` guard on the ones that never reach them — a panic in the
//!   measurement, or the probe future being dropped by a timeout or a shutdown.
//!   A row pointing at a probe would need a reaper, and a reaper that fails
//!   leaves our VM running on hardware we do not own.
//! - **Its id is outside the range a customer can reach.** Domains are named
//!   from the VM id, so a probe using a plausible id could collide with a
//!   customer's domain on that node — and `delete_vm` would then destroy a
//!   customer's disk. The reserved range makes that arithmetically impossible.
//! - **It is built from the region's real template and a real image**, not a
//!   special probe shape. A probe that is configured differently from a customer
//!   proves something about probes.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use lnvps_api_common::host::config::ProvisionerConfig;
use lnvps_api_common::host::{FullVmInfo, get_host_client};
use lnvps_db::{
    DiskInterface, DiskType, IpRange, LNVpsDb, MarketplaceNode, MarketplaceNodeHealth, UserSshKey,
    Vm, VmHost, VmHostDisk, VmIpAssignment, VmOsImage, VmTemplate,
};

use super::{probe_address, probe_mac};

/// Where probe VM ids start.
///
/// Domains on a node are named from the VM id, and `delete_vm` finds a domain by
/// that name. A probe that used an id a customer's VM could also have would, on
/// the wrong node, delete a customer's disk. This range cannot be reached by an
/// `AUTO_INCREMENT` column that would have to issue 18 quintillion rows first,
/// so the collision is not unlikely — it is impossible.
pub const PROBE_ID_BASE: u64 = 0xFFFF_0000_0000_0000;

/// The id a probe on this node uses. Stable, so a probe left behind by a crashed
/// process is found and removed by the next one rather than accumulating.
pub fn probe_vm_id(node_id: u64) -> u64 {
    PROBE_ID_BASE + node_id
}

/// Whether an id belongs to a probe rather than a customer.
pub fn is_probe(vm_id: u64) -> bool {
    vm_id >= PROBE_ID_BASE
}

/// What a probe found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeResult {
    pub provision_ms: Option<u32>,
    pub memory_mb: Option<u32>,
    pub disk_write_mb: Option<u32>,
    pub disk_read_mb: Option<u32>,
    pub failure: Option<String>,
}

impl ProbeResult {
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }

    /// The row this becomes, with the shape it was measured at.
    pub fn into_health(self, node_id: u64, spec: &ProbeSpec) -> MarketplaceNodeHealth {
        MarketplaceNodeHealth {
            node_id,
            passed: self.passed(),
            failure: self.failure,
            provision_ms: self.provision_ms,
            memory_mb: self.memory_mb,
            disk_write_mb: self.disk_write_mb,
            disk_read_mb: self.disk_read_mb,
            cpu: spec.template.cpu,
            memory_bytes: spec.template.memory,
            disk_bytes: spec.template.disk_size,
            image: spec.image.url.clone(),
            ..Default::default()
        }
    }
}

/// Everything needed to build one probe VM, held in memory only.
pub struct ProbeSpec {
    pub node_id: u64,
    pub host: VmHost,
    pub template: VmTemplate,
    pub image: VmOsImage,
    pub address: String,
    pub gateway: String,
    /// The block the probe is addressed from: its own host prefix.
    ///
    /// Deliberately *not* the pool's block. A guest whose prefix covers the
    /// pool treats every address in it as on-link — including the route
    /// server's — and resolves them on the bridge instead of sending them to
    /// its gateway. Nothing on that bridge answers for a machine up a tunnel,
    /// so replies are never sent and a working node looks dead. A host prefix
    /// plus an on-link gateway sends everything to the node, which is the only
    /// thing on that link that can route.
    pub range_cidr: String,
    /// The public half of a keypair generated for this probe and thrown away
    /// after it. A long-lived key that opened a shell on every operator's
    /// hardware would be the most valuable secret LNVPS holds.
    pub ssh_public_key: String,
}

impl ProbeSpec {
    /// Choose what to probe a node with.
    ///
    /// The region's cheapest sellable template and an enabled image, so the
    /// probe exercises the artefacts customers are actually sold. A dedicated
    /// probe template would be one more thing to keep in step, and a node could
    /// pass on it while failing on everything a customer can buy.
    pub async fn build(
        db: &Arc<dyn LNVpsDb>,
        node: &MarketplaceNode,
        ssh_public_key: String,
    ) -> Result<Self> {
        let host = db
            .get_marketplace_node_host(node.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Node {} has no host to probe", node.id))?;

        let tunnel = super::get_node_tunnel(db, node)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Node {} has no tunnel", node.id))?;
        let address = probe_address(&tunnel.tunnel)
            .ok_or_else(|| anyhow::anyhow!("Node {} has no IPv6 address to probe on", node.id))?;
        // The node's own probe gateway, which it answers for on the bridge —
        // not the route server's address, which the node also holds and would
        // therefore swallow every reply to.
        let gateway = super::probe_gateway(&tunnel.tunnel)
            .and_then(|g| g.split('/').next().map(str::to_string))
            .ok_or_else(|| anyhow::anyhow!("Node {} has no IPv6 gateway", node.id))?;
        // Its own address as the range, so the guest's prefix covers nothing
        // but itself.
        let range_cidr = address.clone();

        let mut templates: Vec<VmTemplate> = db
            .list_vm_templates()
            .await?
            .into_iter()
            .filter(|t| t.enabled && t.region_id == host.region_id)
            .collect();
        // Cheapest by resources rather than by price: a probe is a cost we bear,
        // and the smallest shape still proves the machine can build, boot and
        // serve a guest.
        templates.sort_by_key(|t| (t.memory, t.disk_size, t.cpu));
        let Some(template) = templates.into_iter().next() else {
            bail!("Region {} has no template to probe with", host.region_id);
        };

        let image = db
            .list_os_image()
            .await?
            .into_iter()
            .filter(|i| i.enabled && i.cpu_arch == template.cpu_arch)
            .max_by_key(|i| i.release_date)
            .ok_or_else(|| anyhow::anyhow!("No enabled OS image to probe with"))?;

        Ok(Self {
            node_id: node.id,
            host,
            template,
            image,
            address,
            gateway,
            range_cidr,
            ssh_public_key,
        })
    }

    /// The bare address a probe is reached on.
    pub fn ip(&self) -> &str {
        self.address.split('/').next().unwrap_or(&self.address)
    }

    /// The synthetic rows the hypervisor client needs.
    ///
    /// Assembled rather than loaded, because none of this is in the database and
    /// deliberately so. The ids are the reserved probe id throughout: nothing
    /// reads them back, and a plausible-looking customer id here is the one
    /// mistake that could destroy a customer's disk.
    pub fn vm_info(&self) -> FullVmInfo {
        let vm_id = probe_vm_id(self.node_id);
        FullVmInfo {
            vm: Vm {
                id: vm_id,
                host_id: self.host.id,
                image_id: self.image.id,
                template_id: Some(self.template.id),
                disk_id: 0,
                mac_address: probe_mac(self.node_id),
                ..Default::default()
            },
            host: self.host.clone(),
            disk: VmHostDisk {
                id: 0,
                host_id: self.host.id,
                // The pool the node's libvirt was configured with. A probe that
                // wrote somewhere else would measure a disk no customer gets.
                name: "default".to_string(),
                size: self.template.disk_size,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
            template: Some(self.template.clone()),
            custom_template: None,
            image: self.image.clone(),
            ips: vec![VmIpAssignment {
                id: vm_id,
                vm_id,
                ip_range_id: 0,
                // Bare, as the database stores it. A prefix here is silently
                // dropped by the cloud-init renderer, which parses an address:
                // the guest then boots with no address at all, and the node
                // looks broken.
                ip: self.ip().to_string(),
                ..Default::default()
            }],
            ranges: vec![IpRange {
                id: 0,
                cidr: self.range_cidr.clone(),
                gateway: self.gateway.clone(),
                enabled: true,
                region_id: self.host.region_id,
                ..Default::default()
            }],
            ssh_key: UserSshKey {
                id: 0,
                name: "probe".to_string(),
                key_data: self.ssh_public_key.clone().into(),
                ..Default::default()
            },
            // No rules: the node's own filter is what isolates a guest, and a
            // probe that installed extra rules would be measuring a machine
            // configured unlike the one customers get.
            firewall_rules: vec![],
        }
    }
}

/// Destroys the probe VM if the normal path did not get to.
///
/// The normal path deletes inline, because a delete that fails has to be
/// reported on the result rather than logged and forgotten. This is the
/// backstop for the paths that never reach it: a panic in the measurement, and
/// — more likely on a probe that runs for minutes — the whole future being
/// dropped by a `tokio::time::timeout`, a task abort or a shutdown. Without it
/// those leave an LNVPS VM running on hardware LNVPS does not own, which is the
/// one outcome this module exists to prevent.
///
/// `Drop` cannot await, so the delete is spawned. A spawn can itself be lost if
/// the runtime is shutting down; that is strictly better than not trying, and
/// the stale-probe delete at the start of the next probe on this node is the
/// final catch.
struct ProbeVmGuard {
    client: Arc<dyn lnvps_api_common::host::VmHostClient>,
    vm: Vm,
    node_id: u64,
    armed: bool,
}

impl ProbeVmGuard {
    /// Stop the guard from deleting: the inline delete already ran, and its
    /// outcome is on the result.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProbeVmGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = self.client.clone();
        let vm = self.vm.clone();
        let node_id = self.node_id;
        let vm_id = vm.id;
        // `tokio::spawn` needs a runtime; a drop outside one (a synchronous
        // test, a runtime already gone) must not panic in a destructor.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            log::error!(
                "Probe VM {vm_id} on marketplace node {node_id} could not be destroyed: \
                 no runtime to do it on"
            );
            return;
        };
        handle.spawn(async move {
            if let Err(e) = client.delete_vm(&vm).await {
                // Logged rather than returned: by definition nothing is waiting
                // for this result. A node accumulating probe VMs is visible
                // here and in the next probe's own cleanup.
                log::error!(
                    "Probe VM {vm_id} on marketplace node {node_id} could not be destroyed \
                     after an interrupted probe: {e}"
                );
            }
        });
    }
}

/// Build a probe VM, hand it to `measure`, and destroy it whatever happens.
///
/// The VM is deleted on every path out of this function. The normal paths —
/// including a measurement that returns an error — delete inline, so a failed
/// delete is reported on the result. A panic in the measurement, or this future
/// being dropped before it finishes, is caught by [`ProbeVmGuard`] instead. A
/// probe that leaked its VM would leave LNVPS squatting on an operator's
/// machine, which is exactly the behaviour that would get the marketplace a
/// reputation it could not recover from.
pub async fn with_probe_vm<F, Fut>(
    db: &Arc<dyn LNVpsDb>,
    cfg: &ProvisionerConfig,
    spec: &ProbeSpec,
    measure: F,
) -> ProbeResult
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<ProbeResult>>,
{
    let _ = db;
    let client = match get_host_client(&spec.host, cfg) {
        Ok(c) => c,
        Err(e) => return ProbeResult::failed(format!("cannot reach the node: {e}")),
    };
    let info = spec.vm_info();
    let vm = info.vm.clone();

    // Removed first as well as last: a probe left by a process that was killed
    // holds the address this one needs, and a stale domain would make every
    // later probe on that node fail for a reason that has nothing to do with
    // the machine.
    let _ = client.delete_vm(&vm).await;

    // Armed before the VM exists: `create_vm` can fail having already built the
    // domain, and a delete of a VM that was never created is a no-op anyway.
    let mut guard = ProbeVmGuard {
        client: client.clone(),
        vm: vm.clone(),
        node_id: spec.node_id,
        armed: true,
    };

    let started = std::time::Instant::now();
    let mut result = match client.create_vm(&info).await {
        Ok(()) => match measure().await {
            Ok(mut r) => {
                r.provision_ms
                    .get_or_insert(started.elapsed().as_millis() as u32);
                r
            }
            Err(e) => ProbeResult::failed(e.to_string()),
        },
        Err(e) => ProbeResult::failed(format!("the node could not build the VM: {e}")),
    };

    let deleted = client.delete_vm(&vm).await;
    // Only now: until the inline delete has actually run, the guard is the only
    // thing that would clean up.
    guard.disarm();
    if let Err(e) = deleted {
        // Reported on the result rather than logged and forgotten: a node whose
        // probes cannot be cleaned up is one LNVPS is accumulating VMs on, and
        // that has to be visible in the series rather than in a log nobody
        // reads.
        result
            .failure
            .get_or_insert(format!("the probe VM could not be destroyed: {e}"));
    }
    result
}

impl ProbeResult {
    pub(super) fn failed(why: String) -> Self {
        Self {
            failure: Some(why),
            ..Default::default()
        }
    }
}

/// Record what a probe found.
pub async fn record(
    db: &Arc<dyn LNVpsDb>,
    node_id: u64,
    spec: &ProbeSpec,
    result: ProbeResult,
) -> Result<()> {
    db.insert_marketplace_node_health(&result.into_health(node_id, spec))
        .await
        .context("recording the probe result")?;
    Ok(())
}

/// Record a probe that never got as far as having a shape.
///
/// A node with no tunnel, no address, or a region with no template cannot be
/// specified, so there is nothing to denormalise into the shape columns — they
/// stay zero, which is honest: nothing was measured, and `passed` is false.
/// Written down anyway, because the alternative was writing nothing, and a node
/// with no rows is indistinguishable from a node nobody probed. It is also what
/// starts the cooldown that stops this node monopolising every sweep.
pub async fn record_unspecified(
    db: &Arc<dyn LNVpsDb>,
    node_id: u64,
    result: ProbeResult,
) -> Result<()> {
    db.insert_marketplace_node_health(&MarketplaceNodeHealth {
        node_id,
        passed: result.passed(),
        failure: result.failure,
        ..Default::default()
    })
    .await
    .context("recording an unspecifiable probe")?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// How long a node is left alone after a probe.
///
/// A probe costs the operator real resources — a disk clone, a boot, a few
/// hundred megabytes of I/O — on hardware they are not yet being paid much for.
/// Probing a node every few minutes would be indistinguishable from abusing it.
pub const PROBE_COOLDOWN: chrono::Duration = chrono::Duration::hours(6);

/// Nodes that are due a probe, oldest measurement first.
///
/// A node that has never been probed comes before one that was probed a week
/// ago: the first is a node LNVPS knows nothing about and may already be placing
/// customers on.
pub async fn probe_candidates(
    db: &Arc<dyn LNVpsDb>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<MarketplaceNode>> {
    let mut due = Vec::new();
    for node in db
        .list_all_marketplace_nodes(Some(lnvps_db::MarketplaceNodeStatus::Approved))
        .await?
    {
        // A node with no host has nothing to build a VM on, and a node with no
        // tunnel has nowhere to reach it. Both are states an approved node
        // passes through, and neither is a failure worth recording.
        if db.get_marketplace_node_host(node.id).await?.is_none() {
            continue;
        }

        let last = db
            .list_marketplace_node_health(node.id, 1, 0)
            .await?
            .0
            .into_iter()
            .next();
        match last {
            Some(h) if now - h.created < PROBE_COOLDOWN => continue,
            Some(h) => due.push((Some(h.created), node)),
            None => due.push((None, node)),
        }
    }

    // Never probed first, then longest since.
    due.sort_by_key(|(created, _)| *created);
    Ok(due.into_iter().map(|(_, node)| node).collect())
}
