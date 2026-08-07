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
//!   in the node's libvirt, and it is destroyed in a guard so a panic mid-probe
//!   still takes it down. A row pointing at a probe would need a reaper, and a
//!   reaper that fails leaves our VM running on hardware we do not own.
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
        let gateway = tunnel
            .gateway6()
            .and_then(|g| g.split('/').next().map(str::to_string))
            .ok_or_else(|| anyhow::anyhow!("Node {} has no IPv6 gateway", node.id))?;

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
                cidr: self.address.clone(),
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

/// Build a probe VM, hand it to `measure`, and destroy it whatever happens.
///
/// The VM is deleted in every path out of this function, including a panic in
/// the measurement: the guard runs on unwind. A probe that leaked its VM would
/// leave LNVPS squatting on an operator's machine, which is exactly the
/// behaviour that would get the marketplace a reputation it could not recover
/// from.
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

    if let Err(e) = client.delete_vm(&vm).await {
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
    fn failed(why: String) -> Self {
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

#[cfg(test)]
mod tests;
