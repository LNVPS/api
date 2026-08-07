//! The whole desired state of a marketplace node.
//!
//! The node holds this and makes its machine match: it creates what is missing,
//! matches the run state LNVPS asked for, and destroys what LNVPS no longer
//! lists. That last part is the only tear-down mechanism that survives LNVPS
//! failing — an API that dies mid-provision leaves nothing to clean up, because
//! the half-built VM is simply absent from the next document.
//!
//! Three decisions about the wire format are worth stating, because each of
//! them is a thing the node deliberately does *not* get:
//!
//! - **Node-shaped, not database-shaped.** The node has no business knowing
//!   about users, cost plans or subscriptions, and a format that mirrored the
//!   schema would make every migration a node-compatibility question. What is
//!   sent is what the machine has to build.
//! - **Cloud-init arrives rendered.** LNVPS decides what a guest is configured
//!   with; the node writes the bytes to a disk and attaches it. The alternative
//!   — sending the ingredients and having the node render — puts the decision on
//!   the operator's machine, where a node running an old daemon would configure
//!   a guest differently from the rest of the fleet.
//! - **The image is a URL and a checksum.** The node fetches it itself, over its
//!   own connection, and verifies it. Streaming images through LNVPS would make
//!   provisioning wait on our bandwidth for a file the node can get directly.

use std::sync::Arc;

use anyhow::{Context, Result};
use lnvps_api_common::host::{FullVmInfo, cloud_init};
use lnvps_db::{LNVpsDb, MarketplaceNode, Vm};
use serde::{Deserialize, Serialize};

use super::NodeDataPlane;

/// What a node's machine should look like.
/// Not serialisable itself: the data plane inside it is a provisioner type, and
/// the wire format is stated once, in the API layer, where it can be reviewed
/// as a contract rather than derived from whatever the internals happen to be.
#[derive(Debug, Clone)]
pub struct NodeState {
    /// The network the VMs below sit on. `None` before a tunnel is allocated,
    /// which is a node that cannot carry anything yet — and is told that,
    /// rather than being sent VMs it has nowhere to put.
    pub dataplane: Option<NodeDataPlane>,
    /// Every VM this node should be running, and nothing else. A VM the node
    /// holds that is not in this list is one LNVPS has deleted, moved, or never
    /// finished creating — in all three cases it must go.
    pub vms: Vec<NodeVm>,
}

/// One VM, as the machine that runs it needs to see it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeVm {
    /// LNVPS's id for this VM, which the node uses to name its domain. Stable
    /// across restarts of either side, unlike anything the node could invent.
    pub id: u64,
    /// The guest's hostname, and the name an operator will see in `virsh list`.
    pub name: String,
    pub cpu: u16,
    /// Bytes, not megabytes: the unit that has to be agreed on is the one that
    /// is written down, and "memory: 2048" has been read as both.
    pub memory: u64,
    pub disk_bytes: u64,
    /// Where the guest's disk image comes from, fetched by the node itself.
    pub image: NodeVmImage,
    /// Rendered cloud-init, written to a config drive by the node.
    pub cloud_init: NodeVmCloudInit,
    /// The NIC's MAC. LNVPS assigns it, because it is also the anti-spoof
    /// binding in the node's packet filter and the identity its addresses are
    /// tied to.
    pub mac: String,
    /// Addresses as host prefixes, matching the guest list in the data plane.
    pub addresses: Vec<String>,
    /// Whether LNVPS wants this VM running. Expressed as state rather than as a
    /// start/stop call, because a call is a thing that can be missed and a
    /// state is a thing that can be reconciled.
    pub running: bool,
}

/// Where a guest's disk comes from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeVmImage {
    pub url: String,
    /// SHA-2 of the downloaded file, when LNVPS knows it.
    ///
    /// `None` is not "skip the check": the node caches by URL and LNVPS records
    /// checksums for the images it mirrors, so a missing one means an image
    /// nobody has verified — which the node logs, because an unverified image
    /// is a guest whose contents nobody can account for.
    pub sha2: Option<String>,
    /// The filename the node caches it under, so two VMs from one image do not
    /// download it twice.
    pub filename: String,
}

/// Cloud-init, rendered by LNVPS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeVmCloudInit {
    pub meta_data: String,
    pub user_data: String,
    /// Netplan v2, matching addresses to the NIC by MAC rather than by
    /// interface name — the guest's name for it depends on its distro.
    pub network_config: String,
}

/// Build the desired state for a node.
pub async fn node_state(db: &Arc<dyn LNVpsDb>, node: &MarketplaceNode) -> Result<NodeState> {
    let dataplane = super::node_dataplane(db, node).await?;

    let Some(host) = db.get_marketplace_node_host(node.id).await? else {
        // Approved nodes have a host; one without has nothing to run and is
        // told so, rather than being sent a document it cannot act on.
        return Ok(NodeState {
            dataplane,
            vms: vec![],
        });
    };

    let mut vms = Vec::new();
    for vm in db.list_vms_on_host(host.id).await? {
        // A deleted VM is absent from the document, which is how the node is
        // told to destroy it. There is no "delete" message: the absence *is*
        // the message, and it works even if LNVPS was down when the deletion
        // happened.
        if vm.deleted {
            continue;
        }
        vms.push(node_vm(db, &vm).await?);
    }
    vms.sort_by_key(|v| v.id);
    Ok(NodeState { dataplane, vms })
}

/// One VM's spec, from the same rows the hypervisor clients load.
async fn node_vm(db: &Arc<dyn LNVpsDb>, vm: &Vm) -> Result<NodeVm> {
    let full = FullVmInfo::load(vm.id, db.clone())
        .await
        .with_context(|| format!("VM {} cannot be described to its node", vm.id))?;
    let resources = full.resources()?;

    let network = cloud_init::network_config(&full)?;
    let meta_data = cloud_init::meta_data(&full)?;
    let user_data = cloud_init::user_data(&full)?;

    let addresses = full
        .ips
        .iter()
        .filter(|ip| !ip.deleted)
        .filter_map(|ip| host_prefix(&ip.ip))
        .collect();

    Ok(NodeVm {
        id: vm.id,
        name: cloud_init::hostname(vm.id),
        cpu: resources.cpu,
        memory: resources.memory,
        disk_bytes: resources.disk_size,
        image: NodeVmImage {
            filename: image_filename(&full.image.url),
            url: full.image.url.clone(),
            sha2: full.image.sha2.clone(),
        },
        cloud_init: NodeVmCloudInit {
            meta_data,
            user_data,
            network_config: network.yaml,
        },
        mac: vm.mac_address.clone(),
        addresses,
        // `disabled` is LNVPS's switch — non-payment, abuse, an admin
        // intervention — and it is expressed as "do not run this" rather than
        // as a stop command, because a command can be missed while the machine
        // is down and a state cannot.
        running: !vm.disabled,
    })
}

/// `203.0.113.5` -> `203.0.113.5/32`, and the v6 equivalent.
fn host_prefix(ip: &str) -> Option<String> {
    let bare = ip.split('/').next()?;
    let parsed: std::net::IpAddr = bare.parse().ok()?;
    Some(format!(
        "{bare}/{}",
        if parsed.is_ipv4() { 32 } else { 128 }
    ))
}

/// The name a node caches an image under.
///
/// Taken from the URL rather than invented, so two VMs from one image share a
/// download, and so an operator looking at their own storage pool can tell what
/// a file is.
fn image_filename(url: &str) -> String {
    url.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("os-image")
        .to_string()
}

#[cfg(test)]
mod tests;
