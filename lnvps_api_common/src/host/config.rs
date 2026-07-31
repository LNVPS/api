//! Hypervisor provisioning configuration.
//!
//! These types are deserialized from the `provisioner` section of the API's
//! `config.yaml` and consumed by [`crate::host::get_host_client`] to build a
//! [`crate::host::VmHostClient`]. They live here rather than in `lnvps_api`'s
//! settings module so that any crate able to construct a host client can also
//! describe one.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProvisionerConfig {
    pub proxmox: Option<ProxmoxConfig>,
    pub libvirt: Option<LibVirtConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProxmoxConfig {
    /// Generic VM configuration
    pub qemu: QemuConfig,
    /// SSH config for issuing commands via CLI
    pub ssh: Option<SshConfig>,
    /// MAC address prefix for NIC (eg. bc:24:11)
    pub mac_prefix: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LibVirtConfig {
    /// Generic VM configuration
    pub qemu: QemuConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SshConfig {
    /// Location of SSH key used to run commands on the host
    pub key: PathBuf,
    /// Username used to run commands on the host, default = root
    pub user: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct QemuConfig {
    /// Machine type (q35)
    pub machine: String,
    /// OS Type
    pub os_type: String,
    /// Network bridge used for the networking interface
    pub bridge: String,
    /// CPU type
    pub cpu: String,
    /// Enable virtualization inside VM
    pub kvm: bool,
    /// CPU architecture
    pub arch: String,
    /// Auto-ballooning floor as a percentage of the VM's sold RAM.
    ///
    /// When set (1..=99), created/reconfigured VMs carry a `balloon` value of
    /// `memory_mb * balloon_min_pct / 100`, guaranteeing the guest at least
    /// that percentage of its RAM while allowing Proxmox auto-ballooning to
    /// reclaim the remainder under host memory pressure (a pressure-relief
    /// valve against host OOM-kills). Unset / `0` / `>= 100` leaves the
    /// `balloon` key out, which disables dynamic ballooning (current default).
    pub balloon_min_pct: Option<u8>,
    /// Firewall configuration options
    pub firewall_config: Option<FirewallConfig>,
}

impl QemuConfig {
    /// Compute the Proxmox `balloon` value (in MB) for a VM with the given
    /// sold memory, honouring [`QemuConfig::balloon_min_pct`].
    ///
    /// Returns `None` (no `balloon` key, i.e. dynamic ballooning disabled)
    /// when the floor is unset, `0`, or `>= 100`.
    pub fn balloon_mb(&self, memory_mb: u64) -> Option<i32> {
        match self.balloon_min_pct {
            Some(pct) if (1..100).contains(&pct) => Some((memory_mb * pct as u64 / 100) as i32),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FirewallPolicy {
    Accept,
    Reject,
    Drop,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirewallConfig {
    /// Enable DHCP
    pub dhcp: Option<bool>,
    /// Enable firewall
    pub enable: Option<bool>,
    /// Enable IP filtering
    pub ip_filter: Option<bool>,
    /// Enable MAC filtering
    pub mac_filter: Option<bool>,
    /// Enable NDP (Neighbor Discovery Protocol)
    pub ndp: Option<bool>,
    /// Input policy (ACCEPT, REJECT, DROP)
    pub policy_in: Option<FirewallPolicy>,
    /// Output policy (ACCEPT, REJECT, DROP)
    pub policy_out: Option<FirewallPolicy>,
}
