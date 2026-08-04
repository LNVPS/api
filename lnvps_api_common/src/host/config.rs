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
    /// Storage pool used to cache OS images on the host (default: `default`).
    ///
    /// VM disks are cloned from images in this pool; it may be the same pool
    /// the VM disks live in.
    #[serde(default)]
    pub image_pool: Option<String>,
    /// Local directory used to cache downloaded OS images before they are
    /// uploaded to a host (default: a `lnvps-os-images` dir under the system
    /// temp dir).
    #[serde(default)]
    pub image_cache_dir: Option<PathBuf>,
    /// Declares that [`QemuConfig::bridge`] has VLAN filtering enabled
    /// (`vlan_filtering=1`, e.g. a Proxmox-style VLAN-aware bridge).
    ///
    /// libvirt accepts a `<vlan>` tag on any bridge interface, but a plain
    /// Linux bridge silently ignores it and puts the VM on the untagged
    /// network. VM creation therefore fails when the host has a `vlan_id` and
    /// this is not set, rather than quietly breaking tenant isolation.
    #[serde(default)]
    pub vlan_aware_bridge: bool,
    /// Enable UEFI secure boot for guests.
    ///
    /// Requires an OVMF secure-boot firmware on the host and a signed
    /// bootloader in the guest image, so it defaults to `false` — enabling it
    /// for an unsigned image makes the VM fail to boot.
    #[serde(default)]
    pub secure_boot: bool,
    /// How long a graceful (ACPI) shutdown is given before the VM is powered
    /// off by force. Default 60s.
    ///
    /// Without a forced stop, a guest that ignores ACPI would leave `stop_vm`
    /// reporting success while the VM keeps running.
    #[serde(default)]
    pub shutdown_timeout_secs: Option<u64>,
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
