use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

use lnvps_db::{
    IpRange, LNVpsDb, UserSshKey, Vm, VmCustomTemplate, VmFirewallRule, VmHost, VmHostDisk,
    VmHostKind, VmIpAssignment, VmOsImage, VmTemplate,
};

use crate::HostVmSpec;
use crate::VmRunningState;
use crate::host::config::ProvisionerConfig;
use crate::retry::OpResult;

pub mod cloud_init;
pub mod config;
#[cfg(feature = "libvirt")]
mod libvirt;
pub mod marketplace_pki;
#[cfg(feature = "proxmox")]
mod proxmox;
#[cfg(feature = "proxmox")]
pub mod proxmox_config;

pub mod dummy_host;

/// A request to move a VM from the host this client talks to onto another host.
///
/// Expressed in host-native terms (a Proxmox node name, a storage pool name)
/// because the target host record means nothing to the hypervisor; the caller
/// resolves the database host/disk into these fields.
#[derive(Debug, Clone)]
pub struct MigrateVmRequest {
    /// Host-native name of the destination (Proxmox node name).
    pub target_node: String,
    /// Attempt a live (online) migration instead of stopping the VM first.
    pub online: bool,
    /// Destination storage pool, when the disk has to land somewhere new.
    ///
    /// `None` means a pool of the same name exists on the destination, and
    /// leaves the copy decision to the host client: only the hypervisor knows
    /// whether that pool is shared (nothing to copy) or node-local (the disk
    /// must travel, under the same name).
    pub target_storage: Option<String>,
}

pub struct TerminalStream {
    pub rx: Receiver<Vec<u8>>,
    pub tx: Sender<Vec<u8>>,
}

/// Extract hostname/IP from a URL or return the input if it's already a plain host
/// e.g. "https://192.168.1.1:8006/" -> "192.168.1.1"
///      "192.168.1.1" -> "192.168.1.1"
pub fn extract_host_from_url(input: &str) -> String {
    // Strip protocol prefix if present
    let without_protocol = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .unwrap_or(input);

    // Take everything before the first ':' or '/' (to strip port and path)
    without_protocol
        .split(|c| c == ':' || c == '/')
        .next()
        .unwrap_or(input)
        .to_string()
}

/// Generic type for creating VM's
#[async_trait]
pub trait VmHostClient: Send + Sync {
    async fn get_info(&self) -> OpResult<VmHostInfo>;

    /// List all VMs present on the host, described in host-native terms.
    ///
    /// Used for discovering/importing VMs that exist on the host but aren't
    /// tracked in the database. Defaults to unsupported for hosts that don't
    /// implement discovery.
    async fn list_host_vms(&self) -> OpResult<Vec<HostVmSpec>> {
        use crate::retry::OpError;
        Err(OpError::Fatal(anyhow!(
            "VM discovery is not supported on this host type"
        )))
    }

    /// Move a VM from this host to another host of the same kind.
    ///
    /// The VM keeps its id, MAC and IP assignments — only its placement
    /// changes. Implementations must leave the VM on the source host when the
    /// migration fails, so the caller can keep the database pointing at a host
    /// that actually has the VM.
    async fn migrate_vm(&self, _vm: &Vm, _req: &MigrateVmRequest) -> OpResult<()> {
        use crate::retry::OpError;
        Err(OpError::Fatal(anyhow!(
            "VM migration is not supported on this host type"
        )))
    }

    /// Download OS image to the host
    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()>;

    /// Create a random MAC address for the NIC
    async fn generate_mac(&self, vm: &Vm) -> OpResult<String>;

    /// Start a VM
    async fn start_vm(&self, vm: &Vm) -> OpResult<()>;

    /// Stop a VM
    async fn stop_vm(&self, vm: &Vm) -> OpResult<()>;

    /// Reset VM (Hard)
    async fn reset_vm(&self, vm: &Vm) -> OpResult<()>;

    /// Spawn a VM
    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()>;

    /// Delete a VM
    async fn delete_vm(&self, vm: &Vm) -> OpResult<()>;

    /// Unlink/delete the primary disk of a VM
    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()>;

    /// Remove any orphaned/unused disks left attached to a VM.
    ///
    /// This must never touch the live primary disk — it only sweeps up disks
    /// that are detached from the running config (e.g. Proxmox `unused[n]`
    /// entries accumulated by repeated reinstalls). Defaults to a no-op for
    /// hosts that don't support the concept.
    async fn delete_unused_disks(&self, _vm: &Vm) -> OpResult<()> {
        Ok(())
    }

    /// Import a fresh disk from the OS template
    async fn import_template_disk(&self, cfg: &FullVmInfo) -> OpResult<()>;

    /// Resize the primary disk of a VM
    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()>;

    /// Get the running status of a VM
    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState>;

    /// Get the running status of all VMs on this host
    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>>;

    /// Apply vm configuration (patch)
    async fn configure_vm(&self, cfg: &FullVmInfo) -> OpResult<()>;

    /// Re-apply the VM configuration **only if** the config on the host has
    /// drifted from the config we expect from the database.
    ///
    /// Returns the list of drifted field names (empty when nothing changed).
    /// Defaults to a no-op for hosts that cannot read back their config.
    async fn patch_config(&self, _cfg: &FullVmInfo) -> OpResult<Vec<String>> {
        Ok(vec![])
    }

    /// Update VM firewall configuration and IPsets
    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()>;

    /// Get resource usage data
    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>>;

    /// Connect to terminal serial port
    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream>;
}

pub async fn get_vm_host_client(
    db: &Arc<dyn LNVpsDb>,
    vm_id: u64,
    cfg: &ProvisionerConfig,
) -> Result<Arc<dyn VmHostClient>> {
    let vm = db.get_vm(vm_id).await?;
    let host = db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, cfg)?;
    Ok(client)
}

pub fn get_host_client(
    host: &VmHost,
    // Only read by the hypervisor-specific arms below, so it is unused when the
    // crate is built with neither `proxmox` nor `libvirt` enabled.
    #[cfg_attr(
        not(any(feature = "proxmox", feature = "libvirt")),
        allow(unused_variables)
    )]
    cfg: &ProvisionerConfig,
) -> Result<Arc<dyn VmHostClient>> {
    Ok(match host.kind.clone() {
        #[cfg(feature = "proxmox")]
        VmHostKind::Proxmox if cfg.proxmox.is_some() => {
            let cfg = cfg.proxmox.clone().unwrap();
            Arc::new(proxmox::ProxmoxClient::new(
                host.ip.parse()?,
                &host.name,
                host.api_token.as_str(),
                cfg.mac_prefix,
                cfg.qemu,
                cfg.ssh,
            ))
        }
        #[cfg(feature = "libvirt")]
        VmHostKind::LibVirt if cfg.libvirt.is_some() => {
            let cfg = cfg.libvirt.clone().unwrap();
            Arc::new(libvirt::LibVirtHost::new(&host.ip, cfg)?)
        }
        // A marketplace node is just another libvirt host: same client, same
        // flows, reached over the tunnel instead of the LAN. What differs is
        // trust — each node is verified against the certificate it registered,
        // so nothing else answering on its tunnel address can report that a
        // customer's VM is fine.
        #[cfg(feature = "libvirt")]
        VmHostKind::MarketplaceNode if cfg.libvirt.is_some() && cfg.marketplace.is_some() => {
            let libvirt = cfg.libvirt.clone().unwrap();
            let marketplace = cfg.marketplace.clone().unwrap();
            let node_id = host
                .marketplace_node_id
                .ok_or_else(|| anyhow::anyhow!("Host {} is not backed by a node", host.id))?;
            let pki = marketplace_pki::node_pki_path(&marketplace, node_id);
            // Written when the node presents its certificate. Absent means it
            // never has, and connecting without it would mean not checking
            // which machine answered.
            if !pki.join("cacert.pem").exists() {
                bail!(
                    "Node {node_id} has not registered a libvirt certificate; \
                     it cannot be verified and will not be dialled"
                );
            }
            let uri = marketplace_pki::connection_uri(&host.ip, &pki);
            Arc::new(libvirt::LibVirtHost::new(&uri, libvirt)?)
        }
        VmHostKind::Dummy => {
            if cfg!(test) {
                Arc::new(dummy_host::DummyVmHost::new().with_host_id(host.id))
            } else {
                Arc::new(dummy_host::DummyVmHost::new_persistent().with_host_id(host.id))
            }
        }
        _ => bail!("Unknown host config: {}", host.kind),
    })
}

/// All VM info necessary to provision a VM and its associated resources
pub struct FullVmInfo {
    /// Instance to create
    pub vm: Vm,
    /// Host where the VM will be spawned
    pub host: VmHost,
    /// Disk where this VM will be saved on the host
    pub disk: VmHostDisk,
    /// VM template resources
    pub template: Option<VmTemplate>,
    /// VM custom template resources
    pub custom_template: Option<VmCustomTemplate>,
    /// The OS image used to create the VM
    pub image: VmOsImage,
    /// List of IP resources assigned to this VM
    pub ips: Vec<VmIpAssignment>,
    /// Ranges associated with [ips]
    pub ranges: Vec<IpRange>,
    /// SSH key to access the VM
    pub ssh_key: UserSshKey,
    /// User-configured firewall rules for this VM (ordered by priority)
    pub firewall_rules: Vec<VmFirewallRule>,
}

impl FullVmInfo {
    pub async fn load(vm_id: u64, db: Arc<dyn LNVpsDb>) -> Result<Self> {
        let vm = db.get_vm(vm_id).await?;
        let host = db.get_host(vm.host_id).await?;
        let image = db.get_os_image(vm.image_id).await?;
        let disk = db.get_host_disk(vm.disk_id).await?;
        let ssh_key_id = vm
            .ssh_key_id
            .ok_or_else(|| anyhow!("VM {} has no SSH key assigned", vm_id))?;
        let ssh_key = db.get_user_ssh_key(ssh_key_id).await?;
        let ips = db.list_vm_ip_assignments(vm_id).await?;

        let ip_range_ids: HashSet<u64> = ips.iter().map(|i| i.ip_range_id).collect();
        let ip_ranges: Vec<_> = ip_range_ids.iter().map(|i| db.get_ip_range(*i)).collect();
        let ranges: Vec<IpRange> = join_all(ip_ranges)
            .await
            .into_iter()
            .filter_map(Result::ok)
            .collect();

        let template = if let Some(t) = vm.template_id {
            Some(db.get_vm_template(t).await?)
        } else {
            None
        };
        let custom_template = if let Some(t) = vm.custom_template_id {
            Some(db.get_custom_vm_template(t).await?)
        } else {
            None
        };
        let firewall_rules = db.list_vm_firewall_rules(vm_id).await?;
        // create VM
        Ok(FullVmInfo {
            vm,
            host,
            template,
            custom_template,
            image,
            ips,
            disk,
            ranges,
            ssh_key,
            firewall_rules,
        })
    }

    /// CPU cores
    pub fn resources(&self) -> Result<VmResources> {
        if let Some(t) = &self.template {
            Ok(VmResources {
                cpu: t.cpu,
                memory: t.memory,
                disk_size: t.disk_size,
            })
        } else if let Some(t) = &self.custom_template {
            Ok(VmResources {
                cpu: t.cpu,
                memory: t.memory,
                disk_size: t.disk_size,
            })
        } else {
            bail!("Invalid VM config, no template");
        }
    }

    /// IPv4 and IPv6 address counts this VM's offer specifies.
    ///
    /// A VM with neither template falls back to one IPv4, which is what every
    /// offer implied before counts existed.
    pub fn ip_counts(&self) -> (u16, u16) {
        if let Some(t) = &self.template {
            (t.ip4_count, t.ip6_count)
        } else if let Some(t) = &self.custom_template {
            (t.ip4_count, t.ip6_count)
        } else {
            (1, 1)
        }
    }

    pub async fn vm_resources(vm_id: u64, db: Arc<dyn LNVpsDb>) -> Result<VmResources> {
        let vm = db.get_vm(vm_id).await?;
        if let Some(t) = vm.template_id {
            let template = db.get_vm_template(t).await?;
            Ok(VmResources {
                cpu: template.cpu,
                memory: template.memory,
                disk_size: template.disk_size,
            })
        } else if let Some(t) = vm.custom_template_id {
            let custom = db.get_custom_vm_template(t).await?;
            Ok(VmResources {
                cpu: custom.cpu,
                memory: custom.memory,
                disk_size: custom.disk_size,
            })
        } else {
            bail!("Invalid VM config, no template");
        }
    }

    /// Resource limits for this VM (derived from template or custom template).
    /// Returns `VmLimits::default()` (all `None`) if no limits are configured.
    pub fn limits(&self) -> VmLimits {
        if let Some(t) = &self.template {
            VmLimits {
                disk_iops_read: t.disk_iops_read,
                disk_iops_write: t.disk_iops_write,
                disk_mbps_read: t.disk_mbps_read,
                disk_mbps_write: t.disk_mbps_write,
                network_mbps: t.network_mbps,
                cpu_limit: t.cpu_limit,
            }
        } else if let Some(t) = &self.custom_template {
            VmLimits {
                disk_iops_read: t.disk_iops_read,
                disk_iops_write: t.disk_iops_write,
                disk_mbps_read: t.disk_mbps_read,
                disk_mbps_write: t.disk_mbps_write,
                network_mbps: t.network_mbps,
                cpu_limit: t.cpu_limit,
            }
        } else {
            VmLimits::default()
        }
    }
}

#[derive(Clone)]
pub struct VmResources {
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
}

/// Optional resource limits for a VM.  `None` fields mean uncapped.
#[derive(Clone, Default)]
pub struct VmLimits {
    /// Maximum disk read IOPS (None = uncapped)
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores (None = uncapped)
    pub cpu_limit: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesData {
    pub timestamp: u64,
    pub cpu: f32,
    pub memory: f32,
    pub memory_size: u64,
    pub net_in: f32,
    pub net_out: f32,
    pub disk_write: f32,
    pub disk_read: f32,
}

#[derive(Debug, Clone)]
pub enum TimeSeries {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone)]
pub struct VmHostInfo {
    pub cpu: u16,
    pub memory: u64,
    pub disks: Vec<VmHostDiskInfo>,
}

#[derive(Debug, Clone)]
pub struct VmHostDiskInfo {
    pub name: String,
    pub size: u64,
    pub used: u64,
}

#[cfg(test)]
mod tests {
    use crate::host::FullVmInfo;
    use crate::{GB, TB};
    use chrono::Utc;
    use lnvps_db::{
        CpuArch, DiskInterface, DiskType, IpRange, IpRangeAllocationMode, OsDistribution,
        UserSshKey, Vm, VmHost, VmHostDisk, VmIpAssignment, VmOsImage, VmTemplate,
    };

    pub fn mock_full_vm() -> FullVmInfo {
        let template = VmTemplate {
            id: 1,
            name: "example".to_string(),
            enabled: true,
            created: Default::default(),
            expires: None,
            cpu: 2,
            cpu_mfg: Default::default(),
            cpu_arch: Default::default(),
            cpu_features: Default::default(),
            memory: 2 * GB,
            disk_size: 100 * GB,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            cost_plan_id: 1,
            region_id: 1,
            ..Default::default()
        };
        FullVmInfo {
            vm: Vm {
                id: 1,
                host_id: 1,
                user_id: 1,
                image_id: 1,
                template_id: Some(template.id),
                custom_template_id: None,
                subscription_line_item_id: 0,
                ssh_key_id: Some(1),
                disk_id: 1,
                mac_address: "ff:ff:ff:ff:ff:fe".to_string(),
                ssh_host_keys: None,
                deleted: false,
                ref_code: None,
                disabled: false,
                fw_policy_in: None,
                fw_policy_out: None,
                admin_notes: None,
            },
            host: VmHost {
                id: 1,
                kind: Default::default(),
                region_id: 1,
                name: "mock".to_string(),
                ip: "https://localhost:8006".to_string(),
                cpu: 20,
                cpu_mfg: Default::default(),
                cpu_arch: Default::default(),
                cpu_features: Default::default(),
                memory: 128 * GB,
                enabled: true,
                api_token: "mock".into(),
                load_cpu: 1.0,
                load_memory: 1.0,
                load_disk: 1.0,
                vlan_id: Some(100),
                mtu: None,
                ssh_user: None,
                ssh_key: None,
                sunset_date: None,
                marketplace_node_id: None,
                deleted: false,
            },
            disk: VmHostDisk {
                id: 1,
                host_id: 1,
                name: "ssd".to_string(),
                size: TB * 20,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
            template: Some(template.clone()),
            custom_template: None,
            image: VmOsImage {
                id: 1,
                distribution: OsDistribution::Ubuntu,
                flavour: "Server".to_string(),
                version: "24.04.03".to_string(),
                enabled: true,
                release_date: Utc::now(),
                url: "http://localhost.com/ubuntu_server_24.04.img".to_string(),
                cpu_arch: CpuArch::X86_64,
                default_username: None,
                sha2: None,
                sha2_url: None,
            },
            ips: vec![
                VmIpAssignment {
                    id: 1,
                    vm_id: 1,
                    ip_range_id: 1,
                    ip: "192.168.1.2".to_string(),
                    deleted: false,
                    arp_ref: None,
                    dns_forward: None,
                    dns_forward_ref: None,
                    dns_reverse: None,
                    dns_reverse_ref: None,
                },
                VmIpAssignment {
                    id: 2,
                    vm_id: 1,
                    ip_range_id: 2,
                    ip: "192.168.2.2".to_string(),
                    deleted: false,
                    arp_ref: None,
                    dns_forward: None,
                    dns_forward_ref: None,
                    dns_reverse: None,
                    dns_reverse_ref: None,
                },
                VmIpAssignment {
                    id: 3,
                    vm_id: 1,
                    ip_range_id: 3,
                    ip: "fd00::ff:ff:ff:ff:ff".to_string(),
                    deleted: false,
                    arp_ref: None,
                    dns_forward: None,
                    dns_forward_ref: None,
                    dns_reverse: None,
                    dns_reverse_ref: None,
                },
            ],
            ranges: vec![
                IpRange {
                    id: 1,
                    cidr: "192.168.1.0/24".to_string(),
                    gateway: "192.168.1.1/16".to_string(),
                    enabled: true,
                    region_id: 1,
                    ..Default::default()
                },
                IpRange {
                    id: 2,
                    cidr: "192.168.2.0/24".to_string(),
                    gateway: "10.10.10.10".to_string(),
                    enabled: true,
                    region_id: 2,
                    ..Default::default()
                },
                IpRange {
                    id: 3,
                    cidr: "fd00::/64".to_string(),
                    gateway: "fd00::1".to_string(),
                    enabled: true,
                    region_id: 1,
                    allocation_mode: IpRangeAllocationMode::SlaacEui64,
                    ..Default::default()
                },
            ],
            ssh_key: UserSshKey {
                id: 1,
                name: "test".to_string(),
                user_id: 1,
                created: Default::default(),
                key_data: "ssh-ed25519 AAA=".into(),
            },
            firewall_rules: vec![],
        }
    }
}

#[cfg(all(test, feature = "libvirt"))]
mod marketplace_client_tests {
    use lnvps_db::{VmHost, VmHostKind};
    use tempfile::TempDir;

    use super::config::{MarketplaceLibvirtConfig, ProvisionerConfig, QemuConfig};
    use super::*;

    fn host(node_id: Option<u64>) -> VmHost {
        VmHost {
            id: 1,
            kind: VmHostKind::MarketplaceNode,
            ip: "10.66.0.2".to_string(),
            marketplace_node_id: node_id,
            ..Default::default()
        }
    }

    fn config(dir: &TempDir) -> ProvisionerConfig {
        for name in ["ca.pem", "client.pem", "client.key"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        ProvisionerConfig {
            proxmox: None,
            libvirt: Some(config::LibVirtConfig {
                qemu: QemuConfig {
                    machine: "q35".to_string(),
                    os_type: "l26".to_string(),
                    bridge: "br-lnvps".to_string(),
                    cpu: "host".to_string(),
                    kvm: true,
                    arch: "x86_64".to_string(),
                    balloon_min_pct: None,
                    firewall_config: None,
                },
                image_pool: None,
                image_cache_dir: None,
                vlan_aware_bridge: false,
                secure_boot: false,
                shutdown_timeout_secs: None,
            }),
            marketplace: Some(MarketplaceLibvirtConfig {
                ca_cert: dir.path().join("ca.pem"),
                client_cert: dir.path().join("client.pem"),
                client_key: dir.path().join("client.key"),
                pki_dir: dir.path().join("pki"),
            }),
        }
    }

    /// A node that never registered a certificate is refused rather than
    /// dialled. Connecting without one would mean not checking which machine
    /// answered — and the machine is the operator's, on an address their own
    /// guests share a namespace with.
    #[test]
    fn an_unverifiable_node_is_not_dialled() {
        let dir = TempDir::new().unwrap();
        let err = get_host_client(&host(Some(9)), &config(&dir))
            .err()
            .expect("an unverifiable node must not produce a client");

        assert!(err.to_string().contains("libvirt certificate"), "{err}");
    }

    /// A marketplace host with no node behind it is a broken row, and is named
    /// as such rather than producing a connection to nowhere.
    #[test]
    fn a_host_with_no_node_is_an_error() {
        let dir = TempDir::new().unwrap();
        let err = get_host_client(&host(None), &config(&dir))
            .err()
            .expect("a host with no node must not produce a client");

        assert!(err.to_string().contains("not backed by a node"), "{err}");
    }

    /// Without a client identity, no VM is placed on a node at all. The
    /// alternative is an unauthenticated hypervisor connection over the tunnel,
    /// which is worse than not having the feature.
    #[test]
    fn no_client_identity_means_no_marketplace_hosts() {
        let dir = TempDir::new().unwrap();
        let mut cfg = config(&dir);
        cfg.marketplace = None;

        assert!(get_host_client(&host(Some(9)), &cfg).is_err());
    }
}
