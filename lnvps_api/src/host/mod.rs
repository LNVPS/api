use crate::settings::ProvisionerConfig;
use anyhow::{Result, bail};
use async_trait::async_trait;
use futures::future::join_all;
use lnvps_api_common::VmRunningState;
use lnvps_api_common::retry::OpResult;
use lnvps_db::{
    IpRange, LNVpsDb, UserSshKey, Vm, VmCustomTemplate, VmHost, VmHostDisk, VmHostKind,
    VmIpAssignment, VmOsImage, VmTemplate,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(feature = "libvirt")]
mod libvirt;
#[cfg(feature = "proxmox")]
mod proxmox;

pub struct TerminalStream {
    pub rx: Receiver<Vec<u8>>,
    pub tx: Sender<Vec<u8>>,
}

/// Generic type for creating VM's
#[async_trait]
pub trait VmHostClient: Send + Sync {
    async fn get_info(&self) -> OpResult<VmHostInfo>;

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

pub fn get_host_client(host: &VmHost, cfg: &ProvisionerConfig) -> Result<Arc<dyn VmHostClient>> {
    #[cfg(test)]
    return Ok(Arc::new(crate::mocks::MockVmHost::new()));

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
            Arc::new(libvirt::LibVirtHost::new(&host.ip, cfg.qemu)?)
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
}

impl FullVmInfo {
    pub async fn load(vm_id: u64, db: Arc<dyn LNVpsDb>) -> Result<Self> {
        let vm = db.get_vm(vm_id).await?;
        let host = db.get_host(vm.host_id).await?;
        let image = db.get_os_image(vm.image_id).await?;
        let disk = db.get_host_disk(vm.disk_id).await?;
        let ssh_key = db.get_user_ssh_key(vm.ssh_key_id).await?;
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
}

#[derive(Clone)]
pub struct VmResources {
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
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
        DiskInterface, DiskType, IpRange, IpRangeAllocationMode, OsDistribution, UserSshKey, Vm,
        VmHost, VmHostDisk, VmIpAssignment, VmOsImage, VmTemplate,
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
        };
        FullVmInfo {
            vm: Vm {
                id: 1,
                host_id: 1,
                user_id: 1,
                image_id: 1,
                template_id: Some(template.id),
                custom_template_id: None,
                ssh_key_id: 1,
                created: Default::default(),
                expires: Default::default(),
                disk_id: 1,
                mac_address: "ff:ff:ff:ff:ff:fe".to_string(),
                deleted: false,
                ref_code: None,
                auto_renewal_enabled: false,
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
                ssh_user: None,
                ssh_key: None,
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
                default_username: None,
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
        }
    }
}
