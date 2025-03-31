use crate::settings::ProvisionerConfig;
use crate::status::VmState;
use anyhow::{bail, Result};
use futures::future::join_all;
use lnvps_db::{
    async_trait, IpRange, LNVpsDb, UserSshKey, Vm, VmCustomTemplate, VmHost, VmHostDisk,
    VmHostKind, VmIpAssignment, VmOsImage, VmTemplate,
};
use schemars::JsonSchema;
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
    async fn get_info(&self) -> Result<VmHostInfo>;

    /// Download OS image to the host
    async fn download_os_image(&self, image: &VmOsImage) -> Result<()>;

    /// Create a random MAC address for the NIC
    async fn generate_mac(&self, vm: &Vm) -> Result<String>;

    /// Start a VM
    async fn start_vm(&self, vm: &Vm) -> Result<()>;

    /// Stop a VM
    async fn stop_vm(&self, vm: &Vm) -> Result<()>;

    /// Reset VM (Hard)
    async fn reset_vm(&self, vm: &Vm) -> Result<()>;

    /// Spawn a VM
    async fn create_vm(&self, cfg: &FullVmInfo) -> Result<()>;

    /// Delete a VM
    async fn delete_vm(&self, vm: &Vm) -> Result<()>;

    /// Re-install a vm OS
    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> Result<()>;

    /// Get the running status of a VM
    async fn get_vm_state(&self, vm: &Vm) -> Result<VmState>;

    /// Apply vm configuration (patch)
    async fn configure_vm(&self, cfg: &FullVmInfo) -> Result<()>;

    /// Get resource usage data
    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> Result<Vec<TimeSeriesData>>;

    /// Connect to terminal serial port
    async fn connect_terminal(&self, vm: &Vm) -> Result<TerminalStream>;
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
                &host.api_token,
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
}

#[derive(Clone)]
pub struct VmResources {
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
