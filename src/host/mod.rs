use crate::settings::ProvisionerConfig;
use crate::status::VmState;
use anyhow::{bail, Result};
use futures::future::join_all;
use lnvps_db::{
    async_trait, IpRange, LNVpsDb, UserSshKey, Vm, VmHost, VmHostDisk, VmHostKind, VmIpAssignment,
    VmOsImage, VmTemplate,
};
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(feature = "libvirt")]
mod libvirt;
#[cfg(feature = "proxmox")]
mod proxmox;

/// Generic type for creating VM's
#[async_trait]
pub trait VmHostClient: Send + Sync {
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

    /// Get the running status of a VM
    async fn get_vm_state(&self, vm: &Vm) -> Result<VmState>;

    /// Apply vm configuration (patch)
    async fn configure_vm(&self, cfg: &FullVmInfo) -> Result<()>;
}

pub fn get_host_client(host: &VmHost, cfg: &ProvisionerConfig) -> Result<Arc<dyn VmHostClient>> {
    #[cfg(test)]
    {
        Ok(Arc::new(crate::mocks::MockVmHost::new()))
    }
    #[cfg(not(test))]
    {
        Ok(match (host.kind.clone(), &cfg) {
            #[cfg(feature = "proxmox")]
            (
                VmHostKind::Proxmox,
                ProvisionerConfig::Proxmox {
                    qemu,
                    ssh,
                    mac_prefix,
                },
            ) => Arc::new(proxmox::ProxmoxClient::new(
                host.ip.parse()?,
                &host.name,
                &host.api_token,
                mac_prefix.clone(),
                qemu.clone(),
                ssh.clone(),
            )),
            _ => bail!("Unknown host config: {}", host.kind),
        })
    }
}

/// All VM info necessary to provision a VM and its associated resources
pub struct FullVmInfo {
    /// Instance to create
    pub vm: Vm,
    /// Disk where this VM will be saved on the host
    pub disk: VmHostDisk,
    /// VM template resources
    pub template: VmTemplate,
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
        let template = db.get_vm_template(vm.template_id).await?;
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

        // create VM
        Ok(FullVmInfo {
            vm,
            template,
            image,
            ips,
            disk,
            ranges,
            ssh_key,
        })
    }
}
