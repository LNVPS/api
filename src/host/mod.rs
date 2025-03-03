use crate::settings::ProvisionerConfig;
use crate::status::VmState;
use anyhow::{bail, Result};
use lnvps_db::{
    async_trait, IpRange, UserSshKey, Vm, VmHost, VmHostDisk, VmHostKind, VmIpAssignment,
    VmOsImage, VmTemplate,
};
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
    async fn create_vm(&self, cfg: &CreateVmRequest) -> Result<()>;

    /// Get the running status of a VM
    async fn get_vm_state(&self, vm: &Vm) -> Result<VmState>;

    /// Apply vm configuration (update)
    async fn configure_vm(&self, vm: &Vm) -> Result<()>;
}

pub fn get_host_client(host: &VmHost, cfg: &ProvisionerConfig) -> Result<Arc<dyn VmHostClient>> {
    #[cfg(test)]
    {
        Ok(Arc::new(crate::mocks::MockVmHost::default()))
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
            ) => Arc::new(
                proxmox::ProxmoxClient::new(
                    host.ip.parse()?,
                    &host.name,
                    mac_prefix.clone(),
                    qemu.clone(),
                    ssh.clone(),
                )
                .with_api_token(&host.api_token),
            ),
            _ => bail!("Unknown host config: {}", host.kind),
        })
    }
}

/// Generic VM create request, host impl decides how VMs are created
/// based on app settings
pub struct CreateVmRequest {
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
