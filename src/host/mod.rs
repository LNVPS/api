use crate::host::proxmox::ProxmoxClient;
use crate::settings::ProvisionerConfig;
use anyhow::{bail, Result};
use lnvps_db::{async_trait, VmHost, VmHostKind};

pub mod proxmox;

/// Generic type for creating VM's
#[async_trait]
pub trait VmHostClient {

}

pub fn get_host_client(host: &VmHost, cfg: &ProvisionerConfig) -> Result<ProxmoxClient> {
    Ok(match (host.kind.clone(), &cfg) {
        (VmHostKind::Proxmox, ProvisionerConfig::Proxmox { qemu, ssh, .. }) => {
            ProxmoxClient::new(host.ip.parse()?, qemu.clone(), ssh.clone())
                .with_api_token(&host.api_token)
        }
        _ => bail!("Unsupported host type"),
    })
}
