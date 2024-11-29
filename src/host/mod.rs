use crate::host::proxmox::ProxmoxClient;
use anyhow::Result;
use lnvps_db::{VmHost, VmHostKind};

pub mod proxmox;
pub trait VmHostClient {}

pub fn get_host_client(host: &VmHost) -> Result<ProxmoxClient> {
    Ok(match host.kind {
        VmHostKind::Proxmox => ProxmoxClient::new(host.ip.parse()?).with_api_token(&host.api_token),
    })
}
