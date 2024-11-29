use crate::exchange::ExchangeRateCache;
use crate::provisioner::lnvps::LNVpsProvisioner;
use crate::provisioner::Provisioner;
use fedimint_tonic_lnd::Client;
use lnvps_db::LNVpsDb;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub listen: Option<String>,
    pub db: String,
    pub lnd: LndConfig,
    pub provisioner: ProvisionerConfig,

    /// Number of days after an expired VM is deleted
    pub delete_after: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LndConfig {
    pub url: String,
    pub cert: PathBuf,
    pub macaroon: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ProvisionerConfig {
    Proxmox {
        /// Readonly mode, don't spawn any VM's
        read_only: bool,
        /// Generic VM configuration
        qemu: QemuConfig,
        /// SSH config for issuing commands via CLI
        ssh: Option<SshConfig>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SshConfig {
    /// Location of SSH key used to run commands on the host
    pub key: PathBuf,
    /// Username used to run commands on the host, default = root
    pub user: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QemuConfig {
    /// Machine type (q35)
    pub machine: String,

    /// OS Type
    pub os_type: String,

    /// Network bridge used for the networking interface
    pub bridge: String,

    /// CPU type
    pub cpu: String,

    /// VLAN tag all spawned VM's
    pub vlan: Option<u16>,

    /// Enable virtualization inside VM
    pub kvm: bool,
}

impl ProvisionerConfig {
    pub fn get_provisioner(
        &self,
        db: impl LNVpsDb + 'static,
        lnd: Client,
        exchange: ExchangeRateCache,
    ) -> impl Provisioner + 'static {
        match self {
            ProvisionerConfig::Proxmox {
                qemu,
                ssh,
                read_only,
            } => LNVpsProvisioner::new(*read_only, qemu.clone(), ssh.clone(), db, lnd, exchange),
        }
    }
}
