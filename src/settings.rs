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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LndConfig {
    pub url: String,
    pub cert: PathBuf,
    pub macaroon: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ProvisionerConfig {
    Proxmox(QemuConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QemuConfig {
    /// Readonly mode, don't spawn any VM's
    pub read_only: bool,

    /// Machine type (q35)
    pub machine: String,

    /// OS Type
    pub os_type: String,

    /// Network bridge used for the networking interface
    pub bridge: String,

    /// CPU type
    pub cpu: String,

    /// VLAN tag all spawned VM's
    pub vlan: Option<u16>
}

impl ProvisionerConfig {
    pub fn get_provisioner(
        &self,
        db: impl LNVpsDb + 'static,
        lnd: Client,
        exchange: ExchangeRateCache,
    ) -> impl Provisioner + 'static {
        match self {
            ProvisionerConfig::Proxmox(c) => LNVpsProvisioner::new(c.clone(), db, lnd, exchange),
        }
    }
}
