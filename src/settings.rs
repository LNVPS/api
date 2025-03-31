use crate::dns::DnsServer;
use crate::exchange::ExchangeRateService;
use crate::fiat::FiatPaymentService;
use crate::lightning::LightningNode;
use crate::provisioner::LNVpsProvisioner;
use anyhow::Result;
use isocountry::CountryCode;
use lnvps_db::LNVpsDb;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Listen address for http server
    pub listen: Option<String>,

    /// MYSQL connection string
    pub db: String,

    /// Public URL mapping to this service
    pub public_url: String,

    /// Lightning node config for creating LN payments
    pub lightning: LightningConfig,

    /// Readonly mode, don't spawn any VM's
    pub read_only: bool,

    /// Provisioning profiles
    pub provisioner: ProvisionerConfig,

    /// Number of days after an expired VM is deleted
    pub delete_after: u16,

    /// SMTP settings for sending emails
    pub smtp: Option<SmtpConfig>,

    /// DNS configurations for PTR records
    pub dns: Option<DnsServerConfig>,

    /// Nostr config for sending DMs
    pub nostr: Option<NostrConfig>,

    /// Config for accepting revolut payments
    pub revolut: Option<RevolutConfig>,

    #[serde(default)]
    /// Tax rates to change per country as a percent of the amount
    pub tax_rate: HashMap<CountryCode, f32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LightningConfig {
    #[serde(rename = "lnd")]
    LND {
        url: String,
        cert: PathBuf,
        macaroon: PathBuf,
    },
    #[serde(rename_all = "kebab-case")]
    Bitvora {
        token: String,
        webhook_secret: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    pub nsec: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsServerConfig {
    pub forward_zone_id: String,
    pub api: DnsServerApi,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsServerApi {
    #[serde(rename_all = "kebab-case")]
    Cloudflare { token: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpConfig {
    /// Admin user id, for sending system notifications
    pub admin: Option<u64>,
    /// Email server host:port
    pub server: String,
    /// From header to use, otherwise empty
    pub from: Option<String>,
    /// Username for SMTP connection
    pub username: String,
    /// Password for SMTP connection
    pub password: String,
}

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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RevolutConfig {
    pub url: Option<String>,
    pub api_version: String,
    pub token: String,
    pub public_key: String,
}

impl Settings {
    pub fn get_provisioner(
        &self,
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        exchange: Arc<dyn ExchangeRateService>,
    ) -> Arc<LNVpsProvisioner> {
        Arc::new(LNVpsProvisioner::new(self.clone(), db, node, exchange))
    }

    pub fn get_dns(&self) -> Result<Option<Arc<dyn DnsServer>>> {
        #[cfg(test)]
        {
            Ok(Some(Arc::new(crate::mocks::MockDnsServer::new())))
        }
        #[cfg(not(test))]
        {
            match &self.dns {
                None => Ok(None),
                Some(c) => match &c.api {
                    #[cfg(feature = "cloudflare")]
                    DnsServerApi::Cloudflare { token } => {
                        Ok(Some(Arc::new(crate::dns::Cloudflare::new(token))))
                    }
                },
            }
        }
    }

    pub fn get_revolut(&self) -> Result<Option<Arc<dyn FiatPaymentService>>> {
        match &self.revolut {
            #[cfg(feature = "revolut")]
            Some(c) => Ok(Some(Arc::new(crate::fiat::RevolutApi::new(c.clone())?))),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
pub fn mock_settings() -> Settings {
    Settings {
        listen: None,
        db: "".to_string(),
        public_url: "http://localhost:8000".to_string(),
        lightning: LightningConfig::LND {
            url: "".to_string(),
            cert: Default::default(),
            macaroon: Default::default(),
        },
        read_only: false,
        provisioner: ProvisionerConfig {
            proxmox: Some(ProxmoxConfig {
                qemu: QemuConfig {
                    machine: "q35".to_string(),
                    os_type: "l26".to_string(),
                    bridge: "vmbr1".to_string(),
                    cpu: "kvm64".to_string(),
                    kvm: false,
                },
                ssh: None,
                mac_prefix: Some("ff:ff:ff".to_string()),
            }),
            libvirt: None,
        },
        delete_after: 0,
        smtp: None,
        dns: Some(DnsServerConfig {
            forward_zone_id: "mock-forward-zone-id".to_string(),
            api: DnsServerApi::Cloudflare {
                token: "abc".to_string(),
            },
        }),
        nostr: None,
        revolut: None,
        tax_rate: HashMap::from([(CountryCode::IRL, 23.0), (CountryCode::USA, 1.0)]),
    }
}
