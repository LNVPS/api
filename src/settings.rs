use crate::dns::DnsServer;
use crate::exchange::ExchangeRateService;
use crate::lightning::LightningNode;
use crate::provisioner::LNVpsProvisioner;
use crate::router::Router;
use anyhow::Result;
use lnvps_db::LNVpsDb;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    pub listen: Option<String>,
    pub db: String,

    /// Lightning node config for creating LN payments
    pub lightning: LightningConfig,

    /// Readonly mode, don't spawn any VM's
    pub read_only: bool,

    /// Provisioning profiles
    pub provisioner: ProvisionerConfig,

    /// Network policy
    #[serde(default)]
    pub network_policy: NetworkPolicy,

    /// Number of days after an expired VM is deleted
    pub delete_after: u16,

    /// SMTP settings for sending emails
    pub smtp: Option<SmtpConfig>,

    /// Network router config
    pub router: Option<RouterConfig>,

    /// DNS configurations for PTR records
    pub dns: Option<DnsServerConfig>,

    /// Nostr config for sending DMs
    pub nostr: Option<NostrConfig>,
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
pub enum RouterConfig {
    Mikrotik {
        url: String,
        username: String,
        password: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsServerConfig {
    #[serde(rename_all = "kebab-case")]
    Cloudflare {
        token: String,
        forward_zone_id: String,
        reverse_zone_id: String,
    },
}

/// Policy that determines how packets arrive at the VM
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkAccessPolicy {
    /// No special procedure required for packets to arrive
    #[default]
    Auto,
    /// ARP entries are added statically on the access router
    StaticArp {
        /// Interface used to add arp entries
        interface: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct NetworkPolicy {
    /// Policy that determines how packets arrive at the VM
    pub access: NetworkAccessPolicy,

    /// Use SLAAC for IPv6 allocation
    pub ip6_slaac: Option<bool>,
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
pub enum ProvisionerConfig {
    #[serde(rename_all = "kebab-case")]
    Proxmox {
        /// Generic VM configuration
        qemu: QemuConfig,
        /// SSH config for issuing commands via CLI
        ssh: Option<SshConfig>,
        /// MAC address prefix for NIC (eg. bc:24:11)
        mac_prefix: Option<String>,
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
    /// VLAN tag all spawned VM's
    pub vlan: Option<u16>,
    /// Enable virtualization inside VM
    pub kvm: bool,
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

    pub fn get_router(&self) -> Result<Option<Arc<dyn Router>>> {
        #[cfg(test)]
        {
            if let Some(router) = &self.router {
                let router = crate::mocks::MockRouter::new(self.network_policy.clone());
                Ok(Some(Arc::new(router)))
            } else {
                Ok(None)
            }
        }
        #[cfg(not(test))]
        {
            match &self.router {
                #[cfg(feature = "mikrotik")]
                Some(RouterConfig::Mikrotik {
                    url,
                    username,
                    password,
                }) => Ok(Some(Arc::new(crate::router::MikrotikRouter::new(
                    url, username, password,
                )))),
                _ => Ok(None),
            }
        }
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
                #[cfg(feature = "cloudflare")]
                Some(DnsServerConfig::Cloudflare {
                    token,
                    forward_zone_id,
                    reverse_zone_id,
                }) => Ok(Some(Arc::new(crate::dns::Cloudflare::new(
                    token,
                    reverse_zone_id,
                    forward_zone_id,
                )))),
            }
        }
    }
}
