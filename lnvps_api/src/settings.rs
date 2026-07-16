use anyhow::Result;
use lnvps_api_common::RedisConfig;
use payments_rs::fiat::FiatPaymentService;
use payments_rs::lightning::LightningNode;
use serde::{Deserialize, Serialize};
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

    /// Number of days after an expired VM is deleted (monthly/yearly billing)
    pub delete_after: u16,

    /// SMTP settings for sending emails
    pub smtp: Option<SmtpConfig>,

    /// Legacy DNS configuration. Runtime DNS config now lives in the `dns_server`
    /// DB table (referenced per IP range). This field is only consumed once, by
    /// `DnsDataMigration`, to bootstrap those DB rows for existing deployments.
    pub dns: Option<DnsServerConfig>,

    /// Nostr config for sending DMs
    pub nostr: Option<NostrConfig>,

    /// Telegram bot config for sending notifications
    pub telegram: Option<TelegramConfig>,

    /// WhatsApp Cloud API config for sending notifications
    pub whatsapp: Option<WhatsAppConfig>,

    /// Config for accepting revolut payments
    pub revolut: Option<payments_rs::fiat::RevolutConfig>,

    /// public host of lnvps_nostr service
    pub nostr_address_host: Option<String>,

    /// Redis configuration for shared VM state cache
    pub redis: Option<RedisConfig>,

    /// Database encryption configuration
    pub encryption: Option<EncryptionConfig>,

    /// Captcha config
    pub captcha: Option<CaptchaConfig>,

    /// Path to a MaxMind GeoLite2/GeoIP2 Country database (`.mmdb`) used to
    /// resolve client IPs to a country as VAT place-of-supply evidence. When
    /// unset, IP geolocation is disabled.
    pub geoip_database: Option<PathBuf>,

    /// Referral program automated payout settings. **Automated payouts are
    /// opt-in**: when this section is omitted, commission still accrues and can
    /// be paid manually by admins, but no automatic Lightning payouts are made.
    pub referral: Option<ReferralConfig>,
}

fn default_min_payout_sats() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReferralConfig {
    /// Minimum accrued BTC commission (in satoshis) before an automated payout
    /// is attempted for a referrer. Defaults to 1000 sats.
    #[serde(default = "default_min_payout_sats")]
    pub min_payout_sats: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptchaConfig {
    #[serde(rename_all = "kebab-case")]
    Turnstile { secret_key: String },
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
pub struct TelegramConfig {
    /// Bot API token from @BotFather
    pub token: String,
    /// Bot username (without @), used to build account-linking deep links
    /// e.g. `https://t.me/<username>?start=<token>`
    pub username: String,
}

fn default_whatsapp_api_version() -> String {
    "v21.0".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WhatsAppConfig {
    /// Permanent (or temporary) access token for the WhatsApp Cloud API
    pub access_token: String,
    /// Phone number ID of the sending WhatsApp business number
    pub phone_number_id: String,
    /// Graph API version, e.g. `v21.0`
    #[serde(default = "default_whatsapp_api_version")]
    pub api_version: String,
    /// Approved template used to deliver notifications. Must have a single body
    /// parameter `{{1}}` which receives the message text.
    pub message_template: String,
    /// Language code of the message template (e.g. `en`, `en_US`)
    pub message_template_lang: String,
    /// Approved template used to deliver verification codes. Must have a single
    /// body parameter `{{1}}` which receives the code.
    pub verify_template: String,
    /// Language code of the verification template
    pub verify_template_lang: String,
}

/// Legacy DNS configuration, migrated into the `dns_server` DB table on startup.
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

    #[cfg(test)]
    Mock,
}

impl DnsServerConfig {
    /// Map the legacy config to a database `dns_server` row kind + credential token.
    pub fn to_db_kind_token(&self) -> (lnvps_db::DnsServerKind, String) {
        match &self.api {
            DnsServerApi::Cloudflare { token } => {
                (lnvps_db::DnsServerKind::Cloudflare, token.clone())
            }
            #[cfg(test)]
            DnsServerApi::Mock => (lnvps_db::DnsServerKind::MockDns, "mock-token".to_string()),
        }
    }
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
    /// CPU architecture
    pub arch: String,
    /// Firewall configuration options
    pub firewall_config: Option<FirewallConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FirewallPolicy {
    Accept,
    Reject,
    Drop,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FirewallConfig {
    /// Enable DHCP
    pub dhcp: Option<bool>,
    /// Enable firewall
    pub enable: Option<bool>,
    /// Enable IP filtering
    pub ip_filter: Option<bool>,
    /// Enable MAC filtering
    pub mac_filter: Option<bool>,
    /// Enable NDP (Neighbor Discovery Protocol)
    pub ndp: Option<bool>,
    /// Input policy (ACCEPT, REJECT, DROP)
    pub policy_in: Option<FirewallPolicy>,
    /// Output policy (ACCEPT, REJECT, DROP)
    pub policy_out: Option<FirewallPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EncryptionConfig {
    /// Path to the encryption key file
    pub key_file: PathBuf,
    /// Automatically generate key if file doesn't exist
    pub auto_generate: bool,
}

impl Settings {
    pub fn get_revolut(&self) -> Result<Option<Arc<dyn FiatPaymentService>>> {
        match &self.revolut {
            #[cfg(feature = "revolut")]
            Some(c) => Ok(Some(Arc::new(payments_rs::fiat::RevolutApi::new(
                c.clone(),
            )?))),
            _ => Ok(None),
        }
    }

    pub async fn get_node(&self) -> Result<Arc<dyn LightningNode>> {
        match &self.lightning {
            #[cfg(feature = "lnd")]
            LightningConfig::LND {
                url,
                cert,
                macaroon,
            } => Ok(Arc::new(
                payments_rs::lightning::LndNode::new(url, cert, macaroon).await?,
            )),
            #[cfg(feature = "bitvora")]
            LightningConfig::Bitvora {
                token,
                webhook_secret,
            } => Ok(Arc::new(payments_rs::lightning::BitvoraNode::new(
                token,
                webhook_secret,
                "/api/v1/webhook/bitvora",
            ))),
            _ => anyhow::bail!("Unsupported lightning config!"),
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
                    arch: "x86_64".to_string(),
                    firewall_config: None,
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
            api: DnsServerApi::Mock,
        }),
        nostr: None,
        telegram: None,
        whatsapp: None,
        revolut: None,
        nostr_address_host: None,
        redis: None,
        encryption: None,
        captcha: None,
        geoip_database: None,
        referral: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_db::DnsServerKind;

    #[test]
    fn test_dns_config_to_db_kind_token() {
        let cfg = DnsServerConfig {
            forward_zone_id: "z".to_string(),
            api: DnsServerApi::Cloudflare {
                token: "cf-token".to_string(),
            },
        };
        let (kind, token) = cfg.to_db_kind_token();
        assert!(matches!(kind, DnsServerKind::Cloudflare));
        assert_eq!(token, "cf-token");

        let mock = DnsServerConfig {
            forward_zone_id: "z".to_string(),
            api: DnsServerApi::Mock,
        };
        let (kind, _) = mock.to_db_kind_token();
        assert!(matches!(kind, DnsServerKind::MockDns));
    }
}
