use lnvps_api_common::RedisConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Listen address for http server
    pub listen: Option<String>,

    /// MYSQL connection string
    pub db: String,

    /// Public URL mapping to this service
    pub public_url: String,

    /// Readonly mode, don't spawn any VM's
    pub read_only: bool,

    /// Provisioning profiles
    pub provisioner: ProvisionerConfig,

    /// Number of days after an expired VM is deleted (monthly/yearly billing)
    pub delete_after: u16,

    /// Global default for the maximum number of days a subscription may be
    /// prepaid/renewed in advance. Used when a company's own `max_prepay_days`
    /// is `0` (unset). Bounds both a single large renewal and repeated
    /// back-to-back renewals. Defaults to 365 (one year).
    #[serde(default = "default_max_prepay_days")]
    pub max_prepay_days: u16,

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

    /// public host of lnvps_nostr service
    pub nostr_address_host: Option<String>,

    /// Redis configuration for shared VM state cache
    pub redis: Option<RedisConfig>,

    /// Database encryption configuration (fallback when the
    /// `LNVPS_ENCRYPTION_KEY` environment variable is not set)
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

    /// External OAuth/OIDC login support. When omitted, only Nostr (NIP-98)
    /// authentication is available.
    pub oauth: Option<OAuthConfig>,

    /// Passwordless WebAuthn / passkey login. When omitted, passkey endpoints
    /// are disabled. Issues the same session JWTs as OAuth.
    pub webauthn: Option<WebauthnConfig>,

    /// Shared session-token settings. Required when `oauth` or `webauthn` is
    /// configured — both issue the same stateless session JWTs. When omitted,
    /// `Bearer` session auth is disabled and only Nostr (NIP-98) auth works.
    pub session: Option<SessionConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SessionConfig {
    /// Secret used to sign session JWTs (and the OAuth CSRF `state` / WebAuthn
    /// challenge tokens). Must be a strong, stable random string — changing it
    /// invalidates all outstanding sessions.
    pub secret: String,
    /// Session token lifetime in seconds. Defaults to 30 days.
    #[serde(default = "default_session_ttl")]
    pub ttl: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WebauthnConfig {
    /// Relying Party ID — the registrable domain passkeys are bound to (e.g.
    /// `app.lnvps.com`). PERMANENT: changing it invalidates every passkey.
    pub rp_id: String,
    /// Relying Party origin — the exact origin the frontend runs on (e.g.
    /// `https://app.lnvps.com`). Its host must equal or be a subdomain of
    /// `rp_id`.
    pub rp_origin: String,
    /// Human-friendly Relying Party name shown in the authenticator UI.
    pub rp_name: String,
    /// Require a discoverable (resident-key) credential at registration so
    /// usernameless "Sign in with a passkey" works across all authenticators
    /// (platform passkeys, security keys, Windows Hello). Defaults to `true`.
    ///
    /// Set to `false` only to work around a specific authenticator that refuses
    /// resident-key registration — non-discoverable credentials it creates will
    /// NOT be usable for usernameless login.
    #[serde(default = "default_require_resident_key")]
    pub require_resident_key: bool,
}

fn default_require_resident_key() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OAuthConfig {
    /// After a successful login the browser is redirected here with the issued
    /// token appended as `#token=<jwt>` (fragment). Typically your frontend.
    /// When omitted, the callback returns the token as JSON instead.
    pub success_redirect: Option<String>,

    /// Allowlist of origins/prefixes a login may request a post-login redirect
    /// to via the `?redirect=<url>` query param on `/oauth/{provider}/login`.
    /// A requested redirect is accepted when it exactly equals an entry or
    /// extends one at a path boundary (next char is `/`, `?` or `#`), which
    /// prevents `http://localhost:3000` from also matching
    /// `http://localhost:30000.evil`. `success_redirect` is always implicitly
    /// allowed. Defaults to empty (only `success_redirect` permitted).
    #[serde(default)]
    pub allowed_redirects: Vec<String>,

    /// Configured identity providers, keyed by a short provider tag (e.g.
    /// `google`, `github`). The tag is part of the synthetic identity
    /// (`sha256("{tag}:{subject}")`) so it must remain stable.
    pub providers: std::collections::HashMap<String, OAuthProviderConfig>,
}

fn default_session_ttl() -> u64 {
    lnvps_api_common::DEFAULT_SESSION_TTL_SECS
}

/// How the stable subject id is obtained after the token exchange.
pub enum SubjectSource {
    /// GET the userinfo endpoint and read `field` from the JSON response.
    Userinfo { url: String, field: String },
    /// Decode the `id_token` returned by the token endpoint and read `sub`
    /// (used by "Sign in with Apple", which has no userinfo endpoint).
    IdToken,
}

/// A configured OAuth/OIDC identity provider. The `type` tag selects a built-in
/// flavor with sensible default endpoints/scopes and any provider-specific
/// quirks; `oidc` is a fully generic provider requiring explicit endpoints.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OAuthProviderConfig {
    /// Google (OpenID Connect).
    Google(OAuthCommon),
    /// GitHub (OAuth2; subject is the numeric user `id`).
    Github(OAuthCommon),
    /// Facebook Login (Graph API; subject is the numeric user `id`).
    Facebook(OAuthCommon),
    /// Sign in with Apple (subject comes from the `id_token`; client secret is
    /// a dynamically-signed ES256 JWT).
    Apple(AppleConfig),
    /// Fully generic OIDC/OAuth2 provider.
    Oidc(OAuthCommon),
}

/// Common fields for standard client-secret providers. Endpoint/scope fields are
/// optional overrides — built-in flavors supply defaults, `oidc` requires them.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OAuthCommon {
    /// OAuth2 client id.
    pub client_id: String,
    /// OAuth2 client secret.
    pub client_secret: String,
    /// Override the authorization endpoint.
    pub auth_url: Option<String>,
    /// Override the token endpoint.
    pub token_url: Option<String>,
    /// Override the userinfo endpoint.
    pub userinfo_url: Option<String>,
    /// Override the requested scopes.
    pub scopes: Option<Vec<String>>,
    /// Override the userinfo JSON field used as the stable subject id.
    pub subject_field: Option<String>,
}

/// Sign in with Apple configuration. Apple requires the OAuth `client_secret` to
/// be a short-lived ES256 JWT signed with your private key, so it takes key
/// material instead of a static secret.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppleConfig {
    /// The Services ID (client id / `sub` of the client-secret JWT).
    pub client_id: String,
    /// Apple Developer Team ID (`iss` of the client-secret JWT).
    pub team_id: String,
    /// The key id of the `.p8` private key (`kid` header of the JWT).
    pub key_id: String,
    /// PEM contents of the Apple `.p8` (PKCS#8) private key.
    pub private_key: String,
    /// Scopes to request. Requesting `name`/`email` forces Apple's `form_post`
    /// response mode (the callback arrives as a POST). Defaults to none.
    pub scopes: Option<Vec<String>>,
    /// Override the authorization endpoint.
    pub auth_url: Option<String>,
    /// Override the token endpoint.
    pub token_url: Option<String>,
}

impl OAuthProviderConfig {
    /// OAuth2 client id sent in the authorization/token requests.
    pub fn client_id(&self) -> &str {
        match self {
            OAuthProviderConfig::Google(c)
            | OAuthProviderConfig::Github(c)
            | OAuthProviderConfig::Facebook(c)
            | OAuthProviderConfig::Oidc(c) => &c.client_id,
            OAuthProviderConfig::Apple(a) => &a.client_id,
        }
    }

    /// The provider authorization endpoint (built-in default or override).
    pub fn auth_url(&self) -> &str {
        match self {
            OAuthProviderConfig::Google(c) => c
                .auth_url
                .as_deref()
                .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth"),
            OAuthProviderConfig::Github(c) => c
                .auth_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/authorize"),
            OAuthProviderConfig::Facebook(c) => c
                .auth_url
                .as_deref()
                .unwrap_or("https://www.facebook.com/v21.0/dialog/oauth"),
            OAuthProviderConfig::Apple(a) => a
                .auth_url
                .as_deref()
                .unwrap_or("https://appleid.apple.com/auth/authorize"),
            OAuthProviderConfig::Oidc(c) => c.auth_url.as_deref().unwrap_or_default(),
        }
    }

    /// The provider token endpoint (built-in default or override).
    pub fn token_url(&self) -> &str {
        match self {
            OAuthProviderConfig::Google(c) => c
                .token_url
                .as_deref()
                .unwrap_or("https://oauth2.googleapis.com/token"),
            OAuthProviderConfig::Github(c) => c
                .token_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/access_token"),
            OAuthProviderConfig::Facebook(c) => c
                .token_url
                .as_deref()
                .unwrap_or("https://graph.facebook.com/v21.0/oauth/access_token"),
            OAuthProviderConfig::Apple(a) => a
                .token_url
                .as_deref()
                .unwrap_or("https://appleid.apple.com/auth/token"),
            OAuthProviderConfig::Oidc(c) => c.token_url.as_deref().unwrap_or_default(),
        }
    }

    /// Scopes to request at the authorization endpoint.
    pub fn scopes(&self) -> Vec<String> {
        let default: &[&str] = match self {
            OAuthProviderConfig::Google(_) => &["openid", "email"],
            OAuthProviderConfig::Github(_) => &["read:user", "user:email"],
            OAuthProviderConfig::Facebook(_) => &["email"],
            OAuthProviderConfig::Apple(_) => &[],
            OAuthProviderConfig::Oidc(_) => &["openid", "email"],
        };
        let override_scopes = match self {
            OAuthProviderConfig::Google(c)
            | OAuthProviderConfig::Github(c)
            | OAuthProviderConfig::Facebook(c)
            | OAuthProviderConfig::Oidc(c) => c.scopes.clone(),
            OAuthProviderConfig::Apple(a) => a.scopes.clone(),
        };
        override_scopes.unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect())
    }

    /// Apple's `name`/`email` scopes require `response_mode=form_post`, which
    /// makes the callback a POST. Returns the response mode to request, if any.
    pub fn response_mode(&self) -> Option<&'static str> {
        match self {
            OAuthProviderConfig::Apple(_) if !self.scopes().is_empty() => Some("form_post"),
            _ => None,
        }
    }

    /// Whether requests to this provider need a `User-Agent` header (GitHub's
    /// API rejects requests without one).
    pub fn needs_user_agent(&self) -> bool {
        matches!(self, OAuthProviderConfig::Github(_))
    }

    /// How to obtain the stable subject id after the token exchange.
    pub fn subject_source(&self) -> SubjectSource {
        match self {
            OAuthProviderConfig::Apple(_) => SubjectSource::IdToken,
            OAuthProviderConfig::Google(c) => SubjectSource::Userinfo {
                url: c.userinfo_url.clone().unwrap_or_else(|| {
                    "https://openidconnect.googleapis.com/v1/userinfo".to_string()
                }),
                field: c.subject_field.clone().unwrap_or_else(|| "sub".to_string()),
            },
            OAuthProviderConfig::Github(c) => SubjectSource::Userinfo {
                url: c
                    .userinfo_url
                    .clone()
                    .unwrap_or_else(|| "https://api.github.com/user".to_string()),
                field: c.subject_field.clone().unwrap_or_else(|| "id".to_string()),
            },
            OAuthProviderConfig::Facebook(c) => SubjectSource::Userinfo {
                url: c.userinfo_url.clone().unwrap_or_else(|| {
                    "https://graph.facebook.com/me?fields=id,name,email".to_string()
                }),
                field: c.subject_field.clone().unwrap_or_else(|| "id".to_string()),
            },
            OAuthProviderConfig::Oidc(c) => SubjectSource::Userinfo {
                url: c.userinfo_url.clone().unwrap_or_default(),
                field: c.subject_field.clone().unwrap_or_else(|| "sub".to_string()),
            },
        }
    }
}

fn default_min_payout_sats() -> u64 {
    1000
}

fn default_min_onchain_payout_sats() -> Option<u64> {
    Some(1000)
}

fn default_max_onchain_fee_per_vbyte() -> u64 {
    50
}

fn default_mempool_url() -> String {
    "https://mempool.space".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReferralConfig {
    /// Minimum accrued BTC commission (in satoshis) before an automated
    /// Lightning payout is attempted for a referrer. Defaults to 1000 sats.
    #[serde(default = "default_min_payout_sats")]
    pub min_payout_sats: u64,
    /// Minimum accrued BTC commission (in satoshis) before an automated
    /// **on-chain** payout is attempted. Defaults to 1000 sats; this minimum
    /// acts as a small buffer so a payout can absorb the referrer's fee. Set to
    /// `null` to disable on-chain payouts entirely (commission still accrues for
    /// manual payout).
    #[serde(default = "default_min_onchain_payout_sats")]
    pub min_onchain_payout_sats: Option<u64>,
    /// Maximum acceptable next-block fee rate (sat/vByte) for on-chain payouts.
    /// Before broadcasting a payout batch, the current next-block fee rate is
    /// fetched from mempool.space; if it exceeds this cap the batch is skipped
    /// and retried on a later run, so payouts wait for cheaper fees rather than
    /// paying "crazy" fees. Defaults to 50 sat/vByte.
    #[serde(default = "default_max_onchain_fee_per_vbyte")]
    pub max_onchain_fee_per_vbyte: u64,
    /// Base URL of the mempool.space (compatible) instance used to fetch the
    /// recommended next-block fee rate. Defaults to `https://mempool.space`.
    #[serde(default = "default_mempool_url")]
    pub mempool_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptchaConfig {
    #[serde(rename_all = "kebab-case")]
    Turnstile { secret_key: String },
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
    /// Auto-ballooning floor as a percentage of the VM's sold RAM.
    ///
    /// When set (1..=99), created/reconfigured VMs carry a `balloon` value of
    /// `memory_mb * balloon_min_pct / 100`, guaranteeing the guest at least
    /// that percentage of its RAM while allowing Proxmox auto-ballooning to
    /// reclaim the remainder under host memory pressure (a pressure-relief
    /// valve against host OOM-kills). Unset / `0` / `>= 100` leaves the
    /// `balloon` key out, which disables dynamic ballooning (current default).
    pub balloon_min_pct: Option<u8>,
    /// Firewall configuration options
    pub firewall_config: Option<FirewallConfig>,
}

impl QemuConfig {
    /// Compute the Proxmox `balloon` value (in MB) for a VM with the given
    /// sold memory, honouring [`QemuConfig::balloon_min_pct`].
    ///
    /// Returns `None` (no `balloon` key, i.e. dynamic ballooning disabled)
    /// when the floor is unset, `0`, or `>= 100`.
    pub fn balloon_mb(&self, memory_mb: u64) -> Option<i32> {
        match self.balloon_min_pct {
            Some(pct) if (1..100).contains(&pct) => Some((memory_mb * pct as u64 / 100) as i32),
            _ => None,
        }
    }
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

/// Environment variable holding the hex-encoded database encryption key
pub const ENCRYPTION_KEY_ENV: &str = "LNVPS_ENCRYPTION_KEY";

/// Default global maximum prepay window (days) when unspecified in config.
pub fn default_max_prepay_days() -> u16 {
    365
}

#[cfg(test)]
pub fn mock_settings() -> Settings {
    Settings {
        listen: None,
        db: "".to_string(),
        encryption: None,
        public_url: "http://localhost:8000".to_string(),
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
                    balloon_min_pct: None,
                    firewall_config: None,
                },
                ssh: None,
                mac_prefix: Some("ff:ff:ff".to_string()),
            }),
            libvirt: None,
        },
        delete_after: 0,
        max_prepay_days: default_max_prepay_days(),
        smtp: None,
        dns: Some(DnsServerConfig {
            forward_zone_id: "mock-forward-zone-id".to_string(),
            api: DnsServerApi::Mock,
        }),
        nostr: None,
        telegram: None,
        whatsapp: None,
        nostr_address_host: None,
        redis: None,
        captcha: None,
        geoip_database: None,
        referral: None,
        oauth: None,
        webauthn: None,
        session: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_db::DnsServerKind;

    fn qemu_with_balloon(pct: Option<u8>) -> QemuConfig {
        QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "host".to_string(),
            kvm: false,
            arch: "x86_64".to_string(),
            balloon_min_pct: pct,
            firewall_config: None,
        }
    }

    #[test]
    fn test_balloon_mb_floor() {
        // Configured floor: balloon = memory * pct / 100
        assert_eq!(qemu_with_balloon(Some(90)).balloon_mb(4096), Some(3686));
        assert_eq!(qemu_with_balloon(Some(50)).balloon_mb(2048), Some(1024));
        assert_eq!(qemu_with_balloon(Some(1)).balloon_mb(2048), Some(20));
        assert_eq!(qemu_with_balloon(Some(99)).balloon_mb(1000), Some(990));
    }

    #[test]
    fn test_balloon_mb_disabled_cases() {
        // Unset / 0 / >= 100 => no balloon key (dynamic ballooning disabled)
        assert_eq!(qemu_with_balloon(None).balloon_mb(4096), None);
        assert_eq!(qemu_with_balloon(Some(0)).balloon_mb(4096), None);
        assert_eq!(qemu_with_balloon(Some(100)).balloon_mb(4096), None);
        assert_eq!(qemu_with_balloon(Some(150)).balloon_mb(4096), None);
    }

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

    #[test]
    fn test_oauth_provider_defaults_and_quirks() {
        // Google: OIDC defaults, userinfo `sub`.
        let g: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "google",
            "client-id": "gid",
            "client-secret": "gsecret",
        }))
        .unwrap();
        assert_eq!(g.client_id(), "gid");
        assert_eq!(g.auth_url(), "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(g.scopes(), vec!["openid", "email"]);
        assert!(!g.needs_user_agent());
        assert!(g.response_mode().is_none());
        assert!(matches!(
            g.subject_source(),
            SubjectSource::Userinfo { field, .. } if field == "sub"
        ));

        // GitHub: needs UA, numeric `id` subject.
        let gh: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "github",
            "client-id": "ghid",
            "client-secret": "ghsecret",
        }))
        .unwrap();
        assert!(gh.needs_user_agent());
        assert_eq!(
            gh.token_url(),
            "https://github.com/login/oauth/access_token"
        );
        assert!(matches!(
            gh.subject_source(),
            SubjectSource::Userinfo { field, .. } if field == "id"
        ));

        // Facebook: Graph me endpoint.
        let fb: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "facebook",
            "client-id": "fbid",
            "client-secret": "fbsecret",
        }))
        .unwrap();
        assert!(matches!(
            fb.subject_source(),
            SubjectSource::Userinfo { url, .. } if url.contains("graph.facebook.com")
        ));

        // Apple: id_token subject, no static secret, form_post only with scopes.
        let apple: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "apple",
            "client-id": "com.example.svc",
            "team-id": "TEAM",
            "key-id": "KEY",
            "private-key": "pem",
        }))
        .unwrap();
        assert!(matches!(apple.subject_source(), SubjectSource::IdToken));
        assert!(apple.response_mode().is_none()); // no scopes -> query callback
        assert_eq!(apple.client_id(), "com.example.svc");

        let apple_scoped: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "apple",
            "client-id": "com.example.svc",
            "team-id": "TEAM",
            "key-id": "KEY",
            "private-key": "pem",
            "scopes": ["name", "email"],
        }))
        .unwrap();
        assert_eq!(apple_scoped.response_mode(), Some("form_post"));

        // Generic OIDC honours explicit overrides.
        let oidc: OAuthProviderConfig = serde_json::from_value(serde_json::json!({
            "type": "oidc",
            "client-id": "oid",
            "client-secret": "osecret",
            "auth-url": "https://id.example.com/authorize",
            "token-url": "https://id.example.com/token",
            "userinfo-url": "https://id.example.com/userinfo",
            "subject-field": "uid",
        }))
        .unwrap();
        assert_eq!(oidc.auth_url(), "https://id.example.com/authorize");
        assert!(matches!(
            oidc.subject_source(),
            SubjectSource::Userinfo { field, url } if field == "uid" && url.contains("id.example.com")
        ));
    }
}
