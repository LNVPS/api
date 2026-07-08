//! Local bootstrap configuration for `lnvps_fw_service`, loaded from a YAML
//! file (matching the kebab-case YAML convention used across the LNVPS API
//! configs). The control-plane/API sync (increment 7) will later augment or
//! override the runtime values, but the interface list and file paths always
//! come from here.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Protected IPv4 prefixes as (prefix_len, network-bytes).
pub type ProtectedV4 = Vec<(u32, [u8; 4])>;
/// Protected IPv6 prefixes as (prefix_len, network-bytes).
pub type ProtectedV6 = Vec<(u32, [u8; 16])>;

/// Top-level service configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Interfaces to attach to. Each entry is either a bare name (host role:
    /// XDP filter + TC-egress learn on one NIC) or `{ name, role }`.
    pub interfaces: Vec<InterfaceSpec>,
    /// Passive port-learning parameters.
    #[serde(default)]
    pub learning: LearningConfig,
    /// Detection thresholds and hysteresis for the mitigation state machine.
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Per-source rate limiting and CIDR escalation while mitigating.
    #[serde(default)]
    pub escalation: Escalation,
    /// Protected prefixes (CIDR strings) this host serves. Used for prefix-wide
    /// (carpet-bomb) mitigation. Populated from the API in a later increment.
    #[serde(default)]
    pub protected: Vec<String>,
    /// Aggregate per-prefix detection thresholds (carpet-bomb floods).
    #[serde(default)]
    pub network: NetworkThresholds,
    /// RESTful control API (increment 7). Absent = API disabled.
    #[serde(default)]
    pub api: Option<ApiConfig>,
}

/// Role of an attached interface, deciding which hooks are installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IfaceRole {
    /// Single-NIC host: XDP filter (ingress) + TC-egress port learning. Default.
    #[default]
    Host,
    /// Router upstream/underlay: XDP filter (ingress), GRE-decap-aware, no
    /// learning. Attack traffic to protected IPs is dropped here (including
    /// inside GRE tunnels).
    Filter,
    /// Router VM-facing NIC: TC-ingress port learning only (VM replies enter
    /// here as plain L2). No filtering.
    Learn,
}

/// An interface entry: a bare name (host role) or a `{ name, role }` object.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum InterfaceSpec {
    Bare(String),
    Full(InterfaceFull),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InterfaceFull {
    pub name: String,
    #[serde(default)]
    pub role: IfaceRole,
}

impl InterfaceSpec {
    pub fn name(&self) -> &str {
        match self {
            Self::Bare(s) => s,
            Self::Full(f) => &f.name,
        }
    }
    pub fn role(&self) -> IfaceRole {
        match self {
            Self::Bare(_) => IfaceRole::Host,
            Self::Full(f) => f.role,
        }
    }
}

/// RESTful control-API (HTTPS) configuration. HTTPS is mandatory: if no
/// cert/key is supplied a self-signed pair is generated at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ApiConfig {
    /// Address to bind the HTTPS listener to.
    #[serde(default = "default_api_listen")]
    pub listen: std::net::SocketAddr,
    /// Bearer token required on every API request.
    pub token: String,
    /// PEM certificate chain path (optional; self-signed if omitted).
    #[serde(default)]
    pub tls_cert: Option<std::path::PathBuf>,
    /// PEM private key path (optional; self-signed if omitted).
    #[serde(default)]
    pub tls_key: Option<std::path::PathBuf>,
    /// Optional source-IP allow-list (empty = allow any peer).
    #[serde(default)]
    pub allow_ips: Vec<std::net::IpAddr>,
    /// Bounded in-memory event ring-buffer size.
    #[serde(default = "default_events_buffer")]
    pub events_buffer: usize,
}

fn default_api_listen() -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888)
}
fn default_events_buffer() -> usize {
    1024
}

/// Port-learning / garbage-collection parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct LearningConfig {
    /// Learned open ports are forgotten after this many seconds without any
    /// matching egress traffic refreshing them.
    #[serde(default = "default_port_ttl_secs")]
    pub port_ttl_secs: u64,
    /// How often the userspace GC sweeps expired learned ports.
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,
    /// How often per-destination stats are logged (0 disables logging).
    #[serde(default = "default_stats_interval_secs")]
    pub stats_interval_secs: u64,
}

/// Attack-detection thresholds and hysteresis (per destination IP), consumed
/// by the detection state machine.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Thresholds {
    /// Packets/second into a destination that trips mitigation.
    #[serde(default = "default_pps")]
    pub pps: u64,
    /// TCP SYNs/second into a destination that trips mitigation.
    #[serde(default = "default_syn_pps")]
    pub syn_pps: u64,
    /// Bytes/second into a destination that trips mitigation.
    #[serde(default = "default_bps")]
    pub bps: u64,
    /// Exit hysteresis: leave mitigation only once every rate falls below this
    /// percentage of its entry threshold.
    #[serde(default = "default_exit_pct")]
    pub exit_pct: u64,
    /// Sustained seconds below the exit thresholds before returning to normal.
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    /// How often (milliseconds) the detection loop samples counters.
    #[serde(default = "default_sample_interval_ms")]
    pub sample_interval_ms: u64,
}

fn default_port_ttl_secs() -> u64 {
    600
}
fn default_gc_interval_secs() -> u64 {
    60
}
fn default_stats_interval_secs() -> u64 {
    5
}
fn default_pps() -> u64 {
    100_000
}
fn default_syn_pps() -> u64 {
    10_000
}
fn default_bps() -> u64 {
    1_000_000_000
}
fn default_exit_pct() -> u64 {
    50
}
fn default_cooldown_secs() -> u64 {
    30
}
fn default_sample_interval_ms() -> u64 {
    500
}
fn default_agg_fanout() -> usize {
    4
}
fn default_net_pps() -> u64 {
    500_000
}
fn default_net_syn_pps() -> u64 {
    50_000
}
fn default_net_bps() -> u64 {
    5_000_000_000
}
fn default_block_ttl_secs() -> u64 {
    300
}
fn default_src_rate_pps() -> u64 {
    500
}
fn default_escalate_pass_pps() -> u64 {
    50_000
}
fn default_max_real_sources() -> usize {
    10_000
}
fn default_syn_proxy_syn_pps() -> u64 {
    5_000
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            port_ttl_secs: default_port_ttl_secs(),
            gc_interval_secs: default_gc_interval_secs(),
            stats_interval_secs: default_stats_interval_secs(),
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            pps: default_pps(),
            syn_pps: default_syn_pps(),
            bps: default_bps(),
            exit_pct: default_exit_pct(),
            cooldown_secs: default_cooldown_secs(),
            sample_interval_ms: default_sample_interval_ms(),
        }
    }
}

/// Per-source rate limiting and CIDR escalation parameters (applied while a
/// destination is mitigating). The eBPF datapath only counts per source; these
/// drive the userspace decision of what to block.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Escalation {
    /// A source is an offender once its per-window rate reaches this many
    /// packets/second toward a mitigated destination.
    #[serde(default = "default_src_rate_pps")]
    pub src_rate_pps: u64,
    /// Aggregation fan-out: this many child prefixes under a common parent
    /// collapse into one wider block (/32->/24->/16->/8), keeping the LPM trie
    /// bounded under distributed floods.
    #[serde(default = "default_agg_fanout")]
    pub agg_fanout: usize,
    /// A CIDR block is lifted after this many seconds without being refreshed.
    #[serde(default = "default_block_ttl_secs")]
    pub block_ttl_secs: u64,
    /// Escalate a mitigating dest/prefix to source blocking only if this many
    /// packets/second are still getting through after the port-filter layer.
    #[serde(default = "default_escalate_pass_pps")]
    pub escalate_pass_pps: u64,
    /// Spoof gate: if more than this many distinct offenders appear in a window
    /// the flood is treated as spoofed and source blocking is skipped.
    #[serde(default = "default_max_real_sources")]
    pub max_real_sources: usize,
    /// Enable the SYN_PROXY flag on a mitigating dest/prefix once its SYN rate
    /// reaches this many SYNs/second (spoofed SYN floods to open TCP ports).
    #[serde(default = "default_syn_proxy_syn_pps")]
    pub syn_proxy_syn_pps: u64,
}

impl Default for Escalation {
    fn default() -> Self {
        Self {
            src_rate_pps: default_src_rate_pps(),
            agg_fanout: default_agg_fanout(),
            block_ttl_secs: default_block_ttl_secs(),
            escalate_pass_pps: default_escalate_pass_pps(),
            max_real_sources: default_max_real_sources(),
            syn_proxy_syn_pps: default_syn_proxy_syn_pps(),
        }
    }
}

/// Aggregate detection thresholds applied per protected prefix. Defaults are
/// large (network-scale) so a prefix only flips under a genuine carpet bomb.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NetworkThresholds {
    #[serde(default = "default_net_pps")]
    pub pps: u64,
    #[serde(default = "default_net_syn_pps")]
    pub syn_pps: u64,
    #[serde(default = "default_net_bps")]
    pub bps: u64,
    #[serde(default = "default_exit_pct")]
    pub exit_pct: u64,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
}

impl Default for NetworkThresholds {
    fn default() -> Self {
        Self {
            pps: default_net_pps(),
            syn_pps: default_net_syn_pps(),
            bps: default_net_bps(),
            exit_pct: default_exit_pct(),
            cooldown_secs: default_cooldown_secs(),
        }
    }
}

impl Config {
    /// Interface names (for logging + the API status snapshot).
    pub fn interface_names(&self) -> Vec<String> {
        self.interfaces
            .iter()
            .map(|i| i.name().to_string())
            .collect()
    }

    /// Load and validate a config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Build a config directly from a list of interfaces (used when no config
    /// file is provided, and by tests).
    pub fn from_interfaces(interfaces: Vec<String>) -> Self {
        Self {
            interfaces: interfaces.into_iter().map(InterfaceSpec::Bare).collect(),
            learning: LearningConfig::default(),
            thresholds: Thresholds::default(),
            escalation: Escalation::default(),
            protected: Vec::new(),
            network: NetworkThresholds::default(),
            api: None,
        }
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.interfaces.is_empty(),
            "config must list at least one interface"
        );
        anyhow::ensure!(
            self.learning.gc_interval_secs > 0,
            "learning.gc-interval-secs must be > 0"
        );
        anyhow::ensure!(
            self.thresholds.sample_interval_ms > 0,
            "thresholds.sample-interval-ms must be > 0"
        );
        Ok(())
    }

    /// Learned-port TTL as a `Duration`.
    pub fn port_ttl(&self) -> Duration {
        Duration::from_secs(self.learning.port_ttl_secs)
    }

    /// GC sweep interval as a `Duration`.
    pub fn gc_interval(&self) -> Duration {
        Duration::from_secs(self.learning.gc_interval_secs)
    }

    /// Detection loop sample interval as a `Duration`.
    pub fn sample_interval(&self) -> Duration {
        Duration::from_millis(self.thresholds.sample_interval_ms)
    }

    /// Build the pure detection config from the parsed thresholds.
    pub fn detection_config(&self) -> crate::detect::DetectionConfig {
        crate::detect::DetectionConfig {
            pps: self.thresholds.pps,
            syn_pps: self.thresholds.syn_pps,
            bps: self.thresholds.bps,
            exit_pct: self.thresholds.exit_pct,
            cooldown_ns: self.thresholds.cooldown_secs * 1_000_000_000,
        }
    }

    /// Aggregate (per-prefix) detection config.
    pub fn network_config(&self) -> crate::detect::DetectionConfig {
        crate::detect::DetectionConfig {
            pps: self.network.pps,
            syn_pps: self.network.syn_pps,
            bps: self.network.bps,
            exit_pct: self.network.exit_pct,
            cooldown_ns: self.network.cooldown_secs * 1_000_000_000,
        }
    }

    /// Parse the `protected` CIDR strings into (prefix_len, network-bytes) pairs
    /// per address family, with host bits masked off.
    pub fn parse_protected(&self) -> Result<(ProtectedV4, ProtectedV6)> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for cidr in &self.protected {
            let (addr, len) = cidr
                .split_once('/')
                .with_context(|| format!("protected entry '{cidr}' is not CIDR (addr/len)"))?;
            let len: u32 = len
                .parse()
                .with_context(|| format!("invalid prefix length in '{cidr}'"))?;
            let ip: std::net::IpAddr = addr
                .parse()
                .with_context(|| format!("invalid address in '{cidr}'"))?;
            match ip {
                std::net::IpAddr::V4(a) => {
                    anyhow::ensure!(len <= 32, "IPv4 prefix >32 in '{cidr}'");
                    v4.push((len, crate::cidr::mask_v4(a.octets(), len)));
                }
                std::net::IpAddr::V6(a) => {
                    anyhow::ensure!(len <= 128, "IPv6 prefix >128 in '{cidr}'");
                    v6.push((len, crate::cidr::mask_v6(a.octets(), len)));
                }
            }
        }
        Ok((v4, v6))
    }

    /// Build the runtime control-tick config from the parsed settings.
    pub fn runtime_config(&self) -> Result<crate::runtime::RuntimeConfig> {
        let (protected_v4, protected_v6) = self.parse_protected()?;
        Ok(crate::runtime::RuntimeConfig {
            detection: self.detection_config(),
            network: self.network_config(),
            protected_v4,
            protected_v6,
            src_rate_pps: self.escalation.src_rate_pps,
            fanout: self.escalation.agg_fanout,
            block_ttl_ns: self.escalation.block_ttl_secs * 1_000_000_000,
            escalate_pass_pps: self.escalation.escalate_pass_pps,
            max_real_sources: self.escalation.max_real_sources,
            syn_proxy_pps: self.escalation.syn_proxy_syn_pps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg: Config = serde_yaml_ng::from_str("interfaces: [eno1, eno2]\n").unwrap();
        assert_eq!(cfg.interface_names(), vec!["eno1", "eno2"]);
        assert_eq!(cfg.interfaces[0].role(), IfaceRole::Host);
        // Defaults applied.
        assert_eq!(cfg.learning.port_ttl_secs, 600);
        assert_eq!(cfg.learning.gc_interval_secs, 60);
        assert_eq!(cfg.thresholds.syn_pps, 10_000);
    }

    #[test]
    fn parses_interface_roles() {
        let cfg: Config = serde_yaml_ng::from_str(
            "interfaces:\n  - ens18\n  - { name: ens19, role: filter }\n  - { name: ens21, role: learn }\n",
        )
        .unwrap();
        assert_eq!(cfg.interface_names(), vec!["ens18", "ens19", "ens21"]);
        assert_eq!(cfg.interfaces[0].role(), IfaceRole::Host);
        assert_eq!(cfg.interfaces[1].role(), IfaceRole::Filter);
        assert_eq!(cfg.interfaces[2].role(), IfaceRole::Learn);
    }

    #[test]
    fn parses_full_config_with_overrides() {
        let cfg: Config = serde_yaml_ng::from_str(
            r#"
interfaces:
  - eth0
learning:
  port-ttl-secs: 120
  gc-interval-secs: 30
  stats-interval-secs: 0
thresholds:
  pps: 50000
  syn-pps: 5000
  bps: 500000000
"#,
        )
        .unwrap();
        assert_eq!(cfg.learning.port_ttl_secs, 120);
        assert_eq!(cfg.learning.stats_interval_secs, 0);
        assert_eq!(cfg.thresholds.pps, 50_000);
        assert_eq!(cfg.port_ttl(), Duration::from_secs(120));
        assert_eq!(cfg.gc_interval(), Duration::from_secs(30));
    }

    #[test]
    fn from_interfaces_uses_defaults() {
        let cfg = Config::from_interfaces(vec!["eno2".to_string()]);
        assert_eq!(cfg.interface_names(), vec!["eno2"]);
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_interfaces() {
        let cfg = Config::from_interfaces(vec![]);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_gc_interval() {
        let mut cfg = Config::from_interfaces(vec!["eno2".to_string()]);
        cfg.learning.gc_interval_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_and_masks_protected_prefixes() {
        let cfg: Config = serde_yaml_ng::from_str(
            "interfaces: [eno1]\nprotected:\n  - 10.0.1.130/24\n  - fd00:1::5/64\n",
        )
        .unwrap();
        let (v4, v6) = cfg.parse_protected().unwrap();
        // Host bits masked off: 10.0.1.130/24 -> 10.0.1.0/24.
        assert_eq!(v4, vec![(24, [10, 0, 1, 0])]);
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].0, 64);
        assert_eq!(&v6[0].1[..8], &[0xfd, 0x00, 0, 1, 0, 0, 0, 0]);
        assert_eq!(&v6[0].1[8..], &[0u8; 8]);
    }

    #[test]
    fn rejects_bad_protected_cidr() {
        let cfg = Config {
            protected: vec!["not-a-cidr".to_string()],
            ..Config::from_interfaces(vec!["e".to_string()])
        };
        assert!(cfg.parse_protected().is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = serde_yaml_ng::from_str::<Config>("interfaces: [e]\nbogus: 1\n").unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}
