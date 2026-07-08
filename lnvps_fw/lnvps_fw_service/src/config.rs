//! Local bootstrap configuration for `lnvps_fw_service`, loaded from a YAML
//! file (matching the kebab-case YAML convention used across the LNVPS API
//! configs). The control-plane/API sync (increment 7) will later augment or
//! override the runtime values, but the interface list and file paths always
//! come from here.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Top-level service configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Uplink interfaces to attach the XDP ingress + TC egress programs to.
    pub interfaces: Vec<String>,
    /// Passive port-learning parameters.
    #[serde(default)]
    pub learning: LearningConfig,
    /// Detection thresholds and hysteresis for the mitigation state machine.
    #[serde(default)]
    pub thresholds: Thresholds,
    /// Per-source rate limiting and CIDR escalation while mitigating.
    #[serde(default)]
    pub escalation: Escalation,
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
fn default_min_src_drops() -> u64 {
    100
}
fn default_min_sources() -> usize {
    5
}
fn default_block_ttl_secs() -> u64 {
    300
}
fn default_src_rate_pps() -> u64 {
    500
}
fn default_src_rate_burst() -> u64 {
    1_000
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
/// destination is mitigating).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Escalation {
    /// Per-source packets/second budget under mitigation.
    #[serde(default = "default_src_rate_pps")]
    pub src_rate_pps: u64,
    /// Per-source burst budget under mitigation.
    #[serde(default = "default_src_rate_burst")]
    pub src_rate_burst: u64,
    /// A source counts as an offender once its per-window drop delta reaches
    /// this many packets.
    #[serde(default = "default_min_src_drops")]
    pub min_src_drops: u64,
    /// A prefix (/24 v4, /64 v6) is hard-blocked once this many distinct
    /// offending sources fall within it.
    #[serde(default = "default_min_sources")]
    pub min_sources: usize,
    /// A CIDR block is lifted after this many seconds without being refreshed.
    #[serde(default = "default_block_ttl_secs")]
    pub block_ttl_secs: u64,
}

impl Default for Escalation {
    fn default() -> Self {
        Self {
            src_rate_pps: default_src_rate_pps(),
            src_rate_burst: default_src_rate_burst(),
            min_src_drops: default_min_src_drops(),
            min_sources: default_min_sources(),
            block_ttl_secs: default_block_ttl_secs(),
        }
    }
}

impl Config {
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
            interfaces,
            learning: LearningConfig::default(),
            thresholds: Thresholds::default(),
            escalation: Escalation::default(),
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

    /// Build the pure escalation config from the parsed settings.
    pub fn escalation_config(&self) -> crate::cidr::EscalationConfig {
        crate::cidr::EscalationConfig {
            min_src_drops: self.escalation.min_src_drops,
            min_sources: self.escalation.min_sources,
        }
    }

    /// CIDR block TTL in nanoseconds.
    pub fn block_ttl_ns(&self) -> u64 {
        self.escalation.block_ttl_secs * 1_000_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let cfg: Config = serde_yaml_ng::from_str("interfaces: [eno1, eno2]\n").unwrap();
        assert_eq!(cfg.interfaces, vec!["eno1", "eno2"]);
        // Defaults applied.
        assert_eq!(cfg.learning.port_ttl_secs, 600);
        assert_eq!(cfg.learning.gc_interval_secs, 60);
        assert_eq!(cfg.thresholds.syn_pps, 10_000);
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
        assert_eq!(cfg.interfaces, vec!["eno2"]);
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
    fn rejects_unknown_fields() {
        let err = serde_yaml_ng::from_str::<Config>("interfaces: [e]\nbogus: 1\n").unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}
