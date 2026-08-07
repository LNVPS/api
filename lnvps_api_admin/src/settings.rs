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

    /// Redis configuration for shared VM state cache
    pub redis: Option<RedisConfig>,

    /// Database encryption configuration (fallback when the
    /// `LNVPS_ENCRYPTION_KEY` environment variable is not set)
    pub encryption: Option<EncryptionConfig>,

    /// Marketplace config: the key LNVPS controls its nodes with. Absent in a
    /// deployment that runs no marketplace, where every node call is refused
    /// with that reason rather than with a missing-key panic.
    pub marketplace: Option<lnvps_api_common::node_control::MarketplaceConfig>,

    /// Per-IP API rate limiting. Enabled unless explicitly turned off, which
    /// is only intended for the E2E suite (hundreds of requests a minute from
    /// one address).
    #[serde(default)]
    pub rate_limit: lnvps_api_common::RateLimitConfig,
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
