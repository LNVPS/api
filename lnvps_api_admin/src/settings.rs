use lnvps_api_common::RedisConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// Listen address for http server
    pub listen: Option<String>,

    /// Public URL this admin API is served on, e.g. `https://admin.lnvps.net`.
    ///
    /// Used to bind NIP-98 `u` tags to this host so an auth event signed for
    /// another origin cannot be replayed here. When unset the host portion of
    /// the `u` tag is not checked (path and method still are).
    pub public_url: Option<String>,

    /// MYSQL connection string
    pub db: String,

    /// Redis configuration for shared VM state cache
    pub redis: Option<RedisConfig>,

    /// Database encryption configuration (fallback when the
    /// `LNVPS_ENCRYPTION_KEY` environment variable is not set)
    pub encryption: Option<EncryptionConfig>,
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
