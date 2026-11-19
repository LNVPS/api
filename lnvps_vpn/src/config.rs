//! What `lvd` needs to start.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct VpnConfig {
    /// Base URL of the LNVPS API, e.g. `https://api.lnvps.net`.
    pub api_url: String,

    /// This route server's credential, `<router_id>.<secret>`.
    ///
    /// Static, and provisioned by hand with everything else about the machine.
    /// There is nothing to register: unlike a marketplace node, which is
    /// somebody else's hardware enrolling itself, a route server is LNVPS's own
    /// and exists in the database before it is ever switched on.
    pub token: String,

    /// Seconds to ask LNVPS to hold a fetch open waiting for a change.
    ///
    /// Zero turns the wait off and makes this an ordinary poll. The server caps
    /// it, so setting it higher than the server's limit is not an error, it is
    /// just capped.
    #[serde(default = "default_wait_secs")]
    pub wait_secs: u64,

    /// Seconds to wait before fetching again after a failure.
    ///
    /// Deliberately short. The daemon is idle almost all of the time, so the
    /// cost of retrying is nothing, and the thing being delayed is a
    /// revocation.
    #[serde(default = "default_retry_secs")]
    pub retry_secs: u64,

    /// Seconds a peer may go without a handshake before its recorded endpoint
    /// is scrubbed. See [`crate::scrub`].
    #[serde(default = "default_scrub_after_secs")]
    pub scrub_after_secs: u64,
}

fn default_wait_secs() -> u64 {
    25
}

fn default_retry_secs() -> u64 {
    5
}

/// Ten minutes, which is Mullvad's figure and a reasonable one: long enough
/// that a laptop closing its lid for a moment does not have to renegotiate,
/// short enough that an address is not kept for an afternoon.
fn default_scrub_after_secs() -> u64 {
    600
}

impl VpnConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read {}", path.display()))?;
        let config: Self = serde_yaml_ng::from_str(&text)
            .with_context(|| format!("Cannot parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Check what can be checked without contacting anything.
    ///
    /// Run at startup rather than on first use, so a typo in the config is a
    /// message at boot instead of an interface that never appears.
    pub fn validate(&self) -> Result<()> {
        if !self.api_url.starts_with("https://") && !self.api_url.starts_with("http://") {
            bail!("api-url must be an http or https URL, got {}", self.api_url);
        }
        // The id is checked here because it is the half of the token that can
        // be wrong in a way LNVPS answers with a flat 401, which reads like a
        // bad secret and sends an operator looking in the wrong place.
        match self.token.split_once('.') {
            Some((id, secret)) if id.parse::<u64>().is_ok() && !secret.is_empty() => {}
            _ => bail!("token must be <router_id>.<secret>"),
        }
        Ok(())
    }

    pub fn wait(&self) -> Duration {
        Duration::from_secs(self.wait_secs)
    }

    pub fn retry(&self) -> Duration {
        Duration::from_secs(self.retry_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_config() -> VpnConfig {
        VpnConfig {
            api_url: "https://api.lnvps.net".to_string(),
            token: "7.s3cret".to_string(),
            wait_secs: 25,
            retry_secs: 5,
            scrub_after_secs: 600,
        }
    }

    #[test]
    fn a_good_config_passes() {
        a_config().validate().unwrap();
    }

    #[test]
    fn a_token_without_a_router_id_is_refused_at_startup() {
        // Rather than at the first fetch, where LNVPS answers 401 and an
        // operator goes looking at the secret.
        for bad in ["s3cret", "seven.s3cret", "7.", "7"] {
            let mut c = a_config();
            c.token = bad.to_string();
            assert!(c.validate().is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn an_api_url_that_is_not_a_url_is_refused() {
        let mut c = a_config();
        c.api_url = "api.lnvps.net".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_minimal_file_loads_and_fills_in_the_rest() {
        let dir = std::env::temp_dir().join(format!("lvd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(&path, "api-url: https://api.lnvps.net\ntoken: 7.s3cret\n").unwrap();

        let config = VpnConfig::load(&path).unwrap();

        assert_eq!(config.api_url, "https://api.lnvps.net");
        assert_eq!(config.wait_secs, 25);
        assert_eq!(config.retry_secs, 5);
        // Mullvad's figure, and the one this defends.
        assert_eq!(config.scrub_after_secs, 600);
        assert_eq!(config.wait(), Duration::from_secs(25));
        assert_eq!(config.retry(), Duration::from_secs(5));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_with_a_key_that_does_not_exist_is_refused() {
        let dir = std::env::temp_dir().join(format!("lvd-typo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        // `deny_unknown_fields`, so a typo is a message at startup rather than
        // a setting that silently does nothing.
        std::fs::write(
            &path,
            "api-url: https://api.lnvps.net\ntoken: 7.s3cret\nwait_secs: 5\n",
        )
        .unwrap();

        assert!(VpnConfig::load(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_that_is_not_there_says_so() {
        let err = VpnConfig::load(Path::new("/nonexistent/lvd.yaml")).unwrap_err();
        assert!(format!("{err:#}").contains("Cannot read"), "{err:#}");
    }

    #[test]
    fn the_shipped_example_is_a_config_this_build_accepts() {
        // Otherwise the file an operator copies is the one thing never tested.
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.yaml");
        VpnConfig::load(&example).unwrap();
    }
}
