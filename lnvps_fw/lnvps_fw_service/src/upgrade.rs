//! Self-upgrade: check the GitHub releases API for a newer version, download
//! the packaged `.deb`, and install + restart the service in a detached
//! transient systemd unit (so the upgrade survives this process restarting).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Upgrade availability, cached by the daemon and served over the API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpgradeStatus {
    /// The running version.
    pub current: String,
    /// The latest release tag (e.g. `v0.1.1`), if the check succeeded.
    pub latest: Option<String>,
    /// True if `latest` is newer than `current` and a `.deb` asset exists.
    pub available: bool,
    /// Download URL of the `.deb` asset on the latest release.
    pub deb_url: Option<String>,
    /// Unix time of the last check.
    pub checked_at: u64,
    /// Error from the last check, if any.
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("lnvps_fw/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building http client")
}

/// Query the latest GitHub release: returns `(tag, deb_download_url)`.
async fn latest_release(repo: &str) -> Result<(String, Option<String>)> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let rel: GhRelease = client()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("parsing GitHub release JSON")?;
    let deb = rel
        .assets
        .into_iter()
        .find(|a| a.name.ends_with(".deb"))
        .map(|a| a.browser_download_url);
    Ok((rel.tag_name, deb))
}

/// True if `latest` (e.g. `v0.1.1`) is a newer semantic version than `current`
/// (e.g. `0.1.0`). Falls back to string inequality if either doesn't parse.
pub fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u64, u64, u64)> {
        let v = v.trim().trim_start_matches('v');
        let mut it = v
            .split('.')
            .map(|x| x.split(['-', '+']).next().unwrap_or(x).parse::<u64>().ok());
        Some((it.next()??, it.next()??, it.next()??))
    }
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => latest.trim().trim_start_matches('v') != current.trim(),
    }
}

/// Check for an available upgrade (never fails; errors are captured).
pub async fn check(repo: &str, current: &str) -> UpgradeStatus {
    match latest_release(repo).await {
        Ok((tag, deb)) => {
            let available = deb.is_some() && is_newer(&tag, current);
            UpgradeStatus {
                current: current.to_string(),
                latest: Some(tag),
                available,
                deb_url: deb,
                checked_at: now_unix(),
                error: None,
            }
        }
        Err(e) => UpgradeStatus {
            current: current.to_string(),
            latest: None,
            available: false,
            deb_url: None,
            checked_at: now_unix(),
            error: Some(e.to_string()),
        },
    }
}

/// Download `url` to `dest`, validating it looks like a Debian package.
pub async fn download(url: &str, dest: &Path) -> Result<()> {
    let bytes = client()?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    // A .deb is an `ar` archive: the magic is `!<arch>\n`.
    if bytes.len() < 128 || &bytes[..8] != b"!<arch>\n" {
        bail!("downloaded file is not a .deb archive");
    }
    std::fs::write(dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

/// Install `deb` and restart `unit` in a detached transient systemd unit, so the
/// install completes even though restarting the service kills this process.
pub fn install_and_restart(deb: &Path, unit: &str) -> Result<()> {
    let script = format!("dpkg -i '{}' && systemctl restart {}", deb.display(), unit);
    let status = std::process::Command::new("systemd-run")
        .args([
            "--collect",
            "--unit",
            "lnvps-fw-upgrade",
            "/bin/sh",
            "-c",
            &script,
        ])
        .status()
        .context("spawning systemd-run (needs root + systemd)")?;
    if !status.success() {
        bail!("systemd-run exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn version_comparison() {
        assert!(is_newer("v0.1.1", "0.1.0"));
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.1"));
        // Pre-release / build suffixes are ignored on the patch component.
        assert!(is_newer("v0.1.2-rc1", "0.1.1"));
        // Non-semver falls back to string inequality.
        assert!(is_newer("nightly", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
    }

    // Hits the live GitHub API; run with:
    //   cargo test -p lnvps_fw_service --lib upgrade -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "network: queries the live GitHub releases API"]
    async fn live_latest_release() {
        let status = super::check("LNVPS/api", env!("CARGO_PKG_VERSION")).await;
        println!("current  = {}", status.current);
        println!("latest   = {:?}", status.latest);
        println!("available= {}", status.available);
        println!("deb_url  = {:?}", status.deb_url);
        println!("error    = {:?}", status.error);
    }
}
