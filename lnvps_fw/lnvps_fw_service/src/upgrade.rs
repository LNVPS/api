//! Self-upgrade: check the GitHub releases API for a newer version, download
//! the packaged `.deb`, and install + restart the service in a detached
//! transient systemd unit (so the upgrade survives this process restarting).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// SHA-256 digest (hex) of the `.deb` asset as reported by GitHub, if any.
    /// Verified against the downloaded bytes before install.
    #[serde(default)]
    pub deb_sha256: Option<String>,
    /// Download URL of the matching `.deb.minisig` signature asset, if present.
    #[serde(default)]
    pub deb_sig_url: Option<String>,
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
    /// GitHub-computed digest, e.g. `"sha256:abcd..."` (newer API responses).
    #[serde(default)]
    digest: Option<String>,
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

/// Details of the `.deb` asset on a release.
struct DebAsset {
    url: String,
    /// SHA-256 hex digest from GitHub's `digest` field, if provided.
    sha256: Option<String>,
    /// URL of the matching `.deb.minisig` asset, if the release carries one.
    sig_url: Option<String>,
}

/// Query the latest GitHub release: returns `(tag, deb_asset)`.
async fn latest_release(repo: &str) -> Result<(String, Option<DebAsset>)> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let rel: GhRelease = client()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("parsing GitHub release JSON")?;
    let sig_url = rel
        .assets
        .iter()
        .find(|a| a.name.ends_with(".deb.minisig"))
        .map(|a| a.browser_download_url.clone());
    let deb = rel
        .assets
        .iter()
        .find(|a| a.name.ends_with(".deb"))
        .map(|a| DebAsset {
            url: a.browser_download_url.clone(),
            sha256: a
                .digest
                .as_ref()
                .and_then(|d| d.strip_prefix("sha256:"))
                .map(|h| h.to_ascii_lowercase()),
            sig_url: sig_url.clone(),
        });
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
            let (deb_url, deb_sha256, deb_sig_url) = match deb {
                Some(d) => (Some(d.url), d.sha256, d.sig_url),
                None => (None, None, None),
            };
            UpgradeStatus {
                current: current.to_string(),
                latest: Some(tag),
                available,
                deb_url,
                deb_sha256,
                deb_sig_url,
                checked_at: now_unix(),
                error: None,
            }
        }
        Err(e) => UpgradeStatus {
            current: current.to_string(),
            latest: None,
            available: false,
            deb_url: None,
            deb_sha256: None,
            deb_sig_url: None,
            checked_at: now_unix(),
            error: Some(e.to_string()),
        },
    }
}

/// Hex-encode a byte slice (lowercase).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Create a private, root-only staging directory and return an exclusive,
/// unpredictable path within it for the downloaded artifact. Avoids the
/// world-writable `/tmp` TOCTOU: an unprivileged local user cannot pre-create
/// or swap the file.
fn staging_path() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = Path::new("/run/lnvps_fw");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    // Randomized filename + O_EXCL so we never open an attacker-planted file.
    let mut rnd = [0u8; 16];
    getrandom::getrandom(&mut rnd).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let path = dir.join(format!("upgrade-{}.deb", hex(&rnd)));
    // Create it exclusively now (0600) to claim the name; download() truncates.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(path)
}

/// Full secure upgrade pipeline: download the `.deb`, verify its SHA-256
/// against the value GitHub reported (integrity), optionally verify a minisign
/// signature against the operator's pinned key (authenticity), then install +
/// restart. Any verification failure aborts before touching `dpkg`.
pub async fn download_verify_install(
    _repo: &str,
    url: &str,
    sha256: Option<String>,
    sig_url: Option<String>,
    pubkey: Option<String>,
) -> Result<()> {
    let dest = staging_path()?;
    let bytes = fetch_deb(url).await?;

    // 1. Integrity: match GitHub's reported digest when available.
    let got = hex(&Sha256::digest(&bytes));
    match &sha256 {
        Some(want) if *want != got => {
            let _ = std::fs::remove_file(&dest);
            bail!("sha256 mismatch: expected {want}, got {got}");
        }
        Some(_) => log::info!("upgrade: sha256 verified ({got})"),
        None => log::warn!("upgrade: release has no sha256 digest to verify against"),
    }

    // 2. Authenticity: if a pinned minisign key is configured, a valid
    //    signature is REQUIRED (fail closed).
    if let Some(key) = pubkey {
        let Some(sig_url) = sig_url else {
            let _ = std::fs::remove_file(&dest);
            bail!("upgrade-pubkey configured but release has no .deb.minisig asset");
        };
        verify_minisign(&key, url, &sig_url, &bytes)
            .await
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&dest);
            })?;
        log::info!("upgrade: minisign signature verified");
    }

    std::fs::write(&dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;
    log::warn!("upgrade: installing {url} and restarting");
    let r = install_and_restart(&dest, "lnvps_fw");
    // Only clean up here if the detached install unit never started. On success
    // the unit runs `dpkg` asynchronously (systemd-run returns immediately), so
    // the parent must NOT delete the .deb — the unit removes it after dpkg.
    if r.is_err() {
        let _ = std::fs::remove_file(&dest);
    }
    r
}

/// Fetch + sanity-check that the body is an `ar` archive (a `.deb`).
async fn fetch_deb(url: &str) -> Result<Vec<u8>> {
    let bytes = client()?
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if bytes.len() < 128 || &bytes[..8] != b"!<arch>\n" {
        bail!("downloaded file is not a .deb archive");
    }
    Ok(bytes.to_vec())
}

/// Download the `.deb.minisig` and verify it over `bytes` using `key`.
async fn verify_minisign(key: &str, deb_url: &str, sig_url: &str, bytes: &[u8]) -> Result<()> {
    use minisign_verify::{PublicKey, Signature};
    // Accept either a bare base64 key line or a full two-line key file.
    let key_line = key
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with("untrusted comment:"))
        .unwrap_or(key)
        .trim();
    let pk = PublicKey::from_base64(key_line)
        .map_err(|e| anyhow::anyhow!("invalid upgrade-pubkey: {e}"))?;
    let sig_text = client()?
        .get(sig_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
        .with_context(|| format!("downloading signature {sig_url}"))?;
    let sig = Signature::decode(&sig_text)
        .map_err(|e| anyhow::anyhow!("decoding minisig for {deb_url}: {e}"))?;
    pk.verify(bytes, &sig, false)
        .map_err(|e| anyhow::anyhow!("signature verification failed: {e}"))
}



/// Install `deb` and restart `unit` in a detached transient systemd unit, so the
/// install completes even though restarting the service kills this process.
pub fn install_and_restart(deb: &Path, unit: &str) -> Result<()> {
    // The .deb is removed inside this detached unit *after* dpkg installs it
    // (systemd-run is fire-and-forget, so cleaning it up in the parent would
    // race the dpkg here and delete the archive before it is read).
    let script = format!(
        "dpkg -i '{deb}' && rm -f '{deb}' && systemctl restart {unit}",
        deb = deb.display(),
    );
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
    use super::{hex, is_newer};
    use sha2::{Digest, Sha256};

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        // Known SHA-256 of the empty input.
        assert_eq!(
            hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

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
