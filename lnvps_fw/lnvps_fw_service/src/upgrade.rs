//! Self-upgrade: check the GitHub releases API for a newer version, download
//! the packaged `.deb`, and install + restart the service in a detached
//! transient systemd unit (so the upgrade survives this process restarting).
//!
//! The firewall releases on its own tag (`lnvps_fw-vX.Y.Z`), separately from
//! the main API's `vX.Y.Z` tags, so this cannot use `/releases/latest`: that is
//! repo-wide and usually returns an API release carrying no `.deb` at all. It
//! instead lists releases and picks the newest one that actually ships a
//! firewall package — see [`select_release`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Tag prefix carried by firewall releases (`lnvps_fw-v0.5.0`), mirroring the
/// `nixos-image-v*` convention used for the other independently-released
/// artifact in this repo.
pub const RELEASE_TAG_PREFIX: &str = "lnvps_fw-v";

/// Filename prefix of the packaged firewall `.deb` (as produced by
/// `cargo deb`: `lnvps-fw_0.5.0-1_amd64.deb`). Used to recognise a release that
/// actually carries a firewall build, rather than any release with any `.deb`.
const DEB_ASSET_PREFIX: &str = "lnvps-fw";

/// The version part of a release tag: `lnvps_fw-v0.5.0` and the legacy
/// `v0.5.0` both yield `0.5.0`.
fn tag_version(tag: &str) -> &str {
    let t = tag.trim();
    t.strip_prefix(RELEASE_TAG_PREFIX)
        .unwrap_or_else(|| t.trim_start_matches('v'))
}

/// Upgrade availability, cached by the daemon and served over the API.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpgradeStatus {
    /// The running version.
    pub current: String,
    /// The latest firewall release tag (e.g. `lnvps_fw-v0.5.0`), if the check
    /// succeeded.
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
    draft: bool,
    #[serde(default)]
    prerelease: bool,
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

/// The firewall `.deb` (and its signature) on one release, if it carries one.
fn deb_asset(rel: &GhRelease) -> Option<DebAsset> {
    let is_fw = |n: &str| n.starts_with(DEB_ASSET_PREFIX);
    let sig_url = rel
        .assets
        .iter()
        .find(|a| is_fw(&a.name) && a.name.ends_with(".deb.minisig"))
        .map(|a| a.browser_download_url.clone());
    rel.assets
        .iter()
        .find(|a| is_fw(&a.name) && a.name.ends_with(".deb"))
        .map(|a| DebAsset {
            url: a.browser_download_url.clone(),
            sha256: a
                .digest
                .as_ref()
                .and_then(|d| d.strip_prefix("sha256:"))
                .map(|h| h.to_ascii_lowercase()),
            sig_url,
        })
}

/// Pick the newest published release that actually ships a firewall `.deb`.
///
/// Selection is by *asset*, not by tag pattern, for two reasons: it ignores
/// main-API releases (`vX.Y.Z`, no firewall package) without having to guess
/// which tag shapes this repo uses, and it keeps working across the tag change
/// — a legacy `vX.Y.Z` release that still carries a firewall `.deb` remains
/// upgradeable to, so a daemon installed before the split is not stranded.
/// Drafts and pre-releases are skipped, matching `/releases/latest` semantics.
///
/// Ordering is by the version parsed from the tag rather than by GitHub's
/// listing order (creation date), so re-cutting an old release cannot present
/// itself as newer than the current one.
fn select_release(rels: Vec<GhRelease>) -> Option<(String, DebAsset)> {
    rels.into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter_map(|r| deb_asset(&r).map(|d| (r.tag_name, d)))
        .max_by_key(|(tag, _)| semver(tag_version(tag)).unwrap_or((0, 0, 0)))
}

/// Query the newest firewall release: returns `(tag, deb_asset)`.
async fn latest_release(repo: &str) -> Result<(String, Option<DebAsset>)> {
    // One page is ample: releases are listed newest-first, and the firewall
    // ships far more often than 100 releases would take to bury.
    let url = format!("https://api.github.com/repos/{repo}/releases?per_page=100");
    let rels: Vec<GhRelease> = client()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("parsing GitHub releases JSON")?;
    match select_release(rels) {
        Some((tag, deb)) => Ok((tag, Some(deb))),
        // No firewall release at all (fresh repo / all drafts): report the
        // check as successful with nothing available, not as an error.
        None => Ok((String::new(), None)),
    }
}

/// Parse a bare `X.Y.Z` version, ignoring any pre-release/build suffix.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v
        .trim()
        .split('.')
        .map(|x| x.split(['-', '+']).next().unwrap_or(x).parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// True if release tag `latest` (`lnvps_fw-v0.5.0`, or the legacy `v0.5.0`) is
/// a newer semantic version than the running `current` (`0.4.7`). Falls back to
/// string inequality if either doesn't parse; an empty tag (no release found)
/// is never newer.
pub fn is_newer(latest: &str, current: &str) -> bool {
    let (l, c) = (tag_version(latest), current.trim());
    if l.is_empty() {
        return false;
    }
    match (semver(l), semver(c)) {
        (Some(l), Some(c)) => l > c,
        _ => l != c,
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
///
/// MUST be the unit's `StateDirectory` (`/var/lib/lnvps_fw`), NOT its
/// `RuntimeDirectory` (`/run/lnvps_fw`): `dpkg -i` stops the old service
/// mid-install (prerm), and systemd removes the RuntimeDirectory on service
/// stop (`RuntimeDirectoryPreserve=no` default) — deleting the staged archive
/// out from under dpkg (`cannot access archive`). The StateDirectory persists
/// across stops/restarts.
fn staging_path() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = Path::new("/var/lib/lnvps_fw");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    // Staged archives now persist across restarts: sweep leftovers from any
    // earlier failed/aborted upgrade before claiming a new name.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("upgrade-") && name.ends_with(".deb") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
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
    use super::{GhAsset, GhRelease, hex, is_newer, select_release, tag_version};
    use sha2::{Digest, Sha256};

    /// A published release with the given tag and asset names.
    fn rel(tag: &str, assets: &[&str]) -> GhRelease {
        GhRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: assets
                .iter()
                .map(|n| GhAsset {
                    name: (*n).into(),
                    browser_download_url: format!("https://example.invalid/{n}"),
                    digest: Some("sha256:AB".into()),
                })
                .collect(),
        }
    }

    const FW_DEB: &str = "lnvps-fw_0.5.0-1_amd64.deb";

    #[test]
    fn tag_version_strips_both_tag_forms() {
        assert_eq!(tag_version("lnvps_fw-v0.5.0"), "0.5.0");
        assert_eq!(tag_version("v0.4.7"), "0.4.7"); // legacy shared tag
        assert_eq!(tag_version(" 0.4.7 "), "0.4.7");
    }

    /// The newest release *carrying a firewall .deb* wins — API releases on the
    /// main `v*` tags carry none and must never be reported as an upgrade.
    #[test]
    fn select_release_ignores_releases_without_a_firewall_deb() {
        let rels = vec![
            rel("v9.9.9", &["lnvps-api-linux-amd64.tar.gz"]), // newest, but no .deb
            rel(
                "lnvps_fw-v0.5.0",
                &[FW_DEB, "lnvps-fw_0.5.0-1_amd64.deb.minisig"],
            ),
            rel("v0.4.7", &["lnvps-fw_0.4.7-1_amd64.deb"]), // legacy fw release
        ];
        let (tag, deb) = select_release(rels).expect("a firewall release");
        assert_eq!(tag, "lnvps_fw-v0.5.0");
        assert!(deb.url.ends_with(FW_DEB));
        assert_eq!(deb.sha256.as_deref(), Some("ab"), "digest lower-cased");
        assert!(deb.sig_url.is_some(), "signature asset picked up");
    }

    /// A daemon installed before the tag split must still find the legacy
    /// release, so it is never stranded on an un-upgradeable version.
    #[test]
    fn select_release_accepts_a_legacy_tag_when_it_is_the_only_firewall_build() {
        let rels = vec![
            rel("v9.9.9", &[]),
            rel("v0.4.7", &["lnvps-fw_0.4.7-1_amd64.deb"]),
        ];
        let (tag, _) = select_release(rels).expect("legacy release");
        assert_eq!(tag, "v0.4.7");
    }

    /// Ordering is by parsed version, not GitHub's listing order, so re-cutting
    /// an older release cannot masquerade as the newest.
    #[test]
    fn select_release_orders_by_version_not_listing_order() {
        let rels = vec![
            rel("lnvps_fw-v0.4.9", &["lnvps-fw_0.4.9-1_amd64.deb"]),
            rel("lnvps_fw-v0.10.0", &["lnvps-fw_0.10.0-1_amd64.deb"]),
        ];
        let (tag, _) = select_release(rels).expect("a release");
        assert_eq!(tag, "lnvps_fw-v0.10.0", "0.10.0 > 0.4.9");
    }

    #[test]
    fn select_release_skips_drafts_and_prereleases() {
        let draft = GhRelease {
            draft: true,
            ..rel("lnvps_fw-v0.9.0", &["lnvps-fw_0.9.0-1_amd64.deb"])
        };
        let pre = GhRelease {
            prerelease: true,
            ..rel("lnvps_fw-v0.8.0", &["lnvps-fw_0.8.0-1_amd64.deb"])
        };
        let rels = vec![draft, pre, rel("lnvps_fw-v0.5.0", &[FW_DEB])];
        let (tag, _) = select_release(rels).expect("a published release");
        assert_eq!(tag, "lnvps_fw-v0.5.0");
        // Nothing published at all -> no upgrade, not a panic.
        assert!(select_release(vec![]).is_none());
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        // Known SHA-256 of the empty input.
        assert_eq!(
            hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// The prefixed tag must compare as a version, not as a string: without
    /// stripping it, `lnvps_fw-v0.4.7` would fall back to string inequality
    /// against `0.4.7` and every daemon would report a perpetual upgrade.
    #[test]
    fn version_comparison_across_tag_prefixes() {
        assert!(is_newer("lnvps_fw-v0.5.0", "0.4.7"));
        assert!(!is_newer("lnvps_fw-v0.4.7", "0.4.7"));
        assert!(!is_newer("lnvps_fw-v0.4.6", "0.4.7"));
        // Legacy tags stay comparable during the transition.
        assert!(is_newer("v0.5.0", "0.4.7"));
        // No firewall release found -> nothing to upgrade to.
        assert!(!is_newer("", "0.4.7"));
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
