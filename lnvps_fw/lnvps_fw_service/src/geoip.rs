//! Optional GeoIP enrichment for IPs listed on the control API.
//!
//! Every IP the API returns (attacker sources on `/sources` and `/blocks`,
//! destinations on `/tracked`, `/prefixes`, `/mitigations`) can be annotated
//! with `{asn, org, country}` looked up from MaxMind GeoLite2 databases. The
//! operator supplies the `.mmdb` files (the GeoLite2 EULA forbids bundling
//! them in the `.deb`); when no database is configured, enrichment is silently
//! skipped and the geo fields are simply absent from the JSON.
//!
//! Enrichment happens at response-build time, not on the detection hot path,
//! and API pages are bounded, so the lookup cost is negligible.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use log::{info, warn};
use maxminddb::{Reader, geoip2, path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::config::GeoIpConfig;

/// MaxMind's permanent direct-download endpoint (keyed by a license key).
const MAXMIND_DOWNLOAD: &str = "https://download.maxmind.com/app/geoip_download";
/// The two GeoLite2 editions this service consumes.
pub const EDITION_ASN: &str = "GeoLite2-ASN";
pub const EDITION_COUNTRY: &str = "GeoLite2-Country";

/// Per-IP enrichment flattened onto each API item. Every field is optional and
/// omitted from the JSON when unknown, so an item with no geo data serialises
/// exactly as it did before enrichment existed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoInfo {
    /// Autonomous System Number the IP is announced from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// AS / ISP organisation name (from the GeoLite2-ASN database).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    /// ISO 3166-1 alpha-2 country code (from the GeoLite2-Country database).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl GeoInfo {
    /// True when no field is populated (used to decide whether a lookup found
    /// anything at all).
    pub fn is_empty(&self) -> bool {
        self.asn.is_none() && self.org.is_none() && self.country.is_none()
    }
}

/// Loaded MaxMind readers. Either reader may be absent; a lookup fills whatever
/// fields the available databases provide.
pub struct GeoIp {
    asn: Option<Reader<Vec<u8>>>,
    country: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    /// Open the configured databases. A path that fails to open is logged and
    /// treated as absent rather than aborting startup — enrichment is a
    /// best-effort convenience, never a hard dependency.
    pub fn load(asn_db: Option<&Path>, country_db: Option<&Path>) -> Self {
        let open = |p: &Path, kind: &str| match Reader::open_readfile(p) {
            Ok(r) => {
                info!("GeoIP {kind} database loaded from {}", p.display());
                Some(r)
            }
            Err(e) => {
                warn!(
                    "GeoIP {kind} database at {} could not be opened ({e}); \
                     {kind} enrichment disabled",
                    p.display()
                );
                None
            }
        };
        Self {
            asn: asn_db.and_then(|p| open(p, "ASN")),
            country: country_db.and_then(|p| open(p, "country")),
        }
    }

    /// True when at least one database is loaded (nothing to do otherwise).
    pub fn enabled(&self) -> bool {
        self.asn.is_some() || self.country.is_some()
    }

    /// Look up an IP, returning whatever fields the loaded databases provide.
    /// Missing databases, missing records, and decode errors all degrade to an
    /// absent field rather than an error.
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let mut info = GeoInfo::default();
        if let Some(reader) = &self.asn
            && let Ok(res) = reader.lookup(ip)
            && let Ok(Some(asn)) = res.decode::<geoip2::Asn>()
        {
            info.asn = asn.autonomous_system_number;
            info.org = asn.autonomous_system_organization.map(str::to_string);
        }
        if let Some(reader) = &self.country
            && let Ok(res) = reader.lookup(ip)
            && let Ok(cc) = res.decode_path::<String>(&path!["country", "iso_code"])
        {
            info.country = cc;
        }
        info
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("lnvps_fw/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building geoip http client")
}

/// True if `path` exists and was last modified within `max_age`.
fn is_fresh(path: &Path, max_age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|age| age < max_age)
        .unwrap_or(false)
}

/// Extract the first `*.mmdb` member from a GeoLite2 `.tar.gz` archive (the
/// archive wraps the database in a dated directory alongside COPYRIGHT/LICENSE).
fn extract_mmdb(targz: &[u8]) -> Result<Vec<u8>> {
    let mut ar = Archive::new(GzDecoder::new(targz));
    for entry in ar.entries().context("reading tar archive")? {
        let mut e = entry.context("reading tar entry")?;
        let is_mmdb = e
            .path()
            .ok()
            .and_then(|p| p.extension().map(|x| x == "mmdb"))
            .unwrap_or(false);
        if is_mmdb {
            let mut buf = Vec::new();
            e.read_to_end(&mut buf)
                .context("reading mmdb from archive")?;
            return Ok(buf);
        }
    }
    bail!("archive contained no .mmdb file")
}

/// Write `bytes` to `dest` atomically (temp file + rename), creating parents.
fn atomic_write(dest: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = dest.with_extension("mmdb.tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, dest).with_context(|| format!("installing {}", dest.display()))?;
    Ok(())
}

/// Download one edition to `dest_dir/<edition>.mmdb`, verifying the companion
/// SHA-256 when present. Returns the installed path. The license key is only
/// ever placed in the request URL — never logged.
pub async fn download_edition(
    client: &reqwest::Client,
    license_key: &str,
    edition: &str,
    dest_dir: &Path,
) -> Result<PathBuf> {
    let base = format!("{MAXMIND_DOWNLOAD}?edition_id={edition}&license_key={license_key}");
    let targz = client
        .get(format!("{base}&suffix=tar.gz"))
        .send()
        .await
        .context("requesting archive")?
        .error_for_status()
        .context("archive http status")?
        .bytes()
        .await
        .context("reading archive body")?
        .to_vec();
    // Companion digest line is "<hex>  <edition>_<date>.tar.gz".
    if let Ok(resp) = client
        .get(format!("{base}&suffix=tar.gz.sha256"))
        .send()
        .await
        && let Ok(resp) = resp.error_for_status()
        && let Ok(text) = resp.text().await
        && let Some(want) = text.split_whitespace().next()
    {
        let got = hex(&Sha256::digest(&targz));
        if !want.eq_ignore_ascii_case(&got) {
            bail!("{edition}: sha256 mismatch (expected {want}, got {got})");
        }
    }
    let mmdb = extract_mmdb(&targz).with_context(|| format!("extracting {edition}"))?;
    let dest = dest_dir.join(format!("{edition}.mmdb"));
    atomic_write(&dest, &mmdb)?;
    info!(
        "GeoIP {edition} downloaded to {} ({} bytes)",
        dest.display(),
        mmdb.len()
    );
    Ok(dest)
}

/// Return a usable path for `edition`: a fresh cached copy if one exists,
/// otherwise a freshly downloaded one. On download failure a stale cached copy
/// is used if present; `None` only when nothing usable exists. `force` skips
/// the freshness check (used by the periodic refresh).
async fn cached_or_download(
    client: &reqwest::Client,
    key: &str,
    edition: &str,
    dir: &Path,
    max_age: Duration,
    force: bool,
) -> Option<PathBuf> {
    let dest = dir.join(format!("{edition}.mmdb"));
    if !force && is_fresh(&dest, max_age) {
        info!("GeoIP {edition} is up to date, skipping download");
        return Some(dest);
    }
    match download_edition(client, key, edition, dir).await {
        Ok(p) => Some(p),
        Err(e) => {
            if dest.exists() {
                warn!(
                    "GeoIP {edition} download failed ({e}); using existing {}",
                    dest.display()
                );
                Some(dest)
            } else {
                warn!("GeoIP {edition} download failed ({e}); that field stays disabled");
                None
            }
        }
    }
}

/// Resolve the ASN and country database paths from config, downloading via the
/// license key any path not given explicitly. `state_dir` is the default
/// download location. `force` re-downloads even when the cached copy is fresh.
pub async fn resolve_databases(
    cfg: &GeoIpConfig,
    state_dir: &Path,
    force: bool,
) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut asn = cfg.asn_db.clone();
    let mut country = cfg.country_db.clone();
    if let Some(key) = cfg.license_key.as_deref() {
        let dir = cfg
            .download_dir
            .clone()
            .unwrap_or_else(|| state_dir.to_path_buf());
        let max_age = Duration::from_secs(cfg.refresh_interval_hours.max(1) as u64 * 3600);
        match http_client() {
            Ok(client) => {
                if asn.is_none() {
                    asn = cached_or_download(&client, key, EDITION_ASN, &dir, max_age, force).await;
                }
                if country.is_none() {
                    country =
                        cached_or_download(&client, key, EDITION_COUNTRY, &dir, max_age, force)
                            .await;
                }
            }
            Err(e) => warn!("GeoIP auto-download disabled: {e}"),
        }
    }
    (asn, country)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_databases_yield_empty_lookup() {
        let geo = GeoIp::load(None, None);
        assert!(!geo.enabled());
        let info = geo.lookup("1.1.1.1".parse().unwrap());
        assert!(info.is_empty());
    }

    #[test]
    fn bad_path_is_treated_as_absent() {
        let geo = GeoIp::load(
            Some(Path::new("/nonexistent/GeoLite2-ASN.mmdb")),
            Some(Path::new("/nonexistent/GeoLite2-Country.mmdb")),
        );
        assert!(!geo.enabled());
        assert!(geo.lookup("8.8.8.8".parse().unwrap()).is_empty());
    }

    #[test]
    fn geoinfo_is_empty_semantics() {
        assert!(GeoInfo::default().is_empty());
        let g = GeoInfo {
            asn: Some(13335),
            ..Default::default()
        };
        assert!(!g.is_empty());
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    }

    /// Build a GeoLite2-shaped .tar.gz in memory (mmdb nested in a dated dir
    /// alongside a LICENSE file) and confirm the mmdb bytes are extracted.
    #[test]
    fn extract_mmdb_finds_nested_database() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let payload = b"\xab\xcdFAKE-MMDB-BYTES";
        let mut tar_buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_buf);
            let mut add = |name: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, data).unwrap();
            };
            add("GeoLite2-ASN_20240102/LICENSE.txt", b"license");
            add("GeoLite2-ASN_20240102/GeoLite2-ASN.mmdb", payload);
            b.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_buf).unwrap();
        let targz = gz.finish().unwrap();

        assert_eq!(extract_mmdb(&targz).unwrap(), payload);
    }

    #[test]
    fn extract_mmdb_errors_without_database() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let mut tar_buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_buf);
            let data = b"nope";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "dir/readme.txt", &data[..]).unwrap();
            b.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_buf).unwrap();
        assert!(extract_mmdb(&gz.finish().unwrap()).is_err());
    }

    #[test]
    fn atomic_write_then_fresh() {
        let dir = std::env::temp_dir().join(format!("lnvps_geoip_test_{}", std::process::id()));
        let dest = dir.join("sub").join("GeoLite2-ASN.mmdb");
        atomic_write(&dest, b"hello").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        assert!(is_fresh(&dest, Duration::from_secs(3600)));
        assert!(!is_fresh(&dest, Duration::ZERO));
        assert!(!is_fresh(
            &dir.join("missing.mmdb"),
            Duration::from_secs(3600)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn resolve_without_key_uses_explicit_paths_only() {
        let cfg = GeoIpConfig {
            asn_db: Some(PathBuf::from("/x/asn.mmdb")),
            ..Default::default()
        };
        let (asn, country) = resolve_databases(&cfg, Path::new("/tmp"), false).await;
        assert_eq!(asn, Some(PathBuf::from("/x/asn.mmdb")));
        assert_eq!(country, None);
    }

    /// Live end-to-end download; set MAXMIND_LICENSE_KEY to run.
    #[tokio::test]
    #[ignore = "requires network + MAXMIND_LICENSE_KEY"]
    async fn live_download_editions() {
        let Ok(key) = std::env::var("MAXMIND_LICENSE_KEY") else {
            return;
        };
        let cfg = GeoIpConfig {
            license_key: Some(key),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("lnvps_geoip_live");
        let (asn, country) = resolve_databases(&cfg, &dir, true).await;
        let geo = GeoIp::load(asn.as_deref(), country.as_deref());
        assert!(geo.enabled());
        let info = geo.lookup("1.1.1.1".parse().unwrap());
        assert_eq!(info.asn, Some(13335), "1.1.1.1 is Cloudflare AS13335");
    }
}
