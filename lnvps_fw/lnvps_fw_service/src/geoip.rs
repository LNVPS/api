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

use std::net::IpAddr;
use std::path::Path;

use log::{info, warn};
use maxminddb::{Reader, geoip2, path};
use serde::{Deserialize, Serialize};

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
}
