use anyhow::Result;
use isocountry::CountryCode;
use log::trace;
use maxminddb::{Reader, geoip2};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// Resolve an IP address to a country for VAT place-of-supply evidence.
///
/// Implementations return an ISO 3166-1 **alpha-3** country code (to match the
/// `users.country_code` storage convention) or `None` when the address cannot
/// be attributed to a country (private/reserved ranges, missing DB entry, ...).
///
/// Lookups are expected to be cheap and local (a MaxMind DB lookup is on the
/// order of microseconds), so this is a synchronous trait and callers may run
/// it inline on the request path.
pub trait CountryResolver: Send + Sync {
    fn resolve(&self, ip: IpAddr) -> Option<String>;
}

impl<T: CountryResolver + ?Sized> CountryResolver for Arc<T> {
    fn resolve(&self, ip: IpAddr) -> Option<String> {
        (**self).resolve(ip)
    }
}

/// Returns `true` for addresses that can never yield useful geolocation
/// (loopback, private, link-local, unspecified, unique-local IPv6, ...).
fn is_non_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique local (fc00::/7)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link local (fe80::/10)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Convert an ISO 3166-1 alpha-2 code to alpha-3, returning `None` for unknowns.
pub fn alpha2_to_alpha3(alpha2: &str) -> Option<String> {
    CountryCode::for_alpha2(&alpha2.to_uppercase())
        .ok()
        .map(|c| c.alpha3().to_string())
}

/// [`CountryResolver`] backed by a local MaxMind GeoLite2/GeoIP2 Country
/// database (`.mmdb`). The whole file is read into memory once at construction;
/// lookups are then pure in-memory and never touch the network.
pub struct MaxmindCountryResolver {
    reader: Reader<Vec<u8>>,
}

impl MaxmindCountryResolver {
    /// Open a MaxMind Country (or City) database from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let reader = Reader::open_readfile(path)?;
        Ok(Self { reader })
    }
}

impl CountryResolver for MaxmindCountryResolver {
    fn resolve(&self, ip: IpAddr) -> Option<String> {
        if is_non_routable(&ip) {
            trace!("Skipping geolocation for non-routable address {}", ip);
            return None;
        }
        let looked = match self.reader.lookup(ip) {
            Ok(r) => r,
            Err(e) => {
                trace!("Geolocation lookup failed for {}: {}", ip, e);
                return None;
            }
        };
        let country: Option<geoip2::Country> = looked.decode().ok()?;
        let iso = country?.country.iso_code?;
        alpha2_to_alpha3(iso)
    }
}

/// No-op resolver that always returns `None` (used when geolocation is disabled
/// or the database path is not configured).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCountryResolver;

impl CountryResolver for NoopCountryResolver {
    fn resolve(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha2_conversion() {
        assert_eq!(alpha2_to_alpha3("DE").as_deref(), Some("DEU"));
        assert_eq!(alpha2_to_alpha3("ie").as_deref(), Some("IRL"));
        assert_eq!(alpha2_to_alpha3("ZZ"), None);
    }

    #[test]
    fn non_routable_detection() {
        assert!(is_non_routable(&"127.0.0.1".parse().unwrap()));
        assert!(is_non_routable(&"10.0.0.1".parse().unwrap()));
        assert!(is_non_routable(&"192.168.1.1".parse().unwrap()));
        assert!(is_non_routable(&"::1".parse().unwrap()));
        assert!(is_non_routable(&"fd00::1".parse().unwrap()));
        assert!(is_non_routable(&"fe80::1".parse().unwrap()));
        assert!(!is_non_routable(&"8.8.8.8".parse().unwrap()));
        assert!(!is_non_routable(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn noop_resolver_returns_none() {
        let r = NoopCountryResolver;
        assert_eq!(r.resolve("203.0.113.7".parse().unwrap()), None);
    }

    #[test]
    fn arc_dyn_resolver_delegates() {
        let r: Arc<dyn CountryResolver> = Arc::new(NoopCountryResolver);
        assert_eq!(r.resolve("203.0.113.7".parse().unwrap()), None);
    }
}
