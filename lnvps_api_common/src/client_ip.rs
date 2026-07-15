use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::convert::Infallible;
use std::net::IpAddr;

/// Extractor for the originating client IP address.
///
/// The API always runs behind a reverse proxy (and the GSL -> AVS scrubbing
/// path), so the peer socket address is never the real client. The client IP is
/// therefore read from forwarding headers set by the trusted front proxy:
///
/// 1. `X-Forwarded-For` — the left-most (original client) entry, or
/// 2. `X-Real-IP` — a single address.
///
/// This is best-effort: the value is only used as *one* non-contradictory piece
/// of place-of-supply evidence for EU VAT and is never trusted for
/// authentication. Extraction never fails; the address is `None` when no usable
/// header is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    /// Parse the client IP out of a set of request headers.
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        // X-Forwarded-For: client, proxy1, proxy2 -> take the left-most entry.
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            for part in xff.split(',') {
                if let Some(ip) = parse_ip(part) {
                    return ClientIp(Some(ip));
                }
            }
        }
        if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok())
            && let Some(ip) = parse_ip(xri)
        {
            return ClientIp(Some(ip));
        }
        ClientIp(None)
    }
}

/// Parse a single IP token, tolerating surrounding whitespace and an optional
/// `:port` suffix on IPv4 or `[addr]:port` bracketing on IPv6.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // [2001:db8::1]:443 or [2001:db8::1]
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].parse::<IpAddr>().ok();
    }
    // 1.2.3.4:443 (only strip a port when exactly one ':' is present so we
    // don't mangle a bare IPv6 address).
    if s.matches(':').count() == 1
        && let Some((host, _port)) = s.rsplit_once(':')
    {
        return host.parse::<IpAddr>().ok();
    }
    None
}

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp::from_headers(&parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use std::str::FromStr;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_str(k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parses_plain_ipv4() {
        let ip = ClientIp::from_headers(&headers(&[("x-forwarded-for", "203.0.113.7")]));
        assert_eq!(ip.0, Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn takes_leftmost_of_chain() {
        let ip = ClientIp::from_headers(&headers(&[(
            "x-forwarded-for",
            "203.0.113.7, 70.41.3.18, 150.172.238.178",
        )]));
        assert_eq!(ip.0, Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn strips_ipv4_port() {
        let ip = ClientIp::from_headers(&headers(&[("x-forwarded-for", "203.0.113.7:51234")]));
        assert_eq!(ip.0, Some("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn parses_bare_ipv6() {
        let ip = ClientIp::from_headers(&headers(&[("x-forwarded-for", "2001:db8::1")]));
        assert_eq!(ip.0, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let ip = ClientIp::from_headers(&headers(&[("x-forwarded-for", "[2001:db8::1]:443")]));
        assert_eq!(ip.0, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn falls_back_to_x_real_ip() {
        let ip = ClientIp::from_headers(&headers(&[("x-real-ip", "198.51.100.9")]));
        assert_eq!(ip.0, Some("198.51.100.9".parse().unwrap()));
    }

    #[test]
    fn none_when_absent_or_garbage() {
        assert_eq!(ClientIp::from_headers(&HeaderMap::new()).0, None);
        let ip = ClientIp::from_headers(&headers(&[("x-forwarded-for", "not-an-ip")]));
        assert_eq!(ip.0, None);
    }

    #[tokio::test]
    async fn from_request_parts_extractor() {
        use axum::extract::FromRequestParts;
        let req = axum::http::Request::builder()
            .header("x-forwarded-for", "198.51.100.9, 10.0.0.1")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let ip = ClientIp::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(ip.0, Some("198.51.100.9".parse().unwrap()));
    }
}
