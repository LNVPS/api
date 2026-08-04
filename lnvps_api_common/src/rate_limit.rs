//! In-process, per-client-IP fixed-window rate limiting for the public API.
//!
//! The API has no edge rate limiter, so brute-force-sensitive endpoints (auth
//! ceremony starts, verification-code confirms) and expensive actions (VM
//! provisioning, host power operations) need in-process protection. This is a
//! deliberately small dependency-free implementation: a fixed window counter
//! per (bucket, client IP) keyed off the same forwarding headers [`ClientIp`]
//! uses, with a bounded map so untracked-key memory cannot grow without limit.
//!
//! Being per-process it is not exact across multiple API replicas, but every
//! replica enforces the limit independently, which is sufficient to blunt
//! single-source brute force and resource-exhaustion abuse.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::ClientIp;

/// Hard cap on tracked (bucket, IP) pairs. Beyond this the oldest entries are
/// dropped, which is safe: an attacker spreading across many IPs just gets
/// their oldest counters reset — they can never exceed the limit *per* IP.
const MAX_TRACKED_KEYS: usize = 100_000;

/// A named rate-limit bucket: `max` requests per `window` per client IP.
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    /// Requests allowed within the window.
    pub max: u32,
    /// Window length.
    pub window: Duration,
}

impl RateLimit {
    /// Limit for the general API surface.
    pub const fn general() -> Self {
        Self {
            max: 600,
            window: Duration::from_secs(60),
        }
    }

    /// Strict limit for authentication-start and verification endpoints that
    /// guard brute-forceable secrets (OAuth login, WebAuthn ceremonies,
    /// WhatsApp/Telegram/email verification).
    pub const fn auth() -> Self {
        Self {
            max: 10,
            window: Duration::from_secs(60),
        }
    }
}

struct Bucket {
    count: u32,
    window_start: Instant,
    last_seen: Instant,
}

/// Shared, cheap-to-clone rate limiter state.
#[derive(Clone)]
pub struct RateLimiter {
    strict: Arc<Mutex<HashMap<(IpAddr, &'static str), Bucket>>>,
    general: Arc<Mutex<HashMap<(IpAddr, &'static str), Bucket>>>,
    strict_limit: RateLimit,
    general_limit: RateLimit,
    /// Path prefixes subject to the strict bucket (e.g. auth ceremony starts,
    /// verification confirms). Matched case-sensitively against
    /// `request.uri().path()`.
    strict_prefixes: &'static [&'static str],
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimit::auth(), RateLimit::general(), STRICT_PREFIXES)
    }
}

impl RateLimiter {
    /// Build a limiter with explicit per-bucket limits and strict prefixes.
    pub fn new(
        strict_limit: RateLimit,
        general_limit: RateLimit,
        strict_prefixes: &'static [&'static str],
    ) -> Self {
        Self {
            strict: Arc::new(Mutex::new(HashMap::new())),
            general: Arc::new(Mutex::new(HashMap::new())),
            strict_limit,
            general_limit,
            strict_prefixes,
        }
    }

    /// Whether `path` falls into the strict (brute-force-sensitive) bucket.
    fn is_strict(&self, path: &str) -> bool {
        self.strict_prefixes.iter().any(|p| path.starts_with(p))
            || STRICT_SUFFIXES.iter().any(|s| path.ends_with(s))
    }

    /// Check and record one request from `ip` for `path`. Returns the number
    /// of seconds until the current window resets when the limit is exceeded.
    pub fn check(&self, ip: IpAddr, path: &str) -> Result<(), u64> {
        let (map, limit) = if self.is_strict(path) {
            (&self.strict, self.strict_limit)
        } else {
            (&self.general, self.general_limit)
        };
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        evict_if_full(&mut guard);
        let now = Instant::now();
        let bucket = guard.entry((ip, "req")).or_insert(Bucket {
            count: 0,
            window_start: now,
            last_seen: now,
        });
        bucket.last_seen = now;
        if now.duration_since(bucket.window_start) >= limit.window {
            bucket.count = 0;
            bucket.window_start = now;
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > limit.max {
            let reset = limit
                .window
                .saturating_sub(now.duration_since(bucket.window_start));
            return Err(reset.as_secs().max(1));
        }
        Ok(())
    }
}

/// Fixed-window rate limiter keyed by user id rather than client IP.
///
/// Some actions cost real money or send a message to a third party, and must be
/// bounded per *account* — an attacker with many source addresses trivially
/// defeats a per-IP bucket for those.
pub struct UserRateLimiter {
    buckets: Mutex<HashMap<u64, Bucket>>,
    max: u32,
    window: Duration,
}

impl UserRateLimiter {
    /// Allow `max` actions per `window` per user.
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max,
            window,
        }
    }

    /// Record one action for `user_id`, returning seconds until the window
    /// resets when the limit is exceeded.
    pub fn check(&self, user_id: u64) -> Result<(), u64> {
        let mut guard = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        // Bound memory: drop entries whose window has fully elapsed.
        guard.retain(|_, b| now.duration_since(b.window_start) < self.window);

        let bucket = guard.entry(user_id).or_insert(Bucket {
            count: 0,
            window_start: now,
            last_seen: now,
        });
        bucket.last_seen = now;
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.count = 0;
            bucket.window_start = now;
        }
        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > self.max {
            let reset = self
                .window
                .saturating_sub(now.duration_since(bucket.window_start));
            return Err(reset.as_secs().max(1));
        }
        Ok(())
    }
}

/// Drop the stalest entries once the map is at capacity.
fn evict_if_full(map: &mut HashMap<(IpAddr, &'static str), Bucket>) {
    if map.len() < MAX_TRACKED_KEYS {
        return;
    }
    // Remove the oldest 10% by last_seen — enough to amortise the sweep.
    let mut by_age: Vec<(IpAddr, &'static str, Instant)> =
        map.iter().map(|(k, b)| (k.0, k.1, b.last_seen)).collect();
    by_age.sort_by_key(|(_, _, t)| *t);
    for (ip, tag, _) in by_age.into_iter().take(MAX_TRACKED_KEYS / 10) {
        map.remove(&(ip, tag));
    }
}

/// Path prefixes guarded by the strict bucket: anything that starts an auth
/// ceremony, confirms a brute-forceable code/token, or lets an unauthenticated
/// caller make us do expensive work.
const STRICT_PREFIXES: &[&str] = &[
    "/api/v1/oauth/",
    "/api/v1/webauthn/login",
    "/api/v1/webauthn/register",
    "/api/v1/account/verify-email",
    "/api/v1/account/whatsapp/verify",
    "/api/v1/account/whatsapp/confirm",
    "/api/v1/contact",
    // Unauthenticated LNURL-pay surface. `/.well-known/lnurlp/{id}` is a VM-id
    // enumeration oracle and the renew callback mints a real Lightning invoice
    // (a DB row plus node state) per request.
    "/.well-known/lnurlp/",
];

// NOTE: ticket minting (`/api/v1/auth/ticket`) is deliberately NOT strict. It
// requires full authentication and guards no brute-forceable secret, so the
// strict bucket buys nothing — while a user opening several invoices, or a
// console that reconnects, would hit 10/min immediately and start seeing 429s.
// The general bucket is the right home for it.

/// Suffixes guarded by the strict bucket, matched against the whole path.
///
/// Used where the abuse-prone segment is not a prefix, e.g. the LNURL renew
/// callback sits under the per-VM path `/api/v1/vm/{id}/renew-lnurlp`.
const STRICT_SUFFIXES: &[&str] = &["/renew-lnurlp"];

/// Resolve the client IP the same way handlers do (forwarding headers first),
/// falling back to the peer socket address when no headers are present.
fn request_ip(req: &Request<Body>) -> Option<IpAddr> {
    if let Some(ip) = ClientIp::from_headers(req.headers()).0 {
        return Some(ip);
    }
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Axum middleware enforcing the per-IP fixed-window limits. Exceeding the
/// limit yields `429 Too Many Requests` with a `Retry-After` hint.
///
/// A request whose IP cannot be resolved is counted against a shared
/// `UNRESOLVED_IP` bucket rather than being waved through. Previously such
/// requests skipped rate limiting entirely, so anything reaching the socket
/// without forwarding headers (a misconfigured LB, in-cluster access, a leaked
/// origin address) was unlimited. The server now supplies `ConnectInfo`, so in
/// practice this bucket should stay empty; it is the fail-closed backstop.
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let ip = bucket_ip(&req);
    if let Err(retry_after) = limiter.check(ip, &path) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", retry_after.to_string())],
            "Rate limit exceeded",
        )
            .into_response();
    }
    next.run(req).await
}

/// Bucket key for requests with no resolvable client address.
///
/// `100::` is the IPv6 discard prefix (RFC 6666) — never a real client, so it
/// cannot collide with a genuine peer's bucket.
const UNRESOLVED_IP: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0));

/// The address a request is billed to, falling back to [`UNRESOLVED_IP`] so a
/// request can never escape the limiter entirely.
fn bucket_ip(req: &Request<Body>) -> IpAddr {
    request_ip(req).unwrap_or(UNRESOLVED_IP)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(strict_max: u32, general_max: u32) -> RateLimiter {
        RateLimiter::new(
            RateLimit {
                max: strict_max,
                window: Duration::from_secs(60),
            },
            RateLimit {
                max: general_max,
                window: Duration::from_secs(60),
            },
            STRICT_PREFIXES,
        )
    }

    #[test]
    fn general_bucket_allows_up_to_max_then_blocks() {
        let l = limiter(2, 3);
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(l.check(ip, "/api/v1/vm").is_ok());
        assert!(l.check(ip, "/api/v1/vm").is_ok());
        assert!(l.check(ip, "/api/v1/vm").is_ok());
        assert!(l.check(ip, "/api/v1/vm").is_err());
    }

    #[test]
    fn strict_bucket_applies_to_auth_paths_only() {
        let l = limiter(2, 100);
        let ip: IpAddr = "203.0.113.2".parse().unwrap();
        assert!(l.check(ip, "/api/v1/webauthn/login/start").is_ok());
        assert!(l.check(ip, "/api/v1/webauthn/login/finish").is_ok());
        // Third call on the strict path exceeds the strict limit...
        assert!(l.check(ip, "/api/v1/webauthn/login/start").is_err());
        // ...but a non-strict path for the same IP uses the general bucket.
        assert!(l.check(ip, "/api/v1/vm").is_ok());
    }

    #[test]
    fn limits_are_per_ip() {
        let l = limiter(1, 1);
        let a: IpAddr = "203.0.113.3".parse().unwrap();
        let b: IpAddr = "203.0.113.4".parse().unwrap();
        assert!(l.check(a, "/api/v1/vm").is_ok());
        assert!(l.check(a, "/api/v1/vm").is_err());
        // A different IP has its own budget.
        assert!(l.check(b, "/api/v1/vm").is_ok());
    }

    #[test]
    fn window_reset_allows_requests_again() {
        let l = RateLimiter::new(
            RateLimit {
                max: 1,
                window: Duration::from_millis(20),
            },
            RateLimit {
                max: 1,
                window: Duration::from_millis(20),
            },
            STRICT_PREFIXES,
        );
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(l.check(ip, "/api/v1/vm").is_ok());
        assert!(l.check(ip, "/api/v1/vm").is_err());
        std::thread::sleep(Duration::from_millis(25));
        assert!(l.check(ip, "/api/v1/vm").is_ok());
    }

    #[test]
    fn eviction_keeps_map_bounded() {
        let mut map = HashMap::new();
        for i in 0..MAX_TRACKED_KEYS {
            map.insert(
                (
                    IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8]),
                    "req",
                ),
                Bucket {
                    count: 1,
                    window_start: Instant::now(),
                    last_seen: Instant::now(),
                },
            );
        }
        evict_if_full(&mut map);
        assert!(map.len() <= MAX_TRACKED_KEYS - MAX_TRACKED_KEYS / 10);
    }

    /// Regression (F-13): the unauthenticated LNURL-pay surface must land in
    /// the strict bucket. `/.well-known/lnurlp/{id}` is an enumeration oracle
    /// and the renew callback mints a real Lightning invoice per request.
    #[test]
    fn lnurlp_paths_are_strict() {
        let l = limiter(1, 100);
        let ip: IpAddr = "203.0.113.6".parse().unwrap();

        assert!(l.check(ip, "/.well-known/lnurlp/42").is_ok());
        // Second request exhausts the strict budget, proving it is not using
        // the general bucket (which allows 100 here).
        assert!(l.check(ip, "/.well-known/lnurlp/42").is_err());

        // The renew callback is matched by suffix, not prefix.
        let l = limiter(1, 100);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(l.check(ip, "/api/v1/vm/1/renew-lnurlp").is_ok());
        assert!(l.check(ip, "/api/v1/vm/1/renew-lnurlp").is_err());
    }

    /// The ordinary per-VM renew endpoint is authenticated and must stay in the
    /// general bucket — the suffix match must not catch it.
    #[test]
    fn authenticated_renew_stays_general() {
        let l = limiter(1, 100);
        let ip: IpAddr = "203.0.113.8".parse().unwrap();

        assert!(l.check(ip, "/api/v1/vm/1/renew").is_ok());
        assert!(l.check(ip, "/api/v1/vm/1/renew").is_ok());
    }

    /// Ticket minting must stay in the general bucket. It is authenticated and
    /// guards no brute-forceable secret, and a client legitimately mints one
    /// per invoice opened or console reconnect — the strict bucket's 10/min
    /// would start returning 429 during ordinary use.
    #[test]
    fn ticket_minting_stays_general() {
        let l = limiter(1, 100);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        for _ in 0..20 {
            assert!(
                l.check(ip, "/api/v1/auth/ticket").is_ok(),
                "ticket minting must not hit the strict bucket"
            );
        }
    }

    /// Regression (F-08): a request with no resolvable IP used to skip the
    /// limiter entirely (the middleware only counted it `if let Some(ip)`).
    /// It must now be billed to the shared fallback bucket, so anything
    /// reaching the socket without forwarding headers is still limited.
    #[test]
    fn unresolvable_ip_falls_back_to_shared_bucket() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(request_ip(&req), None, "precondition: no resolvable IP");
        assert_eq!(bucket_ip(&req), UNRESOLVED_IP);

        // And that bucket is enforced like any other.
        let l = limiter(1, 1);
        assert!(l.check(UNRESOLVED_IP, "/api/v1/vm").is_ok());
        assert!(
            l.check(UNRESOLVED_IP, "/api/v1/vm").is_err(),
            "requests without a resolvable IP must not bypass the limiter"
        );
    }

    /// A resolvable request is billed to its own address, not the fallback.
    #[test]
    fn resolvable_ip_is_used_as_the_bucket_key() {
        let req = Request::builder()
            .header("x-real-ip", "198.51.100.7")
            .body(Body::empty())
            .unwrap();
        assert_eq!(bucket_ip(&req), "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    /// Regression (F-15): WhatsApp verification sends were bounded only by the
    /// per-IP bucket, so an attacker spreading across addresses could pump
    /// messages at arbitrary numbers on our bill from a single account. Costly
    /// actions need a per-*account* cap.
    #[test]
    fn user_limiter_bounds_per_account() {
        let l = UserRateLimiter::new(2, Duration::from_secs(3600));

        assert!(l.check(1).is_ok());
        assert!(l.check(1).is_ok());
        let retry = l.check(1).expect_err("third send must be refused");
        assert!(retry > 0, "a refusal must carry a retry hint");

        // A different account has its own budget — the cap is per user, not
        // global.
        assert!(l.check(2).is_ok());
    }

    /// The per-user window resets, so a legitimate user is never locked out
    /// permanently.
    #[test]
    fn user_limiter_window_resets() {
        let l = UserRateLimiter::new(1, Duration::from_millis(20));

        assert!(l.check(1).is_ok());
        assert!(l.check(1).is_err());

        std::thread::sleep(Duration::from_millis(25));
        assert!(l.check(1).is_ok());
    }

    #[test]
    fn request_ip_prefers_forwarding_headers_then_connect_info() {
        // Header present -> used.
        let req = Request::builder()
            .header("x-real-ip", "198.51.100.7")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request_ip(&req),
            Some("198.51.100.7".parse::<IpAddr>().unwrap())
        );

        // No header, ConnectInfo present -> peer address used.
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::new(
                "203.0.113.9".parse().unwrap(),
                1234,
            )));
        assert_eq!(
            request_ip(&req),
            Some("203.0.113.9".parse::<IpAddr>().unwrap())
        );

        // Neither -> None (middleware lets the request through).
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(request_ip(&req), None);
    }
}
