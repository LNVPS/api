//! Garbage collection of learned open ports.
//!
//! The TC egress program stamps each learned `(ip, port, proto)` entry with a
//! `bpf_ktime_get_ns` timestamp and refreshes it on subsequent matching
//! traffic. Userspace periodically sweeps the maps and removes entries that
//! have not been refreshed within the configured TTL, so ports that a VM stops
//! serving are eventually forgotten.

use aya::Pod;

use lnvps_fw_common::LastSeen;

/// Current value of the monotonic clock in nanoseconds, matching the clock
/// used by `bpf_ktime_get_ns` (both derive from `CLOCK_MONOTONIC`).
pub fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid pointer never fails for MONOTONIC.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// True if an entry last seen at `last_seen_ns` is older than `ttl_ns` at
/// `now_ns`. A clock that appears to move backwards (e.g. `last_seen` in the
/// future relative to `now`) is treated as not expired.
#[inline]
pub fn is_expired(last_seen_ns: u64, now_ns: u64, ttl_ns: u64) -> bool {
    now_ns.saturating_sub(last_seen_ns) > ttl_ns
}

/// Select the expired keys from a pre-scanned learned-ports snapshot (pure —
/// the scan itself is done batched by the caller, so the sweep costs one
/// syscall per ~4k entries instead of two per entry).
pub fn expired_ports<K>(
    entries: &[(K, LastSeen)],
    now_ns: u64,
    tcp_ttl_ns: u64,
    udp_ttl_ns: u64,
    proto_of: impl Fn(&K) -> u8,
) -> Vec<K>
where
    K: Pod,
{
    entries
        .iter()
        .filter(|(k, v)| {
            let ttl_ns = if proto_of(k) == lnvps_fw_common::PROTO_UDP {
                udp_ttl_ns
            } else {
                tcp_ttl_ns
            };
            is_expired(v.last_seen, now_ns, ttl_ns)
        })
        .map(|(k, _)| *k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u64 = 600 * 1_000_000_000; // 600s in ns

    #[test]
    fn fresh_entry_not_expired() {
        let now = 1_000 * 1_000_000_000;
        assert!(!is_expired(now, now, TTL));
    }

    #[test]
    fn entry_at_exactly_ttl_not_expired() {
        let now = 1_000 * 1_000_000_000;
        assert!(!is_expired(now - TTL, now, TTL));
    }

    #[test]
    fn entry_past_ttl_expired() {
        let now = 1_000 * 1_000_000_000;
        assert!(is_expired(now - TTL - 1, now, TTL));
    }

    #[test]
    fn future_timestamp_not_expired() {
        let now = 1_000 * 1_000_000_000;
        assert!(!is_expired(now + 5, now, TTL));
    }

    #[test]
    fn monotonic_now_is_nonzero_and_advances() {
        let a = monotonic_now_ns();
        let b = monotonic_now_ns();
        assert!(a > 0);
        assert!(b >= a);
    }
}
