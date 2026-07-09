//! Garbage collection of learned open ports.
//!
//! The TC egress program stamps each learned `(ip, port, proto)` entry with a
//! `bpf_ktime_get_ns` timestamp and refreshes it on subsequent matching
//! traffic. Userspace periodically sweeps the maps and removes entries that
//! have not been refreshed within the configured TTL, so ports that a VM stops
//! serving are eventually forgotten.

use aya::Pod;
use aya::maps::{HashMap, MapData};

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

/// Sweep one learned-ports map, removing entries older than `ttl_ns`. Returns
/// the number of entries removed.
pub fn gc_open_ports<K>(
    map: &mut HashMap<&mut MapData, K, LastSeen>,
    now_ns: u64,
    tcp_ttl_ns: u64,
    udp_ttl_ns: u64,
    proto_of: impl Fn(&K) -> u8,
) -> usize
where
    K: Pod,
{
    // Collect keys first so the immutable iterator borrow is released before
    // the mutable removals.
    let keys: Vec<K> = map.keys().flatten().collect();
    let mut removed = 0;
    for k in keys {
        let ttl_ns = if proto_of(&k) == lnvps_fw_common::PROTO_UDP {
            udp_ttl_ns
        } else {
            tcp_ttl_ns
        };
        if let Ok(v) = map.get(&k, 0)
            && is_expired(v.last_seen, now_ns, ttl_ns)
            && map.remove(&k).is_ok()
        {
            removed += 1;
        }
    }
    removed
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
