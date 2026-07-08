//! CIDR escalation logic (pure userspace).
//!
//! Under mitigation the datapath rate-limits each source individually and
//! flags over-rate sources by incrementing a per-source drop counter. This
//! module aggregates those offenders: when enough distinct source addresses
//! within the same aggregation prefix (a /24 for IPv4, /64 for IPv6) misbehave
//! in one sample window, the whole prefix is escalated to a hard block
//! installed in the datapath's LPM trie.
//!
//! Keeping the aggregation free of BPF handles makes it fully unit-testable;
//! [`crate::runtime`] wires it to the maps and applies TTL-based decay.

use std::collections::HashMap;

/// IPv4 aggregation prefix length (group offenders by /24).
pub const V4_AGG_PREFIX: u32 = 24;
/// IPv6 aggregation prefix length (group offenders by /64).
pub const V6_AGG_PREFIX: u32 = 64;

/// A CIDR to block: prefix length plus the network address bytes (host-order
/// significant bytes first, i.e. exactly as they appear on the wire), with the
/// bits below the prefix zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrV4 {
    pub prefix_len: u32,
    pub network: [u8; 4],
}

/// IPv6 equivalent of [`CidrV4`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrV6 {
    pub prefix_len: u32,
    pub network: [u8; 16],
}

/// Thresholds controlling when a prefix is escalated.
#[derive(Debug, Clone, Copy)]
pub struct EscalationConfig {
    /// A source counts as an offender if its per-window drop delta is at least
    /// this many packets.
    pub min_src_drops: u64,
    /// A prefix is blocked once at least this many distinct offending sources
    /// fall within it.
    pub min_sources: usize,
}

/// Zero the host bits below `/24` of an IPv4 address.
fn network_v4(addr: [u8; 4]) -> [u8; 4] {
    [addr[0], addr[1], addr[2], 0]
}

/// Zero the host bits below `/64` of an IPv6 address (keep the first 8 bytes).
fn network_v6(addr: [u8; 16]) -> [u8; 16] {
    let mut net = [0u8; 16];
    net[..8].copy_from_slice(&addr[..8]);
    net
}

/// Given `(source, drops_this_window)` deltas, return the IPv4 /24 prefixes
/// that should be blocked. Deterministically sorted for stable behaviour.
pub fn offending_cidrs_v4(deltas: &[([u8; 4], u64)], cfg: &EscalationConfig) -> Vec<CidrV4> {
    let mut groups: HashMap<[u8; 4], usize> = HashMap::new();
    for (src, drops) in deltas {
        if *drops >= cfg.min_src_drops {
            *groups.entry(network_v4(*src)).or_default() += 1;
        }
    }
    let mut out: Vec<CidrV4> = groups
        .into_iter()
        .filter(|(_, count)| *count >= cfg.min_sources)
        .map(|(network, _)| CidrV4 {
            prefix_len: V4_AGG_PREFIX,
            network,
        })
        .collect();
    out.sort_by(|a, b| a.network.cmp(&b.network));
    out
}

/// IPv6 /64 equivalent of [`offending_cidrs_v4`].
pub fn offending_cidrs_v6(deltas: &[([u8; 16], u64)], cfg: &EscalationConfig) -> Vec<CidrV6> {
    let mut groups: HashMap<[u8; 16], usize> = HashMap::new();
    for (src, drops) in deltas {
        if *drops >= cfg.min_src_drops {
            *groups.entry(network_v6(*src)).or_default() += 1;
        }
    }
    let mut out: Vec<CidrV6> = groups
        .into_iter()
        .filter(|(_, count)| *count >= cfg.min_sources)
        .map(|(network, _)| CidrV6 {
            prefix_len: V6_AGG_PREFIX,
            network,
        })
        .collect();
    out.sort_by(|a, b| a.network.cmp(&b.network));
    out
}

/// Compute per-source drop deltas between the previous and current cumulative
/// snapshots. Sources whose counters reset (LRU eviction) contribute a zero
/// delta. Returns owned `(src, delta)` pairs for every source in `cur`.
pub fn drop_deltas<K: Copy + Eq + std::hash::Hash>(
    prev: &HashMap<K, u64>,
    cur: &[(K, u64)],
) -> Vec<(K, u64)> {
    cur.iter()
        .map(|(k, c)| {
            let p = prev.get(k).copied().unwrap_or(0);
            (*k, c.saturating_sub(p))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: EscalationConfig = EscalationConfig {
        min_src_drops: 10,
        min_sources: 3,
    };

    #[test]
    fn blocks_v24_when_enough_sources_offend() {
        let deltas = [
            ([10, 0, 5, 1], 50),
            ([10, 0, 5, 2], 50),
            ([10, 0, 5, 9], 50),
            ([10, 0, 5, 40], 5), // below min_src_drops, ignored
        ];
        let blocks = offending_cidrs_v4(&deltas, &CFG);
        assert_eq!(
            blocks,
            vec![CidrV4 {
                prefix_len: 24,
                network: [10, 0, 5, 0]
            }]
        );
    }

    #[test]
    fn does_not_block_below_min_sources() {
        let deltas = [([10, 0, 5, 1], 50), ([10, 0, 5, 2], 50)];
        assert!(offending_cidrs_v4(&deltas, &CFG).is_empty());
    }

    #[test]
    fn separates_distinct_v24s() {
        let deltas = [
            ([10, 0, 5, 1], 50),
            ([10, 0, 5, 2], 50),
            ([10, 0, 5, 3], 50),
            ([10, 0, 6, 1], 50), // different /24, only one source
        ];
        let blocks = offending_cidrs_v4(&deltas, &CFG);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].network, [10, 0, 5, 0]);
    }

    #[test]
    fn ignores_repeat_of_same_source() {
        // Same source appearing once with a big delta is still one source.
        let deltas = [([10, 0, 5, 1], 1_000)];
        assert!(offending_cidrs_v4(&deltas, &CFG).is_empty());
    }

    #[test]
    fn v6_blocks_by_64() {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0]);
        let mk = |last: u8| {
            let mut x = a;
            x[15] = last;
            x
        };
        let deltas = [(mk(1), 50), (mk(2), 50), (mk(3), 50)];
        let blocks = offending_cidrs_v6(&deltas, &CFG);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].prefix_len, 64);
        assert_eq!(&blocks[0].network[..8], &a[..8]);
        assert_eq!(&blocks[0].network[8..], &[0u8; 8]);
    }

    #[test]
    fn drop_deltas_handles_new_and_reset_sources() {
        let mut prev = HashMap::new();
        prev.insert([1, 1, 1, 1], 100u64);
        prev.insert([2, 2, 2, 2], 50u64);
        let cur = [
            ([1, 1, 1, 1], 130), // +30
            ([2, 2, 2, 2], 10),  // reset -> 0
            ([3, 3, 3, 3], 7),   // new -> 7
        ];
        let mut d = drop_deltas(&prev, &cur);
        d.sort();
        assert_eq!(
            d,
            vec![([1, 1, 1, 1], 30), ([2, 2, 2, 2], 0), ([3, 3, 3, 3], 7)]
        );
    }
}
