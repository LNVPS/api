//! Source-blocking + CIDR aggregation logic (pure userspace).
//!
//! Under mitigation the eBPF datapath only *counts* packets per source (in a
//! bounded LRU map) and enforces the CIDR block trie. All the rate math and the
//! decision of *what* to block lives here:
//!
//! 1. compute per-source packets/second from consecutive counter snapshots
//!    ([`per_source_pps`]),
//! 2. pick offenders exceeding the per-source limit ([`offenders`]),
//! 3. aggregate offenders into as few LPM-trie entries as possible
//!    ([`aggregate_v4`] / [`aggregate_v6`]): individual `/32`s collapse to a
//!    `/24`, `/24`s to a `/16`, up to `/8` (and the IPv6 equivalents), so the
//!    trie stays bounded even under a large distributed/spoofed flood.
//!
//! Keeping this free of BPF handles makes it fully unit-testable.

use std::collections::HashMap;
use std::hash::Hash;

/// A blocked IPv4 CIDR: prefix length + network address (bits below the prefix
/// zeroed, bytes exactly as on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrV4 {
    pub prefix_len: u32,
    pub network: [u8; 4],
}

/// A blocked IPv6 CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrV6 {
    pub prefix_len: u32,
    pub network: [u8; 16],
}

/// IPv4 aggregation levels, widest cap first is applied last: offenders start
/// as /32 and collapse toward /8.
const V4_LEVELS: [u32; 3] = [24, 16, 8];
/// IPv6 aggregation levels: offenders start as /128 and collapse toward /32.
const V6_LEVELS: [u32; 3] = [64, 48, 32];

/// Zero the host bits of a byte-aligned IPv4 prefix.
fn mask_v4(addr: [u8; 4], prefix: u32) -> [u8; 4] {
    let bytes = (prefix / 8) as usize;
    let mut out = [0u8; 4];
    out[..bytes].copy_from_slice(&addr[..bytes]);
    out
}

/// Zero the host bits of a byte-aligned IPv6 prefix.
fn mask_v6(addr: [u8; 16], prefix: u32) -> [u8; 16] {
    let bytes = (prefix / 8) as usize;
    let mut out = [0u8; 16];
    out[..bytes].copy_from_slice(&addr[..bytes]);
    out
}

/// Compute per-source packets/second from the previous and current cumulative
/// counter snapshots. Sources whose counters reset (LRU eviction) yield 0.
pub fn per_source_pps<K: Copy + Eq + Hash>(
    prev: &HashMap<K, u64>,
    cur: &[(K, u64)],
    elapsed_ns: u64,
) -> Vec<(K, u64)> {
    if elapsed_ns == 0 {
        return Vec::new();
    }
    cur.iter()
        .map(|(k, c)| {
            let p = prev.get(k).copied().unwrap_or(0);
            let delta = c.saturating_sub(p);
            let pps = ((delta as u128 * 1_000_000_000u128) / elapsed_ns as u128) as u64;
            (*k, pps)
        })
        .collect()
}

/// Select the sources whose per-second rate is at or above `min_pps`.
pub fn offenders<K: Copy>(rates: &[(K, u64)], min_pps: u64) -> Vec<K> {
    rates
        .iter()
        .filter(|(_, pps)| *pps >= min_pps)
        .map(|(k, _)| *k)
        .collect()
}

/// Aggregate offending IPv4 sources into the fewest CIDR blocks. A parent
/// prefix replaces its children once at least `fanout` distinct children fall
/// under it; otherwise the children are blocked individually. `fanout` of 0 or
/// 1 is treated as 2 (a single child never widens).
pub fn aggregate_v4(offenders: &[[u8; 4]], fanout: usize) -> Vec<CidrV4> {
    let fanout = fanout.max(2);
    let mut blocks: Vec<CidrV4> = dedup(offenders.iter().map(|a| CidrV4 {
        prefix_len: 32,
        network: *a,
    }));
    for &target in &V4_LEVELS {
        blocks = collapse_v4(blocks, target, fanout);
    }
    blocks.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
    blocks
}

/// IPv6 equivalent of [`aggregate_v4`].
pub fn aggregate_v6(offenders: &[[u8; 16]], fanout: usize) -> Vec<CidrV6> {
    let fanout = fanout.max(2);
    let mut blocks: Vec<CidrV6> = dedup(offenders.iter().map(|a| CidrV6 {
        prefix_len: 128,
        network: *a,
    }));
    for &target in &V6_LEVELS {
        blocks = collapse_v6(blocks, target, fanout);
    }
    blocks.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
    blocks
}

fn dedup<C: Eq + Hash + Copy>(it: impl Iterator<Item = C>) -> Vec<C> {
    let mut seen: Vec<C> = Vec::new();
    for c in it {
        if !seen.contains(&c) {
            seen.push(c);
        }
    }
    seen
}

fn collapse_v4(blocks: Vec<CidrV4>, target: u32, fanout: usize) -> Vec<CidrV4> {
    let mut groups: HashMap<[u8; 4], Vec<CidrV4>> = HashMap::new();
    let mut keep: Vec<CidrV4> = Vec::new();
    for b in blocks {
        if b.prefix_len > target {
            groups
                .entry(mask_v4(b.network, target))
                .or_default()
                .push(b);
        } else {
            keep.push(b);
        }
    }
    for (net, children) in groups {
        if children.len() >= fanout {
            keep.push(CidrV4 {
                prefix_len: target,
                network: net,
            });
        } else {
            keep.extend(children);
        }
    }
    keep
}

fn collapse_v6(blocks: Vec<CidrV6>, target: u32, fanout: usize) -> Vec<CidrV6> {
    let mut groups: HashMap<[u8; 16], Vec<CidrV6>> = HashMap::new();
    let mut keep: Vec<CidrV6> = Vec::new();
    for b in blocks {
        if b.prefix_len > target {
            groups
                .entry(mask_v6(b.network, target))
                .or_default()
                .push(b);
        } else {
            keep.push(b);
        }
    }
    for (net, children) in groups {
        if children.len() >= fanout {
            keep.push(CidrV6 {
                prefix_len: target,
                network: net,
            });
        } else {
            keep.extend(children);
        }
    }
    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_source_pps_and_offenders() {
        let mut prev = HashMap::new();
        prev.insert([1, 1, 1, 1], 100u64);
        let cur = [([1, 1, 1, 1], 700), ([2, 2, 2, 2], 50)];
        let rates = per_source_pps(&prev, &cur, 1_000_000_000);
        // .1.1.1.1: +600 => 600pps; .2.2.2.2: new => 50pps
        let off = offenders(&rates, 500);
        assert_eq!(off, vec![[1, 1, 1, 1]]);
    }

    #[test]
    fn single_offender_blocked_as_slash32() {
        let blocks = aggregate_v4(&[[9, 9, 9, 9]], 4);
        assert_eq!(
            blocks,
            vec![CidrV4 {
                prefix_len: 32,
                network: [9, 9, 9, 9]
            }]
        );
    }

    #[test]
    fn four_sources_in_a_24_collapse_to_24() {
        let srcs = [[10, 0, 5, 1], [10, 0, 5, 2], [10, 0, 5, 3], [10, 0, 5, 4]];
        let blocks = aggregate_v4(&srcs, 4);
        assert_eq!(
            blocks,
            vec![CidrV4 {
                prefix_len: 24,
                network: [10, 0, 5, 0]
            }]
        );
    }

    #[test]
    fn three_sources_below_fanout_stay_as_32s() {
        let srcs = [[10, 0, 5, 1], [10, 0, 5, 2], [10, 0, 5, 3]];
        let blocks = aggregate_v4(&srcs, 4);
        assert_eq!(blocks.len(), 3);
        assert!(blocks.iter().all(|b| b.prefix_len == 32));
    }

    #[test]
    fn collapses_multiple_levels_to_16() {
        // Four /24s (each with four sources) under 10.0.x -> collapse to /16.
        let mut srcs = Vec::new();
        for third in 0..4u8 {
            for host in 1..=4u8 {
                srcs.push([10, 0, third, host]);
            }
        }
        let blocks = aggregate_v4(&srcs, 4);
        assert_eq!(
            blocks,
            vec![CidrV4 {
                prefix_len: 16,
                network: [10, 0, 0, 0]
            }]
        );
    }

    #[test]
    fn distinct_24s_not_over_fanout_kept_separate() {
        let srcs = [
            [10, 0, 5, 1],
            [10, 0, 5, 2],
            [10, 0, 5, 3],
            [10, 0, 5, 4], // 10.0.5.0/24
            [10, 0, 9, 1], // lone source, different /24
        ];
        let blocks = aggregate_v4(&srcs, 4);
        assert!(blocks.contains(&CidrV4 {
            prefix_len: 24,
            network: [10, 0, 5, 0]
        }));
        assert!(blocks.contains(&CidrV4 {
            prefix_len: 32,
            network: [10, 0, 9, 1]
        }));
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn v6_four_sources_in_64_collapse() {
        let base = [0x20u8, 1, 0xd, 0xb8, 0, 0, 0, 0];
        let mk = |last: u8| {
            let mut a = [0u8; 16];
            a[..8].copy_from_slice(&base);
            a[15] = last;
            a
        };
        let srcs: Vec<[u8; 16]> = (1..=4).map(mk).collect();
        let blocks = aggregate_v6(&srcs, 4);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].prefix_len, 64);
        assert_eq!(&blocks[0].network[..8], &base);
    }
}
