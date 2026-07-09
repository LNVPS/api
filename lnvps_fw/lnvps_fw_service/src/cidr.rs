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
/// as /32 and collapse toward /8 — but only levels at least as narrow as the
/// configured `max_prefix` cap are ever applied (see [`aggregate_v4`]), so the
/// default cap keeps blocks from ever crossing large allocation boundaries.
const V4_LEVELS: [u32; 3] = [24, 16, 8];
/// IPv6 aggregation levels: offenders start as /128 and collapse toward /32.
const V6_LEVELS: [u32; 3] = [64, 48, 32];

/// Safe default widest IPv4 aggregation prefix (smallest prefix length). A /24
/// is the smallest globally-routable unit and is typically single-org, so
/// aggregation never blackholes across organisation / RIR-allocation
/// boundaries (which is how a handful of CDN edge IPs could otherwise collapse
/// into a catastrophic /8). Operators can widen it via config if they really
/// want, but the default never produces anything wider than a /24.
pub const DEFAULT_AGG_MAX_PREFIX_V4: u32 = 24;
/// Safe default widest IPv6 aggregation prefix. A /48 is a single site/customer
/// allocation; wider than that risks an entire ISP block.
pub const DEFAULT_AGG_MAX_PREFIX_V6: u32 = 48;

/// Zero the host bits of an IPv4 prefix (supports non-byte-aligned lengths
/// like /22).
pub fn mask_v4(addr: [u8; 4], prefix: u32) -> [u8; 4] {
    mask_bytes::<4>(addr, prefix.min(32))
}

/// Zero the host bits of an IPv6 prefix.
pub fn mask_v6(addr: [u8; 16], prefix: u32) -> [u8; 16] {
    mask_bytes::<16>(addr, prefix.min(128))
}

/// Bit-level network mask over an N-byte address.
fn mask_bytes<const N: usize>(addr: [u8; N], prefix: u32) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let bit_start = (i as u32) * 8;
        if bit_start + 8 <= prefix {
            *o = addr[i];
        } else if bit_start < prefix {
            let keep = prefix - bit_start; // 1..=7 bits from this byte
            *o = addr[i] & (0xFFu8 << (8 - keep));
        }
    }
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
///
/// `max_prefix` caps how wide a block may become (the smallest prefix length,
/// e.g. 24 = never wider than a /24). Only ladder levels `>= max_prefix` are
/// applied, so the block set can never expand past the cap and blackhole a
/// whole allocation. `max_prefix` is clamped to `1..=32`.
pub fn aggregate_v4(offenders: &[[u8; 4]], fanout: usize, max_prefix: u32) -> Vec<CidrV4> {
    let fanout = fanout.max(2);
    let max_prefix = max_prefix.clamp(1, 32);
    let mut blocks: Vec<CidrV4> = dedup(offenders.iter().map(|a| CidrV4 {
        prefix_len: 32,
        network: *a,
    }));
    for &target in &V4_LEVELS {
        if target < max_prefix {
            continue; // would exceed the configured widest-block cap
        }
        blocks = collapse_v4(blocks, target, fanout);
    }
    blocks.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
    blocks
}

/// IPv6 equivalent of [`aggregate_v4`]. `max_prefix` is clamped to `1..=128`.
pub fn aggregate_v6(offenders: &[[u8; 16]], fanout: usize, max_prefix: u32) -> Vec<CidrV6> {
    let fanout = fanout.max(2);
    let max_prefix = max_prefix.clamp(1, 128);
    let mut blocks: Vec<CidrV6> = dedup(offenders.iter().map(|a| CidrV6 {
        prefix_len: 128,
        network: *a,
    }));
    for &target in &V6_LEVELS {
        if target < max_prefix {
            continue;
        }
        blocks = collapse_v6(blocks, target, fanout);
    }
    blocks.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
    blocks
}

/// Plan the IPv4 source-block set from the currently-DROPPING source addresses.
///
/// Individual `/32`s are preferred so each source is governed independently by
/// its own rate state machine. Aggregation is applied **only under trie space
/// pressure**: if the `/32` count exceeds `budget`, offenders are progressively
/// collapsed (densest `/24`s first, then wider) until the set fits — never past
/// the `max_prefix` safety cap. So in the normal case nothing is merged.
pub fn plan_blocks_v4(
    dropping: &[[u8; 4]],
    fanout: usize,
    budget: usize,
    max_prefix: u32,
) -> Vec<CidrV4> {
    let base: Vec<CidrV4> = dedup(dropping.iter().map(|a| CidrV4 {
        prefix_len: 32,
        network: *a,
    }));
    if base.len() <= budget {
        let mut b = base;
        b.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
        return b;
    }
    // Under pressure: widen only as far as needed, never wider than max_prefix.
    for &cap in &[24u32, 16, 8] {
        if cap < max_prefix.clamp(1, 32) {
            continue;
        }
        let blocks = aggregate_v4(dropping, fanout, cap);
        if blocks.len() <= budget {
            return blocks;
        }
    }
    aggregate_v4(dropping, fanout, max_prefix)
}

/// IPv6 counterpart of [`plan_blocks_v4`].
pub fn plan_blocks_v6(
    dropping: &[[u8; 16]],
    fanout: usize,
    budget: usize,
    max_prefix: u32,
) -> Vec<CidrV6> {
    let base: Vec<CidrV6> = dedup(dropping.iter().map(|a| CidrV6 {
        prefix_len: 128,
        network: *a,
    }));
    if base.len() <= budget {
        let mut b = base;
        b.sort_by(|a, b| (a.prefix_len, a.network).cmp(&(b.prefix_len, b.network)));
        return b;
    }
    for &cap in &[64u32, 48, 32] {
        if cap < max_prefix.clamp(1, 128) {
            continue;
        }
        let blocks = aggregate_v6(dropping, fanout, cap);
        if blocks.len() <= budget {
            return blocks;
        }
    }
    aggregate_v6(dropping, fanout, max_prefix)
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
        let blocks = aggregate_v4(&[[9, 9, 9, 9]], 4, 8);
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
        let blocks = aggregate_v4(&srcs, 4, 8);
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
        let blocks = aggregate_v4(&srcs, 4, 8);
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
        // A permissive cap (/16) is required for this collapse.
        let blocks = aggregate_v4(&srcs, 4, 16);
        assert_eq!(
            blocks,
            vec![CidrV4 {
                prefix_len: 16,
                network: [10, 0, 0, 0]
            }]
        );
    }

    #[test]
    fn default_cap_never_widens_past_slash24() {
        // Same 16 sources spread across four /24s under 10.0.0.0/16 that would
        // collapse to a /16 with a permissive cap must stay as four /24s under
        // the safe default cap — never a /16 or wider.
        let mut srcs = Vec::new();
        for third in 0..4u8 {
            for host in 1..=4u8 {
                srcs.push([10, 0, third, host]);
            }
        }
        let blocks = aggregate_v4(&srcs, 4, DEFAULT_AGG_MAX_PREFIX_V4);
        assert_eq!(blocks.len(), 4);
        assert!(
            blocks.iter().all(|b| b.prefix_len == 24),
            "no block may be wider than /24: {blocks:?}"
        );
    }

    #[test]
    fn cap_prevents_slash8_blackhole() {
        // Emulate the reported regression: many offenders scattered across a
        // /8 (e.g. CDN edge IPs). With the default cap they must NEVER roll up
        // into a /8 or /16 that blackholes the whole allocation.
        let mut srcs = Vec::new();
        for second in 20..24u8 {
            for third in 0..4u8 {
                for host in 1..=4u8 {
                    srcs.push([104, second, third, host]);
                }
            }
        }
        let blocks = aggregate_v4(&srcs, 4, DEFAULT_AGG_MAX_PREFIX_V4);
        assert!(
            blocks.iter().all(|b| b.prefix_len >= 24),
            "cap breached, produced a block wider than /24: {blocks:?}"
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
        let blocks = aggregate_v4(&srcs, 4, 8);
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
    fn plan_blocks_prefers_slash32_with_space() {
        // Even a dense /24 worth of offenders stays as individual /32s while
        // there is trie budget — no eager aggregation.
        let srcs: Vec<[u8; 4]> = (1..=8).map(|h| [10, 0, 5, h]).collect();
        let blocks = plan_blocks_v4(&srcs, 4, 50_000, 24);
        assert_eq!(blocks.len(), 8);
        assert!(blocks.iter().all(|b| b.prefix_len == 32));
    }

    #[test]
    fn plan_blocks_aggregates_only_under_pressure() {
        // 8 offenders across two dense /24s, but a budget of only 2 entries
        // forces aggregation — collapsing each /24.
        let mut srcs: Vec<[u8; 4]> = (1..=4).map(|h| [10, 0, 5, h]).collect();
        srcs.extend((1..=4).map(|h| [10, 0, 6, h]));
        let blocks = plan_blocks_v4(&srcs, 4, 2, 24);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| b.prefix_len == 24));
    }

    #[test]
    fn plan_blocks_never_exceeds_max_prefix_cap() {
        // Under extreme pressure the planner still never goes wider than the cap.
        let mut srcs = Vec::new();
        for third in 0..8u8 {
            for host in 1..=4u8 {
                srcs.push([10, 0, third, host]);
            }
        }
        let blocks = plan_blocks_v4(&srcs, 4, 1, 24);
        assert!(
            blocks.iter().all(|b| b.prefix_len >= 24),
            "cap breached: {blocks:?}"
        );
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
        let blocks = aggregate_v6(&srcs, 4, 32);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].prefix_len, 64);
        assert_eq!(&blocks[0].network[..8], &base);
    }
}
