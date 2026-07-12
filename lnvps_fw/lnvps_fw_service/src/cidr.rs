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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_v4_clears_host_bits() {
        assert_eq!(mask_v4([10, 1, 2, 3], 24), [10, 1, 2, 0]);
        assert_eq!(mask_v4([10, 1, 2, 3], 32), [10, 1, 2, 3]);
        assert_eq!(mask_v4([10, 1, 2, 3], 0), [0, 0, 0, 0]);
        assert_eq!(mask_v4([255, 255, 255, 255], 20), [255, 255, 240, 0]);
    }

    #[test]
    fn mask_v6_clears_host_bits() {
        let mut a = [0xffu8; 16];
        a[0] = 0x20;
        let m = mask_v6(a, 48);
        assert_eq!(&m[..6], &a[..6]);
        assert!(m[6..].iter().all(|&b| b == 0));
    }
}
