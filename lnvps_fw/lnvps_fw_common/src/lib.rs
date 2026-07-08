//! Types shared between the eBPF programs (`lnvps_ebpf`) and the userspace
//! daemon (`lnvps_fw_service`).
//!
//! All types used as BPF map keys/values must be `#[repr(C)]` with no
//! implicit padding (explicit `_pad` fields where required) so that:
//! - the layout is identical on both sides of the map,
//! - hashing map keys is deterministic (no uninitialised padding bytes),
//! - the userspace `aya::Pod` impls (behind the `user` feature) are sound.
#![cfg_attr(not(feature = "user"), no_std)]

/// IP protocol number for ICMP (IPv4).
pub const PROTO_ICMP: u8 = 1;
/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for GRE (RFC 2784), used for tunnel decapsulation.
pub const PROTO_GRE: u8 = 47;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;
/// IP protocol number for ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

// The mitigation mode of a destination (or protected prefix) is a set of
// independent protection FLAGS, stored as a bitmask in `DestState.mode`. Each
// flag is a self-contained filter the XDP datapath applies when set, so any
// subset can be active simultaneously (e.g. SOURCE_BLOCK without SYN_PROXY).
// Userspace *enables* flags in efficacy order — the open-port allow-list drop
// (highest efficacy, lowest false-positive) is turned on first; source/CIDR
// blocking (highest FP risk, useless vs spoofed floods) only when warranted —
// but the datapath treats them as an orthogonal flag set, not an ordered ladder.

/// Empty flag set: not under attack; all traffic passes (learning continues).
pub const DEST_MODE_NORMAL: u32 = 0;
/// Flag: drop non-first fragments and traffic to non-learned-open ports (the
/// high-efficacy, low-false-positive heavy lifter).
pub const DEST_MODE_PORT_FILTER: u32 = 1 << 0;
/// Flag (reserved, increment 6): validate TCP handshakes to open ports with SYN
/// cookies so spoofed SYN floods never reach the guest.
pub const DEST_MODE_SYN_PROXY: u32 = 1 << 1;
/// Flag (reserved): per-(dst,port) rate caps for open UDP/ICMP services.
pub const DEST_MODE_RATE_CAPS: u32 = 1 << 2;
/// Flag: drop sources matching a blocked CIDR (last resort; userspace only
/// enables it for bounded/real offenders, never vs spoofed floods).
pub const DEST_MODE_SOURCE_BLOCK: u32 = 1 << 3;

/// Per-destination traffic counters, updated by the XDP ingress program and
/// sampled by the userspace detection loop. Stored in per-CPU maps; userspace
/// must sum across CPUs.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct DestCounters {
    /// Total packets seen
    pub packets: u64,
    /// Total bytes seen
    pub bytes: u64,
    /// TCP SYN (SYN set, ACK clear) packets seen
    pub syn_packets: u64,
    /// TCP packets seen
    pub tcp_packets: u64,
    /// UDP packets seen
    pub udp_packets: u64,
    /// ICMP packets seen
    pub icmp_packets: u64,
    /// Packets dropped by any protection stage
    pub dropped: u64,
}

/// Mitigation state for a destination IP. Written by userspace (detection
/// state machine), read by the XDP ingress program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DestState {
    /// One of DEST_MODE_*
    pub mode: u32,
    pub _pad: u32,
    /// bpf_ktime_get_ns timestamp when this mode was entered
    pub entered_at: u64,
}

/// Compute a SYN-cookie for an IPv4 4-tuple under `secret`. Used by the XDP
/// SYN-proxy: the challenge SYN-ACK carries this value as its sequence number;
/// a legitimate client echoes it back as `ack_seq - 1`, proving it can complete
/// a handshake (i.e. its source address is not spoofed). Userspace rotates
/// `secret` so old cookies expire.
///
/// This is a fast non-cryptographic mix (FNV-1a style). It does not need to be
/// cryptographically strong: a spoofed source never receives the SYN-ACK, so it
/// cannot learn the cookie regardless. Ports/addresses are passed as raw header
/// bytes so both the generate and verify sides agree without endianness care.
#[inline(always)]
pub fn syn_cookie_v4(
    secret: u32,
    saddr: [u8; 4],
    daddr: [u8; 4],
    sport: [u8; 2],
    dport: [u8; 2],
) -> u32 {
    let mut h: u32 = 2_166_136_261u32 ^ secret;
    let mut mix = |b: u8| {
        h ^= b as u32;
        h = h.wrapping_mul(16_777_619);
    };
    for b in saddr {
        mix(b);
    }
    for b in daddr {
        mix(b);
    }
    for b in sport {
        mix(b);
    }
    for b in dport {
        mix(b);
    }
    h
}

/// IPv6 SYN cookie — identical mix to [`syn_cookie_v4`] over the 128-bit
/// address 4-tuple.
#[inline(always)]
pub fn syn_cookie_v6(
    secret: u32,
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: [u8; 2],
    dport: [u8; 2],
) -> u32 {
    let mut h: u32 = 2_166_136_261u32 ^ secret;
    let mut mix = |b: u8| {
        h ^= b as u32;
        h = h.wrapping_mul(16_777_619);
    };
    for b in saddr {
        mix(b);
    }
    for b in daddr {
        mix(b);
    }
    for b in sport {
        mix(b);
    }
    for b in dport {
        mix(b);
    }
    h
}

/// Config-map keys for the two-slot rotating SYN-cookie secret (current +
/// previous, so cookies issued just before a rotation still validate).
pub const COOKIE_SECRET_CURRENT: u32 = 0;
pub const COOKIE_SECRET_PREVIOUS: u32 = 1;

/// PROG_ARRAY slot of the IPv4 SYN-proxy tail-call program. The main XDP
/// program tail-calls here (rather than inlining the packet-rewrite, which
/// blows the verifier budget) so the rewrite program is verified independently
/// with a full XDP context.
pub const SLOT_SYN_PROXY_V4: u32 = 0;

/// PROG_ARRAY slot of the IPv6 SYN-proxy tail-call program.
pub const SLOT_SYN_PROXY_V6: u32 = 1;

/// Value stored in the learned-open-ports maps: when the port was last seen
/// serving traffic (via passive egress observation), on the
/// `bpf_ktime_get_ns` monotonic clock. Userspace GC expires entries whose
/// `last_seen` is older than the configured TTL.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LastSeen {
    /// bpf_ktime_get_ns timestamp of the most recent matching egress packet
    pub last_seen: u64,
}

/// Key for the learned-open-ports maps (IPv4).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PortKeyV4 {
    /// Local address bytes, exactly as they appear in the IP header
    pub addr: [u8; 4],
    /// Port in host byte order (both learning and lookup decode via
    /// `u16::from_be_bytes`, so the two sides always agree)
    pub port: u16,
    /// PROTO_TCP or PROTO_UDP
    pub proto: u8,
    pub _pad: u8,
}

impl PortKeyV4 {
    /// Construct a key with the padding byte zeroed (required for correct
    /// hashing of map keys).
    #[inline(always)]
    pub fn new(addr: [u8; 4], port: u16, proto: u8) -> Self {
        Self {
            addr,
            port,
            proto,
            _pad: 0,
        }
    }
}

/// Key for the learned-open-ports maps (IPv6).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PortKeyV6 {
    /// Local address bytes, exactly as they appear in the IP header
    pub addr: [u8; 16],
    /// Port in host byte order (both learning and lookup decode via
    /// `u16::from_be_bytes`, so the two sides always agree)
    pub port: u16,
    /// PROTO_TCP or PROTO_UDP
    pub proto: u8,
    pub _pad: u8,
}

impl PortKeyV6 {
    /// Construct a key with the padding byte zeroed (required for correct
    /// hashing of map keys).
    #[inline(always)]
    pub fn new(addr: [u8; 16], port: u16, proto: u8) -> Self {
        Self {
            addr,
            port,
            proto,
            _pad: 0,
        }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for DestCounters {}
    unsafe impl aya::Pod for DestState {}
    unsafe impl aya::Pod for LastSeen {}
    unsafe impl aya::Pod for PortKeyV4 {}
    unsafe impl aya::Pod for PortKeyV6 {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_is_deterministic_and_tuple_sensitive() {
        let a = syn_cookie_v4(0x1234, [10, 0, 0, 2], [10, 0, 1, 2], [0x30, 0x39], [0, 80]);
        let b = syn_cookie_v4(0x1234, [10, 0, 0, 2], [10, 0, 1, 2], [0x30, 0x39], [0, 80]);
        assert_eq!(a, b, "same inputs must give same cookie");
        // Different source port -> different cookie.
        let c = syn_cookie_v4(0x1234, [10, 0, 0, 2], [10, 0, 1, 2], [0x30, 0x40], [0, 80]);
        assert_ne!(a, c);
        // Different secret -> different cookie.
        let d = syn_cookie_v4(0x9999, [10, 0, 0, 2], [10, 0, 1, 2], [0x30, 0x39], [0, 80]);
        assert_ne!(a, d);
        // Different source address -> different cookie.
        let e = syn_cookie_v4(0x1234, [10, 0, 0, 3], [10, 0, 1, 2], [0x30, 0x39], [0, 80]);
        assert_ne!(a, e);
    }

    #[test]
    fn cookie_v6_is_deterministic_and_tuple_sensitive() {
        let s = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let d = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let a = syn_cookie_v6(0x1234, s, d, [0x30, 0x39], [0, 80]);
        assert_eq!(a, syn_cookie_v6(0x1234, s, d, [0x30, 0x39], [0, 80]));
        // Different source port / secret / address -> different cookie.
        assert_ne!(a, syn_cookie_v6(0x1234, s, d, [0x30, 0x40], [0, 80]));
        assert_ne!(a, syn_cookie_v6(0x9999, s, d, [0x30, 0x39], [0, 80]));
        let mut s2 = s;
        s2[15] = 3;
        assert_ne!(a, syn_cookie_v6(0x1234, s2, d, [0x30, 0x39], [0, 80]));
    }

    #[test]
    fn key_sizes_have_no_hidden_padding() {
        assert_eq!(core::mem::size_of::<PortKeyV4>(), 8);
        assert_eq!(core::mem::size_of::<PortKeyV6>(), 20);
        assert_eq!(core::mem::size_of::<DestState>(), 16);
        assert_eq!(core::mem::size_of::<LastSeen>(), 8);
        assert_eq!(core::mem::size_of::<DestCounters>(), 56);
    }
}
