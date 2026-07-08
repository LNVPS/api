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
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;
/// IP protocol number for ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

/// Destination is not under attack; all traffic passes (learning continues).
pub const DEST_MODE_NORMAL: u32 = 0;
/// Destination is under attack; only traffic to learned-open ports passes.
pub const DEST_MODE_MITIGATE: u32 = 1;
/// Destination is under a sustained SYN flood; SYN-proxy validation active.
pub const DEST_MODE_SYN_PROXY: u32 = 2;

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
    fn key_sizes_have_no_hidden_padding() {
        assert_eq!(core::mem::size_of::<PortKeyV4>(), 8);
        assert_eq!(core::mem::size_of::<PortKeyV6>(), 20);
        assert_eq!(core::mem::size_of::<DestState>(), 16);
        assert_eq!(core::mem::size_of::<LastSeen>(), 8);
        assert_eq!(core::mem::size_of::<DestCounters>(), 56);
    }
}
