//! Types shared between the eBPF programs (`lnvps_ebpf`) and the userspace
//! daemon (`lnvps_fw_service`).
//!
//! All types used as BPF map keys/values must be `#[repr(C)]` with no
//! implicit padding (explicit `_pad` fields where required) so that:
//! - the layout is identical on both sides of the map,
//! - hashing map keys is deterministic (no uninitialised padding bytes),
//! - the userspace `aya::Pod` impls (behind the `user` feature) are sound.
#![cfg_attr(not(feature = "user"), no_std)]

/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

/// Default SYN rate limit per destination (packets/second).
pub const DEFAULT_SYN_RATE_LIMIT: u64 = 1_000;
/// Default SYN burst limit per destination.
pub const DEFAULT_SYN_RATE_BURST_LIMIT: u64 = 10_000;

/// Destination is not under attack; all traffic passes (learning continues).
pub const DEST_MODE_NORMAL: u32 = 0;
/// Destination is under attack; only traffic to learned-open ports passes.
pub const DEST_MODE_MITIGATE: u32 = 1;
/// Destination is under a sustained SYN flood; SYN-proxy validation active.
pub const DEST_MODE_SYN_PROXY: u32 = 2;

/// Simple token bucket.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bucket {
    /// Tokens available
    pub tokens: u64,
    /// Timestamp in nanoseconds (bpf_ktime_get_ns clock)
    pub timestamp: u64,
}

impl Bucket {
    /// Create a bucket seeded with `burst` tokens minus one consumed token.
    pub fn seeded(limits: &PacketLimits, now: u64) -> Self {
        Self {
            tokens: limits.burst.saturating_sub(1),
            timestamp: now,
        }
    }

    /// Refill the bucket according to `limits` for the elapsed time.
    #[inline(always)]
    pub fn tick(&mut self, now: u64, limits: &PacketLimits) {
        // A limit of 0 would divide by zero; treat it as "no refill".
        if limits.limit == 0 {
            self.timestamp = now;
            return;
        }
        // Nanoseconds required to accrue a single token.
        let ns_per_token = 1_000_000_000 / limits.limit;
        if ns_per_token == 0 {
            // Refill faster than 1 token/ns: just top up to burst.
            self.tokens = limits.burst;
            self.timestamp = now;
            return;
        }
        let elapsed = now.saturating_sub(self.timestamp);
        let new_tokens = elapsed / ns_per_token;
        self.tokens = limits.burst.min(self.tokens.saturating_add(new_tokens));
        self.timestamp = now;
    }

    /// Refill then try to consume a single token. Returns true if a token
    /// was available (packet should pass).
    #[inline(always)]
    pub fn try_consume(&mut self, now: u64, limits: &PacketLimits) -> bool {
        self.tick(now, limits);
        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Configurable rate limits.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLimits {
    /// Rate limit per second
    pub limit: u64,
    /// Burst limit
    pub burst: u64,
}

/// Per-destination traffic counters, updated by the XDP ingress program and
/// sampled by the userspace detection loop. Stored in per-CPU maps; userspace
/// must sum across CPUs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
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

/// Key for the learned-open-ports maps (IPv4).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PortKeyV4 {
    /// Destination address (network byte order, as seen in the IP header)
    pub addr: [u8; 4],
    /// Port (network byte order, as seen in the L4 header)
    pub port: u16,
    /// PROTO_TCP or PROTO_UDP
    pub proto: u8,
    pub _pad: u8,
}

/// Key for the learned-open-ports maps (IPv6).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PortKeyV6 {
    /// Destination address (network byte order, as seen in the IP header)
    pub addr: [u8; 16],
    /// Port (network byte order, as seen in the L4 header)
    pub port: u16,
    /// PROTO_TCP or PROTO_UDP
    pub proto: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for Bucket {}
    unsafe impl aya::Pod for PacketLimits {}
    unsafe impl aya::Pod for DestCounters {}
    unsafe impl aya::Pod for DestState {}
    unsafe impl aya::Pod for PortKeyV4 {}
    unsafe impl aya::Pod for PortKeyV6 {}
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: PacketLimits = PacketLimits {
        limit: 1_000,
        burst: 10_000,
    };

    #[test]
    fn bucket_seeded_consumes_one_token() {
        let b = Bucket::seeded(&LIMITS, 42);
        assert_eq!(b.tokens, 9_999);
        assert_eq!(b.timestamp, 42);
    }

    #[test]
    fn bucket_tick_refills_at_rate() {
        let mut b = Bucket {
            tokens: 0,
            timestamp: 0,
        };
        // 1 second elapsed at 1000/s => 1000 tokens
        b.tick(1_000_000_000, &LIMITS);
        assert_eq!(b.tokens, 1_000);
        assert_eq!(b.timestamp, 1_000_000_000);
    }

    #[test]
    fn bucket_tick_caps_at_burst() {
        let mut b = Bucket {
            tokens: 0,
            timestamp: 0,
        };
        // 100 seconds elapsed => 100_000 tokens, capped at burst
        b.tick(100_000_000_000, &LIMITS);
        assert_eq!(b.tokens, LIMITS.burst);
    }

    #[test]
    fn bucket_tick_zero_limit_never_refills() {
        let limits = PacketLimits { limit: 0, burst: 5 };
        let mut b = Bucket {
            tokens: 3,
            timestamp: 0,
        };
        b.tick(1_000_000_000, &limits);
        assert_eq!(b.tokens, 3);
        assert_eq!(b.timestamp, 1_000_000_000);
    }

    #[test]
    fn bucket_tick_extreme_limit_tops_up_to_burst() {
        // limit > 1e9 => ns_per_token == 0 path
        let limits = PacketLimits {
            limit: 2_000_000_000,
            burst: 7,
        };
        let mut b = Bucket {
            tokens: 0,
            timestamp: 0,
        };
        b.tick(1, &limits);
        assert_eq!(b.tokens, 7);
    }

    #[test]
    fn bucket_tick_clock_going_backwards_is_safe() {
        let mut b = Bucket {
            tokens: 5,
            timestamp: 1_000_000_000,
        };
        b.tick(0, &LIMITS);
        assert_eq!(b.tokens, 5);
    }

    #[test]
    fn bucket_try_consume_depletes_then_blocks() {
        let limits = PacketLimits { limit: 1, burst: 2 };
        let mut b = Bucket {
            tokens: 2,
            timestamp: 0,
        };
        assert!(b.try_consume(0, &limits));
        assert!(b.try_consume(0, &limits));
        assert!(!b.try_consume(0, &limits));
        // After 1s one token accrues again
        assert!(b.try_consume(1_000_000_000, &limits));
    }

    #[test]
    fn key_sizes_have_no_hidden_padding() {
        assert_eq!(core::mem::size_of::<PortKeyV4>(), 8);
        assert_eq!(core::mem::size_of::<PortKeyV6>(), 20);
        assert_eq!(core::mem::size_of::<DestState>(), 16);
        assert_eq!(core::mem::size_of::<Bucket>(), 16);
        assert_eq!(core::mem::size_of::<PacketLimits>(), 16);
        assert_eq!(core::mem::size_of::<DestCounters>(), 56);
    }
}
