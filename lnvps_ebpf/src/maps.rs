use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::error;
use core::ptr;
use network_types::ip::Ipv4Hdr;

/// Simple token bucket
#[repr(C, packed)]
pub struct Bucket {
    /// Tokens available
    pub tokens: u64,
    /// Timestamp in nanoseconds
    pub timestamp: u64,
}

impl Bucket {
    /// Tick bucket with rate/burst values
    #[inline(always)]
    pub fn tick(&mut self, now: u64, limits: &PacketLimits) {
        let tokens_per_ns = 1_000_000_000 / limits.limit;
        let elapsed = now - self.timestamp;
        let new_tokens = (elapsed / tokens_per_ns) * limits.limit;
        self.tokens = limits.burst.min(self.tokens.saturating_add(new_tokens));
        self.timestamp = now;
    }

    /// Track SYN IPv4 per dest, true if pass
    #[inline(always)]
    pub fn syn_dest_v4(ctx: &XdpContext, ip: &Ipv4Hdr) -> Result<bool, &'static str> {
        const DEFAULT_LIMITS: PacketLimits = PacketLimits {
            limit: DEFAULT_V4_SYN_RATE_LIMIT,
            burst: DEFAULT_V4_SYN_RATE_BURST_LIMIT,
        };
        let rate = unsafe { V4_SYN_RATE_LIMITS.get(&ip.dst_addr) }.unwrap_or(&DEFAULT_LIMITS);

        let now = unsafe { bpf_ktime_get_ns() } as u64;
        if let Some(b) = V4_SYN_RATE.get(&ip.dst_addr) {
            let bucket = unsafe { &mut *b };
            bucket.tick(now, rate);
            if bucket.tokens >= 1 {
                bucket.tokens -= 1;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            let new_bucket = Bucket {
                tokens: DEFAULT_V4_SYN_RATE_BURST_LIMIT,
                timestamp: now,
            };
            V4_SYN_RATE.insert(&ip.dst_addr, &new_bucket, 0).unwrap();
            Ok(true)
        }
    }
}

/// TCP Protection stage for src/dst
#[repr(C)]
pub enum TcpProtectionMode {
    /// SYN proxy
    SynProxy,
    /// Drop packets over a threshold
    ThrottleVolume {
        /// Max number of bytes to allow
        bytes_per_sec: u32,
    },
    /// Drop all TCP packets
    Drop,
}

#[repr(C, packed)]
pub struct CidrMode {
    pub bucket: Bucket,
}

/// Configurable rate limits
#[repr(C, packed)]
pub struct PacketLimits {
    /// Rate limit per second
    pub limit: u64,
    /// Burst limit per second
    pub burst: u64,
}

/// Max number of source IPS to track in LRU sets
pub const V4_MAX_LRU_SRC_IPS: u32 = 256 * 1024;

/// Max number of source IPS to track in LRU sets
pub const V4_MAX_LRU_DST_IPS: u32 = 256 * 1024;

/// Minimum entry to add into CIDR source tracking
pub const V4_MIN_CIDR: u8 = 24;

/// Max CIDR size in source tracking
pub const V4_MAX_CIDR: u8 = 8;

/// Protection stage to apply per source CIDR, this covers generic packet rate limits per source IP
/// Each IP in a CIDR counts up these counters, if the counter is breached, the CIDR mask is increased
/// until the max value, overlapping entries are removed
#[map]
pub static V4_CIDR_SRC: LpmTrie<[u8; 4], CidrMode> =
    LpmTrie::with_max_entries(V4_MAX_LRU_SRC_IPS, 0);

/// Protection stage to apply per source IP
#[map]
pub static V4_TCP_SRC_STAGE: LruHashMap<[u8; 4], TcpProtectionMode> =
    LruHashMap::with_max_entries(V4_MAX_LRU_SRC_IPS, 0);

/// Protection stage to apply per destination IP
#[map]
pub static V4_TCP_DST_STAGE: LruHashMap<[u8; 4], TcpProtectionMode> =
    LruHashMap::with_max_entries(V4_MAX_LRU_DST_IPS, 0);

/// Map tracking SYN rate per dest IPv4: DST -> Bucket
#[map]
pub static V4_SYN_RATE: LruHashMap<[u8; 4], Bucket> =
    LruHashMap::with_max_entries(V4_MAX_LRU_DST_IPS, 0);

/// Set SYN rate limits per dest IPv4: DST -> PacketLimits
#[map]
pub static V4_SYN_RATE_LIMITS: HashMap<[u8; 4], PacketLimits> =
    HashMap::with_max_entries(V4_MAX_LRU_DST_IPS, 0);

/// Set absolute rate limits per dest IPv4: DST -> PacketLimits
#[map]
pub static V4_RATE_LIMITS: HashMap<[u8; 4], PacketLimits> =
    HashMap::with_max_entries(V4_MAX_LRU_DST_IPS, 0);

/// Default SYN rate limit is 1000/s
pub const DEFAULT_V4_SYN_RATE_LIMIT: u64 = 1_000;

/// Default SYN rate burst limit is 10000/s
pub const DEFAULT_V4_SYN_RATE_BURST_LIMIT: u64 = 10_000;
