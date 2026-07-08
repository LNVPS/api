use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruHashMap, LruPerCpuHashMap};
use lnvps_fw_common::{
    Bucket, DEFAULT_SYN_RATE_BURST_LIMIT, DEFAULT_SYN_RATE_LIMIT, DestCounters, PacketLimits,
};

/// Max number of destination IPs to track (per address family)
pub const MAX_DST_IPS: u32 = 256 * 1024;

/// Per-destination traffic counters (IPv4), sampled by userspace detection loop
#[map]
pub static V4_DEST_COUNTERS: LruPerCpuHashMap<[u8; 4], DestCounters> =
    LruPerCpuHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Per-destination traffic counters (IPv6), sampled by userspace detection loop
#[map]
pub static V6_DEST_COUNTERS: LruPerCpuHashMap<[u8; 16], DestCounters> =
    LruPerCpuHashMap::with_max_entries(MAX_DST_IPS, 0);

/// SYN rate bucket per dest IPv4
#[map]
pub static V4_SYN_RATE: LruHashMap<[u8; 4], Bucket> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// SYN rate bucket per dest IPv6
#[map]
pub static V6_SYN_RATE: LruHashMap<[u8; 16], Bucket> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// SYN rate limit overrides per dest IPv4 (set by userspace)
#[map]
pub static V4_SYN_RATE_LIMITS: HashMap<[u8; 4], PacketLimits> =
    HashMap::with_max_entries(MAX_DST_IPS, 0);

/// SYN rate limit overrides per dest IPv6 (set by userspace)
#[map]
pub static V6_SYN_RATE_LIMITS: HashMap<[u8; 16], PacketLimits> =
    HashMap::with_max_entries(MAX_DST_IPS, 0);

const DEFAULT_SYN_LIMITS: PacketLimits = PacketLimits {
    limit: DEFAULT_SYN_RATE_LIMIT,
    burst: DEFAULT_SYN_RATE_BURST_LIMIT,
};

/// Generate a SYN-gate function for one address family. The logic is
/// identical; only the key width and backing maps differ, and BPF map
/// statics cannot be passed as runtime arguments.
macro_rules! syn_gate {
    ($name:ident, $key:ty, $rate_map:ident, $limits_map:ident) => {
        /// Track SYN rate per dest, true if the packet should pass.
        #[inline(always)]
        pub fn $name(dst: &$key) -> bool {
            let limits = unsafe { $limits_map.get(dst) }.unwrap_or(&DEFAULT_SYN_LIMITS);
            let now = unsafe { bpf_ktime_get_ns() };
            if let Some(b) = $rate_map.get_ptr_mut(dst) {
                let bucket = unsafe { &mut *b };
                bucket.try_consume(now, limits)
            } else {
                // First SYN seen for this destination: seed the bucket with
                // the configured burst and consume one token. Fail open if
                // the map insert fails.
                let new_bucket = Bucket::seeded(limits, now);
                let _ = $rate_map.insert(dst, &new_bucket, 0);
                true
            }
        }
    };
}

syn_gate!(syn_allowed_v4, [u8; 4], V4_SYN_RATE, V4_SYN_RATE_LIMITS);
syn_gate!(syn_allowed_v6, [u8; 16], V6_SYN_RATE, V6_SYN_RATE_LIMITS);

/// Generate a counters-accessor for one address family: returns a pointer to
/// the current-CPU counters slot for `dst`, creating it if missing.
macro_rules! counters_for {
    ($name:ident, $key:ty, $map:ident) => {
        #[inline(always)]
        pub fn $name(dst: &$key) -> Option<*mut DestCounters> {
            if let Some(p) = $map.get_ptr_mut(dst) {
                return Some(p);
            }
            let zero = DestCounters::default();
            let _ = $map.insert(dst, &zero, 0);
            $map.get_ptr_mut(dst)
        }
    };
}

counters_for!(counters_v4, [u8; 4], V4_DEST_COUNTERS);
counters_for!(counters_v6, [u8; 16], V6_DEST_COUNTERS);
