use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap};
use lnvps_fw_common::{
    Bucket, DEFAULT_ICMP_RATE_BURST_LIMIT, DEFAULT_ICMP_RATE_LIMIT, DEFAULT_SRC_RATE_BURST_LIMIT,
    DEFAULT_SRC_RATE_LIMIT, DEFAULT_SYN_RATE_BURST_LIMIT, DEFAULT_SYN_RATE_LIMIT, DEST_MODE_NORMAL,
    DestCounters, DestState, LastSeen, PacketLimits, PortKeyV4, PortKeyV6, SRC_RATE_CONFIG_KEY,
};

/// Max number of destination IPs to track (per address family)
pub const MAX_DST_IPS: u32 = 256 * 1024;

/// Max number of learned (ip, port, proto) tuples to track (per family)
pub const MAX_OPEN_PORTS: u32 = 1024 * 1024;

/// Learned-open TCP/UDP ports for local IPv4 addresses, discovered by passive
/// egress observation. Read by the XDP ingress program under mitigation.
#[map]
pub static OPEN_PORTS_V4: LruHashMap<PortKeyV4, LastSeen> =
    LruHashMap::with_max_entries(MAX_OPEN_PORTS, 0);

/// Learned-open TCP/UDP ports for local IPv6 addresses.
#[map]
pub static OPEN_PORTS_V6: LruHashMap<PortKeyV6, LastSeen> =
    LruHashMap::with_max_entries(MAX_OPEN_PORTS, 0);

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

/// Mitigation state per dest IPv4 (written by userspace detection loop)
#[map]
pub static V4_DEST_STATE: HashMap<[u8; 4], DestState> = HashMap::with_max_entries(MAX_DST_IPS, 0);

/// Mitigation state per dest IPv6
#[map]
pub static V6_DEST_STATE: HashMap<[u8; 16], DestState> = HashMap::with_max_entries(MAX_DST_IPS, 0);

/// ICMP rate bucket per dest IPv4 (only consulted while mitigating)
#[map]
pub static V4_ICMP_RATE: LruHashMap<[u8; 4], Bucket> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// ICMP rate bucket per dest IPv6
#[map]
pub static V6_ICMP_RATE: LruHashMap<[u8; 16], Bucket> =
    LruHashMap::with_max_entries(MAX_DST_IPS, 0);

const DEFAULT_SYN_LIMITS: PacketLimits = PacketLimits {
    limit: DEFAULT_SYN_RATE_LIMIT,
    burst: DEFAULT_SYN_RATE_BURST_LIMIT,
};

const DEFAULT_ICMP_LIMITS: PacketLimits = PacketLimits {
    limit: DEFAULT_ICMP_RATE_LIMIT,
    burst: DEFAULT_ICMP_RATE_BURST_LIMIT,
};

const DEFAULT_SRC_LIMITS: PacketLimits = PacketLimits {
    limit: DEFAULT_SRC_RATE_LIMIT,
    burst: DEFAULT_SRC_RATE_BURST_LIMIT,
};

/// Per-source token bucket (IPv4), consulted only while the destination is
/// mitigating.
#[map]
pub static V4_SRC_RATE: LruHashMap<[u8; 4], Bucket> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Per-source token bucket (IPv6).
#[map]
pub static V6_SRC_RATE: LruHashMap<[u8; 16], Bucket> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Cumulative per-source drop counter (IPv4): incremented when a source
/// exceeds its per-source rate under mitigation. Sampled by userspace to drive
/// CIDR escalation.
#[map]
pub static V4_SRC_DROPS: LruHashMap<[u8; 4], u64> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Cumulative per-source drop counter (IPv6).
#[map]
pub static V6_SRC_DROPS: LruHashMap<[u8; 16], u64> = LruHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Blocked source CIDRs (IPv4), an LPM trie of network-order address bytes.
/// Written by userspace escalation; any source matching a prefix is dropped.
#[map]
pub static V4_CIDR_SRC: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(MAX_DST_IPS, 0);

/// Blocked source CIDRs (IPv6).
#[map]
pub static V6_CIDR_SRC: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(MAX_DST_IPS, 0);

/// Global per-source rate-limit override (key `SRC_RATE_CONFIG_KEY`), set by
/// userspace from config; falls back to `DEFAULT_SRC_LIMITS`.
#[map]
pub static SRC_RATE_LIMITS: HashMap<u32, PacketLimits> = HashMap::with_max_entries(1, 0);

/// Per-source rate gate for one address family (used under mitigation). Returns
/// true if the packet is within the source's rate budget.
macro_rules! src_gate {
    ($name:ident, $key:ty, $rate_map:ident) => {
        #[inline(always)]
        pub fn $name(src: &$key) -> bool {
            let limits =
                unsafe { SRC_RATE_LIMITS.get(&SRC_RATE_CONFIG_KEY) }.unwrap_or(&DEFAULT_SRC_LIMITS);
            let now = unsafe { bpf_ktime_get_ns() };
            if let Some(b) = $rate_map.get_ptr_mut(src) {
                let bucket = unsafe { &mut *b };
                bucket.try_consume(now, limits)
            } else {
                let new_bucket = Bucket::seeded(limits, now);
                let _ = $rate_map.insert(src, &new_bucket, 0);
                true
            }
        }
    };
}

src_gate!(src_allowed_v4, [u8; 4], V4_SRC_RATE);
src_gate!(src_allowed_v6, [u8; 16], V6_SRC_RATE);

/// Record a per-source offense (rate-limit drop) for one address family.
macro_rules! src_drop_recorder {
    ($name:ident, $key:ty, $map:ident) => {
        #[inline(always)]
        pub fn $name(src: &$key) {
            if let Some(c) = $map.get_ptr_mut(src) {
                unsafe { *c += 1 };
            } else {
                let one: u64 = 1;
                let _ = $map.insert(src, &one, 0);
            }
        }
    };
}

src_drop_recorder!(record_src_drop_v4, [u8; 4], V4_SRC_DROPS);
src_drop_recorder!(record_src_drop_v6, [u8; 16], V6_SRC_DROPS);

/// CIDR block check for one address family: true if `src` matches a blocked
/// prefix. A full-length prefix lookup returns the longest covering entry.
macro_rules! cidr_block_check {
    ($name:ident, $key:ty, $bits:expr, $map:ident) => {
        #[inline(always)]
        pub fn $name(src: $key) -> bool {
            let key = Key::new($bits, src);
            $map.get(&key).is_some()
        }
    };
}

cidr_block_check!(cidr_blocked_v4, [u8; 4], 32, V4_CIDR_SRC);
cidr_block_check!(cidr_blocked_v6, [u8; 16], 128, V6_CIDR_SRC);

/// Generate a dest-mode reader for one address family: returns the current
/// mitigation mode (DEST_MODE_*) for `dst`, defaulting to NORMAL.
macro_rules! dest_mode_for {
    ($name:ident, $key:ty, $map:ident) => {
        #[inline(always)]
        pub fn $name(dst: &$key) -> u32 {
            match unsafe { $map.get(dst) } {
                Some(s) => s.mode,
                None => DEST_MODE_NORMAL,
            }
        }
    };
}

dest_mode_for!(dest_mode_v4, [u8; 4], V4_DEST_STATE);
dest_mode_for!(dest_mode_v6, [u8; 16], V6_DEST_STATE);

/// Generate an ICMP-rate gate for one address family (used under mitigation).
macro_rules! icmp_gate {
    ($name:ident, $key:ty, $rate_map:ident) => {
        /// Rate-limit ICMP per dest; true if the packet should pass.
        #[inline(always)]
        pub fn $name(dst: &$key) -> bool {
            let now = unsafe { bpf_ktime_get_ns() };
            if let Some(b) = $rate_map.get_ptr_mut(dst) {
                let bucket = unsafe { &mut *b };
                bucket.try_consume(now, &DEFAULT_ICMP_LIMITS)
            } else {
                let new_bucket = Bucket::seeded(&DEFAULT_ICMP_LIMITS, now);
                let _ = $rate_map.insert(dst, &new_bucket, 0);
                true
            }
        }
    };
}

icmp_gate!(icmp_allowed_v4, [u8; 4], V4_ICMP_RATE);
icmp_gate!(icmp_allowed_v6, [u8; 16], V6_ICMP_RATE);

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

/// Generate a learn-open-port function for one address family. Called from the
/// TC egress program with the local (source) address/port of an outbound
/// packet that indicates an open service (TCP SYN-ACK or any UDP). Inserts a
/// fresh entry or refreshes `last_seen` on an existing one. Fails open (best
/// effort) if the map is full.
macro_rules! learn_port_for {
    ($name:ident, $key:ty) => {
        #[inline(always)]
        pub fn $name(map: &$crate::maps::OpenPortsMapAlias<$key>, key: &$key) {
            let now = unsafe { bpf_ktime_get_ns() };
            if let Some(v) = map.get_ptr_mut(key) {
                unsafe { (*v).last_seen = now };
            } else {
                let seen = LastSeen { last_seen: now };
                let _ = map.insert(key, &seen, 0);
            }
        }
    };
}

/// Type alias so the macro can name the concrete `LruHashMap` type generically.
pub type OpenPortsMapAlias<K> = LruHashMap<K, LastSeen>;

learn_port_for!(learn_port_v4, PortKeyV4);
learn_port_for!(learn_port_v6, PortKeyV6);

/// Generate an open-port lookup for one address family. `port` is host byte
/// order (as learned by the egress program). Returns true if `(addr, port,
/// proto)` is a currently-learned open service.
macro_rules! port_open_for {
    ($name:ident, $key:ty, $addr:ty, $map:ident) => {
        #[inline(always)]
        pub fn $name(addr: $addr, port: u16, proto: u8) -> bool {
            let key = <$key>::new(addr, port, proto);
            unsafe { $map.get(&key) }.is_some()
        }
    };
}

port_open_for!(port_is_open_v4, PortKeyV4, [u8; 4], OPEN_PORTS_V4);
port_open_for!(port_is_open_v6, PortKeyV6, [u8; 16], OPEN_PORTS_V6);
