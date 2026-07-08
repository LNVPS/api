use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap};
use lnvps_fw_common::{DEST_MODE_NORMAL, DestCounters, DestState, LastSeen, PortKeyV4, PortKeyV6};

/// Max number of destination IPs to track (per address family)
pub const MAX_DST_IPS: u32 = 256 * 1024;

/// Max number of learned (ip, port, proto) tuples to track (per family)
pub const MAX_OPEN_PORTS: u32 = 1024 * 1024;

/// Max number of distinct source addresses tracked while mitigating. The map
/// is LRU, so under a very high-cardinality (spoofed) flood it self-bounds by
/// evicting cold entries — that pressure is the signal for userspace to
/// escalate to wide CIDR blocks rather than chase individual /32s.
pub const MAX_SRC_IPS: u32 = 256 * 1024;

/// Max number of CIDR block entries in the LPM tries. Kept bounded by the
/// userspace aggregation/expansion logic (/32 -> /24 -> /16 -> /8).
pub const MAX_CIDR_BLOCKS: u32 = 64 * 1024;

/// Per-destination traffic counters (IPv4), sampled by userspace detection loop
#[map]
pub static V4_DEST_COUNTERS: LruPerCpuHashMap<[u8; 4], DestCounters> =
    LruPerCpuHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Per-destination traffic counters (IPv6), sampled by userspace detection loop
#[map]
pub static V6_DEST_COUNTERS: LruPerCpuHashMap<[u8; 16], DestCounters> =
    LruPerCpuHashMap::with_max_entries(MAX_DST_IPS, 0);

/// Per-source packet counters (IPv4), incremented only while the destination
/// is mitigating. Sampled by userspace to compute per-source rates and drive
/// CIDR escalation. LRU + per-CPU: bounded memory, summed across CPUs.
#[map]
pub static V4_SRC_COUNTERS: LruPerCpuHashMap<[u8; 4], u64> =
    LruPerCpuHashMap::with_max_entries(MAX_SRC_IPS, 0);

/// Per-source packet counters (IPv6).
#[map]
pub static V6_SRC_COUNTERS: LruPerCpuHashMap<[u8; 16], u64> =
    LruPerCpuHashMap::with_max_entries(MAX_SRC_IPS, 0);

/// Mitigation state per dest IPv4 (written by userspace detection loop)
#[map]
pub static V4_DEST_STATE: HashMap<[u8; 4], DestState> = HashMap::with_max_entries(MAX_DST_IPS, 0);

/// Mitigation state per dest IPv6
#[map]
pub static V6_DEST_STATE: HashMap<[u8; 16], DestState> = HashMap::with_max_entries(MAX_DST_IPS, 0);

/// Learned-open TCP/UDP ports for local IPv4 addresses, discovered by passive
/// egress observation. Read by the XDP ingress program under mitigation.
#[map]
pub static OPEN_PORTS_V4: LruHashMap<PortKeyV4, LastSeen> =
    LruHashMap::with_max_entries(MAX_OPEN_PORTS, 0);

/// Learned-open TCP/UDP ports for local IPv6 addresses.
#[map]
pub static OPEN_PORTS_V6: LruHashMap<PortKeyV6, LastSeen> =
    LruHashMap::with_max_entries(MAX_OPEN_PORTS, 0);

/// Blocked source CIDRs (IPv4), an LPM trie of network-order address bytes.
/// Written by userspace escalation; any source matching a prefix is dropped.
/// Holds both individual /32 offenders and aggregated wider prefixes.
#[map]
pub static V4_CIDR_SRC: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(MAX_CIDR_BLOCKS, 0);

/// Blocked source CIDRs (IPv6).
#[map]
pub static V6_CIDR_SRC: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(MAX_CIDR_BLOCKS, 0);

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

/// Generate a per-source packet-count incrementer for one address family
/// (called under mitigation). Pure counting — no policy decision.
macro_rules! count_src_for {
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

count_src_for!(count_src_v4, [u8; 4], V4_SRC_COUNTERS);
count_src_for!(count_src_v6, [u8; 16], V6_SRC_COUNTERS);

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
