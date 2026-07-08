//! Virtualized-network test harness for the LNVPS firewall datapath.
//!
//! Builds a netns/veth topology (see [`netns`]), loads the compiled eBPF
//! object into the `filter` namespace, attaches the XDP ingress program to the
//! uplink veth in SKB (generic) mode — which veth interfaces support on any
//! modern kernel — and exposes typed handles over the BPF maps plus traffic
//! generators for writing datapath assertions.
//!
//! All of this requires `CAP_NET_ADMIN`/`CAP_BPF` (root). Tests using the
//! harness are `#[ignore]`d and additionally guarded by [`require_root`] so a
//! plain `cargo test` stays green for unprivileged runs.
//!
//! Some items are only used by a subset of the test binaries that include this
//! module, so unused-code warnings are silenced here.
#![allow(dead_code)]

pub mod netns;
pub mod traffic;

use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap as AyaHashMap, PerCpuHashMap};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc::qdisc_add_clsact};
use aya::{Ebpf, EbpfLoader};
use nix::sched::{CloneFlags, setns};

use lnvps_fw_common::{
    DEST_MODE_MITIGATE, DestCounters, DestState, LastSeen, PortKeyV4, PortKeyV6,
};
use lnvps_fw_service::runtime::{DetectionState, RuntimeConfig, run_control};

use netns::NetnsTopology;

/// The compiled eBPF object, produced by the package build script
/// (`aya-build`) at the same `OUT_DIR` the service binary embeds.
pub static EBPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lnvps_ebpf"));

// `include_bytes_aligned!` is re-exported from aya; keep a local alias so the
// static above reads cleanly.
use aya::include_bytes_aligned;

/// Skip a test (returning `false`) unless running as root. Prints a clear
/// notice so an accidentally-unignored run is obvious.
pub fn require_root() -> bool {
    // SAFETY: geteuid is always safe.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!("SKIP: firewall harness tests require root (run via scripts/fw-e2e.sh)");
        return false;
    }
    true
}

/// A fully wired harness: topology + loaded/attached eBPF, with map accessors.
pub struct Harness {
    pub topo: NetnsTopology,
    bpf: Ebpf,
}

impl Harness {
    /// Build the topology and attach the XDP program on the filter uplink.
    pub fn new() -> anyhow::Result<Self> {
        let topo = NetnsTopology::new()?;

        let mut bpf = EbpfLoader::new().load(EBPF_OBJECT)?;

        // XDP/TC attach resolves the interface index in the *current* thread's
        // network namespace, so switch into the filter namespace for the
        // load+attach, then switch back. Map access afterwards is fd-based and
        // namespace-independent. Both programs attach to the uplink veth
        // (f_up): XDP inspects ingress (attack) traffic, TC egress learns open
        // ports from the VM's outbound replies. Each program's borrow of `bpf`
        // is scoped so the two do not overlap.
        {
            let _guard = NetnsSwitch::enter(&topo.filter_ns_path())?;
            {
                let prog: &mut Xdp = bpf
                    .program_mut("xdp_lnvps")
                    .ok_or_else(|| anyhow::anyhow!("xdp_lnvps program not found"))?
                    .try_into()?;
                prog.load()?;
                prog.attach(&topo.filter_up_if, XdpMode::Skb)?;
            }
            {
                let tc: &mut SchedClassifier = bpf
                    .program_mut("tc_lnvps_egress")
                    .ok_or_else(|| anyhow::anyhow!("tc_lnvps_egress program not found"))?
                    .try_into()?;
                tc.load()?;
                let _ = qdisc_add_clsact(&topo.filter_up_if);
                tc.attach(&topo.filter_up_if, TcAttachType::Egress)?;
            }
        }

        Ok(Self { topo, bpf })
    }

    /// Sum the per-CPU IPv4 destination counters for `ip`, if present.
    pub fn dest_counters_v4(&self, ip: Ipv4Addr) -> anyhow::Result<Option<DestCounters>> {
        let map: PerCpuHashMap<_, [u8; 4], DestCounters> =
            PerCpuHashMap::try_from(self.bpf.map("V4_DEST_COUNTERS").unwrap())?;
        match map.get(&ip.octets(), 0) {
            Ok(values) => Ok(Some(sum_counters(values.iter()))),
            Err(_) => Ok(None),
        }
    }

    /// Sum the per-CPU IPv6 destination counters for `ip`, if present.
    pub fn dest_counters_v6(&self, ip: Ipv6Addr) -> anyhow::Result<Option<DestCounters>> {
        let map: PerCpuHashMap<_, [u8; 16], DestCounters> =
            PerCpuHashMap::try_from(self.bpf.map("V6_DEST_COUNTERS").unwrap())?;
        match map.get(&ip.octets(), 0) {
            Ok(values) => Ok(Some(sum_counters(values.iter()))),
            Err(_) => Ok(None),
        }
    }

    /// Look up a learned IPv4 open port, returning its `LastSeen` if present.
    /// `port`/`proto` use the same host-order/`PROTO_*` convention the eBPF
    /// program writes.
    pub fn open_port_v4(
        &self,
        ip: Ipv4Addr,
        port: u16,
        proto: u8,
    ) -> anyhow::Result<Option<LastSeen>> {
        let map: AyaHashMap<_, PortKeyV4, LastSeen> =
            AyaHashMap::try_from(self.bpf.map("OPEN_PORTS_V4").unwrap())?;
        let key = PortKeyV4 {
            addr: ip.octets(),
            port,
            proto,
            _pad: 0,
        };
        Ok(map.get(&key, 0).ok())
    }

    /// Number of IPv4 learned-open-port entries currently in the map.
    pub fn open_port_count_v4(&self) -> anyhow::Result<usize> {
        let map: AyaHashMap<_, PortKeyV4, LastSeen> =
            AyaHashMap::try_from(self.bpf.map("OPEN_PORTS_V4").unwrap())?;
        Ok(map.keys().flatten().count())
    }

    /// Run the userspace learned-port GC (as the daemon does) over the IPv4
    /// map with the given TTL, returning the number of entries removed. Uses
    /// the shared `gc` logic so the harness test exercises real code.
    pub fn gc_open_ports_v4(&mut self, ttl_ns: u64) -> anyhow::Result<usize> {
        let now = lnvps_fw_service::gc::monotonic_now_ns();
        let mut map: AyaHashMap<_, PortKeyV4, LastSeen> =
            AyaHashMap::try_from(self.bpf.map_mut("OPEN_PORTS_V4").unwrap())?;
        Ok(lnvps_fw_service::gc::gc_open_ports(&mut map, now, ttl_ns))
    }

    /// Force an IPv4 destination (or prefix) into MITIGATE mode by writing the
    /// dest-state LPM trie, for testing enforcement independently of detection.
    /// `prefix_len` of 32 blocks a single IP; a shorter length a whole prefix.
    pub fn set_mitigate_v4(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        self.set_mitigate_prefix_v4(ip, 32)
    }

    /// Write a MITIGATE entry at an arbitrary prefix length.
    pub fn set_mitigate_prefix_v4(&mut self, net: Ipv4Addr, prefix_len: u32) -> anyhow::Result<()> {
        let mut trie: LpmTrie<_, [u8; 4], DestState> =
            LpmTrie::try_from(self.bpf.map_mut("V4_DEST_STATE").unwrap())?;
        let st = DestState {
            mode: DEST_MODE_MITIGATE,
            _pad: 0,
            entered_at: 0,
        };
        trie.insert(&Key::new(prefix_len, net.octets()), st, 0)?;
        Ok(())
    }

    /// Read the effective mitigation mode covering an IPv4 destination via a
    /// longest-prefix lookup (default NORMAL = 0 if no covering entry).
    pub fn dest_mode_v4(&self, ip: Ipv4Addr) -> anyhow::Result<u32> {
        let trie: LpmTrie<_, [u8; 4], DestState> =
            LpmTrie::try_from(self.bpf.map("V4_DEST_STATE").unwrap())?;
        Ok(trie
            .get(&Key::new(32, ip.octets()), 0)
            .map(|s| s.mode)
            .unwrap_or(0))
    }

    /// Run one real control tick (the daemon's `runtime::run_control`, i.e.
    /// detection plus per-source CIDR escalation) at the injected `now_ns`,
    /// driving the shared `state` across calls.
    pub fn run_control_tick(
        &mut self,
        state: &mut DetectionState,
        cfg: &RuntimeConfig,
        now_ns: u64,
    ) -> anyhow::Result<()> {
        run_control(&mut self.bpf, state, cfg, now_ns)
    }

    /// True if `ip` is covered by a blocked source CIDR in `V4_CIDR_SRC`.
    pub fn cidr_blocked_v4(&self, ip: Ipv4Addr) -> anyhow::Result<bool> {
        let trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(self.bpf.map("V4_CIDR_SRC").unwrap())?;
        Ok(trie.get(&Key::new(32, ip.octets()), 0).is_ok())
    }

    /// Summed per-CPU per-source packet count for `ip` (0 if absent).
    pub fn src_packets_v4(&self, ip: Ipv4Addr) -> anyhow::Result<u64> {
        let map: PerCpuHashMap<_, [u8; 4], u64> =
            PerCpuHashMap::try_from(self.bpf.map("V4_SRC_COUNTERS").unwrap())?;
        match map.get(&ip.octets(), 0) {
            Ok(values) => Ok(values.iter().copied().sum()),
            Err(_) => Ok(0),
        }
    }

    /// Provide access to the raw v6 port key type for callers building keys.
    pub fn open_port_v6(
        &self,
        ip: Ipv6Addr,
        port: u16,
        proto: u8,
    ) -> anyhow::Result<Option<LastSeen>> {
        let map: AyaHashMap<_, PortKeyV6, LastSeen> =
            AyaHashMap::try_from(self.bpf.map("OPEN_PORTS_V6").unwrap())?;
        let key = PortKeyV6 {
            addr: ip.octets(),
            port,
            proto,
            _pad: 0,
        };
        Ok(map.get(&key, 0).ok())
    }
}

/// Sum per-CPU `DestCounters` slots into one total.
fn sum_counters<'a>(values: impl IntoIterator<Item = &'a DestCounters>) -> DestCounters {
    let mut total = DestCounters::default();
    for v in values {
        total.packets += v.packets;
        total.bytes += v.bytes;
        total.syn_packets += v.syn_packets;
        total.tcp_packets += v.tcp_packets;
        total.udp_packets += v.udp_packets;
        total.icmp_packets += v.icmp_packets;
        total.dropped += v.dropped;
    }
    total
}

/// RAII network-namespace switch for the current thread. Restores the original
/// namespace on drop.
struct NetnsSwitch {
    original: File,
}

impl NetnsSwitch {
    fn enter(ns_path: &str) -> anyhow::Result<Self> {
        let original = File::open("/proc/self/ns/net")?;
        let target = File::open(ns_path)?;
        setns(target.as_fd(), CloneFlags::CLONE_NEWNET)
            .map_err(|e| anyhow::anyhow!("setns({ns_path}): {e}"))?;
        Ok(Self { original })
    }
}

impl Drop for NetnsSwitch {
    fn drop(&mut self) {
        let _ = setns(self.original.as_fd(), CloneFlags::CLONE_NEWNET);
    }
}
