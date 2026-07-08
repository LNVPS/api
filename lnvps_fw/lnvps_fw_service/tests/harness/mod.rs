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

use aya::maps::{HashMap as AyaHashMap, PerCpuHashMap};
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use nix::sched::{CloneFlags, setns};

use lnvps_fw_common::{Bucket, DestCounters, PacketLimits};

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
        let prog: &mut Xdp = bpf
            .program_mut("xdp_lnvps")
            .ok_or_else(|| anyhow::anyhow!("xdp_lnvps program not found"))?
            .try_into()?;
        prog.load()?;

        // XDP attach resolves the interface index in the *current* thread's
        // network namespace, so switch into the filter namespace just for the
        // attach, then switch back. Map access afterwards is fd-based and
        // namespace-independent.
        {
            let _guard = NetnsSwitch::enter(&topo.filter_ns_path())?;
            prog.attach(&topo.filter_up_if, XdpMode::Skb)?;
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

    /// Read the current SYN token bucket for an IPv4 destination, if present.
    pub fn syn_bucket_v4(&self, ip: Ipv4Addr) -> anyhow::Result<Option<Bucket>> {
        let map: AyaHashMap<_, [u8; 4], Bucket> =
            AyaHashMap::try_from(self.bpf.map("V4_SYN_RATE").unwrap())?;
        Ok(map.get(&ip.octets(), 0).ok())
    }

    /// Override the SYN rate limits for an IPv4 destination.
    pub fn set_syn_limits_v4(&mut self, ip: Ipv4Addr, limits: PacketLimits) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, [u8; 4], PacketLimits> =
            AyaHashMap::try_from(self.bpf.map_mut("V4_SYN_RATE_LIMITS").unwrap())?;
        map.insert(ip.octets(), limits, 0)?;
        Ok(())
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
