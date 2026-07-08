//! BPF-facing control loop. Each tick:
//! 1. sample per-destination counters and run the pure detection state machine
//!    ([`crate::detect`]), writing modes into `*_DEST_STATE`;
//! 2. sample the bounded per-source counters, compute per-source rates, pick
//!    offenders, aggregate them into CIDR blocks ([`crate::cidr`]) and reconcile
//!    the `*_CIDR_SRC` LPM tries (install new, decay stale).
//!
//! The eBPF side only counts and enforces; every rate/threshold decision is made
//! here. The timestamp is injected (`now_ns`) so the datapath test harness can
//! drive deterministic sample windows.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuHashMap};
use aya::{Ebpf, Pod};
use log::{info, warn};

use lnvps_fw_common::{DEST_MODE_MITIGATE, DestCounters, DestState};

use crate::cidr::{CidrV4, CidrV6, aggregate_v4, aggregate_v6, offenders, per_source_pps};
use crate::detect::{DestTracker, DetectionConfig, Rates, Transition, process_sample};

/// Runtime configuration for one control tick.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeConfig {
    /// Per-destination detection thresholds + hysteresis.
    pub detection: DetectionConfig,
    /// Per-source packets/second that marks a source as an offender.
    pub src_rate_pps: u64,
    /// Aggregation fan-out: this many child prefixes under a parent collapse to
    /// the parent (/32->/24->/16->/8, /128->/64->/48->/32).
    pub fanout: usize,
    /// A CIDR block is lifted this many ns after it stops being refreshed.
    pub block_ttl_ns: u64,
}

/// Per-address-family control state kept across sample windows.
#[derive(Default)]
pub struct DetectionState {
    pub v4: HashMap<[u8; 4], DestTracker>,
    pub v6: HashMap<[u8; 16], DestTracker>,
    /// Injected timestamp of the previous sample (0 = first run).
    pub last_sample_ns: u64,
    /// Previous cumulative per-source counter snapshots (for rate deltas).
    pub prev_src_v4: HashMap<[u8; 4], u64>,
    pub prev_src_v6: HashMap<[u8; 16], u64>,
    /// Active CIDR blocks -> timestamp last refreshed (for TTL decay).
    pub blocks_v4: HashMap<CidrV4, u64>,
    pub blocks_v6: HashMap<CidrV6, u64>,
}

/// Sum per-CPU `DestCounters` slots into one total.
pub fn sum_counters<'a>(values: impl IntoIterator<Item = &'a DestCounters>) -> DestCounters {
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

fn log_event_start(ip: &str, rates: &Rates) {
    warn!(
        "MITIGATION START dest={ip} pps={} syn_pps={} bps={} drop_pps={} pass_pps={}",
        rates.pps, rates.syn_pps, rates.bps, rates.drop_pps, rates.pass_pps
    );
}

fn log_event_stop(ip: &str, peak: &Rates, dropped_total: u64) {
    info!(
        "MITIGATION STOP dest={ip} peak_pps={} peak_syn_pps={} peak_bps={} peak_drop_pps={} peak_pass_pps={} dropped_total={dropped_total}",
        peak.pps, peak.syn_pps, peak.bps, peak.drop_pps, peak.pass_pps
    );
}

/// Run the detection state machine for every sampled destination of one family
/// and apply transitions to `state_map`.
fn detect_family<K>(
    samples: Vec<(K, DestCounters)>,
    state_map: &mut AyaHashMap<&mut MapData, K, DestState>,
    trackers: &mut HashMap<K, DestTracker>,
    cfg: &DetectionConfig,
    now_ns: u64,
    elapsed_ns: u64,
    fmt_ip: impl Fn(&K) -> String,
) where
    K: Pod + Eq + Hash + Copy,
{
    for (key, cur) in samples {
        let tracker = trackers.entry(key).or_default();
        let (transition, rates) = process_sample(cur, tracker, cfg, now_ns, elapsed_ns);
        match transition {
            Transition::Entered => {
                let st = DestState {
                    mode: DEST_MODE_MITIGATE,
                    _pad: 0,
                    entered_at: now_ns,
                };
                if let Err(e) = state_map.insert(key, st, 0) {
                    warn!("failed to set mitigate state for {}: {e}", fmt_ip(&key));
                }
                log_event_start(&fmt_ip(&key), &rates);
            }
            Transition::Exited => {
                let peak = tracker.peak;
                if let Err(e) = state_map.remove(&key) {
                    warn!("failed to clear mitigate state for {}: {e}", fmt_ip(&key));
                }
                log_event_stop(&fmt_ip(&key), &peak, cur.dropped);
                tracker.peak = Rates::default();
            }
            Transition::None => {}
        }
    }
}

/// Read + per-CPU-sum a `DestCounters` map into an owned vec.
fn read_counters<K>(bpf: &Ebpf, name: &str) -> Result<Vec<(K, DestCounters)>>
where
    K: Pod,
{
    let map: PerCpuHashMap<_, K, DestCounters> =
        PerCpuHashMap::try_from(bpf.map(name).with_context(|| format!("{name} missing"))?)?;
    let mut out = Vec::new();
    for entry in map.iter() {
        let (k, values) = entry?;
        out.push((k, sum_counters(values.iter())));
    }
    Ok(out)
}

/// Read + per-CPU-sum a per-source `u64` counter map into an owned vec.
fn read_src_counters<K>(bpf: &Ebpf, name: &str) -> Result<Vec<(K, u64)>>
where
    K: Pod,
{
    let map: PerCpuHashMap<_, K, u64> =
        PerCpuHashMap::try_from(bpf.map(name).with_context(|| format!("{name} missing"))?)?;
    let mut out = Vec::new();
    for entry in map.iter() {
        let (k, values) = entry?;
        out.push((k, values.iter().copied().sum()));
    }
    Ok(out)
}

/// Reconcile one family's CIDR block trie with the freshly-computed `desired`
/// block set: install/refresh desired blocks, then decay any not refreshed
/// within the TTL. Updates `prev_src` for the next window's deltas.
#[allow(clippy::too_many_arguments)]
fn reconcile_blocks<K, C>(
    cur_src: Vec<(K, u64)>,
    prev_src: &mut HashMap<K, u64>,
    blocks: &mut HashMap<C, u64>,
    trie: &mut LpmTrie<&mut MapData, K, u8>,
    desired: Vec<C>,
    block_ttl_ns: u64,
    now_ns: u64,
    key_of: impl Fn(&C) -> Key<K>,
    fmt_cidr: impl Fn(&C) -> String,
) where
    K: Pod + Eq + Hash + Copy,
    C: Eq + Hash + Copy,
{
    for cidr in desired {
        if blocks.insert(cidr, now_ns).is_none() {
            if let Err(e) = trie.insert(&key_of(&cidr), 1, 0) {
                warn!("failed to install CIDR block {}: {e}", fmt_cidr(&cidr));
                blocks.remove(&cidr);
                continue;
            }
            warn!("CIDR BLOCK {}", fmt_cidr(&cidr));
        }
    }
    let expired: Vec<C> = blocks
        .iter()
        .filter(|(_, ts)| now_ns.saturating_sub(**ts) > block_ttl_ns)
        .map(|(c, _)| *c)
        .collect();
    for cidr in expired {
        let _ = trie.remove(&key_of(&cidr));
        blocks.remove(&cidr);
        info!("CIDR UNBLOCK {}", fmt_cidr(&cidr));
    }
    *prev_src = cur_src.into_iter().collect();
}

/// One control tick at the injected `now_ns`: detection + source control across
/// both address families, sharing a single elapsed window. The first tick
/// (`last_sample_ns == 0`) seeds snapshots with a zero elapsed so it never
/// computes spurious rates.
pub fn run_control(
    bpf: &mut Ebpf,
    state: &mut DetectionState,
    cfg: &RuntimeConfig,
    now_ns: u64,
) -> Result<()> {
    let elapsed = if state.last_sample_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(state.last_sample_ns)
    };
    state.last_sample_ns = now_ns;

    // --- Per-destination detection ---
    let v4 = read_counters::<[u8; 4]>(bpf, "V4_DEST_COUNTERS")?;
    {
        let mut sm: AyaHashMap<_, [u8; 4], DestState> =
            AyaHashMap::try_from(bpf.map_mut("V4_DEST_STATE").context("v4 state missing")?)?;
        detect_family(
            v4,
            &mut sm,
            &mut state.v4,
            &cfg.detection,
            now_ns,
            elapsed,
            |k| Ipv4Addr::from(*k).to_string(),
        );
    }
    let v6 = read_counters::<[u8; 16]>(bpf, "V6_DEST_COUNTERS")?;
    {
        let mut sm: AyaHashMap<_, [u8; 16], DestState> =
            AyaHashMap::try_from(bpf.map_mut("V6_DEST_STATE").context("v6 state missing")?)?;
        detect_family(
            v6,
            &mut sm,
            &mut state.v6,
            &cfg.detection,
            now_ns,
            elapsed,
            |k| Ipv6Addr::from(*k).to_string(),
        );
    }

    // --- Per-source control (rate -> CIDR blocks) ---
    let s4 = read_src_counters::<[u8; 4]>(bpf, "V4_SRC_COUNTERS")?;
    let off4 = offenders(
        &per_source_pps(&state.prev_src_v4, &s4, elapsed),
        cfg.src_rate_pps,
    );
    let desired4 = aggregate_v4(&off4, cfg.fanout);
    {
        let mut trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(bpf.map_mut("V4_CIDR_SRC").context("v4 cidr trie missing")?)?;
        reconcile_blocks(
            s4,
            &mut state.prev_src_v4,
            &mut state.blocks_v4,
            &mut trie,
            desired4,
            cfg.block_ttl_ns,
            now_ns,
            |c| Key::new(c.prefix_len, c.network),
            |c| format!("{}/{}", Ipv4Addr::from(c.network), c.prefix_len),
        );
    }

    let s6 = read_src_counters::<[u8; 16]>(bpf, "V6_SRC_COUNTERS")?;
    let off6 = offenders(
        &per_source_pps(&state.prev_src_v6, &s6, elapsed),
        cfg.src_rate_pps,
    );
    let desired6 = aggregate_v6(&off6, cfg.fanout);
    {
        let mut trie: LpmTrie<_, [u8; 16], u8> =
            LpmTrie::try_from(bpf.map_mut("V6_CIDR_SRC").context("v6 cidr trie missing")?)?;
        reconcile_blocks(
            s6,
            &mut state.prev_src_v6,
            &mut state.blocks_v6,
            &mut trie,
            desired6,
            cfg.block_ttl_ns,
            now_ns,
            |c| Key::new(c.prefix_len, c.network),
            |c| format!("{}/{}", Ipv6Addr::from(c.network), c.prefix_len),
        );
    }
    Ok(())
}
