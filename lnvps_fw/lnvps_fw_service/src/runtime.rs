//! BPF-facing control loop implementing the mitigation escalation ladder.
//!
//! Each tick, in efficacy order (cheapest/highest-efficacy/lowest-false-
//! positive first):
//! 1. sample the bounded per-source counters and decide, in userspace, whether
//!    to do source blocking at all — only when offenders are *bounded* (a real
//!    botnet). Under a spoofed flood the offender set explodes, so we skip it
//!    (blocking spoofed /32s is pointless and raises false positives);
//! 2. run the per-destination and per-protected-prefix detection state machine,
//!    writing an escalation *level* into the dest-state LPM trie. Every attacked
//!    dest/prefix enters at `PORT_FILTER` (the open-port allow-list drop, which
//!    sheds the bulk of a flood); it is only escalated to `SOURCE_BLOCK` when
//!    traffic keeps getting through (`pass_pps` stays high) *and* source
//!    blocking is warranted.
//!
//! The eBPF side only counts and enforces; every threshold decision is here.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{MapData, PerCpuHashMap};
use aya::{Ebpf, Pod};
use log::{info, warn};

use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY,
    DestCounters, DestState,
};

use crate::cidr::{CidrV4, CidrV6, mask_v4, mask_v6, plan_blocks_v4, plan_blocks_v6};
use crate::detect::{
    DestTracker, DetectionConfig, Rates, SourceDetectionConfig, SourceTracker, Transition,
    advance_source, compute_rates, process_sample,
};

/// Runtime configuration for one control tick.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Per-destination detection thresholds + hysteresis (single-IP attacks).
    pub detection: DetectionConfig,
    /// Per-protected-prefix aggregate thresholds (carpet-bomb / thin-spread
    /// floods that never trip any single destination).
    pub network: DetectionConfig,
    /// Protected IPv4 prefixes as (prefix_len, network-bytes).
    pub protected_v4: Vec<(u32, [u8; 4])>,
    /// Protected IPv6 prefixes.
    pub protected_v6: Vec<(u32, [u8; 16])>,
    /// Per-source packets/second that marks a source as an offender.
    pub src_rate_pps: u64,
    /// Aggregation fan-out: this many child prefixes under a parent collapse to
    /// the parent (/32->/24->/16->/8, /128->/64->/48->/32).
    pub fanout: usize,
    /// Widest IPv4 source block aggregation may ever produce (smallest prefix
    /// length, e.g. 24 = never wider than a /24). Prevents a scatter of
    /// offenders from collapsing into a huge allocation-crossing block.
    pub agg_max_prefix_v4: u32,
    /// Widest IPv6 source block aggregation may ever produce.
    pub agg_max_prefix_v6: u32,
    /// A DROPPING source's exit hysteresis (% of `src_rate_pps`).
    pub src_exit_pct: u64,
    /// Sustained time below the source exit threshold before a source returns
    /// to NORMAL and is unblocked.
    pub src_cooldown_ns: u64,
    /// Trie-space budget: block sources as individual /32s (v4) / /128s (v6)
    /// until this many entries, only aggregating under pressure beyond it.
    pub max_source_blocks: usize,
    /// A CIDR block is lifted this many ns after it stops being refreshed
    /// (safety upper-bound for sources evicted from the per-source counter LRU;
    /// the per-source state machine is the primary release mechanism).
    pub block_ttl_ns: u64,
    /// Escalate a mitigating dest/prefix to `SOURCE_BLOCK` only if this many
    /// packets/second are still getting through after the port filter.
    pub escalate_pass_pps: u64,
    /// Spoof gate: if more than this many distinct offenders are seen in a
    /// window, treat the flood as spoofed and skip source blocking entirely
    /// (rely on the port filter instead of chasing unblockable /32s).
    pub max_real_sources: usize,
    /// Enable the SYN_PROXY flag once a mitigating entity's SYN rate reaches
    /// this many SYNs/second.
    pub syn_proxy_pps: u64,
}

/// Per-address-family control state kept across sample windows.
#[derive(Default)]
pub struct DetectionState {
    pub v4: HashMap<[u8; 4], DestTracker>,
    pub v6: HashMap<[u8; 16], DestTracker>,
    /// Injected timestamp of the previous sample (0 = first run).
    pub last_sample_ns: u64,
    /// Per-protected-prefix detection trackers, keyed by (prefix_len, network).
    pub prefix_v4: HashMap<(u32, [u8; 4]), DestTracker>,
    pub prefix_v6: HashMap<(u32, [u8; 16]), DestTracker>,
    /// Per-source rate state machines (NORMAL/DROPPING with hysteresis), keyed
    /// by source address. A source is in the block trie only while its tracker
    /// is DROPPING; it is released as soon as its rate falls back (hysteresis),
    /// not held for a blind TTL.
    pub src_v4: HashMap<[u8; 4], SourceTracker>,
    pub src_v6: HashMap<[u8; 16], SourceTracker>,
    /// Active CIDR blocks -> timestamp last refreshed (for TTL decay).
    pub blocks_v4: HashMap<CidrV4, u64>,
    pub blocks_v6: HashMap<CidrV6, u64>,
    /// Active CIDR blocks -> current aggregate pps from sources under them.
    pub block_pps_v4: HashMap<CidrV4, u64>,
    pub block_pps_v6: HashMap<CidrV6, u64>,
    /// Previous cumulative TX (egress) counter snapshots, keyed by local IP.
    pub prev_tx_v4: HashMap<[u8; 4], DestCounters>,
    pub prev_tx_v6: HashMap<[u8; 16], DestCounters>,
    /// Latest per-local-IP TX rates (for the tx/rx dashboard view).
    pub tx_v4: HashMap<[u8; 4], Rates>,
    pub tx_v6: HashMap<[u8; 16], Rates>,
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

fn dest_state(level: u32, now_ns: u64) -> DestState {
    DestState {
        mode: level,
        _pad: 0,
        entered_at: now_ns,
    }
}

/// Protection flags for a mitigating entity. The port filter is the always-on
/// base; the SOURCE_BLOCK flag is added only when source blocking is warranted
/// (bounded/real offenders present) and traffic is still getting through after
/// the port filter. Other flags (SYN_PROXY, RATE_CAPS) are OR'd in here as they
/// are implemented, so any subset can be active at once.
fn enforced_flags(
    rates: &Rates,
    source_block_active: bool,
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
) -> u32 {
    let mut flags = DEST_MODE_PORT_FILTER;
    // A sustained SYN flood engages the SYN-proxy (validate handshakes to open
    // TCP ports with cookies). High efficacy vs spoofed SYN floods, low FP.
    if rates.syn_pps >= syn_proxy_pps {
        flags |= DEST_MODE_SYN_PROXY;
    }
    if source_block_active && rates.pass_pps >= escalate_pass_pps {
        flags |= DEST_MODE_SOURCE_BLOCK;
    }
    flags
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

/// Per-destination detection for one family, writing the escalation level into
/// the dest-state LPM trie on transitions and level changes.
#[allow(clippy::too_many_arguments)]
fn detect_family<K>(
    samples: &[(K, DestCounters)],
    trie: &mut LpmTrie<&mut MapData, K, DestState>,
    bits: u32,
    trackers: &mut HashMap<K, DestTracker>,
    cfg: &DetectionConfig,
    source_block_active: bool,
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
    now_ns: u64,
    elapsed_ns: u64,
    fmt_ip: impl Fn(&K) -> String,
) where
    K: Pod + Eq + Hash + Copy,
{
    for (key, cur) in samples {
        let tracker = trackers.entry(*key).or_default();
        let (transition, rates) = process_sample(*cur, tracker, cfg, now_ns, elapsed_ns);
        if tracker.mode == DEST_MODE_NORMAL {
            if transition == Transition::Exited {
                let _ = trie.remove(&Key::new(bits, *key));
                log_event_stop(&fmt_ip(key), &tracker.peak, cur.dropped);
                tracker.peak = Rates::default();
                tracker.flags = DEST_MODE_NORMAL;
            }
            continue;
        }
        // Active: pick the enforcement level and (re)write it if changed.
        let target = enforced_flags(
            &rates,
            source_block_active,
            escalate_pass_pps,
            syn_proxy_pps,
        );
        if transition == Transition::Entered {
            let _ = trie.insert(&Key::new(bits, *key), dest_state(target, now_ns), 0);
            tracker.flags = target;
            log_event_start(&fmt_ip(key), &rates);
        } else if target != tracker.flags {
            let _ = trie.insert(&Key::new(bits, *key), dest_state(target, now_ns), 0);
            info!("MITIGATION FLAGS dest={} flags={target:#06b}", fmt_ip(key));
            tracker.flags = target;
        }
    }
}

/// Aggregate per-destination counters over one protected prefix and run the
/// network-level state machine, writing a prefix-wide level entry into the
/// dest-state LPM trie. Catches thin carpet-bomb floods.
#[allow(clippy::too_many_arguments)]
fn detect_prefix<K>(
    samples: &[(K, DestCounters)],
    trie: &mut LpmTrie<&mut MapData, K, DestState>,
    prefix_len: u32,
    network: K,
    mask: impl Fn(K, u32) -> K,
    trackers: &mut HashMap<(u32, K), DestTracker>,
    cfg: &DetectionConfig,
    source_block_active: bool,
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
    now_ns: u64,
    elapsed_ns: u64,
    fmt: impl Fn(u32, &K) -> String,
) where
    K: Pod + Eq + Hash + Copy,
{
    let mut agg = DestCounters::default();
    for (addr, c) in samples {
        if mask(*addr, prefix_len) == network {
            agg.packets += c.packets;
            agg.bytes += c.bytes;
            agg.syn_packets += c.syn_packets;
            agg.tcp_packets += c.tcp_packets;
            agg.udp_packets += c.udp_packets;
            agg.icmp_packets += c.icmp_packets;
            agg.dropped += c.dropped;
        }
    }
    let tracker = trackers.entry((prefix_len, network)).or_default();
    let (transition, rates) = process_sample(agg, tracker, cfg, now_ns, elapsed_ns);
    if tracker.mode == DEST_MODE_NORMAL {
        if transition == Transition::Exited {
            let _ = trie.remove(&Key::new(prefix_len, network));
            info!("PREFIX MITIGATION STOP net={}", fmt(prefix_len, &network));
            tracker.flags = DEST_MODE_NORMAL;
        }
        return;
    }
    let target = enforced_flags(
        &rates,
        source_block_active,
        escalate_pass_pps,
        syn_proxy_pps,
    );
    if transition == Transition::Entered {
        let _ = trie.insert(
            &Key::new(prefix_len, network),
            dest_state(target, now_ns),
            0,
        );
        tracker.flags = target;
        warn!(
            "PREFIX MITIGATION START net={} pps={} bps={} syn_pps={}",
            fmt(prefix_len, &network),
            rates.pps,
            rates.bps,
            rates.syn_pps
        );
    } else if target != tracker.flags {
        let _ = trie.insert(
            &Key::new(prefix_len, network),
            dest_state(target, now_ns),
            0,
        );
        info!(
            "PREFIX MITIGATION FLAGS net={} flags={target:#06b}",
            fmt(prefix_len, &network)
        );
        tracker.flags = target;
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

/// Advance every source's rate state machine for one family and return the set
/// of addresses currently in DROPPING. Sources not sampled this window (evicted
/// from the counter LRU, or gone quiet) are driven toward NORMAL with a
/// zero-rate window and dropped from the tracker map once they return to
/// NORMAL, so the map stays bounded.
fn step_sources<K>(
    cur: &[(K, u64)],
    trackers: &mut HashMap<K, SourceTracker>,
    scfg: &SourceDetectionConfig,
    now_ns: u64,
    elapsed_ns: u64,
) -> Vec<K>
where
    K: Eq + Hash + Copy,
{
    let cur_map: HashMap<K, u64> = cur.iter().copied().collect();
    let mut dropping = Vec::new();
    for (k, c) in cur {
        let t = trackers.entry(*k).or_default();
        let (drop, _) = advance_source(t, *c, scfg, now_ns, elapsed_ns);
        if drop {
            dropping.push(*k);
        }
    }
    // Sources absent from this window's sample: no new packets, so advance them
    // with a zero-rate window (delta 0). Once a source returns to NORMAL it is
    // removed; while still cooling down in DROPPING it stays blocked.
    let stale: Vec<K> = trackers
        .keys()
        .filter(|k| !cur_map.contains_key(*k))
        .copied()
        .collect();
    for k in stale {
        let t = trackers.get_mut(&k).expect("stale key present");
        let prev = t.prev;
        let (drop, _) = advance_source(t, prev, scfg, now_ns, elapsed_ns);
        if drop {
            dropping.push(k);
        } else {
            trackers.remove(&k);
        }
    }
    dropping
}

/// Reconcile one family's CIDR block trie to exactly the `desired` set: install
/// entries that are newly desired, remove entries no longer desired. Unlike the
/// old TTL scheme this is a pure set-diff against the per-source state machine's
/// current DROPPING set — a source is unblocked the moment its tracker leaves
/// DROPPING, not after a blind TTL.
fn reconcile_block_set<K, C>(
    blocks: &mut HashMap<C, u64>,
    trie: &mut LpmTrie<&mut MapData, K, u8>,
    desired: &[C],
    now_ns: u64,
    key_of: impl Fn(&C) -> Key<K>,
    fmt_cidr: impl Fn(&C) -> String,
) where
    K: Pod,
    C: Eq + Hash + Copy,
{
    let want: HashSet<C> = desired.iter().copied().collect();
    for c in desired {
        if !blocks.contains_key(c) {
            if let Err(e) = trie.insert(&key_of(c), 1, 0) {
                warn!("failed to install CIDR block {}: {e}", fmt_cidr(c));
                continue;
            }
            blocks.insert(*c, now_ns);
            warn!("CIDR BLOCK {}", fmt_cidr(c));
        }
    }
    let gone: Vec<C> = blocks
        .keys()
        .filter(|c| !want.contains(c))
        .copied()
        .collect();
    for c in gone {
        let _ = trie.remove(&key_of(&c));
        blocks.remove(&c);
        info!("CIDR UNBLOCK {}", fmt_cidr(&c));
    }
}

/// Aggregate per-block current pps from the per-source trackers under each
/// active block (for the API/dashboard view).
fn block_pps<K, C>(
    blocks: &HashMap<C, u64>,
    trackers: &HashMap<K, SourceTracker>,
    covers: impl Fn(&C, &K) -> bool,
) -> HashMap<C, u64>
where
    K: Eq + Hash + Copy,
    C: Eq + Hash + Copy,
{
    blocks
        .keys()
        .map(|c| {
            let sum = trackers
                .iter()
                .filter(|(ip, _)| covers(c, ip))
                .map(|(_, t)| t.last_pps)
                // (covers takes &C, &K; ip is &&K via match ergonomics)
                .sum();
            (*c, sum)
        })
        .collect::<HashMap<C, u64>>()
}

fn src_cfg(cfg: &RuntimeConfig) -> SourceDetectionConfig {
    SourceDetectionConfig {
        rate_pps: cfg.src_rate_pps,
        exit_pct: cfg.src_exit_pct,
        cooldown_ns: cfg.src_cooldown_ns,
    }
}

/// Source analysis for one family: advance the per-source state machines, apply
/// the spoof gate, plan the block set (/32-first, aggregating only under trie
/// pressure), and reconcile the trie. Returns whether any block is active
/// (drives escalation to `SOURCE_BLOCK`).
fn source_control_v4(
    bpf: &mut Ebpf,
    state: &mut DetectionState,
    cfg: &RuntimeConfig,
    now_ns: u64,
    elapsed_ns: u64,
) -> Result<bool> {
    let cur = read_src_counters::<[u8; 4]>(bpf, "V4_SRC_COUNTERS")?;
    let dropping = step_sources(&cur, &mut state.src_v4, &src_cfg(cfg), now_ns, elapsed_ns);
    // Spoof gate: an unbounded DROPPING set means a spoofed flood — skip source
    // blocking (chasing spoofed /32s is pointless; rely on the port filter).
    let desired = if dropping.len() > cfg.max_real_sources {
        Vec::new()
    } else {
        plan_blocks_v4(
            &dropping,
            cfg.fanout,
            cfg.max_source_blocks,
            cfg.agg_max_prefix_v4,
        )
    };
    {
        let mut trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(bpf.map_mut("V4_CIDR_SRC").context("v4 cidr trie missing")?)?;
        reconcile_block_set(
            &mut state.blocks_v4,
            &mut trie,
            &desired,
            now_ns,
            |c| Key::new(c.prefix_len, c.network),
            |c| format!("{}/{}", Ipv4Addr::from(c.network), c.prefix_len),
        );
    }
    state.block_pps_v4 =
        block_pps(&state.blocks_v4, &state.src_v4, |c, ip| mask_v4(*ip, c.prefix_len) == c.network);
    Ok(!state.blocks_v4.is_empty())
}

fn source_control_v6(
    bpf: &mut Ebpf,
    state: &mut DetectionState,
    cfg: &RuntimeConfig,
    now_ns: u64,
    elapsed_ns: u64,
) -> Result<bool> {
    let cur = read_src_counters::<[u8; 16]>(bpf, "V6_SRC_COUNTERS")?;
    let dropping = step_sources(&cur, &mut state.src_v6, &src_cfg(cfg), now_ns, elapsed_ns);
    let desired = if dropping.len() > cfg.max_real_sources {
        Vec::new()
    } else {
        plan_blocks_v6(
            &dropping,
            cfg.fanout,
            cfg.max_source_blocks,
            cfg.agg_max_prefix_v6,
        )
    };
    {
        let mut trie: LpmTrie<_, [u8; 16], u8> =
            LpmTrie::try_from(bpf.map_mut("V6_CIDR_SRC").context("v6 cidr trie missing")?)?;
        reconcile_block_set(
            &mut state.blocks_v6,
            &mut trie,
            &desired,
            now_ns,
            |c| Key::new(c.prefix_len, c.network),
            |c| format!("{}/{}", Ipv6Addr::from(c.network), c.prefix_len),
        );
    }
    state.block_pps_v6 =
        block_pps(&state.blocks_v6, &state.src_v6, |c, ip| mask_v6(*ip, c.prefix_len) == c.network);
    Ok(!state.blocks_v6.is_empty())
}

/// Sample one TX-counter map, compute per-local-IP egress rates against the
/// previous snapshot, and refresh both the rate map and the prev snapshot.
fn compute_tx<K>(
    bpf: &Ebpf,
    name: &str,
    prev: &mut HashMap<K, DestCounters>,
    out: &mut HashMap<K, Rates>,
    elapsed_ns: u64,
) -> Result<()>
where
    K: Pod + Eq + Hash + Copy,
{
    let cur = read_counters::<K>(bpf, name)?;
    out.clear();
    for (k, c) in &cur {
        let p = prev.get(k).copied().unwrap_or_default();
        out.insert(*k, compute_rates(&p, c, elapsed_ns));
    }
    *prev = cur.into_iter().collect();
    Ok(())
}

/// One control tick at the injected `now_ns`. Source analysis runs first (it
/// gates escalation), then per-destination and per-prefix detection write the
/// escalation level into the dest-state trie. The first tick
/// (`last_sample_ns == 0`) seeds snapshots with zero elapsed.
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

    // --- Source control first (spoof-gated); result gates escalation ---
    let sba4 = source_control_v4(bpf, state, cfg, now_ns, elapsed)?;
    let sba6 = source_control_v6(bpf, state, cfg, now_ns, elapsed)?;

    // --- TX (egress) rates per local IP (display only; no mitigation) ---
    compute_tx::<[u8; 4]>(bpf, "V4_TX_COUNTERS", &mut state.prev_tx_v4, &mut state.tx_v4, elapsed)?;
    compute_tx::<[u8; 16]>(bpf, "V6_TX_COUNTERS", &mut state.prev_tx_v6, &mut state.tx_v6, elapsed)?;

    // --- Per-destination + per-prefix detection (shared dest-state trie) ---
    let v4 = read_counters::<[u8; 4]>(bpf, "V4_DEST_COUNTERS")?;
    {
        let mut trie: LpmTrie<_, [u8; 4], DestState> =
            LpmTrie::try_from(bpf.map_mut("V4_DEST_STATE").context("v4 state missing")?)?;
        detect_family(
            &v4,
            &mut trie,
            32,
            &mut state.v4,
            &cfg.detection,
            sba4,
            cfg.escalate_pass_pps,
            cfg.syn_proxy_pps,
            now_ns,
            elapsed,
            |k| Ipv4Addr::from(*k).to_string(),
        );
        for &(len, net) in &cfg.protected_v4 {
            detect_prefix(
                &v4,
                &mut trie,
                len,
                net,
                mask_v4,
                &mut state.prefix_v4,
                &cfg.network,
                sba4,
                cfg.escalate_pass_pps,
                cfg.syn_proxy_pps,
                now_ns,
                elapsed,
                |l, n| format!("{}/{}", Ipv4Addr::from(*n), l),
            );
        }
    }
    let v6 = read_counters::<[u8; 16]>(bpf, "V6_DEST_COUNTERS")?;
    {
        let mut trie: LpmTrie<_, [u8; 16], DestState> =
            LpmTrie::try_from(bpf.map_mut("V6_DEST_STATE").context("v6 state missing")?)?;
        detect_family(
            &v6,
            &mut trie,
            128,
            &mut state.v6,
            &cfg.detection,
            sba6,
            cfg.escalate_pass_pps,
            cfg.syn_proxy_pps,
            now_ns,
            elapsed,
            |k| Ipv6Addr::from(*k).to_string(),
        );
        for &(len, net) in &cfg.protected_v6 {
            detect_prefix(
                &v6,
                &mut trie,
                len,
                net,
                mask_v6,
                &mut state.prefix_v6,
                &cfg.network,
                sba6,
                cfg.escalate_pass_pps,
                cfg.syn_proxy_pps,
                now_ns,
                elapsed,
                |l, n| format!("{}/{}", Ipv6Addr::from(*n), l),
            );
        }
    }
    Ok(())
}
