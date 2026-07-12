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

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{MapData, PerCpuHashMap};
use aya::{Ebpf, Pod};
use log::{info, warn};

use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY,
    DestCounters, DestState, SrcRateConfig, SrcState,
};

use crate::cidr::{mask_v4, mask_v6};
use crate::detect::{
    DestTracker, DetectionConfig, Rates, Transition, compute_rates, process_sample,
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
    /// Operator-pushed manual override flags as (prefix_len, masked-network,
    /// flags). These are a *floor*: per-destination / per-prefix auto-detection
    /// ORs its computed flags on top and never drops them, and on
    /// mitigation-exit restores the manual entry instead of removing it. Kept in
    /// sync with the pushed ruleset by `apply_rules`; empty when none are set.
    pub manual_v4: Vec<(u32, [u8; 4], u32)>,
    /// Manual override flags (IPv6).
    pub manual_v6: Vec<(u32, [u8; 16], u32)>,
    /// Per-source packets/second limit for the in-kernel rate machine
    /// (written to `SRC_RATE_CFG` as `max_per_window` over a 1s window).
    pub src_rate_pps: u64,
    /// How long the kernel machine blocks a tripped source before it is
    /// re-evaluated (re-extended each window it is still over-rate).
    pub src_cooldown_ns: u64,
    /// Escalate a mitigating dest/prefix to `SOURCE_BLOCK` only if this many
    /// packets/second are still getting through after the port filter.
    pub escalate_pass_pps: u64,
    /// Enable the SYN_PROXY flag once a mitigating entity's SYN rate reaches
    /// this many SYNs/second.
    pub syn_proxy_pps: u64,
}

impl RuntimeConfig {
    /// OR of the flags of every manual override whose CIDR covers `addr` (an
    /// exact /32 entry or a wider prefix). Auto-detection uses this as a floor
    /// so an operator-forced flag (e.g. SYN_PROXY) is never dropped when the
    /// same destination also trips auto-mitigation.
    pub fn manual_flags_v4(&self, addr: [u8; 4]) -> u32 {
        self.manual_v4
            .iter()
            .filter(|(bits, net, _)| mask_v4(addr, *bits) == *net)
            .fold(0, |a, (_, _, f)| a | f)
    }

    /// OR of the manual-override flags covering `addr` (IPv6).
    pub fn manual_flags_v6(&self, addr: [u8; 16]) -> u32 {
        self.manual_v6
            .iter()
            .filter(|(bits, net, _)| mask_v6(addr, *bits) == *net)
            .fold(0, |a, (_, _, f)| a | f)
    }
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
    /// Latest batched snapshot of the kernel-owned per-source rate states
    /// (display only — the rate machine and blocking decision live in XDP).
    pub src_v4: Vec<([u8; 4], SrcState)>,
    pub src_v6: Vec<([u8; 16], SrcState)>,
    /// `bpf_ktime_get_ns`-domain timestamp of the snapshot (SrcState fields
    /// are kernel-monotonic; compare against this, not userspace clocks).
    pub src_sampled_ns: u64,
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
        add_counters(&mut total, v);
    }
    total
}

/// Add one per-CPU `DestCounters` slot into an accumulator (batch-read fold).
fn add_counters(acc: &mut DestCounters, v: &DestCounters) {
    acc.packets += v.packets;
    acc.bytes += v.bytes;
    acc.syn_packets += v.syn_packets;
    acc.tcp_packets += v.tcp_packets;
    acc.udp_packets += v.udp_packets;
    acc.icmp_packets += v.icmp_packets;
    acc.dropped += v.dropped;
}

/// Cached count of possible CPUs (the per-CPU map value stride).
fn possible_cpus() -> Result<usize> {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if let Some(n) = N.get() {
        return Ok(*n);
    }
    let n = aya::util::nr_cpus().map_err(|(what, e)| anyhow::anyhow!("{what}: {e}"))?;
    Ok(*N.get_or_init(|| n))
}

/// The map's fd if its type takes the hash-family `BPF_MAP_LOOKUP_BATCH` path.
fn batch_fd(map: &aya::maps::Map) -> Option<std::os::fd::BorrowedFd<'_>> {
    use std::os::fd::AsFd;
    match map {
        aya::maps::Map::HashMap(d)
        | aya::maps::Map::LruHashMap(d)
        | aya::maps::Map::PerCpuHashMap(d)
        | aya::maps::Map::PerCpuLruHashMap(d) => Some(d.fd().as_fd()),
        _ => None,
    }
}

/// Handle a batch-read failure: permanent unsupport logs once and returns
/// `Ok(())` so the caller falls through to per-entry iteration; anything else
/// propagates.
fn batch_fallback(name: &str, e: std::io::Error) -> Result<()> {
    if crate::batch::note_failure(&e) {
        warn!("batched read of {name} unsupported ({e}); using per-entry iteration");
        Ok(())
    } else {
        Err(anyhow::anyhow!("batched read of {name} failed: {e}"))
    }
}

/// Batched read of a **plain** hash map with per-entry fallback (GC scans).
pub fn scan_plain<K, V>(bpf: &Ebpf, name: &str) -> Result<Vec<(K, V)>>
where
    K: Pod,
    V: Pod + Copy,
{
    let map = bpf.map(name).with_context(|| format!("{name} missing"))?;
    if crate::batch::supported()
        && let Some(fd) = batch_fd(map)
    {
        match crate::batch::read_plain::<K, V>(fd) {
            Ok(v) => return Ok(v),
            Err(e) => batch_fallback(name, e)?,
        }
    }
    let map: aya::maps::HashMap<_, K, V> = aya::maps::HashMap::try_from(map)?;
    let mut out = Vec::new();
    for entry in map.iter() {
        out.push(entry?);
    }
    Ok(out)
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
fn enforced_flags(rates: &Rates, escalate_pass_pps: u64, syn_proxy_pps: u64) -> u32 {
    let mut flags = DEST_MODE_PORT_FILTER;
    // A sustained SYN flood engages the SYN-proxy (validate handshakes to open
    // TCP ports with cookies). High efficacy vs spoofed SYN floods, low FP.
    if rates.syn_pps >= syn_proxy_pps {
        flags |= DEST_MODE_SYN_PROXY;
    }
    // Escalate on residual pass-rate alone: the in-kernel gate only ever
    // blocks sources genuinely over the per-source limit, so a spoofed flood
    // (which never trips it) makes the flag harmless rather than dangerous.
    if rates.pass_pps >= escalate_pass_pps {
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
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
    now_ns: u64,
    elapsed_ns: u64,
    manual_flags: impl Fn(&K) -> u32,
    fmt_ip: impl Fn(&K) -> String,
) where
    K: Pod + Eq + Hash + Copy,
{
    for (key, cur) in samples {
        // Operator-forced flags for this destination; a floor auto-detection
        // may add to but never drops (see RuntimeConfig::manual_flags_v4).
        let manual = manual_flags(key);
        let tracker = trackers.entry(*key).or_default();
        let (transition, rates) = process_sample(*cur, tracker, cfg, now_ns, elapsed_ns);
        if tracker.mode == DEST_MODE_NORMAL {
            if transition == Transition::Exited {
                // Restore the manual floor rather than deleting the entry: an
                // auto-mitigation exit must not wipe an operator override.
                if manual != DEST_MODE_NORMAL {
                    let _ = trie.insert(&Key::new(bits, *key), dest_state(manual, now_ns), 0);
                } else {
                    let _ = trie.remove(&Key::new(bits, *key));
                }
                log_event_stop(&fmt_ip(key), &tracker.peak, cur.dropped);
                tracker.peak = Rates::default();
                tracker.flags = DEST_MODE_NORMAL;
            }
            continue;
        }
        // Active: pick the enforcement level (never below the manual floor) and
        // (re)write it if changed.
        let target = enforced_flags(&rates, escalate_pass_pps, syn_proxy_pps) | manual;
        if transition == Transition::Entered {
            let _ = trie.insert(&Key::new(bits, *key), dest_state(target, now_ns), 0);
            tracker.flags = target;
            log_event_start(&fmt_ip(key), &rates);
        } else if target != tracker.flags {
            let _ = trie.insert(&Key::new(bits, *key), dest_state(target, now_ns), 0);
            info!("MITIGATION FLAGS dest={} flags={target:#06b}", fmt_ip(key));
            tracker.flags = target;
        } else if manual != DEST_MODE_NORMAL {
            // Re-assert the floor unconditionally while a manual override is
            // present: `apply_rules` may have just (re)written the trie entry
            // with manual-only flags when the override was pushed mid-attack,
            // which would otherwise persist until the next flag change.
            let _ = trie.insert(&Key::new(bits, *key), dest_state(target, now_ns), 0);
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
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
    now_ns: u64,
    elapsed_ns: u64,
    manual: u32,
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
            // Restore the manual floor rather than deleting the prefix entry.
            if manual != DEST_MODE_NORMAL {
                let _ = trie.insert(
                    &Key::new(prefix_len, network),
                    dest_state(manual, now_ns),
                    0,
                );
            } else {
                let _ = trie.remove(&Key::new(prefix_len, network));
            }
            info!("PREFIX MITIGATION STOP net={}", fmt(prefix_len, &network));
            tracker.flags = DEST_MODE_NORMAL;
        }
        return;
    }
    let target = enforced_flags(&rates, escalate_pass_pps, syn_proxy_pps) | manual;
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
    } else if manual != DEST_MODE_NORMAL {
        // Re-assert the floor (see detect_family for the rationale).
        let _ = trie.insert(
            &Key::new(prefix_len, network),
            dest_state(target, now_ns),
            0,
        );
    }
}

/// Read + per-CPU-sum a `DestCounters` map into an owned vec. Uses one
/// `BPF_MAP_LOOKUP_BATCH` syscall per ~4k entries, falling back to aya's
/// per-entry iteration (2 syscalls/entry) on kernels without batch support.
fn read_counters<K>(bpf: &Ebpf, name: &str) -> Result<Vec<(K, DestCounters)>>
where
    K: Pod,
{
    let map = bpf.map(name).with_context(|| format!("{name} missing"))?;
    if crate::batch::supported()
        && let Some(fd) = batch_fd(map)
    {
        match crate::batch::read_percpu_folded::<K, DestCounters, DestCounters>(
            fd,
            possible_cpus()?,
            add_counters,
        ) {
            Ok(v) => return Ok(v),
            Err(e) => batch_fallback(name, e)?,
        }
    }
    let map: PerCpuHashMap<_, K, DestCounters> = PerCpuHashMap::try_from(map)?;
    let mut out = Vec::new();
    for entry in map.iter() {
        let (k, values) = entry?;
        out.push((k, sum_counters(values.iter())));
    }
    Ok(out)
}

/// Fixed per-source counting window for the in-kernel rate machine. One
/// second: `src_rate_pps` is then literally "packets per second", exact, not
/// a delta over a variable sample interval.
pub const SRC_WINDOW_NS: u64 = 1_000_000_000;

/// Write the kernel per-source rate-machine config (`SRC_RATE_CFG[0]`).
/// Called at startup and whenever the limits change (`PUT /limits`).
/// `max_per_window` is precomputed so the datapath never divides.
pub fn write_src_rate_cfg(bpf: &mut Ebpf, cfg: &RuntimeConfig) -> Result<()> {
    let mut arr: aya::maps::Array<_, SrcRateConfig> = aya::maps::Array::try_from(
        bpf.map_mut("SRC_RATE_CFG")
            .context("SRC_RATE_CFG missing")?,
    )?;
    let c = SrcRateConfig {
        max_per_window: cfg.src_rate_pps.saturating_mul(SRC_WINDOW_NS) / 1_000_000_000,
        window_ns: SRC_WINDOW_NS,
        cooldown_ns: cfg.src_cooldown_ns,
    };
    arr.set(0, c, 0).context("writing SRC_RATE_CFG")?;
    Ok(())
}

/// Remove idle per-source state entries: the kernel machine never self-cleans,
/// so without this sweep the state maps (and the `/sources` view) would hold
/// every source ever seen under mitigation. An entry is stale once it is not
/// blocked and its window anchor is older than `idle_ttl_ns`. Runs on the slow
/// GC timer — steady-state cost is proportional to live sources, not history.
pub fn gc_src_states(bpf: &mut Ebpf, idle_ttl_ns: u64) -> Result<usize> {
    let now = crate::gc::monotonic_now_ns();
    let mut removed = 0;
    removed += gc_src_state_map::<[u8; 4]>(bpf, "V4_SRC_STATE", now, idle_ttl_ns)?;
    removed += gc_src_state_map::<[u8; 16]>(bpf, "V6_SRC_STATE", now, idle_ttl_ns)?;
    Ok(removed)
}

fn gc_src_state_map<K>(bpf: &mut Ebpf, name: &str, now_ns: u64, idle_ttl_ns: u64) -> Result<usize>
where
    K: Pod + Eq + Hash,
{
    let entries: Vec<(K, SrcState)> = scan_plain(&*bpf, name)?;
    let stale: Vec<K> = entries
        .iter()
        .filter(|(_, st)| {
            st.blocked_until_ns <= now_ns
                && now_ns.saturating_sub(st.window_start_ns) >= idle_ttl_ns
        })
        .map(|(k, _)| *k)
        .collect();
    let mut map: aya::maps::HashMap<_, K, SrcState> = aya::maps::HashMap::try_from(
        bpf.map_mut(name)
            .with_context(|| format!("{name} missing"))?,
    )?;
    Ok(stale.iter().filter(|k| map.remove(k).is_ok()).count())
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

    // --- Per-source rate machine lives in XDP; snapshot its state maps for
    // the display views only (batched: ~1 syscall per 4k entries) ---
    state.src_v4 = scan_plain::<[u8; 4], SrcState>(bpf, "V4_SRC_STATE")?;
    state.src_v6 = scan_plain::<[u8; 16], SrcState>(bpf, "V6_SRC_STATE")?;
    state.src_sampled_ns = crate::gc::monotonic_now_ns();

    // --- TX (egress) rates per local IP (display only; no mitigation) ---
    compute_tx::<[u8; 4]>(
        bpf,
        "V4_TX_COUNTERS",
        &mut state.prev_tx_v4,
        &mut state.tx_v4,
        elapsed,
    )?;
    compute_tx::<[u8; 16]>(
        bpf,
        "V6_TX_COUNTERS",
        &mut state.prev_tx_v6,
        &mut state.tx_v6,
        elapsed,
    )?;

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
            cfg.escalate_pass_pps,
            cfg.syn_proxy_pps,
            now_ns,
            elapsed,
            |k| cfg.manual_flags_v4(*k),
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
                cfg.escalate_pass_pps,
                cfg.syn_proxy_pps,
                now_ns,
                elapsed,
                cfg.manual_flags_v4(net),
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
            cfg.escalate_pass_pps,
            cfg.syn_proxy_pps,
            now_ns,
            elapsed,
            |k| cfg.manual_flags_v6(*k),
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
                cfg.escalate_pass_pps,
                cfg.syn_proxy_pps,
                now_ns,
                elapsed,
                cfg.manual_flags_v6(net),
                |l, n| format!("{}/{}", Ipv6Addr::from(*n), l),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod manual_floor_tests {
    use super::*;
    use lnvps_fw_common::{DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY};

    /// Build a minimal RuntimeConfig from a trivial config, then inject the
    /// manual overrides under test.
    fn cfg_with_manual(
        v4: Vec<(u32, [u8; 4], u32)>,
        v6: Vec<(u32, [u8; 16], u32)>,
    ) -> RuntimeConfig {
        let cfg: crate::config::Config = serde_yaml_ng::from_str("interfaces: [eno1]\n").unwrap();
        let mut rt = cfg.runtime_config().unwrap();
        rt.manual_v4 = v4;
        rt.manual_v6 = v6;
        rt
    }

    #[test]
    fn manual_flags_v4_ors_exact_and_wider_prefixes() {
        let rt = cfg_with_manual(
            vec![
                (32, [10, 0, 0, 5], DEST_MODE_SYN_PROXY),
                (24, [10, 0, 0, 0], DEST_MODE_PORT_FILTER),
            ],
            Vec::new(),
        );
        // Exact /32 override OR'd with the covering /24 override.
        assert_eq!(
            rt.manual_flags_v4([10, 0, 0, 5]),
            DEST_MODE_SYN_PROXY | DEST_MODE_PORT_FILTER
        );
        // A different host inside the /24 gets only the /24 flags.
        assert_eq!(rt.manual_flags_v4([10, 0, 0, 9]), DEST_MODE_PORT_FILTER);
        // Outside every override -> no floor.
        assert_eq!(rt.manual_flags_v4([10, 0, 1, 9]), 0);
    }

    #[test]
    fn manual_flags_v6_ors_exact_and_wider_prefixes() {
        let mut host = [0u8; 16];
        host[0] = 0x20;
        host[1] = 0x01;
        host[15] = 0x01;
        let mut net = [0u8; 16];
        net[0] = 0x20;
        net[1] = 0x01;
        let rt = cfg_with_manual(
            Vec::new(),
            vec![
                (128, host, DEST_MODE_SOURCE_BLOCK),
                (32, net, DEST_MODE_PORT_FILTER),
            ],
        );
        assert_eq!(
            rt.manual_flags_v6(host),
            DEST_MODE_SOURCE_BLOCK | DEST_MODE_PORT_FILTER
        );
        let mut other = net;
        other[15] = 0x99; // same /32, different host
        assert_eq!(rt.manual_flags_v6(other), DEST_MODE_PORT_FILTER);
        let mut outside = [0u8; 16];
        outside[0] = 0xfd;
        assert_eq!(rt.manual_flags_v6(outside), 0);
    }
}
