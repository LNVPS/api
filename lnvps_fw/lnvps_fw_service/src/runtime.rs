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
    DestCounters, DestState, GlobalConfig, SrcRateConfig, SrcState,
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
    /// (written to `GLOBAL_CFG.src_rate` as `max_per_window` over a 1s window).
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
    /// Per-destination budget of SYNs/second to unlearned TCP ports leaked
    /// through the port filter so open ports can still be learned while
    /// mitigating. 0 disables the leak. Written to `GLOBAL_CFG.learn_leak_pps`.
    pub learn_leak_pps: u64,
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
    /// Latest per-local-IP TX rates (for the tx/rx dashboard view). Computed
    /// directly from the drained per-window delta (no previous snapshot needed).
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
    // TCP ports with cookies). `syn_proxy_pps == 0` disables it entirely —
    // required for tunneled/asymmetric-routed deployments (GRE-backed VMs,
    // non-GRE tunnels, or return traffic on a different NIC) where the
    // XDP_TX'd cookie reply can neither be re-encapsulated nor sent out the
    // correct egress NIC, so the proxy would black-hole real services.
    if syn_proxy_pps != 0 && rates.syn_pps >= syn_proxy_pps {
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

/// Advance one destination's state machine for a reconstructed cumulative
/// snapshot `cur` and (re)write the dest-state LPM trie on transitions / level
/// changes. Shared by the live sample pass and the synthetic zero-delta pass.
#[allow(clippy::too_many_arguments)]
fn apply_dest_decision<K>(
    key: &K,
    cur: DestCounters,
    tracker: &mut DestTracker,
    trie: &mut LpmTrie<&mut MapData, K, DestState>,
    bits: u32,
    cfg: &DetectionConfig,
    escalate_pass_pps: u64,
    syn_proxy_pps: u64,
    now_ns: u64,
    elapsed_ns: u64,
    manual: u32,
    fmt_ip: impl Fn(&K) -> String,
) where
    K: Pod + Eq + Hash + Copy,
{
    let (transition, rates) = process_sample(cur, tracker, cfg, now_ns, elapsed_ns);
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
        return;
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

/// Per-destination detection for one family, writing the escalation level into
/// the dest-state LPM trie on transitions and level changes.
///
/// `samples` now carries **per-window deltas** (the counter maps are drained
/// each tick). The cumulative snapshot the state machine expects is
/// reconstructed in userspace as `tracker.prev + delta`, which is immune to
/// kernel-side LRU eviction. Because a drained map drops silent destinations
/// entirely, mitigating trackers absent from `samples` are fed a synthetic
/// zero-delta sample so their cooldown/exit still advances.
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
    let seen: std::collections::HashSet<K> = samples.iter().map(|(k, _)| *k).collect();
    for (key, delta) in samples {
        // Operator-forced flags for this destination; a floor auto-detection
        // may add to but never drops (see RuntimeConfig::manual_flags_v4).
        let manual = manual_flags(key);
        let tracker = trackers.entry(*key).or_default();
        // Reconstruct the cumulative snapshot from the accumulated previous plus
        // this window's drained delta.
        let mut cur = tracker.prev;
        add_counters(&mut cur, delta);
        apply_dest_decision(
            key,
            cur,
            tracker,
            trie,
            bits,
            cfg,
            escalate_pass_pps,
            syn_proxy_pps,
            now_ns,
            elapsed_ns,
            manual,
            &fmt_ip,
        );
    }
    // Silent mitigating destinations (drained away this tick): feed a zero delta
    // so `process_sample` still runs the cooldown clock and can exit.
    let silent: Vec<K> = trackers
        .iter()
        .filter(|(k, t)| !seen.contains(*k) && t.mode != DEST_MODE_NORMAL)
        .map(|(k, _)| *k)
        .collect();
    for key in silent {
        let manual = manual_flags(&key);
        let tracker = trackers.get_mut(&key).expect("tracked");
        let cur = tracker.prev; // cumulative unchanged (zero-delta window)
        apply_dest_decision(
            &key,
            cur,
            tracker,
            trie,
            bits,
            cfg,
            escalate_pass_pps,
            syn_proxy_pps,
            now_ns,
            elapsed_ns,
            manual,
            &fmt_ip,
        );
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
    // `samples` are per-window deltas; sum them over the prefix to get the
    // prefix's aggregate delta, then reconstruct the cumulative snapshot as
    // `tracker.prev + aggregate delta` (same accumulate scheme as
    // `detect_family`). detect_prefix runs every tick for every configured
    // prefix, so no synthetic zero-delta pass is needed here.
    let mut agg = DestCounters::default();
    for (addr, c) in samples {
        if mask(*addr, prefix_len) == network {
            add_counters(&mut agg, c);
        }
    }
    let tracker = trackers.entry((prefix_len, network)).or_default();
    let mut cur = tracker.prev;
    add_counters(&mut cur, &agg);
    let (transition, rates) = process_sample(cur, tracker, cfg, now_ns, elapsed_ns);
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

/// Drain + per-CPU-sum a `DestCounters` map into an owned vec of **per-window
/// deltas**. Uses one `BPF_MAP_LOOKUP_AND_DELETE_BATCH` syscall per ~4k entries
/// (read-and-remove), so each entry returned is the traffic accumulated since
/// the previous tick and the kernel map is left (near) empty. Draining removes
/// LRU-eviction skew entirely (a churned entry can never make a counter appear
/// to go backwards) and doubles as GC for cold destinations. Falls back to
/// aya's per-entry iterate-then-remove on kernels without batch support (still
/// drain semantics, just more syscalls).
fn read_counters<K>(bpf: &mut Ebpf, name: &str) -> Result<Vec<(K, DestCounters)>>
where
    K: Pod + Eq + Hash,
{
    if crate::batch::supported() {
        let map = bpf.map(name).with_context(|| format!("{name} missing"))?;
        if let Some(fd) = batch_fd(map) {
            match crate::batch::read_percpu_folded::<K, DestCounters, DestCounters>(
                fd,
                possible_cpus()?,
                true,
                add_counters,
            ) {
                Ok(v) => return Ok(v),
                Err(e) => batch_fallback(name, e)?,
            }
        }
    }
    // Per-entry fallback: read every entry, then remove it so the semantics
    // still match the drain path (deltas, not cumulative).
    let mut map: PerCpuHashMap<_, K, DestCounters> = PerCpuHashMap::try_from(
        bpf.map_mut(name)
            .with_context(|| format!("{name} missing"))?,
    )?;
    let keys: Vec<K> = map.keys().collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(keys.len());
    for k in &keys {
        if let Ok(values) = map.get(k, 0) {
            out.push((*k, sum_counters(values.iter())));
        }
        let _ = map.remove(k);
    }
    Ok(out)
}

/// Fixed per-source counting window for the in-kernel rate machine. One
/// second: `src_rate_pps` is then literally "packets per second", exact, not
/// a delta over a variable sample interval.
pub const SRC_WINDOW_NS: u64 = 1_000_000_000;

/// Read-modify-write the single consolidated `GLOBAL_CFG` entry. Each writer
/// mutates only its own fields so independent callers (rate/leak limits,
/// scoping, manual-block presence, verified TTL) never clobber one another.
pub fn update_global_cfg(bpf: &mut Ebpf, f: impl FnOnce(&mut GlobalConfig)) -> Result<()> {
    let mut arr: aya::maps::Array<_, GlobalConfig> =
        aya::maps::Array::try_from(bpf.map_mut("GLOBAL_CFG").context("GLOBAL_CFG missing")?)?;
    let mut cfg = arr.get(&0, 0).unwrap_or_default();
    f(&mut cfg);
    arr.set(0, cfg, 0).context("writing GLOBAL_CFG")?;
    Ok(())
}

/// Write the kernel per-source rate-machine config into `GLOBAL_CFG.src_rate`.
/// Called at startup and whenever the limits change (`PUT /limits`).
/// `max_per_window` is precomputed so the datapath never divides.
pub fn write_src_rate_cfg(bpf: &mut Ebpf, cfg: &RuntimeConfig) -> Result<()> {
    let src_rate = SrcRateConfig {
        max_per_window: cfg.src_rate_pps.saturating_mul(SRC_WINDOW_NS) / 1_000_000_000,
        window_ns: SRC_WINDOW_NS,
        cooldown_ns: cfg.src_cooldown_ns,
    };
    update_global_cfg(bpf, |c| c.src_rate = src_rate)
}

/// Write the per-destination learning-leak budget into
/// `GLOBAL_CFG.learn_leak_pps`: the max SYNs/second to unlearned ports the port
/// filter leaks per destination. Called at startup and on live `PUT /limits`.
pub fn write_learn_leak_cfg(bpf: &mut Ebpf, cfg: &RuntimeConfig) -> Result<()> {
    let pps = cfg.learn_leak_pps.min(u32::MAX as u64) as u32;
    update_global_cfg(bpf, |c| c.learn_leak_pps = pps)
}

/// Bulk-remove `keys` from a plain hash-family map named `name`, using one
/// `BPF_MAP_DELETE_BATCH` syscall per ~4k keys and falling back to aya's
/// per-key removal on kernels without batch-delete support.
pub fn delete_keys<K, V>(bpf: &mut Ebpf, name: &str, keys: &[K]) -> Result<usize>
where
    K: Pod,
    V: Pod,
{
    if keys.is_empty() {
        return Ok(0);
    }
    if crate::batch::supported() {
        let map = bpf.map(name).with_context(|| format!("{name} missing"))?;
        if let Some(fd) = batch_fd(map) {
            match crate::batch::delete_batch(fd, keys) {
                Ok(n) => return Ok(n),
                Err(e) => batch_fallback(name, e)?,
            }
        }
    }
    let mut map: aya::maps::HashMap<_, K, V> = aya::maps::HashMap::try_from(
        bpf.map_mut(name)
            .with_context(|| format!("{name} missing"))?,
    )?;
    Ok(keys.iter().filter(|k| map.remove(k).is_ok()).count())
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
    delete_keys::<K, SrcState>(bpf, name, &stale)
}

/// Sample one TX-counter map (drained: each entry is this window's delta) and
/// convert directly into per-local-IP egress rates. Silent IPs are drained
/// away and simply drop off the live dashboard, which is the desired behaviour.
fn compute_tx<K>(
    bpf: &mut Ebpf,
    name: &str,
    out: &mut HashMap<K, Rates>,
    elapsed_ns: u64,
) -> Result<()>
where
    K: Pod + Eq + Hash + Copy,
{
    let cur = read_counters::<K>(bpf, name)?;
    out.clear();
    for (k, c) in &cur {
        out.insert(*k, compute_rates(&DestCounters::default(), c, elapsed_ns));
    }
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
    compute_tx::<[u8; 4]>(bpf, "V4_TX_COUNTERS", &mut state.tx_v4, elapsed)?;
    compute_tx::<[u8; 16]>(bpf, "V6_TX_COUNTERS", &mut state.tx_v6, elapsed)?;

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

#[cfg(test)]
mod enforced_flags_tests {
    use super::*;

    fn rates(syn_pps: u64, pass_pps: u64) -> Rates {
        Rates {
            syn_pps,
            pass_pps,
            ..Default::default()
        }
    }

    // syn_proxy_pps == 0 disables the SYN-proxy entirely (the switch that lets
    // tunneled/asymmetric-routed deployments turn it off), even at an extreme
    // SYN rate. PORT_FILTER remains the always-on base.
    #[test]
    fn syn_proxy_disabled_when_threshold_zero() {
        let f = enforced_flags(&rates(1_000_000, 0), u64::MAX, 0);
        assert_eq!(f & DEST_MODE_SYN_PROXY, 0, "must be off at threshold 0");
        assert_ne!(f & DEST_MODE_PORT_FILTER, 0, "port filter still on");
    }

    // A non-zero threshold engages only at/over the rate (unchanged behaviour).
    #[test]
    fn syn_proxy_engages_only_at_or_over_threshold() {
        assert_ne!(
            enforced_flags(&rates(6_000, 0), u64::MAX, 5_000) & DEST_MODE_SYN_PROXY,
            0
        );
        assert_eq!(
            enforced_flags(&rates(4_000, 0), u64::MAX, 5_000) & DEST_MODE_SYN_PROXY,
            0
        );
    }
}
