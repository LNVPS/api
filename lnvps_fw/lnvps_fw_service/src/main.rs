use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as AyaHashMap, PerCpuHashMap, ProgramArray};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc::qdisc_add_clsact};
use aya::util::KernelVersion;
use aya::{Ebpf, include_bytes_aligned};
use log::{info, warn};

use lnvps_fw_common::{
    COOKIE_SECRET_CURRENT, COOKIE_SECRET_PREVIOUS, DEST_MODE_NORMAL, DestCounters, DestState,
    LastSeen, PortKeyV4, PortKeyV6, SLOT_SYN_PROXY_V4, SLOT_SYN_PROXY_V6,
};

use lnvps_fw_service::api::{self, CidrKey, Mitigation, RuleSet, SharedState, parse_cidr};
use lnvps_fw_service::config::{Config, IfaceRole};
use lnvps_fw_service::detect::DestTracker;
use lnvps_fw_service::gc;
use lnvps_fw_service::publish::{MitInput, MitTracker};
use lnvps_fw_service::runtime::{DetectionState, RuntimeConfig, run_control, sum_counters};

fn format_counters(c: &DestCounters) -> String {
    format!(
        "pkts={} bytes={} syn={} tcp={} udp={} icmp={} dropped={}",
        c.packets, c.bytes, c.syn_packets, c.tcp_packets, c.udp_packets, c.icmp_packets, c.dropped
    )
}

fn log_stats(bpf: &Ebpf) -> Result<()> {
    let v4: PerCpuHashMap<_, [u8; 4], DestCounters> =
        PerCpuHashMap::try_from(bpf.map("V4_DEST_COUNTERS").context("v4 counters missing")?)?;
    for entry in v4.iter() {
        let (dst, values) = entry?;
        let total = sum_counters(values.iter());
        info!("{}: {}", Ipv4Addr::from(dst), format_counters(&total));
    }
    let v6: PerCpuHashMap<_, [u8; 16], DestCounters> =
        PerCpuHashMap::try_from(bpf.map("V6_DEST_COUNTERS").context("v6 counters missing")?)?;
    for entry in v6.iter() {
        let (dst, values) = entry?;
        let total = sum_counters(values.iter());
        info!("{}: {}", Ipv6Addr::from(dst), format_counters(&total));
    }
    Ok(())
}

/// Sweep both learned-ports maps, returning the total number of entries
/// removed. TTL is compared against the monotonic clock (matching
/// `bpf_ktime_get_ns`).
fn gc_learned_ports(bpf: &mut Ebpf, ttl_ns: u64) -> Result<usize> {
    let now = gc::monotonic_now_ns();
    let mut removed = 0;
    {
        let mut v4: AyaHashMap<_, PortKeyV4, LastSeen> = AyaHashMap::try_from(
            bpf.map_mut("OPEN_PORTS_V4")
                .context("open ports v4 missing")?,
        )?;
        removed += gc::gc_open_ports(&mut v4, now, ttl_ns);
    }
    {
        let mut v6: AyaHashMap<_, PortKeyV6, LastSeen> = AyaHashMap::try_from(
            bpf.map_mut("OPEN_PORTS_V6")
                .context("open ports v6 missing")?,
        )?;
        removed += gc::gc_open_ports(&mut v6, now, ttl_ns);
    }
    Ok(removed)
}

/// Parse CLI args: either `--config <path>` or a bare list of interfaces.
fn load_config() -> Result<Config> {
    let mut args = std::env::args().skip(1).peekable();
    if matches!(args.peek().map(String::as_str), Some("--config")) {
        let _ = args.next();
        let path: PathBuf = args.next().context("--config requires a path")?.into();
        return Config::load(&path);
    }
    let interfaces: Vec<String> = args.collect();
    if interfaces.is_empty() {
        bail!("usage: lnvps_fw_service (--config <file> | <interface> [interface...])");
    }
    Ok(Config::from_interfaces(interfaces))
}

/// Load the eBPF object and attach both the XDP ingress and TC egress programs
/// to every configured interface.
fn attach_programs(cfg: &Config) -> Result<Ebpf> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lnvps_ebpf"
    )))?;

    // XDP ingress protection -- attached to host + filter roles. The program is
    // GRE-decap-aware, so a `filter` interface on a router underlay drops
    // attack traffic inside GRE tunnels too.
    {
        let xdp: &mut Xdp = bpf
            .program_mut("xdp_lnvps")
            .context("xdp_lnvps program not found")?
            .try_into()?;
        xdp.load()?;
        for spec in &cfg.interfaces {
            if matches!(spec.role(), IfaceRole::Host | IfaceRole::Filter) {
                let iface = spec.name();
                match xdp.attach(iface, XdpMode::default()) {
                    Ok(_) => info!("XDP attached to {iface} ({:?}, default mode)", spec.role()),
                    Err(e) => {
                        warn!("XDP default attach failed on {iface} ({e}), trying SKB mode");
                        xdp.attach(iface, XdpMode::Skb)
                            .with_context(|| format!("failed to attach XDP to {iface}"))?;
                        info!("XDP attached to {iface} ({:?}, skb mode)", spec.role());
                    }
                }
            }
        }
    }

    // TC port learning -- egress for host role (single NIC), ingress for the
    // router `learn` role (VM replies enter the VM-facing NIC on ingress).
    {
        let tc: &mut SchedClassifier = bpf
            .program_mut("tc_lnvps_egress")
            .context("tc_lnvps_egress program not found")?
            .try_into()?;
        tc.load()?;
        for spec in &cfg.interfaces {
            let (iface, hook) = match spec.role() {
                IfaceRole::Host => (spec.name(), TcAttachType::Egress),
                IfaceRole::Learn => (spec.name(), TcAttachType::Ingress),
                IfaceRole::Filter => continue,
            };
            // On kernels < 6.6 the clsact qdisc must exist before attaching; on
            // 6.6+ TCX is used and this is unnecessary. Best-effort either way.
            let _ = qdisc_add_clsact(iface);
            tc.attach(iface, hook)
                .with_context(|| format!("failed to attach TC {hook:?} to {iface}"))?;
            info!("TC {hook:?} learning attached to {iface}");
        }
    }

    // SYN-proxy tail-call programs (v4 + v6): load them (not attached to an
    // interface -- only reached via bpf_tail_call) and register in the jump
    // table at their protocol slots.
    {
        let load = |bpf: &mut Ebpf, name: &str| -> Result<aya::programs::ProgramFd> {
            let sp: &mut Xdp = bpf
                .program_mut(name)
                .with_context(|| format!("{name} program not found"))?
                .try_into()?;
            sp.load()?;
            Ok(sp.fd()?.try_clone()?)
        };
        let v4_fd = load(&mut bpf, "xdp_syn_proxy")?;
        let v6_fd = load(&mut bpf, "xdp_syn_proxy_v6")?;
        let mut jt: ProgramArray<_> = ProgramArray::try_from(
            bpf.map_mut("SYN_PROXY_JUMP")
                .context("jump table missing")?,
        )?;
        jt.set(SLOT_SYN_PROXY_V4, &v4_fd, 0)?;
        jt.set(SLOT_SYN_PROXY_V6, &v6_fd, 0)?;
        info!("SYN-proxy programs (v4+v6) loaded into jump table");
    }
    // Seed an initial SYN-cookie secret.
    rotate_cookie_secret(&mut bpf, gc::monotonic_now_ns() as u32 | 1)?;

    Ok(bpf)
}

/// Expire verified sources whose verification is older than `ttl_ns` (both
/// address families).
fn gc_verified(bpf: &mut Ebpf, ttl_ns: u64) -> Result<usize> {
    let v4 = gc_verified_map::<[u8; 4]>(bpf, "VERIFIED_V4", ttl_ns)?;
    let v6 = gc_verified_map::<[u8; 16]>(bpf, "VERIFIED_V6", ttl_ns)?;
    Ok(v4 + v6)
}

fn gc_verified_map<K>(bpf: &mut Ebpf, name: &str, ttl_ns: u64) -> Result<usize>
where
    K: aya::Pod + Eq + std::hash::Hash,
{
    let now = gc::monotonic_now_ns();
    let mut map: AyaHashMap<_, K, u64> = AyaHashMap::try_from(
        bpf.map_mut(name)
            .with_context(|| format!("{name} missing"))?,
    )?;
    let expired: Vec<K> = map
        .keys()
        .flatten()
        .filter(|k| match map.get(k, 0) {
            Ok(ts) => gc::is_expired(ts, now, ttl_ns),
            Err(_) => false,
        })
        .collect();
    let mut removed = 0;
    for k in &expired {
        if map.remove(k).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Rotate the SYN-cookie secret: previous <- current, current <- `new`.
fn rotate_cookie_secret(bpf: &mut Ebpf, new: u32) -> Result<()> {
    let mut secret: Array<_, u32> = Array::try_from(
        bpf.map_mut("COOKIE_SECRET")
            .context("COOKIE_SECRET missing")?,
    )?;
    let cur = secret.get(&COOKIE_SECRET_CURRENT, 0).unwrap_or(0);
    secret.set(COOKIE_SECRET_PREVIOUS, cur, 0)?;
    secret.set(COOKIE_SECRET_CURRENT, new, 0)?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Scrape the currently-active auto-detected mitigations out of the detection
/// state (dest + prefix trackers, both families) for the API snapshot.
fn collect_active(det: &DetectionState) -> Vec<MitInput> {
    let mut out = Vec::new();
    let mut push = |cidr: String, tr: &DestTracker| {
        if tr.flags != DEST_MODE_NORMAL {
            out.push(MitInput {
                cidr,
                flags: tr.flags,
                pps: tr.peak.pps,
                bps: tr.peak.bps,
                syn_pps: tr.peak.syn_pps,
            });
        }
    };
    for (k, tr) in &det.v4 {
        push(format!("{}/32", Ipv4Addr::from(*k)), tr);
    }
    for (k, tr) in &det.v6 {
        push(format!("{}/128", Ipv6Addr::from(*k)), tr);
    }
    for ((len, net), tr) in &det.prefix_v4 {
        push(format!("{}/{len}", Ipv4Addr::from(*net)), tr);
    }
    for ((len, net), tr) in &det.prefix_v6 {
        push(format!("{}/{len}", Ipv6Addr::from(*net)), tr);
    }
    out
}

/// Write a manual protection-flag override into the dest-state trie.
fn write_dest_state(bpf: &mut Ebpf, key: CidrKey, flags: u32, now_ns: u64) -> Result<()> {
    let st = DestState {
        mode: flags,
        _pad: 0,
        entered_at: now_ns,
    };
    match key {
        CidrKey::V4 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 4], DestState> =
                LpmTrie::try_from(bpf.map_mut("V4_DEST_STATE").context("v4 state missing")?)?;
            t.insert(&Key::new(bits, net), st, 0)?;
        }
        CidrKey::V6 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 16], DestState> =
                LpmTrie::try_from(bpf.map_mut("V6_DEST_STATE").context("v6 state missing")?)?;
            t.insert(&Key::new(bits, net), st, 0)?;
        }
    }
    Ok(())
}

/// Remove a manual override from the dest-state trie.
fn remove_dest_state(bpf: &mut Ebpf, key: CidrKey) -> Result<()> {
    match key {
        CidrKey::V4 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 4], DestState> =
                LpmTrie::try_from(bpf.map_mut("V4_DEST_STATE").context("v4 state missing")?)?;
            let _ = t.remove(&Key::new(bits, net));
        }
        CidrKey::V6 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 16], DestState> =
                LpmTrie::try_from(bpf.map_mut("V6_DEST_STATE").context("v6 state missing")?)?;
            let _ = t.remove(&Key::new(bits, net));
        }
    }
    Ok(())
}

/// Apply a pushed ruleset: refresh the protected-prefix list used by prefix
/// detection, and reconcile manual overrides into the dest-state trie.
fn apply_rules(
    bpf: &mut Ebpf,
    rules: &RuleSet,
    applied: &mut HashMap<String, CidrKey>,
    rt: &mut RuntimeConfig,
    now_ns: u64,
) -> Result<()> {
    let mut pv4 = Vec::new();
    let mut pv6 = Vec::new();
    for c in &rules.protected {
        match parse_cidr(c) {
            Some(CidrKey::V4 { bits, net }) => pv4.push((bits, net)),
            Some(CidrKey::V6 { bits, net }) => pv6.push((bits, net)),
            None => warn!("ignoring bad protected cidr {c}"),
        }
    }
    rt.protected_v4 = pv4;
    rt.protected_v6 = pv6;

    let mut desired: HashMap<String, (CidrKey, u32)> = HashMap::new();
    for o in &rules.overrides {
        if let Some(k) = parse_cidr(&o.cidr) {
            desired.insert(o.cidr.clone(), (k, o.flags));
        }
    }
    let gone: Vec<String> = applied
        .keys()
        .filter(|c| !desired.contains_key(*c))
        .cloned()
        .collect();
    for c in gone {
        if let Some(k) = applied.remove(&c) {
            remove_dest_state(bpf, k)?;
        }
    }
    for (c, (k, flags)) in &desired {
        write_dest_state(bpf, *k, *flags, now_ns)?;
        applied.insert(c.clone(), *k);
    }
    Ok(())
}

/// Build the API shared state and spawn the HTTPS server; returns the shared
/// handle the control loop publishes into.
fn start_api(cfg: &Config) -> Result<Option<std::sync::Arc<SharedState>>> {
    let Some(api_cfg) = &cfg.api else {
        return Ok(None);
    };
    let initial = RuleSet {
        protected: cfg.protected.clone(),
        overrides: Vec::new(),
    };
    let state = SharedState::new(
        api_cfg.token.clone(),
        api_cfg.allow_ips.clone(),
        cfg.interface_names(),
        initial,
        api_cfg.events_buffer,
    );
    let tls = api::load_or_generate_tls(
        api_cfg.tls_cert.as_deref(),
        api_cfg.tls_key.as_deref(),
        api_cfg.listen.ip(),
    )?;
    if tls.self_signed {
        info!("Control API: no cert configured, generated a self-signed cert");
    }
    let addr = api_cfg.listen;
    let srv_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = api::serve(srv_state, addr, tls).await {
            warn!("Control API server exited: {e}");
        }
    });
    info!("Control API (HTTPS) listening on https://{addr}");
    Ok(Some(state))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = load_config()?;
    let kernel = KernelVersion::current()?;
    info!(
        "Running on kernel {kernel}; interfaces={:?}",
        cfg.interfaces
    );

    let mut bpf = attach_programs(&cfg)?;

    let ttl_ns = cfg.port_ttl().as_nanos() as u64;
    let mut runtime_cfg = cfg.runtime_config()?;
    let mut detection_state = DetectionState::default();

    // Control API (increment 7): HTTPS server + shared state the loop publishes
    // into. Rules are pushed by lnvps_api and reconciled below on change.
    let api_state = start_api(&cfg)?;
    let mut rules_version = 0u64;
    let mut applied_overrides: HashMap<String, CidrKey> = HashMap::new();
    let mut mit_tracker = MitTracker::default();
    let mut detect_timer = tokio::time::interval(cfg.sample_interval());
    let mut gc_timer = tokio::time::interval(cfg.gc_interval());
    let stats_secs = cfg.learning.stats_interval_secs;
    // A zero stats interval disables logging; use a long dummy period.
    let mut stats_timer = tokio::time::interval(Duration::from_secs(if stats_secs == 0 {
        3600
    } else {
        stats_secs
    }));
    // Rotate the SYN-cookie secret periodically; cookies issued in the previous
    // window still validate against the prev slot.
    let mut cookie_timer = tokio::time::interval(Duration::from_secs(120));
    let verified_ttl_ns = ttl_ns;

    info!(
        "Learning: port TTL {}s, GC every {}s",
        cfg.learning.port_ttl_secs, cfg.learning.gc_interval_secs
    );

    info!(
        "Detection: sample every {}ms; thresholds pps={} syn_pps={} bps={} exit={}% cooldown={}s",
        cfg.thresholds.sample_interval_ms,
        cfg.thresholds.pps,
        cfg.thresholds.syn_pps,
        cfg.thresholds.bps,
        cfg.thresholds.exit_pct,
        cfg.thresholds.cooldown_secs
    );

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = detect_timer.tick() => {
                let now = gc::monotonic_now_ns();
                // Reconcile any newly-pushed rules before detecting.
                if let Some(st) = &api_state {
                    let v = st.rules_version();
                    if v != rules_version {
                        rules_version = v;
                        let rules = st.rules();
                        if let Err(e) =
                            apply_rules(&mut bpf, &rules, &mut applied_overrides, &mut runtime_cfg, now)
                        {
                            warn!("apply rules failed: {e}");
                        }
                    }
                }
                if let Err(e) = run_control(&mut bpf, &mut detection_state, &runtime_cfg, now) {
                    warn!("control tick failed: {e}");
                }
                // Publish the active snapshot + record transition events.
                if let Some(st) = &api_state {
                    let (mut active, events) =
                        mit_tracker.step(collect_active(&detection_state), now_unix());
                    for ev in events {
                        st.record_event(ev.kind, ev.cidr, ev.flags, ev.pps, ev.bps, ev.syn_pps);
                    }
                    for o in st.rules().overrides {
                        active.push(Mitigation {
                            cidr: o.cidr,
                            flags: o.flags,
                            since_unix: now_unix(),
                            manual: true,
                            peak_pps: 0,
                            peak_bps: 0,
                            peak_syn_pps: 0,
                        });
                    }
                    st.set_active(active);
                }
            }
            _ = gc_timer.tick() => {
                match gc_learned_ports(&mut bpf, ttl_ns) {
                    Ok(n) if n > 0 => info!("GC removed {n} expired learned port(s)"),
                    Ok(_) => {}
                    Err(e) => warn!("GC failed: {e}"),
                }
                if let Err(e) = gc_verified(&mut bpf, verified_ttl_ns) {
                    warn!("verified GC failed: {e}");
                }
            }
            _ = cookie_timer.tick() => {
                let new = gc::monotonic_now_ns() as u32 | 1;
                if let Err(e) = rotate_cookie_secret(&mut bpf, new) {
                    warn!("cookie rotation failed: {e}");
                }
            }
            _ = stats_timer.tick(), if stats_secs > 0 => {
                if let Err(e) = log_stats(&bpf) {
                    warn!("Failed to read stats: {e}");
                }
            }
        }
    }
    info!("Shutdown complete.");
    Ok(())
}
