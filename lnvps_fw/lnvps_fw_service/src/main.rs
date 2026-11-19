use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, ProgramArray};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc::qdisc_add_clsact};
use aya::util::KernelVersion;
use aya::{Ebpf, include_bytes_aligned};
use log::{info, warn};

use lnvps_fw_common::{
    COOKIE_SECRET_CURRENT, COOKIE_SECRET_PREVIOUS, DEST_MODE_NORMAL, DestState, LastSeen,
    PROTO_TCP, PROTO_UDP, PortKeyV4, PortKeyV6, SLOT_SYN_PROXY_V4, SLOT_SYN_PROXY_V6,
};

use lnvps_fw_service::api::{
    self, CidrKey, InterfaceInfo, LearnedPort, Limits, Mitigation, Override, PrefixLoad, RuleSet,
    SharedState, SourceBlock, Totals, TrackedIp, TrackedSource, parse_cidr, sni_block_infos,
};
use lnvps_fw_service::cidr::{mask_v4, mask_v6};
use lnvps_fw_service::config::{Config, IfaceRole, XdpModeCfg};
use lnvps_fw_service::detect::{DestTracker, DetectionConfig, Rates};
use lnvps_fw_service::gc;
use lnvps_fw_service::netdev::{self, NicInfo};
use lnvps_fw_service::publish::{self, MitInput, MitTracker, PendingEvent};
use lnvps_fw_service::runtime::{self, DetectionState, RuntimeConfig, run_control, scan_plain};

/// A NORMAL (unblocked) source state idle for this long is swept from the
/// kernel state maps by the GC timer.
const SRC_STATE_IDLE_TTL_NS: u64 = 60 * 1_000_000_000;

/// Upper bound on the learned-ports snapshot published to the control API.
/// The kernel map holds up to a million entries (every VM-initiated connection
/// learns its ephemeral source port too), and every published entry allocates
/// two strings on each GC tick, so the full set is neither cheap nor useful.
/// `Status::learned_ports` still reports the true total.
const MAX_PUBLISHED_PORTS: usize = 20_000;

/// Sweep both learned-ports maps, returning the total number of entries
/// removed. TTL is compared against the monotonic clock (matching
/// `bpf_ktime_get_ns`).
fn gc_learned_ports(bpf: &mut Ebpf, tcp_ttl_ns: u64, udp_ttl_ns: u64) -> Result<usize> {
    let now = gc::monotonic_now_ns();
    let mut removed = 0;
    {
        // Batched scan first (one syscall per ~4k entries), then remove the
        // expired keys through the typed handle.
        let entries: Vec<(PortKeyV4, LastSeen)> = scan_plain(&*bpf, "OPEN_PORTS_V4")?;
        let expired = gc::expired_ports(&entries, now, tcp_ttl_ns, udp_ttl_ns, |k| k.proto);
        removed += runtime::delete_keys::<PortKeyV4, LastSeen>(bpf, "OPEN_PORTS_V4", &expired)?;
    }
    {
        let entries: Vec<(PortKeyV6, LastSeen)> = scan_plain(&*bpf, "OPEN_PORTS_V6")?;
        let expired = gc::expired_ports(&entries, now, tcp_ttl_ns, udp_ttl_ns, |k| k.proto);
        removed += runtime::delete_keys::<PortKeyV6, LastSeen>(bpf, "OPEN_PORTS_V6", &expired)?;
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

/// Attach the XDP program to `iface` in the configured mode. `Auto` asks the
/// kernel for its default (native where the driver has `ndo_bpf`) and falls
/// back to the generic SKB path if that is refused; `Native` refuses the
/// fallback so a driver that cannot run us natively fails startup instead of
/// silently degrading.
fn attach_xdp(xdp: &mut Xdp, iface: &str, mode: XdpModeCfg) -> Result<()> {
    match mode {
        XdpModeCfg::Native => {
            xdp.attach(iface, XdpMode::Driver).with_context(|| {
                format!(
                    "failed to attach XDP to {iface} in native mode (xdp-mode: native \
                     refuses the generic fallback; check MTU/frags support and dmesg)"
                )
            })?;
        }
        XdpModeCfg::Generic => {
            xdp.attach(iface, XdpMode::Skb)
                .with_context(|| format!("failed to attach XDP to {iface} in generic mode"))?;
        }
        XdpModeCfg::Auto => {
            if let Err(e) = xdp.attach(iface, XdpMode::default()) {
                warn!("XDP default attach failed on {iface} ({e}), trying SKB mode");
                xdp.attach(iface, XdpMode::Skb)
                    .with_context(|| format!("failed to attach XDP to {iface}"))?;
            }
        }
    }
    Ok(())
}

/// Load the eBPF object and attach both the XDP ingress and TC egress programs
/// to every configured interface. Returns the loaded object plus what the
/// kernel/driver did with each NIC: the XDP mode actually installed and any
/// offload feature the attach flipped (virtio_net clears guest TSO/GRO-HW/CSUM,
/// a refused native attach lands on the slow generic path). The datapath
/// cannot see any of that, so it is diffed here and logged loudly.
fn attach_programs(cfg: &Config) -> Result<(Ebpf, Vec<NicInfo>)> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lnvps_ebpf"
    )))?;

    // Offload features before we touch anything, for the post-attach diff.
    let before: Vec<_> = cfg
        .interfaces
        .iter()
        .map(|spec| netdev::features(spec.name()).unwrap_or_default())
        .collect();
    let mut hooks: Vec<Vec<String>> = vec![Vec::new(); cfg.interfaces.len()];

    // XDP ingress protection -- attached to host + filter roles. The program is
    // GRE-decap-aware, so a `filter` interface on a router underlay drops
    // attack traffic inside GRE tunnels too.
    {
        let xdp: &mut Xdp = bpf
            .program_mut("xdp_lnvps")
            .context("xdp_lnvps program not found")?
            .try_into()?;
        xdp.load()?;
        for (i, spec) in cfg.interfaces.iter().enumerate() {
            if matches!(spec.role(), IfaceRole::Host | IfaceRole::Filter) {
                attach_xdp(xdp, spec.name(), spec.xdp_mode())?;
                hooks[i].push("xdp".to_string());
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
        for (i, spec) in cfg.interfaces.iter().enumerate() {
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
            hooks[i].push(
                match hook {
                    TcAttachType::Ingress => "tc-ingress",
                    TcAttachType::Egress => "tc-egress",
                    TcAttachType::Custom(_) => "tc",
                }
                .to_string(),
            );
        }
    }

    // What the kernel actually did with each NIC.
    let mut nics = Vec::with_capacity(cfg.interfaces.len());
    for ((spec, before), hooks) in cfg.interfaces.iter().zip(before).zip(hooks) {
        let iface = spec.name();
        let mut nic = NicInfo::snapshot(iface);
        nic.hooks = hooks;
        nic.record_flips(&before);
        info!(
            "{iface} ({:?}): hooks={:?} xdp={} driver={} mtu={} speed={}",
            spec.role(),
            nic.hooks,
            nic.xdp_mode.as_deref().unwrap_or("?"),
            nic.driver.as_deref().unwrap_or("?"),
            nic.mtu.map_or("?".to_string(), |m| m.to_string()),
            nic.speed_mbps
                .map_or("?".to_string(), |s| format!("{s}Mbit/s")),
        );
        if nic.hooks.iter().any(|h| h == "xdp") && nic.xdp_mode.as_deref() != Some("native") {
            warn!(
                "{iface}: XDP is running in {} mode, not native. Generic XDP copies/linearises \
                 every skb and DROPS the large GRO/TSO ones it cannot copy (throughput collapses \
                 for exactly the flows that arrive coalesced). Fix the native attach (kernel \
                 >= 6.3 with multi-buffer support for this driver, MTU, dmesg) or pin \
                 `xdp-mode: generic` and turn off rx-gro-hw/gro on this NIC.",
                nic.xdp_mode.as_deref().unwrap_or("an unknown")
            );
        }
        if !nic.offloads_changed_by_attach.is_empty() {
            warn!(
                "{iface}: attaching changed NIC offloads: {}",
                nic.offloads_changed_by_attach.join(", ")
            );
        }
        nics.push(nic);
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
    // Seed an initial SYN-cookie secret from the CSPRNG.
    rotate_cookie_secret(&mut bpf, fresh_cookie_secret())?;

    Ok((bpf, nics))
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
    // Batched scan (one syscall per ~4k entries), then targeted removals.
    let entries: Vec<(K, u64)> = scan_plain(&*bpf, name)?;
    let expired: Vec<K> = entries
        .iter()
        .filter(|(_, ts)| gc::is_expired(*ts, now, ttl_ns))
        .map(|(k, _)| *k)
        .collect();
    runtime::delete_keys::<K, u64>(bpf, name, &expired)
}

/// Rotate the SYN-cookie secret: previous <- current, current <- `new`.
fn rotate_cookie_secret(bpf: &mut Ebpf, new: u64) -> Result<()> {
    let mut secret: Array<_, u64> = Array::try_from(
        bpf.map_mut("COOKIE_SECRET")
            .context("COOKIE_SECRET missing")?,
    )?;
    let cur = secret.get(&COOKIE_SECRET_CURRENT, 0).unwrap_or(0);
    secret.set(COOKIE_SECRET_PREVIOUS, cur, 0)?;
    secret.set(COOKIE_SECRET_CURRENT, new, 0)?;
    Ok(())
}

/// A fresh 64-bit SYN-cookie key from the OS CSPRNG (never 0). Falls back to a
/// monotonic-clock mix only if `getrandom` somehow fails, so a key is always
/// present.
fn fresh_cookie_secret() -> u64 {
    let mut buf = [0u8; 8];
    match getrandom::getrandom(&mut buf) {
        Ok(()) => u64::from_ne_bytes(buf) | 1,
        Err(e) => {
            warn!("getrandom failed ({e}); using clock-derived cookie secret");
            let t = gc::monotonic_now_ns();
            (t.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Percentage of packets being dropped (drop_pps as a share of pps), clamped
/// to 0..=100.
fn drop_pct(drop_pps: u64, pps: u64) -> u32 {
    if pps == 0 {
        0
    } else {
        (drop_pps.saturating_mul(100) / pps).min(100) as u32
    }
}

/// Manual mitigation overrides parsed for fast per-destination coverage tests,
/// so the live views can reflect a manually-dropped IP/prefix (which the
/// auto-detection trackers never flag).
#[derive(Default)]
struct ManualOverrides {
    /// (prefix_len, masked-network, flags)
    v4: Vec<(u32, [u8; 4], u32)>,
    v6: Vec<(u32, [u8; 16], u32)>,
}

impl ManualOverrides {
    fn from_overrides(overrides: &[Override]) -> Self {
        let mut m = Self::default();
        for o in overrides {
            match parse_cidr(&o.cidr) {
                Some(CidrKey::V4 { bits, net }) => m.v4.push((bits, mask_v4(net, bits), o.flags)),
                Some(CidrKey::V6 { bits, net }) => m.v6.push((bits, mask_v6(net, bits), o.flags)),
                None => {}
            }
        }
        m
    }

    /// OR of the flags of every override whose CIDR covers `ip`.
    fn flags_v4(&self, ip: [u8; 4]) -> u32 {
        self.v4
            .iter()
            .filter(|(bits, net, _)| mask_v4(ip, *bits) == *net)
            .fold(0, |a, (_, _, f)| a | f)
    }

    fn flags_v6(&self, ip: [u8; 16]) -> u32 {
        self.v6
            .iter()
            .filter(|(bits, net, _)| mask_v6(ip, *bits) == *net)
            .fold(0, |a, (_, _, f)| a | f)
    }
}

/// Aggregate live traffic across every per-destination tracker sampled this
/// tick (per-IP only; prefixes aggregate the same dests and would double-count).
fn collect_totals(det: &DetectionState, now_ns: u64) -> Totals {
    let (mut pps, mut bps, mut syn_pps, mut drop_pps) = (0u64, 0u64, 0u64, 0u64);
    let mut acc = |tr: &DestTracker| {
        if tr.last_ns == now_ns {
            pps += tr.last.pps;
            bps += tr.last.bps;
            syn_pps += tr.last.syn_pps;
            drop_pps += tr.last.drop_pps;
        }
    };
    for tr in det.v4.values() {
        acc(tr);
    }
    for tr in det.v6.values() {
        acc(tr);
    }
    let (mut tx_pps, mut tx_bps) = (0u64, 0u64);
    for r in det.tx_v4.values().chain(det.tx_v6.values()) {
        tx_pps += r.pps;
        tx_bps += r.bps;
    }
    Totals {
        rx_pps: pps,
        rx_bps: bps,
        rx_syn_pps: syn_pps,
        rx_drop_pps: drop_pps,
        rx_drop_pct: drop_pct(drop_pps, pps),
        tx_pps,
        tx_bps,
    }
}

/// Snapshot live per-IP rates for every destination sampled this tick (the
/// live dashboard view). Only trackers updated this tick are reported, so idle
/// IPs drop off. Manual overrides are folded into the reported flags so a
/// manually-dropped IP shows as mitigating even though auto-detection never
/// flagged it.
fn collect_tracked(
    det: &DetectionState,
    now_ns: u64,
    cfg: &DetectionConfig,
    manual: &ManualOverrides,
) -> Vec<TrackedIp> {
    let mut out = Vec::new();
    let mut push = |ip: String, tr: &DestTracker, mflags: u32, tx: Rates| {
        let flags = tr.flags | mflags;
        let mitigating = flags != DEST_MODE_NORMAL;
        // Show a row if there's any RX or TX activity this tick, or it's mitigating.
        if tr.last_ns == now_ns && (tr.last.pps > 0 || tx.pps > 0 || mitigating) {
            out.push(TrackedIp {
                ip,
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.pps,
                tx_bps: tx.bps,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                mitigating,
                flags,
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, cfg),
                geo: Default::default(),
            });
        }
    };
    for (k, tr) in &det.v4 {
        let tx = det.tx_v4.get(k).copied().unwrap_or_default();
        push(Ipv4Addr::from(*k).to_string(), tr, manual.flags_v4(*k), tx);
    }
    for (k, tr) in &det.v6 {
        let tx = det.tx_v6.get(k).copied().unwrap_or_default();
        push(Ipv6Addr::from(*k).to_string(), tr, manual.flags_v6(*k), tx);
    }
    out.sort_by(|a, b| b.load_pct.cmp(&a.load_pct));
    out
}

/// Estimate a source's live pps from its kernel window state: packets counted
/// this window over the window's elapsed time. An idle source's stale window
/// decays toward zero naturally (elapsed keeps growing while count doesn't).
/// Elapsed is floored at 100ms so a freshly-rolled window can't inflate.
fn src_pps_estimate(st: &lnvps_fw_common::SrcState, now_ns: u64) -> u64 {
    let elapsed = now_ns.saturating_sub(st.window_start_ns).max(100_000_000);
    ((st.count as u128 * 1_000_000_000u128) / elapsed as u128) as u64
}

/// Snapshot the currently-blocked sources (kernel `blocked_until` in the
/// future) as /32|/128 "blocks" for the legacy `/blocks` view. The block list
/// IS the per-source state map now — there is no CIDR aggregation; `age_secs`
/// reports seconds until the block expires (re-extended while still over-rate)
/// and `cooling` is always false (the exit-hysteresis display state is gone).
fn collect_blocks(det: &DetectionState, now_ns: u64) -> Vec<SourceBlock> {
    let remaining = |until: u64| until.saturating_sub(now_ns) / 1_000_000_000;
    let mut out: Vec<SourceBlock> = det
        .src_v4
        .iter()
        .filter(|(_, st)| st.blocked_until_ns > now_ns)
        .map(|(ip, st)| SourceBlock {
            cidr: format!("{}/32", Ipv4Addr::from(*ip)),
            age_secs: remaining(st.blocked_until_ns),
            pps: src_pps_estimate(st, now_ns),
            manual: false,
            cooling: false,
            geo: Default::default(),
        })
        .chain(
            det.src_v6
                .iter()
                .filter(|(_, st)| st.blocked_until_ns > now_ns)
                .map(|(ip, st)| SourceBlock {
                    cidr: format!("{}/128", Ipv6Addr::from(*ip)),
                    age_secs: remaining(st.blocked_until_ns),
                    pps: src_pps_estimate(st, now_ns),
                    manual: false,
                    cooling: false,
                    geo: Default::default(),
                }),
        )
        .collect();
    // Most active first (the API re-sorts the merged manual+auto set too).
    out.sort_by(|a, b| b.pps.cmp(&a.pps).then_with(|| a.cidr.cmp(&b.cidr)));
    out
}

/// Snapshot every kernel-tracked source for the `/sources` view. The rate
/// machine (and the blocking decision) lives in XDP; this only relabels its
/// state for display: blocked → `dropping`, otherwise `normal`.
fn collect_sources(det: &DetectionState, now_ns: u64) -> Vec<TrackedSource> {
    let row = |ip: String, st: &lnvps_fw_common::SrcState| TrackedSource {
        ip,
        pps: src_pps_estimate(st, now_ns),
        state: if st.blocked_until_ns > now_ns {
            "dropping"
        } else {
            "normal"
        }
        .to_string(),
        manual: false,
        age_secs: now_ns.saturating_sub(st.window_start_ns) / 1_000_000_000,
        geo: Default::default(),
    };
    let mut out: Vec<TrackedSource> = det
        .src_v4
        .iter()
        .map(|(ip, st)| row(Ipv4Addr::from(*ip).to_string(), st))
        .chain(
            det.src_v6
                .iter()
                .map(|(ip, st)| row(Ipv6Addr::from(*ip).to_string(), st)),
        )
        .collect();
    // Most active first (the API re-sorts + paginates too).
    out.sort_by(|a, b| b.pps.cmp(&a.pps).then_with(|| a.ip.cmp(&b.ip)));
    out
}

/// Apply live-edited thresholds from the control API into the runtime config
/// (applied to both the per-destination and per-prefix detectors). `router`
/// only drives the SYN-proxy warning (see `Config::syn_proxy_syn_pps`).
fn apply_limits(rt: &mut RuntimeConfig, l: &Limits, router: bool) {
    if router && l.syn_proxy_pps != 0 && rt.syn_proxy_pps == 0 {
        warn!(
            "limits: syn_proxy_pps set to {} on a router — the SYN-proxy cannot reach \
             clients over tunneled/asymmetric paths and will black-hole real services there",
            l.syn_proxy_pps
        );
    }
    let cooldown_ns = l.cooldown_secs.saturating_mul(1_000_000_000);
    rt.detection.pps = l.pps;
    rt.detection.syn_pps = l.syn_pps;
    rt.detection.bps = l.bps;
    rt.detection.exit_pct = l.exit_pct;
    rt.detection.cooldown_ns = cooldown_ns;
    rt.network.pps = l.net_pps;
    rt.network.syn_pps = l.net_syn_pps;
    rt.network.bps = l.net_bps;
    rt.network.exit_pct = l.exit_pct;
    rt.network.cooldown_ns = cooldown_ns;
    rt.src_rate_pps = l.src_rate_pps;
    rt.src_cooldown_ns = l.src_cooldown_secs.saturating_mul(1_000_000_000);
    rt.syn_proxy_pps = l.syn_proxy_pps;
    rt.learn_leak_pps = l.learn_leak_pps;
}

/// How close a set of rates is to tripping mitigation: the max of the three
/// axes as a percentage of their entry thresholds (>=100 = tripping).
fn load_pct(pps: u64, syn_pps: u64, bps: u64, cfg: &DetectionConfig) -> u32 {
    let r = |v: u64, th: u64| {
        if th == 0 {
            0
        } else {
            (v.saturating_mul(100) / th) as u32
        }
    };
    r(pps, cfg.pps)
        .max(r(syn_pps, cfg.syn_pps))
        .max(r(bps, cfg.bps))
}

/// Snapshot per-protected-prefix aggregate load (the carpet-bomb gauge). Every
/// protected prefix is reported each tick, including at 0% load.
fn collect_prefixes(
    det: &DetectionState,
    now_ns: u64,
    cfg: &DetectionConfig,
    manual: &ManualOverrides,
) -> Vec<PrefixLoad> {
    let mut out = Vec::new();
    let mut push = |cidr: String, tr: &DestTracker, mflags: u32, tx: (u64, u64)| {
        if tr.last_ns == now_ns {
            let flags = tr.flags | mflags;
            out.push(PrefixLoad {
                cidr,
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.0,
                tx_bps: tx.1,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                mitigating: flags != DEST_MODE_NORMAL,
                flags,
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, cfg),
                geo: Default::default(),
            });
        }
    };
    for ((len, net), tr) in &det.prefix_v4 {
        let tx = det
            .tx_v4
            .iter()
            .filter(|(ip, _)| mask_v4(**ip, *len) == *net)
            .fold((0u64, 0u64), |a, (_, r)| (a.0 + r.pps, a.1 + r.bps));
        push(
            format!("{}/{len}", Ipv4Addr::from(*net)),
            tr,
            manual.flags_v4(*net),
            tx,
        );
    }
    for ((len, net), tr) in &det.prefix_v6 {
        let tx = det
            .tx_v6
            .iter()
            .filter(|(ip, _)| mask_v6(**ip, *len) == *net)
            .fold((0u64, 0u64), |a, (_, r)| (a.0 + r.pps, a.1 + r.bps));
        push(
            format!("{}/{len}", Ipv6Addr::from(*net)),
            tr,
            manual.flags_v6(*net),
            tx,
        );
    }
    out.sort_by(|a, b| b.load_pct.cmp(&a.load_pct));
    out
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

/// Live per-window rates keyed by canonical CIDR string, for every tracked
/// dest/prefix sampled this tick. Used to enrich manual overrides: a manually
/// mitigated destination is counted + dropped by XDP, but never enters the
/// auto-detection flag state, so `collect_active` would otherwise report it
/// with zero rates.
fn live_rates_by_cidr(det: &DetectionState, now_ns: u64) -> HashMap<String, Rates> {
    let mut out = HashMap::new();
    let mut push = |cidr: String, tr: &DestTracker| {
        if tr.last_ns == now_ns {
            out.insert(cidr, tr.last);
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

/// Live per-window rates for a mitigation row, matching the tracked-IP columns.
#[derive(Default, Clone, Copy)]
struct MitLive {
    rx_pps: u64,
    rx_bps: u64,
    rx_syn_pps: u64,
    rx_drop_pps: u64,
    tx_pps: u64,
    tx_bps: u64,
    rx_drop_pct: u32,
    load_pct: u32,
}

/// Full live per-window rows keyed by canonical CIDR, for every dest/prefix
/// sampled this tick — used to give each active mitigation the same live rate
/// columns as the tracked-IP view (rx/tx pps+bps, syn/s, drop/s, drop%, load).
fn live_rows_by_cidr(
    det: &DetectionState,
    now_ns: u64,
    det_cfg: &DetectionConfig,
    net_cfg: &DetectionConfig,
) -> HashMap<String, MitLive> {
    let mut out = HashMap::new();
    for (k, tr) in &det.v4 {
        if tr.last_ns != now_ns {
            continue;
        }
        let tx = det.tx_v4.get(k).copied().unwrap_or_default();
        out.insert(
            format!("{}/32", Ipv4Addr::from(*k)),
            MitLive {
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.pps,
                tx_bps: tx.bps,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, det_cfg),
            },
        );
    }
    for (k, tr) in &det.v6 {
        if tr.last_ns != now_ns {
            continue;
        }
        let tx = det.tx_v6.get(k).copied().unwrap_or_default();
        out.insert(
            format!("{}/128", Ipv6Addr::from(*k)),
            MitLive {
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.pps,
                tx_bps: tx.bps,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, det_cfg),
            },
        );
    }
    for ((len, net), tr) in &det.prefix_v4 {
        if tr.last_ns != now_ns {
            continue;
        }
        let tx = det
            .tx_v4
            .iter()
            .filter(|(ip, _)| mask_v4(**ip, *len) == *net)
            .fold((0u64, 0u64), |a, (_, r)| (a.0 + r.pps, a.1 + r.bps));
        out.insert(
            format!("{}/{len}", Ipv4Addr::from(*net)),
            MitLive {
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.0,
                tx_bps: tx.1,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, net_cfg),
            },
        );
    }
    for ((len, net), tr) in &det.prefix_v6 {
        if tr.last_ns != now_ns {
            continue;
        }
        let tx = det
            .tx_v6
            .iter()
            .filter(|(ip, _)| mask_v6(**ip, *len) == *net)
            .fold((0u64, 0u64), |a, (_, r)| (a.0 + r.pps, a.1 + r.bps));
        out.insert(
            format!("{}/{len}", Ipv6Addr::from(*net)),
            MitLive {
                rx_pps: tr.last.pps,
                rx_bps: tr.last.bps,
                rx_syn_pps: tr.last.syn_pps,
                rx_drop_pps: tr.last.drop_pps,
                tx_pps: tx.0,
                tx_bps: tx.1,
                rx_drop_pct: drop_pct(tr.last.drop_pps, tr.last.pps),
                load_pct: load_pct(tr.last.pps, tr.last.syn_pps, tr.last.bps, net_cfg),
            },
        );
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
    applied: &mut HashMap<String, (CidrKey, u32)>,
    applied_blocks: &mut HashMap<String, CidrKey>,
    rt: &mut RuntimeConfig,
    now_ns: u64,
) -> Result<Vec<PendingEvent>> {
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

    // Publish the manual overrides as detection floors so the auto state machine
    // ORs them in (and restores them on exit) instead of clobbering an
    // operator-forced flag on the shared dest-state trie.
    let manual = ManualOverrides::from_overrides(&rules.overrides);
    rt.manual_v4 = manual.v4;
    rt.manual_v6 = manual.v6;

    let mut desired: HashMap<String, (CidrKey, u32)> = HashMap::new();
    for o in &rules.overrides {
        if let Some(k) = parse_cidr(&o.cidr) {
            desired.insert(o.cidr.clone(), (k, o.flags));
        }
    }
    // Every change to what the datapath enforces is logged and recorded as an
    // event: an override or block takes effect with no traffic-side signal
    // (no MITIGATION line), so this is the only trail a throughput complaint
    // can be lined up against.
    let flags_of = |m: &HashMap<String, (CidrKey, u32)>| -> HashMap<String, u32> {
        m.iter().map(|(c, (_, f))| (c.clone(), *f)).collect()
    };
    let mut events = publish::override_events(&flags_of(applied), &flags_of(&desired));
    let gone: Vec<String> = applied
        .keys()
        .filter(|c| !desired.contains_key(*c))
        .cloned()
        .collect();
    for c in gone {
        if let Some((k, _)) = applied.remove(&c) {
            remove_dest_state(bpf, k)?;
            info!("OVERRIDE CLEARED cidr={c}");
        }
    }
    for (c, (k, flags)) in &desired {
        // Re-written unconditionally: idempotent, and self-heals a partial write.
        write_dest_state(bpf, *k, *flags, now_ns)?;
        if applied.insert(c.clone(), (*k, *flags)).map(|(_, f)| f) != Some(*flags) {
            info!("OVERRIDE SET cidr={c} flags={flags:#06b}");
        }
    }

    // Manual source blocks -> MANUAL_BLOCK tries (unconditional drops).
    let mut want: HashMap<String, CidrKey> = HashMap::new();
    for c in &rules.source_blocks {
        match parse_cidr(c) {
            Some(k) => {
                want.insert(c.clone(), k);
            }
            None => warn!("ignoring bad source-block cidr {c}"),
        }
    }
    let prev_blocks: Vec<String> = applied_blocks.keys().cloned().collect();
    let gone_blocks: Vec<String> = applied_blocks
        .keys()
        .filter(|c| !want.contains_key(*c))
        .cloned()
        .collect();
    for c in gone_blocks {
        if let Some(k) = applied_blocks.remove(&c) {
            manual_block(bpf, k, false)?;
            info!("SOURCE BLOCK REMOVED cidr={c}");
        }
    }
    for (c, k) in &want {
        manual_block(bpf, *k, true)?;
        if applied_blocks.insert(c.clone(), *k).is_none() {
            info!("SOURCE BLOCK ADDED cidr={c}");
        }
    }
    let cur_blocks: Vec<String> = applied_blocks.keys().cloned().collect();
    events.extend(publish::set_events(
        &prev_blocks,
        &cur_blocks,
        api::EventKind::BlockStart,
        api::EventKind::BlockStop,
    ));
    // Let the XDP fast-path skip the per-packet MANUAL_BLOCK LPM lookup unless
    // at least one block is installed.
    let have_blocks = !applied_blocks.is_empty();
    runtime::update_global_cfg(bpf, |c| c.manual_blocks = u32::from(have_blocks))?;
    Ok(events)
}

/// Keys of one LPM trie map as `<tag>:<addr>/<len>` strings (empty if the map
/// is missing or of another type).
fn trie_entries<K, V>(bpf: &Ebpf, name: &str, tag: &str, addr: impl Fn(K) -> String) -> Vec<String>
where
    K: aya::Pod,
    V: aya::Pod,
{
    bpf.map(name)
        .and_then(|m| LpmTrie::<_, K, V>::try_from(m).ok())
        .map(|t| {
            t.keys()
                .flatten()
                .map(|k| format!("{tag}:{}/{}", addr(k.data()), k.prefix_len()))
                .collect()
        })
        .unwrap_or_default()
}

/// Every entry currently in the dest-state and manual-block tries. Only
/// consulted when drops are seen with nothing known to be mitigating (a
/// userspace/kernel desync), so cost is irrelevant.
fn enforcing_entries(bpf: &Ebpf) -> Vec<String> {
    let v4 = |a: [u8; 4]| Ipv4Addr::from(a).to_string();
    let v6 = |a: [u8; 16]| Ipv6Addr::from(a).to_string();
    let mut out = trie_entries::<[u8; 4], DestState>(bpf, "V4_DEST_STATE", "dest", v4);
    out.extend(trie_entries::<[u8; 16], DestState>(
        bpf,
        "V6_DEST_STATE",
        "dest",
        v6,
    ));
    out.extend(trie_entries::<[u8; 4], u8>(
        bpf,
        "MANUAL_BLOCK_V4",
        "block",
        v4,
    ));
    out.extend(trie_entries::<[u8; 16], u8>(
        bpf,
        "MANUAL_BLOCK_V6",
        "block",
        v6,
    ));
    out
}

/// Add (`set`) or remove a manual source-CIDR block in the MANUAL_BLOCK tries.
fn manual_block(bpf: &mut Ebpf, key: CidrKey, set: bool) -> Result<()> {
    match key {
        CidrKey::V4 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(
                bpf.map_mut("MANUAL_BLOCK_V4")
                    .context("manual v4 missing")?,
            )?;
            if set {
                t.insert(&Key::new(bits, net), 1u8, 0)?;
            } else {
                let _ = t.remove(&Key::new(bits, net));
            }
        }
        CidrKey::V6 { bits, net } => {
            let mut t: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(
                bpf.map_mut("MANUAL_BLOCK_V6")
                    .context("manual v6 missing")?,
            )?;
            if set {
                t.insert(&Key::new(bits, net), 1u8, 0)?;
            } else {
                let _ = t.remove(&Key::new(bits, net));
            }
        }
    }
    Ok(())
}

/// Snapshot the learned open ports (both families) for the control API.
fn collect_ports(bpf: &Ebpf) -> (Vec<LearnedPort>, usize) {
    let now = gc::monotonic_now_ns();
    let proto_str = |p: u8| match p {
        PROTO_TCP => "tcp".to_string(),
        PROTO_UDP => "udp".to_string(),
        other => format!("proto-{other}"),
    };
    let age = |last_seen: u64| now.saturating_sub(last_seen) / 1_000_000_000;
    // Batched scan (one syscall per ~4k entries). A per-key `keys()` walk with
    // a `get()` per key costs two syscalls per entry, which pegs a core for
    // tens of seconds once the map holds hundreds of thousands of entries --
    // and because that ran on the control loop, it stalled the control API too.
    let v4: Vec<(PortKeyV4, LastSeen)> = scan_or_empty(bpf, "OPEN_PORTS_V4");
    let v6: Vec<(PortKeyV6, LastSeen)> = scan_or_empty(bpf, "OPEN_PORTS_V6");
    let total = v4.len() + v6.len();

    // Bound the published snapshot: keep the freshest entries per family, then
    // trim the merged list. Only the retained entries are formatted.
    let v4 = gc::freshest(v4, MAX_PUBLISHED_PORTS);
    let v6 = gc::freshest(v6, MAX_PUBLISHED_PORTS);
    let mut out = Vec::with_capacity(v4.len() + v6.len());
    out.extend(v4.into_iter().map(|(k, ls)| LearnedPort {
        ip: Ipv4Addr::from(k.addr).to_string(),
        port: k.port,
        proto: proto_str(k.proto),
        age_secs: age(ls.last_seen),
    }));
    out.extend(v6.into_iter().map(|(k, ls)| LearnedPort {
        ip: Ipv6Addr::from(k.addr).to_string(),
        port: k.port,
        proto: proto_str(k.proto),
        age_secs: age(ls.last_seen),
    }));
    if out.len() > MAX_PUBLISHED_PORTS {
        out.select_nth_unstable_by_key(MAX_PUBLISHED_PORTS, |p| p.age_secs);
        out.truncate(MAX_PUBLISHED_PORTS);
    }
    (out, total)
}

/// Batched map scan that degrades to an empty snapshot (with a warning) rather
/// than failing the control loop -- the snapshot is a view, not state.
fn scan_or_empty<K, V>(bpf: &Ebpf, name: &str) -> Vec<(K, V)>
where
    K: aya::Pod,
    V: aya::Pod,
{
    match scan_plain::<K, V>(bpf, name) {
        Ok(v) => v,
        Err(e) => {
            warn!("scanning {name} failed: {e}");
            Vec::new()
        }
    }
}

/// Reconcile the protected-prefix tries and the `scoped` flag from the current
/// protected lists. When any prefix is set, XDP scopes counting/mitigation to
/// those destinations (and passes everything else); an empty list means
/// protect-everything (single-NIC host mode).
fn sync_protected(
    bpf: &mut Ebpf,
    v4: &[(u32, [u8; 4])],
    v6: &[(u32, [u8; 16])],
    applied_v4: &mut Vec<(u32, [u8; 4])>,
    applied_v6: &mut Vec<(u32, [u8; 16])>,
) -> Result<()> {
    {
        let mut t: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(
            bpf.map_mut("PROTECTED_V4")
                .context("PROTECTED_V4 missing")?,
        )?;
        for (len, net) in applied_v4.drain(..) {
            let _ = t.remove(&Key::new(len, net));
        }
        for &(len, net) in v4 {
            t.insert(&Key::new(len, net), 1u8, 0)?;
            applied_v4.push((len, net));
        }
    }
    {
        let mut t: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(
            bpf.map_mut("PROTECTED_V6")
                .context("PROTECTED_V6 missing")?,
        )?;
        for (len, net) in applied_v6.drain(..) {
            let _ = t.remove(&Key::new(len, net));
        }
        for &(len, net) in v6 {
            t.insert(&Key::new(len, net), 1u8, 0)?;
            applied_v6.push((len, net));
        }
    }
    let scoped = !(v4.is_empty() && v6.is_empty());
    runtime::update_global_cfg(bpf, |c| c.scoped = u32::from(scoped))?;
    Ok(())
}

/// Publish the attached interfaces (role, link speed, XDP mode, offloads, XDP
/// counters) to the control API. Called at startup and on every stats tick.
fn publish_nics(st: &SharedState, cfg: &Config, nics: &[NicInfo]) {
    st.set_nics(
        cfg.interfaces
            .iter()
            .zip(nics)
            .map(|(spec, nic)| InterfaceInfo {
                role: match spec.role() {
                    IfaceRole::Host => "host",
                    IfaceRole::Filter => "filter",
                    IfaceRole::Learn => "learn",
                }
                .to_string(),
                ..InterfaceInfo::from(nic.clone())
            })
            .collect(),
    );
}

/// Build the API shared state and spawn the HTTPS server; returns the shared
/// handle the control loop publishes into.
fn start_api(cfg: &Config, nics: &[NicInfo]) -> Result<Option<std::sync::Arc<SharedState>>> {
    let Some(api_cfg) = &cfg.api else {
        return Ok(None);
    };
    let initial = RuleSet {
        protected: cfg.protected.clone(),
        overrides: Vec::new(),
        source_blocks: Vec::new(),
        // Seed the runtime SNI blocklist from the local config; the API can
        // then add/remove entries live.
        sni_blocks: cfg.sni_blocklist(),
    };
    let state = SharedState::new(
        api_cfg.token.clone(),
        api_cfg.allow_ips.clone(),
        cfg.interface_names(),
        initial,
        api_cfg.events_buffer,
        api_cfg.github_repo.clone(),
        api_cfg.allow_remote_upgrade,
        api_cfg.upgrade_pubkey.clone(),
    );
    // Optional GeoIP enrichment for listed IPs (ASN/org/country). Databases are
    // either explicit paths or auto-downloaded from MaxMind via a license key.
    // Done in a background task (this fn is sync): the initial load may involve
    // a download, and enrichment is best-effort, so requests before it is ready
    // simply carry no geo fields.
    let geoip_configured = cfg.geoip.asn_db.is_some()
        || cfg.geoip.country_db.is_some()
        || cfg.geoip.license_key.is_some();
    if geoip_configured {
        use lnvps_fw_service::geoip::{self, GeoIp};
        let st = state.clone();
        let gcfg = cfg.geoip.clone();
        tokio::spawn(async move {
            let dir = std::path::Path::new("/var/lib/lnvps_fw");
            let load = |asn: Option<std::path::PathBuf>, country: Option<std::path::PathBuf>| {
                let g = GeoIp::load(asn.as_deref(), country.as_deref());
                g.enabled().then_some(g)
            };
            let (asn, country) = geoip::resolve_databases(&gcfg, dir, false).await;
            if let Some(g) = load(asn, country) {
                st.set_geoip(g);
            }
            // Periodic re-download + hot-reload only when a license key drives it.
            if gcfg.license_key.is_some() {
                let hours = gcfg.refresh_interval_hours.max(1) as u64;
                let mut timer = tokio::time::interval(Duration::from_secs(hours * 3600));
                timer.tick().await; // consume the immediate first tick
                loop {
                    timer.tick().await;
                    let (asn, country) = geoip::resolve_databases(&gcfg, dir, true).await;
                    if let Some(g) = load(asn, country) {
                        st.set_geoip(g);
                        info!("GeoIP databases refreshed");
                    }
                }
            }
        });
    }
    // Periodic self-upgrade check (immediately, then every 6h).
    {
        let st = state.clone();
        tokio::spawn(async move {
            let repo = st.upgrade_repo().to_string();
            let current = env!("CARGO_PKG_VERSION").to_string();
            let mut timer = tokio::time::interval(Duration::from_secs(6 * 3600));
            loop {
                timer.tick().await;
                st.set_upgrade(lnvps_fw_service::upgrade::check(&repo, &current).await);
            }
        });
    }
    // Persist an auto-generated self-signed pair here so its fingerprint is
    // stable across restarts (systemd creates this via StateDirectory=).
    let tls_state_dir = std::path::Path::new("/var/lib/lnvps_fw");
    let tls = api::load_or_generate_tls(
        api_cfg.tls_cert.as_deref(),
        api_cfg.tls_key.as_deref(),
        api_cfg.listen.ip(),
        Some(tls_state_dir),
    )?;
    if tls.self_signed {
        info!(
            "Control API: no cert configured, generated a self-signed cert (persisted in {})",
            tls_state_dir.display()
        );
    }
    let addr = api_cfg.listen;
    let srv_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = api::serve(srv_state, addr, tls).await {
            warn!("Control API server exited: {e}");
        }
    });
    // Publish the attached interfaces + their link speeds and roles (for
    // line-rate hints; only ingress/filter NICs count toward the ceiling).
    publish_nics(&state, cfg, nics);
    info!("Control API (HTTPS) listening on https://{addr}");
    Ok(Some(state))
}

// Multi-threaded on purpose: the control loop below runs long blocking BPF map
// sweeps (GC, snapshots) on the thread that drives `main`, so the control API
// and the other background tasks need worker threads of their own to stay
// responsive while a sweep is in progress.
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = load_config()?;
    let kernel = KernelVersion::current()?;
    info!(
        "Running on kernel {kernel}; interfaces={:?}",
        cfg.interfaces
    );

    let (mut bpf, mut nics) = attach_programs(&cfg)?;

    let ttl_ns = cfg.port_ttl().as_nanos() as u64;
    let udp_ttl_ns = cfg.udp_port_ttl().as_nanos() as u64;
    let mut runtime_cfg = cfg.runtime_config()?;
    let mut detection_state = DetectionState::default();
    let router = cfg.is_router();
    if router && runtime_cfg.syn_proxy_pps != 0 {
        warn!(
            "SYN-proxy trigger is {} SYN/s on a router: it black-holes real services on \
             tunneled/asymmetric paths — set escalation.syn-proxy-syn-pps: 0",
            runtime_cfg.syn_proxy_pps
        );
    }

    // Control API (increment 7): HTTPS server + shared state the loop publishes
    // into. Rules are pushed by lnvps_api and reconciled below on change.
    let api_state = start_api(&cfg, &nics)?;
    let mut rules_version = 0u64;
    let mut limits_version = 0u64;
    let mut applied_overrides: HashMap<String, (CidrKey, u32)> = HashMap::new();
    let mut applied_blocks: HashMap<String, CidrKey> = HashMap::new();
    let mut applied_protected_v4: Vec<(u32, [u8; 4])> = Vec::new();
    let mut applied_protected_v6: Vec<(u32, [u8; 16])> = Vec::new();
    let mut mit_tracker = MitTracker::default();
    // Per-manual-override bookkeeping: stable `since` timestamp + running peak
    // rates, keyed by the raw override CIDR string (manual mitigations are not
    // driven by the auto-detection trackers, so we accumulate their live rates
    // here instead of reporting zeros).
    let mut manual_state: HashMap<String, (u64, Rates)> = HashMap::new();

    // Scope XDP to the protected prefixes up front (empty => host mode).
    sync_protected(
        &mut bpf,
        &runtime_cfg.protected_v4,
        &runtime_cfg.protected_v6,
        &mut applied_protected_v4,
        &mut applied_protected_v6,
    )?;
    if runtime_cfg.protected_v4.is_empty() && runtime_cfg.protected_v6.is_empty() {
        warn!(
            "no protected prefixes configured: protecting ALL destinations \
             (host mode). On a router, set `protected` to your ranges."
        );
    } else {
        info!(
            "Scoped to {} protected prefix(es)",
            runtime_cfg.protected_v4.len() + runtime_cfg.protected_v6.len()
        );
    }

    // Publish the detection thresholds so the dashboard/API can show headroom.
    if let Some(st) = &api_state {
        let det = &runtime_cfg.detection;
        let net = &runtime_cfg.network;
        st.set_limits(Limits {
            pps: det.pps,
            syn_pps: det.syn_pps,
            bps: det.bps,
            net_pps: net.pps,
            net_syn_pps: net.syn_pps,
            net_bps: net.bps,
            exit_pct: det.exit_pct,
            cooldown_secs: det.cooldown_ns / 1_000_000_000,
            src_rate_pps: runtime_cfg.src_rate_pps,
            src_cooldown_secs: runtime_cfg.src_cooldown_ns / 1_000_000_000,
            syn_proxy_pps: runtime_cfg.syn_proxy_pps,
            learn_leak_pps: runtime_cfg.learn_leak_pps,
        });
    }
    // Arm the in-kernel per-source rate machine before traffic decisions.
    runtime::write_src_rate_cfg(&mut bpf, &runtime_cfg)?;
    runtime::write_learn_leak_cfg(&mut bpf, &runtime_cfg)?;

    // TLS-SNI egress blocklist: the inspection ports are config-only (written
    // once), the hostnames are seeded from config here so they are enforced
    // even with the control API disabled, and reconciled on every rules change
    // below.
    runtime::write_sni_ports(&mut bpf, &cfg.sni_ports)?;
    let mut sni_hostnames: Vec<String> = cfg.sni_blocklist().into_iter().map(|b| b.sni).collect();
    match runtime::sync_sni_blocks(&mut bpf, &sni_hostnames) {
        Ok(_) if sni_hostnames.is_empty() => {}
        Ok(_) => {
            info!(
                "SNI egress blocklist: {} hostname(s) on port(s) {:?}",
                sni_hostnames.len(),
                cfg.sni_ports
            );
            for sni in &sni_hostnames {
                info!("SNI BLOCK ADDED sni={sni} (config)");
                if let Some(st) = &api_state {
                    st.record_event(api::EventKind::SniStart, sni.clone(), 0, 0, 0, 0);
                }
            }
        }
        Err(e) => warn!("writing SNI blocklist failed: {e}"),
    }
    let mut detect_timer = tokio::time::interval(cfg.sample_interval());
    let mut gc_timer = tokio::time::interval(cfg.gc_interval());
    // Periodic one-line health summary (`learning.stats-interval-secs`, 0 =
    // off). The interval is also where the driver-level XDP counters are
    // re-read and the "drops with nothing mitigating" desync check runs.
    let stats_every = cfg.learning.stats_interval_secs;
    let mut stats_timer = tokio::time::interval(Duration::from_secs(stats_every.max(1)));
    let mut nic_xdp_drops: HashMap<String, u64> = HashMap::new();
    // Rotate the SYN-cookie secret periodically; cookies issued in the previous
    // window still validate against the prev slot.
    let mut cookie_timer = tokio::time::interval(Duration::from_secs(120));
    let verified_ttl_ns = ttl_ns;
    // Publish the verified-source TTL so the XDP SYN-proxy expires stale
    // verifications in-kernel (userspace GC then only reclaims memory).
    runtime::update_global_cfg(&mut bpf, |c| c.verified_ttl_ns = verified_ttl_ns)?;

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

    // systemd stops us with SIGTERM: handle it like ^C so the shutdown path
    // below runs (an abrupt exit detaches the programs but leaves whatever the
    // attach did to the NIC offloads in place).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = detect_timer.tick() => {
                let now = gc::monotonic_now_ns();
                // Reconcile any newly-pushed rules before detecting.
                if let Some(st) = &api_state {
                    let v = st.rules_version();
                    if v != rules_version {
                        rules_version = v;
                        let rules = st.rules();
                        match apply_rules(
                            &mut bpf,
                            &rules,
                            &mut applied_overrides,
                            &mut applied_blocks,
                            &mut runtime_cfg,
                            now,
                        ) {
                            Ok(events) => {
                                for ev in events {
                                    st.record_event(ev.kind, ev.cidr, ev.flags, 0, 0, 0);
                                }
                            }
                            Err(e) => warn!("apply rules failed: {e}"),
                        }
                        if let Err(e) = sync_protected(
                            &mut bpf,
                            &runtime_cfg.protected_v4,
                            &runtime_cfg.protected_v6,
                            &mut applied_protected_v4,
                            &mut applied_protected_v6,
                        ) {
                            warn!("sync protected failed: {e}");
                        }
                        // Reconcile the SNI egress blocklist (API add/remove or
                        // a full rules push) into the datapath.
                        let new_sni: Vec<String> =
                            rules.sni_blocks.iter().map(|b| b.sni.clone()).collect();
                        for ev in publish::set_events(
                            &sni_hostnames,
                            &new_sni,
                            api::EventKind::SniStart,
                            api::EventKind::SniStop,
                        ) {
                            match ev.kind {
                                api::EventKind::SniStart => info!("SNI BLOCK ADDED sni={}", ev.cidr),
                                _ => info!("SNI BLOCK REMOVED sni={}", ev.cidr),
                            }
                            st.record_event(ev.kind, ev.cidr, 0, 0, 0, 0);
                        }
                        sni_hostnames = new_sni;
                        match runtime::sync_sni_blocks(&mut bpf, &sni_hostnames) {
                            Ok((0, 0)) => {}
                            Ok((added, removed)) => info!(
                                "SNI egress blocklist updated: +{added} -{removed} \
                                 ({} active)",
                                sni_hostnames.len()
                            ),
                            Err(e) => warn!("sync SNI blocklist failed: {e}"),
                        }
                    }
                }
                // Reload live-edited detection thresholds.
                if let Some(st) = &api_state {
                    let v = st.limits_version();
                    if v != limits_version {
                        limits_version = v;
                        apply_limits(&mut runtime_cfg, &st.limits(), router);
                        // Push the per-source limits into the kernel rate
                        // machine (it owns per-source blocking now).
                        if let Err(e) = runtime::write_src_rate_cfg(&mut bpf, &runtime_cfg) {
                            warn!("writing src rate config failed: {e}");
                        }
                        if let Err(e) = runtime::write_learn_leak_cfg(&mut bpf, &runtime_cfg) {
                            warn!("writing learn-leak config failed: {e}");
                        }
                        info!("detection limits updated via API");
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
                    let live = live_rates_by_cidr(&detection_state, now);
                    let overrides = st.rules().overrides;
                    let manual = ManualOverrides::from_overrides(&overrides);
                    let mut seen: HashSet<String> = HashSet::new();
                    for o in overrides {
                        seen.insert(o.cidr.clone());
                        // Match live rates against the canonical CIDR form so a
                        // bare address (`1.2.3.4`) still lines up with the
                        // tracker key (`1.2.3.4/32`).
                        let key = parse_cidr(&o.cidr)
                            .map(|k| k.to_cidr_string())
                            .unwrap_or_else(|| o.cidr.clone());
                        let r = live.get(&key).copied().unwrap_or_default();
                        let entry = manual_state
                            .entry(o.cidr.clone())
                            .or_insert_with(|| (now_unix(), Rates::default()));
                        entry.1.pps = entry.1.pps.max(r.pps);
                        entry.1.bps = entry.1.bps.max(r.bps);
                        entry.1.syn_pps = entry.1.syn_pps.max(r.syn_pps);
                        let (since, peak) = *entry;
                        active.push(Mitigation {
                            cidr: o.cidr,
                            flags: o.flags,
                            since_unix: since,
                            manual: true,
                            peak_pps: peak.pps,
                            peak_bps: peak.bps,
                            peak_syn_pps: peak.syn_pps,
                            ..Default::default()
                        });
                    }
                    // Drop bookkeeping for overrides that no longer exist.
                    manual_state.retain(|c, _| seen.contains(c));
                    // Enrich every mitigation (auto + manual) with the same live
                    // per-window rates as the tracked-IP view, keyed by cidr.
                    let live_rows = live_rows_by_cidr(
                        &detection_state,
                        now,
                        &runtime_cfg.detection,
                        &runtime_cfg.network,
                    );
                    for m in &mut active {
                        let key = parse_cidr(&m.cidr)
                            .map(|k| k.to_cidr_string())
                            .unwrap_or_else(|| m.cidr.clone());
                        if let Some(lr) = live_rows.get(&key) {
                            m.rx_pps = lr.rx_pps;
                            m.rx_bps = lr.rx_bps;
                            m.rx_syn_pps = lr.rx_syn_pps;
                            m.rx_drop_pps = lr.rx_drop_pps;
                            m.tx_pps = lr.tx_pps;
                            m.tx_bps = lr.tx_bps;
                            m.rx_drop_pct = lr.rx_drop_pct;
                            m.load_pct = lr.load_pct;
                        }
                    }
                    st.set_active(active);
                    st.set_tracked(collect_tracked(
                        &detection_state,
                        now,
                        &runtime_cfg.detection,
                        &manual,
                    ));
                    st.set_prefixes(collect_prefixes(
                        &detection_state,
                        now,
                        &runtime_cfg.network,
                        &manual,
                    ));
                    st.set_blocks(collect_blocks(&detection_state, now));
                    st.set_sources(collect_sources(&detection_state, now));
                    st.set_totals(collect_totals(&detection_state, now));
                    // Publish the SNI blocklist with its live drop counters.
                    match runtime::read_sni_drops(&bpf) {
                        Ok(drops) => {
                            st.set_sni_blocks(sni_block_infos(&st.rules().sni_blocks, &drops))
                        }
                        Err(e) => warn!("reading SNI drop counters failed: {e}"),
                    }
                }
            }
            _ = gc_timer.tick() => {
                match gc_learned_ports(&mut bpf, ttl_ns, udp_ttl_ns) {
                    Ok(n) if n > 0 => info!("GC removed {n} expired learned port(s)"),
                    Ok(_) => {}
                    Err(e) => warn!("GC failed: {e}"),
                }
                if let Err(e) = gc_verified(&mut bpf, verified_ttl_ns) {
                    warn!("verified GC failed: {e}");
                }
                // Sweep idle per-source rate states (the kernel machine never
                // self-cleans; without this the state maps and the /sources
                // view would hold every source ever seen under mitigation).
                match runtime::gc_src_states(&mut bpf, SRC_STATE_IDLE_TTL_NS) {
                    Ok(n) if n > 0 => info!("GC removed {n} idle source state(s)"),
                    Ok(_) => {}
                    Err(e) => warn!("source-state GC failed: {e}"),
                }
                // Refresh the learned-ports snapshot for the control API.
                if let Some(st) = &api_state {
                    let (ports, total) = collect_ports(&bpf);
                    st.set_ports(ports, total);
                }
            }
            _ = cookie_timer.tick() => {
                let new = fresh_cookie_secret();
                if let Err(e) = rotate_cookie_secret(&mut bpf, new) {
                    warn!("cookie rotation failed: {e}");
                }
            }
            _ = stats_timer.tick(), if stats_every > 0 => {
                // Rates from the most recent detection tick (the trackers are
                // stamped with that tick's timestamp).
                let totals = collect_totals(&detection_state, detection_state.last_sample_ns);
                let mitigating = collect_active(&detection_state).len();
                // Driver-side XDP drops since the last stats tick, per NIC.
                let mut driver_drops = 0u64;
                for nic in &mut nics {
                    nic.refresh();
                    let cur = nic.xdp_stats.get("rx_xdp_drops").copied().unwrap_or(0);
                    let prev = nic_xdp_drops.insert(nic.name.clone(), cur).unwrap_or(cur);
                    driver_drops += cur.saturating_sub(prev);
                }
                info!(
                    "STATS rx_pps={} rx_bps={} drop_pps={} tx_pps={} dests={} mitigating={} \
                     overrides={} blocks={} sni={} nic_xdp_drops_delta={driver_drops}",
                    totals.rx_pps,
                    totals.rx_bps,
                    totals.rx_drop_pps,
                    totals.tx_pps,
                    detection_state.v4.len() + detection_state.v6.len(),
                    mitigating,
                    applied_overrides.len(),
                    applied_blocks.len(),
                    sni_hostnames.len(),
                );
                // The datapath only drops under a dest flag or a manual block,
                // so drops with none of those known to userspace mean the
                // kernel tries hold entries we don't know about.
                if totals.rx_drop_pps > 0
                    && mitigating == 0
                    && applied_overrides.is_empty()
                    && applied_blocks.is_empty()
                {
                    warn!(
                        "dropping {} pps with no mitigation, override or block active — \
                         enforcing trie entries: {:?}",
                        totals.rx_drop_pps,
                        enforcing_entries(&bpf)
                    );
                }
                // Drops the driver counted while our program could not have
                // issued any (nothing mitigating, no override, no block):
                // XDP_ABORTED, a failed linearise on the generic path, ...
                // Gated on the enforcing state rather than `drop_pps` because
                // the detection window and the driver-counter delta do not
                // line up under a real mitigation.
                if driver_drops > 0
                    && mitigating == 0
                    && applied_overrides.is_empty()
                    && applied_blocks.is_empty()
                {
                    warn!(
                        "NIC driver reports {driver_drops} XDP drop(s) this interval while the \
                         program dropped nothing — a driver/kernel-level drop, not a verdict"
                    );
                }
                for nic in &nics {
                    if nic.hooks.iter().any(|h| h == "xdp") && nic.xdp_mode.as_deref() == Some("none") {
                        warn!("{}: XDP program is no longer attached", nic.name);
                    }
                }
                if let Some(st) = &api_state {
                    publish_nics(st, &cfg, &nics);
                }
            }
        }
    }
    // Detach first (dropping the object closes the program/link fds), then
    // undo the offload flips: a generic-XDP install turns `rx-gro-hw` off and
    // the kernel never turns it back on, so without this a stopped firewall
    // would leave the NIC (and, on virtio, the hypervisor's tap) degraded.
    drop(bpf);
    for nic in &nics {
        match nic.restore_offloads() {
            Ok(v) if v.is_empty() => {}
            Ok(v) => info!("{}: restored NIC offloads: {}", nic.name, v.join(", ")),
            Err(e) => warn!("{}: restoring NIC offloads failed: {e}", nic.name),
        }
    }
    info!("Shutdown complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_fw_common::SrcState;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn src_pps_estimate_scales_count_over_window_elapsed() {
        let st = SrcState {
            window_start_ns: 0,
            count: 500,
            blocked_until_ns: 0,
        };
        // Half a second into the window, 500 packets => 1000 pps.
        assert_eq!(src_pps_estimate(&st, SEC / 2), 1000);
        // A stale window decays naturally: same 500 packets over 10s => 50.
        assert_eq!(src_pps_estimate(&st, 10 * SEC), 50);
    }

    #[test]
    fn src_pps_estimate_floors_tiny_elapsed() {
        let st = SrcState {
            window_start_ns: 0,
            count: 10,
            blocked_until_ns: 0,
        };
        // 1ms into a fresh window: elapsed floored at 100ms so the estimate is
        // 100 pps, not 10_000 (no burst inflation from a just-rolled window).
        assert_eq!(src_pps_estimate(&st, 1_000_000), 100);
    }
}
