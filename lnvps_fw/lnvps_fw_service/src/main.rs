use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::maps::{HashMap as AyaHashMap, PerCpuHashMap};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc::qdisc_add_clsact};
use aya::util::KernelVersion;
use aya::{Ebpf, include_bytes_aligned};
use log::{info, warn};

use lnvps_fw_common::{DestCounters, LastSeen, PortKeyV4, PortKeyV6};

use lnvps_fw_service::config::Config;
use lnvps_fw_service::gc;
use lnvps_fw_service::runtime::{DetectionState, run_control, sum_counters};

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

    // XDP ingress protection.
    let xdp: &mut Xdp = bpf
        .program_mut("xdp_lnvps")
        .context("xdp_lnvps program not found")?
        .try_into()?;
    xdp.load()?;
    for iface in &cfg.interfaces {
        match xdp.attach(iface, XdpMode::default()) {
            Ok(_) => info!("XDP attached to {iface} (default mode)"),
            Err(e) => {
                warn!("XDP default attach failed on {iface} ({e}), trying SKB mode");
                xdp.attach(iface, XdpMode::Skb)
                    .with_context(|| format!("failed to attach XDP to {iface}"))?;
                info!("XDP attached to {iface} (skb mode)");
            }
        }
    }

    // TC egress port learning.
    let tc: &mut SchedClassifier = bpf
        .program_mut("tc_lnvps_egress")
        .context("tc_lnvps_egress program not found")?
        .try_into()?;
    tc.load()?;
    for iface in &cfg.interfaces {
        // On kernels < 6.6 the clsact qdisc must exist before attaching; on
        // 6.6+ TCX is used and this is unnecessary. Best-effort either way.
        let _ = qdisc_add_clsact(iface);
        tc.attach(iface, TcAttachType::Egress)
            .with_context(|| format!("failed to attach TC egress to {iface}"))?;
        info!("TC egress attached to {iface}");
    }

    Ok(bpf)
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
    let runtime_cfg = cfg.runtime_config()?;
    let mut detection_state = DetectionState::default();
    let mut detect_timer = tokio::time::interval(cfg.sample_interval());
    let mut gc_timer = tokio::time::interval(cfg.gc_interval());
    let stats_secs = cfg.learning.stats_interval_secs;
    // A zero stats interval disables logging; use a long dummy period.
    let mut stats_timer = tokio::time::interval(Duration::from_secs(if stats_secs == 0 {
        3600
    } else {
        stats_secs
    }));

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
                if let Err(e) = run_control(&mut bpf, &mut detection_state, &runtime_cfg, now) {
                    warn!("control tick failed: {e}");
                }
            }
            _ = gc_timer.tick() => {
                match gc_learned_ports(&mut bpf, ttl_ns) {
                    Ok(n) if n > 0 => info!("GC removed {n} expired learned port(s)"),
                    Ok(_) => {}
                    Err(e) => warn!("GC failed: {e}"),
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
