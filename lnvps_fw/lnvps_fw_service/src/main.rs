use anyhow::{Context, Result, bail};
use aya::maps::PerCpuHashMap;
use aya::programs::{Xdp, XdpMode};
use aya::util::KernelVersion;
use aya::{Ebpf, include_bytes_aligned};
use log::{info, warn};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use lnvps_fw_common::DestCounters;

/// Sum per-CPU counter slots into one total.
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let interfaces: Vec<String> = std::env::args().skip(1).collect();
    if interfaces.is_empty() {
        bail!("usage: lnvps_fw_service <interface> [interface...]");
    }

    let kernel = KernelVersion::current()?;
    info!("Running on kernel {}", kernel);

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lnvps_ebpf"
    )))?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_lnvps")
        .context("xdp_lnvps program not found")?
        .try_into()?;
    program.load()?;
    for iface in &interfaces {
        match program.attach(iface, XdpMode::default()) {
            Ok(_) => info!("Attached to {} (default mode)", iface),
            Err(e) => {
                warn!(
                    "Default XDP attach failed on {} ({}), falling back to SKB mode",
                    iface, e
                );
                program
                    .attach(iface, XdpMode::Skb)
                    .with_context(|| format!("failed to attach to {}", iface))?;
                info!("Attached to {} (skb mode)", iface);
            }
        }
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if let Err(e) = log_stats(&bpf) {
                    warn!("Failed to read stats: {}", e);
                }
            }
        }
    }
    info!("Shutdown complete.");
    Ok(())
}
