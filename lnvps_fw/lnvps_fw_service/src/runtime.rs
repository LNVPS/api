//! BPF-facing detection driver: samples the per-destination counters, runs the
//! pure [`crate::detect`] state machine for each destination, and applies mode
//! transitions to the `*_DEST_STATE` maps (insert on enter, remove on exit),
//! emitting structured mitigation events.
//!
//! The timestamp is injected (`now_ns`) so the datapath test harness can drive
//! deterministic sample windows; production passes the monotonic clock.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuHashMap};
use aya::{Ebpf, Pod};
use log::{info, warn};

use lnvps_fw_common::{DEST_MODE_MITIGATE, DestCounters, DestState};

use crate::detect::{DestTracker, DetectionConfig, Rates, Transition, process_sample};

/// Per-address-family detection state kept across sample windows.
#[derive(Default)]
pub struct DetectionState {
    pub v4: HashMap<[u8; 4], DestTracker>,
    pub v6: HashMap<[u8; 16], DestTracker>,
    /// Injected timestamp of the previous sample (0 = first run).
    pub last_sample_ns: u64,
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
        "MITIGATION START dest={ip} pps={} syn_pps={} bps={}",
        rates.pps, rates.syn_pps, rates.bps
    );
}

fn log_event_stop(ip: &str, peak: &Rates, dropped_total: u64) {
    info!(
        "MITIGATION STOP dest={ip} peak_pps={} peak_syn_pps={} peak_bps={} dropped_total={dropped_total}",
        peak.pps, peak.syn_pps, peak.bps
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

/// One detection tick across both address families at the injected `now_ns`.
/// The first tick (when `last_sample_ns == 0`) seeds the previous snapshots
/// with a zero elapsed window so it never computes spurious rates.
pub fn run_detection(
    bpf: &mut Ebpf,
    state: &mut DetectionState,
    cfg: &DetectionConfig,
    now_ns: u64,
) -> Result<()> {
    let elapsed = if state.last_sample_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(state.last_sample_ns)
    };
    state.last_sample_ns = now_ns;

    let v4 = read_counters::<[u8; 4]>(bpf, "V4_DEST_COUNTERS")?;
    {
        let mut sm: AyaHashMap<_, [u8; 4], DestState> =
            AyaHashMap::try_from(bpf.map_mut("V4_DEST_STATE").context("v4 state missing")?)?;
        detect_family(v4, &mut sm, &mut state.v4, cfg, now_ns, elapsed, |k| {
            Ipv4Addr::from(*k).to_string()
        });
    }

    let v6 = read_counters::<[u8; 16]>(bpf, "V6_DEST_COUNTERS")?;
    {
        let mut sm: AyaHashMap<_, [u8; 16], DestState> =
            AyaHashMap::try_from(bpf.map_mut("V6_DEST_STATE").context("v6 state missing")?)?;
        detect_family(v6, &mut sm, &mut state.v6, cfg, now_ns, elapsed, |k| {
            Ipv6Addr::from(*k).to_string()
        });
    }
    Ok(())
}
