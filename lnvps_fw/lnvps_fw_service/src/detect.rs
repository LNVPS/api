//! Attack-detection state machine (pure userspace logic).
//!
//! The daemon samples the per-destination counters at a fixed interval,
//! converts the deltas into rates, and feeds them through [`evaluate`] to drive
//! a per-destination [`DEST_MODE_NORMAL`] ↔ [`DEST_MODE_PORT_FILTER`] state
//! machine with entry thresholds, exit hysteresis, and a cooldown. Keeping this
//! logic free of I/O and BPF handles makes it fully unit-testable.

use lnvps_fw_common::{DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DestCounters};

/// Traffic rates for a single destination over the last sample window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rates {
    /// Packets per second (all verdicts).
    pub pps: u64,
    /// TCP SYNs per second.
    pub syn_pps: u64,
    /// Bytes per second.
    pub bps: u64,
    /// Packets per second dropped by any protection stage.
    pub drop_pps: u64,
    /// Packets per second passed (accepted) = pps - drop_pps.
    pub pass_pps: u64,
}

/// Detection parameters (entry thresholds + hysteresis).
#[derive(Debug, Clone, Copy)]
pub struct DetectionConfig {
    /// Enter mitigation at or above this packets/second.
    pub pps: u64,
    /// Enter mitigation at or above this SYNs/second.
    pub syn_pps: u64,
    /// Enter mitigation at or above this bytes/second.
    pub bps: u64,
    /// Exit hysteresis: leave mitigation only once every rate falls below this
    /// percentage of its entry threshold (e.g. 50 = below half).
    pub exit_pct: u64,
    /// Sustained time below the exit thresholds before returning to normal.
    pub cooldown_ns: u64,
}

/// Result of one evaluation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// No mode change.
    None,
    /// Destination entered mitigation this step.
    Entered,
    /// Destination left mitigation this step.
    Exited,
}

/// Per-destination userspace bookkeeping across sample windows.
#[derive(Debug, Clone, Copy)]
pub struct DestTracker {
    /// Previous counter snapshot (summed across CPUs).
    pub prev: DestCounters,
    /// Whether mitigation is active: `DEST_MODE_NORMAL` or
    /// `DEST_MODE_PORT_FILTER` (base active level). The *enforced* level may be
    /// escalated further and is tracked separately in `level`.
    pub mode: u32,
    /// Protection-flag bitmask currently written to the dest-state trie
    /// (`DEST_MODE_*` flags OR'd together).
    pub flags: u32,
    /// Monotonic timestamp when rates first dropped below the exit thresholds
    /// (used to enforce the cooldown); `None` while above them.
    pub below_since_ns: Option<u64>,
    /// Peak rates observed during the current mitigation episode (for events).
    pub peak: Rates,
    /// Most recent per-window rates (for the live per-IP dashboard).
    pub last: Rates,
    /// Injected timestamp when `last` was computed (0 = never sampled).
    pub last_ns: u64,
}

impl Default for DestTracker {
    fn default() -> Self {
        Self {
            prev: DestCounters::default(),
            mode: DEST_MODE_NORMAL,
            flags: DEST_MODE_NORMAL,
            below_since_ns: None,
            peak: Rates::default(),
            last: Rates::default(),
            last_ns: 0,
        }
    }
}

/// Compute per-second rates from two counter snapshots and the elapsed time.
/// A counter that appears to have decreased (LRU eviction / reset) contributes
/// a zero delta rather than a huge spike.
pub fn compute_rates(prev: &DestCounters, cur: &DestCounters, elapsed_ns: u64) -> Rates {
    if elapsed_ns == 0 {
        return Rates::default();
    }
    let per_sec =
        |delta: u64| -> u64 { ((delta as u128 * 1_000_000_000u128) / elapsed_ns as u128) as u64 };
    let d = |cur: u64, prev: u64| cur.saturating_sub(prev);
    // Accepted packets per snapshot = packets - dropped; take the delta of that.
    let cur_pass = cur.packets.saturating_sub(cur.dropped);
    let prev_pass = prev.packets.saturating_sub(prev.dropped);
    Rates {
        pps: per_sec(d(cur.packets, prev.packets)),
        syn_pps: per_sec(d(cur.syn_packets, prev.syn_packets)),
        bps: per_sec(d(cur.bytes, prev.bytes)),
        drop_pps: per_sec(d(cur.dropped, prev.dropped)),
        pass_pps: per_sec(d(cur_pass, prev_pass)),
    }
}

/// True if any rate is at or above its entry threshold.
fn exceeds_entry(rates: &Rates, cfg: &DetectionConfig) -> bool {
    rates.pps >= cfg.pps || rates.syn_pps >= cfg.syn_pps || rates.bps >= cfg.bps
}

/// True if every rate is below its exit threshold (entry × exit_pct%).
fn below_exit(rates: &Rates, cfg: &DetectionConfig) -> bool {
    let exit = |threshold: u64| threshold.saturating_mul(cfg.exit_pct) / 100;
    rates.pps < exit(cfg.pps) && rates.syn_pps < exit(cfg.syn_pps) && rates.bps < exit(cfg.bps)
}

/// Advance the state machine for one destination given the freshly-computed
/// `rates`. Mutates `below_since_ns` to track cooldown progress and returns the
/// new mode plus whether a transition occurred.
pub fn evaluate(
    mode: u32,
    rates: &Rates,
    cfg: &DetectionConfig,
    now_ns: u64,
    below_since_ns: &mut Option<u64>,
) -> (u32, Transition) {
    if mode == DEST_MODE_NORMAL {
        if exceeds_entry(rates, cfg) {
            *below_since_ns = None;
            return (DEST_MODE_PORT_FILTER, Transition::Entered);
        }
        return (DEST_MODE_NORMAL, Transition::None);
    }

    // Currently mitigating.
    if below_exit(rates, cfg) {
        let since = below_since_ns.get_or_insert(now_ns);
        if now_ns.saturating_sub(*since) >= cfg.cooldown_ns {
            *below_since_ns = None;
            return (DEST_MODE_NORMAL, Transition::Exited);
        }
    } else {
        // Rates climbed back up; restart the cooldown clock.
        *below_since_ns = None;
    }
    (DEST_MODE_PORT_FILTER, Transition::None)
}

/// Element-wise maximum of two rate samples.
fn max_rates(a: Rates, b: Rates) -> Rates {
    Rates {
        pps: a.pps.max(b.pps),
        syn_pps: a.syn_pps.max(b.syn_pps),
        bps: a.bps.max(b.bps),
        drop_pps: a.drop_pps.max(b.drop_pps),
        pass_pps: a.pass_pps.max(b.pass_pps),
    }
}

/// Process one destination's fresh counter snapshot: compute rates, advance the
/// state machine, and update the tracker (mode, previous snapshot, cooldown,
/// peak rates). Returns the transition and the rates for this window so the
/// caller can update the BPF state map and emit events. Pure aside from the
/// `tracker` mutation, so it is unit-testable without any BPF handles.
pub fn process_sample(
    cur: DestCounters,
    tracker: &mut DestTracker,
    cfg: &DetectionConfig,
    now_ns: u64,
    elapsed_ns: u64,
) -> (Transition, Rates) {
    let rates = compute_rates(&tracker.prev, &cur, elapsed_ns);
    let (mode, transition) = evaluate(
        tracker.mode,
        &rates,
        cfg,
        now_ns,
        &mut tracker.below_since_ns,
    );

    match transition {
        Transition::Entered => tracker.peak = rates,
        _ if mode == DEST_MODE_PORT_FILTER => tracker.peak = max_rates(tracker.peak, rates),
        _ => {}
    }

    tracker.mode = mode;
    tracker.prev = cur;
    tracker.last = rates;
    tracker.last_ns = now_ns;
    (transition, rates)
}

// --- Per-source rate state machine ---------------------------------------
//
// A blocked source is not a sticky list entry: it has its own NORMAL <->
// DROPPING state driven by its *current* packet rate, with the same entry
// threshold / exit hysteresis / cooldown shape as a destination. A source is
// only in DROPPING (and thus in the CIDR block trie) while it is actually over
// the rate limit; once it falls back below the exit threshold for the cooldown
// it returns to NORMAL and is unblocked — so legitimate low-rate traffic from
// an address that had one burst is not dropped for the whole TTL.

/// Detection parameters for the per-source state machine.
#[derive(Debug, Clone, Copy)]
pub struct SourceDetectionConfig {
    /// Enter DROPPING at or above this packets/second.
    pub rate_pps: u64,
    /// Exit hysteresis: leave DROPPING only once the rate falls below this
    /// percentage of `rate_pps`.
    pub exit_pct: u64,
    /// Sustained time below the exit threshold before returning to NORMAL.
    pub cooldown_ns: u64,
}

/// Per-source userspace bookkeeping across sample windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct SourceTracker {
    /// False until the first observation has seeded `prev`. The eBPF source
    /// counter is monotonic-cumulative and is not reset between mitigation
    /// episodes, so a fresh tracker's first sample must establish the baseline
    /// rather than treat the entire historical count as one window's traffic
    /// (which would spike a benign source straight into DROPPING).
    pub seeded: bool,
    /// Previous cumulative packet count (for the rate delta).
    pub prev: u64,
    /// True while this source is being dropped (in the CIDR block trie).
    pub dropping: bool,
    /// Monotonic timestamp when the rate first fell below the exit threshold
    /// (cooldown progress); `None` while above it.
    pub below_since_ns: Option<u64>,
    /// Most recent per-window rate (for display + block pps).
    pub last_pps: u64,
    /// Injected timestamp when `last_pps` was computed.
    pub last_ns: u64,
}

/// Advance one source's state machine from its fresh cumulative packet count.
/// Returns `(is_dropping, pps)` for this window. A counter that appears to have
/// decreased (LRU eviction / reset) yields a zero-rate window (never a spike).
pub fn advance_source(
    tracker: &mut SourceTracker,
    cur_count: u64,
    cfg: &SourceDetectionConfig,
    now_ns: u64,
    elapsed_ns: u64,
) -> (bool, u64) {
    // First observation: seed the baseline and report a zero-rate window. A
    // single cumulative snapshot carries no rate information, and the counter
    // may already hold a large historical total (see `seeded`).
    if !tracker.seeded {
        tracker.seeded = true;
        tracker.prev = cur_count;
        tracker.last_pps = 0;
        tracker.last_ns = now_ns;
        return (false, 0);
    }
    let pps = if elapsed_ns == 0 {
        0
    } else {
        let delta = cur_count.saturating_sub(tracker.prev);
        ((delta as u128 * 1_000_000_000u128) / elapsed_ns as u128) as u64
    };
    tracker.prev = cur_count;
    tracker.last_pps = pps;
    tracker.last_ns = now_ns;

    let exit = cfg.rate_pps.saturating_mul(cfg.exit_pct) / 100;
    if !tracker.dropping {
        if pps >= cfg.rate_pps {
            tracker.dropping = true;
            tracker.below_since_ns = None;
        }
    } else if pps < exit {
        let since = *tracker.below_since_ns.get_or_insert(now_ns);
        if now_ns.saturating_sub(since) >= cfg.cooldown_ns {
            tracker.dropping = false;
            tracker.below_since_ns = None;
        }
    } else {
        // Rate climbed back up; restart the cooldown clock.
        tracker.below_since_ns = None;
    }
    (tracker.dropping, pps)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    const CFG: DetectionConfig = DetectionConfig {
        pps: 1_000,
        syn_pps: 500,
        bps: 1_000_000,
        exit_pct: 50,
        cooldown_ns: 2_000_000_000, // 2s
    };

    fn counters(packets: u64, syn: u64, bytes: u64) -> DestCounters {
        DestCounters {
            packets,
            bytes,
            syn_packets: syn,
            ..Default::default()
        }
    }

    #[test]
    fn drop_and_pass_rates_computed() {
        let prev = DestCounters::default();
        let cur = DestCounters {
            packets: 1_000,
            dropped: 300,
            ..Default::default()
        };
        let r = compute_rates(&prev, &cur, 1_000_000_000);
        assert_eq!(r.pps, 1_000);
        assert_eq!(r.drop_pps, 300);
        assert_eq!(r.pass_pps, 700);
    }

    #[test]
    fn rates_computed_over_one_second() {
        let prev = counters(0, 0, 0);
        let cur = counters(2_000, 300, 500_000);
        let r = compute_rates(&prev, &cur, 1_000_000_000);
        assert_eq!(r.pps, 2_000);
        assert_eq!(r.syn_pps, 300);
        assert_eq!(r.bps, 500_000);
    }

    #[test]
    fn rates_zero_on_counter_reset() {
        let prev = counters(5_000, 0, 0);
        let cur = counters(10, 0, 0);
        let r = compute_rates(&prev, &cur, 1_000_000_000);
        assert_eq!(r.pps, 0);
    }

    #[test]
    fn rates_zero_elapsed_is_safe() {
        let r = compute_rates(&counters(1, 1, 1), &counters(9, 9, 9), 0);
        assert_eq!(r, Rates::default());
    }

    #[test]
    fn enters_mitigation_on_pps() {
        let mut below = None;
        let r = Rates {
            pps: 1_000,
            syn_pps: 0,
            bps: 0,
            ..Default::default()
        };
        let (mode, t) = evaluate(DEST_MODE_NORMAL, &r, &CFG, 0, &mut below);
        assert_eq!(mode, DEST_MODE_PORT_FILTER);
        assert_eq!(t, Transition::Entered);
    }

    #[test]
    fn enters_mitigation_on_syn_only() {
        let mut below = None;
        let r = Rates {
            pps: 1,
            syn_pps: 500,
            bps: 1,
            ..Default::default()
        };
        let (mode, t) = evaluate(DEST_MODE_NORMAL, &r, &CFG, 0, &mut below);
        assert_eq!(mode, DEST_MODE_PORT_FILTER);
        assert_eq!(t, Transition::Entered);
    }

    #[test]
    fn stays_normal_below_threshold() {
        let mut below = None;
        let r = Rates {
            pps: 999,
            syn_pps: 499,
            bps: 999_999,
            ..Default::default()
        };
        let (mode, t) = evaluate(DEST_MODE_NORMAL, &r, &CFG, 0, &mut below);
        assert_eq!(mode, DEST_MODE_NORMAL);
        assert_eq!(t, Transition::None);
    }

    #[test]
    fn cooldown_required_before_exit() {
        // Below exit thresholds (half = 500pps/250syn/500k).
        let low = Rates {
            pps: 100,
            syn_pps: 10,
            bps: 10_000,
            ..Default::default()
        };
        let mut below = None;

        // First low sample starts the cooldown clock; still mitigating.
        let (mode, t) = evaluate(DEST_MODE_PORT_FILTER, &low, &CFG, 1_000, &mut below);
        assert_eq!(mode, DEST_MODE_PORT_FILTER);
        assert_eq!(t, Transition::None);
        assert_eq!(below, Some(1_000));

        // Before cooldown elapses: still mitigating.
        let (mode, _) = evaluate(
            DEST_MODE_PORT_FILTER,
            &low,
            &CFG,
            1_000 + 1_000_000_000,
            &mut below,
        );
        assert_eq!(mode, DEST_MODE_PORT_FILTER);

        // After cooldown: exit.
        let (mode, t) = evaluate(
            DEST_MODE_PORT_FILTER,
            &low,
            &CFG,
            1_000 + 2_000_000_000,
            &mut below,
        );
        assert_eq!(mode, DEST_MODE_NORMAL);
        assert_eq!(t, Transition::Exited);
        assert_eq!(below, None);
    }

    #[test]
    fn traffic_resurgence_resets_cooldown() {
        let low = Rates {
            pps: 100,
            syn_pps: 10,
            bps: 10_000,
            ..Default::default()
        };
        let high = Rates {
            pps: 2_000,
            syn_pps: 0,
            bps: 0,
            ..Default::default()
        };
        let mut below = None;

        evaluate(DEST_MODE_PORT_FILTER, &low, &CFG, 0, &mut below);
        assert_eq!(below, Some(0));
        // A high sample clears the cooldown clock.
        let (mode, _) = evaluate(DEST_MODE_PORT_FILTER, &high, &CFG, 500, &mut below);
        assert_eq!(mode, DEST_MODE_PORT_FILTER);
        assert_eq!(below, None);
    }

    #[test]
    fn process_sample_enters_and_tracks_peak() {
        let mut tr = DestTracker::default();
        // First window: 2000 pps -> enter mitigation, peak seeded.
        let (t, r) = process_sample(counters(2_000, 0, 0), &mut tr, &CFG, 0, 1_000_000_000);
        assert_eq!(t, Transition::Entered);
        assert_eq!(r.pps, 2_000);
        assert_eq!(tr.mode, DEST_MODE_PORT_FILTER);
        assert_eq!(tr.peak.pps, 2_000);

        // Second window: +3000 packets -> 3000 pps, peak rises.
        let (t, _) = process_sample(
            counters(5_000, 0, 0),
            &mut tr,
            &CFG,
            1_000_000_000,
            1_000_000_000,
        );
        assert_eq!(t, Transition::None);
        assert_eq!(tr.peak.pps, 3_000);
    }

    #[test]
    fn process_sample_exits_after_cooldown() {
        let mut tr = DestTracker {
            mode: DEST_MODE_PORT_FILTER,
            prev: counters(0, 0, 0),
            ..Default::default()
        };
        // Low traffic (100 pps) starts cooldown.
        let (t, _) = process_sample(counters(100, 0, 0), &mut tr, &CFG, 0, 1_000_000_000);
        assert_eq!(t, Transition::None);
        // After cooldown elapses, low traffic again -> exit.
        let (t, _) = process_sample(
            counters(200, 0, 0),
            &mut tr,
            &CFG,
            3_000_000_000,
            1_000_000_000,
        );
        assert_eq!(t, Transition::Exited);
        assert_eq!(tr.mode, DEST_MODE_NORMAL);
    }

    #[test]
    fn between_exit_and_entry_holds_mitigation() {
        // Rate in the hysteresis band (below entry, above exit): stay put, no
        // cooldown progress.
        let mid = Rates {
            pps: 700,
            syn_pps: 0,
            bps: 0,
            ..Default::default()
        };
        let mut below = None;
        let (mode, t) = evaluate(DEST_MODE_PORT_FILTER, &mid, &CFG, 0, &mut below);
        assert_eq!(mode, DEST_MODE_PORT_FILTER);
        assert_eq!(t, Transition::None);
        assert_eq!(below, None);
    }

    const SCFG: SourceDetectionConfig = SourceDetectionConfig {
        rate_pps: 500,
        exit_pct: 50, // exit below 250pps
        cooldown_ns: 2_000_000_000,
    };

    /// Seed a fresh tracker's baseline at `base` cumulative packets (the first
    /// observation always reports zero rate), so the following windows exercise
    /// real deltas.
    fn seeded_at(base: u64) -> SourceTracker {
        let mut t = SourceTracker::default();
        let (dropping, pps) = advance_source(&mut t, base, &SCFG, 0, SEC);
        assert!(!dropping);
        assert_eq!(pps, 0, "first observation seeds, never spikes");
        t
    }

    #[test]
    fn source_enters_dropping_over_rate() {
        let mut t = seeded_at(0);
        // 600 pkts in the next 1s => 600pps >= 500 => DROPPING.
        let (dropping, pps) = advance_source(&mut t, 600, &SCFG, SEC, SEC);
        assert!(dropping);
        assert_eq!(pps, 600);
    }

    #[test]
    fn source_stays_normal_below_rate() {
        let mut t = seeded_at(0);
        let (dropping, pps) = advance_source(&mut t, 100, &SCFG, SEC, SEC);
        assert!(!dropping);
        assert_eq!(pps, 100);
    }

    #[test]
    fn source_releases_after_cooldown_below_exit() {
        let mut t = seeded_at(0);
        // Enter DROPPING at 600pps.
        advance_source(&mut t, 600, &SCFG, SEC, SEC);
        assert!(t.dropping);
        // Next window: no new packets (delta 0 => 0pps < 250 exit). Records
        // "below since", still dropping (cooldown not elapsed).
        let (d1, _) = advance_source(&mut t, 600, &SCFG, 2 * SEC, SEC);
        assert!(d1, "still dropping during cooldown");
        // A full cooldown later: returns to NORMAL.
        let (d2, _) = advance_source(&mut t, 600, &SCFG, 4 * SEC, SEC);
        assert!(!d2, "released once below exit for the cooldown");
    }

    #[test]
    fn source_resurgence_resets_cooldown() {
        let mut t = seeded_at(0);
        advance_source(&mut t, 600, &SCFG, SEC, SEC);
        // Drop below exit (records below_since).
        advance_source(&mut t, 600, &SCFG, 2 * SEC, SEC);
        assert!(t.below_since_ns.is_some());
        // Rate climbs back over the entry threshold: cooldown clock clears.
        let (d, _) = advance_source(&mut t, 1200, &SCFG, 3 * SEC, SEC);
        assert!(d);
        assert_eq!(t.below_since_ns, None);
    }

    #[test]
    fn source_counter_reset_is_zero_rate() {
        let mut t = seeded_at(0);
        advance_source(&mut t, 1000, &SCFG, SEC, SEC);
        // Counter appears to decrease (LRU eviction/reset): zero rate, not a spike.
        let (_, pps) = advance_source(&mut t, 10, &SCFG, 2 * SEC, SEC);
        assert_eq!(pps, 0);
    }

    // Regression: the eBPF `V*_SRC_COUNTERS` map is monotonic-cumulative and is
    // NOT reset between mitigation episodes (LRU eviction is the only way an
    // entry disappears). A source's userspace `SourceTracker`, however, is
    // recreated fresh (`prev = 0`) each time it is first observed in a sample.
    //
    // So when mitigation (re)activates over a source whose counter already holds
    // a large accumulated total from earlier counting, the very first window
    // computes `delta = cur_count - 0 = cur_count` — the entire historical count
    // attributed to a single window. A slow, benign source is then reported at a
    // huge bogus pps and shoved straight into DROPPING even though its real rate
    // is far below the limit. This is exactly the "manual activation puts IPs
    // straight into dropping" symptom.
    //
    // Desired behaviour: the first observation must SEED the baseline, not emit a
    // rate. This test asserts that and currently FAILS, demonstrating the bug.
    #[test]
    fn source_first_observation_of_large_counter_is_not_a_spike() {
        let mut t = SourceTracker::default();
        // Counter already sits at 100_000 packets accumulated before this tracker
        // ever existed (prior mitigation episode / pre-first-sample counting).
        // The source is actually slow: it will add only ~5 pkts/s from here.
        let (dropping, pps) = advance_source(&mut t, 100_000, &SCFG, 0, SEC);
        assert!(
            !dropping,
            "benign source wrongly entered DROPPING on its first observation \
             (reported {pps} pps from a cumulative counter, limit {} pps)",
            SCFG.rate_pps
        );

        // And its true rate (5 pkts over the next second) stays well under limit.
        let (dropping2, pps2) = advance_source(&mut t, 100_005, &SCFG, 2 * SEC, SEC);
        assert!(!dropping2, "slow source must stay NORMAL");
        assert_eq!(pps2, 5);
    }
}
