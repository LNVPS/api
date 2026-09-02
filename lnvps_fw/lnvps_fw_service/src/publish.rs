//! Pure diffing between control-loop ticks and the API-visible state: turns the
//! set of currently-active auto-detected mitigations into (a) the active
//! snapshot and (b) the start/flags/stop events to record. Kept free of BPF /
//! `DetectionState` types so it is unit-testable; `main.rs` scrapes the current
//! set from `DetectionState` and feeds it in.

use std::collections::HashMap;

use crate::api::{EventKind, Mitigation};

/// One currently-active auto-detected mitigation for this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitInput {
    pub cidr: String,
    pub flags: u32,
    pub pps: u64,
    pub bps: u64,
    pub syn_pps: u64,
}

/// An event the loop should record into the shared ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    pub kind: EventKind,
    pub cidr: String,
    pub flags: u32,
    pub pps: u64,
    pub bps: u64,
    pub syn_pps: u64,
}

/// Tracks the previous active set across ticks so transitions become events.
#[derive(Default)]
pub struct MitTracker {
    prev_flags: HashMap<String, u32>,
    since: HashMap<String, u64>,
    /// Last-seen peak rates per active cidr, so a Stop event can report the
    /// peak of the episode instead of zeros.
    peak: HashMap<String, (u64, u64, u64)>,
}

impl MitTracker {
    /// Diff `cur` against the previous tick. Returns the active snapshot
    /// (auto-detected, `manual = false`) and the events to record (Start for
    /// newly-active, Flags when the flag set changes, Stop for gone).
    pub fn step(
        &mut self,
        cur: Vec<MitInput>,
        now_unix: u64,
    ) -> (Vec<Mitigation>, Vec<PendingEvent>) {
        let mut events = Vec::new();
        let mut active = Vec::with_capacity(cur.len());
        let mut cur_flags = HashMap::with_capacity(cur.len());

        for m in &cur {
            cur_flags.insert(m.cidr.clone(), m.flags);
            // Remember the latest (peak) rates so the eventual Stop can report them.
            self.peak.insert(m.cidr.clone(), (m.pps, m.bps, m.syn_pps));
            match self.prev_flags.get(&m.cidr) {
                None => {
                    self.since.insert(m.cidr.clone(), now_unix);
                    events.push(PendingEvent {
                        kind: EventKind::Start,
                        cidr: m.cidr.clone(),
                        flags: m.flags,
                        pps: m.pps,
                        bps: m.bps,
                        syn_pps: m.syn_pps,
                    });
                }
                Some(&pf) if pf != m.flags => events.push(PendingEvent {
                    kind: EventKind::Flags,
                    cidr: m.cidr.clone(),
                    flags: m.flags,
                    pps: m.pps,
                    bps: m.bps,
                    syn_pps: m.syn_pps,
                }),
                _ => {}
            }
            let since = *self.since.get(&m.cidr).unwrap_or(&now_unix);
            active.push(Mitigation {
                cidr: m.cidr.clone(),
                flags: m.flags,
                since_unix: since,
                manual: false,
                peak_pps: m.pps,
                peak_bps: m.bps,
                peak_syn_pps: m.syn_pps,
                // Live rates are filled in by the control loop (which has the
                // per-window tracker data), keyed by cidr.
                ..Default::default()
            });
        }

        // Anything that was active last tick but isn't now -> Stop.
        for (cidr, &flags) in &self.prev_flags {
            if !cur_flags.contains_key(cidr) {
                // Report the episode's peak rates on Stop (not zeros).
                let (pps, bps, syn_pps) = self.peak.remove(cidr).unwrap_or((0, 0, 0));
                events.push(PendingEvent {
                    kind: EventKind::Stop,
                    cidr: cidr.clone(),
                    flags,
                    pps,
                    bps,
                    syn_pps,
                });
                self.since.remove(cidr);
            }
        }

        self.prev_flags = cur_flags;
        (active, events)
    }
}

/// Rate-less event (rule changes carry no traffic sample).
fn rule_event(kind: EventKind, cidr: &str, flags: u32) -> PendingEvent {
    PendingEvent {
        kind,
        cidr: cidr.to_string(),
        flags,
        pps: 0,
        bps: 0,
        syn_pps: 0,
    }
}

/// Events for a manual-override reconcile: `ManualStart` for every override
/// that is new or whose flags changed, `ManualStop` for every one removed.
/// Both maps are keyed by the canonical CIDR string.
pub fn override_events(
    prev: &HashMap<String, u32>,
    cur: &HashMap<String, u32>,
) -> Vec<PendingEvent> {
    let mut out: Vec<PendingEvent> = cur
        .iter()
        .filter(|(c, f)| prev.get(*c) != Some(*f))
        .map(|(c, f)| rule_event(EventKind::ManualStart, c, *f))
        .collect();
    out.extend(
        prev.iter()
            .filter(|(c, _)| !cur.contains_key(*c))
            .map(|(c, f)| rule_event(EventKind::ManualStop, c, *f)),
    );
    out.sort_by(|a, b| a.cidr.cmp(&b.cidr));
    out
}

/// Events for a plain set reconcile (source blocks, SNI hostnames): `start`
/// for every entry only in `cur`, `stop` for every entry only in `prev`.
pub fn set_events<'a>(
    prev: impl IntoIterator<Item = &'a String>,
    cur: impl IntoIterator<Item = &'a String>,
    start: EventKind,
    stop: EventKind,
) -> Vec<PendingEvent> {
    let prev: std::collections::HashSet<&String> = prev.into_iter().collect();
    let cur: std::collections::HashSet<&String> = cur.into_iter().collect();
    let mut out: Vec<PendingEvent> = cur
        .difference(&prev)
        .map(|c| rule_event(start, c, 0))
        .chain(prev.difference(&cur).map(|c| rule_event(stop, c, 0)))
        .collect();
    out.sort_by(|a, b| a.cidr.cmp(&b.cidr));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inp(cidr: &str, flags: u32) -> MitInput {
        MitInput {
            cidr: cidr.into(),
            flags,
            pps: 10,
            bps: 20,
            syn_pps: 5,
        }
    }

    #[test]
    fn start_flags_and_stop_transitions() {
        let mut t = MitTracker::default();

        // Tick 1: a/32 becomes active -> Start, since=100.
        let (active, ev) = t.step(vec![inp("a/32", 1)], 100);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].since_unix, 100);
        assert!(!active[0].manual);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Start);

        // Tick 2: flags change 1 -> 3 -> Flags event; since preserved.
        let (active, ev) = t.step(vec![inp("a/32", 3)], 150);
        assert_eq!(active[0].since_unix, 100);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Flags);
        assert_eq!(ev[0].flags, 3);

        // Tick 3: unchanged -> no events.
        let (_active, ev) = t.step(vec![inp("a/32", 3)], 160);
        assert!(ev.is_empty());

        // Tick 4: gone -> Stop, carrying the episode's peak rates (not zeros).
        let (active, ev) = t.step(vec![], 170);
        assert!(active.is_empty());
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Stop);
        assert_eq!(ev[0].flags, 3);
        assert_eq!((ev[0].pps, ev[0].bps, ev[0].syn_pps), (10, 20, 5));
    }

    #[test]
    fn override_events_report_new_changed_and_removed() {
        let prev: HashMap<String, u32> = [("a/32".to_string(), 1), ("b/24".to_string(), 8)].into();
        let cur: HashMap<String, u32> = [("a/32".to_string(), 3), ("c/32".to_string(), 1)].into();
        let ev = override_events(&prev, &cur);
        let kinds: Vec<(&str, EventKind, u32)> = ev
            .iter()
            .map(|e| (e.cidr.as_str(), e.kind, e.flags))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("a/32", EventKind::ManualStart, 3),
                ("b/24", EventKind::ManualStop, 8),
                ("c/32", EventKind::ManualStart, 1),
            ]
        );
        assert!(override_events(&cur, &cur).is_empty());
    }

    #[test]
    fn set_events_diff_plain_sets() {
        let prev = vec!["x.example".to_string(), "y.example".to_string()];
        let cur = vec!["y.example".to_string(), "z.example".to_string()];
        let ev = set_events(&prev, &cur, EventKind::SniStart, EventKind::SniStop);
        let kinds: Vec<(&str, EventKind)> = ev.iter().map(|e| (e.cidr.as_str(), e.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("x.example", EventKind::SniStop),
                ("z.example", EventKind::SniStart)
            ]
        );
        assert!(set_events(&cur, &cur, EventKind::BlockStart, EventKind::BlockStop).is_empty());
    }
}
