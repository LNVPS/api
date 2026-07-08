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
            });
        }

        // Anything that was active last tick but isn't now -> Stop.
        for (cidr, &flags) in &self.prev_flags {
            if !cur_flags.contains_key(cidr) {
                events.push(PendingEvent {
                    kind: EventKind::Stop,
                    cidr: cidr.clone(),
                    flags,
                    pps: 0,
                    bps: 0,
                    syn_pps: 0,
                });
                self.since.remove(cidr);
            }
        }

        self.prev_flags = cur_flags;
        (active, events)
    }
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

        // Tick 4: gone -> Stop.
        let (active, ev) = t.step(vec![], 170);
        assert!(active.is_empty());
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::Stop);
        assert_eq!(ev[0].flags, 3);
    }
}
