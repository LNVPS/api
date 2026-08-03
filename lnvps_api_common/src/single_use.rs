//! A bounded, time-windowed "have I seen this before?" set.
//!
//! Used to make one-shot credentials actually one-shot: NIP-98 auth events and
//! WebAuthn challenge tokens are both stateless (nothing server-side records
//! that they were used), so without this a captured credential can be replayed
//! for as long as its validity window lasts.
//!
//! Per-process, like the rate limiter: not exact across replicas, but every
//! replica enforces it independently, which removes the trivial "capture and
//! resubmit" path. Entries are dropped once they age past the window, because a
//! credential that old fails its own expiry check anyway.

use anyhow::{Result, bail};
use log::warn;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks recently-used credential identifiers.
pub struct SingleUseGuard<K> {
    seen: Mutex<HashMap<K, Instant>>,
    /// How long an entry is remembered.
    window: Duration,
    /// Hard cap on tracked entries, so a flood cannot grow the map unbounded.
    capacity: usize,
    /// Name used in log messages.
    label: &'static str,
}

impl<K: Eq + Hash> SingleUseGuard<K> {
    /// Create a guard remembering entries for `window`, holding at most
    /// `capacity` of them.
    pub fn new(label: &'static str, window: Duration, capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            window,
            capacity,
            label,
        }
    }

    /// Record `key` as used. Fails if it was already used inside the window.
    ///
    /// Callers must only reach this **after** every other validity check has
    /// passed, so an invalid credential cannot burn a legitimate one's id.
    pub fn consume(&self, key: K) -> Result<()> {
        let now = Instant::now();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        seen.retain(|_, used_at| now.duration_since(*used_at) < self.window);

        // If ageing out was not enough we are under an active flood. Clearing
        // is far better than unbounded growth: the worst case is that a
        // credential becomes replayable for the rest of its (short) window,
        // which is exactly the pre-existing behaviour.
        if seen.len() >= self.capacity {
            warn!(
                "{} single-use cache is full ({} entries), clearing",
                self.label, self.capacity
            );
            seen.clear();
        }

        if seen.insert(key, now).is_some() {
            bail!("Credential has already been used");
        }
        Ok(())
    }

    /// Number of tracked entries. Test/diagnostic helper.
    pub fn len(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether nothing is currently tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_succeeds_and_replay_fails() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 1000);

        assert!(guard.consume(1).is_ok());
        assert!(
            guard.consume(1).is_err(),
            "the same credential must not be usable twice"
        );
        // A different credential is unaffected.
        assert!(guard.consume(2).is_ok());
    }

    #[test]
    fn entries_age_out_of_the_window() {
        let guard: SingleUseGuard<u32> =
            SingleUseGuard::new("test", Duration::from_millis(20), 1000);

        assert!(guard.consume(1).is_ok());
        assert!(guard.consume(1).is_err());

        std::thread::sleep(Duration::from_millis(25));

        // Past the window the entry is forgotten. That is safe: a credential
        // this old fails its own expiry check before ever reaching here.
        assert!(guard.consume(1).is_ok());
    }

    #[test]
    fn capacity_is_enforced() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 8);

        for i in 0..32 {
            let _ = guard.consume(i);
        }

        assert!(
            guard.len() <= 8,
            "cache grew past its capacity: {}",
            guard.len()
        );
    }

    #[test]
    fn reports_emptiness() {
        let guard: SingleUseGuard<u32> = SingleUseGuard::new("test", Duration::from_secs(60), 1000);
        assert!(guard.is_empty());
        assert!(guard.consume(1).is_ok());
        assert!(!guard.is_empty());
    }
}
