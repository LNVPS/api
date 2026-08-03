//! Overflow-safe expiry arithmetic and the bound on how far ahead a
//! subscription may be renewed in one request.
//!
//! `chrono` panics rather than saturating on both ends of this calculation:
//! `TimeDelta::seconds` panics when the value exceeds `i64::MAX` milliseconds,
//! and `DateTime + TimeDelta` panics when the result leaves the representable
//! date range. A renewal request carries a caller-supplied interval count, so
//! both were reachable from the public API — and with `panic = "abort"` on the
//! release profile a single request took the whole process down.

use chrono::{DateTime, TimeDelta, Utc};

/// Largest number of billing intervals a single renewal request may cover.
///
/// A renewal is additionally bounded by the per-company `max_prepay_days`
/// horizon, but that check runs *after* pricing has already computed a
/// projected expiry, so it cannot be the only guard. 120 comfortably covers the
/// longest legitimate prepay (10 years of monthly intervals) while keeping
/// every intermediate calculation far inside `i64` seconds.
pub const MAX_RENEWAL_INTERVALS: u32 = 120;

/// Clamp a caller-supplied interval count into `1..=MAX_RENEWAL_INTERVALS`.
///
/// Returns `None` when the request is out of range so the API layer can reject
/// it with a 400 rather than silently charging for a different period than the
/// caller asked for.
pub fn validate_intervals(intervals: u32) -> Option<u32> {
    (1..=MAX_RENEWAL_INTERVALS)
        .contains(&intervals)
        .then_some(intervals)
}

/// Add `seconds` to `base`, saturating at the representable date range instead
/// of panicking.
///
/// Used for every projected-expiry calculation. Saturating is the right
/// behaviour here: an absurd expiry is caught by the `max_prepay_days` horizon
/// check downstream, whereas a panic is an availability incident.
pub fn saturating_add_seconds(base: DateTime<Utc>, seconds: u64) -> DateTime<Utc> {
    // `TimeDelta::try_seconds` returns None beyond ~9.2e15 seconds; clamp there
    // first so the delta itself is always constructible.
    let delta = i64::try_from(seconds)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .unwrap_or(TimeDelta::MAX);

    base.checked_add_signed(delta)
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (F-02): `intervals` arrived from the query string as an
    /// unbounded `u32`. Anything past the cap must be rejected, not clamped
    /// silently, so the caller is never charged for a different period.
    #[test]
    fn validate_intervals_bounds_the_request() {
        assert_eq!(validate_intervals(1), Some(1));
        assert_eq!(validate_intervals(12), Some(12));
        assert_eq!(
            validate_intervals(MAX_RENEWAL_INTERVALS),
            Some(MAX_RENEWAL_INTERVALS)
        );

        // Zero is not a renewal.
        assert_eq!(validate_intervals(0), None);
        // The values that used to reach the panicking arithmetic.
        assert_eq!(validate_intervals(MAX_RENEWAL_INTERVALS + 1), None);
        assert_eq!(validate_intervals(1_000_000_000), None);
        assert_eq!(validate_intervals(u32::MAX), None);
    }

    /// Regression (F-02): `base.add(TimeDelta::seconds(n))` panicked with
    /// "`DateTime + TimeDelta` overflowed" for large `n`, and
    /// "TimeDelta::seconds out of bounds" for very large `n`. Both must now
    /// saturate.
    #[test]
    fn saturating_add_seconds_never_panics() {
        let base = DateTime::<Utc>::from_timestamp(0, 0).unwrap();

        // Ordinary case is exact.
        assert_eq!(
            saturating_add_seconds(base, 86_400),
            base + TimeDelta::seconds(86_400)
        );

        // 1e9 monthly intervals: used to panic on the DateTime add.
        let overflow_datetime = 2_592_000u64 * 1_000_000_000;
        assert_eq!(
            saturating_add_seconds(base, overflow_datetime),
            DateTime::<Utc>::MAX_UTC
        );

        // u32::MAX monthly intervals: used to panic constructing the TimeDelta.
        let overflow_delta = 2_592_000u64 * u32::MAX as u64;
        assert_eq!(
            saturating_add_seconds(base, overflow_delta),
            DateTime::<Utc>::MAX_UTC
        );

        // Absolute worst case.
        assert_eq!(
            saturating_add_seconds(base, u64::MAX),
            DateTime::<Utc>::MAX_UTC
        );
    }

    /// Saturation is stable: adding to an already-saturated value stays there.
    #[test]
    fn saturating_add_seconds_is_idempotent_at_the_ceiling() {
        let max = DateTime::<Utc>::MAX_UTC;
        assert_eq!(saturating_add_seconds(max, 1), DateTime::<Utc>::MAX_UTC);
        assert_eq!(
            saturating_add_seconds(max, u64::MAX),
            DateTime::<Utc>::MAX_UTC
        );
    }
}
