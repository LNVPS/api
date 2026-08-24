//! Per-day VM traffic accounting.
//!
//! Traffic is derived from the cumulative per-VM NIC byte counters the
//! hypervisor reports, which the worker already reads on every VM sweep. Each
//! reading is differenced against the previous one and the difference is added
//! to the current UTC day's row.
//!
//! Nothing here enforces anything: a VM over its `transfer_gb` quota is still
//! served at full speed, and the quota only drives display and warnings.

use anyhow::Result;
use chrono::{Datelike, NaiveDate, Utc};
use log::warn;
use std::sync::Arc;

use lnvps_db::LNVpsDb;

use crate::status::VmRunningState;

/// Ceiling on the transfer rate a single sample may imply, in bytes per second.
///
/// A VM whose counter appears to have moved faster than this did not move that
/// much traffic: the reading came from a different counter than the baseline —
/// a live migration onto a host where the guest had run before, or a host agent
/// restart that resumed mid-counter. Such a jump is clamped rather than
/// recorded, because a single bogus terabyte would silently exhaust a
/// customer's monthly quota and trigger a warning email for traffic they never
/// sent.
///
/// Set well above any link this fleet has (25 Gbit/s ≈ 3.1 GB/s) so a genuinely
/// saturated NIC is never clamped.
const MAX_SAMPLE_BYTES_PER_SEC: u64 = 4_000_000_000;

/// First and last day of the UTC calendar month containing `day`.
///
/// The quota period. Calendar months rather than the VM's billing cycle: a
/// monthly plan, a yearly plan and a VM renewed on the 3rd all then share one
/// window, which is both what customers expect from a "monthly transfer
/// allowance" and what makes a daily table aggregate without per-VM arithmetic.
pub fn quota_period(day: NaiveDate) -> (NaiveDate, NaiveDate) {
    let start = NaiveDate::from_ymd_opt(day.year(), day.month(), 1).unwrap_or(day);
    // The last day is the day before the first of the next month, which avoids
    // hardcoding month lengths and leap years.
    let end = match day.month() {
        12 => NaiveDate::from_ymd_opt(day.year() + 1, 1, 1),
        m => NaiveDate::from_ymd_opt(day.year(), m + 1, 1),
    }
    .and_then(|d| d.pred_opt())
    .unwrap_or(day);
    (start, end)
}

/// Longest range a single traffic query may span, in days.
///
/// Bounds the response: without it a caller could ask for a VM's whole history
/// and get an unpaged row per day. A little over a year, so "the last 12
/// months" is always answerable in one call.
pub const MAX_TRAFFIC_RANGE_DAYS: i64 = 400;

/// Resolve an optional traffic date range into an inclusive, validated one.
///
/// Both bounds default to the quota period containing `today`, so the common
/// query — "what have I used this month" — needs no parameters at all.
///
/// Returns the message to hand back to the caller if the range is unusable.
pub fn resolve_traffic_range(
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
    today: NaiveDate,
) -> std::result::Result<(NaiveDate, NaiveDate), String> {
    let (period_start, period_end) = quota_period(today);
    let start = start.unwrap_or(period_start);
    let end = end.unwrap_or(period_end);

    if end < start {
        return Err("end must not be before start".to_string());
    }
    if (end - start).num_days() > MAX_TRAFFIC_RANGE_DAYS {
        return Err(format!(
            "Range too large, maximum {MAX_TRAFFIC_RANGE_DAYS} days"
        ));
    }
    Ok((start, end))
}

/// Records VM traffic deltas into the daily counters.
#[derive(Clone)]
pub struct TrafficRecorder {
    db: Arc<dyn LNVpsDb>,
}

/// What one counter reading contributed, before it is written.
///
/// Split out from [`TrafficRecorder::record`] so the differencing rules — the
/// interesting part — can be tested without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficDelta {
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Difference one counter reading against the previous one.
///
/// `elapsed_secs` is the time between the two readings, used only for the
/// implausible-jump clamp.
///
/// Counters are cumulative and reset to zero whenever the guest reboots, is
/// stopped and started, or migrates. A reading below its baseline is therefore
/// a reset, and everything the new reading shows has accrued since it — so the
/// contribution is the new value itself, not a subtraction that would
/// underflow.
pub fn traffic_delta(
    last_in: u64,
    last_out: u64,
    new_in: u64,
    new_out: u64,
    elapsed_secs: u64,
) -> TrafficDelta {
    let diff = |last: u64, new: u64| if new >= last { new - last } else { new };

    // A zero or negative interval (clock step, two reads in the same second)
    // still has to admit some traffic, so the cap is never below one second's
    // worth.
    let cap = MAX_SAMPLE_BYTES_PER_SEC.saturating_mul(elapsed_secs.max(1));

    TrafficDelta {
        bytes_in: diff(last_in, new_in).min(cap),
        bytes_out: diff(last_out, new_out).min(cap),
    }
}

impl TrafficRecorder {
    pub fn new(db: Arc<dyn LNVpsDb>) -> Self {
        Self { db }
    }

    /// Fold one counter reading for a VM into today's traffic row.
    ///
    /// The first reading for a VM only establishes the baseline: how much of
    /// that counter accrued while nobody was watching is unknowable, and
    /// crediting all of it to today would attribute a VM's whole lifetime of
    /// traffic to one day.
    ///
    /// The delta is attributed to the UTC day of *this* reading, so traffic
    /// spanning midnight lands on the later day. That misplaces at most one
    /// sweep interval's worth, which is immaterial against a monthly quota and
    /// far cheaper than sampling on a schedule aligned to midnight.
    pub async fn record(&self, vm_id: u64, state: &VmRunningState) -> Result<()> {
        let previous = self.db.get_vm_traffic_sample(vm_id).await?;

        if let Some(prev) = previous {
            let elapsed = (Utc::now() - prev.sampled).num_seconds().max(0) as u64;
            let delta = traffic_delta(
                prev.last_bytes_in,
                prev.last_bytes_out,
                state.net_in,
                state.net_out,
                elapsed,
            );

            if delta.bytes_in > 0 || delta.bytes_out > 0 {
                self.db
                    .add_vm_traffic(
                        vm_id,
                        Utc::now().date_naive(),
                        delta.bytes_in,
                        delta.bytes_out,
                    )
                    .await?;
            }
        }

        self.db
            .upsert_vm_traffic_sample(vm_id, state.net_in, state.net_out)
            .await?;
        Ok(())
    }

    /// [`Self::record`], but a failure is logged rather than propagated.
    ///
    /// Traffic accounting is a bystander on the VM sweep: it must never be the
    /// reason a pass aborts and leaves the VMs behind it unchecked.
    pub async fn record_best_effort(&self, vm_id: u64, state: &VmRunningState) {
        if let Err(e) = self.record(vm_id, state).await {
            warn!("Failed to record traffic for VM {}: {}", vm_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockDb;
    use crate::status::VmRunningStates;
    use chrono::Duration;
    use lnvps_db::LNVpsDbBase;

    fn state(net_in: u64, net_out: u64) -> VmRunningState {
        VmRunningState {
            state: VmRunningStates::Running,
            net_in,
            net_out,
            ..Default::default()
        }
    }

    /// One hour of headroom, so the clamp is never what a test is measuring
    /// unless it says so.
    const HOUR: u64 = 3600;

    #[test]
    fn quota_period_spans_the_whole_calendar_month() {
        let (start, end) = quota_period(NaiveDate::from_ymd_opt(2026, 8, 24).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 8, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 8, 31).unwrap());
    }

    /// December must roll the year, not overflow the month.
    #[test]
    fn quota_period_handles_december() {
        let (start, end) = quota_period(NaiveDate::from_ymd_opt(2026, 12, 9).unwrap());
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 12, 1).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 12, 31).unwrap());
    }

    /// Month length is derived, so a leap February is 29 days without a table.
    #[test]
    fn quota_period_handles_leap_february() {
        let (_, end) = quota_period(NaiveDate::from_ymd_opt(2028, 2, 5).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2028, 2, 29).unwrap());
        let (_, end) = quota_period(NaiveDate::from_ymd_opt(2027, 2, 5).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2027, 2, 28).unwrap());
    }

    /// No parameters must answer the question customers actually ask, which is
    /// about this month.
    #[test]
    fn traffic_range_defaults_to_the_quota_period() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
        assert_eq!(
            resolve_traffic_range(None, None, today).unwrap(),
            (
                NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
                NaiveDate::from_ymd_opt(2026, 8, 31).unwrap()
            )
        );
    }

    /// One bound given, the other still falls back to the period.
    #[test]
    fn traffic_range_accepts_a_partial_range() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 8, 10).unwrap();
        assert_eq!(
            resolve_traffic_range(Some(start), None, today).unwrap(),
            (start, NaiveDate::from_ymd_opt(2026, 8, 31).unwrap())
        );
    }

    /// An inverted range is a caller bug and must be reported, not silently
    /// answered with an empty list.
    #[test]
    fn traffic_range_rejects_end_before_start() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
        assert!(
            resolve_traffic_range(
                Some(NaiveDate::from_ymd_opt(2026, 8, 10).unwrap()),
                Some(NaiveDate::from_ymd_opt(2026, 8, 1).unwrap()),
                today
            )
            .is_err()
        );
    }

    /// The response is one row per day and unpaged, so the span has to be
    /// bounded.
    #[test]
    fn traffic_range_rejects_an_unbounded_span() {
        let today = NaiveDate::from_ymd_opt(2026, 8, 24).unwrap();
        let start = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        assert!(resolve_traffic_range(Some(start), Some(today), today).is_err());

        // The limit itself is allowed.
        let start = today - Duration::days(MAX_TRAFFIC_RANGE_DAYS);
        assert!(resolve_traffic_range(Some(start), Some(today), today).is_ok());
    }

    #[test]
    fn delta_is_the_difference_between_readings() {
        assert_eq!(
            traffic_delta(100, 200, 350, 500, HOUR),
            TrafficDelta {
                bytes_in: 250,
                bytes_out: 300
            }
        );
    }

    /// A counter that went backwards was reset (reboot, migration), so the new
    /// reading is entirely traffic since the reset — and must not underflow.
    #[test]
    fn counter_reset_contributes_the_new_reading() {
        assert_eq!(
            traffic_delta(5_000, 9_000, 120, 40, HOUR),
            TrafficDelta {
                bytes_in: 120,
                bytes_out: 40
            }
        );
    }

    /// A VM stopped between passes reads as zero on both counters, which is a
    /// reset contributing nothing rather than a subtraction contributing a
    /// negative.
    #[test]
    fn stopped_vm_contributes_nothing() {
        assert_eq!(
            traffic_delta(5_000, 9_000, 0, 0, HOUR),
            TrafficDelta {
                bytes_in: 0,
                bytes_out: 0
            }
        );
    }

    /// A jump no link could have carried is a counter swap, not traffic, and is
    /// clamped so it cannot exhaust a quota on its own.
    #[test]
    fn implausible_jump_is_clamped_to_the_line_rate() {
        // 10 seconds at 4 GB/s is 40 GB; the reading claims 900 GB.
        let d = traffic_delta(0, 0, 900_000_000_000, 900_000_000_000, 10);
        assert_eq!(d.bytes_in, MAX_SAMPLE_BYTES_PER_SEC * 10);
        assert_eq!(d.bytes_out, MAX_SAMPLE_BYTES_PER_SEC * 10);
    }

    /// A saturated 25 Gbit/s NIC (~3.1 GB/s) must pass through untouched: the
    /// clamp exists for impossible readings, not busy ones.
    #[test]
    fn saturated_link_is_not_clamped() {
        let bytes = 3_125_000_000u64 * 60; // 25 Gbit/s for a minute
        let d = traffic_delta(0, 0, bytes, bytes, 60);
        assert_eq!(d.bytes_out, bytes);
    }

    /// Two readings in the same second still get a full second of headroom, so
    /// a fast sweep does not clamp normal traffic to zero.
    #[test]
    fn zero_elapsed_still_allows_one_second_of_traffic() {
        let d = traffic_delta(0, 0, 1_000, 1_000, 0);
        assert_eq!(d.bytes_out, 1_000);
    }

    /// The first reading is a baseline only. Crediting it would charge a VM's
    /// entire lifetime of traffic to whichever day it was first sampled.
    #[tokio::test]
    async fn first_reading_only_sets_the_baseline() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());

        recorder.record(1, &state(10_000, 20_000)).await.unwrap();

        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(1, today, today).await.unwrap(),
            (0, 0),
            "nothing may be attributed from a single reading"
        );
        let sample = db
            .get_vm_traffic_sample(1)
            .await
            .unwrap()
            .expect("baseline");
        assert_eq!(sample.last_bytes_in, 10_000);
        assert_eq!(sample.last_bytes_out, 20_000);
    }

    /// Successive readings accumulate, and the baseline follows the latest one.
    #[tokio::test]
    async fn successive_readings_accumulate() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());

        recorder.record(1, &state(1_000, 2_000)).await.unwrap();
        recorder.record(1, &state(1_500, 3_000)).await.unwrap();
        recorder.record(1, &state(1_800, 3_100)).await.unwrap();

        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(1, today, today).await.unwrap(),
            (800, 1_100)
        );
        let sample = db
            .get_vm_traffic_sample(1)
            .await
            .unwrap()
            .expect("baseline");
        assert_eq!(sample.last_bytes_in, 1_800);
    }

    /// A reboot between passes must not lose the traffic that followed it, nor
    /// underflow the subtraction.
    #[tokio::test]
    async fn reboot_between_passes_keeps_counting() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());

        recorder.record(1, &state(1_000, 5_000)).await.unwrap();
        recorder.record(1, &state(1_500, 6_000)).await.unwrap();
        // Guest reboots; the hypervisor's counter starts over.
        recorder.record(1, &state(70, 90)).await.unwrap();

        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(1, today, today).await.unwrap(),
            (570, 1_090)
        );
    }

    /// Traffic is per VM: two VMs sampled in the same pass keep separate
    /// baselines and separate rows.
    #[tokio::test]
    async fn baselines_are_per_vm() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());

        recorder.record(1, &state(100, 100)).await.unwrap();
        recorder.record(2, &state(9_000, 9_000)).await.unwrap();
        recorder.record(1, &state(150, 175)).await.unwrap();

        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(1, today, today).await.unwrap(),
            (50, 75)
        );
        assert_eq!(
            db.get_vm_traffic_total(2, today, today).await.unwrap(),
            (0, 0)
        );
    }

    /// A stale baseline is still a baseline: a VM that has been off the sweep
    /// for days resumes differencing rather than re-crediting its whole
    /// counter.
    #[tokio::test]
    async fn stale_baseline_is_still_differenced() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());

        recorder.record(1, &state(1_000, 1_000)).await.unwrap();
        {
            let mut samples = db.vm_traffic_samples.lock().await;
            let s = samples.get_mut(&1).expect("baseline");
            s.sampled = Utc::now() - Duration::days(3);
        }
        recorder.record(1, &state(1_400, 1_600)).await.unwrap();

        let today = Utc::now().date_naive();
        assert_eq!(
            db.get_vm_traffic_total(1, today, today).await.unwrap(),
            (400, 600)
        );
    }

    /// A recording failure must not surface to the caller: the VM sweep has
    /// more important work behind it.
    #[tokio::test]
    async fn record_best_effort_swallows_failures() {
        let db = Arc::new(MockDb::default());
        let recorder = TrafficRecorder::new(db.clone());
        // MockDb accepts any vm_id, so this only exercises the success path
        // reaching the same place; the point is that the signature cannot
        // propagate an error into the sweep.
        recorder.record_best_effort(1, &state(1, 1)).await;
        assert!(db.get_vm_traffic_sample(1).await.unwrap().is_some());
    }
}
