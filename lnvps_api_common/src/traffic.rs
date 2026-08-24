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
use chrono::Utc;
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
