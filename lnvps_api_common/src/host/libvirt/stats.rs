//! Domain state and resource-usage sampling.

use crate::{VmRunningState, VmRunningStates};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use virt::domain::{DomainInfo, DomainState};

/// Map libvirt's domain state onto the API's coarser running state.
pub fn map_state(state: DomainState) -> VmRunningStates {
    match state {
        DomainState::Running | DomainState::Blocked => VmRunningStates::Running,
        DomainState::Paused | DomainState::PMSuspended => VmRunningStates::Running,
        DomainState::Shutdown | DomainState::Shutoff | DomainState::Crashed => {
            VmRunningStates::Stopped
        }
        DomainState::NoState => VmRunningStates::Unknown,
    }
}

/// Previous CPU-time readings, used to turn libvirt's monotonic counter into a
/// usage percentage.
///
/// libvirt only exposes cumulative nanoseconds of CPU time, so a single sample
/// says nothing about current load; the rate between two samples does.
#[derive(Debug, Default)]
pub struct CpuSampler {
    samples: Mutex<HashMap<u64, CpuSample>>,
}

#[derive(Debug, Clone, Copy)]
struct CpuSample {
    cpu_time_ns: u64,
    at_ms: i64,
}

impl CpuSampler {
    /// Record a reading and return CPU usage as a fraction (0.0–1.0) of the
    /// VM's allocated cores, or `0.0` on the first sample for a VM.
    pub fn observe(&self, vm_id: u64, cpu_time_ns: u64, vcpus: u32) -> f32 {
        let now_ms = Utc::now().timestamp_millis();
        let mut guard = match self.samples.lock() {
            Ok(g) => g,
            // A poisoned mutex must not take down stats collection.
            Err(e) => e.into_inner(),
        };

        let previous = guard.insert(
            vm_id,
            CpuSample {
                cpu_time_ns,
                at_ms: now_ms,
            },
        );

        let Some(previous) = previous else {
            return 0.0;
        };

        let elapsed_ms = now_ms.saturating_sub(previous.at_ms);
        if elapsed_ms <= 0 || vcpus == 0 {
            return 0.0;
        }
        // Counter resets (host reboot, domain recreated) would otherwise show
        // as a huge negative spike.
        let Some(delta_ns) = cpu_time_ns.checked_sub(previous.cpu_time_ns) else {
            return 0.0;
        };

        let elapsed_ns = elapsed_ms as f64 * 1_000_000.0;
        let usage = delta_ns as f64 / (elapsed_ns * vcpus as f64);
        usage.clamp(0.0, 1.0) as f32
    }

    /// Drop the sample for a VM that no longer exists so the map doesn't grow
    /// without bound on a busy host.
    pub fn forget(&self, vm_id: u64) {
        if let Ok(mut guard) = self.samples.lock() {
            guard.remove(&vm_id);
        }
    }
}

/// Build a [`VmRunningState`] from a domain's info block.
///
/// Traffic counters are left at zero: they need extra per-device round-trips
/// and are filled in by the caller when it wants them.
pub fn state_from_info(info: &DomainInfo, vm_id: u64, sampler: &CpuSampler) -> VmRunningState {
    let state = map_state(info.state.unwrap_or(DomainState::NoState));
    let cpu_usage = sampler.observe(vm_id, info.cpu_time, info.nr_virt_cpu);

    // `memory` is the balloon's current allocation in KiB; without a balloon
    // driver in the guest it equals max_mem, which is still the honest answer
    // for "how much RAM is committed to this VM".
    let mem_usage = if info.max_mem > 0 {
        (info.memory as f64 / info.max_mem as f64) as f32
    } else {
        0.0
    };

    VmRunningState {
        timestamp: Utc::now().timestamp() as u64,
        state,
        cpu_usage,
        mem_usage,
        // libvirt exposes no domain uptime; the caller tracks start times.
        uptime: 0,
        net_in: 0,
        net_out: 0,
        disk_write: 0,
        disk_read: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_map_to_running_or_stopped() {
        assert_eq!(map_state(DomainState::Running), VmRunningStates::Running);
        assert_eq!(map_state(DomainState::Blocked), VmRunningStates::Running);
        // A paused VM still holds its resources and is not "stopped" from a
        // billing or capacity point of view.
        assert_eq!(map_state(DomainState::Paused), VmRunningStates::Running);
        assert_eq!(map_state(DomainState::Shutoff), VmRunningStates::Stopped);
        assert_eq!(map_state(DomainState::Crashed), VmRunningStates::Stopped);
        assert_eq!(map_state(DomainState::NoState), VmRunningStates::Unknown);
    }

    #[test]
    fn first_cpu_sample_reports_zero() {
        let sampler = CpuSampler::default();
        assert_eq!(sampler.observe(1, 1_000_000_000, 2), 0.0);
    }

    #[test]
    fn cpu_usage_is_a_fraction_of_allocated_cores() {
        let sampler = CpuSampler::default();
        sampler.observe(1, 0, 2);

        std::thread::sleep(std::time::Duration::from_millis(50));
        // Two full cores busy for the whole interval would be 100%; consume
        // roughly one core's worth and expect somewhere near half.
        let usage = sampler.observe(1, 25_000_000, 2);
        assert!(usage > 0.0 && usage <= 1.0, "usage was {usage}");
    }

    #[test]
    fn cpu_usage_is_clamped() {
        let sampler = CpuSampler::default();
        sampler.observe(1, 0, 1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Absurd delta (counter jump) must not produce >100%.
        let usage = sampler.observe(1, u64::MAX / 2, 1);
        assert!(usage <= 1.0, "usage was {usage}");
    }

    #[test]
    fn counter_reset_does_not_panic_or_go_negative() {
        let sampler = CpuSampler::default();
        sampler.observe(1, 5_000_000_000, 2);
        // Domain recreated: cpu_time restarts from zero.
        let usage = sampler.observe(1, 0, 2);
        assert_eq!(usage, 0.0);
    }

    #[test]
    fn zero_vcpus_does_not_divide_by_zero() {
        let sampler = CpuSampler::default();
        sampler.observe(1, 0, 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(sampler.observe(1, 1_000_000, 0), 0.0);
    }

    #[test]
    fn forget_drops_history() {
        let sampler = CpuSampler::default();
        sampler.observe(1, 1_000_000, 1);
        sampler.forget(1);
        // Without history the next reading is a first sample again.
        assert_eq!(sampler.observe(1, 9_000_000, 1), 0.0);
    }
}
