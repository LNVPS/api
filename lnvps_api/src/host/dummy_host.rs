use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use async_trait::async_trait;
use chrono::Utc;
use lnvps_api_common::retry::OpResult;
use lnvps_api_common::{GB, PB, TB, VmRunningState, VmRunningStates, op_fatal};
use lnvps_db::{Vm, VmOsImage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

/// Per-VM state tracked by the mock host.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MockVm {
    state: VmRunningStates,
    /// Monotonically increasing uptime counter (seconds). Reset to 0 on stop.
    uptime_secs: u64,
    /// Simulated cumulative network-in bytes.
    net_in: u64,
    /// Simulated cumulative network-out bytes.
    net_out: u64,
    /// Simulated cumulative disk-read bytes.
    disk_read: u64,
    /// Simulated cumulative disk-write bytes.
    disk_write: u64,
    /// Unix timestamp of the last `tick` call (used to advance counters).
    last_tick: u64,
}

impl MockVm {
    /// Advance the simulated counters based on elapsed wall-clock time.
    /// Only accumulates when the VM is Running.
    fn tick(&mut self) {
        let now = now_secs();
        let elapsed = now.saturating_sub(self.last_tick);
        self.last_tick = now;

        if self.state == VmRunningStates::Running {
            self.uptime_secs += elapsed;
            // Randomise per-second rates within realistic ranges:
            //   net_in:    0 – 2 Mbps  (0 – 250 KB/s)
            //   net_out:   0 – 1 Mbps  (0 – 125 KB/s)
            //   disk_read: 0 – 50 MB/s
            //   disk_write:0 – 25 MB/s
            self.net_in += elapsed * (rand::random::<u64>() % 250_000);
            self.net_out += elapsed * (rand::random::<u64>() % 125_000);
            self.disk_read += elapsed * (rand::random::<u64>() % 50_000_000);
            self.disk_write += elapsed * (rand::random::<u64>() % 25_000_000);
        }
    }

    fn to_running_state(&self) -> VmRunningState {
        // Vary CPU and memory usage with a simple pseudo-random pattern
        // based on uptime so the values change over time but stay realistic.
        let cpu_usage = if self.state == VmRunningStates::Running {
            // oscillates between ~5 % and ~35 %
            0.05 + 0.30 * ((self.uptime_secs % 60) as f32 / 60.0)
        } else {
            0.0
        };
        let mem_usage = if self.state == VmRunningStates::Running {
            // slowly rises from 20 % to 60 % then wraps
            0.20 + 0.40 * ((self.uptime_secs % 300) as f32 / 300.0)
        } else {
            0.0
        };

        VmRunningState {
            timestamp: now_secs(),
            state: self.state.clone(),
            cpu_usage,
            mem_usage,
            uptime: self.uptime_secs,
            net_in: self.net_in,
            net_out: self.net_out,
            disk_write: self.disk_write,
            disk_read: self.disk_read,
        }
    }
}

fn now_secs() -> u64 {
    Utc::now().timestamp() as u64
}

// ---------------------------------------------------------------------------

/// A mock `VmHostClient` that simulates VM lifecycle without contacting any
/// real hypervisor.
///
/// Two construction modes:
/// - [`DummyVmHost::new()`] — fresh independent in-memory map; used by tests.
/// - [`DummyVmHost::new_persistent()`] — process-wide shared map backed by a
///   JSON file in `/tmp`; used by the real API service so state survives
///   restarts.
#[derive(Debug, Clone)]
pub struct DummyVmHost {
    vms: Arc<Mutex<HashMap<u64, MockVm>>>,
    /// When `true`, mutations are flushed to [`STATE_FILE`].
    persist: bool,
}

impl Default for DummyVmHost {
    fn default() -> Self {
        Self::new()
    }
}

/// Path used to persist dummy-host VM state across restarts.
const STATE_FILE: &str = "/tmp/lnvps_dummy_vms.json";

impl DummyVmHost {
    /// Create a fresh, isolated in-memory host.  State is never written to
    /// disk.  Use this in tests.
    pub fn new() -> Self {
        Self {
            vms: Arc::new(Mutex::new(HashMap::new())),
            persist: false,
        }
    }

    /// Create (or reuse) the process-wide persistent host.  State is loaded
    /// from [`STATE_FILE`] on first call and flushed after every mutation.
    /// Use this in the real API service.
    pub fn new_persistent() -> Self {
        static LAZY_VMS: LazyLock<Arc<Mutex<HashMap<u64, MockVm>>>> = LazyLock::new(|| {
            let map = DummyVmHost::load_from_file().unwrap_or_default();
            Arc::new(Mutex::new(map))
        });
        Self {
            vms: LAZY_VMS.clone(),
            persist: true,
        }
    }

    /// Load the VM map from the JSON state file, if it exists.
    fn load_from_file() -> Option<HashMap<u64, MockVm>> {
        let data = std::fs::read_to_string(STATE_FILE).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Flush the current VM map to disk.  No-op when `persist` is false.
    async fn save(&self) {
        if !self.persist {
            return;
        }
        let vms = self.vms.lock().await;
        if let Ok(json) = serde_json::to_string(&*vms) {
            let _ = std::fs::write(STATE_FILE, json);
        }
    }
}

#[async_trait]
impl VmHostClient for DummyVmHost {
    async fn get_info(&self) -> OpResult<VmHostInfo> {
        Ok(VmHostInfo {
            cpu: 100,
            memory: 1 * TB,
            disks: vec![VmHostDiskInfo {
                name: "mock-disk".to_string(),
                size: 1 * PB,
                used: 0,
            }],
        })
    }

    async fn download_os_image(&self, _image: &VmOsImage) -> OpResult<()> {
        Ok(())
    }

    async fn generate_mac(&self, _vm: &Vm) -> OpResult<String> {
        Ok(format!(
            "ff:ff:ff:{:02x}:{:02x}:{:02x}",
            rand::random::<u8>(),
            rand::random::<u8>(),
            rand::random::<u8>(),
        ))
    }

    /// Register the VM under its DB id in the `Creating` state, then
    /// transition it to `Stopped` after a real async delay of 10–60 seconds,
    /// simulating provisioning time on a real hypervisor.
    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let vm_id = cfg.vm.id;

        // when using dummy host in real dev env, add a small delete in create_vm
        #[cfg(not(test))]
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        {
            let mut vms = self.vms.lock().await;
            vms.insert(
                vm_id,
                MockVm {
                    state: VmRunningStates::Stopped,
                    ..MockVm::default()
                },
            );
        }
        self.save().await;

        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        {
            let mut vms = self.vms.lock().await;
            vms.remove(&vm.id);
        }
        self.save().await;
        Ok(())
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        {
            let mut vms = self.vms.lock().await;
            if let Some(m) = vms.get_mut(&vm.id) {
                m.tick();
                m.state = VmRunningStates::Running;
            }
        }
        self.save().await;
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        {
            let mut vms = self.vms.lock().await;
            if let Some(m) = vms.get_mut(&vm.id) {
                m.tick();
                m.state = VmRunningStates::Stopped;
                m.uptime_secs = 0;
            }
        }
        self.save().await;
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        {
            let mut vms = self.vms.lock().await;
            if let Some(m) = vms.get_mut(&vm.id) {
                m.tick();
                m.uptime_secs = 0;
                m.state = VmRunningStates::Running;
            }
        }
        self.save().await;
        Ok(())
    }

    async fn unlink_primary_disk(&self, _vm: &Vm) -> OpResult<()> {
        Ok(())
    }

    async fn import_template_disk(&self, _cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn resize_disk(&self, _cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn configure_vm(&self, _vm: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn patch_firewall(&self, _cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    /// Return the current state of a single VM.
    ///
    /// If the VM is not registered (e.g. it was deleted or never created),
    /// return a Stopped state rather than a fatal error so the worker does not
    /// endlessly try to re-spawn it.
    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        let mut vms = self.vms.lock().await;
        if let Some(m) = vms.get_mut(&vm.id) {
            m.tick();
            Ok(m.to_running_state())
        } else {
            op_fatal!("Vm not found")
        }
    }

    /// Return states for all registered VMs.
    ///
    /// The worker uses the returned `u64` key as the VM's DB id to look up
    /// the corresponding row, so we must use `vm.id` (not a hypervisor id).
    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        let mut vms = self.vms.lock().await;
        let states = vms
            .iter_mut()
            .map(|(vm_id, m)| {
                m.tick();
                (*vm_id, m.to_running_state())
            })
            .collect();
        Ok(states)
    }

    /// Return synthetic time-series data for the requested period.
    ///
    /// Generates one data point per minute for the period length so callers
    /// receive a non-empty list with plausible values.
    async fn get_time_series_data(
        &self,
        _vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        let points: u64 = match series {
            TimeSeries::Hourly => 60,
            TimeSeries::Daily => 24 * 4, // 15-min buckets
            TimeSeries::Weekly => 7 * 24,
            TimeSeries::Monthly => 30 * 24,
            TimeSeries::Yearly => 365,
        };

        let now = now_secs();
        let interval = match series {
            TimeSeries::Hourly => 60,
            TimeSeries::Daily => 900,
            TimeSeries::Weekly => 3600,
            TimeSeries::Monthly => 3600,
            TimeSeries::Yearly => 86400,
        };

        let data = (0..points)
            .map(|i| {
                let ts = now.saturating_sub((points - i) * interval);
                // Simple sinusoidal CPU/mem pattern so graphs look live
                let phase = (i as f32) / (points as f32);
                let cpu = 0.05 + 0.30 * (std::f32::consts::TAU * phase).sin().abs();
                let mem = 0.20 + 0.40 * (std::f32::consts::PI * phase).sin().abs();
                TimeSeriesData {
                    timestamp: ts,
                    cpu,
                    memory: mem,
                    memory_size: 1 * GB,
                    net_in: (64_000.0 * cpu) as f32,
                    net_out: (32_000.0 * cpu) as f32,
                    disk_write: (2_500_000.0 * cpu) as f32,
                    disk_read: (5_000_000.0 * cpu) as f32,
                }
            })
            .collect();

        Ok(data)
    }

    async fn connect_terminal(&self, _vm: &Vm) -> OpResult<TerminalStream> {
        use tokio::sync::mpsc::channel;
        let (client_tx, client_rx) = channel::<Vec<u8>>(256);
        let (server_tx, mut server_rx) = channel::<Vec<u8>>(256);
        tokio::spawn(async move {
            while let Some(buf) = server_rx.recv().await {
                if client_tx.send(buf).await.is_err() {
                    break;
                }
            }
        });
        Ok(TerminalStream {
            rx: client_rx,
            tx: server_tx,
        })
    }
}
