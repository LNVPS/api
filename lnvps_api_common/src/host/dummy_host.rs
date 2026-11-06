use crate::host::{
    DiskStream, FullVmInfo, ImportedDisk, MigrateVmRequest, TerminalStream, TimeSeries,
    TimeSeriesData, VmHostClient, VmHostDiskInfo, VmHostInfo, VmSnapshot,
};
use crate::retry::OpResult;
use crate::{GB, HostVmSpec, PB, TB, VmRunningState, VmRunningStates, op_fatal};
use async_trait::async_trait;
use chrono::Utc;
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
    /// Database id of the host this client stands in for, when known.
    ///
    /// Only used to answer [`VmHostClient::list_host_vms`] per host, so a test
    /// can place different VMs on different hosts (which is the whole subject
    /// of placement-drift detection).
    host_id: Option<u64>,
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
            host_id: None,
        }
    }

    /// Tag this client with the database host id it represents.
    pub fn with_host_id(mut self, host_id: u64) -> Self {
        self.host_id = Some(host_id);
        self
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
            host_id: None,
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

    /// Migrations recorded by [`VmHostClient::migrate_vm`], oldest first.
    ///
    /// Lets a test assert what the provisioner asked the hypervisor to do
    /// (target node, online or not, whether the disk was copied) without a real
    /// host.
    pub async fn migrations() -> Vec<(u64, MigrateVmRequest)> {
        DUMMY_MIGRATIONS.lock().await.clone()
    }

    pub async fn clear_all_snapshots() {
        DUMMY_SNAPSHOTS.lock().await.clear();
    }

    pub async fn exclusive_snapshots() -> tokio::sync::MutexGuard<'static, ()> {
        static SNAPSHOT_TESTS: Mutex<()> = Mutex::const_new(());
        let guard = SNAPSHOT_TESTS.lock().await;
        Self::clear_all_snapshots().await;
        guard
    }

    /// Forget all recorded migrations.
    pub async fn clear_migrations() {
        DUMMY_MIGRATIONS.lock().await.clear();
    }

    pub async fn set_disk(host_id: u64, vm_id: u64, bytes: Vec<u8>) {
        DUMMY_DISKS.lock().await.insert((host_id, vm_id), bytes);
    }

    pub async fn disk(host_id: u64, vm_id: u64) -> Option<Vec<u8>> {
        DUMMY_DISKS.lock().await.get(&(host_id, vm_id)).cloned()
    }

    pub async fn set_fault(host_id: u64, fault: Option<DummyFault>) {
        let mut faults = DUMMY_FAULTS.lock().await;
        match fault {
            Some(f) => faults.insert(host_id, f),
            None => faults.remove(&host_id),
        };
    }

    pub async fn is_retired(host_id: u64, vm_id: u64) -> bool {
        DUMMY_RETIRED.lock().await.contains(&(host_id, vm_id))
    }

    pub async fn clear_disks() {
        DUMMY_DISKS.lock().await.clear();
        DUMMY_FAULTS.lock().await.clear();
        DUMMY_RETIRED.lock().await.clear();
    }

    async fn fault(&self) -> Option<DummyFault> {
        let id = self.host_id?;
        DUMMY_FAULTS.lock().await.get(&id).copied()
    }

    /// Set the list of host VMs reported by [`list_host_vms`].
    ///
    /// Backed by a process-wide registry so the value survives the fresh
    /// [`DummyVmHost`] instances that `get_host_client` constructs. Intended for
    /// exercising VM import/discovery flows.
    pub async fn set_host_vms(vms: Vec<HostVmSpec>) {
        *DUMMY_HOST_VMS.lock().await = vms;
    }

    /// Set the VM list reported by the client for one specific host.
    ///
    /// Takes precedence over [`set_host_vms`] for that host, so a test can give
    /// two hosts different VM lists.
    pub async fn set_host_vms_for(host_id: u64, vms: Vec<HostVmSpec>) {
        DUMMY_HOST_VMS_BY_HOST.lock().await.insert(host_id, vms);
    }

    /// Forget all per-host VM lists.
    pub async fn clear_host_vms() {
        DUMMY_HOST_VMS_BY_HOST.lock().await.clear();
        DUMMY_HOST_VMS.lock().await.clear();
    }
}

/// Process-wide registry of "host" VMs reported by [`DummyVmHost::list_host_vms`].
static DUMMY_HOST_VMS: LazyLock<Arc<Mutex<Vec<HostVmSpec>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// Per-host VM lists, keyed by database host id.
static DUMMY_HOST_VMS_BY_HOST: LazyLock<Arc<Mutex<HashMap<u64, Vec<HostVmSpec>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

static DUMMY_SNAPSHOTS: LazyLock<Arc<Mutex<HashMap<u64, Vec<VmSnapshot>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Process-wide log of migrations requested through [`DummyVmHost::migrate_vm`].
static DUMMY_MIGRATIONS: LazyLock<Arc<Mutex<Vec<(u64, MigrateVmRequest)>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DummyFault {
    ExportFails,
    ImportFails,
    CorruptImport,
    StartFails,
    DeleteFails,
}

static DUMMY_DISKS: LazyLock<Mutex<HashMap<(u64, u64), Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static DUMMY_FAULTS: LazyLock<Mutex<HashMap<u64, DummyFault>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static DUMMY_RETIRED: LazyLock<Mutex<std::collections::HashSet<(u64, u64)>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

#[async_trait]
impl VmHostClient for DummyVmHost {
    async fn list_host_vms(&self) -> OpResult<Vec<HostVmSpec>> {
        if let Some(host_id) = self.host_id
            && let Some(vms) = DUMMY_HOST_VMS_BY_HOST.lock().await.get(&host_id)
        {
            return Ok(vms.clone());
        }
        Ok(DUMMY_HOST_VMS.lock().await.clone())
    }

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

    async fn list_snapshots(&self, vm: &Vm) -> OpResult<Vec<VmSnapshot>> {
        let snapshots = DUMMY_SNAPSHOTS.lock().await;
        Ok(snapshots.get(&vm.id).cloned().unwrap_or_default())
    }

    async fn create_snapshot(
        &self,
        vm: &Vm,
        name: &str,
        description: Option<&str>,
    ) -> OpResult<()> {
        let mut snapshots = DUMMY_SNAPSHOTS.lock().await;
        let held = snapshots.entry(vm.id).or_default();
        if held.iter().any(|s| s.name == name) {
            op_fatal!("Snapshot {} already exists", name);
        }
        held.push(VmSnapshot {
            name: name.to_string(),
            description: description.map(str::to_string),
            created: Some(Utc::now()),
        });
        Ok(())
    }

    async fn rollback_snapshot(&self, vm: &Vm, name: &str) -> OpResult<()> {
        {
            let snapshots = DUMMY_SNAPSHOTS.lock().await;
            if !snapshots
                .get(&vm.id)
                .is_some_and(|held| held.iter().any(|s| s.name == name))
            {
                op_fatal!("Snapshot {} does not exist", name);
            }
        }
        {
            let mut vms = self.vms.lock().await;
            if let Some(m) = vms.get_mut(&vm.id) {
                m.state = VmRunningStates::Stopped;
                m.uptime_secs = 0;
            }
        }
        self.save().await;
        Ok(())
    }

    async fn delete_snapshot(&self, vm: &Vm, name: &str) -> OpResult<()> {
        if let Some(held) = DUMMY_SNAPSHOTS.lock().await.get_mut(&vm.id) {
            held.retain(|s| s.name != name);
        }
        Ok(())
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

    async fn migrate_vm(&self, vm: &Vm, req: &MigrateVmRequest) -> OpResult<()> {
        DUMMY_MIGRATIONS.lock().await.push((vm.id, req.clone()));
        Ok(())
    }

    async fn export_primary_disk(&self, vm: &Vm) -> OpResult<DiskStream> {
        if self.fault().await == Some(DummyFault::ExportFails) {
            op_fatal!("export failed");
        }
        let host_id = self.host_id.unwrap_or_default();
        let Some(bytes) = Self::disk(host_id, vm.id).await else {
            op_fatal!("VM {} has no disk on host {}", vm.id, host_id);
        };
        Ok(DiskStream {
            size: bytes.len() as u64,
            format: crate::host::DiskFormat::Raw,
            reader: Box::pin(std::io::Cursor::new(bytes)),
        })
    }

    async fn create_vm_from_disk(
        &self,
        cfg: &FullVmInfo,
        mut disk: DiskStream,
    ) -> OpResult<ImportedDisk> {
        use sha2::Digest;
        use tokio::io::AsyncReadExt;
        let fault = self.fault().await;
        if fault == Some(DummyFault::ImportFails) {
            op_fatal!("import failed");
        }
        let mut bytes = Vec::new();
        disk.reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| crate::retry::OpError::Fatal(e.into()))?;
        if fault == Some(DummyFault::CorruptImport)
            && let Some(b) = bytes.first_mut()
        {
            *b ^= 0xff;
        }
        let imported = ImportedDisk {
            bytes: bytes.len() as u64,
            sha256: hex::encode(sha2::Sha256::digest(&bytes)),
        };
        Self::set_disk(self.host_id.unwrap_or_default(), cfg.vm.id, bytes).await;
        self.create_vm(cfg).await?;
        Ok(imported)
    }

    async fn retire_vm(&self, vm: &Vm) -> OpResult<()> {
        self.stop_vm(vm).await?;
        DUMMY_RETIRED
            .lock()
            .await
            .insert((self.host_id.unwrap_or_default(), vm.id));
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        if self.fault().await == Some(DummyFault::DeleteFails) {
            op_fatal!("delete failed");
        }
        if let Some(host_id) = self.host_id {
            DUMMY_DISKS.lock().await.remove(&(host_id, vm.id));
        }
        {
            let mut vms = self.vms.lock().await;
            vms.remove(&vm.id);
        }
        self.save().await;
        Ok(())
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        if self.fault().await == Some(DummyFault::StartFails) {
            op_fatal!("start failed");
        }
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

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::host::tests::mock_full_vm;

    #[tokio::test]
    async fn snapshots_round_trip() {
        let host = DummyVmHost::new();
        let mut info = mock_full_vm();
        info.vm.id = 940_001;
        host.create_vm(&info).await.unwrap();
        host.start_vm(&info.vm).await.unwrap();

        assert!(host.list_snapshots(&info.vm).await.unwrap().is_empty());
        host.create_snapshot(&info.vm, "one", Some("first"))
            .await
            .unwrap();
        host.create_snapshot(&info.vm, "two", None).await.unwrap();
        assert!(host.create_snapshot(&info.vm, "one", None).await.is_err());

        let listed = host.list_snapshots(&info.vm).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].description.as_deref(), Some("first"));

        host.rollback_snapshot(&info.vm, "one").await.unwrap();
        assert_eq!(
            host.get_vm_state(&info.vm).await.unwrap().state,
            VmRunningStates::Stopped
        );
        assert!(host.rollback_snapshot(&info.vm, "nope").await.is_err());

        host.delete_snapshot(&info.vm, "one").await.unwrap();
        host.delete_snapshot(&info.vm, "one").await.unwrap();
        assert_eq!(host.list_snapshots(&info.vm).await.unwrap().len(), 1);

        DummyVmHost::clear_all_snapshots().await;
        assert!(host.list_snapshots(&info.vm).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rolling_back_to_nothing_fails() {
        let host = DummyVmHost::new();
        let mut vm = mock_full_vm().vm;
        vm.id = 940_002;
        assert!(host.rollback_snapshot(&vm, "one").await.is_err());
        host.delete_snapshot(&vm, "one").await.unwrap();
    }

    #[tokio::test]
    async fn disks_export_and_import_byte_for_byte() {
        use sha2::Digest;
        let src = DummyVmHost::new().with_host_id(940_010);
        let dst = DummyVmHost::new().with_host_id(940_011);
        let mut info = mock_full_vm();
        info.vm.id = 940_003;
        let bytes: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        DummyVmHost::set_disk(940_010, info.vm.id, bytes.clone()).await;

        let stream = src.export_primary_disk(&info.vm).await.unwrap();
        assert_eq!(stream.size, bytes.len() as u64);
        let imported = dst.create_vm_from_disk(&info, stream).await.unwrap();
        assert_eq!(imported.bytes, bytes.len() as u64);
        assert_eq!(imported.sha256, hex::encode(sha2::Sha256::digest(&bytes)));
        assert_eq!(
            DummyVmHost::disk(940_011, info.vm.id).await,
            Some(bytes.clone())
        );

        DummyVmHost::set_fault(940_011, Some(DummyFault::CorruptImport)).await;
        let stream = src.export_primary_disk(&info.vm).await.unwrap();
        let corrupt = dst.create_vm_from_disk(&info, stream).await.unwrap();
        assert_ne!(corrupt.sha256, imported.sha256);

        src.retire_vm(&info.vm).await.unwrap();
        assert!(DummyVmHost::is_retired(940_010, info.vm.id).await);
        DummyVmHost::set_fault(940_011, None).await;
        dst.delete_vm(&info.vm).await.unwrap();
        assert!(DummyVmHost::disk(940_011, info.vm.id).await.is_none());
        assert!(
            DummyVmHost::new()
                .export_primary_disk(&info.vm)
                .await
                .is_err()
        );
    }
}
