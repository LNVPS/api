use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use async_trait::async_trait;
use chrono::Utc;
use lnvps_api_common::retry::OpResult;
use lnvps_api_common::{PB, TB, VmRunningState, VmRunningStates, op_fatal};
use lnvps_db::{Vm, VmOsImage};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct DummyVmHost {
    vms: Arc<Mutex<HashMap<u64, MockVm>>>,
}

#[derive(Debug, Clone)]
struct MockVm {
    pub state: VmRunningStates,
}

impl Default for DummyVmHost {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyVmHost {
    pub fn new() -> Self {
        static LAZY_VMS: LazyLock<Arc<Mutex<HashMap<u64, MockVm>>>> =
            LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
        Self {
            vms: LAZY_VMS.clone(),
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
                name: "dummy-disk".to_string(),
                size: 1 * PB,
                used: 0,
            }],
        })
    }

    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        Ok(())
    }

    async fn generate_mac(&self, vm: &Vm) -> OpResult<String> {
        Ok(format!(
            "ff:ff:ff:{}:{}:{}",
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
            hex::encode([rand::random::<u8>()]),
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Running;
        }
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Stopped;
        }
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        if let Some(vm) = vms.get_mut(&vm.id) {
            vm.state = VmRunningStates::Running;
        }
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        let max_id = *vms.keys().max().unwrap_or(&0);
        vms.insert(
            max_id + 1,
            MockVm {
                state: VmRunningStates::Stopped,
            },
        );
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        let mut vms = self.vms.lock().await;
        vms.remove(&vm.id);
        Ok(())
    }

    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
        Ok(())
    }

    async fn import_template_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        let vms = self.vms.lock().await;
        if let Some(vm) = vms.get(&vm.id) {
            Ok(VmRunningState {
                timestamp: Utc::now().timestamp() as u64,
                state: vm.state.clone(),
                cpu_usage: 0.69,
                mem_usage: 0.99,
                uptime: 100,
                net_in: 69,
                net_out: 69,
                disk_write: 69,
                disk_read: 69,
            })
        } else {
            op_fatal!("No vm with id {}", vm.id)
        }
    }

    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        let vms = self.vms.lock().await;
        let states = vms
            .iter()
            .map(|(vm_id, vm)| {
                (
                    *vm_id,
                    VmRunningState {
                        timestamp: Utc::now().timestamp() as u64,
                        state: vm.state.clone(),
                        cpu_usage: 69.0,
                        mem_usage: 69.0,
                        uptime: 100,
                        net_in: 69,
                        net_out: 69,
                        disk_write: 69,
                        disk_read: 69,
                    },
                )
            })
            .collect();
        Ok(states)
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        Ok(())
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        Ok(vec![])
    }

    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream> {
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
