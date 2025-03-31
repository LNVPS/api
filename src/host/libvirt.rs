use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use crate::settings::QemuConfig;
use crate::status::{VmRunningState, VmState};
use crate::KB;
use anyhow::{Context, Result};
use chrono::Utc;
use lnvps_db::{async_trait, Vm, VmOsImage};
use virt::connect::Connect;
use virt::domain::Domain;
use virt::sys::{virDomainCreate, VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE};

#[derive(Debug)]
pub struct LibVirtHost {
    connection: Connect,
    qemu: QemuConfig,
}

impl LibVirtHost {
    pub fn new(url: &str, qemu: QemuConfig) -> Result<Self> {
        Ok(Self {
            connection: Connect::open(Some(url))?,
            qemu,
        })
    }
}

#[async_trait]
impl VmHostClient for LibVirtHost {
    async fn get_info(&self) -> Result<VmHostInfo> {
        let info = self.connection.get_node_info()?;
        let storage = self
            .connection
            .list_all_storage_pools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)?;
        Ok(VmHostInfo {
            cpu: info.cpus as u16,
            memory: info.memory * KB,
            disks: storage
                .iter()
                .filter_map(|p| {
                    let info = p.get_info().ok()?;
                    Some(VmHostDiskInfo {
                        name: p.get_name().context("storage pool name is missing").ok()?,
                        size: info.capacity,
                        used: info.allocation,
                    })
                })
                .collect(),
        })
    }

    async fn download_os_image(&self, image: &VmOsImage) -> Result<()> {
        Ok(())
    }

    async fn generate_mac(&self, vm: &Vm) -> Result<String> {
        Ok("ff:ff:ff:ff:ff:ff".to_string())
    }

    async fn start_vm(&self, vm: &Vm) -> Result<()> {
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> Result<()> {
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> Result<()> {
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> Result<()> {
        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> Result<()> {
        todo!()
    }

    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> Result<()> {
        todo!()
    }

    async fn get_vm_state(&self, vm: &Vm) -> Result<VmState> {
        Ok(VmState {
            timestamp: Utc::now().timestamp() as u64,
            state: VmRunningState::Stopped,
            cpu_usage: 0.0,
            mem_usage: 0.0,
            uptime: 0,
            net_in: 0,
            net_out: 0,
            disk_write: 0,
            disk_read: 0,
        })
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> Result<()> {
        todo!()
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> Result<Vec<TimeSeriesData>> {
        todo!()
    }

    async fn connect_terminal(&self, vm: &Vm) -> Result<TerminalStream> {
        todo!()
    }
}
