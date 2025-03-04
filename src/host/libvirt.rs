use crate::host::{FullVmInfo, VmHostClient};
use crate::status::VmState;
use lnvps_db::{async_trait, Vm, VmOsImage};

pub struct LibVirt {}

#[async_trait]
impl VmHostClient for LibVirt {
    async fn download_os_image(&self, image: &VmOsImage) -> anyhow::Result<()> {
        todo!()
    }

    async fn generate_mac(&self, vm: &Vm) -> anyhow::Result<String> {
        todo!()
    }

    async fn start_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        todo!()
    }

    async fn stop_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        todo!()
    }

    async fn reset_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        todo!()
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> anyhow::Result<()> {
        todo!()
    }

    async fn get_vm_state(&self, vm: &Vm) -> anyhow::Result<VmState> {
        todo!()
    }

    async fn configure_vm(&self, vm: &Vm) -> anyhow::Result<()> {
        todo!()
    }
}
