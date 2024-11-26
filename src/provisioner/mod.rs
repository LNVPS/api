use anyhow::Result;
use lnvps_db::{Vm, VmIpAssignment, VmPayment};
use rocket::async_trait;

pub mod lnvps;

#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Provision a new VM for a user on the database
    ///
    /// Note:
    /// 1. Does not create a VM on the host machine
    /// 2. Does not assign any IP resources
    async fn provision(
        &self,
        user_id: u64,
        template_id: u64,
        image_id: u64,
        ssh_key_id: u64,
    ) -> Result<Vm>;

    /// Create a renewal payment
    async fn renew(&self, vm_id: u64) -> Result<VmPayment>;

    /// Allocate ips for a VM
    async fn allocate_ips(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>>;
}
