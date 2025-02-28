use anyhow::Result;
use lnvps_db::{Vm, VmIpAssignment, VmPayment};
use rocket::async_trait;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

mod lnvps;
mod network;

pub use lnvps::*;
pub use network::*;

#[async_trait]
pub trait Provisioner: Send + Sync {
    /// Do any necessary initialization
    async fn init(&self) -> Result<()>;

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

    /// Spawn a VM on the host
    async fn spawn_vm(&self, vm_id: u64) -> Result<()>;

    /// Start a VM
    async fn start_vm(&self, vm_id: u64) -> Result<()>;

    /// Stop a running VM
    async fn stop_vm(&self, vm_id: u64) -> Result<()>;

    /// Restart a VM
    async fn restart_vm(&self, vm_id: u64) -> Result<()>;

    /// Delete a VM
    async fn delete_vm(&self, vm_id: u64) -> Result<()>;

    /// Open terminal proxy connection
    async fn terminal_proxy(
        &self,
        vm_id: u64,
    ) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>>;

    /// Re-Configure VM
    async fn patch_vm(&self, vm_id: u64) -> Result<()>;
}
