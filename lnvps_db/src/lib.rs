use anyhow::Result;
use async_trait::async_trait;

mod model;
#[cfg(feature = "mysql")]
mod mysql;
pub mod hydrate;

pub use model::*;
#[cfg(feature = "mysql")]
pub use mysql::*;

#[async_trait]
pub trait LNVpsDb: Sync + Send {
    /// Migrate database
    async fn migrate(&self) -> Result<()>;

    /// Insert/Fetch user by pubkey
    async fn upsert_user(&self, pubkey: &[u8; 32]) -> Result<u64>;

    /// Get a user by id
    async fn get_user(&self, id: u64) -> Result<User>;

    /// Update user record
    async fn update_user(&self, user: &User) -> Result<()>;

    /// Delete user record
    async fn delete_user(&self, id: u64) -> Result<()>;

    /// Insert a new user ssh key
    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> Result<u64>;

    /// Get user ssh key by id
    async fn get_user_ssh_key(&self, id: u64) -> Result<UserSshKey>;

    /// Delete a user ssh key by id
    async fn delete_user_ssh_key(&self, id: u64) -> Result<()>;

    /// List a users ssh keys
    async fn list_user_ssh_key(&self, user_id: u64) -> Result<Vec<UserSshKey>>;

    /// Get VM host region by id
    async fn get_host_region(&self, id: u64) -> Result<VmHostRegion>;

    /// List VM's owned by a specific user
    async fn list_hosts(&self) -> Result<Vec<VmHost>>;

    /// Update host resources (usually from [auto_discover])
    async fn update_host(&self, host: &VmHost) -> Result<()>;

    /// List VM's owned by a specific user
    async fn list_host_disks(&self, host_id: u64) -> Result<Vec<VmHostDisk>>;

    /// Get OS image by id
    async fn get_os_image(&self, id: u64) -> Result<VmOsImage>;

    /// List available OS images
    async fn list_os_image(&self) -> Result<Vec<VmOsImage>>;

    /// List available IP Ranges
    async fn list_ip_range(&self) -> Result<Vec<IpRange>>;

    /// Get a VM cost plan by id
    async fn get_cost_plan(&self, id: u64) -> Result<VmCostPlan>;

    /// Get VM template by id
    async fn get_vm_template(&self, id: u64) -> Result<VmTemplate>;

    /// List VM templates
    async fn list_vm_templates(&self) -> Result<Vec<VmTemplate>>;

    /// List VM's owned by a specific user
    async fn list_user_vms(&self, id: u64) -> Result<Vec<Vm>>;

    /// Get a VM by id
    async fn get_vm(&self, vm_id: u64) -> Result<Vm>;

    /// Insert a new VM record
    async fn insert_vm(&self, vm: &Vm) -> Result<u64>;

    /// List VM ip assignments
    async fn get_vm_ip_assignments(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>>;

    /// List payments by VM id
    async fn list_vm_payment(&self, vm_id: u64) -> Result<Vec<VmPayment>>;

    /// Insert a new VM payment record
    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> Result<u64>;

    /// Update a VM payment record
    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> Result<()>;
}