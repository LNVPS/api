use anyhow::Result;
#[cfg(feature = "admin")]
mod admin;
mod model;
#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "nostr-domain")]
pub mod nostr;

#[cfg(feature = "admin")]
pub use admin::*;
pub use model::*;
#[cfg(feature = "mysql")]
pub use mysql::*;

#[cfg(feature = "nostr-domain")]
use crate::nostr::LNVPSNostrDb;
pub use async_trait::async_trait;

#[async_trait]
pub trait LNVpsDbBase: Send + Sync {
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

    /// List all users
    async fn list_users(&self) -> Result<Vec<User>>;

    /// List users with pagination
    async fn list_users_paginated(&self, limit: u64, offset: u64) -> Result<Vec<User>>;

    /// Get total count of users
    async fn count_users(&self) -> Result<u64>;

    /// Insert a new user ssh key
    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> Result<u64>;

    /// Get user ssh key by id
    async fn get_user_ssh_key(&self, id: u64) -> Result<UserSshKey>;

    /// Delete a user ssh key by id
    async fn delete_user_ssh_key(&self, id: u64) -> Result<()>;

    /// List a users ssh keys
    async fn list_user_ssh_key(&self, user_id: u64) -> Result<Vec<UserSshKey>>;

    /// Get VM host regions
    async fn list_host_region(&self) -> Result<Vec<VmHostRegion>>;

    /// Get VM host region by id
    async fn get_host_region(&self, id: u64) -> Result<VmHostRegion>;

    /// Get VM host region by name
    async fn get_host_region_by_name(&self, name: &str) -> Result<VmHostRegion>;

    /// List VM's owned by a specific user
    async fn list_hosts(&self) -> Result<Vec<VmHost>>;
    
    /// List hosts with pagination
    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> Result<(Vec<VmHost>, u64)>;
    
    /// List hosts with region information for admin interface
    async fn list_hosts_with_regions_paginated(&self, limit: u64, offset: u64) -> Result<(Vec<(VmHost, VmHostRegion)>, u64)>;

    /// List VM's owned by a specific user
    async fn get_host(&self, id: u64) -> Result<VmHost>;

    /// Update host resources (usually from [auto_discover])
    async fn update_host(&self, host: &VmHost) -> Result<()>;

    /// Create a new host
    async fn create_host(&self, host: &VmHost) -> Result<u64>;

    /// List enabled storage disks on the host
    async fn list_host_disks(&self, host_id: u64) -> Result<Vec<VmHostDisk>>;

    /// Get a specific host disk
    async fn get_host_disk(&self, disk_id: u64) -> Result<VmHostDisk>;

    /// Update a host disk
    async fn update_host_disk(&self, disk: &VmHostDisk) -> Result<()>;

    /// Get OS image by id
    async fn get_os_image(&self, id: u64) -> Result<VmOsImage>;

    /// List available OS images
    async fn list_os_image(&self) -> Result<Vec<VmOsImage>>;

    /// List available IP Ranges
    async fn get_ip_range(&self, id: u64) -> Result<IpRange>;

    /// List available IP Ranges
    async fn list_ip_range(&self) -> Result<Vec<IpRange>>;

    /// List available IP Ranges in a given region
    async fn list_ip_range_in_region(&self, region_id: u64) -> Result<Vec<IpRange>>;

    /// Get a VM cost plan by id
    async fn get_cost_plan(&self, id: u64) -> Result<VmCostPlan>;

    /// Get VM template by id
    async fn get_vm_template(&self, id: u64) -> Result<VmTemplate>;

    /// List VM templates
    async fn list_vm_templates(&self) -> Result<Vec<VmTemplate>>;

    /// Insert a new VM template
    async fn insert_vm_template(&self, template: &VmTemplate) -> Result<u64>;

    /// List all VM's
    async fn list_vms(&self) -> Result<Vec<Vm>>;

    /// List all VM's on a given host
    async fn list_vms_on_host(&self, host_id: u64) -> Result<Vec<Vm>>;

    /// Count active (non-deleted) VM's on a given host
    async fn count_active_vms_on_host(&self, host_id: u64) -> Result<u64>;

    /// List expired VM's
    async fn list_expired_vms(&self) -> Result<Vec<Vm>>;

    /// List VM's owned by a specific user
    async fn list_user_vms(&self, id: u64) -> Result<Vec<Vm>>;

    /// Get a VM by id
    async fn get_vm(&self, vm_id: u64) -> Result<Vm>;

    /// Insert a new VM record
    async fn insert_vm(&self, vm: &Vm) -> Result<u64>;

    /// Delete a VM by id
    async fn delete_vm(&self, vm_id: u64) -> Result<()>;

    /// Update a VM
    async fn update_vm(&self, vm: &Vm) -> Result<()>;

    /// List VM ip assignments
    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> Result<u64>;

    /// Update VM ip assignments (arp/dns refs)
    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> Result<()>;

    /// List VM ip assignments
    async fn list_vm_ip_assignments(&self, vm_id: u64) -> Result<Vec<VmIpAssignment>>;

    /// List VM ip assignments by IP range
    async fn list_vm_ip_assignments_in_range(&self, range_id: u64) -> Result<Vec<VmIpAssignment>>;

    /// Delete assigned VM ips
    async fn delete_vm_ip_assignment(&self, vm_id: u64) -> Result<()>;

    /// List payments by VM id
    async fn list_vm_payment(&self, vm_id: u64) -> Result<Vec<VmPayment>>;

    /// Insert a new VM payment record
    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> Result<()>;

    /// Get VM payment by payment id
    async fn get_vm_payment(&self, id: &Vec<u8>) -> Result<VmPayment>;

    /// Get VM payment by payment id
    async fn get_vm_payment_by_ext_id(&self, id: &str) -> Result<VmPayment>;

    /// Update a VM payment record
    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> Result<()>;

    /// Mark a payment as paid and update the vm expiry
    async fn vm_payment_paid(&self, id: &VmPayment) -> Result<()>;

    /// Return the most recently settled invoice
    async fn last_paid_invoice(&self) -> Result<Option<VmPayment>>;

    /// Return the list of active custom pricing models for a given region
    async fn list_custom_pricing(&self, region_id: u64) -> Result<Vec<VmCustomPricing>>;

    /// Get a custom pricing model
    async fn get_custom_pricing(&self, id: u64) -> Result<VmCustomPricing>;

    /// Get a custom pricing model
    async fn get_custom_vm_template(&self, id: u64) -> Result<VmCustomTemplate>;

    /// Insert custom vm template
    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> Result<u64>;

    /// Return the list of disk prices for a given custom pricing model
    async fn list_custom_pricing_disk(&self, pricing_id: u64) -> Result<Vec<VmCustomPricingDisk>>;


    /// Get router config
    async fn get_router(&self, router_id: u64) -> Result<Router>;

    /// List all routers
    async fn list_routers(&self) -> Result<Vec<Router>>;

    /// Get VM IP assignment by IP address
    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> Result<VmIpAssignment>;

    /// Get access policy
    async fn get_access_policy(&self, access_policy_id: u64) -> Result<AccessPolicy>;

    /// Get company
    async fn get_company(&self, company_id: u64) -> Result<Company>;

    /// Insert a new VM history record
    async fn insert_vm_history(&self, history: &VmHistory) -> Result<u64>;

    /// List VM history for a given VM
    async fn list_vm_history(&self, vm_id: u64) -> Result<Vec<VmHistory>>;

    /// List VM history for a given VM with pagination
    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<VmHistory>>;

    /// Get VM history entry by id
    async fn get_vm_history(&self, id: u64) -> Result<VmHistory>;
}

/// Super trait that combines all database functionality based on enabled features
#[cfg(all(feature = "admin", feature = "nostr-domain"))]
#[async_trait]
pub trait LNVpsDb: LNVpsDbBase + AdminDb + LNVPSNostrDb + Send + Sync {}

#[cfg(all(feature = "admin", not(feature = "nostr-domain")))]
#[async_trait]
pub trait LNVpsDb: LNVpsDbBase + AdminDb + Send + Sync {}

#[cfg(all(not(feature = "admin"), feature = "nostr-domain"))]
#[async_trait]
pub trait LNVpsDb: LNVpsDbBase + LNVPSNostrDb + Send + Sync {}

#[cfg(all(not(feature = "admin"), not(feature = "nostr-domain")))]
#[async_trait]
pub trait LNVpsDb: LNVpsDbBase + Send + Sync {}

// Blanket implementations for each feature combination
#[cfg(all(feature = "admin", feature = "nostr-domain"))]
impl<T> LNVpsDb for T where T: LNVpsDbBase + AdminDb + LNVPSNostrDb + Send + Sync {}

#[cfg(all(feature = "admin", not(feature = "nostr-domain")))]
impl<T> LNVpsDb for T where T: LNVpsDbBase + AdminDb + Send + Sync {}

#[cfg(all(not(feature = "admin"), feature = "nostr-domain"))]
impl<T> LNVpsDb for T where T: LNVpsDbBase + LNVPSNostrDb + Send + Sync {}

#[cfg(all(not(feature = "admin"), not(feature = "nostr-domain")))]
impl<T> LNVpsDb for T where T: LNVpsDbBase + Send + Sync {}
