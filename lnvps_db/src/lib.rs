use anyhow::{Error, Result, anyhow};
use async_trait::async_trait;
use sqlx::migrate::MigrateError;
use thiserror::Error;

#[cfg(feature = "admin")]
mod admin;
pub mod encrypted_string;
pub mod encryption;
mod model;
#[cfg(feature = "mysql")]
mod mysql;
#[cfg(feature = "nostr-domain")]
pub mod nostr;

#[cfg(feature = "nostr-domain")]
use crate::nostr::LNVPSNostrDb;
#[cfg(feature = "admin")]
pub use admin::*;
pub use encrypted_string::EncryptedString;
pub use encryption::EncryptionContext;
pub use model::*;
#[cfg(feature = "mysql")]
pub use mysql::*;
use try_procedure::OpError;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("sqlx: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("{0}")]
    Source(#[source] Box<dyn std::error::Error + 'static + Send + Sync>),

    #[error("{0}")]
    Other(#[source] anyhow::Error),

    #[error("Unknown database error")]
    Unknown,
}

impl From<DbError> for OpError<anyhow::Error> {
    fn from(e: DbError) -> OpError<Error> {
        match &e {
            DbError::SqlxError(_) => {
                // TODO: match error types
                OpError::Fatal(anyhow!(e))
            }
            _ => OpError::Fatal(anyhow!(e)),
        }
    }
}

impl From<MigrateError> for DbError {
    fn from(value: MigrateError) -> Self {
        match value {
            MigrateError::Execute(e) => DbError::SqlxError(e),
            MigrateError::ExecuteMigration(e, _) => DbError::SqlxError(e),
            MigrateError::Source(e) => DbError::Source(e),
            _ => DbError::Source(
                anyhow!("Unknown migration error: {}", value).into_boxed_dyn_error(),
            ),
        }
    }
}

impl From<anyhow::Error> for DbError {
    fn from(value: Error) -> Self {
        Self::Source(value.into_boxed_dyn_error())
    }
}

pub type DbResult<T> = Result<T, DbError>;

#[async_trait]
pub trait LNVpsDbBase: Send + Sync {
    /// Migrate database
    async fn migrate(&self) -> DbResult<()>;

    /// Insert/Fetch user by pubkey
    async fn upsert_user(&self, pubkey: &[u8; 32]) -> DbResult<u64>;

    /// Get a user by id
    async fn get_user(&self, id: u64) -> DbResult<User>;

    /// Update user record
    async fn update_user(&self, user: &User) -> DbResult<()>;

    /// Delete user record
    async fn delete_user(&self, id: u64) -> DbResult<()>;

    /// List all users
    async fn list_users(&self) -> DbResult<Vec<User>>;

    /// List users with pagination
    async fn list_users_paginated(&self, limit: u64, offset: u64) -> DbResult<Vec<User>>;

    /// Get total count of users
    async fn count_users(&self) -> DbResult<u64>;

    /// Insert a new user ssh key
    async fn insert_user_ssh_key(&self, new_key: &UserSshKey) -> DbResult<u64>;

    /// Get user ssh key by id
    async fn get_user_ssh_key(&self, id: u64) -> DbResult<UserSshKey>;

    /// Delete a user ssh key by id
    async fn delete_user_ssh_key(&self, id: u64) -> DbResult<()>;

    /// List a users ssh keys
    async fn list_user_ssh_key(&self, user_id: u64) -> DbResult<Vec<UserSshKey>>;

    /// Get VM host regions
    async fn list_host_region(&self) -> DbResult<Vec<VmHostRegion>>;

    /// Get VM host region by id
    async fn get_host_region(&self, id: u64) -> DbResult<VmHostRegion>;

    /// Get VM host region by name
    async fn get_host_region_by_name(&self, name: &str) -> DbResult<VmHostRegion>;

    /// List VM's owned by a specific user
    async fn list_hosts(&self) -> DbResult<Vec<VmHost>>;

    /// List hosts with pagination
    async fn list_hosts_paginated(&self, limit: u64, offset: u64) -> DbResult<(Vec<VmHost>, u64)>;

    /// List hosts with region information for admin interface
    async fn list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<(VmHost, VmHostRegion)>, u64)>;

    /// List VM's owned by a specific user
    async fn get_host(&self, id: u64) -> DbResult<VmHost>;

    /// Update host resources (usually from [auto_discover])
    async fn update_host(&self, host: &VmHost) -> DbResult<()>;

    /// Create a new host
    async fn create_host(&self, host: &VmHost) -> DbResult<u64>;

    /// List enabled storage disks on the host
    async fn list_host_disks(&self, host_id: u64) -> DbResult<Vec<VmHostDisk>>;

    /// Get a specific host disk
    async fn get_host_disk(&self, disk_id: u64) -> DbResult<VmHostDisk>;

    /// Update a host disk
    async fn update_host_disk(&self, disk: &VmHostDisk) -> DbResult<()>;

    /// Create a new host disk
    async fn create_host_disk(&self, disk: &VmHostDisk) -> DbResult<u64>;

    /// Get OS image by id
    async fn get_os_image(&self, id: u64) -> DbResult<VmOsImage>;

    /// List available OS images
    async fn list_os_image(&self) -> DbResult<Vec<VmOsImage>>;

    /// List available IP Ranges
    async fn get_ip_range(&self, id: u64) -> DbResult<IpRange>;

    /// List available IP Ranges
    async fn list_ip_range(&self) -> DbResult<Vec<IpRange>>;

    /// List available IP Ranges in a given region
    async fn list_ip_range_in_region(&self, region_id: u64) -> DbResult<Vec<IpRange>>;

    /// Get a VM cost plan by id
    async fn get_cost_plan(&self, id: u64) -> DbResult<VmCostPlan>;

    /// List all VM cost plans
    async fn list_cost_plans(&self) -> DbResult<Vec<VmCostPlan>>;

    /// Insert a new VM cost plan
    async fn insert_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<u64>;

    /// Update a VM cost plan
    async fn update_cost_plan(&self, cost_plan: &VmCostPlan) -> DbResult<()>;

    /// Delete a VM cost plan
    async fn delete_cost_plan(&self, id: u64) -> DbResult<()>;

    /// Get VM template by id
    async fn get_vm_template(&self, id: u64) -> DbResult<VmTemplate>;

    /// List VM templates
    async fn list_vm_templates(&self) -> DbResult<Vec<VmTemplate>>;

    /// Insert a new VM template
    async fn insert_vm_template(&self, template: &VmTemplate) -> DbResult<u64>;

    /// List all VM's
    async fn list_vms(&self) -> DbResult<Vec<Vm>>;

    /// List all VM's on a given host
    async fn list_vms_on_host(&self, host_id: u64) -> DbResult<Vec<Vm>>;

    /// Count active (non-deleted) VM's on a given host
    async fn count_active_vms_on_host(&self, host_id: u64) -> DbResult<u64>;

    /// List expired VM's
    async fn list_expired_vms(&self) -> DbResult<Vec<Vm>>;

    /// List VM's owned by a specific user
    async fn list_user_vms(&self, id: u64) -> DbResult<Vec<Vm>>;

    /// Get a VM by id
    async fn get_vm(&self, vm_id: u64) -> DbResult<Vm>;

    /// Insert a new VM record
    async fn insert_vm(&self, vm: &Vm) -> DbResult<u64>;

    /// Delete a VM by id
    async fn delete_vm(&self, vm_id: u64) -> DbResult<()>;

    /// Update a VM
    async fn update_vm(&self, vm: &Vm) -> DbResult<()>;

    /// List VM ip assignments
    async fn insert_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<u64>;

    /// Update VM ip assignments (arp/dns refs)
    async fn update_vm_ip_assignment(&self, ip_assignment: &VmIpAssignment) -> DbResult<()>;

    /// List VM ip assignments
    async fn list_vm_ip_assignments(&self, vm_id: u64) -> DbResult<Vec<VmIpAssignment>>;

    /// List VM ip assignments by IP range
    async fn list_vm_ip_assignments_in_range(&self, range_id: u64)
    -> DbResult<Vec<VmIpAssignment>>;

    /// Delete assigned VM ips
    async fn delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()>;

    /// Delete assigned VM ips
    async fn hard_delete_vm_ip_assignments_by_vm_id(&self, vm_id: u64) -> DbResult<()>;

    /// Delete assigned VM ip
    async fn delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()>;

    /// List payments by VM id
    async fn list_vm_payment(&self, vm_id: u64) -> DbResult<Vec<VmPayment>>;

    /// List payments by VM id with pagination
    async fn list_vm_payment_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmPayment>>;

    /// List active payments by VM id, payment method, and payment type
    async fn list_vm_payment_by_method_and_type(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        payment_type: PaymentType,
    ) -> DbResult<Vec<VmPayment>>;

    /// Insert a new VM payment record
    async fn insert_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()>;

    /// Get VM payment by payment id
    async fn get_vm_payment(&self, id: &Vec<u8>) -> DbResult<VmPayment>;

    /// Get VM payment by payment id
    async fn get_vm_payment_by_ext_id(&self, id: &str) -> DbResult<VmPayment>;

    /// Update a VM payment record
    async fn update_vm_payment(&self, vm_payment: &VmPayment) -> DbResult<()>;

    /// Mark a payment as paid and update the vm expiry
    async fn vm_payment_paid(&self, id: &VmPayment) -> DbResult<()>;

    /// Return the most recently settled invoice
    async fn last_paid_invoice(&self) -> DbResult<Option<VmPayment>>;

    /// Return the list of active custom pricing models for a given region
    async fn list_custom_pricing(&self, region_id: u64) -> DbResult<Vec<VmCustomPricing>>;

    /// Get a custom pricing model
    async fn get_custom_pricing(&self, id: u64) -> DbResult<VmCustomPricing>;

    /// Get a custom pricing model
    async fn get_custom_vm_template(&self, id: u64) -> DbResult<VmCustomTemplate>;

    /// Insert custom vm template
    async fn insert_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<u64>;

    /// Update custom vm template
    async fn update_custom_vm_template(&self, template: &VmCustomTemplate) -> DbResult<()>;

    /// Return the list of disk prices for a given custom pricing model
    async fn list_custom_pricing_disk(&self, pricing_id: u64)
    -> DbResult<Vec<VmCustomPricingDisk>>;

    /// Get router config
    async fn get_router(&self, router_id: u64) -> DbResult<Router>;

    /// List all routers
    async fn list_routers(&self) -> DbResult<Vec<Router>>;

    /// Get VM IP assignment
    async fn get_vm_ip_assignment(&self, id: u64) -> DbResult<VmIpAssignment>;

    /// Get VM IP assignment by IP address
    async fn get_vm_ip_assignment_by_ip(&self, ip: &str) -> DbResult<VmIpAssignment>;

    /// Get access policy
    async fn get_access_policy(&self, access_policy_id: u64) -> DbResult<AccessPolicy>;

    /// Get company
    async fn get_company(&self, company_id: u64) -> DbResult<Company>;

    /// List all companies
    async fn list_companies(&self) -> DbResult<Vec<Company>>;

    /// Get base currency for a VM based on its region's company
    async fn get_vm_base_currency(&self, vm_id: u64) -> DbResult<String>;

    /// Get company ID for a VM based on its region's company
    async fn get_vm_company_id(&self, vm_id: u64) -> DbResult<u64>;

    /// Insert a new VM history record
    async fn insert_vm_history(&self, history: &VmHistory) -> DbResult<u64>;

    /// List VM history for a given VM
    async fn list_vm_history(&self, vm_id: u64) -> DbResult<Vec<VmHistory>>;

    /// List VM history for a given VM with pagination
    async fn list_vm_history_paginated(
        &self,
        vm_id: u64,
        limit: u64,
        offset: u64,
    ) -> DbResult<Vec<VmHistory>>;

    /// Get VM history entry by id
    async fn get_vm_history(&self, id: u64) -> DbResult<VmHistory>;

    /// Execute a raw SQL query that doesn't return data
    async fn execute_query(&self, query: &str) -> DbResult<u64>;

    /// Execute a raw SQL query with string parameters that doesn't return data  
    async fn execute_query_with_string_params(
        &self,
        query: &str,
        params: Vec<String>,
    ) -> DbResult<u64>;

    /// Fetch raw string data from database bypassing EncryptedString decoding
    async fn fetch_raw_strings(&self, query: &str) -> DbResult<Vec<(u64, String)>>;

    /// Get all active customers with their contact preferences for bulk messaging
    /// Returns users who have at least one non-deleted VM and at least one contact method enabled
    async fn get_active_customers_with_contact_prefs(&self) -> DbResult<Vec<crate::User>>;

    /// Get all user IDs that have admin privileges (active role assignments)
    async fn list_admin_user_ids(&self) -> DbResult<Vec<u64>>;

    // ========================================================================
    // Subscription Billing System Methods
    // ========================================================================

    // Subscriptions
    async fn list_subscriptions(&self) -> DbResult<Vec<Subscription>>;
    async fn list_subscriptions_by_user(&self, user_id: u64) -> DbResult<Vec<Subscription>>;
    async fn list_subscriptions_active(&self, user_id: u64) -> DbResult<Vec<Subscription>>;
    async fn get_subscription(&self, id: u64) -> DbResult<Subscription>;
    async fn get_subscription_by_ext_id(&self, external_id: &str) -> DbResult<Subscription>;
    async fn insert_subscription(&self, subscription: &Subscription) -> DbResult<u64>;
    async fn insert_subscription_with_line_items(
        &self,
        subscription: &Subscription,
        line_items: Vec<SubscriptionLineItem>,
    ) -> DbResult<u64>;
    async fn update_subscription(&self, subscription: &Subscription) -> DbResult<()>;
    async fn delete_subscription(&self, id: u64) -> DbResult<()>;
    async fn get_subscription_base_currency(&self, subscription_id: u64) -> DbResult<String>;

    // Subscription Line Items
    async fn list_subscription_line_items(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionLineItem>>;
    async fn get_subscription_line_item(&self, id: u64) -> DbResult<SubscriptionLineItem>;
    async fn insert_subscription_line_item(
        &self,
        line_item: &SubscriptionLineItem,
    ) -> DbResult<u64>;
    async fn update_subscription_line_item(&self, line_item: &SubscriptionLineItem)
    -> DbResult<()>;
    async fn delete_subscription_line_item(&self, id: u64) -> DbResult<()>;

    // Subscription Payments
    async fn list_subscription_payments(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>>;
    async fn list_subscription_payments_by_user(
        &self,
        user_id: u64,
    ) -> DbResult<Vec<SubscriptionPayment>>;
    async fn get_subscription_payment(&self, id: &Vec<u8>) -> DbResult<SubscriptionPayment>;
    async fn get_subscription_payment_by_ext_id(
        &self,
        external_id: &str,
    ) -> DbResult<SubscriptionPayment>;
    async fn get_subscription_payment_with_company(
        &self,
        id: &Vec<u8>,
    ) -> DbResult<SubscriptionPaymentWithCompany>;
    async fn insert_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()>;
    async fn update_subscription_payment(&self, payment: &SubscriptionPayment) -> DbResult<()>;
    async fn subscription_payment_paid(&self, payment: &SubscriptionPayment) -> DbResult<()>;
    async fn last_paid_subscription_invoice(&self) -> DbResult<Option<SubscriptionPayment>>;

    // Available IP Space
    async fn list_available_ip_space(&self) -> DbResult<Vec<AvailableIpSpace>>;
    async fn get_available_ip_space(&self, id: u64) -> DbResult<AvailableIpSpace>;
    async fn get_available_ip_space_by_cidr(&self, cidr: &str) -> DbResult<AvailableIpSpace>;
    async fn insert_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<u64>;
    async fn update_available_ip_space(&self, space: &AvailableIpSpace) -> DbResult<()>;
    async fn delete_available_ip_space(&self, id: u64) -> DbResult<()>;

    // IP Space Pricing
    async fn list_ip_space_pricing_by_space(
        &self,
        available_ip_space_id: u64,
    ) -> DbResult<Vec<IpSpacePricing>>;
    async fn get_ip_space_pricing(&self, id: u64) -> DbResult<IpSpacePricing>;
    async fn get_ip_space_pricing_by_prefix(
        &self,
        available_ip_space_id: u64,
        prefix_size: u16,
    ) -> DbResult<IpSpacePricing>;
    async fn insert_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<u64>;
    async fn update_ip_space_pricing(&self, pricing: &IpSpacePricing) -> DbResult<()>;
    async fn delete_ip_space_pricing(&self, id: u64) -> DbResult<()>;

    // IP Range Subscriptions
    async fn list_ip_range_subscriptions_by_line_item(
        &self,
        subscription_line_item_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>>;
    async fn list_ip_range_subscriptions_by_subscription(
        &self,
        subscription_id: u64,
    ) -> DbResult<Vec<IpRangeSubscription>>;
    async fn list_ip_range_subscriptions_by_user(&self, user_id: u64) -> DbResult<Vec<IpRangeSubscription>>;
    async fn get_ip_range_subscription(&self, id: u64) -> DbResult<IpRangeSubscription>;
    async fn get_ip_range_subscription_by_cidr(&self, cidr: &str) -> DbResult<IpRangeSubscription>;
    async fn insert_ip_range_subscription(&self, subscription: &IpRangeSubscription) -> DbResult<u64>;
    async fn update_ip_range_subscription(&self, subscription: &IpRangeSubscription) -> DbResult<()>;
    async fn delete_ip_range_subscription(&self, id: u64) -> DbResult<()>;

    // ========================================================================
    // Payment Method Configuration
    // ========================================================================

    /// List all payment method configurations
    async fn list_payment_method_configs(&self) -> DbResult<Vec<PaymentMethodConfig>>;

    /// List payment method configurations for a company
    async fn list_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>>;

    /// List enabled payment method configurations for a company
    async fn list_enabled_payment_method_configs_for_company(
        &self,
        company_id: u64,
    ) -> DbResult<Vec<PaymentMethodConfig>>;

    /// Get a payment method configuration by id
    async fn get_payment_method_config(&self, id: u64) -> DbResult<PaymentMethodConfig>;

    /// Get a payment method configuration by company and payment method type
    /// Returns a single result since each company can only have one config per payment method
    async fn get_payment_method_config_for_company(
        &self,
        company_id: u64,
        method: PaymentMethod,
    ) -> DbResult<PaymentMethodConfig>;

    /// Insert a new payment method configuration
    async fn insert_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<u64>;

    /// Update a payment method configuration
    async fn update_payment_method_config(&self, config: &PaymentMethodConfig) -> DbResult<()>;

    /// Delete a payment method configuration
    async fn delete_payment_method_config(&self, id: u64) -> DbResult<()>;
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
