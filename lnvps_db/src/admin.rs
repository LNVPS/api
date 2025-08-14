use crate::{AdminRole, AdminRoleAssignment, RegionStats};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;

/// Database trait for admin/RBAC operations
#[async_trait]
pub trait AdminDb: Send + Sync {
    /// Get all permissions for a user (computed from all assigned active roles)
    /// Returns a set of tuples where (resource_enum_value, action_enum_value)
    async fn get_user_permissions(&self, user_id: u64) -> Result<HashSet<(u16, u16)>>;

    /// Get all active role IDs assigned to a user
    async fn get_user_roles(&self, user_id: u64) -> Result<Vec<u64>>;

    /// Check if user has admin privileges (has any active role assignment)
    async fn is_admin_user(&self, user_id: u64) -> Result<bool>;

    /// Assign a role to a user
    async fn assign_user_role(&self, user_id: u64, role_id: u64, assigned_by: u64) -> Result<()>;

    /// Revoke a role from a user
    async fn revoke_user_role(&self, user_id: u64, role_id: u64) -> Result<()>;

    /// Create a new role
    async fn create_role(&self, name: &str, description: Option<&str>) -> Result<u64>;

    /// Get role by id
    async fn get_role(&self, role_id: u64) -> Result<AdminRole>;

    /// Get role by name
    async fn get_role_by_name(&self, name: &str) -> Result<AdminRole>;

    /// List all roles
    async fn list_roles(&self) -> Result<Vec<AdminRole>>;

    /// Update role information
    async fn update_role(&self, role: &AdminRole) -> Result<()>;

    /// Delete role (only if not system role and no users assigned)
    async fn delete_role(&self, role_id: u64) -> Result<()>;

    /// Add permission to role
    async fn add_role_permission(&self, role_id: u64, resource: u16, action: u16) -> Result<()>;

    /// Remove permission from role
    async fn remove_role_permission(&self, role_id: u64, resource: u16, action: u16) -> Result<()>;

    /// Get all permissions for a role as (resource, action) tuples
    async fn get_role_permissions(&self, role_id: u64) -> Result<Vec<(u16, u16)>>;

    /// Get role assignments for a user with full details
    async fn get_user_role_assignments(&self, user_id: u64) -> Result<Vec<AdminRoleAssignment>>;

    /// Count users assigned to a role
    async fn count_role_users(&self, role_id: u64) -> Result<u64>;

    /// List users with admin data in a single query (paginated)
    /// Returns (users_with_stats, total_count)
    async fn admin_list_users(
        &self,
        limit: u64,
        offset: u64,
        search_pubkey: Option<&str>,
    ) -> Result<(Vec<crate::AdminUserInfo>, u64)>;

    // Region management methods
    /// List all regions with pagination
    async fn admin_list_regions(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::VmHostRegion>, u64)>;

    /// Create a new region
    async fn admin_create_region(&self, name: &str, enabled: bool, company_id: Option<u64>) -> Result<u64>;

    /// Update region information
    async fn admin_update_region(&self, region: &crate::VmHostRegion) -> Result<()>;

    /// Delete/disable region (only if no hosts assigned)
    async fn admin_delete_region(&self, region_id: u64) -> Result<()>;

    /// Count hosts in a region
    async fn admin_count_region_hosts(&self, region_id: u64) -> Result<u64>;

    /// Get comprehensive region statistics
    async fn admin_get_region_stats(&self, region_id: u64) -> Result<RegionStats>;

    // VM OS Image management methods
    /// List all VM OS images with pagination
    async fn admin_list_vm_os_images(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::VmOsImage>, u64)>;

    /// Get VM OS image by ID
    async fn admin_get_vm_os_image(&self, image_id: u64) -> Result<crate::VmOsImage>;

    /// Create a new VM OS image
    async fn admin_create_vm_os_image(&self, image: &crate::VmOsImage) -> Result<u64>;

    /// Update VM OS image information
    async fn admin_update_vm_os_image(&self, image: &crate::VmOsImage) -> Result<()>;

    /// Delete VM OS image (only if not referenced by any VMs)
    async fn admin_delete_vm_os_image(&self, image_id: u64) -> Result<()>;

    // VM Template management methods
    /// List all VM templates with pagination
    async fn list_vm_templates_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<crate::VmTemplate>, i64)>;

    /// Update VM template information
    async fn update_vm_template(&self, template: &crate::VmTemplate) -> Result<()>;

    /// Delete VM template (only if not referenced by any VMs)
    async fn delete_vm_template(&self, template_id: u64) -> Result<()>;

    /// Check how many VMs are using a specific template
    async fn check_vm_template_usage(&self, template_id: u64) -> Result<i64>;

    // Host management methods
    /// List all hosts (including disabled) with regions for admin purposes
    async fn admin_list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<(crate::VmHost, crate::VmHostRegion)>, u64)>;

    // Custom Pricing management methods
    /// Insert a new custom pricing model
    async fn insert_custom_pricing(&self, pricing: &crate::VmCustomPricing) -> Result<u64>;

    /// Update a custom pricing model
    async fn update_custom_pricing(&self, pricing: &crate::VmCustomPricing) -> Result<()>;

    /// Delete a custom pricing model
    async fn delete_custom_pricing(&self, id: u64) -> Result<()>;

    /// Insert a custom pricing disk configuration
    async fn insert_custom_pricing_disk(&self, disk: &crate::VmCustomPricingDisk) -> Result<u64>;

    /// Delete all disk pricing configurations for a pricing model
    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> Result<()>;

    /// Count custom templates using a pricing model
    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> Result<u64>;

    /// List custom templates by pricing model with pagination
    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<crate::VmCustomTemplate>, u64)>;

    /// Insert a custom template
    async fn insert_custom_template(&self, template: &crate::VmCustomTemplate) -> Result<u64>;

    /// Get a custom template by id
    async fn get_custom_template(&self, id: u64) -> Result<crate::VmCustomTemplate>;

    /// Update a custom template
    async fn update_custom_template(&self, template: &crate::VmCustomTemplate) -> Result<()>;

    /// Delete a custom template
    async fn delete_custom_template(&self, id: u64) -> Result<()>;

    /// Count VMs using a custom template
    async fn count_vms_by_custom_template(&self, template_id: u64) -> Result<u64>;

    // Company management methods
    /// List all companies with pagination
    async fn admin_list_companies(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::Company>, u64)>;

    /// Get company by ID
    async fn admin_get_company(&self, company_id: u64) -> Result<crate::Company>;

    /// Create a new company
    async fn admin_create_company(&self, company: &crate::Company) -> Result<u64>;

    /// Update company information
    async fn admin_update_company(&self, company: &crate::Company) -> Result<()>;

    /// Delete company (only if no regions assigned)
    async fn admin_delete_company(&self, company_id: u64) -> Result<()>;

    /// Count regions assigned to a company
    async fn admin_count_company_regions(&self, company_id: u64) -> Result<u64>;

    /// Get payments within a date range (admin only)
    async fn admin_get_payments_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::VmPayment>>;

    /// Get payments within a date range for a specific company (admin only)
    async fn admin_get_payments_by_date_range_and_company(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
    ) -> Result<Vec<crate::VmPayment>>;

    /// Get payments with company and currency info for time-series reporting
    async fn admin_get_payments_with_company_info(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        currency: Option<&str>,
    ) -> Result<Vec<crate::VmPaymentWithCompany>>;

    /// Get referral cost usage report within date range for a specific company
    async fn admin_get_referral_usage_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        ref_code: Option<&str>,
    ) -> Result<Vec<crate::ReferralCostUsage>>;

    // IP Range management methods
    /// List all IP ranges with pagination
    async fn admin_list_ip_ranges(
        &self,
        limit: u64,
        offset: u64,
        region_id: Option<u64>,
    ) -> Result<(Vec<crate::IpRange>, u64)>;

    /// Get IP range by ID
    async fn admin_get_ip_range(&self, ip_range_id: u64) -> Result<crate::IpRange>;

    /// Create a new IP range
    async fn admin_create_ip_range(&self, ip_range: &crate::IpRange) -> Result<u64>;

    /// Update IP range information
    async fn admin_update_ip_range(&self, ip_range: &crate::IpRange) -> Result<()>;

    /// Delete IP range (only if no IP assignments exist)
    async fn admin_delete_ip_range(&self, ip_range_id: u64) -> Result<()>;

    /// Count IP assignments in an IP range
    async fn admin_count_ip_range_assignments(&self, ip_range_id: u64) -> Result<u64>;

    /// List access policies
    async fn admin_list_access_policies(&self) -> Result<Vec<crate::AccessPolicy>>;

    // Access Policy management methods (full CRUD)
    /// List all access policies with pagination
    async fn admin_list_access_policies_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::AccessPolicy>, u64)>;

    /// Get access policy by ID
    async fn admin_get_access_policy(&self, access_policy_id: u64) -> Result<crate::AccessPolicy>;

    /// Create a new access policy
    async fn admin_create_access_policy(&self, access_policy: &crate::AccessPolicy) -> Result<u64>;

    /// Update access policy information
    async fn admin_update_access_policy(&self, access_policy: &crate::AccessPolicy) -> Result<()>;

    /// Delete access policy (only if not used by any IP ranges)
    async fn admin_delete_access_policy(&self, access_policy_id: u64) -> Result<()>;

    /// Count IP ranges using an access policy
    async fn admin_count_access_policy_ip_ranges(&self, access_policy_id: u64) -> Result<u64>;

    /// List routers (helper for access policy management)
    async fn admin_list_routers(&self) -> Result<Vec<crate::Router>>;

    // Router management methods (full CRUD)
    /// List all routers with pagination
    async fn admin_list_routers_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<crate::Router>, u64)>;

    /// Get router by ID
    async fn admin_get_router(&self, router_id: u64) -> Result<crate::Router>;

    /// Create a new router
    async fn admin_create_router(&self, router: &crate::Router) -> Result<u64>;

    /// Update router information
    async fn admin_update_router(&self, router: &crate::Router) -> Result<()>;

    /// Delete router (only if not used by any access policies)
    async fn admin_delete_router(&self, router_id: u64) -> Result<()>;

    /// Count access policies using a router
    async fn admin_count_router_access_policies(&self, router_id: u64) -> Result<u64>;

    // VM management methods with advanced filtering
    /// List VMs with advanced filtering for admin interface
    /// Supports filtering by user_id, host_id, pubkey (hex string), region_id, and deleted status
    /// Returns (vms, total_count_before_pagination)
    async fn admin_list_vms_filtered(
        &self,
        limit: u64,
        offset: u64,
        user_id: Option<u64>,
        host_id: Option<u64>,
        pubkey: Option<&str>,
        region_id: Option<u64>,
        include_deleted: Option<bool>,
    ) -> Result<(Vec<crate::Vm>, u64)>;

    /// Get user by pubkey (hex string)
    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> Result<crate::User>;
}
