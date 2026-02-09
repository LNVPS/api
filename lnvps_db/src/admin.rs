use crate::{AdminRole, AdminRoleAssignment, DbResult, RegionStats};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;

/// Database trait for admin/RBAC operations
#[async_trait]
pub trait AdminDb: Send + Sync {
    /// Get all permissions for a user (computed from all assigned active roles)
    /// Returns a set of tuples where (resource_enum_value, action_enum_value)
    async fn get_user_permissions(&self, user_id: u64) -> DbResult<HashSet<(u16, u16)>>;

    /// Get all active role IDs assigned to a user
    async fn get_user_roles(&self, user_id: u64) -> DbResult<Vec<u64>>;

    /// Check if user has admin privileges (has any active role assignment)
    async fn is_admin_user(&self, user_id: u64) -> DbResult<bool>;

    /// Assign a role to a user
    async fn assign_user_role(&self, user_id: u64, role_id: u64, assigned_by: u64) -> DbResult<()>;

    /// Revoke a role from a user
    async fn revoke_user_role(&self, user_id: u64, role_id: u64) -> DbResult<()>;

    /// Create a new role
    async fn create_role(&self, name: &str, description: Option<&str>) -> DbResult<u64>;

    /// Get role by id
    async fn get_role(&self, role_id: u64) -> DbResult<AdminRole>;

    /// Get role by name
    async fn get_role_by_name(&self, name: &str) -> DbResult<AdminRole>;

    /// List all roles
    async fn list_roles(&self) -> DbResult<Vec<AdminRole>>;

    /// Update role information
    async fn update_role(&self, role: &AdminRole) -> DbResult<()>;

    /// Delete role (only if not system role and no users assigned)
    async fn delete_role(&self, role_id: u64) -> DbResult<()>;

    /// Add permission to role
    async fn add_role_permission(&self, role_id: u64, resource: u16, action: u16) -> DbResult<()>;

    /// Remove permission from role
    async fn remove_role_permission(
        &self,
        role_id: u64,
        resource: u16,
        action: u16,
    ) -> DbResult<()>;

    /// Get all permissions for a role as (resource, action) tuples
    async fn get_role_permissions(&self, role_id: u64) -> DbResult<Vec<(u16, u16)>>;

    /// Get role assignments for a user with full details
    async fn get_user_role_assignments(&self, user_id: u64) -> DbResult<Vec<AdminRoleAssignment>>;

    /// Count users assigned to a role
    async fn count_role_users(&self, role_id: u64) -> DbResult<u64>;

    /// List users with admin data in a single query (paginated)
    /// Returns (users_with_stats, total_count)
    async fn admin_list_users(
        &self,
        limit: u64,
        offset: u64,
        search_pubkey: Option<&str>,
    ) -> DbResult<(Vec<crate::AdminUserInfo>, u64)>;

    // Region management methods
    /// List all regions with pagination
    async fn admin_list_regions(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::VmHostRegion>, u64)>;

    /// Create a new region
    async fn admin_create_region(
        &self,
        name: &str,
        enabled: bool,
        company_id: Option<u64>,
    ) -> DbResult<u64>;

    /// Update region information
    async fn admin_update_region(&self, region: &crate::VmHostRegion) -> DbResult<()>;

    /// Delete/disable region (only if no hosts assigned)
    async fn admin_delete_region(&self, region_id: u64) -> DbResult<()>;

    /// Count hosts in a region
    async fn admin_count_region_hosts(&self, region_id: u64) -> DbResult<u64>;

    /// Get comprehensive region statistics
    async fn admin_get_region_stats(&self, region_id: u64) -> DbResult<RegionStats>;

    // VM OS Image management methods
    /// List all VM OS images with pagination
    async fn admin_list_vm_os_images(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::VmOsImage>, u64)>;

    /// Get VM OS image by ID
    async fn admin_get_vm_os_image(&self, image_id: u64) -> DbResult<crate::VmOsImage>;

    /// Create a new VM OS image
    async fn admin_create_vm_os_image(&self, image: &crate::VmOsImage) -> DbResult<u64>;

    /// Update VM OS image information
    async fn admin_update_vm_os_image(&self, image: &crate::VmOsImage) -> DbResult<()>;

    /// Delete VM OS image (only if not referenced by any VMs)
    async fn admin_delete_vm_os_image(&self, image_id: u64) -> DbResult<()>;

    // VM Template management methods
    /// List all VM templates with pagination
    async fn list_vm_templates_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<crate::VmTemplate>, i64)>;

    /// Update VM template information
    async fn update_vm_template(&self, template: &crate::VmTemplate) -> DbResult<()>;

    /// Delete VM template (only if not referenced by any VMs)
    async fn delete_vm_template(&self, template_id: u64) -> DbResult<()>;

    /// Check how many VMs are using a specific template
    async fn check_vm_template_usage(&self, template_id: u64) -> DbResult<i64>;

    // Host management methods
    /// List all hosts (including disabled) with regions for admin purposes
    async fn admin_list_hosts_with_regions_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::AdminVmHost>, u64)>;

    // Custom Pricing management methods
    /// Insert a new custom pricing model
    async fn insert_custom_pricing(&self, pricing: &crate::VmCustomPricing) -> DbResult<u64>;

    /// Update a custom pricing model
    async fn update_custom_pricing(&self, pricing: &crate::VmCustomPricing) -> DbResult<()>;

    /// Delete a custom pricing model
    async fn delete_custom_pricing(&self, id: u64) -> DbResult<()>;

    /// Insert a custom pricing disk configuration
    async fn insert_custom_pricing_disk(&self, disk: &crate::VmCustomPricingDisk) -> DbResult<u64>;

    /// Delete all disk pricing configurations for a pricing model
    async fn delete_custom_pricing_disks(&self, pricing_id: u64) -> DbResult<()>;

    /// Count custom templates using a pricing model
    async fn count_custom_templates_by_pricing(&self, pricing_id: u64) -> DbResult<u64>;

    /// List custom templates by pricing model with pagination
    async fn list_custom_templates_by_pricing_paginated(
        &self,
        pricing_id: u64,
        limit: i64,
        offset: i64,
    ) -> DbResult<(Vec<crate::VmCustomTemplate>, u64)>;

    /// Insert a custom template
    async fn insert_custom_template(&self, template: &crate::VmCustomTemplate) -> DbResult<u64>;

    /// Update a custom template
    async fn update_custom_template(&self, template: &crate::VmCustomTemplate) -> DbResult<()>;

    /// Delete a custom template
    async fn delete_custom_template(&self, id: u64) -> DbResult<()>;

    /// Count VMs using a custom template
    async fn count_vms_by_custom_template(&self, template_id: u64) -> DbResult<u64>;

    // Company management methods
    /// List all companies with pagination
    async fn admin_list_companies(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::Company>, u64)>;

    /// Get company by ID
    async fn admin_get_company(&self, company_id: u64) -> DbResult<crate::Company>;

    /// Create a new company
    async fn admin_create_company(&self, company: &crate::Company) -> DbResult<u64>;

    /// Update company information
    async fn admin_update_company(&self, company: &crate::Company) -> DbResult<()>;

    /// Delete company (only if no regions assigned)
    async fn admin_delete_company(&self, company_id: u64) -> DbResult<()>;

    /// Count regions assigned to a company
    async fn admin_count_company_regions(&self, company_id: u64) -> DbResult<u64>;

    /// Get payments within a date range (admin only)
    async fn admin_get_payments_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
    ) -> DbResult<Vec<crate::VmPayment>>;

    /// Get payments within a date range for a specific company (admin only)
    async fn admin_get_payments_by_date_range_and_company(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
    ) -> DbResult<Vec<crate::VmPayment>>;

    /// Get payments with company and currency info for time-series reporting
    async fn admin_get_payments_with_company_info(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        currency: Option<&str>,
    ) -> DbResult<Vec<crate::VmPaymentWithCompany>>;

    /// Get referral cost usage report within date range for a specific company
    async fn admin_get_referral_usage_by_date_range(
        &self,
        start_date: chrono::DateTime<chrono::Utc>,
        end_date: chrono::DateTime<chrono::Utc>,
        company_id: u64,
        ref_code: Option<&str>,
    ) -> DbResult<Vec<crate::ReferralCostUsage>>;

    // IP Range management methods
    /// List all IP ranges with pagination
    async fn admin_list_ip_ranges(
        &self,
        limit: u64,
        offset: u64,
        region_id: Option<u64>,
    ) -> DbResult<(Vec<crate::IpRange>, u64)>;

    /// Get IP range by ID
    async fn admin_get_ip_range(&self, ip_range_id: u64) -> DbResult<crate::IpRange>;

    /// Create a new IP range
    async fn admin_create_ip_range(&self, ip_range: &crate::IpRange) -> DbResult<u64>;

    /// Update IP range information
    async fn admin_update_ip_range(&self, ip_range: &crate::IpRange) -> DbResult<()>;

    /// Delete IP range (only if no IP assignments exist)
    async fn admin_delete_ip_range(&self, ip_range_id: u64) -> DbResult<()>;

    /// Count IP assignments in an IP range
    async fn admin_count_ip_range_assignments(&self, ip_range_id: u64) -> DbResult<u64>;

    /// List access policies
    async fn admin_list_access_policies(&self) -> DbResult<Vec<crate::AccessPolicy>>;

    // Access Policy management methods (full CRUD)
    /// List all access policies with pagination
    async fn admin_list_access_policies_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::AccessPolicy>, u64)>;

    /// Get access policy by ID
    async fn admin_get_access_policy(&self, access_policy_id: u64)
    -> DbResult<crate::AccessPolicy>;

    /// Create a new access policy
    async fn admin_create_access_policy(
        &self,
        access_policy: &crate::AccessPolicy,
    ) -> DbResult<u64>;

    /// Update access policy information
    async fn admin_update_access_policy(&self, access_policy: &crate::AccessPolicy)
    -> DbResult<()>;

    /// Delete access policy (only if not used by any IP ranges)
    async fn admin_delete_access_policy(&self, access_policy_id: u64) -> DbResult<()>;

    /// Count IP ranges using an access policy
    async fn admin_count_access_policy_ip_ranges(&self, access_policy_id: u64) -> DbResult<u64>;

    /// List routers (helper for access policy management)
    async fn admin_list_routers(&self) -> DbResult<Vec<crate::Router>>;

    // Router management methods (full CRUD)
    /// List all routers with pagination
    async fn admin_list_routers_paginated(
        &self,
        limit: u64,
        offset: u64,
    ) -> DbResult<(Vec<crate::Router>, u64)>;

    /// Get router by ID
    async fn admin_get_router(&self, router_id: u64) -> DbResult<crate::Router>;

    /// Create a new router
    async fn admin_create_router(&self, router: &crate::Router) -> DbResult<u64>;

    /// Update router information
    async fn admin_update_router(&self, router: &crate::Router) -> DbResult<()>;

    /// Delete router (only if not used by any access policies)
    async fn admin_delete_router(&self, router_id: u64) -> DbResult<()>;

    /// Count access policies using a router
    async fn admin_count_router_access_policies(&self, router_id: u64) -> DbResult<u64>;

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
    ) -> DbResult<(Vec<crate::Vm>, u64)>;

    /// Get user by pubkey (hex string)
    async fn get_user_by_pubkey(&self, pubkey: &[u8]) -> DbResult<crate::User>;

    // VM IP Assignment management methods
    /// List all VM IP assignments with pagination and filtering
    async fn admin_list_vm_ip_assignments(
        &self,
        limit: u64,
        offset: u64,
        vm_id: Option<u64>,
        ip_range_id: Option<u64>,
        ip: Option<&str>,
        include_deleted: Option<bool>,
    ) -> DbResult<(Vec<crate::VmIpAssignment>, u64)>;

    /// Get VM IP assignment by ID
    async fn admin_get_vm_ip_assignment(
        &self,
        assignment_id: u64,
    ) -> DbResult<crate::VmIpAssignment>;

    /// Create a new VM IP assignment
    async fn admin_create_vm_ip_assignment(
        &self,
        assignment: &crate::VmIpAssignment,
    ) -> DbResult<u64>;

    /// Update VM IP assignment
    async fn admin_update_vm_ip_assignment(
        &self,
        assignment: &crate::VmIpAssignment,
    ) -> DbResult<()>;

    /// Delete VM IP assignment (soft delete)
    async fn admin_delete_vm_ip_assignment(&self, assignment_id: u64) -> DbResult<()>;
}
