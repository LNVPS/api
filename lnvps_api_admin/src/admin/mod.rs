use crate::admin::access_policies::{
    admin_create_access_policy, admin_delete_access_policy, admin_get_access_policy,
    admin_list_access_policies, admin_update_access_policy,
};
use crate::admin::companies::{
    admin_create_company, admin_delete_company, admin_get_company, admin_list_companies,
    admin_update_company,
};
use crate::admin::cost_plans::{
    admin_create_cost_plan, admin_delete_cost_plan, admin_get_cost_plan,
    admin_list_cost_plans, admin_update_cost_plan,
};
use crate::admin::custom_pricing::{
    admin_copy_custom_pricing, admin_create_custom_pricing, admin_delete_custom_pricing,
    admin_get_custom_pricing, admin_list_custom_pricing, admin_update_custom_pricing,
};
use crate::admin::ip_ranges::{
    admin_create_ip_range, admin_delete_ip_range, admin_get_ip_range,
    admin_list_ip_ranges, admin_update_ip_range,
};
use crate::admin::hosts::{
    admin_create_host, admin_get_host, admin_get_host_disk, admin_list_host_disks,
    admin_list_hosts, admin_update_host, admin_update_host_disk,
};
use crate::admin::regions::{
    admin_create_region, admin_delete_region, admin_get_region, admin_list_regions,
    admin_update_region,
};
use crate::admin::roles::{
    admin_assign_user_role, admin_create_role, admin_delete_role, admin_get_my_roles,
    admin_get_role, admin_get_user_roles, admin_list_roles, admin_revoke_user_role,
    admin_update_role,
};
use crate::admin::users::{admin_list_users, admin_update_user};
use crate::admin::vm_os_images::{
    admin_create_vm_os_image, admin_delete_vm_os_image, admin_get_vm_os_image,
    admin_list_vm_os_images, admin_update_vm_os_image,
};
use crate::admin::vm_templates::{
    admin_create_vm_template, admin_delete_vm_template, admin_get_vm_template,
    admin_list_vm_templates, admin_update_vm_template,
};
use crate::admin::routers::{
    admin_create_router, admin_delete_router, admin_get_router, admin_list_routers,
    admin_update_router,
};
use crate::admin::vms::{
    admin_delete_vm, admin_get_vm, admin_list_vms, admin_start_vm, admin_stop_vm,
    admin_list_vm_history, admin_get_vm_history, admin_list_vm_payments, admin_get_vm_payment,
};
use crate::admin::reports::{admin_monthly_sales_report};
use rocket::{routes, Route};

pub mod access_policies;
pub mod auth;
pub mod companies;
pub mod cost_plans;
pub mod custom_pricing;
pub mod hosts;
pub mod ip_ranges;
pub mod model;
pub mod regions;
pub mod reports;
pub mod roles;
pub mod routers;
pub mod users;
pub mod vm_os_images;
pub mod vm_templates;
pub mod vms;

pub fn admin_routes() -> Vec<Route> {
    routes![
        // User management
        admin_list_users,
        admin_update_user,
        // VM management
        admin_list_vms,
        admin_get_vm,
        admin_start_vm,
        admin_stop_vm,
        admin_delete_vm,
        // VM History management
        admin_list_vm_history,
        admin_get_vm_history,
        // VM Payment management
        admin_list_vm_payments,
        admin_get_vm_payment,
        // Host management
        admin_list_hosts,
        admin_get_host,
        admin_create_host,
        admin_update_host,
        // Host disk management
        admin_list_host_disks,
        admin_get_host_disk,
        admin_update_host_disk,
        // Region management
        admin_list_regions,
        admin_get_region,
        admin_create_region,
        admin_update_region,
        admin_delete_region,
        // Role management
        admin_list_roles,
        admin_get_role,
        admin_create_role,
        admin_update_role,
        admin_delete_role,
        // User role assignments
        admin_get_user_roles,
        admin_assign_user_role,
        admin_revoke_user_role,
        admin_get_my_roles,
        // VM OS Image management
        admin_list_vm_os_images,
        admin_get_vm_os_image,
        admin_create_vm_os_image,
        admin_update_vm_os_image,
        admin_delete_vm_os_image,
        // VM Template management
        admin_list_vm_templates,
        admin_get_vm_template,
        admin_create_vm_template,
        admin_update_vm_template,
        admin_delete_vm_template,
        // Custom Pricing management
        admin_list_custom_pricing,
        admin_get_custom_pricing,
        admin_create_custom_pricing,
        admin_update_custom_pricing,
        admin_delete_custom_pricing,
        admin_copy_custom_pricing,
        // Company management
        admin_list_companies,
        admin_get_company,
        admin_create_company,
        admin_update_company,
        admin_delete_company,
        // Cost Plan management
        admin_list_cost_plans,
        admin_get_cost_plan,
        admin_create_cost_plan,
        admin_update_cost_plan,
        admin_delete_cost_plan,
        // IP Range management
        admin_list_ip_ranges,
        admin_get_ip_range,
        admin_create_ip_range,
        admin_update_ip_range,
        admin_delete_ip_range,
        // Access Policy management
        admin_list_access_policies,
        admin_get_access_policy,
        admin_create_access_policy,
        admin_update_access_policy,
        admin_delete_access_policy,
        // Router management (full CRUD)
        admin_list_routers,
        admin_get_router,
        admin_create_router,
        admin_update_router,
        admin_delete_router,
        // Reports
        admin_monthly_sales_report,
    ]
}
