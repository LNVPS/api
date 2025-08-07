use anyhow::anyhow;
use chrono::{DateTime, Utc};
use lnvps_api_common::{VmRunningState, ApiDiskType, ApiDiskInterface, ApiOsDistribution, ApiVmCostPlanIntervalType};
use lnvps_db::{AdminAction, AdminResource, AdminRole, VmHostKind, IpRangeAllocationMode, NetworkAccessPolicy, RouterKind, OsDistribution, VmHistory, VmHistoryActionType, VmPayment, PaymentMethod};
use rocket_okapi::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

// Admin API Enums - Using enums from common crate where available, creating new ones only where needed

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdminVmHostKind {
    Proxmox,
    Libvirt,
}

impl From<VmHostKind> for AdminVmHostKind {
    fn from(host_kind: VmHostKind) -> Self {
        match host_kind {
            VmHostKind::Proxmox => AdminVmHostKind::Proxmox,
            VmHostKind::LibVirt => AdminVmHostKind::Libvirt,
        }
    }
}

impl From<AdminVmHostKind> for VmHostKind {
    fn from(admin_host_kind: AdminVmHostKind) -> Self {
        match admin_host_kind {
            AdminVmHostKind::Proxmox => VmHostKind::Proxmox,
            AdminVmHostKind::Libvirt => VmHostKind::LibVirt,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminIpRangeAllocationMode {
    Random,
    Sequential,
    SlaacEui64,
}

impl From<IpRangeAllocationMode> for AdminIpRangeAllocationMode {
    fn from(allocation_mode: IpRangeAllocationMode) -> Self {
        match allocation_mode {
            IpRangeAllocationMode::Random => AdminIpRangeAllocationMode::Random,
            IpRangeAllocationMode::Sequential => AdminIpRangeAllocationMode::Sequential,
            IpRangeAllocationMode::SlaacEui64 => AdminIpRangeAllocationMode::SlaacEui64,
        }
    }
}

impl From<AdminIpRangeAllocationMode> for IpRangeAllocationMode {
    fn from(admin_allocation_mode: AdminIpRangeAllocationMode) -> Self {
        match admin_allocation_mode {
            AdminIpRangeAllocationMode::Random => IpRangeAllocationMode::Random,
            AdminIpRangeAllocationMode::Sequential => IpRangeAllocationMode::Sequential,
            AdminIpRangeAllocationMode::SlaacEui64 => IpRangeAllocationMode::SlaacEui64,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminNetworkAccessPolicy {
    StaticArp,
}

impl From<NetworkAccessPolicy> for AdminNetworkAccessPolicy {
    fn from(policy: NetworkAccessPolicy) -> Self {
        match policy {
            NetworkAccessPolicy::StaticArp => AdminNetworkAccessPolicy::StaticArp,
        }
    }
}

impl From<AdminNetworkAccessPolicy> for NetworkAccessPolicy {
    fn from(admin_policy: AdminNetworkAccessPolicy) -> Self {
        match admin_policy {
            AdminNetworkAccessPolicy::StaticArp => NetworkAccessPolicy::StaticArp,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminRouterKind {
    Mikrotik,
    OvhAdditionalIp,
}

impl From<RouterKind> for AdminRouterKind {
    fn from(router_kind: RouterKind) -> Self {
        match router_kind {
            RouterKind::Mikrotik => AdminRouterKind::Mikrotik,
            RouterKind::OvhAdditionalIp => AdminRouterKind::OvhAdditionalIp,
        }
    }
}

impl From<AdminRouterKind> for RouterKind {
    fn from(admin_router_kind: AdminRouterKind) -> Self {
        match admin_router_kind {
            AdminRouterKind::Mikrotik => RouterKind::Mikrotik,
            AdminRouterKind::OvhAdditionalIp => RouterKind::OvhAdditionalIp,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserStatus {
    Active,
    Suspended,
    Deleted,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserRole {
    SuperAdmin,
    Admin,
    ReadOnly,
}

#[derive(Serialize, JsonSchema)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminUserInfo {
    pub id: u64,
    pub pubkey: String, // hex encoded
    pub created: DateTime<Utc>,
    pub email: Option<String>,
    pub contact_nip17: bool,
    pub contact_email: bool,
    pub country_code: Option<String>,
    pub billing_name: Option<String>,
    pub billing_address_1: Option<String>,
    pub billing_address_2: Option<String>,
    pub billing_city: Option<String>,
    pub billing_state: Option<String>,
    pub billing_postcode: Option<String>,
    pub billing_tax_id: Option<String>,
    // Admin-specific fields
    pub vm_count: u64,
    pub last_login: Option<DateTime<Utc>>,
    pub is_admin: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminUserUpdateRequest {
    pub email: Option<String>,
    pub contact_nip17: Option<bool>,
    pub contact_email: Option<bool>,
    pub country_code: Option<String>,
    pub billing_name: Option<String>,
    pub billing_address_1: Option<String>,
    pub billing_address_2: Option<String>,
    pub billing_city: Option<String>,
    pub billing_state: Option<String>,
    pub billing_postcode: Option<String>,
    pub billing_tax_id: Option<String>,
    // Admin fields
    pub notes: Option<String>,
    pub status: Option<AdminUserStatus>,
    pub admin_role: Option<AdminUserRole>, // null to remove
}

#[derive(Serialize, JsonSchema)]
pub struct AdminUserStats {
    pub total_users: u64,
    pub active_users_30d: u64,
    pub new_users_30d: u64,
    pub users_by_country: HashMap<String, u64>,
}

// RBAC API Models

#[derive(Serialize, JsonSchema)]
pub struct AdminRoleInfo {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub is_system_role: bool,
    pub permissions: Vec<String>, // Formatted as "resource::action"
    pub user_count: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>, // Formatted as "resource::action"
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>, // Formatted as "resource::action"
}

#[derive(Serialize, JsonSchema)]
pub struct UserRoleInfo {
    pub role: AdminRoleInfo,
    pub assigned_by: Option<u64>,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Deserialize, JsonSchema)]
pub struct AssignRoleRequest {
    pub role_id: u64,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<lnvps_db::User> for AdminUserInfo {
    fn from(user: lnvps_db::User) -> Self {
        Self {
            id: user.id,
            pubkey: hex::encode(&user.pubkey),
            created: user.created,
            email: user.email,
            contact_nip17: user.contact_nip17,
            contact_email: user.contact_email,
            country_code: user.country_code,
            billing_name: user.billing_name,
            billing_address_1: user.billing_address_1,
            billing_address_2: user.billing_address_2,
            billing_city: user.billing_city,
            billing_state: user.billing_state,
            billing_postcode: user.billing_postcode,
            billing_tax_id: user.billing_tax_id,
            // Admin-specific fields will be filled by the handler
            vm_count: 0,
            last_login: None,
            is_admin: false,
        }
    }
}

impl From<AdminRole> for AdminRoleInfo {
    fn from(role: AdminRole) -> Self {
        Self {
            id: role.id,
            name: role.name,
            description: role.description,
            is_system_role: role.is_system_role,
            permissions: Vec::new(), // Will be filled by handler
            user_count: 0,           // Will be filled by handler
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }
}

// VM Management Models

// IP address with IDs for admin linking
#[derive(Serialize, JsonSchema)]
pub struct AdminVmIpAddress {
    /// IP assignment ID for linking
    pub id: u64,
    /// IP address
    pub ip: String,
    /// IP range ID for linking to range details
    pub range_id: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminVmInfo {
    // Core VM information (moved from ApiVmStatus)
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// When the VM was created
    pub created: DateTime<Utc>,
    /// When the VM expires
    pub expires: DateTime<Utc>,
    /// Network MAC address
    pub mac_address: String,
    /// OS Image ID for linking
    pub image_id: u64,
    /// OS Image name/version with distribution (e.g., "Ubuntu 22.04 Server")
    pub image_name: String,
    /// Template ID for linking (standard template if used)
    pub template_id: u64,
    /// Template name (simplified, no cost details)
    pub template_name: String,
    /// Custom template ID for linking (custom template if used)
    pub custom_template_id: Option<u64>,
    /// Indicates whether this VM uses a standard template (true) or custom template (false)
    pub is_standard_template: bool,
    /// SSH key ID for linking
    pub ssh_key_id: u64,
    /// SSH key name (simplified)
    pub ssh_key_name: String,
    /// IP addresses with IDs for linking
    pub ip_addresses: Vec<AdminVmIpAddress>,
    /// Full VM running state with metrics (CPU usage, memory usage, etc.)
    pub running_state: Option<VmRunningState>,

    // VM Resources
    /// Number of CPU cores allocated to this VM
    pub cpu: u16,
    /// Memory in bytes allocated to this VM  
    pub memory: u64,
    /// Disk size in bytes
    pub disk_size: u64,
    /// Disk type (HDD/SSD)
    pub disk_type: ApiDiskType,
    /// Disk interface (SATA/SCSI/PCIe)
    pub disk_interface: ApiDiskInterface,

    // Admin-specific fields
    pub host_id: u64,
    pub user_id: u64,
    pub user_pubkey: String, // hex encoded
    pub user_email: Option<String>,
    pub host_name: Option<String>,
    pub region_name: Option<String>,
    pub deleted: bool,
    pub ref_code: Option<String>,
}

impl AdminVmInfo {
    pub async fn from_vm_with_admin_data(
        db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
        vm: &lnvps_db::Vm,
        running_state: Option<VmRunningState>,
        host_id: u64,
        user_id: u64,
        user_pubkey: String,
        user_email: Option<String>,
        host_name: Option<String>,
        region_name: Option<String>,
        deleted: bool,
        ref_code: Option<String>,
    ) -> anyhow::Result<Self> {
        let image = db.get_os_image(vm.image_id).await?;
        let ssh_key = db.get_user_ssh_key(vm.ssh_key_id).await?;
        let ips = db.list_vm_ip_assignments(vm.id).await?;

        // Get template info and VM resources
        let (template_id, template_name, custom_template_id, is_standard_template, cpu, memory, disk_size, disk_type, disk_interface) = 
            if let Some(template_id) = vm.template_id {
                let template = db.get_vm_template(template_id).await?;
                (
                    template_id, 
                    template.name,
                    None,
                    true,
                    template.cpu,
                    template.memory,
                    template.disk_size,
                    ApiDiskType::from(template.disk_type),
                    ApiDiskInterface::from(template.disk_interface),
                )
            } else if let Some(custom_template_id) = vm.custom_template_id {
                let custom_template = db.get_custom_vm_template(custom_template_id).await?;
                let pricing = db.get_custom_pricing(custom_template.pricing_id).await?;
                (
                    0, // No standard template ID
                    format!("Custom - {}", pricing.name),
                    Some(custom_template_id),
                    false,
                    custom_template.cpu,
                    custom_template.memory,
                    custom_template.disk_size,
                    ApiDiskType::from(custom_template.disk_type),
                    ApiDiskInterface::from(custom_template.disk_interface),
                )
            } else {
                (0, "Unknown".to_string(), None, true, 0, 0, 0, ApiDiskType::HDD, ApiDiskInterface::SATA)
            };

        let mut ip_addresses = Vec::new();
        for ip in ips {
            ip_addresses.push(AdminVmIpAddress {
                id: ip.id,
                ip: ip.ip,
                range_id: ip.ip_range_id,
            });
        }

        Ok(Self {
            id: vm.id,
            created: vm.created,
            expires: vm.expires,
            mac_address: vm.mac_address.clone(),
            image_id: vm.image_id,
            image_name: format!("{} {} {}", image.distribution, image.flavour, image.version),
            template_id,
            template_name,
            custom_template_id,
            is_standard_template,
            ssh_key_id: vm.ssh_key_id,
            ssh_key_name: ssh_key.name,
            ip_addresses,
            running_state,
            cpu,
            memory,
            disk_size,
            disk_type,
            disk_interface,
            host_id,
            user_id,
            user_pubkey,
            user_email,
            host_name,
            region_name,
            deleted,
            ref_code,
        })
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminVmAction {
    Start,
    Stop,
    Delete,
}

#[derive(Deserialize, JsonSchema)]
pub struct VmActionRequest {
    pub action: AdminVmAction,
}

#[derive(Eq, PartialEq, Clone, Hash)]
pub struct Permission {
    pub resource: AdminResource,
    pub action: AdminAction,
}

impl FromStr for Permission {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split("::");
        let resource = split
            .next()
            .ok_or(anyhow!("resource is missing from '{}'", s))?;
        let action = split
            .next()
            .ok_or(anyhow!("action is missing from '{}'", s))?;
        Ok(Self {
            resource: resource.parse()?,
            action: action.parse()?,
        })
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.resource, self.action)
    }
}

#[derive(Serialize, JsonSchema)]
pub struct AdminHostInfo {
    pub id: u64,
    pub name: String,
    pub kind: AdminVmHostKind,
    pub region: AdminHostRegion,
    pub ip: String,
    pub cpu: u16,
    pub memory: u64,
    pub enabled: bool,
    pub load_cpu: f32,
    pub load_memory: f32,
    pub load_disk: f32,
    pub vlan_id: Option<u64>,
    pub disks: Vec<AdminHostDisk>,
    // Calculated load metrics
    pub calculated_load: CalculatedHostLoad,
}

#[derive(Serialize, JsonSchema)]
pub struct CalculatedHostLoad {
    /// Overall load percentage (0.0-1.0)
    pub overall_load: f32,
    /// CPU load percentage (0.0-1.0)
    pub cpu_load: f32,
    /// Memory load percentage (0.0-1.0)  
    pub memory_load: f32,
    /// Disk load percentage (0.0-1.0)
    pub disk_load: f32,
    /// Available CPU cores
    pub available_cpu: u16,
    /// Available memory in bytes
    pub available_memory: u64,
    /// Number of active VMs on this host
    pub active_vms: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminHostRegion {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminHostDisk {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    pub enabled: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminRegionInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub company_id: Option<u64>,
    pub host_count: u64,
    pub total_vms: u64,
    pub total_cpu_cores: u64,
    pub total_memory_bytes: u64,
    pub total_ip_assignments: u64,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateRegionRequest {
    pub name: String,
    pub company_id: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateRegionRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub company_id: Option<u64>,
}

impl AdminHostInfo {
    pub fn from_host_and_region(host: lnvps_db::VmHost, region: lnvps_db::VmHostRegion) -> Self {
        Self {
            id: host.id,
            name: host.name,
            kind: AdminVmHostKind::from(host.kind),
            region: AdminHostRegion {
                id: region.id,
                name: region.name,
                enabled: region.enabled,
            },
            ip: host.ip,
            cpu: host.cpu,
            memory: host.memory,
            enabled: host.enabled,
            load_cpu: host.load_cpu,
            load_memory: host.load_memory,
            load_disk: host.load_disk,
            vlan_id: host.vlan_id,
            disks: Vec::new(), // Empty disks - should be populated separately
            calculated_load: CalculatedHostLoad {
                overall_load: 0.0,
                cpu_load: 0.0,
                memory_load: 0.0,
                disk_load: 0.0,
                available_cpu: host.cpu,
                available_memory: host.memory,
                active_vms: 0,
            },
        }
    }

    pub fn from_host_region_and_disks(
        host: lnvps_db::VmHost,
        region: lnvps_db::VmHostRegion,
        disks: Vec<lnvps_db::VmHostDisk>,
    ) -> Self {
        let admin_disks = disks
            .into_iter()
            .map(|disk| AdminHostDisk {
                id: disk.id,
                name: disk.name,
                size: disk.size,
                kind: ApiDiskType::from(disk.kind),
                interface: ApiDiskInterface::from(disk.interface),
                enabled: disk.enabled,
            })
            .collect();

        Self {
            id: host.id,
            name: host.name,
            kind: AdminVmHostKind::from(host.kind),
            region: AdminHostRegion {
                id: region.id,
                name: region.name,
                enabled: region.enabled,
            },
            ip: host.ip,
            cpu: host.cpu,
            memory: host.memory,
            enabled: host.enabled,
            load_cpu: host.load_cpu,
            load_memory: host.load_memory,
            load_disk: host.load_disk,
            vlan_id: host.vlan_id,
            disks: admin_disks,
            calculated_load: CalculatedHostLoad {
                overall_load: 0.0,
                cpu_load: 0.0,
                memory_load: 0.0,
                disk_load: 0.0,
                available_cpu: host.cpu,
                available_memory: host.memory,
                active_vms: 0,
            },
        }
    }

    pub fn from_host_capacity(
        capacity: &lnvps_api_common::HostCapacity,
        region: lnvps_db::VmHostRegion,
        disks: Vec<lnvps_db::VmHostDisk>,
        active_vms: u64,
    ) -> Self {
        let admin_disks = disks
            .into_iter()
            .map(|disk| AdminHostDisk {
                id: disk.id,
                name: disk.name,
                size: disk.size,
                kind: ApiDiskType::from(disk.kind),
                interface: ApiDiskInterface::from(disk.interface),
                enabled: disk.enabled,
            })
            .collect();

        Self {
            id: capacity.host.id,
            name: capacity.host.name.clone(),
            kind: AdminVmHostKind::from(capacity.host.kind.clone()),
            region: AdminHostRegion {
                id: region.id,
                name: region.name,
                enabled: region.enabled,
            },
            ip: capacity.host.ip.clone(),
            cpu: capacity.host.cpu,
            memory: capacity.host.memory,
            enabled: capacity.host.enabled,
            load_cpu: capacity.host.load_cpu,
            load_memory: capacity.host.load_memory,
            load_disk: capacity.host.load_disk,
            vlan_id: capacity.host.vlan_id,
            disks: admin_disks,
            calculated_load: CalculatedHostLoad {
                overall_load: capacity.load(),
                cpu_load: capacity.cpu_load(),
                memory_load: capacity.memory_load(),
                disk_load: capacity.disk_load(),
                available_cpu: capacity.available_cpu(),
                available_memory: capacity.available_memory(),
                active_vms,
            },
        }
    }
}

// VM OS Image Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminVmOsImageInfo {
    pub id: u64,
    pub distribution: ApiOsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    pub url: String,
    pub default_username: Option<String>,
    pub active_vm_count: i64, // Number of active (non-deleted) VMs using this image
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateVmOsImageRequest {
    pub distribution: ApiOsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    pub url: String,
    pub default_username: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateVmOsImageRequest {
    pub distribution: Option<ApiOsDistribution>,
    pub flavour: Option<String>,
    pub version: Option<String>,
    pub enabled: Option<bool>,
    pub release_date: Option<DateTime<Utc>>,
    pub url: Option<String>,
    pub default_username: Option<String>,
}

impl AdminVmOsImageInfo {
    pub async fn from_db_with_vm_count(
        db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
        image: lnvps_db::VmOsImage,
    ) -> anyhow::Result<Self> {
        // Count active VMs using this image
        let all_vms = db.list_vms().await.unwrap_or_default();
        let active_vm_count = all_vms
            .iter()
            .filter(|vm| vm.image_id == image.id && !vm.deleted)
            .count() as i64;
        
        Ok(Self {
            id: image.id,
            distribution: ApiOsDistribution::from(image.distribution),
            flavour: image.flavour,
            version: image.version,
            enabled: image.enabled,
            release_date: image.release_date,
            url: image.url,
            default_username: image.default_username,
            active_vm_count,
        })
    }
}

impl From<lnvps_db::VmOsImage> for AdminVmOsImageInfo {
    fn from(image: lnvps_db::VmOsImage) -> Self {
        Self {
            id: image.id,
            distribution: ApiOsDistribution::from(image.distribution),
            flavour: image.flavour,
            version: image.version,
            enabled: image.enabled,
            release_date: image.release_date,
            url: image.url,
            default_username: image.default_username,
            active_vm_count: 0, // Default when not using the async method
        }
    }
}

fn api_os_distribution_to_db(api_distribution: ApiOsDistribution) -> OsDistribution {
    match api_distribution {
        ApiOsDistribution::Ubuntu => OsDistribution::Ubuntu,
        ApiOsDistribution::Debian => OsDistribution::Debian,
        ApiOsDistribution::CentOS => OsDistribution::CentOS,
        ApiOsDistribution::Fedora => OsDistribution::Fedora,
        ApiOsDistribution::FreeBSD => OsDistribution::FreeBSD,
        ApiOsDistribution::OpenSUSE => OsDistribution::OpenSUSE,
        ApiOsDistribution::ArchLinux => OsDistribution::ArchLinux,
        ApiOsDistribution::RedHatEnterprise => OsDistribution::RedHatEnterprise,
    }
}

impl CreateVmOsImageRequest {
    pub fn to_vm_os_image(&self) -> anyhow::Result<lnvps_db::VmOsImage> {
        let distribution = api_os_distribution_to_db(self.distribution);

        Ok(lnvps_db::VmOsImage {
            id: 0, // Will be set by database
            distribution,
            flavour: self.flavour.clone(),
            version: self.version.clone(),
            enabled: self.enabled,
            release_date: self.release_date,
            url: self.url.clone(),
            default_username: self.default_username.clone(),
        })
    }
}

// VM Template Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminVmTemplateInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
    pub cost_plan_id: u64,
    pub region_id: u64,
    pub region_name: Option<String>,
    pub cost_plan_name: Option<String>,
    pub active_vm_count: i64, // Number of active (non-deleted) VMs using this template
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminCreateVmTemplateRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
    pub cost_plan_id: Option<u64>, // Optional - if not provided, will auto-create cost plan
    pub region_id: u64,
    // Cost plan creation fields - used when cost_plan_id is not provided
    pub cost_plan_name: Option<String>, // Defaults to "{template_name} Cost Plan"
    pub cost_plan_amount: Option<f32>, // Required if cost_plan_id not provided
    pub cost_plan_currency: Option<String>, // Defaults to "USD"
    pub cost_plan_interval_amount: Option<u64>, // Defaults to 1
    pub cost_plan_interval_type: Option<ApiVmCostPlanIntervalType>, // Defaults to Month
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminUpdateVmTemplateRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub expires: Option<Option<DateTime<Utc>>>,
    pub cpu: Option<u16>,
    pub memory: Option<u64>,
    pub disk_size: Option<u64>,
    pub disk_type: Option<ApiDiskType>,
    pub disk_interface: Option<ApiDiskInterface>,
    pub cost_plan_id: Option<u64>,
    pub region_id: Option<u64>,
    // Cost plan update fields - will update the associated cost plan for this template
    pub cost_plan_name: Option<String>,
    pub cost_plan_amount: Option<f32>,
    pub cost_plan_currency: Option<String>,
    pub cost_plan_interval_amount: Option<u64>,
    pub cost_plan_interval_type: Option<ApiVmCostPlanIntervalType>,
}

// Common response structures
#[derive(Serialize, JsonSchema)]
pub struct AdminListResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminSingleResponse<T> {
    pub data: T,
}

// Custom Pricing Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminCustomPricingInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub region_name: Option<String>,
    pub currency: String,
    pub cpu_cost: f32,
    pub memory_cost: f32,
    pub ip4_cost: f32,
    pub ip6_cost: f32,
    pub disk_pricing: Vec<AdminCustomPricingDisk>,
    pub template_count: u64,
}

#[derive(Serialize, JsonSchema)]
pub struct AdminCustomPricingDisk {
    pub id: u64,
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    pub cost: f32,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateCustomPricingRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub expires: Option<Option<DateTime<Utc>>>,
    pub region_id: Option<u64>,
    pub currency: Option<String>,
    pub cpu_cost: Option<f32>,
    pub memory_cost: Option<f32>,
    pub ip4_cost: Option<f32>,
    pub ip6_cost: Option<f32>,
    pub disk_pricing: Option<Vec<CreateCustomPricingDisk>>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateCustomPricingRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub currency: String,
    pub cpu_cost: f32,
    pub memory_cost: f32,
    pub ip4_cost: f32,
    pub ip6_cost: f32,
    pub disk_pricing: Vec<CreateCustomPricingDisk>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateCustomPricingDisk {
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    pub cost: f32,
}

#[derive(Deserialize, JsonSchema)]
pub struct CopyCustomPricingRequest {
    pub name: String,
    pub region_id: Option<u64>,
    pub enabled: Option<bool>,
}

// Company Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminCompanyInfo {
    pub id: u64,
    pub created: DateTime<Utc>,
    pub name: String,
    pub address_1: Option<String>,
    pub address_2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country_code: Option<String>,
    pub tax_id: Option<String>,
    pub postcode: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub base_currency: String,
    pub region_count: u64, // Number of regions assigned to this company
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateCompanyRequest {
    pub name: String,
    pub address_1: Option<String>,
    pub address_2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country_code: Option<String>,
    pub tax_id: Option<String>,
    pub postcode: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub base_currency: Option<String>, // 3-letter ISO currency code (default: EUR)
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateCompanyRequest {
    pub name: Option<String>,
    pub address_1: Option<String>,
    pub address_2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub country_code: Option<String>,
    pub tax_id: Option<String>,
    pub postcode: Option<String>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub base_currency: Option<String>, // 3-letter ISO currency code
}

impl From<lnvps_db::Company> for AdminCompanyInfo {
    fn from(company: lnvps_db::Company) -> Self {
        Self {
            id: company.id,
            created: company.created,
            name: company.name,
            address_1: company.address_1,
            address_2: company.address_2,
            city: company.city,
            state: company.state,
            country_code: company.country_code,
            tax_id: company.tax_id,
            postcode: company.postcode,
            phone: company.phone,
            email: company.email,
            base_currency: company.base_currency,
            region_count: 0, // Will be filled by handler
        }
    }
}

// IP Range Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminIpRangeInfo {
    pub id: u64,
    pub cidr: String,
    pub gateway: String,
    pub enabled: bool,
    pub region_id: u64,
    pub region_name: Option<String>, // Populated with region name
    pub reverse_zone_id: Option<String>,
    pub access_policy_id: Option<u64>,
    pub access_policy_name: Option<String>, // Populated with access policy name
    pub allocation_mode: AdminIpRangeAllocationMode,
    pub use_full_range: bool,
    pub assignment_count: u64, // Number of active IP assignments in this range
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateIpRangeRequest {
    pub cidr: String,
    pub gateway: String,
    pub enabled: Option<bool>, // Default: true
    pub region_id: u64,
    pub reverse_zone_id: Option<String>,
    pub access_policy_id: Option<u64>,
    pub allocation_mode: Option<AdminIpRangeAllocationMode>, // default: "sequential"
    pub use_full_range: Option<bool>, // Default: false
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateIpRangeRequest {
    pub cidr: Option<String>,
    pub gateway: Option<String>,
    pub enabled: Option<bool>,
    pub region_id: Option<u64>,
    pub reverse_zone_id: Option<Option<String>>, // Use Option<Option<String>> to allow setting to null
    pub access_policy_id: Option<Option<u64>>, // Use Option<Option<u64>> to allow setting to null
    pub allocation_mode: Option<AdminIpRangeAllocationMode>,
    pub use_full_range: Option<bool>,
}

// Access Policy Models for IP range management
#[derive(Serialize, JsonSchema)]
pub struct AdminAccessPolicyInfo {
    pub id: u64,
    pub name: String,
    pub kind: AdminNetworkAccessPolicy,
    pub router_id: Option<u64>,
    pub interface: Option<String>,
}

impl From<lnvps_db::IpRange> for AdminIpRangeInfo {
    fn from(ip_range: lnvps_db::IpRange) -> Self {
        Self {
            id: ip_range.id,
            cidr: ip_range.cidr,
            gateway: ip_range.gateway,
            enabled: ip_range.enabled,
            region_id: ip_range.region_id,
            region_name: None, // Will be filled by handler
            reverse_zone_id: ip_range.reverse_zone_id,
            access_policy_id: ip_range.access_policy_id,
            access_policy_name: None, // Will be filled by handler
            allocation_mode: AdminIpRangeAllocationMode::from(ip_range.allocation_mode),
            use_full_range: ip_range.use_full_range,
            assignment_count: 0, // Will be filled by handler
        }
    }
}

impl From<lnvps_db::AccessPolicy> for AdminAccessPolicyInfo {
    fn from(policy: lnvps_db::AccessPolicy) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            kind: AdminNetworkAccessPolicy::from(policy.kind),
            router_id: policy.router_id,
            interface: policy.interface,
        }
    }
}

impl CreateIpRangeRequest {
    pub fn to_ip_range(&self) -> anyhow::Result<lnvps_db::IpRange> {
        let allocation_mode = self.allocation_mode.unwrap_or(AdminIpRangeAllocationMode::Sequential);
        let db_allocation_mode = IpRangeAllocationMode::from(allocation_mode);

        Ok(lnvps_db::IpRange {
            id: 0, // Will be set by database
            cidr: self.cidr.trim().to_string(),
            gateway: self.gateway.trim().to_string(),
            enabled: self.enabled.unwrap_or(true),
            region_id: self.region_id,
            reverse_zone_id: self.reverse_zone_id.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            access_policy_id: self.access_policy_id,
            allocation_mode: db_allocation_mode,
            use_full_range: self.use_full_range.unwrap_or(false),
        })
    }
}

// Access Policy Management Models (Extended)
#[derive(Serialize, JsonSchema)]
pub struct AdminAccessPolicyDetail {
    pub id: u64,
    pub name: String,
    pub kind: AdminNetworkAccessPolicy,
    pub router_id: Option<u64>,
    pub router_name: Option<String>, // Populated with router name
    pub interface: Option<String>,
    pub ip_range_count: u64, // Number of IP ranges using this policy
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateAccessPolicyRequest {
    pub name: String,
    pub kind: Option<AdminNetworkAccessPolicy>, // default: "static_arp"
    pub router_id: Option<u64>,
    pub interface: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateAccessPolicyRequest {
    pub name: Option<String>,
    pub kind: Option<AdminNetworkAccessPolicy>,
    pub router_id: Option<Option<u64>>, // Use Option<Option<u64>> to allow setting to null
    pub interface: Option<Option<String>>, // Use Option<Option<String>> to allow setting to null
}

// Router Models for access policy management
#[derive(Serialize, JsonSchema)]
pub struct AdminRouterInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: AdminRouterKind,
    pub url: String,
}

impl From<lnvps_db::AccessPolicy> for AdminAccessPolicyDetail {
    fn from(policy: lnvps_db::AccessPolicy) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            kind: AdminNetworkAccessPolicy::from(policy.kind),
            router_id: policy.router_id,
            router_name: None, // Will be filled by handler
            interface: policy.interface,
            ip_range_count: 0, // Will be filled by handler
        }
    }
}

impl From<lnvps_db::Router> for AdminRouterInfo {
    fn from(router: lnvps_db::Router) -> Self {
        Self {
            id: router.id,
            name: router.name,
            enabled: router.enabled,
            kind: AdminRouterKind::from(router.kind),
            url: router.url,
        }
    }
}

impl CreateAccessPolicyRequest {
    pub fn to_access_policy(&self) -> anyhow::Result<lnvps_db::AccessPolicy> {
        let admin_kind = self.kind.unwrap_or(AdminNetworkAccessPolicy::StaticArp);
        let db_kind = NetworkAccessPolicy::from(admin_kind);

        Ok(lnvps_db::AccessPolicy {
            id: 0, // Will be set by database
            name: self.name.trim().to_string(),
            kind: db_kind,
            router_id: self.router_id,
            interface: self.interface.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        })
    }
}

// Router Management Models (Extended)
#[derive(Serialize, JsonSchema)]
pub struct AdminRouterDetail {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: AdminRouterKind,
    pub url: String,
    pub access_policy_count: u64, // Number of access policies using this router
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateRouterRequest {
    pub name: String,
    pub enabled: Option<bool>, // Default: true
    pub kind: AdminRouterKind,
    pub url: String,
    pub token: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct UpdateRouterRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub kind: Option<AdminRouterKind>,
    pub url: Option<String>,
    pub token: Option<String>,
}

impl From<lnvps_db::Router> for AdminRouterDetail {
    fn from(router: lnvps_db::Router) -> Self {
        Self {
            id: router.id,
            name: router.name,
            enabled: router.enabled,
            kind: AdminRouterKind::from(router.kind),
            url: router.url,
            access_policy_count: 0, // Will be filled by handler
        }
    }
}

impl CreateRouterRequest {
    pub fn to_router(&self) -> anyhow::Result<lnvps_db::Router> {
        let db_kind = RouterKind::from(self.kind);

        Ok(lnvps_db::Router {
            id: 0, // Will be set by database
            name: self.name.trim().to_string(),
            enabled: self.enabled.unwrap_or(true),
            kind: db_kind,
            url: self.url.trim().to_string(),
            token: self.token.clone(),
        })
    }
}

// Cost Plan Management Models
#[derive(Serialize, JsonSchema)]
pub struct AdminCostPlanInfo {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    pub amount: f32,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
    pub template_count: u64, // Number of VM templates using this cost plan
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminCreateCostPlanRequest {
    pub name: String,
    pub amount: f32,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
}

#[derive(Deserialize, JsonSchema)]
pub struct AdminUpdateCostPlanRequest {
    pub name: Option<String>,
    pub amount: Option<f32>,
    pub currency: Option<String>,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<ApiVmCostPlanIntervalType>,
}

impl From<lnvps_db::VmCostPlan> for AdminCostPlanInfo {
    fn from(cost_plan: lnvps_db::VmCostPlan) -> Self {
        Self {
            id: cost_plan.id,
            name: cost_plan.name,
            created: cost_plan.created,
            amount: cost_plan.amount,
            currency: cost_plan.currency,
            interval_amount: cost_plan.interval_amount,
            interval_type: ApiVmCostPlanIntervalType::from(cost_plan.interval_type),
            template_count: 0, // Will be filled by handler
        }
    }
}

impl AdminCreateCostPlanRequest {
    pub fn to_cost_plan(&self) -> anyhow::Result<lnvps_db::VmCostPlan> {
        use chrono::Utc;
        
        if self.name.trim().is_empty() {
            return Err(anyhow::anyhow!("Cost plan name cannot be empty"));
        }

        if self.amount < 0.0 {
            return Err(anyhow::anyhow!("Cost plan amount cannot be negative"));
        }

        if self.currency.trim().is_empty() {
            return Err(anyhow::anyhow!("Currency cannot be empty"));
        }

        if self.interval_amount == 0 {
            return Err(anyhow::anyhow!("Interval amount cannot be zero"));
        }

        Ok(lnvps_db::VmCostPlan {
            id: 0, // Will be set by database
            name: self.name.trim().to_string(),
            created: Utc::now(),
            amount: self.amount,
            currency: self.currency.trim().to_uppercase(),
            interval_amount: self.interval_amount,
            interval_type: self.interval_type.into(),
        })
    }
}

// VM History Models

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminVmHistoryActionType {
    Created,
    Started,
    Stopped,
    Restarted,
    Deleted,
    Expired,
    Renewed,
    Reinstalled,
    StateChanged,
    PaymentReceived,
    ConfigurationChanged,
}

impl From<VmHistoryActionType> for AdminVmHistoryActionType {
    fn from(action_type: VmHistoryActionType) -> Self {
        match action_type {
            VmHistoryActionType::Created => AdminVmHistoryActionType::Created,
            VmHistoryActionType::Started => AdminVmHistoryActionType::Started,
            VmHistoryActionType::Stopped => AdminVmHistoryActionType::Stopped,
            VmHistoryActionType::Restarted => AdminVmHistoryActionType::Restarted,
            VmHistoryActionType::Deleted => AdminVmHistoryActionType::Deleted,
            VmHistoryActionType::Expired => AdminVmHistoryActionType::Expired,
            VmHistoryActionType::Renewed => AdminVmHistoryActionType::Renewed,
            VmHistoryActionType::Reinstalled => AdminVmHistoryActionType::Reinstalled,
            VmHistoryActionType::StateChanged => AdminVmHistoryActionType::StateChanged,
            VmHistoryActionType::PaymentReceived => AdminVmHistoryActionType::PaymentReceived,
            VmHistoryActionType::ConfigurationChanged => AdminVmHistoryActionType::ConfigurationChanged,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct AdminVmHistoryInfo {
    pub id: u64,
    pub vm_id: u64,
    pub action_type: AdminVmHistoryActionType,
    pub timestamp: DateTime<Utc>,
    pub initiated_by_user: Option<u64>,
    pub initiated_by_user_pubkey: Option<String>, // hex encoded
    pub initiated_by_user_email: Option<String>,
    pub description: Option<String>,
    // Note: previous_state, new_state, and metadata are omitted as they contain binary data
    // and may be sensitive. They can be added later if needed.
}

impl AdminVmHistoryInfo {
    pub async fn from_vm_history_with_admin_data(
        db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
        history: &VmHistory,
    ) -> anyhow::Result<Self> {
        let mut initiated_by_user_pubkey = None;
        let mut initiated_by_user_email = None;

        // Get user info if available
        if let Some(user_id) = history.initiated_by_user {
            if let Ok(user) = db.get_user(user_id).await {
                initiated_by_user_pubkey = Some(hex::encode(&user.pubkey));
                initiated_by_user_email = user.email;
            }
        }

        Ok(Self {
            id: history.id,
            vm_id: history.vm_id,
            action_type: AdminVmHistoryActionType::from(history.action_type.clone()),
            timestamp: history.timestamp,
            initiated_by_user: history.initiated_by_user,
            initiated_by_user_pubkey,
            initiated_by_user_email,
            description: history.description.clone(),
        })
    }
}

// VM Payment Models

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminPaymentMethod {
    Lightning,
    Revolut,
    Paypal,
}

impl From<PaymentMethod> for AdminPaymentMethod {
    fn from(payment_method: PaymentMethod) -> Self {
        match payment_method {
            PaymentMethod::Lightning => AdminPaymentMethod::Lightning,
            PaymentMethod::Revolut => AdminPaymentMethod::Revolut,
            PaymentMethod::Paypal => AdminPaymentMethod::Paypal,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct AdminVmPaymentInfo {
    pub id: String, // hex encoded payment ID
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64, // Amount in smallest currency unit (e.g., satoshis, cents)
    pub currency: String,
    pub payment_method: AdminPaymentMethod,
    pub external_id: Option<String>,
    pub is_paid: bool,
    pub rate: f32, // Exchange rate to base currency (EUR)
    // Note: external_data is omitted as it may contain sensitive payment provider data
}

impl AdminVmPaymentInfo {
    pub fn from_vm_payment(payment: &VmPayment) -> Self {
        Self {
            id: hex::encode(&payment.id),
            vm_id: payment.vm_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency: payment.currency.clone(),
            payment_method: AdminPaymentMethod::from(payment.payment_method),
            external_id: payment.external_id.clone(),
            is_paid: payment.is_paid,
            rate: payment.rate,
        }
    }
}
