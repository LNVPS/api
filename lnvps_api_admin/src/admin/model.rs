use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use lnvps_api_common::{
    ApiDiskInterface, ApiDiskType, ApiOsDistribution, ApiVmCostPlanIntervalType, VmRunningState,
};
use lnvps_db::{
    AdminAction, AdminResource, AdminRole, IpRangeAllocationMode, NetworkAccessPolicy,
    OsDistribution, PaymentMethod, RouterKind, SubscriptionType, VmHistory, VmHistoryActionType,
    VmHostKind, VmPayment,
};

// Admin API Enums - Using enums from common crate where available, creating new ones only where needed

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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
            // MockRouter is a test-only variant and should never appear in production.
            // Map it to Mikrotik as a safe fallback rather than panicking.
            RouterKind::MockRouter => AdminRouterKind::Mikrotik,
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserStatus {
    Active,
    Suspended,
    Deleted,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminUserRole {
    SuperAdmin,
    Admin,
    ReadOnly,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebSocketMessage {
    Connected {
        message: String,
    },
    Pong,
    Error {
        error: String,
    },
    JobFeedback {
        feedback: lnvps_api_common::JobFeedback,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JobResponse {
    pub job_id: String,
}

#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Serialize)]
pub struct AdminUserInfo {
    pub id: u64,
    pub pubkey: String, // hex encoded
    pub created: DateTime<Utc>,
    pub email: Option<String>,
    pub email_verified: bool,
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
    pub has_nwc: bool,
}

#[derive(Deserialize)]
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

#[derive(Serialize)]
pub struct AdminUserStats {
    pub total_users: u64,
    pub active_users_30d: u64,
    pub new_users_30d: u64,
    pub users_by_country: HashMap<String, u64>,
}

// RBAC API Models

#[derive(Serialize)]
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

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>, // Formatted as "resource::action"
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>, // Formatted as "resource::action"
}

#[derive(Serialize)]
pub struct UserRoleInfo {
    pub role: AdminRoleInfo,
    pub assigned_by: Option<u64>,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
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
            email: if user.email.is_empty() {
                None
            } else {
                Some(user.email.into())
            },
            email_verified: user.email_verified,
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
            has_nwc: user.nwc_connection_string.is_some(),
        }
    }
}

impl From<lnvps_db::AdminUserInfo> for AdminUserInfo {
    fn from(user: lnvps_db::AdminUserInfo) -> Self {
        Self {
            id: user.user_info.id,
            pubkey: hex::encode(&user.user_info.pubkey),
            created: user.user_info.created,
            email: if user.user_info.email.is_empty() {
                None
            } else {
                Some(user.user_info.email.into())
            },
            email_verified: user.user_info.email_verified,
            contact_nip17: user.user_info.contact_nip17,
            contact_email: user.user_info.contact_email,
            country_code: user.user_info.country_code,
            billing_name: user.user_info.billing_name,
            billing_address_1: user.user_info.billing_address_1,
            billing_address_2: user.user_info.billing_address_2,
            billing_city: user.user_info.billing_city,
            billing_state: user.user_info.billing_state,
            billing_postcode: user.user_info.billing_postcode,
            billing_tax_id: user.user_info.billing_tax_id,
            // Admin-specific fields will be filled by the handler
            vm_count: user.vm_count as _,
            last_login: None,
            is_admin: user.is_admin,
            has_nwc: user.user_info.nwc_connection_string.is_some(),
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
#[derive(Serialize)]
pub struct AdminVmIpAddress {
    /// IP assignment ID for linking
    pub id: u64,
    /// IP address
    pub ip: String,
    /// IP range ID for linking to range details
    pub range_id: u64,
}

#[derive(Serialize)]
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
    pub auto_renewal_enabled: bool,

    // VM Resources
    /// Number of CPU cores allocated to this VM
    pub cpu: u16,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
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
    pub host_name: String,
    pub region_id: u64,
    pub region_name: String,
    pub deleted: bool,
    pub ref_code: Option<String>,
    pub disabled: bool,
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
        host_name: String,
        region_id: u64,
        region_name: String,
        deleted: bool,
        ref_code: Option<String>,
    ) -> anyhow::Result<Self> {
        let image = db.get_os_image(vm.image_id).await?;
        let ssh_key = db.get_user_ssh_key(vm.ssh_key_id).await?;
        let ips = db.list_vm_ip_assignments(vm.id).await?;

        // Get template info and VM resources
        let (
            template_id,
            template_name,
            custom_template_id,
            is_standard_template,
            cpu,
            cpu_mfg,
            cpu_arch,
            cpu_features,
            memory,
            disk_size,
            disk_type,
            disk_interface,
        ) = if let Some(template_id) = vm.template_id {
            let template = db.get_vm_template(template_id).await?;
            (
                template_id,
                template.name.clone(),
                None,
                true,
                template.cpu,
                if matches!(template.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                    None
                } else {
                    Some(template.cpu_mfg.to_string())
                },
                if matches!(template.cpu_arch, lnvps_db::CpuArch::Unknown) {
                    None
                } else {
                    Some(template.cpu_arch.to_string())
                },
                template
                    .cpu_features
                    .iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>(),
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
                if matches!(custom_template.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                    None
                } else {
                    Some(custom_template.cpu_mfg.to_string())
                },
                if matches!(custom_template.cpu_arch, lnvps_db::CpuArch::Unknown) {
                    None
                } else {
                    Some(custom_template.cpu_arch.to_string())
                },
                custom_template
                    .cpu_features
                    .iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>(),
                custom_template.memory,
                custom_template.disk_size,
                ApiDiskType::from(custom_template.disk_type),
                ApiDiskInterface::from(custom_template.disk_interface),
            )
        } else {
            (
                0,
                "Unknown".to_string(),
                None,
                true,
                0,
                None,
                None,
                Vec::new(),
                0,
                0,
                ApiDiskType::HDD,
                ApiDiskInterface::SATA,
            )
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
            auto_renewal_enabled: vm.auto_renewal_enabled,
            cpu,
            cpu_mfg,
            cpu_arch,
            cpu_features,
            memory,
            disk_size,
            disk_type,
            disk_interface,
            host_id,
            user_id,
            user_pubkey,
            user_email,
            host_name,
            region_id,
            region_name,
            deleted,
            ref_code,
            disabled: vm.disabled,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminVmAction {
    Start,
    Stop,
    Delete,
}

#[derive(Deserialize)]
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

#[derive(Serialize)]
pub struct AdminHostInfo {
    pub id: u64,
    pub name: String,
    pub kind: AdminVmHostKind,
    pub region: AdminHostRegion,
    pub ip: String,
    pub cpu: u16,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
    pub memory: u64,
    pub enabled: bool,
    pub load_cpu: f32,
    pub load_memory: f32,
    pub load_disk: f32,
    pub vlan_id: Option<u64>,
    /// MTU setting for network configuration
    pub mtu: Option<u16>,
    pub disks: Vec<AdminHostDisk>,
    // Calculated load metrics
    pub calculated_load: CalculatedHostLoad,
    /// SSH username for host utilities (None if not configured)
    pub ssh_user: Option<String>,
    /// Whether SSH key is configured (key itself is not exposed)
    pub ssh_key_configured: bool,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
pub struct AdminHostRegion {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct AdminHostDisk {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    pub enabled: bool,
}

impl From<lnvps_db::VmHostDisk> for AdminHostDisk {
    fn from(disk: lnvps_db::VmHostDisk) -> Self {
        Self {
            id: disk.id,
            name: disk.name,
            size: disk.size,
            kind: disk.kind.into(),
            interface: disk.interface.into(),
            enabled: disk.enabled,
        }
    }
}

#[derive(Serialize)]
pub struct AdminRegionInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub company_id: u64,
    pub host_count: u64,
    pub total_vms: u64,
    pub total_cpu_cores: u64,
    pub total_memory_bytes: u64,
    pub total_ip_assignments: u64,
}

#[derive(Deserialize)]
pub struct CreateRegionRequest {
    pub name: String,
    pub enabled: bool,
    pub company_id: u64,
}

#[derive(Deserialize)]
pub struct UpdateRegionRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub company_id: Option<u64>,
}

impl AdminHostInfo {
    pub fn from_host_and_region(host: lnvps_db::VmHost, region: lnvps_db::VmHostRegion) -> Self {
        let ssh_key_configured = host.ssh_key.is_some();
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
            cpu_mfg: if matches!(host.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                None
            } else {
                Some(host.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(host.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(host.cpu_arch.to_string())
            },
            cpu_features: host.cpu_features.iter().map(|f| f.to_string()).collect(),
            memory: host.memory,
            enabled: host.enabled,
            load_cpu: host.load_cpu,
            load_memory: host.load_memory,
            load_disk: host.load_disk,
            vlan_id: host.vlan_id,
            mtu: host.mtu,
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
            ssh_user: host.ssh_user,
            ssh_key_configured,
        }
    }

    pub fn from_host_region_and_disks(
        host: lnvps_db::VmHost,
        region: lnvps_db::VmHostRegion,
        disks: Vec<lnvps_db::VmHostDisk>,
    ) -> Self {
        let admin_disks = disks.into_iter().map(|disk| disk.into()).collect();
        let ssh_key_configured = host.ssh_key.is_some();

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
            cpu_mfg: if matches!(host.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                None
            } else {
                Some(host.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(host.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(host.cpu_arch.to_string())
            },
            cpu_features: host.cpu_features.iter().map(|f| f.to_string()).collect(),
            memory: host.memory,
            enabled: host.enabled,
            load_cpu: host.load_cpu,
            load_memory: host.load_memory,
            load_disk: host.load_disk,
            vlan_id: host.vlan_id,
            mtu: host.mtu,
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
            ssh_user: host.ssh_user,
            ssh_key_configured,
        }
    }

    pub fn from_host_capacity(
        capacity: &lnvps_api_common::HostCapacity,
        region: lnvps_db::VmHostRegion,
        disks: Vec<lnvps_db::VmHostDisk>,
        active_vms: u64,
    ) -> Self {
        let admin_disks = disks.into_iter().map(|disk| disk.into()).collect();
        let ssh_key_configured = capacity.host.ssh_key.is_some();

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
            cpu_mfg: if matches!(capacity.host.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                None
            } else {
                Some(capacity.host.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(capacity.host.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(capacity.host.cpu_arch.to_string())
            },
            cpu_features: capacity
                .host
                .cpu_features
                .iter()
                .map(|f| f.to_string())
                .collect(),
            memory: capacity.host.memory,
            enabled: capacity.host.enabled,
            load_cpu: capacity.host.load_cpu,
            load_memory: capacity.host.load_memory,
            load_disk: capacity.host.load_disk,
            vlan_id: capacity.host.vlan_id,
            mtu: capacity.host.mtu,
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
            ssh_user: capacity.host.ssh_user.clone(),
            ssh_key_configured,
        }
    }

    /// Convert from unified AdminVmHost struct with basic load calculation
    pub fn from_admin_vm_host(admin_host: lnvps_db::AdminVmHost) -> Self {
        let admin_disks = admin_host
            .disks
            .into_iter()
            .map(|disk| disk.into())
            .collect();
        let ssh_key_configured = admin_host.host.ssh_key.is_some();

        Self {
            id: admin_host.host.id,
            name: admin_host.host.name.clone(),
            kind: AdminVmHostKind::from(admin_host.host.kind.clone()),
            region: AdminHostRegion {
                id: admin_host.region_id,
                name: admin_host.region_name,
                enabled: admin_host.region_enabled,
            },
            ip: admin_host.host.ip.clone(),
            cpu: admin_host.host.cpu,
            cpu_mfg: if matches!(admin_host.host.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                None
            } else {
                Some(admin_host.host.cpu_mfg.to_string())
            },
            cpu_arch: if matches!(admin_host.host.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(admin_host.host.cpu_arch.to_string())
            },
            cpu_features: admin_host
                .host
                .cpu_features
                .iter()
                .map(|f| f.to_string())
                .collect(),
            memory: admin_host.host.memory,
            enabled: admin_host.host.enabled,
            load_cpu: admin_host.host.load_cpu,
            load_memory: admin_host.host.load_memory,
            load_disk: admin_host.host.load_disk,
            vlan_id: admin_host.host.vlan_id,
            mtu: admin_host.host.mtu,
            disks: admin_disks,
            calculated_load: CalculatedHostLoad {
                overall_load: 0.0,
                cpu_load: 0.0,
                memory_load: 0.0,
                disk_load: 0.0,
                available_cpu: admin_host.host.cpu,
                available_memory: admin_host.host.memory,
                active_vms: admin_host.active_vm_count as _,
            },
            ssh_user: admin_host.host.ssh_user,
            ssh_key_configured,
        }
    }

    /// Convert from unified AdminVmHost struct with capacity calculation
    pub async fn from_admin_vm_host_with_capacity(
        db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
        admin_host: lnvps_db::AdminVmHost,
    ) -> Self {
        // Try to calculate capacity data
        match lnvps_api_common::HostCapacityService::new(db.clone())
            .get_host_capacity(&admin_host.host, None, None)
            .await
        {
            Ok(capacity) => {
                // Convert disks
                let admin_disks = admin_host
                    .disks
                    .into_iter()
                    .map(|disk| disk.into())
                    .collect();
                let ssh_key_configured = capacity.host.ssh_key.is_some();

                Self {
                    id: capacity.host.id,
                    name: capacity.host.name.clone(),
                    kind: AdminVmHostKind::from(capacity.host.kind.clone()),
                    region: AdminHostRegion {
                        id: admin_host.region_id,
                        name: admin_host.region_name,
                        enabled: admin_host.region_enabled,
                    },
                    ip: capacity.host.ip.clone(),
                    cpu: capacity.host.cpu,
                    cpu_mfg: if matches!(capacity.host.cpu_mfg, lnvps_db::CpuMfg::Unknown) {
                        None
                    } else {
                        Some(capacity.host.cpu_mfg.to_string())
                    },
                    cpu_arch: if matches!(capacity.host.cpu_arch, lnvps_db::CpuArch::Unknown) {
                        None
                    } else {
                        Some(capacity.host.cpu_arch.to_string())
                    },
                    cpu_features: capacity
                        .host
                        .cpu_features
                        .iter()
                        .map(|f| f.to_string())
                        .collect(),
                    memory: capacity.host.memory,
                    enabled: capacity.host.enabled,
                    load_cpu: capacity.host.load_cpu,
                    load_memory: capacity.host.load_memory,
                    load_disk: capacity.host.load_disk,
                    vlan_id: capacity.host.vlan_id,
                    mtu: capacity.host.mtu,
                    disks: admin_disks,
                    calculated_load: CalculatedHostLoad {
                        overall_load: capacity.load(),
                        cpu_load: capacity.cpu_load(),
                        memory_load: capacity.memory_load(),
                        disk_load: capacity.disk_load(),
                        available_cpu: capacity.available_cpu(),
                        available_memory: capacity.available_memory(),
                        active_vms: admin_host.active_vm_count as _,
                    },
                    ssh_user: capacity.host.ssh_user.clone(),
                    ssh_key_configured,
                }
            }
            Err(_) => {
                // Fallback to basic conversion if capacity calculation fails
                Self::from_admin_vm_host(admin_host)
            }
        }
    }
}

// VM OS Image Management Models
#[derive(Serialize)]
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
    pub sha2: Option<String>,
    pub sha2_url: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateVmOsImageRequest {
    pub distribution: ApiOsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    pub url: String,
    pub default_username: Option<String>,
    pub sha2: Option<String>,
    pub sha2_url: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateVmOsImageRequest {
    pub distribution: Option<ApiOsDistribution>,
    pub flavour: Option<String>,
    pub version: Option<String>,
    pub enabled: Option<bool>,
    pub release_date: Option<DateTime<Utc>>,
    pub url: Option<String>,
    pub default_username: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub sha2: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub sha2_url: Option<Option<String>>,
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
            sha2: image.sha2,
            sha2_url: image.sha2_url,
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
            sha2: image.sha2,
            sha2_url: image.sha2_url,
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
            sha2: self.sha2.clone(),
            sha2_url: self.sha2_url.clone(),
        })
    }
}

// VM Template Management Models
#[derive(Serialize)]
pub struct AdminVmTemplateInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mfg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
    pub cost_plan_id: u64,
    pub region_id: u64,
    pub region_name: Option<String>,
    pub cost_plan_name: Option<String>,
    pub active_vm_count: i64, // Number of active (non-deleted) VMs using this template
    /// Maximum disk read IOPS (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores (None = uncapped)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f32>,
}

#[derive(Deserialize)]
pub struct AdminCreateVmTemplateRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    pub cpu_arch: Option<String>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    #[serde(default)]
    pub cpu_features: Vec<String>,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
    pub cost_plan_id: Option<u64>, // Optional - if not provided, will auto-create cost plan
    pub region_id: u64,
    // Cost plan creation fields - used when cost_plan_id is not provided
    pub cost_plan_name: Option<String>, // Defaults to "{template_name} Cost Plan"
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC) - required if cost_plan_id not provided
    pub cost_plan_amount: Option<u64>,
    pub cost_plan_currency: Option<String>, // Defaults to "USD"
    pub cost_plan_interval_amount: Option<u64>, // Defaults to 1
    pub cost_plan_interval_type: Option<ApiVmCostPlanIntervalType>, // Defaults to Month
    /// Maximum disk read IOPS (None = uncapped)
    pub disk_iops_read: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub disk_iops_write: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub disk_mbps_read: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub disk_mbps_write: Option<u32>,
    /// Maximum network bandwidth in Mbit/s (None = uncapped)
    pub network_mbps: Option<u32>,
    /// Maximum CPU usage as a fraction of allocated cores, e.g. 0.5 = 50% (None = uncapped)
    pub cpu_limit: Option<f32>,
}

#[derive(Deserialize)]
pub struct AdminUpdateVmTemplateRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub expires: Option<Option<DateTime<Utc>>>,
    pub cpu: Option<u16>,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    /// Use `Some(None)` or `null` to clear (reset to unknown)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_mfg: Option<Option<String>>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    /// Use `Some(None)` or `null` to clear (reset to unknown)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_arch: Option<Option<String>>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    /// Use `Some(None)` or `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_features: Option<Option<Vec<String>>>,
    pub memory: Option<u64>,
    pub disk_size: Option<u64>,
    pub disk_type: Option<ApiDiskType>,
    pub disk_interface: Option<ApiDiskInterface>,
    pub cost_plan_id: Option<u64>,
    pub region_id: Option<u64>,
    // Cost plan update fields - will update the associated cost plan for this template
    pub cost_plan_name: Option<String>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub cost_plan_amount: Option<u64>,
    pub cost_plan_currency: Option<String>,
    pub cost_plan_interval_amount: Option<u64>,
    pub cost_plan_interval_type: Option<ApiVmCostPlanIntervalType>,
    /// Maximum disk read IOPS — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub disk_iops_read: Option<Option<u32>>,
    /// Maximum disk write IOPS — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub disk_iops_write: Option<Option<u32>>,
    /// Maximum disk read throughput in MB/s — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub disk_mbps_read: Option<Option<u32>>,
    /// Maximum disk write throughput in MB/s — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub disk_mbps_write: Option<Option<u32>>,
    /// Maximum network bandwidth in Mbit/s — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub network_mbps: Option<Option<u32>>,
    /// Maximum CPU usage as a fraction of allocated cores — use `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_limit: Option<Option<f32>>,
}

// Common response structures
#[derive(Serialize)]
pub struct AdminListResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Serialize)]
pub struct AdminSingleResponse<T> {
    pub data: T,
}

// Custom Pricing Management Models
#[derive(Serialize)]
pub struct AdminCustomPricingInfo {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub region_name: Option<String>,
    pub currency: String,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cpu_features: Vec<String>,
    /// Cost per CPU core in smallest currency units (cents for fiat, millisats for BTC)
    pub cpu_cost: u64,
    /// Cost per GB RAM in smallest currency units (cents for fiat, millisats for BTC)
    pub memory_cost: u64,
    /// Cost per IPv4 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip4_cost: u64,
    /// Cost per IPv6 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip6_cost: u64,
    pub min_cpu: u16,
    pub max_cpu: u16,
    pub min_memory: u64,
    pub max_memory: u64,
    pub disk_pricing: Vec<AdminCustomPricingDisk>,
    pub template_count: u64,
}

#[derive(Serialize)]
pub struct AdminCustomPricingDisk {
    pub id: u64,
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    /// Cost per GB in smallest currency units (cents for fiat, millisats for BTC)
    pub cost: u64,
    pub max_disk_size: u64,
    pub min_disk_size: u64,
}

#[derive(Deserialize)]
pub struct UpdateCustomPricingRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub expires: Option<Option<DateTime<Utc>>>,
    pub region_id: Option<u64>,
    pub currency: Option<String>,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    /// Use `Some(None)` or `null` to clear (reset to unknown)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_mfg: Option<Option<String>>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    /// Use `Some(None)` or `null` to clear (reset to unknown)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_arch: Option<Option<String>>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    /// Use `Some(None)` or `null` to clear
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_features: Option<Option<Vec<String>>>,
    /// Cost per CPU core in smallest currency units (cents for fiat, millisats for BTC)
    pub cpu_cost: Option<u64>,
    /// Cost per GB RAM in smallest currency units (cents for fiat, millisats for BTC)
    pub memory_cost: Option<u64>,
    /// Cost per IPv4 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip4_cost: Option<u64>,
    /// Cost per IPv6 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip6_cost: Option<u64>,
    pub min_cpu: Option<u16>,
    pub max_cpu: Option<u16>,
    pub min_memory: Option<u64>,
    pub max_memory: Option<u64>,
    pub disk_pricing: Option<Vec<CreateCustomPricingDisk>>,
}

#[derive(Deserialize)]
pub struct CreateCustomPricingRequest {
    pub name: String,
    pub enabled: Option<bool>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub currency: String,
    /// CPU manufacturer (e.g. "intel", "amd", "apple")
    pub cpu_mfg: Option<String>,
    /// CPU architecture (e.g. "x86_64", "arm64")
    pub cpu_arch: Option<String>,
    /// CPU features (e.g. ["AVX2", "AES", "VMX"])
    #[serde(default)]
    pub cpu_features: Vec<String>,
    /// Cost per CPU core in smallest currency units (cents for fiat, millisats for BTC)
    pub cpu_cost: u64,
    /// Cost per GB RAM in smallest currency units (cents for fiat, millisats for BTC)
    pub memory_cost: u64,
    /// Cost per IPv4 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip4_cost: u64,
    /// Cost per IPv6 address in smallest currency units (cents for fiat, millisats for BTC)
    pub ip6_cost: u64,
    pub min_cpu: u16,
    pub max_cpu: u16,
    pub min_memory: u64,
    pub max_memory: u64,
    pub disk_pricing: Vec<CreateCustomPricingDisk>,
}

#[derive(Deserialize)]
pub struct CreateCustomPricingDisk {
    pub kind: ApiDiskType,
    pub interface: ApiDiskInterface,
    /// Cost per GB in smallest currency units (cents for fiat, millisats for BTC)
    pub cost: u64,
    pub min_disk_size: u64,
    pub max_disk_size: u64,
}

#[derive(Deserialize)]
pub struct CopyCustomPricingRequest {
    pub name: String,
    pub region_id: Option<u64>,
    pub enabled: Option<bool>,
}

// Company Management Models
#[derive(Serialize)]
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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
#[derive(Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_ips: Option<u64>, // Number of available IPs (only for IPv4 ranges)
}

#[derive(Deserialize)]
pub struct CreateIpRangeRequest {
    pub cidr: String,
    pub gateway: String,
    pub enabled: Option<bool>, // Default: true
    pub region_id: u64,
    pub reverse_zone_id: Option<String>,
    pub access_policy_id: Option<u64>,
    pub allocation_mode: Option<AdminIpRangeAllocationMode>, // default: "sequential"
    pub use_full_range: Option<bool>,                        // Default: false
}

#[derive(Deserialize)]
pub struct UpdateIpRangeRequest {
    pub cidr: Option<String>,
    pub gateway: Option<String>,
    pub enabled: Option<bool>,
    pub region_id: Option<u64>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub reverse_zone_id: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub access_policy_id: Option<Option<u64>>,
    pub allocation_mode: Option<AdminIpRangeAllocationMode>,
    pub use_full_range: Option<bool>,
}

// Access Policy Models for IP range management
#[derive(Serialize)]
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
            available_ips: None, // Will be filled by handler for IPv4 ranges
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
        let allocation_mode = self
            .allocation_mode
            .unwrap_or(AdminIpRangeAllocationMode::Sequential);
        let db_allocation_mode = IpRangeAllocationMode::from(allocation_mode);

        Ok(lnvps_db::IpRange {
            id: 0, // Will be set by database
            cidr: self.cidr.trim().to_string(),
            gateway: self.gateway.trim().to_string(),
            enabled: self.enabled.unwrap_or(true),
            region_id: self.region_id,
            reverse_zone_id: self
                .reverse_zone_id
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            access_policy_id: self.access_policy_id,
            allocation_mode: db_allocation_mode,
            use_full_range: self.use_full_range.unwrap_or(false),
        })
    }
}

// Access Policy Management Models (Extended)
#[derive(Serialize)]
pub struct AdminAccessPolicyDetail {
    pub id: u64,
    pub name: String,
    pub kind: AdminNetworkAccessPolicy,
    pub router_id: Option<u64>,
    pub router_name: Option<String>, // Populated with router name
    pub interface: Option<String>,
    pub ip_range_count: u64, // Number of IP ranges using this policy
}

#[derive(Deserialize)]
pub struct CreateAccessPolicyRequest {
    pub name: String,
    pub kind: Option<AdminNetworkAccessPolicy>, // default: "static_arp"
    pub router_id: Option<u64>,
    pub interface: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateAccessPolicyRequest {
    pub name: Option<String>,
    pub kind: Option<AdminNetworkAccessPolicy>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub router_id: Option<Option<u64>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub interface: Option<Option<String>>,
}

// Router Models for access policy management
#[derive(Serialize)]
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
            interface: self
                .interface
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        })
    }
}

// Router Management Models (Extended)
#[derive(Serialize)]
pub struct AdminRouterDetail {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: AdminRouterKind,
    pub url: String,
    pub access_policy_count: u64, // Number of access policies using this router
}

#[derive(Deserialize)]
pub struct CreateRouterRequest {
    pub name: String,
    pub enabled: Option<bool>, // Default: true
    pub kind: AdminRouterKind,
    pub url: String,
    pub token: String,
}

#[derive(Deserialize)]
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
            token: self.token.as_str().into(),
        })
    }
}

// Cost Plan Management Models
#[derive(Serialize)]
pub struct AdminCostPlanInfo {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
    pub template_count: u64, // Number of VM templates using this cost plan
}

#[derive(Deserialize)]
pub struct AdminCreateCostPlanRequest {
    pub name: String,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
}

#[derive(Deserialize)]
pub struct AdminUpdateCostPlanRequest {
    pub name: Option<String>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: Option<u64>,
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
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
            VmHistoryActionType::ConfigurationChanged => {
                AdminVmHistoryActionType::ConfigurationChanged
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
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
        if let Some(user_id) = history.initiated_by_user
            && let Ok(user) = db.get_user(user_id).await
        {
            initiated_by_user_pubkey = Some(hex::encode(&user.pubkey));
            initiated_by_user_email = if user.email.is_empty() {
                None
            } else {
                Some(user.email.into())
            };
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminPaymentMethod {
    Lightning,
    Revolut,
    Paypal,
    Stripe,
}

impl From<PaymentMethod> for AdminPaymentMethod {
    fn from(payment_method: PaymentMethod) -> Self {
        match payment_method {
            PaymentMethod::Lightning => AdminPaymentMethod::Lightning,
            PaymentMethod::Revolut => AdminPaymentMethod::Revolut,
            PaymentMethod::Paypal => AdminPaymentMethod::Paypal,
            PaymentMethod::Stripe => AdminPaymentMethod::Stripe,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdminRefundAmountInfo {
    /// The refund amount in smallest currency units (cents for fiat, milli-sats for BTC)
    pub amount: u64,
    /// The currency of the refund amount
    pub currency: String,
    /// Exchange rate used for conversion (if applicable)
    pub rate: f32,
    /// VM expiry date
    pub expires: DateTime<Utc>,
    /// Seconds remaining until VM expires
    pub seconds_remaining: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdminVmPaymentInfo {
    pub id: String, // hex encoded payment ID
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64, // Amount in smallest currency unit (e.g., satoshis, cents)
    pub tax: u64,    // Tax amount in smallest currency unit
    pub processing_fee: u64, // Processing fee in smallest currency unit
    pub currency: String,
    pub company_base_currency: String, // Base currency of the company that owns this VM
    pub payment_method: AdminPaymentMethod,
    pub external_id: Option<String>,
    pub is_paid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<DateTime<Utc>>,
    pub rate: f32, // Exchange rate to base currency (EUR)
                   // Note: external_data is omitted as it may contain sensitive payment provider data
}

impl AdminVmPaymentInfo {
    pub fn from_vm_payment(payment: &VmPayment, company_base_currency: String) -> Self {
        Self {
            id: hex::encode(&payment.id),
            vm_id: payment.vm_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            tax: payment.tax,
            processing_fee: payment.processing_fee,
            currency: payment.currency.clone(),
            company_base_currency,
            payment_method: AdminPaymentMethod::from(payment.payment_method),
            external_id: payment.external_id.clone(),
            is_paid: payment.is_paid,
            paid_at: payment.paid_at,
            rate: payment.rate,
        }
    }
}

// VM IP Assignment Management Models
#[derive(Serialize)]
pub struct AdminVmIpAssignmentInfo {
    pub id: u64,
    pub vm_id: u64,
    pub ip_range_id: u64,
    pub region_id: u64,
    pub user_id: u64,
    pub ip: String,
    pub deleted: bool,
    pub arp_ref: Option<String>,
    pub dns_forward: Option<String>,
    pub dns_forward_ref: Option<String>,
    pub dns_reverse: Option<String>,
    pub dns_reverse_ref: Option<String>,
    pub ip_range_cidr: Option<String>,
    pub region_name: Option<String>,
}

impl AdminVmIpAssignmentInfo {
    pub async fn from_ip_assignment_with_admin_data(
        db: &Arc<dyn lnvps_db::LNVpsDb>,
        assignment: &lnvps_db::VmIpAssignment,
    ) -> anyhow::Result<Self> {
        let mut admin_assignment = Self {
            id: assignment.id,
            vm_id: assignment.vm_id,
            ip_range_id: assignment.ip_range_id,
            region_id: 0, // Will be set when IP range is fetched
            ip: assignment.ip.clone(),
            deleted: assignment.deleted,
            arp_ref: assignment.arp_ref.clone(),
            dns_forward: assignment.dns_forward.clone(),
            dns_forward_ref: assignment.dns_forward_ref.clone(),
            dns_reverse: assignment.dns_reverse.clone(),
            dns_reverse_ref: assignment.dns_reverse_ref.clone(),
            user_id: 0,
            ip_range_cidr: None,
            region_name: None,
        };

        // Get VM details
        if let Ok(vm) = db.get_vm(assignment.vm_id).await {
            admin_assignment.user_id = vm.user_id;
        }

        // Get IP range details
        if let Ok(ip_range) = db.admin_get_ip_range(assignment.ip_range_id).await {
            admin_assignment.ip_range_cidr = Some(ip_range.cidr);
            admin_assignment.region_id = ip_range.region_id;

            // Get region name
            if let Ok(region) = db.get_host_region(ip_range.region_id).await {
                admin_assignment.region_name = Some(region.name);
            }
        }

        Ok(admin_assignment)
    }
}

#[derive(Deserialize)]
pub struct CreateVmIpAssignmentRequest {
    pub vm_id: u64,
    pub ip_range_id: u64,
    pub ip: Option<String>,
    pub arp_ref: Option<String>,
    pub dns_forward: Option<String>,
    pub dns_reverse: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateVmIpAssignmentRequest {
    pub ip: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub arp_ref: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub dns_forward: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub dns_reverse: Option<Option<String>>,
}

// Bulk Message Models
#[derive(Deserialize)]
pub struct BulkMessageRequest {
    pub subject: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct BulkMessageResponse {
    pub job_dispatched: bool,
    pub job_id: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminCreateVmRequest {
    pub user_id: u64,
    pub template_id: u64,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
    pub reason: Option<String>,
}

// ============================================================================
// Subscription Models
// ============================================================================

#[derive(Serialize)]
pub struct AdminSubscriptionInfo {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub currency: String,
    pub setup_fee: u64,
    pub auto_renewal_enabled: bool,
    pub external_id: Option<String>,
    pub line_items: Vec<AdminSubscriptionLineItemInfo>,
    pub payment_count: u64,
}

#[derive(Deserialize)]
pub struct AdminCreateSubscriptionRequest {
    pub user_id: u64,
    pub company_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub currency: String,
    pub setup_fee: u64,
    pub auto_renewal_enabled: bool,
    pub external_id: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminUpdateSubscriptionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub expires: Option<Option<DateTime<Utc>>>,
    pub is_active: Option<bool>,
    pub currency: Option<String>,
    pub setup_fee: Option<u64>,
    pub auto_renewal_enabled: Option<bool>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub external_id: Option<Option<String>>,
}

impl From<lnvps_db::Subscription> for AdminSubscriptionInfo {
    fn from(subscription: lnvps_db::Subscription) -> Self {
        Self {
            id: subscription.id,
            user_id: subscription.user_id,
            name: subscription.name,
            description: subscription.description,
            created: subscription.created,
            expires: subscription.expires,
            is_active: subscription.is_active,
            currency: subscription.currency,
            setup_fee: subscription.setup_fee,
            auto_renewal_enabled: subscription.auto_renewal_enabled,
            external_id: subscription.external_id,
            line_items: Vec::new(),
            payment_count: 0,
        }
    }
}

impl AdminCreateSubscriptionRequest {
    pub fn to_subscription(&self) -> anyhow::Result<lnvps_db::Subscription> {
        if self.name.trim().is_empty() {
            return Err(anyhow::anyhow!("Subscription name cannot be empty"));
        }

        if self.currency.trim().is_empty() {
            return Err(anyhow::anyhow!("Currency cannot be empty"));
        }

        Ok(lnvps_db::Subscription {
            id: 0,
            user_id: self.user_id,
            company_id: self.company_id,
            name: self.name.trim().to_string(),
            description: self.description.clone(),
            created: chrono::Utc::now(),
            expires: self.expires,
            is_active: self.is_active,
            currency: self.currency.trim().to_uppercase(),
            setup_fee: self.setup_fee,
            auto_renewal_enabled: self.auto_renewal_enabled,
            external_id: self.external_id.clone(),
        })
    }
}

// Subscription Line Item Models
#[derive(Serialize)]
pub struct AdminSubscriptionLineItemInfo {
    pub id: u64,
    pub subscription_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    pub configuration: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct AdminCreateSubscriptionLineItemRequest {
    pub subscription_id: u64,
    pub subscription_type: SubscriptionType,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    pub configuration: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct AdminUpdateSubscriptionLineItemRequest {
    pub subscription_type: Option<SubscriptionType>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub amount: Option<u64>,
    pub setup_amount: Option<u64>,
    pub configuration: Option<serde_json::Value>,
}

impl From<lnvps_db::SubscriptionLineItem> for AdminSubscriptionLineItemInfo {
    fn from(line_item: lnvps_db::SubscriptionLineItem) -> Self {
        Self {
            id: line_item.id,
            subscription_id: line_item.subscription_id,
            name: line_item.name,
            description: line_item.description,
            amount: line_item.amount,
            setup_amount: line_item.setup_amount,
            configuration: line_item.configuration,
        }
    }
}

impl AdminCreateSubscriptionLineItemRequest {
    pub fn to_line_item(&self) -> anyhow::Result<lnvps_db::SubscriptionLineItem> {
        if self.name.trim().is_empty() {
            return Err(anyhow::anyhow!("Line item name cannot be empty"));
        }

        Ok(lnvps_db::SubscriptionLineItem {
            id: 0,
            subscription_id: self.subscription_id,
            subscription_type: self.subscription_type,
            name: self.name.trim().to_string(),
            description: self.description.clone(),
            amount: self.amount,
            setup_amount: self.setup_amount,
            configuration: self.configuration.clone(),
        })
    }
}

// Subscription Payment Models
#[derive(Serialize)]
pub struct AdminSubscriptionPaymentInfo {
    pub id: String, // Hex encoded
    pub subscription_id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: AdminPaymentMethod,
    pub payment_type: ApiSubscriptionPaymentType,
    pub external_id: Option<String>,
    pub is_paid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<DateTime<Utc>>,
    pub rate: f32,
    pub tax: u64,
    pub processing_fee: u64,
}

#[derive(Serialize, Deserialize)]
pub enum ApiSubscriptionPaymentType {
    Purchase,
    Renewal,
}

impl From<lnvps_db::SubscriptionPaymentType> for ApiSubscriptionPaymentType {
    fn from(payment_type: lnvps_db::SubscriptionPaymentType) -> Self {
        match payment_type {
            lnvps_db::SubscriptionPaymentType::Purchase => ApiSubscriptionPaymentType::Purchase,
            lnvps_db::SubscriptionPaymentType::Renewal => ApiSubscriptionPaymentType::Renewal,
        }
    }
}

impl From<ApiSubscriptionPaymentType> for lnvps_db::SubscriptionPaymentType {
    fn from(payment_type: ApiSubscriptionPaymentType) -> Self {
        match payment_type {
            ApiSubscriptionPaymentType::Purchase => lnvps_db::SubscriptionPaymentType::Purchase,
            ApiSubscriptionPaymentType::Renewal => lnvps_db::SubscriptionPaymentType::Renewal,
        }
    }
}

impl From<lnvps_db::SubscriptionPayment> for AdminSubscriptionPaymentInfo {
    fn from(payment: lnvps_db::SubscriptionPayment) -> Self {
        Self {
            id: hex::encode(&payment.id),
            subscription_id: payment.subscription_id,
            user_id: payment.user_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency: payment.currency,
            payment_method: AdminPaymentMethod::from(payment.payment_method),
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            paid_at: payment.paid_at,
            rate: payment.rate,
            tax: payment.tax,
            processing_fee: payment.processing_fee,
        }
    }
}

// IP Space Management Models
#[derive(Serialize)]
pub struct AdminInternetRegistry {
    pub value: u8,
    pub name: String,
}

impl From<lnvps_db::InternetRegistry> for AdminInternetRegistry {
    fn from(registry: lnvps_db::InternetRegistry) -> Self {
        Self {
            value: registry as u8,
            name: registry.to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct AdminAvailableIpSpaceInfo {
    pub id: u64,
    pub company_id: u64,
    pub cidr: String,
    pub min_prefix_size: u16,
    pub max_prefix_size: u16,
    pub registry: AdminInternetRegistry,
    pub external_id: Option<String>,
    pub is_available: bool,
    pub is_reserved: bool,
    pub metadata: Option<serde_json::Value>,
    pub pricing_count: u64, // Number of pricing tiers for this block
}

#[derive(Deserialize)]
pub struct CreateAvailableIpSpaceRequest {
    pub company_id: u64,
    pub cidr: String,
    pub min_prefix_size: u16,
    pub max_prefix_size: u16,
    pub registry: u8, // 0=ARIN, 1=RIPE, 2=APNIC, 3=LACNIC, 4=AFRINIC
    pub external_id: Option<String>,
    pub is_available: Option<bool>, // Default: true
    pub is_reserved: Option<bool>,  // Default: false
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct UpdateAvailableIpSpaceRequest {
    pub cidr: Option<String>,
    pub min_prefix_size: Option<u16>,
    pub max_prefix_size: Option<u16>,
    pub registry: Option<u8>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub external_id: Option<Option<String>>,
    pub is_available: Option<bool>,
    pub is_reserved: Option<bool>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub metadata: Option<Option<serde_json::Value>>,
}

impl From<lnvps_db::AvailableIpSpace> for AdminAvailableIpSpaceInfo {
    fn from(space: lnvps_db::AvailableIpSpace) -> Self {
        Self {
            id: space.id,
            company_id: space.company_id,
            cidr: space.cidr,
            min_prefix_size: space.min_prefix_size,
            max_prefix_size: space.max_prefix_size,
            registry: AdminInternetRegistry::from(space.registry),
            external_id: space.external_id,
            is_available: space.is_available,
            is_reserved: space.is_reserved,
            metadata: space.metadata,
            pricing_count: 0, // Will be filled by handler
        }
    }
}

impl CreateAvailableIpSpaceRequest {
    pub fn to_available_ip_space(&self) -> anyhow::Result<lnvps_db::AvailableIpSpace> {
        use chrono::Utc;
        use lnvps_db::InternetRegistry;

        let registry = match self.registry {
            0 => InternetRegistry::ARIN,
            1 => InternetRegistry::RIPE,
            2 => InternetRegistry::APNIC,
            3 => InternetRegistry::LACNIC,
            4 => InternetRegistry::AFRINIC,
            _ => return Err(anyhow::anyhow!("Invalid registry value")),
        };

        if self.min_prefix_size < self.max_prefix_size {
            return Err(anyhow::anyhow!(
                "min_prefix_size must be greater than or equal to max_prefix_size (smaller prefix number = larger block)"
            ));
        }

        // Parse CIDR to determine if IPv4 or IPv6
        let network: ipnetwork::IpNetwork = self
            .cidr
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR format"))?;
        let is_ipv6 = network.is_ipv6();
        let parent_prefix = network.prefix() as u16;

        // Validate max_prefix_size
        // 1. Must not be smaller than RIR BGP minimum
        // 2. Must not be larger than the parent CIDR block
        let rir_min = if is_ipv6 {
            registry.min_ipv6_prefix_size()
        } else {
            registry.min_ipv4_prefix_size()
        };

        if self.max_prefix_size > rir_min {
            return Err(anyhow::anyhow!(
                "max_prefix_size /{} is too small for BGP announcement (RIR minimum: /{})",
                self.max_prefix_size,
                rir_min
            ));
        }

        if self.max_prefix_size < parent_prefix {
            return Err(anyhow::anyhow!(
                "max_prefix_size /{} cannot be larger than parent CIDR /{}",
                self.max_prefix_size,
                parent_prefix
            ));
        }

        // Validate min_prefix_size is within valid bounds
        let max_prefix_num = if is_ipv6 { 128 } else { 32 };
        if self.min_prefix_size > max_prefix_num {
            return Err(anyhow::anyhow!(
                "min_prefix_size /{} exceeds maximum /{}",
                self.min_prefix_size,
                max_prefix_num
            ));
        }

        Ok(lnvps_db::AvailableIpSpace {
            id: 0, // Will be set by database
            company_id: self.company_id,
            cidr: self.cidr.trim().to_string(),
            min_prefix_size: self.min_prefix_size,
            max_prefix_size: self.max_prefix_size,
            created: Utc::now(),
            updated: Utc::now(),
            registry,
            external_id: self
                .external_id
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            is_available: self.is_available.unwrap_or(true),
            is_reserved: self.is_reserved.unwrap_or(false),
            metadata: self.metadata.clone(),
        })
    }
}

// IP Space Pricing Management Models
#[derive(Serialize)]
pub struct AdminIpSpacePricingInfo {
    pub id: u64,
    pub available_ip_space_id: u64,
    pub prefix_size: u16,
    pub price_per_month: u64, // In cents/millisats
    pub currency: String,
    pub setup_fee: u64,       // In cents/millisats
    pub cidr: Option<String>, // Populated with parent CIDR for context
}

#[derive(Deserialize)]
pub struct CreateIpSpacePricingRequest {
    pub prefix_size: u16,
    pub price_per_month: u64,     // In cents/millisats
    pub currency: Option<String>, // Default: "USD"
    pub setup_fee: Option<u64>,   // Default: 0
}

#[derive(Deserialize)]
pub struct UpdateIpSpacePricingRequest {
    pub prefix_size: Option<u16>,
    pub price_per_month: Option<u64>,
    pub currency: Option<String>,
    pub setup_fee: Option<u64>,
}

impl From<lnvps_db::IpSpacePricing> for AdminIpSpacePricingInfo {
    fn from(pricing: lnvps_db::IpSpacePricing) -> Self {
        Self {
            id: pricing.id,
            available_ip_space_id: pricing.available_ip_space_id,
            prefix_size: pricing.prefix_size,
            price_per_month: pricing.price_per_month,
            currency: pricing.currency,
            setup_fee: pricing.setup_fee,
            cidr: None, // Will be filled by handler
        }
    }
}

impl CreateIpSpacePricingRequest {
    pub fn to_ip_space_pricing(
        &self,
        available_ip_space_id: u64,
    ) -> anyhow::Result<lnvps_db::IpSpacePricing> {
        use chrono::Utc;

        // Validate price is not zero
        if self.price_per_month == 0 {
            return Err(anyhow::anyhow!("price_per_month cannot be 0"));
        }

        Ok(lnvps_db::IpSpacePricing {
            id: 0, // Will be set by database
            available_ip_space_id,
            prefix_size: self.prefix_size,
            price_per_month: self.price_per_month,
            currency: self.currency.clone().unwrap_or_else(|| "USD".to_string()),
            setup_fee: self.setup_fee.unwrap_or(0),
            created: Utc::now(),
            updated: Utc::now(),
        })
    }
}

// IP Range Subscription Management Models
#[derive(Serialize)]
pub struct AdminIpRangeSubscriptionInfo {
    pub id: u64,
    pub subscription_line_item_id: u64,
    pub available_ip_space_id: u64,
    pub cidr: String,
    pub is_active: bool,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
    // Enriched data
    pub subscription_id: Option<u64>,
    pub user_id: Option<u64>,
    pub parent_cidr: Option<String>, // The available_ip_space CIDR this was allocated from
}

impl From<lnvps_db::IpRangeSubscription> for AdminIpRangeSubscriptionInfo {
    fn from(sub: lnvps_db::IpRangeSubscription) -> Self {
        Self {
            id: sub.id,
            subscription_line_item_id: sub.subscription_line_item_id,
            available_ip_space_id: sub.available_ip_space_id,
            cidr: sub.cidr,
            is_active: sub.is_active,
            started_at: sub.started_at,
            ended_at: sub.ended_at,
            metadata: sub.metadata,
            subscription_id: None,
            user_id: None,
            parent_cidr: None,
        }
    }
}

impl AdminIpRangeSubscriptionInfo {
    pub async fn from_subscription_with_admin_data(
        db: &Arc<dyn lnvps_db::LNVpsDb>,
        sub: lnvps_db::IpRangeSubscription,
    ) -> anyhow::Result<Self> {
        let mut info = Self::from(sub.clone());

        // Get line item details
        if let Ok(line_item) = db
            .get_subscription_line_item(sub.subscription_line_item_id)
            .await
        {
            info.subscription_id = Some(line_item.subscription_id);

            // Get subscription details for user_id
            if let Ok(subscription) = db.get_subscription(line_item.subscription_id).await {
                info.user_id = Some(subscription.user_id);
            }
        }

        // Get parent IP space CIDR
        if let Ok(ip_space) = db.get_available_ip_space(sub.available_ip_space_id).await {
            info.parent_cidr = Some(ip_space.cidr);
        }

        Ok(info)
    }
}

// Payment Method Configuration Models

/// Admin payment method enum matching PaymentMethod from lnvps_db
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdminPaymentMethodType {
    Lightning,
    Revolut,
    Paypal,
    Stripe,
}

impl From<lnvps_db::PaymentMethod> for AdminPaymentMethodType {
    fn from(method: lnvps_db::PaymentMethod) -> Self {
        match method {
            lnvps_db::PaymentMethod::Lightning => AdminPaymentMethodType::Lightning,
            lnvps_db::PaymentMethod::Revolut => AdminPaymentMethodType::Revolut,
            lnvps_db::PaymentMethod::Paypal => AdminPaymentMethodType::Paypal,
            lnvps_db::PaymentMethod::Stripe => AdminPaymentMethodType::Stripe,
        }
    }
}

impl From<AdminPaymentMethodType> for lnvps_db::PaymentMethod {
    fn from(method: AdminPaymentMethodType) -> Self {
        match method {
            AdminPaymentMethodType::Lightning => lnvps_db::PaymentMethod::Lightning,
            AdminPaymentMethodType::Revolut => lnvps_db::PaymentMethod::Revolut,
            AdminPaymentMethodType::Paypal => lnvps_db::PaymentMethod::Paypal,
            AdminPaymentMethodType::Stripe => lnvps_db::PaymentMethod::Stripe,
        }
    }
}

// Sanitized provider configs - hide secret values for view-only/display purposes

/// Sanitized LND config (shows paths but not file contents)
#[derive(Serialize)]
pub struct SanitizedLndConfig {
    pub url: String,
    pub cert_path: String,
    pub macaroon_path: String,
}

/// Sanitized Bitvora config (hides token and webhook_secret)
#[derive(Serialize)]
pub struct SanitizedBitvoraConfig {
    /// Whether token is configured
    pub has_token: bool,
    /// Whether webhook secret is configured
    pub has_webhook_secret: bool,
}

/// Sanitized Revolut config (hides token and webhook_secret)
#[derive(Serialize)]
pub struct SanitizedRevolutConfig {
    pub url: String,
    pub api_version: String,
    pub public_key: String,
    /// Whether token is configured
    pub has_token: bool,
    /// Whether webhook secret is configured
    pub has_webhook_secret: bool,
}

/// Sanitized Stripe config (hides secret_key and webhook_secret)
#[derive(Serialize)]
pub struct SanitizedStripeConfig {
    pub publishable_key: String,
    /// Whether secret key is configured
    pub has_secret_key: bool,
    /// Whether webhook secret is configured
    pub has_webhook_secret: bool,
}

/// Sanitized PayPal config (hides client_secret)
#[derive(Serialize)]
pub struct SanitizedPaypalConfig {
    pub client_id: String,
    pub mode: String,
    /// Whether client secret is configured
    pub has_client_secret: bool,
}

/// Sanitized provider configuration - hides all secret/token values
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SanitizedProviderConfig {
    Lnd(SanitizedLndConfig),
    Bitvora(SanitizedBitvoraConfig),
    Revolut(SanitizedRevolutConfig),
    Stripe(SanitizedStripeConfig),
    Paypal(SanitizedPaypalConfig),
}

impl From<&lnvps_db::ProviderConfig> for SanitizedProviderConfig {
    fn from(config: &lnvps_db::ProviderConfig) -> Self {
        match config {
            lnvps_db::ProviderConfig::Lnd(cfg) => {
                SanitizedProviderConfig::Lnd(SanitizedLndConfig {
                    url: cfg.url.clone(),
                    cert_path: cfg.cert_path.display().to_string(),
                    macaroon_path: cfg.macaroon_path.display().to_string(),
                })
            }
            lnvps_db::ProviderConfig::Bitvora(cfg) => {
                SanitizedProviderConfig::Bitvora(SanitizedBitvoraConfig {
                    has_token: !cfg.token.is_empty(),
                    has_webhook_secret: !cfg.webhook_secret.is_empty(),
                })
            }
            lnvps_db::ProviderConfig::Revolut(cfg) => {
                SanitizedProviderConfig::Revolut(SanitizedRevolutConfig {
                    url: cfg.url.clone(),
                    api_version: cfg.api_version.clone(),
                    public_key: cfg.public_key.clone(),
                    has_token: !cfg.token.is_empty(),
                    has_webhook_secret: cfg
                        .webhook_secret
                        .as_ref()
                        .map_or(false, |s| !s.is_empty()),
                })
            }
            lnvps_db::ProviderConfig::Stripe(cfg) => {
                SanitizedProviderConfig::Stripe(SanitizedStripeConfig {
                    publishable_key: cfg.publishable_key.clone(),
                    has_secret_key: !cfg.secret_key.is_empty(),
                    has_webhook_secret: !cfg.webhook_secret.is_empty(),
                })
            }
            lnvps_db::ProviderConfig::Paypal(cfg) => {
                SanitizedProviderConfig::Paypal(SanitizedPaypalConfig {
                    client_id: cfg.client_id.clone(),
                    mode: cfg.mode.clone(),
                    has_client_secret: !cfg.client_secret.is_empty(),
                })
            }
        }
    }
}

/// Admin view of payment method configuration
/// Note: Secret values (tokens, API keys, etc.) are never returned - use sanitized config
#[derive(Serialize)]
pub struct AdminPaymentMethodConfigInfo {
    pub id: u64,
    /// Company this config belongs to - enforces one config per payment method per company
    pub company_id: u64,
    pub payment_method: AdminPaymentMethodType,
    pub name: String,
    pub enabled: bool,
    pub provider_type: String,
    /// Sanitized provider configuration - secrets are hidden (may be None if deserialization fails)
    pub config: Option<SanitizedProviderConfig>,
    /// Processing fee percentage rate (e.g., 1.0 for 1%)
    pub processing_fee_rate: Option<f32>,
    /// Processing fee base amount in smallest currency units (cents for fiat, millisats for BTC)
    pub processing_fee_base: Option<u64>,
    /// Currency for the processing fee base
    pub processing_fee_currency: Option<String>,
    /// Supported currency codes (e.g., ["EUR", "USD"])
    pub supported_currencies: Vec<String>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

impl From<lnvps_db::PaymentMethodConfig> for AdminPaymentMethodConfigInfo {
    fn from(config: lnvps_db::PaymentMethodConfig) -> Self {
        let provider_config = config.get_provider_config();
        // Convert to sanitized config - hide all secret values
        let sanitized_config = provider_config.as_ref().map(SanitizedProviderConfig::from);
        Self {
            id: config.id,
            company_id: config.company_id,
            payment_method: AdminPaymentMethodType::from(config.payment_method),
            name: config.name,
            enabled: config.enabled,
            provider_type: config.provider_type,
            config: sanitized_config,
            processing_fee_rate: config.processing_fee_rate,
            processing_fee_base: config.processing_fee_base,
            processing_fee_currency: config.processing_fee_currency,
            supported_currencies: config.supported_currencies.into_inner(),
            created: config.created,
            modified: config.modified,
        }
    }
}

/// Request to create a new payment method configuration
#[derive(Deserialize)]
pub struct CreatePaymentMethodConfigRequest {
    /// Company this config belongs to - each company can have one config per payment method type
    pub company_id: u64,
    pub name: String,
    pub enabled: Option<bool>,
    /// Typed provider configuration
    pub config: lnvps_db::ProviderConfig,
    pub processing_fee_rate: Option<f32>,
    /// Processing fee base in smallest currency units (cents for fiat, millisats for BTC)
    pub processing_fee_base: Option<u64>,
    pub processing_fee_currency: Option<String>,
    /// Supported currency codes (e.g., ["EUR", "USD"])
    pub supported_currencies: Option<Vec<String>>,
}

impl CreatePaymentMethodConfigRequest {
    pub fn to_payment_method_config(&self) -> anyhow::Result<lnvps_db::PaymentMethodConfig> {
        if self.name.trim().is_empty() {
            return Err(anyhow!("Payment method config name cannot be empty"));
        }

        // Validate that if processing fee base is set, currency must also be set
        if self.processing_fee_base.is_some() && self.processing_fee_currency.is_none() {
            return Err(anyhow!(
                "Processing fee currency is required when processing fee base is set"
            ));
        }

        let mut payment_config = lnvps_db::PaymentMethodConfig::new_with_config(
            self.company_id,
            self.config.payment_method(),
            self.name.trim().to_string(),
            self.enabled.unwrap_or(true),
            self.config.clone(),
        );
        payment_config.processing_fee_rate = self.processing_fee_rate;
        payment_config.processing_fee_base = self.processing_fee_base;
        payment_config.processing_fee_currency = self
            .processing_fee_currency
            .as_ref()
            .map(|s| s.trim().to_uppercase());
        if let Some(currencies) = &self.supported_currencies {
            payment_config.supported_currencies = lnvps_db::CommaSeparated::new(
                currencies.iter().map(|s| s.trim().to_uppercase()).collect(),
            );
        }

        Ok(payment_config)
    }
}

/// Request to update an existing payment method configuration
#[derive(Deserialize)]
pub struct UpdatePaymentMethodConfigRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    /// Partial provider configuration - only provided fields will be updated
    pub config: Option<PartialProviderConfig>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub processing_fee_rate: Option<Option<f32>>,
    /// Processing fee base in smallest currency units (cents for fiat, millisats for BTC)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub processing_fee_base: Option<Option<u64>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub processing_fee_currency: Option<Option<String>>,
    /// Supported currency codes (e.g., ["EUR", "USD"])
    pub supported_currencies: Option<Vec<String>>,
}

// Partial provider config types for updates - all fields are optional

/// Partial LND config for updates
#[derive(Deserialize)]
pub struct PartialLndConfig {
    pub url: Option<String>,
    pub cert_path: Option<std::path::PathBuf>,
    pub macaroon_path: Option<std::path::PathBuf>,
}

/// Partial Bitvora config for updates
#[derive(Deserialize)]
pub struct PartialBitvoraConfig {
    pub token: Option<String>,
    pub webhook_secret: Option<String>,
}

/// Partial Revolut config for updates
#[derive(Deserialize)]
pub struct PartialRevolutConfig {
    pub url: Option<String>,
    pub token: Option<String>,
    pub api_version: Option<String>,
    pub public_key: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub webhook_secret: Option<Option<String>>,
}

/// Partial Stripe config for updates
#[derive(Deserialize)]
pub struct PartialStripeConfig {
    pub secret_key: Option<String>,
    pub publishable_key: Option<String>,
    pub webhook_secret: Option<String>,
}

/// Partial PayPal config for updates
#[derive(Deserialize)]
pub struct PartialPaypalConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub mode: Option<String>,
}

/// Partial provider configuration for updates - only provided fields will be updated
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PartialProviderConfig {
    Lnd(PartialLndConfig),
    Bitvora(PartialBitvoraConfig),
    Revolut(PartialRevolutConfig),
    Stripe(PartialStripeConfig),
    Paypal(PartialPaypalConfig),
}

impl PartialProviderConfig {
    /// Merge this partial config with an existing full config
    /// Returns an error if the types don't match
    pub fn merge_with(
        self,
        existing: &lnvps_db::ProviderConfig,
    ) -> anyhow::Result<lnvps_db::ProviderConfig> {
        use lnvps_db::ProviderConfig;

        match (self, existing) {
            (PartialProviderConfig::Lnd(partial), ProviderConfig::Lnd(existing)) => {
                Ok(ProviderConfig::Lnd(lnvps_db::LndConfig {
                    url: partial.url.unwrap_or_else(|| existing.url.clone()),
                    cert_path: partial
                        .cert_path
                        .unwrap_or_else(|| existing.cert_path.clone()),
                    macaroon_path: partial
                        .macaroon_path
                        .unwrap_or_else(|| existing.macaroon_path.clone()),
                }))
            }
            (PartialProviderConfig::Bitvora(partial), ProviderConfig::Bitvora(existing)) => {
                Ok(ProviderConfig::Bitvora(lnvps_db::BitvoraConfig {
                    token: partial.token.unwrap_or_else(|| existing.token.clone()),
                    webhook_secret: partial
                        .webhook_secret
                        .unwrap_or_else(|| existing.webhook_secret.clone()),
                }))
            }
            (PartialProviderConfig::Revolut(partial), ProviderConfig::Revolut(existing)) => {
                Ok(ProviderConfig::Revolut(lnvps_db::RevolutProviderConfig {
                    url: partial.url.unwrap_or_else(|| existing.url.clone()),
                    token: partial.token.unwrap_or_else(|| existing.token.clone()),
                    api_version: partial
                        .api_version
                        .unwrap_or_else(|| existing.api_version.clone()),
                    public_key: partial
                        .public_key
                        .unwrap_or_else(|| existing.public_key.clone()),
                    webhook_secret: partial
                        .webhook_secret
                        .unwrap_or_else(|| existing.webhook_secret.clone()),
                }))
            }
            (PartialProviderConfig::Stripe(partial), ProviderConfig::Stripe(existing)) => {
                Ok(ProviderConfig::Stripe(lnvps_db::StripeProviderConfig {
                    secret_key: partial
                        .secret_key
                        .unwrap_or_else(|| existing.secret_key.clone()),
                    publishable_key: partial
                        .publishable_key
                        .unwrap_or_else(|| existing.publishable_key.clone()),
                    webhook_secret: partial
                        .webhook_secret
                        .unwrap_or_else(|| existing.webhook_secret.clone()),
                }))
            }
            (PartialProviderConfig::Paypal(partial), ProviderConfig::Paypal(existing)) => {
                Ok(ProviderConfig::Paypal(lnvps_db::PaypalProviderConfig {
                    client_id: partial
                        .client_id
                        .unwrap_or_else(|| existing.client_id.clone()),
                    client_secret: partial
                        .client_secret
                        .unwrap_or_else(|| existing.client_secret.clone()),
                    mode: partial.mode.unwrap_or_else(|| existing.mode.clone()),
                }))
            }
            _ => Err(anyhow!(
                "Cannot change provider type during update. Create a new config instead."
            )),
        }
    }

    /// Get the provider type for validation
    pub fn provider_type(&self) -> &'static str {
        match self {
            PartialProviderConfig::Lnd(_) => "lnd",
            PartialProviderConfig::Bitvora(_) => "bitvora",
            PartialProviderConfig::Revolut(_) => "revolut",
            PartialProviderConfig::Stripe(_) => "stripe",
            PartialProviderConfig::Paypal(_) => "paypal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_template_update_cpu_mfg_can_be_unset_with_null() {
        // When cpu_mfg is null in JSON, it should deserialize to Some(None)
        // allowing us to distinguish "unset to null" from "not provided"
        let json = r#"{"cpu_mfg": null}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, Some(None));
    }

    #[test]
    fn test_vm_template_update_cpu_mfg_can_be_omitted() {
        // When cpu_mfg is not present in JSON, it should deserialize to None
        let json = r#"{}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, None);
    }

    #[test]
    fn test_vm_template_update_cpu_mfg_can_be_set() {
        // When cpu_mfg has a value, it should deserialize to Some(Some(value))
        let json = r#"{"cpu_mfg": "intel"}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, Some(Some("intel".to_string())));
    }

    #[test]
    fn test_vm_template_update_cpu_arch_can_be_unset_with_null() {
        let json = r#"{"cpu_arch": null}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_arch, Some(None));
    }

    #[test]
    fn test_vm_template_update_cpu_features_can_be_unset_with_null() {
        let json = r#"{"cpu_features": null}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_features, Some(None));
    }

    #[test]
    fn test_vm_template_update_cpu_features_can_be_set_to_empty() {
        let json = r#"{"cpu_features": []}"#;
        let req: AdminUpdateVmTemplateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_features, Some(Some(vec![])));
    }

    #[test]
    fn test_custom_pricing_update_cpu_mfg_can_be_unset_with_null() {
        let json = r#"{"cpu_mfg": null}"#;
        let req: UpdateCustomPricingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, Some(None));
    }

    #[test]
    fn test_custom_pricing_update_cpu_mfg_can_be_omitted() {
        let json = r#"{}"#;
        let req: UpdateCustomPricingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, None);
    }

    #[test]
    fn test_custom_pricing_update_cpu_mfg_can_be_set() {
        let json = r#"{"cpu_mfg": "amd"}"#;
        let req: UpdateCustomPricingRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cpu_mfg, Some(Some("amd".to_string())));
    }
}
