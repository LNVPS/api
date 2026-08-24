use anyhow::anyhow;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use lnvps_api_common::{
    ApiDiskInterface, ApiDiskType, ApiIntervalType, ApiOsDistribution,
    ApiSubscriptionLineItemResource, ApiVmTrafficSummary, VmRunningState, quota_period,
};
use lnvps_db::{
    AdminAction, AdminResource, AdminRole, IpRangeAllocationMode, NetworkAccessPolicy,
    OsDistribution, PaymentMethod, RouterKind, SubscriptionPayment, SubscriptionType, VmHistory,
    VmHistoryActionType, VmHostKind,
};

// Admin API Enums - Using enums from common crate where available, creating new ones only where needed

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdminVmHostKind {
    Proxmox,
    Libvirt,
    /// Operator-owned hardware, controlled over the marketplace node daemon's
    /// outbound channel. Reported for existing hosts, but a host of this kind
    /// cannot be *created* through the admin host API: the backing row is
    /// created by node approval, which is what supplies its
    /// `marketplace_node_id`.
    MarketplaceNode,
    Mock,
}

impl From<VmHostKind> for AdminVmHostKind {
    fn from(host_kind: VmHostKind) -> Self {
        match host_kind {
            VmHostKind::Proxmox => AdminVmHostKind::Proxmox,
            VmHostKind::LibVirt => AdminVmHostKind::Libvirt,
            VmHostKind::MarketplaceNode => AdminVmHostKind::MarketplaceNode,
            VmHostKind::Dummy => AdminVmHostKind::Mock,
        }
    }
}

impl From<AdminVmHostKind> for VmHostKind {
    fn from(admin_host_kind: AdminVmHostKind) -> Self {
        match admin_host_kind {
            AdminVmHostKind::Proxmox => VmHostKind::Proxmox,
            AdminVmHostKind::Libvirt => VmHostKind::LibVirt,
            AdminVmHostKind::MarketplaceNode => VmHostKind::MarketplaceNode,
            AdminVmHostKind::Mock => VmHostKind::Dummy,
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
    LinuxSsh,
}

impl From<RouterKind> for AdminRouterKind {
    fn from(router_kind: RouterKind) -> Self {
        match router_kind {
            RouterKind::Mikrotik => AdminRouterKind::Mikrotik,
            RouterKind::OvhAdditionalIp => AdminRouterKind::OvhAdditionalIp,
            RouterKind::LinuxSsh => AdminRouterKind::LinuxSsh,
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
            AdminRouterKind::LinuxSsh => RouterKind::LinuxSsh,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminDnsServerKind {
    Cloudflare,
    Ovh,
}

impl From<lnvps_db::DnsServerKind> for AdminDnsServerKind {
    fn from(kind: lnvps_db::DnsServerKind) -> Self {
        match kind {
            lnvps_db::DnsServerKind::Cloudflare => AdminDnsServerKind::Cloudflare,
            lnvps_db::DnsServerKind::Ovh => AdminDnsServerKind::Ovh,
            // MockDns is a test-only variant; map to Cloudflare as a safe fallback.
            lnvps_db::DnsServerKind::MockDns => AdminDnsServerKind::Cloudflare,
        }
    }
}

impl From<AdminDnsServerKind> for lnvps_db::DnsServerKind {
    fn from(kind: AdminDnsServerKind) -> Self {
        match kind {
            AdminDnsServerKind::Cloudflare => lnvps_db::DnsServerKind::Cloudflare,
            AdminDnsServerKind::Ovh => lnvps_db::DnsServerKind::Ovh,
        }
    }
}

#[derive(Serialize)]
pub struct AdminDnsServerDetail {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: AdminDnsServerKind,
    pub url: String,
    /// Number of IP ranges referencing this DNS server (forward or reverse)
    pub ip_range_count: u64,
}

impl From<lnvps_db::DnsServer> for AdminDnsServerDetail {
    fn from(dns: lnvps_db::DnsServer) -> Self {
        Self {
            id: dns.id,
            name: dns.name,
            enabled: dns.enabled,
            kind: AdminDnsServerKind::from(dns.kind),
            url: dns.url,
            ip_range_count: 0, // Will be filled by handler
        }
    }
}

#[derive(Deserialize)]
pub struct CreateDnsServerRequest {
    pub name: String,
    pub enabled: Option<bool>, // Default: true
    pub kind: AdminDnsServerKind,
    #[serde(default)]
    pub url: String,
    pub token: String,
}

#[derive(Deserialize)]
pub struct UpdateDnsServerRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub kind: Option<AdminDnsServerKind>,
    pub url: Option<String>,
    pub token: Option<String>,
}

impl CreateDnsServerRequest {
    pub fn to_dns_server(&self) -> lnvps_db::DnsServer {
        lnvps_db::DnsServer {
            id: 0, // Will be set by database
            name: self.name.trim().to_string(),
            enabled: self.enabled.unwrap_or(true),
            kind: lnvps_db::DnsServerKind::from(self.kind),
            url: self.url.trim().to_string(),
            token: self.token.as_str().into(),
        }
    }
}

/// The kind of resource a cost record is attached to (weak/polymorphic link).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminCostResourceType {
    VmHost,
    IpRange,
    Generic,
}

impl From<lnvps_db::CostResourceType> for AdminCostResourceType {
    fn from(v: lnvps_db::CostResourceType) -> Self {
        match v {
            lnvps_db::CostResourceType::VmHost => Self::VmHost,
            lnvps_db::CostResourceType::IpRange => Self::IpRange,
            lnvps_db::CostResourceType::Generic => Self::Generic,
        }
    }
}

impl From<AdminCostResourceType> for lnvps_db::CostResourceType {
    fn from(v: AdminCostResourceType) -> Self {
        match v {
            AdminCostResourceType::VmHost => Self::VmHost,
            AdminCostResourceType::IpRange => Self::IpRange,
            AdminCostResourceType::Generic => Self::Generic,
        }
    }
}

/// Recurring vs one-time capital cost.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminCostType {
    Recurring,
    OneTime,
}

impl From<lnvps_db::CostType> for AdminCostType {
    fn from(v: lnvps_db::CostType) -> Self {
        match v {
            lnvps_db::CostType::Recurring => Self::Recurring,
            lnvps_db::CostType::OneTime => Self::OneTime,
        }
    }
}

impl From<AdminCostType> for lnvps_db::CostType {
    fn from(v: AdminCostType) -> Self {
        match v {
            AdminCostType::Recurring => Self::Recurring,
            AdminCostType::OneTime => Self::OneTime,
        }
    }
}

#[derive(Serialize)]
pub struct AdminResourceCostDetail {
    pub id: u64,
    pub resource_type: AdminCostResourceType,
    pub resource_id: u64,
    /// Free-form label for `generic` costs (null for entity-linked costs)
    pub label: Option<String>,
    pub cost_type: AdminCostType,
    /// Cost amount in smallest currency units (per-IP for ip_range recurring)
    pub amount: u64,
    pub currency: String,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<ApiIntervalType>,
    pub billing_start: Option<DateTime<Utc>>,
    pub billing_end: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl From<lnvps_db::ResourceCost> for AdminResourceCostDetail {
    fn from(c: lnvps_db::ResourceCost) -> Self {
        Self {
            id: c.id,
            resource_type: c.resource_type.into(),
            resource_id: c.resource_id,
            label: c.label,
            cost_type: c.cost_type.into(),
            amount: c.amount,
            currency: c.currency,
            interval_amount: c.interval_amount,
            interval_type: c.interval_type.map(Into::into),
            billing_start: c.billing_start,
            billing_end: c.billing_end,
            created: c.created,
            updated: c.updated,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateResourceCostRequest {
    pub resource_type: AdminCostResourceType,
    /// Id within the resource's table. For `generic` costs this is overloaded
    /// as the region id it should be attributed to in the P/L report
    /// (0 = global / not region-specific).
    #[serde(default)]
    pub resource_id: u64,
    /// Required for `generic` costs; optional otherwise
    pub label: Option<String>,
    pub cost_type: AdminCostType,
    pub amount: u64,
    pub currency: String,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<ApiIntervalType>,
    pub billing_start: Option<DateTime<Utc>>,
    pub billing_end: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct UpdateResourceCostRequest {
    /// For `generic` costs, the region id to attribute this cost to in the P/L
    /// report (0 = global). Ignored for entity-linked costs.
    pub resource_id: Option<u64>,
    pub cost_type: Option<AdminCostType>,
    pub amount: Option<u64>,
    pub currency: Option<String>,
    #[serde(default, deserialize_with = "crate::admin::model::double_option")]
    pub label: Option<Option<String>>,
    // Interval / billing fields: present-but-null clears the value, absent leaves unchanged.
    #[serde(default, deserialize_with = "crate::admin::model::double_option")]
    pub interval_amount: Option<Option<u64>>,
    #[serde(default, deserialize_with = "crate::admin::model::double_option")]
    pub interval_type: Option<Option<ApiIntervalType>>,
    #[serde(default, deserialize_with = "crate::admin::model::double_option")]
    pub billing_start: Option<Option<DateTime<Utc>>>,
    #[serde(default, deserialize_with = "crate::admin::model::double_option")]
    pub billing_end: Option<Option<DateTime<Utc>>>,
}

/// Deserialize helper distinguishing an absent field (`None`) from an explicit
/// JSON `null` (`Some(None)`), enabling PATCH semantics that can clear a value.
pub fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
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

impl AdminUserRole {
    /// The role's canonical name as stored in the `admin_roles` table.
    pub fn role_name(&self) -> &'static str {
        match self {
            AdminUserRole::SuperAdmin => "super_admin",
            AdminUserRole::Admin => "admin",
            AdminUserRole::ReadOnly => "read_only",
        }
    }
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
    /// Country (ISO 3166-1 alpha-3) resolved from the client's IP address.
    /// Independent place-of-supply evidence, captured automatically and stored
    /// separately from the self-declared `country_code`.
    pub geo_country_code: Option<String>,
    /// Last client IP address geolocation was resolved from.
    pub geo_ip: Option<String>,
    /// When the geolocation was last resolved (auto-updated on edit).
    pub geo_updated: Option<DateTime<Utc>>,
    // Admin-specific fields
    pub vm_count: u64,
    pub last_login: Option<DateTime<Utc>>,
    pub is_admin: bool,
    pub has_nwc: bool,
    /// Account type: `nostr`, `oauth` or `webauthn`.
    pub account_type: String,
    /// Number of registered passkeys (WebAuthn credentials). Populated on the
    /// single-user detail endpoint; 0 in list responses.
    pub passkey_count: u64,
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
    /// IP-resolved country evidence (ISO 3166-1 alpha-3). Editing either geo
    /// field bumps `geo_updated` to now.
    pub geo_country_code: Option<String>,
    /// Last client IP address geolocation was resolved from.
    pub geo_ip: Option<String>,
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
            geo_country_code: user.geo_country_code,
            geo_ip: user.geo_ip,
            geo_updated: user.geo_updated,
            // Admin-specific fields will be filled by the handler
            vm_count: 0,
            last_login: None,
            is_admin: false,
            // Computed via a DB lookup (AdminUserInfo path); default false here.
            has_nwc: false,
            account_type: user.account_type.to_string(),
            // Populated by the handler (single-user detail) when needed.
            passkey_count: 0,
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
            geo_country_code: user.user_info.geo_country_code,
            geo_ip: user.user_info.geo_ip,
            geo_updated: user.user_info.geo_updated,
            // Admin-specific fields will be filled by the handler
            vm_count: user.vm_count as _,
            last_login: None,
            is_admin: user.is_admin,
            has_nwc: user.has_nwc,
            account_type: user.user_info.account_type.to_string(),
            passkey_count: 0,
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
    /// When the subscription was created (i.e. when the VM was ordered)
    pub created: DateTime<Utc>,
    /// When the VM's subscription expires (None = never paid)
    pub expires: Option<DateTime<Utc>>,
    /// Network MAC address
    pub mac_address: String,
    /// OS Image ID for linking
    pub image_id: u64,
    /// OS Image name/version with distribution (e.g., "Ubuntu 22.04 Server")
    pub image_name: String,
    /// Template ID for linking (standard template if used; `null` for custom templates)
    pub template_id: Option<u64>,
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
    /// Free-form admin-only notes about this VM (not exposed to the customer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_notes: Option<String>,
    /// Subscription linked to this VM (includes line items and payment count)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<AdminSubscriptionInfo>,
    /// Network transfer used in the current UTC calendar month, against the
    /// plan's allowance. Same shape as the customer-facing `VmStatus.traffic`.
    pub traffic: ApiVmTrafficSummary,
}

/// Everything needed to render a batch of VMs as [`AdminVmInfo`], loaded up
/// front with a fixed number of queries.
///
/// Rendering one VM touches a dozen tables. Doing that per VM made a 50-row
/// listing several hundred round trips, so every lookup here is either a whole
/// small shared table (hosts, regions, os images, templates, custom pricing)
/// or a single `IN (...)` query keyed on the batch. Adding a field to
/// [`AdminVmInfo`] means adding a bulk load here — never a query per VM.
pub struct AdminVmBatch {
    pub hosts: HashMap<u64, lnvps_db::VmHost>,
    pub regions: HashMap<u64, lnvps_db::Region>,
    pub users: HashMap<u64, lnvps_db::User>,
    pub os_images: HashMap<u64, lnvps_db::VmOsImage>,
    pub templates: HashMap<u64, lnvps_db::VmTemplate>,
    pub custom_templates: HashMap<u64, lnvps_db::VmCustomTemplate>,
    pub custom_pricing: HashMap<u64, lnvps_db::VmCustomPricing>,
    pub ssh_keys: HashMap<u64, lnvps_db::UserSshKey>,
    /// Non-deleted ip assignments, keyed by vm id
    pub ip_assignments: HashMap<u64, Vec<lnvps_db::VmIpAssignment>>,
    /// `(bytes_in, bytes_out)` over the current quota period, keyed by vm id.
    /// A VM with no traffic rows is absent and reads as zero.
    pub traffic: HashMap<u64, (u64, u64)>,
    /// Subscription owning each VM's line item, keyed by *line item* id
    pub subscriptions_by_line_item: HashMap<u64, lnvps_db::Subscription>,
    /// Rendered subscription payload, keyed by subscription id
    pub subscription_infos: HashMap<u64, AdminSubscriptionInfo>,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
}

impl AdminVmBatch {
    /// Load everything the given VMs need.
    ///
    /// Hosts and regions are read whole (and unfiltered): `enabled` is a
    /// placement flag, and a VM on a disabled host must still render.
    pub async fn load(
        db: &Arc<dyn lnvps_db::LNVpsDb>,
        vms: &[lnvps_db::Vm],
    ) -> anyhow::Result<Self> {
        let (period_start, period_end) = quota_period(Utc::now().date_naive());
        let mut batch = Self {
            hosts: HashMap::new(),
            regions: HashMap::new(),
            users: HashMap::new(),
            os_images: HashMap::new(),
            templates: HashMap::new(),
            custom_templates: HashMap::new(),
            custom_pricing: HashMap::new(),
            ssh_keys: HashMap::new(),
            ip_assignments: HashMap::new(),
            traffic: HashMap::new(),
            subscriptions_by_line_item: HashMap::new(),
            subscription_infos: HashMap::new(),
            period_start,
            period_end,
        };
        if vms.is_empty() {
            return Ok(batch);
        }

        let vm_ids: Vec<u64> = vms.iter().map(|v| v.id).collect();
        let ssh_key_ids = dedup(vms.iter().filter_map(|v| v.ssh_key_id));
        let custom_template_ids = dedup(vms.iter().filter_map(|v| v.custom_template_id));
        let line_item_ids = dedup(vms.iter().map(|v| v.subscription_line_item_id));

        // Small shared tables: one read each, whatever the batch size
        batch.hosts = db
            .list_hosts_all()
            .await?
            .into_iter()
            .map(|h| (h.id, h))
            .collect();
        batch.regions = db
            .list_host_region_all()
            .await?
            .into_iter()
            .map(|r| (r.id, r))
            .collect();
        batch.os_images = db
            .list_os_image()
            .await?
            .into_iter()
            .map(|i| (i.id, i))
            .collect();
        batch.templates = db
            .list_vm_templates_all()
            .await?
            .into_iter()
            .map(|t| (t.id, t))
            .collect();
        batch.custom_pricing = db
            .list_all_custom_pricing()
            .await?
            .into_iter()
            .map(|p| (p.id, p))
            .collect();

        // Per-batch bulk loads
        batch.custom_templates = db
            .list_custom_vm_templates_by_ids(&custom_template_ids)
            .await?
            .into_iter()
            .map(|t| (t.id, t))
            .collect();
        batch.ssh_keys = db
            .list_user_ssh_keys_by_ids(&ssh_key_ids)
            .await?
            .into_iter()
            .map(|k| (k.id, k))
            .collect();
        for ip in db.list_vm_ip_assignments_by_vms(&vm_ids).await? {
            batch.ip_assignments.entry(ip.vm_id).or_default().push(ip);
        }
        batch.traffic = db
            .list_vm_traffic_totals_by_vms(&vm_ids, period_start, period_end)
            .await?
            .into_iter()
            .map(|t| (t.vm_id, (t.bytes_in, t.bytes_out)))
            .collect();

        // Subscriptions: vm -> line item -> subscription, then everything the
        // rendered subscription payload needs for those subscriptions.
        let vm_line_items = db
            .list_subscription_line_items_by_ids(&line_item_ids)
            .await?;
        let subscription_ids = dedup(vm_line_items.iter().map(|li| li.subscription_id));
        let subscriptions: HashMap<u64, lnvps_db::Subscription> = db
            .list_subscriptions_by_ids(&subscription_ids)
            .await?
            .into_iter()
            .map(|s| (s.id, s))
            .collect();
        for li in &vm_line_items {
            if let Some(sub) = subscriptions.get(&li.subscription_id) {
                batch.subscriptions_by_line_item.insert(li.id, sub.clone());
            }
        }

        // Users: VM owners and subscription owners in one read
        let user_ids = dedup(
            vms.iter()
                .map(|v| v.user_id)
                .chain(subscriptions.values().map(|s| s.user_id)),
        );
        batch.users = db
            .list_users_by_ids(&user_ids)
            .await?
            .into_iter()
            .map(|u| (u.id, u))
            .collect();
        let pubkeys: HashMap<u64, String> = batch
            .users
            .iter()
            .map(|(id, u)| (*id, hex::encode(&u.pubkey)))
            .collect();

        batch.subscription_infos =
            AdminSubscriptionInfo::load_many(db, subscriptions.into_values().collect(), &pubkeys)
                .await?
                .into_iter()
                .map(|i| (i.id, i))
                .collect();

        Ok(batch)
    }
}

/// Distinct ids, order-preserving, for an `IN (...)` bulk load.
fn dedup(ids: impl Iterator<Item = u64>) -> Vec<u64> {
    let mut seen = std::collections::HashSet::new();
    ids.filter(|id| seen.insert(*id)).collect()
}

impl AdminVmInfo {
    /// Render one VM from an [`AdminVmBatch`]. Issues no queries: everything
    /// missing from the batch is reported as absent rather than fetched.
    pub fn from_vm_batched(
        vm: &lnvps_db::Vm,
        batch: &AdminVmBatch,
        running_state: Option<VmRunningState>,
    ) -> anyhow::Result<Self> {
        let user = batch
            .users
            .get(&vm.user_id)
            .ok_or_else(|| anyhow!("VM {} references non-existent user {}", vm.id, vm.user_id))?;
        let host = batch
            .hosts
            .get(&vm.host_id)
            .ok_or_else(|| anyhow!("VM {} references non-existent host {}", vm.id, vm.host_id))?;
        let region = batch.regions.get(&host.region_id).ok_or_else(|| {
            anyhow!(
                "Host {} references non-existent region {}",
                host.id,
                host.region_id
            )
        })?;
        let image = batch
            .os_images
            .get(&vm.image_id)
            .ok_or_else(|| anyhow!("VM {} references non-existent image {}", vm.id, vm.image_id))?;

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
            transfer_gb,
        ) = if let Some(template) = vm.template_id.and_then(|id| batch.templates.get(&id)) {
            (
                Some(template.id),
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
                template.transfer_gb,
            )
        } else if let Some(custom_template) = vm
            .custom_template_id
            .and_then(|id| batch.custom_templates.get(&id))
        {
            let pricing_name = batch
                .custom_pricing
                .get(&custom_template.pricing_id)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            (
                None, // No standard template ID
                format!("Custom - {}", pricing_name),
                Some(custom_template.id),
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
                custom_template.transfer_gb,
            )
        } else {
            (
                None,
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
                None,
            )
        };

        let (traffic_in, traffic_out) = batch.traffic.get(&vm.id).copied().unwrap_or((0, 0));

        let ip_addresses = batch
            .ip_assignments
            .get(&vm.id)
            .map(|ips| {
                ips.iter()
                    .map(|ip| AdminVmIpAddress {
                        id: ip.id,
                        ip: ip.ip.clone(),
                        range_id: ip.ip_range_id,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Subscription supplies created/expires/auto-renewal as well as the
        // rendered payload; a VM whose line item has lost its subscription
        // still renders, with those fields left at their neutral values.
        let sub = batch
            .subscriptions_by_line_item
            .get(&vm.subscription_line_item_id);
        let subscription = sub
            .and_then(|s| batch.subscription_infos.get(&s.id))
            .cloned();

        Ok(Self {
            id: vm.id,
            created: sub.map(|s| s.created).unwrap_or_else(Utc::now),
            expires: sub.and_then(|s| s.expires),
            mac_address: vm.mac_address.clone(),
            image_id: vm.image_id,
            image_name: format!("{} {} {}", image.distribution, image.flavour, image.version),
            template_id,
            template_name,
            custom_template_id,
            is_standard_template,
            ssh_key_id: vm.ssh_key_id.unwrap_or(0),
            ssh_key_name: vm
                .ssh_key_id
                .and_then(|id| batch.ssh_keys.get(&id))
                .map(|k| k.name.clone())
                .unwrap_or_default(),
            ip_addresses,
            running_state,
            auto_renewal_enabled: sub.map(|s| s.auto_renewal_enabled).unwrap_or_default(),
            cpu,
            cpu_mfg,
            cpu_arch,
            cpu_features,
            memory,
            disk_size,
            disk_type,
            disk_interface,
            host_id: vm.host_id,
            user_id: vm.user_id,
            user_pubkey: hex::encode(&user.pubkey),
            user_email: if user.email.is_empty() {
                None
            } else {
                Some(user.email.clone().into())
            },
            host_name: host.name.clone(),
            region_id: region.id,
            region_name: region.name.clone(),
            deleted: vm.deleted,
            ref_code: vm.ref_code.clone(),
            disabled: vm.disabled,
            admin_notes: vm.admin_notes.clone(),
            subscription,
            traffic: ApiVmTrafficSummary {
                transfer_gb,
                period_start: batch.period_start,
                period_end: batch.period_end,
                bytes_out: traffic_out,
                bytes_in: traffic_in,
            },
        })
    }
}

/// Date range for an admin traffic query. Both bounds are inclusive UTC dates
/// (`YYYY-MM-DD`) and default to the current calendar month.
#[derive(Deserialize)]
pub struct AdminVmTrafficQuery {
    pub start: Option<NaiveDate>,
    pub end: Option<NaiveDate>,
}

/// One UTC day's transfer for a VM, in bytes.
#[derive(Serialize, Deserialize, Debug)]
pub struct AdminVmTrafficDay {
    pub day: NaiveDate,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// A VM's transfer over a range, plus the current month's use of its allowance.
#[derive(Serialize, Deserialize, Debug)]
pub struct AdminVmTrafficInfo {
    pub vm_id: u64,
    /// Owner, so a traffic investigation does not need a second lookup to know
    /// whose VM this is.
    pub user_id: u64,
    /// Current calendar month, whatever range was requested
    pub summary: ApiVmTrafficSummary,
    /// Daily rows over the requested range, oldest first. Days with no recorded
    /// traffic are omitted.
    pub days: Vec<AdminVmTrafficDay>,
}

/// One VM's transfer totalled over a range, for the fleet-wide report.
#[derive(Serialize, Deserialize, Debug)]
pub struct AdminVmTrafficTotal {
    pub vm_id: u64,
    pub user_id: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
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

#[derive(Eq, PartialEq, Clone, Hash, Debug)]
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
    /// When set, the host is being sunset: disabled for new provisioning and
    /// renewals are capped at this date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset_date: Option<chrono::DateTime<chrono::Utc>>,
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
    /// Bytes consumed by the VM disks placed on this disk.
    /// `None` when the response was produced without a capacity calculation.
    pub usage: Option<u64>,
    /// `usage` as a fraction of the load-adjusted disk size (0.0-1.0, may exceed 1.0
    /// only in the saturated case where it is reported as 1.0).
    /// `None` when the response was produced without a capacity calculation.
    pub load: Option<f32>,
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
            usage: None,
            load: None,
        }
    }
}

impl AdminHostDisk {
    /// Build the disk list for a host, attaching per-disk usage from the host
    /// capacity calculation.
    ///
    /// The disk list comes from `disks` rather than from `capacity.disks` so the
    /// admin UI always sees every configured disk: the capacity calculation may
    /// filter disks by kind/interface, and a disk it skipped is still a disk the
    /// operator manages (it just has no usage figure attached).
    pub fn list_with_capacity(
        disks: Vec<lnvps_db::VmHostDisk>,
        capacity: &lnvps_api_common::HostCapacity,
    ) -> Vec<Self> {
        disks
            .into_iter()
            .map(|disk| {
                let usage = capacity.disks.iter().find(|d| d.disk.id == disk.id);
                let mut admin_disk: Self = disk.into();
                if let Some(usage) = usage {
                    admin_disk.usage = Some(usage.usage);
                    admin_disk.load = Some(usage.load());
                }
                admin_disk
            })
            .collect()
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
    /// Active IPv4 assignments in this region
    pub ipv4_assignments: u64,
    /// Unassigned usable IPv4 addresses across the region's **enabled** IP ranges.
    /// Disabled ranges are not available for allocation so they are not counted.
    pub ipv4_available: u64,
    /// Active IPv6 assignments in this region. There is no matching "available"
    /// figure: an IPv6 range's free space is effectively unbounded.
    pub ipv6_assignments: u64,
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
    pub fn from_host_and_region(host: lnvps_db::VmHost, region: lnvps_db::Region) -> Self {
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
            sunset_date: host.sunset_date,
        }
    }

    pub fn from_host_region_and_disks(
        host: lnvps_db::VmHost,
        region: lnvps_db::Region,
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
            sunset_date: host.sunset_date,
        }
    }

    pub fn from_host_capacity(
        capacity: &lnvps_api_common::HostCapacity,
        region: lnvps_db::Region,
        disks: Vec<lnvps_db::VmHostDisk>,
        active_vms: u64,
    ) -> Self {
        let admin_disks = AdminHostDisk::list_with_capacity(disks, capacity);
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
            sunset_date: capacity.host.sunset_date,
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
            sunset_date: admin_host.host.sunset_date,
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
                // Convert disks, attaching per-disk usage from the capacity calculation
                let admin_disks = AdminHostDisk::list_with_capacity(admin_host.disks, &capacity);
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
                    sunset_date: capacity.host.sunset_date,
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
    /// CPU architecture this image targets (e.g. `x86_64`, `arm64`);
    /// `None` means unspecified/any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_arch: Option<String>,
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
    /// CPU architecture (e.g. `x86_64`, `arm64`). Defaults to `x86_64` when omitted.
    pub cpu_arch: Option<String>,
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
    /// CPU architecture (e.g. `x86_64`, `arm64`); send `null` to reset to unspecified.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub cpu_arch: Option<Option<String>>,
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
            cpu_arch: if matches!(image.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(image.cpu_arch.to_string())
            },
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
            cpu_arch: if matches!(image.cpu_arch, lnvps_db::CpuArch::Unknown) {
                None
            } else {
                Some(image.cpu_arch.to_string())
            },
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
        ApiOsDistribution::AlmaLinux => OsDistribution::AlmaLinux,
        ApiOsDistribution::RockyLinux => OsDistribution::RockyLinux,
        ApiOsDistribution::Alpine => OsDistribution::Alpine,
        ApiOsDistribution::NixOS => OsDistribution::NixOS,
        ApiOsDistribution::OpenBSD => OsDistribution::OpenBSD,
        ApiOsDistribution::NetBSD => OsDistribution::NetBSD,
        ApiOsDistribution::Gentoo => OsDistribution::Gentoo,
        ApiOsDistribution::VoidLinux => OsDistribution::VoidLinux,
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
            // Default to x86_64 when omitted (matches the migration default and
            // the fact that all existing images are x86_64).
            cpu_arch: self
                .cpu_arch
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(lnvps_db::CpuArch::X86_64),
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
    pub ip4_count: u16,
    pub ip6_count: u16,
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
    /// Monthly outbound transfer quota in GB (None = unmetered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_gb: Option<u32>,
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
    /// IPv4 addresses included in this offer (defaults to 1)
    pub ip4_count: Option<u16>,
    /// IPv6 addresses included in this offer (defaults to 1)
    pub ip6_count: Option<u16>,
    // Cost plan creation fields - used when cost_plan_id is not provided
    pub cost_plan_name: Option<String>, // Defaults to "{template_name} Cost Plan"
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC) - required if cost_plan_id not provided
    pub cost_plan_amount: Option<u64>,
    pub cost_plan_currency: Option<String>, // Defaults to "USD"
    pub cost_plan_interval_amount: Option<u64>, // Defaults to 1
    pub cost_plan_interval_type: Option<ApiIntervalType>, // Defaults to Month
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
    /// Monthly outbound transfer quota in GB (None = unmetered)
    pub transfer_gb: Option<u32>,
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
    pub ip4_count: Option<u16>,
    pub ip6_count: Option<u16>,
    // Cost plan update fields - will update the associated cost plan for this template
    pub cost_plan_name: Option<String>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub cost_plan_amount: Option<u64>,
    pub cost_plan_currency: Option<String>,
    pub cost_plan_interval_amount: Option<u64>,
    pub cost_plan_interval_type: Option<ApiIntervalType>,
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
    /// Monthly outbound transfer quota in GB — use `null` to clear (unmetered)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub transfer_gb: Option<Option<u32>>,
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
    pub min_ip4: u16,
    pub max_ip4: u16,
    pub min_ip6: u16,
    pub max_ip6: u16,
    pub disk_pricing: Vec<AdminCustomPricingDisk>,
    pub template_count: u64,
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
    /// Monthly outbound transfer quota in GB granted to VMs on this plan
    /// (None = unmetered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_gb: Option<u32>,
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
    pub min_ip4: Option<u16>,
    pub max_ip4: Option<u16>,
    pub min_ip6: Option<u16>,
    pub max_ip6: Option<u16>,
    pub disk_pricing: Option<Vec<CreateCustomPricingDisk>>,
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
    /// Monthly outbound transfer quota in GB — use `null` to clear (unmetered)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub transfer_gb: Option<Option<u32>>,
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
    /// Minimum IPv4 addresses selectable (defaults to 1)
    pub min_ip4: Option<u16>,
    /// Maximum IPv4 addresses selectable (defaults to 1)
    pub max_ip4: Option<u16>,
    /// Minimum IPv6 addresses selectable (defaults to 1)
    pub min_ip6: Option<u16>,
    /// Maximum IPv6 addresses selectable (defaults to 1)
    pub max_ip6: Option<u16>,
    pub disk_pricing: Vec<CreateCustomPricingDisk>,
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
    /// Monthly outbound transfer quota in GB (None = unmetered)
    pub transfer_gb: Option<u32>,
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
    /// Default referral commission for VMs sold by this company, as a whole
    /// percentage of a referred VM's first payment (0 = disabled).
    pub referral_rate: f32,
    /// Maximum number of days a subscription may be prepaid/renewed in advance
    /// (0 = inherit the global default).
    pub max_prepay_days: u16,
    /// One-off fee charged per marketplace node before an admin can approve it,
    /// in this company's `base_currency`. `0` requires no fee.
    pub marketplace_node_fee: u64,
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
    /// Default referral commission %, whole percentage (default 0).
    pub referral_rate: Option<f32>,
    /// Maximum prepay/renewal window in days (0 = inherit the global default).
    pub max_prepay_days: Option<u16>,
    /// One-off marketplace node listing fee, in the company's base currency.
    pub marketplace_node_fee: Option<u64>,
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
    /// Default referral commission %, whole percentage.
    pub referral_rate: Option<f32>,
    /// Maximum prepay/renewal window in days (0 = inherit the global default).
    pub max_prepay_days: Option<u16>,
    /// One-off marketplace node listing fee, in the company's base currency.
    pub marketplace_node_fee: Option<u64>,
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
            referral_rate: company.referral_rate,
            max_prepay_days: company.max_prepay_days,
            marketplace_node_fee: company.marketplace_node_fee,
            region_count: 0, // Will be filled by handler
        }
    }
}

// Referral Program Management Models

/// A referral enrollment as seen by admins. Never exposes NWC secrets (the NWC
/// connection lives on the user's payment method, not here).
#[derive(Serialize)]
pub struct AdminReferralInfo {
    pub id: u64,
    pub user_id: u64,
    /// Owner's Nostr pubkey (hex), for cross-referencing with users.
    pub user_pubkey: String,
    pub code: String,
    /// Payout target address; its type is determined by `mode` (Lightning
    /// address for `lightning_address`, Bitcoin address for `on_chain`, absent
    /// for `nwc`).
    pub address: Option<String>,
    /// Payout method: `lightning_address`, `nwc`, `account_credit`, or
    /// `on_chain`.
    pub mode: String,
    /// Per-referrer commission override (whole %); `null` = use company default.
    pub referral_rate: Option<f32>,
    /// User-chosen minimum accrued commission (satoshis) before an automated
    /// payout; `null` = use the system minimum. Effective threshold is
    /// `max(system minimum, this value)`, judged against the referrer's total
    /// outstanding commission across every currency.
    pub payout_threshold: Option<u64>,
    pub created: DateTime<Utc>,
}

/// Per-currency earned commission for a referral.
#[derive(Serialize)]
pub struct AdminReferralEarning {
    pub currency: String,
    /// Commission earned = sum of (first payment * effective_rate%) in this currency.
    pub amount: u64,
}

/// What a referral is still owed in one settled currency, and what that is
/// worth in millisats — the unit the payout threshold is expressed in.
#[derive(Serialize)]
pub struct AdminReferralBalance {
    pub currency: String,
    /// Commission earned in this currency (smallest unit).
    pub earned: u64,
    /// Already paid **or reserved** against this currency (amount + fee), in
    /// its smallest unit. A payout nets the currency it settles, not the one it
    /// sent.
    pub settled: u64,
    /// Still owed = `earned - settled`, in the currency's smallest unit.
    pub outstanding: u64,
    /// `outstanding` valued in millisats at the current rate (identical to
    /// `outstanding` for BTC). `null` when no rate is available for the
    /// currency, in which case it is also excluded from
    /// `outstanding_total_msat`.
    pub outstanding_msat: Option<u64>,
}

/// A payout record for a referral (admin view; includes preimage for audit).
///
/// A payout has a settled side (`amount`, `fee`, `currency`) — what it
/// discharges against the earned balance — and a sent side (`sent_amount`,
/// `sent_fee`, `sent_currency`) — what left the wallet. They are equal, with
/// `rate` 1 and `rate_collected` null, when no conversion happened.
#[derive(Serialize)]
pub struct AdminReferralPayoutInfo {
    pub id: u64,
    pub amount: u64,
    /// Network/routing fee charged to the referrer (smallest unit of
    /// `currency`), debited from their balance alongside `amount`.
    pub fee: u64,
    pub currency: String,
    /// Amount actually transferred, in the smallest unit of `sent_currency`.
    pub sent_amount: u64,
    /// Network/routing fee as the network charged it, in the smallest unit of
    /// `sent_currency`.
    pub sent_fee: u64,
    /// Currency actually transferred.
    pub sent_currency: String,
    /// Settled-currency standard units per one sent-currency standard unit; 1
    /// when the two currencies are the same.
    pub rate: f32,
    /// When `rate` was quoted; null when no conversion happened.
    pub rate_collected: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub is_paid: bool,
    /// How this payout was made: `lightning_address`, `nwc`, or `on_chain`.
    pub mode: String,
    /// The payout output reference: a BOLT11 invoice for a Lightning payout, or
    /// the on-chain outpoint (`"{txid}:{vout}"`) for an on-chain payout. Rows
    /// batched into one transaction share the txid but carry distinct vouts.
    pub output: Option<String>,
    /// Payment preimage (hex), when a Lightning payout has been settled.
    pub pre_image: Option<String>,
}

impl From<lnvps_db::ReferralPayout> for AdminReferralPayoutInfo {
    fn from(p: lnvps_db::ReferralPayout) -> Self {
        Self {
            id: p.id,
            amount: p.amount,
            fee: p.fee,
            currency: p.currency,
            sent_amount: p.sent_amount,
            sent_fee: p.sent_fee,
            sent_currency: p.sent_currency,
            rate: p.rate,
            rate_collected: p.rate_collected,
            created: p.created,
            is_paid: p.is_paid,
            mode: p.mode.to_string(),
            output: p.output,
            pre_image: p.pre_image.map(hex::encode),
        }
    }
}

/// Full referral detail: enrollment + earnings + payout history + counts.
#[derive(Serialize)]
pub struct AdminReferralDetail {
    #[serde(flatten)]
    pub referral: AdminReferralInfo,
    pub earned: Vec<AdminReferralEarning>,
    /// Outstanding (unpaid, unreserved) commission per settled currency.
    pub balances: Vec<AdminReferralBalance>,
    /// Everything still owed, valued in millisats at current rates — the figure
    /// the payout threshold is judged against, so it can be compared directly
    /// with `payout_threshold` (satoshis × 1000) and the system minimum.
    /// Currencies with no available rate are excluded.
    pub outstanding_total_msat: u64,
    pub payouts: Vec<AdminReferralPayoutInfo>,
    /// Referred VMs that made at least one payment.
    pub referrals_success: u64,
    /// Referred VMs that never made a payment.
    pub referrals_failed: u64,
}

/// Update a referral's admin-controlled fields (referral code and/or commission override).
#[derive(Deserialize)]
pub struct AdminUpdateReferralRequest {
    /// Rename the referral code. Used to relink a user's enrollment to a
    /// historical `vm.ref_code` that was tracked before the user auto-generated
    /// their own code. Omitted leaves it unchanged.
    #[serde(default)]
    pub code: Option<String>,
    /// Set (`Some(Some(rate))`) or clear (`Some(None)`) the per-referrer
    /// commission override, as a whole percentage; omitted leaves it unchanged.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub referral_rate: Option<Option<f32>>,
    /// Set (`Some(Some(sats))`) or clear (`Some(None)`) the referrer's
    /// minimum-payout threshold in satoshis; omitted leaves it unchanged. Not
    /// bounded by the system minimum here (admin override).
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub payout_threshold: Option<Option<u64>>,
}

/// Create a manual payout record for a referral.
#[derive(Deserialize)]
pub struct AdminCreateReferralPayoutRequest {
    /// Settled amount in the smallest unit of `currency`: what this payout takes
    /// off the earned balance.
    pub amount: u64,
    /// Currency this payout settles against (e.g. `BTC`, `EUR`) — the currency
    /// the commission was earned in.
    pub currency: String,
    /// Currency actually transferred, when it differs from `currency`. Omit (or
    /// repeat `currency`) for a payout that sent what it settles.
    pub sent_currency: Option<String>,
    /// Amount actually transferred, in the smallest unit of `sent_currency`.
    /// Required when `sent_currency` differs from `currency`.
    pub sent_amount: Option<u64>,
    /// Network/routing fee as the network charged it, in the smallest unit of
    /// `sent_currency`. Defaults to 0.
    pub sent_fee: Option<u64>,
    /// Network/routing fee charged to the referrer, in the smallest unit of
    /// `currency`. Defaults to 0.
    pub fee: Option<u64>,
    /// Settled-currency standard units per one sent-currency standard unit.
    /// Required, and must be greater than 0, when the currencies differ;
    /// rejected when they are the same.
    pub rate: Option<f32>,
    /// When the rate was quoted. Defaults to now for a converted payout;
    /// rejected when no conversion happened.
    pub rate_collected: Option<DateTime<Utc>>,
    /// Optional payout output reference (BOLT11 invoice or on-chain outpoint).
    pub output: Option<String>,
    /// Optional payout mode (`lightning_address`, `nwc`, `on_chain`); defaults
    /// to `lightning_address` when omitted.
    pub mode: Option<String>,
    /// Mark the payout as already paid (e.g. reconciling an out-of-band payment).
    #[serde(default)]
    pub is_paid: bool,
}

/// Update / reconcile a payout record.
#[derive(Deserialize)]
pub struct AdminUpdateReferralPayoutRequest {
    /// Mark paid / unpaid.
    pub is_paid: Option<bool>,
    /// Set or clear the payout output reference (BOLT11 invoice or on-chain
    /// outpoint `"{txid}:{vout}"`).
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub output: Option<Option<String>>,
    /// Change the payout mode (`lightning_address`, `nwc`, `on_chain`).
    pub mode: Option<String>,
    /// Set or clear the payment preimage (hex-encoded, 32 bytes).
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub pre_image: Option<Option<String>>,
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
    pub forward_dns_server_id: Option<u64>,
    pub reverse_dns_server_id: Option<u64>,
    pub forward_zone_id: Option<String>,
    pub assignment_count: u64, // Number of active IP assignments in this range
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_ips: Option<u64>, // Number of available IPs (only for IPv4 ranges)
    /// Routers that route this range, resolved via the range's access policy.
    /// Empty when the range has no access policy or the policy has no router.
    pub routers: Vec<AdminIpRangeRouter>,
}

/// A router associated with an IP range (via its access policy)
#[derive(Serialize, Clone)]
pub struct AdminIpRangeRouter {
    pub id: u64,
    pub name: String,
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
    pub forward_dns_server_id: Option<u64>,
    pub reverse_dns_server_id: Option<u64>,
    pub forward_zone_id: Option<String>,
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
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub forward_dns_server_id: Option<Option<u64>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub reverse_dns_server_id: Option<Option<u64>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub forward_zone_id: Option<Option<String>>,
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
            forward_dns_server_id: ip_range.forward_dns_server_id,
            reverse_dns_server_id: ip_range.reverse_dns_server_id,
            forward_zone_id: ip_range.forward_zone_id,
            assignment_count: 0, // Will be filled by handler
            available_ips: None, // Will be filled by handler for IPv4 ranges
            routers: Vec::new(), // Will be filled by handler
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
            forward_dns_server_id: self.forward_dns_server_id,
            reverse_dns_server_id: self.reverse_dns_server_id,
            forward_zone_id: self
                .forward_zone_id
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
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

/// A cached tunnel discovered on a router
#[derive(Serialize)]
pub struct AdminRouterTunnel {
    pub id: u64,
    pub router_id: u64,
    pub name: String,
    /// Tunnel type: `"gre"`, `"vxlan"` or `"wireguard"`
    pub kind: String,
    /// Local tunnel endpoint. `"any"` means no specific endpoint is bound
    /// (e.g. the catch-all `gre0`/`gretap0` template devices, usually unused).
    pub local_addr: Option<String>,
    /// Remote tunnel endpoint. `"any"` means no specific endpoint is bound.
    pub remote_addr: Option<String>,
    /// **Administrative** state. `true` = the interface is configured and not
    /// shut down. Independent of whether the tunnel is actually passing traffic.
    pub enabled: bool,
    /// When the background sampler last observed this interface in the router's
    /// inventory (not a traffic timestamp).
    pub last_seen: DateTime<Utc>,
}

impl From<lnvps_db::RouterTunnel> for AdminRouterTunnel {
    fn from(t: lnvps_db::RouterTunnel) -> Self {
        let kind = match t.kind {
            lnvps_db::RouterTunnelKind::Gre => "gre",
            lnvps_db::RouterTunnelKind::Vxlan => "vxlan",
            lnvps_db::RouterTunnelKind::Wireguard => "wireguard",
        }
        .to_string();
        Self {
            id: t.id,
            router_id: t.router_id,
            name: t.name,
            kind,
            local_addr: t.local_addr,
            remote_addr: t.remote_addr,
            enabled: t.enabled,
            last_seen: t.last_seen,
        }
    }
}

/// A single per-tunnel traffic sample
#[derive(Serialize)]
pub struct AdminRouterTunnelTraffic {
    pub tunnel_name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub sampled_at: DateTime<Utc>,
}

impl From<lnvps_db::RouterTunnelTraffic> for AdminRouterTunnelTraffic {
    fn from(t: lnvps_db::RouterTunnelTraffic) -> Self {
        Self {
            tunnel_name: t.tunnel_name,
            rx_bytes: t.rx_bytes,
            tx_bytes: t.tx_bytes,
            sampled_at: t.sampled_at,
        }
    }
}

/// A cached BGP session on a router
#[derive(Serialize)]
pub struct AdminRouterBgpSession {
    pub id: u64,
    pub router_id: u64,
    /// Backend session id used for toggling (protocol name / RouterOS .id)
    pub name: String,
    pub peer_ip: Option<String>,
    pub peer_asn: Option<u32>,
    pub local_asn: Option<u32>,
    /// **Operational** BGP FSM state, reported live by the routing daemon and
    /// copied verbatim. This is NOT a boolean and does NOT mean "disabled".
    /// Progression: `Idle` -> `Connect` -> `Active` -> `OpenSent` ->
    /// `OpenConfirm` -> `Established`, plus `Down` (BIRD: protocol not started
    /// or not up). Only `Established` means the session is up and exchanging
    /// routes. `Active` = locally trying to reach an unresponsive peer.
    ///
    /// Independent of [`enabled`](Self::enabled): a session can be
    /// `enabled == true` (admin on) while `state == "Down"` (protocol not up).
    pub state: String,
    /// Routes received from the peer; `None` until the session is `Established`.
    pub prefixes_received: Option<u64>,
    /// Routes advertised to the peer; `None` until the session is `Established`.
    pub prefixes_sent: Option<u64>,
    /// **Administrative** state. `true` = the session is configured and not
    /// administratively shut down (operator wants it up). NOT the same as the
    /// session being up — see [`state`](Self::state). Changed via the toggle
    /// endpoint.
    pub enabled: bool,
    /// Peer classification relative to us: `"upstream"` (transit), `"downstream"`
    /// (customer), `"peer"` (settlement-free peer) or `"unknown"` (not yet
    /// classified — common for sessions that are not `Established`).
    pub direction: String,
    /// When the background sampler last refreshed this session's cached state.
    pub last_seen: DateTime<Utc>,
}

impl From<lnvps_db::RouterBgpSession> for AdminRouterBgpSession {
    fn from(s: lnvps_db::RouterBgpSession) -> Self {
        let direction = match s.direction {
            lnvps_db::RouterBgpDirection::Upstream => "upstream",
            lnvps_db::RouterBgpDirection::Downstream => "downstream",
            lnvps_db::RouterBgpDirection::Peer => "peer",
            lnvps_db::RouterBgpDirection::Unknown => "unknown",
        }
        .to_string();
        Self {
            id: s.id,
            router_id: s.router_id,
            name: s.name,
            peer_ip: s.peer_ip,
            peer_asn: s.peer_asn,
            local_asn: s.local_asn,
            state: s.state,
            prefixes_received: s.prefixes_received,
            prefixes_sent: s.prefixes_sent,
            enabled: s.enabled,
            direction,
            last_seen: s.last_seen,
        }
    }
}

/// A cached BGP route on a router (locally-originated prefix or default route)
#[derive(Serialize)]
pub struct AdminRouterBgpRoute {
    pub router_id: u64,
    /// Destination prefix in CIDR notation
    pub prefix: String,
    /// Next hop / gateway, if any
    pub next_hop: Option<String>,
    /// Whether this entry is the router's default route
    pub is_default: bool,
    /// When the background sampler last refreshed this route's cached state.
    pub last_seen: DateTime<Utc>,
}

impl From<lnvps_db::RouterBgpRoute> for AdminRouterBgpRoute {
    fn from(r: lnvps_db::RouterBgpRoute) -> Self {
        Self {
            router_id: r.router_id,
            prefix: r.prefix,
            next_hop: r.next_hop,
            is_default: r.is_default,
            last_seen: r.last_seen,
        }
    }
}

/// Toggle a BGP session on/off
#[derive(Deserialize)]
pub struct ToggleBgpSessionRequest {
    /// Backend session id (protocol name on BIRD, `.id` on Mikrotik)
    pub session_id: String,
    pub enabled: bool,
}

/// Enable or disable a tunnel
#[derive(Deserialize)]
pub struct ToggleTunnelRequest {
    pub enabled: bool,
}

/// Set the static default route on a router
#[derive(Deserialize)]
pub struct SetDefaultRouteRequest {
    /// Next-hop / gateway address. The address family (`0.0.0.0/0` vs `::/0`) is
    /// inferred from this value.
    pub next_hop: String,
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
    pub interval_type: ApiIntervalType,
    pub template_count: u64, // Number of VM templates using this cost plan
}

#[derive(Deserialize)]
pub struct AdminCreateCostPlanRequest {
    pub name: String,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
}

#[derive(Deserialize)]
pub struct AdminUpdateCostPlanRequest {
    pub name: Option<String>,
    /// Cost amount in smallest currency units (cents for fiat, millisats for BTC)
    pub amount: Option<u64>,
    pub currency: Option<String>,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<ApiIntervalType>,
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
            interval_type: ApiIntervalType::from(cost_plan.interval_type),
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
    Transferred,
    Refunded,
    Migrated,
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
            VmHistoryActionType::Refunded => AdminVmHistoryActionType::Refunded,
            VmHistoryActionType::ConfigurationChanged => {
                AdminVmHistoryActionType::ConfigurationChanged
            }
            VmHistoryActionType::Transferred => AdminVmHistoryActionType::Transferred,
            VmHistoryActionType::Migrated => AdminVmHistoryActionType::Migrated,
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
    /// VM state before the action, as recorded by `VmHistoryLogger` (JSON, `None` when not recorded)
    pub previous_state: Option<serde_json::Value>,
    /// VM state after the action (JSON, `None` when not recorded)
    pub new_state: Option<serde_json::Value>,
    /// Extra context for the action, e.g. reason/admin_action flags (JSON, `None` when not recorded)
    pub metadata: Option<serde_json::Value>,
}

/// Decode a `vm_history` JSON blob.
///
/// The columns are `BLOB`s written with `serde_json::to_vec`, but nothing at the
/// database level guarantees that — rows predating the current writers, or a
/// truncated write, would otherwise fail the whole request. An undecodable blob
/// is therefore reported as absent rather than an error.
fn decode_history_json(bytes: Option<&Vec<u8>>) -> Option<serde_json::Value> {
    bytes.and_then(|b| serde_json::from_slice(b).ok())
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
            previous_state: decode_history_json(history.previous_state.as_ref()),
            new_state: decode_history_json(history.new_state.as_ref()),
            metadata: decode_history_json(history.metadata.as_ref()),
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
    OnChain,
}

impl From<PaymentMethod> for AdminPaymentMethod {
    fn from(payment_method: PaymentMethod) -> Self {
        match payment_method {
            PaymentMethod::Lightning => AdminPaymentMethod::Lightning,
            PaymentMethod::Revolut => AdminPaymentMethod::Revolut,
            PaymentMethod::Paypal => AdminPaymentMethod::Paypal,
            PaymentMethod::Stripe => AdminPaymentMethod::Stripe,
            PaymentMethod::OnChain => AdminPaymentMethod::OnChain,
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
    /// Subscription expiry date (None = never paid)
    pub expires: Option<DateTime<Utc>>,
    /// Seconds remaining until subscription expires (0 if not set)
    pub seconds_remaining: i64,
}

/// The discount applied to one payment, as seen from the payment.
///
/// Without this a discounted payment is indistinguishable from a plain
/// cheaper one in an admin payment table (issue #384).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AdminPaymentDiscountInfo {
    pub discount_id: u64,
    /// The code the customer entered. `None` for a code-less (automatic) discount.
    pub code: Option<String>,
    /// What was taken off, in minor units of [`Self::currency`].
    pub amount_off: u64,
    pub currency: String,
    /// False while the discounted invoice is unpaid: the redemption consumes no
    /// limit and has not yet cost the campaign anything.
    pub settled: bool,
}

impl From<lnvps_db::DiscountRedemptionWithCode> for AdminPaymentDiscountInfo {
    fn from(r: lnvps_db::DiscountRedemptionWithCode) -> Self {
        Self {
            discount_id: r.redemption.discount_id,
            code: r.discount_code,
            amount_off: r.redemption.amount_off,
            currency: r.redemption.currency,
            settled: r.redemption.settled,
        }
    }
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
    /// What this row is. A `refund` row's `amount`/`tax` are the magnitude
    /// returned to the customer, so anything totalling a VM's payments must
    /// subtract it rather than add it (issue #193).
    pub payment_type: ApiSubscriptionPaymentType,
    /// For a `refund` row, the hex id of the payment it reverses; null otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refunded_payment_id: Option<String>,
    /// The discount applied to this payment, if any. `amount` is already net of
    /// it — this only says which code was used and how much came off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discount: Option<AdminPaymentDiscountInfo>,
    // Note: external_data is omitted as it may contain sensitive payment provider data
}

/// Refunds recorded against one payment, with what is still refundable on it.
#[derive(Serialize)]
pub struct AdminPaymentRefundsInfo {
    /// Hex id of the payment these refunds reverse.
    pub payment_id: String,
    /// Currency of the payment and of every amount in this response.
    pub currency: String,
    /// Gross amount originally charged, in the smallest unit.
    pub amount: u64,
    /// Sum of the refunds already recorded against it.
    pub refunded_total: u64,
    /// `amount - refunded_total`: the ceiling on the next refund.
    pub refundable_remaining: u64,
    /// The refund rows themselves, oldest first.
    pub refunds: Vec<AdminVmPaymentInfo>,
}

impl AdminVmPaymentInfo {
    pub fn from_subscription_payment(
        payment: &SubscriptionPayment,
        vm_id: u64,
        company_base_currency: String,
    ) -> Self {
        Self {
            id: hex::encode(&payment.id),
            vm_id,
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
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            refunded_payment_id: payment.refunded_payment_id.as_ref().map(hex::encode),
            discount: None,
        }
    }

    /// Attach the discount applied to this payment, if one was.
    ///
    /// Separate from the constructor so listings can resolve a whole page of
    /// discounts in one query and hand each row its own.
    pub fn with_discount(mut self, discount: Option<AdminPaymentDiscountInfo>) -> Self {
        self.discount = discount;
        self
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
    /// Optional recipient targeting; when absent, message all active customers.
    #[serde(default)]
    pub target: Option<lnvps_db::BulkMessageTarget>,
    /// Resolve the recipient list and report it without sending anything.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize)]
pub struct BulkMessageResponse {
    pub job_dispatched: bool,
    pub job_id: Option<String>,
    /// How many users the target resolved to (both runs and dry runs).
    pub recipient_count: u64,
    /// How many of those have at least one usable contact method.
    pub reachable_count: u64,
    /// Users matched by the target that have no contact method at all and so
    /// will not be messaged. Reported rather than silently dropped.
    pub unreachable_users: Vec<BulkMessageUnreachableUser>,
    /// Per-channel recipient counts, keyed by contact method
    /// (`email`, `nip17`, `telegram`, `whatsapp`). A user opted into several
    /// channels counts once per channel.
    pub channel_counts: HashMap<String, u64>,
}

#[derive(Serialize)]
pub struct BulkMessageUnreachableUser {
    pub user_id: u64,
    /// Billing name if known, to make the user identifiable in the report.
    pub billing_name: Option<String>,
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

/// Create a VM from a custom spec, priced against a custom pricing plan.
///
/// Mirrors the customer custom-order body: the region comes from `pricing_id`,
/// and `ssh_key_id` must be one of the target user's own keys.
#[derive(Deserialize)]
pub struct AdminCreateCustomVmRequest {
    pub user_id: u64,
    /// Spec fields are flattened into this body, matching the customer order shape.
    #[serde(flatten)]
    pub spec: lnvps_api_common::CustomVmSpec,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
    pub reason: Option<String>,
}

/// Request to import an existing host VM into the database (issue #166)
#[derive(Deserialize)]
pub struct AdminImportVmRequest {
    /// Raw host VM id (e.g. Proxmox vmid)
    pub host_vm_id: i64,
    /// User the imported VM is assigned to
    pub user_id: u64,
    pub reason: Option<String>,
}

/// A VM present on a host that is not tracked in the database
#[derive(Serialize)]
pub struct AdminUnmanagedVmInfo {
    /// Raw host VM id (e.g. Proxmox vmid)
    pub host_vm_id: i64,
    /// Database id this VM would map to on import
    pub mapped_vm_id: Option<u64>,
    pub name: Option<String>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_storage: Option<String>,
    pub mac_address: Option<String>,
    pub running: bool,
}

impl From<lnvps_api_common::HostVmSpec> for AdminUnmanagedVmInfo {
    fn from(s: lnvps_api_common::HostVmSpec) -> Self {
        Self {
            host_vm_id: s.host_vm_id,
            mapped_vm_id: s.mapped_vm_id,
            name: s.name,
            cpu: s.cpu,
            memory: s.memory,
            disk_size: s.disk_size,
            disk_storage: s.disk_storage,
            mac_address: s.mac_address,
            running: s.running,
        }
    }
}

// ============================================================================
// Subscription Models
// ============================================================================

#[derive(Serialize, Clone)]
pub struct AdminSubscriptionInfo {
    pub id: u64,
    pub user_id: u64,
    /// Hex-encoded Nostr pubkey of the owning user
    pub user_pubkey: String,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub is_setup: bool,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
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
    /// Number of intervals per billing cycle (default 1)
    #[serde(default = "default_interval_amount")]
    pub interval_amount: u64,
    /// Interval unit: "day", "month", or "year" (default "month")
    #[serde(default = "default_interval_type")]
    pub interval_type: ApiIntervalType,
    pub setup_fee: u64,
    pub auto_renewal_enabled: bool,
    pub external_id: Option<String>,
}

fn default_interval_amount() -> u64 {
    1
}

fn default_interval_type() -> ApiIntervalType {
    ApiIntervalType::Month
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
            // Populated by `from_subscription` which has DB access to resolve the pubkey
            user_pubkey: String::new(),
            name: subscription.name,
            description: subscription.description,
            created: subscription.created,
            expires: subscription.expires,
            is_active: subscription.is_active,
            is_setup: subscription.is_setup,
            currency: subscription.currency,
            interval_amount: subscription.interval_amount,
            interval_type: ApiIntervalType::from(subscription.interval_type),
            setup_fee: subscription.setup_fee,
            auto_renewal_enabled: subscription.auto_renewal_enabled,
            external_id: subscription.external_id,
            line_items: Vec::new(),
            payment_count: 0,
        }
    }
}

impl AdminSubscriptionInfo {
    /// Render many subscriptions with a fixed number of queries: one for their
    /// line items, one per resource table behind those line items, and one for
    /// the payment counts.
    ///
    /// `pubkeys` is the caller's already-loaded owner index (subscriptions are
    /// always rendered alongside their users, so re-reading them here would be
    /// a second pass over the same rows); an owner missing from it renders as
    /// an empty pubkey rather than failing the row.
    pub async fn load_many(
        db: &Arc<dyn lnvps_db::LNVpsDb>,
        subscriptions: Vec<lnvps_db::Subscription>,
        pubkeys: &HashMap<u64, String>,
    ) -> anyhow::Result<Vec<Self>> {
        if subscriptions.is_empty() {
            return Ok(vec![]);
        }
        let ids: Vec<u64> = subscriptions.iter().map(|s| s.id).collect();

        let line_items = db
            .list_subscription_line_items_by_subscriptions(&ids)
            .await?;
        let resources =
            ApiSubscriptionLineItemResource::resolve_many(db.as_ref(), &line_items).await;
        let payment_counts: HashMap<u64, u64> = db
            .count_subscription_payments_by_subscriptions(&ids)
            .await?
            .into_iter()
            .collect();

        let mut by_subscription: HashMap<u64, Vec<AdminSubscriptionLineItemInfo>> = HashMap::new();
        for li in line_items {
            let resource = resources.get(&li.id).cloned();
            by_subscription.entry(li.subscription_id).or_default().push(
                AdminSubscriptionLineItemInfo::from_line_item_with_resource(li, resource),
            );
        }

        Ok(subscriptions
            .into_iter()
            .map(|sub| {
                let id = sub.id;
                let user_pubkey = pubkeys.get(&sub.user_id).cloned().unwrap_or_default();
                let line_items = by_subscription.remove(&id).unwrap_or_default();
                let payment_count = payment_counts.get(&id).copied().unwrap_or(0);
                Self::from_parts(sub, user_pubkey, line_items, payment_count)
            })
            .collect())
    }

    /// Assemble from parts already loaded by the caller. The batch path: no
    /// query is issued here, so a page of subscriptions costs a fixed number
    /// of queries rather than a handful per row.
    pub fn from_parts(
        subscription: lnvps_db::Subscription,
        user_pubkey: String,
        line_items: Vec<AdminSubscriptionLineItemInfo>,
        payment_count: u64,
    ) -> Self {
        let mut info = AdminSubscriptionInfo::from(subscription);
        info.user_pubkey = user_pubkey;
        info.line_items = line_items;
        info.payment_count = payment_count;
        info
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
            is_setup: false,
            currency: self.currency.trim().to_uppercase(),
            interval_amount: self.interval_amount,
            interval_type: lnvps_db::IntervalType::from(self.interval_type),
            setup_fee: self.setup_fee,
            auto_renewal_enabled: self.auto_renewal_enabled,
            external_id: self.external_id.clone(),
        })
    }
}

// Subscription Line Item Models
#[derive(Serialize, Clone)]
pub struct AdminSubscriptionLineItemInfo {
    pub id: u64,
    pub subscription_id: u64,
    pub subscription_type: SubscriptionType,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    /// Raw upgrade configuration stored on the line item (e.g. `new_cpu` /
    /// `new_memory` / `new_disk`). This is NOT a resource link — see `resource`.
    pub configuration: Option<serde_json::Value>,
    /// Typed reference to the resource this line item bills for, resolved from
    /// `subscription_type` (`null` when there is no linked resource).
    pub resource: Option<ApiSubscriptionLineItemResource>,
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
    // `subscription_type` is intentionally absent: a line item is bound to its
    // resource at creation time and its type must not change afterwards.
    pub name: Option<String>,
    pub description: Option<String>,
    pub amount: Option<u64>,
    pub setup_amount: Option<u64>,
    pub configuration: Option<serde_json::Value>,
}

impl AdminSubscriptionLineItemInfo {
    /// Build from a line item, resolving the linked `resource` from the line
    /// item's subscription type via the DB back-reference tables.
    pub async fn from_line_item<D: lnvps_db::LNVpsDbBase + ?Sized>(
        db: &D,
        line_item: lnvps_db::SubscriptionLineItem,
    ) -> Self {
        let resource = ApiSubscriptionLineItemResource::resolve(db, &line_item).await;
        Self::from_line_item_with_resource(line_item, resource)
    }

    /// Build from a line item whose resource link has already been resolved
    /// (see [`ApiSubscriptionLineItemResource::resolve_many`]), so a batch of
    /// line items costs no per-row query.
    pub fn from_line_item_with_resource(
        line_item: lnvps_db::SubscriptionLineItem,
        resource: Option<ApiSubscriptionLineItemResource>,
    ) -> Self {
        Self {
            id: line_item.id,
            subscription_id: line_item.subscription_id,
            subscription_type: line_item.subscription_type,
            name: line_item.name,
            description: line_item.description,
            amount: line_item.amount,
            setup_amount: line_item.setup_amount,
            configuration: line_item.configuration,
            resource,
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
    pub company_base_currency: String,
    pub payment_method: AdminPaymentMethod,
    pub payment_type: ApiSubscriptionPaymentType,
    pub external_id: Option<String>,
    pub is_paid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<DateTime<Utc>>,
    pub rate: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub tax: u64,
    pub processing_fee: u64,
    /// The discount applied to this payment, if any. `amount` is already net of
    /// it — this only says which code was used and how much came off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discount: Option<AdminPaymentDiscountInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ApiSubscriptionPaymentType {
    Purchase,
    Renewal,
    Upgrade,
    /// Money returned to the customer: `amount`/`tax` are magnitudes to
    /// subtract from earnings, not another sale.
    Refund,
}

impl From<lnvps_db::SubscriptionPaymentType> for ApiSubscriptionPaymentType {
    fn from(payment_type: lnvps_db::SubscriptionPaymentType) -> Self {
        match payment_type {
            lnvps_db::SubscriptionPaymentType::Purchase => ApiSubscriptionPaymentType::Purchase,
            lnvps_db::SubscriptionPaymentType::Renewal => ApiSubscriptionPaymentType::Renewal,
            lnvps_db::SubscriptionPaymentType::Upgrade => ApiSubscriptionPaymentType::Upgrade,
            lnvps_db::SubscriptionPaymentType::Refund => ApiSubscriptionPaymentType::Refund,
        }
    }
}

impl From<ApiSubscriptionPaymentType> for lnvps_db::SubscriptionPaymentType {
    fn from(payment_type: ApiSubscriptionPaymentType) -> Self {
        match payment_type {
            ApiSubscriptionPaymentType::Purchase => lnvps_db::SubscriptionPaymentType::Purchase,
            ApiSubscriptionPaymentType::Renewal => lnvps_db::SubscriptionPaymentType::Renewal,
            ApiSubscriptionPaymentType::Upgrade => lnvps_db::SubscriptionPaymentType::Upgrade,
            ApiSubscriptionPaymentType::Refund => lnvps_db::SubscriptionPaymentType::Refund,
        }
    }
}

impl AdminSubscriptionPaymentInfo {
    pub fn new(payment: lnvps_db::SubscriptionPayment, company_base_currency: String) -> Self {
        Self {
            id: hex::encode(&payment.id),
            subscription_id: payment.subscription_id,
            user_id: payment.user_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency: payment.currency,
            company_base_currency,
            payment_method: AdminPaymentMethod::from(payment.payment_method),
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            paid_at: payment.paid_at,
            rate: payment.rate,
            time_value: payment.time_value,
            metadata: payment.metadata,
            tax: payment.tax,
            processing_fee: payment.processing_fee,
            discount: None,
        }
    }

    /// Attach the discount applied to this payment, if one was.
    ///
    /// Separate from the constructor so listings can resolve a whole page of
    /// discounts in one query and hand each row its own.
    pub fn with_discount(mut self, discount: Option<AdminPaymentDiscountInfo>) -> Self {
        self.discount = discount;
        self
    }

    pub fn from_with_company(payment: lnvps_db::SubscriptionPaymentWithCompany) -> Self {
        Self {
            id: hex::encode(&payment.id),
            subscription_id: payment.subscription_id,
            user_id: payment.user_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency: payment.currency,
            company_base_currency: payment.company_base_currency,
            payment_method: AdminPaymentMethod::from(payment.payment_method),
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            paid_at: payment.paid_at,
            rate: payment.rate,
            time_value: payment.time_value,
            metadata: payment.metadata,
            tax: payment.tax,
            processing_fee: payment.processing_fee,
            discount: None,
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

        // Get subscription details for user_id (use shortcut function)
        if let Ok(subscription) = db
            .get_subscription_by_line_item_id(sub.subscription_line_item_id)
            .await
        {
            info.user_id = Some(subscription.user_id);
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
    OnChain,
}

impl From<lnvps_db::PaymentMethod> for AdminPaymentMethodType {
    fn from(method: lnvps_db::PaymentMethod) -> Self {
        match method {
            lnvps_db::PaymentMethod::Lightning => AdminPaymentMethodType::Lightning,
            lnvps_db::PaymentMethod::Revolut => AdminPaymentMethodType::Revolut,
            lnvps_db::PaymentMethod::Paypal => AdminPaymentMethodType::Paypal,
            lnvps_db::PaymentMethod::Stripe => AdminPaymentMethodType::Stripe,
            lnvps_db::PaymentMethod::OnChain => AdminPaymentMethodType::OnChain,
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
            AdminPaymentMethodType::OnChain => lnvps_db::PaymentMethod::OnChain,
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

/// Sanitized on-chain config (nothing secret, mirrors OnChainProviderConfig)
#[derive(Serialize)]
pub struct SanitizedOnChainConfig {
    pub url: String,
    pub cert_path: String,
    pub macaroon_path: String,
    pub address_type: String,
    pub account: Option<String>,
    pub min_confirmations: u32,
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
    OnChain(SanitizedOnChainConfig),
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
            lnvps_db::ProviderConfig::OnChain(cfg) => {
                SanitizedProviderConfig::OnChain(SanitizedOnChainConfig {
                    url: cfg.url.clone(),
                    cert_path: cfg.cert_path.display().to_string(),
                    macaroon_path: cfg.macaroon_path.display().to_string(),
                    address_type: format!("{:?}", cfg.address_type),
                    account: cfg.account.clone(),
                    min_confirmations: cfg.min_confirmations,
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
    /// Minimum processable amount in smallest currency units (cents for fiat,
    /// millisats for BTC). Payments below this are rejected for this method.
    pub min_amount: Option<u64>,
    /// Currency for the minimum amount
    pub min_amount_currency: Option<String>,
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
            min_amount: config.min_amount,
            min_amount_currency: config.min_amount_currency,
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
    /// Minimum processable amount in smallest currency units (cents for fiat,
    /// millisats for BTC)
    pub min_amount: Option<u64>,
    pub min_amount_currency: Option<String>,
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

        // Validate that if min amount is set, currency must also be set
        if self.min_amount.is_some() && self.min_amount_currency.is_none() {
            return Err(anyhow!(
                "Minimum amount currency is required when minimum amount is set"
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
        payment_config.min_amount = self.min_amount;
        payment_config.min_amount_currency = self
            .min_amount_currency
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
    /// Minimum processable amount in smallest currency units (cents for fiat,
    /// millisats for BTC)
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub min_amount: Option<Option<u64>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub min_amount_currency: Option<Option<String>>,
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

/// Partial on-chain (LND wallet) config for updates
#[derive(Deserialize)]
pub struct PartialOnChainConfig {
    pub url: Option<String>,
    pub cert_path: Option<std::path::PathBuf>,
    pub macaroon_path: Option<std::path::PathBuf>,
    pub address_type: Option<lnvps_db::OnChainAddressType>,
    /// Wallet account name: `Some(Some(x))` sets it, `Some(None)` clears it back
    /// to the default account, omitted leaves it unchanged.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub account: Option<Option<String>>,
    pub min_confirmations: Option<u32>,
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
    #[serde(rename = "onchain")]
    OnChain(PartialOnChainConfig),
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
            (PartialProviderConfig::OnChain(partial), ProviderConfig::OnChain(existing)) => {
                Ok(ProviderConfig::OnChain(lnvps_db::OnChainProviderConfig {
                    url: partial.url.unwrap_or_else(|| existing.url.clone()),
                    cert_path: partial
                        .cert_path
                        .unwrap_or_else(|| existing.cert_path.clone()),
                    macaroon_path: partial
                        .macaroon_path
                        .unwrap_or_else(|| existing.macaroon_path.clone()),
                    address_type: partial.address_type.unwrap_or(existing.address_type),
                    // `account` is nullable: omitted keeps the existing value,
                    // `Some(None)` clears it to the default account.
                    account: match partial.account {
                        Some(v) => v,
                        None => existing.account.clone(),
                    },
                    min_confirmations: partial
                        .min_confirmations
                        .unwrap_or(existing.min_confirmations),
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
            PartialProviderConfig::OnChain(_) => "onchain",
        }
    }
}

/// Admin view of a user's saved payment method for automatic renewals.
/// Never exposes the underlying provider tokens / NWC connection string.
#[derive(Serialize, Deserialize)]
pub struct AdminUserPaymentMethodInfo {
    pub id: u64,
    /// User that owns this payment method
    pub user_id: u64,
    /// Payment processor: `nwc` or `revolut`
    pub provider: String,
    /// Optional user-defined label
    pub name: Option<String>,
    pub created: DateTime<Utc>,
    /// Whether a provider customer id is on file (secret value is redacted)
    pub has_external_customer_id: bool,
    pub card_brand: Option<String>,
    pub card_last_four: Option<String>,
    pub exp_month: Option<u16>,
    pub exp_year: Option<u16>,
    pub is_default: bool,
    pub enabled: bool,
}

impl From<lnvps_db::UserPaymentMethod> for AdminUserPaymentMethodInfo {
    fn from(m: lnvps_db::UserPaymentMethod) -> Self {
        Self {
            id: m.id,
            user_id: m.user_id,
            provider: m.provider,
            name: m.name,
            created: m.created,
            has_external_customer_id: m.external_customer_id.is_some(),
            card_brand: m.card_brand,
            card_last_four: m.card_last_four,
            exp_month: m.exp_month,
            exp_year: m.exp_year,
            is_default: m.is_default,
            enabled: m.enabled,
        }
    }
}

/// Admin request to update a user's saved payment method.
/// Only mutates non-sensitive fields (label / default / enabled).
#[derive(Deserialize)]
pub struct AdminUpdateUserPaymentMethodRequest {
    /// Mark this method as the user's default (clears the flag on their others)
    pub is_default: Option<bool>,
    /// Enable/disable the method
    pub enabled: Option<bool>,
    /// Set/clear the user-defined label. `Some(Some(..))` sets, `Some(None)` clears.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub name: Option<Option<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-disk usage is attached to each configured disk, and a disk the
    /// capacity calculation did not cover reports no usage rather than zero
    /// (which would read as "empty").
    #[test]
    fn host_disks_carry_per_disk_usage() {
        let disk = |id: u64, size: u64| lnvps_db::VmHostDisk {
            id,
            host_id: 1,
            name: format!("disk-{id}"),
            size,
            kind: lnvps_db::DiskType::SSD,
            interface: lnvps_db::DiskInterface::PCIe,
            enabled: true,
        };
        let host = lnvps_db::VmHost {
            id: 1,
            load_disk: 1.0,
            ..Default::default()
        };
        let capacity = lnvps_api_common::HostCapacity {
            load_factor: lnvps_api_common::LoadFactors {
                cpu: 1.0,
                memory: 1.0,
                disk: 1.0,
            },
            host,
            cpu: 0,
            memory: 0,
            disks: vec![lnvps_api_common::DiskCapacity {
                load_factor: 1.0,
                disk: disk(1, 400),
                usage: 100,
            }],
            ranges: vec![],
        };

        let disks = AdminHostDisk::list_with_capacity(vec![disk(1, 400), disk(2, 800)], &capacity);

        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].usage, Some(100));
        assert_eq!(disks[0].load, Some(0.25));
        // Disk 2 was not part of the capacity calculation
        assert_eq!(disks[1].usage, None);
        assert_eq!(disks[1].load, None);
    }

    /// The history state blobs are JSON and are surfaced verbatim (issue #393).
    #[test]
    fn decode_history_json_round_trips_and_tolerates_garbage() {
        let value = serde_json::json!({"host_id": 3});
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(decode_history_json(Some(&bytes)), Some(value));
        assert_eq!(decode_history_json(None), None);
        // A non-JSON blob must degrade to None rather than error the request
        assert_eq!(decode_history_json(Some(&vec![0xff, 0x00, 0xfe])), None);
    }

    /// The state/metadata blobs reach the admin API response (issue #393).
    #[tokio::test]
    async fn vm_history_info_exposes_state_blobs() {
        let db: std::sync::Arc<dyn lnvps_db::LNVpsDb> =
            std::sync::Arc::new(lnvps_api_common::MockDb::default());
        let history = VmHistory {
            id: 1,
            vm_id: 1,
            action_type: VmHistoryActionType::Migrated,
            timestamp: Utc::now(),
            initiated_by_user: None,
            previous_state: Some(serde_json::to_vec(&serde_json::json!({"host_id": 1})).unwrap()),
            new_state: Some(serde_json::to_vec(&serde_json::json!({"host_id": 2})).unwrap()),
            metadata: Some(serde_json::to_vec(&serde_json::json!({"detected": true})).unwrap()),
            description: Some("moved".to_string()),
        };

        let info = AdminVmHistoryInfo::from_vm_history_with_admin_data(&db, &history)
            .await
            .unwrap();
        assert_eq!(info.previous_state, Some(serde_json::json!({"host_id": 1})));
        assert_eq!(info.new_state, Some(serde_json::json!({"host_id": 2})));
        assert_eq!(info.metadata, Some(serde_json::json!({"detected": true})));
    }

    /// A payment carries its discount, and an undiscounted payment omits the
    /// key entirely rather than serialising `null` (issue #384).
    #[test]
    fn payment_info_carries_optional_discount() {
        let payment = lnvps_db::SubscriptionPayment {
            id: vec![1; 32],
            subscription_id: 1,
            user_id: 1,
            created: Utc::now(),
            expires: Utc::now(),
            amount: 900,
            currency: "EUR".to_string(),
            payment_method: lnvps_db::PaymentMethod::Lightning,
            payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
            external_data: lnvps_db::EncryptedString::new(String::new()),
            external_id: None,
            is_paid: false,
            rate: 1.0,
            time_value: Some(2_592_000),
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
        };

        let plain = AdminVmPaymentInfo::from_subscription_payment(&payment, 1, "EUR".to_string());
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json.get("discount").is_none());

        let discount = AdminPaymentDiscountInfo::from(lnvps_db::DiscountRedemptionWithCode {
            redemption: lnvps_db::DiscountRedemption {
                discount_id: 7,
                amount_off: 100,
                currency: "EUR".to_string(),
                settled: true,
                ..Default::default()
            },
            discount_code: Some("SAVE10".to_string()),
        });

        let vm = AdminVmPaymentInfo::from_subscription_payment(&payment, 1, "EUR".to_string())
            .with_discount(Some(discount.clone()));
        let json = serde_json::to_value(&vm).unwrap();
        assert_eq!(json["discount"]["code"], "SAVE10");
        assert_eq!(json["discount"]["discount_id"], 7);
        assert_eq!(json["discount"]["amount_off"], 100);
        assert_eq!(json["discount"]["currency"], "EUR");
        assert_eq!(json["discount"]["settled"], true);
        // The charged amount stays net of the discount.
        assert_eq!(json["amount"], 900);

        let sub = AdminSubscriptionPaymentInfo::new(payment.clone(), "EUR".to_string())
            .with_discount(Some(discount));
        let json = serde_json::to_value(&sub).unwrap();
        assert_eq!(json["discount"]["code"], "SAVE10");

        let sub_plain =
            AdminSubscriptionPaymentInfo::new(payment, "EUR".to_string()).with_discount(None);
        assert!(
            serde_json::to_value(&sub_plain)
                .unwrap()
                .get("discount")
                .is_none()
        );
    }

    #[test]
    fn test_partial_provider_config_deserializes_onchain() {
        // Regression: `type: "onchain"` previously failed with
        // "unknown variant `onchain`" so on-chain payment method configs could
        // not be PATCHed (e.g. to set a minimum amount).
        let json = r#"{"type":"onchain","min_confirmations":2}"#;
        let cfg: PartialProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.provider_type(), "onchain");
        match cfg {
            PartialProviderConfig::OnChain(p) => assert_eq!(p.min_confirmations, Some(2)),
            _ => panic!("expected OnChain variant"),
        }
    }

    #[test]
    fn test_partial_onchain_merge_updates_only_provided_fields() {
        use lnvps_db::{OnChainAddressType, OnChainProviderConfig, ProviderConfig};
        use std::path::PathBuf;

        let existing = ProviderConfig::OnChain(OnChainProviderConfig {
            url: "https://old:10009".to_string(),
            cert_path: PathBuf::from("/old/tls.cert"),
            macaroon_path: PathBuf::from("/old/admin.macaroon"),
            address_type: OnChainAddressType::WitnessPubkeyHash,
            account: Some("orders".to_string()),
            min_confirmations: 1,
        });

        // Only change the URL + confirmations; everything else is preserved.
        let partial: PartialProviderConfig = serde_json::from_str(
            r#"{"type":"onchain","url":"https://new:10009","min_confirmations":3}"#,
        )
        .unwrap();
        let merged = partial.merge_with(&existing).unwrap();
        match merged {
            ProviderConfig::OnChain(c) => {
                assert_eq!(c.url, "https://new:10009");
                assert_eq!(c.min_confirmations, 3);
                assert_eq!(c.cert_path, PathBuf::from("/old/tls.cert"));
                assert_eq!(c.address_type, OnChainAddressType::WitnessPubkeyHash);
                assert_eq!(c.account, Some("orders".to_string()));
            }
            _ => panic!("expected OnChain"),
        }

        // `account: null` clears it to the default account.
        let clear: PartialProviderConfig =
            serde_json::from_str(r#"{"type":"onchain","account":null}"#).unwrap();
        match clear.merge_with(&existing).unwrap() {
            ProviderConfig::OnChain(c) => assert_eq!(c.account, None),
            _ => panic!("expected OnChain"),
        }
    }

    #[test]
    fn test_partial_provider_config_rejects_type_change() {
        use lnvps_db::{LndConfig, ProviderConfig};
        use std::path::PathBuf;

        let existing = ProviderConfig::Lnd(LndConfig {
            url: "https://lnd:10009".to_string(),
            cert_path: PathBuf::from("/tls.cert"),
            macaroon_path: PathBuf::from("/admin.macaroon"),
        });
        // Cannot morph an LND config into an on-chain one via update.
        let partial: PartialProviderConfig =
            serde_json::from_str(r#"{"type":"onchain","url":"https://x:10009"}"#).unwrap();
        assert!(partial.merge_with(&existing).is_err());
    }

    #[test]
    fn test_create_vm_os_image_request_accepts_new_distros() {
        for name in ["almalinux", "rockylinux", "alpine", "nixos"] {
            let json = format!(
                r#"{{"distribution":"{name}","flavour":"server","version":"9","enabled":true,"release_date":"2026-01-01T00:00:00Z","url":"https://example.com/image.qcow2"}}"#
            );
            let req: CreateVmOsImageRequest = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
            assert!(req.to_vm_os_image().is_ok());
        }
    }

    #[test]
    fn test_create_vm_os_image_request_cpu_arch() {
        // Explicit arm64
        let json = r#"{"distribution":"debian","flavour":"server","version":"12","enabled":true,"release_date":"2026-01-01T00:00:00Z","url":"https://example.com/image.qcow2","cpu_arch":"arm64"}"#;
        let req: CreateVmOsImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.to_vm_os_image().unwrap().cpu_arch,
            lnvps_db::CpuArch::ARM64
        );

        // Omitted => defaults to x86_64
        let json = r#"{"distribution":"debian","flavour":"server","version":"12","enabled":true,"release_date":"2026-01-01T00:00:00Z","url":"https://example.com/image.qcow2"}"#;
        let req: CreateVmOsImageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.to_vm_os_image().unwrap().cpu_arch,
            lnvps_db::CpuArch::X86_64
        );
    }

    #[test]
    fn test_update_vm_os_image_request_cpu_arch_nullable() {
        // null => Some(None) (reset to unspecified)
        let req: UpdateVmOsImageRequest = serde_json::from_str(r#"{"cpu_arch": null}"#).unwrap();
        assert_eq!(req.cpu_arch, Some(None));
        // provided => Some(Some(..))
        let req: UpdateVmOsImageRequest = serde_json::from_str(r#"{"cpu_arch": "arm64"}"#).unwrap();
        assert_eq!(req.cpu_arch, Some(Some("arm64".to_string())));
        // absent => None
        let req: UpdateVmOsImageRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(req.cpu_arch, None);
    }

    #[test]
    fn test_api_os_distribution_to_db_covers_new_distros() {
        for (api, db) in [
            (ApiOsDistribution::AlmaLinux, OsDistribution::AlmaLinux),
            (ApiOsDistribution::RockyLinux, OsDistribution::RockyLinux),
            (ApiOsDistribution::Alpine, OsDistribution::Alpine),
            (ApiOsDistribution::NixOS, OsDistribution::NixOS),
            (ApiOsDistribution::OpenBSD, OsDistribution::OpenBSD),
            (ApiOsDistribution::NetBSD, OsDistribution::NetBSD),
            (ApiOsDistribution::Gentoo, OsDistribution::Gentoo),
            (ApiOsDistribution::VoidLinux, OsDistribution::VoidLinux),
        ] {
            assert_eq!(api_os_distribution_to_db(api), db);
        }
    }

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

    #[test]
    fn test_admin_router_tunnel_from() {
        use chrono::Utc;
        let t = lnvps_db::RouterTunnel {
            id: 7,
            router_id: 1,
            name: "wg0".to_string(),
            kind: lnvps_db::RouterTunnelKind::Wireguard,
            local_addr: Some("10.0.0.1".to_string()),
            remote_addr: None,
            enabled: true,
            last_seen: Utc::now(),
        };
        let a = AdminRouterTunnel::from(t);
        assert_eq!(a.id, 7);
        assert_eq!(a.kind, "wireguard");
        assert_eq!(a.local_addr.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn test_admin_router_tunnel_traffic_from() {
        use chrono::Utc;
        let t = lnvps_db::RouterTunnelTraffic {
            id: 1,
            router_id: 1,
            tunnel_name: "gre1".to_string(),
            rx_bytes: 100,
            tx_bytes: 200,
            sampled_at: Utc::now(),
        };
        let a = AdminRouterTunnelTraffic::from(t);
        assert_eq!(a.tunnel_name, "gre1");
        assert_eq!(a.rx_bytes, 100);
        assert_eq!(a.tx_bytes, 200);
    }

    #[test]
    fn test_admin_router_bgp_session_from() {
        use chrono::Utc;
        let s = lnvps_db::RouterBgpSession {
            id: 3,
            router_id: 1,
            name: "peer1".to_string(),
            peer_ip: Some("192.0.2.1".to_string()),
            peer_asn: Some(64512),
            local_asn: Some(64500),
            state: "Established".to_string(),
            prefixes_received: Some(5),
            prefixes_sent: Some(1),
            enabled: true,
            direction: lnvps_db::RouterBgpDirection::Upstream,
            last_seen: Utc::now(),
        };
        let a = AdminRouterBgpSession::from(s);
        assert_eq!(a.id, 3);
        assert_eq!(a.peer_asn, Some(64512));
        assert_eq!(a.direction, "upstream");
        assert_eq!(a.state, "Established");
    }

    #[test]
    fn test_admin_router_bgp_route_from() {
        use chrono::Utc;
        let r = lnvps_db::RouterBgpRoute {
            id: 7,
            router_id: 2,
            prefix: "192.0.2.0/24".to_string(),
            next_hop: Some("192.0.2.1".to_string()),
            is_default: false,
            last_seen: Utc::now(),
        };
        let a = AdminRouterBgpRoute::from(r);
        assert_eq!(a.router_id, 2);
        assert_eq!(a.prefix, "192.0.2.0/24");
        assert_eq!(a.next_hop.as_deref(), Some("192.0.2.1"));
        assert!(!a.is_default);
    }

    #[test]
    fn test_toggle_bgp_session_request_deserialize() {
        let json = r#"{"session_id": "bgp1", "enabled": false}"#;
        let req: ToggleBgpSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.session_id, "bgp1");
        assert!(!req.enabled);
    }
}

// ----- App catalog (managed app deployments) -----

/// Admin view of a catalog app.
#[derive(Serialize)]
pub struct AdminAppInfo {
    pub id: u64,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// Canonical source repository URL (e.g. the project's GitHub).
    pub repo_url: Option<String>,
    /// Short class of software (e.g. `Nostr relay`); free text, always set.
    pub category: String,
    /// Per-app override for the public page `<title>` (English only).
    pub seo_title: Option<String>,
    /// Per-app override for the public page meta description (English only).
    pub seo_description: Option<String>,
    /// docker-compose-style YAML defining the app.
    pub compose: String,
    /// Recurring price in the smallest currency unit (cents / millisats).
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
    pub setup_amount: u64,
    pub enabled: bool,
    /// Resource footprint computed from the compose (CPU millicores).
    pub cpu_milli: u64,
    /// Memory footprint in bytes.
    pub memory_bytes: u64,
    /// Persistent storage footprint in bytes.
    pub storage_bytes: u64,
    /// Grouping labels currently assigned, ordered by slug. Returned so the
    /// admin list is not a blind edit: `tags` on create/update is a replace-set
    /// of slugs, so an editor has to be able to see the current set first.
    pub tags: Vec<AdminAppTagRef>,
    pub created: DateTime<Utc>,
}

/// A tag as it appears on an app. The id is included so an admin UI can drive
/// a picker off `GET /api/admin/v1/app-tags` without matching on strings.
#[derive(Serialize)]
pub struct AdminAppTagRef {
    pub id: u64,
    pub slug: String,
    pub display_name: String,
}

impl From<lnvps_db::AppTag> for AdminAppTagRef {
    fn from(t: lnvps_db::AppTag) -> Self {
        Self {
            id: t.id,
            slug: t.slug,
            display_name: t.display_name,
        }
    }
}

/// Admin view of a tag in the vocabulary.
#[derive(Serialize)]
pub struct AdminAppTagInfo {
    pub id: u64,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    /// Number of **enabled** apps carrying this tag — the same count the
    /// public facet endpoint reports, so an admin sees what a visitor sees.
    /// A disabled app carrying the tag is not counted here.
    pub app_count: u64,
    pub created: DateTime<Utc>,
}

/// Create a tag. The vocabulary is controlled, so this is the only way one
/// comes into existence — assigning an unknown slug to an app is an error, not
/// an implicit create.
#[derive(Deserialize)]
pub struct AdminCreateAppTagRequest {
    /// URL-safe slug, unique. Lowercase letters, digits and hyphens.
    pub slug: String,
    /// Chip / heading label. Required: deriving it from the slug is what
    /// mangles `NIP-96`.
    pub display_name: String,
    /// Optional lede for a tag landing page.
    pub description: Option<String>,
}

/// Patch a tag. All fields optional (omitted = unchanged).
///
/// `slug` and `display_name` are `Option<String>` rather than the nullable
/// `Option<Option<String>>` used elsewhere, because both are `NOT NULL` and
/// there is no null to clear to. `description` is nullable and accepts an
/// explicit `null`.
#[derive(Deserialize)]
pub struct AdminUpdateAppTagRequest {
    pub slug: Option<String>,
    pub display_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub description: Option<Option<String>>,
}

/// Result of deleting a tag, which cascades its assignments.
#[derive(Serialize)]
pub struct AdminDeleteAppTagResult {
    /// How many apps were untagged as a side effect. Reported because the
    /// cascade is silent otherwise — an admin retiring a tag should be told
    /// what it took with it.
    pub assignments_removed: u64,
}

impl AdminAppInfo {
    /// Build the admin view from a catalog row plus its already-loaded tags.
    ///
    /// Not a `From<App>` impl for the same reason as [`ApiApp::from_app`]:
    /// tags do not live on `App`, and fetching them inside a per-item
    /// conversion is where an N+1 over the listing would come from.
    pub fn from_app(a: lnvps_db::App, tags: Vec<AdminAppTagRef>) -> Self {
        Self {
            tags,
            id: a.id,
            name: a.name,
            display_name: a.display_name,
            description: a.description,
            icon: a.icon,
            repo_url: a.repo_url,
            category: a.category,
            seo_title: a.seo_title,
            seo_description: a.seo_description,
            compose: a.compose,
            amount: a.amount,
            currency: a.currency,
            interval_amount: a.interval_amount,
            interval_type: a.interval_type.into(),
            setup_amount: a.setup_amount,
            enabled: a.enabled,
            cpu_milli: a.cpu_milli,
            memory_bytes: a.memory_bytes,
            storage_bytes: a.storage_bytes,
            created: a.created,
        }
    }
}

/// Create a catalog app.
#[derive(Deserialize)]
pub struct AdminCreateAppRequest {
    /// URL/DNS-safe slug, unique (e.g. `nostr-relay`).
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// Canonical source repository URL (e.g. the project's GitHub).
    pub repo_url: Option<String>,
    /// Short class of software (e.g. `Nostr relay`); free text, **required**.
    ///
    /// Sentence case, proper nouns capitalised, no article and no
    /// "hosting"/"managed"/trailing punctuation — the public page templates
    /// `{display_name} Hosting — Managed {category}` around it, and whatever
    /// is stored is what search engines show.
    pub category: String,
    /// Per-app override for the public page `<title>` (English only).
    pub seo_title: Option<String>,
    /// Per-app override for the public page meta description (English only).
    pub seo_description: Option<String>,
    /// docker-compose-style YAML defining the app.
    pub compose: String,
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: ApiIntervalType,
    #[serde(default)]
    pub setup_amount: u64,
    /// Whether the app is offered in the catalog (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Grouping-label slugs to assign. Genuinely optional, unlike `category`:
    /// an untagged app is a normal state, because nothing in the page title
    /// depends on it.
    ///
    /// Every slug must already exist — an unknown one is a `400` naming it,
    /// not an implicit create. Auto-creating is exactly the vocabulary drift a
    /// controlled tag table exists to prevent.
    pub tags: Option<Vec<String>>,
}

/// Update a catalog app (all fields optional; omitted = unchanged).
#[derive(Deserialize)]
pub struct AdminUpdateAppRequest {
    pub name: Option<String>,
    pub display_name: Option<String>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub description: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub icon: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub repo_url: Option<Option<String>>,
    /// Omit to leave unchanged, send a string to set. Unlike the nullable
    /// fields around it there is **no clear**, because `category` is `NOT
    /// NULL` — there is no null to clear to.
    ///
    /// Carries the nullable-option deserializer anyway, purely so an explicit
    /// `"category": null` can be told apart from an omitted key and rejected.
    /// A plain `Option<String>` collapses the two, and a client asking to
    /// clear a required field would get `200 OK` and no change.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub category: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub seo_title: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub seo_description: Option<Option<String>>,
    pub compose: Option<String>,
    pub amount: Option<u64>,
    pub currency: Option<String>,
    pub interval_amount: Option<u64>,
    pub interval_type: Option<ApiIntervalType>,
    pub setup_amount: Option<u64>,
    pub enabled: Option<bool>,
    /// Replace-set of grouping-label slugs: omit to leave the set unchanged,
    /// send `[]` to clear it, send a list to make that list exact. Unknown
    /// slugs are a `400`.
    ///
    /// A plain `Option<Vec<String>>` is enough here, unlike `category` above:
    /// `[]` is a meaningful, honourable "clear", so there is no need to tell an
    /// explicit `null` apart from an omitted key.
    pub tags: Option<Vec<String>>,
}

/// Admin view of an app cluster.
#[derive(Serialize)]
pub struct AdminAppClusterInfo {
    pub id: u64,
    pub name: String,
    pub region_id: u64,
    pub ingress_domain: String,
    pub enabled: bool,
    /// Static total capacity available for app deployments.
    pub capacity_cpu_milli: u64,
    pub capacity_memory_bytes: u64,
    pub capacity_storage_bytes: u64,
    pub created: DateTime<Utc>,
}

impl From<lnvps_db::AppCluster> for AdminAppClusterInfo {
    fn from(c: lnvps_db::AppCluster) -> Self {
        Self {
            id: c.id,
            name: c.name,
            region_id: c.region_id,
            ingress_domain: c.ingress_domain,
            enabled: c.enabled,
            capacity_cpu_milli: c.capacity_cpu_milli,
            capacity_memory_bytes: c.capacity_memory_bytes,
            capacity_storage_bytes: c.capacity_storage_bytes,
            created: c.created,
        }
    }
}

/// An app deployment as seen by an admin (oversight / support). Excludes the
/// encrypted per-deployment config blob.
#[derive(Serialize)]
pub struct AdminAppDeploymentInfo {
    pub id: u64,
    pub user_id: u64,
    pub app_id: u64,
    pub cluster_id: u64,
    /// Size as a multiple of the catalog app's base footprint and price
    /// (`1` = base). Customers raise this via the app upgrade endpoint.
    pub resource_multiplier: u32,
    pub subscription_line_item_id: u64,
    pub name: String,
    pub namespace: String,
    pub hostname: Option<String>,
    /// Customer-owned domain (CNAME'd to `hostname`), served alongside it.
    pub custom_domain: Option<String>,
    /// Whether that domain is served yet. `false` means held: stored, but never
    /// seen resolving to `hostname`, so no ingress rule and no certificate.
    pub custom_domain_verified: bool,
    /// Desired run state: `running` or `stopped`.
    pub desired_state: String,
    /// Observed status: `pending`, `running`, `stopped`, `error`, `deleting`.
    pub status: String,
    pub status_message: Option<String>,
    /// Decrypted customer-supplied `config` map (may hold secret values —
    /// admin-only). `None` when no config was stored. Populated only on the
    /// single-deployment GET; the list endpoint leaves it `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<std::collections::BTreeMap<String, String>>,
    /// What the workload is consuming, in the same shape and units the customer
    /// API serves. `None` when nothing has been observed: a deployment that has
    /// never run, or a cluster with no metrics source.
    pub usage: Option<lnvps_api_common::AppDeploymentUsage>,
    pub created: DateTime<Utc>,
    /// Soft-deleted: the operator has torn the workload down and the row is
    /// retained only for accounting. Only ever `true` in listings requested
    /// with `include_deleted=true`.
    pub deleted: bool,
}

impl From<lnvps_db::AppDeployment> for AdminAppDeploymentInfo {
    fn from(d: lnvps_db::AppDeployment) -> Self {
        Self {
            id: d.id,
            user_id: d.user_id,
            app_id: d.app_id,
            cluster_id: d.cluster_id,
            resource_multiplier: d.resource_multiplier.max(1),
            subscription_line_item_id: d.subscription_line_item_id,
            name: d.name,
            namespace: d.namespace,
            hostname: d.hostname,
            custom_domain_verified: d.custom_domain.is_some() && d.custom_domain_verified,
            custom_domain: d.custom_domain,
            desired_state: d.desired_state.to_string(),
            status: d.status.to_string(),
            status_message: d.status_message,
            config: None, // filled in by the single-GET handler (decrypted)
            usage: None,  // filled in by the handler, which reads the breakdown
            created: d.created,
            deleted: d.deleted,
        }
    }
}

/// Admin update of an app deployment. All fields optional — only those present
/// change (partial update). Mirrors the customer PATCH but admin-scoped.
#[derive(Deserialize)]
pub struct AdminUpdateAppDeploymentRequest {
    /// New DNS-safe instance name (becomes the ingress subdomain).
    #[serde(default)]
    pub name: Option<String>,
    /// New values for the app's `config` fields (validated against the compose
    /// schema; replaces the stored config wholesale).
    #[serde(default)]
    pub config: Option<std::collections::BTreeMap<String, String>>,
    /// Set (`Some("blog.example.com")`) or clear (`Some("")` / `Some(null)`)
    /// the custom domain. Absent = leave unchanged.
    #[serde(default)]
    pub custom_domain: Option<Option<String>>,
}

/// Create an app cluster.
#[derive(Deserialize)]
pub struct AdminCreateAppClusterRequest {
    pub name: String,
    pub region_id: u64,
    pub ingress_domain: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Static total capacity (millicores / bytes / bytes). A cluster with 0
    /// capacity accepts no deployments.
    #[serde(default)]
    pub capacity_cpu_milli: u64,
    #[serde(default)]
    pub capacity_memory_bytes: u64,
    #[serde(default)]
    pub capacity_storage_bytes: u64,
}

/// Update an app cluster (all fields optional; omitted = unchanged).
#[derive(Deserialize)]
pub struct AdminUpdateAppClusterRequest {
    pub name: Option<String>,
    pub region_id: Option<u64>,
    pub ingress_domain: Option<String>,
    pub enabled: Option<bool>,
    pub capacity_cpu_milli: Option<u64>,
    pub capacity_memory_bytes: Option<u64>,
    pub capacity_storage_bytes: Option<u64>,
}

fn default_true() -> bool {
    true
}

/// Admin view of a discount campaign.
#[derive(Serialize, Deserialize)]
pub struct AdminDiscountInfo {
    pub id: u64,
    pub company_id: u64,
    /// The code customers enter. `None` is a phase 2 automatic discount.
    pub code: Option<String>,
    pub name: String,
    /// The CEL expression evaluated when the code is used.
    pub rule: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: Option<DateTime<Utc>>,
    pub usage_limit: Option<u64>,
    pub used_count: u64,
    pub per_user_limit: Option<u64>,
    pub active: bool,
    pub created: DateTime<Utc>,
    /// What this campaign has given away so far, per currency (minor units).
    /// Redemptions are recorded in the currency the customer paid in, so this
    /// is a list rather than one number.
    pub given_away: Vec<AdminDiscountTotal>,
}

/// One currency's share of a campaign's cost.
#[derive(Serialize, Deserialize)]
pub struct AdminDiscountTotal {
    pub currency: String,
    /// Minor units (cents / milli-sats).
    pub amount: u64,
}

/// One recorded redemption.
#[derive(Serialize, Deserialize)]
pub struct AdminDiscountRedemptionInfo {
    pub id: u64,
    pub discount_id: u64,
    pub user_id: u64,
    /// Hex payment hash of the payment the discount was applied to.
    pub subscription_payment_id: String,
    /// Minor units (cents / milli-sats).
    pub amount_off: u64,
    pub currency: String,
    /// False while the discounted invoice is unpaid. Unsettled rows consume no
    /// limit and do not count towards what the campaign has cost.
    pub settled: bool,
    /// When the discounted invoice was created.
    pub created: DateTime<Utc>,
    /// When the payment settled, if it has.
    pub settled_at: Option<DateTime<Utc>>,
}

impl From<lnvps_db::DiscountRedemption> for AdminDiscountRedemptionInfo {
    fn from(r: lnvps_db::DiscountRedemption) -> Self {
        Self {
            id: r.id,
            discount_id: r.discount_id,
            user_id: r.user_id,
            subscription_payment_id: hex::encode(r.subscription_payment_id),
            amount_off: r.amount_off,
            currency: r.currency,
            settled: r.settled,
            created: r.created,
            settled_at: r.settled_at,
        }
    }
}

/// Create a discount.
#[derive(Deserialize)]
pub struct AdminCreateDiscountRequest {
    pub company_id: u64,
    /// Customer-entered code. Required in phase 1 — a code-less discount would
    /// apply automatically, which is not implemented yet.
    pub code: String,
    pub name: String,
    /// CEL expression returning a decision map, e.g. `{'percent': 10}`.
    pub rule: String,
    /// Defaults to now.
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub usage_limit: Option<u64>,
    pub per_user_limit: Option<u64>,
    /// Defaults to true.
    pub active: Option<bool>,
}

/// Update a discount (omitted fields unchanged).
///
/// `used_count` is deliberately absent: it is owned by redemption, and an edit
/// that could rewrite it would reopen an exhausted campaign by accident.
#[derive(Deserialize)]
pub struct AdminUpdateDiscountRequest {
    pub code: Option<String>,
    pub name: Option<String>,
    pub rule: Option<String>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub usage_limit: Option<u64>,
    pub per_user_limit: Option<u64>,
    pub active: Option<bool>,
}

/// Try a rule against a sample order before saving it.
#[derive(Deserialize)]
pub struct AdminPreviewDiscountRequest {
    /// The CEL expression to evaluate.
    pub rule: String,
    /// Sample context. Omitted fields fall back to a representative order:
    /// a new 100.00 EUR monthly template VM for an Irish customer with no
    /// order history.
    #[serde(default)]
    pub order: Option<AdminPreviewOrder>,
}

/// The sample order a rule preview is evaluated against.
#[derive(Deserialize)]
pub struct AdminPreviewOrder {
    /// Net order amount in minor units (cents / milli-sats).
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub intervals: Option<i64>,
    /// `day`, `month` or `year`.
    pub interval_type: Option<String>,
    pub is_new: Option<bool>,
    /// The order's lines. Omitted keeps the sample's single standard VM line;
    /// supply this to try a rule against a custom build, a multi-line order, or
    /// a non-VM product.
    pub items: Option<Vec<lnvps_api_common::OrderLineItem>>,
    /// ISO 3166-1 alpha-3 country of the sample customer.
    pub country: Option<String>,
    /// Number of settled orders the sample customer has.
    pub orders: Option<i64>,
}

/// The outcome of a rule preview.
#[derive(Serialize, Deserialize)]
pub struct AdminDiscountPreview {
    /// True when the rule applies to the sample order.
    pub applies: bool,
    /// Percentage off, after clamping to 0..=100.
    pub percent: Option<u8>,
    /// Fixed amount off in minor units of `currency`, after clamping.
    pub amount: Option<u64>,
    pub currency: Option<String>,
    /// What the sample order would actually be reduced by, in its own currency
    /// and minor units. Zero when the rule declines.
    pub amount_off: u64,
    /// Why the rule produced nothing, when it produced nothing.
    pub error: Option<String>,
}
