use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

#[derive(FromRow, Clone, Debug, Default)]
/// Users who buy VM's
pub struct User {
    /// Unique ID of this user (database generated)
    pub id: u64,
    /// The nostr public key for this user
    pub pubkey: Vec<u8>,
    /// When this user first started using the service (first login)
    pub created: DateTime<Utc>,
    /// Users email address for notifications
    pub email: Option<String>,
    /// If user should be contacted via NIP-17 for notifications
    pub contact_nip17: bool,
    /// If user should be contacted via email for notifications
    pub contact_email: bool,
    /// Users country
    pub country_code: Option<String>,
    /// Name to show on invoices
    pub billing_name: Option<String>,
    /// Billing address line 1
    pub billing_address_1: Option<String>,
    /// Billing address line 2
    pub billing_address_2: Option<String>,
    /// Billing city
    pub billing_city: Option<String>,
    /// Billing state/county
    pub billing_state: Option<String>,
    /// Billing postcode/zip
    pub billing_postcode: Option<String>,
    /// Billing tax id
    pub billing_tax_id: Option<String>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct UserSshKey {
    pub id: u64,
    pub name: String,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub key_data: String,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct AdminUserInfo {
    pub id: u64,
    pub pubkey: Vec<u8>,
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
    pub vm_count: i64,
    pub is_admin: bool,
}

#[derive(Clone, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
/// The type of VM host
pub enum VmHostKind {
    #[default]
    Proxmox = 0,
    LibVirt = 1,
}

impl Display for VmHostKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VmHostKind::Proxmox => write!(f, "proxmox"),
            VmHostKind::LibVirt => write!(f, "libvirt"),
        }
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct VmHostRegion {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub company_id: Option<u64>,
}

#[derive(FromRow, Clone, Debug, Default)]
/// A VM host
pub struct VmHost {
    /// Unique id of this host
    pub id: u64,
    /// The host kind (Hypervisor)
    pub kind: VmHostKind,
    /// What region / group this host is part of
    pub region_id: u64,
    /// Internal name of this host
    pub name: String,
    /// Endpoint for controlling this host
    pub ip: String,
    /// Total number of CPU cores
    pub cpu: u16,
    /// Total memory size in bytes
    pub memory: u64,
    /// If VM's should be provisioned on this host
    pub enabled: bool,
    /// API token used to control this host via [ip]
    pub api_token: String,
    /// CPU load factor for provisioning
    pub load_cpu: f32,
    /// Memory load factor
    pub load_memory: f32,
    /// Disk load factor
    pub load_disk: f32,
    /// VLAN id assigned to all vms on the host
    pub vlan_id: Option<u64>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct VmHostDisk {
    pub id: u64,
    pub host_id: u64,
    pub name: String,
    pub size: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum DiskType {
    #[default]
    HDD = 0,
    SSD = 1,
}

impl FromStr for DiskType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hdd" => Ok(DiskType::HDD),
            "ssd" => Ok(DiskType::SSD),
            _ => Err(anyhow!("unknown disk type {}", s)),
        }
    }
}

impl Display for DiskType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskType::HDD => write!(f, "hdd"),
            DiskType::SSD => write!(f, "ssd"),
        }
    }
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum DiskInterface {
    #[default]
    SATA = 0,
    SCSI = 1,
    PCIe = 2,
}

impl FromStr for DiskInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sata" => Ok(DiskInterface::SATA),
            "scsi" => Ok(DiskInterface::SCSI),
            "pcie" => Ok(DiskInterface::PCIe),
            _ => Err(anyhow!("unknown disk interface {}", s)),
        }
    }
}

impl Display for DiskInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiskInterface::SATA => write!(f, "sata"),
            DiskInterface::SCSI => write!(f, "scsi"),
            DiskInterface::PCIe => write!(f, "pcie"),
        }
    }
}

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum OsDistribution {
    #[default]
    Ubuntu = 0,
    Debian = 1,
    CentOS = 2,
    Fedora = 3,
    FreeBSD = 4,
    OpenSUSE = 5,
    ArchLinux = 6,
    RedHatEnterprise = 7,
}

impl FromStr for OsDistribution {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ubuntu" => Ok(OsDistribution::Ubuntu),
            "debian" => Ok(OsDistribution::Debian),
            "centos" => Ok(OsDistribution::CentOS),
            "fedora" => Ok(OsDistribution::Fedora),
            "freebsd" => Ok(OsDistribution::FreeBSD),
            "opensuse" => Ok(OsDistribution::OpenSUSE),
            "archlinux" => Ok(OsDistribution::ArchLinux),
            "redhatenterprise" => Ok(OsDistribution::RedHatEnterprise),
            _ => Err(anyhow!("unknown distribution {}", s)),
        }
    }
}

impl Display for OsDistribution {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OsDistribution::Ubuntu => write!(f, "Ubuntu"),
            OsDistribution::Debian => write!(f, "Debian"),
            OsDistribution::CentOS => write!(f, "CentOs"),
            OsDistribution::Fedora => write!(f, "Fedora"),
            OsDistribution::FreeBSD => write!(f, "FreeBSD"),
            OsDistribution::OpenSUSE => write!(f, "OpenSuse"),
            OsDistribution::ArchLinux => write!(f, "Arch Linux"),
            OsDistribution::RedHatEnterprise => write!(f, "Red Hat Enterprise"),
        }
    }
}

/// OS Images are templates which are used as a basis for
/// provisioning new vms
#[derive(FromRow, Clone, Debug)]
pub struct VmOsImage {
    pub id: u64,
    pub distribution: OsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    /// URL location of cloud image
    pub url: String,
    pub default_username: Option<String>,
}

impl VmOsImage {
    pub fn filename(&self) -> Result<String> {
        let u: Url = self.url.parse()?;
        let mut name: PathBuf = u
            .path_segments()
            .ok_or(anyhow!("Invalid URL"))?
            .next_back()
            .ok_or(anyhow!("Invalid URL"))?
            .parse()?;
        name.set_extension("img");
        Ok(name.to_string_lossy().to_string())
    }
}

impl Display for VmOsImage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} {}", self.distribution, self.version)
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct Router {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub kind: RouterKind,
    pub url: String,
    pub token: String,
}

#[derive(Debug, Clone, sqlx::Type)]
#[repr(u16)]
pub enum RouterKind {
    /// Mikrotik router (JSON-Api)
    Mikrotik = 0,
    /// A pseudo-router which allows adding virtual mac addresses to a dedicated server
    OvhAdditionalIp = 1,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct IpRange {
    pub id: u64,
    pub cidr: String,
    pub gateway: String,
    pub enabled: bool,
    pub region_id: u64,
    pub reverse_zone_id: Option<String>,
    pub access_policy_id: Option<u64>,
    pub allocation_mode: IpRangeAllocationMode,
    /// Use all IPs in the range, including first and last
    pub use_full_range: bool,
}

#[derive(Debug, Clone, Copy, sqlx::Type, Default)]
#[repr(u16)]
/// How ips are allocated from this range
pub enum IpRangeAllocationMode {
    /// IPs are assigned in a random order
    Random = 0,
    #[default]
    /// IPs are assigned in sequential order
    Sequential = 1,
    /// IP(v6) assignment uses SLAAC EUI-64
    SlaacEui64 = 2,
}

#[derive(FromRow, Clone, Debug)]
pub struct AccessPolicy {
    pub id: u64,
    pub name: String,
    pub kind: NetworkAccessPolicy,
    /// Router used to apply this network access policy
    pub router_id: Option<u64>,
    /// Interface name used to apply this policy
    pub interface: Option<String>,
}

/// Policy that determines how packets arrive at the VM
#[derive(Debug, Clone, Copy, sqlx::Type)]
#[repr(u16)]
pub enum NetworkAccessPolicy {
    /// ARP entries are added statically on the access router
    StaticArp = 0,
}

#[derive(Clone, Copy, Debug, sqlx::Type)]
#[repr(u16)]
pub enum VmCostPlanIntervalType {
    Day = 0,
    Month = 1,
    Year = 2,
}

#[derive(FromRow, Clone, Debug)]
pub struct VmCostPlan {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    pub amount: f32,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: VmCostPlanIntervalType,
}

/// Offers.
/// These are the same as the offers visible to customers
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmTemplate {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub cost_plan_id: u64,
    pub region_id: u64,
}

/// A custom pricing template, used for billing calculation of a specific VM
/// This mostly just stores the number of resources assigned and the specific pricing used
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomTemplate {
    pub id: u64,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub pricing_id: u64,
}

/// Custom pricing template, usually 1 per region
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomPricing {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub region_id: u64,
    pub currency: String,
    /// Cost per CPU core
    pub cpu_cost: f32,
    /// Cost per GB ram
    pub memory_cost: f32,
    /// Cost per IPv4 address
    pub ip4_cost: f32,
    /// Cost per IPv6 address
    pub ip6_cost: f32,
}

/// Pricing per GB on a disk type (SSD/HDD)
#[derive(FromRow, Clone, Debug, Default)]
pub struct VmCustomPricingDisk {
    pub id: u64,
    pub pricing_id: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    /// Cost as per the currency of the [VmCustomPricing::currency]
    pub cost: f32,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct Vm {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// The host this VM is on
    pub host_id: u64,
    /// The user that owns this VM
    pub user_id: u64,
    /// The base image of this VM
    pub image_id: u64,
    /// The base image of this VM [VmTemplate]
    pub template_id: Option<u64>,
    /// Custom pricing specification used for this vm [VmCustomTemplate]
    pub custom_template_id: Option<u64>,
    /// Users ssh-key assigned to this VM
    pub ssh_key_id: u64,
    /// When the VM was created
    pub created: DateTime<Utc>,
    /// When the VM expires
    pub expires: DateTime<Utc>,
    /// The [VmHostDisk] this VM is on
    pub disk_id: u64,
    /// Network MAC address
    pub mac_address: String,
    /// Is the VM deleted
    pub deleted: bool,
    /// Referral code (recorded during ordering)
    pub ref_code: Option<String>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct VmIpAssignment {
    /// Unique id of this assignment
    pub id: u64,
    /// VM id this IP is assigned to
    pub vm_id: u64,
    /// IP range id
    pub ip_range_id: u64,
    /// The IP address (v4/v6)
    pub ip: String,
    /// If this record was freed
    pub deleted: bool,
    /// External ID pointing to a static arp entry on the router
    pub arp_ref: Option<String>,
    /// Forward DNS FQDN
    pub dns_forward: Option<String>,
    /// External ID pointing to the forward DNS entry for this IP
    pub dns_forward_ref: Option<String>,
    /// Reverse DNS FQDN
    pub dns_reverse: Option<String>,
    /// External ID pointing to the reverse DNS entry for this IP
    pub dns_reverse_ref: Option<String>,
}

impl Display for VmIpAssignment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip)
    }
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct VmPayment {
    pub id: Vec<u8>,
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    /// External data (invoice / json)
    pub external_data: String,
    /// External id on other system
    pub external_id: Option<String>,
    pub is_paid: bool,
    /// Exchange rate back to company's base currency
    pub rate: f32,
    /// Number of seconds this payment will add to vm expiry
    pub time_value: u64,
    /// Taxes to charge on payment
    pub tax: u64,
}

/// VM Payment with company information for time-series reporting
#[derive(FromRow, Clone, Debug)]
pub struct VmPaymentWithCompany {
    pub id: Vec<u8>,
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    /// External data (invoice / json)
    pub external_data: String,
    /// External id on other system
    pub external_id: Option<String>,
    pub is_paid: bool,
    /// Exchange rate back to company's base currency
    pub rate: f32,
    /// Number of seconds this payment will add to vm expiry
    pub time_value: u64,
    /// Taxes to charge on payment
    pub tax: u64,
    // Company information
    pub company_id: u64,
    pub company_name: String,
    pub company_base_currency: String,
}

#[derive(Type, Clone, Copy, Debug, Default, PartialEq)]
#[repr(u16)]
pub enum PaymentMethod {
    #[default]
    Lightning,
    Revolut,
    Paypal,
}

impl Display for PaymentMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentMethod::Lightning => write!(f, "Lightning"),
            PaymentMethod::Revolut => write!(f, "Revolut"),
            PaymentMethod::Paypal => write!(f, "PayPal"),
        }
    }
}

impl FromStr for PaymentMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "lightning" => Ok(PaymentMethod::Lightning),
            "revolut" => Ok(PaymentMethod::Revolut),
            "paypal" => Ok(PaymentMethod::Paypal),
            _ => bail!("Unknown payment method: {}", s),
        }
    }
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct NostrDomain {
    pub id: u64,
    pub owner_id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    pub enabled: bool,
    pub relays: Option<String>,
    pub handles: i64,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct NostrDomainHandle {
    pub id: u64,
    pub domain_id: u64,
    pub handle: String,
    pub created: DateTime<Utc>,
    pub pubkey: Vec<u8>,
    pub relays: Option<String>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct Company {
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
}

#[derive(Clone, Debug, Default)]
pub struct RegionStats {
    pub host_count: u64,
    pub total_vms: u64,
    pub total_cpu_cores: u64,
    pub total_memory_bytes: u64,
    pub total_ip_assignments: u64,
}

#[derive(Clone, Debug, sqlx::Type)]
#[repr(u16)]
pub enum VmHistoryActionType {
    Created = 0,
    Started = 1,
    Stopped = 2,
    Restarted = 3,
    Deleted = 4,
    Expired = 5,
    Renewed = 6,
    Reinstalled = 7,
    StateChanged = 8,
    PaymentReceived = 9,
    ConfigurationChanged = 10,
}

impl Display for VmHistoryActionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VmHistoryActionType::Created => write!(f, "created"),
            VmHistoryActionType::Started => write!(f, "started"),
            VmHistoryActionType::Stopped => write!(f, "stopped"),
            VmHistoryActionType::Restarted => write!(f, "restarted"),
            VmHistoryActionType::Deleted => write!(f, "deleted"),
            VmHistoryActionType::Expired => write!(f, "expired"),
            VmHistoryActionType::Renewed => write!(f, "renewed"),
            VmHistoryActionType::Reinstalled => write!(f, "reinstalled"),
            VmHistoryActionType::StateChanged => write!(f, "state_changed"),
            VmHistoryActionType::PaymentReceived => write!(f, "payment_received"),
            VmHistoryActionType::ConfigurationChanged => write!(f, "configuration_changed"),
        }
    }
}

impl FromStr for VmHistoryActionType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "created" => Ok(VmHistoryActionType::Created),
            "started" => Ok(VmHistoryActionType::Started),
            "stopped" => Ok(VmHistoryActionType::Stopped),
            "restarted" => Ok(VmHistoryActionType::Restarted),
            "deleted" => Ok(VmHistoryActionType::Deleted),
            "expired" => Ok(VmHistoryActionType::Expired),
            "renewed" => Ok(VmHistoryActionType::Renewed),
            "reinstalled" => Ok(VmHistoryActionType::Reinstalled),
            "state_changed" => Ok(VmHistoryActionType::StateChanged),
            "payment_received" => Ok(VmHistoryActionType::PaymentReceived),
            "configuration_changed" => Ok(VmHistoryActionType::ConfigurationChanged),
            _ => Err(anyhow!("unknown VM history action type: {}", s)),
        }
    }
}

#[derive(FromRow, Clone, Debug)]
pub struct VmHistory {
    pub id: u64,
    pub vm_id: u64,
    pub action_type: VmHistoryActionType,
    pub timestamp: DateTime<Utc>,
    pub initiated_by_user: Option<u64>,
    pub previous_state: Option<Vec<u8>>,
    pub new_state: Option<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
    pub description: Option<String>,
}

// RBAC Models

/// Administrative role definition
#[derive(FromRow, Clone, Debug)]
pub struct AdminRole {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role permission mapping
#[derive(FromRow, Clone, Debug)]
pub struct AdminRolePermission {
    pub id: u64,
    pub role_id: u64,
    pub resource: u16, // AdminResource enum value
    pub action: u16,   // AdminAction enum value
    pub created_at: DateTime<Utc>,
}

/// User role assignment
#[derive(FromRow, Clone, Debug)]
pub struct AdminRoleAssignment {
    pub id: u64,
    pub user_id: u64,
    pub role_id: u64,
    pub assigned_by: Option<u64>,
    pub assigned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Administrative resources that can be managed
#[derive(Clone, Copy, Debug, sqlx::Type, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AdminResource {
    Users = 0,
    VirtualMachines = 1,
    Hosts = 2,
    Payments = 3,
    Analytics = 4,
    System = 5,
    Roles = 6,
    Audit = 7,
    AccessPolicy = 8,
    Company = 9,
    IpRange = 10,
    Router = 11,
    VmCustomPricing = 12,
    HostRegion = 13,
    VmOsImage = 14,
    VmPayment = 15,
    VmTemplate = 16,
}

/// Actions that can be performed on administrative resources
#[derive(Clone, Copy, Debug, sqlx::Type, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum AdminAction {
    Create = 0,
    View = 1, // Covers both read single item and list multiple items
    Update = 2,
    Delete = 3,
}

impl Display for AdminResource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminResource::Users => write!(f, "users"),
            AdminResource::VirtualMachines => write!(f, "virtual_machines"),
            AdminResource::Hosts => write!(f, "hosts"),
            AdminResource::Payments => write!(f, "payments"),
            AdminResource::Analytics => write!(f, "analytics"),
            AdminResource::System => write!(f, "system"),
            AdminResource::Roles => write!(f, "roles"),
            AdminResource::Audit => write!(f, "audit"),
            AdminResource::AccessPolicy => write!(f, "access_policy"),
            AdminResource::Company => write!(f, "company"),
            AdminResource::IpRange => write!(f, "ip_range"),
            AdminResource::Router => write!(f, "router"),
            AdminResource::VmCustomPricing => write!(f, "vm_custom_pricing"),
            AdminResource::HostRegion => write!(f, "host_region"),
            AdminResource::VmOsImage => write!(f, "vm_os_image"),
            AdminResource::VmPayment => write!(f, "vm_payment"),
            AdminResource::VmTemplate => write!(f, "vm_template"),
        }
    }
}

impl FromStr for AdminResource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "users" => Ok(AdminResource::Users),
            "virtual_machines" | "vms" => Ok(AdminResource::VirtualMachines),
            "hosts" => Ok(AdminResource::Hosts),
            "payments" => Ok(AdminResource::Payments),
            "analytics" => Ok(AdminResource::Analytics),
            "system" => Ok(AdminResource::System),
            "roles" => Ok(AdminResource::Roles),
            "audit" => Ok(AdminResource::Audit),
            "access_policy" => Ok(AdminResource::AccessPolicy),
            "company" => Ok(AdminResource::Company),
            "ip_range" => Ok(AdminResource::IpRange),
            "router" => Ok(AdminResource::Router),
            "vm_custom_pricing" => Ok(AdminResource::VmCustomPricing),
            "host_region" => Ok(AdminResource::HostRegion),
            "vm_os_image" => Ok(AdminResource::VmOsImage),
            "vm_payment" => Ok(AdminResource::VmPayment),
            "vm_template" => Ok(AdminResource::VmTemplate),
            _ => Err(anyhow!("unknown admin resource: {}", s)),
        }
    }
}

impl TryFrom<u16> for AdminResource {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminResource::Users),
            1 => Ok(AdminResource::VirtualMachines),
            2 => Ok(AdminResource::Hosts),
            3 => Ok(AdminResource::Payments),
            4 => Ok(AdminResource::Analytics),
            5 => Ok(AdminResource::System),
            6 => Ok(AdminResource::Roles),
            7 => Ok(AdminResource::Audit),
            8 => Ok(AdminResource::AccessPolicy),
            9 => Ok(AdminResource::Company),
            10 => Ok(AdminResource::IpRange),
            11 => Ok(AdminResource::Router),
            12 => Ok(AdminResource::VmCustomPricing),
            13 => Ok(AdminResource::HostRegion),
            14 => Ok(AdminResource::VmOsImage),
            15 => Ok(AdminResource::VmPayment),
            16 => Ok(AdminResource::VmTemplate),
            _ => Err(anyhow!("unknown admin resource value: {}", value)),
        }
    }
}

impl AdminResource {
    /// Get all available admin resources
    pub fn all() -> Vec<AdminResource> {
        vec![
            AdminResource::Users,
            AdminResource::VirtualMachines,
            AdminResource::Hosts,
            AdminResource::Payments,
            AdminResource::Analytics,
            AdminResource::System,
            AdminResource::Roles,
            AdminResource::Audit,
            AdminResource::AccessPolicy,
            AdminResource::Company,
            AdminResource::IpRange,
            AdminResource::Router,
            AdminResource::VmCustomPricing,
            AdminResource::HostRegion,
            AdminResource::VmOsImage,
            AdminResource::VmPayment,
            AdminResource::VmTemplate,
        ]
    }
}

impl Display for AdminAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminAction::Create => write!(f, "create"),
            AdminAction::View => write!(f, "view"),
            AdminAction::Update => write!(f, "update"),
            AdminAction::Delete => write!(f, "delete"),
        }
    }
}

impl FromStr for AdminAction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(AdminAction::Create),
            "view" | "read" | "list" => Ok(AdminAction::View),
            "update" | "edit" => Ok(AdminAction::Update),
            "delete" | "remove" => Ok(AdminAction::Delete),
            _ => Err(anyhow!("unknown admin action: {}", s)),
        }
    }
}

impl TryFrom<u16> for AdminAction {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminAction::Create),
            1 => Ok(AdminAction::View),
            2 => Ok(AdminAction::Update),
            3 => Ok(AdminAction::Delete),
            _ => Err(anyhow!("unknown admin action value: {}", value)),
        }
    }
}

impl AdminAction {
    /// Get all available admin actions
    pub fn all() -> Vec<AdminAction> {
        vec![
            AdminAction::Create,
            AdminAction::View,
            AdminAction::Update,
            AdminAction::Delete,
        ]
    }
}
