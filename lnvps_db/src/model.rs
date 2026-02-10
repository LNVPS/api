use crate::encrypted_string::EncryptedString;
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
    /// Users email address for notifications (encrypted)
    pub email: Option<EncryptedString>,
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
    /// Nostr Wallet Connect connection string for automatic renewals (encrypted)
    pub nwc_connection_string: Option<EncryptedString>,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct UserSshKey {
    pub id: u64,
    pub name: String,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub key_data: EncryptedString,
}

#[derive(FromRow, Clone, Debug, Default)]
pub struct AdminUserInfo {
    #[sqlx(flatten)]
    pub user_info: User,
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
    /// API token used to control this host via [ip] (encrypted)
    pub api_token: EncryptedString,
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

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DiskType {
    #[default]
    HDD = 0,
    SSD = 1,
}

/// Unified struct containing all VM host data needed for admin purposes
#[derive(FromRow, Clone, Debug)]
pub struct AdminVmHost {
    #[sqlx(flatten)]
    pub host: VmHost,

    // Region fields with prefixed names to avoid conflicts
    pub region_id: u64,
    #[sqlx(rename = "region_name")]
    pub region_name: String,
    #[sqlx(rename = "region_enabled")]
    pub region_enabled: bool,
    #[sqlx(rename = "region_company_id")]
    pub region_company_id: Option<u64>,

    // Disk information (populated separately, not from SQL)
    #[sqlx(skip)]
    pub disks: Vec<VmHostDisk>,

    // Additional calculated data that can be populated by the database function
    pub active_vm_count: i64,
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

#[derive(Clone, Copy, Debug, sqlx::Type, Default, PartialEq, Eq, Hash)]
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
    pub token: EncryptedString,
}

#[derive(Debug, Clone, sqlx::Type)]
#[repr(u16)]
pub enum RouterKind {
    /// Mikrotik router (JSON-Api)
    Mikrotik = 0,
    /// A pseudo-router which allows adding virtual mac addresses to a dedicated server
    OvhAdditionalIp = 1,
    /// Mock router access in tests
    MockRouter = u16::MAX,
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

#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize)]
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
    /// Minimum CPU cores allowed
    pub min_cpu: u16,
    /// Maximum CPU cores allowed
    pub max_cpu: u16,
    /// Minimum memory in bytes
    pub min_memory: u64,
    /// Maximum memory in bytes
    pub max_memory: u64,
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
    /// Minimum disk size in bytes for this disk type/interface
    pub min_disk_size: u64,
    /// Maximum disk size in bytes for this disk type/interface
    pub max_disk_size: u64,
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
    /// Enable automatic renewal
    pub auto_renewal_enabled: bool,
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
    pub payment_type: PaymentType,
    /// External data (invoice / json) (encrypted)
    pub external_data: EncryptedString,
    /// External id on other system
    pub external_id: Option<String>,
    pub is_paid: bool,
    /// Exchange rate back to company's base currency
    pub rate: f32,
    /// Number of seconds this payment will add to vm expiry
    pub time_value: u64,
    /// Taxes to charge on payment
    pub tax: u64,
    /// JSON-encoded upgrade parameters (CPU, memory, disk) for upgrade payments
    pub upgrade_params: Option<String>,
}

#[derive(FromRow, Clone, Debug)]
pub struct ReferralCostUsage {
    pub vm_id: u64,
    pub ref_code: String,
    pub created: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub rate: f32,
    pub base_currency: String,
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
    pub payment_type: PaymentType,
    /// External data (invoice / json) (encrypted)
    pub external_data: EncryptedString,
    /// External id on other system
    pub external_id: Option<String>,
    pub is_paid: bool,
    /// Exchange rate back to company's base currency
    pub rate: f32,
    /// Number of seconds this payment will add to vm expiry
    pub time_value: u64,
    /// Taxes to charge on payment
    pub tax: u64,
    /// JSON-encoded upgrade parameters (CPU, memory, disk) for upgrade payments
    pub upgrade_params: Option<String>,
    // Company information
    pub company_id: u64,
    pub company_name: String,
    pub company_base_currency: String,
}

#[derive(Type, Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PaymentMethod {
    #[default]
    Lightning,
    Revolut,
    Paypal,
    Stripe,
}

#[derive(Type, Clone, Copy, Debug, Default, PartialEq)]
#[repr(u16)]
pub enum PaymentType {
    #[default]
    Renewal = 0,
    Upgrade = 1,
}

impl Display for PaymentMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentMethod::Lightning => write!(f, "Lightning"),
            PaymentMethod::Revolut => write!(f, "Revolut"),
            PaymentMethod::Paypal => write!(f, "PayPal"),
            PaymentMethod::Stripe => write!(f, "Stripe"),
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
            "stripe" => Ok(PaymentMethod::Stripe),
            _ => bail!("Unknown payment method: {}", s),
        }
    }
}

impl Display for PaymentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PaymentType::Renewal => write!(f, "Renewal"),
            PaymentType::Upgrade => write!(f, "Upgrade"),
        }
    }
}

impl FromStr for PaymentType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "renewal" => Ok(PaymentType::Renewal),
            "upgrade" => Ok(PaymentType::Upgrade),
            _ => bail!("Unknown payment type: {}", s),
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
    pub last_status_change: DateTime<Utc>,
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
    Subscriptions = 17,
    SubscriptionLineItems = 18,
    SubscriptionPayments = 19,
    IpSpace = 20,
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
            AdminResource::Subscriptions => write!(f, "subscriptions"),
            AdminResource::SubscriptionLineItems => write!(f, "subscription_line_items"),
            AdminResource::SubscriptionPayments => write!(f, "subscription_payments"),
            AdminResource::IpSpace => write!(f, "ip_space"),
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
            "subscriptions" => Ok(AdminResource::Subscriptions),
            "subscription_line_items" => Ok(AdminResource::SubscriptionLineItems),
            "subscription_payments" => Ok(AdminResource::SubscriptionPayments),
            "ip_space" => Ok(AdminResource::IpSpace),
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
            17 => Ok(AdminResource::Subscriptions),
            18 => Ok(AdminResource::SubscriptionLineItems),
            19 => Ok(AdminResource::SubscriptionPayments),
            20 => Ok(AdminResource::IpSpace),
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
            AdminResource::Subscriptions,
            AdminResource::SubscriptionLineItems,
            AdminResource::SubscriptionPayments,
            AdminResource::IpSpace,
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

// ============================================================================
// Subscription Billing System - Recurring services (LIR, ASN, etc.)
// ============================================================================

/// Subscription payment type (Purchase or Renewal)
#[derive(Type, Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum SubscriptionPaymentType {
    /// Initial purchase including setup fees
    #[default]
    Purchase = 0,
    /// Recurring renewal payment
    Renewal = 1,
}

impl Display for SubscriptionPaymentType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionPaymentType::Purchase => write!(f, "Purchase"),
            SubscriptionPaymentType::Renewal => write!(f, "Renewal"),
        }
    }
}

/// Subscription for a recurring service (always monthly billing)
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
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
}

/// Subscription Type - Type of service being sold
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum SubscriptionType {
    IpRange = 0,       // IP range allocation/LIR services
    AsnSponsoring = 1, // ASN sponsoring services
    DnsHosting = 2,    // DNS hosting services
}

impl Display for SubscriptionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionType::IpRange => write!(f, "IP Range"),
            SubscriptionType::AsnSponsoring => write!(f, "ASN Sponsoring"),
            SubscriptionType::DnsHosting => write!(f, "DNS Hosting"),
        }
    }
}

/// Line item within a subscription
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionLineItem {
    pub id: u64,
    pub subscription_id: u64,
    pub subscription_type: SubscriptionType,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    pub configuration: Option<serde_json::Value>,
}

/// Subscription payment
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionPayment {
    pub id: Vec<u8>,
    pub subscription_id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    pub payment_type: SubscriptionPaymentType,
    pub external_data: EncryptedString,
    pub external_id: Option<String>,
    pub is_paid: bool,
    pub rate: f32,
    pub tax: u64,
}

/// Subscription payment with company info (for admin views)
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionPaymentWithCompany {
    pub id: Vec<u8>,
    pub subscription_id: u64,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub payment_method: PaymentMethod,
    pub payment_type: SubscriptionPaymentType,
    pub external_data: EncryptedString,
    pub external_id: Option<String>,
    pub is_paid: bool,
    pub rate: f32,
    pub tax: u64,
    pub company_base_currency: String,
}

/// Internet Registry - Regional Internet Registry
#[derive(Clone, Copy, Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum InternetRegistry {
    ARIN = 0,    // American Registry for Internet Numbers
    RIPE = 1,    // Réseaux IP Européens Network Coordination Centre
    APNIC = 2,   // Asia-Pacific Network Information Centre
    LACNIC = 3,  // Latin America and Caribbean Network Information Centre
    AFRINIC = 4, // African Network Information Centre
}

impl Display for InternetRegistry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InternetRegistry::ARIN => write!(f, "ARIN"),
            InternetRegistry::RIPE => write!(f, "RIPE"),
            InternetRegistry::APNIC => write!(f, "APNIC"),
            InternetRegistry::LACNIC => write!(f, "LACNIC"),
            InternetRegistry::AFRINIC => write!(f, "AFRINIC"),
        }
    }
}

impl InternetRegistry {
    /// Get the minimum IPv4 prefix size that can be announced in BGP for this RIR
    /// Based on industry-standard minimum announcement sizes
    pub fn min_ipv4_prefix_size(&self) -> u16 {
        match self {
            InternetRegistry::ARIN => 24,    // /24 minimum
            InternetRegistry::RIPE => 24,    // /24 minimum
            InternetRegistry::APNIC => 24,   // /24 minimum
            InternetRegistry::LACNIC => 24,  // /24 minimum
            InternetRegistry::AFRINIC => 24, // /24 minimum
        }
    }

    /// Get the minimum IPv6 prefix size that can be announced in BGP for this RIR
    /// Based on industry-standard minimum announcement sizes
    pub fn min_ipv6_prefix_size(&self) -> u16 {
        match self {
            InternetRegistry::ARIN => 48, // /48 minimum (though /32 is more common for allocations)
            InternetRegistry::RIPE => 48, // /48 minimum
            InternetRegistry::APNIC => 48, // /48 minimum
            InternetRegistry::LACNIC => 48, // /48 minimum
            InternetRegistry::AFRINIC => 48, // /48 minimum
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_registry_min_prefix_sizes() {
        // Test that all RIRs return correct minimum prefix sizes
        assert_eq!(InternetRegistry::ARIN.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::RIPE.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::APNIC.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::LACNIC.min_ipv4_prefix_size(), 24);
        assert_eq!(InternetRegistry::AFRINIC.min_ipv4_prefix_size(), 24);

        assert_eq!(InternetRegistry::ARIN.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::RIPE.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::APNIC.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::LACNIC.min_ipv6_prefix_size(), 48);
        assert_eq!(InternetRegistry::AFRINIC.min_ipv6_prefix_size(), 48);
    }
}

/// Available IP Space - Inventory of IP ranges available for sale
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct AvailableIpSpace {
    pub id: u64,
    pub cidr: String,
    pub min_prefix_size: u16,
    pub max_prefix_size: u16,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub registry: InternetRegistry,
    pub external_id: Option<String>,
    pub is_available: bool,
    pub is_reserved: bool,
    pub metadata: Option<serde_json::Value>,
}

/// IP Space Pricing - Pricing for different prefix sizes from an IP block
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct IpSpacePricing {
    pub id: u64,
    pub available_ip_space_id: u64,
    pub prefix_size: u16,
    pub price_per_month: u64,
    pub currency: String,
    pub setup_fee: u64,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// IP Range Subscription - Stores IP ranges sold to users via subscriptions
#[derive(FromRow, Clone, Debug, Serialize, Deserialize)]
pub struct IpRangeSubscription {
    pub id: u64,
    pub subscription_line_item_id: u64,
    pub available_ip_space_id: u64,
    pub created: DateTime<Utc>,
    pub cidr: String,
    pub is_active: bool,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}
