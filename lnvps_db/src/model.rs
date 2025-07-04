use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
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
            .last()
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

#[derive(Debug, Clone, sqlx::Type, Default)]
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
#[derive(Debug, Clone, sqlx::Type)]
#[repr(u16)]
pub enum NetworkAccessPolicy {
    /// ARP entries are added statically on the access router
    StaticArp = 0,
}

#[derive(Clone, Debug, sqlx::Type)]
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
    /// TODO: handle other base currencies
    /// Exchange rate back to base currency (EUR)
    pub rate: f32,
    /// Number of seconds this payment will add to vm expiry
    pub time_value: u64,
    /// Taxes to charge on payment
    pub tax: u64,
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
}
