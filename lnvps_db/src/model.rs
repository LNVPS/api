use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sqlx::FromRow;

#[serde_as]
#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
/// Users who buy VM's
pub struct User {
    /// Unique ID of this user (database generated)
    pub id: u64,

    /// The nostr public key for this user
    #[serde_as(as = "serde_with::hex::Hex")]
    pub pubkey: Vec<u8>,

    /// When this user first started using the service (first login)
    pub created: DateTime<Utc>,

    pub email: Option<String>,
    pub contact_nip4: bool,
    pub contact_nip17: bool,
    pub contact_email: bool,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug, Default)]
pub struct UserSshKey {
    pub id: u64,
    pub name: String,
    pub user_id: u64,
    pub created: DateTime<Utc>,
    #[serde(skip_serializing)]
    pub key_data: String,

    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vms: Option<Vec<Vm>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, sqlx::Type)]
#[repr(u16)]
/// The type of VM host
pub enum VmHostKind {
    Proxmox = 0,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct VmHostRegion {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
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
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct VmHostDisk {
    pub id: u64,
    pub host_id: u64,
    pub name: String,
    pub size: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, sqlx::Type, Default)]
#[serde(rename_all = "lowercase")]
#[repr(u16)]
pub enum DiskType {
    #[default]
    HDD = 0,
    SSD = 1,
}

#[derive(Serialize, Deserialize, Clone, Debug, sqlx::Type, Default)]
#[serde(rename_all = "lowercase")]
#[repr(u16)]
pub enum DiskInterface {
    #[default]
    SATA = 0,
    SCSI = 1,
    PCIe = 2,
}

#[derive(Serialize, Deserialize, Clone, Debug, sqlx::Type, Default)]
#[repr(u16)]
pub enum OsDistribution {
    #[default]
    Ubuntu = 0,
    Debian = 1,
}

/// OS Images are templates which are used as a basis for
/// provisioning new vms
#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct VmOsImage {
    pub id: u64,
    pub distribution: OsDistribution,
    pub flavour: String,
    pub version: String,
    pub enabled: bool,
    pub release_date: DateTime<Utc>,
    #[serde(skip_serializing)]
    /// URL location of cloud image
    pub url: String,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct IpRange {
    pub id: u64,
    pub cidr: String,
    pub enabled: bool,
    pub region_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[repr(u16)]
pub enum VmCostPlanIntervalType {
    Day = 0,
    Month = 1,
    Year = 2,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct VmCostPlan {
    pub id: u64,
    pub name: String,
    pub created: DateTime<Utc>,
    pub amount: u64,
    pub currency: String,
    pub interval_amount: u64,
    pub interval_type: VmCostPlanIntervalType,
}

/// Offers.
/// These are the same as the offers visible to customers
#[derive(Serialize, Deserialize, FromRow, Clone, Debug, Default)]
pub struct VmTemplate {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub created: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub cpu: u16,
    pub memory: u64,
    pub disk_size: u64,
    pub disk_type: DiskType,
    pub disk_interface: DiskInterface,
    pub cost_plan_id: u64,
    pub region_id: u64,

    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_plan: Option<VmCostPlan>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<VmHostRegion>,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug, Default)]
pub struct Vm {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// The host this VM is on
    pub host_id: u64,
    /// The user that owns this VM
    pub user_id: u64,
    /// The base image of this VM
    pub image_id: u64,
    /// The base image of this VM
    pub template_id: u64,
    /// Users ssh-key assigned to this VM
    pub ssh_key_id: u64,
    /// When the VM was created
    pub created: DateTime<Utc>,
    /// When the VM expires
    pub expires: DateTime<Utc>,
    /// How many vCPU's this VM has
    pub cpu: u16,
    /// How much RAM this VM has in bytes
    pub memory: u64,
    /// How big the disk is on this VM in bytes
    pub disk_size: u64,
    /// The [VmHostDisk] this VM is on
    pub disk_id: u64,

    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<VmOsImage>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<VmTemplate>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<UserSshKey>,

    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payments: Option<Vec<VmPayment>>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_assignments: Option<Vec<VmIpAssignment>>,
}

#[derive(Serialize, Deserialize, FromRow, Clone, Debug)]
pub struct VmIpAssignment {
    pub id: u64,
    pub vm_id: u64,
    pub ip_range_id: u64,
    pub ip: String,
}

#[serde_as]
#[derive(Serialize, Deserialize, FromRow, Clone, Debug, Default)]
pub struct VmPayment {
    /// Payment hash
    #[serde_as(as = "serde_with::hex::Hex")]
    pub id: Vec<u8>,
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub invoice: String,
    pub is_paid: bool,
    /// Exchange rate
    pub rate: f32,

    /// Number of seconds this payment will add to vm expiry
    #[serde(skip_serializing)]
    pub time_value: u64,

    #[serde(skip_serializing)]
    pub settle_index: Option<u64>,
}
