use chrono::{DateTime, Utc};
use rocket::serde::Serialize;
use sqlx::FromRow;

#[derive(Serialize, FromRow)]
/// Users who buy VM's
pub struct User {
    /// Unique ID of this user (database generated)
    pub id: u64,
    /// The nostr public key for this user
    pub pubkey: [u8; 32],
    /// When this user first started using the service (first login)
    pub created: DateTime<Utc>,
}

#[derive(Serialize)]
/// The type of VM host
pub enum VmHostKind {
    Proxmox,
}

#[derive(Serialize, FromRow)]
/// A VM host
pub struct VmHost {
    pub id: u64,
    pub kind: VmHostKind,
    pub name: String,
    pub ip: String,
    /// Total number of CPU cores
    pub cpu: u16,
    /// Total memory size in bytes
    pub memory: u64,
    /// If VM's should be provisioned on this host
    pub enabled: bool,
    pub api_token: String,
}

#[derive(Serialize, FromRow)]
pub struct VmHostDisk {
    pub id: u64,
    pub host_id: u64,
    pub name: String,
    pub size: u64,
    pub kind: DiskType,
    pub interface: DiskInterface,
    pub enabled: bool,
}

#[derive(Serialize)]
pub enum DiskType {
    HDD,
    SSD,
}

#[derive(Serialize)]
pub enum DiskInterface {
    SATA,
    SCSI,
    PCIe,
}

#[derive(Serialize, FromRow)]
pub struct VmOsImage {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
}

#[derive(Serialize, FromRow)]
pub struct IpRange {
    pub id: u64,
    pub cidr: String,
    pub enabled: bool,
}

#[derive(Serialize, FromRow)]
pub struct Vm {
    /// Unique VM ID (Same in proxmox)
    pub id: u64,
    /// The host this VM is on
    pub host_id: u64,
    /// The user that owns this VM
    pub user_id: u64,
    /// The base image of this VM
    pub image_id: u64,
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
}
