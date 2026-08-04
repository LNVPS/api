//! Libvirt domain / storage volume XML types and builders.
//!
//! These mirror the subset of <https://libvirt.org/formatdomain.html> and
//! <https://libvirt.org/formatstorage.html> that LNVPS needs. Serialization is
//! done with `quick_xml`, so **field order is XML element order**.

use crate::host::FullVmInfo;
use crate::host::config::QemuConfig;
use anyhow::{Result, bail};
use lnvps_db::{DiskInterface, DiskType as DbDiskType};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// Namespace for deterministic per-VM domain UUIDs.
///
/// The UUID must be stable across re-definitions of the same VM: libvirt keys
/// a domain's identity on it, and a changing UUID makes the guest look like
/// new hardware (new machine-id, re-triggered cloud-init, re-licensed Windows).
const VM_UUID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0x0e, 0x4d, 0x9a, 0x1c, 0x74, 0x4d, 0x2e, 0x9f, 0x3b, 0x2d, 0x51, 0x8a, 0x4c, 0x77, 0x10,
]);

/// Domain name as libvirt sees it. Also the key used to map a domain back to a
/// database VM id, so the format is load-bearing — see [`vm_id_from_domain_name`].
pub fn domain_name(vm_id: u64) -> String {
    format!("VM{vm_id}")
}

/// Inverse of [`domain_name`]. Returns `None` for domains LNVPS doesn't manage,
/// which is how foreign VMs on a shared host are skipped.
pub fn vm_id_from_domain_name(name: &str) -> Option<u64> {
    name.strip_prefix("VM")?.parse().ok()
}

/// Deterministic domain UUID for a VM id.
pub fn domain_uuid(vm_id: u64) -> Uuid {
    Uuid::new_v5(&VM_UUID_NAMESPACE, domain_name(vm_id).as_bytes())
}

/// Storage volume name holding a VM's primary disk.
pub fn primary_disk_volume(vm_id: u64) -> String {
    format!("vm-{vm_id}-disk0")
}

/// Guest device name of the primary disk. Load-bearing: block-level operations
/// (live resize, IO stats) address the disk by this name.
pub const PRIMARY_DISK_TARGET: &str = "vda";

/// Storage volume name holding a VM's cloud-init NoCloud seed image.
pub fn seed_volume(vm_id: u64) -> String {
    format!("vm-{vm_id}-seed.iso")
}

/// Storage volume name caching an OS image on the host.
pub fn os_image_volume(image_id: u64, format: VolumeFormat) -> String {
    format!("os-image-{image_id}.{}", format.extension())
}

/// Validate the parts of a VM config that must be present before any host
/// state is touched.
pub fn validate(cfg: &FullVmInfo) -> Result<()> {
    let resources = cfg.resources()?;
    if resources.cpu == 0 {
        bail!("VM {} has no CPU cores assigned", cfg.vm.id);
    }
    if resources.memory == 0 {
        bail!("VM {} has no memory assigned", cfg.vm.id);
    }
    if cfg.vm.mac_address.is_empty() {
        bail!("VM {} has no MAC address assigned", cfg.vm.id);
    }
    Ok(())
}

/// Build the full domain XML for a VM.
///
/// `disk_path` is the **resolved** host path of the primary disk volume. It has
/// to be resolved by the caller (via libvirt) rather than referenced as
/// `<disk type='volume'>`: with a volume-typed disk libvirt does not apply DAC
/// relabelling to the backing file, so QEMU starts as `libvirt-qemu` and is
/// denied access to a root-owned image. The identical disk works when given as
/// `type='file'`.
pub fn build_domain(
    cfg: &FullVmInfo,
    qemu: &QemuConfig,
    secure_boot: bool,
    disk_path: &str,
    seed_path: Option<&str>,
    vlan_aware_bridge: bool,
) -> Result<DomainXML> {
    validate(cfg)?;

    // libvirt happily accepts <vlan> on a bridge interface and QEMU starts
    // fine, but a Linux bridge without `vlan_filtering=1` ignores the tag
    // entirely — the guest silently joins the untagged network, breaking
    // tenant isolation with no error anywhere. Refuse rather than guess.
    if cfg.host.vlan_id.is_some() && !vlan_aware_bridge {
        bail!(
            "host has vlan_id {} but bridge \"{}\" is not declared VLAN-aware: a \
             Linux bridge without vlan_filtering=1 silently ignores the tag and \
             places the VM on the untagged network. Enable VLAN filtering on the \
             bridge and set `vlan-aware-bridge: true` in the libvirt provisioner \
             config, or clear the host's vlan_id.",
            cfg.host.vlan_id.unwrap_or_default(),
            qemu.bridge
        );
    }
    let resources = cfg.resources()?;
    let limits = cfg.limits();

    let mut devices = Vec::new();

    devices.push(DomainDevice::Disk(Disk {
        kind: DiskType::File,
        device: DiskDevice::Disk,
        driver: Some(DiskDriver {
            name: "qemu".to_string(),
            kind: Some(VolumeFormat::QCow2),
            // Guest writes hit stable storage before being acknowledged; the
            // alternative silently trades customer data for benchmark numbers.
            cache: Some("none".to_string()),
            discard: Some("unmap".to_string()),
        }),
        source: DiskSource {
            file: Some(disk_path.to_string()),
            ..Default::default()
        },
        target: DiskTarget {
            dev: PRIMARY_DISK_TARGET.to_string(),
            bus: Some(disk_bus(cfg.disk.interface)),
        },
        read_only: None,
        iotune: DiskIoTune::from_limits(&limits),
    }));

    // cloud-init NoCloud seed, attached read-only as a CD-ROM. cloud-init finds
    // it by filesystem label (`cidata`) rather than by device, so the bus and
    // target name here are not load-bearing.
    if let Some(seed) = seed_path {
        devices.push(DomainDevice::Disk(Disk {
            kind: DiskType::File,
            device: DiskDevice::CdRom,
            driver: Some(DiskDriver {
                name: "qemu".to_string(),
                kind: Some(VolumeFormat::Raw),
                cache: None,
                discard: None,
            }),
            source: DiskSource {
                file: Some(seed.to_string()),
                ..Default::default()
            },
            target: DiskTarget {
                dev: "sda".to_string(),
                bus: Some(DiskBus::SATA),
            },
            read_only: Some(EmptyElement {}),
            iotune: None,
        }));
    }

    devices.push(DomainDevice::Interface(NetworkInterface {
        kind: NetworkKind::Bridge,
        mac: Some(NetworkMac {
            address: cfg.vm.mac_address.clone(),
        }),
        source: Some(NetworkSource {
            bridge: Some(qemu.bridge.clone()),
        }),
        model: Some(NetworkModel {
            kind: "virtio".to_string(),
        }),
        target: None,
        vlan: cfg.host.vlan_id.map(|v| NetworkVlan {
            tags: vec![NetworkVlanTag { id: v as u32 }],
        }),
        bandwidth: limits.network_mbps.map(NetworkBandwidth::from_mbps),
        mtu: cfg.host.mtu.map(|m| NetworkMtu { size: m as u32 }),
        // Without this reference the per-VM nwfilter is defined on the host but
        // attached to nothing, so every rule (including anti-spoofing) silently
        // enforces nothing.
        filterref: Some(FilterRef {
            filter: super::nwfilter::filter_name(cfg.vm.id),
        }),
    }));

    // Serial console: required for out-of-band access when networking breaks,
    // which for a VPS is the difference between a support ticket and a rebuild.
    devices.push(DomainDevice::Serial(SerialDevice {
        kind: "pty".to_string(),
        target: Some(SerialTarget {
            port: Some(0),
            kind: None,
        }),
    }));
    devices.push(DomainDevice::Console(ConsoleDevice {
        kind: "pty".to_string(),
        target: Some(SerialTarget {
            port: Some(0),
            kind: Some("serial".to_string()),
        }),
    }));

    Ok(DomainXML {
        kind: if qemu.kvm {
            DomainType::KVM
        } else {
            DomainType::QEMU
        },
        name: Some(domain_name(cfg.vm.id)),
        uuid: Some(domain_uuid(cfg.vm.id)),
        title: None,
        description: None,
        // NOTE: libvirt defaults <memory> to KiB. Sizes are stored in bytes in
        // the database, so the unit must be stated explicitly or every VM gets
        // 1024x the RAM it was sold.
        memory: MemoryValue::bytes(resources.memory),
        current_memory: MemoryValue::bytes(resources.memory),
        vcpu: resources.cpu,
        os: DomainOs {
            kind: DomainOsType {
                kind: DomainOsTypeKind::Hvm,
                arch: Some(DomainOsArch::from_str(&qemu.arch)?),
                machine: Some(DomainOsMachine::from_str(&qemu.machine)?),
            },
            firmware: Some(DomainOsFirmware::EFI),
            // Firmware autoselection MUST be constrained. Given only
            // `firmware='efi'`, libvirt is free to pick the Microsoft
            // secure-boot OVMF build (`OVMF_CODE_4M.ms.fd`, enrolled-keys +
            // secure-boot on). A guest booted on it without SMM produces no
            // output whatsoever — no firmware banner, no bootloader, nothing —
            // and looks exactly like a broken disk. Stating the requirement
            // explicitly pins the plain `OVMF_CODE_4M.fd` build instead.
            firmware_features: Some(DomainOsFirmwareFeatures::new(secure_boot)),
            // No <loader>: libvirt fills in the correct loader/nvram pair from
            // the feature constraints above.
            loader: None,
            boot: DomainOsBoot {
                dev: DomainOsBootDev::HardDrive,
            },
        },
        features: Some(DomainFeatures::new(secure_boot)),
        cpu: Some(DomainCpu::from_model(&qemu.cpu)),
        clock: Some(DomainClock {
            offset: "utc".to_string(),
        }),
        on_poweroff: Some(DomainLifecycleAction::Destroy),
        // Keep a guest-initiated reboot inside the guest instead of leaving the
        // domain powered off and the customer locked out.
        on_reboot: Some(DomainLifecycleAction::Restart),
        on_crash: Some(DomainLifecycleAction::Restart),
        devices: DomainDevices { contents: devices },
    })
}

fn disk_bus(interface: DiskInterface) -> DiskBus {
    match interface {
        // VirtIO is the fast path and what cloud images expect; SATA is only
        // used where a guest lacks virtio drivers.
        DiskInterface::PCIe => DiskBus::VirtIO,
        DiskInterface::SCSI => DiskBus::SCSI,
        DiskInterface::SATA => DiskBus::SATA,
    }
}

/// Storage volume XML used when creating or cloning volumes.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "volume")]
pub struct VolumeXML {
    pub name: String,
    pub capacity: VolumeCapacity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation: Option<VolumeCapacity>,
    pub target: VolumeTarget,
}

impl VolumeXML {
    pub fn new(name: &str, capacity_bytes: u64, format: VolumeFormat) -> Self {
        Self {
            name: name.to_string(),
            capacity: VolumeCapacity::bytes(capacity_bytes),
            allocation: None,
            target: VolumeTarget {
                format: VolumeTargetFormat { kind: format },
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct VolumeCapacity {
    #[serde(rename = "@unit")]
    pub unit: String,
    #[serde(rename = "$text")]
    pub value: u64,
}

impl VolumeCapacity {
    pub fn bytes(value: u64) -> Self {
        Self {
            unit: "bytes".to_string(),
            value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "target")]
pub struct VolumeTarget {
    pub format: VolumeTargetFormat,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "format")]
pub struct VolumeTargetFormat {
    #[serde(rename = "@type")]
    pub kind: VolumeFormat,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VolumeFormat {
    Raw,
    #[default]
    #[serde(rename = "qcow2")]
    QCow2,
}

impl VolumeFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            VolumeFormat::Raw => "raw",
            VolumeFormat::QCow2 => "qcow2",
        }
    }

    /// Guess the on-disk format of a downloaded OS image from its URL.
    ///
    /// Cloud images are overwhelmingly qcow2, so that is the fallback — a wrong
    /// guess would make QEMU misread the image, so this is deliberately
    /// conservative about what counts as raw.
    pub fn from_url(url: &str) -> Self {
        let path = url.split(['?', '#']).next().unwrap_or(url);
        let lower = path.to_lowercase();
        if lower.ends_with(".raw") || lower.ends_with(".img") {
            VolumeFormat::Raw
        } else {
            VolumeFormat::QCow2
        }
    }
}

impl From<DbDiskType> for VolumeFormat {
    fn from(_: DbDiskType) -> Self {
        // Disk *type* (HDD/SSD) describes the backing hardware, not the image
        // format; VM disks are always qcow2 so snapshots stay possible.
        VolumeFormat::QCow2
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "domain")]
pub struct DomainXML {
    #[serde(rename = "@type")]
    pub kind: DomainType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub memory: MemoryValue,
    #[serde(rename = "currentMemory")]
    pub current_memory: MemoryValue,
    pub vcpu: u16,
    pub os: DomainOs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<DomainFeatures>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<DomainCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock: Option<DomainClock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_poweroff: Option<DomainLifecycleAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_reboot: Option<DomainLifecycleAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_crash: Option<DomainLifecycleAction>,
    pub devices: DomainDevices,
}

impl DomainXML {
    pub fn to_xml(&self) -> Result<String> {
        Ok(quick_xml::se::to_string(self)?)
    }
}

/// A size with an explicit unit. Always written in bytes to avoid libvirt's
/// KiB default silently rescaling values.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct MemoryValue {
    #[serde(rename = "@unit")]
    pub unit: String,
    #[serde(rename = "$text")]
    pub value: u64,
}

impl MemoryValue {
    pub fn bytes(value: u64) -> Self {
        Self {
            unit: "bytes".to_string(),
            value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "devices")]
pub struct DomainDevices {
    #[serde(rename = "$value")]
    pub contents: Vec<DomainDevice>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainType {
    #[default]
    KVM,
    XEN,
    HVF,
    QEMU,
    LXC,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acpi: Option<EmptyElement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apic: Option<EmptyElement>,
    /// System Management Mode — required by libvirt whenever secure boot is
    /// requested, and rejected as pointless clutter otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smm: Option<FeatureState>,
}

impl DomainFeatures {
    pub fn new(secure_boot: bool) -> Self {
        // ACPI is required for graceful shutdown to work at all; without it
        // `stop_vm` degrades into pulling the power cord.
        Self {
            acpi: Some(EmptyElement {}),
            apic: Some(EmptyElement {}),
            smm: secure_boot.then(|| FeatureState {
                state: "on".to_string(),
            }),
        }
    }
}

impl Default for DomainFeatures {
    fn default() -> Self {
        Self::new(false)
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct FeatureState {
    #[serde(rename = "@state")]
    pub state: String,
}

/// libvirt spells booleans `yes` / `no` in most attributes; serializing a Rust
/// `bool` produces `true` / `false`, which libvirt rejects outright.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum YesNo {
    #[default]
    Yes,
    No,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct EmptyElement {}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "cpu")]
pub struct DomainCpu {
    #[serde(rename = "@mode")]
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@match")]
    pub match_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl DomainCpu {
    pub fn from_model(model: &str) -> Self {
        match model {
            // Expose the physical CPU, including instruction sets the guest may
            // need; blocks live migration between dissimilar hosts, which LNVPS
            // does not rely on.
            "host" | "host-passthrough" => Self {
                mode: "host-passthrough".to_string(),
                match_kind: None,
                model: None,
            },
            "host-model" => Self {
                mode: "host-model".to_string(),
                match_kind: None,
                model: None,
            },
            other => Self {
                mode: "custom".to_string(),
                match_kind: Some("exact".to_string()),
                model: Some(other.to_string()),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "clock")]
pub struct DomainClock {
    #[serde(rename = "@offset")]
    pub offset: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainLifecycleAction {
    #[default]
    Destroy,
    Restart,
    Preserve,
    #[serde(rename = "rename-restart")]
    RenameRestart,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "os")]
pub struct DomainOs {
    #[serde(rename = "type")]
    pub kind: DomainOsType,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@firmware")]
    pub firmware: Option<DomainOsFirmware>,
    // The element name comes from the *field* name; a rename on the struct
    // definition is ignored here and would emit <firmware_features>, which
    // libvirt silently drops.
    #[serde(rename = "firmware")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_features: Option<DomainOsFirmwareFeatures>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<DomainOsLoader>,
    pub boot: DomainOsBoot,
}

/// Constraints handed to libvirt's firmware autoselection.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "firmware")]
pub struct DomainOsFirmwareFeatures {
    #[serde(rename = "feature")]
    pub features: Vec<DomainOsFirmwareFeature>,
}

impl DomainOsFirmwareFeatures {
    pub fn new(secure_boot: bool) -> Self {
        let enabled = if secure_boot { YesNo::Yes } else { YesNo::No };
        let mut features = vec![DomainOsFirmwareFeature {
            enabled,
            name: "secure-boot".to_string(),
        }];
        // A secure-boot firmware is useless without the vendor keys enrolled.
        if secure_boot {
            features.push(DomainOsFirmwareFeature {
                enabled: YesNo::Yes,
                name: "enrolled-keys".to_string(),
            });
        }
        Self { features }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "feature")]
pub struct DomainOsFirmwareFeature {
    #[serde(rename = "@enabled")]
    pub enabled: YesNo,
    #[serde(rename = "@name")]
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsFirmware {
    #[default]
    EFI,
    BIOS,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct DomainOsType {
    #[serde(rename = "$text")]
    pub kind: DomainOsTypeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@arch")]
    pub arch: Option<DomainOsArch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@machine")]
    pub machine: Option<DomainOsMachine>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsTypeKind {
    #[default]
    Hvm,
    Xen,
    Linux,
    XenPvh,
    Exe,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsMachine {
    #[default]
    Q35,
    PC,
}

impl FromStr for DomainOsMachine {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "q35" => Ok(DomainOsMachine::Q35),
            "pc" => Ok(DomainOsMachine::PC),
            v => bail!("Unknown machine type {}", v),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsArch {
    #[default]
    X86_64,
    I686,
}

impl FromStr for DomainOsArch {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64" => Ok(Self::X86_64),
            "i686" => Ok(Self::I686),
            v => bail!("unsupported arch {}", v),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "loader")]
pub struct DomainOsLoader {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@readonly")]
    pub read_only: Option<YesNo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@type")]
    pub kind: Option<DomainOsLoaderType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@secure")]
    pub secure: Option<YesNo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@stateless")]
    pub stateless: Option<YesNo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@format")]
    pub format: Option<DomainOsLoaderFormat>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsLoaderType {
    #[default]
    ROM,
    PFlash,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsLoaderFormat {
    Raw,
    #[default]
    QCow2,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct DomainOsBoot {
    #[serde(rename = "@dev")]
    pub dev: DomainOsBootDev,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DomainOsBootDev {
    #[serde(rename = "fd")]
    Floppy,
    #[serde(rename = "hd")]
    #[default]
    HardDrive,
    CdRom,
    Network,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DomainDevice {
    #[serde(rename = "disk")]
    Disk(Disk),
    #[serde(rename = "interface")]
    Interface(NetworkInterface),
    #[serde(rename = "serial")]
    Serial(SerialDevice),
    #[serde(rename = "console")]
    Console(ConsoleDevice),
    #[serde(other)]
    Other,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "serial")]
pub struct SerialDevice {
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<SerialTarget>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "console")]
pub struct ConsoleDevice {
    #[serde(rename = "@type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<SerialTarget>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "target")]
pub struct SerialTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@type")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@port")]
    pub port: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "interface")]
pub struct NetworkInterface {
    #[serde(rename = "@type")]
    pub kind: NetworkKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<NetworkMac>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<NetworkSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<NetworkModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<NetworkTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<NetworkVlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<NetworkBandwidth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<NetworkMtu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filterref: Option<FilterRef>,
}

/// Reference from an interface to the VM's nwfilter.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "filterref")]
pub struct FilterRef {
    #[serde(rename = "@filter")]
    pub filter: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "model")]
pub struct NetworkModel {
    #[serde(rename = "@type")]
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "mtu")]
pub struct NetworkMtu {
    #[serde(rename = "@size")]
    pub size: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "bandwidth")]
pub struct NetworkBandwidth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound: Option<NetworkBandwidthLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<NetworkBandwidthLimit>,
}

impl NetworkBandwidth {
    /// libvirt expresses `average` in **kilobytes per second**, while templates
    /// store megabits per second.
    pub fn from_mbps(mbps: u32) -> Self {
        let kbytes_sec = (mbps as u64 * 1000) / 8;
        let limit = NetworkBandwidthLimit {
            average: kbytes_sec,
        };
        Self {
            inbound: Some(limit.clone()),
            outbound: Some(limit),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct NetworkBandwidthLimit {
    #[serde(rename = "@average")]
    pub average: u64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "vlan")]
pub struct NetworkVlan {
    #[serde(rename = "tag")]
    pub tags: Vec<NetworkVlanTag>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "tag")]
pub struct NetworkVlanTag {
    #[serde(rename = "@id")]
    pub id: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Network,
    #[default]
    Bridge,
    User,
    Ethernet,
    Direct,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "mac")]
pub struct NetworkMac {
    #[serde(rename = "@address")]
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "source")]
pub struct NetworkSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@bridge")]
    pub bridge: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "target")]
pub struct NetworkTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@dev")]
    pub dev: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "disk")]
pub struct Disk {
    #[serde(rename = "@type")]
    pub kind: DiskType,
    #[serde(rename = "@device")]
    pub device: DiskDevice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<DiskDriver>,
    pub source: DiskSource,
    pub target: DiskTarget,
    #[serde(rename = "readonly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<EmptyElement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iotune: Option<DiskIoTune>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "driver")]
pub struct DiskDriver {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@type")]
    pub kind: Option<VolumeFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@cache")]
    pub cache: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@discard")]
    pub discard: Option<String>,
}

/// Per-disk throttling. Mirrors the template's IOPS / throughput caps.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "iotune")]
pub struct DiskIoTune {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_iops_sec: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_iops_sec: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_bytes_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_bytes_sec: Option<u64>,
}

impl DiskIoTune {
    /// Returns `None` when nothing is capped so no empty `<iotune/>` element is
    /// emitted (libvirt rejects it).
    pub fn from_limits(limits: &crate::host::VmLimits) -> Option<Self> {
        let tune = Self {
            read_iops_sec: limits.disk_iops_read,
            write_iops_sec: limits.disk_iops_write,
            read_bytes_sec: limits.disk_mbps_read.map(|m| m as u64 * 1000 * 1000),
            write_bytes_sec: limits.disk_mbps_write.map(|m| m as u64 * 1000 * 1000),
        };
        if tune.read_iops_sec.is_none()
            && tune.write_iops_sec.is_none()
            && tune.read_bytes_sec.is_none()
            && tune.write_bytes_sec.is_none()
        {
            None
        } else {
            Some(tune)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DiskType {
    #[default]
    File,
    Block,
    Dir,
    Network,
    Volume,
    Nvme,
    VHostUser,
    VHostVdpa,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DiskDevice {
    Floppy,
    #[default]
    Disk,
    CdRom,
    Lun,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "source")]
pub struct DiskSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@file")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@dir")]
    pub dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@pool")]
    pub pool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@volume")]
    pub volume: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "target")]
pub struct DiskTarget {
    /// Device name (hint)
    #[serde(rename = "@dev")]
    pub dev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@bus")]
    pub bus: Option<DiskBus>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DiskBus {
    #[default]
    IDE,
    SCSI,
    VirtIO,
    XEN,
    USB,
    SATA,
}

/// Devices extracted from a *live* domain XML document.
///
/// The live XML contains hypervisor-generated values that the builder cannot
/// know (the tap device name, the resolved volume path), so it is parsed with a
/// streaming reader rather than deserialized into [`DomainXML`] — libvirt adds
/// many elements this crate does not model.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveDomainDevices {
    /// Host-side tap interface names, used for network counters.
    pub interface_targets: Vec<String>,
    /// Guest NIC MAC addresses.
    pub interface_macs: Vec<String>,
    /// Guest disk device names (`vda`), used for block counters.
    pub disk_targets: Vec<String>,
    /// `(pool, volume)` pairs for disks backed by storage pool volumes.
    pub disk_volumes: Vec<(String, String)>,
    /// Absolute paths for disks backed by files.
    pub disk_files: Vec<String>,
}

/// Parse the interesting device bits out of a live domain XML document.
pub fn parse_live_devices(xml: &str) -> Result<LiveDomainDevices> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    let mut out = LiveDomainDevices::default();
    let mut buf = Vec::new();
    // Disk and interface both have <target> and <source> children, so the
    // parent element has to be tracked to know which list to fill.
    let mut in_disk = false;
    let mut in_interface = false;

    loop {
        let event = reader.read_event_into(&mut buf)?;
        match event {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) => {
                let name = e.name();
                let name = String::from_utf8_lossy(name.as_ref()).to_string();
                let empty = matches!(event, Event::Empty(_));
                match name.as_str() {
                    "disk" => in_disk = !empty,
                    "interface" => in_interface = !empty,
                    "target" => {
                        if let Some(dev) = attr(e, "dev")? {
                            if in_disk {
                                out.disk_targets.push(dev);
                            } else if in_interface {
                                out.interface_targets.push(dev);
                            }
                        }
                    }
                    "source" if in_disk => {
                        if let (Some(pool), Some(volume)) = (attr(e, "pool")?, attr(e, "volume")?) {
                            out.disk_volumes.push((pool, volume));
                        } else if let Some(file) = attr(e, "file")? {
                            out.disk_files.push(file);
                        }
                    }
                    "mac" if in_interface => {
                        if let Some(address) = attr(e, "address")? {
                            out.interface_macs.push(address);
                        }
                    }
                    _ => {}
                }
            }
            Event::End(ref e) => match String::from_utf8_lossy(e.name().as_ref()).as_ref() {
                "disk" => in_disk = false,
                "interface" => in_interface = false,
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

fn attr(e: &quick_xml::events::BytesStart, key: &str) -> Result<Option<String>> {
    for a in e.attributes() {
        let a = a?;
        if a.key.as_ref() == key.as_bytes() {
            return Ok(Some(String::from_utf8_lossy(a.value.as_ref()).to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::VmLimits;
    use crate::host::tests::mock_full_vm;

    fn qemu_cfg() -> QemuConfig {
        QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        }
    }

    #[test]
    fn domain_name_round_trips() {
        assert_eq!(domain_name(42), "VM42");
        assert_eq!(vm_id_from_domain_name("VM42"), Some(42));
        // Foreign domains must not be mistaken for LNVPS VMs.
        assert_eq!(vm_id_from_domain_name("win10"), None);
        assert_eq!(vm_id_from_domain_name("VMabc"), None);
        assert_eq!(vm_id_from_domain_name(""), None);
    }

    #[test]
    fn domain_uuid_is_stable_and_unique() {
        assert_eq!(domain_uuid(1), domain_uuid(1));
        assert_ne!(domain_uuid(1), domain_uuid(2));
    }

    #[test]
    fn volume_names() {
        assert_eq!(primary_disk_volume(7), "vm-7-disk0");
        assert_eq!(os_image_volume(3, VolumeFormat::QCow2), "os-image-3.qcow2");
        assert_eq!(os_image_volume(3, VolumeFormat::Raw), "os-image-3.raw");
    }

    #[test]
    fn volume_format_from_url() {
        assert_eq!(
            VolumeFormat::from_url("https://x/y/debian-12.qcow2"),
            VolumeFormat::QCow2
        );
        assert_eq!(
            VolumeFormat::from_url("https://x/y/ubuntu.img"),
            VolumeFormat::Raw
        );
        assert_eq!(
            VolumeFormat::from_url("https://x/y/disk.raw?sig=abc"),
            VolumeFormat::Raw
        );
        // Unknown extensions fall back to qcow2, the cloud-image norm.
        assert_eq!(
            VolumeFormat::from_url("https://x/y/image"),
            VolumeFormat::QCow2
        );
    }

    #[test]
    fn memory_is_written_in_bytes() -> Result<()> {
        // Regression: without an explicit unit libvirt reads <memory> as KiB,
        // which handed every VM 1024x its purchased RAM.
        let xml = quick_xml::se::to_string(&MemoryValue::bytes(2147483648))?;
        assert!(xml.contains("unit=\"bytes\""), "got {xml}");
        assert!(xml.contains("2147483648"), "got {xml}");
        Ok(())
    }

    #[test]
    fn iotune_is_omitted_when_uncapped() {
        assert!(DiskIoTune::from_limits(&VmLimits::default()).is_none());

        let limits = VmLimits {
            disk_iops_read: Some(1000),
            disk_mbps_write: Some(100),
            ..Default::default()
        };
        let tune = DiskIoTune::from_limits(&limits).expect("iotune");
        assert_eq!(tune.read_iops_sec, Some(1000));
        assert_eq!(tune.write_bytes_sec, Some(100_000_000));
        assert_eq!(tune.write_iops_sec, None);
    }

    #[test]
    fn bandwidth_converts_mbit_to_kbytes() {
        let bw = NetworkBandwidth::from_mbps(100);
        assert_eq!(bw.inbound.expect("inbound").average, 12_500);
        assert_eq!(bw.outbound.expect("outbound").average, 12_500);
    }

    #[test]
    fn cpu_modes() {
        assert_eq!(DomainCpu::from_model("host").mode, "host-passthrough");
        assert_eq!(DomainCpu::from_model("host-model").mode, "host-model");
        let custom = DomainCpu::from_model("kvm64");
        assert_eq!(custom.mode, "custom");
        assert_eq!(custom.model.as_deref(), Some("kvm64"));
    }

    #[test]
    fn disk_bus_mapping() {
        assert!(matches!(disk_bus(DiskInterface::PCIe), DiskBus::VirtIO));
        assert!(matches!(disk_bus(DiskInterface::SCSI), DiskBus::SCSI));
        assert!(matches!(disk_bus(DiskInterface::SATA), DiskBus::SATA));
    }

    #[test]
    fn build_domain_rejects_incomplete_vm() {
        let mut cfg = mock_full_vm();
        cfg.vm.mac_address = String::new();
        assert!(build_domain(&cfg, &qemu_cfg(), false, "/tmp/x.qcow2", None, true).is_err());
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn interface_references_the_vm_firewall() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.disk.name = "default-pool".to_string();

        let xml = build_domain(&cfg, &qemu_cfg(), false, "/tmp/x.qcow2", None, true)?.to_xml()?;
        // A filter that nothing references enforces nothing.
        assert!(
            xml.contains(r#"<filterref filter="lnvps-vm-1"/>"#),
            "interface must reference the VM nwfilter: {xml}"
        );
        Ok(())
    }

    #[test]
    fn disk_is_file_typed_so_libvirt_relabels_it() -> Result<()> {
        // Regression: `<disk type='volume'>` skips libvirt's DAC relabelling,
        // so QEMU (running as libvirt-qemu) gets EACCES on the root-owned
        // image and the domain fails to start. Only reproducible against a real
        // hypervisor — the test driver never launches QEMU.
        let mut cfg = mock_full_vm();
        cfg.disk.name = "default-pool".to_string();

        let xml = build_domain(
            &cfg,
            &qemu_cfg(),
            false,
            "/var/lib/libvirt/images/vm-1-disk0",
            None,
            true,
        )?
        .to_xml()?;
        assert!(
            xml.contains(r#"<disk type="file" device="disk">"#),
            "got {xml}"
        );
        assert!(
            xml.contains(r#"<source file="/var/lib/libvirt/images/vm-1-disk0"/>"#),
            "got {xml}"
        );
        assert!(!xml.contains("type=\"volume\""), "got {xml}");
        Ok(())
    }

    #[test]
    fn libvirt_booleans_are_yes_no() -> Result<()> {
        // Regression: libvirt rejects `secure="true"` with
        // "Invalid value for attribute 'secure' in element 'loader'".
        let mut cfg = mock_full_vm();
        cfg.disk.name = "default-pool".to_string();

        let xml = build_domain(&cfg, &qemu_cfg(), true, "/tmp/x.qcow2", None, true)?.to_xml()?;
        assert!(xml.contains("<firmware>"), "got {xml}");
        assert!(
            xml.contains(r#"<feature enabled="yes" name="secure-boot"/>"#),
            "got {xml}"
        );
        assert!(!xml.contains("enabled=\"true\""), "got {xml}");
        // A secure-boot firmware needs its keys enrolled and SMM available.
        assert!(
            xml.contains(r#"<feature enabled="yes" name="enrolled-keys"/>"#),
            "got {xml}"
        );
        assert!(xml.contains(r#"<smm state="on"/>"#), "got {xml}");
        Ok(())
    }

    #[test]
    fn secure_boot_is_explicitly_disabled_by_default() -> Result<()> {
        // Regression: with no <firmware> constraints libvirt may autoselect the
        // Microsoft secure-boot OVMF build, on which an ordinary cloud image
        // boots to *silence* — no firmware output, no bootloader, no kernel.
        // Verified against Debian 13 genericcloud on libvirt 11.3.
        let mut cfg = mock_full_vm();
        cfg.disk.name = "default-pool".to_string();

        let xml = build_domain(&cfg, &qemu_cfg(), false, "/tmp/x.qcow2", None, true)?.to_xml()?;
        assert!(
            xml.contains(r#"<firmware><feature enabled="no" name="secure-boot"/></firmware>"#),
            "secure boot must be explicitly disabled inside a <firmware> element, \
             not merely omitted (libvirt silently drops unknown elements): {xml}"
        );
        assert!(!xml.contains("enrolled-keys"), "got {xml}");
        assert!(!xml.contains("smm"), "got {xml}");
        // libvirt derives the loader/nvram pair from the features.
        assert!(!xml.contains("<loader"), "got {xml}");
        Ok(())
    }

    #[test]
    fn build_domain_produces_expected_xml() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.disk.name = "default-pool".to_string();

        let domain = build_domain(&cfg, &qemu_cfg(), false, "/pool/vm-1-disk0", None, true)?;
        let res = cfg.resources()?;
        assert_eq!(domain.vcpu, res.cpu);
        assert_eq!(domain.memory.value, res.memory);
        assert_eq!(domain.memory.unit, "bytes");

        let xml = domain.to_xml()?;
        // A real resolved path, never a Proxmox-style "storage:volume" string.
        assert!(
            xml.contains(r#"<source file="/pool/vm-1-disk0"/>"#),
            "got {xml}"
        );
        assert!(!xml.contains("default-pool:vm-1-disk0"), "got {xml}");
        assert!(xml.contains(r#"<memory unit="bytes">"#), "got {xml}");
        assert!(xml.contains("<serial"), "serial console missing: {xml}");
        assert!(xml.contains(r#"<model type="virtio"/>"#), "got {xml}");
        // The runtime domain id is assigned by libvirt; sending one is invalid.
        assert!(!xml.contains("<domain type=\"kvm\" id="), "got {xml}");
        Ok(())
    }

    #[test]
    fn parse_live_devices_extracts_targets() -> Result<()> {
        let xml = r#"
        <domain type='kvm'>
          <name>VM1</name>
          <devices>
            <disk type='volume' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source pool='default-pool' volume='vm-1-disk0'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <disk type='file' device='cdrom'>
              <source file='/var/lib/libvirt/images/seed.iso'/>
              <target dev='sda' bus='sata'/>
            </disk>
            <interface type='bridge'>
              <mac address='52:54:00:01:02:03'/>
              <source bridge='vmbr0'/>
              <target dev='vnet3'/>
            </interface>
          </devices>
        </domain>"#;

        let devices = parse_live_devices(xml)?;
        assert_eq!(devices.disk_targets, vec!["vda", "sda"]);
        assert_eq!(devices.interface_targets, vec!["vnet3"]);
        assert_eq!(devices.interface_macs, vec!["52:54:00:01:02:03"]);
        assert_eq!(
            devices.disk_volumes,
            vec![("default-pool".to_string(), "vm-1-disk0".to_string())]
        );
        assert_eq!(
            devices.disk_files,
            vec!["/var/lib/libvirt/images/seed.iso".to_string()]
        );
        Ok(())
    }

    #[test]
    fn parse_live_devices_handles_no_devices() -> Result<()> {
        let devices = parse_live_devices("<domain type='kvm'><name>x</name></domain>")?;
        assert_eq!(devices, LiveDomainDevices::default());
        Ok(())
    }
}
