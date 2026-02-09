use crate::KB;
use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use crate::settings::QemuConfig;
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use lnvps_api_common::VmRunningState;
use lnvps_api_common::VmRunningStates;
use lnvps_api_common::retry::{OpError, OpResult};
use lnvps_db::{LNVpsDb, Vm, VmOsImage};
use log::info;
use rand::random;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use virt::connect::Connect;
use virt::domain::Domain;
use virt::sys::{
    VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, VIR_DOMAIN_START_VALIDATE, virDomainCreate,
};

#[derive(Debug)]
pub struct LibVirtHost {
    connection: Connect,
    qemu: QemuConfig,
}

impl LibVirtHost {
    pub fn new(url: &str, qemu: QemuConfig) -> Result<Self> {
        Ok(Self {
            connection: Connect::open(Some(url))?,
            qemu,
        })
    }

    pub fn import_disk_image(&self, vm: &Vm, image: &VmOsImage) -> Result<()> {
        // https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolUpload
        // https://libvirt.org/html/libvirt-libvirt-storage.html#virStorageVolResize
        Ok(())
    }

    pub fn create_domain_xml(&self, cfg: &FullVmInfo) -> Result<DomainXML> {
        let storage = self
            .connection
            .list_all_storage_pools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)?;

        // check the storage disk exists, we don't need anything else from it for now
        let _storage_disk = if let Some(d) = storage
            .iter()
            .find(|s| s.get_name().map(|n| n == cfg.disk.name).unwrap_or(false))
        {
            d
        } else {
            bail!(
                "Disk \"{}\" not found on host! Available pools: {}",
                cfg.disk.name,
                storage
                    .iter()
                    .filter_map(|s| s.get_name().ok())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        };

        let resources = cfg.resources()?;
        let mut devices = vec![];
        // primary disk
        devices.push(DomainDevice::Disk(Disk {
            kind: DiskType::File,
            device: DiskDevice::Disk,
            source: DiskSource {
                file: Some(format!("{}:vm-{}-disk0", cfg.disk.name, cfg.vm.id)),
                ..Default::default()
            },
            target: DiskTarget {
                dev: "vda".to_string(),
                bus: Some(DiskBus::VirtIO),
            },
        }));
        devices.push(DomainDevice::Interface(NetworkInterface {
            kind: NetworkKind::Bridge,
            mac: Some(NetworkMac {
                address: cfg.vm.mac_address.clone(),
            }),
            source: Some(NetworkSource {
                bridge: Some(self.qemu.bridge.clone()),
            }),
            target: None,
            vlan: cfg.host.vlan_id.map(|v| NetworkVlan {
                tags: vec![NetworkVlanTag { id: v as u32 }],
            }),
        }));
        Ok(DomainXML {
            kind: DomainType::KVM,
            id: Some(cfg.vm.id),
            name: Some(format!("VM{}", cfg.vm.id)),
            uuid: None,
            title: None,
            description: None,
            os: DomainOs {
                kind: DomainOsType {
                    kind: DomainOsTypeKind::Hvm,
                    arch: Some(DomainOsArch::from_str(&self.qemu.arch)?),
                    machine: Some(DomainOsMachine::from_str(&self.qemu.machine)?),
                },
                firmware: Some(DomainOsFirmware::EFI),
                loader: Some(DomainOsLoader {
                    read_only: None,
                    kind: None,
                    secure: Some(true),
                    stateless: None,
                    format: None,
                }),
                boot: DomainOsBoot {
                    dev: DomainOsBootDev::HardDrive,
                },
            },
            vcpu: resources.cpu,
            memory: resources.memory,
            devices: DomainDevices { contents: devices },
        })
    }
}

#[async_trait::async_trait]
impl VmHostClient for LibVirtHost {
    async fn get_info(&self) -> Result<VmHostInfo> {
        let info = self.connection.get_node_info()?;
        let storage = self
            .connection
            .list_all_storage_pools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)?;
        Ok(VmHostInfo {
            cpu: info.cpus as u16,
            memory: info.memory * KB,
            disks: storage
                .iter()
                .filter_map(|p| {
                    let info = p.get_info().ok()?;
                    Some(VmHostDiskInfo {
                        name: p.get_name().context("storage pool name is missing").ok()?,
                        size: info.capacity,
                        used: info.allocation,
                    })
                })
                .collect(),
        })
    }

    async fn download_os_image(&self, image: &VmOsImage) -> Result<()> {
        // TODO: download ISO images to host (somehow, ssh?)
        Ok(())
    }

    async fn generate_mac(&self, _vm: &Vm) -> Result<String> {
        Ok(format!(
            "52:54:00:{}:{}:{}",
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()])
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> Result<()> {
        Ok(())
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let domain = self.create_domain_xml(cfg).map_err(OpError::Transient)?;
        let xml = quick_xml::se::to_string(&domain).map_err(|e| OpError::Fatal(e.into()))?;
        let domain = Domain::create_xml(&self.connection, &xml, VIR_DOMAIN_START_VALIDATE)
            .map_err(|e| OpError::Transient(e.into()))?;

        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        todo!()
    }

    async fn reinstall_vm(&self, cfg: &FullVmInfo) -> Result<()> {
        todo!()
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> Result<()> {
        todo!()
    }

    async fn get_vm_state(&self, vm: &Vm) -> Result<VmRunningState> {
        Ok(VmRunningState {
            timestamp: Utc::now().timestamp() as u64,
            state: VmRunningStates::Stopped,
            cpu_usage: 0.0,
            mem_usage: 0.0,
            uptime: 0,
            net_in: 0,
            net_out: 0,
            disk_write: 0,
            disk_read: 0,
        })
    }

    async fn get_all_vm_states(&self) -> Result<Vec<(u64, VmRunningState)>> {
        // For libvirt, this is a stub implementation
        // In a real implementation, this would list all VMs and get their states
        Ok(Vec::new())
    }

    async fn configure_vm(&self, vm: &FullVmInfo) -> Result<()> {
        todo!()
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> Result<()> {
        // LibVirt doesn't have native firewall/IPset support like Proxmox
        // This would typically be handled by the host's iptables/firewalld
        Ok(())
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> Result<Vec<TimeSeriesData>> {
        todo!()
    }

    async fn connect_terminal(&self, vm: &Vm) -> Result<TerminalStream> {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "domain")]
struct DomainXML {
    #[serde(rename = "@type")]
    pub kind: DomainType,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@id")]
    pub id: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub os: DomainOs,
    pub vcpu: u16,
    pub memory: u64,
    pub devices: DomainDevices,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "devices")]
struct DomainDevices {
    #[serde(rename = "$value")]
    pub contents: Vec<DomainDevice>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainType {
    #[default]
    KVM,
    XEN,
    HVF,
    QEMU,
    LXC,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "os")]
struct DomainOs {
    #[serde(rename = "type")]
    pub kind: DomainOsType,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@firmware")]
    pub firmware: Option<DomainOsFirmware>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<DomainOsLoader>,
    pub boot: DomainOsBoot,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainOsFirmware {
    #[default]
    EFI,
    BIOS,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct DomainOsType {
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
enum DomainOsTypeKind {
    #[default]
    Hvm,
    Xen,
    Linux,
    XenPvh,
    Exe,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainOsMachine {
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
enum DomainOsArch {
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
struct DomainOsLoader {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@readonly")]
    pub read_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@type")]
    pub kind: Option<DomainOsLoaderType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@secure")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@stateless")]
    pub stateless: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@format")]
    pub format: Option<DomainOsLoaderFormat>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainOsLoaderType {
    #[default]
    ROM,
    PFlash,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainOsLoaderFormat {
    Raw,
    #[default]
    QCow2,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct DomainOsBoot {
    #[serde(rename = "@dev")]
    pub dev: DomainOsBootDev,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DomainOsBootDev {
    #[serde(rename = "fd")]
    Floppy,
    #[serde(rename = "hd")]
    #[default]
    HardDrive,
    CdRom,
    Network,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "vcpu")]
struct DomainVCPU {
    #[serde(rename = "$text")]
    pub count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum DomainDevice {
    #[serde(rename = "disk")]
    Disk(Disk),
    #[serde(rename = "interface")]
    Interface(NetworkInterface),
    #[serde(other)]
    Other,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "interface")]
struct NetworkInterface {
    #[serde(rename = "@type")]
    pub kind: NetworkKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<NetworkMac>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<NetworkSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<NetworkTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<NetworkVlan>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "vlan")]
struct NetworkVlan {
    #[serde(rename = "tag")]
    pub tags: Vec<NetworkVlanTag>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "tag")]
struct NetworkVlanTag {
    #[serde(rename = "@id")]
    pub id: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum NetworkKind {
    Network,
    #[default]
    Bridge,
    User,
    Ethernet,
    Direct,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "mac")]
struct NetworkMac {
    #[serde(rename = "@address")]
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "source")]
struct NetworkSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@bridge")]
    pub bridge: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "target")]
struct NetworkTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@dev")]
    pub dev: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "disk")]
struct Disk {
    #[serde(rename = "@type")]
    pub kind: DiskType,
    #[serde(rename = "@device")]
    pub device: DiskDevice,
    pub source: DiskSource,
    pub target: DiskTarget,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DiskType {
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
enum DiskDevice {
    Floppy,
    #[default]
    Disk,
    CdRom,
    Lun,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "source")]
struct DiskSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@file")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@dir")]
    pub dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename = "target")]
struct DiskTarget {
    /// Device name (hint)
    #[serde(rename = "@dev")]
    pub dev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "@bus")]
    pub bus: Option<DiskBus>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "lowercase")]
enum DiskBus {
    #[default]
    IDE,
    SCSI,
    VirtIO,
    XEN,
    USB,
    SATA,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::tests::mock_full_vm;

    fn cfg() -> FullVmInfo {
        let mut cfg = mock_full_vm();
        // adjust mock data for libvirt test driver
        cfg.disk.name = "default-pool".to_string();

        cfg
    }

    #[test]
    fn test_xml_os() -> Result<()> {
        let tag = "<os firmware=\"efi\"><type>hvm</type><boot dev=\"hd\"/></os>";

        let test = DomainOs {
            kind: DomainOsType {
                kind: DomainOsTypeKind::Hvm,
                arch: None,
                machine: None,
            },
            firmware: Some(DomainOsFirmware::EFI),
            loader: None,
            boot: DomainOsBoot {
                dev: DomainOsBootDev::HardDrive,
            },
        };

        let xml = quick_xml::se::to_string(&test)?;
        assert_eq!(tag, xml);
        Ok(())
    }

    #[test]
    fn text_xml_disk() -> Result<()> {
        let tag = "<disk type=\"file\" device=\"disk\"><source file=\"/var/lib/libvirt/images/disk.qcow2\"/><target dev=\"vda\" bus=\"virtio\"/></disk>";

        let test = Disk {
            kind: DiskType::File,
            device: DiskDevice::Disk,
            source: DiskSource {
                file: Some("/var/lib/libvirt/images/disk.qcow2".to_string()),
                ..Default::default()
            },
            target: DiskTarget {
                dev: "vda".to_string(),
                bus: Some(DiskBus::VirtIO),
            },
        };
        let xml = quick_xml::se::to_string(&test)?;
        assert_eq!(tag, xml);
        Ok(())
    }

    #[test]
    fn text_config_to_domain() -> Result<()> {
        let cfg = cfg();
        let template = cfg.template.clone().unwrap();

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            firewall_config: None,
        };
        let host = LibVirtHost::new("test:///default", q_cfg)?;
        let xml = host.create_domain_xml(&cfg)?;

        let res = cfg.resources()?;
        assert_eq!(xml.vcpu, res.cpu);
        assert_eq!(xml.memory, res.memory);

        let xml = quick_xml::se::to_string(&xml)?;
        println!("{}", xml);

        let output = r#"<domain type="kvm" id="1"><name>VM1</name><os firmware="efi"><type arch="x86_64" machine="q35">hvm</type><loader secure="true"/><boot dev="hd"/></os><vcpu>2</vcpu><memory>2147483648</memory><devices><disk type="file" device="disk"><source file="default-pool:vm-1-disk0"/><target dev="vda" bus="virtio"/></disk><interface type="bridge"><mac address="ff:ff:ff:ff:ff:fe"/><source bridge="vmbr0"/><vlan><tag id="100"/></vlan></interface></devices></domain>"#;
        assert_eq!(xml, output);

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn text_vm_lifecycle() -> Result<()> {
        let cfg = cfg();
        let template = cfg.template.clone().unwrap();

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            firewall_config: None,
        };
        let host = LibVirtHost::new("test:///default", q_cfg)?;
        println!("{:?}", host.get_info().await?);
        host.create_vm(&cfg).await?;

        Ok(())
    }
}
