//! Typed representations of the Proxmox "property string" config values.
//!
//! Proxmox stores compound VM config values as comma separated property
//! strings, e.g. `net0 = virtio=BC:24:11:00:11:22,bridge=vmbr0,firewall=1`.
//! Handling those as raw `String`s means every read is a substring search and
//! every comparison has to re-implement Proxmox's normalisation (it re-orders
//! keys and upper-cases MAC addresses when it stores them), which made config
//! comparison unreliable.
//!
//! Each property string we set therefore gets a real type here, parsed on the
//! way in and rendered on the way out, so the rest of the code can read fields
//! and compare values with `==`.
//!
//! Parsing is deliberately lenient: keys we do not model are ignored and
//! malformed values are dropped rather than failing the whole config read — a
//! VM with a hand-edited config must still be readable. We own every property
//! string we write, so nothing meaningful is lost by not round-tripping keys we
//! never set.

use ipnetwork::IpNetwork;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

/// Serialize any property-string type through its [`Display`] impl.
fn serialize_display<S: Serializer, T: Display>(value: &T, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&value.to_string())
}

/// Deserialize any property-string type through its [`FromStr`] impl.
fn deserialize_from_str<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let s = String::deserialize(d)?;
    T::from_str(&s).map_err(D::Error::custom)
}

/// `Option<T>` variants of the helpers above, for use with `serde(with = ...)`.
pub mod opt_prop_string {
    use super::*;

    pub fn serialize<S: Serializer, T: Display>(
        value: &Option<T>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serialize_display(v, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr,
        T::Err: Display,
    {
        match Option::<String>::deserialize(d)? {
            Some(s) => deserialize_from_str(serde::de::value::StrDeserializer::<D::Error>::new(&s))
                .map(Some),
            None => Ok(None),
        }
    }
}

/// Split a property string into its `key=value` pairs, keeping any leading
/// positional value (a volume reference) as the first element without a key.
fn props(value: &str) -> impl Iterator<Item = (Option<&str>, &str)> {
    value
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (Some(k.trim()), v.trim()),
            None => (None, p),
        })
}

/// Proxmox writes flags as `1`/`0`, and `discard` as `on`/`ignore`.
fn parse_flag(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "on" | "true")
}

/// A 6-octet MAC address, stored upper-case so that a config read back from
/// Proxmox (which upper-cases them) compares equal to one we generated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MacAddress(String);

impl MacAddress {
    /// Parse a MAC address, returning `None` when it is not 6 hex octets.
    pub fn parse(value: &str) -> Option<Self> {
        let octets: Vec<&str> = value.split(':').collect();
        if octets.len() != 6
            || !octets
                .iter()
                .all(|o| o.len() == 2 && o.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return None;
        }
        Some(Self(value.to_ascii_uppercase()))
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// NIC model, which in a Proxmox `netN` string doubles as the key holding the
/// MAC address (`virtio=BC:24:11:00:11:22`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetModel {
    #[default]
    VirtIo,
    E1000,
    Rtl8139,
    VmxNet3,
    Other(String),
}

impl NetModel {
    fn parse(key: &str) -> Option<Self> {
        Some(match key.to_ascii_lowercase().as_str() {
            "virtio" => NetModel::VirtIo,
            "e1000" => NetModel::E1000,
            "rtl8139" => NetModel::Rtl8139,
            "vmxnet3" => NetModel::VmxNet3,
            // Anything else is only a model if its value looks like a MAC
            other => {
                if MacAddress::parse(key).is_some() {
                    return None;
                }
                NetModel::Other(other.to_string())
            }
        })
    }
}

impl Display for NetModel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetModel::VirtIo => write!(f, "virtio"),
            NetModel::E1000 => write!(f, "e1000"),
            NetModel::Rtl8139 => write!(f, "rtl8139"),
            NetModel::VmxNet3 => write!(f, "vmxnet3"),
            NetModel::Other(v) => write!(f, "{}", v),
        }
    }
}

/// A `netN` device.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetDevice {
    pub model: NetModel,
    pub mac: Option<MacAddress>,
    pub bridge: Option<String>,
    pub firewall: bool,
    /// VLAN tag
    pub tag: Option<u16>,
    pub mtu: Option<u32>,
    /// Whether the virtual link is administratively down
    pub link_down: bool,
    /// Rate limit in MB/s (Proxmox' unit, not Mbit/s)
    pub rate: Option<f32>,
}

impl FromStr for NetDevice {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = NetDevice::default();
        for (key, value) in props(s) {
            let Some(key) = key else { continue };
            match key.to_ascii_lowercase().as_str() {
                "bridge" => out.bridge = Some(value.to_string()),
                "firewall" => out.firewall = parse_flag(value),
                "tag" => out.tag = value.parse().ok(),
                "mtu" => out.mtu = value.parse().ok(),
                "link_down" => out.link_down = parse_flag(value),
                "rate" => out.rate = value.parse().ok(),
                _ => {
                    // The model key carries the MAC as its value
                    if let (Some(model), Some(mac)) =
                        (NetModel::parse(key), MacAddress::parse(value))
                    {
                        out.model = model;
                        out.mac = Some(mac);
                    }
                }
            }
        }
        Ok(out)
    }
}

impl Display for NetDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(mac) = &self.mac {
            parts.push(format!("{}={}", self.model, mac));
        }
        if let Some(bridge) = &self.bridge {
            parts.push(format!("bridge={}", bridge));
        }
        if self.firewall {
            parts.push("firewall=1".to_string());
        }
        if let Some(tag) = self.tag {
            parts.push(format!("tag={}", tag));
        }
        if let Some(mtu) = self.mtu {
            parts.push(format!("mtu={}", mtu));
        }
        if self.link_down {
            parts.push("link_down=1".to_string());
        }
        if let Some(rate) = self.rate {
            parts.push(format!("rate={}", rate));
        }
        write!(f, "{}", parts.join(","))
    }
}

/// IPv4 setting of an `ipconfigN` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv4Setting {
    Dhcp,
    Static(IpNetwork),
}

/// IPv6 setting of an `ipconfigN` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6Setting {
    /// SLAAC — let the guest pick its address from router advertisements
    Auto,
    Dhcp,
    Static(IpNetwork),
}

/// An `ipconfigN` entry: at most one address per family plus its gateway.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IpConfig {
    pub ip: Option<Ipv4Setting>,
    pub gateway: Option<IpAddr>,
    pub ip6: Option<Ipv6Setting>,
    pub gateway6: Option<IpAddr>,
}

impl FromStr for IpConfig {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = IpConfig::default();
        for (key, value) in props(s) {
            let Some(key) = key else { continue };
            match key.to_ascii_lowercase().as_str() {
                "ip" => {
                    out.ip = match value.to_ascii_lowercase().as_str() {
                        "dhcp" => Some(Ipv4Setting::Dhcp),
                        _ => value.parse().ok().map(Ipv4Setting::Static),
                    }
                }
                "gw" => out.gateway = value.parse().ok(),
                "ip6" => {
                    out.ip6 = match value.to_ascii_lowercase().as_str() {
                        "auto" => Some(Ipv6Setting::Auto),
                        "dhcp" => Some(Ipv6Setting::Dhcp),
                        _ => value.parse().ok().map(Ipv6Setting::Static),
                    }
                }
                "gw6" => out.gateway6 = value.parse().ok(),
                _ => {}
            }
        }
        Ok(out)
    }
}

impl Display for IpConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        match &self.ip {
            Some(Ipv4Setting::Dhcp) => parts.push("ip=dhcp".to_string()),
            Some(Ipv4Setting::Static(net)) => parts.push(format!("ip={}", net)),
            None => {}
        }
        if let Some(gw) = &self.gateway {
            parts.push(format!("gw={}", gw));
        }
        match &self.ip6 {
            Some(Ipv6Setting::Auto) => parts.push("ip6=auto".to_string()),
            Some(Ipv6Setting::Dhcp) => parts.push("ip6=dhcp".to_string()),
            Some(Ipv6Setting::Static(net)) => parts.push(format!("ip6={}", net)),
            None => {}
        }
        if let Some(gw) = &self.gateway6 {
            parts.push(format!("gw6={}", gw));
        }
        write!(f, "{}", parts.join(","))
    }
}

/// A storage volume reference, e.g. `local-lvm:vm-100-disk-0`. Special forms
/// like `local-lvm:cloudinit` (generated cloud-init drive) and `local-lvm:0`
/// (EFI disk to create) use the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VolumeRef {
    pub storage: String,
    pub volume: String,
}

impl VolumeRef {
    pub fn new(storage: impl Into<String>, volume: impl Into<String>) -> Self {
        Self {
            storage: storage.into(),
            volume: volume.into(),
        }
    }
}

impl FromStr for VolumeRef {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.split_once(':') {
            Some((storage, volume)) => VolumeRef::new(storage, volume),
            // No storage prefix (e.g. `none`, `cdrom`) — keep it as the volume
            None => VolumeRef::new("", s),
        })
    }
}

impl Display for VolumeRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.storage.is_empty() {
            write!(f, "{}", self.volume)
        } else {
            write!(f, "{}:{}", self.storage, self.volume)
        }
    }
}

/// A disk device (`scsiN`, `efidiskN`): the volume plus the options we manage.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DiskDevice {
    pub volume: VolumeRef,
    /// Size as Proxmox reports it, e.g. `100G`. Owned by create/resize.
    pub size: Option<String>,
    pub discard: bool,
    pub ssd: bool,
    pub iothread: bool,
    /// EFI disk format, e.g. `4m`
    pub efi_type: Option<String>,
    pub mbps_rd: Option<f32>,
    pub mbps_wr: Option<f32>,
    pub iops_rd: Option<u32>,
    pub iops_wr: Option<u32>,
}

impl DiskDevice {
    /// A bare volume with no options, used when creating disks.
    pub fn volume(storage: impl Into<String>, volume: impl Into<String>) -> Self {
        Self {
            volume: VolumeRef::new(storage, volume),
            ..Default::default()
        }
    }
}

impl FromStr for DiskDevice {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = DiskDevice::default();
        for (key, value) in props(s) {
            match key.map(|k| k.to_ascii_lowercase()) {
                // The positional leading value is the volume reference
                None => out.volume = value.parse().unwrap_or_default(),
                Some(key) => match key.as_str() {
                    "size" => out.size = Some(value.to_string()),
                    "discard" => out.discard = parse_flag(value),
                    "ssd" => out.ssd = parse_flag(value),
                    "iothread" => out.iothread = parse_flag(value),
                    "efitype" => out.efi_type = Some(value.to_string()),
                    "mbps_rd" => out.mbps_rd = value.parse().ok(),
                    "mbps_wr" => out.mbps_wr = value.parse().ok(),
                    "iops_rd" => out.iops_rd = value.parse().ok(),
                    "iops_wr" => out.iops_wr = value.parse().ok(),
                    _ => {}
                },
            }
        }
        Ok(out)
    }
}

impl Display for DiskDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = vec![self.volume.to_string()];
        if let Some(size) = &self.size {
            parts.push(format!("size={}", size));
        }
        if self.discard {
            parts.push("discard=on".to_string());
        }
        if self.ssd {
            parts.push("ssd=1".to_string());
        }
        if self.iothread {
            parts.push("iothread=1".to_string());
        }
        if let Some(efi_type) = &self.efi_type {
            parts.push(format!("efitype={}", efi_type));
        }
        if let Some(v) = self.mbps_rd {
            parts.push(format!("mbps_rd={}", v));
        }
        if let Some(v) = self.mbps_wr {
            parts.push(format!("mbps_wr={}", v));
        }
        if let Some(v) = self.iops_rd {
            parts.push(format!("iops_rd={}", v));
        }
        if let Some(v) = self.iops_wr {
            parts.push(format!("iops_wr={}", v));
        }
        write!(f, "{}", parts.join(","))
    }
}

/// The `cicustom` property string, pointing at cloud-init snippet volumes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CiCustom {
    pub vendor: Option<VolumeRef>,
    pub network: Option<VolumeRef>,
    pub user: Option<VolumeRef>,
    pub meta: Option<VolumeRef>,
}

impl CiCustom {
    pub fn is_empty(&self) -> bool {
        self.vendor.is_none()
            && self.network.is_none()
            && self.user.is_none()
            && self.meta.is_none()
    }
}

impl FromStr for CiCustom {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = CiCustom::default();
        for (key, value) in props(s) {
            let Some(key) = key else { continue };
            let value = value.parse().ok();
            match key.to_ascii_lowercase().as_str() {
                "vendor" => out.vendor = value,
                "network" => out.network = value,
                "user" => out.user = value,
                "meta" => out.meta = value,
                _ => {}
            }
        }
        Ok(out)
    }
}

impl Display for CiCustom {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(v) = &self.vendor {
            parts.push(format!("vendor={}", v));
        }
        if let Some(v) = &self.network {
            parts.push(format!("network={}", v));
        }
        if let Some(v) = &self.user {
            parts.push(format!("user={}", v));
        }
        if let Some(v) = &self.meta {
            parts.push(format!("meta={}", v));
        }
        write!(f, "{}", parts.join(","))
    }
}

/// The `sshkeys` config value: url-encoded `authorized_keys` content.
///
/// Typed as the list of keys so that a value we generated compares equal to one
/// read back from Proxmox regardless of escaping differences.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SshKeys(pub Vec<String>);

impl SshKeys {
    /// Builds a key list from a single key, dropping it when it is blank.
    ///
    /// A blank key would otherwise serialise to an empty `sshkeys=` value,
    /// which Proxmox rejects with `invalid urlencoded string`. It would also
    /// never compare equal to the value read back from the host (which parses
    /// as an empty list), so the broken update would be retried forever.
    pub fn one(key: impl Into<String>) -> Self {
        let key = key.into();
        let key = key.trim();
        if key.is_empty() {
            Self(vec![])
        } else {
            Self(vec![key.to_string()])
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for SshKeys {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = urlencoding::decode(s)
            .map(|d| d.into_owned())
            .unwrap_or_else(|_| s.to_string());
        Ok(Self(
            decoded
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
        ))
    }
}

impl Display for SshKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", urlencoding::encode(&self.0.join("\n")))
    }
}

macro_rules! impl_prop_serde {
    ($($t:ty),*) => {
        $(
            impl Serialize for $t {
                fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    serialize_display(self, s)
                }
            }

            impl<'de> Deserialize<'de> for $t {
                fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    deserialize_from_str(d)
                }
            }
        )*
    };
}

impl_prop_serde!(
    NetDevice, IpConfig, DiskDevice, VolumeRef, CiCustom, SshKeys
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address() {
        // Case is normalised so a generated MAC equals one read back from PVE
        assert_eq!(
            MacAddress::parse("bc:24:11:00:11:22"),
            MacAddress::parse("BC:24:11:00:11:22")
        );
        assert_eq!(
            MacAddress::parse("bc:24:11:00:11:22").unwrap().to_string(),
            "BC:24:11:00:11:22"
        );
        assert!(MacAddress::parse("vmbr0").is_none());
        assert!(MacAddress::parse("bc:24:11:00:11").is_none());
        assert!(MacAddress::parse("zz:24:11:00:11:22").is_none());
    }

    #[test]
    fn test_net_device() {
        let parsed: NetDevice = "virtio=BC:24:11:00:11:22,bridge=vmbr0,firewall=1,tag=100,mtu=9000,rate=12.5,link_down=1"
            .parse()
            .unwrap();
        assert_eq!(parsed.model, NetModel::VirtIo);
        assert_eq!(parsed.mac, MacAddress::parse("bc:24:11:00:11:22"));
        assert_eq!(parsed.bridge.as_deref(), Some("vmbr0"));
        assert!(parsed.firewall);
        assert_eq!(parsed.tag, Some(100));
        assert_eq!(parsed.mtu, Some(9000));
        assert_eq!(parsed.rate, Some(12.5));
        assert!(parsed.link_down);

        // Round-trips, and key order/case in the source does not matter
        assert_eq!(
            parsed,
            "firewall=1,tag=100,link_down=1,mtu=9000,rate=12.5,VIRTIO=bc:24:11:00:11:22,bridge=vmbr0"
                .parse()
                .unwrap()
        );
        assert_eq!(parsed, parsed.to_string().parse().unwrap());

        // Other models are recognised, unknown keys ignored
        let other: NetDevice = "e1000=00:15:5D:01:02:03,bridge=vmbr1,queues=4"
            .parse()
            .unwrap();
        assert_eq!(other.model, NetModel::E1000);
        assert_eq!(other.bridge.as_deref(), Some("vmbr1"));
        assert!(!other.firewall);

        // No MAC at all
        let no_mac: NetDevice = "bridge=vmbr0,firewall=1".parse().unwrap();
        assert_eq!(no_mac.mac, None);
        assert_eq!(no_mac.to_string(), "bridge=vmbr0,firewall=1");
    }

    #[test]
    fn test_net_model() {
        assert_eq!(NetModel::parse("rtl8139"), Some(NetModel::Rtl8139));
        assert_eq!(NetModel::parse("vmxnet3"), Some(NetModel::VmxNet3));
        assert_eq!(
            NetModel::parse("Custom"),
            Some(NetModel::Other("custom".to_string()))
        );
        assert_eq!(NetModel::Other("custom".to_string()).to_string(), "custom");
        // A MAC-looking key is not a model
        assert_eq!(NetModel::parse("bc:24:11:00:11:22"), None);
    }

    #[test]
    fn test_ip_config() {
        let parsed: IpConfig = "ip=185.18.221.65/24,gw=185.18.221.1,ip6=fd00::2/64,gw6=fd00::1"
            .parse()
            .unwrap();
        assert_eq!(
            parsed.ip,
            Some(Ipv4Setting::Static("185.18.221.65/24".parse().unwrap()))
        );
        assert_eq!(parsed.gateway, Some("185.18.221.1".parse().unwrap()));
        assert_eq!(
            parsed.ip6,
            Some(Ipv6Setting::Static("fd00::2/64".parse().unwrap()))
        );
        assert_eq!(parsed.gateway6, Some("fd00::1".parse().unwrap()));
        // Key order does not affect equality, and Display round-trips
        assert_eq!(
            parsed,
            "gw6=fd00::1,ip6=fd00::2/64,gw=185.18.221.1,ip=185.18.221.65/24"
                .parse()
                .unwrap()
        );
        assert_eq!(parsed, parsed.to_string().parse().unwrap());

        // Dynamic settings
        let dynamic: IpConfig = "ip=dhcp,ip6=auto".parse().unwrap();
        assert_eq!(dynamic.ip, Some(Ipv4Setting::Dhcp));
        assert_eq!(dynamic.ip6, Some(Ipv6Setting::Auto));
        assert_eq!(dynamic.to_string(), "ip=dhcp,ip6=auto");
        let dhcp6: IpConfig = "ip6=dhcp".parse().unwrap();
        assert_eq!(dhcp6.ip6, Some(Ipv6Setting::Dhcp));
        assert_eq!(dhcp6.to_string(), "ip6=dhcp");

        // Garbage values are dropped rather than failing the whole config
        let bad: IpConfig = "ip=not-an-ip,unknown=1".parse().unwrap();
        assert_eq!(bad, IpConfig::default());
        assert_eq!(bad.to_string(), "");
    }

    #[test]
    fn test_volume_ref() {
        let v: VolumeRef = "local-lvm:vm-100-disk-0".parse().unwrap();
        assert_eq!(v.storage, "local-lvm");
        assert_eq!(v.volume, "vm-100-disk-0");
        assert_eq!(v.to_string(), "local-lvm:vm-100-disk-0");
        // Without a storage prefix the whole value is the volume
        let bare: VolumeRef = "none".parse().unwrap();
        assert_eq!(bare.storage, "");
        assert_eq!(bare.to_string(), "none");
    }

    #[test]
    fn test_disk_device() {
        let parsed: DiskDevice =
            "ssd:vm-100-disk-0,size=100G,discard=on,ssd=1,iothread=1,mbps_rd=100,mbps_wr=50,iops_rd=1000,iops_wr=500"
                .parse()
                .unwrap();
        assert_eq!(parsed.volume, VolumeRef::new("ssd", "vm-100-disk-0"));
        assert_eq!(parsed.size.as_deref(), Some("100G"));
        assert!(parsed.discard && parsed.ssd && parsed.iothread);
        assert_eq!(parsed.mbps_rd, Some(100.0));
        assert_eq!(parsed.mbps_wr, Some(50.0));
        assert_eq!(parsed.iops_rd, Some(1000));
        assert_eq!(parsed.iops_wr, Some(500));
        assert_eq!(parsed, parsed.to_string().parse().unwrap());

        // Flags absent or explicitly off, unknown keys ignored
        let plain: DiskDevice = "ssd:vm-100-disk-0,size=32G,ssd=0,backup=0".parse().unwrap();
        assert!(!plain.discard && !plain.ssd && !plain.iothread);
        assert_eq!(plain.to_string(), "ssd:vm-100-disk-0,size=32G");

        // EFI disks carry a format instead of throttle options
        let efi: DiskDevice = "ssd:0,efitype=4m".parse().unwrap();
        assert_eq!(efi.efi_type.as_deref(), Some("4m"));
        assert_eq!(efi.to_string(), "ssd:0,efitype=4m");

        assert_eq!(
            DiskDevice::volume("ssd", "cloudinit").to_string(),
            "ssd:cloudinit"
        );
    }

    #[test]
    fn test_ci_custom() {
        let parsed: CiCustom = "vendor=local:snippets/v.yaml,network=local:snippets/n.yaml"
            .parse()
            .unwrap();
        assert_eq!(
            parsed.vendor,
            Some(VolumeRef::new("local", "snippets/v.yaml"))
        );
        assert_eq!(
            parsed.network,
            Some(VolumeRef::new("local", "snippets/n.yaml"))
        );
        assert!(!parsed.is_empty());
        assert_eq!(parsed, parsed.to_string().parse().unwrap());

        let full: CiCustom = "user=local:snippets/u.yaml,meta=local:snippets/m.yaml"
            .parse()
            .unwrap();
        assert_eq!(full.user, Some(VolumeRef::new("local", "snippets/u.yaml")));
        assert_eq!(full.meta, Some(VolumeRef::new("local", "snippets/m.yaml")));
        assert_eq!(full, full.to_string().parse().unwrap());

        assert!(CiCustom::default().is_empty());
        assert_eq!(CiCustom::default().to_string(), "");
    }

    #[test]
    fn test_ssh_keys() {
        let key = "ssh-ed25519 AAAAC3Nz test@host";
        let keys = SshKeys::one(key);
        // Encoded on the wire, but equal to the same value read back
        let encoded = keys.to_string();
        assert!(encoded.contains("%20"));
        assert_eq!(keys, encoded.parse().unwrap());
        // Trailing newlines/blank lines do not create drift
        assert_eq!(
            keys,
            urlencoding::encode(&format!("{key}\n\n")).parse().unwrap()
        );
        // Multiple keys keep their order
        let two = SshKeys(vec![key.to_string(), "ssh-rsa BBBB other".to_string()]);
        assert_eq!(two, two.to_string().parse().unwrap());
        assert_eq!(two.0.len(), 2);
    }

    /// A blank key must not produce `sshkeys=` (Proxmox: "unable to parse value
    /// of 'sshkeys' - invalid urlencoded string"), and must compare equal to
    /// what an empty host value parses to, so no endless update loop occurs.
    #[test]
    fn test_ssh_keys_blank() {
        assert!(SshKeys::one("").is_empty());
        assert!(SshKeys::one("   \n").is_empty());
        assert_eq!(SshKeys::one(""), "".parse::<SshKeys>().unwrap());
        assert_eq!(SshKeys::one("").to_string(), "");
        assert!(!SshKeys::one("ssh-ed25519 AAAA x").is_empty());
    }

    #[test]
    fn test_prop_serde_roundtrip() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Holder {
            net: NetDevice,
            #[serde(default, with = "opt_prop_string")]
            ipconfig0: Option<IpConfig>,
            #[serde(default, with = "opt_prop_string")]
            scsi0: Option<DiskDevice>,
        }

        let value = Holder {
            net: "virtio=BC:24:11:00:11:22,bridge=vmbr0,firewall=1"
                .parse()
                .unwrap(),
            ipconfig0: Some("ip=1.2.3.4/24,gw=1.2.3.1".parse().unwrap()),
            scsi0: None,
        };

        // Serialises as the plain property strings Proxmox expects
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(
            json["net"],
            serde_json::json!("virtio=BC:24:11:00:11:22,bridge=vmbr0,firewall=1")
        );
        assert_eq!(
            json["ipconfig0"],
            serde_json::json!("ip=1.2.3.4/24,gw=1.2.3.1")
        );
        assert!(json["scsi0"].is_null());

        let back: Holder = serde_json::from_value(json).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn test_parse_flag() {
        assert!(parse_flag("1"));
        assert!(parse_flag("on"));
        assert!(parse_flag("TRUE"));
        assert!(!parse_flag("0"));
        assert!(!parse_flag("ignore"));
    }

    #[test]
    fn test_props_iterator() {
        let parts: Vec<_> = props("vol:x, size=1G ,,flag=1").collect();
        assert_eq!(
            parts,
            vec![(None, "vol:x"), (Some("size"), "1G"), (Some("flag"), "1")]
        );
    }
}
