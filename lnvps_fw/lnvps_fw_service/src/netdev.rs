//! What the daemon can observe about the NICs it hooks: driver, MTU, link
//! speed, the XDP mode the kernel actually installed, the offload feature set,
//! and the driver's own XDP counters.
//!
//! Attaching XDP is not free of side effects: a driver may clear guest/HW
//! offloads (virtio_net drops guest TSO/GRO-HW/CSUM), refuse a native attach
//! on a jumbo MTU or a non-multi-buffer program (falling back to the generic
//! SKB path, which linearises every skb and drops the large GRO/TSO ones it
//! cannot copy), or silently count drops the program never issued. None of
//! that is visible from inside the eBPF program, so it is snapshotted here
//! around every attach and surfaced in the log and `GET /status`.
//!
//! Everything is best-effort and read-only: sysfs for the static facts,
//! `ip -j -d link` for the XDP mode (aya has no query API and its netlink is
//! crate-private), and the `SIOCETHTOOL` ioctl for features and stats (`libc`
//! ships no ethtool bindings, so the handful of structs are defined locally).

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

/// Everything observed about one attached interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NicInfo {
    pub name: String,
    /// Kernel driver bound to the device (e.g. `virtio_net`, `mlx5_core`).
    pub driver: Option<String>,
    pub mtu: Option<u32>,
    /// Link speed in Mbit/s, if the driver reports one (virtual NICs don't).
    pub speed_mbps: Option<u64>,
    /// XDP mode the kernel actually installed: `native`, `generic`, `offload`,
    /// `multi`, or `none`. `None` when it could not be determined.
    pub xdp_mode: Option<String>,
    /// Hooks this daemon attached: `xdp`, `tc-ingress`, `tc-egress`.
    pub hooks: Vec<String>,
    /// Offload features of interest and whether each is active.
    pub offloads: BTreeMap<String, bool>,
    /// Features whose state flipped as a side effect of our attach (`name
    /// on->off`), diffed over the full feature set, not just `offloads`.
    pub offloads_changed_by_attach: Vec<String>,
    /// The same flips as `(feature, was, now)`, kept so they can be undone on
    /// shutdown: the kernel never re-enables what a generic-XDP install turned
    /// off (`rx-gro-hw` stays off after the program is gone).
    #[serde(skip)]
    pub flipped: Vec<(String, bool, bool)>,
    /// Driver XDP counters (ethtool -S names containing `xdp`, summed across
    /// queues, e.g. virtio_net `rx_xdp_drops`).
    pub xdp_stats: BTreeMap<String, u64>,
}

impl NicInfo {
    /// Snapshot everything observable about `name` right now.
    pub fn snapshot(name: &str) -> Self {
        Self {
            name: name.to_string(),
            driver: driver(name),
            mtu: mtu(name),
            speed_mbps: speed_mbps(name),
            xdp_mode: xdp_mode(name),
            hooks: Vec::new(),
            offloads: watched_offloads(&features(name).unwrap_or_default()),
            offloads_changed_by_attach: Vec::new(),
            flipped: Vec::new(),
            xdp_stats: xdp_stats(name),
        }
    }

    /// Record the offload flips our attach caused (from a pre-attach feature
    /// snapshot) so they show in `/status` and can be undone on exit.
    pub fn record_flips(&mut self, before: &BTreeMap<String, bool>) {
        self.flipped = changed_offloads(before, &features(&self.name).unwrap_or_default());
        self.offloads_changed_by_attach = describe_flips(&self.flipped);
    }

    /// Put back every feature our attach flipped. Call after the programs are
    /// detached (a still-installed generic XDP program keeps GRO-HW disabled).
    /// Returns the features re-applied.
    pub fn restore_offloads(&self) -> io::Result<Vec<String>> {
        if self.flipped.is_empty() {
            return Ok(Vec::new());
        }
        let wanted: Vec<(String, bool)> = self
            .flipped
            .iter()
            .map(|(k, was, _)| (k.clone(), *was))
            .collect();
        set_features(&self.name, &wanted)?;
        Ok(wanted.iter().map(|(k, _)| k.clone()).collect())
    }

    /// Re-read the parts that move at runtime (a program that fell off or was
    /// replaced, and the driver's XDP counters).
    pub fn refresh(&mut self) {
        self.xdp_mode = xdp_mode(&self.name);
        self.xdp_stats = xdp_stats(&self.name);
    }

    /// True when the kernel is running our program on the generic (SKB) path.
    pub fn is_generic_xdp(&self) -> bool {
        self.xdp_mode.as_deref() == Some("generic")
    }
}

/// Read a sysfs attribute of a net device, trimmed.
fn sysfs(name: &str, attr: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/{attr}"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Driver bound to the device, from the `device/driver` symlink (absent for
/// software devices such as bridges, veths, or tunnels).
pub fn driver(name: &str) -> Option<String> {
    std::fs::read_link(format!("/sys/class/net/{name}/device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
}

pub fn mtu(name: &str) -> Option<u32> {
    sysfs(name, "mtu")?.parse().ok()
}

/// Link speed (Mbit/s) from sysfs. `None` when the driver doesn't report it
/// (virtual NICs report -1 / error).
pub fn speed_mbps(name: &str) -> Option<u64> {
    match sysfs(name, "speed")?.parse::<i64>() {
        Ok(mbps) if mbps > 0 => Some(mbps as u64),
        _ => None,
    }
}

/// XDP mode installed on `name`, via `ip -j -d link show`. `IFLA_XDP_ATTACHED`
/// values: 1 native (driver), 2 generic (SKB), 3 offload, 4 multi. A link with
/// no `xdp` object has no program.
pub fn xdp_mode(name: &str) -> Option<String> {
    // The systemd unit's PATH may not include the sbin dirs.
    let out = ["ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"]
        .iter()
        .find_map(|bin| {
            std::process::Command::new(bin)
                .args(["-j", "-d", "link", "show", "dev", name])
                .output()
                .ok()
                .filter(|o| o.status.success())
        })?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let link = v.as_array()?.first()?;
    Some(
        match link
            .get("xdp")
            .and_then(|x| x.get("mode"))
            .and_then(|m| m.as_u64())
        {
            None => "none",
            Some(1) => "native",
            Some(2) => "generic",
            Some(3) => "offload",
            Some(4) => "multi",
            Some(_) => "unknown",
        }
        .to_string(),
    )
}

// --- SIOCETHTOOL -------------------------------------------------------------

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_GSTATS: u32 = 0x1d;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GFEATURES: u32 = 0x3a;
const ETHTOOL_SFEATURES: u32 = 0x3b;
const ETH_SS_STATS: u32 = 1;
const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;

/// `struct ifreq`: 16-byte name + a 24-byte union, of which we only use the
/// leading data pointer. Padded to the full 40 bytes because the kernel copies
/// the whole struct.
#[repr(C)]
struct Ifreq {
    name: [u8; libc::IFNAMSIZ],
    data: *mut libc::c_void,
    _pad: [u8; 24 - std::mem::size_of::<*mut libc::c_void>()],
}

/// Issue one `SIOCETHTOOL` request for `name`; `buf` is the ethtool command
/// struct (already laid out with its `cmd` word first).
fn ethtool_ioctl(name: &str, buf: &mut [u64]) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad ifname"));
    }
    let mut ifr = Ifreq {
        name: [0; libc::IFNAMSIZ],
        data: buf.as_mut_ptr().cast(),
        _pad: [0; 24 - std::mem::size_of::<*mut libc::c_void>()],
    };
    ifr.name[..bytes.len()].copy_from_slice(bytes);
    // SAFETY: plain socket/ioctl/close on a fd we own; `ifr` and `buf` outlive
    // the call and `buf` is sized by the caller for the request it encodes.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = libc::ioctl(fd, SIOCETHTOOL, &mut ifr as *mut Ifreq);
        let err = io::Error::last_os_error();
        libc::close(fd);
        if rc < 0 {
            return Err(err);
        }
    }
    Ok(())
}

/// A u64-backed (hence 8-byte aligned) buffer of at least `bytes` bytes.
fn words(bytes: usize) -> Vec<u64> {
    vec![0u64; bytes.div_ceil(8)]
}

fn put_u32(buf: &mut [u64], idx: usize, v: u32) {
    // SAFETY: `idx` is a u32 index inside a buffer whose byte length the
    // callers size for it.
    unsafe { *(buf.as_mut_ptr() as *mut u32).add(idx) = v }
}

fn get_u32(buf: &[u64], idx: usize) -> u32 {
    // SAFETY: as above, read side.
    unsafe { *(buf.as_ptr() as *const u32).add(idx) }
}

/// Number of strings in a string set (`ETHTOOL_GSSET_INFO`).
fn sset_count(name: &str, set: u32) -> io::Result<usize> {
    // struct ethtool_sset_info { u32 cmd; u32 reserved; u64 sset_mask; u32 data[]; }
    let mut buf = words(8 + 8 + 8);
    put_u32(&mut buf, 0, ETHTOOL_GSSET_INFO);
    buf[1] = 1u64 << set;
    ethtool_ioctl(name, &mut buf)?;
    // The kernel clears the mask bit of a set the driver doesn't provide.
    if buf[1] == 0 {
        return Ok(0);
    }
    Ok(get_u32(&buf, 4) as usize)
}

/// All names of a string set (`ETHTOOL_GSTRINGS`), unused slots as `""`.
fn strings(name: &str, set: u32) -> io::Result<Vec<String>> {
    let n = sset_count(name, set)?;
    // struct ethtool_gstrings { u32 cmd; u32 string_set; u32 len; u8 data[]; }
    const HDR: usize = 12;
    let mut buf = words(HDR + n * ETH_GSTRING_LEN);
    put_u32(&mut buf, 0, ETHTOOL_GSTRINGS);
    put_u32(&mut buf, 1, set);
    put_u32(&mut buf, 2, n as u32);
    ethtool_ioctl(name, &mut buf)?;
    let n = (get_u32(&buf, 2) as usize).min(n);
    // SAFETY: reinterpreting our own u64 buffer as bytes within its length.
    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
    Ok((0..n)
        .map(|i| {
            let s = &data[HDR + i * ETH_GSTRING_LEN..HDR + (i + 1) * ETH_GSTRING_LEN];
            let end = s.iter().position(|&b| b == 0).unwrap_or(ETH_GSTRING_LEN);
            String::from_utf8_lossy(&s[..end]).into_owned()
        })
        .collect())
}

/// Every named netdev feature and whether it is currently active
/// (`ETHTOOL_GFEATURES`, the same bits `ethtool -k` prints under their kernel
/// names, e.g. `rx-gro-hw`, `tx-tcp-segmentation`).
pub fn features(name: &str) -> io::Result<BTreeMap<String, bool>> {
    let names = strings(name, ETH_SS_FEATURES)?;
    let blocks = names.len().div_ceil(32);
    // struct ethtool_gfeatures { u32 cmd; u32 size;
    //   struct ethtool_get_features_block { u32 available, requested, active, never_changed; } features[]; }
    let mut buf = words(8 + blocks * 16);
    put_u32(&mut buf, 0, ETHTOOL_GFEATURES);
    put_u32(&mut buf, 1, blocks as u32);
    ethtool_ioctl(name, &mut buf)?;
    Ok(names
        .iter()
        .enumerate()
        .filter(|(_, n)| !n.is_empty())
        .map(|(i, n)| {
            let active = get_u32(&buf, 2 + (i / 32) * 4 + 2);
            (n.clone(), (active >> (i % 32)) & 1 == 1)
        })
        .collect())
}

/// Set named features on/off (`ETHTOOL_SFEATURES`, i.e. `ethtool -K`).
/// Unknown names are ignored; a feature the kernel refuses to change (fixed,
/// or forced off by an installed program) is silently left as is, exactly
/// like `ethtool -K`.
pub fn set_features(name: &str, wanted: &[(String, bool)]) -> io::Result<()> {
    let names = strings(name, ETH_SS_FEATURES)?;
    let blocks = names.len().div_ceil(32);
    // struct ethtool_sfeatures { u32 cmd; u32 size;
    //   struct ethtool_set_features_block { u32 valid, requested; } features[]; }
    let mut buf = words(8 + blocks * 8);
    put_u32(&mut buf, 0, ETHTOOL_SFEATURES);
    put_u32(&mut buf, 1, blocks as u32);
    let mut any = false;
    for (k, on) in wanted {
        let Some(i) = names.iter().position(|n| n == k) else {
            continue;
        };
        let (blk, bit) = (i / 32, i % 32);
        let valid = 2 + blk * 2;
        let v = get_u32(&buf, valid) | (1 << bit);
        put_u32(&mut buf, valid, v);
        if *on {
            let r = get_u32(&buf, valid + 1) | (1 << bit);
            put_u32(&mut buf, valid + 1, r);
        }
        any = true;
    }
    if any {
        ethtool_ioctl(name, &mut buf)?;
    }
    Ok(())
}

/// Raw driver statistics (`ETHTOOL_GSTATS`), as `ethtool -S` lists them.
pub fn stats(name: &str) -> io::Result<Vec<(String, u64)>> {
    let names = strings(name, ETH_SS_STATS)?;
    // struct ethtool_stats { u32 cmd; u32 n_stats; u64 data[]; }
    let mut buf = words(8 + names.len() * 8);
    put_u32(&mut buf, 0, ETHTOOL_GSTATS);
    put_u32(&mut buf, 1, names.len() as u32);
    ethtool_ioctl(name, &mut buf)?;
    let n = (get_u32(&buf, 1) as usize).min(names.len());
    Ok(names
        .into_iter()
        .take(n)
        .zip(buf[1..].iter().copied())
        .collect())
}

/// The offload features worth showing in `/status` (the ones an XDP attach
/// is known to flip, plus the segmentation/checksum basics).
const WATCHED_FEATURES: &[&str] = &[
    "rx-gro-hw",
    "rx-lro",
    "rx-gro",
    "rx-gro-list",
    "rx-udp-gro-forwarding",
    "tx-tcp-segmentation",
    "tx-tcp6-segmentation",
    "tx-generic-segmentation",
    "tx-scatter-gather",
    "rx-checksum",
    "tx-checksum-ip-generic",
];

/// Filter a full feature map down to [`WATCHED_FEATURES`].
pub fn watched_offloads(all: &BTreeMap<String, bool>) -> BTreeMap<String, bool> {
    all.iter()
        .filter(|(k, _)| WATCHED_FEATURES.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// Features that differ between two snapshots, as `(feature, was, now)`.
pub fn changed_offloads(
    before: &BTreeMap<String, bool>,
    after: &BTreeMap<String, bool>,
) -> Vec<(String, bool, bool)> {
    after
        .iter()
        .filter_map(|(k, now)| {
            let was = before.get(k)?;
            (was != now).then(|| (k.clone(), *was, *now))
        })
        .collect()
}

/// `changed_offloads` output as `name was->now` strings for logs and the API.
pub fn describe_flips(flips: &[(String, bool, bool)]) -> Vec<String> {
    let onoff = |b: bool| if b { "on" } else { "off" };
    flips
        .iter()
        .map(|(k, was, now)| format!("{k} {}->{}", onoff(*was), onoff(*now)))
        .collect()
}

/// Collapse a per-queue stat name to its per-direction total:
/// `rx_queue_3_xdp_drops` -> `rx_xdp_drops`. Names without the `_queue_N_`
/// infix are returned unchanged.
pub fn collapse_queue(name: &str) -> String {
    let parts: Vec<&str> = name.split('_').collect();
    match parts.as_slice() {
        [dir, "queue", n, rest @ ..] if n.parse::<u32>().is_ok() && !rest.is_empty() => {
            format!("{dir}_{}", rest.join("_"))
        }
        _ => name.to_string(),
    }
}

/// Driver XDP counters summed across queues (empty when the driver exposes
/// none, e.g. on the generic path or software devices).
pub fn xdp_stats(name: &str) -> BTreeMap<String, u64> {
    stats(name)
        .unwrap_or_default()
        .into_iter()
        .filter(|(n, _)| n.contains("xdp"))
        .fold(BTreeMap::new(), |mut m, (n, v)| {
            *m.entry(collapse_queue(&n)).or_default() += v;
            m
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_queue_strips_queue_index() {
        assert_eq!(collapse_queue("rx_queue_3_xdp_drops"), "rx_xdp_drops");
        assert_eq!(
            collapse_queue("tx_queue_12_xdp_tx_drops"),
            "tx_xdp_tx_drops"
        );
        assert_eq!(collapse_queue("rx_xdp_drops"), "rx_xdp_drops");
        assert_eq!(collapse_queue("rx_queue_x_packets"), "rx_queue_x_packets");
        assert_eq!(collapse_queue("rx_queue_3"), "rx_queue_3");
    }

    #[test]
    fn changed_offloads_reports_only_flips() {
        let before: BTreeMap<String, bool> = [
            ("rx-gro-hw", true),
            ("rx-gro", true),
            ("tx-tcp-segmentation", true),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let mut after = before.clone();
        after.insert("rx-gro-hw".into(), false);
        after.insert("new-feature".into(), true);
        let flips = changed_offloads(&before, &after);
        assert_eq!(flips, vec![("rx-gro-hw".to_string(), true, false)]);
        assert_eq!(describe_flips(&flips), vec!["rx-gro-hw on->off"]);
        assert!(changed_offloads(&before, &before).is_empty());
    }

    #[test]
    fn watched_offloads_filters_to_the_watch_list() {
        let all: BTreeMap<String, bool> = [
            ("rx-gro-hw", true),
            ("highdma", true),
            ("rx-checksum", false),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let w = watched_offloads(&all);
        assert_eq!(w.len(), 2);
        assert_eq!(w.get("rx-gro-hw"), Some(&true));
        assert_eq!(w.get("rx-checksum"), Some(&false));
    }

    /// Loopback exists everywhere; it has no driver symlink and reports no
    /// XDP program, but the ethtool feature ioctl must succeed on it.
    #[test]
    fn loopback_snapshot_is_sane() {
        let f = features("lo").expect("ETHTOOL_GFEATURES on lo");
        assert!(f.contains_key("rx-gro"));
        assert_eq!(driver("lo"), None);
        assert!(mtu("lo").is_some());
        assert!(stats("lo").map(|s| s.is_empty()).unwrap_or(true));
        let info = NicInfo::snapshot("lo");
        assert_eq!(info.name, "lo");
        assert!(!info.is_generic_xdp());
    }

    /// `ETHTOOL_SFEATURES` needs CAP_NET_ADMIN; as an unprivileged user it must
    /// fail cleanly (EPERM), never panic or corrupt the request buffer. Run as
    /// root it round-trips `rx-gro` on lo without changing anything.
    #[test]
    fn set_features_is_well_formed() {
        let cur = features("lo").unwrap();
        let want = vec![("rx-gro".to_string(), cur["rx-gro"])];
        match set_features("lo", &want) {
            Ok(()) => assert_eq!(features("lo").unwrap()["rx-gro"], cur["rx-gro"]),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPERM)),
        }
        // Unknown names are skipped without touching the device.
        set_features("lo", &[("no-such-feature".to_string(), true)]).unwrap();
    }
}
