//! What a node reports about the machine it is running on.
//!
//! Two sources, deliberately separated:
//!
//! - CPU and GPU capability detection comes from [`lnvps_host_util`], the same
//!   code behind the `lnvps-host-info` binary an operator runs before signing
//!   up. One implementation, so a machine cannot pass the pre-flight check and
//!   then report something different once enrolled.
//! - Everything else — memory, disks, kernel, virtualisation state — is read
//!   here from procfs and sysfs.
//!
//! Every parser takes a `&str` rather than a path so it can be tested against
//! captured fixtures. A parser that can only be exercised on the machine that
//! happens to be running the tests is a parser tested on one kernel version.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Everything a node reports about its hardware.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    /// CPU vendor, model and feature list, from `lnvps_host_util`.
    pub cpu: Cpu,
    /// Physical memory.
    pub memory: Memory,
    /// Kernel release, e.g. `6.12.94-1-lts`.
    pub kernel: Option<String>,
    /// Distribution `PRETTY_NAME` from `/etc/os-release`.
    pub os: Option<String>,
    /// Seconds since boot. Reported so a node that silently reboots between
    /// heartbeats is visible as a restart rather than as continuous uptime.
    pub uptime_secs: Option<u64>,
    /// Confidential-computing state of the host.
    pub confidential: Confidential,
    /// Block devices that could back guest storage.
    pub disks: Vec<Disk>,
}

/// CPU facts, as reported by the shared detection code.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cpu {
    /// Vendor: `amd`, `intel`, ...
    pub mfg: String,
    /// Architecture: `x86_64`, `arm64`, ...
    pub arch: String,
    /// Brand string, e.g. `AMD Ryzen Threadripper 9960X 24-Cores`.
    pub model: Option<String>,
    /// Canonical LNVPS feature names, sorted and deduplicated.
    pub features: Vec<String>,
    /// Online logical CPUs.
    pub threads: Option<u32>,
}

/// Physical memory, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    /// `MemTotal`, the memory the kernel can hand out.
    pub total_bytes: u64,
    /// `MemAvailable`, an estimate of what is allocatable without swapping.
    pub available_bytes: u64,
}

/// Whether this host can run encrypted guests.
///
/// Reported as three separate facts because they fail independently: firmware
/// can advertise SEV-SNP while the kernel module has it disabled, which looks
/// identical to "no support" unless both are reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Confidential {
    /// CPU advertises AMD SEV-SNP.
    pub sev_snp: bool,
    /// CPU advertises Intel TDX.
    pub tdx: bool,
    /// Nested virtualisation is enabled.
    pub nested_virt: bool,
}

/// One block device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disk {
    /// Kernel name, e.g. `nvme0n1`.
    pub name: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// False for spinning disks (`rotational` = 1).
    pub solid_state: bool,
}

impl Inventory {
    /// Collect everything about the machine this is running on.
    pub fn collect() -> Self {
        Self::collect_from(Path::new("/"))
    }

    /// Collect with `root` as the filesystem root, so the whole collector can
    /// be pointed at a fixture tree in tests instead of the running host.
    pub fn collect_from(root: &Path) -> Self {
        let host = lnvps_host_util::host_info();
        let read = |rel: &str| fs::read_to_string(root.join(rel)).ok();

        Inventory {
            cpu: Cpu {
                mfg: serde_json::to_value(&host.cpu_mfg)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "unknown".to_string()),
                arch: serde_json::to_value(&host.cpu_arch)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "unknown".to_string()),
                model: host.cpu_model.clone(),
                features: host.cpu_features.clone(),
                threads: read("proc/cpuinfo").as_deref().map(count_threads),
            },
            memory: read("proc/meminfo")
                .as_deref()
                .map(parse_meminfo)
                .unwrap_or_default(),
            kernel: read("proc/sys/kernel/osrelease").map(|s| s.trim().to_string()),
            os: read("etc/os-release")
                .as_deref()
                .and_then(parse_os_release_pretty_name),
            uptime_secs: read("proc/uptime").as_deref().and_then(parse_uptime_secs),
            confidential: Confidential {
                sev_snp: host.cpu_features.iter().any(|f| f == "SevSnp"),
                tdx: host.cpu_features.iter().any(|f| f == "Tdx"),
                nested_virt: host.cpu_features.iter().any(|f| f == "NestedVirt"),
            },
            disks: collect_disks(&root.join("sys/block")),
        }
    }
}

/// Total and available memory from `/proc/meminfo`.
///
/// Values there are in kibibytes despite the `kB` label; reporting them
/// unconverted would understate every machine by a factor of 1024.
pub fn parse_meminfo(contents: &str) -> Memory {
    let mut memory = Memory::default();
    for line in contents.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(kib) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => memory.total_bytes = kib * 1024,
            "MemAvailable" => memory.available_bytes = kib * 1024,
            _ => {}
        }
    }
    memory
}

/// Count online logical CPUs from `/proc/cpuinfo`.
pub fn count_threads(contents: &str) -> u32 {
    contents
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count() as u32
}

/// `PRETTY_NAME` from `/etc/os-release`, unquoted.
pub fn parse_os_release_pretty_name(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim().trim_matches('"').to_string())
    })
}

/// Whole seconds since boot from `/proc/uptime`.
pub fn parse_uptime_secs(contents: &str) -> Option<u64> {
    contents
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|s| s as u64)
}

/// Enumerate block devices under a `sys/block` directory.
///
/// Partitions never appear here — `/sys/block` lists whole devices only — but
/// loop, ram and device-mapper entries do, and reporting them would inflate a
/// node's advertised storage with things that cannot back a guest.
pub fn collect_disks(sys_block: &Path) -> Vec<Disk> {
    let Ok(entries) = fs::read_dir(sys_block) else {
        return Vec::new();
    };

    let mut disks: Vec<Disk> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_real_disk(&name) {
                return None;
            }
            // Sector counts here are always 512-byte sectors, regardless of the
            // device's own logical block size.
            let sectors: u64 = fs::read_to_string(entry.path().join("size"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            if sectors == 0 {
                return None;
            }
            let rotational = fs::read_to_string(entry.path().join("queue/rotational"))
                .map(|s| s.trim() == "1")
                .unwrap_or(false);
            Some(Disk {
                name,
                size_bytes: sectors * 512,
                solid_state: !rotational,
            })
        })
        .collect();

    // Stable order so two reports from an unchanged machine compare equal;
    // readdir order is not guaranteed.
    disks.sort_by(|a, b| a.name.cmp(&b.name));
    disks
}

/// Whether a `/sys/block` entry is a real disk rather than a virtual device.
fn is_real_disk(name: &str) -> bool {
    const VIRTUAL: [&str; 6] = ["loop", "ram", "zram", "dm-", "md", "sr"];
    !VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn meminfo_is_converted_from_kibibytes_to_bytes() {
        // Captured from a running host; the trailing entries are there to prove
        // unrelated keys are skipped rather than mis-parsed.
        let fixture = "\
MemTotal:       131611288 kB
MemFree:         5417016 kB
MemAvailable:   120731064 kB
Buffers:         2461048 kB
Cached:         98765432 kB
";
        let memory = parse_meminfo(fixture);
        assert_eq!(memory.total_bytes, 131_611_288 * 1024);
        assert_eq!(memory.available_bytes, 120_731_064 * 1024);
        // The unit suffix says kB but the values are KiB. Reporting them as-is
        // would understate a 128 GiB machine as 128 MB.
        assert!(memory.total_bytes > 100_000_000_000);
    }

    #[test]
    fn meminfo_missing_keys_do_not_invent_memory() {
        let memory = parse_meminfo("SwapTotal: 0 kB\ngarbage\n");
        assert_eq!(memory, Memory::default());
        // An unparseable value must not be read as zero-with-confidence either.
        assert_eq!(parse_meminfo("MemTotal: notanumber kB"), Memory::default());
    }

    #[test]
    fn threads_are_counted_per_processor_entry() {
        let fixture = "processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n";
        assert_eq!(count_threads(fixture), 2);
        assert_eq!(count_threads(""), 0);
    }

    #[test]
    fn os_release_pretty_name_is_unquoted() {
        let fixture = "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\n";
        assert_eq!(
            parse_os_release_pretty_name(fixture).as_deref(),
            Some("Arch Linux")
        );
        assert_eq!(parse_os_release_pretty_name("ID=arch\n"), None);
    }

    #[test]
    fn uptime_truncates_to_whole_seconds() {
        assert_eq!(parse_uptime_secs("12345.67 98765.43\n"), Some(12345));
        assert_eq!(parse_uptime_secs(""), None);
        assert_eq!(parse_uptime_secs("garbage 1\n"), None);
    }

    /// A fake `/sys/block` tree, so disk enumeration is tested against known
    /// contents rather than whatever the test machine happens to have.
    fn sys_block(devices: &[(&str, &str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, size, rotational) in devices {
            let dev = dir.path().join(name);
            fs::create_dir_all(dev.join("queue")).unwrap();
            fs::write(dev.join("size"), size).unwrap();
            fs::write(dev.join("queue/rotational"), rotational).unwrap();
        }
        dir
    }

    #[test]
    fn disks_report_size_in_bytes_and_media_type() {
        let dir = sys_block(&[
            ("nvme0n1", "3907029168\n", "0\n"),
            ("sda", "1953525168\n", "1\n"),
        ]);
        let disks = collect_disks(dir.path());

        assert_eq!(disks.len(), 2);
        // Sorted, so an unchanged machine produces an identical report.
        assert_eq!(disks[0].name, "nvme0n1");
        assert_eq!(disks[1].name, "sda");
        // /sys/block sizes are always 512-byte sectors, whatever the device's
        // own block size: 3907029168 * 512 is the 2 TB NVMe.
        assert_eq!(disks[0].size_bytes, 3_907_029_168 * 512);
        assert!(disks[0].solid_state);
        assert!(!disks[1].solid_state, "rotational=1 is a spinning disk");
    }

    /// Loop, ram, zram, device-mapper, md and optical devices are not storage
    /// an operator can sell. Counting them would inflate advertised capacity.
    #[test]
    fn virtual_devices_are_not_reported_as_storage() {
        let dir = sys_block(&[
            ("loop0", "204800\n", "0\n"),
            ("ram0", "131072\n", "0\n"),
            ("zram0", "8388608\n", "0\n"),
            ("dm-0", "204800\n", "0\n"),
            ("md0", "204800\n", "0\n"),
            ("sr0", "204800\n", "1\n"),
            ("nvme0n1", "1000\n", "0\n"),
        ]);
        let disks = collect_disks(dir.path());
        assert_eq!(
            disks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["nvme0n1"]
        );
    }

    /// An empty removable slot reports size 0; advertising it as a disk would
    /// put a zero-capacity device into placement.
    #[test]
    fn zero_sized_devices_are_skipped() {
        let dir = sys_block(&[("sdb", "0\n", "1\n")]);
        assert!(collect_disks(dir.path()).is_empty());
    }

    #[test]
    fn a_missing_sys_block_is_not_fatal() {
        assert!(collect_disks(Path::new("/nonexistent/sys/block")).is_empty());
    }

    #[test]
    fn real_disks_are_told_from_virtual_ones() {
        for name in ["nvme0n1", "sda", "vda", "hda"] {
            assert!(is_real_disk(name), "{name} is a real disk");
        }
        for name in ["loop0", "ram0", "zram0", "dm-0", "md127", "sr0"] {
            assert!(!is_real_disk(name), "{name} is virtual");
        }
    }

    /// The collector must survive a host where none of the expected files
    /// exist, reporting "unknown" rather than refusing to start: a node that
    /// cannot report its kernel version is still a node that can run guests.
    #[test]
    fn collection_degrades_rather_than_failing() {
        let empty = tempfile::tempdir().unwrap();
        let inventory = Inventory::collect_from(empty.path());
        assert_eq!(inventory.kernel, None);
        assert_eq!(inventory.os, None);
        assert_eq!(inventory.uptime_secs, None);
        assert_eq!(inventory.memory, Memory::default());
        assert!(inventory.disks.is_empty());
        // CPU detection does not read the fixture root, so it still reports.
        assert!(!inventory.cpu.arch.is_empty());
    }

    /// Reads the real host, so it asserts only what must hold on any machine
    /// capable of running this test.
    #[test]
    fn the_running_host_reports_itself() {
        let inventory = Inventory::collect();
        assert!(inventory.cpu.threads.unwrap_or(0) >= 1);
        assert!(inventory.memory.total_bytes > 0);
        assert!(inventory.kernel.is_some());
        assert!(inventory.uptime_secs.is_some());
        // Round-trips, so the wire format the API will receive is exactly what
        // was collected.
        let json = serde_json::to_string(&inventory).unwrap();
        assert_eq!(serde_json::from_str::<Inventory>(&json).unwrap(), inventory);
    }
}
