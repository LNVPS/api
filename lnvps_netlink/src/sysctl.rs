//! Kernel knobs, read and written through `/proc/sys`.

use std::path::Path;

use anyhow::{Context, Result};

/// Where the kernel exposes its knobs. A path rather than the `sysctl` binary:
/// one less program a node has to have installed, and a write that either
/// happens or reports why.
pub const PROC_SYS: &str = "/proc/sys";

/// Read a kernel knob from `/proc/sys`.
pub fn read_sysctl(root: &Path, key: &str) -> Result<Option<String>> {
    let path = root.join(key);
    match std::fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value)),
        // Absent means this kernel does not have the knob — IPv6 can be
        // compiled out — which is a fact about the machine, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Cannot read {}", path.display())),
    }
}

/// Write a kernel knob to `/proc/sys`.
pub fn write_sysctl(root: &Path, key: &str, value: &str) -> Result<()> {
    let path = root.join(key);
    std::fs::write(&path, value).with_context(|| format!("Cannot set {}", path.display()))
}
