//! Storage pool and volume operations.
//!
//! All functions here are **blocking** and expected to be called from inside
//! [`super::conn::LibVirtConn::run`].

use super::error::{is_not_found, map_virt_error};
use super::xml::{VolumeFormat, VolumeXML};
use crate::retry::{OpError, OpResult};
use anyhow::anyhow;
use log::{info, warn};
use std::path::Path;
use virt::connect::Connect;
use virt::storage_pool::StoragePool;
use virt::storage_vol::StorageVol;
use virt::stream::Stream;
use virt::sys::{VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, VIR_STORAGE_VOL_DELETE_NORMAL};

/// Chunk size for streaming an image into a storage volume. Large enough to
/// keep the libvirt RPC efficient, small enough not to balloon memory.
const UPLOAD_CHUNK: usize = 256 * 1024;

/// Look up a storage pool, turning "no such pool" into a clear message that
/// names the pools that *do* exist — the most common misconfiguration is a
/// `VmHostDisk.name` that doesn't match any pool on the host.
pub fn find_pool(conn: &Connect, name: &str) -> OpResult<StoragePool> {
    match conn.lookup_storage_pool_by_name(name) {
        Ok(p) => Ok(p),
        Err(e) if is_not_found(&e) => {
            let available = conn.list_storage_pools().unwrap_or_default().join(", ");
            Err(OpError::Fatal(anyhow!(
                "storage pool \"{}\" not found on host (available: [{}])",
                name,
                available
            )))
        }
        Err(e) => Err(map_virt_error("lookup_storage_pool", e)),
    }
}

/// Find a volume in a pool, returning `None` rather than an error when it is
/// absent so callers can implement create-if-missing / delete-if-present.
pub fn find_volume(pool: &StoragePool, name: &str) -> OpResult<Option<StorageVol>> {
    match pool.lookup_storage_vol_by_name(name) {
        Ok(v) => Ok(Some(v)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(map_virt_error("lookup_storage_vol", e)),
    }
}

/// Delete a volume if it exists. Idempotent: deleting an absent volume is a
/// success, which matters because rollback paths re-run on retry.
pub fn delete_volume(pool: &StoragePool, name: &str) -> OpResult<()> {
    let Some(vol) = find_volume(pool, name)? else {
        return Ok(());
    };
    match vol.delete(VIR_STORAGE_VOL_DELETE_NORMAL) {
        Ok(()) => Ok(()),
        // Lost a race with another delete — the desired end state still holds.
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(map_virt_error("delete_storage_vol", e)),
    }
}

/// Clone `source` into a new volume named `name`, then grow it to `capacity`.
///
/// This is how a VM's primary disk is created from a cached OS image: the
/// clone is the customer's writable copy, the image stays pristine.
pub fn clone_volume(
    pool: &StoragePool,
    source: &StorageVol,
    name: &str,
    capacity: u64,
    format: VolumeFormat,
) -> OpResult<StorageVol> {
    // A stale volume from a failed previous attempt would make the clone fail,
    // and reusing it risks handing a customer another customer's data.
    delete_volume(pool, name)?;

    let source_capacity = source
        .info()
        .map_err(|e| map_virt_error("storage_vol_info", e))?
        .capacity;
    if capacity < source_capacity {
        return Err(OpError::Fatal(anyhow!(
            "requested disk size {} bytes is smaller than the OS image ({} bytes)",
            capacity,
            source_capacity
        )));
    }

    let xml = VolumeXML::new(name, capacity, format)
        .to_xml()
        .map_err(OpError::Fatal)?;

    let vol = StorageVol::create_xml_from(pool, &xml, source, 0)
        .map_err(|e| map_virt_error("create_storage_vol_from", e))?;

    // Cloning preserves the source's capacity on some drivers, so the grow is
    // done explicitly rather than trusted to the create call.
    resize_volume(&vol, capacity)?;
    Ok(vol)
}

/// Grow a volume to `capacity` bytes.
///
/// Shrinking is refused: qcow2 has no idea where the guest filesystem ends, so
/// a shrink silently truncates live data.
pub fn resize_volume(vol: &StorageVol, capacity: u64) -> OpResult<()> {
    let info = vol
        .info()
        .map_err(|e| map_virt_error("storage_vol_info", e))?;

    if info.capacity == capacity {
        return Ok(());
    }
    if info.capacity > capacity {
        return Err(OpError::Fatal(anyhow!(
            "refusing to shrink volume from {} to {} bytes",
            info.capacity,
            capacity
        )));
    }

    vol.resize(capacity, 0)
        .map_err(|e| map_virt_error("resize_storage_vol", e))
}

/// Stream a local file into a (new) storage volume on the host.
///
/// Used to publish OS images to hypervisors that have no direct internet
/// access: the API downloads the image, then pushes the bytes over the same
/// libvirt connection it already uses for control, so no extra SSH/HTTP path
/// to the host is required.
pub fn upload_volume(
    conn: &Connect,
    pool: &StoragePool,
    name: &str,
    file: &Path,
    format: VolumeFormat,
) -> OpResult<StorageVol> {
    let size = std::fs::metadata(file)
        .map_err(|e| OpError::Fatal(anyhow!("cannot stat {}: {}", file.display(), e)))?
        .len();
    let source = std::fs::File::open(file)
        .map_err(|e| OpError::Fatal(anyhow!("cannot open {}: {}", file.display(), e)))?;
    upload_stream(conn, pool, name, source, size, format)
}

/// Create a volume from an in-memory image (used for cloud-init seeds, which
/// are far too small to be worth staging on disk first).
pub fn upload_bytes(
    conn: &Connect,
    pool: &StoragePool,
    name: &str,
    data: &[u8],
    format: VolumeFormat,
) -> OpResult<StorageVol> {
    upload_stream(
        conn,
        pool,
        name,
        std::io::Cursor::new(data.to_vec()),
        data.len() as u64,
        format,
    )
}

fn upload_stream<R: std::io::Read>(
    conn: &Connect,
    pool: &StoragePool,
    name: &str,
    mut source: R,
    size: u64,
    format: VolumeFormat,
) -> OpResult<StorageVol> {
    // Any partial volume from an interrupted upload must go: its contents are
    // undefined and would otherwise be cloned into customer VMs.
    delete_volume(pool, name)?;

    let xml = VolumeXML::new(name, size, format)
        .to_xml()
        .map_err(OpError::Fatal)?;
    // Metadata preallocation is a qcow2 concept; libvirt rejects the flag for
    // raw volumes with "metadata preallocation is not supported for raw
    // volumes". The mock test driver accepts it either way.
    let create_flags = match format {
        VolumeFormat::QCow2 => VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA,
        VolumeFormat::Raw => 0,
    };
    let vol = StorageVol::create_xml(pool, &xml, create_flags)
        .map_err(|e| map_virt_error("create_storage_vol", e))?;

    let mut upload = || -> OpResult<()> {
        let stream = Stream::new(conn, 0).map_err(|e| map_virt_error("new_stream", e))?;
        vol.upload(&stream, 0, size, 0)
            .map_err(|e| map_virt_error("upload_storage_vol", e))?;

        let mut buf = vec![0u8; UPLOAD_CHUNK];
        loop {
            let read = source
                .read(&mut buf)
                .map_err(|e| OpError::Transient(anyhow!("read source for {}: {}", name, e)))?;
            if read == 0 {
                break;
            }
            let mut sent = 0usize;
            while sent < read {
                let n = stream
                    .send(&buf[sent..read])
                    .map_err(|e| map_virt_error("stream_send", e))?;
                if n <= 0 {
                    return Err(OpError::Transient(anyhow!(
                        "libvirt stream closed after {} of {} bytes",
                        sent,
                        read
                    )));
                }
                sent += n as usize;
            }
        }
        stream
            .finish()
            .map_err(|e| map_virt_error("stream_finish", e))
    };

    match upload() {
        Ok(()) => {
            info!("uploaded {} ({} bytes) to storage pool", name, size);
            Ok(vol)
        }
        Err(e) => {
            // Never leave a half-written image behind for a later clone to use.
            if let Err(cleanup) = delete_volume(pool, name) {
                warn!("failed to clean up partial volume {name}: {cleanup:?}");
            }
            Err(e)
        }
    }
}

impl VolumeXML {
    pub fn to_xml(&self) -> anyhow::Result<String> {
        Ok(quick_xml::se::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::libvirt::xml::VolumeFormat;
    use anyhow::Result;

    fn conn() -> Result<Connect> {
        Ok(Connect::open(Some("test:///default"))?)
    }

    #[test]
    fn volume_xml_states_units() -> Result<()> {
        let xml = VolumeXML::new("vm-1-disk0", 1024, VolumeFormat::QCow2).to_xml()?;
        assert!(
            xml.contains(r#"<capacity unit="bytes">1024</capacity>"#),
            "got {xml}"
        );
        assert!(xml.contains(r#"<format type="qcow2"/>"#), "got {xml}");
        assert!(xml.contains("<name>vm-1-disk0</name>"), "got {xml}");
        Ok(())
    }

    #[test]
    fn find_pool_reports_available_pools() -> Result<()> {
        let conn = conn()?;
        let err = find_pool(&conn, "does-not-exist").expect_err("should fail");
        let msg = format!("{err:?}");
        assert!(msg.contains("does-not-exist"), "got {msg}");
        // The operator needs to know what they *could* have typed.
        assert!(msg.contains("available"), "got {msg}");
        assert!(matches!(err, OpError::Fatal(_)));
        Ok(())
    }

    #[test]
    fn find_pool_succeeds_for_default() -> Result<()> {
        let conn = conn()?;
        let pool = find_pool(&conn, "default-pool")?;
        assert_eq!(pool.name()?, "default-pool");
        Ok(())
    }

    #[test]
    fn find_volume_returns_none_when_absent() -> Result<()> {
        let conn = conn()?;
        let pool = find_pool(&conn, "default-pool")?;
        assert!(find_volume(&pool, "no-such-volume")?.is_none());
        Ok(())
    }

    #[test]
    fn delete_volume_is_idempotent() -> Result<()> {
        let conn = conn()?;
        let pool = find_pool(&conn, "default-pool")?;
        // Deleting something that was never there must not error, otherwise
        // rollback and retry paths fail on their second run.
        delete_volume(&pool, "no-such-volume")?;
        delete_volume(&pool, "no-such-volume")?;
        Ok(())
    }

    #[test]
    fn resize_refuses_to_shrink() -> Result<()> {
        let conn = conn()?;
        let pool = find_pool(&conn, "default-pool")?;
        let vols = pool.list_all_volumes(0)?;
        let Some(vol) = vols.first() else {
            // The test driver always ships one volume; skip rather than fail if
            // that ever changes.
            return Ok(());
        };
        let capacity = vol.info()?.capacity;
        assert!(capacity > 0);

        let err = resize_volume(vol, capacity - 1).expect_err("shrink must be refused");
        assert!(matches!(err, OpError::Fatal(_)));
        assert!(format!("{err:?}").contains("shrink"));

        // Same size is a no-op, not an error.
        resize_volume(vol, capacity)?;
        Ok(())
    }
}
