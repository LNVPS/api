//! LibVirt / QEMU-KVM host backend.
//!
//! Layout:
//! - [`conn`]    — async-safe wrapper over libvirt's blocking C API
//! - [`error`]   — libvirt error code → retry classification
//! - [`xml`]     — domain / volume XML types and builders
//! - [`storage`] — storage pool and volume operations
//! - [`image`]   — OS image download and checksum verification
//! - [`stats`]   — domain state and usage sampling
//!
//! # Guest personalisation
//!
//! Cloud-init seed generation is **not implemented yet**, so a VM created here
//! boots with no injected SSH key, hostname or network configuration. Rather
//! than pretend otherwise, [`LibVirtHost::create_vm`] refuses to run unless the
//! operator explicitly opts in via `allow-unconfigured-guests`.

mod conn;
mod console;
mod error;
mod image;
mod iso9660;
mod nwfilter;
mod stats;
mod storage;
mod xml;

#[cfg(test)]
mod qemu_tests;

use crate::host::cloud_init;
use crate::host::config::LibVirtConfig;
use crate::host::{
    FullVmInfo, HostVmSpec, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient,
    VmHostDiskInfo, VmHostInfo,
};
use crate::retry::{OpError, OpResult};
use crate::{KB, VmRunningState};
use anyhow::{Context, Result, anyhow};
use conn::LibVirtConn;
use error::{is_not_found, map_virt_error};
use lnvps_db::{Vm, VmOsImage};
use log::{debug, info, warn};
use rand::random;
use stats::CpuSampler;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use virt::connect::Connect;
use virt::domain::Domain;
use virt::sys::{
    VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, VIR_DOMAIN_BLOCK_RESIZE_BYTES, VIR_DOMAIN_MEM_CONFIG,
    VIR_DOMAIN_MEM_LIVE, VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA, VIR_DOMAIN_UNDEFINE_NVRAM,
    VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, VIR_DOMAIN_VCPU_CONFIG, VIR_DOMAIN_VCPU_LIVE,
};
use xml::{
    PRIMARY_DISK_TARGET, VolumeFormat, build_domain, domain_name, os_image_volume,
    parse_live_devices, primary_disk_volume, seed_volume, vm_id_from_domain_name,
};

#[derive(Debug)]
pub struct LibVirtHost {
    conn: LibVirtConn,
    cfg: LibVirtConfig,
    cpu: CpuSampler,
}

impl LibVirtHost {
    pub fn new(url: &str, cfg: LibVirtConfig) -> Result<Self> {
        Ok(Self {
            conn: LibVirtConn::open(url)?,
            cfg,
            cpu: CpuSampler::default(),
        })
    }

    fn image_pool(&self) -> String {
        self.cfg
            .image_pool
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }

    fn image_cache_dir(&self) -> PathBuf {
        self.cfg
            .image_cache_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("lnvps-os-images"))
    }

    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.shutdown_timeout_secs.unwrap_or(60))
    }

    /// Resolve the host path of a VM's primary disk volume.
    ///
    /// Needed because the domain XML must reference the disk as a file (see
    /// [`xml::build_domain`]).
    async fn primary_disk_path(&self, cfg: &FullVmInfo) -> OpResult<String> {
        let pool_name = cfg.disk.name.clone();
        let volume = primary_disk_volume(cfg.vm.id);
        self.conn
            .run(move |c| {
                let pool = storage::find_pool(c, &pool_name)?;
                let vol = storage::find_volume(&pool, &volume)?.ok_or_else(|| {
                    OpError::Fatal(anyhow!(
                        "disk volume {} does not exist in pool {}",
                        volume,
                        pool_name
                    ))
                })?;
                vol.path()
                    .map_err(|e| map_virt_error("storage_vol_path", e))
            })
            .await
    }

    /// Is the domain for this VM currently running?
    async fn is_active(&self, vm_id: u64) -> OpResult<bool> {
        self.conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))
            })
            .await
    }

    /// Build the cloud-init NoCloud seed image for a VM and publish it as a
    /// storage volume, returning its host path.
    ///
    /// Re-uploaded on every apply: the seed encodes the SSH key and IP
    /// assignments, so a stale one silently locks the customer out after a key
    /// rotation or IP change.
    async fn write_seed(&self, cfg: &FullVmInfo) -> OpResult<String> {
        let iso = Self::build_seed_image(cfg)?;
        let pool_name = cfg.disk.name.clone();
        let volume = seed_volume(cfg.vm.id);
        self.conn
            .run(move |c| {
                let pool = storage::find_pool(c, &pool_name)?;
                let vol = storage::upload_bytes(c, &pool, &volume, &iso, VolumeFormat::Raw)?;
                vol.path()
                    .map_err(|e| map_virt_error("storage_vol_path", e))
            })
            .await
    }

    /// Make sure the OS image exists as a volume on the host, downloading and
    /// uploading it if not. Returns the volume name.
    async fn ensure_image_volume(&self, img: &VmOsImage) -> OpResult<String> {
        let format = VolumeFormat::from_url(&img.url);
        let volume = os_image_volume(img.id, format);
        let pool_name = self.image_pool();

        let exists = {
            let pool_name = pool_name.clone();
            let volume = volume.clone();
            self.conn
                .run(move |c| {
                    let pool = storage::find_pool(c, &pool_name)?;
                    Ok(storage::find_volume(&pool, &volume)?.is_some())
                })
                .await?
        };
        if exists {
            return Ok(volume);
        }

        info!(
            "OS image {} not present on host, downloading {}",
            img.id, img.url
        );
        let local = image::download_to_cache(img, &self.image_cache_dir()).await?;

        let pool_for_upload = pool_name.clone();
        let volume_for_upload = volume.clone();
        self.conn
            .run(move |c| {
                let pool = storage::find_pool(c, &pool_for_upload)?;
                // Another API instance may have uploaded it while we were
                // downloading; don't waste the transfer.
                if storage::find_volume(&pool, &volume_for_upload)?.is_some() {
                    return Ok(());
                }
                storage::upload_volume(c, &pool, &volume_for_upload, &local, format)?;
                Ok(())
            })
            .await?;

        Ok(volume)
    }

    /// Render a VM's cloud-init NoCloud seed image.
    fn build_seed_image(cfg: &FullVmInfo) -> OpResult<Vec<u8>> {
        let user_data = cloud_init::user_data(cfg).map_err(OpError::Fatal)?;
        let meta_data = cloud_init::meta_data(cfg).map_err(OpError::Fatal)?;
        let network = cloud_init::network_config(cfg).map_err(OpError::Fatal)?;

        iso9660::build(
            "cidata",
            &[
                iso9660::IsoFile::new("user-data", user_data),
                iso9660::IsoFile::new("meta-data", meta_data),
                iso9660::IsoFile::new("network-config", network.yaml),
            ],
        )
        .map_err(OpError::Fatal)
    }

    /// Delete a VM's primary disk from every pool that has one.
    ///
    /// Pools are swept rather than targeted because the caller may only have a
    /// [`Vm`] (no host-disk record), and because a failed create can leave the
    /// volume behind in a pool the current config no longer points at.
    async fn delete_primary_disk(&self, vm_id: u64) -> OpResult<()> {
        self.delete_volume_everywhere(primary_disk_volume(vm_id))
            .await
    }

    async fn delete_volume_everywhere(&self, volume: String) -> OpResult<()> {
        self.conn
            .run(move |c| {
                let pools = c
                    .list_all_storage_pools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)
                    .map_err(|e| map_virt_error("list_storage_pools", e))?;
                for pool in pools {
                    storage::delete_volume(&pool, &volume)?;
                }
                Ok(())
            })
            .await
    }

    /// Look up a domain by VM id inside a blocking libvirt closure.
    fn lookup_domain(c: &Connect, vm_id: u64) -> OpResult<Option<Domain>> {
        match c.lookup_domain_by_name(&domain_name(vm_id)) {
            Ok(d) => Ok(Some(d)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(map_virt_error("lookup_domain", e)),
        }
    }

    fn require_domain(c: &Connect, vm_id: u64) -> OpResult<Domain> {
        Self::lookup_domain(c, vm_id)?.ok_or_else(|| {
            OpError::Fatal(anyhow!(
                "domain {} does not exist on this host",
                domain_name(vm_id)
            ))
        })
    }
}

#[async_trait::async_trait]
impl VmHostClient for LibVirtHost {
    async fn get_info(&self) -> OpResult<VmHostInfo> {
        self.conn
            .run(|c| {
                let info = c.node_info().map_err(|e| map_virt_error("node_info", e))?;
                let storage = c
                    .list_all_storage_pools(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)
                    .map_err(|e| map_virt_error("list_storage_pools", e))?;
                Ok(VmHostInfo {
                    cpu: info.cpus as u16,
                    memory: info.memory * KB,
                    disks: storage
                        .iter()
                        .filter_map(|p| {
                            let info = p.info().ok()?;
                            Some(VmHostDiskInfo {
                                name: p.name().context("storage pool name is missing").ok()?,
                                size: info.capacity,
                                used: info.allocation,
                            })
                        })
                        .collect(),
                })
            })
            .await
    }

    /// Enumerate every domain on the host, for importing VMs that exist on the
    /// hypervisor but aren't tracked in the database.
    ///
    /// NOTE: this reports *all* domains, including any the operator runs for
    /// themselves. That is correct for an LNVPS-owned host, but a host we do
    /// not own must never expose it — see `work/marketplace.md`.
    async fn list_host_vms(&self) -> OpResult<Vec<HostVmSpec>> {
        self.conn
            .run(|c| {
                let domains = c
                    .list_all_domains(0)
                    .map_err(|e| map_virt_error("list_all_domains", e))?;

                let mut out = Vec::with_capacity(domains.len());
                for domain in domains {
                    let name = domain.name().ok();
                    let info = domain
                        .info()
                        .map_err(|e| map_virt_error("domain_info", e))?;

                    // Tolerate a single unreadable domain rather than aborting
                    // discovery for the whole host.
                    let devices = domain
                        .xml_desc(0)
                        .ok()
                        .and_then(|x| parse_live_devices(&x).ok())
                        .unwrap_or_default();

                    // Resolve the primary disk back to a pool + size.
                    let (disk_size, disk_storage) = devices
                        .disk_files
                        .first()
                        .and_then(|path| c.lookup_storage_vol_by_path(path).ok())
                        .map(|vol| {
                            let size = vol.info().map(|i| i.capacity).unwrap_or(0);
                            let pool = vol.lookup_storage_pool().ok().and_then(|p| p.name().ok());
                            (size, pool)
                        })
                        .unwrap_or((0, None));

                    out.push(HostVmSpec {
                        // libvirt only assigns a numeric id while a domain is
                        // running; -1 marks "inactive", as virsh reports it.
                        host_vm_id: domain.id().map(|id| id as i64).unwrap_or(-1),
                        mapped_vm_id: name.as_deref().and_then(vm_id_from_domain_name),
                        name,
                        cpu: info.nr_virt_cpu as u16,
                        // libvirt reports memory in KiB.
                        memory: info.max_mem * KB,
                        disk_size,
                        disk_storage,
                        mac_address: devices.interface_macs.first().cloned(),
                        running: domain.is_active().unwrap_or(false),
                    });
                }
                Ok(out)
            })
            .await
    }

    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        self.ensure_image_volume(image).await?;
        Ok(())
    }

    async fn generate_mac(&self, _vm: &Vm) -> OpResult<String> {
        // 52:54:00 is the QEMU/KVM assigned OUI.
        Ok(format!(
            "52:54:00:{}:{}:{}",
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()])
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        let vm_id = vm.id;
        self.conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                // Starting an already-running domain is an error in libvirt but
                // the desired state is already met, and this runs under retry.
                if domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    return Ok(());
                }
                domain
                    .create()
                    .map_err(|e| map_virt_error("start_domain", e))?;
                Ok(())
            })
            .await
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        let vm_id = vm.id;
        self.conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                if !domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    return Ok(());
                }
                // ACPI shutdown gives the guest a chance to flush its
                // filesystems; a hard destroy risks corrupting them.
                domain
                    .shutdown()
                    .map_err(|e| map_virt_error("shutdown_domain", e))?;
                Ok(())
            })
            .await?;

        // A guest that ignores ACPI (no OS installed, crashed, or simply
        // refusing) would otherwise leave `stop_vm` reporting success while the
        // VM keeps running and keeps billing resources. Wait, then pull power.
        let deadline = Instant::now() + self.shutdown_timeout();
        while Instant::now() < deadline {
            if !self.is_active(vm_id).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        warn!(
            "VM {} did not shut down within {:?}, forcing power off",
            vm_id,
            self.shutdown_timeout()
        );
        self.conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                if !domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    return Ok(());
                }
                domain
                    .destroy()
                    .map_err(|e| map_virt_error("destroy_domain", e))?;
                Ok(())
            })
            .await
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        let vm_id = vm.id;
        self.conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                if domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    domain
                        .reset()
                        .map_err(|e| map_virt_error("reset_domain", e))?;
                } else {
                    // "Reset" of a stopped VM is understood as "make it run".
                    domain
                        .create()
                        .map_err(|e| map_virt_error("start_domain", e))?;
                }
                Ok(())
            })
            .await
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        // Validate before touching any host state so a bad config fails without
        // leaving a disk behind.
        xml::validate(cfg).map_err(OpError::Fatal)?;

        let vm_id = cfg.vm.id;

        // This runs under retry, so it must be idempotent. Re-importing the
        // template disk for an existing VM would wipe a live customer disk, so
        // an existing domain is only ensured to be running.
        let exists = self
            .conn
            .run(move |c| Ok(LibVirtHost::lookup_domain(c, vm_id)?.is_some()))
            .await?;
        if exists {
            info!(
                "domain {} already exists, ensuring it is running",
                domain_name(vm_id)
            );
            return self.start_vm(&cfg.vm).await;
        }

        self.import_template_disk(cfg).await?;

        // The nwfilter must exist before the domain references it, or libvirt
        // refuses to define the domain at all.
        self.patch_firewall(cfg).await?;

        // Both volumes must exist before the XML is built: their resolved paths
        // go into the domain definition.
        let disk_path = self.primary_disk_path(cfg).await?;
        let seed_path = self.write_seed(cfg).await?;
        let domain_xml = build_domain(
            cfg,
            &self.cfg.qemu,
            self.cfg.secure_boot,
            &disk_path,
            Some(&seed_path),
            self.cfg.vlan_aware_bridge,
        )
        .map_err(OpError::Fatal)?
        .to_xml()
        .map_err(OpError::Fatal)?;

        self.conn
            .run(move |c| {
                let domain = c
                    .define_domain_xml(&domain_xml)
                    .map_err(|e| map_virt_error("define_domain", e))?;
                if !domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    domain
                        .create()
                        .map_err(|e| map_virt_error("start_domain", e))?;
                }
                info!("created domain {}", domain_name(vm_id));
                Ok(())
            })
            .await
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        let vm_id = vm.id;

        // Collect the volumes the domain actually references before removing
        // the definition, otherwise disks attached by hand are orphaned.
        let extra_volumes = self
            .conn
            .run(move |c| {
                let Some(domain) = LibVirtHost::lookup_domain(c, vm_id)? else {
                    return Ok(Vec::new());
                };

                let volumes = domain
                    .xml_desc(0)
                    .ok()
                    .and_then(|x| parse_live_devices(&x).ok())
                    .map(|d| d.disk_volumes)
                    .unwrap_or_default();

                if domain
                    .is_active()
                    .map_err(|e| map_virt_error("domain_is_active", e))?
                {
                    domain
                        .destroy()
                        .map_err(|e| map_virt_error("destroy_domain", e))?;
                }

                // Without these flags libvirt refuses to undefine a domain that
                // has UEFI NVRAM, snapshots or checkpoints attached.
                match domain.undefine_flags(
                    VIR_DOMAIN_UNDEFINE_NVRAM
                        | VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA
                        | VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA,
                ) {
                    Ok(()) => {}
                    Err(e) if is_not_found(&e) => {}
                    Err(e) => return Err(map_virt_error("undefine_domain", e)),
                }
                Ok(volumes)
            })
            .await?;

        if !extra_volumes.is_empty() {
            self.conn
                .run(move |c| {
                    for (pool_name, volume) in extra_volumes {
                        let pool = match storage::find_pool(c, &pool_name) {
                            Ok(p) => p,
                            // Pool gone: nothing left to delete.
                            Err(OpError::Fatal(_)) => continue,
                            Err(e) => return Err(e),
                        };
                        storage::delete_volume(&pool, &volume)?;
                    }
                    Ok(())
                })
                .await?;
        }

        // Sweep for volumes left behind by a create that failed before the
        // domain was defined.
        self.delete_primary_disk(vm_id).await?;
        self.delete_volume_everywhere(seed_volume(vm_id)).await?;
        self.cpu.forget(vm_id);
        info!("deleted domain {}", domain_name(vm_id));
        Ok(())
    }

    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
        self.delete_primary_disk(vm.id).await
    }

    async fn import_template_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let image_volume = self.ensure_image_volume(&cfg.image).await?;
        let resources = cfg.resources().map_err(OpError::Fatal)?;

        let image_pool = self.image_pool();
        let disk_pool = cfg.disk.name.clone();
        let target = primary_disk_volume(cfg.vm.id);
        let disk_size = resources.disk_size;

        self.conn
            .run(move |c| {
                let src_pool = storage::find_pool(c, &image_pool)?;
                let src = storage::find_volume(&src_pool, &image_volume)?.ok_or_else(|| {
                    OpError::Transient(anyhow!(
                        "OS image volume {} vanished from pool {}",
                        image_volume,
                        image_pool
                    ))
                })?;

                let dst_pool = storage::find_pool(c, &disk_pool)?;
                storage::clone_volume(&dst_pool, &src, &target, disk_size, VolumeFormat::QCow2)?;
                Ok(())
            })
            .await
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let resources = cfg.resources().map_err(OpError::Fatal)?;
        let disk_pool = cfg.disk.name.clone();
        let target = primary_disk_volume(cfg.vm.id);
        let disk_size = resources.disk_size;

        let vm_id = cfg.vm.id;
        self.conn
            .run(move |c| {
                let running = LibVirtHost::lookup_domain(c, vm_id)?
                    .filter(|d| d.is_active().unwrap_or(false));

                match running {
                    // A running domain holds a write lock on its image, so the
                    // storage API (which shells out to `qemu-img resize`) fails
                    // with "Failed to get write lock". QEMU has to grow its own
                    // disk, which also makes the new size visible to the guest
                    // immediately instead of after a power cycle.
                    Some(domain) => domain
                        .block_resize(
                            PRIMARY_DISK_TARGET,
                            disk_size,
                            VIR_DOMAIN_BLOCK_RESIZE_BYTES,
                        )
                        .map_err(|e| map_virt_error("block_resize", e))?,
                    // Stopped: no QEMU process, so resize the volume directly.
                    None => {
                        let pool = storage::find_pool(c, &disk_pool)?;
                        let vol = storage::find_volume(&pool, &target)?.ok_or_else(|| {
                            OpError::Fatal(anyhow!("disk volume {} does not exist", target))
                        })?;
                        storage::resize_volume(&vol, disk_size)?;
                    }
                }
                Ok(())
            })
            .await?;

        info!("resized disk for VM {} to {} bytes", vm_id, disk_size);
        Ok(())
    }

    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        let vm_id = vm.id;
        let sampler = &self.cpu;
        let domain_state = self
            .conn
            .run(move |c| {
                let domain = LibVirtHost::require_domain(c, vm_id)?;
                let info = domain
                    .info()
                    .map_err(|e| map_virt_error("domain_info", e))?;
                let xml = domain.xml_desc(0).ok();
                let counters = xml
                    .as_deref()
                    .and_then(|x| parse_live_devices(x).ok())
                    .map(|devices| {
                        let mut net = (0u64, 0u64);
                        let mut disk = (0u64, 0u64);
                        for iface in &devices.interface_targets {
                            if let Ok(s) = domain.interface_stats(iface) {
                                net.0 += s.rx_bytes.max(0) as u64;
                                net.1 += s.tx_bytes.max(0) as u64;
                            }
                        }
                        for dev in &devices.disk_targets {
                            if let Ok(s) = domain.block_stats(dev) {
                                disk.0 += s.rd_bytes.max(0) as u64;
                                disk.1 += s.wr_bytes.max(0) as u64;
                            }
                        }
                        (net, disk)
                    })
                    .unwrap_or_default();
                Ok((info, counters))
            })
            .await?;

        let (info, ((net_in, net_out), (disk_read, disk_write))) = domain_state;
        let mut state = stats::state_from_info(&info, vm_id, sampler);
        state.net_in = net_in;
        state.net_out = net_out;
        state.disk_read = disk_read;
        state.disk_write = disk_write;
        Ok(state)
    }

    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        let raw = self
            .conn
            .run(|c| {
                let domains = c
                    .list_all_domains(0)
                    .map_err(|e| map_virt_error("list_all_domains", e))?;

                let mut out = Vec::new();
                for domain in domains {
                    let Ok(name) = domain.name() else { continue };
                    // Foreign VMs sharing the host are not ours to report on.
                    let Some(vm_id) = vm_id_from_domain_name(&name) else {
                        continue;
                    };
                    let Ok(info) = domain.info() else { continue };
                    out.push((vm_id, info));
                }
                Ok(out)
            })
            .await?;

        Ok(raw
            .into_iter()
            .map(|(vm_id, info)| (vm_id, stats::state_from_info(&info, vm_id, &self.cpu)))
            .collect())
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        // Keep the filter in step with the config being applied.
        self.patch_firewall(cfg).await?;

        let disk_path = self.primary_disk_path(cfg).await?;
        // Regenerate the seed so key/IP changes reach the guest on next boot.
        let seed_path = self.write_seed(cfg).await?;
        let domain_xml = build_domain(
            cfg,
            &self.cfg.qemu,
            self.cfg.secure_boot,
            &disk_path,
            Some(&seed_path),
            self.cfg.vlan_aware_bridge,
        )
        .map_err(OpError::Fatal)?
        .to_xml()
        .map_err(OpError::Fatal)?;

        let vm_id = cfg.vm.id;
        let resources = cfg.resources().map_err(OpError::Fatal)?;

        self.conn
            .run(move |c| {
                // Re-defining replaces the persistent config, so everything here
                // is guaranteed to be in effect after the next boot.
                c.define_domain_xml(&domain_xml)
                    .map_err(|e| map_virt_error("define_domain", e))?;

                // Best effort on top of that: apply CPU/memory to the running
                // domain so a customer who just upgraded doesn't have to wait
                // for a reboot. Growing beyond the values the domain booted
                // with needs a restart, and libvirt says so — that is reported,
                // not treated as a failure, because the config *is* saved.
                let Some(domain) = LibVirtHost::lookup_domain(c, vm_id)? else {
                    return Ok(());
                };
                if !domain.is_active().unwrap_or(false) {
                    return Ok(());
                }

                // libvirt's memory APIs are in KiB, not bytes.
                let memory_kib = resources.memory / KB;
                if let Err(e) =
                    domain.set_memory_flags(memory_kib, VIR_DOMAIN_MEM_LIVE | VIR_DOMAIN_MEM_CONFIG)
                {
                    warn!(
                        "VM {}: memory change to {} KiB needs a restart to take effect: {}",
                        vm_id,
                        memory_kib,
                        e.message()
                    );
                }
                if let Err(e) = domain.set_vcpus_flags(
                    resources.cpu as u32,
                    VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG,
                ) {
                    warn!(
                        "VM {}: vCPU change to {} needs a restart to take effect: {}",
                        vm_id,
                        resources.cpu,
                        e.message()
                    );
                }
                Ok(())
            })
            .await
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let vm_id = cfg.vm.id;
        let rules = cfg.firewall_rules.clone();

        self.conn
            .run(move |c| {
                // libvirt matches nwfilters by UUID, not name: re-defining
                // without the existing UUID fails outright, so the current one
                // has to be carried over.
                let name = nwfilter::filter_name(vm_id);
                let existing = c
                    .lookup_nwfilter_by_name(&name)
                    .ok()
                    .and_then(|f| f.uuid_string().ok());

                let xml =
                    nwfilter::build(vm_id, &rules, existing.as_deref()).map_err(OpError::Fatal)?;
                c.define_nwfilter_xml(&xml)
                    .map_err(|e| map_virt_error("define_nwfilter", e))?;
                Ok(())
            })
            .await?;

        debug!(
            "applied {} firewall rule(s) to VM {}",
            cfg.firewall_rules.iter().filter(|r| r.enabled).count(),
            vm_id
        );
        Ok(())
    }

    async fn get_time_series_data(
        &self,
        _vm: &Vm,
        _series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        // Unlike Proxmox, libvirt keeps no RRD history — historical series need
        // an external store (Prometheus) rather than a host query.
        Err(OpError::Fatal(anyhow!(
            "libvirt does not store historical resource usage"
        )))
    }

    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream> {
        console::connect(self.conn.handle()?, vm.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::config::QemuConfig;
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

    fn cfg() -> LibVirtConfig {
        LibVirtConfig {
            qemu: qemu_cfg(),
            image_pool: Some("default-pool".to_string()),
            image_cache_dir: None,
            secure_boot: false,
            vlan_aware_bridge: true,
            shutdown_timeout_secs: Some(1),
        }
    }

    fn host() -> Result<LibVirtHost> {
        LibVirtHost::new("test:///default", cfg())
    }

    fn vm_info() -> FullVmInfo {
        let mut info = mock_full_vm();
        info.disk.name = "default-pool".to_string();
        info
    }

    #[tokio::test]
    async fn get_info_reports_host_resources() -> Result<()> {
        let host = host()?;
        let info = host.get_info().await.map_err(|e| anyhow!("{:?}", e))?;
        assert!(info.cpu > 0);
        assert!(info.memory > 0);
        assert!(!info.disks.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn generated_mac_uses_qemu_oui() -> Result<()> {
        let host = host()?;
        let vm = vm_info().vm;
        let mac = host
            .generate_mac(&vm)
            .await
            .map_err(|e| anyhow!("{:?}", e))?;
        assert!(mac.starts_with("52:54:00:"), "got {mac}");
        assert_eq!(mac.split(':').count(), 6);
        Ok(())
    }

    /// The seed carries the customer's SSH key and IP configuration into the
    /// guest, so it must be rendered from the *current* config every time.
    #[test]
    fn seed_image_carries_the_current_key() -> Result<()> {
        let mut info = vm_info();
        let first = LibVirtHost::build_seed_image(&info).map_err(|e| anyhow!("{e:?}"))?;
        let text = String::from_utf8_lossy(&first).to_string();

        assert!(
            text.contains(info.ssh_key.key_data.as_str()),
            "ssh key missing from the seed image"
        );
        assert!(
            !text.contains("[ENCRYPTED]"),
            "EncryptedString's Display placeholder leaked into the seed"
        );
        assert!(
            text.contains("instance-id: lnvps-vm-1"),
            "meta-data missing"
        );
        assert!(text.contains("version: 2"), "network-config missing");
        assert!(text.contains(&info.vm.mac_address.to_lowercase()));

        // A rotated key must change the image, or the customer keeps the old
        // key and never notices until they cannot log in.
        info.ssh_key.key_data = "ssh-ed25519 AAAArotated rotated@key".to_string().into();
        let second = LibVirtHost::build_seed_image(&info).map_err(|e| anyhow!("{e:?}"))?;
        assert_ne!(first, second);
        assert!(String::from_utf8_lossy(&second).contains("AAAArotated"));
        Ok(())
    }

    #[test]
    fn seed_image_is_reproducible() -> Result<()> {
        let info = vm_info();
        // Same config in, same bytes out.
        assert_eq!(
            LibVirtHost::build_seed_image(&info).map_err(|e| anyhow!("{e:?}"))?,
            LibVirtHost::build_seed_image(&info).map_err(|e| anyhow!("{e:?}"))?
        );
        Ok(())
    }

    #[tokio::test]
    async fn configure_vm_requires_an_existing_disk() -> Result<()> {
        let host = host()?;
        // Applying config to a VM that was never created must fail loudly
        // rather than define a domain pointing at a non-existent disk.
        let err = host.configure_vm(&vm_info()).await.expect_err("must fail");
        assert!(matches!(err, OpError::Fatal(_)));
        Ok(())
    }

    /// A rule libvirt cannot express must fail before anything is applied,
    /// rather than being dropped from the generated filter.
    #[tokio::test]
    async fn unrepresentable_firewall_rules_are_rejected() -> Result<()> {
        let host = host()?;
        let mut info = vm_info();

        info.firewall_rules.push(lnvps_db::VmFirewallRule {
            id: 1,
            vm_id: info.vm.id,
            // Ports with no protocol: emitting <all/> would open every port.
            protocol: lnvps_db::VmFirewallProtocol::Any,
            dst_port_start: Some(22),
            enabled: true,
            ..Default::default()
        });

        let err = host
            .patch_firewall(&info)
            .await
            .expect_err("rules must not be silently widened");
        assert!(matches!(err, OpError::Fatal(_)));
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_operations_error_instead_of_panicking() -> Result<()> {
        let host = host()?;
        let vm = vm_info().vm;

        // Previously `todo!()` — a panic reachable from an HTTP handler.
        assert!(matches!(
            host.get_time_series_data(&vm, TimeSeries::Hourly).await,
            Err(OpError::Fatal(_))
        ));
        assert!(matches!(
            host.connect_terminal(&vm).await,
            Err(OpError::Fatal(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_operations_report_missing_domains() -> Result<()> {
        let host = host()?;
        let vm = vm_info().vm;

        // Previously these silently returned Ok(()) while doing nothing, so the
        // API believed VMs were started and stopped that never existed.
        for res in [
            host.start_vm(&vm).await,
            host.stop_vm(&vm).await,
            host.reset_vm(&vm).await,
        ] {
            let err = res.expect_err("missing domain must be an error");
            assert!(matches!(err, OpError::Fatal(_)));
            assert!(format!("{err:?}").contains("does not exist"));
        }

        // ...and state must not be reported as a confident "Stopped".
        assert!(host.get_vm_state(&vm).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn delete_vm_is_idempotent() -> Result<()> {
        let host = host()?;
        let vm = vm_info().vm;
        // Rollback runs this on VMs that may never have been created.
        host.delete_vm(&vm).await.map_err(|e| anyhow!("{:?}", e))?;
        host.delete_vm(&vm).await.map_err(|e| anyhow!("{:?}", e))?;
        host.unlink_primary_disk(&vm)
            .await
            .map_err(|e| anyhow!("{:?}", e))?;
        Ok(())
    }

    #[tokio::test]
    async fn get_all_vm_states_ignores_foreign_domains() -> Result<()> {
        let host = host()?;
        // The test driver ships a domain called "test" which is not ours.
        let states = host
            .get_all_vm_states()
            .await
            .map_err(|e| anyhow!("{:?}", e))?;
        let names: Vec<u64> = states.iter().map(|(id, _)| *id).collect();
        assert!(
            states.is_empty(),
            "foreign domains must not be reported as LNVPS VMs: {names:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn resize_disk_requires_an_existing_volume() -> Result<()> {
        let host = host()?;
        let err = host
            .resize_disk(&vm_info())
            .await
            .expect_err("no disk exists yet");
        assert!(matches!(err, OpError::Fatal(_)));
        Ok(())
    }
}
