//! A marketplace node as a host client.
//!
//! Everything LNVPS does to a node it does through libvirt, exactly as it would
//! to a hypervisor it owns — with one exception. libvirt's storage API can only
//! be *handed* bytes, so caching an OS image through it means pulling the image
//! into LNVPS and pushing it back out over the node's own tunnel: the same
//! gigabyte paid for twice, at tunnel speed, to a machine with a perfectly good
//! connection.
//!
//! The node can fetch it. That is the one operation that differs, so it is the
//! one operation this type overrides; everything else forwards untouched. The
//! difference lives here rather than in the caller so that every path which
//! wants an image on a node — the download sweep, a VM being provisioned —
//! gets it without having to know which kind of host it is holding.
//!
//! What makes delegating safe is that LNVPS names the digest. The node fetches
//! what it likes from where it likes; bytes that do not hash to what was asked
//! for never become a volume.

use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use lnvps_db::{MarketplaceNode, Vm, VmHost, VmOsImage};
use log::{info, warn};

use super::{FullVmInfo, HostVmSpec, MigrateVmRequest, TerminalStream, VmHostClient, VmHostInfo};
use super::{TimeSeries, TimeSeriesData};
use crate::VmRunningState;
use crate::node_control::{NodeControl, NodeImageFetch};
use crate::retry::{OpError, OpResult};

pub struct MarketplaceNodeHost {
    inner: Arc<dyn VmHostClient>,
    control: NodeControl,
    node: MarketplaceNode,
    host: VmHost,
}

impl MarketplaceNodeHost {
    pub fn new(
        inner: Arc<dyn VmHostClient>,
        control: NodeControl,
        node: MarketplaceNode,
        host: VmHost,
    ) -> Self {
        Self {
            inner,
            control,
            node,
            host,
        }
    }
}

/// What to ask a node to fetch, or `None` when there is nothing it could be
/// asked for.
///
/// Both halves are required. Without a volume name LNVPS would not know what to
/// look the result up as, and without a digest the node has nothing to check
/// the download against — a fetch nobody can verify is a volume LNVPS has no
/// reason to believe holds the image it asked for. Either way the bytes go the
/// slow way instead of going unchecked.
fn fetch_request(volume: Option<String>, image: &VmOsImage) -> Option<NodeImageFetch> {
    // 64 hex characters: SHA-256, which is what the node verifies. A SHA-512
    // from a distro's SUMS file is a digest the node cannot check.
    let sha256 = image.sha2.clone().filter(|s| s.len() == 64)?;
    Some(NodeImageFetch {
        url: image.url.clone(),
        sha256,
        name: volume?,
    })
}

#[async_trait]
impl VmHostClient for MarketplaceNodeHost {
    /// Ask the node to fetch the image, and make its pool show the result.
    ///
    /// An image with no published checksum falls back to uploading: the node is
    /// told a digest or it is told nothing, because a fetch nobody can check is
    /// a volume LNVPS has no reason to believe holds the image it asked for.
    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        let Some(request) = fetch_request(self.inner.os_image_volume_name(image), image) else {
            warn!(
                "Image {} has no volume name or no sha256, uploading it to node {} instead",
                image.url, self.host.name
            );
            return self.inner.download_os_image(image).await;
        };

        info!("Asking node {} to fetch {}", self.host.name, image.url);
        self.control
            .fetch_image(&self.node, &self.host, &request)
            .await
            // Transient: a mirror that timed out, a node mid-reboot. The sweep
            // runs again, and a fatal error here would take the image out of
            // the catalog for a node rather than retrying it.
            .map_err(|e| OpError::Transient(anyhow!("{e:#}")))?;

        // libvirt lists a directory pool from its own cache, so until this runs
        // the file is on the node's disk and the volume does not exist.
        self.inner.refresh_image_pool().await
    }

    async fn get_info(&self) -> OpResult<VmHostInfo> {
        self.inner.get_info().await
    }

    async fn list_host_vms(&self) -> OpResult<Vec<HostVmSpec>> {
        self.inner.list_host_vms().await
    }

    async fn migrate_vm(&self, vm: &Vm, req: &MigrateVmRequest) -> OpResult<()> {
        self.inner.migrate_vm(vm, req).await
    }

    async fn generate_mac(&self, vm: &Vm) -> OpResult<String> {
        self.inner.generate_mac(vm).await
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        self.inner.start_vm(vm).await
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        self.inner.stop_vm(vm).await
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        self.inner.reset_vm(vm).await
    }

    async fn create_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        self.inner.create_vm(cfg).await
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        self.inner.delete_vm(vm).await
    }

    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
        self.inner.unlink_primary_disk(vm).await
    }

    fn os_image_volume_name(&self, image: &VmOsImage) -> Option<String> {
        self.inner.os_image_volume_name(image)
    }

    async fn refresh_image_pool(&self) -> OpResult<()> {
        self.inner.refresh_image_pool().await
    }

    async fn delete_unused_disks(&self, vm: &Vm) -> OpResult<()> {
        self.inner.delete_unused_disks(vm).await
    }

    async fn import_template_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        self.inner.import_template_disk(cfg).await
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        self.inner.resize_disk(cfg).await
    }

    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        self.inner.get_vm_state(vm).await
    }

    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        self.inner.get_all_vm_states().await
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        self.inner.configure_vm(cfg).await
    }

    async fn patch_config(&self, cfg: &FullVmInfo) -> OpResult<Vec<String>> {
        self.inner.patch_config(cfg).await
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        self.inner.patch_firewall(cfg).await
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        self.inner.get_time_series_data(vm, series).await
    }

    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream> {
        self.inner.connect_terminal(vm).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(sha2: Option<&str>) -> VmOsImage {
        VmOsImage {
            id: 1,
            distribution: lnvps_db::OsDistribution::Ubuntu,
            flavour: "Server".to_string(),
            version: "24.04".to_string(),
            enabled: true,
            release_date: chrono::Utc::now(),
            url: "https://example.com/image.img".to_string(),
            cpu_arch: Default::default(),
            default_username: None,
            sha2: sha2.map(|s| s.to_string()),
            sha2_url: None,
        }
    }

    /// An image with a digest and a volume name is the node's to fetch.
    #[test]
    fn an_image_with_a_digest_is_fetched_by_the_node() {
        let sha = "ab".repeat(32);
        let request = fetch_request(Some("os-image-1.raw".to_string()), &image(Some(&sha)))
            .expect("a verifiable image is the node's to fetch");
        assert_eq!(request.sha256, sha);
        assert_eq!(request.name, "os-image-1.raw");
        assert_eq!(request.url, "https://example.com/image.img");
    }

    /// Without a digest the node has nothing to verify against, and a SHA-512
    /// is a digest it cannot check, so both go the slow way.
    #[test]
    fn an_unverifiable_image_is_uploaded_instead() {
        assert!(fetch_request(Some("os-image-1.raw".to_string()), &image(None)).is_none());
        assert!(
            fetch_request(
                Some("os-image-1.raw".to_string()),
                &image(Some(&"ab".repeat(64)))
            )
            .is_none(),
            "a sha512 is not something the node checks"
        );
    }

    /// A host that does not cache images as named volumes has nothing to ask
    /// for.
    #[test]
    fn a_host_with_no_volume_name_is_not_asked() {
        assert!(fetch_request(None, &image(Some(&"ab".repeat(32)))).is_none());
    }
}
