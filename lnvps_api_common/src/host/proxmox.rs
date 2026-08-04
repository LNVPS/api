use crate::HostVmSpec;
use crate::JsonApi;
use crate::host::config::{QemuConfig, SshConfig};
use crate::host::proxmox_config::{
    CiCustom, DiskDevice, IpConfig, Ipv4Setting, Ipv6Setting, MacAddress, NetDevice, NetModel,
    SshKeys, opt_prop_string,
};
use crate::host::{
    FullVmInfo, MigrateVmRequest, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient,
    VmHostDiskInfo, VmHostInfo,
};
use crate::retry::{OpError, OpResult, Pipeline, RetryPolicy};
use crate::ssh_client::SshClient;
use crate::{VmRunningState, VmRunningStates, op_fatal, parse_gateway};
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use ipnetwork::IpNetwork;
use lnvps_db::{DiskType, IpRangeAllocationMode, Vm, VmOsImage};
use log::{info, warn};
use rand::random;
use reqwest::{Method, Url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

/// Comment prefix used to tag user-defined firewall rules (#36) on Proxmox so
/// they can be identified and re-synced without disturbing system rules.
const USER_FW_MARKER: &str = "lnvps-fw";

#[derive(Clone)]
pub struct ProxmoxClient {
    api: JsonApi,
    config: QemuConfig,
    ssh: Option<SshConfig>,
    mac_prefix: String,
    node: String,
}

impl ProxmoxClient {
    pub fn new(
        base: Url,
        node: &str,
        token: &str,
        mac_prefix: Option<String>,
        config: QemuConfig,
        ssh: Option<SshConfig>,
    ) -> Self {
        Self {
            api: JsonApi::token(base.as_str(), &format!("PVEAPIToken={}", token), true).unwrap(),
            config,
            ssh,
            node: node.to_string(),
            mac_prefix: mac_prefix.unwrap_or("bc:24:11".to_string()),
        }
    }

    /// Get version info
    pub async fn version(&self) -> OpResult<VersionResponse> {
        let rsp: ResponseBase<VersionResponse> = self.api.get("/api2/json/version").await?;
        Ok(rsp.data)
    }

    /// List nodes
    pub async fn list_nodes(&self) -> OpResult<Vec<NodeResponse>> {
        let rsp: ResponseBase<Vec<NodeResponse>> = self.api.get("/api2/json/nodes").await?;
        Ok(rsp.data)
    }

    pub async fn get_vm_status(&self, node: &str, vm_id: ProxmoxVmId) -> OpResult<VmInfo> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<VmInfo> = api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/status/current",
                node_str, vm_id
            ))
            .await?;

        Ok(rsp.data)
    }

    /// Like [`get_vm_status`] but returns `Ok(None)` when the VM does not exist
    /// (404). Transient failures (timeout, connection error, 5xx) are returned
    /// as `Err` so callers can tell "gone" apart from "couldn't reach the host".
    pub async fn get_vm_status_opt(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
    ) -> OpResult<Option<VmInfo>> {
        let rsp: Option<ResponseBase<VmInfo>> = self
            .api
            .get_opt(&format!(
                "/api2/json/nodes/{}/qemu/{}/status/current",
                node, vm_id
            ))
            .await?;
        Ok(rsp.map(|r| r.data))
    }

    pub async fn list_vms(&self, node: &str) -> OpResult<Vec<VmInfo>> {
        let rsp: ResponseBase<Vec<VmInfo>> = self
            .api
            .get(&format!("/api2/json/nodes/{node}/qemu"))
            .await?;
        Ok(rsp.data)
    }

    pub async fn list_storage(&self, node: &str) -> OpResult<Vec<NodeStorage>> {
        let rsp: ResponseBase<Vec<NodeStorage>> = self
            .api
            .get(&format!("/api2/json/nodes/{node}/storage"))
            .await?;
        Ok(rsp.data)
    }

    pub async fn list_disks(&self, node: &str) -> OpResult<Vec<NodeDisk>> {
        let rsp: ResponseBase<Vec<NodeDisk>> = self
            .api
            .get(&format!("/api2/json/nodes/{node}/disks/list"))
            .await?;
        Ok(rsp.data)
    }

    /// List files in a storage pool
    pub async fn list_storage_files(
        &self,
        node: &str,
        storage: &str,
    ) -> OpResult<Vec<StorageContentEntry>> {
        let rsp: ResponseBase<Vec<StorageContentEntry>> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{node}/storage/{storage}/content"
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Create a new VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu
    pub async fn create_vm(&self, req: CreateVm) -> OpResult<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();

        let rsp: ResponseBase<Option<String>> = api
            .post(&format!("/api2/json/nodes/{}/qemu", req.node), &req)
            .await?;

        if let Some(id) = rsp.data {
            Ok(TaskId {
                id,
                node: node_clone,
            })
        } else {
            op_fatal!("Failed to create VM")
        }
    }

    /// Get a VM current config
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu/{vmid}/config
    pub async fn get_vm_config(&self, node: &str, vm_id: ProxmoxVmId) -> OpResult<HashedVmConfig> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<HashedVmConfig> = api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/config",
                node_str, vm_id
            ))
            .await?;

        Ok(rsp.data)
    }

    /// Configure a VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu/{vmid}/config
    pub async fn configure_vm(&self, req: ConfigureVm) -> OpResult<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();

        let rsp: ResponseBase<Option<String>> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/config", req.node, req.vm_id),
                &req,
            )
            .await?;

        if let Some(id) = rsp.data {
            Ok(TaskId {
                id,
                node: node_clone,
            })
        } else {
            op_fatal!("Failed to configure VM")
        }
    }

    /// Delete VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu
    pub async fn delete_vm(&self, node: &str, vm: ProxmoxVmId) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<Option<String>> = api
            .req::<_, ()>(
                Method::DELETE,
                &format!("/api2/json/nodes/{}/qemu/{}", node_str, vm),
                None,
            )
            .await?;

        if let Some(id) = rsp.data {
            Ok(TaskId { id, node: node_str })
        } else {
            op_fatal!("Failed to delete VM")
        }
    }

    pub async fn get_vm_rrd_data(
        &self,
        id: ProxmoxVmId,
        timeframe: &str,
    ) -> OpResult<Vec<RrdDataPoint>> {
        let data: ResponseBase<Vec<_>> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/rrddata?timeframe={}",
                &self.node, id, timeframe
            ))
            .await?;

        Ok(data.data)
    }

    /// Get the current status of a running task
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/tasks/{upid}/status
    pub async fn get_task_status(&self, task: &TaskId) -> OpResult<TaskStatus> {
        let api = &self.api;
        let task_node = task.node.clone();
        let task_id = task.id.clone();

        let rsp: ResponseBase<TaskStatus> = api
            .get(&format!(
                "/api2/json/nodes/{}/tasks/{}/status",
                task_node, task_id
            ))
            .await?;

        Ok(rsp.data)
    }

    /// Helper function to wait for a task to complete
    pub async fn wait_for_task(&self, task: &TaskId) -> OpResult<TaskStatus> {
        let max_wait_time = Duration::from_secs(300); // 5 minutes max
        let start_time = std::time::Instant::now();

        loop {
            if start_time.elapsed() > max_wait_time {
                op_fatal!("Task {} timed out after 5 minutes", task.id);
            }

            let s = self.get_task_status(task).await?;
            if s.is_finished() {
                if s.is_success() {
                    return Ok(s);
                } else {
                    op_fatal!(
                        "Task finished with error: {}",
                        s.exit_status.unwrap_or("no error message".to_string())
                    );
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Poll VM status until it reports `Stopped`, or until the timeout expires.
    ///
    /// Proxmox marks the stop *task* as complete before the VM process has fully
    /// terminated.  Attempting to unlink (delete) the primary disk while the VM
    /// is still shutting down can leave the disk as an unattached volume instead
    /// of removing it.  Calling this after `wait_for_task` on the stop task
    /// ensures the disk is truly free before any disk operations proceed.
    pub async fn wait_for_vm_stopped(&self, vm_id: ProxmoxVmId) -> OpResult<()> {
        self.wait_for_vm_stopped_with_interval(vm_id, Duration::from_secs(2))
            .await
    }

    async fn wait_for_vm_stopped_with_interval(
        &self,
        vm_id: ProxmoxVmId,
        poll_interval: Duration,
    ) -> OpResult<()> {
        let max_wait_time = Duration::from_secs(120); // 2 minutes max
        let start_time = std::time::Instant::now();

        loop {
            if start_time.elapsed() > max_wait_time {
                op_fatal!("VM {} did not reach stopped state within 2 minutes", vm_id);
            }

            match self.get_vm_status(&self.node, vm_id).await {
                Ok(info) if info.status == VmStatus::Stopped => return Ok(()),
                Ok(_) => {}
                Err(e) => {
                    // Log and retry — transient API errors should not abort the wait
                    warn!(
                        "Error polling VM {} status while waiting for stop: {}",
                        vm_id, e
                    );
                }
            }
            sleep(poll_interval).await;
        }
    }

    async fn get_iso_storage(&self, node: &str) -> OpResult<String> {
        let storages = self.list_storage(node).await?;
        if let Some(s) = storages
            .iter()
            .find(|s| s.contents().contains(&StorageContent::ISO))
        {
            Ok(s.storage.clone())
        } else {
            op_fatal!("No image storage found");
        }
    }

    /// Find a storage pool that supports snippets content type
    async fn get_snippet_storage(&self, node: &str) -> OpResult<Option<String>> {
        let storages = self.list_storage(node).await?;
        Ok(storages
            .iter()
            .find(|s| s.contents().contains(&StorageContent::Snippets))
            .map(|s| s.storage.clone()))
    }

    /// Ensure the shared vendor-data snippet for cloud-init exists on the host.
    ///
    /// This snippet disables SSH host key regeneration so that cloud-init
    /// reconfiguration (IP changes, SSH key updates, etc.) does not cause
    /// host-key warnings for users connecting via SSH, and pins the guest
    /// resolvers, which minimal images otherwise drop.
    ///
    /// Returns the Proxmox volume reference (e.g. `local:snippets/lnvps-vendor.yaml`)
    /// or `None` if SSH is not configured or no snippet storage is available.
    async fn ensure_vendor_snippet(&self) -> OpResult<Option<String>> {
        self.write_snippet(
            "lnvps-vendor.yaml",
            &build_vendor_snippet(GUEST_DNS_SERVERS),
        )
        .await
    }

    /// Resolve the on-disk path of a snippet volume, writing it only when the
    /// content differs. Returns the volume reference to put in `cicustom`.
    async fn write_snippet(&self, filename: &str, content: &str) -> OpResult<Option<String>> {
        let ssh_config = match &self.ssh {
            Some(s) => s,
            None => return Ok(None),
        };
        let storage_name = match self.get_snippet_storage(&self.node).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        // Snippet storage path depends on the storage type; for the default
        // `local` storage this is `/var/lib/vz/snippets/`. For other directory-
        // based storages it varies, so `pvesm path` resolves it.
        let host = self.api.base().host().unwrap().to_string();
        let mut ssh = SshClient::new();
        ssh.connect((host, 22), &ssh_config.user, &ssh_config.key)
            .await
            .map_err(OpError::Transient)?;

        let vol_ref = format!("{storage_name}:snippets/{filename}");
        let (exit_code, path_output) = ssh
            .execute(&format!("pvesm path '{vol_ref}'"))
            .await
            .map_err(OpError::Transient)?;
        if exit_code != 0 {
            info!(
                "Cannot resolve snippet path for {}: {}",
                vol_ref,
                path_output.trim()
            );
            return Ok(None);
        }
        let snippet_path = path_output.trim().to_string();

        let (_, existing) = ssh
            .execute(&format!("cat '{snippet_path}' 2>/dev/null || true"))
            .await
            .map_err(OpError::Transient)?;
        if existing.trim() != content.trim() {
            let parent = snippet_path
                .rsplit_once('/')
                .map(|(p, _)| p)
                .unwrap_or("/tmp")
                .to_string();
            ssh.execute(&format!("mkdir -p '{parent}'"))
                .await
                .map_err(OpError::Transient)?;
            // Uploaded rather than echoed through a shell: the content is
            // multi-line YAML and quoting it into a command is a foot-gun.
            ssh.scp_upload(
                content.as_bytes(),
                std::path::Path::new(&snippet_path),
                0o644,
            )
            .await
            .map_err(OpError::Transient)?;
            info!("Wrote cloud-init snippet to {}", snippet_path);
        }
        Ok(Some(vol_ref))
    }

    /// Snippet filename holding a VM's network config, if it needs one.
    fn network_snippet_filename(vm_id: u64) -> String {
        format!("lnvps-net-{vm_id}.yaml")
    }

    /// Write the VM's network snippet, if it needs one.
    ///
    /// Failing to write one the VM needs is fatal rather than a downgrade: every
    /// address is already allocated, routed and billed, and carrying on would
    /// hand the customer a VM holding one of them.
    async fn ensure_network_snippet(&self, cfg: &FullVmInfo) -> OpResult<Option<String>> {
        let content = match Self::make_network_config(cfg).map_err(OpError::Fatal)? {
            Some(c) => c,
            None => return Ok(None),
        };
        match self
            .write_snippet(&Self::network_snippet_filename(cfg.vm.id), &content)
            .await?
        {
            Some(vol_ref) => Ok(Some(vol_ref)),
            None => op_fatal!(
                "VM {} needs a cloud-init network snippet but none could be written; \
                 snippet storage and SSH access are required to configure more than \
                 one address per family",
                cfg.vm.id
            ),
        }
    }

    /// Remove a VM's network snippet, if one was ever written.
    ///
    /// A VM cannot start when a `cicustom` volume it references is missing, so
    /// this only ever runs after the VM itself is gone.
    async fn remove_network_snippet(&self, vm_id: u64) -> OpResult<()> {
        let ssh_config = match &self.ssh {
            Some(s) => s,
            None => return Ok(()),
        };
        let storage_name = match self.get_snippet_storage(&self.node).await? {
            Some(s) => s,
            None => return Ok(()),
        };
        let host = self.api.base().host().unwrap().to_string();
        let mut ssh = SshClient::new();
        ssh.connect((host, 22), &ssh_config.user, &ssh_config.key)
            .await
            .map_err(OpError::Transient)?;

        let vol_ref = format!(
            "{storage_name}:snippets/{}",
            Self::network_snippet_filename(vm_id)
        );
        let (exit_code, path_output) = ssh
            .execute(&format!("pvesm path '{vol_ref}'"))
            .await
            .map_err(OpError::Transient)?;
        if exit_code != 0 {
            return Ok(());
        }
        let snippet_path = path_output.trim();
        ssh.execute(&format!("rm -f '{snippet_path}'"))
            .await
            .map_err(OpError::Transient)?;
        Ok(())
    }

    pub async fn import_disk_image(&self, req: ImportDiskImageRequest) -> OpResult<()> {
        // import the disk
        // TODO: find a way to avoid using SSH
        if let Some(ssh_config) = &self.ssh {
            let ssh_user = ssh_config.user.clone();
            let ssh_key = ssh_config.key.clone();
            let host = self.api.base().host().unwrap().to_string();

            // Prepare command first
            let mut disk_args: HashMap<&str, String> = HashMap::new();
            disk_args.insert(
                "import-from",
                format!("/var/lib/vz/template/iso/{}", req.image),
            );

            // If disk is SSD, enable discard + ssd options
            if req.is_ssd {
                disk_args.insert("discard", "on".to_string());
                disk_args.insert("ssd", "1".to_string());
            }

            // Dedicated IO thread for this disk. Without it every guest's block IO is
            // serialised through the main QEMU event loop alongside device emulation and
            // networking, capping a guest at roughly one thread of throughput.
            // Only honoured with the `virtio-scsi-single` controller (see `make_config`);
            // qemu-server warns and ignores it otherwise, so it is safe on legacy VMs.
            disk_args.insert("iothread", "1".to_string());

            // Disk I/O throttle limits — set at import time alongside discard/ssd
            if let Some(v) = req.mbps_rd {
                disk_args.insert("mbps_rd", v.to_string());
            }
            if let Some(v) = req.mbps_wr {
                disk_args.insert("mbps_wr", v.to_string());
            }
            if let Some(v) = req.iops_rd {
                disk_args.insert("iops_rd", v.to_string());
            }
            if let Some(v) = req.iops_wr {
                disk_args.insert("iops_wr", v.to_string());
            }

            let cmd = format!(
                "/usr/sbin/qm set {} --{} {}:0,{}",
                req.vm_id,
                &req.disk,
                &req.storage,
                disk_args
                    .into_iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",")
            );

            // SSH connection and execution with retry
            let mut s = SshClient::new();
            s.connect((host.clone(), 22), &ssh_user, &ssh_key)
                .await
                .map_err(OpError::Transient)?;
            let (code, rsp) = s.execute(&cmd).await.map_err(OpError::Transient)?;
            info!("{}", rsp);

            if code != 0 {
                op_fatal!("Failed to import disk, exit-code {}, {}", code, rsp);
            }
            Ok(())
        } else {
            op_fatal!(
                "Cannot complete, no method available to import disk, consider configuring ssh"
            )
        }
    }

    /// Resize a disk on a VM
    pub async fn resize_disk(&self, req: ResizeDiskRequest) -> OpResult<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();

        let rsp: ResponseBase<String> = api
            .req(
                Method::PUT,
                &format!("/api2/json/nodes/{}/qemu/{}/resize", &req.node, &req.vm_id),
                Some(&req),
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_clone,
        })
    }

    /// Start a VM
    pub async fn start_vm(&self, node: &str, vm: ProxmoxVmId) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<String> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/start", node_str, vm),
                (),
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Migrate a VM to another node in the same Proxmox cluster.
    ///
    /// The task runs on the **source** node, which is also where the returned
    /// task id must be polled: the destination has no record of the job until
    /// it completes.
    pub async fn migrate_vm(
        &self,
        node: &str,
        vm: ProxmoxVmId,
        req: &MigrateVmParams,
    ) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<String> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/migrate", node_str, vm),
                req,
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn stop_vm(&self, node: &str, vm: ProxmoxVmId) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<String> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/stop", node_str, vm),
                (),
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn shutdown_vm(&self, node: &str, vm: ProxmoxVmId) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<String> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/shutdown", node_str, vm),
                (),
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn reset_vm(&self, node: &str, vm: ProxmoxVmId) -> OpResult<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();

        let rsp: ResponseBase<String> = api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/reset", node_str, vm),
                (),
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Delete disks from VM
    pub async fn unlink_disk(
        &self,
        node: &str,
        vm: ProxmoxVmId,
        disks: Vec<String>,
        force: bool,
    ) -> OpResult<()> {
        self.api
            .req_status::<()>(
                Method::PUT,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/unlink?idlist={}&force={}",
                    node,
                    vm,
                    disks.join(","),
                    if force { "1" } else { "0" }
                ),
                None,
            )
            .await?;
        Ok(())
    }

    /// Fetch the raw VM config as a key/value map.
    ///
    /// Unlike [`get_vm_config`], this preserves dynamically-named keys such as
    /// `unused0`, `unused1`, ... which are not modelled on [`VmConfig`].
    pub async fn get_vm_config_raw(
        &self,
        node: &str,
        vm: ProxmoxVmId,
    ) -> OpResult<HashMap<String, serde_json::Value>> {
        let rsp: ResponseBase<HashMap<String, serde_json::Value>> = self
            .api
            .get(&format!("/api2/json/nodes/{}/qemu/{}/config", node, vm))
            .await?;
        Ok(rsp.data)
    }

    /// Force-remove the primary disk (`scsi0`) and any orphaned `unused[n]`
    /// disks from a VM.
    ///
    /// Proxmox moves a still-referenced disk to an `unused[n]` config entry
    /// (instead of deleting it) whenever a new disk is imported into a slot
    /// that is already populated — e.g. a retried/repeated `import-from` during
    /// reinstall. Left unchecked these accumulate indefinitely, so this enumerates
    /// the current config and physically removes the primary disk plus every
    /// `unused[n]` entry in a single request. Unlinking is a no-op when there is
    /// nothing to remove.
    async fn cleanup_vm_disks(&self, vm: ProxmoxVmId, include_primary: bool) -> OpResult<()> {
        let cfg = self.get_vm_config_raw(&self.node, vm).await?;
        let mut to_remove: Vec<String> = cfg
            .keys()
            .filter(|k| {
                let rest = match k.strip_prefix("unused") {
                    Some(r) => r,
                    None => return false,
                };
                !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
            })
            .cloned()
            .collect();

        if include_primary && cfg.contains_key("scsi0") {
            to_remove.push("scsi0".to_string());
        }

        if to_remove.is_empty() {
            return Ok(());
        }

        info!(
            "Removing {} disk(s) from VM {}: {:?}",
            to_remove.len(),
            vm,
            to_remove
        );
        self.unlink_disk(&self.node, vm, to_remove, true).await
    }

    /// Get VM firewall config
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/options
    pub async fn get_vm_firewall_config(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
    ) -> OpResult<VmFirewallConfig> {
        let rsp: ResponseBase<VmFirewallConfig> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/firewall/options",
                node, vm_id
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Configure VM firewall
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/options
    pub async fn configure_vm_firewall(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        req: VmFirewallConfig,
    ) -> OpResult<()> {
        self.api
            .req_status(
                Method::PUT,
                &format!("/api2/json/nodes/{}/qemu/{}/firewall/options", node, vm_id),
                Some(&req),
            )
            .await?;
        Ok(())
    }

    /// List VM firewall IPsets
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset
    pub async fn list_vm_ipsets(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
    ) -> OpResult<Vec<VmIpsetInfo>> {
        let rsp: ResponseBase<Vec<VmIpsetInfo>> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/firewall/ipset",
                node, vm_id
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Create VM firewall IPset
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset
    pub async fn add_vm_ipset(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        req: CreateVmIpsetRequest,
    ) -> OpResult<()> {
        self.api
            .req_status(
                Method::POST,
                &format!("/api2/json/nodes/{}/qemu/{}/firewall/ipset", node, vm_id),
                Some(&req),
            )
            .await?;
        Ok(())
    }

    /// Delete VM firewall IPset
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
    pub async fn remove_vm_ipset(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        ipset_name: &str,
    ) -> OpResult<()> {
        self.api
            .req_status::<()>(
                Method::DELETE,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/firewall/ipset/{}",
                    node, vm_id, ipset_name
                ),
                None,
            )
            .await?;
        Ok(())
    }

    /// List entries in a VM firewall IPset
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
    pub async fn list_vm_ipset_entries(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        ipset_name: &str,
    ) -> OpResult<Vec<VmIpsetEntry>> {
        let rsp: ResponseBase<Vec<VmIpsetEntry>> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/firewall/ipset/{}",
                node, vm_id, ipset_name
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Add entry to VM firewall IPset
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
    pub async fn add_vm_ipset_entry(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        ipset_name: &str,
        req: CreateVmIpsetEntryRequest,
    ) -> OpResult<()> {
        self.api
            .req_status(
                Method::POST,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/firewall/ipset/{}",
                    node, vm_id, ipset_name
                ),
                Some(&req),
            )
            .await?;
        Ok(())
    }

    /// Remove entry from VM firewall IPset
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}
    pub async fn remove_vm_ipset_entry(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        ipset_name: &str,
        cidr: &str,
    ) -> OpResult<()> {
        self.api
            .req_status::<()>(
                Method::DELETE,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/firewall/ipset/{}/{}",
                    node,
                    vm_id,
                    ipset_name,
                    urlencoding::encode(cidr)
                ),
                None,
            )
            .await?;
        Ok(())
    }

    /// List VM firewall rules
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/rules
    pub async fn list_vm_firewall_rules(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
    ) -> OpResult<Vec<VmFirewallRule>> {
        let rsp: ResponseBase<Vec<VmFirewallRule>> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/qemu/{}/firewall/rules",
                node, vm_id
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Add VM firewall rule
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/rules
    pub async fn add_vm_firewall_rule(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        req: VmFirewallRule,
    ) -> OpResult<()> {
        self.api
            .req_status(
                Method::POST,
                &format!("/api2/json/nodes/{}/qemu/{}/firewall/rules", node, vm_id),
                Some(&req),
            )
            .await?;
        Ok(())
    }

    /// Delete a VM firewall rule by its position
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}
    pub async fn delete_vm_firewall_rule(
        &self,
        node: &str,
        vm_id: ProxmoxVmId,
        pos: i32,
    ) -> OpResult<()> {
        self.api
            .req_status::<()>(
                Method::DELETE,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/firewall/rules/{}",
                    node, vm_id, pos
                ),
                None,
            )
            .await?;
        Ok(())
    }
}

impl ProxmoxClient {
    fn convert_firewall_policy(policy: &crate::host::config::FirewallPolicy) -> VmFirewallPolicy {
        match policy {
            crate::host::config::FirewallPolicy::Accept => VmFirewallPolicy::ACCEPT,
            crate::host::config::FirewallPolicy::Reject => VmFirewallPolicy::REJECT,
            crate::host::config::FirewallPolicy::Drop => VmFirewallPolicy::DROP,
        }
    }

    /// Translate a user-defined per-VM default firewall policy into a Proxmox
    /// policy value.
    fn convert_vm_firewall_policy(policy: lnvps_db::VmFirewallPolicy) -> VmFirewallPolicy {
        match policy {
            lnvps_db::VmFirewallPolicy::Accept => VmFirewallPolicy::ACCEPT,
            lnvps_db::VmFirewallPolicy::Drop => VmFirewallPolicy::DROP,
            lnvps_db::VmFirewallPolicy::Reject => VmFirewallPolicy::REJECT,
        }
    }

    /// Translate a user-defined DB firewall rule into a Proxmox PVE firewall rule.
    ///
    /// The rule is tagged with a [`USER_FW_MARKER`]-prefixed comment so it can be
    /// identified and re-synced on subsequent applies without disturbing the
    /// always-enforced ipfilter (anti-spoof) rule.
    /// Convert a database firewall rule into one or more Proxmox rules.
    ///
    /// Proxmox rejects `dport` unless `proto` is also set ("'dport' requires
    /// this property"). A port with an "Any" protocol therefore can't be a
    /// single rule; instead we expand it into two rules — one for `tcp` and one
    /// for `udp` — so the port restriction is preserved. All expanded rules
    /// share the same `lnvps-fw:<id>` comment marker so cleanup still matches
    /// them as a group.
    fn to_pve_firewall_rules(rule: &lnvps_db::VmFirewallRule) -> Vec<VmFirewallRule> {
        use lnvps_db::{VmFirewallDirection, VmFirewallProtocol, VmFirewallRuleAction};

        let action = match rule.action {
            VmFirewallRuleAction::Accept => VmFirewallAction::ACCEPT,
            VmFirewallRuleAction::Drop => VmFirewallAction::DROP,
            VmFirewallRuleAction::Reject => VmFirewallAction::REJECT,
        };
        let rule_type = match rule.direction {
            VmFirewallDirection::Inbound => VmFirewallRuleType::In,
            VmFirewallDirection::Outbound => VmFirewallRuleType::Out,
        };
        let dport = match (rule.dst_port_start, rule.dst_port_end) {
            (Some(s), Some(e)) if e != s => Some(format!("{}:{}", s, e)),
            (Some(s), _) => Some(s.to_string()),
            (None, _) => None,
        };

        // Determine which protocol(s) this rule maps to. "Any" with a port must
        // be expanded to tcp + udp (Proxmox has no protocol-less dport); "Any"
        // without a port stays a single protocol-less rule.
        let protos: Vec<Option<&str>> = match rule.protocol {
            VmFirewallProtocol::Any => {
                if dport.is_some() {
                    vec![Some("tcp"), Some("udp")]
                } else {
                    vec![None]
                }
            }
            VmFirewallProtocol::Tcp => vec![Some("tcp")],
            VmFirewallProtocol::Udp => vec![Some("udp")],
            VmFirewallProtocol::Icmp => vec![Some("icmp")],
        };

        protos
            .into_iter()
            .map(|proto| VmFirewallRule {
                action: action.clone(),
                rule_type: rule_type.clone(),
                // Only carry the port when a protocol is present.
                dport: proto.and(dport.clone()),
                proto: proto.map(|p| p.to_string()),
                source: rule.src_cidr.clone(),
                enable: Some(if rule.enabled { 1 } else { 0 }),
                comment: Some(format!("{}:{}", USER_FW_MARKER, rule.id)),
                ..Default::default()
            })
            .collect()
    }

    /// Build a cloud-init network-config (v2) putting every assignment on the
    /// VM's single NIC.
    ///
    /// Returns `None` when the VM holds at most one address per family: a single
    /// `ipconfig0` expresses that exactly, and leaving those VMs on the built-in
    /// path keeps their config untouched. Above that, `ipconfig[n]` cannot help —
    /// it carries one `ip=` and one `ip6=` per interface — and a second NIC is not
    /// an option either, because the addresses share one router-issued vMAC and
    /// must therefore share the interface carrying it.
    ///
    /// The interface is matched by MAC rather than by name so the config does not
    /// depend on how the guest enumerates devices.
    /// Cloud-init network snippet, or `None` when the simpler `ipconfig` path
    /// can express the layout on its own (at most one address per family).
    ///
    /// The document itself is built by [`crate::host::cloud_init::network_config`],
    /// shared with the libvirt backend so the address/gateway handling cannot
    /// drift between hypervisors.
    fn make_network_config(value: &FullVmInfo) -> Result<Option<String>> {
        let net = crate::host::cloud_init::network_config(value)?;
        if net.v4_count <= 1 && net.v6_count <= 1 {
            return Ok(None);
        }
        Ok(Some(net.yaml))
    }

    fn make_config(
        &self,
        value: &FullVmInfo,
        vendor_snippet: Option<&str>,
        network_snippet: Option<&str>,
    ) -> Result<VmConfig> {
        // `ipconfig[n]` holds at most one address per family; repeating a key
        // produces something the guest cannot act on. Any address beyond the
        // first of each family is carried by the network snippet instead.
        let mut ip_config = IpConfig::default();
        for ip in &value.ips {
            let Ok(addr) = ip.ip.parse::<IpAddr>() else {
                continue;
            };
            let Some(ip_range) = value.ranges.iter().find(|r| r.id == ip.ip_range_id) else {
                continue;
            };
            match addr {
                IpAddr::V4(_) if ip_config.ip.is_none() => {
                    let (Ok(range), Ok(range_gw)) = (
                        ip_range.cidr.parse::<IpNetwork>(),
                        parse_gateway(&ip_range.gateway),
                    ) else {
                        continue;
                    };
                    let prefix = range.prefix().min(range_gw.prefix());
                    if let Ok(net) = IpNetwork::new(addr, prefix) {
                        ip_config.ip = Some(Ipv4Setting::Static(net));
                        ip_config.gateway = Some(range_gw.ip());
                    }
                }
                IpAddr::V6(_) if ip_config.ip6.is_none() => {
                    if matches!(ip_range.allocation_mode, IpRangeAllocationMode::SlaacEui64) {
                        // just ignore what's in the db and use whatever the host wants
                        // what's in the db is purely informational
                        ip_config.ip6 = Some(Ipv6Setting::Auto);
                        continue;
                    }
                    let (Ok(range), Ok(range_gw)) = (
                        ip_range.cidr.parse::<IpNetwork>(),
                        parse_gateway(&ip_range.gateway),
                    ) else {
                        continue;
                    };
                    let prefix = range.prefix().min(range_gw.prefix());
                    if let Ok(net) = IpNetwork::new(addr, prefix) {
                        ip_config.ip6 = Some(Ipv6Setting::Static(net));
                        ip_config.gateway6 = Some(range_gw.ip());
                    }
                }
                _ => {}
            }
        }

        let limits = value.limits();
        let net = NetDevice {
            model: NetModel::VirtIo,
            mac: MacAddress::parse(&value.vm.mac_address),
            bridge: Some(self.config.bridge.clone()),
            firewall: true, //always enable on interface
            tag: value.host.vlan_id.map(|t| t as u16),
            mtu: value.host.mtu.map(|m| m as u32),
            link_down: value.vm.disabled,
            // Proxmox rate= is in MB/s; our field is stored in Mbit/s
            rate: limits.network_mbps.map(|mbps| mbps as f32 / 8.0),
        };

        let cicustom = CiCustom {
            vendor: vendor_snippet.and_then(|v| v.parse().ok()),
            network: network_snippet.and_then(|n| n.parse().ok()),
            ..Default::default()
        };

        let vm_resources = value.resources()?;
        Ok(VmConfig {
            name: Some(format!("VM{}", value.vm.id)), // set name to DB name
            cpu: Some(self.config.cpu.clone()),
            kvm: Some(self.config.kvm),
            ip_config: Some(ip_config),
            machine: Some(self.config.machine.clone()),
            net: Some(net),
            os_type: Some(self.config.os_type.clone()),
            on_boot: Some(true),
            bios: Some(VmBios::OVMF),
            boot: Some("order=scsi0".to_string()),
            cores: Some(vm_resources.cpu as i32),
            memory: Some((vm_resources.memory / crate::MB).to_string()),
            balloon: self.config.balloon_mb(vm_resources.memory / crate::MB),
            // `virtio-scsi-single` gives each disk its own controller, which is the only
            // scsi controller type that supports `iothread=1` (set on scsi0 at import /
            // in `apply_disk_options`). Takes effect on next VM start.
            scsi_hw: Some("virtio-scsi-single".to_string()),
            serial_0: Some("socket".to_string()),
            scsi_1: Some(DiskDevice::volume(&value.disk.name, "cloudinit")),
            ssh_keys: Some(SshKeys::one(value.ssh_key.key_data.as_str())),
            efi_disk_0: Some(DiskDevice {
                efi_type: Some("4m".to_string()),
                ..DiskDevice::volume(&value.disk.name, "0")
            }),
            cpu_limit: limits.cpu_limit,
            cicustom: (!cicustom.is_empty()).then_some(cicustom),
            ..Default::default()
        })
    }

    /// Compare the config currently on the host against the config we expect
    /// from the database, returning the names of the fields that differ.
    ///
    /// Only fields the expected config actually sets are considered. The disk
    /// *volumes* themselves are ignored (they are managed by create/resize),
    /// but the disk *options* we own (`iothread`, `ssd`/`discard`, throttle
    /// limits) are compared by the caller via [`Self::make_scsi0`].
    fn config_drift(current: &VmConfig, expected: &VmConfig) -> Vec<String> {
        let mut drift = Vec::new();

        macro_rules! cmp {
            ($field:ident) => {
                if let Some(want) = expected.$field.as_ref() {
                    if current.$field.as_ref() != Some(want) {
                        drift.push(stringify!($field).to_string());
                    }
                }
            };
        }

        cmp!(name);
        cmp!(cores);
        cmp!(memory);
        cmp!(balloon);
        cmp!(cpu);
        cmp!(cpu_limit);
        cmp!(on_boot);
        cmp!(machine);
        cmp!(os_type);
        cmp!(bios);
        cmp!(boot);
        cmp!(kvm);
        cmp!(scsi_hw);
        cmp!(serial_0);
        cmp!(cicustom);
        cmp!(net);
        cmp!(ip_config);
        cmp!(ssh_keys);

        drift
    }

    /// Apply disk options (iothread, SSD hints, I/O throttle limits) to the primary disk.
    ///
    /// Fetches the current scsi0 device string from Proxmox, rebuilds it from the bare
    /// volume reference plus the options we own, and sends a PATCH to update the VM
    /// config. Runs unconditionally so that VMs without throttle limits still converge
    /// onto `iothread=1`.
    async fn apply_disk_options(&self, req: &FullVmInfo) -> OpResult<()> {
        // Fetch the current config to get the live scsi0 disk
        let current = self.get_vm_config(&self.node, req.vm.id.into()).await?;
        let scsi_0 = match current.config.scsi_0 {
            Some(v) => v,
            None => op_fatal!("scsi0 not found in VM config"),
        };

        self.configure_vm(ConfigureVm {
            node: self.node.clone(),
            vm_id: req.vm.id.into(),
            current: None,
            snapshot: None,
            digest: None,
            config: VmConfig {
                scsi_0: Some(Self::make_scsi0(&scsi_0, req)),
                ..Default::default()
            },
        })
        .await?;

        Ok(())
    }

    /// The `scsi0` device we expect for a VM: the live volume (owned by
    /// create/resize) carrying the options we own.
    fn make_scsi0(current: &DiskDevice, req: &FullVmInfo) -> DiskDevice {
        let limits = req.limits();
        let is_ssd = matches!(req.disk.kind, DiskType::SSD);
        DiskDevice {
            volume: current.volume.clone(),
            size: current.size.clone(),
            discard: is_ssd,
            ssd: is_ssd,
            // Keep in sync with `import_disk_image`; requires scsihw=virtio-scsi-single.
            iothread: true,
            efi_type: None,
            mbps_rd: limits.disk_mbps_read.map(|v| v as f32),
            mbps_wr: limits.disk_mbps_write.map(|v| v as f32),
            iops_rd: limits.disk_iops_read,
            iops_wr: limits.disk_iops_write,
        }
    }

    /// Import main disk image from the template (without resizing)
    async fn import_disk(&self, req: &FullVmInfo) -> OpResult<()> {
        let vm_id = req.vm.id.into();
        let limits = req.limits();

        // Ensure the scsi0 slot is empty before importing. If scsi0 is still
        // populated (e.g. a retried import during reinstall), Proxmox would move
        // the existing disk to an `unused[n]` entry instead of overwriting it,
        // leaking volumes on every retry. This also sweeps up any pre-existing
        // orphaned `unused[n]` disks. Keeps import idempotent.
        self.cleanup_vm_disks(vm_id, true).await?;

        // import primary disk from image (scsi0); throttle limits are set here
        // alongside discard/ssd and apply to the resulting disk without a second request
        self.import_disk_image(ImportDiskImageRequest {
            vm_id,
            node: self.node.clone(),
            storage: req.disk.name.clone(),
            disk: "scsi0".to_string(),
            image: req.image.filename()?,
            is_ssd: matches!(req.disk.kind, DiskType::SSD),
            mbps_rd: limits.disk_mbps_read,
            mbps_wr: limits.disk_mbps_write,
            iops_rd: limits.disk_iops_read,
            iops_wr: limits.disk_iops_write,
        })
        .await?;

        Ok(())
    }

    /// Resize the main disk to match template size
    async fn resize_main_disk(&self, req: &FullVmInfo) -> OpResult<()> {
        let vm_id = req.vm.id.into();

        let j_resize = self
            .resize_disk(ResizeDiskRequest {
                node: self.node.clone(),
                vm_id,
                disk: "scsi0".to_string(),
                size: req.resources()?.disk_size.to_string(),
            })
            .await?;
        self.wait_for_task(&j_resize).await?;

        Ok(())
    }

    /// Import main disk image from the template (import + resize)
    /// Used by reinstall_vm which doesn't use the pipeline
    async fn import_template_disk(&self, req: &FullVmInfo) -> OpResult<()> {
        self.import_disk(req).await?;
        self.resize_main_disk(req).await?;
        Ok(())
    }

    /// Destroy a VM by ID (stop first, then delete via SSH)
    async fn destroy_vm(&self, vm_id: ProxmoxVmId) -> OpResult<()> {
        // Check if VM exists first. Only a definitive 404 (Ok(None)) means the VM
        // is already gone; a transient failure returns Err and must abort the
        // destroy so we don't free the DB record / IPs while the VM is still
        // running on the host.
        if self.get_vm_status_opt(&self.node, vm_id).await?.is_none() {
            info!("VM {} doesn't exist, skipping destroy", vm_id);
            return Ok(());
        }

        // Destroying requires SSH access to run `qm destroy`. Without it we can
        // only stop the VM, which would leave it undestroyed while the caller
        // proceeds to release its resources — fail loudly instead.
        let ssh = match &self.ssh {
            Some(ssh) => ssh,
            None => op_fatal!("Cannot destroy VM {}: no SSH access configured", vm_id),
        };

        // Stop first, ignoring errors
        self.stop_vm(&self.node, vm_id).await.ok();

        {
            let mut ses = SshClient::new();
            ses.connect(
                (self.api.base().host().unwrap().to_string(), 22),
                &ssh.user,
                &ssh.key,
            )
            .await
            .map_err(OpError::Transient)?;

            let cmd = format!("/usr/sbin/qm destroy {}", vm_id);
            let (code, rsp) = ses
                .execute(cmd.as_str())
                .await
                .map_err(OpError::Transient)?;
            info!("{}", rsp);
            // exit code 2 = doesn't exist, ignore
            if code != 0 && code != 2 {
                op_fatal!("Failed to destroy vm, exit-code {}, {}", code, rsp)
            }
        }
        Ok(())
    }
}

/// Context for the create_vm pipeline - tracks what we need for rollback
struct CreateVmContext<'a> {
    client: ProxmoxClient,
    req: &'a FullVmInfo,
    vm_id: ProxmoxVmId,
    config: VmConfig,
}

#[async_trait]
impl VmHostClient for ProxmoxClient {
    async fn get_info(&self) -> OpResult<VmHostInfo> {
        use anyhow::Context;
        let nodes = self.list_nodes().await?;
        if let Some(n) = nodes.iter().find(|n| n.name == self.node) {
            let storages = self.list_storage(&n.name).await?;
            let info = VmHostInfo {
                cpu: n.max_cpu
                    .context("Missing cpu count, please make sure you have Sys.Audit permission")?,
                memory: n.max_mem
                    .context("Missing memory size, please make sure you have Sys.Audit permission")?,
                disks: storages
                    .into_iter()
                    .filter_map(|s| {
                        let size = s.total
                            .context("Missing disk size, please make sure you have Datastore.Audit permission")
                            .ok()?;
                        let used = s.used
                            .context("Missing used disk, please make sure you have Datastore.Audit permission")
                            .ok()?;

                        Some(VmHostDiskInfo {
                            name: s.storage,
                            size,
                            used,
                        })
                    })
                    .collect(),
            };

            Ok(info)
        } else {
            op_fatal!("Could not find node {}", self.node);
        }
    }

    async fn list_host_vms(&self) -> OpResult<Vec<HostVmSpec>> {
        let vms = self.list_vms(&self.node).await?;
        let mut out = Vec::with_capacity(vms.len());
        for vm in vms {
            // Map to the LNVPS db id (vmid = db_id + 100). VMs with vmid < 100
            // fall outside the managed range and can't be imported.
            let mapped_vm_id = if vm.vm_id >= 100 {
                let id: ProxmoxVmId = vm.vm_id.into();
                Some(id.inner())
            } else {
                None
            };

            // Pull the live config for MAC + backing storage; tolerate failures
            // so a single unreadable VM doesn't abort discovery.
            let (mac_address, disk_storage) =
                match self.get_vm_config(&self.node, vm.vm_id.into()).await {
                    Ok(cfg) => (
                        cfg.config.net.and_then(|n| n.mac).map(|m| m.to_string()),
                        cfg.config
                            .scsi_0
                            .map(|d| d.volume.storage)
                            .filter(|s| !s.is_empty()),
                    ),
                    Err(e) => {
                        warn!("Failed to read config for vm {}: {}", vm.vm_id, e);
                        (None, None)
                    }
                };

            out.push(HostVmSpec {
                host_vm_id: vm.vm_id as i64,
                mapped_vm_id,
                name: vm.name.clone(),
                cpu: vm.cpus.unwrap_or(0),
                memory: vm.max_mem.unwrap_or(0),
                disk_size: vm.max_disk.unwrap_or(0),
                disk_storage,
                mac_address,
                running: matches!(vm.status, VmStatus::Running),
            });
        }
        Ok(out)
    }

    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        let iso_storage = self.get_iso_storage(&self.node).await?;
        let files = self.list_storage_files(&self.node, &iso_storage).await?;

        info!("Downloading image {} on {}", image.url, &self.node);
        // storage_name: how the final (usable) image is stored on the host (e.g. foo.img)
        // url_name:     the original filename from the URL, used in SHASUMS
        //               (e.g. foo.qcow2 or, when compressed, foo.qcow2.xz)
        // download_name: the filename we download to the host. For compressed
        //               images this is the real compressed file (url_name), which
        //               we fetch directly on the host over SSH (wget/curl) and then
        //               decompress into storage_name. We bypass Proxmox's
        //               download-url API for compressed images because it validates
        //               the filename extension against the ISO content type and only
        //               accepts `.iso`/`.img` (a `.qcow2.xz` name is rejected with
        //               "wrong file extension").
        let compression = image.compression();
        let storage_name = image.filename()?;
        let url_name = image.url_filename()?;
        let download_name = if compression.is_some() {
            url_name.clone()
        } else {
            storage_name.clone()
        };

        // Resolve the expected checksum from sha2_url if present.
        // This is used only for SSH-based verification of the downloaded file;
        // we do NOT pass it to the Proxmox download-url API because that has proven
        // unreliable and causes download failures on the client side.
        let expected_sha2 = if let Some(sha2_url) = &image.sha2_url {
            match Self::fetch_sha2_from_url(sha2_url, &url_name).await {
                Ok(s) => {
                    info!(
                        "Resolved checksum for {} from {}: {}",
                        url_name, sha2_url, s
                    );
                    Some(s)
                }
                Err(e) => {
                    warn!("Failed to fetch sha2 from {}: {}", sha2_url, e);
                    image.sha2.clone()
                }
            }
        } else {
            image.sha2.clone()
        };

        // Determine the checksum algorithm from the digest length
        let checksum_algorithm = expected_sha2
            .as_deref()
            .and_then(|s| crate::shasum::ShasumAlgorithm::from_hex_len(s.len()))
            .map(|a| a.as_str().to_owned());

        let already_present = files
            .iter()
            .any(|v| v.vol_id.ends_with(&format!("iso/{storage_name}")));

        if already_present {
            // Decide whether the stored image is stale (its source changed) and
            // must be re-downloaded. We always do a hash check when a checksum is
            // available:
            //
            // - Uncompressed images: hash the stored file directly and compare to
            //   the expected SHASUMS checksum.
            // - Compressed images: the stored file is the *decompressed* `.img`,
            //   whose hash does not match the SHASUMS entry (which covers the
            //   compressed artifact). We instead record the source checksum in a
            //   sidecar (`<img>.sha2src`) when decompressing, and compare the
            //   current expected checksum against that here. This still detects a
            //   changed source image (e.g. an updated OS image record) without
            //   re-hashing the large decompressed file, and — crucially — no
            //   longer blindly trusts a stale decompressed image.
            let stale = if let (Some(expected), Some(algo)) = (&expected_sha2, &checksum_algorithm)
            {
                if compression.is_some() {
                    let sidecar = Self::image_source_checksum_path(&storage_name);
                    match self
                        .ssh_run(format!("cat '{sidecar}' 2>/dev/null || true"))
                        .await
                    {
                        Ok((_, out)) if out.trim().eq_ignore_ascii_case(expected) => {
                            info!(
                                "Source checksum matches for {}, skipping download",
                                storage_name
                            );
                            false
                        }
                        Ok((_, out)) if out.trim().is_empty() => {
                            info!(
                                "No recorded source checksum for {}, will re-download to record it",
                                storage_name
                            );
                            true
                        }
                        Ok(_) => {
                            info!(
                                "Source checksum changed for {}, will re-download",
                                storage_name
                            );
                            true
                        }
                        Err(e) => {
                            warn!(
                                "Failed to read source checksum for {}: {}, will re-download",
                                storage_name, e
                            );
                            true
                        }
                    }
                } else {
                    match self
                        .verify_image_checksum(&storage_name, &iso_storage, expected, algo)
                        .await
                    {
                        Ok(true) => {
                            info!("Checksum verified for {}, skipping download", storage_name);
                            false
                        }
                        Ok(false) => {
                            info!("Checksum mismatch for {}, will re-download", storage_name);
                            true
                        }
                        Err(e) => {
                            warn!(
                                "Failed to verify checksum for {}: {}, will re-download",
                                storage_name, e
                            );
                            true
                        }
                    }
                }
            } else {
                // No checksum available: cannot verify, trust presence.
                info!(
                    "No checksum available for {}, skipping re-download check",
                    storage_name
                );
                false
            };

            if !stale {
                return Ok(());
            }

            // Delete the stale image (and any source-checksum sidecar) first.
            info!("Deleting stale image {} from {}", storage_name, &self.node);
            if let Err(e) = self
                .delete_storage_file(&self.node, &iso_storage, &storage_name)
                .await
            {
                warn!("Failed to delete stale image {}: {}", storage_name, e);
            }
            let sidecar = Self::image_source_checksum_path(&storage_name);
            if let Err(e) = self.ssh_run(format!("rm -f '{sidecar}'")).await {
                warn!(
                    "Failed to delete source checksum sidecar for {}: {}",
                    storage_name, e
                );
            }
        }

        // Fetch the image directly on the host over SSH (wget/curl). We no longer
        // use Proxmox's download-url API at all: it rejects compressed filenames
        // (`.qcow2.xz` -> "wrong file extension"), does not reliably follow
        // redirects, and its built-in checksum verification has proven broken.
        // wget/curl follow redirects natively; integrity is verified via SSH
        // below (see verify_image_checksum) and compressed images are decompressed
        // by us afterwards.
        self.download_image_ssh(&image.url, &download_name)
            .await
            .map_err(OpError::Fatal)?;

        // Verify the freshly-downloaded file via SSH to confirm integrity. This
        // runs against download_name (the compressed artifact for compressed
        // images), matching the SHASUMS entry.
        if let (Some(expected), Some(algo)) = (&expected_sha2, &checksum_algorithm) {
            match self
                .verify_image_checksum(&download_name, &iso_storage, expected, algo)
                .await
            {
                Ok(true) => {
                    info!("Post-download checksum verified for {}", download_name);
                }
                Ok(false) => {
                    // Delete the corrupt file so the next run re-downloads it.
                    warn!(
                        "Post-download checksum mismatch for {}, deleting corrupt file",
                        download_name
                    );
                    if let Err(e) = self
                        .delete_storage_file(&self.node, &iso_storage, &download_name)
                        .await
                    {
                        warn!("Failed to delete corrupt image {}: {}", download_name, e);
                    }
                    return Err(OpError::Fatal(anyhow::anyhow!(
                        "Checksum mismatch after download of {}",
                        download_name
                    )));
                }
                Err(e) => {
                    warn!(
                        "Could not verify post-download checksum for {}: {}",
                        download_name, e
                    );
                }
            }
        }

        // Decompress compressed images into the final storage_name and remove
        // the compressed source. Must happen after checksum verification.
        if let Some(algo) = &compression {
            info!(
                "Decompressing {} ({}) -> {} on {}",
                download_name, algo, storage_name, &self.node
            );
            self.decompress_image(algo, &download_name, &storage_name)
                .await
                .map_err(OpError::Fatal)?;
            info!("Decompressed image available as {}", storage_name);

            // Record the source (compressed) checksum next to the decompressed
            // image so future runs can detect a changed source via a hash check
            // without re-hashing the large decompressed file. Best-effort: a
            // failure here only means the next run re-downloads to record it.
            if let (Some(expected), Some(_)) = (&expected_sha2, &checksum_algorithm)
                && expected.chars().all(|c| c.is_ascii_hexdigit())
            {
                let sidecar = Self::image_source_checksum_path(&storage_name);
                let expected = expected.to_lowercase();
                if let Err(e) = self
                    .ssh_run(format!("printf '%s' '{expected}' > '{sidecar}'"))
                    .await
                {
                    warn!(
                        "Failed to record source checksum for {}: {}",
                        storage_name, e
                    );
                }
            }
        }

        Ok(())
    }

    async fn generate_mac(&self, _vm: &Vm) -> OpResult<String> {
        if self.mac_prefix.len() != 8 || !self.mac_prefix.contains(":") {
            op_fatal!("Invalid mac prefix");
        }

        Ok(format!(
            "{}:{}:{}:{}",
            self.mac_prefix,
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()])
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> OpResult<()> {
        let task = self.start_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn migrate_vm(&self, vm: &Vm, req: &MigrateVmRequest) -> OpResult<()> {
        if req.target_node == self.node {
            op_fatal!("VM {} is already on node {}", vm.id, req.target_node);
        }
        let params = MigrateVmParams {
            target: req.target_node.clone(),
            online: Some(req.online as u8),
            // Only set when the disk cannot stay where it is: passing
            // `with-local-disks` for a VM on shared storage makes Proxmox copy a
            // disk that both nodes can already see.
            with_local_disks: req.target_storage.as_ref().map(|_| 1),
            targetstorage: req.target_storage.clone(),
        };
        let task = self.migrate_vm(&self.node, vm.id.into(), &params).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> OpResult<()> {
        let task = self.stop_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        // Wait until the VM process has fully terminated before returning.
        // The stop task completing only means the stop command was accepted;
        // the VM may still be shutting down.  Disk operations (e.g. unlink
        // during reinstall) must not run while the VM is still live.
        self.wait_for_vm_stopped(vm.id.into()).await?;
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> OpResult<()> {
        let task = self.reset_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn create_vm(&self, req: &FullVmInfo) -> OpResult<()> {
        let vendor_snippet = self.ensure_vendor_snippet().await?;
        let network_snippet = self.ensure_network_snippet(req).await?;
        let config =
            self.make_config(req, vendor_snippet.as_deref(), network_snippet.as_deref())?;
        let vm_id: ProxmoxVmId = req.vm.id.into();

        let ctx = CreateVmContext {
            client: self.clone(),
            req,
            vm_id,
            config,
        };

        Pipeline::new(ctx)
            .with_retry_policy(
                RetryPolicy::default()
                    .with_min_delay(Duration::from_secs(3))
                    .with_max_delay(Duration::from_secs(60)),
            )
            .step_with_rollback(
                "create_vm_shell",
                |ctx| {
                    Box::pin(async move {
                        let t_create = ctx
                            .client
                            .create_vm(CreateVm {
                                node: ctx.client.node.clone(),
                                vm_id: ctx.vm_id,
                                config: ctx.config.clone(),
                            })
                            .await?;
                        ctx.client.wait_for_task(&t_create).await?;
                        Ok(())
                    })
                },
                |ctx| {
                    Box::pin(async move {
                        info!("Rolling back: deleting VM {}", ctx.vm_id);
                        ctx.client.destroy_vm(ctx.vm_id).await
                    })
                },
            )
            .step("import_disk", |ctx| {
                Box::pin(async move { ctx.client.import_disk(ctx.req).await })
            })
            .step("resize_disk", |ctx| {
                Box::pin(async move { ctx.client.resize_main_disk(ctx.req).await })
            })
            .step("patch_firewall", |ctx| {
                Box::pin(async move { ctx.client.patch_firewall(ctx.req).await })
            })
            .step("start_vm", |ctx| {
                Box::pin(async move {
                    // try start, otherwise ignore error (maybe its already running)
                    if let Ok(j_start) = ctx.client.start_vm(&ctx.client.node, ctx.vm_id).await
                        && let Err(e) = ctx.client.wait_for_task(&j_start).await
                    {
                        warn!("Failed to start vm: {}", e);
                    }
                    Ok(())
                })
            })
            .execute()
            .await?;

        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> OpResult<()> {
        self.destroy_vm(vm.id.into()).await?;
        // Best-effort: a leaked snippet wastes a few hundred bytes, while failing
        // here would leave the caller believing a destroyed VM still exists.
        if let Err(e) = self.remove_network_snippet(vm.id).await {
            warn!("Failed to remove network snippet for VM {}: {}", vm.id, e);
        }
        Ok(())
    }

    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
        // Remove the primary disk and any orphaned `unused[n]` disks left behind
        // by previous reinstalls so they don't accumulate.
        self.cleanup_vm_disks(vm.id.into(), true).await
    }

    async fn delete_unused_disks(&self, vm: &Vm) -> OpResult<()> {
        // Only remove orphaned `unused[n]` disks — never the live scsi0.
        self.cleanup_vm_disks(vm.id.into(), false).await
    }

    async fn import_template_disk(&self, req: &FullVmInfo) -> OpResult<()> {
        self.import_template_disk(req).await
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let task = self
            .resize_disk(ResizeDiskRequest {
                node: self.node.clone(),
                vm_id: cfg.vm.id.into(),
                disk: "scsi0".to_string(),
                size: cfg.resources()?.disk_size.to_string(),
            })
            .await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn get_vm_state(&self, vm: &Vm) -> OpResult<VmRunningState> {
        let s = self.get_vm_status(&self.node, vm.id.into()).await?;
        Ok(s.into())
    }

    async fn get_all_vm_states(&self) -> OpResult<Vec<(u64, VmRunningState)>> {
        let vm_list = self.list_vms(&self.node).await?;
        let mut states = Vec::new();

        for vm in vm_list {
            // Skip VMs not managed by LNVPS (vmid < 100 has no valid db id).
            if vm.vm_id < 100 {
                continue;
            }
            let vmid: ProxmoxVmId = vm.vm_id.into();
            states.push((vmid.0, vm.into()));
        }

        Ok(states)
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let current_config = self.get_vm_config(&self.node, cfg.vm.id.into()).await?;

        let vendor_snippet = self.ensure_vendor_snippet().await?;
        // Rewrites the file when the assignments changed, so the volume ref can
        // compare equal while the config behind it is new.
        let network_snippet = self.ensure_network_snippet(cfg).await?;
        let mut config =
            self.make_config(cfg, vendor_snippet.as_deref(), network_snippet.as_deref())?;

        // dont re-create the disks
        config.scsi_0 = None;
        config.scsi_1 = None;
        config.efi_disk_0 = None;
        if current_config.config.ssh_keys == config.ssh_keys {
            config.ssh_keys = None;
        }
        if current_config.config.cicustom == config.cicustom {
            config.cicustom = None;
        }

        self.configure_vm(ConfigureVm {
            node: self.node.clone(),
            vm_id: cfg.vm.id.into(),
            current: None,
            snapshot: None,
            digest: Some(current_config.digest),
            config,
        })
        .await?;

        // Apply disk options / throttle limits (requires reading live scsi0 path)
        self.apply_disk_options(cfg).await?;

        Ok(())
    }

    async fn patch_config(&self, cfg: &FullVmInfo) -> OpResult<Vec<String>> {
        let current = self.get_vm_config(&self.node, cfg.vm.id.into()).await?;

        let vendor_snippet = self.ensure_vendor_snippet().await?;
        let network_snippet = self.ensure_network_snippet(cfg).await?;
        let expected =
            self.make_config(cfg, vendor_snippet.as_deref(), network_snippet.as_deref())?;

        let mut drift = Self::config_drift(&current.config, &expected);

        // Disk options (iothread, ssd/discard, throttle limits) live on the
        // scsi0 device string, which is rebuilt from the live volume reference
        // rather than from `make_config` — compare it separately so that VMs
        // created before these options existed converge onto them.
        if let Some(scsi_0) = current.config.scsi_0.as_ref() {
            if *scsi_0 != Self::make_scsi0(scsi_0, cfg) {
                drift.push("scsi_0".to_string());
            }
        }

        if drift.is_empty() {
            return Ok(vec![]);
        }

        info!(
            "Config drift detected for VM {} ({}), re-configuring",
            cfg.vm.id,
            drift.join(", ")
        );
        VmHostClient::configure_vm(self, cfg).await?;
        Ok(drift)
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let vm_id = cfg.vm.id.into();

        // Check and fix cloud-init IP config if it doesn't match expected
        let current_config = self.get_vm_config(&self.node, vm_id).await?;
        let network_snippet = self.ensure_network_snippet(cfg).await?;
        let expected_config = self.make_config(cfg, None, network_snippet.as_deref())?;
        if current_config.config.ip_config != expected_config.ip_config {
            info!(
                "IP config mismatch for VM {}: current={:?}, expected={:?}",
                cfg.vm.id, current_config.config.ip_config, expected_config.ip_config
            );
            self.configure_vm(ConfigureVm {
                node: self.node.clone(),
                vm_id,
                current: None,
                snapshot: None,
                digest: Some(current_config.digest),
                config: VmConfig {
                    ip_config: expected_config.ip_config,
                    ..Default::default()
                },
            })
            .await?;
        }

        // disable fw if not enabled, otherwise configure fw
        let fw_enabled = self
            .config
            .firewall_config
            .as_ref()
            .and_then(|c| c.enable)
            .unwrap_or(false);
        if !fw_enabled {
            self.configure_vm_firewall(
                &self.node,
                vm_id,
                VmFirewallConfig {
                    enable: Some(false),
                    ..Default::default()
                },
            )
            .await?;
            return Ok(());
        }

        let fw_cfg = self.config.firewall_config.as_ref().unwrap();
        // Per-VM default policy (user-configured) overrides the host default when
        // set; otherwise fall back to the host-level configured policy.
        let policy_in = cfg
            .vm
            .fw_policy_in
            .map(Self::convert_vm_firewall_policy)
            .or_else(|| fw_cfg.policy_in.as_ref().map(Self::convert_firewall_policy));
        let policy_out = cfg
            .vm
            .fw_policy_out
            .map(Self::convert_vm_firewall_policy)
            .or_else(|| {
                fw_cfg
                    .policy_out
                    .as_ref()
                    .map(Self::convert_firewall_policy)
            });
        // Use configured firewall options or disable firewall if no config
        let firewall_config = VmFirewallConfig {
            dhcp: fw_cfg.dhcp,
            enable: fw_cfg.enable,
            ip_filter: fw_cfg.ip_filter,
            mac_filter: fw_cfg.mac_filter,
            ndp: fw_cfg.ndp,
            policy_in,
            policy_out,
        };

        // Re-apply firewall configuration
        self.configure_vm_firewall(&self.node, vm_id, firewall_config)
            .await?;

        // Only manage IPsets and rules if firewall is enabled
        // Ensure ipfilter-net0 IPset exists
        if let Err(_) = self
            .list_vm_ipset_entries(&self.node, vm_id, "ipfilter-net0")
            .await
        {
            self.add_vm_ipset(
                &self.node,
                vm_id,
                CreateVmIpsetRequest {
                    name: "ipfilter-net0".to_string(),
                    comment: Some("Allowed addresses for net0".to_string()),
                    digest: None,
                    rename: None,
                },
            )
            .await?;
        }

        // Get existing entries to avoid duplicates
        let existing_entries = self
            .list_vm_ipset_entries(&self.node, vm_id, "ipfilter-net0")
            .await?;
        let existing_cidrs: std::collections::HashSet<String> = existing_entries
            .iter()
            .map(|entry| entry.cidr.clone())
            .collect();

        // Add new IPv4 and IPv6 addresses that don't already exist
        for ip in &cfg.ips {
            if let Ok(addr) = ip.ip.parse::<IpAddr>() {
                match addr {
                    IpAddr::V4(ipv4_addr) => {
                        let ip_str = ipv4_addr.to_string();
                        if !existing_cidrs.contains(&ip_str) {
                            self.add_vm_ipset_entry(
                                &self.node,
                                vm_id,
                                "ipfilter-net0",
                                CreateVmIpsetEntryRequest {
                                    cidr: ip_str,
                                    comment: Some("VM IPv4 address".to_string()),
                                    nomatch: None,
                                },
                            )
                            .await?;
                        }
                    }
                    IpAddr::V6(ipv6_addr) => {
                        let ip_str = ipv6_addr.to_string();
                        if !existing_cidrs.contains(&ip_str) {
                            self.add_vm_ipset_entry(
                                &self.node,
                                vm_id,
                                "ipfilter-net0",
                                CreateVmIpsetEntryRequest {
                                    cidr: ip_str,
                                    comment: Some("VM IPv6 address".to_string()),
                                    nomatch: None,
                                },
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        // NOTE: We intentionally do NOT add a blanket `IN ACCEPT -dest
        // +guest/ipfilter-net0` rule. Anti-spoofing is already provided by the
        // Proxmox `ipfilter` option (source-address filtering via the
        // ipfilter-net0 IPset above). A blanket inbound accept for the VM's own
        // IPs would sit above the default `policy_in` and silently neutralize a
        // default-deny inbound policy. Inbound traffic is governed by
        // `policy_in` plus the user-defined firewall rules (#36) below.
        //
        // Remove any such rule left over from previously-provisioned VMs so the
        // input policy behaves as configured going forward.
        let existing_rules = self.list_vm_firewall_rules(&self.node, vm_id).await?;
        let mut stale_ipfilter_positions: Vec<i32> = existing_rules
            .iter()
            .filter(|rule| {
                rule.action == VmFirewallAction::ACCEPT
                    && rule.dest.as_deref() == Some("+guest/ipfilter-net0")
                    && rule.rule_type == VmFirewallRuleType::In
            })
            .filter_map(|rule| rule.pos)
            .collect();
        stale_ipfilter_positions.sort_unstable_by(|a, b| b.cmp(a));
        for pos in stale_ipfilter_positions {
            self.delete_vm_firewall_rule(&self.node, vm_id, pos).await?;
        }

        // Sync user-defined firewall rules (#36).
        // Remove any previously-applied user rules (tagged with USER_FW_MARKER),
        // then re-add the current set. Deletion is done by position in
        // descending order so positions don't shift mid-loop. PVE inserts new
        // rules at the top, so we add in reverse priority order to preserve the
        // intended top-to-bottom (priority ascending) evaluation order.
        let current_rules = self.list_vm_firewall_rules(&self.node, vm_id).await?;
        let mut stale_positions: Vec<i32> = current_rules
            .iter()
            .filter(|r| {
                r.comment
                    .as_deref()
                    .map(|c| c.starts_with(USER_FW_MARKER))
                    .unwrap_or(false)
            })
            .filter_map(|r| r.pos)
            .collect();
        stale_positions.sort_unstable_by(|a, b| b.cmp(a));
        for pos in stale_positions {
            self.delete_vm_firewall_rule(&self.node, vm_id, pos).await?;
        }

        for rule in cfg.firewall_rules.iter().rev() {
            // A single db rule may expand to multiple Proxmox rules (e.g. an
            // "Any" protocol rule with a port -> tcp + udp).
            for pve_rule in Self::to_pve_firewall_rules(rule) {
                self.add_vm_firewall_rule(&self.node, vm_id, pve_rule)
                    .await?;
            }
        }

        Ok(())
    }

    async fn get_time_series_data(
        &self,
        vm: &Vm,
        series: TimeSeries,
    ) -> OpResult<Vec<TimeSeriesData>> {
        let r = self
            .get_vm_rrd_data(
                vm.id.into(),
                match series {
                    TimeSeries::Hourly => "hour",
                    TimeSeries::Daily => "day",
                    TimeSeries::Weekly => "week",
                    TimeSeries::Monthly => "month",
                    TimeSeries::Yearly => "year",
                },
            )
            .await?;
        Ok(r.into_iter().map(TimeSeriesData::from).collect())
    }

    async fn connect_terminal(&self, vm: &Vm) -> OpResult<TerminalStream> {
        let ssh = self
            .ssh
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SSH config required for terminal proxy"))
            .map_err(OpError::Fatal)?;

        let vm_id: ProxmoxVmId = vm.id.into();
        let socket_path = format!("/var/run/qemu-server/{}.serial0", vm_id);

        let host = self.api.base().host().unwrap().to_string();
        let ssh_user = ssh.user.clone();
        let ssh_key = ssh.key.clone();

        let mut client = SshClient::new();
        client
            .connect((host, 22), &ssh_user, &ssh_key)
            .await
            .map_err(OpError::Transient)?;

        let ssh_channel = client
            .tunnel_unix_socket(std::path::Path::new(&socket_path))
            .await
            .map_err(OpError::Transient)?;

        // mpsc channels: the TerminalStream returned to the caller exposes
        // client_rx (bytes from VM) and server_tx (bytes to VM).
        use tokio::sync::mpsc::channel as mpsc_channel;
        let (client_tx, client_rx) = mpsc_channel::<Vec<u8>>(256);
        let (server_tx, server_rx) = mpsc_channel::<Vec<u8>>(256);

        // The client owns the SSH session the tunnel channel belongs to, so it
        // has to outlive the bridge.
        tokio::spawn(async move {
            ssh_terminal_bridge(ssh_channel, client_tx, server_rx).await;
            drop(client);
        });

        info!("Terminal proxy opened for VM {}", vm_id);
        Ok(TerminalStream {
            rx: client_rx,
            tx: server_tx,
        })
    }
}

impl ProxmoxClient {
    /// Fetch a SHA2SUMS file and extract the checksum for the given filename.
    /// Delegates to the common [`crate::shasum`] parser.
    pub async fn fetch_sha2_from_url(sha2_url: &str, filename: &str) -> Result<String> {
        let entry = crate::shasum::fetch_checksum_for_file(sha2_url, filename).await?;
        Ok(entry.checksum)
    }

    /// Run a shell command on the Proxmox node over SSH.
    ///
    /// Delegates to [`SshClient::run_command`], which opens a session per call.
    async fn ssh_run(&self, command: String) -> Result<(i32, String)> {
        let ssh_cfg = match &self.ssh {
            Some(s) => s,
            None => anyhow::bail!("SSH not configured"),
        };
        let host = crate::host::extract_host_from_url(&self.api.base().to_string());
        SshClient::run_command(host, 22, ssh_cfg.user.clone(), ssh_cfg.key.clone(), command).await
    }

    /// Path to the sidecar file that records the *source* (compressed) checksum
    /// used to produce a decompressed image (`<img>.sha2src`).
    ///
    /// The decompressed `.img` cannot be hashed against the SHASUMS entry (which
    /// covers the compressed artifact), so we persist the source checksum here to
    /// still detect a changed source on later runs.
    fn image_source_checksum_path(filename: &str) -> String {
        format!("/var/lib/vz/template/iso/{filename}.sha2src")
    }

    /// Verify an already-downloaded image's checksum via SSH by running the appropriate
    /// sum utility on the Proxmox node.  Returns `true` if the checksum matches.
    pub async fn verify_image_checksum(
        &self,
        filename: &str,
        _storage: &str,
        expected: &str,
        algorithm: &str,
    ) -> Result<bool> {
        // Proxmox stores ISOs under /var/lib/vz/template/iso/ by default
        let iso_path = format!("/var/lib/vz/template/iso/{filename}");
        let cmd = match algorithm {
            "sha256" | "sha384" | "sha512" => format!("{algorithm}sum {iso_path}"),
            other => anyhow::bail!("Unknown checksum algorithm: {other}"),
        };

        let (exit_code, output) = self.ssh_run(cmd).await?;
        if exit_code != 0 {
            anyhow::bail!("Checksum command failed (exit {}): {}", exit_code, output);
        }

        let actual = output
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        let expected_lower = expected.to_lowercase();
        Ok(actual == expected_lower)
    }

    /// Download a URL directly onto the host over SSH into the ISO storage dir.
    ///
    /// Fetches `url` into `filename` under `/var/lib/vz/template/iso/` using
    /// `wget` (falling back to `curl`), both of which follow HTTP redirects
    /// natively. The download goes to a `.part` temp file that is atomically
    /// moved into place on success, so an interrupted download never leaves a
    /// truncated file at the final path. Used for compressed images, whose real
    /// filename (e.g. `foo.qcow2.xz`) Proxmox's download-url API rejects.
    pub async fn download_image_ssh(&self, url: &str, filename: &str) -> Result<()> {
        let dir = "/var/lib/vz/template/iso";
        let dst = format!("{dir}/{filename}");
        let tmp = format!("{dst}.part");
        // Prefer wget; fall back to curl. `-fL`/redirect-following ensures CDN
        // redirects (common for release mirrors) are handled on the host.
        let cmd = format!(
            "mkdir -p '{dir}' && \
             if command -v wget >/dev/null 2>&1; then \
                 wget -q -O '{tmp}' '{url}'; \
             else \
                 curl -fLsS -o '{tmp}' '{url}'; \
             fi && mv -f '{tmp}' '{dst}'"
        );

        let (exit_code, output) = self.ssh_run(cmd).await?;
        if exit_code != 0 {
            // Best-effort cleanup of any partial download.
            let _ = self.ssh_run(format!("rm -f '{tmp}'")).await;
            anyhow::bail!("Download failed (exit {}): {}", exit_code, output.trim());
        }
        Ok(())
    }

    /// Decompress a downloaded compressed image on the host via SSH.
    ///
    /// Reads `compressed` (e.g. `foo.qcow2.xz`) from the ISO storage directory,
    /// streams it through the appropriate decompressor into a temporary file,
    /// atomically moves the result to `output` (e.g. `foo.img`) and removes the
    /// compressed source. Using a temp file + `mv` ensures a failed or partial
    /// decompression never leaves a truncated image at the final path.
    pub async fn decompress_image(
        &self,
        compression: &str,
        compressed: &str,
        output: &str,
    ) -> Result<()> {
        // Proxmox stores ISOs under /var/lib/vz/template/iso/ by default,
        // matching verify_image_checksum and import_disk_image.
        let dir = "/var/lib/vz/template/iso";
        let src = format!("{dir}/{compressed}");
        let dst = format!("{dir}/{output}");
        let tmp = format!("{dst}.tmp");

        // `-d` decompress, `-c` write to stdout. All of these ship with, or are
        // readily available on, a standard Proxmox VE host.
        let tool = match compression {
            "xz" | "lzma" => "xz -dc",
            "zst" | "zstd" => "zstd -dc",
            "gz" => "gzip -dc",
            "bz2" => "bzip2 -dc",
            "lzo" => "lzop -dc",
            other => anyhow::bail!("Unsupported compression algorithm: {other}"),
        };
        let cmd = format!("{tool} '{src}' > '{tmp}' && mv -f '{tmp}' '{dst}' && rm -f '{src}'");

        let (exit_code, output) = self.ssh_run(cmd).await?;
        if exit_code != 0 {
            // Best-effort cleanup of any partial temp file.
            let _ = self.ssh_run(format!("rm -f '{tmp}'")).await;
            anyhow::bail!(
                "Decompression failed (exit {}): {}",
                exit_code,
                output.trim()
            );
        }
        Ok(())
    }

    /// Delete a storage file on the Proxmox node
    pub async fn delete_storage_file(
        &self,
        node: &str,
        storage: &str,
        filename: &str,
    ) -> OpResult<()> {
        let vol_id = format!("{storage}:iso/{filename}");
        let _: ResponseBase<Option<String>> = self
            .api
            .req::<_, ()>(
                Method::DELETE,
                &format!(
                    "/api2/json/nodes/{}/storage/{}/content/{}",
                    node,
                    storage,
                    urlencoding::encode(&vol_id)
                ),
                None,
            )
            .await?;
        Ok(())
    }
}

/// Wrap a database vm id
#[derive(Debug, Copy, Clone, Default)]
pub struct ProxmoxVmId(u64);

impl ProxmoxVmId {
    /// The underlying LNVPS database id (host vmid minus the +100 offset).
    pub fn inner(&self) -> u64 {
        self.0
    }
}

/// DNS resolvers forced into every guest's `/etc/resolv.conf` via the cloud-init
/// vendor snippet (see [`build_vendor_snippet`]).
const GUEST_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    // IPv6 variants of the same providers (Cloudflare, Google, Quad9).
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "2620:fe::fe",
];

/// Structured `#cloud-config` vendor-data document written to the host snippet
/// and referenced by every VM's `cicustom` (see [`build_vendor_snippet`]).
#[derive(Debug, Serialize)]
struct CloudInitVendorData {
    /// Keep SSH host keys across cloud-init reconfiguration so users don't hit
    /// host-key-changed warnings on IP/key updates.
    ssh_deletekeys: bool,
    /// Force cloud-init to write `/etc/resolv.conf` directly. Only emitted when
    /// there are nameservers to set.
    #[serde(skip_serializing_if = "Option::is_none")]
    manage_resolv_conf: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolv_conf: Option<CloudInitResolvConf>,
}

#[derive(Debug, Serialize)]
struct CloudInitResolvConf {
    nameservers: Vec<String>,
}

/// Build the cloud-init vendor-data snippet applied to every VM on the host.
///
/// Always disables SSH host-key regeneration (`ssh_deletekeys: false`). When
/// `nameservers` is non-empty it also forces cloud-init to write
/// `/etc/resolv.conf` directly (`manage_resolv_conf: true`), which is required
/// for minimal images (e.g. Alpine, NixOS) whose native network renderer does
/// not apply the DNS servers Proxmox hands them (Alpine's busybox ifupdown
/// needs `openresolv`, which the stock cloud image lacks).
///
/// Serialised to YAML from a typed struct via `serde_yaml_ng`, prefixed with the
/// `#cloud-config` header line, so the on-disk snippet is real cloud-config
/// YAML without any fragile hand-built indentation/escaping.
fn build_vendor_snippet(nameservers: &[&str]) -> String {
    let has_dns = !nameservers.is_empty();
    let data = CloudInitVendorData {
        ssh_deletekeys: false,
        manage_resolv_conf: has_dns.then_some(true),
        resolv_conf: has_dns.then(|| CloudInitResolvConf {
            nameservers: nameservers.iter().map(|s| s.to_string()).collect(),
        }),
    };
    format!(
        "#cloud-config\n{}",
        // This struct is always serialisable, so this cannot fail.
        serde_yaml_ng::to_string(&data).expect("serialize cloud-init vendor data")
    )
}

impl From<ProxmoxVmId> for i32 {
    fn from(val: ProxmoxVmId) -> Self {
        val.0 as i32 + 100
    }
}

impl From<u64> for ProxmoxVmId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<i32> for ProxmoxVmId {
    fn from(value: i32) -> Self {
        // LNVPS VMs use vmid = db_id + 100. Saturate instead of wrapping so a
        // non-LNVPS VM with vmid < 100 can't underflow into a huge u64 (release)
        // or panic (debug). Ids below 100 aren't managed by us anyway.
        Self((value as i64 - 100).max(0) as u64)
    }
}

impl Display for ProxmoxVmId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let id: i32 = (*self).into();
        write!(f, "{}", id)
    }
}

impl Serialize for ProxmoxVmId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let id: i32 = (*self).into();
        serializer.serialize_i32(id)
    }
}

impl<'de> Deserialize<'de> for ProxmoxVmId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id = i32::deserialize(deserializer)?;
        Ok(id.into())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TerminalProxyTicket {
    pub port: String,
    pub ticket: String,
    pub upid: String,
    pub user: String,
}

#[derive(Debug, Clone)]
pub struct TaskId {
    pub id: String,
    pub node: String,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Running,
    Stopped,
}

#[derive(Deserialize)]
pub struct TaskStatus {
    pub id: String,
    pub node: String,
    pub pid: u32,
    #[serde(rename = "pstart")]
    pub p_start: u64,
    #[serde(rename = "starttime")]
    pub start_time: u64,
    pub status: TaskState,
    #[serde(rename = "type")]
    pub task_type: String,
    #[serde(rename = "upid")]
    pub up_id: String,
    pub user: String,
    #[serde(rename = "exitstatus")]
    pub exit_status: Option<String>,
}

impl TaskStatus {
    pub fn is_finished(&self) -> bool {
        self.status == TaskState::Stopped
    }

    pub fn is_success(&self) -> bool {
        self.is_finished() && self.exit_status == Some("OK".to_string())
    }
}

#[derive(Deserialize)]
pub struct ResponseBase<T> {
    pub data: T,
}

#[derive(Deserialize)]
pub struct VersionResponse {
    #[serde(rename = "repoid")]
    pub repo_id: String,
    pub version: String,
    pub release: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Unknown,
    Online,
    Offline,
}

#[derive(Debug, Deserialize)]
pub struct NodeResponse {
    #[serde(rename = "node")]
    pub name: String,
    pub status: NodeStatus,
    pub cpu: Option<f32>,
    pub support: Option<String>,
    #[serde(rename = "maxcpu")]
    pub max_cpu: Option<u16>,
    #[serde(rename = "maxmem")]
    pub max_mem: Option<u64>,
    pub mem: Option<u64>,
    pub uptime: Option<u64>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VmStatus {
    Stopped,
    Running,
}

#[derive(Debug, Deserialize)]
pub struct VmInfo {
    pub status: VmStatus,
    #[serde(rename = "vmid")]
    pub vm_id: i32,
    pub cpus: Option<u16>,
    #[serde(rename = "maxdisk")]
    pub max_disk: Option<u64>,
    #[serde(rename = "maxmem")]
    pub max_mem: Option<u64>,
    pub name: Option<String>,
    pub tags: Option<String>,
    pub uptime: Option<u64>,
    pub cpu: Option<f32>,
    pub mem: Option<u64>,
    #[serde(rename = "netin")]
    pub net_in: Option<u64>,
    #[serde(rename = "netout")]
    pub net_out: Option<u64>,
    #[serde(rename = "diskwrite")]
    pub disk_write: Option<u64>,
    #[serde(rename = "diskread")]
    pub disk_read: Option<u64>,
}

impl From<VmInfo> for VmRunningState {
    fn from(vm: VmInfo) -> Self {
        Self {
            timestamp: Utc::now().timestamp() as u64,
            state: match vm.status {
                VmStatus::Stopped => VmRunningStates::Stopped,
                VmStatus::Running => VmRunningStates::Running,
            },
            cpu_usage: vm.cpu.unwrap_or(0.0),
            mem_usage: vm.mem.unwrap_or(0) as f32 / vm.max_mem.unwrap_or(1) as f32,
            uptime: vm.uptime.unwrap_or(0),
            net_in: vm.net_in.unwrap_or(0),
            net_out: vm.net_out.unwrap_or(0),
            disk_write: vm.disk_write.unwrap_or(0),
            disk_read: vm.disk_read.unwrap_or(0),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    LVMThin,
    Dir,
    ZFSPool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageContent {
    Images,
    RootDir,
    Backup,
    ISO,
    VZTmpL,
    Import,
    Snippets,
}

impl FromStr for StorageContent {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "images" => Ok(StorageContent::Images),
            "rootdir" => Ok(StorageContent::RootDir),
            "backup" => Ok(StorageContent::Backup),
            "iso" => Ok(StorageContent::ISO),
            "vztmpl" => Ok(StorageContent::VZTmpL),
            "import" => Ok(StorageContent::Import),
            "snippets" => Ok(StorageContent::Snippets),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeStorage {
    pub content: String,
    pub storage: String,
    #[serde(rename = "type")]
    pub kind: StorageType,
    /// Available storage space in bytes
    #[serde(rename = "avial")]
    pub available: Option<u64>,
    /// Total storage space in bytes
    pub total: Option<u64>,
    /// Used storage space in bytes
    pub used: Option<u64>,
}

impl NodeStorage {
    pub fn contents(&self) -> Vec<StorageContent> {
        self.content
            .split(",")
            .filter_map(|s| StorageContent::from_str(s).ok())
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeDisk {}

#[derive(Debug, Deserialize, Serialize)]
pub struct StorageContentEntry {
    pub format: String,
    pub size: u64,
    #[serde(rename = "volid")]
    pub vol_id: String,
    #[serde(rename = "vmid")]
    pub vm_id: Option<u32>,
}

/// Body of `POST /nodes/{node}/qemu/{vmid}/migrate`.
///
/// Flags are sent as `1`/`0` rather than JSON booleans: that is what every
/// other Proxmox client sends and what the API documents, and an omitted flag
/// (`None`) keeps the node's own default.
#[derive(Debug, Serialize, Default)]
pub struct MigrateVmParams {
    /// Destination node name.
    pub target: String,
    /// Migrate the VM while it keeps running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<u8>,
    /// Copy disks that live on node-local storage as part of the migration.
    #[serde(rename = "with-local-disks", skip_serializing_if = "Option::is_none")]
    pub with_local_disks: Option<u8>,
    /// Storage pool to place the disks in on the destination node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targetstorage: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ResizeDiskRequest {
    pub node: String,
    #[serde(rename = "vmid")]
    pub vm_id: ProxmoxVmId,
    pub disk: String,
    /// The new size.
    ///
    /// With the `+` sign the value is added to the actual size of the volume and without it,
    /// the value is taken as an absolute one. Shrinking disk size is not supported.
    pub size: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ImportDiskImageRequest {
    /// VM id
    pub vm_id: ProxmoxVmId,
    /// Node name
    pub node: String,
    /// Storage pool to import disk to
    pub storage: String,
    /// Disk name (scsi0 etc)
    pub disk: String,
    /// Image filename on disk inside the disk storage dir
    pub image: String,
    /// If the disk is an SSD and discard should be enabled
    pub is_ssd: bool,
    /// Maximum disk read IOPS (None = uncapped)
    pub iops_rd: Option<u32>,
    /// Maximum disk write IOPS (None = uncapped)
    pub iops_wr: Option<u32>,
    /// Maximum disk read throughput in MB/s (None = uncapped)
    pub mbps_rd: Option<u32>,
    /// Maximum disk write throughput in MB/s (None = uncapped)
    pub mbps_wr: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VmBios {
    SeaBios,
    OVMF,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct CreateVm {
    pub node: String,
    #[serde(rename = "vmid")]
    pub vm_id: ProxmoxVmId,
    #[serde(flatten)]
    pub config: VmConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ConfigureVm {
    pub node: String,
    #[serde(rename = "vmid")]
    pub vm_id: ProxmoxVmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(flatten)]
    pub config: VmConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct HashedVmConfig {
    pub digest: String,
    #[serde(flatten)]
    pub config: VmConfig,
}

/// A Proxmox VM config.
///
/// Compound values (`netN`, `ipconfigN`, disks, `cicustom`, `sshkeys`) are
/// Proxmox "property strings"; they are typed here (see
/// [`crate::host::proxmox_config`]) so they can be read field-wise and compared
/// with `==` instead of by string matching.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct VmConfig {
    #[serde(rename = "onboot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "crate::deserialize_int_to_bool")]
    pub on_boot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balloon: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bios: Option<VmBios>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cores: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(rename = "ipconfig0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub ip_config: Option<IpConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "net0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub net: Option<NetDevice>,
    #[serde(rename = "ostype")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
    #[serde(rename = "scsi0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub scsi_0: Option<DiskDevice>,
    #[serde(rename = "scsi1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub scsi_1: Option<DiskDevice>,
    #[serde(rename = "scsihw")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scsi_hw: Option<String>,
    #[serde(rename = "sshkeys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub ssh_keys: Option<SshKeys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(rename = "efidisk0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub efi_disk_0: Option<DiskDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "crate::deserialize_int_to_bool")]
    pub kvm: Option<bool>,
    #[serde(rename = "serial0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_0: Option<String>,
    /// CPU usage limit as a fraction of allocated cores (e.g. 0.5 = 50%; 0 = uncapped)
    #[serde(rename = "cpulimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f32>,
    /// Custom cloud-init config files (e.g. "vendor=local:snippets/lnvps-vendor.yaml")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, with = "opt_prop_string")]
    pub cicustom: Option<CiCustom>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RrdDataPoint {
    pub time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f32>,
    #[serde(rename = "mem")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<f32>,
    #[serde(rename = "maxmem")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_size: Option<u64>,
    #[serde(rename = "netin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_in: Option<f32>,
    #[serde(rename = "netout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_out: Option<f32>,
    #[serde(rename = "diskwrite")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_write: Option<f32>,
    #[serde(rename = "diskread")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_read: Option<f32>,
}

impl From<RrdDataPoint> for TimeSeriesData {
    fn from(value: RrdDataPoint) -> Self {
        Self {
            timestamp: value.time,
            cpu: value.cpu.unwrap_or(0.0),
            memory: value.memory.unwrap_or(0.0),
            memory_size: value.memory_size.unwrap_or(0),
            net_in: value.net_in.unwrap_or(0.0),
            net_out: value.net_out.unwrap_or(0.0),
            disk_write: value.disk_write.unwrap_or(0.0),
            disk_read: value.disk_read.unwrap_or(0.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmFirewallConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(rename = "ipfilter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_filter: Option<bool>,
    #[serde(rename = "macfilter")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_filter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ndp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_in: Option<VmFirewallPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_out: Option<VmFirewallPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmFirewallPolicy {
    ACCEPT,
    REJECT,
    DROP,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum VmFirewallAction {
    #[default]
    ACCEPT,
    REJECT,
    DROP,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum VmFirewallRuleType {
    #[default]
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmIpsetInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmIpsetEntry {
    pub cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nomatch: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CreateVmIpsetRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rename: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateVmIpsetEntryRequest {
    pub cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nomatch: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmFirewallRule {
    pub action: VmFirewallAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(rename = "macro")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macro_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pos: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sport: Option<String>,
    #[serde(rename = "type")]
    pub rule_type: VmFirewallRuleType,
}

/// I/O bridge between an SSH channel (QEMU serial socket) and the async mpsc
/// channels exposed as a [`TerminalStream`].
async fn ssh_terminal_bridge(
    mut channel: russh::Channel<russh::client::Msg>,
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut server_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            // --- upstream: serial socket → WebSocket client ---
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        if client_tx.send(data.to_vec()).await.is_err() {
                            // Receiver dropped (WebSocket closed).
                            break;
                        }
                    }
                    // EOF or channel closed by the remote side.
                    Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
            // --- downstream: WebSocket client → serial socket ---
            data = server_rx.recv() => {
                match data {
                    Some(data) => {
                        if let Err(e) = channel.data(data.as_slice()).await {
                            log::warn!("Terminal write error: {}", e);
                            break;
                        }
                    }
                    // Sender dropped (WebSocket closed).
                    None => break,
                }
            }
        }
    }

    let _ = channel.close().await;
    info!("Terminal proxy connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MB;
    use crate::host::proxmox_config::{Ipv4Setting, Ipv6Setting, VolumeRef};
    use crate::host::tests::mock_full_vm;
    use lnvps_db::IpRange;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_make_scsi0() {
        let cfg = mock_full_vm();

        // The live volume and size are kept; every option is rebuilt from the DB.
        let live: DiskDevice = "ssd:vm-100-disk-0,size=100G,iops_rd=99".parse().unwrap();
        let built = ProxmoxClient::make_scsi0(&live, &cfg);
        assert_eq!(built.volume, VolumeRef::new("ssd", "vm-100-disk-0"));
        assert_eq!(built.size.as_deref(), Some("100G"));
        assert!(
            built.discard && built.ssd,
            "ssd disks get discard/ssd hints"
        );
        assert!(built.iothread, "iothread is always on");
        assert_eq!(built.iops_rd, None, "stale throttle values are dropped");

        // Rebuilding an already-correct device is a no-op, so a VM that is up to
        // date never reports scsi0 drift.
        assert_eq!(ProxmoxClient::make_scsi0(&built, &cfg), built);

        // A VM created before iothread existed drifts.
        let old: DiskDevice = "ssd:vm-100-disk-0,size=100G,discard=on,ssd=1"
            .parse()
            .unwrap();
        assert_ne!(old, ProxmoxClient::make_scsi0(&old, &cfg));
    }

    #[test]
    fn test_config_drift() {
        let expected = VmConfig {
            name: Some("VM100".to_string()),
            cores: Some(4),
            memory: Some("2048".to_string()),
            net: Some(
                "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0,firewall=1"
                    .parse()
                    .unwrap(),
            ),
            ip_config: Some("ip=1.2.3.4/24,gw=1.2.3.1".parse().unwrap()),
            ssh_keys: Some(SshKeys::one("ssh-ed25519 AAAA test")),
            ..Default::default()
        };

        // Same config (with Proxmox-style re-ordering/casing) => no drift
        let current = VmConfig {
            name: Some("VM100".to_string()),
            cores: Some(4),
            memory: Some("2048".to_string()),
            net: Some(
                "bridge=vmbr0,firewall=1,virtio=AA:BB:CC:DD:EE:FF"
                    .parse()
                    .unwrap(),
            ),
            ip_config: Some("gw=1.2.3.1,ip=1.2.3.4/24".parse().unwrap()),
            ssh_keys: Some(
                urlencoding::encode("ssh-ed25519 AAAA test\n")
                    .parse()
                    .unwrap(),
            ),
            // Fields not present in the expected config are ignored
            scsi_0: Some("local-lvm:vm-100-disk-0".parse().unwrap()),
            ..Default::default()
        };
        assert!(ProxmoxClient::config_drift(&current, &expected).is_empty());

        // Changed resources + missing ip config => drift on those fields only
        let drifted = VmConfig {
            cores: Some(2),
            memory: Some("1024".to_string()),
            ip_config: None,
            ..current.clone()
        };
        let drift = ProxmoxClient::config_drift(&drifted, &expected);
        assert_eq!(drift, vec!["cores", "memory", "ip_config"]);

        // A different ssh key is detected
        let drifted = VmConfig {
            ssh_keys: Some(SshKeys::one("ssh-ed25519 BBBB other")),
            ..current.clone()
        };
        assert_eq!(
            ProxmoxClient::config_drift(&drifted, &expected),
            vec!["ssh_keys"]
        );
    }

    #[test]
    fn test_build_vendor_snippet() {
        // Every snippet must carry the cloud-config header and parse as YAML.
        let header = "#cloud-config\n";

        // No nameservers -> ssh_deletekeys only, no resolv_conf keys.
        let empty = build_vendor_snippet(&[]);
        assert!(empty.starts_with(header));
        assert!(!empty.contains("manage_resolv_conf"));
        assert!(!empty.contains("resolv_conf"));
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&empty).unwrap();
        assert_eq!(v["ssh_deletekeys"], serde_yaml_ng::Value::Bool(false));

        // With nameservers (incl. IPv6) -> manage_resolv_conf + resolv_conf set.
        let s = build_vendor_snippet(&["1.1.1.1", "2606:4700:4700::1111"]);
        assert!(s.starts_with(header));
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&s).unwrap();
        assert_eq!(v["ssh_deletekeys"], serde_yaml_ng::Value::Bool(false));
        assert_eq!(v["manage_resolv_conf"], serde_yaml_ng::Value::Bool(true));
        assert_eq!(v["resolv_conf"]["nameservers"][0], "1.1.1.1");
        assert_eq!(v["resolv_conf"]["nameservers"][1], "2606:4700:4700::1111");

        // The production constant covers both IPv4 and IPv6 resolvers, and the
        // body must be valid cloud-config YAML.
        let prod = build_vendor_snippet(GUEST_DNS_SERVERS);
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&prod).unwrap();
        let ns = v["resolv_conf"]["nameservers"].as_sequence().unwrap();
        assert!(ns.iter().any(|n| n.as_str() == Some("8.8.8.8")));
        assert!(ns.iter().any(|n| n.as_str() == Some("2620:fe::fe")));
    }

    #[test]
    fn test_image_source_checksum_path() {
        assert_eq!(
            ProxmoxClient::image_source_checksum_path("nixos-24.11-cloudinit-x86_64.img"),
            "/var/lib/vz/template/iso/nixos-24.11-cloudinit-x86_64.img.sha2src"
        );
        // Distinct images produce distinct sidecar paths.
        assert_ne!(
            ProxmoxClient::image_source_checksum_path("a.img"),
            ProxmoxClient::image_source_checksum_path("b.img")
        );
    }

    #[test]
    fn test_config() -> Result<()> {
        let cfg = mock_full_vm();
        let template = cfg.template.clone().unwrap();

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };

        let p = ProxmoxClient::new(
            "http://localhost:8006".parse()?,
            "",
            "",
            None,
            q_cfg.clone(),
            None,
        );

        let vm = p.make_config(&cfg, None, None)?;
        assert_eq!(vm.cpu, Some(q_cfg.cpu));
        assert_eq!(vm.cores, Some(template.cpu as i32));
        assert_eq!(vm.memory, Some((template.memory / MB).to_string()));
        // No balloon floor configured => no balloon key
        assert_eq!(vm.balloon, None);
        assert_eq!(vm.on_boot, Some(true));
        let net = vm.net.as_ref().unwrap();
        assert_eq!(net.tag, Some(100));
        assert!(net.firewall);
        // One address per family: the fixture holds two IPv4s, and repeating
        // `ip=` in the property string is not something the guest can act on.
        assert_eq!(
            vm.ip_config,
            Some("ip=192.168.1.2/16,gw=192.168.1.1,ip6=auto".parse().unwrap())
        );
        Ok(())
    }

    #[test]
    fn test_config_balloon_floor() -> Result<()> {
        let cfg = mock_full_vm();
        let template = cfg.template.clone().unwrap();
        let memory_mb = template.memory / MB;

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: Some(90),
            firewall_config: None,
        };
        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg, None, None)?;
        // Full memory is still the sold amount; balloon is the 90% floor.
        assert_eq!(vm.memory, Some(memory_mb.to_string()));
        assert_eq!(vm.balloon, Some((memory_mb * 90 / 100) as i32));
        Ok(())
    }

    /// Regression test: when the gateway CIDR is wider than the allocation range,
    /// the IP config should use the gateway's prefix so the OS sees the gateway
    /// as inside the subnet (fixes Debian 13 compatibility).
    #[test]
    fn test_config_widens_cidr_to_gateway() -> Result<()> {
        let mut cfg = mock_full_vm();
        // Override range 1: allocation /26 (185.18.221.64-127), gateway in wider /24
        cfg.ranges[0] = IpRange {
            id: 1,
            cidr: "185.18.221.64/26".to_string(),
            gateway: "185.18.221.1/24".to_string(),
            enabled: true,
            region_id: 1,
            ..Default::default()
        };
        // Update the assigned IP to be within the /26 allocation range
        cfg.ips[0].ip = "185.18.221.65".to_string();

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg, None, None)?;
        let ip_config = vm.ip_config.unwrap();
        // The IP should use /24 (gateway prefix), not /26 (range prefix),
        // so the gateway 185.18.221.1 is inside the VM's subnet.
        assert_eq!(
            ip_config.ip,
            Some(Ipv4Setting::Static("185.18.221.65/24".parse()?)),
            "expected /24 (gateway prefix)"
        );
        assert_eq!(ip_config.gateway, Some("185.18.221.1".parse()?));
        Ok(())
    }

    #[test]
    fn test_kvm_field_deserializes_integer_to_bool() {
        // Test that KVM field can deserialize from integer (as Proxmox sends it)
        let json_with_int = r#"{"kvm":1}"#;
        let config: VmConfig =
            serde_json::from_str(json_with_int).expect("Should deserialize integer to bool");
        assert_eq!(config.kvm, Some(true));

        let json_with_zero = r#"{"kvm":0}"#;
        let config: VmConfig =
            serde_json::from_str(json_with_zero).expect("Should deserialize 0 to false");
        assert_eq!(config.kvm, Some(false));

        // Test that it still works with boolean values
        let json_with_bool = r#"{"kvm":true}"#;
        let config: VmConfig =
            serde_json::from_str(json_with_bool).expect("Should deserialize boolean");
        assert_eq!(config.kvm, Some(true));

        // Test null/missing value
        let json_empty = r#"{}"#;
        let config: VmConfig =
            serde_json::from_str(json_empty).expect("Should handle missing field");
        assert_eq!(config.kvm, None);

        // Test the actual JSON from the error message to ensure it parses correctly
        let actual_proxmox_json = r#"{"smbios1":"uuid=42ecc256-a7c5-4d93-b630-0e7a06c051c2","cpu":"host","scsihw":"virtio-scsi-pci","bios":"ovmf","ostype":"l26","serial0":"socket","net0":"virtio=bc:24:11:4e:8f:d1,bridge=vmbr0,firewall=1","meta":"creation-qemu=10.0.2,ctime=1754900283","scsi0":"local-zfs:vm-111-disk-1,discard=on,size=160G,ssd=1","scsi1":"local-zfs:vm-111-cloudinit,media=cdrom","vmgenid":"abac705c-31ed-4b75-8587-8c86d5c810c4","digest":"18389648fd69603dd93ab0c443e1f32267f6c436","efidisk0":"local-zfs:vm-111-disk-0,efitype=4m,size=1M","machine":"q35","kvm":1,"onboot":1,"sshkeys":"ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAILnyd2niY8ht8KRea6M6y%2BTBx08F7zRdhBlKjk7aywMT","memory":"4096","cores":4,"ipconfig0":"ip=10.100.1.174/24,gw=10.100.1.1,ip6=auto","boot":"order=scsi0"}"#;
        let config: VmConfig = serde_json::from_str(actual_proxmox_json)
            .expect("Should deserialize actual Proxmox JSON");
        assert_eq!(config.kvm, Some(true)); // kvm:1 should become Some(true)
        assert_eq!(config.on_boot, Some(true)); // onboot:1 should become Some(true)
    }

    #[test]
    fn test_network_rate_converts_mbps_to_mb_per_sec() -> Result<()> {
        // network_mbps is stored in Mbit/s; Proxmox rate= expects MB/s, so we divide by 8
        let mut cfg = mock_full_vm();
        cfg.template.as_mut().unwrap().network_mbps = Some(800);

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg, None, None)?;
        // 800 Mbit/s ÷ 8 = 100 MB/s
        assert_eq!(vm.net.unwrap().rate, Some(100.0));
        Ok(())
    }

    #[test]
    fn test_cpu_limit_propagated() -> Result<()> {
        let mut cfg = mock_full_vm();
        cfg.template.as_mut().unwrap().cpu_limit = Some(0.5);

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg, None, None)?;
        assert_eq!(vm.cpu_limit, Some(0.5));
        Ok(())
    }

    #[test]
    fn test_to_pve_firewall_rule_inbound_tcp_port_range() {
        let rule = lnvps_db::VmFirewallRule {
            id: 42,
            vm_id: 1,
            priority: 0,
            direction: lnvps_db::VmFirewallDirection::Inbound,
            protocol: lnvps_db::VmFirewallProtocol::Tcp,
            action: lnvps_db::VmFirewallRuleAction::Accept,
            src_cidr: Some("1.2.3.0/24".to_string()),
            dst_port_start: Some(80),
            dst_port_end: Some(443),
            enabled: true,
            created: Default::default(),
            updated: Default::default(),
        };
        let pve = ProxmoxClient::to_pve_firewall_rules(&rule);
        assert_eq!(pve.len(), 1);
        let pve = &pve[0];
        assert_eq!(pve.action, VmFirewallAction::ACCEPT);
        assert_eq!(pve.rule_type, VmFirewallRuleType::In);
        assert_eq!(pve.proto.as_deref(), Some("tcp"));
        assert_eq!(pve.dport.as_deref(), Some("80:443"));
        assert_eq!(pve.source.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(pve.enable, Some(1));
        assert_eq!(pve.comment.as_deref(), Some("lnvps-fw:42"));
    }

    #[test]
    fn test_to_pve_firewall_rule_outbound_any_single_port_expands_to_tcp_udp() {
        let rule = lnvps_db::VmFirewallRule {
            id: 7,
            vm_id: 1,
            priority: 3,
            direction: lnvps_db::VmFirewallDirection::Outbound,
            protocol: lnvps_db::VmFirewallProtocol::Any,
            action: lnvps_db::VmFirewallRuleAction::Drop,
            src_cidr: None,
            dst_port_start: Some(53),
            dst_port_end: None,
            enabled: false,
            created: Default::default(),
            updated: Default::default(),
        };
        // An "Any" protocol rule with a port expands to one tcp + one udp rule,
        // each carrying the port (Proxmox has no protocol-less dport).
        let pve = ProxmoxClient::to_pve_firewall_rules(&rule);
        assert_eq!(pve.len(), 2);
        assert_eq!(pve[0].proto.as_deref(), Some("tcp"));
        assert_eq!(pve[1].proto.as_deref(), Some("udp"));
        for r in &pve {
            assert_eq!(r.action, VmFirewallAction::DROP);
            assert_eq!(r.rule_type, VmFirewallRuleType::Out);
            assert_eq!(r.dport.as_deref(), Some("53"));
            assert_eq!(r.source, None);
            assert_eq!(r.enable, Some(0));
            assert_eq!(r.comment.as_deref(), Some("lnvps-fw:7"));
        }
    }

    #[test]
    fn test_to_pve_firewall_rule_any_no_port_single_rule() {
        // "Any" protocol with no port stays a single protocol-less rule so
        // Proxmox doesn't get a dport without a proto (issue #165).
        let rule = lnvps_db::VmFirewallRule {
            id: 8,
            vm_id: 1,
            priority: 0,
            direction: lnvps_db::VmFirewallDirection::Inbound,
            protocol: lnvps_db::VmFirewallProtocol::Any,
            action: lnvps_db::VmFirewallRuleAction::Accept,
            src_cidr: None,
            dst_port_start: None,
            dst_port_end: None,
            enabled: true,
            created: Default::default(),
            updated: Default::default(),
        };
        let pve = ProxmoxClient::to_pve_firewall_rules(&rule);
        assert_eq!(pve.len(), 1);
        assert_eq!(pve[0].proto, None);
        assert_eq!(pve[0].dport, None);
        let json = serde_json::to_string(&pve[0]).unwrap();
        assert!(!json.contains("dport"), "json: {json}");
        assert!(!json.contains("proto"), "json: {json}");
    }

    #[test]
    fn test_to_pve_firewall_rule_any_proto_port_range_expands_to_tcp_udp() {
        // Issue #165: a port with "Any" protocol must be expanded to tcp + udp
        // rules rather than dropping the port (Proxmox rejects a protocol-less
        // dport with 400 "'dport' requires this property").
        let rule = lnvps_db::VmFirewallRule {
            id: 165,
            vm_id: 1,
            priority: 0,
            direction: lnvps_db::VmFirewallDirection::Inbound,
            protocol: lnvps_db::VmFirewallProtocol::Any,
            action: lnvps_db::VmFirewallRuleAction::Accept,
            src_cidr: None,
            dst_port_start: Some(80),
            dst_port_end: Some(443),
            enabled: true,
            created: Default::default(),
            updated: Default::default(),
        };
        let pve = ProxmoxClient::to_pve_firewall_rules(&rule);
        assert_eq!(pve.len(), 2);
        assert_eq!(pve[0].proto.as_deref(), Some("tcp"));
        assert_eq!(pve[1].proto.as_deref(), Some("udp"));
        for r in &pve {
            assert_eq!(r.dport.as_deref(), Some("80:443"));
            // Each expanded rule is a valid Proxmox rule (proto set with dport).
            let json = serde_json::to_string(r).unwrap();
            assert!(json.contains("dport"), "json: {json}");
            assert!(json.contains("proto"), "json: {json}");
        }
    }

    #[test]
    fn test_proxmox_vm_id_inner_maps_to_db_id() {
        // Host vmid 1566 -> db id 1466
        let id: ProxmoxVmId = 1566i32.into();
        assert_eq!(id.inner(), 1466);
        // Round trip back to host vmid
        let host_id: i32 = id.into();
        assert_eq!(host_id, 1566);
    }

    #[test]
    fn test_to_pve_firewall_rule_reject_action() {
        let rule = lnvps_db::VmFirewallRule {
            id: 9,
            vm_id: 1,
            priority: 0,
            direction: lnvps_db::VmFirewallDirection::Inbound,
            protocol: lnvps_db::VmFirewallProtocol::Tcp,
            action: lnvps_db::VmFirewallRuleAction::Reject,
            src_cidr: None,
            dst_port_start: Some(25),
            dst_port_end: None,
            enabled: true,
            created: Default::default(),
            updated: Default::default(),
        };
        let pve = ProxmoxClient::to_pve_firewall_rules(&rule);
        assert_eq!(pve.len(), 1);
        assert_eq!(pve[0].action, VmFirewallAction::REJECT);
    }

    #[test]
    fn test_convert_vm_firewall_policy() {
        assert!(matches!(
            ProxmoxClient::convert_vm_firewall_policy(lnvps_db::VmFirewallPolicy::Accept),
            VmFirewallPolicy::ACCEPT
        ));
        assert!(matches!(
            ProxmoxClient::convert_vm_firewall_policy(lnvps_db::VmFirewallPolicy::Drop),
            VmFirewallPolicy::DROP
        ));
        assert!(matches!(
            ProxmoxClient::convert_vm_firewall_policy(lnvps_db::VmFirewallPolicy::Reject),
            VmFirewallPolicy::REJECT
        ));
    }

    #[test]
    fn test_no_limits_produces_no_rate_or_cpulimit() -> Result<()> {
        // When no limits are set, rate= must not appear in net and cpu_limit must be None
        let cfg = mock_full_vm(); // template has all limits as None

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg, None, None)?;
        assert_eq!(
            vm.net.unwrap().rate,
            None,
            "rate= must not appear when network_mbps is None"
        );
        assert_eq!(vm.cpu_limit, None);
        Ok(())
    }

    /// Regression: converting an i32 vmid below 100 (a VM not managed by LNVPS)
    /// must not underflow/panic. Ids >= 100 map to db_id = vmid - 100.
    #[test]
    fn test_proxmox_vm_id_from_i32_no_underflow() {
        // Below 100 saturates to 0 rather than wrapping / panicking.
        assert_eq!(ProxmoxVmId::from(0i32).0, 0);
        assert_eq!(ProxmoxVmId::from(50i32).0, 0);
        assert_eq!(ProxmoxVmId::from(99i32).0, 0);
        // Normal LNVPS ids map correctly.
        assert_eq!(ProxmoxVmId::from(100i32).0, 0);
        assert_eq!(ProxmoxVmId::from(101i32).0, 1);
        assert_eq!(ProxmoxVmId::from(600i32).0, 500);
        // Round-trip for a valid id.
        let id = ProxmoxVmId::from(1234u64);
        let back: i32 = id.into();
        assert_eq!(back, 1334);
    }

    #[test]
    fn test_cicustom_set_when_vendor_snippet_provided() -> Result<()> {
        let cfg = mock_full_vm();
        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "host".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        // With vendor snippet
        let vm = p.make_config(&cfg, Some("local:snippets/lnvps-vendor.yaml"), None)?;
        assert_eq!(
            vm.cicustom,
            Some("vendor=local:snippets/lnvps-vendor.yaml".parse().unwrap())
        );

        // Without vendor snippet
        let vm = p.make_config(&cfg, None, None)?;
        assert_eq!(vm.cicustom, None);

        // Both snippets
        let vm = p.make_config(
            &cfg,
            Some("local:snippets/lnvps-vendor.yaml"),
            Some("local:snippets/lnvps-net-1.yaml"),
        )?;
        assert_eq!(
            vm.cicustom,
            Some(
                "vendor=local:snippets/lnvps-vendor.yaml,network=local:snippets/lnvps-net-1.yaml"
                    .parse()
                    .unwrap()
            )
        );

        Ok(())
    }

    /// A VM with one address per family stays on the built-in `ipconfig` path, so
    /// nothing already deployed is reconfigured by the snippet feature.
    /// One IPv4 plus one IPv6 on a single range each, which is what every VM
    /// holds today.
    fn single_address_vm() -> FullVmInfo {
        let mut cfg = mock_full_vm();
        cfg.ranges = vec![IpRange {
            id: 1,
            cidr: "185.18.221.64/26".to_string(),
            gateway: "185.18.221.1/24".to_string(),
            enabled: true,
            region_id: 1,
            ..Default::default()
        }];
        cfg.ips = vec![lnvps_db::VmIpAssignment {
            id: 1,
            vm_id: cfg.vm.id,
            ip_range_id: 1,
            ip: "185.18.221.65".to_string(),
            ..Default::default()
        }];
        cfg
    }

    /// A VM with one address per family stays on the built-in `ipconfig` path, so
    /// nothing already deployed is reconfigured by the snippet feature.
    #[test]
    fn test_no_network_snippet_for_single_address() -> Result<()> {
        assert!(ProxmoxClient::make_network_config(&single_address_vm())?.is_none());
        Ok(())
    }

    #[test]
    fn test_network_snippet_carries_every_ipv4() -> Result<()> {
        let mut cfg = single_address_vm();
        cfg.ips.push(lnvps_db::VmIpAssignment {
            id: 2,
            ip: "185.18.221.66".to_string(),
            ip_range_id: 1,
            vm_id: cfg.vm.id,
            ..Default::default()
        });

        let net = ProxmoxClient::make_network_config(&cfg)?.expect("two v4 needs a snippet");

        // Both addresses, widened to the gateway prefix so the gateway is on-link.
        assert!(net.contains("- 185.18.221.65/24"), "{net}");
        assert!(net.contains("- 185.18.221.66/24"), "{net}");
        // Matched by MAC, not by guest interface name.
        assert!(net.contains("macaddress: ff:ff:ff:ff:ff:fe"), "{net}");
        // One default route, not one per address.
        assert_eq!(1, net.matches("to: default").count(), "{net}");
        assert!(net.contains("via: 185.18.221.1"), "{net}");
        Ok(())
    }

    /// `ipconfig[n]` holds one address per family, so a VM carrying more must not
    /// have the extras repeated into that property string — they live in the
    /// snippet. A repeated key is either rejected by PVE or silently contradicts
    /// the snippet, and nothing in CI reaches a real host to find out.
    #[test]
    fn test_ipconfig_holds_one_address_per_family() -> Result<()> {
        let mut cfg = single_address_vm();
        cfg.ips.push(lnvps_db::VmIpAssignment {
            id: 2,
            ip: "185.18.221.66".to_string(),
            ip_range_id: 1,
            vm_id: cfg.vm.id,
            ..Default::default()
        });
        cfg.ranges.push(IpRange {
            id: 3,
            cidr: "fd00::/64".to_string(),
            gateway: "fd00::1".to_string(),
            enabled: true,
            region_id: 1,
            ..Default::default()
        });
        for (id, ip) in [(3u64, "fd00::2"), (4, "fd00::3")] {
            cfg.ips.push(lnvps_db::VmIpAssignment {
                id,
                ip: ip.to_string(),
                ip_range_id: 3,
                vm_id: cfg.vm.id,
                ..Default::default()
            });
        }

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "host".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);
        let vm = p.make_config(&cfg, None, Some("local:snippets/lnvps-net-1.yaml"))?;
        let ip_config = vm.ip_config.unwrap();

        // One address per family — the first assignment of each, matching what
        // the snippet routes.
        assert_eq!(
            ip_config.ip,
            Some(Ipv4Setting::Static("185.18.221.65/24".parse()?))
        );
        assert_eq!(
            ip_config.ip6,
            Some(Ipv6Setting::Static("fd00::2/64".parse()?))
        );
        Ok(())
    }

    /// Addresses from a second range must not add a second default route.
    #[test]
    fn test_network_snippet_has_one_default_route_per_family() -> Result<()> {
        let mut cfg = single_address_vm();
        cfg.ranges.push(IpRange {
            id: 2,
            cidr: "185.18.221.128/25".to_string(),
            gateway: "185.18.221.2/24".to_string(),
            enabled: true,
            region_id: 1,
            ..Default::default()
        });
        cfg.ips.push(lnvps_db::VmIpAssignment {
            id: 2,
            ip: "185.18.221.130".to_string(),
            ip_range_id: 2,
            vm_id: cfg.vm.id,
            ..Default::default()
        });

        let net = ProxmoxClient::make_network_config(&cfg)?.expect("two v4 needs a snippet");
        assert_eq!(1, net.matches("to: default").count(), "{net}");
        // The first assignment's gateway wins, as it does via `ipconfig`.
        assert!(net.contains("via: 185.18.221.1"), "{net}");
        assert!(net.contains("- 185.18.221.130/24"), "{net}");
        Ok(())
    }

    /// A SLAAC range contributes autoconfiguration rather than a static address.
    #[test]
    fn test_network_snippet_uses_accept_ra_for_slaac() -> Result<()> {
        let mut cfg = single_address_vm();
        cfg.ips.push(lnvps_db::VmIpAssignment {
            id: 2,
            ip: "185.18.221.66".to_string(),
            ip_range_id: 1,
            vm_id: cfg.vm.id,
            ..Default::default()
        });
        cfg.ranges.push(IpRange {
            id: 3,
            cidr: "fd00::/64".to_string(),
            gateway: "fd00::1".to_string(),
            enabled: true,
            region_id: 1,
            allocation_mode: IpRangeAllocationMode::SlaacEui64,
            ..Default::default()
        });
        cfg.ips.push(lnvps_db::VmIpAssignment {
            id: 3,
            ip: "fd00::ffff:ffff:ffff:fffe".to_string(),
            ip_range_id: 3,
            vm_id: cfg.vm.id,
            ..Default::default()
        });

        let net = ProxmoxClient::make_network_config(&cfg)?.expect("two v4 needs a snippet");
        assert!(net.contains("accept-ra: true"), "{net}");
        assert!(
            !net.contains("fd00::"),
            "SLAAC address must not be pinned: {net}"
        );
        Ok(())
    }

    /// Regression test for issue #94.
    ///
    /// `wait_for_vm_stopped` must keep polling until the Proxmox API reports
    /// `stopped`, even when earlier responses report `running`.  Before the fix,
    /// `stop_vm` returned as soon as the Proxmox *task* completed, without
    /// verifying the VM process had actually halted — allowing `unlink_primary_disk`
    /// to race with a still-live VM and leave an orphaned disk.
    #[tokio::test]
    async fn test_wait_for_vm_stopped_polls_until_stopped() -> Result<()> {
        let server = MockServer::start().await;

        let running_body = serde_json::json!({
            "data": { "vmid": 100, "status": "running" }
        });
        let stopped_body = serde_json::json!({
            "data": { "vmid": 100, "status": "stopped" }
        });

        // First two polls return "running"; third returns "stopped"
        Mock::given(method("GET"))
            .and(path_regex(r".*/status/current$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&running_body))
            .up_to_n_times(2)
            .expect(2)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r".*/status/current$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&stopped_body))
            .expect(1)
            .mount(&server)
            .await;

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let client = ProxmoxClient::new(server.uri().parse()?, "pve", "", None, q_cfg, None);

        // Use a short poll interval so the test completes quickly
        client
            .wait_for_vm_stopped_with_interval(
                ProxmoxVmId(100),
                std::time::Duration::from_millis(10),
            )
            .await
            .expect("wait_for_vm_stopped should succeed once status is stopped");

        // wiremock verifies the expected call counts on drop
        Ok(())
    }

    /// The migrate call must reach the source node with the destination node,
    /// and must only ask for a disk copy when the disk actually has to move
    /// (issue #66). Sending `with-local-disks` for a VM on shared storage turns
    /// a seconds-long migration into a full disk transfer.
    #[tokio::test]
    async fn test_migrate_vm_request_body() -> Result<()> {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r".*/qemu/\d+/migrate$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:node:0:0:task"})),
            )
            .expect(2)
            .mount(&server)
            .await;

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let client = ProxmoxClient::new(server.uri().parse()?, "pve1", "", None, q_cfg, None);

        // Shared/identically-named storage: no copy.
        client
            .migrate_vm(
                "pve1",
                ProxmoxVmId(100),
                &MigrateVmParams {
                    target: "pve2".to_string(),
                    online: Some(1),
                    with_local_disks: None,
                    targetstorage: None,
                },
            )
            .await?;

        // Local storage: the disk has to be copied to a named pool.
        client
            .migrate_vm(
                "pve1",
                ProxmoxVmId(100),
                &MigrateVmParams {
                    target: "pve2".to_string(),
                    online: Some(0),
                    with_local_disks: Some(1),
                    targetstorage: Some("nvme-b".to_string()),
                },
            )
            .await?;

        let received = server.received_requests().await.unwrap();
        let bodies: Vec<serde_json::Value> = received
            .iter()
            .map(|r| serde_json::from_slice(&r.body).expect("JSON body"))
            .collect();

        assert_eq!(bodies[0]["target"], "pve2");
        assert_eq!(bodies[0]["online"], 1);
        assert!(
            bodies[0].get("with-local-disks").is_none(),
            "{:?}",
            bodies[0]
        );
        assert!(bodies[0].get("targetstorage").is_none(), "{:?}", bodies[0]);

        assert_eq!(bodies[1]["online"], 0);
        assert_eq!(bodies[1]["with-local-disks"], 1);
        assert_eq!(bodies[1]["targetstorage"], "nvme-b");

        // Migration is driven from the node that currently holds the VM.
        assert!(received[0].url.path().starts_with("/api2/json/nodes/pve1/"));
        Ok(())
    }

    /// The `VmHostClient` wrapper maps the host-agnostic request onto the
    /// Proxmox parameters, and refuses a migration that would target the node
    /// the VM is already on.
    #[tokio::test]
    async fn test_migrate_vm_trait_maps_request() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r".*/qemu/\d+/migrate$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:node:0:0:task"})),
            )
            .mount(&server)
            .await;
        // Task polling for the migration task.
        Mock::given(method("GET"))
            .and(path_regex(r".*/tasks/.*/status$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "id": "100",
                    "node": "pve1",
                    "pid": 1,
                    "pstart": 1,
                    "starttime": 1,
                    "status": "stopped",
                    "type": "qmigrate",
                    "upid": "UPID:node:0:0:task",
                    "user": "root@pam",
                    "exitstatus": "OK"
                }
            })))
            .mount(&server)
            .await;

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let client = ProxmoxClient::new(server.uri().parse()?, "pve1", "", None, q_cfg, None);
        let vm = mock_full_vm().vm;

        // Same node is a caller mistake, not a hypervisor round-trip.
        assert!(
            VmHostClient::migrate_vm(
                &client,
                &vm,
                &MigrateVmRequest {
                    target_node: "pve1".to_string(),
                    online: true,
                    target_storage: None,
                },
            )
            .await
            .is_err()
        );

        VmHostClient::migrate_vm(
            &client,
            &vm,
            &MigrateVmRequest {
                target_node: "pve2".to_string(),
                online: true,
                target_storage: Some("nvme-b".to_string()),
            },
        )
        .await?;

        let received = server.received_requests().await.unwrap();
        let post = received
            .iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("expected a migrate POST");
        let body: serde_json::Value = serde_json::from_slice(&post.body)?;
        assert_eq!(body["target"], "pve2");
        assert_eq!(body["online"], 1);
        // A named target storage implies the disk is copied.
        assert_eq!(body["with-local-disks"], 1);
        assert_eq!(body["targetstorage"], "nvme-b");
        Ok(())
    }

    /// Regression test: `apply_disk_options` must preserve `discard=on,ssd=1` for SSD disks.
    ///
    /// Before the fix, it stripped all existing disk params (including
    /// `discard=on,ssd=1`) when applying I/O throttle limits, taking only the bare volume
    /// path and adding back only the throttle params.
    #[tokio::test]
    async fn test_apply_disk_options_preserves_ssd_params() -> Result<()> {
        let server = MockServer::start().await;

        // The existing scsi0 config as Proxmox would return it
        let config_body = serde_json::json!({
            "data": {
                "digest": "abc123",
                "scsi0": "local-zfs:vm-1-disk-0,discard=on,size=100G,ssd=1"
            }
        });

        // GET /config — returns existing VM config
        Mock::given(method("GET"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&config_body))
            .expect(1)
            .mount(&server)
            .await;

        // POST /config — accept the update; return a task ID
        Mock::given(method("POST"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:node:0:0:task"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr0".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
            arch: "x86_64".to_string(),
            balloon_min_pct: None,
            firewall_config: None,
        };
        let client = ProxmoxClient::new(server.uri().parse()?, "pve", "", None, q_cfg, None);

        // Build a FullVmInfo with SSD disk and disk throttle limits
        let mut info = mock_full_vm();
        info.template.as_mut().unwrap().disk_mbps_read = Some(200);
        info.template.as_mut().unwrap().disk_mbps_write = Some(100);

        client
            .apply_disk_options(&info)
            .await
            .expect("apply_disk_options should succeed");

        // Inspect the POST request body to verify ssd params are present
        let received = server.received_requests().await.unwrap();
        let post_req = received
            .iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("expected a POST to /config");

        let body: serde_json::Value =
            serde_json::from_slice(&post_req.body).expect("POST body should be JSON");
        let scsi0 = body["scsi0"].as_str().expect("scsi0 field must be present");

        assert!(
            scsi0.contains("discard=on"),
            "expected discard=on in scsi0, got: {}",
            scsi0
        );
        assert!(
            scsi0.contains("ssd=1"),
            "expected ssd=1 in scsi0, got: {}",
            scsi0
        );
        assert!(
            scsi0.contains("mbps_rd=200"),
            "expected mbps_rd=200 in scsi0, got: {}",
            scsi0
        );
        assert!(
            scsi0.contains("mbps_wr=100"),
            "expected mbps_wr=100 in scsi0, got: {}",
            scsi0
        );
        assert!(
            scsi0.contains("iothread=1"),
            "expected iothread=1 in scsi0, got: {}",
            scsi0
        );

        Ok(())
    }

    /// `apply_disk_options` must still run when the template carries no throttle limits,
    /// otherwise existing VMs would never converge onto `iothread=1`.
    #[tokio::test]
    async fn test_apply_disk_options_sets_iothread_without_limits() -> Result<()> {
        let server = MockServer::start().await;

        let config_body = serde_json::json!({
            "data": {
                "digest": "abc123",
                "scsi0": "local-zfs:vm-1-disk-0,discard=on,size=100G,ssd=1"
            }
        });

        Mock::given(method("GET"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&config_body))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:node:0:0:task"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = ProxmoxClient::new(
            server.uri().parse()?,
            "pve",
            "",
            None,
            test_qemu_config(),
            None,
        );

        // No disk_mbps_*/disk_iops_* set on the template
        let info = mock_full_vm();

        client
            .apply_disk_options(&info)
            .await
            .expect("apply_disk_options should succeed without limits");

        let received = server.received_requests().await.unwrap();
        let post_req = received
            .iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("expected a POST to /config even with no throttle limits");

        let body: serde_json::Value =
            serde_json::from_slice(&post_req.body).expect("POST body should be JSON");
        let scsi0 = body["scsi0"].as_str().expect("scsi0 field must be present");

        assert!(
            scsi0.contains("iothread=1"),
            "expected iothread=1 in scsi0, got: {}",
            scsi0
        );
        assert!(
            scsi0.starts_with("local-zfs:vm-1-disk-0"),
            "expected the bare volume ref to be preserved, got: {}",
            scsi0
        );

        Ok(())
    }

    /// `iothread=1` is only honoured by qemu-server with the `virtio-scsi-single`
    /// controller, so the two settings must not drift apart.
    #[test]
    fn test_make_config_uses_virtio_scsi_single() -> Result<()> {
        let cfg = mock_full_vm();
        let p = ProxmoxClient::new(
            "http://localhost:8006".parse()?,
            "",
            "",
            None,
            test_qemu_config(),
            None,
        );

        let vm = p.make_config(&cfg, None, None)?;
        assert_eq!(vm.scsi_hw.as_deref(), Some("virtio-scsi-single"));

        Ok(())
    }

    fn test_qemu_config() -> QemuConfig {
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

    /// `cleanup_vm_disks` must force-unlink every `unused[n]` disk (and the
    /// primary disk when requested) so reinstalls don't leak orphaned volumes.
    #[tokio::test]
    async fn test_cleanup_vm_disks_removes_unused() -> Result<()> {
        let server = MockServer::start().await;

        let config_body = serde_json::json!({
            "data": {
                "scsi0": "local-lvm:vm-100-disk-0,size=20G",
                "unused0": "local-lvm:vm-100-disk-1",
                "unused1": "local-lvm:vm-100-disk-2",
                "unused12": "local-lvm:vm-100-disk-3",
                "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
                "memory": "2048"
            }
        });

        Mock::given(method("GET"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&config_body))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path_regex(r".*/qemu/\d+/unlink$"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": null})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = ProxmoxClient::new(
            server.uri().parse()?,
            "pve",
            "",
            None,
            test_qemu_config(),
            None,
        );

        // include_primary = false: only the unused disks should be removed
        client.cleanup_vm_disks(ProxmoxVmId(100), false).await?;

        let requests = server.received_requests().await.unwrap();
        let unlink = requests
            .iter()
            .find(|r| r.method == wiremock::http::Method::PUT)
            .expect("expected a PUT to /unlink");
        let query = unlink.url.query().unwrap_or("");
        assert!(
            query.contains("force=1"),
            "expected force=1, got: {}",
            query
        );
        let idlist = unlink
            .url
            .query_pairs()
            .find(|(k, _)| k == "idlist")
            .map(|(_, v)| v.into_owned())
            .expect("idlist query param");
        let ids: std::collections::HashSet<&str> = idlist.split(',').collect();
        assert_eq!(
            ids,
            ["unused0", "unused1", "unused12"].into_iter().collect()
        );
        assert!(
            !ids.contains("scsi0"),
            "scsi0 must not be removed when include_primary=false"
        );

        Ok(())
    }

    /// When there are no unused disks and the primary is excluded, no unlink
    /// request should be made.
    #[tokio::test]
    async fn test_cleanup_vm_disks_noop_when_nothing_to_remove() -> Result<()> {
        let server = MockServer::start().await;

        let config_body = serde_json::json!({
            "data": {
                "scsi0": "local-lvm:vm-100-disk-0,size=20G",
                "memory": "2048"
            }
        });

        Mock::given(method("GET"))
            .and(path_regex(r".*/qemu/\d+/config$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&config_body))
            .expect(1)
            .mount(&server)
            .await;

        // No PUT mock mounted: any unlink call would 404 and fail the test.
        let client = ProxmoxClient::new(
            server.uri().parse()?,
            "pve",
            "",
            None,
            test_qemu_config(),
            None,
        );

        client.cleanup_vm_disks(ProxmoxVmId(100), false).await?;

        let made_unlink = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.method == wiremock::http::Method::PUT);
        assert!(!made_unlink, "no unlink request expected");

        Ok(())
    }
}
