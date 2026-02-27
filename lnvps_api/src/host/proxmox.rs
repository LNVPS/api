use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use crate::json_api::JsonApi;
use crate::settings::{QemuConfig, SshConfig};
use crate::ssh_client::SshClient;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use ipnetwork::IpNetwork;
use lnvps_api_common::retry::{OpError, OpResult, Pipeline, RetryPolicy};
use lnvps_api_common::{VmRunningState, VmRunningStates, op_fatal, parse_gateway};
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

    /// Download an image to the host disk
    pub async fn download_image(&self, req: DownloadUrlRequest) -> OpResult<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();

        let rsp: ResponseBase<String> = api
            .post(
                &format!(
                    "/api2/json/nodes/{}/storage/{}/download-url",
                    req.node, req.storage
                ),
                &req,
            )
            .await?;

        Ok(TaskId {
            id: rsp.data,
            node: node_clone,
        })
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
            let mut s = SshClient::new().map_err(OpError::Transient)?;
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
}

impl ProxmoxClient {
    fn convert_firewall_policy(policy: &crate::settings::FirewallPolicy) -> VmFirewallPolicy {
        match policy {
            crate::settings::FirewallPolicy::Accept => VmFirewallPolicy::ACCEPT,
            crate::settings::FirewallPolicy::Reject => VmFirewallPolicy::REJECT,
            crate::settings::FirewallPolicy::Drop => VmFirewallPolicy::DROP,
        }
    }

    fn make_config(&self, value: &FullVmInfo) -> Result<VmConfig> {
        let ip_config = value
            .ips
            .iter()
            .filter_map(|ip| {
                if let Ok(addr) = ip.ip.parse::<IpAddr>() {
                    Some(match addr {
                        IpAddr::V4(_) => {
                            let ip_range = value.ranges.iter().find(|r| r.id == ip.ip_range_id)?;
                            let range: IpNetwork = ip_range.cidr.parse().ok()?;
                            let range_gw: IpNetwork = parse_gateway(&ip_range.gateway).ok()?;
                            format!(
                                "ip={},gw={}",
                                IpNetwork::new(addr, range.prefix()).ok()?,
                                range_gw.ip()
                            )
                        }
                        IpAddr::V6(_) => {
                            let ip_range = value.ranges.iter().find(|r| r.id == ip.ip_range_id)?;
                            if matches!(ip_range.allocation_mode, IpRangeAllocationMode::SlaacEui64)
                            {
                                // just ignore what's in the db and use whatever the host wants
                                // what's in the db is purely informational
                                "ip6=auto".to_string()
                            } else {
                                let range: IpNetwork = ip_range.cidr.parse().ok()?;
                                let range_gw: IpNetwork = parse_gateway(&ip_range.gateway).ok()?;
                                format!(
                                    "ip6={},gw6={}",
                                    IpNetwork::new(addr, range.prefix()).ok()?,
                                    range_gw.ip(),
                                )
                            }
                        }
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut net = vec![
            format!("virtio={}", value.vm.mac_address),
            format!("bridge={}", self.config.bridge),
            "firewall=1".to_string(), //always enable on interface
        ];
        if let Some(t) = value.host.vlan_id {
            net.push(format!("tag={}", t));
        }
        if let Some(mtu) = value.host.mtu {
            net.push(format!("mtu={}", mtu));
        }
        if value.vm.disabled {
            net.push("link_down=1".to_string());
        }
        let limits = value.limits();
        if let Some(mbps) = limits.network_mbps {
            // Proxmox rate= is in MB/s; our field is stored in Mbit/s
            net.push(format!("rate={}", mbps as f32 / 8.0));
        }

        let vm_resources = value.resources()?;
        Ok(VmConfig {
            name: Some(format!("VM{}", value.vm.id)), // set name to DB name
            cpu: Some(self.config.cpu.clone()),
            kvm: Some(self.config.kvm),
            ip_config: Some(ip_config.join(",")),
            machine: Some(self.config.machine.clone()),
            net: Some(net.join(",")),
            os_type: Some(self.config.os_type.clone()),
            on_boot: Some(true),
            bios: Some(VmBios::OVMF),
            boot: Some("order=scsi0".to_string()),
            cores: Some(vm_resources.cpu as i32),
            memory: Some((vm_resources.memory / crate::MB).to_string()),
            scsi_hw: Some("virtio-scsi-pci".to_string()),
            serial_0: Some("socket".to_string()),
            scsi_1: Some(format!("{}:cloudinit", &value.disk.name)),
            ssh_keys: Some(urlencoding::encode(value.ssh_key.key_data.as_str()).to_string()),
            efi_disk_0: Some(format!("{}:0,efitype=4m", &value.disk.name)),
            cpu_limit: limits.cpu_limit,
            ..Default::default()
        })
    }

    /// Apply disk I/O throttle limits to the primary disk of a VM.
    ///
    /// Fetches the current scsi0 device string from Proxmox, appends the
    /// throttle parameters, and sends a PATCH to update the VM config.
    async fn apply_disk_limits(&self, req: &FullVmInfo) -> OpResult<()> {
        let limits = req.limits();
        let has_disk_limits = limits.disk_iops_read.is_some()
            || limits.disk_iops_write.is_some()
            || limits.disk_mbps_read.is_some()
            || limits.disk_mbps_write.is_some();

        if !has_disk_limits {
            return Ok(());
        }

        // Fetch the current config to get the live scsi0 disk path
        let current = self.get_vm_config(&self.node, req.vm.id.into()).await?;
        let scsi0_base = match current.config.scsi_0 {
            Some(v) => v,
            None => op_fatal!("scsi0 not found in VM config"),
        };

        // Strip any pre-existing throttle params so we get the bare volume ref
        let volume_part = scsi0_base
            .split(',')
            .next()
            .unwrap_or(&scsi0_base)
            .to_string();

        let mut parts = vec![volume_part];
        if let Some(v) = limits.disk_mbps_read {
            parts.push(format!("mbps_rd={}", v));
        }
        if let Some(v) = limits.disk_mbps_write {
            parts.push(format!("mbps_wr={}", v));
        }
        if let Some(v) = limits.disk_iops_read {
            parts.push(format!("iops_rd={}", v));
        }
        if let Some(v) = limits.disk_iops_write {
            parts.push(format!("iops_wr={}", v));
        }

        self.configure_vm(ConfigureVm {
            node: self.node.clone(),
            vm_id: req.vm.id.into(),
            current: None,
            snapshot: None,
            digest: None,
            config: VmConfig {
                scsi_0: Some(parts.join(",")),
                ..Default::default()
            },
        })
        .await?;

        Ok(())
    }

    /// Import main disk image from the template (without resizing)
    async fn import_disk(&self, req: &FullVmInfo) -> OpResult<()> {
        let vm_id = req.vm.id.into();
        let limits = req.limits();

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
        // Check if VM exists first
        if self.get_vm_status(&self.node, vm_id).await.is_err() {
            info!("VM {} doesn't exist, skipping destroy", vm_id);
            return Ok(());
        }

        // Stop first, ignoring errors
        self.stop_vm(&self.node, vm_id).await.ok();

        if let Some(ssh) = &self.ssh {
            let mut ses = SshClient::new().map_err(OpError::Transient)?;
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

    async fn download_os_image(&self, image: &VmOsImage) -> OpResult<()> {
        let iso_storage = self.get_iso_storage(&self.node).await?;
        let files = self.list_storage_files(&self.node, &iso_storage).await?;

        info!("Downloading image {} on {}", image.url, &self.node);
        // storage_name: how Proxmox stores the file (e.g. foo.img)
        // url_name: the original filename from the URL, used in SHASUMS (e.g. foo.qcow2)
        let storage_name = image.filename()?;
        let url_name = image.url_filename()?;

        // Resolve the expected checksum from sha2_url if present.
        // This is used only for SSH-based verification of already-present files;
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
            .and_then(|s| lnvps_api_common::shasum::ShasumAlgorithm::from_hex_len(s.len()))
            .map(|a| a.as_str().to_owned());

        let already_present = files
            .iter()
            .any(|v| v.vol_id.ends_with(&format!("iso/{storage_name}")));

        if already_present {
            // If we have an expected checksum, verify the stored file via SSH
            let stale = if let (Some(expected), Some(algo)) = (&expected_sha2, &checksum_algorithm)
            {
                match self
                    .verify_image_checksum(&storage_name, &iso_storage, expected, algo)
                    .await
                {
                    Ok(matches) => {
                        if matches {
                            info!("Checksum verified for {}, skipping download", storage_name);
                            false
                        } else {
                            info!("Checksum mismatch for {}, will re-download", storage_name);
                            true
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to verify checksum for {}: {}, will re-download",
                            storage_name, e
                        );
                        true
                    }
                }
            } else {
                info!(
                    "No checksum available for {}, skipping re-download check",
                    storage_name
                );
                false
            };

            if !stale {
                return Ok(());
            }

            // Delete the stale image before re-downloading
            info!("Deleting stale image {} from {}", storage_name, &self.node);
            if let Err(e) = self
                .delete_storage_file(&self.node, &iso_storage, &storage_name)
                .await
            {
                warn!("Failed to delete stale image {}: {}", storage_name, e);
            }
        }

        // Resolve any HTTP redirects before handing the URL to Proxmox.
        // Proxmox's download-url API does not always follow redirects itself,
        // so we probe for the final location here and pass that instead.
        let resolved_url = lnvps_api_common::shasum::resolve_redirect(&image.url).await;
        if resolved_url != image.url {
            info!(
                "Resolved redirect for image {}: {} -> {}",
                storage_name, image.url, resolved_url
            );
        }

        // Do not include checksum/checksum-algorithm in the download-url request.
        // Proxmox's built-in hash verification has proven buggy and causes download
        // failures. Integrity is verified separately via SSH after the download
        // completes (see verify_image_checksum).
        let t_download = self
            .download_image(DownloadUrlRequest {
                content: StorageContent::ISO,
                node: self.node.clone(),
                storage: iso_storage.clone(),
                url: resolved_url,
                filename: storage_name.clone(),
                checksum: None,
                checksum_algorithm: None,
            })
            .await?;
        self.wait_for_task(&t_download).await?;

        // Verify the freshly-downloaded file via SSH to confirm integrity.
        if let (Some(expected), Some(algo)) = (&expected_sha2, &checksum_algorithm) {
            match self
                .verify_image_checksum(&storage_name, &iso_storage, expected, algo)
                .await
            {
                Ok(true) => {
                    info!("Post-download checksum verified for {}", storage_name);
                }
                Ok(false) => {
                    // Delete the corrupt file so the next run re-downloads it.
                    warn!(
                        "Post-download checksum mismatch for {}, deleting corrupt file",
                        storage_name
                    );
                    if let Err(e) = self
                        .delete_storage_file(&self.node, &iso_storage, &storage_name)
                        .await
                    {
                        warn!("Failed to delete corrupt image {}: {}", storage_name, e);
                    }
                    return Err(OpError::Fatal(anyhow::anyhow!(
                        "Checksum mismatch after download of {}",
                        storage_name
                    )));
                }
                Err(e) => {
                    warn!(
                        "Could not verify post-download checksum for {}: {}",
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
        let config = self.make_config(req)?;
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
        self.destroy_vm(vm.id.into()).await
    }

    async fn unlink_primary_disk(&self, vm: &Vm) -> OpResult<()> {
        self.unlink_disk(&self.node, vm.id.into(), vec!["scsi0".to_string()], true)
            .await
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
            let vmid: ProxmoxVmId = vm.vm_id.into();
            states.push((vmid.0, vm.into()));
        }

        Ok(states)
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let current_config = self.get_vm_config(&self.node, cfg.vm.id.into()).await?;

        let mut config = self.make_config(cfg)?;

        // dont re-create the disks
        config.scsi_0 = None;
        config.scsi_1 = None;
        config.efi_disk_0 = None;
        if current_config.config.ssh_keys == config.ssh_keys {
            config.ssh_keys = None;
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

        // Apply disk I/O throttle limits (requires reading live scsi0 path)
        self.apply_disk_limits(cfg).await?;

        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> OpResult<()> {
        let vm_id = cfg.vm.id.into();

        // Check and fix cloud-init IP config if it doesn't match expected
        let current_config = self.get_vm_config(&self.node, vm_id).await?;
        let expected_config = self.make_config(cfg)?;
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
        // Use configured firewall options or disable firewall if no config
        let firewall_config = VmFirewallConfig {
            dhcp: fw_cfg.dhcp,
            enable: fw_cfg.enable,
            ip_filter: fw_cfg.ip_filter,
            mac_filter: fw_cfg.mac_filter,
            ndp: fw_cfg.ndp,
            policy_in: fw_cfg.policy_in.as_ref().map(Self::convert_firewall_policy),
            policy_out: fw_cfg
                .policy_out
                .as_ref()
                .map(Self::convert_firewall_policy),
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

        // Add firewall rule to allow traffic from ipfilter-net0 IPset
        let allow_rule = VmFirewallRule {
            action: VmFirewallAction::ACCEPT,
            dest: Some("+guest/ipfilter-net0".to_string()),
            rule_type: VmFirewallRuleType::In,
            enable: Some(1),
            comment: Some("Allow traffic to ipfilter-net0 IPset".to_string()),
            ..Default::default()
        };

        // Check if this rule already exists to avoid duplicates
        let existing_rules = self.list_vm_firewall_rules(&self.node, vm_id).await?;
        let rule_exists = existing_rules.iter().any(|rule| {
            rule.action == VmFirewallAction::ACCEPT
                && rule.dest.as_deref() == Some("+guest/ipfilter-net0")
                && rule.rule_type == VmFirewallRuleType::In
        });

        if !rule_exists {
            self.add_vm_firewall_rule(&self.node, vm_id, allow_rule)
                .await?;
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

        let mut client = SshClient::new().map_err(OpError::Transient)?;
        client
            .connect((host, 22), &ssh_user, &ssh_key)
            .await
            .map_err(OpError::Transient)?;

        let ssh_channel = client
            .tunnel_unix_socket(std::path::Path::new(&socket_path))
            .map_err(OpError::Transient)?;

        // Enable non-blocking mode *after* the channel is fully established.
        // Setting it before causes the channel_direct_streamlocal handshake to
        // fail with WouldBlock.
        client.set_blocking(false);

        // mpsc channels: the TerminalStream returned to the caller exposes
        // client_rx (bytes from VM) and server_tx (bytes to VM).
        use tokio::sync::mpsc::channel as mpsc_channel;
        let (client_tx, client_rx) = mpsc_channel::<Vec<u8>>(256);
        let (server_tx, server_rx) = mpsc_channel::<Vec<u8>>(256);

        // Run the blocking I/O bridge in a dedicated thread so the non-Send
        // ssh2::Channel does not cross async task boundaries.
        tokio::task::spawn_blocking(move || {
            ssh_terminal_bridge(ssh_channel, client_tx, server_rx);
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
    /// Delegates to the common [`lnvps_api_common::shasum`] parser.
    pub async fn fetch_sha2_from_url(sha2_url: &str, filename: &str) -> Result<String> {
        let entry = lnvps_api_common::shasum::fetch_checksum_for_file(sha2_url, filename).await?;
        Ok(entry.checksum)
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
        let ssh_cfg = match &self.ssh {
            Some(s) => s,
            None => anyhow::bail!("SSH not configured, cannot verify checksum"),
        };

        // Proxmox stores ISOs under /var/lib/vz/template/iso/ by default
        let iso_path = format!("/var/lib/vz/template/iso/{filename}");
        let cmd = match algorithm {
            "sha256" | "sha384" | "sha512" => format!("{algorithm}sum {iso_path}"),
            other => anyhow::bail!("Unknown checksum algorithm: {other}"),
        };

        let host = crate::worker::extract_host_from_url(&self.api.base().to_string());
        let ssh_user = ssh_cfg.user.clone();
        let ssh_key = ssh_cfg.key.clone();

        let mut ssh = SshClient::new()?;
        ssh.connect((host.as_str(), 22), &ssh_user, &ssh_key)
            .await?;
        let (exit_code, output) = ssh.execute(&cmd).await?;
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
        Self(value as u64 - 100)
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

#[derive(Debug, Serialize)]
pub struct DownloadUrlRequest {
    pub content: StorageContent,
    pub node: String,
    pub storage: String,
    pub url: String,
    pub filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(rename = "checksum-algorithm", skip_serializing_if = "Option::is_none")]
    pub checksum_algorithm: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StorageContentEntry {
    pub format: String,
    pub size: u64,
    #[serde(rename = "volid")]
    pub vol_id: String,
    #[serde(rename = "vmid")]
    pub vm_id: Option<u32>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VmConfig {
    #[serde(rename = "onboot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_int_to_bool"
    )]
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
    pub ip_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "net0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net: Option<String>,
    #[serde(rename = "ostype")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
    #[serde(rename = "scsi0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scsi_0: Option<String>,
    #[serde(rename = "scsi1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scsi_1: Option<String>,
    #[serde(rename = "scsihw")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scsi_hw: Option<String>,
    #[serde(rename = "sshkeys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(rename = "efidisk0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub efi_disk_0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_int_to_bool"
    )]
    pub kvm: Option<bool>,
    #[serde(rename = "serial0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_0: Option<String>,
    /// CPU usage limit as a fraction of allocated cores (e.g. 0.5 = 50%; 0 = uncapped)
    #[serde(rename = "cpulimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<f32>,
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

/// Blocking I/O bridge between an SSH channel (QEMU serial socket) and the
/// async mpsc channels exposed as a [`TerminalStream`].
///
/// This function is intended to be executed via [`tokio::task::spawn_blocking`]
/// so that the non-`Send` [`ssh2::Channel`] never crosses async task boundaries.
fn ssh_terminal_bridge(
    mut channel: ssh2::Channel,
    client_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut server_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    use std::io::{Read, Write};

    // Non-blocking mode is already set on the session by the caller.
    let mut buf = [0u8; 4096];
    loop {
        // --- upstream: serial socket → WebSocket client ---
        match channel.stream(0).read(&mut buf) {
            Ok(0) => {
                // EOF: the channel was closed by the remote side.
                break;
            }
            Ok(n) => {
                if client_tx.blocking_send(buf[..n].to_vec()).is_err() {
                    // Receiver dropped (WebSocket closed).
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available right now — fall through to check
                // downstream direction, then sleep briefly.
            }
            Err(e) => {
                log::warn!("Terminal read error: {}", e);
                break;
            }
        }

        // --- downstream: WebSocket client → serial socket ---
        match server_rx.try_recv() {
            Ok(data) => {
                if let Err(e) = channel.stream(0).write_all(&data) {
                    log::warn!("Terminal write error: {}", e);
                    break;
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                // Nothing to write right now.
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                // Sender dropped (WebSocket closed).
                break;
            }
        }
    }

    let _ = channel.close();
    info!("Terminal proxy connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MB;
    use crate::host::tests::mock_full_vm;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

        let vm = p.make_config(&cfg)?;
        assert_eq!(vm.cpu, Some(q_cfg.cpu));
        assert_eq!(vm.cores, Some(template.cpu as i32));
        assert_eq!(vm.memory, Some((template.memory / MB).to_string()));
        assert_eq!(vm.on_boot, Some(true));
        assert!(vm.net.as_ref().unwrap().contains("tag=100"));
        assert!(vm.net.as_ref().unwrap().contains("firewall=1"));
        assert_eq!(
            vm.ip_config,
            Some(
                "ip=192.168.1.2/24,gw=192.168.1.1,ip=192.168.2.2/24,gw=10.10.10.10,ip6=auto"
                    .to_string()
            )
        );
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
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg)?;
        let net = vm.net.unwrap();
        // 800 Mbit/s ÷ 8 = 100 MB/s
        assert!(
            net.contains("rate=100"),
            "expected rate=100 in net string, got: {}",
            net
        );
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
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg)?;
        assert_eq!(vm.cpu_limit, Some(0.5));
        Ok(())
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
            firewall_config: None,
        };

        let p = ProxmoxClient::new("http://localhost:8006".parse()?, "", "", None, q_cfg, None);

        let vm = p.make_config(&cfg)?;
        assert!(
            !vm.net.as_deref().unwrap_or("").contains("rate="),
            "rate= must not appear when network_mbps is None"
        );
        assert_eq!(vm.cpu_limit, None);
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
}
