use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use crate::json_api::JsonApi;
use crate::settings::{QemuConfig, SshConfig};
use crate::ssh_client::SshClient;
use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use backon::{ExponentialBuilder, Retryable};
use chrono::Utc;
use ipnetwork::IpNetwork;
use lnvps_api_common::{VmRunningState, VmRunningStates};
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
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

// Custom deserializer to handle Proxmox's integer-to-boolean conversion for KVM field
fn deserialize_int_to_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrBool {
        Int(i32),
        Bool(bool),
    }

    match IntOrBool::deserialize(deserializer) {
        Ok(IntOrBool::Int(i)) => Ok(Some(i != 0)),
        Ok(IntOrBool::Bool(b)) => Ok(Some(b)),
        Err(_) => Ok(None), // Return None for missing/invalid values, serde default will handle it
    }
}

pub struct ProxmoxClient {
    api: JsonApi,
    config: QemuConfig,
    ssh: Option<SshConfig>,
    mac_prefix: String,
    node: String,
}

impl ProxmoxClient {
    /// Create a retry policy for Proxmox API operations
    fn retry_policy() -> ExponentialBuilder {
        ExponentialBuilder::default()
            .with_min_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(5))
            .with_max_times(3)
    }

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
    pub async fn version(&self) -> Result<VersionResponse> {
        let rsp: ResponseBase<VersionResponse> = self.api.get("/api2/json/version").await?;
        Ok(rsp.data)
    }

    /// List nodes
    pub async fn list_nodes(&self) -> Result<Vec<NodeResponse>> {
        let rsp: ResponseBase<Vec<NodeResponse>> = self.api.get("/api2/json/nodes").await?;
        Ok(rsp.data)
    }

    pub async fn get_vm_status(&self, node: &str, vm_id: ProxmoxVmId) -> Result<VmInfo> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<VmInfo> = (|| async {
            api.get(&format!(
                "/api2/json/nodes/{}/qemu/{}/status/current",
                node_str, vm_id
            ))
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(rsp.data)
    }

    pub async fn list_vms(&self, node: &str) -> Result<Vec<VmInfo>> {
        let rsp: ResponseBase<Vec<VmInfo>> = self
            .api
            .get(&format!("/api2/json/nodes/{node}/qemu"))
            .await?;
        Ok(rsp.data)
    }

    pub async fn list_storage(&self, node: &str) -> Result<Vec<NodeStorage>> {
        let rsp: ResponseBase<Vec<NodeStorage>> = self
            .api
            .get(&format!("/api2/json/nodes/{node}/storage"))
            .await?;
        Ok(rsp.data)
    }

    pub async fn list_disks(&self, node: &str) -> Result<Vec<NodeDisk>> {
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
    ) -> Result<Vec<StorageContentEntry>> {
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
    pub async fn create_vm(&self, req: CreateVm) -> Result<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();
        
        let rsp: ResponseBase<Option<String>> = (|| async {
            api.post(&format!("/api2/json/nodes/{}/qemu", req.node), &req)
                .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        if let Some(id) = rsp.data {
            Ok(TaskId { id, node: node_clone })
        } else {
            Err(anyhow!("Failed to create VM"))
        }
    }

    /// Get a VM current config
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu/{vmid}/config
    pub async fn get_vm_config(&self, node: &str, vm_id: ProxmoxVmId) -> Result<HashedVmConfig> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<HashedVmConfig> = (|| async {
            api.get(&format!("/api2/json/nodes/{}/qemu/{}/config", node_str, vm_id))
                .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(rsp.data)
    }

    /// Configure a VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu/{vmid}/config
    pub async fn configure_vm(&self, req: ConfigureVm) -> Result<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();
        
        let rsp: ResponseBase<Option<String>> = (|| async {
            api.post(
                &format!("/api2/json/nodes/{}/qemu/{}/config", req.node, req.vm_id),
                &req,
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        if let Some(id) = rsp.data {
            Ok(TaskId { id, node: node_clone })
        } else {
            Err(anyhow!("Failed to configure VM"))
        }
    }

    /// Delete VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu
    pub async fn delete_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<Option<String>> = (|| async {
            api.req::<_, ()>(
                Method::DELETE,
                &format!("/api2/json/nodes/{}/qemu/{}", node_str, vm),
                None,
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        if let Some(id) = rsp.data {
            Ok(TaskId {
                id,
                node: node_str,
            })
        } else {
            Err(anyhow!("Failed to delete VM"))
        }
    }

    pub async fn get_vm_rrd_data(
        &self,
        id: ProxmoxVmId,
        timeframe: &str,
    ) -> Result<Vec<RrdDataPoint>> {
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
    pub async fn get_task_status(&self, task: &TaskId) -> Result<TaskStatus> {
        let api = &self.api;
        let task_node = task.node.clone();
        let task_id = task.id.clone();
        
        let rsp: ResponseBase<TaskStatus> = (|| async {
            api.get(&format!(
                "/api2/json/nodes/{}/tasks/{}/status",
                task_node, task_id
            ))
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(rsp.data)
    }

    /// Helper function to wait for a task to complete
    pub async fn wait_for_task(&self, task: &TaskId) -> Result<TaskStatus> {
        let max_wait_time = Duration::from_secs(300); // 5 minutes max
        let start_time = std::time::Instant::now();

        loop {
            if start_time.elapsed() > max_wait_time {
                bail!("Task {} timed out after 5 minutes", task.id);
            }

            let s = self.get_task_status(task).await?;
            if s.is_finished() {
                if s.is_success() {
                    return Ok(s);
                } else {
                    bail!(
                        "Task finished with error: {}",
                        s.exit_status.unwrap_or("no error message".to_string())
                    );
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn get_iso_storage(&self, node: &str) -> Result<String> {
        let storages = self.list_storage(node).await?;
        if let Some(s) = storages
            .iter()
            .find(|s| s.contents().contains(&StorageContent::ISO))
        {
            Ok(s.storage.clone())
        } else {
            bail!("No image storage found");
        }
    }

    /// Download an image to the host disk
    pub async fn download_image(&self, req: DownloadUrlRequest) -> Result<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();
        
        let rsp: ResponseBase<String> = (|| async {
            api.post(
                &format!(
                    "/api2/json/nodes/{}/storage/{}/download-url",
                    req.node, req.storage
                ),
                &req,
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(TaskId {
            id: rsp.data,
            node: node_clone,
        })
    }

    pub async fn import_disk_image(&self, req: ImportDiskImageRequest) -> Result<()> {
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
            let (code, rsp) = (|| async {
                let mut s = SshClient::new()?;
                s.connect((host.clone(), 22), &ssh_user, &ssh_key).await?;
                s.execute(&cmd).await
            })
            .retry(Self::retry_policy())
            .await?;
            
            info!("{}", rsp);

            if code != 0 {
                bail!("Failed to import disk, exit-code {}, {}", code, rsp);
            }
            Ok(())
        } else {
            bail!("Cannot complete, no method available to import disk, consider configuring ssh")
        }
    }

    /// Resize a disk on a VM
    pub async fn resize_disk(&self, req: ResizeDiskRequest) -> Result<TaskId> {
        let api = &self.api;
        let node_clone = req.node.clone();
        
        let rsp: ResponseBase<String> = (|| async {
            api.req(
                Method::PUT,
                &format!("/api2/json/nodes/{}/qemu/{}/resize", &req.node, &req.vm_id),
                Some(&req),
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(TaskId {
            id: rsp.data,
            node: node_clone,
        })
    }

    /// Start a VM
    pub async fn start_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<String> = (|| async {
            api.post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/start", node_str, vm),
                (),
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn stop_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<String> = (|| async {
            api.post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/stop", node_str, vm),
                (),
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn shutdown_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<String> = (|| async {
            api.post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/shutdown", node_str, vm),
                (),
            )
            .await
        })
        .retry(Self::retry_policy())
        .await?;
        
        Ok(TaskId {
            id: rsp.data,
            node: node_str,
        })
    }

    /// Stop a VM
    pub async fn reset_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let api = &self.api;
        let node_str = node.to_string();
        
        let rsp: ResponseBase<String> = (|| async {
            api.post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/reset", node_str, vm),
                (),
            )
            .await
        })
        .retry(Self::retry_policy())
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
    ) -> Result<()> {
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
    ) -> Result<VmFirewallConfig> {
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
    ) -> Result<()> {
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
    pub async fn list_vm_ipsets(&self, node: &str, vm_id: ProxmoxVmId) -> Result<Vec<VmIpsetInfo>> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<Vec<VmIpsetEntry>> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<Vec<VmFirewallRule>> {
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
    ) -> Result<()> {
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
            .map_while(|ip| {
                if let Ok(net) = ip.ip.parse::<IpAddr>() {
                    Some(match net {
                        IpAddr::V4(addr) => {
                            let ip_range = value.ranges.iter().find(|r| r.id == ip.ip_range_id)?;
                            let range: IpNetwork = ip_range.cidr.parse().ok()?;
                            let range_gw: IpNetwork = ip_range.gateway.parse().ok()?;
                            // take the largest (smallest prefix number) of the network prefixes
                            let max_net = range.prefix().min(range_gw.prefix());
                            format!(
                                "ip={},gw={}",
                                IpNetwork::new(addr.into(), max_net).ok()?,
                                range_gw.ip()
                            )
                        }
                        IpAddr::V6(addr) => {
                            let ip_range = value.ranges.iter().find(|r| r.id == ip.ip_range_id)?;
                            if matches!(ip_range.allocation_mode, IpRangeAllocationMode::SlaacEui64)
                            {
                                // just ignore what's in the db and use whatever the host wants
                                // what's in the db is purely informational
                                "ip6=auto".to_string()
                            } else {
                                let range: IpNetwork = ip_range.cidr.parse().ok()?;
                                let range_gw: IpNetwork = ip_range.gateway.parse().ok()?;
                                format!(
                                    "ip6={},gw6={}",
                                    IpNetwork::new(addr.into(), range.prefix()).ok()?,
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
            ..Default::default()
        })
    }

    /// Import main disk image from the template
    async fn import_template_disk(&self, req: &FullVmInfo) -> Result<()> {
        let vm_id = req.vm.id.into();

        // import primary disk from image (scsi0)
        self.import_disk_image(ImportDiskImageRequest {
            vm_id,
            node: self.node.clone(),
            storage: req.disk.name.clone(),
            disk: "scsi0".to_string(),
            image: req.image.filename()?,
            is_ssd: matches!(req.disk.kind, DiskType::SSD),
        })
        .await
        .context("Failed to import disk image")?;

        // resize disk to match template
        let j_resize = self
            .resize_disk(ResizeDiskRequest {
                node: self.node.clone(),
                vm_id,
                disk: "scsi0".to_string(),
                size: req.resources()?.disk_size.to_string(),
            })
            .await
            .context("Failed to start disk resize")?;
        // TODO: rollback
        self.wait_for_task(&j_resize).await
            .context("Disk resize task failed")?;

        Ok(())
    }
}

#[async_trait]
impl VmHostClient for ProxmoxClient {
    async fn get_info(&self) -> Result<VmHostInfo> {
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
            bail!("Could not find node {}", self.node);
        }
    }

    async fn download_os_image(&self, image: &VmOsImage) -> Result<()> {
        let iso_storage = self.get_iso_storage(&self.node).await?;
        let files = self.list_storage_files(&self.node, &iso_storage).await?;

        info!("Downloading image {} on {}", image.url, &self.node);
        let i_name = image.filename()?;
        if files
            .iter()
            .any(|v| v.vol_id.ends_with(&format!("iso/{i_name}")))
        {
            info!("Already downloaded, skipping");
            return Ok(());
        }
        let t_download = self
            .download_image(DownloadUrlRequest {
                content: StorageContent::ISO,
                node: self.node.clone(),
                storage: iso_storage.clone(),
                url: image.url.clone(),
                filename: i_name,
            })
            .await?;
        self.wait_for_task(&t_download).await?;
        Ok(())
    }

    async fn generate_mac(&self, _vm: &Vm) -> Result<String> {
        ensure!(self.mac_prefix.len() == 8, "Invalid mac prefix");
        ensure!(self.mac_prefix.contains(":"), "Invalid mac prefix");

        Ok(format!(
            "{}:{}:{}:{}",
            self.mac_prefix,
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()]),
            hex::encode([random::<u8>()])
        ))
    }

    async fn start_vm(&self, vm: &Vm) -> Result<()> {
        let task = self.start_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn stop_vm(&self, vm: &Vm) -> Result<()> {
        let task = self.stop_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn reset_vm(&self, vm: &Vm) -> Result<()> {
        let task = self.reset_vm(&self.node, vm.id.into()).await?;
        self.wait_for_task(&task).await?;
        Ok(())
    }

    async fn create_vm(&self, req: &FullVmInfo) -> Result<()> {
        let config = self.make_config(req).context("Failed to generate VM config")?;
        let vm_id = req.vm.id.into();
        let t_create = self
            .create_vm(CreateVm {
                node: self.node.clone(),
                vm_id,
                config,
            })
            .await
            .context("Failed to create VM on Proxmox")?;
        self.wait_for_task(&t_create).await
            .context("VM creation task failed")?;

        // import template image
        self.import_template_disk(req).await
            .context("Failed to import template disk")?;

        // apply firewall config and manage IPsets using patch_firewall
        self.patch_firewall(req).await
            .context("Failed to patch firewall configuration")?;

        // try start, otherwise ignore error (maybe its already running)
        if let Ok(j_start) = self.start_vm(&self.node, vm_id).await
            && let Err(e) = self.wait_for_task(&j_start).await {
                warn!("Failed to start vm: {}", e);
            }

        Ok(())
    }

    async fn delete_vm(&self, vm: &Vm) -> Result<()> {
        let vm_id: ProxmoxVmId = vm.id.into();

        // NOT IMPLEMENTED
        //let t = self.delete_vm(&self.node, vm_id).await?;
        //self.wait_for_task(&t).await?;

        //always stop first before deleting, ignoring if already stopped
        self.stop_vm(&self.node, vm_id).await.ok();

        if let Some(ssh) = &self.ssh {
            let mut ses = SshClient::new()?;
            ses.connect(
                (self.api.base().host().unwrap().to_string(), 22),
                &ssh.user,
                &ssh.key,
            )
            .await?;

            let cmd = format!("/usr/sbin/qm destroy {}", vm_id,);
            let (code, rsp) = ses.execute(cmd.as_str()).await?;
            info!("{}", rsp);
            if code != 0 {
                bail!("Failed to destroy vm, exit-code {}, {}", code, rsp);
            }
        }
        Ok(())
    }

    async fn reinstall_vm(&self, req: &FullVmInfo) -> Result<()> {
        let vm_id = req.vm.id.into();

        // try stop, otherwise ignore error (maybe its already running)
        if let Ok(j_stop) = self.stop_vm(&self.node, vm_id).await
            && let Err(e) = self.wait_for_task(&j_stop).await {
                warn!("Failed to stop vm: {}", e);
            }

        // unlink the existing main disk
        self.unlink_disk(&self.node, vm_id, vec!["scsi0".to_string()], true)
            .await?;

        // import disk from template again
        self.import_template_disk(req).await?;

        // try start, otherwise ignore error (maybe its already running)
        if let Ok(j_start) = self.start_vm(&self.node, vm_id).await
            && let Err(e) = self.wait_for_task(&j_start).await {
                warn!("Failed to start vm: {}", e);
            }

        Ok(())
    }

    async fn resize_disk(&self, cfg: &FullVmInfo) -> Result<()> {
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

    async fn get_vm_state(&self, vm: &Vm) -> Result<VmRunningState> {
        let s = self.get_vm_status(&self.node, vm.id.into()).await?;
        Ok(s.into())
    }

    async fn get_all_vm_states(&self) -> Result<Vec<(u64, VmRunningState)>> {
        let vm_list = self.list_vms(&self.node).await?;
        let mut states = Vec::new();

        for vm in vm_list {
            let vmid: ProxmoxVmId = vm.vm_id.into();
            states.push((vmid.0, vm.into()));
        }

        Ok(states)
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> Result<()> {
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
        Ok(())
    }

    async fn patch_firewall(&self, cfg: &FullVmInfo) -> Result<()> {
        let vm_id = cfg.vm.id.into();

        // Check and fix cloud-init IP config if it doesn't match expected
        let current_config = self.get_vm_config(&self.node, vm_id).await
            .context("Failed to get current VM config")?;
        let expected_config = self.make_config(cfg)
            .context("Failed to generate expected config")?;
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
            .await
            .context("Failed to update VM IP config")?;
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
            .await
            .context("Failed to disable VM firewall")?;
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
            .await
            .context("Failed to configure VM firewall")?;

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
            .await
            .context("Failed to create ipfilter-net0 IPset")?;
        }

        // Get existing entries to avoid duplicates
        let existing_entries = self
            .list_vm_ipset_entries(&self.node, vm_id, "ipfilter-net0")
            .await
            .context("Failed to list VM IPset entries")?;
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
    ) -> Result<Vec<TimeSeriesData>> {
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

    async fn connect_terminal(&self, vm: &Vm) -> Result<TerminalStream> {
        let _vm_id: ProxmoxVmId = vm.id.into();

        let (client_tx, client_rx) = channel::<Vec<u8>>(1024);
        let (server_tx, mut server_rx) = channel::<Vec<u8>>(1024);
        tokio::spawn(async move {
            // fire calls to read every 100ms
            loop {
                tokio::select! {
                    Some(buf) = server_rx.recv() => {
                        // echo
                        client_tx.send(buf).await?;
                    }

                }
            }
            info!("SSH connection terminated!");
            Ok::<(), anyhow::Error>(())
        });
        Ok(TerminalStream {
            rx: client_rx,
            tx: server_tx,
        })
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
            .map_while(|s| StorageContent::from_str(s).ok())
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
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct VmConfig {
    #[serde(rename = "onboot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "deserialize_int_to_bool")]
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
    #[serde(default, deserialize_with = "deserialize_int_to_bool")]
    pub kvm: Option<bool>,
    #[serde(rename = "serial0")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_0: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MB;
    use crate::host::tests::mock_full_vm;

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
                "ip=192.168.1.2/16,gw=192.168.1.1,ip=192.168.2.2/24,gw=10.10.10.10,ip6=auto"
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
}
