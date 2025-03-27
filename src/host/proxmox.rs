use crate::host::{
    FullVmInfo, TerminalStream, TimeSeries, TimeSeriesData, VmHostClient, VmHostDiskInfo,
    VmHostInfo,
};
use crate::json_api::JsonApi;
use crate::settings::{QemuConfig, SshConfig};
use crate::ssh_client::SshClient;
use crate::status::{VmRunningState, VmState};
use anyhow::{anyhow, bail, ensure, Result};
use chrono::Utc;
use futures::StreamExt;
use ipnetwork::IpNetwork;
use lnvps_db::{async_trait, DiskType, Vm, VmOsImage};
use log::{info, warn};
use rand::random;
use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::{ClientBuilder, Method, Url};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

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
        let rsp: ResponseBase<VmInfo> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{node}/qemu/{vm_id}/status/current"
            ))
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
        let rsp: ResponseBase<Option<String>> = self
            .api
            .post(&format!("/api2/json/nodes/{}/qemu", req.node), &req)
            .await?;
        if let Some(id) = rsp.data {
            Ok(TaskId { id, node: req.node })
        } else {
            Err(anyhow!("Failed to configure VM"))
        }
    }

    /// Configure a VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu/{vmid}/config
    pub async fn configure_vm(&self, req: ConfigureVm) -> Result<TaskId> {
        let rsp: ResponseBase<Option<String>> = self
            .api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/config", req.node, req.vm_id),
                &req,
            )
            .await?;
        if let Some(id) = rsp.data {
            Ok(TaskId { id, node: req.node })
        } else {
            Err(anyhow!("Failed to configure VM"))
        }
    }

    /// Delete VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu
    pub async fn delete_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let rsp: ResponseBase<Option<String>> = self
            .api
            .req(
                Method::DELETE,
                &format!("/api2/json/nodes/{node}/qemu/{vm}"),
                (),
            )
            .await?;
        if let Some(id) = rsp.data {
            Ok(TaskId {
                id,
                node: node.to_string(),
            })
        } else {
            Err(anyhow!("Failed to configure VM"))
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
        let rsp: ResponseBase<TaskStatus> = self
            .api
            .get(&format!(
                "/api2/json/nodes/{}/tasks/{}/status",
                task.node, task.id
            ))
            .await?;
        Ok(rsp.data)
    }

    /// Helper function to wait for a task to complete
    pub async fn wait_for_task(&self, task: &TaskId) -> Result<TaskStatus> {
        loop {
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
        let rsp: ResponseBase<String> = self
            .api
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
            node: req.node,
        })
    }

    pub async fn import_disk_image(&self, req: ImportDiskImageRequest) -> Result<()> {
        // import the disk
        // TODO: find a way to avoid using SSH
        if let Some(ssh_config) = &self.ssh {
            let mut ses = SshClient::new()?;
            ses.connect(
                (self.api.base().host().unwrap().to_string(), 22),
                &ssh_config.user,
                &ssh_config.key,
            )
            .await?;

            // Disk import args
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
            let (code, rsp) = ses.execute(cmd.as_str()).await?;
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
        let rsp: ResponseBase<String> = self
            .api
            .req(
                Method::PUT,
                &format!("/api2/json/nodes/{}/qemu/{}/resize", &req.node, &req.vm_id),
                &req,
            )
            .await?;
        Ok(TaskId {
            id: rsp.data,
            node: req.node,
        })
    }

    /// Start a VM
    pub async fn start_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let rsp: ResponseBase<String> = self
            .api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/start", node, vm),
                (),
            )
            .await?;
        Ok(TaskId {
            id: rsp.data,
            node: node.to_string(),
        })
    }

    /// Stop a VM
    pub async fn stop_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let rsp: ResponseBase<String> = self
            .api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/stop", node, vm),
                (),
            )
            .await?;
        Ok(TaskId {
            id: rsp.data,
            node: node.to_string(),
        })
    }

    /// Stop a VM
    pub async fn shutdown_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let rsp: ResponseBase<String> = self
            .api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/shutdown", node, vm),
                (),
            )
            .await?;
        Ok(TaskId {
            id: rsp.data,
            node: node.to_string(),
        })
    }

    /// Stop a VM
    pub async fn reset_vm(&self, node: &str, vm: ProxmoxVmId) -> Result<TaskId> {
        let rsp: ResponseBase<String> = self
            .api
            .post(
                &format!("/api2/json/nodes/{}/qemu/{}/status/reset", node, vm),
                (),
            )
            .await?;
        Ok(TaskId {
            id: rsp.data,
            node: node.to_string(),
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
            .req_status(
                Method::PUT,
                &format!(
                    "/api2/json/nodes/{}/qemu/{}/unlink?idlist={}&force={}",
                    node,
                    vm,
                    disks.join(","),
                    if force { "1" } else { "0" }
                ),
                (),
            )
            .await?;
        Ok(())
    }
}

impl ProxmoxClient {
    fn make_config(&self, value: &FullVmInfo) -> Result<VmConfig> {
        let mut ip_config = value
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
                        IpAddr::V6(addr) => format!("ip6={}", addr),
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // TODO: make this configurable
        ip_config.push("ip6=auto".to_string());

        let mut net = vec![
            format!("virtio={}", value.vm.mac_address),
            format!("bridge={}", self.config.bridge),
        ];
        if let Some(t) = value.host.vlan_id {
            net.push(format!("tag={}", t));
        }

        let vm_resources = value.resources()?;
        Ok(VmConfig {
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
            ssh_keys: Some(urlencoding::encode(&value.ssh_key.key_data).to_string()),
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
        .await?;

        // resize disk to match template
        let j_resize = self
            .resize_disk(ResizeDiskRequest {
                node: self.node.clone(),
                vm_id,
                disk: "scsi0".to_string(),
                size: req.resources()?.disk_size.to_string(),
            })
            .await?;
        // TODO: rollback
        self.wait_for_task(&j_resize).await?;

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
                cpu: n.max_cpu.unwrap_or(0),
                memory: n.max_mem.unwrap_or(0),
                disks: storages
                    .into_iter()
                    .map(|s| VmHostDiskInfo {
                        name: s.storage,
                        size: s.total.unwrap_or(0),
                        used: s.used.unwrap_or(0),
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
        let config = self.make_config(req)?;
        let vm_id = req.vm.id.into();
        let t_create = self
            .create_vm(CreateVm {
                node: self.node.clone(),
                vm_id,
                config,
            })
            .await?;
        self.wait_for_task(&t_create).await?;

        // import template image
        self.import_template_disk(&req).await?;

        // try start, otherwise ignore error (maybe its already running)
        if let Ok(j_start) = self.start_vm(&self.node, vm_id).await {
            if let Err(e) = self.wait_for_task(&j_start).await {
                warn!("Failed to start vm: {}", e);
            }
        }

        Ok(())
    }

    async fn reinstall_vm(&self, req: &FullVmInfo) -> Result<()> {
        let vm_id = req.vm.id.into();

        // try stop, otherwise ignore error (maybe its already running)
        if let Ok(j_stop) = self.stop_vm(&self.node, vm_id).await {
            if let Err(e) = self.wait_for_task(&j_stop).await {
                warn!("Failed to stop vm: {}", e);
            }
        }

        // unlink the existing main disk
        self.unlink_disk(&self.node, vm_id, vec!["scsi0".to_string()], true)
            .await?;

        // import disk from template again
        self.import_template_disk(&req).await?;

        // try start, otherwise ignore error (maybe its already running)
        if let Ok(j_start) = self.start_vm(&self.node, vm_id).await {
            if let Err(e) = self.wait_for_task(&j_start).await {
                warn!("Failed to start vm: {}", e);
            }
        }

        Ok(())
    }

    async fn get_vm_state(&self, vm: &Vm) -> Result<VmState> {
        let s = self.get_vm_status(&self.node, vm.id.into()).await?;
        Ok(VmState {
            timestamp: Utc::now().timestamp() as u64,
            state: match s.status {
                VmStatus::Stopped => VmRunningState::Stopped,
                VmStatus::Running => VmRunningState::Running,
            },
            cpu_usage: s.cpu.unwrap_or(0.0),
            mem_usage: s.mem.unwrap_or(0) as f32 / s.max_mem.unwrap_or(1) as f32,
            uptime: s.uptime.unwrap_or(0),
            net_in: s.net_in.unwrap_or(0),
            net_out: s.net_out.unwrap_or(0),
            disk_write: s.disk_write.unwrap_or(0),
            disk_read: s.disk_read.unwrap_or(0),
        })
    }

    async fn configure_vm(&self, cfg: &FullVmInfo) -> Result<()> {
        let mut config = self.make_config(cfg)?;

        // dont re-create the disks
        config.scsi_0 = None;
        config.scsi_1 = None;
        config.efi_disk_0 = None;

        self.configure_vm(ConfigureVm {
            node: self.node.clone(),
            vm_id: cfg.vm.id.into(),
            current: None,
            snapshot: None,
            config,
        })
        .await?;
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
        let vm_id: ProxmoxVmId = vm.id.into();

        let (mut client_tx, client_rx) = channel::<Vec<u8>>(1024);
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
            .map_while(|s| StorageContent::from_str(&s).ok())
            .collect()
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeDisk {
}

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
    #[serde(flatten)]
    pub config: VmConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct VmConfig {
    #[serde(rename = "onboot")]
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GB, MB, TB};
    use lnvps_db::{
        DiskInterface, IpRange, OsDistribution, UserSshKey, VmHost, VmHostDisk, VmIpAssignment,
        VmTemplate,
    };

    #[test]
    fn test_config() -> Result<()> {
        let template = VmTemplate {
            id: 1,
            name: "example".to_string(),
            enabled: true,
            created: Default::default(),
            expires: None,
            cpu: 2,
            memory: 2 * GB,
            disk_size: 100 * GB,
            disk_type: DiskType::SSD,
            disk_interface: DiskInterface::PCIe,
            cost_plan_id: 1,
            region_id: 1,
        };
        let cfg = FullVmInfo {
            vm: Vm {
                id: 1,
                host_id: 1,
                user_id: 1,
                image_id: 1,
                template_id: Some(template.id),
                custom_template_id: None,
                ssh_key_id: 1,
                created: Default::default(),
                expires: Default::default(),
                disk_id: 1,
                mac_address: "ff:ff:ff:ff:ff:fe".to_string(),
                deleted: false,
                ref_code: None,
            },
            host: VmHost {
                id: 1,
                kind: Default::default(),
                region_id: 1,
                name: "mock".to_string(),
                ip: "https://localhost:8006".to_string(),
                cpu: 20,
                memory: 128 * GB,
                enabled: true,
                api_token: "mock".to_string(),
                load_cpu: 1.0,
                load_memory: 1.0,
                load_disk: 1.0,
                vlan_id: Some(100),
            },
            disk: VmHostDisk {
                id: 1,
                host_id: 1,
                name: "ssd".to_string(),
                size: TB * 20,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                enabled: true,
            },
            template: Some(template.clone()),
            custom_template: None,
            image: VmOsImage {
                id: 1,
                distribution: OsDistribution::Ubuntu,
                flavour: "Server".to_string(),
                version: "24.04.03".to_string(),
                enabled: true,
                release_date: Utc::now(),
                url: "http://localhost.com/ubuntu_server_24.04.img".to_string(),
            },
            ips: vec![
                VmIpAssignment {
                    id: 1,
                    vm_id: 1,
                    ip_range_id: 1,
                    ip: "192.168.1.2".to_string(),
                    deleted: false,
                    arp_ref: None,
                    dns_forward: None,
                    dns_forward_ref: None,
                    dns_reverse: None,
                    dns_reverse_ref: None,
                },
                VmIpAssignment {
                    id: 2,
                    vm_id: 1,
                    ip_range_id: 2,
                    ip: "192.168.2.2".to_string(),
                    deleted: false,
                    arp_ref: None,
                    dns_forward: None,
                    dns_forward_ref: None,
                    dns_reverse: None,
                    dns_reverse_ref: None,
                },
            ],
            ranges: vec![
                IpRange {
                    id: 1,
                    cidr: "192.168.1.0/24".to_string(),
                    gateway: "192.168.1.1/16".to_string(),
                    enabled: true,
                    region_id: 1,
                    reverse_zone_id: None,
                    access_policy_id: None,
                },
                IpRange {
                    id: 2,
                    cidr: "192.168.2.0/24".to_string(),
                    gateway: "10.10.10.10".to_string(),
                    enabled: true,
                    region_id: 2,
                    reverse_zone_id: None,
                    access_policy_id: None,
                },
            ],
            ssh_key: UserSshKey {
                id: 1,
                name: "test".to_string(),
                user_id: 1,
                created: Default::default(),
                key_data: "ssh-ed25519 AAA=".to_string(),
            },
        };

        let q_cfg = QemuConfig {
            machine: "q35".to_string(),
            os_type: "l26".to_string(),
            bridge: "vmbr1".to_string(),
            cpu: "kvm64".to_string(),
            kvm: true,
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
        assert!(vm.net.unwrap().contains("tag=100"));
        assert_eq!(
            vm.ip_config,
            Some(
                "ip=192.168.1.2/16,gw=192.168.1.1,ip=192.168.2.2/24,gw=10.10.10.10,ip6=auto"
                    .to_string()
            )
        );
        Ok(())
    }
}
