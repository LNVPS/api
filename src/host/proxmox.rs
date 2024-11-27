use anyhow::{anyhow, bail, Result};
use log::{error, info};
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

pub struct ProxmoxClient {
    base: Url,
    token: String,
    client: reqwest::Client,
}

impl ProxmoxClient {
    pub fn new(base: Url) -> Self {
        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build client");

        Self {
            base,
            token: String::new(),
            client,
        }
    }

    pub fn with_api_token(mut self, token: &str) -> Self {
        // PVEAPIToken=USER@REALM!TOKENID=UUID
        self.token = token.to_string();
        self
    }

    /// Get version info
    pub async fn version(&self) -> Result<VersionResponse> {
        let rsp: ResponseBase<VersionResponse> = self.get("/api2/json/version").await?;
        Ok(rsp.data)
    }

    /// List nodes
    pub async fn list_nodes(&self) -> Result<Vec<NodeResponse>> {
        let rsp: ResponseBase<Vec<NodeResponse>> = self.get("/api2/json/nodes").await?;
        Ok(rsp.data)
    }

    pub async fn get_vm_status(&self, node: &str, vm_id: i32) -> Result<VmInfo> {
        let rsp: ResponseBase<VmInfo> = self
            .get(&format!(
                "/api2/json/nodes/{node}/qemu/{vm_id}/status/current"
            ))
            .await?;
        Ok(rsp.data)
    }

    pub async fn list_vms(&self, node: &str) -> Result<Vec<VmInfo>> {
        let rsp: ResponseBase<Vec<VmInfo>> =
            self.get(&format!("/api2/json/nodes/{node}/qemu")).await?;
        Ok(rsp.data)
    }

    pub async fn list_storage(&self, node: &str) -> Result<Vec<NodeStorage>> {
        let rsp: ResponseBase<Vec<NodeStorage>> =
            self.get(&format!("/api2/json/nodes/{node}/storage")).await?;
        Ok(rsp.data)
    }

    /// List files in a storage pool
    pub async fn list_storage_files(&self, node: &str, storage: &str) -> Result<Vec<StorageContentEntry>> {
        let rsp: ResponseBase<Vec<StorageContentEntry>> =
            self.get(&format!("/api2/json/nodes/{node}/storage/{storage}/content")).await?;
        Ok(rsp.data)
    }

    /// Create a new VM
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/qemu
    pub async fn create_vm(&self, req: CreateVm) -> Result<TaskId> {
        info!("{}", serde_json::to_string_pretty(&req)?);
        let rsp: ResponseBase<Option<String>> = self
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
        info!("{}", serde_json::to_string_pretty(&req)?);
        let rsp: ResponseBase<Option<String>> = self
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

    /// Get the current status of a running task
    ///
    /// https://pve.proxmox.com/pve-docs/api-viewer/?ref=public_apis#/nodes/{node}/tasks/{upid}/status
    pub async fn get_task_status(&self, task: &TaskId) -> Result<TaskStatus> {
        let rsp: ResponseBase<TaskStatus> = self
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

    /// Download an image to the host disk
    pub async fn download_image(&self, req: DownloadUrlRequest) -> Result<TaskId> {
        let rsp: ResponseBase<String> = self
            .post(
                &format!(
                    "/api2/json/nodes/{}/storage/{}/download-url",
                    req.node, req.storage
                ),
                &req,
            )
            .await?;
        Ok(TaskId { id: rsp.data, node: req.node })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let rsp = self
            .client
            .get(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .send()
            .await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        info!("<< {}", text);
        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            bail!("{}", status);
        }
    }

    async fn post<T: DeserializeOwned, R: Serialize>(&self, path: &str, body: R) -> Result<T> {
        let rsp = self
            .client
            .post(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(serde_json::to_string(&body)?)
            .send()
            .await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        info!("<< {}", text);
        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            bail!("{}", status);
        }
    }
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

#[derive(Debug, Deserialize)]
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
            _ => Err(()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct NodeStorage {
    pub content: String,
    pub storage: String,
    #[serde(rename = "type")]
    pub kind: Option<StorageType>,
    #[serde(rename = "thinpool")]
    pub thin_pool: Option<String>,
}

impl NodeStorage {
    pub fn contents(&self) -> Vec<StorageContent> {
        self.content
            .split(",")
            .map_while(|s| s.parse().ok())
            .collect()
    }
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
    pub vm_id: i32,
    #[serde(flatten)]
    pub config: VmConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ConfigureVm {
    pub node: String,
    #[serde(rename = "vmid")]
    pub vm_id: i32,
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
}
