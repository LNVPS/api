use anyhow::Result;
use reqwest::{ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

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

    pub async fn list_vms(&self, node: &str, full: bool) -> Result<Vec<VmInfo>> {
        let rsp: ResponseBase<Vec<VmInfo>> =
            self.get(&format!("/api2/json/nodes/{node}/qemu")).await?;
        Ok(rsp.data)
    }
    pub async fn list_storage(&self) -> Result<Vec<NodeStorage>> {
        let rsp: ResponseBase<Vec<NodeStorage>> = self.get("/api2/json/storage").await?;
        Ok(rsp.data)
    }

    pub async fn create_vm(&self, node: &str, req: CreateVm) -> Result<VmInfo> {
        let rsp: ResponseBase<VmInfo> = self
            .post(&format!("/api2/json/nodes/{node}/qemu"), req)
            .await?;
        Ok(rsp.data)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(self
            .client
            .get(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .send()
            .await?
            .json::<T>()
            .await
            .map_err(|e| anyhow::Error::new(e))?)
    }

    async fn post<T: DeserializeOwned, R: Serialize>(&self, path: &str, body: R) -> Result<T> {
        Ok(self
            .client
            .post(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    LVMThin,
    Dir,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageContent {
    Images,
    RootDir,
    Backup,
    ISO,
    VZTmpL,
}

#[derive(Debug, Deserialize)]
pub struct NodeStorage {
    pub storage: String,
    #[serde(rename = "type")]
    pub kind: Option<StorageType>,
    #[serde(rename = "thinpool")]
    pub thin_pool: Option<String>,
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
