use anyhow::Error;
use reqwest::{Body, ClientBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Deserialize;
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
    pub async fn version(&self) -> Result<VersionResponse, Error> {
        let rsp: ResponseBase<VersionResponse> = self.get("/api2/json/version").await?;
        Ok(rsp.data)
    }

    /// List nodes
    pub async fn list_nodes(&self) -> Result<Vec<NodeResponse>, Error> {
        let rsp: ResponseBase<Vec<NodeResponse>> = self.get("/api2/json/nodes").await?;
        Ok(rsp.data)
    }

    pub async fn list_vms(&self, node: &str, full: bool) -> Result<Vec<VmInfo>, Error> {
        let rsp: ResponseBase<Vec<VmInfo>> =
            self.get(&format!("/api2/json/nodes/{node}/qemu")).await?;
        Ok(rsp.data)
    }
    pub async fn list_storage(&self) -> Result<Vec<NodeStorage>, Error> {
        let rsp: ResponseBase<Vec<NodeStorage>> = self.get("/api2/json/storage").await?;
        Ok(rsp.data)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        Ok(self
            .client
            .get(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .send()
            .await?
            .json::<T>()
            .await
            .map_err(|e| Error::new(e))?)
    }

    async fn post<T: DeserializeOwned, R: Into<Body>>(
        &self,
        path: &str,
        body: R,
    ) -> Result<T, Error> {
        Ok(self
            .client
            .post(self.base.join(path)?)
            .header("Authorization", format!("PVEAPIToken={}", self.token))
            .body(body)
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
