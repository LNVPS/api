use crate::router::{ArpEntry, Router};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lnvps_api_common::JsonApi;
use lnvps_api_common::op_transient;
use lnvps_api_common::ovh_json_api;
use lnvps_api_common::retry::{OpError, OpResult};
use log::{info, warn};
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// This router is not really a router, but it allows
/// managing the virtual mac's for additional IPs on OVH dedicated servers
pub struct OvhDedicatedServerVMacRouter {
    name: String,
    api: JsonApi,
}

impl OvhDedicatedServerVMacRouter {
    pub async fn new(url: &str, name: &str, token: &str) -> OpResult<Self> {
        Ok(Self {
            name: name.to_string(),
            api: ovh_json_api(url, token).await?,
        })
    }

    async fn get_task(&self, task_id: i64) -> OpResult<OvhTaskResponse> {
        self.api
            .get(&format!(
                "v1/dedicated/server/{}/task/{}",
                self.name, task_id
            ))
            .await
    }

    /// Poll a task until it completes
    async fn wait_for_task_result(&self, task_id: i64) -> OpResult<OvhTaskResponse> {
        loop {
            let status = self.get_task(task_id).await?;
            match status.status {
                OvhTaskStatus::Cancelled => {
                    op_transient!("Task was cancelled: {}", status.comment.unwrap_or_default());
                }
                OvhTaskStatus::CustomerError => {
                    // TODO: check error codes
                    op_transient!("Task failed: {}", status.comment.unwrap_or_default());
                }
                OvhTaskStatus::Done => return Ok(status),
                OvhTaskStatus::OvhError => {
                    op_transient!("Task failed: {}", status.comment.unwrap_or_default());
                }
                _ => {}
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
}

#[async_trait]
impl Router for OvhDedicatedServerVMacRouter {
    async fn generate_mac(&self, ip: &str, comment: &str) -> Result<Option<ArpEntry>> {
        info!("[OVH] Generating mac: {}={}", ip, comment);
        let rsp: OvhTaskResponse = self
            .api
            .post(
                &format!("v1/dedicated/server/{}/virtualMac", &self.name),
                OvhVMacRequest {
                    ip_address: ip.to_string(),
                    kind: OvhVMacType::Ovh,
                    name: comment.to_string(),
                },
            )
            .await?;

        self.wait_for_task_result(rsp.task_id).await?;

        // api is shit, lookup ip address in list of arp entries
        let e = self.list_arp_entry().await?;
        Ok(e.into_iter().find(|e| e.address == ip))
    }

    async fn list_arp_entry(&self) -> OpResult<Vec<ArpEntry>> {
        let rsp: Vec<String> = self
            .api
            .get(&format!("v1/dedicated/server/{}/virtualMac", &self.name))
            .await?;

        let mut ret = vec![];
        for mac in rsp {
            let rsp2: Vec<String> = self
                .api
                .get(&format!(
                    "v1/dedicated/server/{}/virtualMac/{}/virtualAddress",
                    &self.name, mac
                ))
                .await?;

            for addr in rsp2 {
                ret.push(ArpEntry {
                    id: Some(format!("{}={}", mac, &addr)),
                    address: addr,
                    mac_address: mac.clone(),
                    interface: None,
                    comment: None,
                })
            }
        }

        Ok(ret)
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        info!(
            "[OVH] Adding mac ip: {} {}",
            entry.mac_address, entry.address
        );
        #[derive(Serialize)]
        struct AddVMacAddressRequest {
            #[serde(rename = "ipAddress")]
            pub ip_address: String,
            #[serde(rename = "virtualMachineName")]
            pub comment: String,
        }
        let id = format!("{}={}", &entry.mac_address, &entry.address);
        let task: OvhTaskResponse = self
            .api
            .post(
                &format!(
                    "v1/dedicated/server/{}/virtualMac/{}/virtualAddress",
                    &self.name, &entry.mac_address
                ),
                AddVMacAddressRequest {
                    ip_address: entry.address.clone(),
                    comment: entry.comment.clone().unwrap_or_default(),
                },
            )
            .await?;
        self.wait_for_task_result(task.task_id).await?;

        Ok(ArpEntry {
            id: Some(id),
            address: entry.address.clone(),
            mac_address: entry.mac_address.clone(),
            interface: None,
            comment: None,
        })
    }

    async fn remove_arp_entry(&self, id: &str) -> OpResult<()> {
        let entries = self.list_arp_entry().await?;
        if let Some(this_entry) = entries.into_iter().find(|e| e.id == Some(id.to_string())) {
            info!(
                "[OVH] Deleting mac ip: {} {}",
                this_entry.mac_address, this_entry.address
            );
            let task: OvhTaskResponse = self
                .api
                .req::<_, ()>(
                    Method::DELETE,
                    &format!(
                        "v1/dedicated/server/{}/virtualMac/{}/virtualAddress/{}",
                        self.name, this_entry.mac_address, this_entry.address
                    ),
                    None,
                )
                .await?;
            self.wait_for_task_result(task.task_id).await?;
            Ok(())
        } else {
            Err(OpError::Fatal(anyhow::anyhow!(
                "Cannot remove arp entry, not found"
            )))
        }
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> OpResult<ArpEntry> {
        // cant patch just return the entry
        warn!("[OVH] Updating virtual mac is not supported");
        Ok(entry.clone())
    }
}

#[derive(Debug, Serialize)]
struct OvhVMacRequest {
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "type")]
    pub kind: OvhVMacType,
    #[serde(rename = "virtualMachineName")]
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum OvhVMacType {
    Ovh,
    VMWare,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhTaskResponse {
    pub comment: Option<String>,
    pub done_date: Option<DateTime<Utc>>,
    pub function: OvhTaskFunction,
    pub last_update: Option<DateTime<Utc>>,
    pub need_schedule: bool,
    pub note: Option<String>,
    pub planned_intervention_id: Option<i64>,
    pub start_date: DateTime<Utc>,
    pub status: OvhTaskStatus,
    pub tags: Option<Vec<KVSimple>>,
    pub task_id: i64,
    pub ticket_reference: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KVSimple {
    pub key: Option<String>,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum OvhTaskStatus {
    Cancelled,
    CustomerError,
    Doing,
    Done,
    Init,
    OvhError,
    Todo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum OvhTaskFunction {
    AddVirtualMac,
    MoveVirtualMac,
    VirtualMacAdd,
    VirtualMacDelete,
    RemoveVirtualMac,
}
