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

/// Decide what to do about an IP that OVH already has a virtual MAC for.
///
/// OVH allows exactly one virtual MAC per IP and rejects a second one with
/// `403 A Virtual Mac already exists on <ip>!`, so the add has to be checked
/// against the current state first:
///
/// - already bound to the MAC we want — nothing to do, report the existing
///   entry so a retried or replayed job succeeds instead of failing fatally
/// - bound to a different MAC — refuse, naming the MAC that holds it. Silently
///   stealing the address would strand whatever is actually using it, and the
///   binding has to be removed (by unassigning the other VM's IP) first
/// - not bound — `None`, carry on with the add
fn existing_binding(entries: &[ArpEntry], entry: &ArpEntry) -> OpResult<Option<ArpEntry>> {
    let Some(existing) = entries.iter().find(|e| e.address == entry.address) else {
        return Ok(None);
    };
    if existing
        .mac_address
        .eq_ignore_ascii_case(&entry.mac_address)
    {
        return Ok(Some(existing.clone()));
    }
    Err(OpError::Fatal(anyhow::anyhow!(
        "Cannot add arp entry, {} already has virtual mac {} on this server (wanted {}). \
         Remove that binding before assigning the address elsewhere.",
        entry.address,
        existing.mac_address,
        entry.mac_address
    )))
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
        // OVH permits one virtual MAC per IP; adding a second is a hard 403, so
        // a retry of a job that already succeeded (or a re-assign of an address
        // the VM is already using) would fail forever without this check.
        if let Some(existing) = existing_binding(&self.list_arp_entry().await?, entry)? {
            info!(
                "[OVH] Mac ip already present, nothing to do: {} {}",
                existing.mac_address, existing.address
            );
            return Ok(existing);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(mac: &str, ip: &str) -> ArpEntry {
        ArpEntry {
            id: Some(format!("{}={}", mac, ip)),
            address: ip.to_string(),
            mac_address: mac.to_string(),
            interface: None,
            comment: None,
        }
    }

    #[test]
    fn test_existing_binding_absent() {
        let entries = vec![arp("02:00:00:aa:bb:cc", "51.68.216.1")];
        let want = arp("02:00:00:cb:52:55", "51.68.216.208");
        assert!(existing_binding(&entries, &want).unwrap().is_none());
        assert!(existing_binding(&[], &want).unwrap().is_none());
    }

    #[test]
    fn test_existing_binding_same_mac_is_a_no_op() {
        let entries = vec![arp("02:00:00:cb:52:55", "51.68.216.208")];
        let want = arp("02:00:00:cb:52:55", "51.68.216.208");
        let found = existing_binding(&entries, &want).unwrap().unwrap();
        assert_eq!(found.mac_address, "02:00:00:cb:52:55");
        assert_eq!(found.address, "51.68.216.208");

        // OVH returns MACs lowercased, but don't depend on the caller matching.
        let upper = arp("02:00:00:CB:52:55", "51.68.216.208");
        assert!(existing_binding(&entries, &upper).unwrap().is_some());
    }

    #[test]
    fn test_existing_binding_other_mac_is_fatal() {
        let entries = vec![arp("02:00:00:aa:bb:cc", "51.68.216.208")];
        let want = arp("02:00:00:cb:52:55", "51.68.216.208");
        let err = existing_binding(&entries, &want).unwrap_err();
        assert!(matches!(err, OpError::Fatal(_)), "retrying cannot help");
        let msg = err.to_string();
        assert!(msg.contains("02:00:00:aa:bb:cc"), "names the holder: {msg}");
        assert!(msg.contains("51.68.216.208"), "names the address: {msg}");
    }
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
