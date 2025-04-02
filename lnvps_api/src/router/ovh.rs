use crate::json_api::{JsonApi, TokenGen};
use crate::router::{ArpEntry, Router};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use lnvps_db::async_trait;
use log::{info, warn};
use nostr::hashes::{sha1, Hash};
use nostr::Url;
use reqwest::header::{HeaderName, HeaderValue, ACCEPT};
use reqwest::{Method, RequestBuilder};
use rocket::form::validate::Contains;
use rocket::serde::Deserialize;
use serde::Serialize;
use std::ops::Sub;
use std::str::FromStr;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

/// This router is not really a router, but it allows
/// managing the virtual mac's for additional IPs on OVH dedicated servers
pub struct OvhDedicatedServerVMacRouter {
    name: String,
    api: JsonApi,
}

#[derive(Clone)]
struct OvhTokenGen {
    time_delta: i64,
    application_key: String,
    application_secret: String,
    consumer_key: String,
}

impl OvhTokenGen {
    pub fn new(time_delta: i64, token: &str) -> Result<Self> {
        let mut t_split = token.split(":");
        Ok(Self {
            time_delta,
            application_key: t_split
                .next()
                .context("Missing application_key")?
                .to_string(),
            application_secret: t_split
                .next()
                .context("Missing application_secret")?
                .to_string(),
            consumer_key: t_split.next().context("Missing consumer_key")?.to_string(),
        })
    }

    /// Compute signature for OVH.
    fn build_sig(
        method: &str,
        query: &str,
        body: &str,
        timestamp: &str,
        aas: &str,
        ck: &str,
    ) -> String {
        let sep = "+";
        let prefix = "$1$".to_string();

        let capacity = 1
            + aas.len()
            + sep.len()
            + ck.len()
            + method.len()
            + sep.len()
            + query.len()
            + sep.len()
            + body.len()
            + sep.len()
            + timestamp.len();
        let mut signature = String::with_capacity(capacity);
        signature.push_str(aas);
        signature.push_str(sep);
        signature.push_str(ck);
        signature.push_str(sep);
        signature.push_str(method);
        signature.push_str(sep);
        signature.push_str(query);
        signature.push_str(sep);
        signature.push_str(body);
        signature.push_str(sep);
        signature.push_str(timestamp);

        // debug!("Signature: {}", &signature);
        let sha1: sha1::Hash = Hash::hash(signature.as_bytes());
        let sig = hex::encode(sha1);
        prefix + &sig
    }
}

impl TokenGen for OvhTokenGen {
    fn generate_token(
        &self,
        method: Method,
        url: &Url,
        body: Option<&str>,
        req: RequestBuilder,
    ) -> Result<RequestBuilder> {
        let now = Utc::now().timestamp().sub(self.time_delta);
        let now_string = now.to_string();
        let sig = Self::build_sig(
            method.as_str(),
            url.as_str(),
            body.unwrap_or(""),
            now_string.as_str(),
            &self.application_secret,
            &self.consumer_key,
        );
        Ok(req
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Timestamp", now_string)
            .header("X-Ovh-Signature", sig))
    }
}

impl OvhDedicatedServerVMacRouter {
    pub async fn new(url: &str, name: &str, token: &str) -> Result<Self> {
        // load API time delta
        let time_api = JsonApi::new(url)?;
        let time = time_api.get_raw("v1/auth/time").await?;
        let delta: i64 = Utc::now().timestamp().sub(time.parse::<i64>()?);

        Ok(Self {
            name: name.to_string(),
            api: JsonApi::token_gen(url, false, OvhTokenGen::new(delta, token)?)?,
        })
    }

    async fn get_task(&self, task_id: i64) -> Result<OvhTaskResponse> {
        self.api
            .get(&format!(
                "v1/dedicated/server/{}/task/{}",
                self.name, task_id
            ))
            .await
    }

    /// Poll a task until it completes
    async fn wait_for_task_result(&self, task_id: i64) -> Result<OvhTaskResponse> {
        loop {
            let status = self.get_task(task_id).await?;
            match status.status {
                OvhTaskStatus::Cancelled => {
                    return Err(anyhow!(
                        "Task was cancelled: {}",
                        status.comment.unwrap_or_default()
                    ))
                }
                OvhTaskStatus::CustomerError => {
                    return Err(anyhow!(
                        "Task failed: {}",
                        status.comment.unwrap_or_default()
                    ))
                }
                OvhTaskStatus::Done => return Ok(status),
                OvhTaskStatus::OvhError => {
                    return Err(anyhow!(
                        "Task failed: {}",
                        status.comment.unwrap_or_default()
                    ))
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

    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>> {
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

    async fn add_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry> {
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
                    comment: entry.comment.clone().unwrap_or(String::new()),
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

    async fn remove_arp_entry(&self, id: &str) -> Result<()> {
        let entries = self.list_arp_entry().await?;
        if let Some(this_entry) = entries.into_iter().find(|e| e.id == Some(id.to_string())) {
            info!(
                "[OVH] Deleting mac ip: {} {}",
                this_entry.mac_address, this_entry.address
            );
            let task: OvhTaskResponse = self
                .api
                .req(
                    Method::DELETE,
                    &format!(
                        "v1/dedicated/server/{}/virtualMac/{}/virtualAddress/{}",
                        self.name, this_entry.mac_address, this_entry.address
                    ),
                    (),
                )
                .await?;
            self.wait_for_task_result(task.task_id).await?;
            Ok(())
        } else {
            bail!("Cannot remove arp entry, not found")
        }
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry> {
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
    RemoveVirtualMac
}
