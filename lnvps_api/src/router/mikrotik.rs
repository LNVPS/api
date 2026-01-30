use crate::json_api::JsonApi;
use crate::router::{ArpEntry, Router};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use log::debug;
use reqwest::Method;
use serde::{Deserialize, Serialize};

pub struct MikrotikRouter {
    api: JsonApi,
}

impl MikrotikRouter {
    pub fn new(url: &str, username: &str, password: &str) -> Self {
        let auth = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", username, password))
        );
        Self {
            api: JsonApi::token(url, &auth, true).unwrap(),
        }
    }
}

#[async_trait]
impl Router for MikrotikRouter {
    async fn generate_mac(&self, _ip: &str, _comment: &str) -> Result<Option<ArpEntry>> {
        // Mikrotik router doesn't care what MAC address you use
        Ok(None)
    }

    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>> {
        let rsp: Vec<MikrotikArpEntry> = self
            .api
            .req::<_, ()>(Method::GET, "/rest/ip/arp", None)
            .await?;
        Ok(rsp.into_iter().filter_map(|e| e.try_into().ok()).collect())
    }

    async fn add_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry> {
        let req: MikrotikArpEntry = entry.clone().into();
        let rsp: MikrotikArpEntry = self.api.req(Method::PUT, "/rest/ip/arp", Some(req)).await?;
        debug!("{:?}", rsp);
        Ok(rsp.try_into()?)
    }

    async fn remove_arp_entry(&self, id: &str) -> Result<()> {
        let rsp: MikrotikArpEntry = self
            .api
            .req::<_, ()>(Method::DELETE, &format!("/rest/ip/arp/{}", id), None)
            .await?;
        debug!("{:?}", rsp);
        Ok(())
    }

    async fn update_arp_entry(&self, entry: &ArpEntry) -> Result<ArpEntry> {
        ensure!(entry.id.is_some(), "Cannot update an arp entry without ID");
        let req: MikrotikArpEntry = entry.clone().into();
        let rsp: MikrotikArpEntry = self
            .api
            .req(
                Method::PATCH,
                &format!("/rest/ip/arp/{}", entry.id.as_ref().unwrap()),
                Some(req),
            )
            .await?;
        debug!("{:?}", rsp);
        Ok(rsp.try_into()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MikrotikArpEntry {
    #[serde(rename = ".id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "mac-address")]
    pub mac_address: Option<String>,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl TryFrom<MikrotikArpEntry> for ArpEntry {
    type Error = anyhow::Error;

    fn try_from(value: MikrotikArpEntry) -> std::result::Result<Self, Self::Error> {
        Ok(ArpEntry {
            id: value.id,
            address: value.address,
            mac_address: value.mac_address.context("Mac address is empty")?,
            interface: Some(value.interface),
            comment: value.comment,
        })
    }
}

impl From<ArpEntry> for MikrotikArpEntry {
    fn from(val: ArpEntry) -> Self {
        MikrotikArpEntry {
            id: val.id,
            address: val.address,
            mac_address: Some(val.mac_address),
            interface: val.interface.unwrap(),
            comment: val.comment,
        }
    }
}
