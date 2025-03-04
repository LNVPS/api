use crate::json_api::JsonApi;
use crate::router::{ArpEntry, Router};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::debug;
use reqwest::Method;
use rocket::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
            api: JsonApi::token(url, &auth).unwrap(),
        }
    }
}

#[async_trait]
impl Router for MikrotikRouter {
    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>> {
        let rsp: Vec<MikrotikArpEntry> = self.api.req(Method::GET, "/rest/ip/arp", ()).await?;
        Ok(rsp.into_iter().map(|e| e.into()).collect())
    }

    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &str,
        arp_interface: &str,
        comment: Option<&str>,
    ) -> Result<ArpEntry> {
        let rsp: MikrotikArpEntry = self
            .api
            .req(
                Method::PUT,
                "/rest/ip/arp",
                MikrotikArpEntry {
                    id: None,
                    address: ip.to_string(),
                    mac_address: Some(mac.to_string()),
                    interface: arp_interface.to_string(),
                    comment: comment.map(|c| c.to_string()),
                },
            )
            .await?;
        debug!("{:?}", rsp);
        Ok(rsp.into())
    }

    async fn remove_arp_entry(&self, id: &str) -> Result<()> {
        let rsp: MikrotikArpEntry = self
            .api
            .req(Method::DELETE, &format!("/rest/ip/arp/{id}"), ())
            .await?;
        debug!("{:?}", rsp);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MikrotikArpEntry {
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

impl Into<ArpEntry> for MikrotikArpEntry {
    fn into(self) -> ArpEntry {
        ArpEntry {
            id: self.id.unwrap(),
            address: self.address,
            mac_address: self.mac_address.unwrap(),
            interface: Some(self.interface),
            comment: self.comment,
        }
    }
}
