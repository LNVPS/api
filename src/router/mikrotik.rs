use crate::json_api::JsonApi;
use crate::router::{ArpEntry, Router};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::Method;
use rocket::async_trait;
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
        let rsp: Vec<ArpEntry> = self.api.req(Method::GET, "/rest/ip/arp", ()).await?;
        Ok(rsp)
    }

    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &str,
        arp_interface: &str,
        comment: Option<&str>,
    ) -> Result<()> {
        let _rsp: ArpEntry = self
            .api
            .req(
                Method::PUT,
                "/rest/ip/arp",
                ArpEntry {
                    address: ip.to_string(),
                    mac_address: Some(mac.to_string()),
                    interface: arp_interface.to_string(),
                    comment: comment.map(|c| c.to_string()),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    async fn remove_arp_entry(&self, id: &str) -> Result<()> {
        let _rsp: ArpEntry = self
            .api
            .req(Method::DELETE, &format!("/rest/ip/arp/{id}"), ())
            .await?;

        Ok(())
    }
}
