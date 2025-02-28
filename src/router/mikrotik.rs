use crate::router::{ArpEntry, Router};
use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::debug;
use reqwest::{Client, Method, Url};
use rocket::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::net::IpAddr;

pub struct MikrotikRouter {
    url: Url,
    username: String,
    password: String,
    client: Client,
}

impl MikrotikRouter {
    pub fn new(url: &str, username: &str, password: &str) -> Self {
        Self {
            url: url.parse().unwrap(),
            username: username.to_string(),
            password: password.to_string(),
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        }
    }

    async fn req<T: DeserializeOwned, R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: R,
    ) -> Result<T> {
        let body = serde_json::to_string(&body)?;
        debug!(">> {} {}: {}", method.clone(), path, &body);
        let rsp = self
            .client
            .request(method.clone(), self.url.join(path)?)
            .header(
                "Authorization",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", self.username, self.password))
                ),
            )
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            bail!("{} {}: {}", method, path, status);
        }
    }
}

#[async_trait]
impl Router for MikrotikRouter {
    async fn list_arp_entry(&self) -> Result<Vec<ArpEntry>> {
        let rsp: Vec<ArpEntry> = self.req(Method::GET, "/rest/ip/arp", ()).await?;
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
            .req(Method::DELETE, &format!("/rest/ip/arp/{id}"), ())
            .await?;

        Ok(())
    }
}
