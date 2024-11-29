use crate::router::Router;
use rocket::async_trait;
use std::net::IpAddr;

pub struct MikrotikRouter {
    url: String,
    token: String,
}

impl MikrotikRouter {
    pub fn new(url: &str, token: &str) -> Self {
        Self {
            url: url.to_string(),
            token: token.to_string(),
        }
    }
}

#[async_trait]
impl Router for MikrotikRouter {
    async fn add_arp_entry(
        &self,
        ip: IpAddr,
        mac: &[u8; 6],
        comment: Option<&str>,
    ) -> anyhow::Result<()> {
        todo!()
    }
}
