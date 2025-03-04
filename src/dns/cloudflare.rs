use crate::dns::{BasicRecord, DnsServer, RecordType};
use crate::json_api::JsonApi;
use lnvps_db::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct Cloudflare {
    api: JsonApi,
    reverse_zone_id: String,
    forward_zone_id: String,
}

impl Cloudflare {
    pub fn new(token: &str, reverse_zone_id: &str, forward_zone_id: &str) -> Cloudflare {
        Self {
            api: JsonApi::token("https://api.cloudflare.com", &format!("Bearer {}", token))
                .unwrap(),
            reverse_zone_id: reverse_zone_id.to_owned(),
            forward_zone_id: forward_zone_id.to_owned(),
        }
    }
}

#[async_trait]
impl DnsServer for Cloudflare {
    async fn add_ptr_record(&self, key: &str, value: &str) -> anyhow::Result<BasicRecord> {
        let id_response: CfResult<CfRecord> = self
            .api
            .post(
                &format!("/client/v4/zones/{}/dns_records", self.reverse_zone_id),
                CfRecord {
                    content: value.to_string(),
                    name: key.to_string(),
                    r_type: "PTR".to_string(),
                    id: None,
                },
            )
            .await?;
        Ok(BasicRecord {
            name: id_response.result.name,
            value: value.to_string(),
            id: id_response.result.id,
            kind: RecordType::PTR,
        })
    }

    async fn delete_ptr_record(&self, key: &str) -> anyhow::Result<()> {
        todo!()
    }

    async fn add_a_record(&self, name: &str, ip: IpAddr) -> anyhow::Result<BasicRecord> {
        let id_response: CfResult<CfRecord> = self
            .api
            .post(
                &format!("/client/v4/zones/{}/dns_records", self.forward_zone_id),
                CfRecord {
                    content: ip.to_string(),
                    name: name.to_string(),
                    r_type: if ip.is_ipv4() {
                        "A".to_string()
                    } else {
                        "AAAA".to_string()
                    },
                    id: None,
                },
            )
            .await?;
        Ok(BasicRecord {
            name: id_response.result.name,
            value: ip.to_string(),
            id: id_response.result.id,
            kind: RecordType::A,
        })
    }

    async fn delete_a_record(&self, name: &str) -> anyhow::Result<()> {
        todo!()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CfRecord {
    pub content: String,
    pub name: String,
    #[serde(rename = "type")]
    pub r_type: String,
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfResult<T> {
    pub success: bool,
    pub result: T,
}
