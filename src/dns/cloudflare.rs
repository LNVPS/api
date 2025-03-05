use crate::dns::{BasicRecord, DnsServer, RecordType};
use crate::json_api::JsonApi;
use anyhow::Context;
use lnvps_db::async_trait;
use log::info;
use serde::{Deserialize, Serialize};

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

    fn bail_error<T>(rsp: &CfResult<T>) -> anyhow::Result<()> {
        if !rsp.success {
            anyhow::bail!(
                "Error updating record: {:?}",
                rsp.errors
                    .as_ref()
                    .map(|e| e.iter().map(|i| i.message.clone()).collect::<Vec<String>>().join(", "))
                    .unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[async_trait]
impl DnsServer for Cloudflare {
    async fn add_record(&self, record: &BasicRecord) -> anyhow::Result<BasicRecord> {
        let zone_id = match &record.kind {
            RecordType::PTR => &self.reverse_zone_id,
            _ => &self.forward_zone_id,
        };
        info!(
            "Adding record: [{}] {} => {}",
            record.kind, record.name, record.value
        );
        let id_response: CfResult<CfRecord> = self
            .api
            .post(
                &format!("/client/v4/zones/{zone_id}/dns_records"),
                CfRecord {
                    content: record.value.to_string(),
                    name: record.name.to_string(),
                    r_type: Some(record.kind.to_string()),
                    id: None,
                },
            )
            .await?;
        Self::bail_error(&id_response)?;
        Ok(BasicRecord {
            name: id_response.result.name,
            value: id_response.result.content,
            id: id_response.result.id,
            kind: record.kind.clone(),
        })
    }

    async fn delete_record(&self, record: &BasicRecord) -> anyhow::Result<()> {
        let zone_id = match &record.kind {
            RecordType::PTR => &self.reverse_zone_id,
            _ => &self.forward_zone_id,
        };
        let record_id = record.id.as_ref().context("record id missing")?;
        info!(
            "Deleting record: [{}] {} => {}",
            record.kind, record.name, record.value
        );
        let res: CfResult<IdResult> = self
            .api
            .req(
                reqwest::Method::DELETE,
                &format!("/client/v4/zones/{}/dns_records/{}", zone_id, record_id),
                CfRecord {
                    content: record.value.to_string(),
                    name: record.name.to_string(),
                    r_type: None,
                    id: None,
                },
            )
            .await?;
        Self::bail_error(&res)?;
        Ok(())
    }

    async fn update_record(&self, record: &BasicRecord) -> anyhow::Result<BasicRecord> {
        let zone_id = match &record.kind {
            RecordType::PTR => &self.reverse_zone_id,
            _ => &self.forward_zone_id,
        };
        info!(
            "Updating record: [{}] {} => {}",
            record.kind, record.name, record.value
        );
        let record_id = record.id.as_ref().context("record id missing")?;
        let id_response: CfResult<CfRecord> = self
            .api
            .req(
                reqwest::Method::PATCH,
                &format!("/client/v4/zones/{}/dns_records/{}", zone_id, record_id),
                CfRecord {
                    content: record.value.to_string(),
                    name: record.name.to_string(),
                    r_type: Some(record.kind.to_string()),
                    id: Some(record_id.to_string()),
                },
            )
            .await?;
        Self::bail_error(&id_response)?;
        Ok(BasicRecord {
            name: id_response.result.name,
            value: id_response.result.content,
            id: id_response.result.id,
            kind: record.kind.clone(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CfRecord {
    pub content: String,
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub r_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdResult {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfResult<T> {
    pub success: bool,
    pub errors: Option<Vec<CfError>>,
    pub result: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfError {
    pub code: i32,
    pub message: String,
}
