use crate::dns::{BasicRecord, DnsRef, DnsServer};
use crate::json_api::JsonApi;
use anyhow::Context;
use async_trait::async_trait;
use lnvps_api_common::op_transient;
use lnvps_api_common::retry::OpResult;
use log::info;
use serde::{Deserialize, Serialize};

pub struct Cloudflare {
    api: JsonApi,
}

impl Cloudflare {
    pub fn new(token: &str) -> Cloudflare {
        Self {
            api: JsonApi::token(
                "https://api.cloudflare.com",
                &format!("Bearer {}", token),
                false,
            )
            .unwrap(),
        }
    }

    fn bail_error<T>(rsp: &CfResult<T>) -> OpResult<()> {
        if !rsp.success {
            // TODO: map error codes
            op_transient!(
                "Error updating record: {:?}",
                rsp.errors
                    .as_ref()
                    .map(|e| e
                        .iter()
                        .map(|i| i.message.clone())
                        .collect::<Vec<String>>()
                        .join(", "))
                    .unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[async_trait]
impl DnsServer for Cloudflare {
    async fn add_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        let zone_id = record
            .zone
            .as_id()
            .context("zone id required for Cloudflare records")?;
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
            id: id_response.result.id.map(DnsRef::Id),
            kind: record.kind.clone(),
            ip: record.ip.clone(),
            zone: record.zone.clone(),
        })
    }

    async fn delete_record(&self, record: &BasicRecord) -> OpResult<()> {
        let zone_id = record
            .zone
            .as_id()
            .context("zone id required for Cloudflare records")?;
        let record_id = record
            .id
            .as_ref()
            .and_then(DnsRef::as_id)
            .context("record id missing")?;
        info!(
            "Deleting record: [{}] {} => {}",
            record.kind, record.name, record.value
        );
        let res: CfResult<IdResult> = self
            .api
            .req(
                reqwest::Method::DELETE,
                &format!("/client/v4/zones/{}/dns_records/{}", zone_id, record_id),
                Some(CfRecord {
                    content: record.value.to_string(),
                    name: record.name.to_string(),
                    r_type: None,
                    id: None,
                }),
            )
            .await?;
        Self::bail_error(&res)?;
        Ok(())
    }

    async fn update_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        let zone_id = record
            .zone
            .as_id()
            .context("zone id required for Cloudflare records")?;
        info!(
            "Updating record: [{}] {} => {}",
            record.kind, record.name, record.value
        );
        let record_id = record
            .id
            .as_ref()
            .and_then(DnsRef::as_id)
            .context("record id missing")?;
        let id_response: CfResult<CfRecord> = self
            .api
            .req(
                reqwest::Method::PATCH,
                &format!("/client/v4/zones/{}/dns_records/{}", zone_id, record_id),
                Some(CfRecord {
                    content: record.value.to_string(),
                    name: record.name.to_string(),
                    r_type: Some(record.kind.to_string()),
                    id: Some(record_id.to_string()),
                }),
            )
            .await?;
        Self::bail_error(&id_response)?;
        Ok(BasicRecord {
            name: id_response.result.name,
            value: id_response.result.content,
            id: id_response.result.id.map(DnsRef::Id),
            kind: record.kind.clone(),
            ip: record.ip.clone(),
            zone: record.zone.clone(),
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
