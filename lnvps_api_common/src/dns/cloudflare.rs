use crate::dns::{BasicRecord, DnsRef, DnsServer, DnsZone};
use crate::json_api::JsonApi;
use crate::op_transient;
use crate::retry::OpResult;
use anyhow::Context;
use async_trait::async_trait;
use log::info;
use serde::{Deserialize, Serialize};

pub struct Cloudflare {
    api: JsonApi,
}

impl Cloudflare {
    pub fn new(token: &str) -> Cloudflare {
        Self::with_base("https://api.cloudflare.com", token)
    }

    /// Construct a client pointed at an arbitrary base URL (used in tests to
    /// target a mock server).
    fn with_base(base: &str, token: &str) -> Cloudflare {
        Self {
            api: JsonApi::token(base, &format!("Bearer {}", token), false).unwrap(),
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

    /// Fetch all Cloudflare zones, following pagination.
    async fn list_zones(&self) -> OpResult<Vec<DnsZone>> {
        let mut zones = Vec::new();
        let mut page = 1u32;
        loop {
            let resp: CfResult<Vec<CfZone>> = self
                .api
                .get(&format!("/client/v4/zones?per_page=50&page={page}"))
                .await?;
            Self::bail_error(&resp)?;

            zones.extend(resp.result.into_iter().map(|z| DnsZone {
                id: z.id,
                name: z.name,
            }));

            let total_pages = resp
                .result_info
                .as_ref()
                .map(|i| i.total_pages)
                .unwrap_or(1)
                .max(1);
            if page >= total_pages {
                break;
            }
            page += 1;
        }
        Ok(zones)
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
    #[serde(default)]
    pub result_info: Option<CfResultInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfZone {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfResultInfo {
    pub total_pages: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct CfError {
    pub code: i32,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsServer;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_list_zones_paginates() -> anyhow::Result<()> {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "z1", "name": "one.example.com" }],
                "result_info": { "total_pages": 2 }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "z2", "name": "two.example.com" }],
                "result_info": { "total_pages": 2 }
            })))
            .mount(&server)
            .await;

        let cf = Cloudflare::with_base(&server.uri(), "token");
        let zones = cf.list_zones().await?;
        assert_eq!(
            zones,
            vec![
                DnsZone {
                    id: "z1".to_string(),
                    name: "one.example.com".to_string()
                },
                DnsZone {
                    id: "z2".to_string(),
                    name: "two.example.com".to_string()
                },
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_list_zones_api_error() -> anyhow::Result<()> {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/client/v4/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 1000, "message": "bad token" }],
                "result": [],
                "result_info": null
            })))
            .mount(&server)
            .await;

        let cf = Cloudflare::with_base(&server.uri(), "token");
        let err = cf.list_zones().await.unwrap_err();
        assert!(err.to_string().contains("bad token"));
        Ok(())
    }
}
