use crate::dns::{BasicRecord, DnsRef, DnsServer, DnsZone};
use crate::json_api::JsonApi;
use crate::op_transient;
use crate::retry::{OpError, OpResult};
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

    /// Cloudflare's error code for "An identical record already exists.".
    ///
    /// It is returned as a `400`, which `JsonApi` maps to a fatal error, so an
    /// add that races or replays a previous success kills the job for good
    /// unless it is treated as the no-op it actually is.
    const ERR_IDENTICAL_RECORD: i32 = 81058;

    /// Whether a failed request is Cloudflare complaining that the record we
    /// wanted to add is already there.
    ///
    /// `JsonApi` folds the response body into the error message, so the code is
    /// matched in the text rather than a typed field.
    fn is_identical_record_error(err: &OpError<anyhow::Error>) -> bool {
        let msg = err.inner().to_string();
        msg.contains(&format!("\"code\":{}", Self::ERR_IDENTICAL_RECORD))
            || msg.contains("An identical record already exists")
    }

    /// Look up a record by exact type/name/content, i.e. the record Cloudflare
    /// considers "identical" to one being added.
    async fn find_record(
        &self,
        zone_id: &str,
        record: &BasicRecord,
    ) -> OpResult<Option<BasicRecord>> {
        let rsp: CfResult<Vec<CfRecord>> = self
            .api
            .get(&format!(
                "/client/v4/zones/{}/dns_records?type={}&name={}&content={}",
                zone_id,
                urlencoding::encode(&record.kind.to_string()),
                urlencoding::encode(&record.name),
                urlencoding::encode(&record.value),
            ))
            .await?;
        Self::bail_error(&rsp)?;
        Ok(rsp.result.into_iter().next().map(|r| BasicRecord {
            name: r.name,
            value: r.content,
            id: r.id.map(DnsRef::Id),
            kind: record.kind.clone(),
            ip: record.ip.clone(),
            zone: record.zone.clone(),
        }))
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
        let posted: OpResult<CfResult<CfRecord>> = self
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
            .await;
        let id_response = match posted {
            Ok(r) => r,
            // The record we wanted already exists — a replayed or retried job,
            // or an assignment being re-applied. Adopt the existing record
            // instead of failing the whole job over work already done.
            Err(e) if Self::is_identical_record_error(&e) => {
                return match self.find_record(zone_id, record).await? {
                    Some(existing) => {
                        info!(
                            "Record already exists, reusing: [{}] {} => {}",
                            record.kind, record.name, record.value
                        );
                        Ok(existing)
                    }
                    // Cloudflare says it exists but will not show it to us
                    // (a different zone, or a permissions-scoped token);
                    // surface the original error rather than inventing a
                    // record with no id.
                    None => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
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

    use crate::dns::{DnsRef, RecordType};

    fn record() -> BasicRecord {
        BasicRecord {
            name: "vm-699.lnvps.cloud".to_string(),
            value: "51.68.216.208".to_string(),
            id: None,
            kind: RecordType::A,
            ip: "51.68.216.208".to_string(),
            zone: DnsRef::Id("zone1".to_string()),
        }
    }

    fn identical_record_body() -> serde_json::Value {
        serde_json::json!({
            "result": null,
            "success": false,
            "errors": [{ "code": 81058, "message": "An identical record already exists." }],
            "messages": []
        })
    }

    #[test]
    fn test_is_identical_record_error() {
        let err = OpError::Fatal(anyhow::anyhow!(
            "POST /client/v4/zones/z/dns_records: 400 Bad Request: {}",
            identical_record_body()
        ));
        assert!(Cloudflare::is_identical_record_error(&err));

        // Any other 400 must keep failing the job.
        let other = OpError::Fatal(anyhow::anyhow!(
            "POST /client/v4/zones/z/dns_records: 400 Bad Request: \
             {{\"errors\":[{{\"code\":9103,\"message\":\"Unauthorized\"}}]}}"
        ));
        assert!(!Cloudflare::is_identical_record_error(&other));
    }

    /// The bug this guards: a replayed or retried AssignVmIp hit Cloudflare's
    /// 81058 and killed the job for good, even though the record it wanted was
    /// already in place.
    #[tokio::test]
    async fn test_add_record_adopts_an_existing_identical_record() -> anyhow::Result<()> {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(400).set_body_json(identical_record_body()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{
                    "id": "rec1",
                    "name": "vm-699.lnvps.cloud",
                    "content": "51.68.216.208",
                    "type": "A"
                }]
            })))
            .mount(&server)
            .await;

        let cf = Cloudflare::with_base(&server.uri(), "token");
        let out = cf.add_record(&record()).await?;
        assert_eq!(out.id, Some(DnsRef::Id("rec1".to_string())));
        assert_eq!(out.value, "51.68.216.208");
        Ok(())
    }

    /// Cloudflare claiming the record exists while refusing to show it (a
    /// scope-limited token) must not silently produce a record with no id.
    #[tokio::test]
    async fn test_add_record_reports_the_error_when_the_record_is_not_visible() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(400).set_body_json(identical_record_body()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/client/v4/zones/zone1/dns_records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .mount(&server)
            .await;

        let cf = Cloudflare::with_base(&server.uri(), "token");
        let err = cf
            .add_record(&record())
            .await
            .expect_err("must not succeed");
        assert!(err.inner().to_string().contains("81058"));
    }

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
