//! OVH reverse DNS provider.
//!
//! OVH exposes reverse DNS (PTR) management per-IP with no zones and no record
//! ids: <https://eu.api.ovh.com/console/?section=%2Fip#post-/ip/-ip-/reverse>.
//! Only reverse records are supported; forward (A/AAAA) records must be managed
//! by another provider (e.g. Cloudflare).

use crate::dns::{BasicRecord, DnsRef, DnsServer, RecordType};
use crate::json_api::JsonApi;
use crate::ovh::ovh_json_api;
use async_trait::async_trait;
use lnvps_api_common::op_fatal;
use lnvps_api_common::retry::OpResult;
use log::info;
use serde::{Deserialize, Serialize};

pub struct OvhDns {
    api: JsonApi,
}

impl OvhDns {
    pub async fn new(url: &str, token: &str) -> OpResult<Self> {
        Ok(Self {
            api: ovh_json_api(url, token).await?,
        })
    }

    /// Ensure the reverse target is a fully-qualified name with a trailing dot,
    /// as required by the OVH API.
    fn fqdn_with_dot(value: &str) -> String {
        if value.ends_with('.') {
            value.to_string()
        } else {
            format!("{value}.")
        }
    }

    /// Set (create or overwrite) the reverse record for an IP.
    async fn set_reverse(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        if !matches!(record.kind, RecordType::PTR) {
            op_fatal!("OVH DNS only supports reverse (PTR) records");
        }
        let reverse = Self::fqdn_with_dot(&record.value);
        info!("[OVH] Setting reverse: {} => {}", record.ip, reverse);

        let _: OvhReverse = self
            .api
            .post(
                &format!("v1/ip/{}/reverse", record.ip),
                OvhReverseRequest {
                    ip_reverse: record.ip.clone(),
                    reverse: reverse.clone(),
                },
            )
            .await?;

        Ok(BasicRecord {
            name: record.ip.clone(),
            value: reverse,
            // OVH keys reverse records on the IP itself — there is no record id.
            id: Some(DnsRef::Implicit),
            kind: RecordType::PTR,
            ip: record.ip.clone(),
            zone: DnsRef::Implicit,
        })
    }
}

#[async_trait]
impl DnsServer for OvhDns {
    async fn add_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        self.set_reverse(record).await
    }

    async fn update_record(&self, record: &BasicRecord) -> OpResult<BasicRecord> {
        // OVH reverse is idempotent — a POST overwrites any existing entry.
        self.set_reverse(record).await
    }

    async fn delete_record(&self, record: &BasicRecord) -> OpResult<()> {
        if !matches!(record.kind, RecordType::PTR) {
            op_fatal!("OVH DNS only supports reverse (PTR) records");
        }
        info!("[OVH] Deleting reverse: {}", record.ip);
        self.api
            .req::<(), ()>(
                reqwest::Method::DELETE,
                &format!("v1/ip/{}/reverse/{}", record.ip, record.ip),
                None,
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OvhReverseRequest {
    ip_reverse: String,
    reverse: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhReverse {
    #[allow(dead_code)]
    ip_reverse: String,
    #[allow(dead_code)]
    reverse: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fqdn_with_dot() {
        assert_eq!(
            OvhDns::fqdn_with_dot("host.example.com"),
            "host.example.com."
        );
        assert_eq!(
            OvhDns::fqdn_with_dot("host.example.com."),
            "host.example.com."
        );
    }
}
