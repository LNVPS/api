//! OVH reverse DNS provider.
//!
//! OVH exposes reverse DNS (PTR) management per-IP with no zones and no record
//! ids: <https://eu.api.ovh.com/console/?section=%2Fip#post-/ip/-ip-/reverse>.
//! Only reverse records are supported; forward (A/AAAA) records must be managed
//! by another provider (e.g. Cloudflare).

use crate::dns::{BasicRecord, DnsRef, DnsServer, DnsZone, RecordType};
use crate::json_api::JsonApi;
use crate::op_fatal;
use crate::ovh::ovh_json_api;
use crate::retry::OpResult;
use async_trait::async_trait;
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

    /// The OVH IP block (CIDR) that a reverse record belongs to. OVH keys reverse
    /// DNS on the *block*, not the individual address — POSTing a bare `/32`
    /// returns `404 This service does not exist`. The block is carried on the
    /// record's `zone` (from the range's `reverse_zone_id`); we fall back to the
    /// bare IP for standalone services with no configured block.
    fn block_for(record: &BasicRecord) -> String {
        match record.zone.as_id() {
            Some(block) => block.replace('/', "%2F"),
            None => record.ip.clone(),
        }
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
        let block = Self::block_for(record);
        info!("[OVH] Setting reverse: {} => {}", record.ip, reverse);

        let _: OvhReverse = self
            .api
            .post(
                &format!("v1/ip/{}/reverse", block),
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
        let block = Self::block_for(record);
        self.api
            .req::<(), ()>(
                reqwest::Method::DELETE,
                &format!("v1/ip/{}/reverse/{}", block, record.ip),
                None,
            )
            .await?;
        Ok(())
    }

    /// OVH reverse DNS is keyed per-IP block and exposes no listable zones.
    async fn list_zones(&self) -> OpResult<Vec<DnsZone>> {
        Ok(vec![])
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

    fn ptr_record(ip: &str, zone: DnsRef) -> BasicRecord {
        BasicRecord {
            name: ip.to_string(),
            value: "vm-1.lnvps.cloud".to_string(),
            id: None,
            kind: RecordType::PTR,
            ip: ip.to_string(),
            zone,
        }
    }

    #[test]
    fn test_block_for_uses_zone() {
        // Zone (block) present -> encoded CIDR used as the path segment.
        let rec = ptr_record("15.235.3.229", DnsRef::Id("15.235.3.224/28".to_string()));
        assert_eq!(OvhDns::block_for(&rec), "15.235.3.224%2F28");

        // No zone -> fall back to the bare IP (standalone service).
        let rec = ptr_record("15.235.3.229", DnsRef::Implicit);
        assert_eq!(OvhDns::block_for(&rec), "15.235.3.229");
    }

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
