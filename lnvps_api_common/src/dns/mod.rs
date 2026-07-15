use crate::NetworkProvisioner;
use crate::retry::OpResult;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use lnvps_db::VmIpAssignment;
use lnvps_db::{DnsServerKind, LNVpsDb};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

mod cloudflare;
mod ovh;
pub use cloudflare::*;
pub use ovh::*;

/// A DNS zone available on a DNS server (provider specific, e.g. a Cloudflare zone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsZone {
    /// Provider specific zone id (e.g. Cloudflare zone id).
    pub id: String,
    /// Human readable zone name (e.g. `example.com`).
    pub name: String,
}

#[async_trait]
pub trait DnsServer: Send + Sync {
    /// Add a DNS record. The target zone (if any) is carried on `record.zone_id`.
    async fn add_record(&self, record: &BasicRecord) -> OpResult<BasicRecord>;

    /// Delete a DNS record. The target zone (if any) is carried on `record.zone_id`.
    async fn delete_record(&self, record: &BasicRecord) -> OpResult<()>;

    /// Update a DNS record. The target zone (if any) is carried on `record.zone_id`.
    async fn update_record(&self, record: &BasicRecord) -> OpResult<BasicRecord>;

    /// List the DNS zones available on this server.
    ///
    /// Read-only helper used by the admin API to populate zone pickers. Returns
    /// an empty list for providers that have no zone concept (e.g. OVH reverse
    /// DNS, which is keyed per-IP block).
    async fn list_zones(&self) -> OpResult<Vec<DnsZone>>;
}

/// Construct a DNS server client from a database `dns_server` row.
pub async fn get_dns_server(
    db: &Arc<dyn LNVpsDb>,
    dns_server_id: u64,
) -> OpResult<Arc<dyn DnsServer>> {
    let cfg = db.get_dns_server(dns_server_id).await?;
    match cfg.kind {
        DnsServerKind::Cloudflare => Ok(Arc::new(cloudflare::Cloudflare::new(cfg.token.as_str()))),
        DnsServerKind::Ovh => Ok(Arc::new(
            ovh::OvhDns::new(&cfg.url, cfg.token.as_str()).await?,
        )),
        DnsServerKind::MockDns => Ok(Arc::new(crate::MockDnsServer::new())),
    }
}

#[derive(Clone, Debug)]
pub enum RecordType {
    A,
    AAAA,
    PTR,
}

/// A reference to a DNS zone or record.
///
/// Some providers don't expose ids: OVH reverse DNS has no zones and addresses
/// records implicitly by the IP itself. Those use [`DnsRef::Implicit`]; zone- and
/// record-id based providers (e.g. Cloudflare) use [`DnsRef::Id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRef {
    /// No provider-assigned id; addressed implicitly (e.g. OVH keys on the IP).
    Implicit,
    /// Explicit provider-assigned id (e.g. a Cloudflare zone or record id).
    Id(String),
}

impl DnsRef {
    /// Build a reference from an optional stored id string; `None` → [`DnsRef::Implicit`].
    pub fn from_opt(s: Option<String>) -> Self {
        match s {
            Some(v) => DnsRef::Id(v),
            None => DnsRef::Implicit,
        }
    }

    /// The explicit id string, if this is [`DnsRef::Id`].
    pub fn as_id(&self) -> Option<&str> {
        match self {
            DnsRef::Id(s) => Some(s.as_str()),
            DnsRef::Implicit => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BasicRecord {
    pub name: String,
    pub value: String,
    /// The record's provider reference. `None` means the record has not been
    /// created yet; `Some(_)` carries its reference once created.
    pub id: Option<DnsRef>,
    pub kind: RecordType,
    /// The IP address this record refers to. Used by providers that key on the
    /// IP directly (e.g. OVH reverse DNS) rather than a zone + record id.
    pub ip: String,
    /// The target zone. [`DnsRef::Implicit`] for zoneless providers (OVH).
    pub zone: DnsRef,
}

impl BasicRecord {
    /// The id to persist after a create/update. Implicit providers (OVH) fall
    /// back to the IP as their stable key so the record can be found later.
    pub fn stored_ref(&self) -> Option<String> {
        match &self.id {
            Some(DnsRef::Id(s)) => Some(s.clone()),
            Some(DnsRef::Implicit) => Some(self.ip.clone()),
            None => None,
        }
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::PTR => write!(f, "PTR"),
        }
    }
}

impl BasicRecord {
    pub fn forward(ip: &VmIpAssignment, zone: DnsRef) -> Result<Self> {
        let addr = IpAddr::from_str(&ip.ip)?;
        Ok(Self {
            name: format!("vm-{}", &ip.vm_id),
            value: addr.to_string(),
            id: ip.dns_forward_ref.clone().map(DnsRef::Id),
            kind: match addr {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            },
            ip: ip.ip.clone(),
            zone,
        })
    }

    pub fn reverse_to_fwd(ip: &VmIpAssignment, zone: DnsRef) -> Result<Self> {
        let addr = IpAddr::from_str(&ip.ip)?;

        // Use explicit reverse entry or use the forward entry
        let fwd = ip
            .dns_reverse
            .as_ref()
            .or(ip.dns_forward.as_ref())
            .context("Reverse/Forward DNS name required for reverse entry")?
            .to_string();

        if !is_valid_fqdn(fwd.as_str()) {
            bail!("Forward DNS name is not a valid FQDN");
        }
        Ok(Self {
            name: match addr {
                IpAddr::V4(i) => i.octets()[3].to_string(),
                IpAddr::V6(i) => NetworkProvisioner::ipv6_to_ptr(&i)?,
            },
            value: fwd,
            id: ip.dns_reverse_ref.clone().map(DnsRef::Id),
            kind: RecordType::PTR,
            ip: ip.ip.clone(),
            zone,
        })
    }

    pub fn reverse(ip: &VmIpAssignment, zone: DnsRef) -> Result<Self> {
        let addr = IpAddr::from_str(&ip.ip)?;
        let rev = ip
            .dns_reverse
            .as_ref()
            .context("Reverse DNS name required for reverse entry")?
            .to_string();
        if !is_valid_fqdn(&rev) {
            bail!("Reverse DNS name is not a valid FQDN");
        }
        Ok(Self {
            name: match addr {
                IpAddr::V4(i) => i.octets()[3].to_string(),
                IpAddr::V6(i) => NetworkProvisioner::ipv6_to_ptr(&i)?,
            },
            value: rev,
            id: ip.dns_reverse_ref.clone().map(DnsRef::Id),
            kind: RecordType::PTR,
            ip: ip.ip.clone(),
            zone,
        })
    }
}

/// Grok 3
pub fn is_valid_fqdn(s: &str) -> bool {
    // Remove trailing dot if present (optional in practice)
    let s = s.strip_suffix('.').unwrap_or(s);

    // Check total length (max 255 chars, including dots)
    if s.len() > 255 || s.is_empty() {
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = s.split('.').collect();

    // Must have at least two labels (e.g., "example.com")
    if labels.len() < 2 {
        return false;
    }

    for label in labels {
        // Each label must be 1-63 chars
        if label.len() > 63 || label.is_empty() {
            return false;
        }

        // Must start with a letter or digit
        if !label.chars().next().unwrap().is_alphanumeric() {
            return false;
        }

        // Must end with a letter or digit
        if !label.chars().last().unwrap().is_alphanumeric() {
            return false;
        }

        // Only letters, digits, and hyphens allowed
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use lnvps_db::VmIpAssignment;

    fn v4_assignment() -> VmIpAssignment {
        VmIpAssignment {
            id: 1,
            vm_id: 42,
            ip_range_id: 1,
            ip: "10.0.0.5".to_string(),
            dns_reverse: Some("host.example.com".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_is_valid_fqdn() {
        assert!(is_valid_fqdn("example.com"));
        assert!(is_valid_fqdn("host.example.com."));
        assert!(!is_valid_fqdn("example"));
        assert!(!is_valid_fqdn(""));
        assert!(!is_valid_fqdn("-bad.example.com"));
    }

    #[test]
    fn test_dns_ref_helpers() {
        assert_eq!(DnsRef::from_opt(None), DnsRef::Implicit);
        assert_eq!(DnsRef::from_opt(Some("z".into())), DnsRef::Id("z".into()));
        assert_eq!(DnsRef::Id("z".into()).as_id(), Some("z"));
        assert_eq!(DnsRef::Implicit.as_id(), None);
    }

    #[test]
    fn test_stored_ref_implicit_uses_ip() {
        let mut rec = BasicRecord::forward(&v4_assignment(), DnsRef::Implicit).unwrap();
        rec.id = Some(DnsRef::Implicit);
        assert_eq!(rec.stored_ref().as_deref(), Some("10.0.0.5"));
        rec.id = Some(DnsRef::Id("cf-123".into()));
        assert_eq!(rec.stored_ref().as_deref(), Some("cf-123"));
        rec.id = None;
        assert_eq!(rec.stored_ref(), None);
    }

    #[test]
    fn test_forward_record_sets_ip_and_zone() -> anyhow::Result<()> {
        let ip = v4_assignment();
        let rec = BasicRecord::forward(&ip, DnsRef::Id("zone-1".to_string()))?;
        assert_eq!(rec.ip, "10.0.0.5");
        assert_eq!(rec.zone, DnsRef::Id("zone-1".to_string()));
        assert!(matches!(rec.kind, RecordType::A));
        assert_eq!(rec.name, "vm-42");
        Ok(())
    }

    #[test]
    fn test_reverse_records() -> anyhow::Result<()> {
        let ip = v4_assignment();
        let rev = BasicRecord::reverse(&ip, DnsRef::Id("rev-zone".to_string()))?;
        assert_eq!(rev.ip, "10.0.0.5");
        assert_eq!(rev.name, "5"); // last octet
        assert_eq!(rev.value, "host.example.com");
        assert!(matches!(rev.kind, RecordType::PTR));

        // reverse_to_fwd falls back to the forward name when reverse is unset
        let mut ip2 = v4_assignment();
        ip2.dns_reverse = None;
        ip2.dns_forward = Some("fwd.example.com".to_string());
        let rev2 = BasicRecord::reverse_to_fwd(&ip2, DnsRef::Implicit)?;
        assert_eq!(rev2.value, "fwd.example.com");
        assert_eq!(rev2.zone, DnsRef::Implicit);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_dns_server_mock() -> anyhow::Result<()> {
        // MockDb::default() seeds a MockDns dns_server with id=1
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let dns = get_dns_server(&db, 1).await?;

        let rec = BasicRecord::forward(&v4_assignment(), DnsRef::Id("zone-x".to_string()))?;
        let added = dns.add_record(&rec).await?;
        assert!(added.id.is_some());
        dns.delete_record(&added).await?;
        Ok(())
    }
}
