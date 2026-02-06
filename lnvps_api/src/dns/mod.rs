use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use lnvps_api_common::retry::OpResult;
use lnvps_db::VmIpAssignment;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

#[cfg(feature = "cloudflare")]
mod cloudflare;
use crate::provisioner::NetworkProvisioner;
#[cfg(feature = "cloudflare")]
pub use cloudflare::*;

#[async_trait]
pub trait DnsServer: Send + Sync {
    /// Add PTR record to the reverse zone
    async fn add_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<BasicRecord>;

    /// Delete PTR record from the reverse zone
    async fn delete_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<()>;

    /// Update a record
    async fn update_record(&self, zone_id: &str, record: &BasicRecord) -> OpResult<BasicRecord>;
}

#[derive(Clone, Debug)]
pub enum RecordType {
    A,
    AAAA,
    PTR,
}

#[derive(Debug, Clone)]
pub struct BasicRecord {
    pub name: String,
    pub value: String,
    pub id: Option<String>,
    pub kind: RecordType,
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
    pub fn forward(ip: &VmIpAssignment) -> Result<Self> {
        let addr = IpAddr::from_str(&ip.ip)?;
        Ok(Self {
            name: format!("vm-{}", &ip.vm_id),
            value: addr.to_string(),
            id: ip.dns_forward_ref.clone(),
            kind: match addr {
                IpAddr::V4(_) => RecordType::A,
                IpAddr::V6(_) => RecordType::AAAA,
            },
        })
    }

    pub fn reverse_to_fwd(ip: &VmIpAssignment) -> Result<Self> {
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
            id: ip.dns_reverse_ref.clone(),
            kind: RecordType::PTR,
        })
    }

    pub fn reverse(ip: &VmIpAssignment) -> Result<Self> {
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
            id: ip.dns_reverse_ref.clone(),
            kind: RecordType::PTR,
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
