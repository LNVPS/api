use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpPolicy {
    #[default]
    Keep,
    Reassign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationMethod {
    Hypervisor,
    CopyAndAdopt,
}

pub const DEFAULT_MIGRATION_SECS_PER_GB: u64 = 60;
pub const MIGRATION_BASE_TIMEOUT_SECS: u64 = 900;
pub const MIGRATION_ESTIMATE_BYTES_PER_SEC: u64 = 50 * crate::MB;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationOptions {
    #[serde(default)]
    pub ip_policy: IpPolicy,
    #[serde(default = "default_keep_source")]
    pub keep_source: bool,
    #[serde(default)]
    pub target_disk_id: Option<u64>,
    #[serde(default)]
    pub timeout_secs_per_gb: Option<u64>,
}

fn default_keep_source() -> bool {
    true
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            ip_policy: IpPolicy::Keep,
            keep_source: true,
            target_disk_id: None,
            timeout_secs_per_gb: None,
        }
    }
}

impl MigrationOptions {
    pub fn transfer_timeout_secs(&self, bytes: u64) -> u64 {
        let per_gb = self
            .timeout_secs_per_gb
            .unwrap_or(DEFAULT_MIGRATION_SECS_PER_GB);
        let gb = bytes.div_ceil(crate::GB);
        MIGRATION_BASE_TIMEOUT_SECS.saturating_add(gb.saturating_mul(per_gb))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationIpChange {
    pub old_ip: Option<String>,
    pub new_ip: Option<String>,
    pub range_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub vm_id: u64,
    pub source_host_id: u64,
    pub source_host_kind: String,
    pub source_region_id: u64,
    pub target_host_id: u64,
    pub target_host_kind: String,
    pub target_region_id: u64,
    pub method: Option<MigrationMethod>,
    pub ip_policy: IpPolicy,
    pub keep_source: bool,
    pub target_disk_id: Option<u64>,
    pub target_storage: Option<String>,
    pub disk_bytes: u64,
    pub estimated_seconds: Option<u64>,
    pub transfer_timeout_seconds: u64,
    pub ip_changes: Vec<MigrationIpChange>,
    pub warnings: Vec<String>,
    pub refusals: Vec<String>,
}

impl MigrationPlan {
    pub fn allowed(&self) -> bool {
        self.refusals.is_empty() && self.method.is_some() && self.target_disk_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_to_keeping_ips_and_the_source_copy() {
        let o: MigrationOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o, MigrationOptions::default());
        assert_eq!(o.ip_policy, IpPolicy::Keep);
        assert!(o.keep_source);
        let o: MigrationOptions =
            serde_json::from_str(r#"{"ip_policy":"reassign","keep_source":false}"#).unwrap();
        assert_eq!(o.ip_policy, IpPolicy::Reassign);
        assert!(!o.keep_source);
    }

    #[test]
    fn transfer_timeout_grows_with_disk_size() {
        let o = MigrationOptions::default();
        assert_eq!(o.transfer_timeout_secs(0), MIGRATION_BASE_TIMEOUT_SECS);
        assert_eq!(
            o.transfer_timeout_secs(100 * crate::GB),
            MIGRATION_BASE_TIMEOUT_SECS + 100 * DEFAULT_MIGRATION_SECS_PER_GB
        );
        let slow = MigrationOptions {
            timeout_secs_per_gb: Some(300),
            ..Default::default()
        };
        assert_eq!(
            slow.transfer_timeout_secs(crate::GB + 1),
            MIGRATION_BASE_TIMEOUT_SECS + 600
        );
    }
}
