use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;

use crate::api_client::ApiClient;

/// Executes tool calls by invoking the LNVPS APIs.
/// Each instance is scoped to a single user — all tools operate
/// within that user's context without taking user identifiers.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String>;
}

/// Parse a tool's JSON arguments into a map (empty on parse failure).
fn parse_args(arguments: &str) -> HashMap<String, serde_json::Value> {
    serde_json::from_str(arguments).unwrap_or_default()
}

/// Extract a required `u64` argument by key.
fn required_u64(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("{} required", key))
}

/// Serialize a JSON value as a pretty string for the LLM to read.
fn pretty(value: &serde_json::Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// The actual tool executor backed by the API client, scoped to one user.
pub struct LnvpsToolExecutor {
    api: Arc<ApiClient>,
    user_id: u64,
}

impl LnvpsToolExecutor {
    pub fn new(api: Arc<ApiClient>, user_id: u64) -> Self {
        Self { api, user_id }
    }

    async fn check_vm_ownership(&self, vm_id: u64) -> Result<()> {
        let vm = self.api.admin_get_vm(vm_id).await?;
        let owner = vm["user_id"]
            .as_u64()
            .ok_or_else(|| anyhow!("VM {} has no user_id field", vm_id))?;
        if owner != self.user_id {
            bail!(
                "VM {} does not belong to the current user (owner is {})",
                vm_id,
                owner
            );
        }
        Ok(())
    }

    /// Extract the `vm_id` argument and confirm the current user owns it.
    async fn owned_vm_id(&self, args: &HashMap<String, serde_json::Value>) -> Result<u64> {
        let vm_id = required_u64(args, "vm_id")?;
        self.check_vm_ownership(vm_id).await?;
        Ok(vm_id)
    }
}

#[async_trait]
impl ToolExecutor for LnvpsToolExecutor {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String> {
        let args = parse_args(arguments);

        match name {
            "get_my_account" => pretty(&self.api.admin_get_user(self.user_id).await?),
            "list_my_vms" => pretty(&serde_json::Value::Array(
                self.api.admin_list_vms(Some(self.user_id), None).await?,
            )),
            "get_vm_details" => {
                let vm_id = self.owned_vm_id(&args).await?;
                pretty(&self.api.admin_get_vm(vm_id).await?)
            }
            "list_vm_payments" => {
                let vm_id = self.owned_vm_id(&args).await?;
                pretty(&serde_json::Value::Array(
                    self.api.admin_list_vm_payments(vm_id).await?,
                ))
            }
            "list_vm_history" => {
                let vm_id = self.owned_vm_id(&args).await?;
                pretty(&serde_json::Value::Array(
                    self.api.admin_list_vm_history(vm_id).await?,
                ))
            }
            "extend_vm" => {
                let vm_id = self.owned_vm_id(&args).await?;
                let days = required_u64(&args, "days")?;
                pretty(&self.api.admin_extend_vm(vm_id, days).await?)
            }
            "refund_vm" => {
                let vm_id = self.owned_vm_id(&args).await?;
                pretty(&self.api.admin_refund_vm(vm_id).await?)
            }
            "delete_vm" => {
                let vm_id = self.owned_vm_id(&args).await?;
                pretty(&self.api.admin_delete_vm(vm_id).await?)
            }
            "list_regions" => pretty(&serde_json::Value::Array(
                self.api.admin_list_regions().await?,
            )),
            "list_templates" => pretty(&serde_json::Value::Array(
                self.api.admin_list_templates().await?,
            )),
            "list_os_images" => pretty(&serde_json::Value::Array(
                self.api.admin_list_os_images().await?,
            )),
            _ => bail!("Unknown tool: {}", name),
        }
    }
}

/// Public tool executor for non-customer requests.
/// Only exposes read-only endpoints that don't require authentication.
pub struct PublicToolExecutor {
    api: Arc<ApiClient>,
}

impl PublicToolExecutor {
    pub fn new(api: Arc<ApiClient>) -> Self {
        Self { api }
    }
}

#[async_trait]
impl ToolExecutor for PublicToolExecutor {
    async fn execute(&self, name: &str, _arguments: &str) -> Result<String> {
        match name {
            "list_regions" => pretty(&serde_json::Value::Array(
                self.api.admin_list_regions().await?,
            )),
            "list_templates" => pretty(&serde_json::Value::Array(
                self.api.admin_list_templates().await?,
            )),
            "list_os_images" => pretty(&serde_json::Value::Array(
                self.api.admin_list_os_images().await?,
            )),
            _ => bail!("Unknown tool: {}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_handles_invalid_json() {
        assert!(parse_args("not json").is_empty());
        let parsed = parse_args(r#"{"vm_id": 5}"#);
        assert_eq!(parsed.get("vm_id").and_then(|v| v.as_u64()), Some(5));
    }

    #[test]
    fn required_u64_extracts_or_errors() {
        let mut args = HashMap::new();
        args.insert("vm_id".to_string(), serde_json::json!(7));
        assert_eq!(required_u64(&args, "vm_id").unwrap(), 7);
        assert!(required_u64(&args, "days").is_err());
    }

    #[test]
    fn pretty_serializes_value() {
        let out = pretty(&serde_json::json!({"a": 1})).unwrap();
        assert!(out.contains("\"a\": 1"));
    }
}
