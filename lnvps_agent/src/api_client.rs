use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use crate::nip98::Nip98Signer;
use crate::settings::Settings;

/// HTTP client for calling the LNVPS admin and user APIs.
///
/// Generates fresh NIP-98 auth tokens from an nsec key on every request.
pub struct ApiClient {
    client: Client,
    admin_api_url: String,
    user_api_url: String,
    signer: Nip98Signer,
}

impl ApiClient {
    pub fn new(settings: &Settings) -> Result<Self> {
        let signer = Nip98Signer::from_nsec(&settings.nsec)?;
        Ok(Self {
            client: Client::new(),
            admin_api_url: settings.admin_api_url.trim_end_matches('/').to_string(),
            user_api_url: settings.user_api_url.trim_end_matches('/').to_string(),
            signer,
        })
    }

    /// Generate a fresh NIP-98 auth header value for the given URL path and method.
    fn auth_header(&self, path: &str, method: &str) -> Result<String> {
        let full_url = format!("{}{}", self.admin_api_url, path);
        let token = self.signer.sign_auth_token(&full_url, method)?;
        Ok(format!("Nostr {}", token))
    }

    // ── Admin API calls ──────────────────────────────────────────────

    /// List all VMs, optionally filtered by user_id
    pub async fn admin_list_vms(
        &self,
        user_id: Option<u64>,
        include_deleted: Option<bool>,
    ) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vms";
        let mut url = format!("{}{}", self.admin_api_url, path);
        let mut params = Vec::new();
        if let Some(uid) = user_id {
            params.push(("user_id", uid.to_string()));
        }
        if let Some(d) = include_deleted {
            params.push(("include_deleted", d.to_string()));
        }
        if !params.is_empty() {
            let qs: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
            url.push('?');
            url.push_str(&qs.join("&"));
        }

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(path, "GET")?)
            .send()
            .await
            .context("admin_list_vms request failed")?
            .json()
            .await
            .context("admin_list_vms parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// Get a specific VM by id
    pub async fn admin_get_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(&path, "GET")?)
            .send()
            .await
            .context("admin_get_vm request failed")?
            .json()
            .await
            .context("admin_get_vm parse failed")?;

        rsp.data.context("No VM data in response")
    }

    /// List a VM's payment history
    pub async fn admin_list_vm_payments(&self, vm_id: u64) -> Result<Vec<serde_json::Value>> {
        let path = format!("/api/admin/v1/vms/{}/payments", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(&path, "GET")?)
            .send()
            .await
            .context("admin_list_vm_payments request failed")?
            .json()
            .await
            .context("admin_list_vm_payments parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// Get a user's info by id
    pub async fn admin_get_user(&self, user_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/users/{}", user_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(&path, "GET")?)
            .send()
            .await
            .context("admin_get_user request failed")?
            .json()
            .await
            .context("admin_get_user parse failed")?;

        rsp.data.context("No user data in response")
    }

    /// List a VM's history
    pub async fn admin_list_vm_history(&self, vm_id: u64) -> Result<Vec<serde_json::Value>> {
        let path = format!("/api/admin/v1/vms/{}/history", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(&path, "GET")?)
            .send()
            .await
            .context("admin_list_vm_history request failed")?
            .json()
            .await
            .context("admin_list_vm_history parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// List all users, paginating through all results (100 per page).
    pub async fn admin_list_users(&self) -> Result<Vec<serde_json::Value>> {
        let mut all_users = Vec::new();
        let mut offset: u64 = 0;
        let limit: u64 = 100;

        loop {
            let path = format!("/api/admin/v1/users?limit={}&offset={}", limit, offset);
            let url = format!("{}{}", self.admin_api_url, path);

            let rsp: AdminPaginatedResponse<Vec<serde_json::Value>> = self
                .client
                .get(&url)
                .header("Authorization", self.auth_header("/api/admin/v1/users", "GET")?)
                .send()
                .await
                .context("admin_list_users request failed")?
                .json()
                .await
                .context("admin_list_users parse failed")?;

            let page = rsp.data.unwrap_or_default();
            let total = rsp.total.unwrap_or(0);
            let page_len = page.len() as u64;
            all_users.extend(page);

            if all_users.len() as u64 >= total || page_len < limit {
                break;
            }
            offset += limit;
        }

        Ok(all_users)
    }

    /// Lookup a user by pubkey hex using the API search parameter.
    pub async fn admin_find_user_by_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/api/admin/v1/users?search={}", pubkey);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminPaginatedResponse<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header("/api/admin/v1/users", "GET")?)
            .send()
            .await
            .context("admin_find_user_by_pubkey request failed")?
            .json()
            .await
            .context("admin_find_user_by_pubkey parse failed")?;

        let users = rsp.data.unwrap_or_default();
        // search returns prefix matches, so filter for exact pubkey
        Ok(users.into_iter().find(|u| {
            u.get("pubkey")
                .and_then(|v| v.as_str())
                .map(|p| p == pubkey)
                .unwrap_or(false)
        }))
    }

    /// Lookup a user by email address via the indexed email_hash column.
    pub async fn admin_find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<serde_json::Value>> {
        let path = format!("/api/admin/v1/users/by-email?email={}", email);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: serde_json::Value = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header("/api/admin/v1/users/by-email", "GET")?)
            .send()
            .await
            .context("admin_find_user_by_email request failed")?
            .json()
            .await
            .context("admin_find_user_by_email parse failed")?;

        if rsp.get("error").is_some() || rsp.get("data").and_then(|v| v.as_object()).is_none() {
            return Ok(None);
        }

        Ok(rsp.get("data").cloned())
    }

    /// Refund a VM payment
    pub async fn admin_refund_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}/refund", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header(&path, "POST")?)
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await
            .context("admin_refund_vm request failed")?
            .json()
            .await
            .context("admin_refund_vm parse failed")?;

        rsp.data.context("No refund data in response")
    }

    /// Extend a VM
    pub async fn admin_extend_vm(&self, vm_id: u64, days: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}/extend", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let body = serde_json::json!({"days": days});

        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header(&path, "PUT")?)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .context("admin_extend_vm request failed")?
            .json()
            .await
            .context("admin_extend_vm parse failed")?;

        rsp.data.context("No extend data in response")
    }

    /// Delete a VM
    pub async fn admin_delete_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}", vm_id);
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .client
            .delete(&url)
            .header("Authorization", self.auth_header(&path, "DELETE")?)
            .send()
            .await
            .context("admin_delete_vm request failed")?
            .json()
            .await
            .context("admin_delete_vm parse failed")?;

        rsp.data.context("No delete data in response")
    }

    /// Get the regions
    pub async fn admin_list_regions(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/regions";
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(path, "GET")?)
            .send()
            .await
            .context("admin_list_regions request failed")?
            .json()
            .await
            .context("admin_list_regions parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// List all VM templates (name, specs, pricing, region)
    pub async fn admin_list_templates(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vm_templates";
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(path, "GET")?)
            .send()
            .await
            .context("admin_list_templates request failed")?
            .json()
            .await
            .context("admin_list_templates parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// List all OS images available for provisioning
    pub async fn admin_list_os_images(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vm_os_images";
        let url = format!("{}{}", self.admin_api_url, path);

        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header(path, "GET")?)
            .send()
            .await
            .context("admin_list_os_images request failed")?
            .json()
            .await
            .context("admin_list_os_images parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    // ── User API calls (for user-scoped lookups) ───────────────────

    /// List user's VMs (user API, not admin)
    /// Note: requires the user's Nip98 auth token, which comes from the support channel
    pub async fn user_list_vms(&self, auth_token: &str) -> Result<Vec<serde_json::Value>> {
        let path = "/api/v1/vm";
        let url = format!("{}{}", self.user_api_url, path);

        let rsp: ApiResponseWrapper<Vec<serde_json::Value>> = self
            .client
            .get(&url)
            .header("Authorization", format!("Nostr {}", auth_token))
            .send()
            .await
            .context("user_list_vms request failed")?
            .json()
            .await
            .context("user_list_vms parse failed")?;

        Ok(rsp.data.unwrap_or_default())
    }

    /// Get user's account info
    pub async fn user_get_account(&self, auth_token: &str) -> Result<serde_json::Value> {
        let path = "/api/v1/account";
        let url = format!("{}{}", self.user_api_url, path);

        let rsp: ApiResponseWrapper<serde_json::Value> = self
            .client
            .get(&url)
            .header("Authorization", format!("Nostr {}", auth_token))
            .send()
            .await
            .context("user_get_account request failed")?
            .json()
            .await
            .context("user_get_account parse failed")?;

        rsp.data.context("No account data")
    }
}

// ── API response wrappers ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AdminResponseWrapper<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    #[allow(dead_code)]
    error: Option<String>,
}

/// Paginated admin API response wrapper.
#[derive(Debug, Deserialize)]
struct AdminPaginatedResponse<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    limit: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ApiResponseWrapper<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    #[allow(dead_code)]
    error: Option<String>,
}
