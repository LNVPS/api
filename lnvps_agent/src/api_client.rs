use anyhow::{Context, Result};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::identity::{Requester, SenderIdentity};
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

    /// Generate a fresh NIP-98 auth header value for the given admin API path and method.
    fn auth_header(&self, path: &str, method: &str) -> Result<String> {
        let full_url = format!("{}{}", self.admin_api_url, path);
        let token = self.signer.sign_auth_token(&full_url, method)?;
        Ok(format!("Nostr {}", token))
    }

    /// Issue an authenticated admin API request and deserialize the JSON body.
    ///
    /// `sign_path` is the path used to compute the NIP-98 signature (no query
    /// string), while `request_path` is the actual path requested (may carry a
    /// query string). `label` is used for error context.
    async fn admin_request<T: DeserializeOwned>(
        &self,
        method: Method,
        sign_path: &str,
        request_path: &str,
        body: Option<serde_json::Value>,
        label: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.admin_api_url, request_path);
        let auth = self.auth_header(sign_path, method.as_str())?;
        let mut req = self
            .client
            .request(method, &url)
            .header("Authorization", auth);
        if let Some(body) = body {
            req = req.header("Content-Type", "application/json").json(&body);
        }
        req.send()
            .await
            .with_context(|| format!("{label} request failed"))?
            .json()
            .await
            .with_context(|| format!("{label} parse failed"))
    }

    /// Authenticated admin GET returning a list (empty when absent).
    async fn admin_get_list(
        &self,
        sign_path: &str,
        request_path: &str,
        label: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let rsp: AdminResponseWrapper<Vec<serde_json::Value>> = self
            .admin_request(Method::GET, sign_path, request_path, None, label)
            .await?;
        Ok(rsp.data.unwrap_or_default())
    }

    /// Authenticated admin GET returning a single object (errors when absent).
    async fn admin_get_one(&self, path: &str, label: &str) -> Result<serde_json::Value> {
        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .admin_request(Method::GET, path, path, None, label)
            .await?;
        rsp.data
            .with_context(|| format!("No data in {label} response"))
    }

    // ── Customer resolution ──────────────────────────────────────────

    /// Resolve a sender identity to a [`Requester`].
    ///
    /// This is the single place sender resolution happens: it selects the
    /// correct lookup endpoint for the identity type and classifies the result
    /// as a known customer or general public. Channels never do this.
    pub async fn resolve(&self, sender: &SenderIdentity) -> Result<Requester> {
        let user = match sender {
            SenderIdentity::Email(email) => self.admin_find_user_by_email(email).await?,
            SenderIdentity::Pubkey(pubkey) => self.admin_find_user_by_pubkey(pubkey).await?,
        };

        let key = sender.conversation_key();
        let Some(user) = user else {
            log::info!("{} is not an LNVPS customer — general", key);
            return Ok(Requester::Anonymous);
        };
        match user.get("id").and_then(|v| v.as_u64()) {
            Some(user_id) => Ok(Requester::Customer {
                user_id,
                account: user,
            }),
            None => {
                log::warn!("Resolved user for {} has no id field — general", key);
                Ok(Requester::Anonymous)
            }
        }
    }

    // ── Admin API calls ──────────────────────────────────────────────

    /// List all VMs, optionally filtered by user_id
    pub async fn admin_list_vms(
        &self,
        user_id: Option<u64>,
        include_deleted: Option<bool>,
    ) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vms";
        let mut params = Vec::new();
        if let Some(uid) = user_id {
            params.push(format!("user_id={uid}"));
        }
        if let Some(d) = include_deleted {
            params.push(format!("include_deleted={d}"));
        }
        let request_path = if params.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", params.join("&"))
        };
        self.admin_get_list(path, &request_path, "admin_list_vms")
            .await
    }

    /// Get a specific VM by id
    pub async fn admin_get_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}", vm_id);
        self.admin_get_one(&path, "admin_get_vm").await
    }

    /// List a VM's payment history
    pub async fn admin_list_vm_payments(&self, vm_id: u64) -> Result<Vec<serde_json::Value>> {
        let path = format!("/api/admin/v1/vms/{}/payments", vm_id);
        self.admin_get_list(&path, &path, "admin_list_vm_payments")
            .await
    }

    /// Get a user's info by id
    pub async fn admin_get_user(&self, user_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/users/{}", user_id);
        self.admin_get_one(&path, "admin_get_user").await
    }

    /// List a VM's history
    pub async fn admin_list_vm_history(&self, vm_id: u64) -> Result<Vec<serde_json::Value>> {
        let path = format!("/api/admin/v1/vms/{}/history", vm_id);
        self.admin_get_list(&path, &path, "admin_list_vm_history")
            .await
    }

    /// List all users, paginating through all results (100 per page).
    pub async fn admin_list_users(&self) -> Result<Vec<serde_json::Value>> {
        let mut all_users = Vec::new();
        let mut offset: u64 = 0;
        let limit: u64 = 100;

        loop {
            let request_path = format!("/api/admin/v1/users?limit={}&offset={}", limit, offset);
            let rsp: AdminPaginatedResponse<Vec<serde_json::Value>> = self
                .admin_request(
                    Method::GET,
                    "/api/admin/v1/users",
                    &request_path,
                    None,
                    "admin_list_users",
                )
                .await?;

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
        let request_path = format!("/api/admin/v1/users?search={}", pubkey);
        let rsp: AdminPaginatedResponse<Vec<serde_json::Value>> = self
            .admin_request(
                Method::GET,
                "/api/admin/v1/users",
                &request_path,
                None,
                "admin_find_user_by_pubkey",
            )
            .await?;

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
    pub async fn admin_find_user_by_email(&self, email: &str) -> Result<Option<serde_json::Value>> {
        let request_path = format!("/api/admin/v1/users/by-email?email={}", email);
        let rsp: serde_json::Value = self
            .admin_request(
                Method::GET,
                "/api/admin/v1/users/by-email",
                &request_path,
                None,
                "admin_find_user_by_email",
            )
            .await?;

        if rsp.get("error").is_some() || rsp.get("data").and_then(|v| v.as_object()).is_none() {
            return Ok(None);
        }

        Ok(rsp.get("data").cloned())
    }

    /// Refund a VM payment
    pub async fn admin_refund_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}/refund", vm_id);
        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .admin_request(
                Method::POST,
                &path,
                &path,
                Some(serde_json::json!({})),
                "admin_refund_vm",
            )
            .await?;
        rsp.data.context("No refund data in response")
    }

    /// Extend a VM
    pub async fn admin_extend_vm(&self, vm_id: u64, days: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}/extend", vm_id);
        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .admin_request(
                Method::PUT,
                &path,
                &path,
                Some(serde_json::json!({ "days": days })),
                "admin_extend_vm",
            )
            .await?;
        rsp.data.context("No extend data in response")
    }

    /// Delete a VM
    pub async fn admin_delete_vm(&self, vm_id: u64) -> Result<serde_json::Value> {
        let path = format!("/api/admin/v1/vms/{}", vm_id);
        let rsp: AdminResponseWrapper<serde_json::Value> = self
            .admin_request(Method::DELETE, &path, &path, None, "admin_delete_vm")
            .await?;
        rsp.data.context("No delete data in response")
    }

    /// Get the regions
    pub async fn admin_list_regions(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/regions";
        self.admin_get_list(path, path, "admin_list_regions").await
    }

    /// List all VM templates (name, specs, pricing, region)
    pub async fn admin_list_templates(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vm_templates";
        self.admin_get_list(path, path, "admin_list_templates")
            .await
    }

    /// List all OS images available for provisioning
    pub async fn admin_list_os_images(&self) -> Result<Vec<serde_json::Value>> {
        let path = "/api/admin/v1/vm_os_images";
        self.admin_get_list(path, path, "admin_list_os_images")
            .await
    }

    // ── User API calls (for user-scoped lookups) ───────────────────

    /// Issue a user API GET authenticated with a caller-supplied NIP-98 token.
    async fn user_get<T: DeserializeOwned>(
        &self,
        path: &str,
        auth_token: &str,
        label: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.user_api_url, path);
        self.client
            .get(&url)
            .header("Authorization", format!("Nostr {}", auth_token))
            .send()
            .await
            .with_context(|| format!("{label} request failed"))?
            .json()
            .await
            .with_context(|| format!("{label} parse failed"))
    }

    /// List user's VMs (user API, not admin)
    /// Note: requires the user's Nip98 auth token, which comes from the support channel
    pub async fn user_list_vms(&self, auth_token: &str) -> Result<Vec<serde_json::Value>> {
        let rsp: ApiResponseWrapper<Vec<serde_json::Value>> = self
            .user_get("/api/v1/vm", auth_token, "user_list_vms")
            .await?;
        Ok(rsp.data.unwrap_or_default())
    }

    /// Get user's account info
    pub async fn user_get_account(&self, auth_token: &str) -> Result<serde_json::Value> {
        let rsp: ApiResponseWrapper<serde_json::Value> = self
            .user_get("/api/v1/account", auth_token, "user_get_account")
            .await?;
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
