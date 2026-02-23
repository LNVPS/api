use std::sync::OnceLock;

use nostr::Keys;
use reqwest::{Client, Method, Response, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::nip98::make_nip98_auth;

/// Standard API success response wrapper.
#[derive(Debug, Deserialize)]
pub struct ApiData<T> {
    pub data: T,
}

/// Standard API paginated response wrapper.
#[derive(Debug, Deserialize)]
pub struct ApiPaginatedData<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

/// Standard API error response.
#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
}

/// Test client for making requests to the LNVPS API.
#[derive(Clone)]
pub struct TestClient {
    pub base_url: String,
    pub keys: Option<Keys>,
    pub http: Client,
}

impl TestClient {
    pub fn new(base_url: &str, keys: Option<Keys>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            keys,
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Returns the full URL for a path.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Make an unauthenticated GET request.
    pub async fn get(&self, path: &str) -> anyhow::Result<Response> {
        let url = self.url(path);
        let resp = self.http.get(&url).send().await?;
        Ok(resp)
    }

    /// Make an unauthenticated POST request with JSON body.
    pub async fn post(&self, path: &str, body: &impl serde::Serialize) -> anyhow::Result<Response> {
        let url = self.url(path);
        let resp = self.http.post(&url).json(body).send().await?;
        Ok(resp)
    }

    /// Make an authenticated GET request.
    pub async fn get_auth(&self, path: &str) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, "GET")?;
        let resp = self
            .http
            .get(&url)
            .header("Authorization", auth)
            .send()
            .await?;
        Ok(resp)
    }

    /// Make an authenticated POST request with JSON body.
    pub async fn post_auth(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, "POST")?;
        let resp = self
            .http
            .post(&url)
            .header("Authorization", auth)
            .json(body)
            .send()
            .await?;
        Ok(resp)
    }

    /// Make an authenticated PATCH request with JSON body.
    pub async fn patch_auth(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, "PATCH")?;
        let resp = self
            .http
            .patch(&url)
            .header("Authorization", auth)
            .json(body)
            .send()
            .await?;
        Ok(resp)
    }

    /// Make an authenticated DELETE request.
    pub async fn delete_auth(&self, path: &str) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, "DELETE")?;
        let resp = self
            .http
            .delete(&url)
            .header("Authorization", auth)
            .send()
            .await?;
        Ok(resp)
    }

    /// Make an authenticated PUT request with JSON body.
    pub async fn put_auth(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, "PUT")?;
        let resp = self
            .http
            .put(&url)
            .header("Authorization", auth)
            .json(body)
            .send()
            .await?;
        Ok(resp)
    }

    /// Make a request that expects a specific HTTP method (for arbitrary methods).
    pub async fn request_auth(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> anyhow::Result<Response> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No keys configured for authenticated request"))?;
        let url = self.url(path);
        let auth = make_nip98_auth(keys, &url, method.as_str())?;
        let mut builder = self
            .http
            .request(method, &url)
            .header("Authorization", auth);
        if let Some(b) = body {
            builder = builder.json(b);
        }
        let resp = builder.send().await?;
        Ok(resp)
    }
}

/// Helper to parse a JSON response body into `ApiData<T>`.
pub async fn parse_data<T: DeserializeOwned>(resp: Response) -> anyhow::Result<ApiData<T>> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("HTTP {status}: {body}");
    }
    let parsed: ApiData<T> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse ApiData from response: {e}\nBody: {body}"))?;
    Ok(parsed)
}

/// Helper to parse a JSON response body into `ApiPaginatedData<T>`.
pub async fn parse_paginated<T: DeserializeOwned>(
    resp: Response,
) -> anyhow::Result<ApiPaginatedData<T>> {
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("HTTP {status}: {body}");
    }
    let parsed: ApiPaginatedData<T> = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("Failed to parse ApiPaginatedData from response: {e}\nBody: {body}")
    })?;
    Ok(parsed)
}

/// Helper to assert a response has a specific status code and return the body.
pub async fn assert_status(resp: Response, expected: StatusCode) -> anyhow::Result<String> {
    let status = resp.status();
    let body = resp.text().await?;
    assert_eq!(
        status, expected,
        "Expected {expected} but got {status}. Body: {body}"
    );
    Ok(body)
}

/// Get the user API base URL from env, defaulting to localhost.
pub fn user_api_url() -> String {
    std::env::var("LNVPS_API_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// Get the admin API base URL from env, defaulting to localhost.
pub fn admin_api_url() -> String {
    std::env::var("LNVPS_ADMIN_API_URL").unwrap_or_else(|_| "http://localhost:8001".to_string())
}

/// Load Nostr keys from an environment variable (hex-encoded secret key).
/// If the env var is not set, generates a random key pair for testing.
pub fn load_keys(env_var: &str) -> Keys {
    match std::env::var(env_var) {
        Ok(hex_key) => {
            let sk = nostr::SecretKey::parse(&hex_key)
                .unwrap_or_else(|e| panic!("Invalid secret key in {env_var}: {e}"));
            Keys::new(sk)
        }
        Err(_) => Keys::generate(),
    }
}

/// Stable keys for the admin user. Generated once per process
/// so that all tests share the same admin identity.
fn admin_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| load_keys("ADMIN_NOSTR_SECRET_KEY"))
}

/// Stable keys for the regular user. Generated once per process.
fn user_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| load_keys("NOSTR_SECRET_KEY"))
}

/// Create a user API test client (always has auth keys).
pub fn user_client() -> TestClient {
    TestClient::new(&user_api_url(), Some(user_keys().clone()))
}

/// Create a user API test client without authentication.
pub fn user_client_no_auth() -> TestClient {
    TestClient::new(&user_api_url(), None)
}

/// Create a user API test client with specific keys.
pub fn user_client_with_keys(keys: nostr::Keys) -> TestClient {
    TestClient::new(&user_api_url(), Some(keys))
}

/// Create an admin API test client with super_admin keys.
///
/// The first call bootstraps the admin user in the database by
/// ensuring the user row exists and has the `super_admin` role.
pub fn admin_client() -> TestClient {
    TestClient::new(&admin_api_url(), Some(admin_keys().clone()))
}

/// Create an admin API test client without authentication.
pub fn admin_client_no_auth() -> TestClient {
    TestClient::new(&admin_api_url(), None)
}

/// Create an admin API test client with specific keys (for RBAC tests).
pub fn admin_client_with_keys(keys: Keys) -> TestClient {
    TestClient::new(&admin_api_url(), Some(keys))
}

/// Bootstrap the admin user: ensure the user exists in the DB with `super_admin` role.
/// Should be called once before admin tests run.
pub async fn bootstrap_admin() -> anyhow::Result<()> {
    let pool = crate::db::connect().await?;
    crate::db::ensure_user_with_role(&pool, admin_keys(), "super_admin").await?;
    pool.close().await;
    Ok(())
}
