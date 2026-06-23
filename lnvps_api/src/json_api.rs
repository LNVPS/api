use anyhow::{Result, anyhow};
use lnvps_api_common::retry::{OpError, OpResult};
use lnvps_api_common::{op_fatal, op_transient};
use log::debug;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, USER_AGENT};
use reqwest::{Client, Method, Request, RequestBuilder, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

/// Maximum number of times to transparently retry a request that failed because
/// a pooled keep-alive connection was closed by the remote before the request
/// was sent. These failures mean the request never reached the server, so they
/// are always safe to retry (even for non-idempotent methods).
const STALE_CONNECTION_RETRIES: u32 = 3;

/// Detect the hyper/reqwest "connection closed before message completed" race,
/// where reqwest reused an idle pooled connection that the server had already
/// closed. This is reported as a request/send error and is safe to retry on a
/// fresh connection because the body was never delivered.
fn is_stale_connection_error(e: &reqwest::Error) -> bool {
    // A timeout or a genuine connect failure is not a stale-pool reuse.
    if e.is_timeout() || e.is_connect() {
        return false;
    }
    let mut source: Option<&(dyn Error + 'static)> = Some(e);
    while let Some(err) = source {
        if is_stale_connection_message(&err.to_string()) {
            return true;
        }
        source = err.source();
    }
    false
}

/// Match the error-message fragments that indicate a pooled connection was
/// closed by the remote before our request was sent (safe to retry).
fn is_stale_connection_message(msg: &str) -> bool {
    msg.contains("connection closed before message completed")
        || msg.contains("IncompleteMessage")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
}

pub trait TokenGen: Send + Sync {
    fn generate_token(
        &self,
        method: Method,
        url: &Url,
        body: Option<&str>,
        req: RequestBuilder,
    ) -> Result<RequestBuilder>;
}

#[derive(Clone)]
pub struct JsonApi {
    client: Client,
    base: Url,
    /// Custom token generator per request
    token_gen: Option<Arc<dyn TokenGen>>,
}

impl JsonApi {
    pub fn new(base: &str) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "lnvps/1.0".parse()?);
        headers.insert(ACCEPT, "application/json; charset=utf-8".parse()?);

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            client,
            base: base.parse()?,
            token_gen: None,
        })
    }

    pub fn token(base: &str, token: &str, allow_invalid_certs: bool) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "lnvps/1.0".parse()?);
        headers.insert(AUTHORIZATION, token.parse()?);
        headers.insert(ACCEPT, "application/json; charset=utf-8".parse()?);

        let client = Client::builder()
            .danger_accept_invalid_certs(allow_invalid_certs)
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            base: base.parse()?,
            token_gen: None,
        })
    }

    pub fn token_gen(
        base: &str,
        allow_invalid_certs: bool,
        tg: impl TokenGen + 'static,
    ) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "lnvps/1.0".parse()?);
        headers.insert(ACCEPT, "application/json; charset=utf-8".parse()?);

        let client = Client::builder()
            .danger_accept_invalid_certs(allow_invalid_certs)
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            base: base.parse()?,
            token_gen: Some(Arc::new(tg)),
        })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> OpResult<T> {
        self.req::<T, ()>(Method::GET, path, None).await
    }

    pub async fn post<T: DeserializeOwned, R: Serialize>(
        &self,
        path: &str,
        body: R,
    ) -> OpResult<T> {
        self.req(Method::POST, path, Some(body)).await
    }

    pub async fn put<T: DeserializeOwned, R: Serialize>(&self, path: &str, body: R) -> OpResult<T> {
        self.req(Method::PUT, path, Some(body)).await
    }

    pub fn build_req(
        &self,
        method: Method,
        path: &str,
        body: Option<impl Serialize>,
    ) -> Result<Request> {
        let url = self.base.join(path)?;
        let mut req = self.client.request(method.clone(), url.clone());
        let req = if let Some(body) = body {
            let body = serde_json::to_string(&body)?;
            if let Some(token_gen) = self.token_gen.as_ref() {
                req = token_gen.generate_token(method.clone(), &url, Some(&body), req)?;
            }
            debug!(">> {} {}: {}", method.clone(), path, &body);
            req.header(CONTENT_TYPE, "application/json; charset=utf-8")
                .body(body)
                .build()?
        } else {
            if let Some(token_gen) = self.token_gen.as_ref() {
                req = token_gen.generate_token(method.clone(), &url, None, req)?;
            }
            req.build()?
        };
        debug!(">> HEADERS {:?}", req.headers());
        Ok(req)
    }

    pub async fn req<T: DeserializeOwned, R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<R>,
    ) -> OpResult<T> {
        // Serialize the body once so we can rebuild the request on each retry.
        let body = body.as_ref();
        let mut attempt = 0u32;
        let rsp = loop {
            let req = self.build_req(method.clone(), path, body)?;
            match self.client.execute(req).await {
                Ok(rsp) => break rsp,
                Err(e) if is_stale_connection_error(&e) && attempt < STALE_CONNECTION_RETRIES => {
                    attempt += 1;
                    debug!(
                        "Stale connection on {} {} (attempt {}/{}), retrying on fresh connection: {}",
                        method, path, attempt, STALE_CONNECTION_RETRIES, e
                    );
                    continue;
                }
                Err(e) => {
                    // Build a detailed error message from the reqwest error chain
                    let mut details = Vec::new();
                    if e.is_connect() {
                        details.push("connection failed".to_string());
                    }
                    if e.is_timeout() {
                        details.push("timeout".to_string());
                    }
                    if let Some(url) = e.url() {
                        details.push(format!("url={}", url));
                    }
                    // Walk the error chain for more context
                    let mut source = e.source();
                    while let Some(err) = source {
                        details.push(err.to_string());
                        source = err.source();
                    }
                    let detail_str = if details.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", details.join(", "))
                    };
                    op_transient!("Request failed: {}{}", e, detail_str);
                }
            }
        };

        let status = rsp.status();
        let text = rsp.text().await.map_err(|e| OpError::Fatal(anyhow!(e)))?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            match serde_json::from_str(&text) {
                Ok(t) => Ok(t),
                Err(e) => {
                    op_fatal!("Failed to parse JSON from {}: {} {}", path, text, e);
                }
            }
        } else {
            // TODO: handle status codes as fatal/transient
            op_transient!("{} {}: {}: {}", method, path, status, &text);
        }
    }

    /// Make a request and only return the status code
    pub async fn req_status<R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<R>,
    ) -> OpResult<u16> {
        // Serialize the body once so we can rebuild the request on each retry.
        let body = body.as_ref();
        let mut attempt = 0u32;
        let rsp = loop {
            let req = self
                .build_req(method.clone(), path, body)
                .map_err(|e| OpError::Fatal(anyhow!(e)))?;
            match self.client.execute(req).await {
                Ok(rsp) => break rsp,
                Err(e) if is_stale_connection_error(&e) && attempt < STALE_CONNECTION_RETRIES => {
                    attempt += 1;
                    debug!(
                        "Stale connection on {} {} (attempt {}/{}), retrying on fresh connection: {}",
                        method, path, attempt, STALE_CONNECTION_RETRIES, e
                    );
                    continue;
                }
                Err(e) => return Err(OpError::Transient(anyhow!(e))),
            }
        };

        let status = rsp.status();
        let text = rsp
            .text()
            .await
            .map_err(|e| OpError::Transient(anyhow!(e)))?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            op_transient!("{} {}: {}: {}", method, path, status, &text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_stale_connection_message;

    #[test]
    fn detects_connection_closed_before_message_completed() {
        // The exact hyper message seen when a pooled keep-alive connection is
        // reused after the remote already closed it (e.g. the resize PUT issued
        // right after a long disk import during VM reinstall).
        assert!(is_stale_connection_message(
            "connection closed before message completed"
        ));
    }

    #[test]
    fn detects_other_stale_connection_variants() {
        assert!(is_stale_connection_message(
            "hyper::Error(IncompleteMessage)"
        ));
        assert!(is_stale_connection_message("connection reset by peer"));
        assert!(is_stale_connection_message("broken pipe (os error 32)"));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!is_stale_connection_message("dns error: failed to lookup"));
        assert!(!is_stale_connection_message("invalid status code: 500"));
        assert!(!is_stale_connection_message(""));
    }
}
