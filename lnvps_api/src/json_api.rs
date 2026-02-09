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
        let req = self.build_req(method.clone(), path, body)?;
        let rsp = match self.client.execute(req).await {
            Ok(rsp) => rsp,
            Err(e) => {
                op_transient!(
                    "Failed to send request: {} source={}",
                    e,
                    e.source()
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "None".to_owned())
                );
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
        let req = self
            .build_req(method.clone(), path, body)
            .map_err(|e| OpError::Fatal(anyhow!(e)))?;
        let rsp = self
            .client
            .execute(req)
            .await
            .map_err(|e| OpError::Transient(anyhow!(e)))?;

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
