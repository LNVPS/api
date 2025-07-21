use anyhow::{bail, Result};
use log::debug;
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{Client, Method, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;

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

        let client = Client::builder().default_headers(headers).build()?;

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

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let text = self.get_raw(path).await?;
        Ok(serde_json::from_str::<T>(&text)?)
    }

    /// Get raw string response
    pub async fn get_raw(&self, path: &str) -> Result<String> {
        debug!(">> GET {}", path);
        let url = self.base.join(path)?;
        let mut req = self.client.request(Method::GET, url.clone());
        if let Some(gen) = &self.token_gen {
            req = gen.generate_token(Method::GET, &url, None, req)?;
        }
        let req = req.build()?;
        debug!(">> HEADERS {:?}", req.headers());
        let rsp = self.client.execute(req).await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        debug!("<< {}", text);
        if status.is_success() {
            Ok(text)
        } else {
            bail!("{}", status);
        }
    }

    pub async fn post<T: DeserializeOwned, R: Serialize>(&self, path: &str, body: R) -> Result<T> {
        self.req(Method::POST, path, body).await
    }

    pub async fn put<T: DeserializeOwned, R: Serialize>(&self, path: &str, body: R) -> Result<T> {
        self.req(Method::PUT, path, body).await
    }

    pub async fn req<T: DeserializeOwned, R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: R,
    ) -> Result<T> {
        let body = serde_json::to_string(&body)?;
        debug!(">> {} {}: {}", method.clone(), path, &body);
        let url = self.base.join(path)?;
        let mut req = self
            .client
            .request(method.clone(), url.clone())
            .header(CONTENT_TYPE, "application/json; charset=utf-8");
        if let Some(gen) = self.token_gen.as_ref() {
            req = gen.generate_token(method.clone(), &url, Some(&body), req)?;
        }
        let req = req.body(body).build()?;
        debug!(">> HEADERS {:?}", req.headers());
        let rsp = self.client.execute(req).await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            match serde_json::from_str(&text) {
                Ok(t) => Ok(t),
                Err(e) => {
                    bail!("Failed to parse JSON from {}: {} {}", path, text, e);
                }
            }
        } else {
            bail!("{} {}: {}: {}", method, url, status, &text);
        }
    }

    /// Make a request and only return the status code
    pub async fn req_status<R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: R,
    ) -> Result<u16> {
        let body = serde_json::to_string(&body)?;
        debug!(">> {} {}: {}", method.clone(), path, &body);
        let url = self.base.join(path)?;
        let mut req = self
            .client
            .request(method.clone(), url.clone())
            .header(CONTENT_TYPE, "application/json; charset=utf-8");
        if let Some(gen) = &self.token_gen {
            req = gen.generate_token(method.clone(), &url, Some(&body), req)?;
        }
        let rsp = req.body(body).send().await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            Ok(status.as_u16())
        } else {
            bail!("{} {}: {}: {}", method, url, status, &text);
        }
    }
}
