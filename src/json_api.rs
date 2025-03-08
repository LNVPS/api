use anyhow::bail;
use log::debug;
use reqwest::header::{HeaderMap, AUTHORIZATION};
use reqwest::{Client, Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct JsonApi {
    pub client: Client,
    pub base: Url,
}

impl JsonApi {
    pub fn token(base: &str, token: &str, allow_invalid_certs: bool) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, token.parse()?);

        let client = Client::builder()
            .danger_accept_invalid_certs(allow_invalid_certs)
            .default_headers(headers)
            .build()?;
        Ok(Self {
            client,
            base: base.parse()?,
        })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        debug!(">> GET {}", path);
        let rsp = self.client.get(self.base.join(path)?).send().await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            bail!("{}", status);
        }
    }

    pub async fn post<T: DeserializeOwned, R: Serialize>(
        &self,
        path: &str,
        body: R,
    ) -> anyhow::Result<T> {
        self.req(Method::POST, path, body).await
    }

    pub async fn req<T: DeserializeOwned, R: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: R,
    ) -> anyhow::Result<T> {
        let body = serde_json::to_string(&body)?;
        debug!(">> {} {}: {}", method.clone(), path, &body);
        let rsp = self
            .client
            .request(method.clone(), self.base.join(path)?)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await?;
        let status = rsp.status();
        let text = rsp.text().await?;
        #[cfg(debug_assertions)]
        debug!("<< {}", text);
        if status.is_success() {
            Ok(serde_json::from_str(&text)?)
        } else {
            bail!("{} {}: {}: {}", method, path, status, &text);
        }
    }
}
