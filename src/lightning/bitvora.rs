use crate::api::WEBHOOK_BRIDGE;
use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use anyhow::bail;
use futures::{Stream, StreamExt};
use lnvps_db::async_trait;
use log::debug;
use reqwest::header::HeaderMap;
use reqwest::{Method, Url};
use rocket::http::ext::IntoCollection;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio_stream::wrappers::BroadcastStream;

pub struct BitvoraNode {
    base: Url,
    client: reqwest::Client,
    webhook_secret: String,
}

impl BitvoraNode {
    pub fn new(api_token: &str, webhook_secret: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", api_token).parse().unwrap(),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();

        Self {
            base: Url::parse("https://api.bitvora.com/").unwrap(),
            client,
            webhook_secret: webhook_secret.to_string(),
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
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

    async fn post<T: DeserializeOwned, R: Serialize>(
        &self,
        path: &str,
        body: R,
    ) -> anyhow::Result<T> {
        self.req(Method::POST, path, body).await
    }

    async fn req<T: DeserializeOwned, R: Serialize>(
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

#[async_trait]
impl LightningNode for BitvoraNode {
    async fn add_invoice(&self, req: AddInvoiceRequest) -> anyhow::Result<AddInvoiceResult> {
        let req = CreateInvoiceRequest {
            amount: req.amount / 1000,
            currency: "sats".to_string(),
            description: req.memo.unwrap_or_default(),
            expiry_seconds: req.expire.unwrap_or(3600) as u64,
        };
        let rsp: BitvoraResponse<CreateInvoiceResponse> = self
            .req(Method::POST, "/v1/bitcoin/deposit/lightning-invoice", req)
            .await?;
        if rsp.status >= 400 {
            bail!(
                "API error: {} {}",
                rsp.status,
                rsp.message.unwrap_or_default()
            );
        }
        Ok(AddInvoiceResult {
            pr: rsp.data.payment_request,
            payment_hash: rsp.data.r_hash,
        })
    }

    async fn subscribe_invoices(
        &self,
        _from_payment_hash: Option<Vec<u8>>,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>> {
        let rx = BroadcastStream::new(WEBHOOK_BRIDGE.listen());
        let mapped = rx.then(|r| async move { InvoiceUpdate::Unknown });
        Ok(Box::pin(mapped))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateInvoiceRequest {
    pub amount: u64,
    pub currency: String,
    pub description: String,
    pub expiry_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct BitvoraResponse<T> {
    pub status: isize,
    pub message: Option<String>,
    pub data: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateInvoiceResponse {
    pub id: String,
    pub r_hash: String,
    pub payment_request: String,
}
