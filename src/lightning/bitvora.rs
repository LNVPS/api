use crate::api::WEBHOOK_BRIDGE;
use crate::json_api::JsonApi;
use crate::lightning::{AddInvoiceRequest, AddInvoiceResult, InvoiceUpdate, LightningNode};
use anyhow::bail;
use futures::{Stream, StreamExt};
use lnvps_db::async_trait;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio_stream::wrappers::BroadcastStream;

pub struct BitvoraNode {
    api: JsonApi,
    webhook_secret: String,
}

impl BitvoraNode {
    pub fn new(api_token: &str, webhook_secret: &str) -> Self {
        let auth = format!("Bearer {}", api_token);
        Self {
            api: JsonApi::token("https://api.bitvora.com/", &auth, false).unwrap(),
            webhook_secret: webhook_secret.to_string(),
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
            .api
            .post("/v1/bitcoin/deposit/lightning-invoice", req)
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
