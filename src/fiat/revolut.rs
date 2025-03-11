use crate::exchange::{Currency, CurrencyAmount};
use crate::fiat::{FiatPaymentInfo, FiatPaymentService};
use crate::json_api::JsonApi;
use crate::settings::RevolutConfig;
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

pub struct RevolutApi {
    api: JsonApi,
}

impl RevolutApi {
    pub fn new(config: RevolutConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {}", config.token).parse()?);
        headers.insert(ACCEPT, "application/json".parse()?);
        headers.insert("Revolut-Api-Version", config.api_version.parse()?);

        let client = Client::builder().default_headers(headers).build()?;
        Ok(Self {
            api: JsonApi {
                client,
                base: config
                    .url
                    .unwrap_or("https://merchant.revolut.com".to_string())
                    .parse()?,
            },
        })
    }

    pub async fn list_webhooks(&self) -> Result<Vec<RevolutWebhook>> {
        self.api.get("/api/1.0/webhooks").await
    }

    pub async fn delete_webhook(&self, webhook_id: &str) -> Result<()> {
        self.api
            .req_status(
                Method::DELETE,
                &format!("/api/1.0/webhooks/{}", webhook_id),
                (),
            )
            .await?;
        Ok(())
    }

    pub async fn create_webhook(
        &self,
        url: &str,
        events: Vec<RevolutWebhookEvent>,
    ) -> Result<RevolutWebhook> {
        self.api
            .post(
                "/api/1.0/webhooks",
                CreateWebhookRequest {
                    url: url.to_string(),
                    events,
                },
            )
            .await
    }
}

impl FiatPaymentService for RevolutApi {
    fn create_order(
        &self,
        description: &str,
        amount: CurrencyAmount,
    ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>> {
        let api = self.api.clone();
        let desc = description.to_string();
        Box::pin(async move {
            let rsp: CreateOrderResponse = api
                .post(
                    "/api/orders",
                    CreateOrderRequest {
                        currency: amount.0.to_string(),
                        amount: match amount.0 {
                            Currency::BTC => bail!("Bitcoin amount not allowed for fiat payments"),
                            Currency::EUR => (amount.1 * 100.0).floor() as u64,
                            Currency::USD => (amount.1 * 100.0).floor() as u64,
                        },
                        description: Some(desc),
                    },
                )
                .await?;

            Ok(FiatPaymentInfo {
                raw_data: serde_json::to_string(&rsp)?,
                external_id: rsp.id,
            })
        })
    }
}

#[derive(Clone, Serialize)]
pub struct CreateOrderRequest {
    pub amount: u64,
    pub currency: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CreateOrderResponse {
    pub id: String,
    pub token: String,
    pub state: PaymentState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub description: Option<String>,
    pub amount: u64,
    pub currency: String,
    pub outstanding_amount: u64,
    pub checkout_url: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentState {
    Pending,
    Processing,
    Authorised,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RevolutWebhook {
    pub id: String,
    pub url: String,
    pub events: Vec<RevolutWebhookEvent>,
    pub signing_secret: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevolutWebhookEvent {
    OrderAuthorised,
    OrderCompleted,
    OrderCancelled,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<RevolutWebhookEvent>,
}
