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

#[derive(Clone)]
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

    pub async fn create_order(
        &self,
        amount: CurrencyAmount,
        description: Option<String>,
    ) -> Result<RevolutOrder> {
        self.api
            .post(
                "/api/orders",
                CreateOrderRequest {
                    currency: amount.0.to_string(),
                    amount: match amount.0 {
                        Currency::BTC => bail!("Bitcoin amount not allowed for fiat payments"),
                        Currency::EUR => amount.value(),
                        Currency::USD => amount.value(),
                    },
                    description,
                },
            )
            .await
    }

    pub async fn get_order(&self, order_id: &str) -> Result<RevolutOrder> {
        self.api.get(&format!("/api/orders/{}", order_id)).await
    }
}

impl FiatPaymentService for RevolutApi {
    fn create_order(
        &self,
        description: &str,
        amount: CurrencyAmount,
    ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>> {
        let s = self.clone();
        let desc = description.to_string();
        Box::pin(async move {
            let rsp = s.create_order(amount, Some(desc)).await?;
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
pub struct RevolutOrder {
    pub id: String,
    pub token: String,
    pub state: RevolutOrderState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub description: Option<String>,
    pub amount: u64,
    pub currency: String,
    pub outstanding_amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payments: Option<Vec<RevolutOrderPayment>>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RevolutOrderPayment {
    pub id: String,
    pub state: RevolutPaymentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<RevolutPaymentMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<RevolutBillingAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RevolutRiskLevel>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RevolutPaymentMethod {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub kind: RevolutPaymentMethodType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_last_four: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutPaymentMethodType {
    ApplePay,
    Card,
    GooglePay,
    RevolutPayCard,
    RevolutPayAccount,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutRiskLevel {
    High,
    Low,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RevolutBillingAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_line_1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_line_2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,

    pub country_code: String,
    pub postcode: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevolutOrderState {
    Pending,
    Processing,
    Authorised,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevolutPaymentState {
    Pending,
    AuthenticationChallenge,
    AuthenticationVerified,
    AuthorisationStarted,
    AuthorisationPassed,
    Authorised,
    CaptureStarted,
    Captured,
    RefundValidated,
    RefundStarted,
    CancellationStarted,
    Declining,
    Completing,
    Cancelling,
    Failing,
    Completed,
    Declined,
    SoftDeclined,
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
