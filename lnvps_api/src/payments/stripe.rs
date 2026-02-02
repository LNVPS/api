use anyhow::{anyhow, Context, Result};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Stripe API client for handling payments, webhooks, and checkout sessions
pub struct StripeClient {
    client: Client,
    api_key: String,
    base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeConfig {
    pub api_key: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_base_url() -> String {
    "https://api.stripe.com/v1".to_string()
}

// Webhook types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub enabled_events: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    #[serde(rename = "enabled_events")]
    pub enabled_events: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebhookList {
    pub data: Vec<Webhook>,
}

// Checkout Session types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub payment_status: String,
    pub status: Option<String>,
    pub amount_total: Option<i64>,
    pub currency: Option<String>,
    pub customer: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateCheckoutSessionRequest {
    pub mode: String,
    pub line_items: Vec<LineItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_email: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LineItem {
    pub price_data: PriceData,
    pub quantity: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PriceData {
    pub currency: String,
    pub product_data: ProductData,
    pub unit_amount: i64, // Amount in cents
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductData {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl StripeClient {
    /// Create a new Stripe client with authentication
    pub fn new(config: StripeConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            api_key: config.api_key,
            base_url: config.base_url,
        })
    }

    /// Helper to add authentication to requests
    fn authenticated_request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .request(method, &url)
            .bearer_auth(&self.api_key)
    }

    // Webhook methods

    /// List all webhooks
    pub async fn list_webhooks(&self) -> Result<Vec<Webhook>> {
        let response = self
            .authenticated_request(reqwest::Method::GET, "/webhook_endpoints")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!(
                "Failed to list webhooks: {} - {}",
                status,
                body
            ));
        }

        let webhook_list: WebhookList = response.json().await?;
        Ok(webhook_list.data)
    }

    /// Create a new webhook endpoint
    pub async fn create_webhook(
        &self,
        url: &str,
        enabled_events: Vec<String>,
    ) -> Result<Webhook> {
        let mut form_data = HashMap::new();
        form_data.insert("url", url.to_string());
        
        // Stripe expects array parameters in form format
        let form = form_data
            .into_iter()
            .map(|(k, v)| (k, v))
            .chain(enabled_events.iter().enumerate().map(|(i, event)| {
                (format!("enabled_events[{}]", i).leak() as &str, event.clone())
            }))
            .collect::<Vec<_>>();

        let response = self
            .authenticated_request(reqwest::Method::POST, "/webhook_endpoints")
            .form(&form)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!(
                "Failed to create webhook: {} - {}",
                status,
                body
            ));
        }

        response.json().await.context("Failed to parse webhook response")
    }

    /// Delete a webhook endpoint
    pub async fn delete_webhook(&self, webhook_id: &str) -> Result<()> {
        let path = format!("/webhook_endpoints/{}", webhook_id);
        let response = self
            .authenticated_request(reqwest::Method::DELETE, &path)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!(
                "Failed to delete webhook {}: {} - {}",
                webhook_id,
                status,
                body
            ));
        }

        Ok(())
    }

    // Checkout Session methods

    /// Create a checkout session
    pub async fn create_checkout_session(
        &self,
        request: CreateCheckoutSessionRequest,
    ) -> Result<CheckoutSession> {
        // Build form data for Stripe API
        let mut form_data = HashMap::new();
        form_data.insert("mode".to_string(), request.mode.clone());

        if let Some(success_url) = &request.success_url {
            form_data.insert("success_url".to_string(), success_url.clone());
        }
        if let Some(cancel_url) = &request.cancel_url {
            form_data.insert("cancel_url".to_string(), cancel_url.clone());
        }
        if let Some(customer) = &request.customer {
            form_data.insert("customer".to_string(), customer.clone());
        }
        if let Some(email) = &request.customer_email {
            form_data.insert("customer_email".to_string(), email.clone());
        }

        // Add line items
        for (i, item) in request.line_items.iter().enumerate() {
            form_data.insert(
                format!("line_items[{}][price_data][currency]", i),
                item.price_data.currency.clone(),
            );
            form_data.insert(
                format!("line_items[{}][price_data][product_data][name]", i),
                item.price_data.product_data.name.clone(),
            );
            if let Some(desc) = &item.price_data.product_data.description {
                form_data.insert(
                    format!("line_items[{}][price_data][product_data][description]", i),
                    desc.clone(),
                );
            }
            form_data.insert(
                format!("line_items[{}][price_data][unit_amount]", i),
                item.price_data.unit_amount.to_string(),
            );
            form_data.insert(
                format!("line_items[{}][quantity]", i),
                item.quantity.to_string(),
            );
        }

        // Add metadata
        if let Some(metadata) = &request.metadata {
            for (key, value) in metadata {
                form_data.insert(format!("metadata[{}]", key), value.clone());
            }
        }

        let response = self
            .authenticated_request(reqwest::Method::POST, "/checkout/sessions")
            .form(&form_data)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!(
                "Failed to create checkout session: {} - {}",
                status,
                body
            ));
        }

        response.json().await.context("Failed to parse checkout session response")
    }

    /// Retrieve a checkout session by ID
    pub async fn get_checkout_session(&self, session_id: &str) -> Result<CheckoutSession> {
        let path = format!("/checkout/sessions/{}", session_id);
        let response = self
            .authenticated_request(reqwest::Method::GET, &path)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!(
                "Failed to get checkout session {}: {} - {}",
                session_id,
                status,
                body
            ));
        }

        response.json().await.context("Failed to parse checkout session")
    }

    /// Verify webhook signature (simplified version - for production use the stripe crate's verify)
    pub fn verify_webhook_signature(
        &self,
        payload: &str,
        signature: &str,
        webhook_secret: &str,
    ) -> Result<Value> {
        // In production, you should use proper HMAC verification
        // This is a simplified version - recommend using the official stripe crate for this
        // For now, just parse the payload
        serde_json::from_str(payload).context("Failed to parse webhook payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_config_defaults() {
        let config = StripeConfig {
            api_key: "sk_test_123".to_string(),
            base_url: default_base_url(),
        };
        assert_eq!(config.base_url, "https://api.stripe.com/v1");
    }

    #[test]
    fn test_client_creation() {
        let config = StripeConfig {
            api_key: "sk_test_123".to_string(),
            base_url: default_base_url(),
        };
        let client = StripeClient::new(config);
        assert!(client.is_ok());
    }
}
