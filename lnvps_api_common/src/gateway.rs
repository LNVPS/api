use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use payment_gateway_client::{CreateAttempt, CreatePayment, Gateway, verify_webhook};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub const GATEWAY_EXTERNAL_ID_PREFIX: &str = "pgw:";
pub const GATEWAY_WEBHOOK_PATH: &str = "/api/v1/webhook/gateway";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct GatewayConfig {
    pub url: String,
    pub api_key: String,
    pub webhook_secret: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default = "default_tolerance")]
    pub webhook_tolerance_seconds: i64,
}

fn default_tolerance() -> i64 {
    300
}

impl GatewayConfig {
    pub fn handles(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

#[derive(Debug, Clone)]
pub struct GatewayInvoiceRequest {
    pub payment_id: Vec<u8>,
    pub amount_msat: u64,
    pub tax_msat: u64,
    pub description: String,
    pub expires_in_secs: u32,
    pub customer_ref: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct GatewayInvoice {
    pub payment_id: Vec<u8>,
    pub bolt11: String,
    pub external_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayEvent {
    pub event_id: String,
    pub kind: String,
    pub reference: String,
    pub status: String,
}

#[async_trait]
pub trait PaymentGateway: Send + Sync {
    async fn create_lightning_invoice(&self, req: GatewayInvoiceRequest) -> Result<GatewayInvoice>;

    async fn cancel(&self, external_id: Option<&str>, payment_id: &[u8]) -> Result<()>;
}

pub struct GatewayClient {
    client: Gateway,
}

impl GatewayClient {
    pub fn new(config: &GatewayConfig) -> Self {
        Self {
            client: Gateway::new(&config.url, &config.api_key),
        }
    }
}

#[async_trait]
impl PaymentGateway for GatewayClient {
    async fn create_lightning_invoice(&self, req: GatewayInvoiceRequest) -> Result<GatewayInvoice> {
        let reference = hex::encode(&req.payment_id);
        let mut input = CreatePayment::new(req.amount_msat, "BTC").reference(&reference);
        input.tax = Some(req.tax_msat.min(req.amount_msat));
        input.expires_in = Some(req.expires_in_secs as i64);
        input.description = Some(req.description);
        input.customer_ref = Some(req.customer_ref);
        input.metadata = Some(req.metadata);
        input.methods = Some(vec!["lightning".to_string()]);
        let payment = self
            .client
            .create_payment_with_key(&input, &reference)
            .await
            .context("gateway create_payment failed")?;
        let payment = self
            .client
            .create_attempt(&payment.id, &CreateAttempt::new("lightning"))
            .await
            .context("gateway create_attempt failed")?;
        let bolt11 = payment
            .attempts
            .iter()
            .find(|a| a.method == "lightning")
            .and_then(|a| a.details.get("bolt11"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(bolt11) = bolt11 else {
            bail!("gateway payment {} has no lightning invoice", payment.id);
        };
        Ok(GatewayInvoice {
            payment_id: req.payment_id,
            bolt11,
            external_id: Some(format!("{GATEWAY_EXTERNAL_ID_PREFIX}{}", payment.id)),
        })
    }

    async fn cancel(&self, external_id: Option<&str>, _payment_id: &[u8]) -> Result<()> {
        let Some(id) = external_id.and_then(|e| e.strip_prefix(GATEWAY_EXTERNAL_ID_PREFIX)) else {
            bail!("not a gateway payment");
        };
        self.client.cancel_payment(id).await?;
        Ok(())
    }
}

pub fn is_gateway_payment(external_id: Option<&str>) -> bool {
    external_id.is_some_and(|e| e.starts_with(GATEWAY_EXTERNAL_ID_PREFIX))
}

pub fn parse_gateway_event(
    body: &[u8],
    signature: Option<&str>,
    config: &GatewayConfig,
) -> Result<GatewayEvent> {
    let value = verify_webhook(
        body,
        signature,
        &config.webhook_secret,
        config.webhook_tolerance_seconds,
    )
    .map_err(|e| anyhow::anyhow!("invalid gateway webhook: {e}"))?;
    let text =
        |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let payment = value.pointer("/data/payment");
    Ok(GatewayEvent {
        event_id: text(value.get("id")),
        kind: text(value.get("type")),
        reference: text(payment.and_then(|p| p.get("reference"))),
        status: text(payment.and_then(|p| p.get("status"))),
    })
}

#[derive(Default)]
pub struct FakeGateway {
    pub created: Mutex<Vec<GatewayInvoiceRequest>>,
    pub cancelled: Mutex<Vec<String>>,
    pub fail: Mutex<bool>,
    ids: Mutex<HashMap<Vec<u8>, String>>,
}

impl FakeGateway {
    pub fn gateway_id_for(&self, payment_id: &[u8]) -> Option<String> {
        self.ids.lock().unwrap().get(payment_id).cloned()
    }
}

#[async_trait]
impl PaymentGateway for FakeGateway {
    async fn create_lightning_invoice(&self, req: GatewayInvoiceRequest) -> Result<GatewayInvoice> {
        if *self.fail.lock().unwrap() {
            bail!("gateway unavailable");
        }
        let gateway_id = format!(
            "gw{}",
            hex::encode(&req.payment_id[..4.min(req.payment_id.len())])
        );
        self.ids
            .lock()
            .unwrap()
            .insert(req.payment_id.clone(), gateway_id.clone());
        let out = GatewayInvoice {
            payment_id: req.payment_id.clone(),
            bolt11: format!("lnbcfake{}", hex::encode(&req.payment_id)),
            external_id: Some(format!("{GATEWAY_EXTERNAL_ID_PREFIX}{gateway_id}")),
        };
        self.created.lock().unwrap().push(req);
        Ok(out)
    }

    async fn cancel(&self, external_id: Option<&str>, _payment_id: &[u8]) -> Result<()> {
        let Some(id) = external_id.and_then(|e| e.strip_prefix(GATEWAY_EXTERNAL_ID_PREFIX)) else {
            bail!("not a gateway payment");
        };
        self.cancelled.lock().unwrap().push(id.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use payment_gateway_client::sign_webhook;

    fn config() -> GatewayConfig {
        GatewayConfig {
            url: "http://gw".into(),
            api_key: "k".into(),
            webhook_secret: "s3cret".into(),
            methods: vec!["lightning".into()],
            webhook_tolerance_seconds: 0,
        }
    }

    fn signed(body: &str, secret: &str) -> String {
        format!(
            "t=1700000000,v1={}",
            sign_webhook(body.as_bytes(), secret, 1700000000)
        )
    }

    #[test]
    fn config_matches_methods_case_insensitively() {
        assert!(config().handles("Lightning"));
        assert!(!config().handles("revolut"));
    }

    #[test]
    fn parses_a_signed_paid_event() {
        let body = r#"{"id":"e1","type":"payment.paid","data":{"payment":{"reference":"abcd","status":"paid"}}}"#;
        let ev =
            parse_gateway_event(body.as_bytes(), Some(&signed(body, "s3cret")), &config()).unwrap();
        assert_eq!(ev.kind, "payment.paid");
        assert_eq!(ev.reference, "abcd");
        assert_eq!(ev.status, "paid");
        assert_eq!(ev.event_id, "e1");
    }

    #[test]
    fn rejects_a_bad_signature_and_missing_header() {
        let body = r#"{"id":"e1","type":"payment.paid","data":{}}"#;
        assert!(
            parse_gateway_event(body.as_bytes(), Some(&signed(body, "other")), &config()).is_err()
        );
        assert!(parse_gateway_event(body.as_bytes(), None, &config()).is_err());
    }

    #[test]
    fn recognises_gateway_external_ids() {
        assert!(is_gateway_payment(Some("pgw:abc")));
        assert!(!is_gateway_payment(Some("abc")));
        assert!(!is_gateway_payment(None));
    }

    #[tokio::test]
    async fn fake_gateway_records_creates_and_cancels() {
        let gw = FakeGateway::default();
        let inv = gw
            .create_lightning_invoice(GatewayInvoiceRequest {
                payment_id: vec![1; 32],
                amount_msat: 1000,
                tax_msat: 0,
                description: "d".into(),
                expires_in_secs: 600,
                customer_ref: "7".into(),
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap();
        assert!(is_gateway_payment(inv.external_id.as_deref()));
        gw.cancel(inv.external_id.as_deref(), &inv.payment_id)
            .await
            .unwrap();
        assert_eq!(gw.cancelled.lock().unwrap().len(), 1);
        assert!(gw.cancel(None, &[]).await.is_err());
    }
}
