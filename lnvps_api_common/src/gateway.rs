use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use payment_gateway_client::{CreateAttempt, CreatePayment, Gateway, RefundInput, verify_webhook};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub const GATEWAY_EXTERNAL_ID_PREFIX: &str = "pgw:";
pub const GATEWAY_WEBHOOK_PATH: &str = "/api/v1/webhook/gateway";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OffSessionRenewals {
    #[default]
    Off,
    DryRun,
    Live,
}

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
    #[serde(default)]
    pub off_session_renewals: OffSessionRenewals,
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

#[derive(Debug, Clone)]
pub struct GatewayCryptoRequest {
    pub payment_id: Vec<u8>,
    pub amount_msat: u64,
    pub tax_msat: u64,
    pub description: String,
    pub expires_in_secs: u32,
    pub customer_ref: String,
    pub metadata: serde_json::Value,
    pub coin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GatewayOnChain {
    pub address: String,
    pub external_id: String,
}

#[derive(Debug, Clone)]
pub struct GatewaySwap {
    pub data: crate::SwapData,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub external_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRefund {
    pub id: u64,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct GatewaySavedCharge {
    pub payment_id: Vec<u8>,
    pub gateway_method_id: u64,
    pub amount: u64,
    pub currency: String,
    pub tax: u64,
    pub description: String,
    pub customer_ref: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCharge {
    pub external_id: String,
    pub paid: bool,
}

#[derive(Debug, Clone)]
pub struct GatewayImportMethod {
    pub customer_ref: String,
    pub provider: String,
    pub external_customer_id: String,
    pub external_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayEvent {
    pub event_id: String,
    pub kind: String,
    pub reference: String,
    pub status: String,
    pub refund_id: Option<u64>,
    pub amount: Option<u64>,
    pub reason: Option<String>,
}

#[async_trait]
pub trait PaymentGateway: Send + Sync {
    async fn create_lightning_invoice(&self, req: GatewayInvoiceRequest) -> Result<GatewayInvoice>;

    async fn cancel(&self, external_id: Option<&str>, payment_id: &[u8]) -> Result<()>;

    async fn create_onchain_address(&self, _req: GatewayCryptoRequest) -> Result<GatewayOnChain> {
        bail!("on-chain payments are not supported by this gateway")
    }

    async fn create_swap(&self, _req: GatewayCryptoRequest) -> Result<GatewaySwap> {
        bail!("swaps are not supported by this gateway")
    }

    async fn refund_payment(
        &self,
        _external_id: &str,
        _amount: Option<u64>,
        _destination: Option<&str>,
    ) -> Result<GatewayRefund> {
        bail!("refunds are not supported by this gateway")
    }

    async fn charge_saved_method(&self, _req: GatewaySavedCharge) -> Result<GatewayCharge> {
        bail!("saved methods are not supported by this gateway")
    }

    async fn delete_saved_method(&self, _gateway_method_id: u64) -> Result<()> {
        bail!("saved methods are not supported by this gateway")
    }

    async fn import_saved_method(&self, _req: GatewayImportMethod) -> Result<u64> {
        bail!("saved methods are not supported by this gateway")
    }
}

pub struct GatewayClient {
    client: Gateway,
}

impl GatewayClient {
    pub fn new(config: &GatewayConfig) -> Self {
        Self::from_parts(&config.url, &config.api_key)
    }

    pub fn from_parts(url: &str, api_key: &str) -> Self {
        Self {
            client: Gateway::new(url, api_key),
        }
    }

    pub async fn check(&self) -> Result<usize> {
        let methods = self
            .client
            .list_methods()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("gateway check failed: {e}"))?;
        Ok(methods.len())
    }
}

impl GatewayClient {
    async fn create_crypto_attempt(
        &self,
        req: &GatewayCryptoRequest,
        method: &str,
        option: Option<String>,
    ) -> Result<(payment_gateway_client::Payment, serde_json::Value)> {
        let reference = hex::encode(&req.payment_id);
        let mut input = CreatePayment::new(req.amount_msat, "BTC").reference(&reference);
        input.tax = Some(req.tax_msat.min(req.amount_msat));
        input.expires_in = Some(req.expires_in_secs as i64);
        input.description = Some(req.description.clone());
        input.customer_ref = Some(req.customer_ref.clone());
        input.metadata = Some(req.metadata.clone());
        input.methods = Some(vec![method.to_string()]);
        let payment = self
            .client
            .create_payment_with_key(&input, &reference)
            .await
            .context("gateway create_payment failed")?;
        let mut attempt = CreateAttempt::new(method);
        attempt.option = option;
        let payment = self
            .client
            .create_attempt(&payment.id, &attempt)
            .await
            .context("gateway create_attempt failed")?;
        let details = payment
            .attempts
            .iter()
            .find(|a| a.method == method)
            .map(|a| a.details.clone())
            .unwrap_or_default();
        Ok((payment, details))
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

    async fn charge_saved_method(&self, req: GatewaySavedCharge) -> Result<GatewayCharge> {
        let reference = hex::encode(&req.payment_id);
        let mut input = CreatePayment::new(req.amount, &req.currency).reference(&reference);
        input.tax = Some(req.tax.min(req.amount));
        input.description = Some(req.description);
        input.customer_ref = Some(req.customer_ref);
        input.metadata = Some(req.metadata);
        let payment = self
            .client
            .charge_saved_method_with_key(req.gateway_method_id, &input, &reference)
            .await
            .context("gateway charge_saved_method failed")?;
        Ok(GatewayCharge {
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}{}", payment.id),
            paid: payment.status == "paid",
        })
    }

    async fn create_onchain_address(&self, req: GatewayCryptoRequest) -> Result<GatewayOnChain> {
        let (payment, details) = self.create_crypto_attempt(&req, "onchain", None).await?;
        let address = details
            .get("address")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let Some(address) = address else {
            bail!("gateway payment {} has no on-chain address", payment.id);
        };
        Ok(GatewayOnChain {
            address,
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}{}", payment.id),
        })
    }

    async fn create_swap(&self, req: GatewayCryptoRequest) -> Result<GatewaySwap> {
        let Some(coin) = req.coin.clone() else {
            bail!("a coin is required for swaps");
        };
        let (payment, details) = self
            .create_crypto_attempt(&req, "fixedfloat", Some(coin))
            .await?;
        let text = |k: &str| {
            details
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .with_context(|| format!("gateway swap details have no {k}"))
        };
        let expires = payment
            .expires
            .as_deref()
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|e| e.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| {
                chrono::Utc::now() + chrono::Duration::seconds(req.expires_in_secs as i64)
            });
        Ok(GatewaySwap {
            data: crate::SwapData {
                coin: text("coin")?,
                order_id: text("order_id")?,
                order_token: text("order_token")?,
                deposit_address: text("deposit_address")?,
                deposit_amount: text("deposit_amount")?,
                receive_address: text("receive_address")?,
            },
            expires,
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}{}", payment.id),
        })
    }

    async fn refund_payment(
        &self,
        external_id: &str,
        amount: Option<u64>,
        destination: Option<&str>,
    ) -> Result<GatewayRefund> {
        let Some(id) = external_id.strip_prefix(GATEWAY_EXTERNAL_ID_PREFIX) else {
            bail!("not a gateway payment");
        };
        let refund = self
            .client
            .refund_payment(
                id,
                &RefundInput {
                    amount,
                    destination: destination.map(str::to_string),
                    attempt_id: None,
                },
            )
            .await
            .context("gateway refund_payment failed")?;
        Ok(GatewayRefund {
            id: refund.id,
            status: refund.status,
        })
    }

    async fn delete_saved_method(&self, gateway_method_id: u64) -> Result<()> {
        self.client
            .delete_saved_method(gateway_method_id)
            .await
            .context("gateway delete_saved_method failed")
    }

    async fn import_saved_method(&self, _req: GatewayImportMethod) -> Result<u64> {
        bail!("importing saved methods is not supported by the pinned payment gateway client")
    }
}

pub fn is_gateway_payment(external_id: Option<&str>) -> bool {
    external_id.is_some_and(|e| e.starts_with(GATEWAY_EXTERNAL_ID_PREFIX))
}

pub fn deposit_outpoint(external_id: &Option<String>) -> Option<String> {
    external_id
        .clone()
        .filter(|e| !is_gateway_payment(Some(e.as_str())))
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
    let detail = value.pointer("/data/detail");
    Ok(GatewayEvent {
        event_id: text(value.get("id")),
        kind: text(value.get("type")),
        reference: text(payment.and_then(|p| p.get("reference"))),
        status: text(payment.and_then(|p| p.get("status"))),
        refund_id: detail
            .and_then(|d| d.get("refund_id"))
            .and_then(|v| v.as_u64()),
        amount: detail
            .and_then(|d| d.get("amount"))
            .and_then(|v| v.as_u64()),
        reason: detail
            .and_then(|d| d.get("reason"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

#[derive(Default)]
pub struct FakeGateway {
    pub created: Mutex<Vec<GatewayInvoiceRequest>>,
    pub cancelled: Mutex<Vec<String>>,
    pub fail: Mutex<bool>,
    pub fail_cancel: Mutex<bool>,
    pub charges: Mutex<Vec<GatewaySavedCharge>>,
    pub deleted_methods: Mutex<Vec<u64>>,
    pub imported: Mutex<Vec<GatewayImportMethod>>,
    pub fail_charges: Mutex<bool>,
    pub crypto: Mutex<Vec<GatewayCryptoRequest>>,
    pub refunds: Mutex<Vec<(String, Option<u64>, Option<String>)>>,
    pub fail_refunds: Mutex<bool>,
    pub charge_leaves_pending: Mutex<bool>,
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
        if *self.fail_cancel.lock().unwrap() {
            bail!("gateway unavailable");
        }
        self.cancelled.lock().unwrap().push(id.to_string());
        Ok(())
    }

    async fn charge_saved_method(&self, req: GatewaySavedCharge) -> Result<GatewayCharge> {
        if *self.fail_charges.lock().unwrap() {
            bail!("card declined");
        }
        let gateway_id = format!(
            "gw{}",
            hex::encode(&req.payment_id[..4.min(req.payment_id.len())])
        );
        self.ids
            .lock()
            .unwrap()
            .insert(req.payment_id.clone(), gateway_id.clone());
        self.charges.lock().unwrap().push(req);
        Ok(GatewayCharge {
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}{gateway_id}"),
            paid: !*self.charge_leaves_pending.lock().unwrap(),
        })
    }

    async fn create_onchain_address(&self, req: GatewayCryptoRequest) -> Result<GatewayOnChain> {
        if *self.fail.lock().unwrap() {
            bail!("gateway unavailable");
        }
        let hexid = hex::encode(&req.payment_id[..4.min(req.payment_id.len())]);
        self.crypto.lock().unwrap().push(req);
        Ok(GatewayOnChain {
            address: format!("bc1qfake{hexid}"),
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}gw{hexid}"),
        })
    }

    async fn create_swap(&self, req: GatewayCryptoRequest) -> Result<GatewaySwap> {
        if *self.fail.lock().unwrap() {
            bail!("gateway unavailable");
        }
        let hexid = hex::encode(&req.payment_id[..4.min(req.payment_id.len())]);
        let coin = req.coin.clone().unwrap_or_default();
        self.crypto.lock().unwrap().push(req);
        Ok(GatewaySwap {
            data: crate::SwapData {
                coin,
                order_id: format!("FF{hexid}"),
                order_token: "tok".to_string(),
                deposit_address: format!("4fakedeposit{hexid}"),
                deposit_amount: "1.5".to_string(),
                receive_address: format!("bc1qfake{hexid}"),
            },
            expires: chrono::Utc::now() + chrono::Duration::minutes(30),
            external_id: format!("{GATEWAY_EXTERNAL_ID_PREFIX}gw{hexid}"),
        })
    }

    async fn refund_payment(
        &self,
        external_id: &str,
        amount: Option<u64>,
        destination: Option<&str>,
    ) -> Result<GatewayRefund> {
        if *self.fail_refunds.lock().unwrap() {
            bail!("refund rejected");
        }
        let mut refunds = self.refunds.lock().unwrap();
        refunds.push((
            external_id.to_string(),
            amount,
            destination.map(str::to_string),
        ));
        Ok(GatewayRefund {
            id: refunds.len() as u64,
            status: "completed".to_string(),
        })
    }

    async fn delete_saved_method(&self, gateway_method_id: u64) -> Result<()> {
        if *self.fail.lock().unwrap() {
            bail!("gateway unavailable");
        }
        self.deleted_methods.lock().unwrap().push(gateway_method_id);
        Ok(())
    }

    async fn import_saved_method(&self, req: GatewayImportMethod) -> Result<u64> {
        let mut imported = self.imported.lock().unwrap();
        imported.push(req);
        Ok(100 + imported.len() as u64)
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
            off_session_renewals: OffSessionRenewals::Off,
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
