use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use lnvps_db::FixedFloatProviderConfig;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::swap::{MoneroSwapData, SwapOrder, SwapOrderRequest, SwapProvider};

const DEFAULT_URL: &str = "https://ff.io/api/v2";

pub struct FixedFloat {
    client: reqwest::Client,
    url: String,
    api_key: String,
    api_secret: String,
    refcode: Option<String>,
    afftax: Option<f32>,
}

#[derive(Deserialize)]
struct Envelope {
    code: i64,
    #[serde(default)]
    msg: String,
    data: Option<Value>,
}

#[derive(Deserialize)]
struct CreatedOrder {
    id: String,
    token: String,
    time: OrderTime,
    from: OrderLeg,
}

#[derive(Deserialize)]
struct OrderTime {
    expiration: i64,
}

#[derive(Deserialize)]
struct OrderLeg {
    address: String,
    amount: String,
}

impl FixedFloat {
    pub fn new(config: &FixedFloatProviderConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: config
                .url
                .clone()
                .unwrap_or_else(|| DEFAULT_URL.to_string()),
            api_key: config.api_key.clone(),
            api_secret: config.api_secret.clone(),
            refcode: config.refcode.clone(),
            afftax: config.afftax,
        }
    }

    fn sign(&self, body: &str) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.api_secret.as_bytes())?;
        mac.update(body.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    async fn call<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Value) -> Result<T> {
        let body = serde_json::to_string(&params)?;
        let res = self
            .client
            .post(format!("{}/{}", self.url.trim_end_matches('/'), method))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json; charset=UTF-8")
            .header("X-API-KEY", &self.api_key)
            .header("X-API-SIGN", self.sign(&body)?)
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let envelope: Envelope = res.json().await.context("parsing FixedFloat response")?;
        if envelope.code != 0 {
            bail!("FixedFloat {}: {}", envelope.code, envelope.msg);
        }
        let data = envelope.data.context("FixedFloat response had no data")?;
        Ok(serde_json::from_value(data)?)
    }

    fn create_params(&self, req: &SwapOrderRequest) -> Value {
        let mut params = json!({
            "type": "float",
            "fromCcy": "XMR",
            "toCcy": "BTC",
            "direction": "to",
            "amount": req.receive_sats as f64 / 100_000_000.0,
            "toAddress": req.receive_address,
        });
        if let (Some(refcode), Some(afftax)) = (&self.refcode, self.afftax) {
            params["refcode"] = json!(refcode);
            params["afftax"] = json!(afftax);
        } else if let Some(refcode) = &self.refcode {
            params["refcode"] = json!(refcode);
        }
        params
    }
}

#[async_trait]
impl SwapProvider for FixedFloat {
    async fn create_order(&self, req: SwapOrderRequest) -> Result<SwapOrder> {
        let order: CreatedOrder = self.call("create", self.create_params(&req)).await?;
        let expires = DateTime::<Utc>::from_timestamp(order.time.expiration, 0)
            .context("FixedFloat order has an invalid expiration")?;
        Ok(SwapOrder {
            data: MoneroSwapData {
                order_id: order.id,
                order_token: order.token,
                deposit_address: order.from.address,
                deposit_amount: order.from.amount,
                receive_address: req.receive_address,
            },
            expires,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(url: String, refcode: Option<&str>, afftax: Option<f32>) -> FixedFloat {
        FixedFloat::new(&FixedFloatProviderConfig {
            api_key: "key".to_string(),
            api_secret: "secret".to_string(),
            url: Some(url),
            refcode: refcode.map(str::to_string),
            afftax,
        })
    }

    fn request() -> SwapOrderRequest {
        SwapOrderRequest {
            receive_sats: 150_000,
            receive_address: "bc1qdest".to_string(),
        }
    }

    fn created() -> Value {
        json!({
            "code": 0,
            "msg": "OK",
            "data": {
                "id": "ABC123",
                "token": "tok",
                "time": {"expiration": 1_900_000_000},
                "from": {"address": "4Axmr", "amount": "0.0123"},
                "to": {"address": "bc1qdest", "amount": "0.0015"}
            }
        })
    }

    #[test]
    fn default_url_is_the_public_api() {
        let ff = FixedFloat::new(&FixedFloatProviderConfig {
            api_key: String::new(),
            api_secret: String::new(),
            url: None,
            refcode: None,
            afftax: None,
        });
        assert_eq!(ff.url, DEFAULT_URL);
    }

    #[test]
    fn signature_is_hmac_sha256_hex() {
        let ff = client("http://x".to_string(), None, None);
        let sig = ff.sign("{}").unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(sig, expected_sign("secret", "{}"));
        assert_ne!(sig, expected_sign("other", "{}"));
    }

    fn expected_sign(secret: &str, body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn params_ask_for_btc_out_to_our_address() {
        let ff = client("http://x".to_string(), None, None);
        let params = ff.create_params(&request());
        assert_eq!(params["fromCcy"], "XMR");
        assert_eq!(params["toCcy"], "BTC");
        assert_eq!(params["direction"], "to");
        assert_eq!(params["type"], "float");
        assert_eq!(params["amount"], 0.0015);
        assert_eq!(params["toAddress"], "bc1qdest");
        assert!(params.get("refcode").is_none());
        assert!(params.get("afftax").is_none());
    }

    #[test]
    fn params_carry_affiliate_fields_when_configured() {
        let ff = client("http://x".to_string(), Some("code"), Some(0.2));
        let params = ff.create_params(&request());
        assert_eq!(params["refcode"], "code");
        assert!(params["afftax"].as_f64().unwrap() - 0.2 < 1e-6);

        let ff = client("http://x".to_string(), Some("code"), None);
        let params = ff.create_params(&request());
        assert_eq!(params["refcode"], "code");
        assert!(params.get("afftax").is_none());
    }

    #[tokio::test]
    async fn create_order_signs_and_parses() -> Result<()> {
        let server = MockServer::start().await;
        let ff = client(server.uri(), None, None);
        let body = ff.create_params(&request());
        let sign = expected_sign("secret", &serde_json::to_string(&body)?);
        Mock::given(method("POST"))
            .and(path("/create"))
            .and(header("X-API-KEY", "key"))
            .and(header("X-API-SIGN", sign.as_str()))
            .and(body_json(&body))
            .respond_with(ResponseTemplate::new(200).set_body_json(created()))
            .expect(1)
            .mount(&server)
            .await;

        let order = ff.create_order(request()).await?;
        assert_eq!(order.data.order_id, "ABC123");
        assert_eq!(order.data.order_token, "tok");
        assert_eq!(order.data.deposit_address, "4Axmr");
        assert_eq!(order.data.deposit_amount, "0.0123");
        assert_eq!(order.data.receive_address, "bc1qdest");
        assert_eq!(order.expires.timestamp(), 1_900_000_000);
        Ok(())
    }

    #[tokio::test]
    async fn api_error_code_is_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({"code": 301, "msg": "Amount less than limit", "data": null}),
                ),
            )
            .mount(&server)
            .await;
        let err = client(server.uri(), None, None)
            .create_order(request())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Amount less than limit"), "{err}");
    }

    #[tokio::test]
    async fn http_error_is_surfaced() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(
            client(server.uri(), None, None)
                .create_order(request())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn missing_data_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"code": 0, "msg": "", "data": null})),
            )
            .mount(&server)
            .await;
        assert!(
            client(server.uri(), None, None)
                .create_order(request())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_expiration_is_an_error() {
        let server = MockServer::start().await;
        let mut body = created();
        body["data"]["time"]["expiration"] = json!(i64::MAX);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        assert!(
            client(server.uri(), None, None)
                .create_order(request())
                .await
                .is_err()
        );
    }
}
