use crate::ip_provider::{
    IpOrderSpec, IpProvider, IpQuote, OwnedIp, PlacedOrder, ProviderOrderStatus,
};
use crate::json_api::JsonApi;
use crate::ovh::ovh_json_api;
use crate::retry::{OpError, OpResult};
use async_trait::async_trait;
use ipnetwork::IpNetwork;
use log::info;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

pub struct OvhIpProvider {
    name: String,
    url: String,
    token: String,
    subsidiary: String,
    rir: String,
    api: OnceCell<JsonApi>,
}

impl OvhIpProvider {
    pub fn new(name: &str, url: &str, token: &str, subsidiary: &str, rir: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            token: token.to_string(),
            subsidiary: subsidiary.to_string(),
            rir: rir.to_string(),
            api: OnceCell::new(),
        }
    }

    async fn api(&self) -> OpResult<&JsonApi> {
        self.api
            .get_or_try_init(|| ovh_json_api(&self.url, &self.token))
            .await
    }

    pub fn plan_code(&self, prefix_len: u16) -> OpResult<String> {
        match prefix_len {
            32 => Ok(format!("ip-failover-{}", self.rir)),
            24..=30 => Ok(format!("ip-v4-s{}-{}", prefix_len, self.rir)),
            other => Err(OpError::Fatal(anyhow::anyhow!(
                "OVH does not sell additional IPv4 with prefix length /{other}"
            ))),
        }
    }

    async fn build_cart(&self, spec: &IpOrderSpec) -> OpResult<String> {
        if spec.quantity == 0 {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "quantity must be at least 1"
            )));
        }
        if spec.prefix_len != 32 && spec.quantity != 1 {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "OVH sells address blocks one at a time"
            )));
        }
        let plan_code = self.plan_code(spec.prefix_len)?;
        let api = self.api().await?;
        let cart: OvhCart = api
            .post(
                "v1/order/cart",
                OvhCartCreation {
                    ovh_subsidiary: self.subsidiary.clone(),
                    description: "lnvps additional ip".to_string(),
                },
            )
            .await?;
        let cart_id = urlencoding::encode(&cart.cart_id).into_owned();
        api.req_status(
            Method::POST,
            &format!("v1/order/cart/{cart_id}/assign"),
            Some(serde_json::json!({})),
        )
        .await?;
        let item: OvhCartItem = api
            .post(
                &format!("v1/order/cart/{cart_id}/ip"),
                OvhProductCreation {
                    plan_code,
                    duration: "P1M".to_string(),
                    pricing_mode: "default".to_string(),
                    quantity: spec.quantity,
                },
            )
            .await?;
        let mut configs = vec![];
        if let Some(c) = &spec.country {
            configs.push(("country", c.clone()));
        }
        if let Some(d) = &spec.destination {
            configs.push(("destination", d.clone()));
        }
        for (label, value) in configs {
            api.post::<serde_json::Value, _>(
                &format!(
                    "v1/order/cart/{cart_id}/item/{}/configuration",
                    item.item_id
                ),
                OvhConfiguration {
                    label: label.to_string(),
                    value,
                },
            )
            .await?;
        }
        Ok(cart_id)
    }

    async fn preview(&self, cart_id: &str) -> OpResult<IpQuote> {
        let order: OvhOrder = self
            .api()
            .await?
            .get(&format!("v1/order/cart/{cart_id}/checkout"))
            .await?;
        order.cost()
    }
}

#[async_trait]
impl IpProvider for OvhIpProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn quote(&self, spec: &IpOrderSpec) -> OpResult<IpQuote> {
        let cart_id = self.build_cart(spec).await?;
        self.preview(&cart_id).await
    }

    async fn order(&self, spec: &IpOrderSpec, max_cost: u64) -> OpResult<PlacedOrder> {
        let cart_id = self.build_cart(spec).await?;
        let quote = self.preview(&cart_id).await?;
        if quote.cost > max_cost {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "OVH quoted {} {} which is above the allowed maximum of {}",
                quote.cost,
                quote.currency,
                max_cost
            )));
        }
        info!(
            "[OVH] Checking out cart {cart_id} for {} minor units",
            quote.cost
        );
        let order: OvhOrder = self
            .api()
            .await?
            .post(
                &format!("v1/order/cart/{cart_id}/checkout"),
                OvhCheckout {
                    auto_pay_with_preferred_payment_method: true,
                    waive_retractation_period: true,
                },
            )
            .await
            .map_err(|e| {
                OpError::Fatal(anyhow::anyhow!(
                    "checkout of cart {cart_id} failed, the order may or may not exist: {}",
                    e.into_inner()
                ))
            })?;
        let order_id = order
            .order_id
            .ok_or_else(|| OpError::Fatal(anyhow::anyhow!("OVH checkout returned no order id")))?;
        let cost = order.cost().unwrap_or(quote);
        Ok(PlacedOrder {
            provider_order_id: order_id.to_string(),
            cost: cost.cost,
            currency: cost.currency,
        })
    }

    async fn order_status(&self, provider_order_id: &str) -> OpResult<ProviderOrderStatus> {
        let api = self.api().await?;
        let status: String = api
            .get(&format!("v1/me/order/{provider_order_id}/status"))
            .await?;
        match status.as_str() {
            "cancelled" | "cancelling" => Ok(ProviderOrderStatus::Failed(format!(
                "OVH order {provider_order_id} is {status}"
            ))),
            "delivered" => Ok(ProviderOrderStatus::Delivered(
                self.order_ips(provider_order_id).await?,
            )),
            _ => Ok(ProviderOrderStatus::Pending),
        }
    }

    async fn list_owned(&self) -> OpResult<Vec<OwnedIp>> {
        let api = self.api().await?;
        let ips: Vec<String> = api.get("v1/ip?isAdditionalIp=true").await?;
        let mut ret = vec![];
        for ip in ips {
            ret.push(self.owned_ip(&ip).await?);
        }
        Ok(ret)
    }

    async fn release(&self, cidr: &str) -> OpResult<()> {
        let encoded = urlencoding::encode(cidr).into_owned();
        let info: OvhIpInfo = self.api().await?.get(&format!("v1/ip/{encoded}")).await?;
        if info.can_be_terminated == Some(false) {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "OVH says {cidr} cannot be terminated"
            )));
        }
        info!("[OVH] Terminating {cidr}");
        self.api()
            .await?
            .post::<serde_json::Value, _>(
                &format!("v1/ip/{encoded}/terminate"),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }
}

impl OvhIpProvider {
    async fn owned_ip(&self, ip: &str) -> OpResult<OwnedIp> {
        let encoded = urlencoding::encode(ip).into_owned();
        let info: OvhIpInfo = self.api().await?.get(&format!("v1/ip/{encoded}")).await?;
        Ok(OwnedIp {
            cidr: normalize_cidr(ip),
            country: info.country,
            routed_to: info.routed_to.and_then(|r| r.service_name),
        })
    }

    async fn order_ips(&self, provider_order_id: &str) -> OpResult<Vec<OwnedIp>> {
        let api = self.api().await?;
        let details: Vec<u64> = api
            .get(&format!("v1/me/order/{provider_order_id}/details"))
            .await?;
        let mut ret = vec![];
        for d in details {
            let detail: OvhOrderDetail = api
                .get(&format!("v1/me/order/{provider_order_id}/details/{d}"))
                .await?;
            let Some(domain) = detail.domain else {
                continue;
            };
            if domain.parse::<IpNetwork>().is_err() {
                continue;
            }
            ret.push(self.owned_ip(&domain).await?);
        }
        Ok(ret)
    }
}

fn normalize_cidr(ip: &str) -> String {
    match ip.parse::<IpNetwork>() {
        Ok(n) if ip.contains('/') => n.to_string(),
        Ok(n) => format!("{}/{}", n.ip(), if n.is_ipv4() { 32 } else { 128 }),
        Err(_) => ip.to_string(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OvhCartCreation {
    ovh_subsidiary: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhCart {
    cart_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OvhProductCreation {
    plan_code: String,
    duration: String,
    pricing_mode: String,
    quantity: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhCartItem {
    item_id: u64,
}

#[derive(Serialize)]
struct OvhConfiguration {
    label: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OvhCheckout {
    auto_pay_with_preferred_payment_method: bool,
    waive_retractation_period: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhOrder {
    order_id: Option<u64>,
    prices: Option<OvhOrderPrices>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhOrderPrices {
    with_tax: Option<OvhPrice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhPrice {
    currency_code: String,
    value: f64,
}

impl OvhOrder {
    fn cost(&self) -> OpResult<IpQuote> {
        let price = self
            .prices
            .as_ref()
            .and_then(|p| p.with_tax.as_ref())
            .ok_or_else(|| OpError::Fatal(anyhow::anyhow!("OVH order carries no price")))?;
        let factor = if price.currency_code == "JPY" {
            1.0
        } else {
            100.0
        };
        Ok(IpQuote {
            cost: (price.value * factor).round() as u64,
            currency: price.currency_code.clone(),
        })
    }
}

#[derive(Deserialize)]
struct OvhOrderDetail {
    domain: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhIpInfo {
    country: Option<String>,
    can_be_terminated: Option<bool>,
    routed_to: Option<OvhRoutedTo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvhRoutedTo {
    service_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "app:secret:consumer";

    fn provider(server: &MockServer) -> OvhIpProvider {
        OvhIpProvider::new("ovh", &server.uri(), TOKEN, "IE", "ripe")
    }

    fn spec() -> IpOrderSpec {
        IpOrderSpec {
            country: Some("IE".to_string()),
            destination: Some("ns1234.ip-1-2-3.eu".to_string()),
            prefix_len: 32,
            quantity: 2,
        }
    }

    async fn cart_sequence(server: &MockServer, price: f64) {
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart"))
            .and(body_json(json!({
                "ovhSubsidiary": "IE",
                "description": "lnvps additional ip"
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"cartId": "cart1", "items": []})),
            )
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/assign"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/ip"))
            .and(body_json(json!({
                "planCode": "ip-failover-ripe",
                "duration": "P1M",
                "pricingMode": "default",
                "quantity": 2
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"itemId": 77})))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/item/77/configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 1})))
            .expect(2)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "prices": {"withTax": {"currencyCode": "EUR", "value": price}}
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn quote_builds_the_cart_without_checking_out() {
        let server = MockServer::start().await;
        cart_sequence(&server, 4.78).await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let q = provider(&server).quote(&spec()).await.unwrap();
        assert_eq!(q.cost, 478);
        assert_eq!(q.currency, "EUR");
    }

    #[tokio::test]
    async fn order_checks_out_and_returns_the_order_id() {
        let server = MockServer::start().await;
        cart_sequence(&server, 4.78).await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .and(body_json(json!({
                "autoPayWithPreferredPaymentMethod": true,
                "waiveRetractationPeriod": true
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "orderId": 424242,
                "prices": {"withTax": {"currencyCode": "EUR", "value": 4.78}}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let placed = provider(&server).order(&spec(), 1000).await.unwrap();
        assert_eq!(placed.provider_order_id, "424242");
        assert_eq!(placed.cost, 478);
        assert_eq!(placed.currency, "EUR");
    }

    #[tokio::test]
    async fn order_above_the_maximum_never_checks_out() {
        let server = MockServer::start().await;
        cart_sequence(&server, 4.78).await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let err = provider(&server).order(&spec(), 477).await.unwrap_err();
        assert!(matches!(err, OpError::Fatal(_)));
        assert!(err.to_string().contains("above the allowed maximum"));
    }

    #[tokio::test]
    async fn checkout_error_body_is_surfaced_as_fatal() {
        let server = MockServer::start().await;
        cart_sequence(&server, 4.78).await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "class": "Client::Forbidden",
                "message": "No default payment method"
            })))
            .mount(&server)
            .await;
        let err = provider(&server).order(&spec(), 1000).await.unwrap_err();
        assert!(matches!(err, OpError::Fatal(_)));
        assert!(err.to_string().contains("No default payment method"));
    }

    #[tokio::test]
    async fn cart_error_is_fatal_and_checkout_is_never_reached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "class": "Client::BadRequest",
                "message": "Invalid subsidiary"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let err = provider(&server).order(&spec(), 1000).await.unwrap_err();
        assert!(matches!(err, OpError::Fatal(_)));
        assert!(err.to_string().contains("Invalid subsidiary"));
    }

    #[tokio::test]
    async fn checkout_server_error_is_fatal_because_the_purchase_may_have_happened() {
        let server = MockServer::start().await;
        cart_sequence(&server, 4.78).await;
        Mock::given(method("POST"))
            .and(path("/v1/order/cart/cart1/checkout"))
            .respond_with(ResponseTemplate::new(503).set_body_string("down"))
            .mount(&server)
            .await;
        let err = provider(&server).order(&spec(), 1000).await.unwrap_err();
        assert!(matches!(err, OpError::Fatal(_)));
        assert!(err.to_string().contains("may or may not exist"));
    }

    #[tokio::test]
    async fn unsupported_prefix_is_rejected_without_http() {
        let p = OvhIpProvider::new("ovh", "http://127.0.0.1:1", TOKEN, "IE", "ripe");
        assert!(p.plan_code(16).is_err());
        assert_eq!(p.plan_code(29).unwrap(), "ip-v4-s29-ripe");
        assert_eq!(p.plan_code(32).unwrap(), "ip-failover-ripe");
    }

    #[tokio::test]
    async fn order_status_pending_and_cancelled() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/1/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!("delivering")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/2/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!("cancelled")))
            .mount(&server)
            .await;
        let p = provider(&server);
        assert_eq!(
            p.order_status("1").await.unwrap(),
            ProviderOrderStatus::Pending
        );
        assert!(matches!(
            p.order_status("2").await.unwrap(),
            ProviderOrderStatus::Failed(_)
        ));
    }

    #[tokio::test]
    async fn delivered_order_reads_the_new_addresses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/9/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!("delivered")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/9/details"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([11, 12])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/9/details/11"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"domain": "203.0.113.5"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/me/order/9/details/12"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"domain": "fee"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/ip/203.0.113.5"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "country": "ie",
                "canBeTerminated": true,
                "routedTo": {"serviceName": "ns1234"}
            })))
            .mount(&server)
            .await;
        let status = provider(&server).order_status("9").await.unwrap();
        let ProviderOrderStatus::Delivered(ips) = status else {
            panic!("expected delivered, got {status:?}");
        };
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].cidr, "203.0.113.5/32");
        assert_eq!(ips[0].routed_to.as_deref(), Some("ns1234"));
    }

    #[tokio::test]
    async fn release_terminates_the_block() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/ip/203.0.113.5%2F32"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"canBeTerminated": true})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/ip/203.0.113.5%2F32/terminate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"taskId": 1})))
            .expect(1)
            .mount(&server)
            .await;
        provider(&server).release("203.0.113.5/32").await.unwrap();
    }

    #[tokio::test]
    async fn release_is_refused_when_ovh_says_it_cannot_be_terminated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/ip/203.0.113.5%2F32"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"canBeTerminated": false})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/ip/203.0.113.5%2F32/terminate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"taskId": 1})))
            .expect(0)
            .mount(&server)
            .await;
        assert!(provider(&server).release("203.0.113.5/32").await.is_err());
    }

    #[tokio::test]
    async fn list_owned_reads_each_additional_ip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/time"))
            .respond_with(ResponseTemplate::new(200).set_body_string("1700000000"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/ip"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(["203.0.113.5/32"])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/ip/203.0.113.5%2F32"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"country": "ie"})))
            .mount(&server)
            .await;
        let owned = provider(&server).list_owned().await.unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].cidr, "203.0.113.5/32");
    }
}
