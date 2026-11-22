use super::{RenewMode, SubscriptionHandler};
use anyhow::{Result, bail};
use chrono::{Datelike, Utc};
use lnvps_api_common::GatewaySavedCharge;
use lnvps_db::{PaymentMethod, SubscriptionPaymentType, UserPaymentMethod};

pub(crate) const GATEWAY_CARD_EXTERNAL_DATA: &str = r#"{"token":"","session_id":""}"#;

pub(crate) struct GatewayCardCharge {
    pub payment_id: Vec<u8>,
    pub external_id: String,
}

fn provider_name(method: PaymentMethod) -> Option<&'static str> {
    match method {
        PaymentMethod::Revolut => Some("revolut"),
        PaymentMethod::Stripe => Some("stripe"),
        _ => None,
    }
}

impl SubscriptionHandler {
    pub(crate) async fn gateway_saved_method(
        &self,
        user_id: u64,
        method: PaymentMethod,
        method_id: Option<u64>,
    ) -> Result<Option<UserPaymentMethod>> {
        let (Some(provider), Some(_)) = (provider_name(method), self.card_gateway()) else {
            return Ok(None);
        };
        let now = Utc::now();
        let (year, month) = (now.year() as u16, now.month() as u16);
        let mut usable = self
            .db()
            .list_user_payment_methods(user_id, Some(provider))
            .await?
            .into_iter()
            .filter(|m| m.gateway_method_id.is_some() && m.enabled && !m.is_expired(year, month));
        Ok(match method_id {
            Some(id) => usable.find(|m| m.id == id),
            None => usable.next(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn charge_gateway_saved_method(
        &self,
        saved: &UserPaymentMethod,
        subscription_id: u64,
        user_id: u64,
        payment_type: SubscriptionPaymentType,
        amount: u64,
        tax: u64,
        currency: &str,
        description: String,
    ) -> Result<GatewayCardCharge> {
        let (Some(gateway), Some(gateway_method_id)) =
            (self.card_gateway(), saved.gateway_method_id)
        else {
            bail!("Saved payment method is not held by the payment gateway");
        };
        let payment_id: [u8; 32] = rand::random();
        let charge = gateway
            .charge_saved_method(GatewaySavedCharge {
                payment_id: payment_id.to_vec(),
                gateway_method_id,
                amount,
                currency: currency.to_string(),
                tax,
                description,
                customer_ref: user_id.to_string(),
                metadata: serde_json::json!({
                    "subscription_id": subscription_id,
                    "payment_type": format!("{payment_type:?}"),
                }),
            })
            .await?;
        Ok(GatewayCardCharge {
            payment_id: payment_id.to_vec(),
            external_id: charge.external_id,
        })
    }

    pub(crate) fn wants_gateway_saved(&self, method: PaymentMethod, mode: &RenewMode) -> bool {
        self.card_gateway().is_some()
            && provider_name(method).is_some()
            && matches!(mode, RenewMode::Saved { .. })
    }
}
