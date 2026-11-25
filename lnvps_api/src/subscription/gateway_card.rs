use super::{RenewMode, SubscriptionHandler};
use anyhow::{Result, bail};
use chrono::{Datelike, Utc};
use lnvps_api_common::{
    GatewayCardProvider, GatewayCardRequest, GatewaySavedCharge, OffSessionRenewals,
};
use lnvps_db::{
    PaymentMethod, RenewalSource, SubscriptionPayment, SubscriptionPaymentType, User,
    UserPaymentMethod,
};
use log::info;

pub(crate) const CARD_EXPIRE_SECS: u32 = 3600;

pub(crate) const GATEWAY_CARD_EXTERNAL_DATA: &str = r#"{"token":"","session_id":""}"#;

pub(crate) struct GatewayCardCharge {
    pub payment_id: Vec<u8>,
    pub external_id: String,
}

pub(crate) struct GatewayCardOrder {
    pub payment_id: Vec<u8>,
    pub external_id: String,
    pub external_data: String,
}

fn card_provider(method: PaymentMethod) -> Option<GatewayCardProvider> {
    match method {
        PaymentMethod::Revolut => Some(GatewayCardProvider::Revolut),
        PaymentMethod::Stripe => Some(GatewayCardProvider::Stripe),
        _ => None,
    }
}

fn provider_name(method: PaymentMethod) -> Option<&'static str> {
    match method {
        PaymentMethod::Revolut => Some("revolut"),
        PaymentMethod::Stripe => Some("stripe"),
        _ => None,
    }
}

impl SubscriptionHandler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn gateway_card_order(
        &self,
        company_id: u64,
        method: PaymentMethod,
        mode: &RenewMode,
        user: &User,
        subscription_id: u64,
        payment_type: SubscriptionPaymentType,
        amount: u64,
        tax: u64,
        currency: &str,
        description: String,
    ) -> Result<Option<GatewayCardOrder>> {
        let (RenewMode::Interactive { save_card }, Some(provider)) = (mode, card_provider(method))
        else {
            return Ok(None);
        };
        let Some(gateway) = self.card_gateway_for(company_id, method).await? else {
            return Ok(None);
        };
        let has_saved_method = self
            .db()
            .list_user_payment_methods(user.id, Some(provider.as_str()))
            .await
            .map(|m| m.iter().any(|pm| pm.enabled))
            .unwrap_or(false);
        let email: String = user.email.clone().into();
        let customer_email = (!email.is_empty()).then_some(email);
        let save_card = *save_card
            && !has_saved_method
            && payment_type != SubscriptionPaymentType::Upgrade
            && customer_email.is_some();
        let payment_id: [u8; 32] = rand::random();
        let (success_url, cancel_url) = self.card_return_urls();
        let attempt = gateway
            .create_card_attempt(GatewayCardRequest {
                payment_id: payment_id.to_vec(),
                provider,
                amount,
                currency: currency.to_string(),
                tax,
                description,
                expires_in_secs: CARD_EXPIRE_SECS,
                customer_ref: user.id.to_string(),
                customer_email,
                save_card,
                success_url: Some(success_url),
                cancel_url: Some(cancel_url),
                metadata: serde_json::json!({
                    "subscription_id": subscription_id,
                    "payment_type": format!("{payment_type:?}"),
                }),
            })
            .await?;
        Ok(Some(GatewayCardOrder {
            payment_id: payment_id.to_vec(),
            external_id: attempt.external_id,
            external_data: attempt.external_data,
        }))
    }

    fn card_return_urls(&self) -> (String, String) {
        let base = self.public_url.trim_end_matches('/').to_string();
        (base.clone(), base)
    }

    pub(crate) async fn gateway_saved_method(
        &self,
        company_id: u64,
        user_id: u64,
        method: PaymentMethod,
        method_id: Option<u64>,
    ) -> Result<Option<UserPaymentMethod>> {
        let Some(provider) = provider_name(method) else {
            return Ok(None);
        };
        if self.card_gateway_for(company_id, method).await?.is_none() {
            return Ok(None);
        }
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
        company_id: u64,
        method: PaymentMethod,
        saved: &UserPaymentMethod,
        subscription_id: u64,
        user_id: u64,
        payment_type: SubscriptionPaymentType,
        amount: u64,
        tax: u64,
        currency: &str,
        description: String,
    ) -> Result<GatewayCardCharge> {
        let (Some(gateway), Some(gateway_method_id)) = (
            self.card_gateway_for(company_id, method).await?,
            saved.gateway_method_id,
        ) else {
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

    pub(crate) async fn holds_gateway_method(
        &self,
        company_id: u64,
        method: PaymentMethod,
        saved: &UserPaymentMethod,
    ) -> bool {
        saved.gateway_method_id.is_some()
            && self
                .card_gateway_for(company_id, method)
                .await
                .ok()
                .flatten()
                .is_some()
    }

    pub(crate) async fn auto_renew_via_gateway_card(
        &self,
        sub_id: u64,
        method: PaymentMethod,
    ) -> Result<SubscriptionPayment> {
        let company_id = self.db().get_subscription(sub_id).await?.company_id;
        match self.gateways().off_session_for(company_id, method).await? {
            OffSessionRenewals::Off => {
                bail!("Off-session card renewals through the gateway are not enabled")
            }
            OffSessionRenewals::DryRun => {
                let quote = self.quote_renewal(sub_id, method, 1, None).await?;
                info!(
                    "DRY RUN: would charge saved {:?} method for subscription {}: {} {} (+{} tax)",
                    method, sub_id, quote.amount, quote.currency, quote.tax
                );
                bail!("Off-session renewal is in dry-run mode, nothing was charged")
            }
            OffSessionRenewals::Live => {
                self.renew_subscription_inner(
                    sub_id,
                    method,
                    1,
                    RenewMode::Saved { method_id: None },
                    None,
                    RenewalSource::Auto,
                )
                .await
            }
        }
    }

    pub(crate) async fn wants_gateway_saved(
        &self,
        company_id: u64,
        method: PaymentMethod,
        mode: &RenewMode,
    ) -> bool {
        provider_name(method).is_some()
            && matches!(mode, RenewMode::Saved { .. })
            && self
                .card_gateway_for(company_id, method)
                .await
                .ok()
                .flatten()
                .is_some()
    }
}
