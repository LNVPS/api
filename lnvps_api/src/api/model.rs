// Re-export common API models
pub use lnvps_api_common::*;

use crate::exchange::{ExchangeRateService, alt_prices};
use anyhow::Result;
use chrono::{DateTime, Utc};
use humantime::format_duration;
use lnvps_api_common::{ApiDiskInterface, ApiDiskType};
use lnvps_db::{PaymentMethod, PaymentType, VmCustomTemplate};

use payments_rs::currency::{Currency, CurrencyAmount};
use serde::{Deserialize, Serialize, Deserializer};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

// Custom deserializer that distinguishes between missing field and explicit null
// Used for PATCH endpoints to allow clearing optional fields
fn deserialize_nullable_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

#[derive(Serialize, Deserialize)]
pub struct ApiCustomVmOrder {
    #[serde(flatten)]
    pub spec: ApiCustomVmRequest,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

#[derive(Serialize)]
pub struct ApiTemplatesResponse {
    pub templates: Vec<ApiVmTemplate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_template: Option<Vec<ApiCustomTemplateParams>>,
}

impl ApiTemplatesResponse {
    pub async fn expand_pricing(&mut self, rates: &Arc<dyn ExchangeRateService>) -> Result<()> {
        let rates = rates.list_rates().await?;

        for template in &mut self.templates {
            let list_price = CurrencyAmount::from_f32(
                template.cost_plan.currency.into(),
                template.cost_plan.amount,
            );
            for alt_price in alt_prices(&rates, list_price) {
                template.cost_plan.other_price.push(ApiPrice {
                    currency: alt_price.currency().into(),
                    amount: alt_price.value_f32(),
                });
            }
        }
        Ok(())
    }
}

// Models that are only used in lnvps_api (moved from common)

#[derive(Serialize, Deserialize)]
pub struct VMPatchRequest {
    /// SSH key assigned to vm
    pub ssh_key_id: Option<u64>,
    /// Reverse DNS PTR domain
    pub reverse_dns: Option<String>,
    /// Enable automatic renewal via NWC for this VM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_renewal_enabled: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct AccountPatchRequest {
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub email: Option<Option<String>>,
    pub contact_nip17: bool,
    pub contact_email: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub country_code: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub address_1: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub address_2: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub state: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub city: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub postcode: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub tax_id: Option<Option<String>>,
    /// Nostr Wallet Connect connection string for automatic VM renewals
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_nullable_option")]
    pub nwc_connection_string: Option<Option<String>>,
}

impl From<lnvps_db::User> for AccountPatchRequest {
    fn from(user: lnvps_db::User) -> Self {
        AccountPatchRequest {
            email: Some(user.email.map(|e| e.into())),
            contact_nip17: user.contact_nip17,
            contact_email: user.contact_email,
            country_code: Some(user.country_code),
            name: Some(user.billing_name),
            address_1: Some(user.billing_address_1),
            address_2: Some(user.billing_address_2),
            state: Some(user.billing_state),
            city: Some(user.billing_city),
            postcode: Some(user.billing_postcode),
            tax_id: Some(user.billing_tax_id),
            nwc_connection_string: Some(user.nwc_connection_string.map(|nwc| nwc.into())),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateVmRequest {
    pub template_id: u64,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateSshKey {
    pub name: String,
    pub key_data: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApiVmPayment {
    pub id: String,
    pub vm_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub tax: u64,
    pub currency: String,
    pub is_paid: bool,
    pub data: ApiPaymentData,
    pub time: u64,
    pub is_upgrade: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_params: Option<String>,
}

#[derive(Serialize)]
pub struct ApiInvoiceItem {
    /// Raw amount in smallest currency unit (cents for fiat, millisats for BTC)
    pub amount: u64,
    /// Raw tax amount in smallest currency unit (cents for fiat, millisats for BTC)
    pub tax: u64,
    /// Raw currency string
    pub currency: String,
    /// Raw duration in seconds
    pub time: u64,
    /// Formatted currency amount (e.g., "EUR 12.34", "BTC 0.00012345")
    pub formatted_amount: String,
    /// Formatted tax amount (e.g., "EUR 2.88", "BTC 0.00002879")
    pub formatted_tax: String,
    /// Formatted duration (e.g., "30 days", "1 month", "6 hours")
    pub formatted_duration: String,
}

impl ApiInvoiceItem {
    /// Creates a formatted invoice item from raw payment data
    pub fn from_payment_data(
        amount: u64,
        tax: u64,
        currency: &str,
        time_seconds: u64,
    ) -> Result<Self, anyhow::Error> {
        let parsed_currency = Currency::from_str(currency)
            .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency))?;

        let amount_currency = CurrencyAmount::from_u64(parsed_currency, amount);
        let tax_currency = CurrencyAmount::from_u64(parsed_currency, tax);

        Ok(Self {
            amount,
            tax,
            currency: currency.to_string(),
            time: time_seconds,
            formatted_amount: amount_currency.to_string(),
            formatted_tax: tax_currency.to_string(),
            formatted_duration: format_duration(Duration::from_secs(time_seconds)).to_string(),
        })
    }

    /// Creates a formatted invoice item from a VmPayment
    pub fn from_vm_payment(payment: &lnvps_db::VmPayment) -> Result<Self, anyhow::Error> {
        Self::from_payment_data(
            payment.amount,
            payment.tax,
            &payment.currency,
            payment.time_value,
        )
    }
}

impl From<lnvps_db::VmPayment> for ApiVmPayment {
    fn from(value: lnvps_db::VmPayment) -> Self {
        Self {
            id: hex::encode(&value.id),
            vm_id: value.vm_id,
            created: value.created,
            expires: value.expires,
            amount: value.amount,
            tax: value.tax,
            currency: value.currency,
            is_paid: value.is_paid,
            time: value.time_value,
            is_upgrade: value.payment_type == PaymentType::Upgrade,
            upgrade_params: value.upgrade_params.clone(),
            data: match &value.payment_method {
                PaymentMethod::Lightning => ApiPaymentData::Lightning(value.external_data.into()),
                PaymentMethod::Revolut => {
                    #[derive(Deserialize)]
                    struct RevolutData {
                        pub token: String,
                    }
                    let data: RevolutData =
                        serde_json::from_str(value.external_data.as_str()).unwrap();
                    ApiPaymentData::Revolut { token: data.token }
                }
                PaymentMethod::Paypal => {
                    todo!()
                }
                PaymentMethod::Stripe => {
                    #[derive(Deserialize)]
                    struct StripeData {
                        pub session_id: String,
                    }
                    let data: StripeData =
                        serde_json::from_str(value.external_data.as_str()).unwrap();
                    ApiPaymentData::Stripe {
                        session_id: data.session_id,
                    }
                }
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiPaymentInfo {
    pub name: ApiPaymentMethod,

    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,

    pub currencies: Vec<ApiCurrency>,
}

/// Payment data related to the payment method
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiPaymentData {
    /// Just an LN invoice
    Lightning(String),
    /// Revolut order data
    Revolut {
        /// Order token
        token: String,
    },
    /// Stripe checkout session
    Stripe {
        /// Stripe checkout session ID
        session_id: String,
    },
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiPaymentMethod {
    #[default]
    Lightning,
    Revolut,
    Paypal,
    Stripe,
    NWC,
}

impl From<PaymentMethod> for ApiPaymentMethod {
    fn from(value: PaymentMethod) -> Self {
        match value {
            PaymentMethod::Lightning => ApiPaymentMethod::Lightning,
            PaymentMethod::Revolut => ApiPaymentMethod::Revolut,
            PaymentMethod::Paypal => ApiPaymentMethod::Paypal,
            PaymentMethod::Stripe => ApiPaymentMethod::Stripe,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiCompany {
    pub id: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postcode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

impl From<lnvps_db::Company> for ApiCompany {
    fn from(value: lnvps_db::Company) -> Self {
        Self {
            email: value.email,
            country_code: value.country_code,
            name: value.name,
            id: value.id,
            address_1: value.address_1,
            address_2: value.address_2,
            state: value.state,
            city: value.city,
            postcode: value.postcode,
            tax_id: value.tax_id,
            phone: value.phone,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiVmHistoryInitiator {
    /// Action initiated by the VM owner
    Owner,
    /// Action initiated by the system
    System,
    /// Action initiated by another user
    Other,
}

#[derive(Serialize)]
pub struct ApiVmHistory {
    /// Unique history entry ID
    pub id: u64,
    /// VM ID this history entry belongs to
    pub vm_id: u64,
    /// Type of action that was performed
    pub action_type: String,
    /// When this action occurred
    pub timestamp: DateTime<Utc>,
    /// Who initiated this action
    pub initiated_by: ApiVmHistoryInitiator,
    /// Previous VM state/configuration if applicable (JSON)
    pub previous_state: Option<String>,
    /// New VM state/configuration if applicable (JSON)
    pub new_state: Option<String>,
    /// Additional metadata about the action (JSON)
    pub metadata: Option<String>,
    /// Human-readable description of the action
    pub description: Option<String>,
}

impl ApiVmHistory {
    pub fn from_with_owner(value: lnvps_db::VmHistory, vm_owner_id: u64) -> Self {
        let initiated_by = match value.initiated_by_user {
            None => ApiVmHistoryInitiator::System,
            Some(user_id) if user_id == vm_owner_id => ApiVmHistoryInitiator::Owner,
            Some(_) => ApiVmHistoryInitiator::Other,
        };

        Self {
            id: value.id,
            vm_id: value.vm_id,
            action_type: value.action_type.to_string(),
            timestamp: value.timestamp,
            initiated_by,
            previous_state: value
                .previous_state
                .map(|v| String::from_utf8_lossy(&v).to_string()),
            new_state: value
                .new_state
                .map(|v| String::from_utf8_lossy(&v).to_string()),
            metadata: value
                .metadata
                .map(|v| String::from_utf8_lossy(&v).to_string()),
            description: value.description,
        }
    }
}

// Simplified versions without complex dependencies
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiCustomVmRequest {
    pub pricing_id: u64,
    pub cpu: u16,
    pub memory: u64,
    pub disk: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
}

impl From<ApiCustomVmRequest> for VmCustomTemplate {
    fn from(value: ApiCustomVmRequest) -> Self {
        VmCustomTemplate {
            id: 0,
            cpu: value.cpu,
            memory: value.memory,
            disk_size: value.disk,
            disk_type: value.disk_type.into(),
            disk_interface: value.disk_interface.into(),
            pricing_id: value.pricing_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiVmUpgradeRequest {
    pub cpu: Option<u16>,
    pub memory: Option<u64>,
    pub disk: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiVmUpgradeQuote {
    pub cost_difference: ApiPrice,
    pub new_renewal_cost: ApiPrice,
    pub discount: ApiPrice,
}

// ============================================================================
// Subscription Models
// ============================================================================

#[derive(Serialize)]
pub struct ApiSubscription {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub currency: ApiCurrency,
    pub interval_amount: u64,
    pub interval_type: ApiVmCostPlanIntervalType,
    pub setup_fee: u64,
    pub auto_renewal_enabled: bool,
    pub line_items: Vec<ApiSubscriptionLineItem>,
}

impl ApiSubscription {
    pub async fn from_subscription(
        db: &dyn lnvps_db::LNVpsDbBase,
        subscription: lnvps_db::Subscription,
    ) -> anyhow::Result<Self> {
        let line_items = db
            .list_subscription_line_items(subscription.id)
            .await?
            .into_iter()
            .map(ApiSubscriptionLineItem::from)
            .collect();

        let currency = match subscription.currency.to_uppercase().as_str() {
            "EUR" => ApiCurrency::EUR,
            "BTC" => ApiCurrency::BTC,
            "USD" => ApiCurrency::USD,
            "GBP" => ApiCurrency::GBP,
            "CAD" => ApiCurrency::CAD,
            "CHF" => ApiCurrency::CHF,
            "AUD" => ApiCurrency::AUD,
            "JPY" => ApiCurrency::JPY,
            _ => ApiCurrency::USD,
        };

        Ok(Self {
            id: subscription.id,
            name: subscription.name,
            description: subscription.description,
            created: subscription.created,
            expires: subscription.expires,
            is_active: subscription.is_active,
            currency,
            interval_amount: subscription.interval_amount,
            interval_type: ApiVmCostPlanIntervalType::from(subscription.interval_type),
            setup_fee: subscription.setup_fee,
            auto_renewal_enabled: subscription.auto_renewal_enabled,
            line_items,
        })
    }
}

#[derive(Serialize)]
pub struct ApiSubscriptionLineItem {
    pub id: u64,
    pub subscription_id: u64,
    pub name: String,
    pub description: Option<String>,
    pub amount: u64,
    pub setup_amount: u64,
    pub configuration: Option<serde_json::Value>,
}

impl From<lnvps_db::SubscriptionLineItem> for ApiSubscriptionLineItem {
    fn from(line_item: lnvps_db::SubscriptionLineItem) -> Self {
        Self {
            id: line_item.id,
            subscription_id: line_item.subscription_id,
            name: line_item.name,
            description: line_item.description,
            amount: line_item.amount,
            setup_amount: line_item.setup_amount,
            configuration: line_item.configuration,
        }
    }
}

#[derive(Serialize)]
pub struct ApiSubscriptionPayment {
    pub id: String, // Hex encoded
    pub subscription_id: u64,
    pub created: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub amount: u64,
    pub currency: ApiCurrency,
    pub payment_method: ApiPaymentMethod,
    pub payment_type: ApiSubscriptionPaymentType,
    pub is_paid: bool,
    pub time_value: Option<u64>,
    pub tax: u64,
}

#[derive(Serialize, Deserialize)]
pub enum ApiSubscriptionPaymentType {
    Purchase,
    Renewal,
}

impl From<lnvps_db::SubscriptionPaymentType> for ApiSubscriptionPaymentType {
    fn from(payment_type: lnvps_db::SubscriptionPaymentType) -> Self {
        match payment_type {
            lnvps_db::SubscriptionPaymentType::Purchase => ApiSubscriptionPaymentType::Purchase,
            lnvps_db::SubscriptionPaymentType::Renewal => ApiSubscriptionPaymentType::Renewal,
        }
    }
}

impl From<lnvps_db::SubscriptionPayment> for ApiSubscriptionPayment {
    fn from(payment: lnvps_db::SubscriptionPayment) -> Self {
        let currency = match payment.currency.to_uppercase().as_str() {
            "EUR" => ApiCurrency::EUR,
            "BTC" => ApiCurrency::BTC,
            "USD" => ApiCurrency::USD,
            "GBP" => ApiCurrency::GBP,
            "CAD" => ApiCurrency::CAD,
            "CHF" => ApiCurrency::CHF,
            "AUD" => ApiCurrency::AUD,
            "JPY" => ApiCurrency::JPY,
            _ => ApiCurrency::USD,
        };

        Self {
            id: hex::encode(&payment.id),
            subscription_id: payment.subscription_id,
            created: payment.created,
            expires: payment.expires,
            amount: payment.amount,
            currency,
            payment_method: ApiPaymentMethod::from(payment.payment_method),
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            is_paid: payment.is_paid,
            time_value: payment.time_value,
            tax: payment.tax,
        }
    }
}
