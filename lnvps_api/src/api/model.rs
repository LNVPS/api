// Re-export common API models
pub use lnvps_api_common::*;

use crate::exchange::{ExchangeRateService, alt_prices};
use anyhow::Result;
use chrono::{DateTime, Utc};
use humantime::format_duration;
use lnvps_api_common::{ApiDiskInterface, ApiDiskType};
use lnvps_db::{PaymentMethod, PaymentType, VmCustomTemplate};

use payments_rs::currency::{Currency, CurrencyAmount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
            let list_price = CurrencyAmount::from_u64(
                template.cost_plan.currency.into(),
                template.cost_plan.amount,
            );
            for alt_price in alt_prices(&rates, list_price) {
                template.cost_plan.other_price.push(ApiPrice {
                    currency: alt_price.currency().into(),
                    amount: alt_price.value(),
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub email: Option<Option<String>>,
    /// Whether the email address has been verified (read-only, ignored on PATCH)
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    pub contact_nip17: bool,
    pub contact_email: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub country_code: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub name: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub address_1: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub address_2: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub state: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub city: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub postcode: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub tax_id: Option<Option<String>>,
    /// Nostr Wallet Connect connection string for automatic VM renewals
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub nwc_connection_string: Option<Option<String>>,
}

impl From<lnvps_db::User> for AccountPatchRequest {
    fn from(user: lnvps_db::User) -> Self {
        let has_email = !user.email.is_empty();
        let email_str: String = user.email.into();
        AccountPatchRequest {
            email: if has_email { Some(Some(email_str)) } else { None },
            email_verified: has_email.then_some(user.email_verified),
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
    pub processing_fee: u64,
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
    /// Raw processing fee amount in smallest currency unit (cents for fiat, millisats for BTC)
    pub processing_fee: u64,
    /// Raw currency string
    pub currency: String,
    /// Raw duration in seconds
    pub time: u64,
    /// Human-readable amount string (e.g. "EUR 8.55" or "BTC 0.00001320")
    pub formatted_amount: String,
    /// Human-readable tax string (e.g. "EUR 1.97" or "BTC 0.00000304")
    pub formatted_tax: String,
    /// Human-readable duration string (e.g. "1month" or "30days")
    pub formatted_duration: String,
}

impl ApiInvoiceItem {
    /// Creates a formatted invoice item from raw payment data
    pub fn from_payment_data(
        amount: u64,
        tax: u64,
        processing_fee: u64,
        currency: &str,
        time_seconds: u64,
    ) -> Result<Self, anyhow::Error> {
        let cur: payments_rs::currency::Currency = currency
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency))?;
        let formatted_amount =
            payments_rs::currency::CurrencyAmount::from_u64(cur, amount).to_string();
        let formatted_tax = payments_rs::currency::CurrencyAmount::from_u64(cur, tax).to_string();
        let duration = Duration::from_secs(time_seconds);
        let formatted_duration = format_duration(duration).to_string();
        Ok(Self {
            amount,
            tax,
            processing_fee,
            currency: currency.to_string(),
            time: time_seconds,
            formatted_amount,
            formatted_tax,
            formatted_duration,
        })
    }

    /// Creates a formatted invoice item from a VmPayment
    pub fn from_vm_payment(payment: &lnvps_db::VmPayment) -> Result<Self, anyhow::Error> {
        Self::from_payment_data(
            payment.amount,
            payment.tax,
            payment.processing_fee,
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
            processing_fee: value.processing_fee,
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

    /// Processing fee percentage rate (e.g., 1.0 for 1%)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_fee_rate: Option<f32>,

    /// Processing fee base amount in smallest currency units (cents for fiat, millisats for BTC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_fee_base: Option<u64>,

    /// Currency for the processing fee base
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_fee_currency: Option<String>,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// CPU manufacturer as string (e.g. "intel", "amd", "apple")
    pub cpu_mfg: Option<String>,
    /// CPU architecture as string (e.g. "x86_64", "arm64")
    pub cpu_arch: Option<String>,
    /// CPU features as strings (e.g. "AVX2", "AES", "VMX")
    #[serde(default)]
    pub cpu_feature: Vec<String>,
}

impl From<ApiCustomVmRequest> for VmCustomTemplate {
    fn from(value: ApiCustomVmRequest) -> Self {
        // Parse CPU features from strings
        let cpu_features: Vec<lnvps_db::CpuFeature> = value
            .cpu_feature
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        VmCustomTemplate {
            id: 0,
            cpu: value.cpu,
            memory: value.memory,
            disk_size: value.disk,
            disk_type: value.disk_type.into(),
            disk_interface: value.disk_interface.into(),
            pricing_id: value.pricing_id,
            cpu_mfg: value.cpu_mfg.and_then(|s| s.parse().ok()).unwrap_or_default(),
            cpu_arch: value.cpu_arch.and_then(|s| s.parse().ok()).unwrap_or_default(),
            cpu_features: cpu_features.into(),
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
            .map(|item| ApiSubscriptionLineItem::from_with_currency(item, &subscription.currency))
            .collect();

        Ok(Self {
            id: subscription.id,
            name: subscription.name,
            description: subscription.description,
            created: subscription.created,
            expires: subscription.expires,
            is_active: subscription.is_active,
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
    pub price: ApiPrice,
    pub setup_fee: ApiPrice,
    pub configuration: Option<serde_json::Value>,
}

impl ApiSubscriptionLineItem {
    pub fn from_with_currency(line_item: lnvps_db::SubscriptionLineItem, currency: &str) -> Self {
        let api_currency: ApiCurrency =
            currency.parse::<Currency>().unwrap_or(Currency::USD).into();

        let price = CurrencyAmount::from_u64(api_currency.into(), line_item.amount);
        let setup_fee = CurrencyAmount::from_u64(api_currency.into(), line_item.setup_amount);

        Self {
            id: line_item.id,
            subscription_id: line_item.subscription_id,
            name: line_item.name,
            description: line_item.description,
            price: price.into(),
            setup_fee: setup_fee.into(),
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
    pub amount: ApiPrice,
    pub payment_method: ApiPaymentMethod,
    pub payment_type: ApiSubscriptionPaymentType,
    pub is_paid: bool,
    pub tax: ApiPrice,
    pub processing_fee: ApiPrice,
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
        let currency: ApiCurrency = payment
            .currency
            .parse::<Currency>()
            .unwrap_or(Currency::USD)
            .into();

        let amount = CurrencyAmount::from_u64(currency.into(), payment.amount);
        let tax = CurrencyAmount::from_u64(currency.into(), payment.tax);
        let processing_fee = CurrencyAmount::from_u64(currency.into(), payment.processing_fee);

        Self {
            id: hex::encode(&payment.id),
            subscription_id: payment.subscription_id,
            created: payment.created,
            expires: payment.expires,
            amount: amount.into(),
            payment_method: ApiPaymentMethod::from(payment.payment_method),
            payment_type: ApiSubscriptionPaymentType::from(payment.payment_type),
            is_paid: payment.is_paid,
            tax: tax.into(),
            processing_fee: processing_fee.into(),
        }
    }
}

// IP Space Models
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiIpVersion {
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiInternetRegistry {
    ARIN,
    RIPE,
    APNIC,
    LACNIC,
    AFRINIC,
}

impl From<lnvps_db::InternetRegistry> for ApiInternetRegistry {
    fn from(registry: lnvps_db::InternetRegistry) -> Self {
        match registry {
            lnvps_db::InternetRegistry::ARIN => ApiInternetRegistry::ARIN,
            lnvps_db::InternetRegistry::RIPE => ApiInternetRegistry::RIPE,
            lnvps_db::InternetRegistry::APNIC => ApiInternetRegistry::APNIC,
            lnvps_db::InternetRegistry::LACNIC => ApiInternetRegistry::LACNIC,
            lnvps_db::InternetRegistry::AFRINIC => ApiInternetRegistry::AFRINIC,
        }
    }
}

#[derive(Serialize)]
pub struct ApiAvailableIpSpace {
    pub id: u64,
    pub min_prefix_size: u16,
    pub max_prefix_size: u16,
    pub registry: ApiInternetRegistry,
    pub ip_version: ApiIpVersion,
    pub pricing: Vec<ApiIpSpacePricing>,
}

impl ApiAvailableIpSpace {
    pub async fn from_ip_space_with_pricing(
        db: &dyn lnvps_db::LNVpsDbBase,
        space: lnvps_db::AvailableIpSpace,
    ) -> Result<Self> {
        let pricing_list = db.list_ip_space_pricing_by_space(space.id).await?;
        let pricing = pricing_list
            .into_iter()
            .map(ApiIpSpacePricing::from)
            .collect();

        // Determine IP version from CIDR
        let network: ipnetwork::IpNetwork = space
            .cidr
            .parse()
            .map_err(|_| anyhow::anyhow!("Failed to parse CIDR"))?;
        let ip_version = if network.is_ipv6() {
            ApiIpVersion::IPv6
        } else {
            ApiIpVersion::IPv4
        };

        Ok(Self {
            id: space.id,
            min_prefix_size: space.min_prefix_size,
            max_prefix_size: space.max_prefix_size,
            registry: ApiInternetRegistry::from(space.registry),
            ip_version,
            pricing,
        })
    }

    /// Expand pricing to include alternative currencies
    pub async fn expand_pricing(&mut self, rates: &Arc<dyn ExchangeRateService>) -> Result<()> {
        let rates = rates.list_rates().await?;

        for pricing in &mut self.pricing {
            let price_amount =
                CurrencyAmount::from_u64(pricing.price.currency.into(), pricing.price.amount);
            let setup_fee_amount = CurrencyAmount::from_u64(
                pricing.setup_fee.currency.into(),
                pricing.setup_fee.amount,
            );

            for alt_price in alt_prices(&rates, price_amount) {
                pricing.other_price.push(ApiPrice {
                    currency: alt_price.currency().into(),
                    amount: alt_price.value(),
                });
            }

            for alt_setup_fee in alt_prices(&rates, setup_fee_amount) {
                pricing.other_setup_fee.push(ApiPrice {
                    currency: alt_setup_fee.currency().into(),
                    amount: alt_setup_fee.value(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct ApiIpSpacePricing {
    pub id: u64,
    pub prefix_size: u16,
    pub price: ApiPrice,
    pub setup_fee: ApiPrice,
    pub other_price: Vec<ApiPrice>,
    pub other_setup_fee: Vec<ApiPrice>,
}

impl From<lnvps_db::IpSpacePricing> for ApiIpSpacePricing {
    fn from(pricing: lnvps_db::IpSpacePricing) -> Self {
        let currency = pricing.currency.parse().unwrap();
        Self {
            id: pricing.id,
            prefix_size: pricing.prefix_size,
            price: CurrencyAmount::from_u64(currency, pricing.price_per_month).into(),
            setup_fee: CurrencyAmount::from_u64(currency, pricing.setup_fee).into(),
            other_price: vec![],     // Filled externally
            other_setup_fee: vec![], // Filled externally
        }
    }
}

#[derive(Serialize)]
pub struct ApiIpRangeSubscription {
    pub id: u64,
    pub cidr: String,
    pub is_active: bool,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub parent_cidr: String, // The IP space this was allocated from
}

impl ApiIpRangeSubscription {
    pub async fn from_subscription_with_space(
        db: &dyn lnvps_db::LNVpsDbBase,
        sub: lnvps_db::IpRangeSubscription,
    ) -> anyhow::Result<Self> {
        let space = db.get_available_ip_space(sub.available_ip_space_id).await?;

        Ok(Self {
            id: sub.id,
            cidr: sub.cidr,
            is_active: sub.is_active,
            started_at: sub.started_at,
            ended_at: sub.ended_at,
            parent_cidr: space.cidr,
        })
    }
}

// ============================================================================
// Subscription Creation Models
// ============================================================================

#[derive(Deserialize)]
pub struct ApiCreateSubscriptionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub currency: Option<String>, // USD, BTC, EUR, etc.
    pub auto_renewal_enabled: Option<bool>,
    pub line_items: Vec<ApiCreateSubscriptionLineItemRequest>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum ApiCreateSubscriptionLineItemRequest {
    #[serde(rename = "ip_range")]
    IpRange { ip_space_pricing_id: u64 },

    #[serde(rename = "asn_sponsoring")]
    AsnSponsoring {
        asn: u32,
        // Add pricing/plan details here
    },

    #[serde(rename = "dns_hosting")]
    DnsHosting {
        domain: String,
        // Add pricing/plan details here
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lnvps_db::{EncryptedString, PaymentMethod, PaymentType, VmPayment};

    fn make_payment(
        currency: &str,
        amount: u64,
        tax: u64,
        processing_fee: u64,
        time_value: u64,
    ) -> VmPayment {
        VmPayment {
            id: vec![0u8; 32],
            vm_id: 1,
            created: Utc::now(),
            expires: Utc::now(),
            amount,
            currency: currency.to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: PaymentType::Renewal,
            external_data: EncryptedString::from("test"),
            external_id: None,
            is_paid: true,
            rate: 1.0,
            time_value,
            tax,
            processing_fee,
            upgrade_params: None,
        }
    }

    #[test]
    fn test_from_payment_data_fiat() {
        // EUR: amounts are in cents, time in seconds (30 days)
        let item = ApiInvoiceItem::from_payment_data(855, 197, 10, "EUR", 30 * 24 * 3600)
            .expect("should succeed");

        assert_eq!(item.amount, 855);
        assert_eq!(item.tax, 197);
        assert_eq!(item.processing_fee, 10);
        assert_eq!(item.currency, "EUR");
        assert_eq!(item.time, 30 * 24 * 3600);
        // CurrencyAmount::to_string for fiat: "{CURRENCY} {value/100:.2}"
        assert_eq!(item.formatted_amount, "EUR 8.55");
        assert_eq!(item.formatted_tax, "EUR 1.97");
        // humantime produces something like "30days" or "720h" for 30*24*3600 seconds
        assert!(!item.formatted_duration.is_empty());
    }

    #[test]
    fn test_from_payment_data_btc() {
        // BTC: amounts in millisats
        let millisats = 1_320_000u64; // 1320 sats = 0.00001320 BTC
        let item = ApiInvoiceItem::from_payment_data(millisats, 0, 0, "BTC", 2_592_000)
            .expect("should succeed");

        assert_eq!(item.amount, millisats);
        assert_eq!(item.tax, 0);
        assert_eq!(item.formatted_amount, "BTC 0.00001320");
        assert_eq!(item.formatted_tax, "BTC 0.00000000");
        assert!(!item.formatted_duration.is_empty());
    }

    #[test]
    fn test_from_payment_data_invalid_currency() {
        let result = ApiInvoiceItem::from_payment_data(100, 0, 0, "NOTACURRENCY", 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_vm_payment() {
        let payment = make_payment("EUR", 500, 115, 6, 86400);
        let item = ApiInvoiceItem::from_vm_payment(&payment).expect("should succeed");

        assert_eq!(item.amount, 500);
        assert_eq!(item.tax, 115);
        assert_eq!(item.processing_fee, 6);
        assert_eq!(item.currency, "EUR");
        assert_eq!(item.time, 86400);
        assert_eq!(item.formatted_amount, "EUR 5.00");
        assert_eq!(item.formatted_tax, "EUR 1.15");
        assert!(!item.formatted_duration.is_empty());
    }
}
