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
            email: if has_email {
                Some(Some(email_str))
            } else {
                None
            },
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<DateTime<Utc>>,
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

    /// Creates a formatted invoice item from a SubscriptionPayment
    pub fn from_subscription_payment(
        payment: &lnvps_db::SubscriptionPayment,
    ) -> Result<Self, anyhow::Error> {
        Self::from_payment_data(
            payment.amount,
            payment.tax,
            payment.processing_fee,
            &payment.currency,
            payment.time_value.unwrap_or(0),
        )
    }
}

impl ApiVmPayment {
    /// Convert a `SubscriptionPayment` to an `ApiVmPayment`.
    /// The `vm_id` must be provided because `SubscriptionPayment` only knows the subscription.
    pub fn from_subscription_payment(
        value: lnvps_db::SubscriptionPayment,
        vm_id: u64,
    ) -> anyhow::Result<Self> {
        let upgrade_params = value
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());
        let is_upgrade = value.payment_type == lnvps_db::SubscriptionPaymentType::Upgrade;
        let data = match &value.payment_method {
            PaymentMethod::Lightning => ApiPaymentData::Lightning(value.external_data.into()),
            PaymentMethod::Revolut => {
                #[derive(Deserialize)]
                struct RevolutData {
                    pub token: String,
                }
                let data: RevolutData = serde_json::from_str(value.external_data.as_str())
                    .map_err(|e| anyhow::anyhow!("Failed to parse Revolut payment data: {}", e))?;
                ApiPaymentData::Revolut { token: data.token }
            }
            PaymentMethod::Paypal => anyhow::bail!("PayPal payments are not supported"),
            PaymentMethod::Stripe => {
                #[derive(Deserialize)]
                struct StripeData {
                    pub session_id: String,
                }
                let data: StripeData = serde_json::from_str(value.external_data.as_str())
                    .map_err(|e| anyhow::anyhow!("Failed to parse Stripe payment data: {}", e))?;
                ApiPaymentData::Stripe {
                    session_id: data.session_id,
                }
            }
        };
        Ok(Self {
            id: hex::encode(&value.id),
            vm_id,
            created: value.created,
            expires: value.expires,
            amount: value.amount,
            tax: value.tax,
            processing_fee: value.processing_fee,
            currency: value.currency,
            is_paid: value.is_paid,
            paid_at: value.paid_at,
            time: value.time_value.unwrap_or(0),
            is_upgrade,
            upgrade_params,
            data,
        })
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
            paid_at: value.paid_at,
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
    LNURL,
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
            cpu_mfg: value
                .cpu_mfg
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            cpu_arch: value
                .cpu_arch
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
            cpu_features: cpu_features.into(),
            ..Default::default()
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
// Firewall Models (#36)
// ============================================================================

/// Direction a firewall rule applies to
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiFirewallDirection {
    Inbound,
    Outbound,
}

impl From<lnvps_db::VmFirewallDirection> for ApiFirewallDirection {
    fn from(v: lnvps_db::VmFirewallDirection) -> Self {
        match v {
            lnvps_db::VmFirewallDirection::Inbound => ApiFirewallDirection::Inbound,
            lnvps_db::VmFirewallDirection::Outbound => ApiFirewallDirection::Outbound,
        }
    }
}

impl From<ApiFirewallDirection> for lnvps_db::VmFirewallDirection {
    fn from(v: ApiFirewallDirection) -> Self {
        match v {
            ApiFirewallDirection::Inbound => lnvps_db::VmFirewallDirection::Inbound,
            ApiFirewallDirection::Outbound => lnvps_db::VmFirewallDirection::Outbound,
        }
    }
}

/// Protocol a firewall rule matches
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiFirewallProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl From<lnvps_db::VmFirewallProtocol> for ApiFirewallProtocol {
    fn from(v: lnvps_db::VmFirewallProtocol) -> Self {
        match v {
            lnvps_db::VmFirewallProtocol::Any => ApiFirewallProtocol::Any,
            lnvps_db::VmFirewallProtocol::Tcp => ApiFirewallProtocol::Tcp,
            lnvps_db::VmFirewallProtocol::Udp => ApiFirewallProtocol::Udp,
            lnvps_db::VmFirewallProtocol::Icmp => ApiFirewallProtocol::Icmp,
        }
    }
}

impl From<ApiFirewallProtocol> for lnvps_db::VmFirewallProtocol {
    fn from(v: ApiFirewallProtocol) -> Self {
        match v {
            ApiFirewallProtocol::Any => lnvps_db::VmFirewallProtocol::Any,
            ApiFirewallProtocol::Tcp => lnvps_db::VmFirewallProtocol::Tcp,
            ApiFirewallProtocol::Udp => lnvps_db::VmFirewallProtocol::Udp,
            ApiFirewallProtocol::Icmp => lnvps_db::VmFirewallProtocol::Icmp,
        }
    }
}

/// Action taken when a firewall rule matches
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiFirewallAction {
    Drop,
    Accept,
    Reject,
}

impl From<lnvps_db::VmFirewallRuleAction> for ApiFirewallAction {
    fn from(v: lnvps_db::VmFirewallRuleAction) -> Self {
        match v {
            lnvps_db::VmFirewallRuleAction::Drop => ApiFirewallAction::Drop,
            lnvps_db::VmFirewallRuleAction::Accept => ApiFirewallAction::Accept,
            lnvps_db::VmFirewallRuleAction::Reject => ApiFirewallAction::Reject,
        }
    }
}

impl From<ApiFirewallAction> for lnvps_db::VmFirewallRuleAction {
    fn from(v: ApiFirewallAction) -> Self {
        match v {
            ApiFirewallAction::Drop => lnvps_db::VmFirewallRuleAction::Drop,
            ApiFirewallAction::Accept => lnvps_db::VmFirewallRuleAction::Accept,
            ApiFirewallAction::Reject => lnvps_db::VmFirewallRuleAction::Reject,
        }
    }
}

/// Default policy applied to a traffic direction when no rule matches
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiFirewallPolicy {
    Accept,
    Drop,
    Reject,
}

impl From<lnvps_db::VmFirewallPolicy> for ApiFirewallPolicy {
    fn from(v: lnvps_db::VmFirewallPolicy) -> Self {
        match v {
            lnvps_db::VmFirewallPolicy::Accept => ApiFirewallPolicy::Accept,
            lnvps_db::VmFirewallPolicy::Drop => ApiFirewallPolicy::Drop,
            lnvps_db::VmFirewallPolicy::Reject => ApiFirewallPolicy::Reject,
        }
    }
}

impl From<ApiFirewallPolicy> for lnvps_db::VmFirewallPolicy {
    fn from(v: ApiFirewallPolicy) -> Self {
        match v {
            ApiFirewallPolicy::Accept => lnvps_db::VmFirewallPolicy::Accept,
            ApiFirewallPolicy::Drop => lnvps_db::VmFirewallPolicy::Drop,
            ApiFirewallPolicy::Reject => lnvps_db::VmFirewallPolicy::Reject,
        }
    }
}

/// Per-VM default firewall policy (None = inherit host default / accept)
#[derive(Serialize, Deserialize)]
pub struct ApiVmFirewallPolicy {
    /// Inbound default policy (None = inherit host default / accept)
    pub policy_in: Option<ApiFirewallPolicy>,
    /// Outbound default policy (None = inherit host default / accept)
    pub policy_out: Option<ApiFirewallPolicy>,
}

/// Request body to update the per-VM default firewall policy.
///
/// Each field is a nullable-option: omit to leave unchanged, `null` to reset to
/// the host default (accept), or a value to set explicitly.
#[derive(Serialize, Deserialize)]
pub struct PatchVmFirewallPolicy {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub policy_in: Option<Option<ApiFirewallPolicy>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub policy_out: Option<Option<ApiFirewallPolicy>>,
}

/// A user-configurable per-VM firewall rule
#[derive(Serialize, Deserialize)]
pub struct ApiVmFirewallRule {
    pub id: u64,
    /// Evaluation order; lower priority is evaluated first
    pub priority: u16,
    pub direction: ApiFirewallDirection,
    pub protocol: ApiFirewallProtocol,
    pub action: ApiFirewallAction,
    /// Optional source CIDR (None = any)
    pub src_cidr: Option<String>,
    /// Optional inclusive destination port range start (None = any)
    pub dst_port_start: Option<u32>,
    /// Optional inclusive destination port range end (None = single port / any)
    pub dst_port_end: Option<u32>,
    pub enabled: bool,
}

impl From<lnvps_db::VmFirewallRule> for ApiVmFirewallRule {
    fn from(r: lnvps_db::VmFirewallRule) -> Self {
        ApiVmFirewallRule {
            id: r.id,
            priority: r.priority,
            direction: r.direction.into(),
            protocol: r.protocol.into(),
            action: r.action.into(),
            src_cidr: r.src_cidr,
            dst_port_start: r.dst_port_start,
            dst_port_end: r.dst_port_end,
            enabled: r.enabled,
        }
    }
}

/// Request body to create a firewall rule
#[derive(Serialize, Deserialize)]
pub struct CreateVmFirewallRule {
    #[serde(default)]
    pub priority: u16,
    pub direction: ApiFirewallDirection,
    pub protocol: ApiFirewallProtocol,
    pub action: ApiFirewallAction,
    pub src_cidr: Option<String>,
    pub dst_port_start: Option<u32>,
    pub dst_port_end: Option<u32>,
    /// Whether the rule is active (defaults to true)
    pub enabled: Option<bool>,
}

/// Request body to update a firewall rule (all fields optional)
#[derive(Serialize, Deserialize)]
pub struct PatchVmFirewallRule {
    pub priority: Option<u16>,
    pub direction: Option<ApiFirewallDirection>,
    pub protocol: Option<ApiFirewallProtocol>,
    pub action: Option<ApiFirewallAction>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub src_cidr: Option<Option<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub dst_port_start: Option<Option<u32>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub dst_port_end: Option<Option<u32>>,
    pub enabled: Option<bool>,
}

/// Validate a source CIDR string, returning a normalised error message on failure.
pub fn validate_firewall_cidr(cidr: &str) -> Result<(), String> {
    use std::str::FromStr;
    ipnetwork::IpNetwork::from_str(cidr)
        .map(|_| ())
        .map_err(|_| format!("Invalid src_cidr: {}", cidr))
}

/// Validate a destination port range. Returns the normalised (start, end) where
/// end defaults to start when only a single port is supplied.
pub fn validate_firewall_ports(
    start: Option<u32>,
    end: Option<u32>,
) -> Result<(Option<u32>, Option<u32>), String> {
    let check = |p: u32| -> Result<(), String> {
        if p == 0 || p > 65535 {
            Err(format!("Port out of range (1-65535): {}", p))
        } else {
            Ok(())
        }
    };
    match (start, end) {
        (None, None) => Ok((None, None)),
        (Some(s), None) => {
            check(s)?;
            Ok((Some(s), None))
        }
        (None, Some(_)) => Err("dst_port_end set without dst_port_start".to_string()),
        (Some(s), Some(e)) => {
            check(s)?;
            check(e)?;
            if s > e {
                return Err("dst_port_start must be <= dst_port_end".to_string());
            }
            Ok((Some(s), Some(e)))
        }
    }
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
        let raw_line_items = db.list_subscription_line_items(subscription.id).await?;
        let mut line_items = Vec::with_capacity(raw_line_items.len());
        for item in raw_line_items {
            line_items.push(
                ApiSubscriptionLineItem::from_line_item(db, item, &subscription.currency).await,
            );
        }

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
    /// Raw upgrade configuration stored on the line item (e.g. `new_cpu` /
    /// `new_memory` / `new_disk`). This is NOT a resource link — see `resource`.
    pub configuration: Option<serde_json::Value>,
    /// Typed reference to the resource this line item bills for, resolved from
    /// the line item's subscription type (`null` when there is no linked resource).
    pub resource: Option<ApiSubscriptionLineItemResource>,
}

impl ApiSubscriptionLineItem {
    pub async fn from_line_item<D: lnvps_db::LNVpsDbBase + ?Sized>(
        db: &D,
        line_item: lnvps_db::SubscriptionLineItem,
        currency: &str,
    ) -> Self {
        let api_currency: ApiCurrency =
            currency.parse::<Currency>().unwrap_or(Currency::USD).into();

        let price = CurrencyAmount::from_u64(api_currency.into(), line_item.amount);
        let setup_fee = CurrencyAmount::from_u64(api_currency.into(), line_item.setup_amount);

        let resource = ApiSubscriptionLineItemResource::resolve(db, &line_item).await;

        Self {
            id: line_item.id,
            subscription_id: line_item.subscription_id,
            name: line_item.name,
            description: line_item.description,
            price: price.into(),
            setup_fee: setup_fee.into(),
            configuration: line_item.configuration,
            resource,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<DateTime<Utc>>,
    pub tax: ApiPrice,
    pub processing_fee: ApiPrice,
}

#[derive(Serialize, Deserialize)]
pub enum ApiSubscriptionPaymentType {
    Purchase,
    Renewal,
    Upgrade,
}

impl From<lnvps_db::SubscriptionPaymentType> for ApiSubscriptionPaymentType {
    fn from(payment_type: lnvps_db::SubscriptionPaymentType) -> Self {
        match payment_type {
            lnvps_db::SubscriptionPaymentType::Purchase => ApiSubscriptionPaymentType::Purchase,
            lnvps_db::SubscriptionPaymentType::Renewal => ApiSubscriptionPaymentType::Renewal,
            lnvps_db::SubscriptionPaymentType::Upgrade => ApiSubscriptionPaymentType::Upgrade,
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
            paid_at: payment.paid_at,
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
            paid_at: Some(Utc::now()),
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

    #[test]
    fn test_validate_firewall_cidr() {
        assert!(validate_firewall_cidr("1.2.3.0/24").is_ok());
        assert!(validate_firewall_cidr("2001:db8::/32").is_ok());
        assert!(validate_firewall_cidr("10.0.0.1").is_ok());
        assert!(validate_firewall_cidr("not-a-cidr").is_err());
        assert!(validate_firewall_cidr("1.2.3.4/99").is_err());
    }

    #[test]
    fn test_validate_firewall_ports() {
        assert_eq!(validate_firewall_ports(None, None), Ok((None, None)));
        assert_eq!(
            validate_firewall_ports(Some(80), None),
            Ok((Some(80), None))
        );
        assert_eq!(
            validate_firewall_ports(Some(80), Some(443)),
            Ok((Some(80), Some(443)))
        );
        // end without start
        assert!(validate_firewall_ports(None, Some(80)).is_err());
        // start > end
        assert!(validate_firewall_ports(Some(443), Some(80)).is_err());
        // out of range
        assert!(validate_firewall_ports(Some(0), None).is_err());
        assert!(validate_firewall_ports(Some(70000), None).is_err());
        assert!(validate_firewall_ports(Some(1), Some(70000)).is_err());
    }

    #[test]
    fn test_firewall_enum_roundtrip() {
        use lnvps_db::{VmFirewallDirection, VmFirewallProtocol, VmFirewallRuleAction};

        for d in [VmFirewallDirection::Inbound, VmFirewallDirection::Outbound] {
            let api: ApiFirewallDirection = d.into();
            let back: VmFirewallDirection = api.into();
            assert_eq!(d, back);
        }
        for p in [
            VmFirewallProtocol::Any,
            VmFirewallProtocol::Tcp,
            VmFirewallProtocol::Udp,
            VmFirewallProtocol::Icmp,
        ] {
            let api: ApiFirewallProtocol = p.into();
            let back: VmFirewallProtocol = api.into();
            assert_eq!(p, back);
        }
        for a in [
            VmFirewallRuleAction::Drop,
            VmFirewallRuleAction::Accept,
            VmFirewallRuleAction::Reject,
        ] {
            let api: ApiFirewallAction = a.into();
            let back: VmFirewallRuleAction = api.into();
            assert_eq!(a, back);
        }
    }

    #[test]
    fn test_firewall_policy_enum_roundtrip() {
        use lnvps_db::VmFirewallPolicy;

        for p in [
            VmFirewallPolicy::Accept,
            VmFirewallPolicy::Drop,
            VmFirewallPolicy::Reject,
        ] {
            let api: ApiFirewallPolicy = p.into();
            let back: VmFirewallPolicy = api.into();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn test_api_firewall_rule_from_db() {
        let rule = lnvps_db::VmFirewallRule {
            id: 7,
            vm_id: 3,
            priority: 5,
            direction: lnvps_db::VmFirewallDirection::Inbound,
            protocol: lnvps_db::VmFirewallProtocol::Tcp,
            action: lnvps_db::VmFirewallRuleAction::Accept,
            src_cidr: Some("1.2.3.0/24".to_string()),
            dst_port_start: Some(22),
            dst_port_end: None,
            enabled: true,
            created: Utc::now(),
            updated: Utc::now(),
        };
        let api = ApiVmFirewallRule::from(rule);
        assert_eq!(api.id, 7);
        assert_eq!(api.priority, 5);
        assert_eq!(api.direction, ApiFirewallDirection::Inbound);
        assert_eq!(api.protocol, ApiFirewallProtocol::Tcp);
        assert_eq!(api.action, ApiFirewallAction::Accept);
        assert_eq!(api.src_cidr.as_deref(), Some("1.2.3.0/24"));
        assert_eq!(api.dst_port_start, Some(22));
        assert!(api.enabled);
    }
}
