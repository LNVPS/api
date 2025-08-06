// Re-export common API models
pub use lnvps_api_common::*;

use crate::exchange::{alt_prices, ExchangeRateService};
use anyhow::Result;
use chrono::{DateTime, Utc};
use lnvps_api_common::{ApiDiskInterface, ApiDiskType, Currency};
use lnvps_db::{PaymentMethod, VmCustomTemplate};
use nostr::util::hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomVmOrder {
    #[serde(flatten)]
    pub spec: ApiCustomVmRequest,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct ApiTemplatesResponse {
    pub templates: Vec<ApiVmTemplate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_template: Option<Vec<ApiCustomTemplateParams>>,
}

impl ApiTemplatesResponse {
    pub async fn expand_pricing(&mut self, rates: &Arc<dyn ExchangeRateService>) -> Result<()> {
        let rates = rates.list_rates().await?;

        for template in &mut self.templates {
            let list_price =
                CurrencyAmount::from_f32(template.cost_plan.currency, template.cost_plan.amount);
            for alt_price in alt_prices(&rates, list_price) {
                template.cost_plan.other_price.push(ApiPrice {
                    currency: alt_price.currency(),
                    amount: alt_price.value_f32(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Serialize, JsonSchema)]
pub struct ApiCustomTemplateParams {
    pub id: u64,
    pub name: String,
    pub region: ApiVmHostRegion,
    pub max_cpu: u16,
    pub min_cpu: u16,
    pub min_memory: u64,
    pub max_memory: u64,
    pub disks: Vec<ApiCustomTemplateDiskParam>,
}

impl ApiCustomTemplateParams {
    pub fn from(
        pricing: &lnvps_db::VmCustomPricing,
        disks: &Vec<lnvps_db::VmCustomPricingDisk>,
        region: &lnvps_db::VmHostRegion,
        max_cpu: u16,
        max_memory: u64,
        max_disk: &HashMap<(ApiDiskType, ApiDiskInterface), u64>,
    ) -> Result<Self> {
        use crate::GB;
        Ok(ApiCustomTemplateParams {
            id: pricing.id,
            name: pricing.name.clone(),
            region: ApiVmHostRegion {
                id: region.id,
                name: region.name.clone(),
            },
            max_cpu,
            min_cpu: 1,
            min_memory: GB,
            max_memory,
            disks: disks
                .iter()
                .filter(|d| d.pricing_id == pricing.id)
                .filter_map(|d| {
                    Some(ApiCustomTemplateDiskParam {
                        min_disk: GB * 5,
                        max_disk: *max_disk.get(&(d.kind.into(), d.interface.into()))?,
                        disk_type: d.kind.into(),
                        disk_interface: d.interface.into(),
                    })
                })
                .collect(),
        })
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiCustomTemplateDiskParam {
    pub min_disk: u64,
    pub max_disk: u64,
    pub disk_type: ApiDiskType,
    pub disk_interface: ApiDiskInterface,
}

// Models that are only used in lnvps_api (moved from common)

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct VMPatchRequest {
    /// SSH key assigned to vm
    pub ssh_key_id: Option<u64>,
    /// Reverse DNS PTR domain
    pub reverse_dns: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccountPatchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub contact_nip17: bool,
    pub contact_email: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
}

impl From<lnvps_db::User> for AccountPatchRequest {
    fn from(user: lnvps_db::User) -> Self {
        AccountPatchRequest {
            email: user.email,
            contact_nip17: user.contact_nip17,
            contact_email: user.contact_email,
            country_code: user.country_code,
            name: user.billing_name,
            address_1: user.billing_address_1,
            address_2: user.billing_address_2,
            state: user.billing_state,
            city: user.billing_city,
            postcode: user.billing_postcode,
            tax_id: user.billing_tax_id,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateVmRequest {
    pub template_id: u64,
    pub image_id: u64,
    pub ssh_key_id: u64,
    pub ref_code: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct CreateSshKey {
    pub name: String,
    pub key_data: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
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
            data: match &value.payment_method {
                PaymentMethod::Lightning => ApiPaymentData::Lightning(value.external_data),
                PaymentMethod::Revolut => {
                    #[derive(Deserialize)]
                    struct RevolutData {
                        pub token: String,
                    }
                    let data: RevolutData = serde_json::from_str(&value.external_data).unwrap();
                    ApiPaymentData::Revolut { token: data.token }
                }
                PaymentMethod::Paypal => {
                    todo!()
                }
            },
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ApiPaymentInfo {
    pub name: ApiPaymentMethod,

    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,

    pub currencies: Vec<Currency>,
}

/// Payment data related to the payment method
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiPaymentData {
    /// Just an LN invoice
    Lightning(String),
    /// Revolut order data
    Revolut {
        /// Order token
        token: String,
    },
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiPaymentMethod {
    #[default]
    Lightning,
    Revolut,
    Paypal,
}

impl From<PaymentMethod> for ApiPaymentMethod {
    fn from(value: PaymentMethod) -> Self {
        match value {
            PaymentMethod::Lightning => ApiPaymentMethod::Lightning,
            PaymentMethod::Revolut => ApiPaymentMethod::Revolut,
            PaymentMethod::Paypal => ApiPaymentMethod::Paypal,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
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

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiVmHistoryInitiator {
    /// Action initiated by the VM owner
    Owner,
    /// Action initiated by the system
    System,
    /// Action initiated by another user
    Other,
}

#[derive(Serialize, JsonSchema)]
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
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
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