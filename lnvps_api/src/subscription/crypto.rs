use lnvps_api_common::GatewayCryptoRequest;

pub(super) const ONCHAIN_EXPIRE_SECS: u32 = 3600;
pub(super) const SWAP_EXPIRE_SECS: u32 = 1800;

pub struct OnChainAddress {
    pub address: String,
    pub external_id: Option<String>,
}

pub(super) struct CryptoContext {
    pub(super) company_id: u64,
    payment_id: Vec<u8>,
    user_id: u64,
    tax_msat: u64,
    metadata: serde_json::Value,
}

impl CryptoContext {
    pub(super) fn payment(
        company_id: u64,
        payment_id: [u8; 32],
        user_id: u64,
        subscription_id: u64,
        payment_type: lnvps_db::SubscriptionPaymentType,
        tax_msat: u64,
    ) -> Self {
        Self {
            company_id,
            payment_id: payment_id.to_vec(),
            user_id,
            tax_msat,
            metadata: serde_json::json!({
                "subscription_id": subscription_id,
                "payment_type": format!("{payment_type:?}"),
            }),
        }
    }

    pub(super) fn topup(company_id: u64, user_id: u64, reference: [u8; 32]) -> Self {
        Self {
            company_id,
            payment_id: reference.to_vec(),
            user_id,
            tax_msat: 0,
            metadata: serde_json::json!({ "payment_type": "credit_topup" }),
        }
    }

    pub(super) fn request(
        &self,
        amount_msat: u64,
        description: String,
        expires_in_secs: u32,
        coin: Option<String>,
    ) -> GatewayCryptoRequest {
        GatewayCryptoRequest {
            payment_id: self.payment_id.clone(),
            amount_msat,
            tax_msat: self.tax_msat,
            description,
            expires_in_secs,
            customer_ref: self.user_id.to_string(),
            metadata: self.metadata.clone(),
            coin,
        }
    }
}
