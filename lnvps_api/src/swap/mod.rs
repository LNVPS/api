use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod fixedfloat;

pub use fixedfloat::FixedFloat;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrderRequest {
    pub coin: String,
    pub receive_sats: u64,
    pub receive_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapOrder {
    pub data: SwapData,
    pub expires: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapData {
    pub coin: String,
    pub order_id: String,
    pub order_token: String,
    pub deposit_address: String,
    pub deposit_amount: String,
    pub receive_address: String,
}

impl SwapData {
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(serde_json::from_str(raw)?)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[async_trait]
pub trait SwapProvider: Send + Sync {
    async fn create_order(&self, req: SwapOrderRequest) -> Result<SwapOrder>;
}
