/// Fiat payment integrations
use crate::exchange::CurrencyAmount;
use anyhow::Result;
use rocket::serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

#[cfg(feature = "revolut")]
mod revolut;
#[cfg(feature = "revolut")]
pub use revolut::*;

pub trait FiatPaymentService: Send + Sync {
    fn create_order(
        &self,
        description: &str,
        amount: CurrencyAmount,
    ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiatPaymentInfo {
    pub external_id: String,
    pub raw_data: String,
}
