mod demand;
mod mock;
mod ovh;
mod service;

pub use demand::*;
pub use mock::*;
pub use ovh::*;
pub use service::*;

use crate::retry::OpResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpOrderSpec {
    pub country: Option<String>,
    pub destination: Option<String>,
    pub prefix_len: u16,
    pub quantity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpQuote {
    pub cost: u64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacedOrder {
    pub provider_order_id: String,
    pub cost: u64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderOrderStatus {
    Pending,
    Delivered(Vec<OwnedIp>),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedIp {
    pub cidr: String,
    pub country: Option<String>,
    pub routed_to: Option<String>,
}

#[async_trait]
pub trait IpProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn quote(&self, spec: &IpOrderSpec) -> OpResult<IpQuote>;
    async fn order(&self, spec: &IpOrderSpec, max_cost: u64) -> OpResult<PlacedOrder>;
    async fn order_status(&self, provider_order_id: &str) -> OpResult<ProviderOrderStatus>;
    async fn list_owned(&self) -> OpResult<Vec<OwnedIp>>;
    async fn release(&self, cidr: &str) -> OpResult<()>;
}

#[cfg(test)]
mod on_demand_tests;
