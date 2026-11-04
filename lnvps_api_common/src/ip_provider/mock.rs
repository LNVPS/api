use crate::ip_provider::{
    IpOrderSpec, IpProvider, IpQuote, OwnedIp, PlacedOrder, ProviderOrderStatus,
};
use crate::retry::{OpError, OpResult};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MockIpProvider {
    name: String,
    pub unit_cost: u64,
    pub currency: String,
    pub order_calls: Arc<AtomicU32>,
    pub release_calls: Arc<Mutex<Vec<String>>>,
    pub status: Arc<Mutex<ProviderOrderStatus>>,
    pub owned: Arc<Mutex<Vec<OwnedIp>>>,
    pub fail_order: Arc<Mutex<Option<String>>>,
}

impl MockIpProvider {
    pub fn new(name: &str, unit_cost: u64) -> Self {
        Self {
            name: name.to_string(),
            unit_cost,
            currency: "EUR".to_string(),
            order_calls: Arc::new(AtomicU32::new(0)),
            release_calls: Arc::new(Mutex::new(vec![])),
            status: Arc::new(Mutex::new(ProviderOrderStatus::Pending)),
            owned: Arc::new(Mutex::new(vec![])),
            fail_order: Arc::new(Mutex::new(None)),
        }
    }

    pub fn orders_placed(&self) -> u32 {
        self.order_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl IpProvider for MockIpProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn quote(&self, spec: &IpOrderSpec) -> OpResult<IpQuote> {
        Ok(IpQuote {
            cost: self.unit_cost * spec.quantity as u64,
            currency: self.currency.clone(),
        })
    }

    async fn order(&self, spec: &IpOrderSpec, max_cost: u64) -> OpResult<PlacedOrder> {
        let cost = self.unit_cost * spec.quantity as u64;
        if cost > max_cost {
            return Err(OpError::Fatal(anyhow::anyhow!(
                "cost {cost} exceeds the allowed maximum {max_cost}"
            )));
        }
        let n = self.order_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(e) = self.fail_order.lock().await.clone() {
            return Err(OpError::Fatal(anyhow::anyhow!(e)));
        }
        Ok(PlacedOrder {
            provider_order_id: format!("mock-{n}"),
            cost,
            currency: self.currency.clone(),
        })
    }

    async fn order_status(&self, _provider_order_id: &str) -> OpResult<ProviderOrderStatus> {
        Ok(self.status.lock().await.clone())
    }

    async fn list_owned(&self) -> OpResult<Vec<OwnedIp>> {
        Ok(self.owned.lock().await.clone())
    }

    async fn release(&self, cidr: &str) -> OpResult<()> {
        self.release_calls.lock().await.push(cidr.to_string());
        Ok(())
    }
}
