mod contact;
mod ip_space;
mod model;
#[cfg(feature = "nostr-domain")]
mod nostr_domain;
mod routes;
mod subscriptions;
mod webhook;

#[derive(Deserialize)]
pub(crate) struct PaymentMethodQuery {
    pub method: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AmountQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    pub amount: u64,
}

#[derive(Deserialize)]
pub(crate) struct AuthQuery {
    pub auth: String,
}

#[derive(Clone)]
pub struct RouterState {
    pub db: Arc<dyn LNVpsDb>,
    pub state: VmStateCache,
    pub provisioner: Arc<LNVpsProvisioner>,
    pub history: Arc<VmHistoryLogger>,
    pub settings: Settings,
    pub rates: Arc<dyn ExchangeRateService>,
    pub work_sender: Arc<dyn WorkCommander>,
}

use crate::provisioner::LNVpsProvisioner;
use crate::settings::Settings;
pub use contact::router as contacts_router;
pub use ip_space::router as ip_space_router;
use lnvps_api_common::{ExchangeRateService, VmHistoryLogger, VmStateCache, WorkCommander};
use lnvps_db::LNVpsDb;
#[cfg(feature = "nostr-domain")]
pub use nostr_domain::router as nostr_domain_router;
pub use routes::routes as main_router;
use serde::Deserialize;
use std::sync::Arc;
pub use subscriptions::router as subscriptions_router;
pub use webhook::router as webhook_router;
