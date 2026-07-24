mod apps;
mod contact;
mod docs;
mod ip_space;
mod legal;
mod model;
#[cfg(feature = "nostr-domain")]
mod nostr_domain;
mod oauth;
mod referral;
mod routes;
mod subscriptions;
mod webauthn;
mod webhook;

use crate::settings::Settings;
use crate::subscription::SubscriptionHandler;
pub use apps::router as apps_router;
pub use contact::router as contacts_router;
pub use docs::router as docs_router;
pub use ip_space::router as ip_space_router;
pub use legal::router as legal_router;
use lnvps_api_common::{
    CountryResolver, ExchangeRateService, VmHistoryLogger, VmStateCache, WorkCommander,
    WorkFeedback,
};
use lnvps_db::LNVpsDb;
#[cfg(feature = "nostr-domain")]
pub use nostr_domain::router as nostr_domain_router;
pub use oauth::router as oauth_router;
pub use referral::router as referral_router;
pub use routes::routes as main_router;
use serde::Deserialize;
use std::sync::Arc;
pub use subscriptions::router as subscriptions_router;
pub use webauthn::router as webauthn_router;
pub use webhook::router as webhook_router;

#[derive(Deserialize)]
pub(crate) struct PaymentMethodQuery {
    pub method: Option<String>,
    /// Number of intervals to renew for (e.g., 2 means renew for 2x the normal period)
    pub intervals: Option<u32>,
    /// For interactive card payments: save the entered card as a reusable
    /// payment method for future use (independent of auto-renewal).
    pub save_card: Option<bool>,
    /// For `method=saved` off-session charges: the specific saved payment
    /// method id to charge. Omitted selects the user's default saved card.
    pub payment_method_id: Option<u64>,
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
    pub sub_handler: SubscriptionHandler,
    pub history: VmHistoryLogger,
    pub settings: Settings,
    pub rates: Arc<dyn ExchangeRateService>,
    pub work_sender: Arc<dyn WorkCommander>,
    /// Job feedback pub/sub used to wait for worker-driven operations (e.g. VM
    /// reinstall). `None` when no feedback service is configured (dev/tests
    /// without Redis), in which case such operations run inline instead.
    pub feedback: Option<Arc<dyn WorkFeedback>>,
    /// Resolves client IPs to a country for VAT place-of-supply evidence.
    /// `None` when no geolocation database is configured.
    pub geoip: Option<Arc<dyn CountryResolver>>,
}

/// Resolve a payment-method query into a concrete `(PaymentMethod, RenewMode)`.
///
/// `method=nwc` collects the user's saved NWC (Lightning) wallet; `method=saved`
/// charges a saved Revolut card off-session (optionally a specific
/// `payment_method_id`); anything else is an interactive payment in the requested
/// method (default Lightning). Shared by the VM renew, VM upgrade and generic
/// subscription renew endpoints so every payment type is collected identically.
pub(crate) async fn resolve_payment_mode(
    this: &RouterState,
    uid: u64,
    q: &PaymentMethodQuery,
) -> Result<(lnvps_db::PaymentMethod, crate::subscription::RenewMode), lnvps_api_common::ApiError> {
    use crate::subscription::RenewMode;
    use lnvps_db::PaymentMethod;
    use std::str::FromStr;

    match q.method.as_deref() {
        Some("nwc") => {
            let has_nwc = this
                .db
                .list_user_payment_methods(uid, Some("nwc"))
                .await
                .map(|m| m.iter().any(|pm| pm.enabled))
                .unwrap_or(false);
            if !has_nwc {
                return Err(lnvps_api_common::ApiError::from(anyhow::anyhow!(
                    "No NWC payment method configured"
                )));
            }
            Ok((
                PaymentMethod::Lightning,
                RenewMode::Saved { method_id: None },
            ))
        }
        Some("saved") => Ok((
            PaymentMethod::Revolut,
            RenewMode::Saved {
                method_id: q.payment_method_id,
            },
        )),
        other => Ok((
            other
                .and_then(|m| PaymentMethod::from_str(m).ok())
                .unwrap_or(PaymentMethod::Lightning),
            RenewMode::Interactive {
                save_card: q.save_card.unwrap_or(false),
            },
        )),
    }
}
