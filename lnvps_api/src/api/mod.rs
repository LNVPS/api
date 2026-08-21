mod apps;
mod contact;
mod docs;
mod ip_space;
mod legal;
// Public so the e2e harness can carry a node's document across the wire format
// both ends actually use: serialising this type and parsing the node's is the
// only thing that proves the two agree.
pub mod marketplace;
mod model;
#[cfg(feature = "nostr-domain")]
mod nostr_domain;
mod oauth;
mod referral;
mod routes;
mod subscriptions;
#[cfg(feature = "agent")]
mod support;
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
pub use marketplace::router as marketplace_router;
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
    /// Number of intervals to renew for (e.g., 2 means renew for 2x the normal
    /// period). Bounded by [`lnvps_api_common::MAX_RENEWAL_INTERVALS`]; use
    /// [`PaymentMethodQuery::validated_intervals`] rather than reading this
    /// directly.
    pub intervals: Option<u32>,
    /// For interactive card payments: save the entered card as a reusable
    /// payment method for future use (independent of auto-renewal).
    pub save_card: Option<bool>,
    /// For `method=saved` off-session charges: the specific saved payment
    /// method id to charge. Omitted selects the user's default saved card.
    pub payment_method_id: Option<u64>,
    /// Discount code to apply to this order. A code that cannot be used fails
    /// the request rather than quietly charging full price.
    pub code: Option<String>,
}

impl PaymentMethodQuery {
    /// The requested interval count, defaulting to 1 and rejecting anything
    /// outside `1..=MAX_RENEWAL_INTERVALS`.
    ///
    /// An unbounded value used to overflow the projected-expiry arithmetic in
    /// the pricing engine and panic, which under the release profile's
    /// `panic = "abort"` killed the whole process (F-02). Rejecting rather than
    /// clamping means a caller is never charged for a period they did not ask
    /// for.
    pub fn validated_intervals(&self) -> Result<u32, lnvps_api_common::ApiError> {
        let requested = self.intervals.unwrap_or(1);
        lnvps_api_common::validate_intervals(requested).ok_or_else(|| {
            lnvps_api_common::ApiError::new(format!(
                "intervals must be between 1 and {}",
                lnvps_api_common::MAX_RENEWAL_INTERVALS
            ))
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct AmountQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    pub amount: u64,
}

/// Credential carried in the query string by endpoints a browser cannot send an
/// `Authorization` header to (WebSocket handshakes, HTML navigations).
///
/// Prefer `ticket`: a single-use, path-scoped, 30-second credential obtained
/// from `POST /api/v1/auth/ticket`. `auth` (a raw base64 NIP-98 event) is the
/// legacy form, kept so existing clients keep working during the migration; it
/// is single-use and 60-second bounded too, but it is a signature made by the
/// user's identity key and so is a worse thing to leave in a log line.
#[derive(Deserialize, Default)]
pub(crate) struct AuthQuery {
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub ticket: Option<String>,
}

impl AuthQuery {
    /// Resolve the caller's 32-byte identity for `path`.
    ///
    /// Tries the ticket first, then falls back to a NIP-98 event bound to the
    /// same path and `GET`.
    pub fn resolve(&self, path: &str) -> Result<[u8; 32], &'static str> {
        if let Some(ticket) = &self.ticket {
            return lnvps_api_common::consume_ticket(ticket, path)
                .map_err(|_| "Invalid or expired ticket");
        }

        let auth = self.auth.as_deref().ok_or("Missing auth or ticket param")?;
        let auth = lnvps_api_common::Nip98Auth::from_base64(auth)
            .map_err(|_| "Missing or invalid auth param")?;
        auth.check(path, "GET").map_err(|_| "Invalid auth event")?;
        Ok(auth.pubkey())
    }
}

/// Request body for minting a websocket/HTML auth ticket.
#[derive(Deserialize)]
pub(crate) struct TicketRequest {
    /// Exact path the ticket should be valid for, e.g. `/api/v1/vm/7/console`.
    pub path: String,
}

/// Response carrying a freshly minted ticket.
#[derive(serde::Serialize)]
pub(crate) struct TicketResponse {
    /// Pass as `?ticket=` on the target endpoint.
    pub ticket: String,
    /// Seconds until it expires.
    pub expires_in: u64,
}

#[derive(Clone, axum::extract::FromRef)]
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
/// The discount line to show on a payment, if it carries one.
///
/// Read back from the recorded redemption rather than from the request, so a
/// reused pending invoice still reports the discount it was actually created
/// with. Failure to look it up hides the line rather than failing the payment.
pub(crate) async fn discount_line(
    db: &std::sync::Arc<dyn lnvps_db::LNVpsDb>,
    payment_id: &Vec<u8>,
) -> Option<crate::api::model::ApiDiscount> {
    let redemption = db
        .get_discount_redemption_by_payment(payment_id)
        .await
        .ok()
        .flatten()?;
    let code = db
        .get_discount(redemption.discount_id)
        .await
        .ok()
        .and_then(|d| d.code);
    Some(crate::api::model::ApiDiscount {
        code,
        amount_off: redemption.amount_off,
    })
}

/// Resolve a payment-method query for *pricing only*.
///
/// Same mapping as [`resolve_payment_mode`] — `nwc` prices as Lightning, `saved`
/// as Revolut — but it collects nothing and so does not require the saved method
/// to exist. A client pricing a saved card must not have to map it back to
/// `revolut` itself, and must not risk charging the customer while doing so.
pub(crate) fn resolve_quote_method(q: &PaymentMethodQuery) -> lnvps_db::PaymentMethod {
    use lnvps_db::PaymentMethod;
    use std::str::FromStr;

    match q.method.as_deref() {
        Some("nwc") => PaymentMethod::Lightning,
        Some("saved") => PaymentMethod::Revolut,
        other => other
            .and_then(|m| PaymentMethod::from_str(m).ok())
            .unwrap_or(PaymentMethod::Lightning),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::{
        DEFAULT_TICKET_TTL_SECS, MAX_RENEWAL_INTERVALS, init_session_secret, issue_ticket,
    };

    fn query(method: Option<&str>, intervals: Option<u32>) -> PaymentMethodQuery {
        PaymentMethodQuery {
            method: method.map(|s| s.to_string()),
            intervals,
            save_card: None,
            payment_method_id: None,
            code: None,
        }
    }

    /// Regression (F-02): `intervals` reached the pricing engine unbounded and
    /// overflowed the expiry arithmetic into a process-killing panic. The API
    /// boundary must reject out-of-range values rather than clamp them, so a
    /// caller is never charged for a period they did not request.
    #[test]
    fn validated_intervals_bounds_the_request() {
        // Absent defaults to a single interval.
        assert_eq!(query(None, None).validated_intervals().unwrap(), 1);
        assert_eq!(query(None, Some(12)).validated_intervals().unwrap(), 12);
        assert_eq!(
            query(None, Some(MAX_RENEWAL_INTERVALS))
                .validated_intervals()
                .unwrap(),
            MAX_RENEWAL_INTERVALS
        );

        // The values that used to reach the panicking arithmetic.
        for bad in [0, MAX_RENEWAL_INTERVALS + 1, 1_000_000_000, u32::MAX] {
            let err = query(None, Some(bad))
                .validated_intervals()
                .expect_err("out-of-range intervals must be refused");
            assert!(
                err.error.contains("intervals must be between"),
                "{}",
                err.error
            );
        }
    }

    /// A ticket resolves to the identity it was minted for, and only on the
    /// path it was minted for.
    #[test]
    fn auth_query_resolves_a_ticket() {
        init_session_secret(b"unit-test-secret".to_vec());
        let pubkey = [11u8; 32];
        let path = "/api/v1/vm/3/console";

        let q = AuthQuery {
            auth: None,
            ticket: Some(issue_ticket(&pubkey, path, DEFAULT_TICKET_TTL_SECS).unwrap()),
        };
        assert_eq!(q.resolve(path).unwrap(), pubkey);

        // A ticket for one VM must not open another's console.
        let q = AuthQuery {
            auth: None,
            ticket: Some(issue_ticket(&pubkey, path, DEFAULT_TICKET_TTL_SECS).unwrap()),
        };
        assert!(q.resolve("/api/v1/vm/4/console").is_err());
    }

    /// Tickets are single use: a copy captured from a log or browser history is
    /// inert once the real client has connected.
    #[test]
    fn auth_query_ticket_is_single_use() {
        init_session_secret(b"unit-test-secret".to_vec());
        let path = "/api/v1/vm/5/console";
        let ticket = issue_ticket(&[12u8; 32], path, DEFAULT_TICKET_TTL_SECS).unwrap();

        let first = AuthQuery {
            auth: None,
            ticket: Some(ticket.clone()),
        };
        assert!(first.resolve(path).is_ok());

        let replay = AuthQuery {
            auth: None,
            ticket: Some(ticket),
        };
        assert!(replay.resolve(path).is_err(), "a used ticket must be dead");
    }

    /// Supplying neither credential is refused rather than treated as anonymous.
    #[test]
    fn auth_query_requires_a_credential() {
        let q = AuthQuery {
            auth: None,
            ticket: None,
        };
        assert!(q.resolve("/api/v1/vm/1/console").is_err());
    }

    /// A garbage legacy `auth` value is refused. (The happy path for NIP-98 is
    /// covered in `lnvps_api_common::nip98`, which owns the verification.)
    #[test]
    fn auth_query_rejects_invalid_legacy_auth() {
        let q = AuthQuery {
            auth: Some("not-base64-at-all!!".to_string()),
            ticket: None,
        };
        assert!(q.resolve("/api/v1/vm/1/console").is_err());
    }

    /// `ticket` wins when both are present, so a caller cannot downgrade to the
    /// weaker legacy path by also sending `auth`.
    #[test]
    fn auth_query_prefers_the_ticket() {
        init_session_secret(b"unit-test-secret".to_vec());
        let pubkey = [13u8; 32];
        let path = "/api/v1/vm/6/console";

        let q = AuthQuery {
            auth: Some("garbage".to_string()),
            ticket: Some(issue_ticket(&pubkey, path, DEFAULT_TICKET_TTL_SECS).unwrap()),
        };
        assert_eq!(q.resolve(path).unwrap(), pubkey);
    }

    /// Pricing must accept the off-session method names, so a client can price a
    /// saved card or NWC wallet without mapping it back to an interactive method
    /// (and without risking a charge while doing so).
    #[test]
    fn resolve_quote_method_prices_off_session_methods() {
        use lnvps_db::PaymentMethod;

        assert_eq!(
            resolve_quote_method(&query(Some("saved"), None)),
            PaymentMethod::Revolut
        );
        assert_eq!(
            resolve_quote_method(&query(Some("nwc"), None)),
            PaymentMethod::Lightning
        );
        assert_eq!(
            resolve_quote_method(&query(Some("revolut"), None)),
            PaymentMethod::Revolut
        );
        // Unknown or absent falls back to Lightning, as the renew path does.
        assert_eq!(
            resolve_quote_method(&query(Some("nonsense"), None)),
            PaymentMethod::Lightning
        );
        assert_eq!(
            resolve_quote_method(&query(None, None)),
            PaymentMethod::Lightning
        );
    }

    /// The wire shape mirrors the payment: amounts already net of the discount,
    /// with the discount reported as a line to show rather than to re-apply.
    #[test]
    fn renewal_quote_serializes_as_the_payment_does() {
        use crate::api::model::ApiRenewalQuote;
        use payments_rs::currency::Currency;

        let quote = crate::subscription::RenewalQuote {
            amount: 900,
            tax: 207,
            processing_fee: 25,
            currency: Currency::EUR,
            time_value: 2_592_000,
            rate: 1.0,
            payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
            tax_lines: vec![],
            discount: Some(lnvps_api_common::AppliedDiscount {
                discount_id: 1,
                code: Some("SAVE10".to_string()),
                amount_off: 100,
                currency: Currency::EUR,
            }),
        };
        let out: ApiRenewalQuote = quote.into();
        assert_eq!(out.amount, 900);
        assert_eq!(out.tax, 207);
        assert_eq!(out.processing_fee, 25);
        assert_eq!(out.currency, "EUR");
        assert_eq!(out.time, 2_592_000);
        let d = out.discount.expect("discount line");
        assert_eq!((d.code.as_deref(), d.amount_off), (Some("SAVE10"), 100));

        // No code, no line at all — an absent field, not a zero saving.
        let plain = crate::subscription::RenewalQuote {
            discount: None,
            ..quote_without_discount()
        };
        let out: ApiRenewalQuote = plain.into();
        assert!(out.discount.is_none());
        assert!(!serde_json::to_string(&out).unwrap().contains("discount"));
    }

    fn quote_without_discount() -> crate::subscription::RenewalQuote {
        crate::subscription::RenewalQuote {
            amount: 1_000,
            tax: 0,
            processing_fee: 0,
            currency: payments_rs::currency::Currency::EUR,
            time_value: 0,
            rate: 1.0,
            payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
            tax_lines: vec![],
            discount: None,
        }
    }
}
