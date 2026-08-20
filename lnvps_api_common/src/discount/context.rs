//! The read-only context exposed to a discount rule.
//!
//! This is the security boundary of the discount engine: a rule can only see
//! the fields defined here. Database rows are **never** serialized into the
//! context wholesale — every field is added deliberately, so a schema change
//! can never widen what rule authors (or a leaked admin account) can read.
//!
//! All money is expressed in **minor units** as `i64` (cents, sats), matching
//! `docs/agents/currency.md`. No `f64` appears anywhere in this module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::OrderLineItem;

/// Everything a discount rule may read about the order being priced.
///
/// Serialized into the CEL evaluation context as the top-level variables
/// `order`, `user`, `history` and `now`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscountContext {
    /// The order currently being priced.
    pub order: OrderContext,
    /// The customer placing the order.
    pub user: UserContext,
    /// Aggregate facts about the customer's past orders.
    pub history: HistoryContext,
    /// Evaluation time as a unix timestamp in seconds.
    ///
    /// Exposed as an integer rather than a CEL timestamp so rules stay
    /// comparable with plain arithmetic and do not depend on the optional
    /// `chrono` feature of the CEL crate.
    pub now: i64,
}

impl DiscountContext {
    /// Build a context, taking the evaluation time from `now`.
    pub fn new(
        order: OrderContext,
        user: UserContext,
        history: HistoryContext,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            order,
            user,
            history,
            now: now.timestamp(),
        }
    }

    /// A representative context used by the admin rule-preview endpoint (and
    /// tests) so a rule can be tried before it is saved: a new 100.00 EUR
    /// monthly template VM for an Irish customer with no order history.
    pub fn sample() -> Self {
        Self::new(
            OrderContext {
                amount: 10_000,
                currency: "EUR".to_string(),
                intervals: 1,
                interval_type: "month".to_string(),
                is_new: true,
                items: vec![OrderLineItem::sample_vm()],
            },
            UserContext {
                id: 42,
                country: Some("IRL".to_string()),
            },
            HistoryContext::default(),
            Utc::now(),
        )
    }
}

/// The order being priced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrderContext {
    /// Net order amount (before tax and processing fees) in minor units.
    pub amount: i64,
    /// ISO currency code of [`Self::amount`], e.g. `EUR`, `BTC`.
    pub currency: String,
    /// Number of billing intervals being purchased.
    pub intervals: i64,
    /// Billing interval unit: `day`, `month` or `year`.
    pub interval_type: String,
    /// True when this is the first payment for the subscription (a new order)
    /// rather than a renewal or an upgrade.
    pub is_new: bool,
    /// The lines of the order, each carrying the properties of the product it
    /// bills for. See [`OrderLineItem`].
    pub items: Vec<OrderLineItem>,
}

/// The customer placing the order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserContext {
    /// Internal user id.
    pub id: i64,
    /// ISO 3166-1 alpha-3 billing country, when the user has provided one.
    pub country: Option<String>,
}

/// Aggregate history, so rules can express "first order" or "loyalty" offers
/// without the engine handing a rule the customer's whole payment log.
///
/// Lifetime spend is deliberately **not** exposed: a customer's payments are
/// spread across currencies, so any single number would either be wrong or
/// require converting their whole payment history at every quote. It can be
/// added when there is a cheap and correct way to compute it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HistoryContext {
    /// Number of settled orders this customer has paid for.
    pub orders: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_timestamp_and_fields() {
        let ctx = DiscountContext::sample();
        assert_eq!(ctx.order.amount, 10_000);
        assert_eq!(ctx.user.id, 42);
        assert_eq!(ctx.history, HistoryContext::default());
        assert!(ctx.now > 1_700_000_000);
    }

    #[test]
    fn round_trips_through_serde() {
        let ctx = DiscountContext::sample();
        let json = serde_json::to_string(&ctx).expect("serialize");
        let back: DiscountContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ctx, back);
    }

    #[test]
    fn history_default_is_empty() {
        assert_eq!(HistoryContext::default().orders, 0);
    }
}
