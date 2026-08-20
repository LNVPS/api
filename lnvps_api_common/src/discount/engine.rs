//! Resolving a discount for an order.
//!
//! This is step 1-4 of the evaluation flow: resolve candidates, filter them by
//! the DB integrity guards, build the read-only context, evaluate each rule and
//! keep the decision worth the most. Step 5 — recording the redemption — happens
//! at payment settlement, not here, so an invoice that is never paid cannot
//! consume a campaign's stock.
//!
//! The money maths lives here rather than in [`super::decision`] because a fixed
//! amount may be denominated in a currency other than the order's, and only the
//! pricing engine owns an exchange-rate service.
//!
//! # Which paths take a discount
//!
//! Discounts apply to *quoted* orders: an invoice is produced for a price, and
//! the discount lowers that price. They deliberately do **not** apply to the
//! amount-already-paid paths ([`PricingEngine::get_cost_by_amount`] and
//! [`PricingEngine::get_subscription_cost_by_amount`]), where the customer has
//! sent an arbitrary amount — an LNURL top-up or an on-chain deposit — and it is
//! converted into time. There, a discount could only mean "more time for the
//! same money", which is a different promise from the one a code makes, and one
//! that cannot be shown as a line on an invoice the customer already paid.
//!
//! # Referral interaction
//!
//! Referral commission is computed from the recorded `subscription_payment.amount`
//! (see `list_referral_usage` in `lnvps_db/src/mysql.rs`). Because a discount
//! reduces that stored amount, commission is paid on what the customer actually
//! paid, with no change to the referral code.

use anyhow::{Result, anyhow, bail};
use chrono::Utc;
use lnvps_db::{Discount, IntervalType};
use log::warn;
use payments_rs::currency::{Currency, CurrencyAmount};
use std::str::FromStr;

use super::{
    DiscountContext, DiscountDecision, HistoryContext, OrderContext, OrderLineItem, UserContext,
};
use crate::{PricingEngine, TaxLine};

/// Everything needed to resolve a discount for one order.
///
/// The order is described here rather than re-derived inside the engine because
/// a discount applies to the whole order — every line item, plus setup fees —
/// not to a single VM's cost.
#[derive(Debug, Clone)]
pub struct DiscountOrder {
    /// The code the customer entered. `None` means no discount is requested;
    /// phase 2 will also evaluate code-less automatic discounts here.
    pub code: Option<String>,
    /// The customer placing the order.
    pub user_id: u64,
    /// The company being billed, used to reject another company's codes.
    pub company_id: u64,
    /// Net order amount (before tax and processing fees) in minor units of
    /// [`Self::currency`].
    pub amount: u64,
    /// Currency of [`Self::amount`] — the payment currency, after any
    /// conversion the pricing engine has already done.
    pub currency: Currency,
    /// Billing intervals being purchased.
    pub intervals: u64,
    /// Billing interval unit.
    pub interval_type: IntervalType,
    /// True for a first (purchase) payment, false for a renewal or upgrade.
    pub is_new: bool,
    /// The lines of the order, resolved with the properties of the products
    /// they bill for (see [`OrderLineItem::resolve_all`]).
    pub items: Vec<OrderLineItem>,
}

/// A discount that was resolved for an order and is ready to be applied.
#[derive(Debug, Clone, PartialEq)]
pub struct AppliedDiscount {
    /// The discount that produced this reduction.
    pub discount_id: u64,
    /// The code that was entered, for display on the invoice.
    pub code: Option<String>,
    /// Amount off, in minor units of [`Self::currency`], already clamped to the
    /// order total.
    pub amount_off: u64,
    /// Currency of [`Self::amount_off`] — always the order currency.
    pub currency: Currency,
}

impl PricingEngine {
    /// Resolve the best discount available for `order`.
    ///
    /// Returns `Ok(None)` when no code was supplied. When a code *was* supplied
    /// but cannot be used, this fails: the customer typed something and is owed
    /// an answer. The message is deliberately the same for "no such code" and
    /// "expired code" so a stranger cannot probe for valid codes.
    pub async fn quote_discount(&self, order: &DiscountOrder) -> Result<Option<AppliedDiscount>> {
        let code = match order.code.as_deref().map(str::trim) {
            Some(c) if !c.is_empty() => c,
            _ => return Ok(None),
        };

        let candidates = self.discount_candidates(code, order).await?;
        let context = self.build_context(order).await?;

        let best = self.best_decision(&candidates, &context, order).await;
        match best {
            Some(applied) => Ok(Some(applied)),
            // Eligible on paper but the rule declined (e.g. minimum spend not
            // met), or it resolved to nothing after clamping.
            None => bail!("Discount code is not valid for this order"),
        }
    }

    /// Candidate discounts for `code`, filtered by the DB integrity guards:
    /// company, `active`, validity window, global usage limit and per-user
    /// limit. These cannot live in the rule — counting redemptions is state a
    /// side-effect-free expression must not be given.
    async fn discount_candidates(
        &self,
        code: &str,
        order: &DiscountOrder,
    ) -> Result<Vec<Discount>> {
        // One generic message for every rejection below, so the endpoint cannot
        // be used to enumerate which codes exist.
        let refuse = || anyhow!("Discount code is not valid for this order");

        let discount = self
            .db()
            .get_discount_by_code(code)
            .await
            .map_err(|_| refuse())?;

        if discount.company_id != order.company_id || !discount.is_available(Utc::now()) {
            return Err(refuse());
        }

        if let Some(limit) = discount.per_user_limit {
            let used = self
                .db()
                .count_discount_redemptions(discount.id, order.user_id)
                .await?;
            if used >= limit {
                return Err(refuse());
            }
        }

        Ok(vec![discount])
    }

    /// Build the read-only context a rule may read.
    async fn build_context(&self, order: &DiscountOrder) -> Result<DiscountContext> {
        let user = self.db().get_user(order.user_id).await?;

        // Settled payments only: an unpaid invoice is not an order.
        let orders = self
            .db()
            .list_subscription_payments_by_user(order.user_id)
            .await
            .map(|payments| payments.iter().filter(|p| p.is_paid).count() as i64)
            .unwrap_or(0);

        Ok(DiscountContext::new(
            OrderContext {
                amount: order.amount.min(i64::MAX as u64) as i64,
                currency: order.currency.to_string(),
                intervals: order.intervals as i64,
                interval_type: interval_type_name(order.interval_type).to_string(),
                is_new: order.is_new,
                items: order.items.clone(),
            },
            UserContext {
                id: order.user_id as i64,
                country: user.country_code.clone(),
            },
            HistoryContext { orders },
            Utc::now(),
        ))
    }

    /// Evaluate every candidate and keep the one worth the most to the
    /// customer. Ties keep the first candidate, which for a code lookup is the
    /// only one; phase 2's automatic discounts extend the candidate list rather
    /// than this selection.
    async fn best_decision(
        &self,
        candidates: &[Discount],
        context: &DiscountContext,
        order: &DiscountOrder,
    ) -> Option<AppliedDiscount> {
        let mut best: Option<AppliedDiscount> = None;
        for candidate in candidates {
            let amount_off = match self.resolve_amount_off(candidate, context, order).await {
                Ok(v) => v,
                Err(e) => {
                    // A single broken rule must not fail the whole order.
                    warn!(
                        "Discount {} could not be resolved, skipping: {e}",
                        candidate.id
                    );
                    continue;
                }
            };
            if amount_off == 0 {
                continue;
            }
            if best.as_ref().is_none_or(|b| amount_off > b.amount_off) {
                best = Some(AppliedDiscount {
                    discount_id: candidate.id,
                    code: candidate.code.clone(),
                    amount_off,
                    currency: order.currency,
                });
            }
        }
        best
    }

    /// Evaluate one candidate's rule and turn its decision into an amount off
    /// in the order currency.
    async fn resolve_amount_off(
        &self,
        candidate: &Discount,
        context: &DiscountContext,
        order: &DiscountOrder,
    ) -> Result<u64> {
        let decision = super::evaluate_rule_or_none(&candidate.rule, context);
        if decision.is_empty() {
            return Ok(0);
        }
        let decision = self.convert_decision(decision, order.currency).await?;
        decision.amount_off(order.amount, &order.currency.to_string())
    }

    /// Convert a fixed amount denominated in another currency into `target`.
    ///
    /// A rule author writes "5 EUR off" once; the same discount then has to work
    /// for a customer paying in sats. Conversion is floored, so a rounding
    /// fraction is never given away.
    async fn convert_decision(
        &self,
        decision: DiscountDecision,
        target: Currency,
    ) -> Result<DiscountDecision> {
        let (amount, currency) = match (decision.amount, decision.currency.as_deref()) {
            (Some(a), Some(c)) if a > 0 => (a, c),
            _ => return Ok(decision),
        };
        if currency.eq_ignore_ascii_case(&target.to_string()) {
            return Ok(decision);
        }

        let from = Currency::from_str(currency)
            .map_err(|_| anyhow!("unknown discount currency '{currency}'"))?;
        let converted = self
            .convert_currency(CurrencyAmount::from_u64(from, amount), target)
            .await?;
        Ok(DiscountDecision {
            amount: Some(converted.value()),
            currency: Some(target.to_string()),
            ..decision
        })
    }
}

/// Spread a discount across the lines of an order, proportionally to each
/// line's net amount.
///
/// An order is billed as line items, each with its own VAT determination, so a
/// discount on the order total has to be attributed to lines before tax can be
/// recomputed. Returns the reduction for each line, summing to exactly
/// `amount_off` (clamped to the order total): proportional shares are floored,
/// then the rounding remainder is taken off the largest line, so the parts
/// always add back up to the whole.
pub fn allocate_discount(nets: &[u64], amount_off: u64) -> Vec<u64> {
    let total: u64 = nets.iter().sum();
    let amount_off = amount_off.min(total);
    if total == 0 || amount_off == 0 {
        return vec![0; nets.len()];
    }

    let mut shares: Vec<u64> = nets
        .iter()
        .map(|net| ((*net as u128 * amount_off as u128) / total as u128) as u64)
        .collect();

    // Floors lose at most one minor unit per line; give the remainder to the
    // largest line, which is the one best able to absorb it without going
    // negative.
    let allocated: u64 = shares.iter().sum();
    if let Some(remainder) = amount_off.checked_sub(allocated).filter(|r| *r > 0) {
        let largest = nets
            .iter()
            .enumerate()
            .max_by_key(|(_, net)| **net)
            .map(|(i, _)| i)
            .unwrap_or(0);
        shares[largest] = (shares[largest] + remainder).min(nets[largest]);
    }
    shares
}

/// Apply a discount to an order's VAT breakdown.
///
/// The discount is attributed to lines in proportion to their net (see
/// [`allocate_discount`]), and each line's tax is then **recomputed** from the
/// amount actually charged — `floor(net * rate)`, the same arithmetic every
/// other pricing path uses — rather than scaled. The rate, place of supply and
/// treatment are untouched: they are facts about the customer and the seller,
/// not about the price.
pub fn discount_tax_lines(lines: &[TaxLine], amount_off: u64) -> Vec<TaxLine> {
    let nets: Vec<u64> = lines.iter().map(|l| l.net).collect();
    let shares = allocate_discount(&nets, amount_off);
    lines
        .iter()
        .zip(shares)
        .map(|(line, off)| {
            let net = line.net.saturating_sub(off);
            TaxLine {
                net,
                tax: ((net as f64) * (line.rate as f64 / 100.0)).floor() as u64,
                ..line.clone()
            }
        })
        .collect()
}

/// The name a rule sees for a billing interval.
fn interval_type_name(interval: IntervalType) -> &'static str {
    match interval {
        IntervalType::Day => "day",
        IntervalType::Month => "month",
        IntervalType::Year => "year",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExchangeRateService, MockDb, MockExchangeRate, Ticker, VatClient};
    use lnvps_db::{DiscountRedemption, LNVpsDbBase, SubscriptionPayment, SubscriptionPaymentType};
    use std::sync::Arc;

    async fn engine() -> (PricingEngine, Arc<MockDb>) {
        let db = Arc::new(MockDb::default());
        let rates = Arc::new(MockExchangeRate::new());
        rates
            .set_rate(Ticker::btc_rate("EUR").unwrap(), 100_000.0)
            .await;
        rates
            .set_rate(Ticker::btc_rate("USD").unwrap(), 120_000.0)
            .await;
        let pe = PricingEngine::new(db.clone(), rates, VatClient::new());
        (pe, db)
    }

    async fn user(db: &MockDb) -> u64 {
        db.upsert_user(&[1; 32]).await.unwrap()
    }

    /// Apply a discount to a payment and settle it, as a paid order does.
    async fn redeem(db: &MockDb, discount_id: u64, user_id: u64, payment: u8) {
        db.insert_discount_redemption(&DiscountRedemption {
            discount_id,
            user_id,
            subscription_payment_id: vec![payment; 32],
            amount_off: 1_000,
            currency: "EUR".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
        db.settle_discount_redemption(&vec![payment; 32])
            .await
            .unwrap()
            .expect("settles");
    }

    fn discount(rule: &str) -> Discount {
        Discount {
            company_id: 1,
            code: Some("SAVE10".to_string()),
            name: "Save".to_string(),
            rule: rule.to_string(),
            active: true,
            ..Default::default()
        }
    }

    fn order(user_id: u64, code: Option<&str>) -> DiscountOrder {
        DiscountOrder {
            code: code.map(|c| c.to_string()),
            user_id,
            company_id: 1,
            amount: 10_000,
            currency: Currency::EUR,
            intervals: 1,
            interval_type: IntervalType::Month,
            is_new: true,
            items: vec![OrderLineItem::sample_vm()],
        }
    }

    #[tokio::test]
    async fn no_code_means_no_discount() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        assert!(pe.quote_discount(&order(u, None)).await.unwrap().is_none());
        // Whitespace is not a code.
        assert!(
            pe.quote_discount(&order(u, Some("   ")))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn percent_discount_is_applied() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        let id = db
            .insert_discount(&discount("{'percent': 10}"))
            .await
            .unwrap();

        let applied = pe
            .quote_discount(&order(u, Some("SAVE10")))
            .await
            .unwrap()
            .expect("discount applies");
        assert_eq!(applied.discount_id, id);
        assert_eq!(applied.amount_off, 1_000);
        assert_eq!(applied.currency, Currency::EUR);
        assert_eq!(applied.code.as_deref(), Some("SAVE10"));
    }

    /// Codes are trimmed and matched exactly: a trailing space from a copy-paste
    /// must work, a different code must not.
    #[tokio::test]
    async fn codes_are_trimmed_and_matched_exactly() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("{'percent': 10}"))
            .await
            .unwrap();

        assert!(
            pe.quote_discount(&order(u, Some(" SAVE10 ")))
                .await
                .unwrap()
                .is_some()
        );
        assert!(pe.quote_discount(&order(u, Some("save10"))).await.is_err());
        assert!(pe.quote_discount(&order(u, Some("OTHER"))).await.is_err());
    }

    #[tokio::test]
    async fn rule_that_declines_is_reported_as_invalid() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("order.amount >= 50000 ? {'percent': 10} : {}"))
            .await
            .unwrap();

        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());

        // ...and applies once the order is big enough.
        let mut big = order(u, Some("SAVE10"));
        big.amount = 50_000;
        assert_eq!(
            pe.quote_discount(&big).await.unwrap().unwrap().amount_off,
            5_000
        );
    }

    /// A rule that cannot be evaluated must not fail the order with a 500, and
    /// must not silently discount either.
    #[tokio::test]
    async fn broken_rule_is_not_a_discount() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("this is not cel {{"))
            .await
            .unwrap();
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());
    }

    #[tokio::test]
    async fn guards_reject_inactive_expired_and_exhausted_codes() {
        let (pe, db) = engine().await;
        let u = user(&db).await;

        let inactive = db
            .insert_discount(&Discount {
                code: Some("INACTIVE".to_string()),
                active: false,
                ..discount("{'percent': 10}")
            })
            .await
            .unwrap();
        assert!(
            pe.quote_discount(&order(u, Some("INACTIVE")))
                .await
                .is_err()
        );
        db.update_discount(&Discount {
            active: true,
            ..db.get_discount(inactive).await.unwrap()
        })
        .await
        .unwrap();
        assert!(pe.quote_discount(&order(u, Some("INACTIVE"))).await.is_ok());

        db.insert_discount(&Discount {
            code: Some("EXPIRED".to_string()),
            valid_to: Some(Utc::now() - chrono::Duration::days(1)),
            ..discount("{'percent': 10}")
        })
        .await
        .unwrap();
        assert!(pe.quote_discount(&order(u, Some("EXPIRED"))).await.is_err());

        db.insert_discount(&Discount {
            code: Some("FUTURE".to_string()),
            valid_from: Utc::now() + chrono::Duration::days(1),
            ..discount("{'percent': 10}")
        })
        .await
        .unwrap();
        assert!(pe.quote_discount(&order(u, Some("FUTURE"))).await.is_err());

        let exhausted = db
            .insert_discount(&Discount {
                code: Some("GONE".to_string()),
                usage_limit: Some(1),
                ..discount("{'percent': 10}")
            })
            .await
            .unwrap();
        redeem(&db, exhausted, u, 9).await;
        assert!(pe.quote_discount(&order(u, Some("GONE"))).await.is_err());
    }

    /// A code belonging to another company must not discount this order, even
    /// though the code itself is live.
    #[tokio::test]
    async fn other_companys_code_is_rejected() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&Discount {
            company_id: 2,
            ..discount("{'percent': 10}")
        })
        .await
        .unwrap();
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());
    }

    #[tokio::test]
    async fn per_user_limit_is_enforced() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        let id = db
            .insert_discount(&Discount {
                per_user_limit: Some(1),
                ..discount("{'percent': 10}")
            })
            .await
            .unwrap();
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_ok());

        redeem(&db, id, u, 7).await;
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());

        // Another customer is unaffected by the first one's redemption.
        let u2 = db.upsert_user(&[2; 32]).await.unwrap();
        assert!(pe.quote_discount(&order(u2, Some("SAVE10"))).await.is_ok());
    }

    /// "5 EUR off" written once must work for a customer paying in sats.
    #[tokio::test]
    async fn fixed_amount_is_converted_into_the_order_currency() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("{'amount': 500, 'currency': 'EUR'}"))
            .await
            .unwrap();

        let mut btc = order(u, Some("SAVE10"));
        btc.currency = Currency::BTC;
        // 1 BTC = 100k EUR, so 5.00 EUR = 5000 sats = 5_000_000 msat.
        btc.amount = 100_000_000;
        let applied = pe.quote_discount(&btc).await.unwrap().unwrap();
        assert_eq!(applied.amount_off, 5_000_000);
        assert_eq!(applied.currency, Currency::BTC);
    }

    #[tokio::test]
    async fn unknown_discount_currency_is_not_a_discount() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("{'amount': 500, 'currency': 'XYZ'}"))
            .await
            .unwrap();
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());
    }

    /// A discount can never exceed the order total, whatever the rule says.
    #[tokio::test]
    async fn discount_is_clamped_to_the_order_total() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        db.insert_discount(&discount("{'amount': 999999, 'currency': 'EUR'}"))
            .await
            .unwrap();
        let applied = pe
            .quote_discount(&order(u, Some("SAVE10")))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(applied.amount_off, 10_000);
    }

    /// The rule can see the customer's country and settled order count.
    #[tokio::test]
    async fn context_exposes_user_and_history() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        let mut usr = db.get_user(u).await.unwrap();
        usr.country_code = Some("IRL".to_string());
        db.update_user(&usr).await.unwrap();

        db.insert_discount(&discount(
            "user.country == 'IRL' && history.orders == 0 ? {'percent': 10} : {}",
        ))
        .await
        .unwrap();
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_ok());

        // Record a settled payment: the customer is no longer a first-timer.
        db.subscription_payments
            .lock()
            .await
            .push(SubscriptionPayment {
                id: vec![5; 32],
                subscription_id: 1,
                user_id: u,
                created: Utc::now(),
                expires: Utc::now(),
                amount: 1_000,
                currency: "EUR".to_string(),
                payment_method: lnvps_db::PaymentMethod::Lightning,
                payment_type: SubscriptionPaymentType::Purchase,
                external_data: Default::default(),
                external_id: None,
                is_paid: true,
                rate: 1.0,
                time_value: None,
                metadata: None,
                tax: 0,
                processing_fee: 0,
                paid_at: Some(Utc::now()),
                tax_rate: None,
                tax_country_code: None,
                tax_treatment: None,
                tax_evidence: None,
                tax_breakdown: None,
                refunded_payment_id: None,
            });
        assert!(pe.quote_discount(&order(u, Some("SAVE10"))).await.is_err());
    }

    /// When several candidates are eligible the customer gets the best one.
    #[tokio::test]
    async fn best_value_candidate_wins() {
        let (pe, db) = engine().await;
        let u = user(&db).await;
        let small = Discount {
            id: 1,
            ..discount("{'percent': 5}")
        };
        let big = Discount {
            id: 2,
            ..discount("{'percent': 20}")
        };
        let declined = Discount {
            id: 3,
            ..discount("{}")
        };
        let broken = Discount {
            id: 4,
            ..discount("nonsense {{")
        };
        let ord = order(u, Some("SAVE10"));
        let ctx = pe.build_context(&ord).await.unwrap();

        let best = pe
            .best_decision(&[small, declined, broken, big], &ctx, &ord)
            .await
            .unwrap();
        assert_eq!(best.discount_id, 2);
        assert_eq!(best.amount_off, 2_000);

        assert!(pe.best_decision(&[], &ctx, &ord).await.is_none());
    }

    #[test]
    fn discount_is_allocated_across_lines_without_losing_a_unit() {
        // Proportional shares.
        assert_eq!(allocate_discount(&[6_000, 4_000], 1_000), vec![600, 400]);
        // The rounding remainder goes to the largest line, so the parts sum to
        // exactly the discount rather than one unit short.
        let shares = allocate_discount(&[3_333, 3_333, 3_334], 1_000);
        assert_eq!(shares.iter().sum::<u64>(), 1_000);
        assert_eq!(shares, vec![333, 333, 334]);

        // A discount larger than the order is clamped to it, and no line is
        // reduced below zero.
        let shares = allocate_discount(&[1_000, 500], 99_999);
        assert_eq!(shares, vec![1_000, 500]);

        // Degenerate inputs.
        assert_eq!(allocate_discount(&[1_000], 0), vec![0]);
        assert_eq!(allocate_discount(&[0, 0], 500), vec![0, 0]);
        assert!(allocate_discount(&[], 500).is_empty());
        assert_eq!(allocate_discount(&[1_000], 1_000), vec![1_000]);
    }

    fn line(net: u64, rate: f32) -> TaxLine {
        TaxLine {
            net,
            tax: ((net as f64) * (rate as f64 / 100.0)).floor() as u64,
            rate,
            country_code: Some("IRL".to_string()),
            treatment: crate::TaxTreatment::Domestic,
        }
    }

    /// A discount changes what is charged, not who the customer is: the rate,
    /// place of supply and treatment survive, and the tax is recomputed from
    /// the amount actually charged — never charged on money the customer does
    /// not pay.
    #[test]
    fn tax_is_recomputed_on_the_discounted_net() {
        let before = vec![line(10_000, 23.0)];
        let after = discount_tax_lines(&before, 1_000);
        assert_eq!(after[0].net, 9_000);
        assert_eq!(after[0].tax, 2_070, "23% of the discounted net");
        assert_eq!(after[0].rate, 23.0);
        assert_eq!(after[0].treatment, before[0].treatment);
        assert_eq!(after[0].country_code, before[0].country_code);

        // Mixed rates across lines each keep their own.
        let mixed = discount_tax_lines(&[line(6_000, 23.0), line(4_000, 0.0)], 1_000);
        assert_eq!((mixed[0].net, mixed[0].tax), (5_400, 1_242));
        assert_eq!((mixed[1].net, mixed[1].tax), (3_600, 0));

        // A 100% discount leaves nothing to tax.
        let free = discount_tax_lines(&before, 10_000);
        assert_eq!((free[0].net, free[0].tax), (0, 0));

        // No discount changes nothing.
        let same = discount_tax_lines(&before, 0);
        assert_eq!((same[0].net, same[0].tax), (10_000, 2_300));
    }

    #[test]
    fn interval_names_are_stable() {
        // Rules compare against these strings, so they are API.
        assert_eq!(interval_type_name(IntervalType::Day), "day");
        assert_eq!(interval_type_name(IntervalType::Month), "month");
        assert_eq!(interval_type_name(IntervalType::Year), "year");
    }
}
