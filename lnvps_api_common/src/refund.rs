//! Recording a refund against the payment it reverses (issue #193).
//!
//! A refund is stored as an ordinary `subscription_payment` row with
//! `payment_type = Refund`, carrying the **magnitude** returned to the customer
//! — the amount columns are `BIGINT UNSIGNED`, so the sign lives in the type and
//! every aggregation branches on it.
//!
//! Everything else on the row is copied from the payment being refunded rather
//! than recomputed: the exchange `rate`, the VAT rate, the place-of-supply
//! country and the treatment were frozen when the customer was charged, and VAT
//! is owed on what was charged, not on what the same service would cost today.

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use lnvps_db::{SubscriptionPayment, SubscriptionPaymentType};
use sha2::{Digest, Sha256};

/// Derive the id of a refund row from what it records.
///
/// Deliberately not random: recording the same refund twice — a double-clicked
/// modal, a retried request — derives the same 32-byte id and collides on the
/// primary key instead of silently paying the customer out twice in the ledger.
/// Two genuinely distinct refunds of the same payment differ in amount or
/// timestamp, so they get distinct ids.
pub fn derive_refund_payment_id(
    refunded_payment_id: &[u8],
    amount: u64,
    refunded_at: DateTime<Utc>,
    admin_user_id: u64,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"lnvps-refund-v1");
    h.update(refunded_payment_id);
    h.update(amount.to_be_bytes());
    h.update(refunded_at.timestamp().to_be_bytes());
    h.update(admin_user_id.to_be_bytes());
    h.finalize().to_vec()
}

/// The tax to reverse when refunding `amount` of `original`.
///
/// Pro-rated against the original payment's own gross/tax split, so the VAT
/// returned is a slice of the VAT that was actually declared — never a fresh
/// calculation at today's rate, which would drift from what the customer was
/// charged and misstate the OSS return.
///
/// A full refund (`amount == original.amount`) returns exactly `original.tax`;
/// integer division only rounds on partial refunds, and rounds **down**, so
/// repeated partial refunds can never return more VAT than was collected.
pub fn prorated_refund_tax(original: &SubscriptionPayment, amount: u64) -> u64 {
    if original.amount == 0 || original.tax == 0 {
        return 0;
    }
    let amount = amount.min(original.amount);
    ((amount as u128 * original.tax as u128) / original.amount as u128) as u64
}

/// What is still refundable on `payment` given the refunds already recorded
/// against it.
///
/// Partial refunds are allowed, so the ceiling is the payment minus everything
/// already returned. Without it a payment could be refunded twice over and the
/// ledger would owe the customer money that was never sent.
pub fn refundable_remaining(
    payment: &SubscriptionPayment,
    existing: &[SubscriptionPayment],
) -> u64 {
    let already: u64 = existing.iter().map(|r| r.amount).sum();
    payment.amount.saturating_sub(already)
}

/// Split `total` across `payments` in the order given, taking as much as each
/// one can still absorb.
///
/// `payments` carries each candidate with what is still refundable on it. The
/// caller decides the order — newest payment first, so a refund reverses the
/// most recent period rather than one whose VAT period may be long closed.
///
/// Fails when the payments cannot absorb the whole amount, so an automated
/// payout can refuse **before** any money moves: paying first and discovering
/// there is nowhere to book it leaves money gone and the ledger silent.
pub fn allocate_refund(
    payments: &[(SubscriptionPayment, u64)],
    total: u64,
) -> Result<Vec<(SubscriptionPayment, u64)>> {
    let capacity: u64 = payments.iter().map(|(_, r)| *r).sum();
    if total > capacity {
        bail!("refund of {total} exceeds the {capacity} still refundable on this VM's payments");
    }

    let mut left = total;
    let mut out = Vec::new();
    for (payment, remaining) in payments {
        if left == 0 {
            break;
        }
        let take = (*remaining).min(left);
        if take == 0 {
            continue;
        }
        left -= take;
        out.push((payment.clone(), take));
    }
    Ok(out)
}

/// Build the accounting row that reverses `amount` of `original`.
///
/// The row is deliberately a copy of the payment it reverses rather than a
/// fresh calculation: same currency, same frozen exchange `rate`, same VAT
/// rate, country and treatment, with `amount`/`tax` pro-rated. VAT is owed on
/// what was charged, so reversing it at today's rates would misstate the
/// return.
///
/// `external_ref` is proof the money actually moved — a Lightning preimage, a
/// Revolut refund id, a bank reference.
pub fn build_refund_row(
    original: &SubscriptionPayment,
    amount: u64,
    refunded_at: DateTime<Utc>,
    admin_user_id: u64,
    reason: Option<&str>,
    external_ref: Option<&str>,
) -> SubscriptionPayment {
    let mut metadata = serde_json::json!({
        "refund": {
            "recorded_by_admin_user_id": admin_user_id,
            "refunded_payment_id": hex::encode(&original.id),
        }
    });
    if let Some(reason) = reason {
        metadata["refund"]["reason"] = serde_json::json!(reason);
    }
    if let Some(ext) = external_ref {
        metadata["refund"]["external_ref"] = serde_json::json!(ext);
    }

    SubscriptionPayment {
        id: derive_refund_payment_id(&original.id, amount, refunded_at, admin_user_id),
        subscription_id: original.subscription_id,
        user_id: original.user_id,
        created: refunded_at,
        // A refund buys no time; `expires` is carried from the payment it
        // reverses so the row sits in the period it belongs to.
        expires: original.expires,
        amount,
        currency: original.currency.clone(),
        // The instrument the original sale used. What the money was actually
        // returned through is free text in `metadata.refund.external_ref`: the
        // accounting row has to stay in the currency and at the rate it
        // reverses, whatever wallet paid it out.
        payment_method: original.payment_method,
        payment_type: SubscriptionPaymentType::Refund,
        // Nothing to store: there is no invoice for money we are giving back.
        external_data: lnvps_db::EncryptedString::new(String::new()),
        external_id: None,
        is_paid: true,
        rate: original.rate,
        // Must stay None. `time_value` is what extends a subscription, and a
        // refund must not touch expiry — the VM's fate is a separate decision.
        time_value: None,
        metadata: Some(metadata),
        tax: prorated_refund_tax(original, amount),
        // Processor fees are not returned on a refund, so the fee stays a sunk
        // cost on the original payment rather than being reversed here.
        processing_fee: 0,
        paid_at: Some(refunded_at),
        tax_rate: original.tax_rate,
        tax_country_code: original.tax_country_code.clone(),
        tax_treatment: original.tax_treatment.clone(),
        tax_evidence: original.tax_evidence.clone(),
        // The original's per-line breakdown describes the sale, not this
        // reversal: on a partial refund its line amounts would not add up to
        // this row. The OSS report falls back to the summary fields above,
        // which are the ones that must match.
        tax_breakdown: None,
        refunded_payment_id: Some(original.id.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use lnvps_db::{LNVpsDbBase, PaymentMethod, SubscriptionPaymentType};

    fn payment(amount: u64, tax: u64) -> SubscriptionPayment {
        SubscriptionPayment {
            id: vec![1u8; 32],
            subscription_id: 1,
            user_id: 1,
            created: Utc::now(),
            expires: Utc::now(),
            amount,
            currency: "EUR".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: "".into(),
            external_id: None,
            is_paid: true,
            rate: 1.0,
            time_value: Some(2_592_000),
            metadata: None,
            tax,
            processing_fee: 0,
            paid_at: Some(Utc::now()),
            tax_rate: Some(23.0),
            tax_country_code: Some("IRL".to_string()),
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
        }
    }

    /// A full refund returns exactly the VAT that was collected — no rounding
    /// drift, or the OSS return stops matching the payments it is built from.
    #[test]
    fn full_refund_returns_the_whole_tax() {
        let p = payment(1230, 230);
        assert_eq!(prorated_refund_tax(&p, p.amount), 230);
    }

    /// Partial refunds take a proportional slice, rounded down, so refunding a
    /// payment in pieces never returns more VAT than was declared on it.
    #[test]
    fn partial_refunds_never_exceed_the_collected_tax() {
        let p = payment(1230, 230);
        let halves = prorated_refund_tax(&p, 615) * 2;
        assert!(halves <= p.tax, "{halves} > {}", p.tax);
        assert_eq!(prorated_refund_tax(&p, 615), 115);

        // Thirds: 76 + 76 + 76 = 228 <= 230.
        let third = prorated_refund_tax(&p, 410);
        assert_eq!(third, 76);
        assert!(third * 3 <= p.tax);
    }

    /// A zero-tax payment (reverse charge, outside scope) reverses no tax.
    #[test]
    fn untaxed_payments_refund_no_tax() {
        assert_eq!(prorated_refund_tax(&payment(1000, 0), 1000), 0);
    }

    /// The id is a function of what is being recorded, so a resubmitted refund
    /// lands on the same primary key instead of double-recording.
    #[test]
    fn refund_id_is_derived_not_random() {
        let at = Utc::now();
        let a = derive_refund_payment_id(&[7u8; 32], 500, at, 3);
        let b = derive_refund_payment_id(&[7u8; 32], 500, at, 3);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);

        // A different amount, payment, admin or second is a different refund.
        assert_ne!(a, derive_refund_payment_id(&[7u8; 32], 501, at, 3));
        assert_ne!(a, derive_refund_payment_id(&[8u8; 32], 500, at, 3));
        assert_ne!(a, derive_refund_payment_id(&[7u8; 32], 500, at, 4));
        assert_ne!(
            a,
            derive_refund_payment_id(&[7u8; 32], 500, at + chrono::Duration::seconds(1), 3)
        );
    }

    /// A refund row is an ordinary payment row that points at the one it
    /// reverses, so the ceiling on the next refund is what the lookup by link
    /// says has already gone out — the property the admin endpoint's
    /// over-refund guard depends on.
    #[tokio::test]
    async fn refunds_accumulate_against_the_payment_they_reverse() {
        let db = MockDb::default();
        let original = payment(1230, 230);
        db.insert_subscription_payment(&original).await.unwrap();

        assert!(
            db.list_refunds_for_payment(&original.id)
                .await
                .unwrap()
                .is_empty(),
            "a fresh payment has no refunds"
        );

        let at = Utc::now();
        let mut first = payment(500, prorated_refund_tax(&original, 500));
        first.id = derive_refund_payment_id(&original.id, 500, at, 1);
        first.payment_type = SubscriptionPaymentType::Refund;
        first.refunded_payment_id = Some(original.id.clone());
        first.time_value = None;
        db.insert_subscription_payment(&first).await.unwrap();

        let mut second = payment(300, prorated_refund_tax(&original, 300));
        second.id = derive_refund_payment_id(&original.id, 300, at, 1);
        second.payment_type = SubscriptionPaymentType::Refund;
        second.refunded_payment_id = Some(original.id.clone());
        second.time_value = None;
        db.insert_subscription_payment(&second).await.unwrap();

        let refunds = db.list_refunds_for_payment(&original.id).await.unwrap();
        assert_eq!(refunds.len(), 2);
        assert!(refunds.iter().all(|r| r.payment_type.is_refund()));
        let refunded: u64 = refunds.iter().map(|r| r.amount).sum();
        assert_eq!(refunded, 800);
        assert_eq!(original.amount - refunded, 430, "still refundable");

        // Refunded tax never exceeds the tax collected, however it is sliced.
        let refunded_tax: u64 = refunds.iter().map(|r| r.tax).sum();
        assert!(refunded_tax <= original.tax, "{refunded_tax} > 230");

        // An unrelated payment's refunds are not mixed in.
        let mut other = payment(999, 0);
        other.id = vec![9u8; 32];
        db.insert_subscription_payment(&other).await.unwrap();
        assert!(
            db.list_refunds_for_payment(&other.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A refund is split over the payments it reverses, newest first, and each
    /// one only absorbs what it has left. The order is the caller's, so the
    /// most recent period is unwound before older ones.
    #[test]
    fn allocation_fills_each_payment_up_to_its_remainder() {
        let mut newest = payment(1000, 0);
        newest.id = vec![2u8; 32];
        let mut older = payment(1000, 0);
        older.id = vec![3u8; 32];

        // 400 already refunded on the newest, so it can only take 600 more.
        let plan = allocate_refund(&[(newest.clone(), 600), (older.clone(), 1000)], 900).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].0.id, newest.id);
        assert_eq!(plan[0].1, 600, "newest is drained first");
        assert_eq!(plan[1].1, 300, "the rest falls to the older payment");
        assert_eq!(plan.iter().map(|(_, a)| a).sum::<u64>(), 900);

        // A refund that fits in the first payment does not touch the second.
        let plan = allocate_refund(&[(newest.clone(), 600), (older.clone(), 1000)], 500).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].1, 500);
    }

    /// More than the payments can absorb is refused rather than clamped: an
    /// automated payout checks this before it pays, and a clamp would send the
    /// full amount while booking less than went out.
    #[test]
    fn allocation_refuses_more_than_is_refundable() {
        let p = payment(1000, 0);
        let err = allocate_refund(&[(p.clone(), 400)], 500)
            .unwrap_err()
            .to_string();
        assert!(err.contains("400"), "{err}");
        assert!(
            allocate_refund(&[], 1).is_err(),
            "nothing to refund against"
        );
        assert!(allocate_refund(&[], 0).unwrap().is_empty());
    }

    /// The ceiling is the payment minus every refund already recorded, so a
    /// fully refunded payment has nothing left.
    #[test]
    fn remaining_is_the_payment_less_what_already_went_back() {
        let p = payment(1000, 230);
        assert_eq!(refundable_remaining(&p, &[]), 1000);
        let mut part = payment(400, 0);
        part.payment_type = SubscriptionPaymentType::Refund;
        assert_eq!(refundable_remaining(&p, std::slice::from_ref(&part)), 600);
        let mut rest = payment(600, 0);
        rest.payment_type = SubscriptionPaymentType::Refund;
        assert_eq!(refundable_remaining(&p, &[part, rest]), 0);
    }

    /// The built row reverses the original at the terms it was charged on, and
    /// buys no time.
    #[test]
    fn refund_row_copies_the_terms_it_reverses() {
        let original = payment(1230, 230);
        let at = Utc::now();
        let row = build_refund_row(&original, 615, at, 7, Some("downgrade"), Some("preimage"));

        assert_eq!(row.payment_type, SubscriptionPaymentType::Refund);
        assert_eq!(row.refunded_payment_id.as_ref(), Some(&original.id));
        assert_eq!(row.amount, 615);
        assert_eq!(row.tax, prorated_refund_tax(&original, 615));
        assert_eq!(row.currency, original.currency);
        assert_eq!(row.rate, original.rate, "frozen at the charged rate");
        assert_eq!(row.tax_rate, original.tax_rate);
        assert_eq!(row.expires, original.expires);
        assert!(row.is_paid);
        assert_eq!(
            row.time_value, None,
            "a refund must not extend a subscription"
        );
        assert_eq!(row.processing_fee, 0);
        assert_eq!(row.tax_breakdown, None);
        assert_eq!(
            row.id,
            derive_refund_payment_id(&original.id, 615, at, 7),
            "id is derived, so a retry collides instead of double-recording"
        );

        let meta = row.metadata.unwrap();
        assert_eq!(meta["refund"]["external_ref"], "preimage");
        assert_eq!(meta["refund"]["reason"], "downgrade");
        assert_eq!(meta["refund"]["recorded_by_admin_user_id"], 7);
    }

    /// Refund rows subtract from earnings; everything else adds. Aggregations
    /// that ignore this overstate revenue by every refund ever issued.
    #[test]
    fn only_refunds_carry_a_negative_sign() {
        assert_eq!(SubscriptionPaymentType::Refund.signum(), -1);
        assert_eq!(SubscriptionPaymentType::Purchase.signum(), 1);
        assert_eq!(SubscriptionPaymentType::Renewal.signum(), 1);
        assert_eq!(SubscriptionPaymentType::Upgrade.signum(), 1);
        assert!(SubscriptionPaymentType::Refund.is_refund());
        assert!(!SubscriptionPaymentType::Renewal.is_refund());
    }
}
