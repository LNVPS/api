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

use chrono::{DateTime, Utc};
use lnvps_db::SubscriptionPayment;
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
