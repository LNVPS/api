//! Automated VM refunds: pay the customer over Lightning, then book it
//! (issue #193).
//!
//! The money and the ledger are two separate systems, and only one of them can
//! be rolled back. Everything that can refuse does so before the invoice is
//! paid — the quote, the invoice amount, and whether the VM's payments can
//! absorb the refund at all. After the payment there is nothing left but
//! writing rows, and a failure there is reported loudly with the preimage so
//! the refund can be recorded by hand rather than lost.
//!
//! A redelivered job cannot pay twice: the invoice is the customer's and a
//! BOLT11 settles once, so the second attempt fails at the node before
//! anything is written.

use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use lightning_invoice::Bolt11Invoice;
use lnvps_api_common::{
    PricingEngine, RefundEvidence, VmHistoryLogger, build_refund_row, refundable_remaining,
};
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment};
use log::{error, info};
use payments_rs::currency::CurrencyAmount;
use payments_rs::lightning::{LightningNode, PayInvoiceRequest};
use std::str::FromStr;
use std::sync::Arc;

/// How long to wait for the payout to settle before giving up on it.
const PAYOUT_TIMEOUT_SECONDS: u32 = 60;

/// What an automated refund did, for job feedback and notifications.
#[derive(Debug)]
pub struct RefundOutcome {
    /// Millisatoshis actually sent to the customer.
    pub amount_msat: u64,
    /// Routing fee we paid on top, which is ours to absorb.
    pub fee_msat: u64,
    /// Proof of payment, hex, when the node returned one.
    pub preimage: Option<String>,
    /// Refunded magnitude booked against the VM's payments, in `currency`.
    pub booked_amount: u64,
    /// The currency the VM was charged in.
    pub currency: String,
    /// How many refund rows were written.
    pub refund_rows: u64,
    /// Account credit returned for the share of the reversed payments that
    /// credit paid for, in the balance currency's minor units.
    pub credit_returned: u64,
}

/// One payment a refund reverses: `amount` is booked against it, `cash` of
/// that goes out over Lightning and `credit` (balance currency) goes back to
/// the customer's account credit.
#[derive(Debug, Clone)]
pub struct RefundShare {
    pub payment: SubscriptionPayment,
    pub amount: u64,
    pub cash: u64,
    pub credit: u64,
}

/// A payment that can absorb a refund: what is still refundable on it and
/// the credit that paid for part of it.
pub struct RefundCandidate {
    pub payment: SubscriptionPayment,
    pub remaining: u64,
    pub debit: Option<lnvps_db::AccountCreditDebit>,
}

/// Split a cash refund of `cash_total` across `candidates`, newest first. A
/// payment that credit partly paid for is reversed in proportion: the cash
/// returned never exceeds the cash it collected, and the credit share is
/// returned as credit.
pub fn allocate_cash_refund(
    candidates: &[RefundCandidate],
    cash_total: u64,
) -> Result<Vec<RefundShare>> {
    let mut left = cash_total;
    let mut out = Vec::new();
    for c in candidates {
        if left == 0 {
            break;
        }
        let billable = (c.payment.amount + c.payment.tax) as u128;
        let credit_paid = c
            .debit
            .as_ref()
            .filter(|d| d.settled)
            .map(|d| (d.payment_amount as u128).min(billable))
            .unwrap_or(0);
        let cash_paid = billable - credit_paid;
        if billable == 0 || cash_paid == 0 {
            continue;
        }
        let cash_capacity = (c.remaining as u128 * cash_paid / billable) as u64;
        let cash = cash_capacity.min(left);
        if cash == 0 {
            continue;
        }
        let amount = if cash == cash_capacity {
            c.remaining
        } else {
            ((cash as u128 * billable).div_ceil(cash_paid) as u64).min(c.remaining)
        };
        let credit = match &c.debit {
            Some(d) if d.payment_amount > 0 => {
                ((amount - cash) as u128 * d.amount as u128 / d.payment_amount as u128) as u64
            }
            _ => 0,
        };
        left -= cash;
        out.push(RefundShare {
            payment: c.payment.clone(),
            amount,
            cash,
            credit,
        });
    }
    ensure!(
        left == 0,
        "refund of {cash_total} exceeds the {} still refundable in cash on this VM's payments",
        cash_total - left
    );
    Ok(out)
}

#[derive(Clone)]
pub struct VmRefundHandler {
    db: Arc<dyn LNVpsDb>,
    node: Arc<dyn LightningNode>,
    pricing: PricingEngine,
    history: VmHistoryLogger,
}

impl VmRefundHandler {
    pub fn new(db: Arc<dyn LNVpsDb>, node: Arc<dyn LightningNode>, pricing: PricingEngine) -> Self {
        let history = VmHistoryLogger::new(db.clone());
        Self {
            db,
            node,
            pricing,
            history,
        }
    }

    /// Pay `lightning_invoice` out of the node and record it against the VM's
    /// payments.
    ///
    /// The invoice is the customer's, so it carries the amount: we refuse to
    /// pay more than the pro-rated refund the VM is owed, but paying less is
    /// the operator's call and is booked for what actually went out.
    pub async fn process(
        &self,
        vm_id: u64,
        admin_user_id: u64,
        refund_from_date: Option<DateTime<Utc>>,
        reason: Option<&str>,
        payment_method: &str,
        lightning_invoice: Option<&str>,
    ) -> Result<RefundOutcome> {
        ensure!(
            payment_method == "lightning",
            "only lightning refunds are automated; issue a {} refund in the provider's dashboard \
             and record it against the payment it reverses",
            payment_method
        );

        let invoice = lightning_invoice
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("a lightning refund needs an invoice to pay"))?;
        let parsed = Bolt11Invoice::from_str(invoice)
            .map_err(|e| anyhow!("invalid lightning invoice: {}", e))?;
        ensure!(!parsed.is_expired(), "lightning invoice has expired");
        let pay_msat = parsed
            .amount_milli_satoshis()
            .ok_or_else(|| anyhow!("lightning invoice must specify an amount"))?;

        let vm = self.db.get_vm(vm_id).await?;
        ensure!(!vm.deleted, "VM {} is already deleted", vm_id);

        // The quote is the ceiling, not the amount: it is what the unused time
        // is worth today, and paying beyond it would refund time the customer
        // never bought.
        let from_date = refund_from_date.unwrap_or_else(Utc::now);
        let quote = self
            .pricing
            .calculate_vm_refund_amount_from_date(vm_id, PaymentMethod::Lightning, from_date)
            .await?;
        let owed_msat = quote.amount.value();
        ensure!(
            pay_msat <= owed_msat,
            "invoice asks for {} msat but VM {} is only owed {} msat from {}",
            pay_msat,
            vm_id,
            owed_msat,
            from_date
        );

        // Booked in the currency the customer was charged in, converted at the
        // same rate the quote used, so the amount on the ledger and the amount
        // that left the node describe one event.
        let booked = quote.rate.convert(CurrencyAmount::millisats(pay_msat))?;
        let currency = booked.currency().to_string();
        // Conversion rounds to the nearest minor unit, so a small enough
        // invoice is worth nothing in the charged currency. Paying it would
        // move money that no refund row could account for.
        ensure!(
            booked.value() > 0,
            "invoice of {} msat rounds to zero {}, too small to refund",
            pay_msat,
            currency
        );

        let plan = self
            .allocation(vm_id, &currency, booked.value())
            .await
            .map_err(|e| anyhow!("VM {} refund cannot be booked, nothing paid: {}", vm_id, e))?;
        let planned: u64 = plan.iter().map(|s| s.amount).sum();
        let owed = quote.rate.convert(CurrencyAmount::millisats(owed_msat))?;
        ensure!(
            planned <= owed.value(),
            "invoice of {} msat reverses {} {} including credit, but VM {} is only owed {} {}",
            pay_msat,
            planned,
            currency,
            vm_id,
            owed.value(),
            currency
        );

        let paid = self
            .node
            .pay_invoice(PayInvoiceRequest {
                invoice: invoice.to_string(),
                timeout_seconds: Some(PAYOUT_TIMEOUT_SECONDS),
            })
            .await?;
        let preimage = paid.payment_preimage.map(|p| p.trim().to_string());
        info!(
            "Refunded {} msat to VM {}'s owner (fee {} msat, preimage {:?})",
            pay_msat, vm_id, paid.fee_msat, preimage
        );

        // Past this line the money is gone. Every remaining failure is written
        // to the log with the preimage and returned, because the refund still
        // has to be recorded — by hand through the manual endpoint if these
        // writes cannot do it.
        let refunded_at = Utc::now();
        let mut refund_rows = 0;
        let mut booked_amount = 0;
        let mut credit_returned = 0;
        let mut failures = Vec::new();
        for RefundShare {
            payment: original,
            amount,
            credit,
            ..
        } in plan
        {
            let row = build_refund_row(
                &original,
                amount,
                refunded_at,
                admin_user_id,
                RefundEvidence {
                    reason,
                    external_ref: preimage.as_deref(),
                    instrument: Some(invoice),
                },
            );
            if let Err(e) = self.db.insert_subscription_payment(&row).await {
                error!(
                    "PAID BUT UNRECORDED: refund of {} {} against payment {} for VM {} (preimage \
                     {:?}) could not be written: {}",
                    amount,
                    row.currency,
                    hex::encode(&original.id),
                    vm_id,
                    preimage,
                    e
                );
                failures.push(format!("{}: {}", hex::encode(&original.id), e));
                continue;
            }
            booked_amount += amount;
            refund_rows += 1;

            if credit > 0 {
                match self
                    .db
                    .adjust_account_credit(
                        original.user_id,
                        credit as i64,
                        "refund",
                        Some(&format!(
                            "VM {} refund of payment {}",
                            vm_id,
                            hex::encode(&original.id)
                        )),
                    )
                    .await
                {
                    Ok(_) => credit_returned += credit,
                    Err(e) => {
                        error!(
                            "Refund of payment {} for VM {} owes {} account credit that could not be returned: {}",
                            hex::encode(&original.id),
                            vm_id,
                            credit,
                            e
                        );
                        failures.push(format!("credit {}: {}", hex::encode(&original.id), e));
                    }
                }
            }

            if let Err(e) = self
                .history
                .log_vm_refunded(
                    vm_id,
                    Some(admin_user_id),
                    &original.id,
                    &row.id,
                    amount,
                    &row.currency,
                    reason,
                    None,
                )
                .await
            {
                // The accounting row is committed; losing its audit line must
                // not fail the refund on top of it.
                error!("Refund recorded but VM history entry failed for VM {vm_id}: {e}");
            }
        }

        if !failures.is_empty() {
            bail!(
                "VM {} was paid {} msat (preimage {:?}) but {} of the refund could not be \
                 recorded — record it by hand against: {}",
                vm_id,
                pay_msat,
                preimage,
                planned - booked_amount,
                failures.join(", ")
            );
        }

        Ok(RefundOutcome {
            amount_msat: pay_msat,
            fee_msat: paid.fee_msat,
            preimage,
            booked_amount,
            currency,
            refund_rows,
            credit_returned,
        })
    }

    /// Which of the VM's payments the refund comes off, newest first.
    ///
    /// Newest first because a refund of unused time reverses the period that
    /// was most recently bought; unwinding an older payment would return VAT
    /// from a period that is more likely already declared.
    async fn allocation(
        &self,
        vm_id: u64,
        currency: &str,
        amount: u64,
    ) -> Result<Vec<RefundShare>> {
        let mut payments: Vec<SubscriptionPayment> = self
            .db
            .list_vm_subscription_payments(vm_id)
            .await?
            .into_iter()
            // A refund reverses money we actually took, in the currency it was
            // taken in. Unpaid rows are not revenue and refunds are not
            // refundable.
            .filter(|p| p.is_paid && !p.payment_type.is_refund() && p.currency == currency)
            .collect();
        payments.sort_by_key(|p| std::cmp::Reverse(p.created));

        let mut candidates = Vec::with_capacity(payments.len());
        for payment in payments {
            let existing = self.db.list_refunds_for_payment(&payment.id).await?;
            let remaining = refundable_remaining(&payment, &existing);
            if remaining > 0 {
                let debit = self
                    .db
                    .get_account_credit_debit_by_payment(&payment.id)
                    .await?;
                candidates.push(RefundCandidate {
                    payment,
                    remaining,
                    debit,
                });
            }
        }
        allocate_cash_refund(&candidates, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use futures::Stream;
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    use lnvps_api_common::{ExchangeRateService, MockDb, MockExchangeRate, VatClient};
    use lnvps_db::{LNVpsDbBase, SubscriptionPaymentType, Vm};
    use payments_rs::lightning::{
        AddInvoiceRequest, AddInvoiceResponse, InvoiceUpdate, PayInvoiceResponse,
    };
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// A node that records what it was asked to pay and can be told to fail,
    /// so a test can tell "refused before paying" from "paid then failed".
    #[derive(Default)]
    struct PayNode {
        paid: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait]
    impl LightningNode for PayNode {
        async fn add_invoice(&self, _req: AddInvoiceRequest) -> anyhow::Result<AddInvoiceResponse> {
            unimplemented!()
        }

        async fn cancel_invoice(&self, _id: &[u8]) -> anyhow::Result<()> {
            unimplemented!()
        }

        async fn pay_invoice(&self, req: PayInvoiceRequest) -> anyhow::Result<PayInvoiceResponse> {
            if self.fail {
                bail!("no route");
            }
            let invoice = Bolt11Invoice::from_str(&req.invoice)
                .map_err(|e| anyhow!("invalid invoice: {}", e))?;
            self.paid.lock().unwrap().push(req.invoice.clone());
            Ok(PayInvoiceResponse {
                payment_hash: hex::encode(invoice.payment_hash().to_byte_array()),
                payment_preimage: Some("aa".repeat(32)),
                amount_msat: invoice.amount_milli_satoshis().unwrap_or(0),
                fee_msat: 1_000,
            })
        }

        async fn subscribe_invoices(
            &self,
            _from_payment_hash: Option<Vec<u8>>,
        ) -> anyhow::Result<Pin<Box<dyn Stream<Item = InvoiceUpdate> + Send>>> {
            unimplemented!()
        }
    }

    use bitcoin::hashes::Hash;

    /// A signed regtest invoice for `msat`, so the amount and expiry checks
    /// run against a real BOLT11 rather than a fixture string.
    fn invoice_for(msat: u64) -> String {
        const NODE_KEY: [u8; 32] = [0xcd; 32];
        let secret: [u8; 32] = [7u8; 32];
        InvoiceBuilder::new(Currency::Regtest)
            .description("refund".to_string())
            .payment_hash(bitcoin::hashes::sha256::Hash::from_slice(&secret).unwrap())
            .payment_secret(PaymentSecret(secret))
            .duration_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap())
            .expiry_time(Duration::from_secs(3600))
            .min_final_cltv_expiry_delta(144)
            .amount_milli_satoshis(msat)
            .build_signed(|s| {
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&NODE_KEY).unwrap();
                bitcoin::secp256k1::Secp256k1::signing_only().sign_ecdsa_recoverable(s, &sk)
            })
            .unwrap()
            .to_string()
    }

    /// A handler at a fixed 100,000 EUR/BTC, so €1 is exactly 1,000,000 msat.
    async fn handler(db: Arc<dyn LNVpsDb>, node: Arc<PayNode>) -> VmRefundHandler {
        let rates = Arc::new(MockExchangeRate::new());
        rates
            .set_rate(
                lnvps_api_common::Ticker(
                    payments_rs::currency::Currency::BTC,
                    payments_rs::currency::Currency::EUR,
                ),
                100_000.0,
            )
            .await;
        let pricing = PricingEngine::new(db.clone(), rates, VatClient::new());
        VmRefundHandler::new(db, node, pricing)
    }

    /// A VM with 15 days left on its subscription and one paid renewal of
    /// `amount` cents behind it.
    async fn vm_with_payment(db: &MockDb, amount: u64, tax: u64) -> (Vm, SubscriptionPayment) {
        let user_id = db.upsert_user(&[0u8; 32]).await.unwrap();
        db.user_ssh_keys.lock().await.insert(
            1,
            lnvps_db::UserSshKey {
                id: 1,
                user_id,
                name: "test".to_string(),
                key_data: "ssh-rsa AAA".into(),
                created: Utc::now(),
            },
        );

        let expires = Utc::now() + chrono::Duration::days(15);
        let (sub_id, line_items) = db
            .insert_subscription_with_line_items(
                &lnvps_db::Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "vm".to_string(),
                    description: None,
                    created: Utc::now() - chrono::Duration::days(15),
                    expires: Some(expires),
                    is_active: true,
                    is_setup: true,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: lnvps_db::IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![lnvps_db::SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: lnvps_db::LineItemType::Vps,
                    name: "vm".to_string(),
                    description: None,
                    amount: 100,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await
            .unwrap();

        let vm_id = db
            .insert_vm(&Vm {
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                ssh_key_id: Some(1),
                disk_id: 1,
                subscription_line_item_id: line_items[0],
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        let vm = db.get_vm(vm_id).await.unwrap();

        let payment = SubscriptionPayment {
            id: vec![4u8; 32],
            subscription_id: sub_id,
            user_id: vm.user_id,
            created: Utc::now() - chrono::Duration::days(15),
            expires,
            amount,
            currency: "EUR".to_string(),
            payment_method: PaymentMethod::Lightning,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: "".into(),
            external_id: None,
            is_paid: true,
            rate: 100_000.0,
            time_value: Some(2_592_000),
            metadata: None,
            tax,
            processing_fee: 0,
            paid_at: Some(Utc::now() - chrono::Duration::days(15)),
            tax_rate: Some(23.0),
            tax_country_code: Some("IRL".to_string()),
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        };
        db.insert_subscription_payment(&payment).await.unwrap();
        (vm, payment)
    }

    /// The happy path: the invoice is paid once and the refund lands on the
    /// payment it reverses, at that payment's own currency and VAT rate.
    #[tokio::test]
    async fn pays_the_invoice_and_books_it_against_the_payment() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db.clone(), node.clone()).await;

        // €0.50 at the mock rate of 100,000 EUR/BTC is 500,000 msat.
        let invoice = invoice_for(500_000);
        let outcome = handler
            .process(1, 9, None, Some("e2e"), "lightning", Some(&invoice))
            .await
            .expect("refund");

        assert_eq!(node.paid.lock().unwrap().len(), 1, "paid exactly once");
        assert_eq!(outcome.amount_msat, 500_000);
        assert_eq!(outcome.currency, "EUR");
        assert_eq!(outcome.booked_amount, 50, "€0.50 booked in cents");
        assert_eq!(outcome.refund_rows, 1);

        let refunds = db.list_refunds_for_payment(&payment.id).await.unwrap();
        assert_eq!(refunds.len(), 1);
        let refund = &refunds[0];
        assert_eq!(refund.amount + refund.tax, 50, "gross returned");
        assert!(refund.tax > 0, "the VAT inside the refund is reversed");
        assert_eq!(refund.currency, "EUR");
        assert_eq!(refund.rate, payment.rate, "frozen at the charged rate");
        assert!(refund.payment_type.is_refund());
        assert_eq!(refund.time_value, None, "a refund buys no time");
        assert_eq!(
            refund.metadata.as_ref().unwrap()["refund"]["external_ref"],
            "aa".repeat(32),
            "the preimage is the proof the money moved"
        );
        assert_eq!(
            refund.external_data.as_str(),
            invoice,
            "the invoice that was paid out"
        );
    }

    /// An invoice for more than the VM is owed is refused, and nothing is
    /// paid: the customer's invoice is not allowed to set the amount.
    #[tokio::test]
    async fn refuses_an_invoice_larger_than_the_refund_owed() {
        let mock = MockDb::default();
        vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db, node.clone()).await;

        let err = handler
            .process(
                1,
                9,
                None,
                None,
                "lightning",
                Some(&invoice_for(500_000_000)),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("only owed"), "{err}");
        assert!(node.paid.lock().unwrap().is_empty(), "nothing was paid");
    }

    /// With no payment to book against, the refund is refused before the node
    /// is touched — money must never leave with nowhere to record it.
    #[tokio::test]
    async fn refuses_before_paying_when_there_is_nothing_to_book_against() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        {
            // Everything on that payment has already been refunded.
            let mut payments = mock.subscription_payments.lock().await;
            let mut spent = payment.clone();
            spent.id = vec![5u8; 32];
            spent.payment_type = SubscriptionPaymentType::Refund;
            spent.refunded_payment_id = Some(payment.id.clone());
            payments.push(spent);
        }
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db, node.clone()).await;

        let err = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(500_000)))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing paid"), "{err}");
        assert!(node.paid.lock().unwrap().is_empty(), "nothing was paid");
    }

    /// An invoice worth less than one minor unit of the charged currency is
    /// refused before paying: it would send money that rounds to nothing on
    /// the ledger, leaving a paid-out refund with no row behind it.
    #[tokio::test]
    async fn refuses_an_invoice_that_rounds_to_zero_in_the_charged_currency() {
        let mock = MockDb::default();
        vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db, node.clone()).await;

        // At 100,000 EUR/BTC one cent is 10,000 msat, so 4,000 msat is worth
        // less than the smallest amount that can be booked.
        let err = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(4_000)))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("rounds to zero"), "{err}");
        assert!(node.paid.lock().unwrap().is_empty(), "nothing was paid");

        // One cent exactly is still refundable.
        let outcome = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(10_000)))
            .await
            .expect("one cent refund");
        assert_eq!(outcome.booked_amount, 1);
        assert_eq!(outcome.refund_rows, 1);
    }

    /// Non-Lightning methods are not automated, and say where to record them.
    #[tokio::test]
    async fn refuses_methods_it_cannot_pay() {
        let mock = MockDb::default();
        vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db, node.clone()).await;

        let err = handler
            .process(1, 9, None, None, "revolut", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("only lightning"), "{err}");
        assert!(node.paid.lock().unwrap().is_empty());
    }

    /// A refund is split across payments, newest first, when one cannot absorb
    /// it alone.
    #[tokio::test]
    async fn splits_across_payments_newest_first() {
        let mock = MockDb::default();
        let (_vm, newest) = vm_with_payment(&mock, 1230, 230).await;
        let older = {
            let mut older = newest.clone();
            older.id = vec![6u8; 32];
            older.amount = 60;
            older.tax = 0;
            older.created = newest.created - chrono::Duration::days(30);
            let mut payments = mock.subscription_payments.lock().await;
            payments.push(older.clone());
            older
        };
        // Only 20 cents left on the newest payment.
        {
            let mut partial = newest.clone();
            partial.id = vec![7u8; 32];
            partial.amount = 1210;
            partial.payment_type = SubscriptionPaymentType::Refund;
            partial.refunded_payment_id = Some(newest.id.clone());
            mock.subscription_payments.lock().await.push(partial);
        }
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db.clone(), node.clone()).await;

        // €0.50 = 50 cents: 20 comes off the newest, the remaining 30 off the
        // older payment.
        let outcome = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(500_000)))
            .await
            .expect("refund");
        assert_eq!(outcome.booked_amount, 50);
        assert_eq!(outcome.refund_rows, 2);
        assert_eq!(
            db.list_refunds_for_payment(&newest.id)
                .await
                .unwrap()
                .iter()
                .filter(|r| r.amount + r.tax == 20)
                .count(),
            1
        );
        let older_refunds = db.list_refunds_for_payment(&older.id).await.unwrap();
        assert_eq!(older_refunds.len(), 1);
        assert_eq!(older_refunds[0].amount + older_refunds[0].tax, 30);
    }

    fn debit(
        payment: &SubscriptionPayment,
        payment_amount: u64,
        amount: u64,
    ) -> lnvps_db::AccountCreditDebit {
        lnvps_db::AccountCreditDebit {
            user_id: payment.user_id,
            subscription_payment_id: Some(payment.id.clone()),
            amount,
            currency: "BTC".to_string(),
            payment_amount,
            settled: true,
            ..Default::default()
        }
    }

    fn sale(amount: u64) -> SubscriptionPayment {
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
            time_value: None,
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        }
    }

    fn candidate(amount: u64, debit: Option<lnvps_db::AccountCreditDebit>) -> RefundCandidate {
        RefundCandidate {
            payment: sale(amount),
            remaining: amount,
            debit,
        }
    }

    #[test]
    fn cash_refund_returns_the_credit_share_as_credit() {
        let p = sale(1000);
        let plan =
            allocate_cash_refund(&[candidate(1000, Some(debit(&p, 500, 5_000_000)))], 200).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(
            (plan[0].amount, plan[0].cash, plan[0].credit),
            (400, 200, 2_000_000)
        );

        let plan = allocate_cash_refund(&[candidate(1000, None)], 200).unwrap();
        assert_eq!(
            (plan[0].amount, plan[0].cash, plan[0].credit),
            (200, 200, 0)
        );
    }

    #[test]
    fn cash_refund_cannot_take_more_cash_than_was_paid() {
        let p = sale(1000);
        let half = [candidate(1000, Some(debit(&p, 500, 5_000_000)))];
        let plan = allocate_cash_refund(&half, 500).unwrap();
        assert_eq!(
            (plan[0].amount, plan[0].cash, plan[0].credit),
            (1000, 500, 5_000_000)
        );
        assert!(allocate_cash_refund(&half, 501).is_err());

        let all_credit = [candidate(1000, Some(debit(&p, 1000, 10_000_000)))];
        assert!(allocate_cash_refund(&all_credit, 1).is_err());
        assert!(allocate_cash_refund(&all_credit, 0).unwrap().is_empty());

        let mut unsettled = debit(&p, 1000, 10_000_000);
        unsettled.settled = false;
        let plan = allocate_cash_refund(&[candidate(1000, Some(unsettled))], 300).unwrap();
        assert_eq!((plan[0].amount, plan[0].credit), (300, 0));
    }

    #[tokio::test]
    async fn a_refund_of_a_credit_funded_payment_returns_credit() {
        let mock = MockDb::default();
        let (vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        mock.account_credit_debits
            .lock()
            .await
            .push(debit(&payment, 730, 7_300_000));
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let handler = handler(db.clone(), node.clone()).await;

        let err = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(500_000)))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("including credit"), "{err}");
        assert!(node.paid.lock().unwrap().is_empty());

        let outcome = handler
            .process(1, 9, None, None, "lightning", Some(&invoice_for(300_000)))
            .await
            .expect("refund");
        assert_eq!(
            outcome.amount_msat, 300_000,
            "only the cash share is paid out"
        );
        assert_eq!(outcome.booked_amount, 60);
        assert_eq!(outcome.credit_returned, 300_000);
        assert_eq!(
            db.get_account_credit(vm.user_id).await.unwrap().balance,
            300_000
        );
        let refunds = db.list_refunds_for_payment(&payment.id).await.unwrap();
        assert_eq!(refunds[0].amount + refunds[0].tax, 60);
        let (events, _) = db
            .list_account_credit_events(vm.user_id, 10, 0)
            .await
            .unwrap();
        assert_eq!(
            (events[0].kind.as_str(), events[0].amount),
            ("refund", 300_000)
        );
    }

    /// A failed payment writes no refund row: the ledger only ever records
    /// money that actually moved.
    #[tokio::test]
    async fn a_failed_payment_books_nothing() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode {
            fail: true,
            ..Default::default()
        });
        let handler = handler(db.clone(), node).await;

        assert!(
            handler
                .process(1, 9, None, None, "lightning", Some(&invoice_for(500_000)))
                .await
                .is_err()
        );
        assert!(
            db.list_refunds_for_payment(&payment.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
