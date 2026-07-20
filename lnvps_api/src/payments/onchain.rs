//! On-chain Bitcoin payment watcher.
//!
//! Subscribes to chain events from the [`OnChainProvider`] (the LND wallet)
//! and settles [`SubscriptionPayment`]s when deposits confirm.
//!
//! # Correlation
//!
//! LND cannot label on-chain outputs, so deposits are correlated back to
//! payments by **receive address**: each on-chain payment stores its derived
//! address encrypted in `external_data`, and the watcher matches updates
//! against those in memory.
//!
//! # Delivery / de-duplication
//!
//! The provider stream is at-least-once and replayable; exactly-once
//! accounting is achieved by storing the deposit's **outpoint**
//! (`{txid}:{vout}`) in `external_id` (unique index) and skipping any update
//! whose outpoint is already settled. The txid alone is not enough: one
//! transaction can pay several watched addresses at once — each output is a
//! distinct deposit that must settle its own payment.
//!
//! # Pricing (issue #109)
//!
//! On-chain funds can arrive at any time and for any amount; deposits are
//! never rejected. The quote on the pending payment is **discarded** when the
//! deposit is discovered: pricing (`time_value`, `tax`, `processing_fee`,
//! `rate`) is re-generated from the received amount at the rates current at
//! discovery, exactly like an LNURL top-up (`PricingEngine::get_cost_by_amount`).
//!
//! - The re-generation happens at `Detected` (0-conf, first sight of the tx),
//!   so time-to-confirm never matters to the customer. `Confirmed` then just
//!   settles. If the `Detected` event was never seen (e.g. the tx confirmed
//!   while the watcher was down), pricing is generated at confirmation
//!   instead — the moment we discover it.
//! - A deposit to an address whose payment already settled (address reuse)
//!   automatically inserts a **new** renewal payment, priced the same way.
//! - Subscriptions without a VM have no amount→cost pricing; they fall back
//!   to scaling the original quote by the value received at the current rate.

use crate::subscription::SubscriptionHandler;
use anyhow::{Result, bail, ensure};
use chrono::Utc;
use futures::StreamExt;
use lnvps_api_common::{CostResult, WorkJob};
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{debug, error, info, warn};
use payments_rs::currency::{Currency, CurrencyAmount};
use payments_rs::onchain::{ChainPaymentUpdate, OnChainProvider};
use std::str::FromStr;
use std::sync::Arc;

pub struct OnChainPaymentHandler {
    provider: Arc<dyn OnChainProvider>,
    db: Arc<dyn LNVpsDb>,
    sub_handler: SubscriptionHandler,
    /// Deposits to deleted VMs already reported to admins (in-memory only:
    /// these deposits are ignored database-wise and handled out of band, this
    /// set just stops stream replays from re-notifying within one process).
    reported_deposits: tokio::sync::Mutex<std::collections::HashSet<String>>,
}

/// Scale `value` by `received / expected` (u128 intermediate, no overflow).
///
/// Only used by the no-VM quote-scaling fallback in [`OnChainPaymentHandler::regenerate`];
/// remove once subscription-level amount→cost pricing exists (issue #181).
fn pro_rate(value: u64, received: u64, expected: u64) -> u64 {
    debug_assert!(expected > 0);
    (value as u128 * received as u128 / expected as u128) as u64
}

/// Scale `value` by an arbitrary ratio, flooring to whole units.
///
/// Only used by the no-VM quote-scaling fallback; see [`pro_rate`].
fn pro_rate_f64(value: u64, ratio: f64) -> u64 {
    (value as f64 * ratio).floor() as u64
}

/// Unique key for one deposit: the standard outpoint notation `{txid}:{vout}`.
///
/// One transaction can pay multiple watched addresses (one output each), so
/// the txid alone does not identify a deposit.
fn deposit_key(txid: &str, vout: u32) -> String {
    format!("{}:{}", txid, vout)
}

impl OnChainPaymentHandler {
    pub fn new(
        provider: Arc<dyn OnChainProvider>,
        db: Arc<dyn LNVpsDb>,
        sub_handler: SubscriptionHandler,
    ) -> Self {
        Self {
            provider,
            db,
            sub_handler,
            reported_deposits: Default::default(),
        }
    }

    /// Find the payment a deposit belongs to: the most recent on-chain payment
    /// whose stored receive address matches.
    async fn payment_for_address(&self, address: &str) -> Result<Option<SubscriptionPayment>> {
        Ok(self
            .db
            .list_subscription_payments_by_method(PaymentMethod::OnChain)
            .await?
            .into_iter()
            .filter(|p| p.external_data.as_str() == address)
            .max_by_key(|p| p.created))
    }

    /// Current BTC exchange rate for the payment's subscription currency.
    async fn current_rate(&self, payment: &SubscriptionPayment) -> Result<f32> {
        let sub = self.db.get_subscription(payment.subscription_id).await?;
        let sub_currency = Currency::from_str(&sub.currency)
            .map_err(|e| anyhow::anyhow!("Invalid subscription currency: {}", e))?;
        Ok(self
            .sub_handler
            .pricing_engine()
            .get_ticker(Currency::BTC, sub_currency)
            .await?
            .rate)
    }

    /// Re-generate a payment's pricing from the gross msats received, at the
    /// rates current right now. The original quote is discarded.
    ///
    /// VM-backed subscriptions price through the pricing engine exactly like
    /// LNURL top-ups. Subscriptions without a VM have no amount→cost pricing
    /// and fall back to scaling the original quote by the value received.
    async fn regenerate(&self, payment: &mut SubscriptionPayment, gross_msat: u64) -> Result<()> {
        match self
            .db
            .get_vm_by_subscription(payment.subscription_id)
            .await
        {
            Ok(vm) => {
                // The engine prices from the net amount and adds tax on top;
                // split the gross deposit using the frozen tax rate.
                let tax_pct = payment.tax_rate.unwrap_or(0.0) as f64;
                let net = (gross_msat as f64 / (1.0 + tax_pct / 100.0)).floor() as u64;
                let cost = self
                    .sub_handler
                    .pricing_engine()
                    .get_cost_by_amount(
                        vm.id,
                        CurrencyAmount::millisats(net),
                        PaymentMethod::OnChain,
                    )
                    .await?;
                let p = match cost {
                    CostResult::New(p) => p,
                    CostResult::Existing(_) => bail!("Unexpected existing cost result"),
                };
                payment.time_value = Some(p.time_value);
                payment.rate = p.rate.rate;
                // Components always sum to exactly what arrived
                payment.tax = p.tax.min(gross_msat);
                payment.processing_fee = p.processing_fee.min(gross_msat - payment.tax);
                payment.amount = gross_msat - payment.tax - payment.processing_fee;
            }
            Err(_) => {
                // No VM: scale the original quote by the value received at
                // the current rate.
                let expected = payment.amount + payment.tax + payment.processing_fee;
                ensure!(
                    expected > 0,
                    "Payment {} has zero expected amount",
                    hex::encode(&payment.id)
                );
                ensure!(
                    payment.rate > 0.0,
                    "Payment {} has invalid quoted rate",
                    hex::encode(&payment.id)
                );
                let rate_now = self.current_rate(payment).await?;
                let ratio =
                    (gross_msat as f64 * rate_now as f64) / (expected as f64 * payment.rate as f64);
                payment.tax = pro_rate(payment.tax, gross_msat, expected);
                payment.processing_fee = pro_rate(payment.processing_fee, gross_msat, expected);
                payment.amount = gross_msat - payment.tax - payment.processing_fee;
                payment.time_value = payment.time_value.map(|tv| pro_rate_f64(tv, ratio));
                payment.rate = rate_now;
            }
        }
        Ok(())
    }

    /// Handle a deposit **first seen** in the mempool (0-conf `Detected`).
    ///
    /// Re-generates the pending payment's pricing from the received amount at
    /// the current rate and tags it with the deposit key (`external_id`), so
    /// settlement at `Confirmed` needs no further pricing — time to confirm
    /// does not matter to the customer.
    async fn handle_detected(
        &self,
        address: &str,
        txid: &str,
        vout: u32,
        amount_msat: u64,
    ) -> Result<()> {
        let key = deposit_key(txid, vout);
        // Already priced or settled (replayed event)
        if self
            .db
            .get_subscription_payment_by_ext_id(&key)
            .await
            .is_ok()
        {
            return Ok(());
        }
        let Some(mut payment) = self.payment_for_address(address).await? else {
            return Ok(());
        };
        // Address-reuse deposits are handled at confirmation; only a pending
        // payment is re-priced here.
        if payment.is_paid {
            return Ok(());
        }
        // Deposits to deleted VMs are ignored; Confirmed sends the admin alert.
        if let Ok(vm) = self
            .db
            .get_vm_by_subscription(payment.subscription_id)
            .await
            && vm.deleted
        {
            return Ok(());
        }
        self.regenerate(&mut payment, amount_msat).await?;
        info!(
            "Deposit {} detected: priced payment {} at rate {} for {} msat ({}s)",
            key,
            hex::encode(&payment.id),
            payment.rate,
            amount_msat,
            payment.time_value.unwrap_or(0)
        );
        payment.external_id = Some(key);
        self.db.update_subscription_payment(&payment).await?;
        Ok(())
    }

    /// Notify the admins about a deposit that arrived for a deleted VM.
    ///
    /// Database-wise the deposit is ignored — nothing is settled or recorded.
    /// The sender is expected to contact support so it can be resolved out of
    /// band.
    async fn notify_deleted_vm_deposit(
        &self,
        payment: SubscriptionPayment,
        vm_id: u64,
        address: &str,
        key: &str,
        amount_msat: u64,
    ) -> Result<()> {
        if !self.reported_deposits.lock().await.insert(key.to_string()) {
            debug!("Deposit {} for deleted VM {} already reported", key, vm_id);
            return Ok(());
        }
        warn!(
            "Deposit {} of {} msat arrived for deleted VM {} (payment {}), notifying admins",
            key,
            amount_msat,
            vm_id,
            hex::encode(&payment.id)
        );
        if let Err(e) = self
            .sub_handler
            .work_commander()
            .send(WorkJob::SendAdminNotification {
                title: Some(format!("[VM{}] On-chain deposit to deleted VM", vm_id)),
                message: format!(
                    "An on-chain deposit of {} sats (outpoint {}) arrived for deleted VM #{} (user {}).\n\
                     Receive address: {}\n\
                     The deposit has NOT been credited. The sender is expected to \
                     contact support so it can be resolved out of band.",
                    amount_msat / 1000,
                    key,
                    vm_id,
                    payment.user_id,
                    address
                ),
            })
            .await
        {
            warn!("Failed to queue admin notification for deposit {}: {}", key, e);
        }
        Ok(())
    }

    /// Handle a confirmed deposit of `amount_msat` to `address` in tx `txid`.
    async fn handle_deposit(
        &self,
        address: &str,
        txid: &str,
        vout: u32,
        amount_msat: u64,
    ) -> Result<()> {
        // De-dupe: the stream is at-least-once, a settled (txid, address)
        // deposit was already handled. An *unpaid* match is the pending
        // payment priced at Detected.
        let key = deposit_key(txid, vout);
        let priced = match self.db.get_subscription_payment_by_ext_id(&key).await {
            Ok(p) if p.is_paid => {
                debug!("Skipping already processed deposit {}", key);
                return Ok(());
            }
            Ok(p) => Some(p),
            Err(_) => None,
        };

        let already_priced = priced.is_some();
        let payment = match priced {
            Some(p) => p,
            None => match self.payment_for_address(address).await? {
                Some(p) => p,
                None => {
                    debug!("Deposit {} to unknown address {}, ignoring", txid, address);
                    return Ok(());
                }
            },
        };

        // A deposit for a deleted VM is ignored database-wise: just alert the
        // admins — the sender is expected to contact support so it can be
        // resolved out of band.
        if let Ok(vm) = self
            .db
            .get_vm_by_subscription(payment.subscription_id)
            .await
            && vm.deleted
        {
            return self
                .notify_deleted_vm_deposit(payment, vm.id, address, &key, amount_msat)
                .await;
        }

        if !payment.is_paid {
            let mut payment = payment;
            // Price now unless Detected already did (and for the same gross
            // amount — a replaced tx could change the output value).
            let priced_gross = payment.amount + payment.tax + payment.processing_fee;
            if !already_priced || priced_gross != amount_msat {
                self.regenerate(&mut payment, amount_msat).await?;
            }
            info!(
                "Settling on-chain payment {}: {} msat at rate {} ({}s)",
                hex::encode(&payment.id),
                amount_msat,
                payment.rate,
                payment.time_value.unwrap_or(0)
            );
            payment.external_id = Some(key);
            self.db.update_subscription_payment(&payment).await?;
            self.sub_handler.complete_payment(&payment).await?;
        } else {
            // Address reuse after settlement: insert a new renewal payment,
            // priced from the received amount (issue #109).
            info!(
                "New deposit {} of {} msat to settled address of payment {}, creating renewal",
                txid,
                amount_msat,
                hex::encode(&payment.id)
            );
            let new_id: [u8; 32] = rand::random();
            let mut renewal = SubscriptionPayment {
                id: new_id.to_vec(),
                subscription_id: payment.subscription_id,
                user_id: payment.user_id,
                created: Utc::now(),
                expires: Utc::now(),
                // Seed pricing from the settled payment; regenerate below
                // overwrites it (and uses it as the quote reference for the
                // no-VM fallback).
                amount: payment.amount,
                currency: payment.currency.clone(),
                payment_method: PaymentMethod::OnChain,
                payment_type: SubscriptionPaymentType::Renewal,
                external_data: address.into(),
                external_id: Some(key),
                is_paid: false,
                rate: payment.rate,
                time_value: payment.time_value,
                metadata: None,
                tax: payment.tax,
                processing_fee: payment.processing_fee,
                paid_at: None,
                tax_rate: payment.tax_rate,
                tax_country_code: payment.tax_country_code.clone(),
                tax_treatment: payment.tax_treatment.clone(),
                tax_evidence: payment.tax_evidence.clone(),
                tax_breakdown: payment.tax_breakdown.clone(),
            };
            self.regenerate(&mut renewal, amount_msat).await?;
            self.db.insert_subscription_payment(&renewal).await?;
            self.sub_handler.complete_payment(&renewal).await?;
        }
        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        info!("Listening for on-chain deposits");
        // Subscribe from the start; the deposit-key de-dupe above makes
        // replaying history harmless (at-least-once -> exactly-once).
        let mut stream = self.provider.subscribe_payments(None).await?;
        while let Some(update) = stream.next().await {
            match update {
                ChainPaymentUpdate::Confirmed {
                    address,
                    txid,
                    vout,
                    amount_msat,
                    ..
                } => {
                    if let Err(e) = self
                        .handle_deposit(&address, &txid, vout, amount_msat)
                        .await
                    {
                        error!("onchain deposit error for {}: {}", txid, e);
                    }
                }
                ChainPaymentUpdate::Detected {
                    address,
                    txid,
                    vout,
                    amount_msat,
                    confirmations,
                    ..
                } => {
                    debug!(
                        "Detected deposit {}:{} of {} msat to {} ({} confs)",
                        txid, vout, amount_msat, address, confirmations
                    );
                    // Price the payment at first sight of the tx
                    if let Err(e) = self
                        .handle_detected(&address, &txid, vout, amount_msat)
                        .await
                    {
                        error!("onchain detect error for {}: {}", txid, e);
                    }
                }
                ChainPaymentUpdate::Error(e) => bail!("onchain stream error: {}", e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{MockNode, MockOnChainProvider};
    use crate::settings::mock_settings;
    use anyhow::Result;
    use lnvps_api_common::{
        ChannelWorkCommander, ExchangeRateService, MockDb, MockExchangeRate, NewPaymentInfo,
        Ticker, VmStateCache,
    };
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionType, Vm,
    };
    use std::time::Duration;

    const ADDRESS: &str = "bcrt1qtestaddr0";
    const AMOUNT: u64 = 1_000_000;
    const TAX: u64 = 100_000;
    const EXPECTED: u64 = AMOUNT + TAX;
    const TIME_VALUE: u64 = 86_400;
    const RATE: f32 = 100_000.0;

    /// Build DB + handler with a subscription and one unpaid on-chain payment
    /// for [`ADDRESS`]. `with_vm` links a VM (template 1 / cost plan 1 from
    /// MockDb) so pricing regenerates through the engine; without it the
    /// watcher uses the quote-scaling fallback.
    async fn setup_with(
        with_vm: bool,
        quoted_rate: f32,
        current_rate: f32,
    ) -> Result<(
        Arc<MockDb>,
        Arc<MockOnChainProvider>,
        OnChainPaymentHandler,
        SubscriptionPayment,
        Arc<MockExchangeRate>,
    )> {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let provider = Arc::new(MockOnChainProvider::default());
        let rates = Arc::new(MockExchangeRate::default());
        rates.set_rate(Ticker::btc_rate("EUR")?, current_rate).await;

        let pubkey: [u8; 32] = [1u8; 32];
        let user_id = db.upsert_user(&pubkey).await?;
        let ssh_key_id = db
            .insert_user_ssh_key(&lnvps_db::UserSshKey {
                id: 0,
                name: "test".to_string(),
                user_id,
                created: Utc::now(),
                key_data: "ssh-rsa AAA==".into(),
            })
            .await?;

        let (sub_id, line_item_ids) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "test".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: false,
                    is_setup: false,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: false,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::Vps,
                    name: "vm renewal".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        if with_vm {
            db.insert_vm(&Vm {
                id: 0,
                host_id: 1,
                user_id,
                image_id: 1,
                template_id: Some(1),
                custom_template_id: None,
                subscription_line_item_id: line_item_ids[0],
                ssh_key_id: Some(ssh_key_id),
                disk_id: 1,
                mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
                deleted: false,
                ..Default::default()
            })
            .await?;
        }

        let payment = SubscriptionPayment {
            id: vec![42u8; 32],
            subscription_id: sub_id,
            user_id,
            created: Utc::now(),
            expires: Utc::now() + chrono::Duration::hours(1),
            amount: AMOUNT,
            currency: "BTC".to_string(),
            payment_method: PaymentMethod::OnChain,
            payment_type: SubscriptionPaymentType::Renewal,
            external_data: ADDRESS.into(),
            external_id: None,
            is_paid: false,
            rate: quoted_rate,
            time_value: Some(TIME_VALUE),
            metadata: None,
            tax: TAX,
            processing_fee: 0,
            paid_at: None,
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
        };
        db.insert_subscription_payment(&payment).await?;

        let sub = SubscriptionHandler::new(
            mock_settings(),
            db.clone(),
            node,
            provider.clone(),
            rates.clone(),
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;
        let handler = OnChainPaymentHandler::new(provider.clone(), db.clone(), sub);

        Ok((db, provider, handler, payment, rates))
    }

    /// VM-backed setup at [`RATE`].
    async fn setup() -> Result<(
        Arc<MockDb>,
        Arc<MockOnChainProvider>,
        OnChainPaymentHandler,
        SubscriptionPayment,
    )> {
        let (db, provider, handler, payment, _rates) = setup_with(true, RATE, RATE).await?;
        Ok((db, provider, handler, payment))
    }

    async fn get_payment(db: &MockDb, id: &[u8]) -> SubscriptionPayment {
        db.subscription_payments
            .lock()
            .await
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .expect("payment")
    }

    /// What the pricing engine would generate for `gross` msats right now.
    async fn engine_price(
        handler: &OnChainPaymentHandler,
        sub_id: u64,
        gross: u64,
    ) -> Result<NewPaymentInfo> {
        let vm = handler.db.get_vm_by_subscription(sub_id).await?;
        match handler
            .sub_handler
            .pricing_engine()
            .get_cost_by_amount(
                vm.id,
                CurrencyAmount::millisats(gross),
                PaymentMethod::OnChain,
            )
            .await?
        {
            CostResult::New(p) => Ok(p),
            CostResult::Existing(_) => bail!("unexpected existing"),
        }
    }

    /// The engine's time_value depends on Utc::now(); allow a small drift
    /// between the expectation call and the watcher's own call.
    fn assert_close(a: u64, b: u64) {
        assert!(
            a.abs_diff(b) <= 5,
            "expected {} ≈ {} (diff {})",
            a,
            b,
            a.abs_diff(b)
        );
    }

    #[test]
    fn test_pro_rate() {
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED, EXPECTED), TIME_VALUE);
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED / 2, EXPECTED), TIME_VALUE / 2);
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED * 2, EXPECTED), TIME_VALUE * 2);
        assert_eq!(pro_rate(0, EXPECTED, EXPECTED), 0);
        // u128 intermediate: no overflow on large values
        assert_eq!(pro_rate(u64::MAX, 1000, 1000), u64::MAX);
        assert_eq!(pro_rate_f64(100, 1.5), 150);
        assert_eq!(pro_rate_f64(100, 0.333), 33);
    }

    #[test]
    fn test_deposit_key() {
        // standard outpoint notation; txid alone is not the key
        assert_eq!(deposit_key("tx1", 0), "tx1:0");
        assert_ne!(deposit_key("tx1", 0), deposit_key("tx1", 1));
    }

    /// A confirmed deposit settles the pending payment with pricing
    /// re-generated by the engine (quote discarded).
    #[tokio::test]
    async fn test_deposit_settles_with_engine_pricing() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        let expect = engine_price(&handler, payment.subscription_id, EXPECTED).await?;

        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.external_id, Some(deposit_key("tx1", 0)));
        assert_eq!(p.rate, expect.rate.rate);
        assert_close(p.time_value.unwrap(), expect.time_value);
        // components sum to exactly what arrived
        assert_eq!(p.amount + p.tax + p.processing_fee, EXPECTED);
        Ok(())
    }

    /// Half the deposit buys half the time (engine pricing is linear).
    #[tokio::test]
    async fn test_partial_deposit_buys_less_time() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        let expect_full = engine_price(&handler, payment.subscription_id, EXPECTED).await?;

        handler
            .handle_deposit(ADDRESS, "tx1", 0, EXPECTED / 2)
            .await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_close(p.time_value.unwrap(), expect_full.time_value / 2);
        assert_eq!(p.amount + p.tax + p.processing_fee, EXPECTED / 2);
        Ok(())
    }

    /// A replayed deposit must not settle or create anything.
    #[tokio::test]
    async fn test_duplicate_deposit_skipped() -> Result<()> {
        let (db, _provider, handler, _payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;

        assert_eq!(db.subscription_payments.lock().await.len(), 1);
        Ok(())
    }

    /// Deposits to unknown addresses are ignored.
    #[tokio::test]
    async fn test_unknown_address_ignored() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler
            .handle_deposit("bcrt1qunknown", "tx1", 0, EXPECTED)
            .await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(!p.is_paid);
        assert_eq!(db.subscription_payments.lock().await.len(), 1);
        Ok(())
    }

    /// A deposit to an already-settled address inserts a new renewal payment
    /// priced from the received amount.
    #[tokio::test]
    async fn test_address_reuse_inserts_renewal() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;

        let expect = engine_price(&handler, payment.subscription_id, EXPECTED / 2).await?;
        handler
            .handle_deposit(ADDRESS, "tx2", 0, EXPECTED / 2)
            .await?;

        let payments = db.subscription_payments.lock().await.clone();
        assert_eq!(payments.len(), 2);
        let renewal = payments
            .iter()
            .find(|p| p.external_id == Some(deposit_key("tx2", 0)))
            .expect("renewal payment");
        assert!(renewal.is_paid);
        assert_ne!(renewal.id, payment.id);
        assert_eq!(renewal.payment_type, SubscriptionPaymentType::Renewal);
        assert_eq!(renewal.payment_method, PaymentMethod::OnChain);
        assert_eq!(renewal.subscription_id, payment.subscription_id);
        assert_eq!(renewal.external_data.as_str(), ADDRESS);
        assert_close(renewal.time_value.unwrap(), expect.time_value);
        assert_eq!(
            renewal.amount + renewal.tax + renewal.processing_fee,
            EXPECTED / 2
        );
        Ok(())
    }

    /// Pricing is generated when the tx is first seen (`Detected`): later
    /// rate moves before confirmation do not change the credited time.
    #[tokio::test]
    async fn test_detected_locks_pricing() -> Result<()> {
        let (db, _provider, handler, payment, rates) = setup_with(true, RATE, RATE).await?;
        let expect = engine_price(&handler, payment.subscription_id, EXPECTED).await?;

        // Tx first seen: payment re-priced in place and tagged
        handler.handle_detected(ADDRESS, "tx1", 0, EXPECTED).await?;
        let p = get_payment(&db, &payment.id).await;
        assert!(!p.is_paid);
        assert_eq!(p.external_id, Some(deposit_key("tx1", 0)));
        assert_eq!(p.rate, expect.rate.rate);
        assert_close(p.time_value.unwrap(), expect.time_value);
        let locked_time = p.time_value.unwrap();

        // Rate halves before the tx confirms -> the locked pricing stays
        rates.set_rate(Ticker::btc_rate("EUR")?, RATE / 2.0).await;
        handler.handle_detected(ADDRESS, "tx1", 0, EXPECTED).await?; // replay, no-op
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.rate, expect.rate.rate);
        assert_eq!(p.time_value, Some(locked_time));
        Ok(())
    }

    /// One transaction paying two watched addresses settles both payments:
    /// deposits are keyed by (txid, address), not txid alone.
    #[tokio::test]
    async fn test_same_txid_two_addresses() -> Result<()> {
        const ADDRESS2: &str = "bcrt1qtestaddr1";
        let (db, _provider, handler, payment) = setup().await?;
        // Second pending payment for another address
        let mut payment2 = payment.clone();
        payment2.id = vec![43u8; 32];
        payment2.external_data = ADDRESS2.into();
        db.insert_subscription_payment(&payment2).await?;

        // Both outputs of the same tx
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;
        handler.handle_deposit(ADDRESS2, "tx1", 1, EXPECTED).await?;

        let p1 = get_payment(&db, &payment.id).await;
        let p2 = get_payment(&db, &payment2.id).await;
        assert!(p1.is_paid);
        assert!(p2.is_paid);
        assert_eq!(p1.external_id, Some(deposit_key("tx1", 0)));
        assert_eq!(p2.external_id, Some(deposit_key("tx1", 1)));
        assert_ne!(p1.external_id, p2.external_id);
        Ok(())
    }

    /// Subscriptions without a VM fall back to scaling the original quote by
    /// value at the current rate.
    #[tokio::test]
    async fn test_no_vm_fallback_scales_quote() -> Result<()> {
        // Quoted at 100k EUR/BTC; rate doubled by discovery -> same msats are
        // worth twice the quoted value -> twice the time.
        let (db, _provider, handler, payment, _rates) = setup_with(false, RATE, RATE * 2.0).await?;
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.time_value, Some(TIME_VALUE * 2));
        assert_eq!(p.rate, RATE * 2.0);
        assert_eq!(p.amount + p.tax + p.processing_fee, EXPECTED);
        Ok(())
    }

    /// listen() drains scripted updates: Detected prices, Confirmed settles.
    #[tokio::test]
    async fn test_listen_processes_updates() -> Result<()> {
        let (db, provider, mut handler, payment) = setup().await?;
        provider.updates.lock().await.extend([
            ChainPaymentUpdate::Detected {
                address: ADDRESS.to_string(),
                txid: "tx1".to_string(),
                vout: 0,
                amount_msat: EXPECTED,
                confirmations: 0,
                label: None,
            },
            ChainPaymentUpdate::Confirmed {
                address: ADDRESS.to_string(),
                txid: "tx1".to_string(),
                vout: 0,
                amount_msat: EXPECTED,
                confirmations: 1,
                label: None,
            },
        ]);
        handler.listen().await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.external_id, Some(deposit_key("tx1", 0)));
        Ok(())
    }

    /// A deposit for a deleted VM is ignored database-wise; the admins are
    /// notified (once per deposit within a process) — the sender is expected
    /// to contact support so it can be resolved out of band.
    #[tokio::test]
    async fn test_deleted_vm_deposit_notifies_admin() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        // Delete the VM
        for vm in db.vms.lock().await.values_mut() {
            vm.deleted = true;
        }

        // Detected: silently ignored (no pricing/tagging), no notification
        handler.handle_detected(ADDRESS, "tx1", 0, EXPECTED).await?;
        let p = get_payment(&db, &payment.id).await;
        assert_eq!(p.external_id, None);

        // Confirmed: nothing touched in the database, one admin notification
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;
        let p = get_payment(&db, &payment.id).await;
        assert!(!p.is_paid, "payment must be untouched");
        assert_eq!(p.external_id, None);
        assert_eq!(p.metadata, None);
        assert_eq!(p.time_value, payment.time_value);
        assert_eq!(p.rate, payment.rate);

        let jobs = handler.sub_handler.work_commander().recv().await?;
        assert_eq!(jobs.len(), 1);
        match &jobs[0].job {
            WorkJob::SendAdminNotification { title, message } => {
                assert!(title.as_deref().unwrap_or("").contains("deleted VM"));
                assert!(message.contains("tx1:0"));
                assert!(message.contains(ADDRESS));
            }
            other => panic!("expected SendAdminNotification, got {:?}", other),
        }

        // Replayed Confirmed: no second notification
        handler.handle_deposit(ADDRESS, "tx1", 0, EXPECTED).await?;
        let no_job = tokio::time::timeout(
            Duration::from_millis(50),
            handler.sub_handler.work_commander().recv(),
        )
        .await;
        assert!(no_job.is_err(), "replay must not re-notify admins");

        // A second distinct deposit to the same address notifies again
        handler.handle_deposit(ADDRESS, "tx2", 0, EXPECTED).await?;
        let jobs = handler.sub_handler.work_commander().recv().await?;
        assert_eq!(jobs.len(), 1);
        Ok(())
    }

    /// A stream error bubbles up so the outer loop reconnects.
    #[tokio::test]
    async fn test_listen_stream_error_bails() -> Result<()> {
        let (_db, provider, mut handler, _payment) = setup().await?;
        provider
            .updates
            .lock()
            .await
            .push(ChainPaymentUpdate::Error("rpc down".to_string()));
        assert!(handler.listen().await.is_err());
        Ok(())
    }
}
