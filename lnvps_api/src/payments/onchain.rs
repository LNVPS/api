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
//! accounting is achieved by storing the **txid** in `external_id` (unique
//! index) and skipping any update whose txid is already recorded.
//!
//! # Pro-rating (issue #109)
//!
//! On-chain funds can arrive at any time and for any amount. Deposits are
//! never rejected, and the exchange rate is **always re-calculated when the
//! transaction is discovered** — the original quote only fixes the price in
//! the subscription's currency, never the BTC rate:
//!
//! - A deposit for a pending payment settles it. `time_value` is scaled by
//!   the *value* that arrived, measured at the current rate:
//!   `received_msat * rate_now / (expected_msat * rate_quoted)`. For
//!   BTC-denominated subscriptions this reduces to `received / expected`.
//! - A deposit to an address whose payment already settled (address reuse)
//!   automatically inserts a **new** pro-rated renewal payment, priced the
//!   same way at the current rate.

use crate::subscription::SubscriptionHandler;
use anyhow::{Result, bail, ensure};
use chrono::Utc;
use futures::StreamExt;
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{debug, error, info, warn};
use payments_rs::currency::Currency;
use payments_rs::onchain::{ChainPaymentUpdate, OnChainProvider};
use std::str::FromStr;
use std::sync::Arc;

pub struct OnChainPaymentHandler {
    provider: Arc<dyn OnChainProvider>,
    db: Arc<dyn LNVpsDb>,
    sub_handler: SubscriptionHandler,
}

/// Scale `value` by `received / expected` (u128 intermediate, no overflow).
fn pro_rate(value: u64, received: u64, expected: u64) -> u64 {
    debug_assert!(expected > 0);
    (value as u128 * received as u128 / expected as u128) as u64
}

/// Scale `value` by an arbitrary ratio, flooring to whole units.
fn pro_rate_f64(value: u64, ratio: f64) -> u64 {
    (value as f64 * ratio).floor() as u64
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

    /// How much of the quoted *value* arrived, measured at the **current**
    /// exchange rate, plus that rate.
    ///
    /// The quote fixed a price in the subscription's currency; the BTC rate is
    /// never locked in. `received_msat * rate_now / (expected_msat *
    /// rate_quoted)` — for BTC-denominated subscriptions (rate 1:1) this is
    /// just `received / expected`.
    async fn value_ratio(
        &self,
        payment: &SubscriptionPayment,
        amount_msat: u64,
        expected: u64,
    ) -> Result<(f64, f32)> {
        let sub = self.db.get_subscription(payment.subscription_id).await?;
        let sub_currency = Currency::from_str(&sub.currency)
            .map_err(|e| anyhow::anyhow!("Invalid subscription currency: {}", e))?;
        let rate_now = self
            .sub_handler
            .pricing_engine()
            .get_ticker(Currency::BTC, sub_currency)
            .await?
            .rate;
        ensure!(
            payment.rate > 0.0,
            "Payment {} has invalid quoted rate",
            hex::encode(&payment.id)
        );
        let ratio =
            (amount_msat as f64 * rate_now as f64) / (expected as f64 * payment.rate as f64);
        Ok((ratio, rate_now))
    }

    /// Handle a confirmed deposit of `amount_msat` to `address` in tx `txid`.
    async fn handle_deposit(&self, address: &str, txid: &str, amount_msat: u64) -> Result<()> {
        // De-dupe: the stream is at-least-once, a known txid was already handled.
        if self
            .db
            .get_subscription_payment_by_ext_id(txid)
            .await
            .is_ok()
        {
            debug!("Skipping already processed deposit {}", txid);
            return Ok(());
        }

        let Some(payment) = self.payment_for_address(address).await? else {
            debug!("Deposit {} to unknown address {}, ignoring", txid, address);
            return Ok(());
        };

        let expected = payment.amount + payment.tax + payment.processing_fee;
        if expected == 0 {
            bail!(
                "Payment {} has zero expected amount, cannot pro-rate deposit {}",
                hex::encode(&payment.id),
                txid
            );
        }

        // The BTC rate is always re-calculated when the tx is discovered; the
        // quote only fixed the price in the subscription's currency.
        let (ratio, rate_now) = self.value_ratio(&payment, amount_msat, expected).await?;

        if !payment.is_paid {
            // Settle the pending payment, crediting the time the received
            // value actually buys at the current rate.
            let mut payment = payment;
            info!(
                "Settling on-chain payment {}: received {} msat (expected {} msat), value ratio {:.4}",
                hex::encode(&payment.id),
                amount_msat,
                expected,
                ratio
            );
            // Split what arrived proportionally between net/tax/fee so the
            // components always sum to the received amount.
            payment.tax = pro_rate(payment.tax, amount_msat, expected);
            payment.processing_fee = pro_rate(payment.processing_fee, amount_msat, expected);
            payment.amount = amount_msat - payment.tax - payment.processing_fee;
            payment.time_value = payment.time_value.map(|tv| pro_rate_f64(tv, ratio));
            payment.rate = rate_now;
            payment.external_id = Some(txid.to_string());
            self.db.update_subscription_payment(&payment).await?;
            self.sub_handler.complete_payment(&payment).await?;
        } else {
            // Address reuse after settlement: insert a new pro-rated renewal
            // payment based on the original quote (issue #109).
            let Some(time_value) = payment.time_value else {
                warn!(
                    "Deposit {} to settled payment {} without time_value, cannot pro-rate",
                    txid,
                    hex::encode(&payment.id)
                );
                return Ok(());
            };
            info!(
                "New deposit {} of {} msat to settled address of payment {}, creating pro-rated renewal (value ratio {:.4})",
                txid,
                amount_msat,
                hex::encode(&payment.id),
                ratio
            );
            let tax = pro_rate(payment.tax, amount_msat, expected);
            let processing_fee = pro_rate(payment.processing_fee, amount_msat, expected);
            let new_id: [u8; 32] = rand::random();
            let renewal = SubscriptionPayment {
                id: new_id.to_vec(),
                subscription_id: payment.subscription_id,
                user_id: payment.user_id,
                created: Utc::now(),
                expires: Utc::now(),
                amount: amount_msat - tax - processing_fee,
                currency: payment.currency.clone(),
                payment_method: PaymentMethod::OnChain,
                payment_type: SubscriptionPaymentType::Renewal,
                external_data: address.into(),
                external_id: Some(txid.to_string()),
                is_paid: false,
                rate: rate_now,
                time_value: Some(pro_rate_f64(time_value, ratio)),
                metadata: None,
                tax,
                processing_fee,
                paid_at: None,
                tax_rate: payment.tax_rate,
                tax_country_code: payment.tax_country_code.clone(),
                tax_treatment: payment.tax_treatment.clone(),
                tax_evidence: payment.tax_evidence.clone(),
                tax_breakdown: payment.tax_breakdown.clone(),
            };
            self.db.insert_subscription_payment(&renewal).await?;
            self.sub_handler.complete_payment(&renewal).await?;
        }
        Ok(())
    }

    pub async fn listen(&mut self) -> Result<()> {
        info!("Listening for on-chain deposits");
        // Subscribe from the start; the txid de-dupe above makes replaying
        // history harmless (at-least-once -> exactly-once).
        let mut stream = self.provider.subscribe_payments(None).await?;
        while let Some(update) = stream.next().await {
            match update {
                ChainPaymentUpdate::Confirmed {
                    address,
                    txid,
                    amount_msat,
                    ..
                } => {
                    if let Err(e) = self.handle_deposit(&address, &txid, amount_msat).await {
                        error!("onchain deposit error for {}: {}", txid, e);
                    }
                }
                ChainPaymentUpdate::Detected {
                    address,
                    txid,
                    amount_msat,
                    confirmations,
                    ..
                } => {
                    debug!(
                        "Detected deposit {} of {} msat to {} ({} confs)",
                        txid, amount_msat, address, confirmations
                    );
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
        ChannelWorkCommander, ExchangeRateService, MockDb, MockExchangeRate, Ticker, VmStateCache,
    };
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, SubscriptionType, Vm,
    };

    const ADDRESS: &str = "bcrt1qtestaddr0";
    const AMOUNT: u64 = 1_000_000;
    const TAX: u64 = 100_000;
    const EXPECTED: u64 = AMOUNT + TAX;
    const TIME_VALUE: u64 = 86_400;

    /// DB with a VM + subscription and one unpaid on-chain payment for [`ADDRESS`].
    async fn setup() -> Result<(
        Arc<MockDb>,
        Arc<MockOnChainProvider>,
        OnChainPaymentHandler,
        SubscriptionPayment,
    )> {
        // BTC-denominated: value ratio is the plain msat ratio
        setup_with("BTC", 1.0, None).await
    }

    /// Like [`setup`] but with an explicit subscription currency, quoted rate
    /// on the pending payment, and current exchange rate.
    async fn setup_with(
        currency: &str,
        quoted_rate: f32,
        current_rate: Option<f32>,
    ) -> Result<(
        Arc<MockDb>,
        Arc<MockOnChainProvider>,
        OnChainPaymentHandler,
        SubscriptionPayment,
    )> {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let provider = Arc::new(MockOnChainProvider::default());
        let rates = Arc::new(MockExchangeRate::default());
        if let Some(r) = current_rate {
            rates.set_rate(Ticker::btc_rate(currency)?, r).await;
        }

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
                    currency: currency.to_string(),
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
            rates,
            lnvps_api_common::VatClient::new(),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;
        let handler = OnChainPaymentHandler::new(provider.clone(), db.clone(), sub);

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

    #[test]
    fn test_pro_rate() {
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED, EXPECTED), TIME_VALUE);
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED / 2, EXPECTED), TIME_VALUE / 2);
        assert_eq!(pro_rate(TIME_VALUE, EXPECTED * 2, EXPECTED), TIME_VALUE * 2);
        assert_eq!(pro_rate(0, EXPECTED, EXPECTED), 0);
        // u128 intermediate: no overflow on large values
        assert_eq!(pro_rate(u64::MAX, 1000, 1000), u64::MAX);
    }

    /// Exact deposit settles the pending payment untouched.
    #[tokio::test]
    async fn test_exact_deposit_settles_payment() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.external_id.as_deref(), Some("tx1"));
        assert_eq!(p.amount, AMOUNT);
        assert_eq!(p.tax, TAX);
        assert_eq!(p.time_value, Some(TIME_VALUE));
        Ok(())
    }

    /// Partial deposit is pro-rated: amount/tax/time all scale by received/expected.
    #[tokio::test]
    async fn test_partial_deposit_pro_rates() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED / 2).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.tax, TAX / 2);
        assert_eq!(p.amount, EXPECTED / 2 - TAX / 2);
        assert_eq!(p.time_value, Some(TIME_VALUE / 2));
        Ok(())
    }

    /// A replayed txid must not settle or create anything (at-least-once stream).
    #[tokio::test]
    async fn test_duplicate_txid_skipped() -> Result<()> {
        let (db, _provider, handler, _payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED).await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED).await?;

        assert_eq!(db.subscription_payments.lock().await.len(), 1);
        Ok(())
    }

    /// Deposits to unknown addresses are ignored.
    #[tokio::test]
    async fn test_unknown_address_ignored() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler
            .handle_deposit("bcrt1qunknown", "tx1", EXPECTED)
            .await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(!p.is_paid);
        assert_eq!(db.subscription_payments.lock().await.len(), 1);
        Ok(())
    }

    /// A deposit to an already-settled address inserts a new pro-rated renewal.
    #[tokio::test]
    async fn test_address_reuse_inserts_renewal() -> Result<()> {
        let (db, _provider, handler, payment) = setup().await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED).await?;
        // half the original amount arrives later at the same address
        handler.handle_deposit(ADDRESS, "tx2", EXPECTED / 2).await?;

        let payments = db.subscription_payments.lock().await.clone();
        assert_eq!(payments.len(), 2);
        let renewal = payments
            .iter()
            .find(|p| p.external_id.as_deref() == Some("tx2"))
            .expect("renewal payment");
        assert!(renewal.is_paid);
        assert_ne!(renewal.id, payment.id);
        assert_eq!(renewal.payment_type, SubscriptionPaymentType::Renewal);
        assert_eq!(renewal.payment_method, PaymentMethod::OnChain);
        assert_eq!(renewal.subscription_id, payment.subscription_id);
        assert_eq!(renewal.external_data.as_str(), ADDRESS);
        assert_eq!(renewal.tax, TAX / 2);
        assert_eq!(renewal.amount, EXPECTED / 2 - TAX / 2);
        assert_eq!(renewal.time_value, Some(TIME_VALUE / 2));
        Ok(())
    }

    /// listen() drains scripted updates: Confirmed settles, Detected is ignored.
    #[tokio::test]
    async fn test_listen_processes_confirmed_updates() -> Result<()> {
        let (db, provider, mut handler, payment) = setup().await?;
        provider.updates.lock().await.extend([
            ChainPaymentUpdate::Detected {
                address: ADDRESS.to_string(),
                txid: "tx1".to_string(),
                amount_msat: EXPECTED,
                confirmations: 0,
                label: None,
            },
            ChainPaymentUpdate::Confirmed {
                address: ADDRESS.to_string(),
                txid: "tx1".to_string(),
                amount_msat: EXPECTED,
                confirmations: 1,
                label: None,
            },
        ]);
        handler.listen().await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.external_id.as_deref(), Some("tx1"));
        Ok(())
    }

    /// The BTC rate is re-calculated when the tx is discovered: a fiat quote
    /// paid in full in msat terms credits time by *value* at the current rate.
    #[tokio::test]
    async fn test_fiat_quote_repriced_at_current_rate() -> Result<()> {
        // Quoted at 100k EUR/BTC; by discovery the rate doubled to 200k, so
        // the same msats are worth twice the quoted value -> twice the time.
        let (db, _provider, handler, payment) =
            setup_with("EUR", 100_000.0, Some(200_000.0)).await?;
        handler.handle_deposit(ADDRESS, "tx1", EXPECTED).await?;

        let p = get_payment(&db, &payment.id).await;
        assert!(p.is_paid);
        assert_eq!(p.time_value, Some(TIME_VALUE * 2));
        assert_eq!(p.rate, 200_000.0, "current rate recorded on the payment");
        // msat components are unchanged (full msat amount arrived)
        assert_eq!(p.amount, AMOUNT);
        assert_eq!(p.tax, TAX);

        // Address reuse is also priced at the (new) current rate
        handler.handle_deposit(ADDRESS, "tx2", EXPECTED / 2).await?;
        let payments = db.subscription_payments.lock().await.clone();
        let renewal = payments
            .iter()
            .find(|p| p.external_id.as_deref() == Some("tx2"))
            .expect("renewal payment");
        // reference payment now has rate 200k and time 2*TIME_VALUE; half the
        // msats at the same rate -> half its time
        assert_eq!(renewal.time_value, Some(TIME_VALUE));
        assert_eq!(renewal.rate, 200_000.0);
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
