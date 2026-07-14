//! Generic subscription line-item lifecycle management.
//!
//! Every product type (VM, IP range, ASN sponsoring, DNS hosting, …) implements
//! [`SubscriptionLineItemHandler`].  Both the payment pipeline and the lifecycle
//! worker call into this single trait, so adding a new product means implementing
//! the trait once in one place.
//!
//! # Usage
//!
//! Build a handler for a specific line item with [`line_item_handler`].
//! The payment pipeline calls [`SubscriptionLineItemHandler::on_payment`].
//! The lifecycle worker calls [`SubscriptionLineItemHandler::on_expiring_soon`],
//! [`SubscriptionLineItemHandler::on_expired`], and
//! [`SubscriptionLineItemHandler::on_grace_period_exceeded`].

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use chrono::{Datelike, Utc};
use lnvps_api_common::{
    CostResult, ExchangeRateService, NewPaymentInfo, PricingEngine, UpgradeConfig, WorkCommander,
    round_msat_to_sat,
};
use lnvps_db::{
    LNVpsDb, PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentType, SubscriptionType, User, UserPaymentMethod,
};
use log::{debug, info, warn};
use payments_rs::currency::{Currency, CurrencyAmount};
use payments_rs::fiat::FiatPaymentService;
use payments_rs::lightning::{AddInvoiceRequest, LightningNode};
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

mod ip_range;
mod vm;

use crate::provisioner::VmProvisioner;
use crate::settings::Settings;
pub use ip_range::IpRangeLineItemHandler;
use lnvps_api_common::VmStateCache;
pub use vm::VmLineItemHandler;

// =========================================================================
// Trait
// =========================================================================

/// Manages the full lifecycle of a single subscription line item.
#[async_trait]
pub trait SubscriptionLineItemHandler: Send + Sync {
    /// Called after `subscription_payment_paid()` has marked the payment as
    /// paid in the DB and extended `subscription.expires`.
    async fn on_payment(&self, payment: &SubscriptionPayment) -> Result<()>;

    /// Called when `subscription.expires` has passed.
    async fn on_expired(&self, sub: &Subscription, line_item: &SubscriptionLineItem) -> Result<()>;

    /// Called when `subscription.expires + delete_after` has passed.
    async fn on_grace_period_exceeded(
        &self,
        sub: &Subscription,
        line_item: &SubscriptionLineItem,
    ) -> Result<()>;
}

// =========================================================================
// Factory
// =========================================================================

pub struct CompletePaymentResult {
    /// Other VM upgrade payments which have been expired
    pub expired_competing_upgrades: Vec<SubscriptionPayment>,
}

#[derive(Clone)]
pub struct SubscriptionHandler {
    db: Arc<dyn LNVpsDb>,
    tx: Arc<dyn WorkCommander>,

    node: Arc<dyn LightningNode>,
    revolut: Option<Arc<dyn FiatPaymentService>>,

    pe: PricingEngine,
    vm_provisioner: VmProvisioner,
    vm_state_cache: VmStateCache,
}

impl SubscriptionHandler {
    pub fn new(
        settings: Settings,
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        rates: Arc<dyn ExchangeRateService>,
        tx: Arc<dyn WorkCommander>,
        vm_state_cache: VmStateCache,
    ) -> Result<Self> {
        Ok(Self {
            revolut: settings.get_revolut()?,
            pe: PricingEngine::new(db.clone(), rates, settings.tax_rate.clone()),
            vm_provisioner: VmProvisioner::new(settings, db.clone()),
            db,
            tx,
            node,
            vm_state_cache,
        })
    }

    pub fn work_commander(&self) -> Arc<dyn WorkCommander> {
        self.tx.clone()
    }

    pub fn vm_provisioner(&self) -> VmProvisioner {
        self.vm_provisioner.clone()
    }

    pub fn pricing_engine(&self) -> PricingEngine {
        self.pe.clone()
    }

    pub fn db(&self) -> Arc<dyn LNVpsDb> {
        self.db.clone()
    }

    #[cfg(test)]
    pub(crate) fn set_revolut_for_test(&mut self, r: Arc<dyn FiatPaymentService>) {
        self.revolut = Some(r);
    }

    pub async fn make_line_item_handler(
        &self,
        li: &SubscriptionLineItem,
    ) -> Result<Box<dyn SubscriptionLineItemHandler>> {
        match li.subscription_type {
            SubscriptionType::Vps => {
                let vm = self.db.get_vm_by_line_item(li.id).await?;
                Ok(Box::new(
                    VmLineItemHandler::new(
                        vm.id,
                        self.db.clone(),
                        self.tx.clone(),
                        self.vm_provisioner.clone(),
                        self.vm_state_cache.clone(),
                    )
                    .await?,
                ))
            }
            SubscriptionType::IpRange => Ok(Box::new(IpRangeLineItemHandler::new(
                self.db.clone(),
                self.tx.clone(),
            ))),
            other => {
                bail!("No line item handler implemented for subscription type {other:?}")
            }
        }
    }

    pub async fn complete_payment(
        &self,
        payment: &SubscriptionPayment,
    ) -> Result<CompletePaymentResult> {
        self.db.subscription_payment_paid(payment).await?;

        let line_items = self
            .db
            .list_subscription_line_items(payment.subscription_id)
            .await?;
        for li in &line_items {
            match self.make_line_item_handler(li).await {
                Ok(handler) => {
                    if let Err(e) = handler.on_payment(payment).await {
                        warn!(
                            "on_payment failed for line item {} (sub {}): {}",
                            li.id, payment.subscription_id, e
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to build handler for line item {} (sub {}): {}",
                        li.id, payment.subscription_id, e
                    );
                }
            }
        }

        info!(
            "Payment {} for subscription {} complete",
            hex::encode(&payment.id),
            payment.subscription_id
        );

        if payment.payment_type == SubscriptionPaymentType::Upgrade {
            // Cancel other pending Lightning upgrade invoices for this subscription.
            // If we can't find the VM the payment is still committed as paid — log a
            // warning and return an empty result rather than propagating an error that
            // would mislead callers into thinking the payment was not completed.
            let vm = match self
                .db
                .get_vm_by_subscription(payment.subscription_id)
                .await
            {
                Ok(vm) => vm,
                Err(e) => {
                    warn!(
                        "Payment {} marked paid but get_vm_by_subscription failed (sub {}): {}",
                        hex::encode(&payment.id),
                        payment.subscription_id,
                        e
                    );
                    return Ok(CompletePaymentResult {
                        expired_competing_upgrades: Vec::new(),
                    });
                }
            };
            let other_upgrades = self
                .db
                .list_pending_vm_subscription_payments(vm.id)
                .await?
                .into_iter()
                .filter(|p| {
                    p.payment_type == SubscriptionPaymentType::Upgrade && p.id != payment.id
                })
                .collect::<Vec<_>>();

            let mut expired_upgrades = Vec::new();
            for ugp in other_upgrades.into_iter() {
                let mut expired = ugp;
                expired.expires = Utc::now();
                if let Err(e) = self.db.update_subscription_payment(&expired).await {
                    warn!(
                        "Failed to update invoice {}: {}",
                        hex::encode(&expired.id),
                        e
                    );
                }
                expired_upgrades.push(expired);
            }
            Ok(CompletePaymentResult {
                expired_competing_upgrades: expired_upgrades,
            })
        } else {
            Ok(CompletePaymentResult {
                expired_competing_upgrades: Vec::new(),
            })
        }
    }

    /// Create a Revolut order for a fiat payment, returning `(external_id, raw_data)`.
    ///
    /// When the subscription has automatic renewal enabled and the user does not
    /// yet have a saved payment method, the order is created as a "subscription"
    /// checkout (`create_subscription`) so Revolut saves the customer's payment
    /// method for future off-session (merchant-initiated) charges. The saved
    /// method is captured on webhook completion (see
    /// `payments::revolut::RevolutPaymentHandler::capture_saved_payment_method`).
    /// Select the user's saved Revolut payment method to charge off-session:
    /// the default enabled, non-expired method, else the first enabled
    /// non-expired one.
    async fn default_revolut_payment_method(&self, user_id: u64) -> Result<UserPaymentMethod> {
        let now = Utc::now();
        let (year, month) = (now.year() as u16, now.month() as u16);
        let methods = self
            .db
            .list_user_payment_methods(user_id, Some("revolut"))
            .await?;
        let usable: Vec<UserPaymentMethod> = methods
            .into_iter()
            .filter(|m| m.enabled && !m.is_expired(year, month))
            .collect();
        // list_user_payment_methods already orders default-first.
        usable
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No usable saved Revolut payment method"))
    }

    async fn create_revolut_order(
        &self,
        rev: &Arc<dyn FiatPaymentService>,
        subscription: &Subscription,
        user: &User,
        payment_type: SubscriptionPaymentType,
        desc: &str,
        amount: CurrencyAmount,
    ) -> Result<(String, String)> {
        // Save the card only when auto-renewal is on, this isn't an upgrade, and
        // the user has no usable saved Revolut method yet.
        let has_saved_method = self
            .db
            .list_user_payment_methods(user.id, Some("revolut"))
            .await
            .map(|m| m.iter().any(|pm| pm.enabled))
            .unwrap_or(false);
        let should_save = subscription.auto_renewal_enabled
            && !has_saved_method
            && payment_type != SubscriptionPaymentType::Upgrade;
        if should_save {
            let email: String = user.email.clone().into();
            let customer_email = if email.is_empty() { None } else { Some(email) };
            let info = rev
                .create_subscription(desc, amount, customer_email, None)
                .await?;
            Ok((info.external_id, info.raw_data))
        } else {
            let info = rev.create_order(desc, amount, None).await?;
            Ok((info.external_id, info.raw_data))
        }
    }

    /// Create a renewal/purchase payment for a subscription.
    ///
    /// The customer completes the payment interactively (Lightning invoice or
    /// Revolut checkout).
    pub async fn renew_subscription(
        &self,
        subscription_id: u64,
        method: PaymentMethod,
        intervals: u32,
    ) -> Result<SubscriptionPayment> {
        self.renew_subscription_inner(subscription_id, method, intervals, false)
            .await
    }

    /// Create a renewal/purchase payment for a subscription.
    ///
    /// When `off_session` is true (Revolut only) the saved payment method is
    /// charged off-session (merchant-initiated) without customer interaction.
    async fn renew_subscription_inner(
        &self,
        subscription_id: u64,
        method: PaymentMethod,
        intervals: u32,
        off_session: bool,
    ) -> Result<SubscriptionPayment> {
        let intervals = intervals.max(1);

        // Get subscription and line items
        let subscription = self.db.get_subscription(subscription_id).await?;
        let line_items = self
            .db
            .list_subscription_line_items(subscription_id)
            .await?;
        ensure!(!line_items.is_empty(), "Subscription has no line items");

        // Get user for tax calculation
        let user = self.db.get_user(subscription.user_id).await?;

        // Calculate total cost for the renewal.
        //
        // VmRenewal line items use get_vm_cost_for_intervals, which already
        // performs the currency conversion (EUR→BTC etc.) internally and
        // returns amounts in the payment method's currency together with the
        // correct time_value.  We must NOT pass those already-converted amounts
        // through get_amount_and_rate again — that would cause double conversion.
        //
        // Non-VM line items store their price in the subscription's base currency
        // and are accumulated separately for a single conversion pass at the end.

        let mut setup_fee: u64 = 0;

        // Accumulate NewPaymentInfo from all VM line items
        let mut vm_payment_infos: Vec<NewPaymentInfo> = Vec::new();
        // Accumulate non-VM amounts (in subscription currency) for conversion
        let mut non_vm_interval_cost: u64 = 0;

        for item in &line_items {
            if item.subscription_type == SubscriptionType::Vps {
                let vm = self.db.get_vm_by_line_item(item.id).await?;
                match self
                    .pe
                    .get_vm_cost_for_intervals(vm.id, method, intervals)
                    .await?
                {
                    CostResult::New(p) => vm_payment_infos.push(p),
                    CostResult::Existing(p) => {
                        // An identical unpaid payment already exists — return it directly
                        return Ok(p);
                    }
                }
            } else {
                non_vm_interval_cost += item.amount * intervals as u64;
            }
            setup_fee += item.setup_amount;
        }

        // is_setup is set to true once the first (purchase) payment is confirmed.
        let payment_type = if subscription.is_setup {
            SubscriptionPaymentType::Renewal
        } else {
            SubscriptionPaymentType::Purchase
        };

        // Parse subscription currency (needed for non-VM item conversion)
        let subscription_currency = Currency::from_str(&subscription.currency)
            .map_err(|_| anyhow::anyhow!("Invalid currency"))?;

        // Setup fees are charged once, on the first (purchase) invoice. They are
        // denominated in the subscription currency and must be converted to the
        // payment currency together with any non-VM line item cost. Include them
        // even when there are no non-VM items (e.g. a VPS-only subscription),
        // otherwise VPS setup fees are silently dropped.
        let setup_fee_due = if subscription.is_setup { 0 } else { setup_fee };
        let non_vm_base = non_vm_interval_cost + setup_fee_due;

        // Convert non-VM amounts (+ setup fee) to the payment method currency
        let (non_vm_converted_amount, non_vm_rate, non_vm_tax, non_vm_processing_fee): (
            u64,
            f32,
            u64,
            u64,
        ) = if non_vm_base > 0 {
            let base = non_vm_base;
            let list_price = CurrencyAmount::from_u64(subscription_currency, base);
            let converted = self.pe.get_amount_and_rate(list_price, method).await?;
            let tax = self
                .pe
                .get_tax_for_user(user.id, converted.amount.value())
                .await?;
            let processing_fee = self
                .pe
                .calculate_processing_fee(
                    subscription.company_id,
                    method,
                    converted.amount.currency(),
                    converted.amount.value(),
                )
                .await;
            (
                converted.amount.value(),
                converted.rate.rate,
                tax,
                processing_fee,
            )
        } else {
            (0u64, 0f32, 0u64, 0u64)
        };

        // Aggregate all line item amounts.  All VM infos are already in the
        // payment method's currency so they can be summed directly.
        let vm_amount: u64 = vm_payment_infos.iter().map(|p| p.amount).sum();
        // time_value: sum of all VM intervals (non-VM items don't extend expiry)
        let time_value: u64 = vm_payment_infos.iter().map(|p| p.time_value).sum();
        // Use the rate from the first VM item if available, else from non-VM conversion
        let rate = vm_payment_infos
            .first()
            .map(|p| p.rate.rate)
            .unwrap_or(non_vm_rate);
        // Tax and processing fee are already computed per-item by get_vm_cost_for_intervals;
        // add non-VM taxes on top.
        let tax: u64 = vm_payment_infos.iter().map(|p| p.tax).sum::<u64>() + non_vm_tax;
        let processing_fee: u64 = vm_payment_infos
            .iter()
            .map(|p| p.processing_fee)
            .sum::<u64>()
            + non_vm_processing_fee;

        let total_amount = vm_amount + non_vm_converted_amount;

        // Payment method currency: BTC for Lightning, otherwise subscription currency
        let payment_currency = vm_payment_infos
            .first()
            .map(|p| p.currency)
            .unwrap_or(subscription_currency);

        // Wrap the aggregated values so the invoice/order creation below can use them
        let converted_amount = total_amount;
        let converted_currency = payment_currency;

        // Generate payment based on method
        let subscription_payment = match method {
            PaymentMethod::Lightning => {
                ensure!(
                    converted_currency == Currency::BTC,
                    "Lightning payment must be in BTC"
                );
                const INVOICE_EXPIRE: u64 = 600;
                // Round to nearest satoshi for wallet compatibility
                let invoice_amount = round_msat_to_sat(converted_amount + tax);
                let desc = match payment_type {
                    SubscriptionPaymentType::Purchase => {
                        format!("Subscription purchase: {}", subscription.name)
                    }
                    SubscriptionPaymentType::Renewal => {
                        format!("Subscription renewal: {}", subscription.name)
                    }
                    SubscriptionPaymentType::Upgrade => {
                        format!("Subscription upgrade: {}", subscription.name)
                    }
                };

                info!(
                    "Creating invoice for subscription {} for {} sats",
                    subscription_id,
                    invoice_amount / 1000
                );

                let invoice = self
                    .node
                    .add_invoice(AddInvoiceRequest {
                        memo: Some(desc),
                        amount: invoice_amount,
                        expire: Some(INVOICE_EXPIRE as u32),
                    })
                    .await?;

                SubscriptionPayment {
                    id: hex::decode(invoice.payment_hash())?,
                    subscription_id,
                    user_id: subscription.user_id,
                    created: Utc::now(),
                    expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE)),
                    amount: converted_amount,
                    currency: converted_currency.to_string(),
                    payment_method: method,
                    payment_type,
                    external_data: invoice.pr().into(),
                    external_id: invoice.external_id,
                    is_paid: false,
                    rate,
                    time_value: if time_value > 0 {
                        Some(time_value)
                    } else {
                        None
                    },
                    metadata: None,
                    tax,
                    processing_fee,
                    paid_at: None,
                }
            }
            PaymentMethod::Revolut => {
                let rev = if let Some(r) = &self.revolut {
                    r
                } else {
                    bail!("Revolut not configured")
                };
                ensure!(
                    converted_currency != Currency::BTC,
                    "Cannot create Revolut orders for BTC currency"
                );

                let desc = match payment_type {
                    SubscriptionPaymentType::Purchase => {
                        format!("Subscription purchase: {}", subscription.name)
                    }
                    SubscriptionPaymentType::Renewal => {
                        format!("Subscription renewal: {}", subscription.name)
                    }
                    SubscriptionPaymentType::Upgrade => {
                        format!("Subscription upgrade: {}", subscription.name)
                    }
                };

                let order_amount = CurrencyAmount::from_u64(
                    converted_currency,
                    converted_amount + tax + processing_fee,
                );
                let (external_id, raw_data) = if off_session {
                    // Off-session (merchant-initiated) charge against the user's
                    // default saved Revolut payment method — no customer
                    // interaction.
                    let method = self.default_revolut_payment_method(user.id).await?;
                    let customer_id: String = method
                        .external_customer_id
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("Revolut method missing customer id"))?
                        .into();
                    let payment_method_id: String = method.external_id.clone().into();
                    let info = rev
                        .charge_subscription(
                            &customer_id,
                            &payment_method_id,
                            order_amount,
                            &desc,
                        )
                        .await?;
                    (info.external_id, info.raw_data)
                } else {
                    self.create_revolut_order(
                        rev,
                        &subscription,
                        &user,
                        payment_type,
                        &desc,
                        order_amount,
                    )
                    .await?
                };

                let new_id: [u8; 32] = rand::random();
                SubscriptionPayment {
                    id: new_id.to_vec(),
                    subscription_id,
                    user_id: subscription.user_id,
                    created: Utc::now(),
                    expires: Utc::now().add(Duration::from_secs(3600)),
                    amount: converted_amount,
                    currency: converted_currency.to_string(),
                    payment_method: method,
                    payment_type,
                    external_data: raw_data.into(),
                    external_id: Some(external_id),
                    is_paid: false,
                    rate,
                    time_value: if time_value > 0 {
                        Some(time_value)
                    } else {
                        None
                    },
                    metadata: None,
                    tax,
                    processing_fee,
                    paid_at: None,
                }
            }
            PaymentMethod::Paypal => bail!("PayPal not implemented"),
            PaymentMethod::Stripe => bail!("Stripe not implemented"),
        };

        // Save payment to database
        self.db
            .insert_subscription_payment(&subscription_payment)
            .await?;

        Ok(subscription_payment)
    }

    async fn price_to_payment(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        price: CostResult,
    ) -> Result<SubscriptionPayment> {
        self.price_to_payment_with_type(
            vm_id,
            method,
            price,
            SubscriptionPaymentType::Renewal,
            None,
        )
        .await
    }

    async fn price_to_payment_with_type(
        &self,
        vm_id: u64,
        method: PaymentMethod,
        price: CostResult,
        payment_type: SubscriptionPaymentType,
        metadata: Option<serde_json::Value>,
    ) -> Result<SubscriptionPayment> {
        match price {
            CostResult::Existing(p) => Ok(p),
            CostResult::New(p) => {
                let vm = self.db.get_vm(vm_id).await?;
                let line_item = self
                    .db
                    .get_subscription_line_item(vm.subscription_line_item_id)
                    .await?;
                let subscription_id = line_item.subscription_id;
                let desc = match payment_type {
                    SubscriptionPaymentType::Renewal => {
                        format!("VM renewal {vm_id} to {}", p.new_expiry)
                    }
                    SubscriptionPaymentType::Upgrade => format!("VM upgrade {vm_id}"),
                    SubscriptionPaymentType::Purchase => format!("VM purchase {vm_id}"),
                };
                let payment = match method {
                    PaymentMethod::Lightning => {
                        ensure!(
                            p.currency == Currency::BTC,
                            "Cannot create invoices for non-BTC currency"
                        );
                        const INVOICE_EXPIRE: u64 = 600;
                        let total_amount = round_msat_to_sat(p.amount + p.tax);
                        info!(
                            "Creating invoice for vm {vm_id} for {} sats",
                            total_amount / 1000
                        );
                        let invoice = self
                            .node
                            .add_invoice(AddInvoiceRequest {
                                memo: Some(desc),
                                amount: total_amount,
                                expire: Some(INVOICE_EXPIRE as u32),
                            })
                            .await?;
                        SubscriptionPayment {
                            id: hex::decode(invoice.payment_hash())?,
                            subscription_id,
                            user_id: vm.user_id,
                            created: Utc::now(),
                            expires: Utc::now().add(Duration::from_secs(INVOICE_EXPIRE)),
                            amount: p.amount,
                            currency: p.currency.to_string(),
                            payment_method: method,
                            payment_type,
                            external_data: invoice.pr().into(),
                            external_id: invoice.external_id,
                            is_paid: false,
                            rate: p.rate.rate,
                            time_value: Some(p.time_value),
                            metadata,
                            tax: p.tax,
                            processing_fee: p.processing_fee,
                            paid_at: None,
                        }
                    }
                    PaymentMethod::Revolut => {
                        let rev = if let Some(r) = &self.revolut {
                            r
                        } else {
                            bail!("Revolut not configured")
                        };
                        ensure!(
                            p.currency != Currency::BTC,
                            "Cannot create revolut orders for BTC currency"
                        );
                        let subscription = self.db.get_subscription(subscription_id).await?;
                        let user = self.db.get_user(vm.user_id).await?;
                        let (external_id, raw_data) = self
                            .create_revolut_order(
                                rev,
                                &subscription,
                                &user,
                                payment_type,
                                &desc,
                                CurrencyAmount::from_u64(
                                    p.currency,
                                    p.amount + p.tax + p.processing_fee,
                                ),
                            )
                            .await?;
                        let new_id: [u8; 32] = rand::random();
                        SubscriptionPayment {
                            id: new_id.to_vec(),
                            subscription_id,
                            user_id: vm.user_id,
                            created: Utc::now(),
                            expires: Utc::now().add(Duration::from_secs(3600)),
                            amount: p.amount,
                            currency: p.currency.to_string(),
                            payment_method: method,
                            payment_type,
                            external_data: raw_data.into(),
                            external_id: Some(external_id),
                            is_paid: false,
                            rate: p.rate.rate,
                            time_value: Some(p.time_value),
                            metadata,
                            tax: p.tax,
                            processing_fee: p.processing_fee,
                            paid_at: None,
                        }
                    }
                    PaymentMethod::Paypal => bail!("PayPal not implemented"),
                    PaymentMethod::Stripe => {
                        bail!("Stripe payment creation not yet implemented")
                    }
                };

                self.db.insert_subscription_payment(&payment).await?;

                Ok(payment)
            }
        }
    }

    /// The user's default usable (enabled, non-expired) saved payment method,
    /// across all providers. Methods are ordered default-first.
    pub async fn default_payment_method(&self, user_id: u64) -> Result<UserPaymentMethod> {
        let now = Utc::now();
        let (year, month) = (now.year() as u16, now.month() as u16);
        self.db
            .list_user_payment_methods(user_id, None)
            .await?
            .into_iter()
            .find(|pm| pm.enabled && !pm.is_expired(year, month))
            .ok_or_else(|| anyhow::anyhow!("No usable saved payment method"))
    }

    /// The user's first enabled NWC payment method.
    async fn nwc_payment_method(&self, user_id: u64) -> Result<UserPaymentMethod> {
        self.db
            .list_user_payment_methods(user_id, Some("nwc"))
            .await?
            .into_iter()
            .find(|pm| pm.enabled)
            .ok_or_else(|| anyhow::anyhow!("No NWC payment method configured"))
    }

    /// Attempt automatic renewal using the user's default saved payment method,
    /// dispatching by provider (NWC Lightning wallet or Revolut card).
    pub async fn auto_renew(&self, sub_id: u64) -> Result<SubscriptionPayment> {
        let sub = self.db.get_subscription(sub_id).await?;
        let method = self.default_payment_method(sub.user_id).await?;
        match method.provider.as_str() {
            "nwc" => {
                #[cfg(feature = "nostr-nwc")]
                {
                    self.auto_renew_via_nwc(sub_id).await
                }
                #[cfg(not(feature = "nostr-nwc"))]
                {
                    bail!("NWC auto-renewal is not supported by this build")
                }
            }
            "revolut" => self.auto_renew_via_revolut(sub_id).await,
            other => bail!("No auto-renewal handler for provider {other}"),
        }
    }

    #[cfg(feature = "nostr-nwc")]
    /// Attempt automatic renewal via the user's saved Nostr Wallet Connect method
    pub async fn auto_renew_via_nwc(&self, sub_id: u64) -> Result<SubscriptionPayment> {
        use nostr_sdk::prelude::*;

        debug!("Attempting automatic renewal for sub {} via NWC", sub_id);

        let sub = self.db.get_subscription(sub_id).await?;
        let nwc_method = self.nwc_payment_method(sub.user_id).await?;
        let nwc_string: String = nwc_method.external_id.clone().into();

        // Use existing renew_subscription method to create the payment/invoice
        let vm_payment = self
            .renew_subscription(sub_id, PaymentMethod::Lightning, 1)
            .await?;

        // Extract the invoice from external_data
        let invoice: String = vm_payment.external_data.clone().into();
        debug!(
            "Created renewal invoice for sub {}, attempting NWC payment",
            sub_id
        );

        // Parse NWC connection string
        let nwc_uri = NostrWalletConnectUri::from_str(&nwc_string)
            .context("Invalid NWC connection string")?;

        // Create nostr client for NWC
        let client = nwc::NostrWalletConnect::new(nwc_uri);
        client.pay_invoice(PayInvoiceRequest::new(invoice)).await?;
        info!("Successful NWC auto-renewal payment for sub {}", sub_id);
        Ok(vm_payment)
    }

    /// Attempt automatic renewal by charging the user's saved Revolut payment
    /// method off-session (merchant-initiated).
    ///
    /// The charge is submitted immediately; the resulting Revolut order is
    /// completed asynchronously via the `OrderCompleted` webhook (same path as
    /// interactive Revolut payments), which extends the subscription expiry.
    pub async fn auto_renew_via_revolut(&self, sub_id: u64) -> Result<SubscriptionPayment> {
        debug!(
            "Attempting automatic renewal for sub {} via Revolut saved card",
            sub_id
        );
        let payment = self
            .renew_subscription_inner(sub_id, PaymentMethod::Revolut, 1, true)
            .await?;
        info!(
            "Submitted Revolut off-session auto-renewal charge for sub {}",
            sub_id
        );
        Ok(payment)
    }

    /// Renew a VM using a specific amount
    pub async fn renew_amount(
        &self,
        vm_id: u64,
        amount: CurrencyAmount,
        method: PaymentMethod,
    ) -> Result<SubscriptionPayment> {
        let price = self.pe.get_cost_by_amount(vm_id, amount, method).await?;
        self.price_to_payment(vm_id, method, price).await
    }

    /// Create a VM upgrade payment
    pub async fn create_vm_upgrade_payment(
        &self,
        vm_id: u64,
        cfg: &UpgradeConfig,
        method: PaymentMethod,
    ) -> Result<SubscriptionPayment> {
        let cost_difference = self
            .pe
            .calculate_vm_upgrade_cost(vm_id, cfg, method)
            .await?;

        // create a payment entry for upgrade
        let payment = NewPaymentInfo {
            amount: cost_difference.upgrade.amount.value(),
            currency: cost_difference.upgrade.amount.currency(),
            rate: cost_difference.upgrade.rate,
            time_value: 0, //upgrades dont add time
            new_expiry: Default::default(),
            tax: 0,            // No tax on upgrades for now
            processing_fee: 0, // No processing fee on upgrades for now
        };
        let metadata = serde_json::to_value(cfg)?;

        self.price_to_payment_with_type(
            vm_id,
            method,
            CostResult::New(payment),
            SubscriptionPaymentType::Upgrade,
            Some(metadata),
        )
        .await
    }
}

#[cfg(all(test, feature = "revolut"))]
mod revolut_autorenew_tests {
    use super::*;
    use crate::mocks::MockNode;
    use crate::settings::mock_settings;
    use config::{Config, File};
    use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, VmStateCache};
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, UserPaymentMethod,
    };
    use payments_rs::fiat::RevolutConfig;
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct HarnessConfig {
        revolut: RevolutConfig,
    }

    /// Load the sandbox Revolut config from config.local.yaml (repo root).
    fn load_revolut() -> Option<RevolutConfig> {
        // Test runs from the crate dir (lnvps_api/), config.local.yaml is at the
        // workspace root.
        for p in ["../config.local.yaml", "config.local.yaml"] {
            if PathBuf::from(p).exists() {
                let cfg: HarnessConfig = Config::builder()
                    .add_source(File::from(PathBuf::from(p)))
                    .build()
                    .ok()?
                    .try_deserialize()
                    .ok()?;
                return Some(cfg.revolut);
            }
        }
        None
    }

    /// End-to-end auto-renew against the Revolut sandbox. Requires:
    ///   - config.local.yaml with a `revolut:` sandbox section
    ///   - a previously-saved sandbox customer + payment method (env below)
    /// Run with:
    ///   REVOLUT_TEST_CUSTOMER=<id> REVOLUT_TEST_PM=<id> \
    ///     cargo test -p lnvps_api --features revolut -- --ignored autorenew
    #[tokio::test]
    #[ignore = "hits the Revolut sandbox; needs config.local.yaml + saved method env"]
    async fn auto_renew_via_revolut_charges_saved_card() -> Result<()> {
        let Some(revolut) = load_revolut() else {
            eprintln!("skipping: no config.local.yaml revolut section");
            return Ok(());
        };
        let customer_id = std::env::var("REVOLUT_TEST_CUSTOMER")
            .expect("set REVOLUT_TEST_CUSTOMER to a saved sandbox customer id");
        let payment_method_id = std::env::var("REVOLUT_TEST_PM")
            .expect("set REVOLUT_TEST_PM to a saved sandbox payment method id");

        let mut settings = mock_settings();
        settings.revolut = Some(revolut);

        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());

        // Seed user + saved Revolut method + auto-renew subscription (EUR).
        let user_id = db.upsert_user(&[7u8; 32]).await?;
        db.insert_user_payment_method(&UserPaymentMethod {
            id: 0,
            user_id,
            created: Utc::now(),
            provider: "revolut".to_string(),
            name: None,
            external_customer_id: Some(customer_id.into()),
            external_id: payment_method_id.into(),
            card_brand: Some("VISA".to_string()),
            card_last_four: Some("5709".to_string()),
            exp_month: Some(12),
            exp_year: Some(2029),
            is_default: true,
            enabled: true,
        })
        .await?;

        let (sub_id, _items) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "autorenew-test".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: true,
                    is_setup: true, // already purchased -> Renewal
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: true,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::IpRange,
                    name: "hosting".to_string(),
                    description: None,
                    amount: 999, // €9.99
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await?;

        let sub = SubscriptionHandler::new(
            settings,
            db.clone(),
            node.clone(),
            Arc::new(MockExchangeRate::default()),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )?;

        let payment = sub.auto_renew_via_revolut(sub_id).await?;

        assert_eq!(payment.payment_method, PaymentMethod::Revolut);
        assert_eq!(payment.currency, "EUR");
        assert_eq!(payment.amount, 999);
        let ext_id = payment.external_id.expect("revolut order id");
        eprintln!("off-session charge order id = {ext_id}");

        // The payment row should be persisted and unpaid (completed via webhook).
        let stored = db.list_subscription_payments(sub_id).await?;
        assert!(stored.iter().any(|p| p.id == payment.id));
        Ok(())
    }
}

#[cfg(test)]
mod revolut_offline_tests {
    use super::*;
    use crate::mocks::MockNode;
    use crate::settings::mock_settings;
    use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, VmStateCache};
    use lnvps_db::{
        IntervalType, LNVpsDbBase, Subscription, SubscriptionLineItem, UserPaymentMethod,
    };
    use payments_rs::currency::CurrencyAmount;
    use payments_rs::fiat::{FiatPaymentInfo, LineItem, SubscriptionPaymentInfo};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// A FiatPaymentService mock that records calls for assertions.
    #[derive(Default)]
    struct MockFiat {
        charged: Mutex<Vec<(String, String, u64)>>,
        created_subscription: Mutex<bool>,
        created_order: Mutex<bool>,
    }

    impl FiatPaymentService for MockFiat {
        fn create_order(
            &self,
            _d: &str,
            _amount: CurrencyAmount,
            _li: Option<Vec<LineItem>>,
        ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>> {
            *self.created_order.lock().unwrap() = true;
            Box::pin(async {
                Ok(FiatPaymentInfo {
                    external_id: "order_mock".to_string(),
                    raw_data: "{}".to_string(),
                })
            })
        }
        fn cancel_order(&self, _id: &str) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
            Box::pin(async { Ok(()) })
        }
        fn create_subscription(
            &self,
            _d: &str,
            _a: CurrencyAmount,
            _e: Option<String>,
            _li: Option<Vec<LineItem>>,
        ) -> Pin<Box<dyn Future<Output = Result<SubscriptionPaymentInfo>> + Send>> {
            *self.created_subscription.lock().unwrap() = true;
            Box::pin(async {
                Ok(SubscriptionPaymentInfo {
                    external_id: "sub_mock".to_string(),
                    customer_id: Some("cust_mock".to_string()),
                    payment_method_id: None,
                    checkout_url: Some("https://checkout".to_string()),
                    raw_data: "{}".to_string(),
                })
            })
        }
        fn charge_subscription(
            &self,
            customer_id: &str,
            payment_method_id: &str,
            amount: CurrencyAmount,
            _d: &str,
        ) -> Pin<Box<dyn Future<Output = Result<FiatPaymentInfo>> + Send>> {
            self.charged.lock().unwrap().push((
                customer_id.to_string(),
                payment_method_id.to_string(),
                amount.value(),
            ));
            Box::pin(async {
                Ok(FiatPaymentInfo {
                    external_id: "charge_mock".to_string(),
                    raw_data: "{}".to_string(),
                })
            })
        }
    }

    fn mk_method(user_id: u64, cust: &str, pm: &str, default: bool, enabled: bool, exp: (u16, u16)) -> UserPaymentMethod {
        UserPaymentMethod {
            id: 0,
            user_id,
            created: Utc::now(),
            provider: "revolut".to_string(),
            name: None,
            external_customer_id: Some(cust.to_string().into()),
            external_id: pm.to_string().into(),
            card_brand: Some("VISA".to_string()),
            card_last_four: Some("5709".to_string()),
            exp_month: Some(exp.1),
            exp_year: Some(exp.0),
            is_default: default,
            enabled,
        }
    }

    async fn setup(auto_renew: bool) -> (Arc<MockDb>, SubscriptionHandler, u64, u64) {
        let db = Arc::new(MockDb::default());
        let node = Arc::new(MockNode::default());
        let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
        let (sub_id, _items) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    id: 0,
                    user_id,
                    company_id: 1,
                    name: "s".to_string(),
                    description: None,
                    created: Utc::now(),
                    expires: None,
                    is_active: true,
                    is_setup: true,
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    setup_fee: 0,
                    auto_renewal_enabled: auto_renew,
                    external_id: None,
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: SubscriptionType::IpRange,
                    name: "hosting".to_string(),
                    description: None,
                    amount: 999,
                    setup_amount: 0,
                    configuration: None,
                }],
            )
            .await
            .unwrap();
        let sub = SubscriptionHandler::new(
            mock_settings(),
            db.clone(),
            node,
            Arc::new(MockExchangeRate::default()),
            Arc::new(ChannelWorkCommander::new()),
            VmStateCache::new(),
        )
        .unwrap();
        (db, sub, user_id, sub_id)
    }

    #[tokio::test]
    async fn test_default_revolut_payment_method_selection() {
        let (db, sub, user_id, _sub_id) = setup(true).await;

        // No methods -> error
        assert!(sub.default_revolut_payment_method(user_id).await.is_err());

        // Default enabled non-expired method is chosen
        let d = db
            .insert_user_payment_method(&mk_method(user_id, "cA", "pA", true, true, (2999, 12)))
            .await
            .unwrap();
        let got = sub.default_revolut_payment_method(user_id).await.unwrap();
        assert_eq!(got.id, d);

        // Expire the default; add a non-default enabled non-expired one -> that is chosen
        let mut expired = db.get_user_payment_method(d).await.unwrap();
        expired.exp_year = Some(2000);
        db.update_user_payment_method(&expired).await.unwrap();
        let good = db
            .insert_user_payment_method(&mk_method(user_id, "cB", "pB", false, true, (2999, 12)))
            .await
            .unwrap();
        assert_eq!(sub.default_revolut_payment_method(user_id).await.unwrap().id, good);

        // Disable all remaining -> error
        let mut g = db.get_user_payment_method(good).await.unwrap();
        g.enabled = false;
        db.update_user_payment_method(&g).await.unwrap();
        assert!(sub.default_revolut_payment_method(user_id).await.is_err());
    }

    #[tokio::test]
    async fn test_auto_renew_via_revolut_offline() {
        let (db, mut sub, user_id, sub_id) = setup(true).await;
        db.insert_user_payment_method(&mk_method(user_id, "cust1", "pm1", true, true, (2999, 12)))
            .await
            .unwrap();
        let fiat = Arc::new(MockFiat::default());
        sub.set_revolut_for_test(fiat.clone());

        let payment = sub.auto_renew_via_revolut(sub_id).await.unwrap();
        assert_eq!(payment.payment_method, PaymentMethod::Revolut);
        assert_eq!(payment.currency, "EUR");
        assert_eq!(payment.amount, 999);

        let charged = fiat.charged.lock().unwrap();
        assert_eq!(charged.len(), 1);
        assert_eq!(charged[0].0, "cust1");
        assert_eq!(charged[0].1, "pm1");

        // Payment row persisted
        assert!(db
            .list_subscription_payments(sub_id)
            .await
            .unwrap()
            .iter()
            .any(|p| p.id == payment.id));
    }

    #[tokio::test]
    async fn test_auto_renew_via_revolut_no_method_errors() {
        let (_db, mut sub, _user_id, sub_id) = setup(true).await;
        sub.set_revolut_for_test(Arc::new(MockFiat::default()));
        assert!(sub.auto_renew_via_revolut(sub_id).await.is_err());
    }

    #[tokio::test]
    async fn test_auto_renew_dispatches_by_provider() {
        // Default method is a revolut card -> auto_renew dispatches to Revolut.
        let (db, mut sub, user_id, sub_id) = setup(true).await;
        db.insert_user_payment_method(&mk_method(user_id, "cust1", "pm1", true, true, (2999, 12)))
            .await
            .unwrap();
        let fiat = Arc::new(MockFiat::default());
        sub.set_revolut_for_test(fiat.clone());

        let payment = sub.auto_renew(sub_id).await.unwrap();
        assert_eq!(payment.payment_method, PaymentMethod::Revolut);
        assert_eq!(fiat.charged.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_default_payment_method_prefers_default_flag() {
        // NWC is the default even though a revolut method also exists.
        let (db, sub, user_id, _sub_id) = setup(true).await;
        let nwc = UserPaymentMethod {
            id: 0,
            user_id,
            created: Utc::now(),
            provider: "nwc".to_string(),
            name: None,
            external_customer_id: None,
            external_id: "nostr+walletconnect://x".to_string().into(),
            card_brand: None,
            card_last_four: None,
            exp_month: None,
            exp_year: None,
            is_default: true,
            enabled: true,
        };
        db.insert_user_payment_method(&nwc).await.unwrap();
        db.insert_user_payment_method(&mk_method(user_id, "c", "p", false, true, (2999, 12)))
            .await
            .unwrap();

        let got = sub.default_payment_method(user_id).await.unwrap();
        assert_eq!(got.provider, "nwc");
    }

    #[tokio::test]
    async fn test_create_revolut_order_saves_when_no_method() {
        // auto-renew on, no saved method -> create_subscription (savable checkout)
        let (_db, mut sub, _user_id, sub_id) = setup(true).await;
        let fiat = Arc::new(MockFiat::default());
        sub.set_revolut_for_test(fiat.clone());

        sub.renew_subscription(sub_id, PaymentMethod::Revolut, 1)
            .await
            .unwrap();
        assert!(*fiat.created_subscription.lock().unwrap());
        assert!(!*fiat.created_order.lock().unwrap());
    }

    #[tokio::test]
    async fn test_create_revolut_order_plain_when_method_exists() {
        // A saved method already exists -> plain create_order (no re-save)
        let (db, mut sub, user_id, sub_id) = setup(true).await;
        db.insert_user_payment_method(&mk_method(user_id, "cust1", "pm1", true, true, (2999, 12)))
            .await
            .unwrap();
        let fiat = Arc::new(MockFiat::default());
        sub.set_revolut_for_test(fiat.clone());

        sub.renew_subscription(sub_id, PaymentMethod::Revolut, 1)
            .await
            .unwrap();
        assert!(*fiat.created_order.lock().unwrap());
        assert!(!*fiat.created_subscription.lock().unwrap());
    }
}
