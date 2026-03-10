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
use chrono::Utc;
use lnvps_api_common::{
    CostResult, ExchangeRateService, NewPaymentInfo, PricingEngine, UpgradeConfig, WorkCommander,
    round_msat_to_sat,
};
use lnvps_db::{
    LNVpsDb, PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionPayment,
    SubscriptionPaymentType, SubscriptionType,
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
}

impl SubscriptionHandler {
    pub fn new(
        settings: Settings,
        db: Arc<dyn LNVpsDb>,
        node: Arc<dyn LightningNode>,
        rates: Arc<dyn ExchangeRateService>,
        tx: Arc<dyn WorkCommander>,
    ) -> Self {
        Self {
            revolut: settings.get_revolut().expect("revolut config"),
            pe: PricingEngine::new(db.clone(), rates, settings.tax_rate.clone()),
            vm_provisioner: VmProvisioner::new(settings, db.clone()),
            db,
            tx,
            node,
        }
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
                    )
                    .await?,
                ))
            }
            SubscriptionType::IpRange => Ok(Box::new(IpRangeLineItemHandler::new(
                self.db.clone(),
                self.tx.clone(),
            ))),
            _ => {
                unimplemented!()
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
            // Cancel other pending Lightning upgrade invoices for this subscription
            let vm = self
                .db
                .get_vm_by_subscription(payment.subscription_id)
                .await?;
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

    /// Create a renewal/purchase payment for a subscription
    pub async fn renew_subscription(
        &self,
        subscription_id: u64,
        method: PaymentMethod,
        intervals: u32,
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

        // Convert non-VM amounts to the payment method currency if any exist
        let (non_vm_converted_amount, non_vm_rate, non_vm_tax, non_vm_processing_fee): (
            u64,
            f32,
            u64,
            u64,
        ) = if non_vm_interval_cost > 0 {
            let mut base = non_vm_interval_cost;
            if !subscription.is_setup {
                base += setup_fee;
            }
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
                let order = rev.create_order(&desc, order_amount, None).await?;

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
                    external_data: order.raw_data.into(),
                    external_id: Some(order.external_id),
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
                        let order = rev
                            .create_order(
                                &desc,
                                CurrencyAmount::from_u64(
                                    p.currency,
                                    p.amount + p.tax + p.processing_fee,
                                ),
                                None,
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
                            external_data: order.raw_data.into(),
                            external_id: Some(order.external_id),
                            is_paid: false,
                            rate: p.rate.rate,
                            time_value: Some(p.time_value),
                            metadata,
                            tax: p.tax,
                            processing_fee: p.processing_fee,
                            paid_at: None,
                        }
                    }
                    PaymentMethod::Paypal => todo!(),
                    PaymentMethod::Stripe => {
                        todo!("Stripe payment integration not yet implemented")
                    }
                };

                self.db.insert_subscription_payment(&payment).await?;

                Ok(payment)
            }
        }
    }

    #[cfg(feature = "nostr-nwc")]
    /// Attempt automatic renewal via Nostr Wallet Connect
    pub async fn auto_renew_via_nwc(
        &self,
        sub_id: u64,
        nwc_string: &str,
    ) -> Result<SubscriptionPayment> {
        use nostr_sdk::prelude::*;

        debug!("Attempting automatic renewal for sub {} via NWC", sub_id);

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
        let nwc_uri =
            NostrWalletConnectUri::from_str(nwc_string).context("Invalid NWC connection string")?;

        // Create nostr client for NWC
        let client = nwc::NostrWalletConnect::new(nwc_uri);
        client.pay_invoice(PayInvoiceRequest::new(invoice)).await?;
        info!("Successful NWC auto-renewal payment for sub {}", sub_id);
        Ok(vm_payment)
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
