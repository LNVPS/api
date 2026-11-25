use crate::subscription::SubscriptionHandler;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use lnvps_api_common::{
    GatewayEvent, GATEWAY_DEPOSIT_KEY, GatewayInvoice, GatewayInvoiceRequest, PaymentGateway, RefundEvidence, WorkJob,
    build_refund_row, is_gateway_payment, refundable_remaining,
};
use lnvps_db::{LNVpsDb, PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
use log::{info, warn};
use payments_rs::lightning::{AddInvoiceRequest, LightningNode};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct InProcessGateway {
    node: Arc<dyn LightningNode>,
}

impl InProcessGateway {
    pub fn new(node: Arc<dyn LightningNode>) -> Self {
        Self { node }
    }
}

#[async_trait]
impl PaymentGateway for InProcessGateway {
    async fn create_lightning_invoice(&self, req: GatewayInvoiceRequest) -> Result<GatewayInvoice> {
        let invoice = self
            .node
            .add_invoice(AddInvoiceRequest {
                memo: Some(req.description),
                amount: req.amount_msat,
                expire: Some(req.expires_in_secs),
            })
            .await?;
        Ok(GatewayInvoice {
            payment_id: hex::decode(invoice.payment_hash())?,
            bolt11: invoice.pr(),
            external_id: invoice.external_id,
        })
    }

    async fn cancel(&self, _external_id: Option<&str>, payment_id: &[u8]) -> Result<()> {
        self.node.cancel_invoice(payment_id).await
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GatewayEventOutcome {
    Settled,
    AlreadySettled,
    Ignored,
    UnknownPayment,
    Failed,
    Refunded,
}

pub(crate) fn gateway_refund_row_id(payment_id: &[u8], refund_id: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"lnvps-gateway-refund-v1");
    h.update(payment_id);
    h.update(refund_id.to_be_bytes());
    h.finalize().to_vec()
}

async fn find_gateway_payment(
    db: &Arc<dyn LNVpsDb>,
    reference: &str,
) -> Option<SubscriptionPayment> {
    let id = hex::decode(reference).ok()?;
    let payment = db.get_subscription_payment(&id).await.ok()?;
    is_gateway_payment(payment.external_id.as_deref()).then_some(payment)
}

async fn handle_attempt_received(
    db: &Arc<dyn LNVpsDb>,
    event: &GatewayEvent,
) -> Result<GatewayEventOutcome> {
    let Some(deposit) = event.deposit.as_deref() else {
        return Ok(GatewayEventOutcome::Ignored);
    };
    let Some(mut payment) = find_gateway_payment(db, &event.reference).await else {
        return Ok(GatewayEventOutcome::UnknownPayment);
    };
    if payment.is_paid {
        return Ok(GatewayEventOutcome::AlreadySettled);
    }
    let mut metadata = match payment.metadata.take() {
        Some(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    if metadata.get(GATEWAY_DEPOSIT_KEY).and_then(|v| v.as_str()) == Some(deposit) {
        payment.metadata = Some(serde_json::Value::Object(metadata));
        return Ok(GatewayEventOutcome::Ignored);
    }
    metadata.insert(GATEWAY_DEPOSIT_KEY.into(), deposit.into());
    payment.metadata = Some(serde_json::Value::Object(metadata));
    db.update_subscription_payment(&payment).await?;
    Ok(GatewayEventOutcome::Ignored)
}

async fn handle_attempt_failed(
    db: &Arc<dyn LNVpsDb>,
    sub_handler: &SubscriptionHandler,
    event: &GatewayEvent,
) -> Result<GatewayEventOutcome> {
    let Some(mut payment) = find_gateway_payment(db, &event.reference).await else {
        return Ok(GatewayEventOutcome::UnknownPayment);
    };
    let now = Utc::now();
    if payment.is_paid || payment.expires <= now {
        return Ok(GatewayEventOutcome::Ignored);
    }
    payment.expires = now;
    db.update_subscription_payment(&payment).await?;
    let reason = event
        .reason
        .as_deref()
        .unwrap_or("the payment was declined");
    sub_handler
        .work_commander()
        .send(WorkJob::SendNotification {
            user_id: payment.user_id,
            message: format!(
                "Your card payment failed: {reason}.\nPlease try another payment method."
            ),
            title: Some("Payment failed".to_string()),
        })
        .await?;
    Ok(GatewayEventOutcome::Failed)
}

async fn handle_refund_completed(
    db: &Arc<dyn LNVpsDb>,
    event: &GatewayEvent,
) -> Result<GatewayEventOutcome> {
    let (Some(refund_id), Some(amount)) = (event.refund_id, event.amount) else {
        warn!(
            "Gateway refund event {} has no refund detail",
            event.event_id
        );
        return Ok(GatewayEventOutcome::Ignored);
    };
    let Some(original) = find_gateway_payment(db, &event.reference).await else {
        return Ok(GatewayEventOutcome::UnknownPayment);
    };
    if !original.is_paid || original.payment_type == SubscriptionPaymentType::Refund {
        return Ok(GatewayEventOutcome::Ignored);
    }
    let row_id = gateway_refund_row_id(&original.id, refund_id);
    if db.get_subscription_payment(&row_id).await.is_ok() {
        return Ok(GatewayEventOutcome::Ignored);
    }
    let existing = db.list_refunds_for_payment(&original.id).await?;
    let gross = amount.min(refundable_remaining(&original, &existing));
    if gross == 0 {
        return Ok(GatewayEventOutcome::Ignored);
    }
    let external_ref = format!("pgw-refund:{refund_id}");
    let mut row = build_refund_row(
        &original,
        gross,
        Utc::now(),
        0,
        RefundEvidence {
            reason: event.reason.as_deref(),
            external_ref: Some(&external_ref),
            instrument: None,
        },
    );
    row.id = row_id;
    db.insert_subscription_payment(&row).await?;
    Ok(GatewayEventOutcome::Refunded)
}

pub async fn cancel_expired_gateway_payments(
    db: &Arc<dyn LNVpsDb>,
    sub_handler: &SubscriptionHandler,
) -> Result<usize> {
    let mut cancelled = 0;
    for mut payment in db.list_expired_unpaid_gateway_payments(Utc::now()).await? {
        let gateway = match sub_handler.payment_gateway_for(&payment).await {
            Ok(g) => g,
            Err(e) => {
                warn!(
                    "Cannot find gateway for payment {}: {}",
                    hex::encode(&payment.id),
                    e
                );
                continue;
            }
        };
        let Some(gateway) = gateway else {
            continue;
        };
        match gateway
            .cancel(payment.external_id.as_deref(), &payment.id)
            .await
        {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    "Failed to cancel gateway payment {}: {}",
                    hex::encode(&payment.id),
                    e
                );
                continue;
            }
        }
        payment.external_id = payment
            .external_id
            .as_deref()
            .and_then(|e| e.strip_prefix(lnvps_api_common::GATEWAY_EXTERNAL_ID_PREFIX))
            .map(|id| format!("{CANCELLED_PREFIX}{id}"));
        db.update_subscription_payment(&payment).await?;
        cancelled += 1;
    }
    Ok(cancelled)
}

const CANCELLED_PREFIX: &str = "pgw-cancelled:";

pub async fn handle_gateway_event(
    db: &Arc<dyn LNVpsDb>,
    sub_handler: &SubscriptionHandler,
    event: &GatewayEvent,
) -> Result<GatewayEventOutcome> {
    match event.kind.as_str() {
        "payment.paid" => {}
        "attempt.failed" => return handle_attempt_failed(db, sub_handler, event).await,
        "attempt.received" => return handle_attempt_received(db, event).await,
        "refund.completed" => return handle_refund_completed(db, event).await,
        "payment.expired" | "payment.cancelled" => {
            info!("Gateway reports payment {} {}", event.reference, event.kind);
            return Ok(GatewayEventOutcome::Ignored);
        }
        _ => return Ok(GatewayEventOutcome::Ignored),
    }
    let Ok(id) = hex::decode(&event.reference) else {
        warn!("Gateway event {} has a non hex reference", event.event_id);
        return Ok(GatewayEventOutcome::UnknownPayment);
    };
    let Ok(payment) = db.get_subscription_payment(&id).await else {
        if let Some(topup) = db.get_account_credit_topup_by_hash(&id).await? {
            if topup.is_paid {
                return Ok(GatewayEventOutcome::AlreadySettled);
            }
            return Ok(match sub_handler.settle_credit_topup(topup.id).await? {
                Some(_) => GatewayEventOutcome::Settled,
                None => GatewayEventOutcome::AlreadySettled,
            });
        }
        return Ok(GatewayEventOutcome::UnknownPayment);
    };
    if payment.is_paid {
        return Ok(GatewayEventOutcome::AlreadySettled);
    }
    let result = sub_handler.complete_payment(&payment).await?;
    cancel_competing(
        &sub_handler.payment_gateway_for(&payment).await?,
        result.expired_competing_upgrades,
    )
    .await;
    Ok(GatewayEventOutcome::Settled)
}

async fn cancel_competing(
    gateway: &Option<Arc<dyn PaymentGateway>>,
    competing: Vec<SubscriptionPayment>,
) {
    let Some(gateway) = gateway else {
        return;
    };
    for p in competing {
        if !is_gateway_payment(p.external_id.as_deref()) {
            continue;
        }
        if let Err(e) = gateway.cancel(p.external_id.as_deref(), &p.id).await {
            warn!(
                "Failed to cancel gateway payment {}: {}",
                hex::encode(&p.id),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::invoice::tests::setup_renewal;
    use lnvps_api_common::FakeGateway;
    use lnvps_db::{LNVpsDbBase, PaymentMethod, SubscriptionPaymentType};

    async fn handler_with_rates(
        db: Arc<lnvps_api_common::MockDb>,
        gateway: Arc<FakeGateway>,
    ) -> Result<SubscriptionHandler> {
        let rates = Arc::new(lnvps_api_common::MockExchangeRate::default());
        lnvps_api_common::ExchangeRateService::set_rate(
            rates.as_ref(),
            lnvps_api_common::Ticker::btc_rate("EUR").unwrap(),
            100_000.0,
        )
        .await;
        Ok(SubscriptionHandler::new(
            crate::settings::mock_settings(),
            db,
            Arc::new(crate::mocks::MockNode::default()),
            Arc::new(crate::mocks::MockOnChainProvider::default()),
            None,
            rates,
            lnvps_api_common::VatClient::new(),
            Arc::new(lnvps_api_common::ChannelWorkCommander::new()),
            lnvps_api_common::VmStateCache::new(),
        )?
        .with_lightning_gateway(gateway))
    }

    fn paid_event(reference: &str) -> GatewayEvent {
        GatewayEvent {
            event_id: "e1".into(),
            kind: "payment.paid".into(),
            reference: reference.into(),
            status: "paid".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn gateway_invoice_is_stored_and_settled_once_by_webhook() -> Result<()> {
        let (db, _node, _sub, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake.clone()).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();

        let payment = sub
            .renew_subscription(existing.subscription_id, PaymentMethod::Lightning, 1)
            .await?;
        assert!(is_gateway_payment(payment.external_id.as_deref()));
        assert_eq!(fake.created.lock().unwrap().len(), 1);
        let created = fake.created.lock().unwrap()[0].clone();
        assert_eq!(created.customer_ref, existing.user_id.to_string());
        assert_eq!(created.payment_id, payment.id);
        assert_eq!(
            created.metadata["subscription_id"],
            existing.subscription_id
        );

        let event = paid_event(&hex::encode(&payment.id));
        let first = handle_gateway_event(&db_dyn, &sub, &event).await?;
        assert_eq!(first, GatewayEventOutcome::Settled);
        assert!(db.get_subscription_payment(&payment.id).await?.is_paid);
        let expiry = db.get_subscription(existing.subscription_id).await?.expires;

        let replay = handle_gateway_event(&db_dyn, &sub, &event).await?;
        assert_eq!(replay, GatewayEventOutcome::AlreadySettled);
        assert_eq!(
            db.get_subscription(existing.subscription_id).await?.expires,
            expiry
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_and_non_paid_events_change_nothing() -> Result<()> {
        let (db, _node, sub, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &paid_event("zz")).await?,
            GatewayEventOutcome::UnknownPayment
        );
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &paid_event(&hex::encode([7u8; 32]))).await?,
            GatewayEventOutcome::UnknownPayment
        );
        let expired = GatewayEvent {
            kind: "payment.expired".into(),
            ..paid_event(&hex::encode(&existing.id))
        };
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &expired).await?,
            GatewayEventOutcome::Ignored
        );
        assert!(!db.get_subscription_payment(&existing.id).await?.is_paid);
        Ok(())
    }

    #[tokio::test]
    async fn gateway_failure_fails_the_renewal_without_a_payment_row() -> Result<()> {
        let (db, _node, _sub, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        *fake.fail.lock().unwrap() = true;
        let sub = handler_with_rates(db.clone(), fake).await?;
        let before = db
            .list_subscription_payments(existing.subscription_id)
            .await?
            .len();
        assert!(
            sub.renew_subscription(existing.subscription_id, PaymentMethod::Lightning, 1)
                .await
                .is_err()
        );
        assert_eq!(
            db.list_subscription_payments(existing.subscription_id)
                .await?
                .len(),
            before
        );
        Ok(())
    }

    async fn issued_gateway_payment(
        db: &Arc<lnvps_api_common::MockDb>,
        sub: &SubscriptionHandler,
        subscription_id: u64,
    ) -> Result<SubscriptionPayment> {
        sub.renew_subscription(subscription_id, PaymentMethod::Lightning, 1)
            .await
    }

    fn kind_event(kind: &str, reference: &str) -> GatewayEvent {
        GatewayEvent {
            event_id: "ev".into(),
            kind: kind.into(),
            reference: reference.into(),
            ..Default::default()
        }
    }

    async fn drain_notifications(sub: &SubscriptionHandler) -> usize {
        let mut n = 0;
        while let Ok(Ok(jobs)) = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            sub.work_commander().recv(),
        )
        .await
        {
            n += jobs
                .iter()
                .filter(|j| matches!(j.job, WorkJob::SendNotification { .. }))
                .count();
        }
        n
    }

    #[tokio::test]
    async fn attempt_failed_expires_the_payment_notifies_and_never_extends() -> Result<()> {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let payment = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        let expiry_before = db.get_subscription(existing.subscription_id).await?.expires;
        let event = kind_event("attempt.failed", &hex::encode(&payment.id));

        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &event).await?,
            GatewayEventOutcome::Failed
        );
        let stored = db.get_subscription_payment(&payment.id).await?;
        assert!(!stored.is_paid);
        assert!(stored.expires <= Utc::now());
        assert_eq!(
            db.get_subscription(existing.subscription_id).await?.expires,
            expiry_before
        );
        assert_eq!(drain_notifications(&sub).await, 1);

        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &event).await?,
            GatewayEventOutcome::Ignored
        );
        assert_eq!(drain_notifications(&sub).await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn attempt_failed_for_an_unknown_or_non_gateway_payment_changes_nothing() -> Result<()> {
        let (db, _node, sub, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        for reference in [
            hex::encode([5u8; 32]),
            hex::encode(&existing.id),
            "zz".into(),
        ] {
            assert_eq!(
                handle_gateway_event(&db_dyn, &sub, &kind_event("attempt.failed", &reference))
                    .await?,
                GatewayEventOutcome::UnknownPayment
            );
        }
        assert!(db.get_subscription_payment(&existing.id).await?.expires > Utc::now());
        assert_eq!(drain_notifications(&sub).await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn attempt_failed_after_payment_is_a_no_op() -> Result<()> {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let payment = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        let reference = hex::encode(&payment.id);
        handle_gateway_event(&db_dyn, &sub, &paid_event(&reference)).await?;
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &kind_event("attempt.failed", &reference)).await?,
            GatewayEventOutcome::Ignored
        );
        assert!(db.get_subscription_payment(&payment.id).await?.is_paid);
        Ok(())
    }

    fn refund_event(reference: &str, refund_id: u64, amount: u64) -> GatewayEvent {
        GatewayEvent {
            refund_id: Some(refund_id),
            amount: Some(amount),
            ..kind_event("refund.completed", reference)
        }
    }

    #[tokio::test]
    async fn refund_completed_books_one_refund_row_and_does_not_recredit() -> Result<()> {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let payment = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        let reference = hex::encode(&payment.id);
        handle_gateway_event(&db_dyn, &sub, &paid_event(&reference)).await?;
        let paid = db.get_subscription_payment(&payment.id).await?;
        let gross = paid.amount + paid.tax;
        let expiry = db.get_subscription(existing.subscription_id).await?.expires;
        let credit_before = db
            .get_account_credit(paid.user_id, &paid.currency)
            .await
            .map(|c| c.balance)
            .unwrap_or(0);

        let event = refund_event(&reference, 9, gross / 2);
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &event).await?,
            GatewayEventOutcome::Refunded
        );
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &event).await?,
            GatewayEventOutcome::Ignored
        );
        let refunds = db.list_refunds_for_payment(&payment.id).await?;
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].amount + refunds[0].tax, gross / 2);
        assert_eq!(refunds[0].payment_type, SubscriptionPaymentType::Refund);
        assert_eq!(refunds[0].time_value, None);
        assert_eq!(
            db.get_subscription(existing.subscription_id).await?.expires,
            expiry
        );
        let credit_after = db
            .get_account_credit(paid.user_id, &paid.currency)
            .await
            .map(|c| c.balance)
            .unwrap_or(0);
        assert_eq!(credit_after, credit_before);

        let rest = refund_event(&reference, 10, gross);
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &rest).await?,
            GatewayEventOutcome::Refunded
        );
        let total: u64 = db
            .list_refunds_for_payment(&payment.id)
            .await?
            .iter()
            .map(|r| r.amount + r.tax)
            .sum();
        assert_eq!(total, gross);
        Ok(())
    }

    #[tokio::test]
    async fn refund_completed_for_unpaid_unknown_or_foreign_payments_changes_nothing() -> Result<()>
    {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let unpaid = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        assert_eq!(
            handle_gateway_event(
                &db_dyn,
                &sub,
                &refund_event(&hex::encode(&unpaid.id), 1, 10)
            )
            .await?,
            GatewayEventOutcome::Ignored
        );
        assert_eq!(
            handle_gateway_event(&db_dyn, &sub, &refund_event(&hex::encode([8u8; 32]), 1, 10))
                .await?,
            GatewayEventOutcome::UnknownPayment
        );
        assert_eq!(
            handle_gateway_event(
                &db_dyn,
                &sub,
                &refund_event(&hex::encode(&existing.id), 1, 10)
            )
            .await?,
            GatewayEventOutcome::UnknownPayment
        );
        assert!(db.list_refunds_for_payment(&unpaid.id).await?.is_empty());
        assert!(db.list_refunds_for_payment(&existing.id).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn expired_gateway_payments_are_cancelled_once_at_the_gateway() -> Result<()> {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake.clone()).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let live = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 0);
        assert!(fake.cancelled.lock().unwrap().is_empty());

        let mut expired = db.get_subscription_payment(&live.id).await?;
        expired.expires = Utc::now() - chrono::Duration::minutes(1);
        db.update_subscription_payment(&expired).await?;
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 1);
        assert_eq!(fake.cancelled.lock().unwrap().len(), 1);
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 0);
        assert_eq!(fake.cancelled.lock().unwrap().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn expiry_sweep_skips_paid_and_retries_after_a_gateway_failure() -> Result<()> {
        let (db, _node, _s, existing, _vm) =
            setup_renewal(86400, SubscriptionPaymentType::Renewal).await?;
        let fake = Arc::new(FakeGateway::default());
        let sub = handler_with_rates(db.clone(), fake.clone()).await?;
        let db_dyn: Arc<dyn LNVpsDb> = db.clone();
        let payment = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        let mut row = db.get_subscription_payment(&payment.id).await?;
        row.expires = Utc::now() - chrono::Duration::minutes(1);
        db.update_subscription_payment(&row).await?;

        *fake.fail_cancel.lock().unwrap() = true;
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 0);
        *fake.fail_cancel.lock().unwrap() = false;
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 1);

        let second = issued_gateway_payment(&db, &sub, existing.subscription_id).await?;
        handle_gateway_event(&db_dyn, &sub, &paid_event(&hex::encode(&second.id))).await?;
        let mut paid = db.get_subscription_payment(&second.id).await?;
        paid.expires = Utc::now() - chrono::Duration::minutes(1);
        db.update_subscription_payment(&paid).await?;
        assert_eq!(cancel_expired_gateway_payments(&db_dyn, &sub).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn in_process_gateway_creates_a_node_invoice() -> Result<()> {
        let node = Arc::new(crate::mocks::MockNode::default());
        let gw = InProcessGateway::new(node.clone());
        let inv = gw
            .create_lightning_invoice(GatewayInvoiceRequest {
                payment_id: vec![],
                amount_msat: 5000,
                tax_msat: 0,
                description: "x".into(),
                expires_in_secs: 600,
                customer_ref: "1".into(),
                metadata: serde_json::json!({}),
            })
            .await?;
        assert_eq!(inv.payment_id.len(), 32);
        assert!(!is_gateway_payment(inv.external_id.as_deref()));
        assert_eq!(node.invoices.lock().await.len(), 1);
        Ok(())
    }
}
