use crate::subscription::SubscriptionHandler;
use anyhow::Result;
use async_trait::async_trait;
use lnvps_api_common::{
    GatewayEvent, GatewayInvoice, GatewayInvoiceRequest, PaymentGateway, is_gateway_payment,
};
use lnvps_db::{LNVpsDb, SubscriptionPayment};
use log::{info, warn};
use payments_rs::lightning::{AddInvoiceRequest, LightningNode};
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
}

pub async fn handle_gateway_event(
    db: &Arc<dyn LNVpsDb>,
    sub_handler: &SubscriptionHandler,
    event: &GatewayEvent,
) -> Result<GatewayEventOutcome> {
    match event.kind.as_str() {
        "payment.paid" => {}
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
        &sub_handler.lightning_gateway(),
        result.expired_competing_upgrades,
    )
    .await;
    Ok(GatewayEventOutcome::Settled)
}

async fn cancel_competing(gateway: &Arc<dyn PaymentGateway>, competing: Vec<SubscriptionPayment>) {
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
