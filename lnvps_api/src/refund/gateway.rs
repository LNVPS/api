use super::*;
use lnvps_api_common::is_gateway_payment;

fn gateway_refund_msat(payment: &SubscriptionPayment, cash: u64) -> Option<u64> {
    if payment.currency.eq_ignore_ascii_case("BTC") {
        return Some(cash);
    }
    if payment.rate <= 0.0 {
        return None;
    }
    Some((cash as f64 * 1e9 / payment.rate as f64).floor() as u64)
}

impl VmRefundHandler {
    pub fn with_gateway(mut self, gateway: Option<Arc<dyn PaymentGateway>>) -> Self {
        self.gateway = gateway;
        self
    }

    pub fn with_gateway_directory(mut self, directory: lnvps_api_common::GatewayDirectory) -> Self {
        self.directory = Some(directory);
        self
    }

    async fn refund_gateway(&self, vm_id: u64) -> Result<Option<Arc<dyn PaymentGateway>>> {
        if let Some(g) = &self.gateway {
            return Ok(Some(g.clone()));
        }
        let Some(directory) = &self.directory else {
            return Ok(None);
        };
        let company_id = self.db.get_vm_company_id(vm_id).await?;
        directory.in_flight(company_id).await
    }

    pub async fn process_gateway(
        &self,
        vm_id: u64,
        admin_user_id: u64,
        refund_from_date: Option<DateTime<Utc>>,
        reason: Option<&str>,
        destination: Option<&str>,
    ) -> Result<RefundOutcome> {
        let gateway = self
            .refund_gateway(vm_id)
            .await?
            .ok_or_else(|| anyhow!("the payment gateway is not configured"))?;
        let vm = self.db.get_vm(vm_id).await?;
        ensure!(!vm.deleted, "VM {} is already deleted", vm_id);

        let from_date = refund_from_date.unwrap_or_else(Utc::now);
        let quote = self
            .pricing
            .calculate_vm_refund_amount_from_date(vm_id, PaymentMethod::Lightning, from_date)
            .await?;
        let owed_msat = quote.amount.value();
        let booked = quote.rate.convert(CurrencyAmount::millisats(owed_msat))?;
        let currency = booked.currency().to_string();
        ensure!(
            booked.value() > 0,
            "VM {} is owed nothing in {} from {}",
            vm_id,
            currency,
            from_date
        );

        let plan = self
            .gateway_allocation(vm_id, &currency, booked.value())
            .await
            .map_err(|e| anyhow!("VM {} refund cannot go through the gateway: {}", vm_id, e))?;
        let planned: u64 = plan.iter().map(|s| s.amount).sum();

        let refunded_at = Utc::now();
        let mut refund_rows = 0;
        let mut booked_amount = 0;
        let mut credit_returned = Vec::new();
        let mut failures = Vec::new();
        for share in plan {
            let RefundShare {
                payment: original,
                amount,
                cash,
                credit,
                credit_currency,
            } = share;
            let external_id = original.external_id.clone().unwrap_or_default();
            let gateway_amount = gateway_refund_msat(&original, cash);
            let refund = match gateway
                .refund_payment(&external_id, gateway_amount, destination)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        "Gateway refund of {} {} against payment {} for VM {} failed: {}",
                        cash,
                        currency,
                        hex::encode(&original.id),
                        vm_id,
                        e
                    );
                    failures.push(format!("{}: {}", hex::encode(&original.id), e));
                    continue;
                }
            };
            let gateway_ref = format!("pgw-refund:{}", refund.id);
            let mut row = build_refund_row(
                &original,
                amount,
                refunded_at,
                admin_user_id,
                RefundEvidence {
                    reason,
                    external_ref: Some(&gateway_ref),
                    instrument: destination,
                },
            );
            row.id = crate::payments::gateway::gateway_refund_row_id(&original.id, refund.id);
            if let Err(e) = self.db.insert_subscription_payment(&row).await {
                error!(
                    "PAID BUT UNRECORDED: gateway refund {} of {} {} against payment {} for VM {} \
                     could not be written: {}",
                    refund.id,
                    amount,
                    row.currency,
                    hex::encode(&original.id),
                    vm_id,
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
                        &credit_currency,
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
                    Ok(_) => add_credit(&mut credit_returned, &credit_currency, credit),
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
                error!("Refund recorded but VM history entry failed for VM {vm_id}: {e}");
            }
        }

        if !failures.is_empty() {
            bail!(
                "VM {} gateway refund booked {} of {} {}; failed on: {}",
                vm_id,
                booked_amount,
                planned,
                currency,
                failures.join(", ")
            );
        }

        Ok(RefundOutcome {
            amount_msat: owed_msat,
            fee_msat: 0,
            preimage: None,
            booked_amount,
            currency,
            refund_rows,
            credit_returned,
        })
    }

    async fn gateway_allocation(
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
            .filter(|p| {
                p.is_paid
                    && !p.payment_type.is_refund()
                    && p.currency == currency
                    && p.payment_method != PaymentMethod::Lightning
                    && is_gateway_payment(p.external_id.as_deref())
            })
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
    use super::super::tests::{PayNode, handler, vm_with_payment};
    use super::*;
    use lnvps_api_common::{FakeGateway, MockDb};

    async fn gateway_payment(db: &MockDb, payment: &SubscriptionPayment, method: PaymentMethod) {
        let mut payments = db.subscription_payments.lock().await;
        let row = payments.iter_mut().find(|p| p.id == payment.id).unwrap();
        row.payment_method = method;
        row.external_id = Some("pgw:gw1".to_string());
    }

    #[tokio::test]
    async fn refunds_a_gateway_payment_through_refund_payment() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        gateway_payment(&mock, &payment, PaymentMethod::OnChain).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let node = Arc::new(PayNode::default());
        let fake = Arc::new(FakeGateway::default());
        let handler = handler(db.clone(), node.clone())
            .await
            .with_gateway(Some(fake.clone()));

        let outcome = handler
            .process_gateway(1, 9, None, Some("e2e"), Some("bc1qdest"))
            .await
            .expect("refund");

        assert!(
            node.paid.lock().unwrap().is_empty(),
            "the node pays nothing"
        );
        let calls = fake.refunds.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "pgw:gw1");
        assert_eq!(calls[0].2.as_deref(), Some("bc1qdest"));
        assert!(calls[0].1.unwrap() > 0);
        assert_eq!(outcome.refund_rows, 1);
        assert!(outcome.booked_amount > 0);

        let refunds = db.list_refunds_for_payment(&payment.id).await.unwrap();
        assert_eq!(refunds.len(), 1);
        assert!(refunds[0].payment_type.is_refund());
        assert_eq!(
            refunds[0].metadata.as_ref().unwrap()["refund"]["external_ref"],
            "pgw-refund:1"
        );
    }

    #[tokio::test]
    async fn lightning_payments_are_never_refunded_through_the_gateway() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        {
            let mut payments = mock.subscription_payments.lock().await;
            let row = payments.iter_mut().find(|p| p.id == payment.id).unwrap();
            row.external_id = Some("pgw:gw1".to_string());
        }
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let fake = Arc::new(FakeGateway::default());
        let handler = handler(db, Arc::new(PayNode::default()))
            .await
            .with_gateway(Some(fake.clone()));

        let err = handler
            .process_gateway(1, 9, None, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot go through the gateway"), "{err}");
        assert!(fake.refunds.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_rejected_gateway_refund_books_nothing() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        gateway_payment(&mock, &payment, PaymentMethod::OnChain).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let fake = Arc::new(FakeGateway::default());
        *fake.fail_refunds.lock().unwrap() = true;
        let handler = handler(db.clone(), Arc::new(PayNode::default()))
            .await
            .with_gateway(Some(fake));

        assert!(
            handler
                .process_gateway(1, 9, None, None, None)
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

    #[tokio::test]
    async fn a_refund_completed_event_after_the_payout_is_not_booked_twice() {
        use crate::payments::gateway::{GatewayEventOutcome, handle_gateway_event};
        use lnvps_api_common::GatewayEvent;
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        gateway_payment(&mock, &payment, PaymentMethod::FixedFloat).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let fake = Arc::new(FakeGateway::default());
        let handler = handler(db.clone(), Arc::new(PayNode::default()))
            .await
            .with_gateway(Some(fake.clone()));
        let outcome = handler
            .process_gateway(1, 9, None, None, None)
            .await
            .unwrap();

        let sub = crate::subscription::SubscriptionHandler::new(
            crate::settings::mock_settings(),
            db.clone(),
            Arc::new(PayNode::default()),
            Arc::new(crate::mocks::MockOnChainProvider::default()),
            None,
            Arc::new(lnvps_api_common::MockExchangeRate::default()),
            lnvps_api_common::VatClient::new(),
            Arc::new(lnvps_api_common::ChannelWorkCommander::new()),
            lnvps_api_common::VmStateCache::new(),
        )
        .unwrap();
        let event = GatewayEvent {
            event_id: "r1".into(),
            kind: "refund.completed".into(),
            reference: hex::encode(&payment.id),
            status: "refunded".into(),
            refund_id: Some(1),
            amount: Some(outcome.booked_amount),
            reason: None,
        };
        for _ in 0..2 {
            assert_eq!(
                handle_gateway_event(&db, &sub, &event).await.unwrap(),
                GatewayEventOutcome::Ignored
            );
        }
        assert_eq!(
            db.list_refunds_for_payment(&payment.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_second_refund_cannot_exceed_what_is_left() {
        let mock = MockDb::default();
        let (_vm, payment) = vm_with_payment(&mock, 1230, 230).await;
        gateway_payment(&mock, &payment, PaymentMethod::OnChain).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let fake = Arc::new(FakeGateway::default());
        let handler = handler(db.clone(), Arc::new(PayNode::default()))
            .await
            .with_gateway(Some(fake.clone()));
        let first = handler
            .process_gateway(1, 9, None, None, None)
            .await
            .unwrap();
        let second = handler.process_gateway(1, 9, None, None, None).await;
        let booked: u64 = db
            .list_refunds_for_payment(&payment.id)
            .await
            .unwrap()
            .iter()
            .map(|r| r.amount + r.tax)
            .sum();
        assert!(booked <= payment.amount + payment.tax, "{booked}");
        assert!(first.booked_amount > 0);
        if let Ok(s) = second {
            assert!(s.booked_amount + first.booked_amount <= payment.amount + payment.tax);
        }
    }

    #[tokio::test]
    async fn gateway_refund_needs_a_configured_gateway() {
        let mock = MockDb::default();
        vm_with_payment(&mock, 1230, 230).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let handler = handler(db, Arc::new(PayNode::default())).await;
        let err = handler
            .process_gateway(1, 9, None, None, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not configured"), "{err}");
    }
}
