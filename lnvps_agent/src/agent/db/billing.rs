//! Billing tools: subscriptions, their payments, and IP-space products.
//!
//! A subscription is the object that actually expires and renews; the VM tools
//! reach payments *through* a VM, which cannot answer "what am I paying for"
//! when an account holds several products. `billing_state` is derived on the
//! model rather than inferred here, because "never paid" and "expired" need
//! opposite answers from support and are one boolean apart.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use lnvps_db::{Subscription, SubscriptionType};

use super::{DbToolExecutor, required_u64, tag};

impl DbToolExecutor {
    /// Load a subscription, confirming the scoped user owns it.
    ///
    /// The same authorisation boundary as [`Self::owned_vm`]: the id comes
    /// from the model, which the customer can influence.
    pub(super) async fn owned_subscription(
        &self,
        args: &HashMap<String, Value>,
    ) -> Result<Subscription> {
        let user_id = self.require_user()?;
        let id = required_u64(args, "subscription_id")?;
        let subscription = self.db.get_subscription(id).await?;
        if subscription.user_id != user_id {
            bail!("Subscription {} does not belong to you", id);
        }
        Ok(subscription)
    }

    /// What a subscription bills for, one entry per line item.
    ///
    /// The linked resource is resolved through the back-reference tables so the
    /// model can say "this is VM 42" rather than quoting a line item id at a
    /// customer.
    pub(super) async fn line_items(&self, subscription: &Subscription) -> Value {
        let items = self
            .db
            .list_subscription_line_items(subscription.id)
            .await
            .unwrap_or_default();
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let resource = match item.subscription_type {
                SubscriptionType::Vps => self
                    .db
                    .get_vm_by_subscription(subscription.id)
                    .await
                    .ok()
                    .map(|vm| json!({ "kind": "vm", "vm_id": vm.id })),
                SubscriptionType::App => self
                    .db
                    .get_app_deployment_by_line_item(item.id)
                    .await
                    .ok()
                    .map(|d| {
                        json!({
                            "kind": "app_deployment",
                            "deployment_id": d.id,
                            "name": d.name,
                        })
                    }),
                SubscriptionType::IpRange => self
                    .db
                    .list_ip_range_subscriptions_by_line_item(item.id)
                    .await
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| json!({ "kind": "ip_range", "cidr": r.cidr })),
                SubscriptionType::AsnSponsoring => self
                    .db
                    .list_asn_subscriptions_by_line_item(item.id)
                    .await
                    .ok()
                    .and_then(|r| r.into_iter().next())
                    .map(|r| json!({ "kind": "asn", "asn": r.asn })),
                _ => None,
            };
            out.push(json!({
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "type": item.subscription_type.to_string(),
                "amount": item.amount,
                "setup_amount": item.setup_amount,
                "currency": subscription.currency,
                "resource": resource,
            }));
        }
        Value::Array(out)
    }

    /// Subscription view. `billing_state` is derived on the model so the agent
    /// cannot confuse "never paid" with "expired" — the two need opposite
    /// answers from support.
    pub(super) async fn subscription_view(&self, subscription: &Subscription) -> Value {
        json!({
            "id": subscription.id,
            "name": subscription.name,
            "description": subscription.description,
            "created": subscription.created,
            "expires": subscription.expires,
            "is_active": subscription.is_active,
            "billing_state": subscription.billing_state(chrono::Utc::now()).to_string(),
            "currency": subscription.currency,
            "billing_interval": format!(
                "{} {}",
                subscription.interval_amount,
                tag(subscription.interval_type)
            ),
            "setup_fee": subscription.setup_fee,
            "auto_renewal_enabled": subscription.auto_renewal_enabled,
            "line_items": self.line_items(subscription).await,
        })
    }

    pub(super) async fn subscriptions(&self) -> Result<Value> {
        let subscriptions = self
            .db
            .list_subscriptions_by_user(self.require_user()?)
            .await?;
        let mut out = Vec::with_capacity(subscriptions.len());
        for subscription in &subscriptions {
            out.push(self.subscription_view(subscription).await);
        }
        Ok(Value::Array(out))
    }

    /// Payments against a subscription. Same redactions as the VM view:
    /// `external_data` is an encrypted payment instrument and `external_id` a
    /// processor reference, neither of which belongs in a model's context.
    pub(super) async fn subscription_payments(&self, subscription: &Subscription) -> Result<Value> {
        let (payments, total) = self
            .db
            .list_subscription_payments_paginated(subscription.id, 50, 0)
            .await?;
        Ok(json!({
            "subscription_id": subscription.id,
            "expires": subscription.expires,
            "total_payments": total,
            "payments": payments.into_iter().map(|p| json!({
                "id": hex::encode(&p.id),
                "created": p.created,
                "expires": p.expires,
                "amount": p.amount,
                "tax": p.tax,
                "processing_fee": p.processing_fee,
                "currency": p.currency,
                "payment_method": p.payment_method.to_string(),
                "payment_type": tag(p.payment_type),
                "is_paid": p.is_paid,
                "paid_at": p.paid_at,
            })).collect::<Vec<_>>(),
        }))
    }

    /// IP-space products: BYOIP / LIR ranges and sponsored ASNs.
    pub(super) async fn ip_subscriptions(&self) -> Result<Value> {
        let user_id = self.require_user()?;
        let ranges = self
            .db
            .list_ip_range_subscriptions_by_user(user_id)
            .await
            .unwrap_or_default();
        let asns = self
            .db
            .list_asn_subscriptions_by_user(user_id)
            .await
            .unwrap_or_default();
        Ok(json!({
            "ip_ranges": ranges.into_iter().map(|r| json!({
                "id": r.id,
                "cidr": r.cidr,
                "origin_asn": r.origin_asn,
                "is_active": r.is_active,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
            })).collect::<Vec<_>>(),
            "asns": asns.into_iter().map(|a| json!({
                "id": a.id,
                "asn": a.asn,
                "registry": a.registry.to_string(),
                "status": a.status.to_string(),
                "is_active": a.is_active,
                "assigned_at": a.assigned_at,
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::agent::ToolExecutor;
    use chrono::{Duration, Utc};
    use lnvps_api_common::MockDb;
    use lnvps_db::{IntervalType, SubscriptionLineItem, SubscriptionPayment};
    use std::sync::Arc;

    /// Seed a subscription owned by `user_id`, with one VPS line item.
    async fn seed_subscription(db: &Arc<MockDb>, id: u64, user_id: u64, is_setup: bool) {
        db.subscriptions.lock().await.insert(
            id,
            Subscription {
                id,
                user_id,
                company_id: 1,
                name: "VPS subscription".to_string(),
                description: None,
                created: Utc::now() - Duration::days(60),
                expires: Some(Utc::now() + Duration::days(5)),
                is_active: true,
                is_setup,
                currency: "EUR".to_string(),
                interval_amount: 1,
                interval_type: IntervalType::Month,
                setup_fee: 0,
                auto_renewal_enabled: true,
                external_id: None,
            },
        );
        db.subscription_line_items.lock().await.insert(
            id,
            SubscriptionLineItem {
                id,
                subscription_id: id,
                subscription_type: SubscriptionType::Vps,
                name: "VPS".to_string(),
                description: None,
                amount: 599,
                setup_amount: 0,
                configuration: None,
            },
        );
    }

    #[tokio::test]
    async fn lists_subscriptions_with_their_line_items() {
        let (db, exec) = executor(1).await;
        seed_subscription(&db, 7, 1, true).await;

        let out = exec.execute("list_my_subscriptions", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        // The mock seeds a subscription of its own, so select the seeded one
        // rather than assuming a position.
        let first = parsed
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == 7)
            .expect("seeded subscription");
        assert_eq!(first["billing_state"], "active");
        assert_eq!(first["billing_interval"], "1 month");
        assert_eq!(first["auto_renewal_enabled"], true);
        assert_eq!(first["line_items"][0]["amount"], 599);
        assert_eq!(first["line_items"][0]["type"], "VPS");
    }

    /// "Never paid" and "expired" need opposite answers from support, and are
    /// one boolean apart in the record.
    #[tokio::test]
    async fn an_unpaid_subscription_is_not_reported_as_expired() {
        let (db, exec) = executor(1).await;
        seed_subscription(&db, 7, 1, false).await;
        db.subscriptions.lock().await.get_mut(&7).unwrap().expires =
            Some(Utc::now() - Duration::days(1));

        let out = exec.execute("list_my_subscriptions", "{}").await.unwrap();
        assert!(out.contains("\"billing_state\": \"unpaid\""), "{out}");
    }

    /// The authorisation boundary for the billing group: a guessed id must not
    /// read another customer's invoices.
    #[tokio::test]
    async fn rejects_subscriptions_owned_by_another_user() {
        let (db, exec) = executor(1).await;
        seed_subscription(&db, 9, 2, true).await;

        for tool in ["get_subscription_details", "list_subscription_payments"] {
            let err = exec
                .execute(tool, r#"{"subscription_id":9}"#)
                .await
                .expect_err(&format!("{tool} must reject another user's subscription"));
            assert!(err.to_string().contains("does not belong to you"), "{err}");
        }

        // And the id itself is still required.
        let err = exec
            .execute("get_subscription_details", "{}")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("subscription_id required"));
    }

    /// Payments must never carry the encrypted payment instrument or the
    /// processor's reference into the model's context.
    #[tokio::test]
    async fn subscription_payments_omit_processor_data() {
        let (db, exec) = executor(1).await;
        seed_subscription(&db, 7, 1, true).await;
        db.subscription_payments
            .lock()
            .await
            .push(SubscriptionPayment {
                id: vec![0xaa; 32],
                subscription_id: 7,
                user_id: 1,
                created: Utc::now(),
                expires: Utc::now() + Duration::days(30),
                amount: 599,
                currency: "EUR".to_string(),
                external_data: "SECRET-INSTRUMENT".to_string().into(),
                external_id: Some("SECRET-PROCESSOR-REF".to_string()),
                is_paid: true,
                rate: 1.0,
                time_value: Some(30 * 24 * 3600),
                metadata: None,
                tax: 114,
                processing_fee: 10,
                paid_at: Some(Utc::now()),
                payment_method: lnvps_db::PaymentMethod::Lightning,
                payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
                tax_rate: None,
                tax_country_code: None,
                tax_treatment: None,
                tax_evidence: None,
                tax_breakdown: None,
                refunded_payment_id: None,
            });

        let out = exec
            .execute("list_subscription_payments", r#"{"subscription_id":7}"#)
            .await
            .unwrap();
        assert!(out.contains("\"amount\": 599"));
        assert!(out.contains("\"tax\": 114"));
        for leaked in [
            "SECRET-INSTRUMENT",
            "SECRET-PROCESSOR-REF",
            "external_data",
            "external_id",
        ] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }

    #[tokio::test]
    async fn lists_ip_space_products() {
        let (db, exec) = executor(1).await;
        seed_subscription(&db, 7, 1, true).await;
        db.ip_range_subscriptions.lock().await.insert(
            1,
            lnvps_db::IpRangeSubscription {
                id: 1,
                subscription_line_item_id: 7,
                available_ip_space_id: 1,
                created: Utc::now(),
                cidr: "185.18.221.0/24".to_string(),
                origin_asn: Some(214973),
                is_active: true,
                started_at: Utc::now(),
                ended_at: None,
                metadata: None,
            },
        );

        let out = exec
            .execute("list_my_ip_subscriptions", "{}")
            .await
            .unwrap();
        assert!(out.contains("185.18.221.0/24"), "{out}");
        assert!(out.contains("214973"));
    }

    /// An account with none of these products gets empty lists, not an error.
    #[tokio::test]
    async fn empty_account_reports_no_products() {
        // User 3 owns nothing in the mock's seed data.
        let (_db, exec) = executor(3).await;
        let subs = exec.execute("list_my_subscriptions", "{}").await.unwrap();
        assert_eq!(subs.trim(), "[]");
        let ips = exec
            .execute("list_my_ip_subscriptions", "{}")
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&ips).unwrap();
        assert!(parsed["ip_ranges"].as_array().unwrap().is_empty());
        assert!(parsed["asns"].as_array().unwrap().is_empty());
    }
}
