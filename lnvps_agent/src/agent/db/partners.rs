//! Partner-programme tools: referrals and marketplace node operators.
//!
//! Both are opt-in enrolments most accounts do not have, so "not enrolled" is
//! returned as data rather than as an error — the model should say so plainly
//! instead of reporting a lookup failure. Neither projection carries a
//! credential: no node API token, no libvirt certificate, no payout preimage.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use super::{DbToolExecutor, tag};

impl DbToolExecutor {
    /// The customer's referral enrolment, if they have one.
    ///
    /// A missing enrolment is a normal answer rather than an error — most
    /// customers have none, and the model should say so rather than report a
    /// lookup failure.
    pub(super) async fn referral(&self) -> Result<Value> {
        let user_id = self.require_user()?;
        let Ok(referral) = self.db.get_referral_by_user(user_id).await else {
            return Ok(json!({
                "enrolled": false,
                "note": "This account has no referral code. Referral enrolment is requested through the website.",
            }));
        };
        Ok(json!({
            "enrolled": true,
            "code": referral.code,
            "created": referral.created,
            "payout_mode": tag(referral.mode),
            "payout_address": referral.address,
            "payout_threshold": referral.payout_threshold,
            // `None` means the company default applies; the rate is not stored
            // on the referral in that case, so do not invent one.
            "commission_rate_percent": referral.referral_rate,
            "commission_rate_note": referral.referral_rate.map_or(
                "No per-referrer override: the company's default commission rate applies.",
                |_| "Per-referrer override in effect.",
            ),
        }))
    }

    /// Commission earned per currency, plus payout history.
    pub(super) async fn referral_usage(&self) -> Result<Value> {
        let user_id = self.require_user()?;
        let Ok(referral) = self.db.get_referral_by_user(user_id).await else {
            bail!("This account has no referral code");
        };

        let usage = self.db.list_referral_usage(&referral.code).await?;
        // Commission is a share of each referred VM's first paid invoice, so
        // the earned figure is the sum of the effective-rate slices, kept per
        // currency rather than converted — payouts settle in the currency the
        // payment was taken in.
        let mut earned: HashMap<String, u64> = HashMap::new();
        for u in &usage {
            let commission = (u.amount as f64 * (u.effective_rate as f64 / 100.0)).round() as u64;
            *earned.entry(u.currency.clone()).or_default() += commission;
        }
        let payouts = self
            .db
            .list_referral_payouts(referral.id)
            .await
            .unwrap_or_default();

        Ok(json!({
            "code": referral.code,
            "referred_paid_vms": usage.len(),
            "referred_unpaid_vms": self.db.count_failed_referrals(&referral.code).await.unwrap_or(0),
            "earned_by_currency": earned,
            "usage": usage.iter().map(|u| json!({
                "vm_id": u.vm_id,
                "created": u.created,
                "invoice_amount": u.amount,
                "currency": u.currency,
                "commission_rate_percent": u.effective_rate,
            })).collect::<Vec<_>>(),
            "payouts": payouts.iter().map(|p| json!({
                "id": p.id,
                "created": p.created,
                "amount": p.amount,
                "fee": p.fee,
                "currency": p.currency,
                "is_paid": p.is_paid,
                "mode": tag(p.mode),
            })).collect::<Vec<_>>(),
            "note": "Amounts are in minor units of each currency (cents / millisats).",
        }))
    }

    /// The customer's operator enrolment and their nodes.
    ///
    /// Node credentials are never included: `token_version` is an enrolment
    /// counter whose only use is invalidating a node's API token, and the
    /// libvirt client certificate is a credential outright.
    pub(super) async fn marketplace_operator(&self) -> Result<Value> {
        let user_id = self.require_user()?;
        let Ok(operator) = self.db.get_marketplace_operator_by_user(user_id).await else {
            return Ok(json!({
                "enrolled": false,
                "note": "This account is not enrolled as a marketplace node operator.",
            }));
        };

        let nodes = self
            .db
            .list_marketplace_nodes(operator.id)
            .await
            .unwrap_or_default();
        let mut node_views = Vec::with_capacity(nodes.len());
        for node in &nodes {
            // Only the most recent probe: health history is long and a support
            // question is about the node's state now.
            let last_health = self
                .db
                .list_marketplace_node_health(node.id, 1, 0)
                .await
                .ok()
                .and_then(|(rows, _)| rows.into_iter().next());
            node_views.push(json!({
                "id": node.id,
                "name": node.name,
                "status": node.status.to_string(),
                "trust_tier": node.trust_tier.to_string(),
                "last_seen": node.last_seen,
                "created": node.created,
                "last_health_check": last_health.map(|h| json!({
                    "checked": h.created,
                    "passed": h.passed,
                    "failure": h.failure,
                    "provision_ms": h.provision_ms,
                })),
            }));
        }

        Ok(json!({
            "enrolled": true,
            "operator_id": operator.id,
            "enabled": operator.enabled,
            "payout_mode": operator.mode.to_string(),
            "payout_address": operator.address,
            "payout_threshold": operator.payout_threshold,
            "revenue_share_percent": operator.rate,
            "revenue_share_note": operator.rate.map_or(
                "No per-operator override: the company's default revenue share applies.",
                |_| "Per-operator override in effect.",
            ),
            "created": operator.created,
            "nodes": node_views,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use crate::agent::ToolExecutor;
    use chrono::Utc;
    use lnvps_api_common::MockDb;
    use lnvps_db::{
        MarketplaceNode, MarketplaceNodeHealth, MarketplaceNodeStatus, MarketplaceOperator,
        MarketplaceTrustTier, PayoutMode, Referral, ReferralPayoutMode,
    };
    use serde_json::Value;
    use std::sync::Arc;

    async fn seed_referral(db: &Arc<MockDb>, user_id: u64, rate: Option<f32>) {
        db.referrals.lock().await.insert(
            1,
            Referral {
                id: 1,
                user_id,
                code: "ALPHA123".to_string(),
                address: Some("bob@getalby.com".to_string()),
                mode: ReferralPayoutMode::LightningAddress,
                created: Utc::now(),
                referral_rate: rate,
                payout_threshold: Some(10_000),
            },
        );
    }

    async fn seed_operator(db: &Arc<MockDb>, user_id: u64) {
        db.marketplace_operators.lock().await.insert(
            1,
            MarketplaceOperator {
                id: 1,
                user_id,
                address: Some("operator@getalby.com".to_string()),
                mode: PayoutMode::LightningAddress,
                payout_threshold: None,
                rate: Some(70.0),
                enabled: true,
                created: Utc::now(),
            },
        );
        db.marketplace_nodes.lock().await.insert(
            1,
            MarketplaceNode {
                id: 1,
                operator_id: 1,
                name: "node-1".to_string(),
                token_version: 3,
                status: MarketplaceNodeStatus::Approved,
                trust_tier: MarketplaceTrustTier::Verified,
                tls_fingerprint: Some(vec![0xab; 32]),
                libvirt_cert: Some("SECRET-LIBVIRT-CERT".to_string()),
                tunnel_id: None,
                last_seen: Some(Utc::now()),
                subscription_line_item_id: None,
                created: Utc::now(),
            },
        );
        db.marketplace_node_health.lock().await.insert(
            1,
            MarketplaceNodeHealth {
                id: 1,
                node_id: 1,
                created: Utc::now(),
                passed: false,
                failure: Some("provision timeout".to_string()),
                provision_ms: Some(90_000),
                ..Default::default()
            },
        );
    }

    /// Most accounts are in neither programme, and "not enrolled" is an answer
    /// the model can relay — an error is not.
    #[tokio::test]
    async fn not_enrolled_is_data_not_an_error() {
        let (_db, exec) = executor(1).await;

        let referral = exec.execute("get_my_referral", "{}").await.unwrap();
        assert!(referral.contains("\"enrolled\": false"), "{referral}");

        let operator = exec
            .execute("get_my_marketplace_operator", "{}")
            .await
            .unwrap();
        assert!(operator.contains("\"enrolled\": false"), "{operator}");

        // Usage has nothing to report without a code, and says so.
        let err = exec.execute("list_referral_usage", "{}").await.unwrap_err();
        assert!(err.to_string().contains("no referral code"));
    }

    /// A null rate means the company default applies; inventing a number here
    /// is exactly the failure the note exists to prevent.
    #[tokio::test]
    async fn a_default_commission_rate_is_reported_as_a_default() {
        let (db, exec) = executor(1).await;
        seed_referral(&db, 1, None).await;

        let out = exec.execute("get_my_referral", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["enrolled"], true);
        assert_eq!(parsed["code"], "ALPHA123");
        assert!(parsed["commission_rate_percent"].is_null());
        assert!(
            parsed["commission_rate_note"]
                .as_str()
                .unwrap()
                .contains("company's default")
        );

        // An override is reported as such.
        seed_referral(&db, 1, Some(12.5)).await;
        let out = exec.execute("get_my_referral", "{}").await.unwrap();
        assert!(out.contains("12.5"));
        assert!(out.contains("override in effect"));
    }

    #[tokio::test]
    async fn referral_usage_totals_commission_per_currency() {
        let (db, exec) = executor(1).await;
        seed_referral(&db, 1, Some(10.0)).await;

        let out = exec.execute("list_referral_usage", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["code"], "ALPHA123");
        // The mock has no referred VMs, so the totals are empty rather than
        // guessed.
        assert!(parsed["earned_by_currency"].is_object());
        assert_eq!(parsed["referred_paid_vms"], 0);
        assert!(parsed["note"].as_str().unwrap().contains("minor units"));
    }

    /// An operator's node credentials must never reach the model: the libvirt
    /// client certificate is a credential, and the token version is only ever
    /// used to invalidate a node's token.
    #[tokio::test]
    async fn operator_view_omits_node_credentials() {
        let (db, exec) = executor(1).await;
        seed_operator(&db, 1).await;

        let out = exec
            .execute("get_my_marketplace_operator", "{}")
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["enrolled"], true);
        assert_eq!(parsed["revenue_share_percent"], 70.0);
        assert_eq!(parsed["nodes"][0]["name"], "node-1");
        assert_eq!(parsed["nodes"][0]["status"], "approved");
        // The failing health check is the answer to "why is my node idle".
        assert_eq!(parsed["nodes"][0]["last_health_check"]["passed"], false);
        assert_eq!(
            parsed["nodes"][0]["last_health_check"]["failure"],
            "provision timeout"
        );
        for leaked in ["SECRET-LIBVIRT-CERT", "libvirt_cert", "token_version"] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }

    /// Another user's enrolment must not be reachable: both lookups key on the
    /// scoped user, never on an argument.
    #[tokio::test]
    async fn enrolments_are_scoped_to_the_requesting_user() {
        let (db, exec) = executor(1).await;
        seed_referral(&db, 2, Some(10.0)).await;
        seed_operator(&db, 2).await;

        assert!(
            exec.execute("get_my_referral", "{}")
                .await
                .unwrap()
                .contains("\"enrolled\": false")
        );
        assert!(
            exec.execute("get_my_marketplace_operator", "{}")
                .await
                .unwrap()
                .contains("\"enrolled\": false")
        );
    }
}
