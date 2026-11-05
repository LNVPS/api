use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use lnvps_api_common::{ApiData, ApiError, ApiResult, deserialize_from_str_optional};
use lnvps_db::{
    AdminAction, AdminResource, LNVpsDb, PaidSubscriptionPayment, SubscriptionPayment, VmHistory,
    VmHistoryActionType,
};

use crate::admin::RouterState;
use crate::admin::apps::deployment_infos;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminAppDeploymentInfo, AdminSubscriptionPaymentInfo, AdminVmInfo, ApiSubscriptionPaymentType,
};
use crate::admin::vms::load_admin_vm_infos;
use crate::admin::vpn_subscriptions::{AdminVpnSubscriptionInfo, subscription_info};

const DEFAULT_DAYS: u32 = 7;
const MAX_DAYS: u32 = 90;
const DEFAULT_LIMIT: u64 = 20;
const MAX_LIMIT: u64 = 100;

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/reports/activity", get(admin_activity_report))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ActivityQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    days: Option<u32>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    expiring_days: Option<u32>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
}

#[derive(Serialize)]
pub struct AdminActivitySection<T> {
    pub total: u64,
    pub items: Vec<T>,
}

impl<T> AdminActivitySection<T> {
    fn new(items: Vec<T>, total: u64) -> Self {
        Self { total, items }
    }
}

#[derive(Serialize)]
pub struct AdminActivityUser {
    pub id: u64,
    pub pubkey: String,
    pub created: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AdminDeletedVmInfo {
    #[serde(flatten)]
    pub vm: AdminVmInfo,
    pub deleted_at: DateTime<Utc>,
    pub delete_reason: Option<String>,
}

#[derive(Serialize)]
pub struct AdminActivityPayment {
    #[serde(flatten)]
    pub payment: AdminSubscriptionPaymentInfo,
    pub subscription_name: String,
    pub vm_id: Option<u64>,
    pub refund_trigger: Option<RefundTrigger>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefundTrigger {
    OwnerDelete,
    AdminDelete,
    Admin,
    Manual,
}

fn metadata_json(history: &VmHistory) -> Option<serde_json::Value> {
    history
        .metadata
        .as_deref()
        .and_then(|m| serde_json::from_slice(m).ok())
}

pub fn refund_trigger(
    payment: &SubscriptionPayment,
    deletion: Option<&VmHistory>,
) -> Option<RefundTrigger> {
    if !payment.payment_type.is_refund() {
        return None;
    }
    let refund = payment.metadata.as_ref().and_then(|m| m.get("refund"));
    let field = |name: &str| refund.and_then(|r| r.get(name)).filter(|v| !v.is_null());
    if field("by_owner_user_id").is_some() {
        return Some(RefundTrigger::OwnerDelete);
    }
    let admin_id = field("recorded_by_admin_user_id").and_then(|v| v.as_u64());
    let deleted_by_that_admin = deletion.is_some_and(|d| {
        d.timestamp <= payment.created
            && metadata_json(d).is_some_and(|m| {
                m.get("admin_action").and_then(|v| v.as_bool()) == Some(true)
                    && admin_id.is_some()
                    && m.get("admin_user_id").and_then(|v| v.as_u64()) == admin_id
            })
    });
    if deleted_by_that_admin {
        Some(RefundTrigger::AdminDelete)
    } else if !payment.external_data.as_str().is_empty() {
        Some(RefundTrigger::Admin)
    } else {
        Some(RefundTrigger::Manual)
    }
}

async fn activity_payment(
    db: &std::sync::Arc<dyn LNVpsDb>,
    p: PaidSubscriptionPayment,
) -> AdminActivityPayment {
    let vm_id = db
        .get_vm_by_subscription(p.payment.subscription_id)
        .await
        .ok()
        .map(|vm| vm.id);
    let deletion = match (vm_id, p.payment.payment_type.is_refund()) {
        (Some(id), true) => db.list_vm_history(id).await.ok().and_then(|h| {
            h.into_iter()
                .filter(|e| matches!(e.action_type, VmHistoryActionType::Deleted))
                .min_by_key(|e| e.timestamp)
        }),
        _ => None,
    };
    AdminActivityPayment {
        refund_trigger: refund_trigger(&p.payment, deletion.as_ref()),
        payment: AdminSubscriptionPaymentInfo::new(p.payment, p.company_base_currency),
        subscription_name: p.subscription_name,
        vm_id,
    }
}

#[derive(Serialize)]
pub struct AdminPaymentTotal {
    pub currency: String,
    pub payment_type: ApiSubscriptionPaymentType,
    pub count: u64,
    pub amount: u64,
    pub tax: u64,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminRefundDestination {
    Cash,
    Credit,
}

#[derive(Serialize, Debug)]
pub struct AdminActivityRefund {
    pub id: String,
    pub subscription_id: u64,
    pub user_id: u64,
    pub currency: String,
    pub amount: u64,
    pub tax: u64,
    pub gross: u64,
    pub refunded_at: DateTime<Utc>,
    pub destination: AdminRefundDestination,
    pub credit_returned: BTreeMap<String, u64>,
    pub original_payment_id: Option<String>,
    pub original_paid_at: Option<DateTime<Utc>>,
    pub original_before_window: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct AdminCurrencySummary {
    pub currency: String,
    pub revenue_count: u64,
    pub revenue: u64,
    pub cash_refund_count: u64,
    pub cash_refunds: u64,
    pub credit_refund_count: u64,
    pub credit_refunds: u64,
    pub refunds_of_earlier_payments: u64,
    pub net: Option<i64>,
    pub net_note: Option<String>,
}

#[derive(Serialize)]
pub struct AdminActivityReport {
    pub since: DateTime<Utc>,
    pub expiring_until: DateTime<Utc>,
    pub new_users: AdminActivitySection<AdminActivityUser>,
    pub new_vms: AdminActivitySection<AdminVmInfo>,
    pub deleted_vms: AdminActivitySection<AdminDeletedVmInfo>,
    pub expiring_vms: AdminActivitySection<AdminVmInfo>,
    pub new_vpn_subscriptions: AdminActivitySection<AdminVpnSubscriptionInfo>,
    pub new_app_deployments: AdminActivitySection<AdminAppDeploymentInfo>,
    pub payments: AdminActivitySection<AdminActivityPayment>,
    pub payment_totals: Vec<AdminPaymentTotal>,
    pub refunds: AdminActivitySection<AdminActivityRefund>,
    pub currency_summaries: Vec<AdminCurrencySummary>,
}

fn credit_returned(refund: &lnvps_db::SubscriptionPayment) -> Option<BTreeMap<String, u64>> {
    let map = refund
        .metadata
        .as_ref()?
        .get("refund")?
        .get("returned_as_credit")?;
    serde_json::from_value(map.clone()).ok()
}

async fn activity_refund(
    db: &std::sync::Arc<dyn LNVpsDb>,
    refund: lnvps_db::SubscriptionPayment,
    since: DateTime<Utc>,
) -> AdminActivityRefund {
    let original = match &refund.refunded_payment_id {
        Some(id) => db.get_subscription_payment(id).await.ok(),
        None => None,
    };
    let original_paid_at = original
        .as_ref()
        .and_then(|o| o.paid_at.or(Some(o.created)));
    let credit = credit_returned(&refund);
    AdminActivityRefund {
        id: hex::encode(&refund.id),
        subscription_id: refund.subscription_id,
        user_id: refund.user_id,
        gross: refund.amount + refund.tax,
        amount: refund.amount,
        tax: refund.tax,
        currency: refund.currency,
        refunded_at: refund.paid_at.unwrap_or(refund.created),
        destination: if credit.is_some() {
            AdminRefundDestination::Credit
        } else {
            AdminRefundDestination::Cash
        },
        credit_returned: credit.unwrap_or_default(),
        original_payment_id: refund.refunded_payment_id.as_ref().map(hex::encode),
        original_before_window: original_paid_at.is_some_and(|at| at < since),
        original_paid_at,
    }
}

fn summarise_currencies(
    totals: &[AdminPaymentTotal],
    refunds: &[AdminActivityRefund],
) -> Vec<AdminCurrencySummary> {
    let mut currencies: Vec<&str> = totals
        .iter()
        .map(|t| t.currency.as_str())
        .chain(refunds.iter().map(|r| r.currency.as_str()))
        .collect();
    currencies.sort();
    currencies.dedup();
    currencies
        .into_iter()
        .map(|currency| {
            let sales = totals
                .iter()
                .filter(|t| t.currency == currency && !matches!(t.payment_type, ApiSubscriptionPaymentType::Refund));
            let (revenue_count, revenue) = sales.fold((0, 0), |(c, a), t| (c + t.count, a + t.amount));
            let mine = || refunds.iter().filter(|r| r.currency == currency);
            let cash: Vec<_> = mine().filter(|r| r.destination == AdminRefundDestination::Cash).collect();
            let credit: Vec<_> = mine().filter(|r| r.destination == AdminRefundDestination::Credit).collect();
            let cash_refunds: u64 = cash.iter().map(|r| r.amount).sum();
            let credit_refunds: u64 = credit.iter().map(|r| r.amount).sum();
            let earlier_of = |rows: &[&AdminActivityRefund]| -> u64 {
                rows.iter().filter(|r| r.original_before_window).map(|r| r.amount).sum()
            };
            let refunds_of_earlier_payments = earlier_of(&cash) + earlier_of(&credit);
            let cash_earlier = earlier_of(&cash) > 0;
            let net = (!cash_earlier).then(|| revenue as i64 - cash_refunds as i64);
            let mut notes = Vec::new();
            if cash_earlier {
                notes.push("Cash refunds reverse payments received before this window, so they are not netted against this window's revenue.");
            }
            if !credit.is_empty() {
                notes.push("Refunds to credit keep the cash as a credit balance owed to the customer, possibly in another currency, and are not deducted from revenue.");
            }
            AdminCurrencySummary {
                currency: currency.to_string(),
                revenue_count,
                revenue,
                cash_refund_count: cash.len() as u64,
                cash_refunds,
                credit_refund_count: credit.len() as u64,
                credit_refunds,
                refunds_of_earlier_payments,
                net,
                net_note: (!notes.is_empty()).then(|| notes.join(" ")),
            }
        })
        .collect()
}

async fn admin_activity_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(query): Query<ActivityQuery>,
) -> ApiResult<AdminActivityReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    let days = query.days.unwrap_or(DEFAULT_DAYS);
    let expiring_days = query.expiring_days.unwrap_or(DEFAULT_DAYS);
    if !(1..=MAX_DAYS).contains(&days) || !(1..=MAX_DAYS).contains(&expiring_days) {
        return Err(ApiError::bad_request(format!(
            "days and expiring_days must be between 1 and {MAX_DAYS}"
        )));
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let now = Utc::now();
    let since = now - Duration::days(days.into());
    let expiring_until = now + Duration::days(expiring_days.into());
    ApiData::ok(build_activity_report(&this, since, expiring_until, limit).await?)
}

async fn build_activity_report(
    this: &RouterState,
    since: DateTime<Utc>,
    expiring_until: DateTime<Utc>,
    limit: u64,
) -> Result<AdminActivityReport, ApiError> {
    let db = &this.db;

    let (users, users_total) = db.admin_list_users_created_since(since, limit).await?;
    let (new_vms, new_vms_total) = db.admin_list_vms_created_since(since, limit).await?;
    let (deleted, deleted_total) = db.admin_list_vms_deleted_since(since, limit).await?;
    let (expiring, expiring_total) = db
        .admin_list_vms_expiring_between(since, expiring_until, limit)
        .await?;
    let (vpn, vpn_total) = db
        .admin_list_vpn_subscriptions_created_since(since, limit)
        .await?;
    let (apps, apps_total) = db
        .admin_list_app_deployments_created_since(since, limit)
        .await?;
    let (payments, payments_total) = db.admin_list_payments_paid_since(since, limit).await?;
    let totals = db.admin_sum_payments_paid_since(since).await?;
    let refund_rows = db.admin_list_refunds_paid_since(since).await?;
    let mut refunds = Vec::with_capacity(refund_rows.len());
    for row in refund_rows {
        refunds.push(activity_refund(db, row, since).await);
    }
    let payment_totals: Vec<AdminPaymentTotal> = totals
        .into_iter()
        .map(|t| AdminPaymentTotal {
            currency: t.currency,
            payment_type: t.payment_type.into(),
            count: t.count,
            amount: t.amount,
            tax: t.tax,
        })
        .collect();
    let currency_summaries = summarise_currencies(&payment_totals, &refunds);
    let refunds_total = refunds.len() as u64;
    refunds.truncate(limit as usize);

    let deleted_vms: Vec<lnvps_db::Vm> = deleted.iter().map(|d| d.vm.clone()).collect();
    let deleted_infos = load_admin_vm_infos(db, &this.vm_state_cache, &deleted_vms)
        .await?
        .into_iter()
        .zip(deleted)
        .map(|(vm, d)| AdminDeletedVmInfo {
            vm,
            deleted_at: d.deleted_at,
            delete_reason: d.delete_reason,
        })
        .collect();

    let mut payment_items = Vec::with_capacity(payments.len());
    for p in payments {
        payment_items.push(activity_payment(db, p).await);
    }

    Ok(AdminActivityReport {
        since,
        expiring_until,
        new_users: AdminActivitySection::new(
            users
                .into_iter()
                .map(|u| AdminActivityUser {
                    id: u.id,
                    pubkey: hex::encode(&u.pubkey),
                    created: u.created,
                })
                .collect(),
            users_total,
        ),
        new_vms: AdminActivitySection::new(
            load_admin_vm_infos(db, &this.vm_state_cache, &new_vms).await?,
            new_vms_total,
        ),
        deleted_vms: AdminActivitySection::new(deleted_infos, deleted_total),
        expiring_vms: AdminActivitySection::new(
            load_admin_vm_infos(db, &this.vm_state_cache, &expiring).await?,
            expiring_total,
        ),
        new_vpn_subscriptions: AdminActivitySection::new(vpn_infos(db, vpn).await?, vpn_total),
        new_app_deployments: AdminActivitySection::new(
            deployment_infos(db.as_ref(), apps).await?,
            apps_total,
        ),
        payments: AdminActivitySection::new(payment_items, payments_total),
        payment_totals,
        refunds: AdminActivitySection::new(refunds, refunds_total),
        currency_summaries,
    })
}

async fn vpn_infos(
    db: &std::sync::Arc<dyn LNVpsDb>,
    plans: Vec<lnvps_db::VpnSubscription>,
) -> Result<Vec<AdminVpnSubscriptionInfo>, ApiError> {
    let mut out = Vec::with_capacity(plans.len());
    for plan in plans {
        out.push(subscription_info(db, plan).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod summary_tests;

#[cfg(test)]
mod tests;
