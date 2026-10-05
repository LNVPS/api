use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{ApiData, ApiError, ApiResult, deserialize_from_str_optional};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};

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
}

#[derive(Serialize)]
pub struct AdminPaymentTotal {
    pub currency: String,
    pub payment_type: ApiSubscriptionPaymentType,
    pub count: u64,
    pub amount: u64,
    pub tax: u64,
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
        payments: AdminActivitySection::new(
            payments
                .into_iter()
                .map(|p| AdminActivityPayment {
                    payment: AdminSubscriptionPaymentInfo::new(p.payment, p.company_base_currency),
                    subscription_name: p.subscription_name,
                })
                .collect(),
            payments_total,
        ),
        payment_totals: totals
            .into_iter()
            .map(|t| AdminPaymentTotal {
                currency: t.currency,
                payment_type: t.payment_type.into(),
                count: t.count,
                amount: t.amount,
                tax: t.tax,
            })
            .collect(),
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
mod tests;
