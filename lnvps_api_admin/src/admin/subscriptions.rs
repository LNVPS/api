use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::discounts::payment_discounts;
use crate::admin::model::{
    AdminCreateSubscriptionLineItemRequest, AdminCreateSubscriptionRequest, AdminSubscriptionInfo,
    AdminSubscriptionLineItemInfo, AdminSubscriptionPaymentInfo,
    AdminUpdateSubscriptionLineItemRequest, AdminUpdateSubscriptionRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Days, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery, WorkJob,
};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb, Subscription};
use serde::Deserialize;
use std::sync::Arc;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/subscriptions",
            get(admin_list_subscriptions).post(admin_create_subscription),
        )
        .route(
            "/api/admin/v1/subscriptions/{id}",
            get(admin_get_subscription)
                .patch(admin_update_subscription)
                .delete(admin_delete_subscription),
        )
        .route(
            "/api/admin/v1/subscriptions/{id}/extend",
            put(admin_extend_subscription),
        )
        .route(
            "/api/admin/v1/subscriptions/{subscription_id}/line_items",
            get(admin_list_subscription_line_items),
        )
        .route(
            "/api/admin/v1/subscription_line_items",
            post(admin_create_subscription_line_item),
        )
        .route(
            "/api/admin/v1/subscription_line_items/{id}",
            get(admin_get_subscription_line_item)
                .patch(admin_update_subscription_line_item)
                .delete(admin_delete_subscription_line_item),
        )
        .route(
            "/api/admin/v1/subscriptions/{subscription_id}/payments",
            get(admin_list_subscription_payments),
        )
        .route(
            "/api/admin/v1/subscription_payments/{id}",
            get(admin_get_subscription_payment),
        )
        .route(
            "/api/admin/v1/subscription_payments/{id}/complete",
            post(admin_complete_subscription_payment),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SubscriptionQuery {
    #[serde(flatten)]
    page: PageQuery,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    /// Case-insensitive substring match against name and description
    search: Option<String>,
    /// Filter by active state; omit for all
    status: Option<SubscriptionStatus>,
    /// Filter by auto-renewal flag; omit for all
    auto_renewal: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum SubscriptionStatus {
    Active,
    Inactive,
}

impl AdminSubscriptionInfo {
    pub async fn from_subscription(
        db: &Arc<dyn LNVpsDb>,
        subscription: &lnvps_db::Subscription,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Resolve the owner's pubkey so the admin UI can render the Nostr profile
        let user_pubkey = db
            .get_user(subscription.user_id)
            .await
            .map(|u| hex::encode(&u.pubkey))
            .unwrap_or_default();
        Self::from_subscription_with_pubkey(db, subscription, user_pubkey).await
    }

    /// Build an `AdminSubscriptionInfo` with the owner's pubkey supplied by the caller.
    /// Lets the list endpoint bulk-load users once instead of one query per row.
    pub async fn from_subscription_with_pubkey(
        db: &Arc<dyn LNVpsDb>,
        subscription: &lnvps_db::Subscription,
        user_pubkey: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Fetch line items
        let line_items = db
            .list_subscription_line_items(subscription.id)
            .await
            .unwrap_or_default();

        let mut line_item_infos: Vec<AdminSubscriptionLineItemInfo> =
            Vec::with_capacity(line_items.len());
        for item in line_items {
            line_item_infos
                .push(AdminSubscriptionLineItemInfo::from_line_item(db.as_ref(), item).await);
        }

        // Count payments
        let payments = db
            .list_subscription_payments(subscription.id)
            .await
            .unwrap_or_default();
        let payment_count = payments.len() as u64;

        let mut info = AdminSubscriptionInfo::from(subscription.clone());
        info.user_pubkey = user_pubkey;
        info.line_items = line_item_infos;
        info.payment_count = payment_count;
        Ok(info)
    }
}

// ============================================================================
// Subscription CRUD
// ============================================================================

/// List subscriptions
async fn admin_list_subscriptions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<SubscriptionQuery>,
) -> ApiPaginatedResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);

    let is_active = params
        .status
        .map(|s| matches!(s, SubscriptionStatus::Active));

    let (subscriptions, total) = this
        .db
        .admin_list_subscriptions_filtered(
            limit,
            offset,
            params.user_id,
            params.search.as_deref(),
            is_active,
            params.auto_renewal,
        )
        .await?;

    // Bulk-load the owners for this page in a single query instead of one per row,
    // then index their pubkeys by user_id.
    let user_ids: Vec<u64> = subscriptions
        .iter()
        .map(|s| s.user_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let pubkeys: std::collections::HashMap<u64, String> = this
        .db
        .list_users_by_ids(&user_ids)
        .await?
        .into_iter()
        .map(|u| (u.id, hex::encode(&u.pubkey)))
        .collect();

    let mut subscription_infos = Vec::new();
    for subscription in subscriptions {
        let user_pubkey = pubkeys
            .get(&subscription.user_id)
            .cloned()
            .unwrap_or_default();
        match AdminSubscriptionInfo::from_subscription_with_pubkey(
            &this.db,
            &subscription,
            user_pubkey,
        )
        .await
        {
            Ok(info) => subscription_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(subscription_infos, total, limit, offset)
}

/// Get subscription details
async fn admin_get_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::View)?;

    let subscription = this.db.get_subscription(id).await?;
    let info = AdminSubscriptionInfo::from_subscription(&this.db, &subscription).await?;
    ApiData::ok(info)
}

/// Create subscription
async fn admin_create_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<AdminCreateSubscriptionRequest>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Create)?;

    // Verify user exists
    let _user = this.db.get_user(request.user_id).await?;

    let subscription = request.to_subscription()?;

    let subscription_id = this.db.insert_subscription(&subscription).await?;
    let created_subscription = this.db.get_subscription(subscription_id).await?;
    let info = AdminSubscriptionInfo::from_subscription(&this.db, &created_subscription).await?;
    ApiData::ok(info)
}

/// Update subscription
async fn admin_update_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<AdminUpdateSubscriptionRequest>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Update)?;

    // Get existing subscription
    let mut subscription = this.db.get_subscription(id).await?;

    // Update fields if provided
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("Subscription name cannot be empty"));
        }
        subscription.name = name.trim().to_string();
    }
    if let Some(description) = request.description {
        subscription.description = Some(description);
    }
    if let Some(expires) = request.expires {
        subscription.expires = expires;
    }
    if let Some(is_active) = request.is_active {
        subscription.is_active = is_active;
    }
    if let Some(currency) = request.currency {
        if currency.trim().is_empty() {
            return Err(ApiError::bad_request("Currency cannot be empty"));
        }
        subscription.currency = currency.trim().to_uppercase();
    }
    if let Some(setup_fee) = request.setup_fee {
        subscription.setup_fee = setup_fee;
    }
    if let Some(auto_renewal_enabled) = request.auto_renewal_enabled {
        subscription.auto_renewal_enabled = auto_renewal_enabled;
    }
    if let Some(external_id) = request.external_id {
        subscription.external_id = external_id;
    }

    this.db.update_subscription(&subscription).await?;
    let info = AdminSubscriptionInfo::from_subscription(&this.db, &subscription).await?;
    ApiData::ok(info)
}

#[derive(Deserialize)]
struct AdminExtendSubscriptionRequest {
    /// Number of days to add to the current expiry (1–365)
    days: u32,
    /// Free-text justification, recorded in the server log
    reason: Option<String>,
}

/// Validate `days` and apply the extension to `subscription` in memory,
/// returning the new expiry.
///
/// Mirrors the VM extension rules (`PUT /api/admin/v1/vms/{id}/extend`): time
/// is added to the existing expiry (or to now when the subscription has never
/// had one), and granting paid time marks the subscription set up and active —
/// otherwise the lifecycle worker, which keys off those flags, would tear the
/// resource down despite the admin having extended it.
fn apply_subscription_extension(
    subscription: &mut Subscription,
    days: u32,
) -> Result<DateTime<Utc>, ApiError> {
    if days == 0 {
        return Err(ApiError::bad_request("Must extend by at least 1 day"));
    }
    if days > 365 {
        return Err(ApiError::bad_request("Cannot extend by more than 365 days"));
    }

    let new_expires = subscription.expires.unwrap_or_else(Utc::now) + Days::new(days as u64);
    subscription.expires = Some(new_expires);
    subscription.is_setup = true;
    subscription.is_active = true;
    Ok(new_expires)
}

/// Extend a subscription's expiry by a number of days (admin grant).
///
/// The subscription-level counterpart of `PUT /api/admin/v1/vms/{id}/extend`,
/// so non-VPS products (apps, IP ranges, ASN sponsoring, DNS hosting) can be
/// credited the same way. No payment row is written: this is granted time, not
/// a settlement.
async fn admin_extend_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<AdminExtendSubscriptionRequest>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Update)?;

    let mut subscription = this.db.get_subscription(id).await?;
    let new_expires = apply_subscription_extension(&mut subscription, request.days)?;

    this.db.update_subscription(&subscription).await?;

    log::info!(
        "Admin {} extended subscription {} by {} days until {} (reason: {})",
        auth.user_id,
        id,
        request.days,
        new_expires,
        request.reason.as_deref().unwrap_or("none")
    );

    // Dispatch CheckSubscriptions so the lifecycle worker picks up the new
    // expiry (e.g. restarts a workload that was stopped for non-payment).
    if let Err(e) = this.work_commander.send(WorkJob::CheckSubscriptions).await {
        log::error!(
            "Subscription {} extended but failed to dispatch CheckSubscriptions: {}",
            id,
            e
        );
    }

    let info = AdminSubscriptionInfo::from_subscription(&this.db, &subscription).await?;
    ApiData::ok(info)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct AdminDeleteSubscriptionRequest {
    /// Permanently purge the subscription along with its line items and payment
    /// history, bypassing the paid-payments guard. Requires the `super_admin`
    /// role. Without it a subscription that was ever paid can never be removed
    /// (regtest/e2e and demo data included).
    purge: Option<bool>,
}

/// Delete subscription
async fn admin_delete_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    body: Option<Json<AdminDeleteSubscriptionRequest>>,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Delete)?;

    // Purging payment history is destructive and irreversible, so it is
    // restricted to super-admins. Authorize before the lookup, matching the VM
    // and app-deployment purges.
    let purge = body.and_then(|b| b.purge).unwrap_or(false);
    if purge && !auth.is_super_admin(&this.db).await? {
        return Err(ApiError::forbidden(
            "Only super admins can permanently purge a subscription",
        ));
    }

    // Check if subscription exists
    let _subscription = this.db.get_subscription(id).await?;

    if purge {
        // Cascades line items and payments; refuses while a VM or app
        // deployment still references one of the line items.
        this.db.hard_delete_subscription(id).await?;
        return ApiData::ok(serde_json::json!({
            "success": true,
            "message": "Subscription purged successfully"
        }));
    }

    // Check if subscription has payments
    let payments = this.db.list_subscription_payments(id).await?;
    let paid_payment_count = payments.iter().filter(|p| p.is_paid).count();

    if paid_payment_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete subscription: {} paid payments exist. Consider deactivating instead, or purge as a super admin.",
            paid_payment_count
        )
        .into());
    }

    this.db.delete_subscription(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Subscription deleted successfully"
    }))
}

// ============================================================================
// Subscription Line Items
// ============================================================================

/// List subscription line items
async fn admin_list_subscription_line_items(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(subscription_id): Path<u64>,
) -> ApiResult<Vec<AdminSubscriptionLineItemInfo>> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::View)?;

    // Verify subscription exists
    let _subscription = this.db.get_subscription(subscription_id).await?;

    let line_items = this
        .db
        .list_subscription_line_items(subscription_id)
        .await?;
    let mut line_item_infos: Vec<AdminSubscriptionLineItemInfo> =
        Vec::with_capacity(line_items.len());
    for item in line_items {
        line_item_infos
            .push(AdminSubscriptionLineItemInfo::from_line_item(this.db.as_ref(), item).await);
    }

    ApiData::ok(line_item_infos)
}

/// Get subscription line item details
async fn admin_get_subscription_line_item(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::View)?;

    let line_item = this.db.get_subscription_line_item(id).await?;
    ApiData::ok(AdminSubscriptionLineItemInfo::from_line_item(this.db.as_ref(), line_item).await)
}

/// Create subscription line item
async fn admin_create_subscription_line_item(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<AdminCreateSubscriptionLineItemRequest>,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Create)?;

    // Verify subscription exists
    let _subscription = this.db.get_subscription(request.subscription_id).await?;

    let line_item = request.to_line_item()?;

    let line_item_id = this.db.insert_subscription_line_item(&line_item).await?;
    let created_line_item = this.db.get_subscription_line_item(line_item_id).await?;
    ApiData::ok(
        AdminSubscriptionLineItemInfo::from_line_item(this.db.as_ref(), created_line_item).await,
    )
}

/// Update subscription line item
async fn admin_update_subscription_line_item(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<AdminUpdateSubscriptionLineItemRequest>,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Update)?;

    // Get existing line item
    let mut line_item = this.db.get_subscription_line_item(id).await?;

    // Update fields if provided. `subscription_type` is intentionally NOT
    // mutable: a line item is bound to its resource at creation time and
    // changing the type would orphan that link.
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("Line item name cannot be empty"));
        }
        line_item.name = name.trim().to_string();
    }
    if let Some(description) = request.description {
        line_item.description = Some(description);
    }
    if let Some(amount) = request.amount {
        line_item.amount = amount;
    }
    if let Some(setup_amount) = request.setup_amount {
        line_item.setup_amount = setup_amount;
    }
    if let Some(configuration) = request.configuration {
        line_item.configuration = Some(configuration);
    }

    this.db.update_subscription_line_item(&line_item).await?;
    ApiData::ok(AdminSubscriptionLineItemInfo::from_line_item(this.db.as_ref(), line_item).await)
}

/// Delete subscription line item
async fn admin_delete_subscription_line_item(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Delete)?;

    // Check if line item exists
    let _line_item = this.db.get_subscription_line_item(id).await?;

    this.db.delete_subscription_line_item(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Subscription line item deleted successfully"
    }))
}

// ============================================================================
// Subscription Payments
// ============================================================================

/// List subscription payments
async fn admin_list_subscription_payments(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(subscription_id): Path<u64>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    // Verify subscription exists and fetch company base currency
    let subscription = this.db.get_subscription(subscription_id).await?;
    let company = this.db.get_company(subscription.company_id).await?;
    let base_currency = company.base_currency;

    let (page, total) = this
        .db
        .list_subscription_payments_paginated(subscription_id, limit, offset)
        .await?;

    let payment_ids: Vec<Vec<u8>> = page.iter().map(|p| p.id.clone()).collect();
    let discounts = payment_discounts(&this.db, &payment_ids).await?;

    let payments: Vec<AdminSubscriptionPaymentInfo> = page
        .into_iter()
        .map(|p| {
            let discount = discounts.get(&p.id).cloned();
            AdminSubscriptionPaymentInfo::new(p, base_currency.clone()).with_discount(discount)
        })
        .collect();

    ApiPaginatedData::ok(payments, total, limit, offset)
}

/// Get subscription payment details
async fn admin_get_subscription_payment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::View)?;

    let payment_id = hex::decode(&id).map_err(|_| anyhow::anyhow!("Invalid payment ID format"))?;

    let payment = this
        .db
        .get_subscription_payment_with_company(&payment_id)
        .await?;
    let discount = this
        .db
        .get_discount_redemptions_by_payments(std::slice::from_ref(&payment_id))
        .await?
        .pop()
        .map(Into::into);
    ApiData::ok(AdminSubscriptionPaymentInfo::from_with_company(payment).with_discount(discount))
}

/// Manually mark a subscription payment as paid (admin override).
///
/// This calls `subscription_payment_paid` which sets `is_paid=true`,
/// records `paid_at`, extends the subscription by 30 days, and activates it,
/// then hands the line item on-payment handling (instant app reconcile,
/// applying an upgrade) to the worker, which owns the provisioner stack this
/// crate has no access to.
///
/// An already-paid payment is re-dispatched rather than refused: the two steps
/// cannot be made atomic, so refusing would leave a payment that is paid with
/// its handlers never run and no way to ask for them again. Re-running them is
/// safe — the subscription is not extended a second time, and the handlers
/// carry absolute target state.
async fn admin_complete_subscription_payment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::Update)?;

    let payment_id = hex::decode(&id).map_err(|_| anyhow::anyhow!("Invalid payment ID format"))?;

    let payment = this.db.get_subscription_payment(&payment_id).await?;

    if !payment.is_paid {
        this.db.subscription_payment_paid(&payment).await?;
        log::info!(
            "Admin {} manually completed subscription payment {} for subscription {}",
            auth.user_id,
            id,
            payment.subscription_id
        );
    } else {
        log::info!(
            "Admin {} re-queued on-payment work for subscription payment {}",
            auth.user_id,
            id
        );
    }

    // Fail the request if this cannot be queued: the payment is paid either
    // way, so a silent success would leave an app without its reconcile and an
    // upgrade never applied, with nothing left to retry it.
    this.work_commander
        .send(WorkJob::ApplySubscriptionPayment {
            payment_id: id.clone(),
        })
        .await?;

    // Dispatch CheckSubscriptions so the lifecycle worker picks up the new expiry
    if let Err(e) = this.work_commander.send(WorkJob::CheckSubscriptions).await {
        log::error!(
            "Payment completed but failed to dispatch CheckSubscriptions for subscription {}: {}",
            payment.subscription_id,
            e
        );
    }

    // Re-read the payment to get updated state (with company info)
    let updated = this
        .db
        .get_subscription_payment_with_company(&payment_id)
        .await?;
    let discount = this
        .db
        .get_discount_redemptions_by_payments(std::slice::from_ref(&payment_id))
        .await?
        .pop()
        .map(Into::into);
    ApiData::ok(AdminSubscriptionPaymentInfo::from_with_company(updated).with_discount(discount))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_db::IntervalType;

    fn mk_subscription(expires: Option<DateTime<Utc>>) -> Subscription {
        Subscription {
            id: 1,
            user_id: 1,
            company_id: 1,
            name: "test".to_string(),
            description: None,
            created: DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap(),
            expires,
            is_active: false,
            is_setup: false,
            currency: "USD".to_string(),
            interval_amount: 1,
            interval_type: IntervalType::Month,
            setup_fee: 0,
            auto_renewal_enabled: false,
            external_id: None,
        }
    }

    #[test]
    fn extension_adds_days_to_existing_expiry() {
        let expires = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        let mut sub = mk_subscription(Some(expires));

        let Ok(new_expires) = apply_subscription_extension(&mut sub, 30) else {
            panic!("30 days is within bounds");
        };

        // Added to the existing expiry, not to "now": an admin crediting a
        // customer must not silently shorten unused paid time.
        assert_eq!(new_expires, expires + Days::new(30));
        assert_eq!(sub.expires, Some(new_expires));
        // Granting paid time also marks the subscription live, otherwise the
        // lifecycle worker would tear the resource down anyway.
        assert!(sub.is_setup);
        assert!(sub.is_active);
    }

    #[test]
    fn extension_without_expiry_starts_from_now() {
        let mut sub = mk_subscription(None);

        let before = Utc::now();
        let Ok(new_expires) = apply_subscription_extension(&mut sub, 1) else {
            panic!("1 day is within bounds");
        };
        let after = Utc::now();

        assert!(new_expires >= before + Days::new(1));
        assert!(new_expires <= after + Days::new(1));
    }

    #[test]
    fn extension_days_are_bounded() {
        let expires = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();

        // Zero is a no-op that would still flip is_setup/is_active, so it is
        // refused rather than accepted.
        let mut sub = mk_subscription(Some(expires));
        assert!(apply_subscription_extension(&mut sub, 0).is_err());
        assert_eq!(sub.expires, Some(expires));
        assert!(!sub.is_active);

        // Upper bound matches the VM endpoint (365 days).
        let mut sub = mk_subscription(Some(expires));
        assert!(apply_subscription_extension(&mut sub, 366).is_err());
        assert_eq!(sub.expires, Some(expires));

        let mut sub = mk_subscription(Some(expires));
        assert!(apply_subscription_extension(&mut sub, 365).is_ok());
    }
}
