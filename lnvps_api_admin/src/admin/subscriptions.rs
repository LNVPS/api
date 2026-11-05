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
        .route(
            "/api/admin/v1/subscription_payments/external",
            post(admin_record_external_payment),
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
    ///
    /// A batch of one: the loading itself lives in
    /// [`AdminSubscriptionInfo::load_many`], so the single-subscription views
    /// cannot drift from the list view or reintroduce a per-line-item query.
    pub async fn from_subscription_with_pubkey(
        db: &Arc<dyn LNVpsDb>,
        subscription: &lnvps_db::Subscription,
        user_pubkey: String,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let pubkeys = std::collections::HashMap::from([(subscription.user_id, user_pubkey)]);
        Self::load_many(db, vec![subscription.clone()], &pubkeys)
            .await?
            .pop()
            .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                format!("subscription {} could not be rendered", subscription.id).into()
            })
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

    // Line items, their linked resources and the payment counts are bulk-loaded
    // for the whole page — one query per table, not per subscription.
    let subscription_infos =
        AdminSubscriptionInfo::load_many(&this.db, subscriptions, &pubkeys).await?;

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

#[derive(Deserialize)]
struct AdminExternalPaymentRequest {
    outpoint: String,
    amount_msat: u64,
    currency: String,
    payment_method: String,
    subscription_id: Option<u64>,
    user_id: Option<u64>,
    note: String,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
enum AdminExternalPaymentResult {
    Payment(Box<AdminSubscriptionPaymentInfo>),
    Credit {
        topup_id: u64,
        user_id: u64,
        amount_msat: u64,
        external_id: String,
        balance_msat: u64,
    },
}

fn random_32_bytes() -> Vec<u8> {
    let mut out = uuid::Uuid::new_v4().into_bytes().to_vec();
    out.extend(uuid::Uuid::new_v4().into_bytes());
    out
}

fn is_duplicate_error(e: &dyn std::fmt::Display) -> bool {
    let text = e.to_string().to_lowercase();
    text.contains("duplicate") || text.contains("unique")
}

fn parse_outpoint(outpoint: &str) -> Result<(String, u32), ApiError> {
    let invalid = || ApiError::bad_request("outpoint must be <txid>:<vout>");
    let (txid, vout) = outpoint.split_once(':').ok_or_else(invalid)?;
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    Ok((
        txid.to_ascii_lowercase(),
        vout.parse().map_err(|_| invalid())?,
    ))
}

async fn ensure_outpoint_unused(db: &Arc<dyn LNVpsDb>, outpoint: &str) -> Result<(), ApiError> {
    let taken = db
        .get_subscription_payment_by_ext_id(outpoint)
        .await
        .is_ok()
        || db
            .get_account_credit_topup_by_ext_id(outpoint)
            .await?
            .is_some();
    if taken {
        return Err(ApiError::conflict(format!(
            "Outpoint {outpoint} is already recorded"
        )));
    }
    Ok(())
}

async fn price_external_payment(
    this: &RouterState,
    payment: &mut lnvps_db::SubscriptionPayment,
) -> Result<(), ApiError> {
    use lnvps_api_common::{CostResult, PricingEngine};
    let engine = PricingEngine::new(this.db.clone(), this.exchange.clone(), this.vat.clone());
    let gross = payments_rs::currency::CurrencyAmount::millisats(payment.amount);
    let cost = match this
        .db
        .get_vm_by_subscription(payment.subscription_id)
        .await
    {
        Ok(vm) => {
            engine
                .get_cost_by_amount(vm.id, gross, payment.payment_method)
                .await
        }
        Err(_) => {
            engine
                .get_subscription_cost_by_amount(
                    payment.subscription_id,
                    gross,
                    payment.payment_method,
                )
                .await
        }
    }
    .map_err(|e| ApiError::bad_request(format!("Cannot price payment: {e}")))?;
    let CostResult::New(p) = cost else {
        return Err(ApiError::bad_request("Unexpected existing cost result"));
    };
    payment.time_value = Some(p.time_value);
    payment.rate = p.rate.rate;
    payment.amount = p.amount;
    payment.tax = p.tax;
    payment.processing_fee = p.processing_fee;
    Ok(())
}

/// Record a confirmed on-chain deposit that has no payment row.
async fn admin_record_external_payment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<AdminExternalPaymentRequest>,
) -> ApiResult<AdminExternalPaymentResult> {
    use lnvps_db::{PaymentMethod, SubscriptionPayment, SubscriptionPaymentType};
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::Create)?;

    if req.payment_method != "onchain" || req.currency != "BTC" {
        return ApiData::err("Only onchain BTC payments can be recorded");
    }
    if req.amount_msat == 0 {
        return ApiData::err("amount_msat must be positive");
    }
    if req.note.trim().is_empty() {
        return ApiData::err("note is required");
    }
    let (txid, vout) = parse_outpoint(&req.outpoint)?;
    let outpoint = format!("{txid}:{vout}");

    ensure_outpoint_unused(&this.db, &outpoint).await?;

    let Some(chain) = &this.chain else {
        return Err(ApiError::with_status(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "No chain explorer configured, cannot verify the outpoint",
        ));
    };
    let output = chain
        .lookup(&txid, vout)
        .await
        .map_err(|e| ApiError::bad_request(format!("Chain lookup failed: {e}")))?
        .ok_or_else(|| ApiError::bad_request("Outpoint not found on chain"))?;
    if !output.confirmed {
        return ApiData::err("Outpoint is not confirmed");
    }
    if !output.ours {
        return ApiData::err("Outpoint does not pay an address in our wallet");
    }
    if output.amount_msat != req.amount_msat {
        return ApiData::err("amount_msat does not match the output value on chain");
    }

    let Some(subscription_id) = req.subscription_id else {
        let user_id = req
            .user_id
            .ok_or_else(|| ApiError::bad_request("user_id is required without subscription_id"))?;
        this.db
            .get_user(user_id)
            .await
            .map_err(|_| ApiError::not_found("User not found"))?;
        let topup_id = this
            .db
            .insert_account_credit_topup(&lnvps_db::AccountCreditTopup {
                user_id,
                amount: req.amount_msat,
                currency: "BTC".to_string(),
                payment_method: PaymentMethod::OnChain,
                invoice_hash: random_32_bytes(),
                external_data: String::new(),
                external_id: Some(outpoint.clone()),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                if is_duplicate_error(&e) {
                    ApiError::conflict(format!("Outpoint {outpoint} is already recorded"))
                } else {
                    ApiError::internal(e)
                }
            })?;
        this.db
            .settle_account_credit_topup(topup_id, "BTC", req.amount_msat)
            .await?;
        log::info!(
            "Admin {} credited external deposit {} ({} msat) to user {}: {}",
            auth.user_id,
            outpoint,
            req.amount_msat,
            user_id,
            req.note
        );
        let balance_msat = this
            .db
            .list_account_credits(user_id)
            .await?
            .into_iter()
            .find(|c| c.currency == "BTC")
            .map(|c| c.balance)
            .unwrap_or(0);
        return ApiData::ok(AdminExternalPaymentResult::Credit {
            topup_id,
            user_id,
            amount_msat: req.amount_msat,
            external_id: outpoint,
            balance_msat,
        });
    };

    let subscription = this
        .db
        .get_subscription(subscription_id)
        .await
        .map_err(|_| ApiError::not_found("Subscription not found"))?;
    if req.user_id.is_some_and(|u| u != subscription.user_id) {
        return ApiData::err("user_id does not own the subscription");
    }

    let id = random_32_bytes();
    let mut payment = SubscriptionPayment {
        id: id.clone(),
        subscription_id,
        user_id: subscription.user_id,
        created: Utc::now(),
        expires: Utc::now(),
        amount: req.amount_msat,
        currency: "BTC".to_string(),
        payment_method: PaymentMethod::OnChain,
        payment_type: SubscriptionPaymentType::Renewal,
        external_data: String::new().into(),
        external_id: Some(outpoint.clone()),
        renewal_source: Some(lnvps_db::RenewalSource::Manual),
        is_paid: false,
        rate: 0.0,
        time_value: None,
        metadata: None,
        tax: 0,
        processing_fee: 0,
        paid_at: None,
        tax_rate: None,
        tax_country_code: None,
        tax_treatment: None,
        tax_evidence: None,
        tax_breakdown: None,
        refunded_payment_id: None,
    };
    price_external_payment(&this, &mut payment).await?;
    this.db
        .insert_subscription_payment(&payment)
        .await
        .map_err(|e| {
            if is_duplicate_error(&e) {
                ApiError::conflict(format!("Outpoint {outpoint} is already recorded"))
            } else {
                ApiError::internal(e)
            }
        })?;
    this.db.subscription_payment_paid(&payment).await?;
    log::info!(
        "Admin {} recorded external deposit {} ({} msat) on subscription {}: {}",
        auth.user_id,
        outpoint,
        req.amount_msat,
        subscription_id,
        req.note
    );

    if let Ok(vm) = this.db.get_vm_by_subscription(subscription_id).await {
        let history = lnvps_db::VmHistory {
            id: 0,
            vm_id: vm.id,
            action_type: lnvps_db::VmHistoryActionType::PaymentReceived,
            timestamp: Utc::now(),
            initiated_by_user: Some(auth.user_id),
            previous_state: None,
            new_state: None,
            metadata: serde_json::to_vec(&serde_json::json!({
                "outpoint": outpoint,
                "amount_msat": req.amount_msat,
                "time_added_seconds": payment.time_value,
                "admin_id": auth.user_id,
                "note": req.note,
            }))
            .ok(),
            description: Some(format!(
                "External on-chain payment {outpoint} recorded by admin: {}",
                req.note
            )),
        };
        if let Err(e) = this.db.insert_vm_history(&history).await {
            log::error!("Failed to write history for external payment {outpoint}: {e}");
        }
    }

    let payment_id = hex::encode(&id);
    this.work_commander
        .send(WorkJob::ApplySubscriptionPayment { payment_id })
        .await?;
    if let Err(e) = this.work_commander.send(WorkJob::CheckSubscriptions).await {
        log::error!(
            "External payment recorded but failed to dispatch CheckSubscriptions for subscription {}: {}",
            subscription_id,
            e
        );
    }

    let updated = this.db.get_subscription_payment_with_company(&id).await?;
    ApiData::ok(AdminExternalPaymentResult::Payment(Box::new(
        AdminSubscriptionPaymentInfo::from_with_company(updated),
    )))
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

    use crate::admin::chain::{ChainOutput, ChainOutputLookup};
    use crate::admin::model::Permission;
    use lnvps_api_common::ExchangeRateService;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, Ticker, VatClient, VmStateCache,
    };
    use lnvps_db::{LNVpsDbBase, LineItemType, SubscriptionLineItem, SubscriptionPayment, Vm};

    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const AMOUNT: u64 = 1_100_000;

    struct FixedChain(Option<ChainOutput>);

    #[async_trait::async_trait]
    impl ChainOutputLookup for FixedChain {
        async fn lookup(&self, _txid: &str, _vout: u32) -> anyhow::Result<Option<ChainOutput>> {
            Ok(self.0.clone())
        }
    }

    fn chain_output(confirmed: bool, ours: bool) -> ChainOutput {
        ChainOutput {
            address: "bcrt1qours".to_string(),
            amount_msat: AMOUNT,
            confirmed,
            ours,
        }
    }

    fn create_auth() -> AdminAuth {
        AdminAuth {
            user_id: 7,
            pubkey: vec![1u8; 32],
            permissions: [Permission {
                resource: AdminResource::SubscriptionPayments,
                action: AdminAction::Create,
            }]
            .into_iter()
            .collect(),
            nip98_auth: None,
        }
    }

    async fn fixture(output: Option<ChainOutput>) -> (Arc<MockDb>, RouterState, u64, u64) {
        crate::verbose_errors_for_tests();
        let db = Arc::new(MockDb::default());
        let rates = Arc::new(MockExchangeRate::default());
        rates
            .set_rate(Ticker::btc_rate("EUR").unwrap(), 100_000.0)
            .await;
        let user_id = db.upsert_user(&[1u8; 32]).await.unwrap();
        let (sub_id, items) = db
            .insert_subscription_with_line_items(
                &Subscription {
                    user_id,
                    company_id: 1,
                    name: "test".to_string(),
                    created: Utc::now(),
                    currency: "EUR".to_string(),
                    interval_amount: 1,
                    interval_type: IntervalType::Month,
                    ..mk_subscription(None)
                },
                vec![SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0,
                    subscription_type: LineItemType::Vps,
                    name: "vm renewal".to_string(),
                    description: None,
                    amount: 1000,
                    setup_amount: 0,
                    configuration: None,
                    deactivated_at: None,
                    parent_line_item_id: None,
                }],
            )
            .await
            .unwrap();
        db.insert_vm(&Vm {
            host_id: 1,
            user_id,
            image_id: 1,
            template_id: Some(1),
            subscription_line_item_id: items[0],
            disk_id: 1,
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ..Default::default()
        })
        .await
        .unwrap();
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let this = RouterState {
            node_control: None,
            db: dyn_db,
            work_commander: Arc::new(ChannelWorkCommander::new()),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: rates,
            vat: VatClient::new(),
            chain: Some(Arc::new(FixedChain(output))),
        };
        (db, this, sub_id, user_id)
    }

    fn request(subscription_id: Option<u64>, user_id: Option<u64>) -> AdminExternalPaymentRequest {
        AdminExternalPaymentRequest {
            outpoint: format!("{TXID}:0"),
            amount_msat: AMOUNT,
            currency: "BTC".to_string(),
            payment_method: "onchain".to_string(),
            subscription_id,
            user_id,
            note: "late payment to purged VM".to_string(),
        }
    }

    async fn credit_balance(db: &MockDb, user_id: u64) -> u64 {
        db.list_account_credits(user_id)
            .await
            .unwrap()
            .iter()
            .filter(|c| c.currency == "BTC")
            .map(|c| c.balance)
            .sum()
    }

    #[tokio::test]
    async fn external_payment_extends_subscription_and_records_history() {
        let (db, this, sub_id, _) = fixture(Some(chain_output(true, true))).await;
        let before = db.get_subscription(sub_id).await.unwrap().expires;

        let out = admin_record_external_payment(
            create_auth(),
            State(this),
            Json(request(Some(sub_id), None)),
        )
        .await
        .unwrap();
        let AdminExternalPaymentResult::Payment(p) = out.0.data else {
            panic!("expected a payment");
        };
        assert!(p.is_paid);
        assert_eq!(p.external_id, Some(format!("{TXID}:0")));
        let time = p.time_value.expect("priced time");
        assert!(time > 0);
        assert_eq!(p.amount + p.tax + p.processing_fee, AMOUNT);

        let after = db.get_subscription(sub_id).await.unwrap().expires.unwrap();
        let floor = before.unwrap_or_else(Utc::now).max(Utc::now());
        assert!((after - floor).num_seconds().abs() as u64 >= time - 5);

        let vm = db.get_vm_by_subscription(sub_id).await.unwrap();
        let history = db.list_vm_history(vm.id).await.unwrap();
        assert!(history.iter().any(|h| {
            h.initiated_by_user == Some(7)
                && h.description
                    .as_deref()
                    .is_some_and(|d| d.contains("late payment"))
        }));
    }

    #[tokio::test]
    async fn external_payment_twice_conflicts_without_extending_again() {
        let (db, this, sub_id, _) = fixture(Some(chain_output(true, true))).await;
        admin_record_external_payment(
            create_auth(),
            State(this.clone()),
            Json(request(Some(sub_id), None)),
        )
        .await
        .unwrap();
        let expires = db.get_subscription(sub_id).await.unwrap().expires;

        let err = admin_record_external_payment(
            create_auth(),
            State(this),
            Json(request(Some(sub_id), None)),
        )
        .await
        .err()
        .expect("second call refused");
        assert_eq!(err.code, axum::http::StatusCode::CONFLICT);
        assert_eq!(db.get_subscription(sub_id).await.unwrap().expires, expires);
    }

    #[tokio::test]
    async fn external_payment_already_settled_by_watcher_conflicts() {
        let (db, this, sub_id, user_id) = fixture(Some(chain_output(true, true))).await;
        db.insert_subscription_payment(&SubscriptionPayment {
            id: vec![9u8; 32],
            subscription_id: sub_id,
            user_id,
            created: Utc::now(),
            expires: Utc::now(),
            amount: AMOUNT,
            currency: "BTC".to_string(),
            payment_method: lnvps_db::PaymentMethod::OnChain,
            payment_type: lnvps_db::SubscriptionPaymentType::Renewal,
            external_data: "bcrt1qours".into(),
            external_id: Some(format!("{TXID}:0")),
            is_paid: true,
            rate: 1.0,
            time_value: Some(86_400),
            metadata: None,
            tax: 0,
            processing_fee: 0,
            paid_at: Some(Utc::now()),
            tax_rate: None,
            tax_country_code: None,
            tax_treatment: None,
            tax_evidence: None,
            tax_breakdown: None,
            refunded_payment_id: None,
            renewal_source: None,
        })
        .await
        .unwrap();
        let expires = db.get_subscription(sub_id).await.unwrap().expires;

        let err = admin_record_external_payment(
            create_auth(),
            State(this),
            Json(request(Some(sub_id), None)),
        )
        .await
        .err()
        .expect("refused");
        assert_eq!(err.code, axum::http::StatusCode::CONFLICT);
        assert_eq!(db.get_subscription(sub_id).await.unwrap().expires, expires);
    }

    #[tokio::test]
    async fn external_payment_without_subscription_credits_user_once() {
        let (db, this, _, user_id) = fixture(Some(chain_output(true, true))).await;
        let before = credit_balance(&db, user_id).await;

        admin_record_external_payment(
            create_auth(),
            State(this.clone()),
            Json(request(None, Some(user_id))),
        )
        .await
        .unwrap();
        assert_eq!(credit_balance(&db, user_id).await, before + AMOUNT);

        let err = admin_record_external_payment(
            create_auth(),
            State(this),
            Json(request(None, Some(user_id))),
        )
        .await
        .err()
        .expect("refused");
        assert_eq!(err.code, axum::http::StatusCode::CONFLICT);
        assert_eq!(credit_balance(&db, user_id).await, before + AMOUNT);
    }

    #[tokio::test]
    async fn external_payment_requires_confirmed_outpoint_in_our_wallet() {
        for output in [
            None,
            Some(chain_output(false, true)),
            Some(chain_output(true, false)),
        ] {
            let (db, this, sub_id, _) = fixture(output).await;
            let err = admin_record_external_payment(
                create_auth(),
                State(this),
                Json(request(Some(sub_id), None)),
            )
            .await
            .err()
            .expect("refused");
            assert_eq!(err.code, axum::http::StatusCode::BAD_REQUEST);
            assert!(db.subscription_payments.lock().await.is_empty());
        }
    }

    #[tokio::test]
    async fn external_payment_requires_create_permission() {
        let (_, this, sub_id, _) = fixture(Some(chain_output(true, true))).await;
        let mut auth = create_auth();
        auth.permissions.clear();
        assert!(
            admin_record_external_payment(auth, State(this), Json(request(Some(sub_id), None)))
                .await
                .is_err()
        );
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
