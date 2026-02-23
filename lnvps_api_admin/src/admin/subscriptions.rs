use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateSubscriptionLineItemRequest, AdminCreateSubscriptionRequest, AdminSubscriptionInfo,
    AdminSubscriptionLineItemInfo, AdminSubscriptionPaymentInfo,
    AdminUpdateSubscriptionLineItemRequest, AdminUpdateSubscriptionRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
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
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
}

impl AdminSubscriptionInfo {
    pub async fn from_subscription(
        db: &Arc<dyn LNVpsDb>,
        subscription: &lnvps_db::Subscription,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Fetch line items
        let line_items = db
            .list_subscription_line_items(subscription.id)
            .await
            .unwrap_or_default();

        let line_item_infos: Vec<AdminSubscriptionLineItemInfo> = line_items
            .into_iter()
            .map(AdminSubscriptionLineItemInfo::from)
            .collect();

        // Count payments
        let payments = db
            .list_subscription_payments(subscription.id)
            .await
            .unwrap_or_default();
        let payment_count = payments.len() as u64;

        let mut info = AdminSubscriptionInfo::from(subscription.clone());
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

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let all_subscriptions = if let Some(uid) = params.user_id {
        this.db.list_subscriptions_by_user(uid).await?
    } else {
        this.db.list_subscriptions().await?
    };

    let total = all_subscriptions.len() as u64;

    let subscriptions = all_subscriptions
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();

    let mut subscription_infos = Vec::new();
    for subscription in subscriptions {
        match AdminSubscriptionInfo::from_subscription(&this.db, &subscription).await {
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
            return Err(anyhow::anyhow!("Subscription name cannot be empty").into());
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
            return Err(anyhow::anyhow!("Currency cannot be empty").into());
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

/// Delete subscription
async fn admin_delete_subscription(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Delete)?;

    // Check if subscription exists
    let _subscription = this.db.get_subscription(id).await?;

    // Check if subscription has payments
    let payments = this.db.list_subscription_payments(id).await?;
    let paid_payment_count = payments.iter().filter(|p| p.is_paid).count();

    if paid_payment_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete subscription: {} paid payments exist. Consider deactivating instead.",
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
    let line_item_infos: Vec<AdminSubscriptionLineItemInfo> = line_items
        .into_iter()
        .map(AdminSubscriptionLineItemInfo::from)
        .collect();

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
    ApiData::ok(AdminSubscriptionLineItemInfo::from(line_item))
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
    ApiData::ok(AdminSubscriptionLineItemInfo::from(created_line_item))
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

    // Update fields if provided
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(anyhow::anyhow!("Line item name cannot be empty").into());
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
    ApiData::ok(AdminSubscriptionLineItemInfo::from(line_item))
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

    // Verify subscription exists
    let _subscription = this.db.get_subscription(subscription_id).await?;

    let all_payments = this.db.list_subscription_payments(subscription_id).await?;
    let total = all_payments.len() as u64;

    let payments: Vec<AdminSubscriptionPaymentInfo> = all_payments
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(AdminSubscriptionPaymentInfo::from)
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

    let payment = this.db.get_subscription_payment(&payment_id).await?;
    ApiData::ok(AdminSubscriptionPaymentInfo::from(payment))
}

/// Manually mark a subscription payment as paid (admin override).
///
/// This calls `subscription_payment_paid` which sets `is_paid=true`,
/// records `paid_at`, extends the subscription by 30 days, and activates it.
async fn admin_complete_subscription_payment(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::Update)?;

    let payment_id = hex::decode(&id).map_err(|_| anyhow::anyhow!("Invalid payment ID format"))?;

    let payment = this.db.get_subscription_payment(&payment_id).await?;

    if payment.is_paid {
        return ApiData::err("Payment is already completed");
    }

    this.db.subscription_payment_paid(&payment).await?;

    log::info!(
        "Admin {} manually completed subscription payment {} for subscription {}",
        auth.user_id,
        id,
        payment.subscription_id
    );

    // Re-read the payment to get updated state
    let updated = this.db.get_subscription_payment(&payment_id).await?;
    ApiData::ok(AdminSubscriptionPaymentInfo::from(updated))
}
