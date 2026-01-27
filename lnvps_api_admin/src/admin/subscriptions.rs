use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateSubscriptionLineItemRequest, AdminCreateSubscriptionRequest,
    AdminSubscriptionInfo, AdminSubscriptionLineItemInfo, AdminSubscriptionPaymentInfo,
    AdminUpdateSubscriptionLineItemRequest, AdminUpdateSubscriptionRequest,
};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::serde::json::Json;
use rocket::{delete, get, patch, post, State};
use std::sync::Arc;

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
#[get("/api/admin/v1/subscriptions?<limit>&<offset>&<user_id>")]
pub async fn admin_list_subscriptions(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
    user_id: Option<u64>,
) -> ApiPaginatedResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let all_subscriptions = if let Some(uid) = user_id {
        db.list_subscriptions_by_user(uid).await?
    } else {
        db.list_subscriptions().await?
    };

    let total = all_subscriptions.len() as u64;

    let subscriptions = all_subscriptions
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect::<Vec<_>>();

    let mut subscription_infos = Vec::new();
    for subscription in subscriptions {
        match AdminSubscriptionInfo::from_subscription(db, &subscription).await {
            Ok(info) => subscription_infos.push(info),
            Err(_) => continue,
        }
    }

    ApiPaginatedData::ok(subscription_infos, total, limit, offset)
}

/// Get subscription details
#[get("/api/admin/v1/subscriptions/<id>")]
pub async fn admin_get_subscription(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::View)?;

    let subscription = db.get_subscription(id).await?;
    let info = AdminSubscriptionInfo::from_subscription(db, &subscription).await?;
    ApiData::ok(info)
}

/// Create subscription
#[post("/api/admin/v1/subscriptions", data = "<request>")]
pub async fn admin_create_subscription(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<AdminCreateSubscriptionRequest>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Create)?;

    let req = request.into_inner();
    
    // Verify user exists
    let _user = db.get_user(req.user_id).await?;
    
    let subscription = req.to_subscription()?;

    let subscription_id = db.insert_subscription(&subscription).await?;
    let created_subscription = db.get_subscription(subscription_id).await?;
    let info = AdminSubscriptionInfo::from_subscription(db, &created_subscription).await?;
    ApiData::ok(info)
}

/// Update subscription
#[patch("/api/admin/v1/subscriptions/<id>", data = "<request>")]
pub async fn admin_update_subscription(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<AdminUpdateSubscriptionRequest>,
) -> ApiResult<AdminSubscriptionInfo> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Update)?;

    let req = request.into_inner();

    // Get existing subscription
    let mut subscription = db.get_subscription(id).await?;

    // Update fields if provided
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(anyhow::anyhow!("Subscription name cannot be empty").into());
        }
        subscription.name = name.trim().to_string();
    }
    if let Some(description) = req.description {
        subscription.description = Some(description);
    }
    if let Some(expires) = req.expires {
        subscription.expires = expires;
    }
    if let Some(is_active) = req.is_active {
        subscription.is_active = is_active;
    }
    if let Some(currency) = req.currency {
        if currency.trim().is_empty() {
            return Err(anyhow::anyhow!("Currency cannot be empty").into());
        }
        subscription.currency = currency.trim().to_uppercase();
    }
    if let Some(interval_amount) = req.interval_amount {
        if interval_amount == 0 {
            return Err(anyhow::anyhow!("Interval amount cannot be zero").into());
        }
        subscription.interval_amount = interval_amount;
    }
    if let Some(interval_type) = req.interval_type {
        subscription.interval_type = interval_type.into();
    }
    if let Some(setup_fee) = req.setup_fee {
        subscription.setup_fee = setup_fee;
    }
    if let Some(auto_renewal_enabled) = req.auto_renewal_enabled {
        subscription.auto_renewal_enabled = auto_renewal_enabled;
    }
    if let Some(external_id) = req.external_id {
        subscription.external_id = external_id;
    }

    db.update_subscription(&subscription).await?;
    let info = AdminSubscriptionInfo::from_subscription(db, &subscription).await?;
    ApiData::ok(info)
}

/// Delete subscription
#[delete("/api/admin/v1/subscriptions/<id>")]
pub async fn admin_delete_subscription(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::Subscriptions, AdminAction::Delete)?;

    // Check if subscription exists
    let _subscription = db.get_subscription(id).await?;

    // Check if subscription has payments
    let payments = db.list_subscription_payments(id).await?;
    let paid_payment_count = payments.iter().filter(|p| p.is_paid).count();

    if paid_payment_count > 0 {
        return Err(anyhow::anyhow!(
            "Cannot delete subscription: {} paid payments exist. Consider deactivating instead.",
            paid_payment_count
        )
        .into());
    }

    db.delete_subscription(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Subscription deleted successfully"
    }))
}

// ============================================================================
// Subscription Line Items
// ============================================================================

/// List subscription line items
#[get("/api/admin/v1/subscriptions/<subscription_id>/line_items")]
pub async fn admin_list_subscription_line_items(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    subscription_id: u64,
) -> ApiResult<Vec<AdminSubscriptionLineItemInfo>> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::View)?;

    // Verify subscription exists
    let _subscription = db.get_subscription(subscription_id).await?;

    let line_items = db.list_subscription_line_items(subscription_id).await?;
    let line_item_infos: Vec<AdminSubscriptionLineItemInfo> = line_items
        .into_iter()
        .map(AdminSubscriptionLineItemInfo::from)
        .collect();

    ApiData::ok(line_item_infos)
}

/// Get subscription line item details
#[get("/api/admin/v1/subscription_line_items/<id>")]
pub async fn admin_get_subscription_line_item(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::View)?;

    let line_item = db.get_subscription_line_item(id).await?;
    ApiData::ok(AdminSubscriptionLineItemInfo::from(line_item))
}

/// Create subscription line item
#[post("/api/admin/v1/subscription_line_items", data = "<request>")]
pub async fn admin_create_subscription_line_item(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    request: Json<AdminCreateSubscriptionLineItemRequest>,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Create)?;

    let req = request.into_inner();
    
    // Verify subscription exists
    let _subscription = db.get_subscription(req.subscription_id).await?;
    
    let line_item = req.to_line_item()?;

    let line_item_id = db.insert_subscription_line_item(&line_item).await?;
    let created_line_item = db.get_subscription_line_item(line_item_id).await?;
    ApiData::ok(AdminSubscriptionLineItemInfo::from(created_line_item))
}

/// Update subscription line item
#[patch("/api/admin/v1/subscription_line_items/<id>", data = "<request>")]
pub async fn admin_update_subscription_line_item(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
    request: Json<AdminUpdateSubscriptionLineItemRequest>,
) -> ApiResult<AdminSubscriptionLineItemInfo> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Update)?;

    let req = request.into_inner();

    // Get existing line item
    let mut line_item = db.get_subscription_line_item(id).await?;

    // Update fields if provided
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(anyhow::anyhow!("Line item name cannot be empty").into());
        }
        line_item.name = name.trim().to_string();
    }
    if let Some(description) = req.description {
        line_item.description = Some(description);
    }
    if let Some(amount) = req.amount {
        line_item.amount = amount;
    }
    if let Some(setup_amount) = req.setup_amount {
        line_item.setup_amount = setup_amount;
    }
    if let Some(configuration) = req.configuration {
        line_item.configuration = Some(configuration);
    }

    db.update_subscription_line_item(&line_item).await?;
    ApiData::ok(AdminSubscriptionLineItemInfo::from(line_item))
}

/// Delete subscription line item
#[delete("/api/admin/v1/subscription_line_items/<id>")]
pub async fn admin_delete_subscription_line_item(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::SubscriptionLineItems, AdminAction::Delete)?;

    // Check if line item exists
    let _line_item = db.get_subscription_line_item(id).await?;

    db.delete_subscription_line_item(id).await?;
    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Subscription line item deleted successfully"
    }))
}

// ============================================================================
// Subscription Payments
// ============================================================================

/// List subscription payments
#[get("/api/admin/v1/subscriptions/<subscription_id>/payments?<limit>&<offset>")]
pub async fn admin_list_subscription_payments(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    subscription_id: u64,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::View)?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    // Verify subscription exists
    let _subscription = db.get_subscription(subscription_id).await?;

    let all_payments = db.list_subscription_payments(subscription_id).await?;
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
#[get("/api/admin/v1/subscription_payments/<id>")]
pub async fn admin_get_subscription_payment(
    auth: AdminAuth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: String,
) -> ApiResult<AdminSubscriptionPaymentInfo> {
    auth.require_permission(AdminResource::SubscriptionPayments, AdminAction::View)?;

    let payment_id = hex::decode(&id)
        .map_err(|_| anyhow::anyhow!("Invalid payment ID format"))?;
    
    let payment = db.get_subscription_payment(&payment_id).await?;
    ApiData::ok(AdminSubscriptionPaymentInfo::from(payment))
}
