use crate::api::model::{ApiSubscription, ApiSubscriptionLineItem, ApiSubscriptionPayment};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth};
use lnvps_db::LNVpsDb;
use rocket::{Route, State, get, routes};
use serde::Serialize;
use std::sync::Arc;

pub fn routes() -> Vec<Route> {
    routes![
        v1_list_subscriptions,
        v1_get_subscription,
        v1_list_subscription_line_items,
        v1_get_subscription_line_item,
        v1_list_subscription_payments,
        v1_get_subscription_payment,
        v1_list_all_subscription_payments,
        v1_get_subscription_summary,
    ]
}

// ============================================================================
// Subscription Endpoints (User-Facing)
// ============================================================================

/// List user's subscriptions
#[get("/api/v1/subscriptions?<limit>&<offset>")]
pub async fn v1_list_subscriptions(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<ApiSubscription> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let all_subscriptions = db.list_subscriptions_by_user(uid).await?;
    let total = all_subscriptions.len() as u64;

    let mut subscriptions = Vec::new();
    for subscription in all_subscriptions
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
    {
        subscriptions.push(ApiSubscription::from_subscription(db.as_ref(), subscription).await?);
    }

    ApiPaginatedData::ok(subscriptions, total, limit, offset)
}

/// Get subscription details
#[get("/api/v1/subscriptions/<id>")]
pub async fn v1_get_subscription(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<ApiSubscription> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let subscription = db.get_subscription(id).await?;
    
    // Verify ownership
    if subscription.user_id != uid {
        return Err(anyhow::anyhow!("Access denied: not your subscription").into());
    }

    ApiData::ok(ApiSubscription::from_subscription(db.as_ref(), subscription).await?)
}

/// List subscription line items
#[get("/api/v1/subscriptions/<subscription_id>/line_items")]
pub async fn v1_list_subscription_line_items(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    subscription_id: u64,
) -> ApiResult<Vec<ApiSubscriptionLineItem>> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    // Verify subscription ownership
    let subscription = db.get_subscription(subscription_id).await?;
    if subscription.user_id != uid {
        return Err(anyhow::anyhow!("Access denied: not your subscription").into());
    }

    let line_items = db.list_subscription_line_items(subscription_id).await?;
    let api_line_items: Vec<ApiSubscriptionLineItem> = line_items
        .into_iter()
        .map(ApiSubscriptionLineItem::from)
        .collect();

    ApiData::ok(api_line_items)
}

/// Get subscription line item details
#[get("/api/v1/subscription_line_items/<id>")]
pub async fn v1_get_subscription_line_item(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: u64,
) -> ApiResult<ApiSubscriptionLineItem> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let line_item = db.get_subscription_line_item(id).await?;
    
    // Verify ownership through subscription
    let subscription = db.get_subscription(line_item.subscription_id).await?;
    if subscription.user_id != uid {
        return Err(anyhow::anyhow!("Access denied: not your line item").into());
    }

    ApiData::ok(ApiSubscriptionLineItem::from(line_item))
}

/// List subscription payments
#[get("/api/v1/subscriptions/<subscription_id>/payments?<limit>&<offset>")]
pub async fn v1_list_subscription_payments(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    subscription_id: u64,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<ApiSubscriptionPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    // Verify subscription ownership
    let subscription = db.get_subscription(subscription_id).await?;
    if subscription.user_id != uid {
        return Err(anyhow::anyhow!("Access denied: not your subscription").into());
    }

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let all_payments = db.list_subscription_payments(subscription_id).await?;
    let total = all_payments.len() as u64;

    let payments: Vec<ApiSubscriptionPayment> = all_payments
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(ApiSubscriptionPayment::from)
        .collect();

    ApiPaginatedData::ok(payments, total, limit, offset)
}

/// Get subscription payment details
#[get("/api/v1/subscription_payments/<id>")]
pub async fn v1_get_subscription_payment(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    id: String,
) -> ApiResult<ApiSubscriptionPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let payment_id = hex::decode(&id)
        .map_err(|_| anyhow::anyhow!("Invalid payment ID format"))?;
    
    let payment = db.get_subscription_payment(&payment_id).await?;
    
    // Verify ownership
    if payment.user_id != uid {
        return Err(anyhow::anyhow!("Access denied: not your payment").into());
    }

    ApiData::ok(ApiSubscriptionPayment::from(payment))
}

/// Get all user's subscription payments
#[get("/api/v1/subscription_payments?<limit>&<offset>")]
pub async fn v1_list_all_subscription_payments(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> ApiPaginatedResult<ApiSubscriptionPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let limit = limit.unwrap_or(50).min(100);
    let offset = offset.unwrap_or(0);

    let all_payments = db.list_subscription_payments_by_user(uid).await?;
    let total = all_payments.len() as u64;

    let payments: Vec<ApiSubscriptionPayment> = all_payments
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(ApiSubscriptionPayment::from)
        .collect();

    ApiPaginatedData::ok(payments, total, limit, offset)
}

#[derive(Serialize)]
pub struct ApiSubscriptionSummary {
    pub active_subscriptions: u64,
    pub total_monthly_cost: u64,
    pub currency: String,
}

/// Get subscription summary for current user
#[get("/api/v1/subscriptions/summary")]
pub async fn v1_get_subscription_summary(
    auth: Nip98Auth,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<ApiSubscriptionSummary> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = db.upsert_user(&pubkey).await?;

    let subscriptions = db.list_subscriptions_by_user(uid).await?;
    let active_subscriptions = subscriptions.iter().filter(|s| s.is_active).count() as u64;

    // Calculate total monthly cost
    let mut total_cost = 0u64;
    let mut currency = String::from("USD");

    for subscription in subscriptions.iter().filter(|s| s.is_active) {
        currency = subscription.currency.clone();
        
        // Get line items
        let line_items = db.list_subscription_line_items(subscription.id).await?;
        
        // Sum line item amounts
        let subscription_cost: u64 = line_items.iter().map(|li| li.amount).sum();
        
        // Convert to monthly if needed
        let monthly_cost = match subscription.interval_type {
            lnvps_db::VmCostPlanIntervalType::Day => {
                subscription_cost * 30 / subscription.interval_amount
            }
            lnvps_db::VmCostPlanIntervalType::Month => {
                subscription_cost / subscription.interval_amount
            }
            lnvps_db::VmCostPlanIntervalType::Year => {
                subscription_cost / (12 * subscription.interval_amount)
            }
        };
        
        total_cost += monthly_cost;
    }

    ApiData::ok(ApiSubscriptionSummary {
        active_subscriptions,
        total_monthly_cost: total_cost,
        currency,
    })
}
