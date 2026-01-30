use crate::api::model::{ApiSubscription, ApiSubscriptionPayment};
use crate::api::{PageQuery, RouterState};
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/subscriptions", get(v1_list_subscriptions))
        .route("/api/v1/subscriptions/{id}", get(v1_get_subscription))
        .route(
            "/api/v1/subscriptions/{id}/payments",
            get(v1_list_subscription_payments),
        )
}

// ============================================================================
// Subscription Endpoints (User-Facing)
// ============================================================================

/// List user's subscriptions
async fn v1_list_subscriptions(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiSubscription> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);

    let all_subscriptions = this.db.list_subscriptions_by_user(uid).await?;
    let total = all_subscriptions.len() as u64;

    let mut subscriptions = Vec::new();
    for subscription in all_subscriptions
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
    {
        subscriptions
            .push(ApiSubscription::from_subscription(this.db.as_ref(), subscription).await?);
    }

    ApiPaginatedData::ok(subscriptions, total, limit, offset)
}

/// Get subscription details
pub async fn v1_get_subscription(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiSubscription> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    let subscription = this.db.get_subscription(id).await?;

    // Verify ownership
    if subscription.user_id != uid {
        return ApiData::err("Access denied: not your subscription");
    }

    ApiData::ok(ApiSubscription::from_subscription(this.db.as_ref(), subscription).await?)
}

/// List subscription payments
pub async fn v1_list_subscription_payments(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiSubscriptionPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Verify subscription ownership
    let subscription = this.db.get_subscription(id).await?;
    if subscription.user_id != uid {
        return ApiPaginatedData::err("Access denied: not your subscription");
    }

    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);

    let all_payments = this.db.list_subscription_payments(id).await?;
    let total = all_payments.len() as u64;

    let payments: Vec<ApiSubscriptionPayment> = all_payments
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(ApiSubscriptionPayment::from)
        .collect();

    ApiPaginatedData::ok(payments, total, limit, offset)
}
