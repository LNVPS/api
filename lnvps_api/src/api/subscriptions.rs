use crate::api::model::{ApiCreateSubscriptionRequest, ApiSubscription, ApiSubscriptionPayment};
use crate::api::{PaymentMethodQuery, RouterState};
use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
};
use lnvps_db::{PaymentMethod, Subscription, SubscriptionLineItem, SubscriptionType};
use std::str::FromStr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/subscriptions",
            get(v1_list_subscriptions).post(v1_create_subscription),
        )
        .route("/api/v1/subscriptions/{id}", get(v1_get_subscription))
        .route(
            "/api/v1/subscriptions/{id}/payments",
            get(v1_list_subscription_payments),
        )
        .route(
            "/api/v1/subscriptions/{id}/renew",
            get(v1_renew_subscription),
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

// ============================================================================
// Create Subscription with Line Items
// ============================================================================

/// Create a new subscription with one or more line items (IP ranges, ASN sponsoring, DNS hosting, etc.)
///
/// This creates the subscription and line items in an INACTIVE state.
/// Resources (IP ranges, ASNs, etc.) are NOT allocated until the first payment is made.
///
/// Workflow:
/// 1. User creates subscription with line items (this endpoint)
/// 2. User makes payment via subscription payment endpoint
/// 3. Payment handler allocates resources (IP ranges, etc.) and activates subscription
/// 4. Resources remain active while subscription is paid
async fn v1_create_subscription(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<ApiCreateSubscriptionRequest>,
) -> ApiResult<ApiSubscription> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Validate that we have at least one line item
    if req.line_items.is_empty() {
        return ApiData::err("At least one line item is required");
    }

    // Determine subscription parameters
    let currency = req.currency.unwrap_or_else(|| "USD".to_string());
    let auto_renewal = req.auto_renewal_enabled.unwrap_or(true);

    // Calculate total setup fee and recurring amount
    let mut total_setup_fee = 0u64;
    let mut total_recurring_amount = 0u64;
    let mut line_items_to_create = Vec::new();
    let mut derived_company_id: Option<u64> = None;

    // Process each line item to validate and calculate pricing
    for item in &req.line_items {
        use crate::api::model::ApiCreateSubscriptionLineItemRequest;

        match item {
            ApiCreateSubscriptionLineItemRequest::IpRange {
                ip_space_pricing_id,
            } => {
                let pricing = this.db.get_ip_space_pricing(*ip_space_pricing_id).await?;
                let ip_space = this
                    .db
                    .get_available_ip_space(pricing.available_ip_space_id)
                    .await?;

                // Derive company_id from the IP space
                match derived_company_id {
                    None => derived_company_id = Some(ip_space.company_id),
                    Some(cid) if cid != ip_space.company_id => {
                        return ApiData::err(
                            "All line items must belong to the same company",
                        );
                    }
                    _ => {}
                }

                // Verify IP space is available
                if !ip_space.is_available || ip_space.is_reserved {
                    return ApiData::err("IP space is not available for allocation");
                }

                total_setup_fee += pricing.setup_fee as u64;
                total_recurring_amount += pricing.price_per_month as u64;

                line_items_to_create.push((
                    format!("IP Range: /{} from {}", pricing.prefix_size, ip_space.cidr),
                    Some(format!(
                        "/{} IP range from {} block",
                        pricing.prefix_size, ip_space.cidr
                    )),
                    pricing.price_per_month as u64,
                    pricing.setup_fee as u64,
                    SubscriptionType::IpRange,
                    Some(serde_json::json!({
                        "ip_space_pricing_id": pricing.id,
                        "available_ip_space_id": ip_space.id,
                        "prefix_size": pricing.prefix_size,
                    })),
                ));
            }
            ApiCreateSubscriptionLineItemRequest::AsnSponsoring { asn: _ } => {
                // TODO: Implement ASN sponsoring pricing lookup
                // For now, return error
                return ApiData::err("ASN sponsoring not yet implemented");
            }
            ApiCreateSubscriptionLineItemRequest::DnsHosting { domain: _ } => {
                // TODO: Implement DNS hosting pricing lookup
                // For now, return error
                return ApiData::err("DNS hosting not yet implemented");
            }
        }
    }

    // company_id must be derived from line items
    let company_id = derived_company_id
        .ok_or_else(|| anyhow::anyhow!("Could not determine company from line items"))?;

    // Create the subscription (always monthly interval)
    let subscription = Subscription {
        id: 0, // Will be set by database
        user_id: uid,
        company_id,
        name: req.name.unwrap_or_else(|| "Subscription".to_string()),
        description: req.description,
        created: Utc::now(),
        expires: None,    // Will be set after first payment
        is_active: false, // Inactive until first payment
        currency,
        setup_fee: total_setup_fee,
        auto_renewal_enabled: auto_renewal,
        external_id: None,
    };

    // Build line items (will get subscription_id after insert)
    let line_items: Vec<SubscriptionLineItem> = line_items_to_create
        .into_iter()
        .map(
            |(name, description, amount, setup_amount, subscription_type, configuration)| {
                SubscriptionLineItem {
                    id: 0,
                    subscription_id: 0, // Will be set below
                    subscription_type,
                    name,
                    description,
                    amount,
                    setup_amount,
                    configuration,
                }
            },
        )
        .collect();

    // Insert subscription and line items in a single transaction
    let subscription_id = this
        .db
        .insert_subscription_with_line_items(&subscription, line_items)
        .await?;

    // Fetch and return the created subscription
    let created_subscription = this.db.get_subscription(subscription_id).await?;
    ApiData::ok(ApiSubscription::from_subscription(this.db.as_ref(), created_subscription).await?)
}

// ============================================================================
// Subscription Renewal
// ============================================================================

/// Renew a subscription - generates payment invoice
///
/// Similar to VM renewal, this generates a payment invoice for the subscription.
/// The payment amount is calculated from the line items.
/// - First payment: Monthly cost + setup fees
/// - Renewal: Monthly cost only
async fn v1_renew_subscription(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
) -> ApiResult<ApiSubscriptionPayment> {
    let pubkey = auth.event.pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Get and verify subscription ownership
    let subscription = this.db.get_subscription(id).await?;
    if subscription.user_id != uid {
        return ApiData::err("Access denied: not your subscription");
    }

    // Determine payment method
    let method = q
        .method
        .and_then(|m| PaymentMethod::from_str(&m).ok())
        .unwrap_or(PaymentMethod::Lightning);

    // Generate payment via provisioner
    let payment = this
        .provisioner
        .renew_subscription(id, method)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to generate payment: {}", e))?;

    ApiData::ok(ApiSubscriptionPayment::from(payment))
}
