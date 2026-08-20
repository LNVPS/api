use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminCreateDiscountRequest, AdminDiscountInfo, AdminDiscountPreview,
    AdminDiscountRedemptionInfo, AdminDiscountTotal, AdminPreviewDiscountRequest,
    AdminPreviewOrder, AdminUpdateDiscountRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, DiscountContext,
    HistoryContext, PageQuery, UserContext, evaluate_rule, validate_rule,
};
use lnvps_db::{AdminAction, AdminResource, Discount, LNVpsDb};
use std::sync::Arc;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/discounts",
            get(admin_list_discounts).post(admin_create_discount),
        )
        .route(
            "/api/admin/v1/discounts/preview",
            post(admin_preview_discount),
        )
        .route(
            "/api/admin/v1/discounts/{id}",
            get(admin_get_discount)
                .patch(admin_update_discount)
                .delete(admin_delete_discount),
        )
        .route(
            "/api/admin/v1/discounts/{id}/redemptions",
            get(admin_list_discount_redemptions),
        )
}

#[derive(serde::Deserialize)]
struct ListDiscountsQuery {
    /// Discounts are per-company, so listing them requires choosing one.
    company_id: u64,
    #[serde(flatten)]
    page: PageQuery,
}

/// Build the admin view of a discount, including what it has cost so far.
async fn discount_info(db: &Arc<dyn LNVpsDb>, d: Discount) -> Result<AdminDiscountInfo, ApiError> {
    let given_away = db
        .sum_discount_redemptions(d.id)
        .await?
        .into_iter()
        .map(|(currency, amount)| AdminDiscountTotal { currency, amount })
        .collect();
    Ok(AdminDiscountInfo {
        id: d.id,
        company_id: d.company_id,
        code: d.code,
        name: d.name,
        rule: d.rule,
        valid_from: d.valid_from,
        valid_to: d.valid_to,
        usage_limit: d.usage_limit,
        used_count: d.used_count,
        per_user_limit: d.per_user_limit,
        active: d.active,
        created: d.created,
        given_away,
    })
}

/// Validate a create request and turn it into a row.
///
/// Split out of the handler so the rules it enforces are unit-testable without
/// standing up an authenticated router.
fn to_discount(request: &AdminCreateDiscountRequest) -> Result<Discount, ApiError> {
    let code = request.code.trim();
    if code.is_empty() {
        // Phase 1 is codes only. A code-less row would be an *automatic*
        // discount applied to every order, which nothing evaluates yet — it
        // would silently do nothing rather than what the admin intended.
        return Err(ApiError::new("Code cannot be empty"));
    }
    if request.name.trim().is_empty() {
        return Err(ApiError::new("Name cannot be empty"));
    }
    validate_rule(&request.rule).map_err(|e| ApiError::new(e.to_string()))?;

    let valid_from = request.valid_from.unwrap_or_else(Utc::now);
    if request
        .valid_to
        .is_some_and(|valid_to| valid_to <= valid_from)
    {
        return Err(ApiError::new("valid_to must be after valid_from"));
    }

    Ok(Discount {
        id: 0,
        company_id: request.company_id,
        // Codes are stored and matched exactly; upper-casing here would make a
        // lower-case code un-enterable rather than case-insensitive.
        code: Some(code.to_string()),
        name: request.name.trim().to_string(),
        rule: request.rule.trim().to_string(),
        valid_from,
        valid_to: request.valid_to,
        usage_limit: request.usage_limit,
        used_count: 0,
        per_user_limit: request.per_user_limit,
        active: request.active.unwrap_or(true),
        created: Utc::now(),
    })
}

/// Apply an update request to an existing row.
fn apply_update(
    mut discount: Discount,
    request: &AdminUpdateDiscountRequest,
) -> Result<Discount, ApiError> {
    if let Some(code) = &request.code {
        let code = code.trim();
        if code.is_empty() {
            return Err(ApiError::new("Code cannot be empty"));
        }
        discount.code = Some(code.to_string());
    }
    if let Some(name) = &request.name {
        if name.trim().is_empty() {
            return Err(ApiError::new("Name cannot be empty"));
        }
        discount.name = name.trim().to_string();
    }
    if let Some(rule) = &request.rule {
        validate_rule(rule).map_err(|e| ApiError::new(e.to_string()))?;
        discount.rule = rule.trim().to_string();
    }
    if let Some(valid_from) = request.valid_from {
        discount.valid_from = valid_from;
    }
    if let Some(valid_to) = request.valid_to {
        discount.valid_to = Some(valid_to);
    }
    if request.usage_limit.is_some() {
        discount.usage_limit = request.usage_limit;
    }
    if request.per_user_limit.is_some() {
        discount.per_user_limit = request.per_user_limit;
    }
    if let Some(active) = request.active {
        discount.active = active;
    }

    if discount
        .valid_to
        .is_some_and(|valid_to| valid_to <= discount.valid_from)
    {
        return Err(ApiError::new("valid_to must be after valid_from"));
    }
    Ok(discount)
}

/// Evaluate a rule against a sample order, reporting what it would do.
///
/// This is what makes raw-CEL "advanced mode" safe to expose: an admin can see
/// the clamped decision, and the reason for a rejection, before any customer
/// meets the rule.
fn preview_rule(request: &AdminPreviewDiscountRequest) -> AdminDiscountPreview {
    let context = sample_context(request.order.as_ref());
    let order_amount = context.order.amount.max(0) as u64;
    let currency = context.order.currency.clone();

    let decision = match evaluate_rule(&request.rule, &context) {
        Ok(d) => d,
        Err(e) => {
            return AdminDiscountPreview {
                applies: false,
                percent: None,
                amount: None,
                currency: None,
                amount_off: 0,
                error: Some(e.to_string()),
            };
        }
    };

    // The preview does no currency conversion: it has no payment method and so
    // no rate to quote. A cross-currency fixed amount is reported as the error
    // it would produce here, with the amount still shown so the admin can see
    // the rule parsed correctly.
    let (amount_off, error) = match decision.amount_off(order_amount, &currency) {
        Ok(v) => (v, None),
        Err(e) => (0, Some(e.to_string())),
    };

    AdminDiscountPreview {
        applies: amount_off > 0,
        percent: decision.percent,
        amount: decision.amount,
        currency: decision.currency,
        amount_off,
        error,
    }
}

/// The context a preview is evaluated against: the shared sample, with any
/// supplied field overriding it.
fn sample_context(order: Option<&AdminPreviewOrder>) -> DiscountContext {
    let mut context = DiscountContext::sample();
    let Some(o) = order else {
        return context;
    };
    if let Some(amount) = o.amount {
        context.order.amount = amount;
    }
    if let Some(currency) = &o.currency {
        context.order.currency = currency.to_uppercase();
    }
    if let Some(intervals) = o.intervals {
        context.order.intervals = intervals;
    }
    if let Some(interval_type) = &o.interval_type {
        context.order.interval_type = interval_type.to_lowercase();
    }
    if let Some(is_new) = o.is_new {
        context.order.is_new = is_new;
    }
    if let Some(items) = &o.items {
        context.order.items = items.clone();
    }
    if o.country.is_some() {
        context.user = UserContext {
            id: context.user.id,
            country: o.country.clone(),
        };
    }
    if let Some(orders) = o.orders {
        context.history = HistoryContext { orders };
    }
    context
}

async fn admin_list_discounts(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListDiscountsQuery>,
) -> ApiPaginatedResult<AdminDiscountInfo> {
    auth.require_permission(AdminResource::Discount, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);
    let (discounts, total) = this
        .db
        .list_discounts_paginated(params.company_id, limit, offset)
        .await?;

    let mut out = Vec::with_capacity(discounts.len());
    for d in discounts {
        out.push(discount_info(&this.db, d).await?);
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_discount(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminDiscountInfo> {
    auth.require_permission(AdminResource::Discount, AdminAction::View)?;

    let discount = this.db.get_discount(id).await?;
    ApiData::ok(discount_info(&this.db, discount).await?)
}

async fn admin_create_discount(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<AdminCreateDiscountRequest>,
) -> ApiResult<AdminDiscountInfo> {
    auth.require_permission(AdminResource::Discount, AdminAction::Create)?;

    // The company must exist: the FK would reject it anyway, but as a 500.
    this.db.get_company(request.company_id).await?;

    let id = this.db.insert_discount(&to_discount(&request)?).await?;
    let created = this.db.get_discount(id).await?;
    ApiData::ok(discount_info(&this.db, created).await?)
}

async fn admin_update_discount(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<AdminUpdateDiscountRequest>,
) -> ApiResult<AdminDiscountInfo> {
    auth.require_permission(AdminResource::Discount, AdminAction::Update)?;

    let existing = this.db.get_discount(id).await?;
    let updated = apply_update(existing, &request)?;
    this.db.update_discount(&updated).await?;

    let after = this.db.get_discount(id).await?;
    ApiData::ok(discount_info(&this.db, after).await?)
}

async fn admin_delete_discount(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::Discount, AdminAction::Delete)?;

    // Deleting a redeemed discount would orphan its redemption rows, so the FK
    // refuses it. Deactivate instead — the campaign's cost stays reportable.
    this.db.delete_discount(id).await?;
    ApiData::ok(())
}

async fn admin_list_discount_redemptions(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminDiscountRedemptionInfo> {
    auth.require_permission(AdminResource::Discount, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_discount_redemptions_paginated(id, limit, offset)
        .await?;

    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_preview_discount(
    auth: AdminAuth,
    State(_this): State<RouterState>,
    Json(request): Json<AdminPreviewDiscountRequest>,
) -> ApiResult<AdminDiscountPreview> {
    // A preview reads no customer data and writes nothing, but it is still the
    // rule-authoring surface, so it takes the same permission as creating one.
    auth.require_permission(AdminResource::Discount, AdminAction::Create)?;

    ApiData::ok(preview_rule(&request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;
    use lnvps_db::{DiscountRedemption, LNVpsDbBase};

    fn create() -> AdminCreateDiscountRequest {
        AdminCreateDiscountRequest {
            company_id: 1,
            code: "SAVE10".to_string(),
            name: "Save 10".to_string(),
            rule: "{'percent': 10}".to_string(),
            valid_from: None,
            valid_to: None,
            usage_limit: None,
            per_user_limit: None,
            active: None,
        }
    }

    fn update() -> AdminUpdateDiscountRequest {
        AdminUpdateDiscountRequest {
            code: None,
            name: None,
            rule: None,
            valid_from: None,
            valid_to: None,
            usage_limit: None,
            per_user_limit: None,
            active: None,
        }
    }

    /// The admin view reports what the campaign has cost, per currency, because
    /// redemptions are recorded in whatever the customer paid in.
    #[tokio::test]
    async fn info_reports_campaign_cost_per_currency() {
        let mock = MockDb::default();
        let user_id = mock.upsert_user(&[1; 32]).await.unwrap();
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let id = db
            .insert_discount(&to_discount(&create()).unwrap())
            .await
            .unwrap();

        let fresh = discount_info(&db, db.get_discount(id).await.unwrap())
            .await
            .unwrap();
        assert_eq!(fresh.code.as_deref(), Some("SAVE10"));
        assert_eq!(fresh.used_count, 0);
        assert!(fresh.given_away.is_empty());

        for (n, amount, currency) in [(1u8, 1_000u64, "EUR"), (2, 500, "EUR"), (3, 700, "BTC")] {
            db.insert_discount_redemption(&DiscountRedemption {
                discount_id: id,
                user_id,
                subscription_payment_id: vec![n; 32],
                amount_off: amount,
                currency: currency.to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
            db.settle_discount_redemption(&vec![n; 32])
                .await
                .unwrap()
                .expect("settles");
        }

        let after = discount_info(&db, db.get_discount(id).await.unwrap())
            .await
            .unwrap();
        assert_eq!(after.used_count, 3);
        let totals: Vec<(String, u64)> = after
            .given_away
            .iter()
            .map(|t| (t.currency.clone(), t.amount))
            .collect();
        assert_eq!(
            totals,
            vec![("BTC".to_string(), 700), ("EUR".to_string(), 1_500)]
        );
    }

    #[test]
    fn create_defaults_are_sane() {
        let d = to_discount(&create()).unwrap();
        assert_eq!(d.code.as_deref(), Some("SAVE10"));
        assert!(d.active, "a new discount is live unless told otherwise");
        assert_eq!(d.used_count, 0);
        assert!(d.valid_to.is_none());
        assert!(d.valid_from <= Utc::now());
    }

    /// Whitespace is trimmed, but case is preserved: upper-casing the stored
    /// code would make a lower-case code impossible to enter, not
    /// case-insensitive.
    #[test]
    fn code_is_trimmed_not_normalised() {
        let d = to_discount(&AdminCreateDiscountRequest {
            code: "  save10  ".to_string(),
            ..create()
        })
        .unwrap();
        assert_eq!(d.code.as_deref(), Some("save10"));
    }

    #[test]
    fn create_rejects_bad_input() {
        for bad in [
            AdminCreateDiscountRequest {
                code: "   ".to_string(),
                ..create()
            },
            AdminCreateDiscountRequest {
                name: " ".to_string(),
                ..create()
            },
            AdminCreateDiscountRequest {
                rule: "not valid cel {{".to_string(),
                ..create()
            },
            AdminCreateDiscountRequest {
                rule: String::new(),
                ..create()
            },
            AdminCreateDiscountRequest {
                valid_from: Some(Utc::now()),
                valid_to: Some(Utc::now() - chrono::Duration::days(1)),
                ..create()
            },
        ] {
            assert!(to_discount(&bad).is_err());
        }
    }

    #[test]
    fn update_changes_only_supplied_fields() {
        let original = to_discount(&create()).unwrap();
        let unchanged = apply_update(
            Discount {
                used_count: 3,
                ..original.clone()
            },
            &update(),
        )
        .unwrap();
        assert_eq!(unchanged.name, original.name);
        assert_eq!(unchanged.rule, original.rule);
        assert_eq!(
            unchanged.used_count, 3,
            "an edit must never rewrite the redemption count"
        );

        let changed = apply_update(
            original.clone(),
            &AdminUpdateDiscountRequest {
                name: Some("Renamed".to_string()),
                rule: Some("{'percent': 20}".to_string()),
                usage_limit: Some(10),
                active: Some(false),
                ..update()
            },
        )
        .unwrap();
        assert_eq!(changed.name, "Renamed");
        assert_eq!(changed.rule, "{'percent': 20}");
        assert_eq!(changed.usage_limit, Some(10));
        assert!(!changed.active);
    }

    #[test]
    fn update_rejects_bad_input() {
        let original = to_discount(&create()).unwrap();
        for bad in [
            AdminUpdateDiscountRequest {
                code: Some(" ".to_string()),
                ..update()
            },
            AdminUpdateDiscountRequest {
                name: Some(" ".to_string()),
                ..update()
            },
            AdminUpdateDiscountRequest {
                rule: Some("{'percent': ".to_string()),
                ..update()
            },
            AdminUpdateDiscountRequest {
                valid_to: Some(original.valid_from - chrono::Duration::days(1)),
                ..update()
            },
        ] {
            assert!(apply_update(original.clone(), &bad).is_err());
        }
    }

    fn preview(rule: &str, order: Option<AdminPreviewOrder>) -> AdminDiscountPreview {
        preview_rule(&AdminPreviewDiscountRequest {
            rule: rule.to_string(),
            order,
        })
    }

    fn order() -> AdminPreviewOrder {
        AdminPreviewOrder {
            amount: None,
            currency: None,
            intervals: None,
            interval_type: None,
            is_new: None,
            items: None,
            country: None,
            orders: None,
        }
    }

    #[test]
    fn preview_reports_the_clamped_decision() {
        // The default sample order is 100.00 EUR.
        let p = preview("{'percent': 10}", None);
        assert!(p.applies);
        assert_eq!(p.percent, Some(10));
        assert_eq!(p.amount_off, 1_000);
        assert!(p.error.is_none());

        // An over-100% rule is shown as what it will actually do.
        let p = preview("{'percent': 900}", None);
        assert_eq!(p.percent, Some(100));
        assert_eq!(p.amount_off, 10_000);
    }

    #[test]
    fn preview_reports_a_rule_that_declines() {
        let p = preview("order.amount >= 50000 ? {'percent': 10} : {}", None);
        assert!(!p.applies);
        assert_eq!(p.amount_off, 0);
        assert!(p.error.is_none(), "declining is not an error");
    }

    #[test]
    fn preview_reports_the_reason_a_rule_fails() {
        let broken = preview("not cel {{", None);
        assert!(!broken.applies);
        assert!(broken.error.is_some());

        // A non-decision result is a mistake worth showing, not a discount.
        let wrong_type = preview("10", None);
        assert!(!wrong_type.applies);
        assert!(wrong_type.error.unwrap().contains("must return a map"));

        // A cross-currency fixed amount cannot be converted without a payment
        // method; the preview says so rather than inventing a rate.
        let cross = preview("{'amount': 500, 'currency': 'USD'}", None);
        assert!(!cross.applies);
        assert_eq!(cross.amount, Some(500));
        assert!(cross.error.unwrap().contains("does not match"));
    }

    #[test]
    fn preview_honours_the_supplied_sample_order() {
        let p = preview(
            "order.amount >= 50000 ? {'percent': 10} : {}",
            Some(AdminPreviewOrder {
                amount: Some(50_000),
                ..order()
            }),
        );
        assert!(p.applies);
        assert_eq!(p.amount_off, 5_000);

        // Every overridable field reaches the rule.
        let cases = [
            (
                "order.currency == 'USD' ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    currency: Some("usd".to_string()),
                    ..order()
                },
            ),
            (
                "order.intervals == 12 ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    intervals: Some(12),
                    ..order()
                },
            ),
            (
                "order.interval_type == 'year' ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    interval_type: Some("YEAR".to_string()),
                    ..order()
                },
            ),
            (
                "!order.is_new ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    is_new: Some(false),
                    ..order()
                },
            ),
            (
                "order.items.exists(i, i.template_id == 7) ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    items: Some(vec![lnvps_api_common::OrderLineItem {
                        line_item_id: 1,
                        name: "VPS".to_string(),
                        product: lnvps_api_common::OrderProduct::Vm {
                            vm_id: Some(1),
                            template_id: Some(7),
                            region_id: Some(1),
                            cpu: Some(2),
                            memory: Some(4_294_967_296),
                            disk_size: Some(85_899_345_920),
                            disk_type: Some("ssd".to_string()),
                            ip4_count: Some(1),
                            ip6_count: Some(1),
                        },
                    }]),
                    ..order()
                },
            ),
            (
                "order.items.exists(i, i.type == 'app' && i.app_id == 3) ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    items: Some(vec![lnvps_api_common::OrderLineItem {
                        line_item_id: 2,
                        name: "Managed app".to_string(),
                        product: lnvps_api_common::OrderProduct::App {
                            deployment_id: Some(5),
                            app_id: Some(3),
                            cluster_id: Some(1),
                            resource_multiplier: Some(2),
                        },
                    }]),
                    ..order()
                },
            ),
            (
                "user.country == 'DEU' ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    country: Some("DEU".to_string()),
                    ..order()
                },
            ),
            (
                "history.orders == 5 ? {'percent': 1} : {}",
                AdminPreviewOrder {
                    orders: Some(5),
                    ..order()
                },
            ),
        ];
        for (rule, o) in cases {
            assert!(preview(rule, Some(o)).applies, "rule did not apply: {rule}");
        }
    }
}
