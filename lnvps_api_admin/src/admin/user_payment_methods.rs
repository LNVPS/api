use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminUpdateUserPaymentMethodRequest, AdminUserPaymentMethodInfo};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, deserialize_from_str_optional,
};
use lnvps_db::{AdminAction, AdminResource};
use serde::Deserialize;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/user_payment_methods",
            get(admin_list_user_payment_methods),
        )
        .route(
            "/api/admin/v1/user_payment_methods/{id}",
            get(admin_get_user_payment_method)
                .patch(admin_update_user_payment_method)
                .delete(admin_delete_user_payment_method),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ListUserPaymentMethodsQuery {
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    offset: Option<u64>,
    /// Optional filter to a single user's payment methods
    #[serde(deserialize_with = "deserialize_from_str_optional")]
    user_id: Option<u64>,
}

/// List saved payment methods across all users (optionally filter by `user_id`)
async fn admin_list_user_payment_methods(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListUserPaymentMethodsQuery>,
) -> ApiPaginatedResult<AdminUserPaymentMethodInfo> {
    auth.require_permission(AdminResource::UserPaymentMethod, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (page, total) = this
        .db
        .admin_list_user_payment_methods_paginated(limit, offset, params.user_id)
        .await?;

    let methods: Vec<AdminUserPaymentMethodInfo> = page
        .into_iter()
        .map(AdminUserPaymentMethodInfo::from)
        .collect();

    ApiPaginatedData::ok(methods, total, limit, offset)
}

/// Get a specific user payment method
async fn admin_get_user_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminUserPaymentMethodInfo> {
    auth.require_permission(AdminResource::UserPaymentMethod, AdminAction::View)?;

    let method = this.db.get_user_payment_method(id).await?;
    ApiData::ok(AdminUserPaymentMethodInfo::from(method))
}

/// Update a user payment method (label / set default / enable-disable)
async fn admin_update_user_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<AdminUpdateUserPaymentMethodRequest>,
) -> ApiResult<AdminUserPaymentMethodInfo> {
    auth.require_permission(AdminResource::UserPaymentMethod, AdminAction::Update)?;

    let mut method = this.db.get_user_payment_method(id).await?;

    if let Some(enabled) = request.enabled {
        method.enabled = enabled;
    }
    if let Some(name) = &request.name {
        method.name = name
            .clone()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty());
    }
    if request.is_default == Some(true) {
        // Only one default per user: clear the flag on the owner's other methods.
        for mut other in this
            .db
            .list_user_payment_methods(method.user_id, None)
            .await?
        {
            if other.id != id && other.is_default {
                other.is_default = false;
                this.db.update_user_payment_method(&other).await?;
            }
        }
        method.is_default = true;
    } else if request.is_default == Some(false) {
        method.is_default = false;
    }

    this.db.update_user_payment_method(&method).await?;
    let updated = this.db.get_user_payment_method(id).await?;
    ApiData::ok(AdminUserPaymentMethodInfo::from(updated))
}

/// Delete a user payment method
async fn admin_delete_user_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::UserPaymentMethod, AdminAction::Delete)?;

    // Verify it exists first for a clean 404 rather than silent success.
    let _ = this.db.get_user_payment_method(id).await?;
    this.db.delete_user_payment_method(id).await?;
    ApiData::ok(())
}
