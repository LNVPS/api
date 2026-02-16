use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminPaymentMethodConfigInfo, CreatePaymentMethodConfigRequest,
    UpdatePaymentMethodConfigRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/payment_methods",
            get(admin_list_payment_methods).post(admin_create_payment_method),
        )
        .route(
            "/api/admin/v1/payment_methods/{id}",
            get(admin_get_payment_method)
                .patch(admin_update_payment_method)
                .delete(admin_delete_payment_method),
        )
}

/// List all payment method configurations
async fn admin_list_payment_methods(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminPaymentMethodConfigInfo> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let all_configs = this.db.list_payment_method_configs().await?;
    let total = all_configs.len() as u64;

    let configs: Vec<AdminPaymentMethodConfigInfo> = all_configs
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .map(AdminPaymentMethodConfigInfo::from)
        .collect();

    ApiPaginatedData::ok(configs, total, limit, offset)
}

/// Get a specific payment method configuration
async fn admin_get_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminPaymentMethodConfigInfo> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::View)?;

    let config = this.db.get_payment_method_config(id).await?;

    ApiData::ok(AdminPaymentMethodConfigInfo::from(config))
}

/// Create a new payment method configuration
async fn admin_create_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(request): Json<CreatePaymentMethodConfigRequest>,
) -> ApiResult<AdminPaymentMethodConfigInfo> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::Create)?;

    let config = request.to_payment_method_config()?;

    let config_id = this.db.insert_payment_method_config(&config).await?;

    let created_config = this.db.get_payment_method_config(config_id).await?;

    ApiData::ok(AdminPaymentMethodConfigInfo::from(created_config))
}

/// Update an existing payment method configuration
async fn admin_update_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(request): Json<UpdatePaymentMethodConfigRequest>,
) -> ApiResult<AdminPaymentMethodConfigInfo> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::Update)?;

    let mut config = this.db.get_payment_method_config(id).await?;

    // Update fields if provided
    if let Some(name) = &request.name {
        if name.trim().is_empty() {
            return Err(anyhow::anyhow!("Payment method config name cannot be empty").into());
        }
        config.name = name.trim().to_string();
    }
    if let Some(enabled) = request.enabled {
        config.enabled = enabled;
    }
    if let Some(partial_config) = request.config {
        // Get existing config to merge with
        let existing_config = config
            .get_provider_config()
            .ok_or_else(|| anyhow::anyhow!("Failed to parse existing provider config"))?;

        // Merge partial config with existing
        let merged_config = partial_config.merge_with(&existing_config)?;

        // Update the config
        config.payment_method = merged_config.payment_method();
        config.set_provider_config(merged_config);
    }
    if let Some(rate) = request.processing_fee_rate {
        config.processing_fee_rate = rate;
    }
    // Handle currency first so we can use it for base conversion
    if let Some(currency) = &request.processing_fee_currency {
        config.processing_fee_currency = currency.as_ref().map(|s| s.trim().to_uppercase());
    }
    // Convert processing_fee_base from f32 (human-readable) to u64 (smallest units)
    if let Some(base) = request.processing_fee_base {
        use payments_rs::currency::{Currency, CurrencyAmount};
        use std::str::FromStr;
        
        config.processing_fee_base = match (base, &config.processing_fee_currency) {
            (Some(amount), Some(currency)) => {
                let cur = Currency::from_str(currency)
                    .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency))?;
                Some(CurrencyAmount::from_f32(cur, amount).value())
            }
            (None, _) => None,
            (Some(_), None) => {
                return Err(anyhow::anyhow!(
                    "Processing fee currency is required when processing fee base is set"
                ).into());
            }
        };
    }

    // Validate that if processing fee base is set, currency must also be set
    if config.processing_fee_base.is_some() && config.processing_fee_currency.is_none() {
        return Err(anyhow::anyhow!(
            "Processing fee currency is required when processing fee base is set"
        )
        .into());
    }

    this.db.update_payment_method_config(&config).await?;

    let updated_config = this.db.get_payment_method_config(id).await?;

    ApiData::ok(AdminPaymentMethodConfigInfo::from(updated_config))
}

/// Delete a payment method configuration
async fn admin_delete_payment_method(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<serde_json::Value> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::Delete)?;

    // Verify the config exists
    let _config = this.db.get_payment_method_config(id).await?;

    this.db.delete_payment_method_config(id).await?;

    ApiData::ok(serde_json::json!({
        "success": true,
        "message": "Payment method configuration deleted successfully"
    }))
}
