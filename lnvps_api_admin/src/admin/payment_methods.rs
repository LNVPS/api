use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminPaymentMethodConfigInfo, CreatePaymentMethodConfigRequest,
    UpdatePaymentMethodConfigRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery,
};
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

    let (page, total) = this
        .db
        .list_payment_method_configs_paginated(limit, offset)
        .await?;

    let configs: Vec<AdminPaymentMethodConfigInfo> = page
        .into_iter()
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
    require_onchain_for_fixedfloat(&this, &config).await?;

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
            return Err(ApiError::bad_request(
                "Payment method config name cannot be empty",
            ));
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
    // processing_fee_base is already in smallest currency units (u64)
    if let Some(base) = request.processing_fee_base {
        config.processing_fee_base = match (base, &config.processing_fee_currency) {
            (Some(amount), Some(_)) => Some(amount),
            (None, _) => None,
            (Some(_), None) => {
                return Err(anyhow::anyhow!(
                    "Processing fee currency is required when processing fee base is set"
                )
                .into());
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

    // Handle currency first so we can validate the min amount against it
    if let Some(currency) = &request.min_amount_currency {
        config.min_amount_currency = currency.as_ref().map(|s| s.trim().to_uppercase());
    }
    if let Some(min) = request.min_amount {
        config.min_amount = match (min, &config.min_amount_currency) {
            (Some(amount), Some(_)) => Some(amount),
            (None, _) => None,
            (Some(_), None) => {
                return Err(anyhow::anyhow!(
                    "Minimum amount currency is required when minimum amount is set"
                )
                .into());
            }
        };
    }

    // Validate that if min amount is set, currency must also be set
    if config.min_amount.is_some() && config.min_amount_currency.is_none() {
        return Err(anyhow::anyhow!(
            "Minimum amount currency is required when minimum amount is set"
        )
        .into());
    }

    // Update supported currencies if provided
    if let Some(currencies) = &request.supported_currencies {
        crate::admin::model::validate_supported_currencies(config.payment_method, currencies)?;
        config.supported_currencies = lnvps_db::CommaSeparated::new(
            currencies.iter().map(|s| s.trim().to_uppercase()).collect(),
        );
    }

    require_onchain_for_fixedfloat(&this, &config).await?;

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

async fn require_onchain_for_fixedfloat(
    this: &RouterState,
    config: &lnvps_db::PaymentMethodConfig,
) -> anyhow::Result<()> {
    if config.payment_method != lnvps_db::PaymentMethod::FixedFloat || !config.enabled {
        return Ok(());
    }
    let onchain = this
        .db
        .get_payment_method_config_for_company(config.company_id, lnvps_db::PaymentMethod::OnChain)
        .await
        .ok()
        .filter(|c| c.enabled);
    anyhow::ensure!(
        onchain.is_some(),
        "FixedFloat pays out to an on-chain address, so the company needs an enabled onchain payment method first"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::Permission;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache,
    };
    use lnvps_db::{
        FixedFloatProviderConfig, LNVpsDb, OnChainAddressType, OnChainProviderConfig,
        PaymentMethod, PaymentMethodConfig, ProviderConfig,
    };
    use std::sync::Arc;

    fn state(db: &Arc<dyn LNVpsDb>) -> RouterState {
        RouterState {
            node_control: None,
            db: db.clone(),
            work_commander: Arc::new(ChannelWorkCommander::new()),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: Arc::new(MockExchangeRate::default()),
            vat: VatClient::new(),
        }
    }

    fn auth() -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: [AdminAction::View, AdminAction::Create, AdminAction::Update]
                .into_iter()
                .map(|action| Permission {
                    resource: AdminResource::PaymentMethodConfig,
                    action,
                })
                .collect(),
            nip98_auth: None,
        }
    }

    fn fixedfloat(enabled: bool) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(
            1,
            PaymentMethod::FixedFloat,
            "FF".to_string(),
            enabled,
            ProviderConfig::FixedFloat(FixedFloatProviderConfig {
                api_key: "k".to_string(),
                api_secret: "s".to_string(),
                url: None,
                refcode: None,
                afftax: None,
            }),
        )
    }

    fn onchain(enabled: bool) -> PaymentMethodConfig {
        PaymentMethodConfig::new_with_config(
            1,
            PaymentMethod::OnChain,
            "OC".to_string(),
            enabled,
            ProviderConfig::OnChain(OnChainProviderConfig {
                url: "https://x:10009".to_string(),
                cert_path: "c".into(),
                macaroon_path: "m".into(),
                address_type: OnChainAddressType::WitnessPubkeyHash,
                account: None,
                min_confirmations: 1,
            }),
        )
    }

    fn create_request(enabled: Option<bool>) -> CreatePaymentMethodConfigRequest {
        CreatePaymentMethodConfigRequest {
            company_id: 1,
            name: "FF".to_string(),
            enabled,
            config: fixedfloat(true).get_provider_config().unwrap(),
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
            supported_currencies: None,
        }
    }

    #[tokio::test]
    async fn guard_ignores_other_methods_and_disabled_fixedfloat() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let this = state(&db);

        assert!(
            require_onchain_for_fixedfloat(&this, &onchain(true))
                .await
                .is_ok()
        );
        assert!(
            require_onchain_for_fixedfloat(&this, &fixedfloat(false))
                .await
                .is_ok()
        );
        assert!(
            require_onchain_for_fixedfloat(&this, &fixedfloat(true))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn guard_needs_an_enabled_onchain_config() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let this = state(&db);

        db.insert_payment_method_config(&onchain(false))
            .await
            .unwrap();
        assert!(
            require_onchain_for_fixedfloat(&this, &fixedfloat(true))
                .await
                .is_err()
        );

        let mut enabled = db
            .get_payment_method_config_for_company(1, PaymentMethod::OnChain)
            .await
            .unwrap();
        enabled.enabled = true;
        db.update_payment_method_config(&enabled).await.unwrap();
        assert!(
            require_onchain_for_fixedfloat(&this, &fixedfloat(true))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn create_fixedfloat_requires_onchain() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let this = state(&db);

        let res =
            admin_create_payment_method(auth(), State(this.clone()), Json(create_request(None)))
                .await;
        assert!(res.is_err());
        assert!(
            db.get_payment_method_config_for_company(1, PaymentMethod::FixedFloat)
                .await
                .is_err()
        );

        db.insert_payment_method_config(&onchain(true))
            .await
            .unwrap();
        let res =
            admin_create_payment_method(auth(), State(this), Json(create_request(None))).await;
        assert!(res.is_ok());
        assert!(
            db.get_payment_method_config_for_company(1, PaymentMethod::FixedFloat)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn create_disabled_fixedfloat_does_not_need_onchain() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let res = admin_create_payment_method(
            auth(),
            State(state(&db)),
            Json(create_request(Some(false))),
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn enabling_fixedfloat_requires_onchain() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let id = db
            .insert_payment_method_config(&fixedfloat(false))
            .await
            .unwrap();
        let enable = || UpdatePaymentMethodConfigRequest {
            name: None,
            enabled: Some(true),
            config: None,
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
            supported_currencies: None,
        };

        let res =
            admin_update_payment_method(auth(), State(state(&db)), Path(id), Json(enable())).await;
        assert!(res.is_err());
        assert!(!db.get_payment_method_config(id).await.unwrap().enabled);

        db.insert_payment_method_config(&onchain(true))
            .await
            .unwrap();
        let res =
            admin_update_payment_method(auth(), State(state(&db)), Path(id), Json(enable())).await;
        assert!(res.is_ok());
        assert!(db.get_payment_method_config(id).await.unwrap().enabled);
    }
}
