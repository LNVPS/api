use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{
    AdminPaymentMethodConfigInfo, AdminPaymentMethodType, CreatePaymentMethodConfigRequest,
    UpdatePaymentMethodConfigRequest,
};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
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
        .route(
            "/api/admin/v1/payment_methods/{id}/gateway/test",
            post(admin_test_gateway),
        )
        .route(
            "/api/admin/v1/payment_methods/{id}/gateway/status",
            get(admin_gateway_status),
        )
}

fn gateway_row_of(
    config: &lnvps_db::PaymentMethodConfig,
) -> Result<lnvps_db::GatewayProviderConfig, ApiError> {
    config
        .get_provider_config()
        .and_then(|c| c.as_gateway().cloned())
        .ok_or_else(|| ApiError::bad_request("This payment method is not a gateway"))
}

#[derive(serde::Serialize)]
struct GatewayTestResult {
    ok: bool,
    message: String,
}

async fn admin_test_gateway(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<GatewayTestResult> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::View)?;
    let config = this.db.get_payment_method_config(id).await?;
    let gw = gateway_row_of(&config)?;
    let client = lnvps_api_common::GatewayClient::from_parts(&gw.url, &gw.api_key);
    let result = match client.check().await {
        Ok(n) => match client.customer_receipts_enabled().await {
            Ok(false) => GatewayTestResult {
                ok: true,
                message: format!("Connected, the gateway lists {n} payment methods"),
            },
            Ok(true) => GatewayTestResult {
                ok: false,
                message: "The gateway project still emails customer receipts, turn them off in the project settings".to_string(),
            },
            Err(e) => GatewayTestResult {
                ok: false,
                message: format!("Could not read the gateway project settings: {e}"),
            },
        },
        Err(e) => GatewayTestResult {
            ok: false,
            message: format!("Could not reach the gateway: {e}"),
        },
    };
    ApiData::ok(result)
}

#[derive(serde::Serialize)]
struct GatewayStatus {
    enabled: bool,
    handles: Vec<AdminPaymentMethodType>,
    last_paid_webhook_at: Option<chrono::DateTime<chrono::Utc>>,
    payments_last_24h: u64,
}

async fn admin_gateway_status(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<GatewayStatus> {
    auth.require_permission(AdminResource::PaymentMethodConfig, AdminAction::View)?;
    let config = this.db.get_payment_method_config(id).await?;
    let gw = gateway_row_of(&config)?;
    let since = chrono::Utc::now() - chrono::Duration::hours(24);
    let (count, last) = this
        .db
        .gateway_payment_stats(config.company_id, since)
        .await?;
    ApiData::ok(GatewayStatus {
        enabled: config.enabled,
        handles: gw
            .handles
            .iter()
            .copied()
            .map(AdminPaymentMethodType::from)
            .collect(),
        last_paid_webhook_at: last,
        payments_last_24h: count,
    })
}

async fn validate_gateway_row(
    this: &RouterState,
    config: &lnvps_db::PaymentMethodConfig,
) -> anyhow::Result<()> {
    let Some(gw) = config
        .get_provider_config()
        .and_then(|c| c.as_gateway().cloned())
    else {
        return Ok(());
    };
    anyhow::ensure!(!gw.url.trim().is_empty(), "The gateway url is required");
    anyhow::ensure!(
        !gw.api_key.is_empty() && !gw.webhook_secret.is_empty(),
        "The gateway api_key and webhook_secret are required"
    );
    for m in &gw.handles {
        anyhow::ensure!(
            lnvps_db::GATEWAY_HANDLEABLE.contains(m),
            "The gateway cannot handle {m} payments"
        );
    }
    if !config.enabled {
        return Ok(());
    }
    let others = this
        .db
        .list_payment_method_configs_for_company(config.company_id)
        .await?;
    let clash = others
        .iter()
        .any(|c| c.id != config.id && c.enabled && c.provider_type == "gateway");
    anyhow::ensure!(
        !clash,
        "This company already has an enabled gateway payment method, disable it first"
    );
    Ok(())
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
    validate_gateway_row(&this, &config).await?;

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
    validate_gateway_row(&this, &config).await?;

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
            chain: None,
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
            step_up: false,
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
                unpaid_purge_grace_hours: 24,
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

    fn gateway_request(company: u64, enabled: bool) -> CreatePaymentMethodConfigRequest {
        CreatePaymentMethodConfigRequest {
            company_id: company,
            name: "Gateway".to_string(),
            enabled: Some(enabled),
            config: ProviderConfig::Gateway(lnvps_db::GatewayProviderConfig {
                url: "https://pay.example".to_string(),
                api_key: "super-secret-key".to_string(),
                webhook_secret: "super-secret-hook".to_string(),
                tolerance_seconds: 300,
                off_session_renewals: lnvps_db::GatewayOffSession::Off,
                handles: vec![PaymentMethod::Lightning],
            }),
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
            supported_currencies: None,
        }
    }

    #[tokio::test]
    async fn gateway_secrets_are_masked_in_the_admin_response() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let res =
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
                .await
                .unwrap();
        let json = serde_json::to_string(&res.0).unwrap();

        assert!(!json.contains("super-secret-key"));
        assert!(!json.contains("super-secret-hook"));
        assert!(json.contains("\"has_api_key\":true"));
        assert!(json.contains("\"has_webhook_secret\":true"));
        assert!(json.contains("\"type\":\"gateway\""));

        let id = res.0.data.id;
        let got = admin_get_payment_method(auth(), State(state(&db)), Path(id))
            .await
            .unwrap();
        let json = serde_json::to_string(&got.0).unwrap();
        assert!(!json.contains("super-secret"));
    }

    #[tokio::test]
    async fn a_second_enabled_gateway_row_for_a_company_is_refused() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
            .await
            .unwrap();

        let second =
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
                .await;

        assert!(second.is_err());
        let rows = db.list_payment_method_configs_for_company(1).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn a_second_gateway_row_is_allowed_when_disabled_or_for_another_company() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
            .await
            .unwrap();

        assert!(
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, false)))
                .await
                .is_ok()
        );
        assert!(
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(2, true)))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn enabling_a_second_gateway_row_is_refused() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
            .await
            .unwrap();
        let spare =
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, false)))
                .await
                .unwrap()
                .0
                .data
                .id;
        let enable = UpdatePaymentMethodConfigRequest {
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
            admin_update_payment_method(auth(), State(state(&db)), Path(spare), Json(enable)).await;

        assert!(res.is_err());
        assert!(!db.get_payment_method_config(spare).await.unwrap().enabled);
    }

    #[tokio::test]
    async fn gateway_handles_outside_the_supported_set_are_refused() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mut req = gateway_request(1, false);
        if let ProviderConfig::Gateway(g) = &mut req.config {
            g.handles = vec![PaymentMethod::Paypal];
        }

        let res = admin_create_payment_method(auth(), State(state(&db)), Json(req)).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn patching_a_gateway_row_keeps_its_secrets() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let id =
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, false)))
                .await
                .unwrap()
                .0
                .data
                .id;
        let patch: UpdatePaymentMethodConfigRequest = serde_json::from_value(serde_json::json!({
            "config": {"type": "gateway", "handles": ["lightning", "onchain"]}
        }))
        .unwrap();

        admin_update_payment_method(auth(), State(state(&db)), Path(id), Json(patch))
            .await
            .unwrap();

        let stored = db.get_payment_method_config(id).await.unwrap();
        let gw = stored.get_provider_config().unwrap();
        let gw = gw.as_gateway().unwrap();
        assert_eq!(gw.api_key, "super-secret-key");
        assert_eq!(
            gw.handles,
            vec![PaymentMethod::Lightning, PaymentMethod::OnChain]
        );
    }

    #[tokio::test]
    async fn gateway_status_counts_only_this_companys_gateway_payments() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let id =
            admin_create_payment_method(auth(), State(state(&db)), Json(gateway_request(1, true)))
                .await
                .unwrap()
                .0
                .data
                .id;

        let status = admin_gateway_status(auth(), State(state(&db)), Path(id))
            .await
            .unwrap()
            .0
            .data;

        assert!(status.enabled);
        assert_eq!(status.payments_last_24h, 0);
        assert!(status.last_paid_webhook_at.is_none());
        assert_eq!(status.handles.len(), 1);
    }

    #[tokio::test]
    async fn gateway_test_rejects_a_non_gateway_row() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let id = db
            .insert_payment_method_config(&onchain(true))
            .await
            .unwrap();

        let res = admin_test_gateway(auth(), State(state(&db)), Path(id)).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn gateway_test_reports_an_unreachable_gateway_clearly() {
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mut req = gateway_request(1, false);
        if let ProviderConfig::Gateway(g) = &mut req.config {
            g.url = "http://127.0.0.1:1".to_string();
        }
        let id = admin_create_payment_method(auth(), State(state(&db)), Json(req))
            .await
            .unwrap()
            .0
            .data
            .id;

        let res = admin_test_gateway(auth(), State(state(&db)), Path(id))
            .await
            .unwrap()
            .0
            .data;

        assert!(!res.ok);
        assert!(res.message.starts_with("Could not reach the gateway"));
    }

    async fn test_against_project(receipts: bool) -> GatewayTestResult {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/methods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"id": 1, "name": "lnvps", "customer_receipts": receipts}),
            ))
            .mount(&server)
            .await;
        let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
        let mut req = gateway_request(1, false);
        if let ProviderConfig::Gateway(g) = &mut req.config {
            g.url = server.uri();
        }
        let id = admin_create_payment_method(auth(), State(state(&db)), Json(req))
            .await
            .unwrap()
            .0
            .data
            .id;
        admin_test_gateway(auth(), State(state(&db)), Path(id))
            .await
            .unwrap()
            .0
            .data
    }

    #[tokio::test]
    async fn gateway_test_fails_while_the_project_emails_customers() {
        let res = test_against_project(true).await;
        assert!(!res.ok);
        assert!(res.message.contains("customer receipts"));
    }

    #[tokio::test]
    async fn gateway_test_passes_when_customer_receipts_are_off() {
        let res = test_against_project(false).await;
        assert!(res.ok, "{}", res.message);
    }
}
