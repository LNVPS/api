use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminCompanyInfo, CreateCompanyRequest, UpdateCompanyRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery};
use lnvps_db::{AdminAction, AdminResource, Company};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/companies",
            get(admin_list_companies).post(admin_create_company),
        )
        .route(
            "/api/admin/v1/companies/{id}",
            get(admin_get_company)
                .patch(admin_update_company)
                .delete(admin_delete_company),
        )
}

/// List all companies with pagination
async fn admin_list_companies(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminCompanyInfo> {
    // Check permission
    auth.require_permission(AdminResource::Company, AdminAction::View)?;

    let limit = params.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = params.offset.unwrap_or(0);

    let (db_companies, total) = this.db.admin_list_companies(limit, offset).await?;

    // Convert to API format with region counts
    let mut companies = Vec::new();
    for company in db_companies {
        let region_count = this
            .db
            .admin_count_company_regions(company.id)
            .await
            .unwrap_or(0);
        let mut admin_company = AdminCompanyInfo::from(company);
        admin_company.region_count = region_count;
        companies.push(admin_company);
    }

    ApiPaginatedData::ok(companies, total, limit, offset)
}

/// Get a specific company by ID
async fn admin_get_company(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminCompanyInfo> {
    // Check permission
    auth.require_permission(AdminResource::Company, AdminAction::View)?;

    let company = this.db.admin_get_company(id).await?;
    let region_count = this.db.admin_count_company_regions(id).await.unwrap_or(0);

    let mut admin_company = AdminCompanyInfo::from(company);
    admin_company.region_count = region_count;

    ApiData::ok(admin_company)
}

/// Create a new company
async fn admin_create_company(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateCompanyRequest>,
) -> ApiResult<AdminCompanyInfo> {
    // Check permission
    auth.require_permission(AdminResource::Company, AdminAction::Create)?;

    // Validate required fields
    if req.name.trim().is_empty() {
        return ApiData::err("Company name is required");
    }

    // Validate base currency if provided, default to EUR
    let base_currency = if let Some(currency) = &req.base_currency {
        let currency = currency.trim().to_uppercase();
        if currency.is_empty() {
            "EUR".to_string()
        } else {
            // Validate currency by parsing it with the Currency enum
            match currency.parse::<payments_rs::currency::Currency>() {
                Ok(_) => {} // Valid currency
                Err(_) => {
                    return ApiData::err(
                        "Invalid currency code. Supported currencies: EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC",
                    );
                }
            }
            currency
        }
    } else {
        "EUR".to_string()
    };

    // Create company object
    let company = Company {
        id: 0, // Will be set by database
        created: Utc::now(),
        name: req.name.trim().to_string(),
        address_1: req
            .address_1
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        address_2: req
            .address_2
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        city: req
            .city
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        state: req
            .state
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        country_code: req
            .country_code
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        tax_id: req
            .tax_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        postcode: req
            .postcode
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        phone: req
            .phone
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        email: req
            .email
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        base_currency,
    };

    let company_id = this.db.admin_create_company(&company).await?;

    // Fetch the created company to return
    let created_company = this.db.admin_get_company(company_id).await?;
    let admin_company = AdminCompanyInfo::from(created_company);

    ApiData::ok(admin_company)
}

/// Update company information
async fn admin_update_company(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<UpdateCompanyRequest>,
) -> ApiResult<AdminCompanyInfo> {
    // Check permission
    auth.require_permission(AdminResource::Company, AdminAction::Update)?;

    let mut company = this.db.admin_get_company(id).await?;

    // Update company fields if provided
    if let Some(name) = &req.name {
        if name.trim().is_empty() {
            return ApiData::err("Company name cannot be empty");
        }
        company.name = name.trim().to_string();
    }
    if let Some(address_1) = &req.address_1 {
        company.address_1 = if address_1.trim().is_empty() {
            None
        } else {
            Some(address_1.trim().to_string())
        };
    }
    if let Some(address_2) = &req.address_2 {
        company.address_2 = if address_2.trim().is_empty() {
            None
        } else {
            Some(address_2.trim().to_string())
        };
    }
    if let Some(city) = &req.city {
        company.city = if city.trim().is_empty() {
            None
        } else {
            Some(city.trim().to_string())
        };
    }
    if let Some(state) = &req.state {
        company.state = if state.trim().is_empty() {
            None
        } else {
            Some(state.trim().to_string())
        };
    }
    if let Some(country_code) = &req.country_code {
        company.country_code = if country_code.trim().is_empty() {
            None
        } else {
            Some(country_code.trim().to_string())
        };
    }
    if let Some(tax_id) = &req.tax_id {
        company.tax_id = if tax_id.trim().is_empty() {
            None
        } else {
            Some(tax_id.trim().to_string())
        };
    }
    if let Some(postcode) = &req.postcode {
        company.postcode = if postcode.trim().is_empty() {
            None
        } else {
            Some(postcode.trim().to_string())
        };
    }
    if let Some(phone) = &req.phone {
        company.phone = if phone.trim().is_empty() {
            None
        } else {
            Some(phone.trim().to_string())
        };
    }
    if let Some(email) = &req.email {
        company.email = if email.trim().is_empty() {
            None
        } else {
            Some(email.trim().to_string())
        };
    }
    if let Some(base_currency) = &req.base_currency {
        let currency = base_currency.trim().to_uppercase();
        if currency.is_empty() {
            return ApiData::err("Base currency cannot be empty");
        } else {
            // Validate currency by parsing it with the Currency enum
            match currency.parse::<payments_rs::currency::Currency>() {
                Ok(_) => {} // Valid currency
                Err(_) => {
                    return ApiData::err(
                        "Invalid currency code. Supported currencies: EUR, USD, GBP, CAD, CHF, AUD, JPY, BTC",
                    );
                }
            }
            company.base_currency = currency;
        }
    }

    // Update company in database
    this.db.admin_update_company(&company).await?;

    // Return updated company
    let region_count = this.db.admin_count_company_regions(id).await.unwrap_or(0);
    let mut admin_company = AdminCompanyInfo::from(company);
    admin_company.region_count = region_count;

    ApiData::ok(admin_company)
}

/// Delete a company
async fn admin_delete_company(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Company, AdminAction::Delete)?;

    // This will fail if there are regions assigned to the company
    this.db.admin_delete_company(id).await?;

    ApiData::ok(())
}
