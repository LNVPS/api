use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{AdminUserInfo, AdminUserRole, AdminUserUpdateRequest};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use isocountry::CountryCode;
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery, PricingEngine,
};
use lnvps_db::{AdminAction, AdminResource, UserFilters, email_hash};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/users", get(admin_list_users))
        .route(
            "/api/admin/v1/users/by-email",
            get(admin_find_user_by_email),
        )
        .route(
            "/api/admin/v1/users/{id}",
            get(admin_get_user)
                .patch(admin_update_user)
                .delete(admin_delete_user),
        )
        .route("/api/admin/v1/users/{id}/tax", get(admin_get_user_tax))
}

/// Get a specific user's information
async fn admin_get_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminUserInfo> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // Get the user directly from the database
    let user = this.db.get_user(id).await?;

    // Create a basic AdminUserInfo with the user data
    let mut result = AdminUserInfo::from(user);

    // Check if user has admin role
    result.is_admin = this.db.is_admin_user(result.id).await.unwrap_or(false);

    // Get the user's VM count - a simple approach by querying for their VMs
    let vms = this.db.list_user_vms(result.id).await.unwrap_or_default();
    result.vm_count = vms.len() as u64;

    // Number of registered passkeys (WebAuthn credentials)
    result.passkey_count = this
        .db
        .list_webauthn_credentials(result.id)
        .await
        .map(|c| c.len() as u64)
        .unwrap_or(0);

    ApiData::ok(result)
}

/// Permanently delete (purge) a user and all of their associated data.
///
/// Refuses to proceed while the user still has live VMs — those must be deleted
/// first so hypervisor resources are released. Requires the `Delete` permission
/// on the `Users` resource.
async fn admin_delete_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::Users, AdminAction::Delete)?;

    // Ensure the user exists before attempting to purge.
    let user = this.db.get_user(id).await?;

    // Prevent an admin from purging their own account.
    if user.id == auth.user_id {
        return ApiData::err("You cannot delete your own account");
    }

    this.db.delete_user(user.id).await?;

    ApiData::ok(())
}

#[derive(Deserialize)]
struct ListUsersQuery {
    #[serde(flatten)]
    pub page: PageQuery,
    /// Search by exact 64-character hex pubkey
    pub search: Option<String>,
    /// Only users with at least one VM whose host is in this region
    pub region_id: Option<u64>,
    /// Only users with an active assignment to this admin role
    /// (`super_admin`, `admin`, `read_only`)
    pub role: Option<AdminUserRole>,
    /// Filter by whether the user has any VMs
    pub has_vms: Option<bool>,
}

/// List all users with pagination and filtering
async fn admin_list_users(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(query): Query<ListUsersQuery>,
) -> ApiPaginatedResult<AdminUserInfo> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    let limit = query.page.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = query.page.offset.unwrap_or(0);

    // Get users with admin data in a single efficient query
    let filters = UserFilters {
        search_pubkey: query.search.clone(),
        region_id: query.region_id,
        role: query.role.map(|r| r.role_name().to_string()),
        has_vms: query.has_vms,
    };
    let (db_admin_users, total) = this.db.admin_list_users(limit, offset, &filters).await?;

    ApiPaginatedData::ok(
        db_admin_users.into_iter().map(|u| u.into()).collect(),
        total,
        limit,
        offset,
    )
}

#[derive(Deserialize)]
struct FindByEmailQuery {
    email: String,
}

/// Find a single user by their email address using the indexed email_hash column.
async fn admin_find_user_by_email(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(query): Query<FindByEmailQuery>,
) -> ApiResult<AdminUserInfo> {
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    let hash = email_hash(&query.email);
    let user = this.db.admin_find_user_by_email_hash(&hash).await?;

    match user {
        Some(u) => ApiData::ok(u.into()),
        None => Err(ApiError::not_found("User not found")),
    }
}

/// Update user account information
async fn admin_update_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUserUpdateRequest>,
) -> ApiResult<()> {
    // Check permission
    auth.require_permission(AdminResource::Users, AdminAction::Update)?;

    let mut user = this.db.get_user(id).await?;

    // Update user fields if provided
    if let Some(email) = &req.email {
        user.email = email.into();
    }
    if let Some(contact_nip17) = req.contact_nip17 {
        user.contact_nip17 = contact_nip17;
    }
    if let Some(contact_email) = req.contact_email {
        user.contact_email = contact_email;
    }
    if let Some(country_code) = &req.country_code {
        user.country_code = CountryCode::for_alpha3(country_code)
            .ok()
            .map(|c| c.alpha3().to_string());
    }
    if let Some(billing_name) = &req.billing_name {
        user.billing_name = Some(billing_name.clone());
    }
    if let Some(billing_address_1) = &req.billing_address_1 {
        user.billing_address_1 = Some(billing_address_1.clone());
    }
    if let Some(billing_address_2) = &req.billing_address_2 {
        user.billing_address_2 = Some(billing_address_2.clone());
    }
    if let Some(billing_city) = &req.billing_city {
        user.billing_city = Some(billing_city.clone());
    }
    if let Some(billing_state) = &req.billing_state {
        user.billing_state = Some(billing_state.clone());
    }
    if let Some(billing_postcode) = &req.billing_postcode {
        user.billing_postcode = Some(billing_postcode.clone());
    }
    if let Some(billing_tax_id) = &req.billing_tax_id {
        user.billing_tax_id = Some(billing_tax_id.clone());
    }
    // IP-resolved geolocation evidence. Editing either field bumps geo_updated
    // to reflect the manual override time.
    let mut geo_changed = false;
    if let Some(geo_country_code) = &req.geo_country_code {
        user.geo_country_code = if geo_country_code.is_empty() {
            None
        } else {
            Some(
                CountryCode::for_alpha3(geo_country_code)
                    .map_err(|_| ApiError::bad_request("Invalid geo_country_code"))?
                    .alpha3()
                    .to_string(),
            )
        };
        geo_changed = true;
    }
    if let Some(geo_ip) = &req.geo_ip {
        user.geo_ip = if geo_ip.is_empty() {
            None
        } else {
            Some(geo_ip.clone())
        };
        geo_changed = true;
    }
    if geo_changed {
        user.geo_updated = Some(Utc::now());
    }

    // Update user in database
    this.db.update_user(&user).await?;

    // Handle admin role changes if requested
    if let Some(admin_role) = &req.admin_role {
        match admin_role {
            AdminUserRole::SuperAdmin | AdminUserRole::Admin | AdminUserRole::ReadOnly => {
                let role_name = admin_role.role_name();

                // Get the role by name
                if let Ok(role) = this.db.get_role_by_name(role_name).await {
                    // First revoke any existing roles for this user
                    let current_roles = this.db.get_user_roles(user.id).await.unwrap_or_default();
                    for role_id in current_roles {
                        let _ = this.db.revoke_user_role(user.id, role_id).await;
                    }
                    // Assign the new role
                    this.db
                        .assign_user_role(user.id, role.id, auth.user_id)
                        .await?;
                } else {
                    return ApiData::err("Invalid admin role specified");
                }
            }
        }
    }

    // TODO: Log admin action for audit trail
    // audit_log.log_user_update(auth.user_id, id, old_values, new_values).await?;

    ApiData::ok(())
}

/// What a user would be charged by one seller company, and why.
#[derive(Serialize, Debug)]
pub struct AdminUserTaxDetermination {
    pub company_id: u64,
    pub company_name: String,
    /// Seller country (ISO 3166-1 alpha-3), taken from the company's VAT
    /// registration number when it has one and its configured country otherwise.
    /// `null` for a company with neither, which is untaxed by definition.
    pub seller_country: Option<String>,
    /// VAT rate as a whole percentage, e.g. `23.0`.
    pub rate: f32,
    /// `domestic`, `oss_b2c`, `reverse_charge`, `out_of_scope` or
    /// `undetermined_default`. This is the part that explains a 0%: a reverse
    /// charge and a non-EU customer are both zero-rated for different reasons.
    pub treatment: String,
    /// Determined place of supply (ISO alpha-3), if known.
    pub place_of_supply: Option<String>,
    /// The customer VAT number the determination used, if any.
    pub vat_number: Option<String>,
    /// Evidence: the customer's self-declared country.
    pub declared_country: Option<String>,
    /// Evidence: the country resolved from their IP.
    pub geo_country: Option<String>,
}

/// Tax treatment for one user across every seller company.
#[derive(Serialize, Debug)]
pub struct AdminUserTaxInfo {
    /// `false` when the EU rate table has not loaded (no network at startup, or
    /// the feed is down). Every `rate` below is then `0.0` because an unknown
    /// country falls back to zero — which must not be read as "this customer
    /// pays no VAT". Treatments remain correct regardless.
    pub rates_loaded: bool,
    /// One determination per company, ordered by company id. A user can be
    /// taxed differently by each: the seller country is half of the rule.
    pub determinations: Vec<AdminUserTaxDetermination>,
}

/// What tax this user attracts right now, per seller company.
///
/// Computed live from the same code that prices a sale, rather than read back
/// from their last payment: it answers "what would we charge them now", which is
/// the question asked when a customer disputes VAT or has just added a VAT
/// number. What they *were* charged is on the payments themselves.
async fn admin_get_user_tax(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminUserTaxInfo> {
    auth.require_permission(AdminResource::Users, AdminAction::View)?;

    // 404 on an unknown user rather than an empty list, which would read as
    // "this user is taxed nowhere".
    let _user = this.db.get_user(id).await?;

    let pricing = PricingEngine::new(this.db.clone(), this.exchange.clone(), this.vat.clone());

    // Every company, not just the ones they have bought from: the question is
    // what they would be charged, including in a region they have not used yet.
    // Paged rather than asked for in one unbounded read, so the answer stays
    // complete if the company list ever outgrows a page.
    const PAGE: u64 = 100;
    let mut companies = Vec::new();
    loop {
        let (page, total) = this
            .db
            .admin_list_companies(PAGE, companies.len() as u64)
            .await?;
        let empty = page.is_empty();
        companies.extend(page);
        if empty || companies.len() as u64 >= total {
            break;
        }
    }

    let mut determinations = Vec::with_capacity(companies.len());
    for company in companies {
        // `amount` scales only the tax amount, never the rate, so 0 is safe
        // here — this endpoint reports the rate and the reasoning, not a charge.
        let tax = pricing.determine_tax(id, 0, company.id).await?;
        determinations.push(AdminUserTaxDetermination {
            company_id: company.id,
            company_name: company.name,
            seller_country: company.country_code.map(|c| c.to_uppercase()),
            rate: tax.rate,
            treatment: tax.treatment.as_str().to_string(),
            place_of_supply: tax.country_code,
            vat_number: tax.vat_number,
            declared_country: tax.declared_country,
            geo_country: tax.geo_country,
        });
    }

    ApiData::ok(AdminUserTaxInfo {
        rates_loaded: this.vat.rate_count() > 0,
        determinations,
    })
}

#[cfg(test)]
mod tax_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use isocountry::CountryCode;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache,
    };
    use lnvps_db::LNVpsDb;

    use super::*;
    use crate::admin::model::Permission;

    fn rates() -> HashMap<CountryCode, f32> {
        HashMap::from([
            (CountryCode::IRL, 23.0),
            (CountryCode::DEU, 19.0),
            (CountryCode::FRA, 20.0),
        ])
    }

    fn state(db: &Arc<dyn LNVpsDb>, vat: VatClient) -> RouterState {
        RouterState {
            node_control: None,
            db: db.clone(),
            work_commander: Arc::new(ChannelWorkCommander::new()),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: Arc::new(MockExchangeRate::default()),
            vat,
        }
    }

    fn auth() -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: [Permission {
                resource: AdminResource::Users,
                action: AdminAction::View,
            }]
            .into_iter()
            .collect(),
            nip98_auth: None,
        }
    }

    /// A seller established in Ireland, and one customer.
    async fn fixture(declared: Option<&str>, vat_number: Option<&str>) -> (Arc<dyn LNVpsDb>, u64) {
        let mock = MockDb::default();
        {
            let mut companies = mock.companies.lock().await;
            let company = companies.get_mut(&1).unwrap();
            company.country_code = Some("IRL".to_string());
            company.name = "LNVPS IE".to_string();
        }
        let db: Arc<dyn LNVpsDb> = Arc::new(mock);
        let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
        let mut user = db.get_user(user_id).await.unwrap();
        user.country_code = declared.map(str::to_string);
        user.billing_tax_id = vat_number.map(str::to_string);
        db.update_user(&user).await.unwrap();
        (db, user_id)
    }

    /// The ordinary case: an Irish customer of an Irish seller pays Irish VAT.
    #[tokio::test]
    async fn a_domestic_customer_pays_the_seller_country_rate() -> Result<(), ApiError> {
        let (db, user_id) = fixture(Some("IRL"), None).await;

        let got = admin_get_user_tax(
            auth(),
            State(state(&db, VatClient::with_rates(rates()))),
            Path(user_id),
        )
        .await?;

        assert!(got.0.data.rates_loaded);
        let d = &got.0.data.determinations[0];
        assert_eq!(d.rate, 23.0);
        assert_eq!(d.treatment, "domestic");
        assert_eq!(d.place_of_supply.as_deref(), Some("IRL"));
        Ok(())
    }

    /// A German customer with no VAT number is destination-rated under OSS.
    #[tokio::test]
    async fn an_eu_consumer_elsewhere_pays_their_own_rate() -> Result<(), ApiError> {
        let (db, user_id) = fixture(Some("DEU"), None).await;

        let got = admin_get_user_tax(
            auth(),
            State(state(&db, VatClient::with_rates(rates()))),
            Path(user_id),
        )
        .await?;

        let d = &got.0.data.determinations[0];
        assert_eq!(d.rate, 19.0);
        assert_eq!(d.treatment, "oss_b2c");
        Ok(())
    }

    /// The case a bare country rate would get wrong: a German business with a
    /// VAT number pays 0%, and the reason is the treatment, not the country.
    #[tokio::test]
    async fn a_cross_border_vat_number_is_zero_rated_by_reverse_charge() -> Result<(), ApiError> {
        let (db, user_id) = fixture(Some("DEU"), Some("DE123456789")).await;

        let got = admin_get_user_tax(
            auth(),
            State(state(&db, VatClient::with_rates(rates()))),
            Path(user_id),
        )
        .await?;

        let d = &got.0.data.determinations[0];
        assert_eq!(d.rate, 0.0);
        assert_eq!(d.treatment, "reverse_charge");
        assert_eq!(d.vat_number.as_deref(), Some("DE123456789"));
        Ok(())
    }

    /// An empty rate table reports every rate as 0%. Saying so is the whole
    /// point of the flag: otherwise the page shows "0% VAT" for every customer
    /// on the planet and looks like a determination.
    #[tokio::test]
    async fn an_unloaded_rate_table_is_reported_as_such() -> Result<(), ApiError> {
        let (db, user_id) = fixture(Some("IRL"), None).await;

        let got =
            admin_get_user_tax(auth(), State(state(&db, VatClient::new())), Path(user_id)).await?;

        assert!(!got.0.data.rates_loaded);
        assert_eq!(got.0.data.determinations[0].rate, 0.0);
        // The reasoning survives an empty table; only the number is unusable.
        assert_eq!(got.0.data.determinations[0].treatment, "domestic");
        Ok(())
    }

    /// An unknown user is a 404, not a list of zero-rated companies.
    #[tokio::test]
    async fn an_unknown_user_is_not_zero_rated() {
        let (db, _) = fixture(Some("IRL"), None).await;

        assert!(
            admin_get_user_tax(
                auth(),
                State(state(&db, VatClient::with_rates(rates()))),
                Path(9_999),
            )
            .await
            .is_err()
        );
    }

    /// Reading a user's tax treatment is user data and needs the users grant.
    #[tokio::test]
    async fn reading_tax_needs_users_view() {
        let (db, user_id) = fixture(Some("IRL"), None).await;
        let wrong = AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: [Permission {
                resource: AdminResource::Hosts,
                action: AdminAction::View,
            }]
            .into_iter()
            .collect(),
            nip98_auth: None,
        };

        assert!(
            admin_get_user_tax(
                wrong,
                State(state(&db, VatClient::with_rates(rates()))),
                Path(user_id),
            )
            .await
            .is_err()
        );
    }
}
