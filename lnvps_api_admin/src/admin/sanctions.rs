use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, ClientInfo, WorkJob,
};
use lnvps_db::{
    AdminAction, AdminResource, PaymentMethod, PaymentScreening, PaymentScreeningFilter,
    SanctionsField, SanctionsListInfo, SanctionsMatch, SanctionsMatchFilter, SanctionsMatchStatus,
    SanctionsSubject, ScreeningMode,
};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/sanctions/lists", get(admin_list_lists))
        .route(
            "/api/admin/v1/sanctions/lists/refresh",
            post(admin_refresh_lists),
        )
        .route("/api/admin/v1/sanctions/matches", get(admin_list_matches))
        .route("/api/admin/v1/sanctions/matches/{id}", get(admin_get_match))
        .route(
            "/api/admin/v1/sanctions/matches/{id}/clear",
            post(admin_clear_match),
        )
        .route(
            "/api/admin/v1/sanctions/matches/{id}/confirm",
            post(admin_confirm_match),
        )
        .route(
            "/api/admin/v1/sanctions/screenings",
            get(admin_list_screenings),
        )
        .route(
            "/api/admin/v1/sanctions/users/{id}/screen",
            post(admin_screen_user),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MatchQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    open: Option<bool>,
    status: Option<SanctionsMatchStatus>,
    subject: Option<SanctionsSubject>,
    payment_ref: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ScreeningQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    held: Option<bool>,
    payment_id: Option<String>,
}

#[derive(Deserialize)]
struct ResolveRequest {
    reason: String,
}

#[derive(Serialize)]
pub struct AdminSanctionsMatch {
    pub id: u64,
    pub created: DateTime<Utc>,
    pub subject: SanctionsSubject,
    pub user_id: Option<u64>,
    pub payment_ref: Option<String>,
    pub field: SanctionsField,
    pub subject_value: String,
    pub list_source: String,
    pub list_version: String,
    pub list_fetched: Option<DateTime<Utc>>,
    pub entry_id: String,
    pub entry_name: String,
    pub score: f32,
    pub status: SanctionsMatchStatus,
    pub resolved_by: Option<u64>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolution_reason: Option<String>,
}

impl From<SanctionsMatch> for AdminSanctionsMatch {
    fn from(m: SanctionsMatch) -> Self {
        Self {
            id: m.id,
            created: m.created,
            subject: m.subject,
            user_id: m.user_id,
            payment_ref: m.payment_ref,
            field: m.field,
            subject_value: m.subject_value.as_str().to_string(),
            list_source: m.list_source,
            list_version: m.list_version,
            list_fetched: m.list_fetched,
            entry_id: m.entry_id,
            entry_name: m.entry_name,
            score: m.score,
            status: m.status,
            resolved_by: m.resolved_by,
            resolved_at: m.resolved_at,
            resolution_reason: m.resolution_reason,
        }
    }
}

#[derive(Serialize)]
pub struct AdminPaymentScreening {
    pub id: u64,
    pub payment_ref: String,
    pub payment_id: Option<String>,
    pub user_id: Option<u64>,
    pub payment_method: PaymentMethod,
    pub mode: ScreeningMode,
    pub provider: String,
    pub result: Option<serde_json::Value>,
    pub held: bool,
    pub source_addresses: Vec<String>,
    pub amount_msat: Option<u64>,
    pub created: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

impl From<PaymentScreening> for AdminPaymentScreening {
    fn from(s: PaymentScreening) -> Self {
        Self {
            held: s.is_held(),
            id: s.id,
            payment_ref: s.payment_ref,
            payment_id: s.payment_id.map(hex::encode),
            user_id: s.user_id,
            payment_method: s.payment_method,
            mode: s.mode,
            provider: s.provider,
            result: s
                .result
                .map(|r| serde_json::from_str(&r).unwrap_or(serde_json::Value::String(r))),
            source_addresses: s
                .sources
                .map(|v| v.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
            amount_msat: s.amount_msat,
            created: s.created,
            released_at: s.released_at,
        }
    }
}

#[derive(Serialize)]
pub struct AdminSanctionsMatchDetail {
    #[serde(flatten)]
    pub entry: AdminSanctionsMatch,
    pub screening: Option<AdminPaymentScreening>,
    pub orders_held: Option<bool>,
}

#[derive(Serialize)]
pub struct AdminScreenUserResult {
    pub held: bool,
    pub review: bool,
    pub new_matches: Vec<u64>,
}

async fn detail(
    this: &RouterState,
    m: SanctionsMatch,
) -> Result<AdminSanctionsMatchDetail, ApiError> {
    let screening = match (&m.subject, &m.payment_ref) {
        (SanctionsSubject::Payment, Some(r)) => this.db.get_payment_screening(r).await?,
        _ => None,
    };
    let orders_held = match (m.subject, m.user_id) {
        (SanctionsSubject::User, Some(u)) => {
            Some(lnvps_api_common::sanctions::user_orders_held(this.db.as_ref(), u).await?)
        }
        _ => None,
    };
    Ok(AdminSanctionsMatchDetail {
        entry: m.into(),
        screening: screening.map(Into::into),
        orders_held,
    })
}

async fn admin_list_lists(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<SanctionsListInfo>> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::View)?;
    ApiData::ok(this.db.list_sanctions_lists().await?)
}

async fn admin_refresh_lists(
    auth: AdminAuth,
    client: ClientInfo,
    State(this): State<RouterState>,
) -> ApiResult<()> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::Update)?;
    lnvps_api_common::record_audit(
        this.db.as_ref(),
        lnvps_api_common::with_client(
            lnvps_db::NewAuditEntry::new("admin", Some(auth.user_id), "admin.sanctions.refresh")
                .auth("nip98", None),
            &client,
        ),
    )
    .await?;
    this.work_commander
        .send(WorkJob::RefreshSanctionsLists)
        .await?;
    ApiData::ok(())
}

async fn admin_list_matches(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<MatchQuery>,
) -> ApiPaginatedResult<AdminSanctionsMatch> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_sanctions_matches(
            &SanctionsMatchFilter {
                subject: q.subject,
                status: q.status,
                open: q.open,
                user_id: q.user_id,
                payment_ref: q.payment_ref,
            },
            limit,
            offset,
        )
        .await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_get_match(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminSanctionsMatchDetail> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::View)?;
    let m = this.db.get_sanctions_match(id).await?;
    ApiData::ok(detail(&this, m).await?)
}

async fn resolve(
    auth: AdminAuth,
    client: ClientInfo,
    this: RouterState,
    id: u64,
    req: ResolveRequest,
    status: SanctionsMatchStatus,
) -> ApiResult<AdminSanctionsMatchDetail> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::Update)?;
    let reason = req.reason.trim();
    if reason.is_empty() {
        return ApiData::err("reason is required");
    }
    let m = this.db.get_sanctions_match(id).await?;
    if !m.status.is_open() {
        return Err(ApiError::conflict("Match is already resolved"));
    }
    let action = match status {
        SanctionsMatchStatus::Cleared => "admin.sanctions.clear",
        _ => "admin.sanctions.confirm",
    };
    let target = match (m.subject, m.user_id, &m.payment_ref) {
        (SanctionsSubject::Payment, _, Some(p)) => format!("payment {p}"),
        (_, Some(u), _) => format!("user {u}"),
        _ => String::new(),
    };
    lnvps_api_common::record_audit(
        this.db.as_ref(),
        lnvps_api_common::with_client(
            lnvps_db::NewAuditEntry::new("admin", Some(auth.user_id), action)
                .auth("nip98", None)
                .target("sanctions_match", id)
                .change(
                    Some(format!("{:?}", m.status)),
                    Some(format!("{status:?} {target}: {reason}")),
                ),
            &client,
        ),
    )
    .await?;
    if !this
        .db
        .resolve_sanctions_match(id, status, auth.user_id, reason)
        .await?
    {
        return Err(ApiError::conflict("Match is already resolved"));
    }
    log::info!(
        "Admin {} resolved sanctions match {} as {:?} ({}): {}",
        auth.user_id,
        id,
        status,
        target,
        reason
    );
    if let (SanctionsMatchStatus::Cleared, SanctionsSubject::Payment, Some(payment_ref)) =
        (status, m.subject, &m.payment_ref)
        && !lnvps_api_common::sanctions::payment_blocked(this.db.as_ref(), payment_ref).await?
        && this
            .db
            .get_payment_screening(payment_ref)
            .await?
            .is_some_and(|s| s.is_held())
    {
        this.work_commander
            .send(WorkJob::ReleaseHeldDeposit {
                payment_ref: payment_ref.clone(),
            })
            .await?;
    }
    let updated = this.db.get_sanctions_match(id).await?;
    ApiData::ok(detail(&this, updated).await?)
}

async fn admin_clear_match(
    auth: AdminAuth,
    client: ClientInfo,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<ResolveRequest>,
) -> ApiResult<AdminSanctionsMatchDetail> {
    resolve(auth, client, this, id, req, SanctionsMatchStatus::Cleared).await
}

async fn admin_confirm_match(
    auth: AdminAuth,
    client: ClientInfo,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<ResolveRequest>,
) -> ApiResult<AdminSanctionsMatchDetail> {
    resolve(auth, client, this, id, req, SanctionsMatchStatus::Confirmed).await
}

async fn admin_list_screenings(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<ScreeningQuery>,
) -> ApiPaginatedResult<AdminPaymentScreening> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let payment_id = match q.payment_id {
        Some(p) => Some(hex::decode(p).map_err(|_| ApiError::bad_request("Invalid payment_id"))?),
        None => None,
    };
    let (rows, total) = this
        .db
        .list_payment_screenings(
            &PaymentScreeningFilter {
                payment_id,
                user_id: q.user_id,
                held: q.held,
            },
            limit,
            offset,
        )
        .await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_screen_user(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminScreenUserResult> {
    auth.require_permission(AdminResource::Sanctions, AdminAction::Update)?;
    let user = this.db.get_user(id).await?;
    let out = screener(&this).screen_user(&user).await?;
    ApiData::ok(AdminScreenUserResult {
        held: out.held,
        review: out.review,
        new_matches: out.new_matches,
    })
}

pub(crate) fn screener(this: &RouterState) -> lnvps_api_common::sanctions::Screener {
    lnvps_api_common::sanctions::Screener::new(
        this.db.clone(),
        std::sync::Arc::new(lnvps_api_common::sanctions::ListSanctionsProvider::new(
            this.db.clone(),
        )),
    )
    .with_notifier(this.work_commander.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::test_support::{admin, fixture};
    use lnvps_api_common::WorkCommander;
    use lnvps_api_common::sanctions::{encode_entries, fixtures};
    use lnvps_db::{LNVpsDbBase, User};

    async fn load_lists(db: &lnvps_api_common::MockDb) {
        for list in [fixtures::ofac().unwrap(), fixtures::eu().unwrap()] {
            db.insert_sanctions_list(&lnvps_db::SanctionsList {
                source: list.source.clone(),
                version: "fixture".into(),
                sha256: "00".into(),
                entry_count: list.entries.len() as u32,
                entries: encode_entries(&list.entries).unwrap(),
                fetched: Utc::now(),
                checked: Utc::now(),
                ..Default::default()
            })
            .await
            .unwrap();
        }
    }

    fn reviewer() -> AdminAuth {
        admin(
            77,
            &[
                (AdminResource::Sanctions, AdminAction::View),
                (AdminResource::Sanctions, AdminAction::Update),
            ],
        )
    }

    async fn held_deposit(db: &lnvps_api_common::MockDb, payment_ref: &str) -> u64 {
        db.insert_payment_screening(&PaymentScreening {
            payment_ref: payment_ref.into(),
            user_id: Some(1),
            payment_method: PaymentMethod::OnChain,
            mode: ScreeningMode::Screened,
            provider: "official_lists".into(),
            held: true,
            sources: Some(fixtures::OFAC_LISTED_ADDRESS.into()),
            amount_msat: Some(1000),
            ..Default::default()
        })
        .await
        .unwrap();
        db.insert_sanctions_match(&SanctionsMatch {
            subject: SanctionsSubject::Payment,
            user_id: Some(1),
            payment_ref: Some(payment_ref.into()),
            field: SanctionsField::Address,
            subject_value: fixtures::OFAC_LISTED_ADDRESS.into(),
            subject_hash: payment_ref.as_bytes().to_vec(),
            list_source: "ofac_sdn".into(),
            list_version: "fixture".into(),
            entry_id: "90001".into(),
            entry_name: "TESTOV, Ivan Petrovich".into(),
            score: 1.0,
            status: SanctionsMatchStatus::Held,
            ..Default::default()
        })
        .await
        .unwrap()
        .unwrap()
    }

    fn reason(r: &str) -> Json<ResolveRequest> {
        Json(ResolveRequest {
            reason: r.to_string(),
        })
    }

    #[tokio::test]
    async fn clearing_a_payment_hold_queues_one_release_and_is_audited() {
        let f = fixture().await;
        let id = held_deposit(&f.mock, "txid:0").await;

        let out = admin_clear_match(
            reviewer(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(id),
            reason("source is an exchange hot wallet, not the listed party"),
        )
        .await
        .unwrap();
        let m = out.0.data;
        assert_eq!(m.entry.status, SanctionsMatchStatus::Cleared);
        assert_eq!(m.entry.resolved_by, Some(77));
        assert!(m.entry.resolution_reason.unwrap().contains("hot wallet"));
        assert!(m.screening.unwrap().held);
        match f.commander.recv().await.unwrap().first().map(|m| &m.job) {
            Some(WorkJob::ReleaseHeldDeposit { payment_ref }) => assert_eq!(payment_ref, "txid:0"),
            other => panic!("unexpected job {other:?}"),
        }
        assert!(
            f.audit_actions()
                .await
                .contains(&"admin.sanctions.clear".to_string())
        );

        let again = admin_clear_match(
            reviewer(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(id),
            reason("again"),
        )
        .await;
        assert_eq!(again.err().unwrap().code, axum::http::StatusCode::CONFLICT);
        assert_eq!(f.queued_jobs().await, 0);
    }

    #[tokio::test]
    async fn confirming_keeps_the_hold_and_queues_nothing() {
        let f = fixture().await;
        let id = held_deposit(&f.mock, "txid:1").await;
        let out = admin_confirm_match(
            reviewer(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(id),
            reason("confirmed against the SDN entry"),
        )
        .await
        .unwrap();
        assert_eq!(out.0.data.entry.status, SanctionsMatchStatus::Confirmed);
        assert_eq!(f.queued_jobs().await, 0);
        assert!(
            lnvps_api_common::sanctions::payment_blocked(f.state.db.as_ref(), "txid:1")
                .await
                .unwrap()
        );
        assert!(
            f.audit_actions()
                .await
                .contains(&"admin.sanctions.confirm".to_string())
        );
    }

    #[tokio::test]
    async fn a_reason_and_the_permission_are_required() {
        let f = fixture().await;
        let id = held_deposit(&f.mock, "txid:2").await;
        let err = admin_clear_match(
            reviewer(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(id),
            reason("  "),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.code, axum::http::StatusCode::BAD_REQUEST);
        let viewer = admin(78, &[(AdminResource::Sanctions, AdminAction::View)]);
        assert!(
            admin_clear_match(
                viewer,
                ClientInfo::default(),
                State(f.state.clone()),
                Path(id),
                reason("x")
            )
            .await
            .is_err()
        );
        assert_eq!(
            f.mock.get_sanctions_match(id).await.unwrap().status,
            SanctionsMatchStatus::Held
        );
    }

    #[tokio::test]
    async fn a_user_hold_is_listed_and_cleared() {
        let f = fixture().await;
        load_lists(&f.mock).await;
        let mut user: User = f.mock.get_user(f.owner_id).await.unwrap();
        user.billing_name = Some("Fixture Widgets OOO".into());
        user.country_code = Some("BLR".into());
        user.billing_tax_id = Some("BY100000000".into());
        f.mock.update_user(&user).await.unwrap();

        let screened = admin_screen_user(reviewer(), State(f.state.clone()), Path(f.owner_id))
            .await
            .unwrap()
            .0
            .data;
        assert!(screened.held);

        let list = admin_list_matches(
            reviewer(),
            State(f.state.clone()),
            Query(MatchQuery {
                open: Some(true),
                user_id: Some(f.owner_id),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(list.total, 1);
        assert_eq!(list.data[0].field, SanctionsField::Entity);

        let got = admin_get_match(reviewer(), State(f.state.clone()), Path(list.data[0].id))
            .await
            .unwrap()
            .0
            .data;
        assert_eq!(got.orders_held, Some(true));

        let cleared = admin_clear_match(
            reviewer(),
            ClientInfo::default(),
            State(f.state.clone()),
            Path(list.data[0].id),
            reason("verified a sole trader resident in the EU"),
        )
        .await
        .unwrap()
        .0
        .data;
        assert_eq!(cleared.orders_held, Some(false));
        let jobs = f.commander.recv().await.unwrap();
        assert!(
            jobs.iter()
                .all(|m| matches!(m.job, WorkJob::SendAdminNotification { .. }))
        );
        assert_eq!(f.queued_jobs().await, 0);
    }

    #[tokio::test]
    async fn lists_and_screenings_are_readable_and_refresh_is_queued() {
        let f = fixture().await;
        load_lists(&f.mock).await;
        held_deposit(&f.mock, "txid:3").await;
        let lists = admin_list_lists(reviewer(), State(f.state.clone()))
            .await
            .unwrap()
            .0
            .data;
        assert_eq!(lists.len(), 2);
        let held = admin_list_screenings(
            reviewer(),
            State(f.state.clone()),
            Query(ScreeningQuery {
                held: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(held.total, 1);
        assert_eq!(
            held.data[0].source_addresses,
            vec![fixtures::OFAC_LISTED_ADDRESS]
        );
        let _ = admin_refresh_lists(reviewer(), ClientInfo::default(), State(f.state.clone()))
            .await
            .unwrap();
        assert!(matches!(
            f.commander.recv().await.unwrap().first().map(|m| &m.job),
            Some(WorkJob::RefreshSanctionsLists)
        ));
    }
}
