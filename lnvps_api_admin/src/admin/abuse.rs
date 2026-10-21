use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, WorkJob,
};
use lnvps_db::{
    AbuseAction, AbuseActionKind, AbuseCase, AbuseCaseKind, AbuseChallenge, AbuseChallengeOutcome,
    AdminAction, AdminResource,
};
use serde::{Deserialize, Serialize};

const CHALLENGE_WINDOW_DAYS: u32 = 183;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/abuse/cases",
            get(admin_list_cases).post(admin_create_case),
        )
        .route("/api/admin/v1/abuse/cases/{id}", get(admin_get_case))
        .route(
            "/api/admin/v1/abuse/cases/{id}/actions",
            post(admin_record_action),
        )
        .route(
            "/api/admin/v1/abuse/cases/{id}/close",
            post(admin_close_case),
        )
        .route(
            "/api/admin/v1/abuse/cases/{id}/challenges",
            post(admin_record_challenge),
        )
        .route(
            "/api/admin/v1/abuse/challenges/{id}/decision",
            post(admin_decide_challenge),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CaseQuery {
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    limit: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    offset: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    vm_id: Option<u64>,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    open: Option<bool>,
}

#[derive(Deserialize)]
struct CreateCaseRequest {
    vm_id: Option<u64>,
    #[serde(default)]
    kind: AbuseCaseKind,
    reported_ip: Option<String>,
    incident_at: Option<DateTime<Utc>>,
    reporter_email: Option<String>,
    summary: String,
    #[serde(default)]
    proceedings_started: bool,
}

#[derive(Deserialize)]
struct RecordActionRequest {
    kind: AbuseActionKind,
    reason: String,
    facts: String,
    legal_basis: Option<String>,
    #[serde(default = "default_true")]
    followed_report: bool,
    notice_withheld: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct RecordChallengeRequest {
    action_id: u64,
    message: String,
}

#[derive(Deserialize)]
struct DecideRequest {
    outcome: AbuseChallengeOutcome,
    response: String,
}

#[derive(Serialize)]
pub struct AdminAbuseCase {
    pub id: u64,
    pub vm_id: Option<u64>,
    pub user_id: Option<u64>,
    pub kind: AbuseCaseKind,
    pub reported_ip: Option<String>,
    pub incident_at: Option<DateTime<Utc>>,
    pub reporter_email: Option<String>,
    pub summary: String,
    pub proceedings_started: bool,
    pub created: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub report_count_for_service: u64,
}

#[derive(Serialize)]
pub struct AdminAbuseAction {
    pub id: u64,
    pub kind: AbuseActionKind,
    pub reason: String,
    pub facts: String,
    pub legal_basis: Option<String>,
    pub followed_report: bool,
    pub notice_withheld: Option<String>,
    pub notified_at: Option<DateTime<Utc>>,
    pub admin_user_id: u64,
    pub created: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AdminAbuseChallenge {
    pub id: u64,
    pub action_id: u64,
    pub message: String,
    pub received_at: DateTime<Utc>,
    pub outcome: Option<AbuseChallengeOutcome>,
    pub response: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<u64>,
}

#[derive(Serialize)]
pub struct AdminAbuseCaseDetail {
    #[serde(flatten)]
    pub case: AdminAbuseCase,
    pub actions: Vec<AdminAbuseAction>,
    pub challenges: Vec<AdminAbuseChallenge>,
}

impl AdminAbuseCase {
    fn new(c: AbuseCase, report_count_for_service: u64) -> Self {
        Self {
            id: c.id,
            vm_id: c.vm_id,
            user_id: c.user_id,
            kind: c.kind,
            reported_ip: c.reported_ip,
            incident_at: c.incident_at,
            reporter_email: c.reporter_email,
            summary: c.summary,
            proceedings_started: c.proceedings_started,
            created: c.created,
            closed_at: c.closed_at,
            report_count_for_service,
        }
    }
}

impl From<AbuseAction> for AdminAbuseAction {
    fn from(a: AbuseAction) -> Self {
        Self {
            id: a.id,
            kind: a.kind,
            reason: a.reason,
            facts: a.facts,
            legal_basis: a.legal_basis,
            followed_report: a.followed_report,
            notice_withheld: a.notice_withheld,
            notified_at: a.notified_at,
            admin_user_id: a.admin_user_id,
            created: a.created,
        }
    }
}

impl From<AbuseChallenge> for AdminAbuseChallenge {
    fn from(c: AbuseChallenge) -> Self {
        Self {
            id: c.id,
            action_id: c.action_id,
            message: c.message,
            received_at: c.received_at,
            outcome: c.outcome,
            response: c.response,
            decided_at: c.decided_at,
            decided_by: c.decided_by,
        }
    }
}

pub fn statement_of_reasons(action: &AbuseAction, kind_label: &str) -> String {
    let followed = if action.followed_report {
        "This followed a report we received about your service."
    } else {
        "This did not follow a report. We acted on our own detection."
    };
    let basis = action
        .legal_basis
        .as_deref()
        .unwrap_or("Section 6 of our Terms of Service");
    format!(
        "We have {kind_label}.\n\nWhat the decision was based on:\n{facts}\n\nReason:\n{reason}\n\n{followed}\n\nThe law or section of our Terms involved:\n{basis}\n\nHow to challenge this: reply to this email or write to support@lnvps.net within {days} days of this notice, and a person will review it and reply without undue delay. We will reverse the decision if it was wrong. You also keep any right you have to go to court.\n\nLNVPS, Apex Strata Ltd",
        facts = action.facts,
        reason = action.reason,
        days = CHALLENGE_WINDOW_DAYS,
    )
}

async fn report_count(this: &RouterState, case: &AbuseCase) -> Result<u64, ApiError> {
    let Some(vm_id) = case.vm_id else {
        return Ok(0);
    };
    let (_, total) = this
        .db
        .list_abuse_cases(1, 0, None, Some(vm_id), None)
        .await?;
    Ok(total)
}

async fn admin_create_case(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Json(req): Json<CreateCaseRequest>,
) -> ApiResult<AdminAbuseCase> {
    auth.require_permission(AdminResource::Abuse, AdminAction::Create)?;
    if req.summary.trim().is_empty() {
        return ApiData::err("summary is required");
    }
    let user_id = match req.vm_id {
        Some(vm_id) => Some(this.db.get_vm(vm_id).await?.user_id),
        None => None,
    };
    let case = AbuseCase {
        vm_id: req.vm_id,
        user_id,
        kind: req.kind,
        reported_ip: req.reported_ip,
        incident_at: req.incident_at,
        reporter_email: req.reporter_email,
        summary: req.summary,
        proceedings_started: req.proceedings_started,
        ..Default::default()
    };
    let id = this.db.insert_abuse_case(&case).await?;
    let stored = this.db.get_abuse_case(id).await?;
    if let Some(to) = stored
        .reporter_email
        .clone()
        .filter(|e| !e.trim().is_empty())
    {
        this.work_commander
            .send(WorkJob::SendAbuseReporterEmail {
                to,
                subject: format!("We received your report (case {id})"),
                message: format!(
                    "We received your report and a person will review it. Your reference is {id}.\n\nLNVPS, Apex Strata Ltd"
                ),
            })
            .await
            .map_err(|e| ApiError::new(format!("Recorded, but failed to queue receipt: {e}")))?;
    }
    let count = report_count(&this, &stored).await?;
    ApiData::ok(AdminAbuseCase::new(stored, count))
}

async fn admin_list_cases(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<CaseQuery>,
) -> ApiPaginatedResult<AdminAbuseCase> {
    auth.require_permission(AdminResource::Abuse, AdminAction::View)?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_abuse_cases(limit, offset, q.user_id, q.vm_id, q.open)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for c in rows {
        let count = report_count(&this, &c).await?;
        out.push(AdminAbuseCase::new(c, count));
    }
    ApiPaginatedData::ok(out, total, limit, offset)
}

async fn admin_get_case(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAbuseCaseDetail> {
    auth.require_permission(AdminResource::Abuse, AdminAction::View)?;
    let case = this.db.get_abuse_case(id).await?;
    let count = report_count(&this, &case).await?;
    let actions = this.db.list_abuse_actions(id).await?;
    let challenges = this.db.list_abuse_challenges(id).await?;
    ApiData::ok(AdminAbuseCaseDetail {
        case: AdminAbuseCase::new(case, count),
        actions: actions.into_iter().map(Into::into).collect(),
        challenges: challenges.into_iter().map(Into::into).collect(),
    })
}

async fn admin_record_action(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<RecordActionRequest>,
) -> ApiResult<AdminAbuseAction> {
    auth.require_permission(AdminResource::Abuse, AdminAction::Update)?;
    if req.reason.trim().is_empty() || req.facts.trim().is_empty() {
        return ApiData::err("reason and facts are required");
    }
    let case = this.db.get_abuse_case(id).await?;
    if case.closed_at.is_some() {
        return Err(ApiError::conflict("Case is closed"));
    }
    let action = AbuseAction {
        case_id: id,
        kind: req.kind,
        reason: req.reason,
        facts: req.facts,
        legal_basis: req.legal_basis,
        followed_report: req.followed_report,
        notice_withheld: req.notice_withheld,
        admin_user_id: auth.user_id,
        ..Default::default()
    };
    let action_id = this.db.insert_abuse_action(&action).await?;

    if let Some(vm_id) = case.vm_id
        && (req.kind.disables_service() || req.kind == AbuseActionKind::Reinstated)
    {
        let mut vm = this.db.get_vm(vm_id).await?;
        let disabled = req.kind.disables_service();
        if vm.disabled != disabled {
            vm.disabled = disabled;
            this.db.update_vm(&vm).await?;
            this.work_commander
                .send(WorkJob::ConfigureVm {
                    vm_id,
                    admin_user_id: Some(auth.user_id),
                })
                .await
                .map_err(|e| {
                    ApiError::new(format!("Recorded, but failed to queue VM reconfigure: {e}"))
                })?;
        }
    }

    let stored = AbuseAction {
        id: action_id,
        ..action
    };
    let notify = stored.notice_withheld.is_none() && stored.kind != AbuseActionKind::NoAction;
    if notify && let Some(user_id) = case.user_id {
        this.work_commander
            .send(WorkJob::SendAbuseNotice {
                user_id,
                subject: "Notice about your LNVPS service".to_string(),
                message: statement_of_reasons(&stored, stored.kind.label()),
                action_id: Some(action_id),
            })
            .await
            .map_err(|e| ApiError::new(format!("Recorded, but failed to queue notice: {e}")))?;
    }
    if let Some(to) = case.reporter_email.clone().filter(|e| !e.trim().is_empty())
        && reporter_is_told(case.kind, stored.kind)
    {
        this.work_commander
            .send(WorkJob::SendAbuseReporterEmail {
                to,
                subject: format!("Update on your report (case {id})"),
                message: format!(
                    "Regarding your report (reference {id}): we have {}.\n\nLNVPS, Apex Strata Ltd",
                    stored
                        .kind
                        .label()
                        .replace("your", "the customer's")
                        .replace("you", "the customer")
                ),
            })
            .await
            .map_err(|e| {
                ApiError::new(format!("Recorded, but failed to queue reporter email: {e}"))
            })?;
    }
    ApiData::ok(this.db.get_abuse_action(action_id).await?.into())
}

pub fn reporter_is_told(case: AbuseCaseKind, action: AbuseActionKind) -> bool {
    match case {
        AbuseCaseKind::IllegalContent => action != AbuseActionKind::Reinstated,
        AbuseCaseKind::CopyrightCa => action == AbuseActionKind::Forwarded,
        AbuseCaseKind::Abuse => false,
    }
}

async fn admin_record_challenge(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<RecordChallengeRequest>,
) -> ApiResult<AdminAbuseChallenge> {
    auth.require_permission(AdminResource::Abuse, AdminAction::Create)?;
    if req.message.trim().is_empty() {
        return ApiData::err("message is required");
    }
    let action = this.db.get_abuse_action(req.action_id).await?;
    if action.case_id != id {
        return Err(ApiError::conflict("Action belongs to a different case"));
    }
    let window = chrono::Duration::days(CHALLENGE_WINDOW_DAYS as i64);
    if Utc::now() - action.created > window {
        return Err(ApiError::conflict(
            "The six month window to challenge this decision has passed",
        ));
    }
    let challenge_id = this
        .db
        .insert_abuse_challenge(&AbuseChallenge {
            id: 0,
            case_id: id,
            action_id: req.action_id,
            message: req.message,
            received_at: Utc::now(),
            outcome: None,
            response: None,
            decided_at: None,
            decided_by: None,
        })
        .await?;
    ApiData::ok(this.db.get_abuse_challenge(challenge_id).await?.into())
}

async fn admin_close_case(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAbuseCase> {
    auth.require_permission(AdminResource::Abuse, AdminAction::Update)?;
    this.db.get_abuse_case(id).await?;
    this.db.close_abuse_case(id).await?;
    let case = this.db.get_abuse_case(id).await?;
    let count = report_count(&this, &case).await?;
    ApiData::ok(AdminAbuseCase::new(case, count))
}

async fn admin_decide_challenge(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<DecideRequest>,
) -> ApiResult<AdminAbuseChallenge> {
    auth.require_permission(AdminResource::Abuse, AdminAction::Update)?;
    if req.response.trim().is_empty() {
        return ApiData::err("response is required");
    }
    let challenge = this.db.get_abuse_challenge(id).await?;
    if challenge.outcome.is_some() {
        return Err(ApiError::conflict("Challenge already decided"));
    }
    let case = this.db.get_abuse_case(challenge.case_id).await?;
    this.db
        .decide_abuse_challenge(id, req.outcome, &req.response, auth.user_id)
        .await?;

    if req.outcome == AbuseChallengeOutcome::Reversed
        && let Some(vm_id) = case.vm_id
    {
        let mut vm = this.db.get_vm(vm_id).await?;
        if vm.disabled {
            vm.disabled = false;
            this.db.update_vm(&vm).await?;
            this.work_commander
                .send(WorkJob::ConfigureVm {
                    vm_id,
                    admin_user_id: Some(auth.user_id),
                })
                .await
                .map_err(|e| {
                    ApiError::new(format!("Decided, but failed to queue VM reconfigure: {e}"))
                })?;
        }
    }
    if let Some(user_id) = case.user_id {
        let verdict = match req.outcome {
            AbuseChallengeOutcome::Reversed => "We reversed the decision.",
            AbuseChallengeOutcome::Upheld => "We reviewed it and upheld the decision.",
        };
        this.work_commander
            .send(WorkJob::SendAbuseNotice {
                user_id,
                subject: "Your challenge about your LNVPS service".to_string(),
                message: format!(
                    "We reviewed your challenge. {verdict}\n\n{}\n\nYou keep any right you have to go to court.\n\nLNVPS, Apex Strata Ltd",
                    req.response
                ),
                action_id: None,
            })
            .await
            .map_err(|e| ApiError::new(format!("Decided, but failed to queue notice: {e}")))?;
    }
    ApiData::ok(this.db.get_abuse_challenge(id).await?.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::Permission;
    use lnvps_api_common::WorkCommander;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache,
    };
    use lnvps_db::{LNVpsDb, LNVpsDbBase};
    use std::sync::Arc;

    struct Fixture {
        db: Arc<MockDb>,
        jobs: Arc<ChannelWorkCommander>,
        this: RouterState,
        vm_id: u64,
        user_id: u64,
    }

    async fn fixture() -> Fixture {
        let db = Arc::new(MockDb::default());
        let user_id = db.upsert_user(&[9u8; 32]).await.unwrap();
        let mut vm = MockDb::mock_vm();
        vm.user_id = user_id;
        vm.ssh_key_id = None;
        let vm_id = db.insert_vm(&vm).await.unwrap();
        let jobs = Arc::new(ChannelWorkCommander::new());
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let this = RouterState {
            node_control: None,
            db: dyn_db,
            work_commander: jobs.clone(),
            feedback: None,
            vm_state_cache: VmStateCache::new(),
            exchange: Arc::new(MockExchangeRate::default()),
            vat: VatClient::new(),
        };
        Fixture {
            db,
            jobs,
            this,
            vm_id,
            user_id,
        }
    }

    fn admin(actions: &[AdminAction]) -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: actions
                .iter()
                .map(|a| Permission {
                    resource: AdminResource::Abuse,
                    action: *a,
                })
                .collect(),
            nip98_auth: None,
        }
    }

    fn all() -> AdminAuth {
        admin(&[AdminAction::Create, AdminAction::View, AdminAction::Update])
    }

    async fn drain(jobs: &ChannelWorkCommander) -> Vec<WorkJob> {
        let mut out = Vec::new();
        while let Ok(Ok(msgs)) =
            tokio::time::timeout(std::time::Duration::from_millis(50), jobs.recv()).await
        {
            out.extend(msgs.into_iter().map(|m| m.job));
        }
        out
    }

    async fn open_case(f: &Fixture, reporter: Option<&str>, kind: AbuseCaseKind) -> u64 {
        let Json(rsp) = admin_create_case(
            all(),
            State(f.this.clone()),
            Json(CreateCaseRequest {
                vm_id: Some(f.vm_id),
                kind,
                reported_ip: Some("203.0.113.9".to_string()),
                incident_at: None,
                reporter_email: reporter.map(str::to_string),
                summary: "port scanning".to_string(),
                proceedings_started: false,
            }),
        )
        .await
        .unwrap();
        rsp.data.id
    }

    fn action_request(kind: AbuseActionKind) -> RecordActionRequest {
        RecordActionRequest {
            kind,
            reason: "Active port scan of third parties".to_string(),
            facts: "Scan traffic from the VM address at 10:00 UTC".to_string(),
            legal_basis: None,
            followed_report: true,
            notice_withheld: None,
        }
    }

    #[tokio::test]
    async fn opening_a_case_links_the_customer_and_confirms_receipt() {
        let f = fixture().await;
        let id = open_case(&f, Some("reporter@example.com"), AbuseCaseKind::Abuse).await;
        let case = f.db.get_abuse_case(id).await.unwrap();
        assert_eq!(case.user_id, Some(f.user_id));
        let jobs = drain(&f.jobs).await;
        assert!(matches!(
            &jobs[0],
            WorkJob::SendAbuseReporterEmail { to, .. } if to == "reporter@example.com"
        ));
    }

    #[tokio::test]
    async fn a_case_without_a_reporter_email_sends_no_receipt() {
        let f = fixture().await;
        open_case(&f, None, AbuseCaseKind::Abuse).await;
        assert!(drain(&f.jobs).await.is_empty());
    }

    #[tokio::test]
    async fn a_case_needs_a_summary_and_the_create_permission() {
        let f = fixture().await;
        let empty = admin_create_case(
            all(),
            State(f.this.clone()),
            Json(CreateCaseRequest {
                vm_id: None,
                kind: AbuseCaseKind::Abuse,
                reported_ip: None,
                incident_at: None,
                reporter_email: None,
                summary: "  ".to_string(),
                proceedings_started: false,
            }),
        )
        .await;
        assert!(empty.is_err());
        let denied = admin_create_case(
            admin(&[AdminAction::View]),
            State(f.this.clone()),
            Json(CreateCaseRequest {
                vm_id: None,
                kind: AbuseCaseKind::Abuse,
                reported_ip: None,
                incident_at: None,
                reporter_email: None,
                summary: "x".to_string(),
                proceedings_started: false,
            }),
        )
        .await;
        assert!(denied.is_err());
    }

    #[tokio::test]
    async fn suspending_disables_the_vm_and_sends_a_statement_of_reasons() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(rsp) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await
        .unwrap();
        assert!(f.db.get_vm(f.vm_id).await.unwrap().disabled);
        let jobs = drain(&f.jobs).await;
        assert!(
            jobs.iter()
                .any(|j| matches!(j, WorkJob::ConfigureVm { .. }))
        );
        let notice = jobs
            .iter()
            .find_map(|j| match j {
                WorkJob::SendAbuseNotice {
                    user_id,
                    message,
                    action_id,
                    ..
                } => Some((*user_id, message.clone(), *action_id)),
                _ => None,
            })
            .expect("a notice is queued");
        assert_eq!(notice.0, f.user_id);
        assert_eq!(notice.2, Some(rsp.data.id));
        assert!(notice.1.contains("suspended your service"));
        assert!(notice.1.contains("Active port scan"));
        assert!(notice.1.contains("Scan traffic"));
        assert!(notice.1.contains("followed a report"));
        assert!(notice.1.contains("support@lnvps.net"));
    }

    #[tokio::test]
    async fn restoring_re_enables_the_vm() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        for kind in [AbuseActionKind::Suspended, AbuseActionKind::Reinstated] {
            admin_record_action(
                all(),
                State(f.this.clone()),
                Path(id),
                Json(action_request(kind)),
            )
            .await
            .unwrap();
        }
        assert!(!f.db.get_vm(f.vm_id).await.unwrap().disabled);
    }

    #[tokio::test]
    async fn a_withheld_notice_is_not_sent_and_is_hidden_from_the_customer() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let mut req = action_request(AbuseActionKind::Suspended);
        req.notice_withheld = Some("Criminal investigation".to_string());
        admin_record_action(all(), State(f.this.clone()), Path(id), Json(req))
            .await
            .unwrap();
        let jobs = drain(&f.jobs).await;
        assert!(
            !jobs
                .iter()
                .any(|j| matches!(j, WorkJob::SendAbuseNotice { .. }))
        );
    }

    #[tokio::test]
    async fn recording_no_action_tells_the_customer_nothing() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::NoAction)),
        )
        .await
        .unwrap();
        assert!(!f.db.get_vm(f.vm_id).await.unwrap().disabled);
        assert!(drain(&f.jobs).await.is_empty());
    }

    #[tokio::test]
    async fn a_closed_case_takes_no_more_actions() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(closed) = admin_close_case(all(), State(f.this.clone()), Path(id))
            .await
            .unwrap();
        assert!(closed.data.closed_at.is_some());
        let again = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await;
        assert!(again.is_err());
    }

    #[tokio::test]
    async fn an_action_needs_a_reason_and_facts() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let mut req = action_request(AbuseActionKind::Suspended);
        req.facts = String::new();
        assert!(
            admin_record_action(all(), State(f.this.clone()), Path(id), Json(req))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn repeat_reports_count_against_the_same_service() {
        let f = fixture().await;
        open_case(&f, None, AbuseCaseKind::Abuse).await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(detail) = admin_get_case(all(), State(f.this.clone()), Path(id))
            .await
            .unwrap();
        assert_eq!(detail.data.case.report_count_for_service, 2);
        let Json(page) = admin_list_cases(
            all(),
            State(f.this.clone()),
            Query(CaseQuery {
                vm_id: Some(f.vm_id),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(page.total, 2);
    }

    #[tokio::test]
    async fn a_challenge_inside_the_window_is_recorded_and_reversal_restores_the_vm() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(action) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await
        .unwrap();
        let Json(challenge) = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: "It was a false positive".to_string(),
            }),
        )
        .await
        .unwrap();
        drain(&f.jobs).await;
        let Json(decided) = admin_decide_challenge(
            all(),
            State(f.this.clone()),
            Path(challenge.data.id),
            Json(DecideRequest {
                outcome: AbuseChallengeOutcome::Reversed,
                response: "Confirmed false positive".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(decided.data.outcome, Some(AbuseChallengeOutcome::Reversed));
        assert!(!f.db.get_vm(f.vm_id).await.unwrap().disabled);
        let jobs = drain(&f.jobs).await;
        assert!(jobs.iter().any(|j| matches!(
            j,
            WorkJob::SendAbuseNotice { message, .. } if message.contains("reversed")
        )));
        let again = admin_decide_challenge(
            all(),
            State(f.this.clone()),
            Path(challenge.data.id),
            Json(DecideRequest {
                outcome: AbuseChallengeOutcome::Upheld,
                response: "x".to_string(),
            }),
        )
        .await;
        assert!(again.is_err());
    }

    #[tokio::test]
    async fn an_upheld_challenge_leaves_the_vm_disabled_and_says_so() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(action) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await
        .unwrap();
        let Json(challenge) = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: "please".to_string(),
            }),
        )
        .await
        .unwrap();
        drain(&f.jobs).await;
        admin_decide_challenge(
            all(),
            State(f.this.clone()),
            Path(challenge.data.id),
            Json(DecideRequest {
                outcome: AbuseChallengeOutcome::Upheld,
                response: "The scan logs are clear".to_string(),
            }),
        )
        .await
        .unwrap();
        assert!(f.db.get_vm(f.vm_id).await.unwrap().disabled);
        let jobs = drain(&f.jobs).await;
        assert!(jobs.iter().any(|j| matches!(
            j,
            WorkJob::SendAbuseNotice { message, .. } if message.contains("upheld")
        )));
    }

    #[tokio::test]
    async fn a_challenge_after_six_months_is_refused() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(action) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await
        .unwrap();
        f.db.abuse_actions.lock().await[0].created =
            Utc::now() - chrono::Duration::days(CHALLENGE_WINDOW_DAYS as i64 + 1);
        let late = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: "late".to_string(),
            }),
        )
        .await;
        assert!(late.is_err());
    }

    #[tokio::test]
    async fn a_challenge_must_name_an_action_of_that_case() {
        let f = fixture().await;
        let a = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let b = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(action) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(a),
            Json(action_request(AbuseActionKind::Restricted)),
        )
        .await
        .unwrap();
        let wrong = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(b),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: "x".to_string(),
            }),
        )
        .await;
        assert!(wrong.is_err());
        let blank = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(a),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: " ".to_string(),
            }),
        )
        .await;
        assert!(blank.is_err());
    }

    #[tokio::test]
    async fn deciding_needs_a_response() {
        let f = fixture().await;
        let id = open_case(&f, None, AbuseCaseKind::Abuse).await;
        let Json(action) = admin_record_action(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(action_request(AbuseActionKind::Suspended)),
        )
        .await
        .unwrap();
        let Json(challenge) = admin_record_challenge(
            all(),
            State(f.this.clone()),
            Path(id),
            Json(RecordChallengeRequest {
                action_id: action.data.id,
                message: "m".to_string(),
            }),
        )
        .await
        .unwrap();
        assert!(
            admin_decide_challenge(
                all(),
                State(f.this.clone()),
                Path(challenge.data.id),
                Json(DecideRequest {
                    outcome: AbuseChallengeOutcome::Upheld,
                    response: String::new(),
                }),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_reporter_hears_about_illegal_content_but_not_ordinary_abuse() {
        let f = fixture().await;
        let abuse = open_case(&f, Some("a@example.com"), AbuseCaseKind::Abuse).await;
        let illegal = open_case(&f, Some("b@example.com"), AbuseCaseKind::IllegalContent).await;
        drain(&f.jobs).await;
        for id in [abuse, illegal] {
            admin_record_action(
                all(),
                State(f.this.clone()),
                Path(id),
                Json(action_request(AbuseActionKind::Suspended)),
            )
            .await
            .unwrap();
        }
        let told: Vec<_> = drain(&f.jobs)
            .await
            .into_iter()
            .filter_map(|j| match j {
                WorkJob::SendAbuseReporterEmail { to, .. } => Some(to),
                _ => None,
            })
            .collect();
        assert_eq!(told, vec!["b@example.com".to_string()]);
    }

    #[test]
    fn reporter_is_told_follows_the_terms() {
        use AbuseActionKind::*;
        use AbuseCaseKind::*;
        assert!(reporter_is_told(IllegalContent, Suspended));
        assert!(!reporter_is_told(IllegalContent, Reinstated));
        assert!(reporter_is_told(CopyrightCa, Forwarded));
        assert!(!reporter_is_told(CopyrightCa, Suspended));
        assert!(!reporter_is_told(Abuse, Terminated));
    }

    #[test]
    fn the_statement_of_reasons_names_the_basis_and_whether_a_report_led_to_it() {
        let action = AbuseAction {
            kind: AbuseActionKind::Terminated,
            reason: "Repeated attacks".to_string(),
            facts: "Three confirmed incidents".to_string(),
            legal_basis: Some("Section 6 of the Terms".to_string()),
            followed_report: false,
            ..Default::default()
        };
        let text = statement_of_reasons(&action, action.kind.label());
        assert!(text.contains("terminated your service"));
        assert!(text.contains("Three confirmed incidents"));
        assert!(text.contains("Repeated attacks"));
        assert!(text.contains("Section 6 of the Terms"));
        assert!(text.contains("did not follow a report"));
        let default_basis = statement_of_reasons(&AbuseAction::default(), "x");
        assert!(default_basis.contains("Section 6 of our Terms of Service"));
    }
}
