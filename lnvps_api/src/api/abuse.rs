use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, Nip98Auth, PageQuery,
};
use lnvps_db::{AbuseActionKind, AbuseChallenge, AbuseChallengeOutcome};
use serde::{Deserialize, Serialize};

use crate::api::RouterState;

const CHALLENGE_WINDOW_DAYS: i64 = 183;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/v1/abuse/cases", get(v1_list_abuse_cases))
        .route("/api/v1/abuse/cases/{id}", get(v1_get_abuse_case))
        .route(
            "/api/v1/abuse/cases/{id}/challenges",
            post(v1_challenge_abuse_decision),
        )
}

#[derive(Serialize)]
pub struct ApiAbuseCase {
    pub id: u64,
    pub vm_id: Option<u64>,
    pub summary: String,
    pub created: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ApiAbuseAction {
    pub id: u64,
    pub kind: AbuseActionKind,
    pub reason: String,
    pub facts: String,
    pub legal_basis: Option<String>,
    pub followed_report: bool,
    pub created: DateTime<Utc>,
    pub challenge_until: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ApiAbuseChallenge {
    pub id: u64,
    pub action_id: u64,
    pub message: String,
    pub received_at: DateTime<Utc>,
    pub outcome: Option<AbuseChallengeOutcome>,
    pub response: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ApiAbuseCaseDetail {
    #[serde(flatten)]
    pub case: ApiAbuseCase,
    pub actions: Vec<ApiAbuseAction>,
    pub challenges: Vec<ApiAbuseChallenge>,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    action_id: u64,
    message: String,
}

pub(crate) fn visible_actions(actions: Vec<lnvps_db::AbuseAction>) -> Vec<ApiAbuseAction> {
    actions
        .into_iter()
        .filter(|a| a.notice_withheld.is_none())
        .map(action_view)
        .collect()
}

pub(crate) fn within_challenge_window(action: &lnvps_db::AbuseAction) -> bool {
    Utc::now() - action.created <= chrono::Duration::days(CHALLENGE_WINDOW_DAYS)
}

fn case_view(c: lnvps_db::AbuseCase) -> ApiAbuseCase {
    ApiAbuseCase {
        id: c.id,
        vm_id: c.vm_id,
        summary: c.summary,
        created: c.created,
        closed_at: c.closed_at,
    }
}

fn action_view(a: lnvps_db::AbuseAction) -> ApiAbuseAction {
    ApiAbuseAction {
        id: a.id,
        kind: a.kind,
        reason: a.reason,
        facts: a.facts,
        legal_basis: a.legal_basis,
        followed_report: a.followed_report,
        created: a.created,
        challenge_until: a.created + chrono::Duration::days(CHALLENGE_WINDOW_DAYS),
    }
}

fn challenge_view(c: AbuseChallenge) -> ApiAbuseChallenge {
    ApiAbuseChallenge {
        id: c.id,
        action_id: c.action_id,
        message: c.message,
        received_at: c.received_at,
        outcome: c.outcome,
        response: c.response,
        decided_at: c.decided_at,
    }
}

async fn v1_list_abuse_cases(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Query(q): Query<PageQuery>,
) -> ApiPaginatedResult<ApiAbuseCase> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let limit = q.limit.unwrap_or(50).min(100);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = this
        .db
        .list_abuse_cases(limit, offset, Some(uid), None, None)
        .await?;
    ApiPaginatedData::ok(
        rows.into_iter().map(case_view).collect(),
        total,
        limit,
        offset,
    )
}

async fn owned_case(
    this: &RouterState,
    uid: u64,
    id: u64,
) -> Result<lnvps_db::AbuseCase, ApiError> {
    let case = this
        .db
        .get_abuse_case(id)
        .await
        .map_err(|_| ApiError::not_found("Case not found"))?;
    if case.user_id != Some(uid) {
        return Err(ApiError::not_found("Case not found"));
    }
    Ok(case)
}

async fn v1_get_abuse_case(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiAbuseCaseDetail> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let case = owned_case(&this, uid, id).await?;
    let actions = visible_actions(this.db.list_abuse_actions(id).await?);
    let challenges = this
        .db
        .list_abuse_challenges(id)
        .await?
        .into_iter()
        .map(challenge_view)
        .collect();
    ApiData::ok(ApiAbuseCaseDetail {
        case: case_view(case),
        actions,
        challenges,
    })
}

async fn v1_challenge_abuse_decision(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<ApiAbuseChallenge> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    owned_case(&this, uid, id).await?;
    if req.message.trim().is_empty() {
        return ApiData::err("message is required");
    }
    let action = this
        .db
        .get_abuse_action(req.action_id)
        .await
        .map_err(|_| ApiError::not_found("Decision not found"))?;
    if action.case_id != id || action.notice_withheld.is_some() {
        return Err(ApiError::not_found("Decision not found"));
    }
    if !within_challenge_window(&action) {
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
    ApiData::ok(challenge_view(
        this.db.get_abuse_challenge(challenge_id).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_db::AbuseAction;

    fn action(withheld: Option<&str>, age_days: i64) -> AbuseAction {
        AbuseAction {
            id: 1,
            kind: AbuseActionKind::Suspended,
            created: Utc::now() - chrono::Duration::days(age_days),
            notice_withheld: withheld.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn a_withheld_decision_is_hidden_from_the_customer() {
        let shown = visible_actions(vec![action(None, 0), action(Some("investigation"), 0)]);
        assert_eq!(shown.len(), 1);
    }

    #[test]
    fn the_customer_can_challenge_for_six_months() {
        assert!(within_challenge_window(&action(None, 182)));
        assert!(!within_challenge_window(&action(None, 184)));
    }

    #[test]
    fn the_customer_view_says_until_when_a_decision_can_be_challenged() {
        let a = action(None, 0);
        let created = a.created;
        let view = action_view(a);
        assert_eq!(
            view.challenge_until,
            created + chrono::Duration::days(CHALLENGE_WINDOW_DAYS)
        );
    }

    #[test]
    fn views_carry_only_what_the_customer_is_owed() {
        let case = case_view(lnvps_db::AbuseCase {
            id: 4,
            vm_id: Some(9),
            summary: "scan".to_string(),
            reporter_email: Some("secret@example.com".to_string()),
            reported_ip: Some("203.0.113.1".to_string()),
            ..Default::default()
        });
        let json = serde_json::to_string(&case).unwrap();
        assert!(!json.contains("secret@example.com"));
        assert!(!json.contains("203.0.113.1"));
        let challenge = challenge_view(AbuseChallenge {
            id: 1,
            case_id: 4,
            action_id: 2,
            message: "m".to_string(),
            received_at: Utc::now(),
            outcome: Some(AbuseChallengeOutcome::Upheld),
            response: Some("r".to_string()),
            decided_at: None,
            decided_by: Some(77),
        });
        assert!(
            !serde_json::to_string(&challenge)
                .unwrap()
                .contains("decided_by")
        );
    }
}
