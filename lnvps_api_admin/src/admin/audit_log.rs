use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use lnvps_api_common::{ApiData, ApiPaginatedData, ApiPaginatedResult, ApiResult};
use lnvps_db::audit::verify_chain;
use lnvps_db::{AdminAction, AdminResource, AuditEntry, AuditFilter};
use serde::{Deserialize, Serialize};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

const DEFAULT_LIMIT: u64 = 50;
const MAX_LIMIT: u64 = 500;
const VERIFY_BATCH: u64 = 1000;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route("/api/admin/v1/audit-log", get(admin_search_audit_log))
        .route(
            "/api/admin/v1/audit-log/verify",
            get(admin_verify_audit_log),
        )
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    actor_type: Option<String>,
    actor_id: Option<u64>,
    action: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<u64>,
    offset: Option<u64>,
}

async fn admin_search_audit_log(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(q): Query<AuditQuery>,
) -> ApiPaginatedResult<AuditEntry> {
    auth.require_permission(AdminResource::Audit, AdminAction::View)?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let filter = AuditFilter {
        actor_type: q.actor_type,
        actor_id: q.actor_id,
        action: q.action,
        target_type: q.target_type,
        target_id: q.target_id,
        since: q.since,
        until: q.until,
    };
    let rows = this.db.list_audit(&filter, limit, offset).await?;
    let total = offset + rows.len() as u64;
    ApiPaginatedData::ok(rows, total, limit, offset)
}

#[derive(Serialize)]
pub struct AuditVerifyResult {
    pub ok: bool,
    pub entries: u64,
    pub head_hash: String,
    pub error: Option<String>,
}

async fn admin_verify_audit_log(
    auth: AdminAuth,
    State(this): State<RouterState>,
) -> ApiResult<AuditVerifyResult> {
    auth.require_permission(AdminResource::Audit, AdminAction::View)?;
    let mut head = None;
    let mut entries = 0;
    loop {
        let after = head
            .as_ref()
            .map(|h: &lnvps_db::audit::ChainHead| h.last_id)
            .unwrap_or(0);
        let batch = this.db.audit_range(after, VERIFY_BATCH).await?;
        if batch.is_empty() {
            break;
        }
        match verify_chain(&batch, head.as_ref()) {
            Ok(h) => {
                entries += batch.len() as u64;
                head = Some(h);
            }
            Err(e) => {
                return ApiData::ok(AuditVerifyResult {
                    ok: false,
                    entries,
                    head_hash: head.map(|h| h.last_hash).unwrap_or_default(),
                    error: Some(e.to_string()),
                });
            }
        }
    }
    ApiData::ok(AuditVerifyResult {
        ok: true,
        entries,
        head_hash: head.map(|h| h.last_hash).unwrap_or_default(),
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::Permission;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache, record_audit,
    };
    use lnvps_db::{LNVpsDb, NewAuditEntry};
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

    fn auth(grant: bool) -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: if grant {
                [Permission {
                    resource: AdminResource::Audit,
                    action: AdminAction::View,
                }]
                .into_iter()
                .collect()
            } else {
                Default::default()
            },
            nip98_auth: None,
            step_up: false,
        }
    }

    #[tokio::test]
    async fn search_requires_audit_view_and_filters() {
        let mock = Arc::new(MockDb::default());
        let db: Arc<dyn LNVpsDb> = mock.clone();
        for a in ["admin.refund", "admin.role.assign"] {
            record_audit(db.as_ref(), NewAuditEntry::new("admin", Some(1), a))
                .await
                .unwrap();
        }
        let denied =
            admin_search_audit_log(auth(false), State(state(&db)), Query(AuditQuery::default()))
                .await;
        assert!(denied.is_err());
        let found = admin_search_audit_log(
            auth(true),
            State(state(&db)),
            Query(AuditQuery {
                action: Some("admin.refund".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(found.0.data.len(), 1);
    }

    #[tokio::test]
    async fn verify_reports_tampering() {
        let mock = Arc::new(MockDb::default());
        let db: Arc<dyn LNVpsDb> = mock.clone();
        for i in 0..3 {
            record_audit(
                db.as_ref(),
                NewAuditEntry::new("admin", Some(1), "admin.refund").target("vm", i),
            )
            .await
            .unwrap();
        }
        let ok = admin_verify_audit_log(auth(true), State(state(&db)))
            .await
            .unwrap();
        assert!(ok.0.data.ok);
        assert_eq!(ok.0.data.entries, 3);

        mock.audit_log.lock().await[1].actor_id = Some(99);
        let bad = admin_verify_audit_log(auth(true), State(state(&db)))
            .await
            .unwrap();
        assert!(!bad.0.data.ok);
        assert!(bad.0.data.error.unwrap().contains("entry 2"));
    }
}
