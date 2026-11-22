use lnvps_db::audit::is_high_risk;
use lnvps_db::{LNVpsDb, NewAuditEntry};

use crate::{ApiError, ClientInfo};

pub const AUDIT_LOG_TARGET: &str = "lnvps_audit";

pub fn with_client(entry: NewAuditEntry, client: &ClientInfo) -> NewAuditEntry {
    entry.origin(
        client.ip.map(|ip| ip.to_string()),
        client.user_agent.clone(),
    )
}

pub async fn audit_user_action(
    db: &dyn LNVpsDb,
    client: &ClientInfo,
    uid: u64,
    auth_method: &str,
    action: &str,
    target: (&str, impl ToString),
    after: Option<String>,
) -> Result<(), ApiError> {
    record_audit(
        db,
        with_client(
            NewAuditEntry::new("user", Some(uid), action)
                .auth(auth_method, None)
                .target(target.0, target.1)
                .change(None, after),
            client,
        ),
    )
    .await
}

pub async fn record_audit(db: &dyn LNVpsDb, entry: NewAuditEntry) -> Result<(), ApiError> {
    let sealed = db.append_audit(entry).await.map_err(|e| {
        log::error!("audit log write failed, refusing the action: {e}");
        ApiError::internal("audit log unavailable")
    })?;
    match serde_json::to_string(&sealed) {
        Ok(line) => {
            if is_high_risk(&sealed.action) {
                log::warn!(target: AUDIT_LOG_TARGET, "high-risk {line}");
            } else {
                log::info!(target: AUDIT_LOG_TARGET, "{line}");
            }
        }
        Err(e) => log::error!("audit entry not serialisable: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockDb;
    use lnvps_db::audit::verify_chain;
    use lnvps_db::{AuditFilter, LNVpsDbBase};

    #[tokio::test]
    async fn recorded_actions_form_a_verifiable_chain() {
        let db = MockDb::default();
        for i in 0..3 {
            record_audit(
                &db,
                NewAuditEntry::new("admin", Some(1), "admin.refund").target("vm", i),
            )
            .await
            .unwrap();
        }
        let rows = db.audit_range(0, 100).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(verify_chain(&rows, None).unwrap().last_id, 3);
        let found = db
            .list_audit(
                &AuditFilter {
                    target_id: Some("1".into()),
                    ..Default::default()
                },
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
    }
}
