use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{BulkMessageRequest, BulkMessageResponse, BulkMessageUnreachableUser};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiResult, WorkJob};
use lnvps_db::User;
use log::{error, info};
use std::collections::HashMap;

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/users/bulk-message", post(admin_bulk_message))
}

/// Split resolved recipients into those that can be reached and those that
/// cannot, and count how many are reachable on each channel.
fn summarise_recipients(
    users: &[User],
) -> (u64, HashMap<String, u64>, Vec<BulkMessageUnreachableUser>) {
    let mut reachable = 0;
    let mut channel_counts: HashMap<String, u64> = HashMap::new();
    let mut unreachable = Vec::new();
    for user in users {
        let methods = user.contact_methods();
        if methods.is_empty() {
            unreachable.push(BulkMessageUnreachableUser {
                user_id: user.id,
                billing_name: user.billing_name.clone(),
            });
            continue;
        }
        reachable += 1;
        for method in methods {
            *channel_counts.entry(method.to_string()).or_default() += 1;
        }
    }
    (reachable, channel_counts, unreachable)
}

async fn admin_bulk_message(
    auth: AdminAuth,
    State(state): State<RouterState>,
    Json(req): Json<BulkMessageRequest>,
) -> ApiResult<BulkMessageResponse> {
    // Check permission - require admin access to users
    auth.require_permission(
        lnvps_db::AdminResource::Users,
        lnvps_db::AdminAction::Update,
    )?;

    // Validate input
    if req.subject.trim().is_empty() {
        return ApiData::err("Message subject cannot be empty");
    }
    if req.message.trim().is_empty() {
        return ApiData::err("Message body cannot be empty");
    }

    let target = req.target.clone().unwrap_or_default();
    // A target carrying only empty lists would resolve to nobody; that is
    // almost certainly a client bug, so say so rather than dispatching a job
    // that quietly messages no one.
    if target.is_explicitly_empty() {
        return ApiData::err("Bulk message target selects no users");
    }

    // Resolve the recipients up front so the blast radius is reported on every
    // call, not only on a dry run.
    let recipients = match state.db.get_bulk_message_recipients(&target).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to resolve bulk message recipients: {}", e);
            return ApiData::err("Failed to resolve message recipients");
        }
    };
    let (reachable_count, channel_counts, unreachable_users) = summarise_recipients(&recipients);
    let recipient_count = recipients.len() as u64;

    if req.dry_run {
        info!(
            "Bulk message dry run for subject '{}': {} matched, {} reachable",
            req.subject.trim(),
            recipient_count,
            reachable_count
        );
        return ApiData::ok(BulkMessageResponse {
            job_dispatched: false,
            job_id: None,
            recipient_count,
            reachable_count,
            unreachable_users,
            channel_counts,
        });
    }

    // Dispatch work job for async processing
    let job = WorkJob::BulkMessage {
        subject: req.subject.clone(),
        message: req.message.clone(),
        admin_user_id: auth.user_id,
        target: req.target.clone(),
    };

    match state.work_commander.send(job).await {
        Ok(job_id) => {
            info!(
                "Bulk message job dispatched with ID: {} for subject: '{}' ({} recipients, {} reachable)",
                job_id,
                req.subject.trim(),
                recipient_count,
                reachable_count
            );
            ApiData::ok(BulkMessageResponse {
                job_dispatched: true,
                job_id: Some(job_id),
                recipient_count,
                reachable_count,
                unreachable_users,
                channel_counts,
            })
        }
        Err(e) => {
            error!("Failed to dispatch bulk message job: {}", e);
            ApiData::err("Failed to dispatch message job")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::Permission;
    use lnvps_api_common::{
        ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache,
    };
    use lnvps_db::{AdminAction, AdminResource, BulkMessageTarget, LNVpsDb, LNVpsDbBase, Vm};
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
            permissions: [Permission {
                resource: AdminResource::Users,
                action: AdminAction::Update,
            }]
            .into_iter()
            .collect(),
            nip98_auth: None,
        }
    }

    fn req(target: Option<BulkMessageTarget>, dry_run: bool) -> BulkMessageRequest {
        BulkMessageRequest {
            subject: "Storage maintenance".to_string(),
            message: "Your VM will reboot".to_string(),
            target,
            dry_run,
        }
    }

    /// One reachable owner and one owner with no contact method at all, both on
    /// host 1 — the shape of the incident this endpoint exists for.
    async fn fixture() -> (Arc<dyn LNVpsDb>, u64, u64) {
        let mock = MockDb::default();
        let reachable = mock.upsert_user(&[1u8; 32]).await.unwrap();
        let unreachable = mock.upsert_user(&[2u8; 32]).await.unwrap();
        {
            let mut users = mock.users.lock().await;
            let u = users.get_mut(&reachable).unwrap();
            u.contact_email = true;
            u.email = "owner@example.com".into();
            u.billing_name = Some("Owner".to_string());
            // The other user opts into nothing, so nothing can reach them.
            let u = users.get_mut(&unreachable).unwrap();
            u.contact_email = false;
            u.contact_nip17 = false;
        }
        {
            let mut vms = mock.vms.lock().await;
            for (id, user_id) in [(1u64, reachable), (2, unreachable)] {
                vms.insert(
                    id,
                    Vm {
                        id,
                        host_id: 1,
                        user_id,
                        ..Default::default()
                    },
                );
            }
        }
        (Arc::new(mock), reachable, unreachable)
    }

    /// A dry run must report the blast radius — including who cannot be reached
    /// — and send nothing.
    #[tokio::test]
    async fn dry_run_reports_recipients_without_dispatching() {
        let (db, _reachable, unreachable) = fixture().await;
        let res = admin_bulk_message(
            auth(),
            State(state(&db)),
            Json(req(
                Some(BulkMessageTarget {
                    host_ids: Some(vec![1]),
                    ..Default::default()
                }),
                true,
            )),
        )
        .await
        .unwrap();

        assert!(!res.data.job_dispatched);
        assert!(res.data.job_id.is_none());
        assert_eq!(res.data.recipient_count, 2);
        assert_eq!(res.data.reachable_count, 1);
        assert_eq!(res.data.channel_counts.get("email"), Some(&1));
        assert_eq!(res.data.unreachable_users.len(), 1);
        assert_eq!(res.data.unreachable_users[0].user_id, unreachable);
    }

    /// A real send dispatches the job and still reports the resolved recipients.
    #[tokio::test]
    async fn send_dispatches_job_and_reports_recipients() {
        let (db, _, _) = fixture().await;
        let res = admin_bulk_message(auth(), State(state(&db)), Json(req(None, false)))
            .await
            .unwrap();

        assert!(res.data.job_dispatched);
        assert!(res.data.job_id.is_some());
        assert_eq!(res.data.recipient_count, 2);
        assert_eq!(res.data.reachable_count, 1);
        assert_eq!(res.data.unreachable_users.len(), 1);
    }

    /// Empty subject/body and a target that selects nobody are all rejected,
    /// rather than dispatching a job that messages the wrong set (or no one).
    #[tokio::test]
    async fn invalid_requests_are_rejected() {
        let (db, _, _) = fixture().await;

        let mut r = req(None, false);
        r.subject = "  ".to_string();
        assert!(
            admin_bulk_message(auth(), State(state(&db)), Json(r))
                .await
                .is_err()
        );

        let mut r = req(None, false);
        r.message = "".to_string();
        assert!(
            admin_bulk_message(auth(), State(state(&db)), Json(r))
                .await
                .is_err()
        );

        let r = req(
            Some(BulkMessageTarget {
                host_ids: Some(vec![]),
                ..Default::default()
            }),
            false,
        );
        assert!(
            admin_bulk_message(auth(), State(state(&db)), Json(r))
                .await
                .is_err()
        );
    }

    /// The endpoint is gated on `users::update`, not on merely being an admin.
    #[tokio::test]
    async fn requires_users_update_permission() {
        let (db, _, _) = fixture().await;
        let mut viewer = auth();
        viewer.permissions = [Permission {
            resource: AdminResource::Users,
            action: AdminAction::View,
        }]
        .into_iter()
        .collect();
        assert!(
            admin_bulk_message(viewer, State(state(&db)), Json(req(None, true)))
                .await
                .is_err()
        );
    }
}
