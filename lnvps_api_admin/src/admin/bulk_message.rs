use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::{BulkMessageRequest, BulkMessageResponse};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiResult, WorkJob};
use log::{error, info};

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/users/bulk-message", post(admin_bulk_message))
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

    // Dispatch work job for async processing
    let job = WorkJob::BulkMessage {
        subject: req.subject.clone(),
        message: req.message.clone(),
        admin_user_id: auth.user_id,
    };

    match state.work_commander.send(job).await {
        Ok(job_id) => {
            info!(
                "Bulk message job dispatched with ID: {} for subject: '{}'",
                job_id,
                req.subject.trim()
            );
            ApiData::ok(BulkMessageResponse {
                job_dispatched: true,
                job_id: Some(job_id),
            })
        }
        Err(e) => {
            error!("Failed to dispatch bulk message job: {}", e);
            ApiData::err("Failed to dispatch message job")
        }
    }
}
