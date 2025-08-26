use crate::admin::auth::AdminAuth;
use crate::admin::model::{BulkMessageRequest, BulkMessageResponse};
use lnvps_api_common::{ApiData, ApiResult, WorkCommander, WorkJob};
use rocket::serde::json::Json;
use rocket::{post, State};
use log::{info, warn, error};

#[post("/api/admin/v1/users/bulk-message", data = "<req>")]
pub async fn admin_bulk_message(
    auth: AdminAuth,
    work_commander: &State<Option<WorkCommander>>,
    req: Json<BulkMessageRequest>,
) -> ApiResult<BulkMessageResponse> {
    // Check permission - require admin access to users
    auth.require_permission(lnvps_db::AdminResource::Users, lnvps_db::AdminAction::Update)?;

    // Validate input
    if req.subject.trim().is_empty() {
        return ApiData::err("Message subject cannot be empty");
    }
    if req.message.trim().is_empty() {
        return ApiData::err("Message body cannot be empty");
    }

    // Dispatch work job for async processing
    match work_commander.inner() {
        Some(commander) => {
            let job = WorkJob::BulkMessage {
                subject: req.subject.clone(),
                message: req.message.clone(),
                admin_user_id: auth.user_id,
            };

            match commander.send_job(job).await {
                Ok(job_id) => {
                    info!("Bulk message job dispatched with ID: {} for subject: '{}'", job_id, req.subject.trim());
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
        None => {
            warn!("WorkCommander not available - cannot process bulk message");
            ApiData::err("Message processing system not available")
        }
    }
}