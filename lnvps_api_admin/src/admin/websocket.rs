use crate::admin::RouterState;
use crate::admin::auth::{AdminAuth, AdminAuthQuery};
use crate::admin::model::WebSocketMessage;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use futures::{SinkExt, StreamExt};
use lnvps_api_common::{
    ApiData, ApiError, ApiResult, DEFAULT_TICKET_TTL_SECS, WorkFeedback, issue_ticket,
};
use lnvps_db::{AdminAction, AdminResource};
use log::{debug, error, info, warn};
use serde::Deserialize;
use tokio::select;

/// Path the websocket auth event / ticket must be bound to.
pub(crate) const FEEDBACK_PATH: &str = "/api/admin/v1/jobs/feedback";

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(FEEDBACK_PATH, get(admin_job_feedback_websocket))
        .route("/api/admin/v1/auth/ticket", post(admin_issue_auth_ticket))
}

/// Request body for minting an admin websocket ticket.
#[derive(Deserialize)]
struct AdminTicketRequest {
    /// Exact path the ticket should be valid for.
    path: String,
}

/// Response carrying a freshly minted ticket.
#[derive(serde::Serialize)]
struct AdminTicketResponse {
    ticket: String,
    expires_in: u64,
}

/// Mint a short-lived, single-use ticket for the job-feedback websocket.
///
/// The caller authenticates normally (header-borne NIP-98) and must already
/// hold the permission the target endpoint requires, so a ticket is never a way
/// to widen access — only a way to carry existing access through a handshake
/// that cannot take an `Authorization` header.
async fn admin_issue_auth_ticket(
    auth: AdminAuth,
    State(_this): State<RouterState>,
    axum::Json(req): axum::Json<AdminTicketRequest>,
) -> ApiResult<AdminTicketResponse> {
    if req.path != FEEDBACK_PATH {
        return Err(ApiError::new("Tickets cannot be issued for that path"));
    }
    auth.require_permission(AdminResource::VirtualMachines, AdminAction::View)?;

    let pubkey: [u8; 32] = auth
        .pubkey
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::internal("Invalid stored pubkey"))?;

    let ticket = issue_ticket(&pubkey, &req.path, DEFAULT_TICKET_TTL_SECS)
        .map_err(|e| ApiError::internal(format!("Failed to issue ticket: {}", e)))?;

    ApiData::ok(AdminTicketResponse {
        ticket,
        expires_in: DEFAULT_TICKET_TTL_SECS,
    })
}

#[derive(Deserialize)]
struct WebSocketQuery {
    #[serde(flatten)]
    auth: AdminAuthQuery,
    job_id: Option<String>,
}

/// WebSocket endpoint for streaming job feedback to admin interfaces
/// Supports both global feedback and specific job feedback via query parameters
async fn admin_job_feedback_websocket(
    ws: WebSocketUpgrade,
    State(this): State<RouterState>,
    Query(params): Query<WebSocketQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, this, params))
}

async fn handle_socket(socket: WebSocket, this: RouterState, params: WebSocketQuery) {
    let (mut sender, mut receiver) = socket.split();

    // Resolve the caller from the query-string credential. The path is passed
    // so a ticket is bound to this endpoint, and so a legacy NIP-98 event has
    // its signature actually verified against it — previously the event was
    // only *parsed*, which authenticated any hand-crafted JSON.
    let admin_user = match params.auth.resolve(FEEDBACK_PATH, &this.db).await {
        Ok(user) => user,
        Err(e) => {
            warn!("WebSocket authentication failed: {}", e);
            let error_msg = WebSocketMessage::Error {
                error: "Authentication failed".to_string(),
            };
            if let Ok(json) = serde_json::to_string(&error_msg) {
                let _ = sender.send(Message::Text(json.into())).await;
            }
            return;
        }
    };

    // Authentication only proves *who* is connecting. The feedback bus carries
    // provisioning detail for every VM on the platform, so it needs an explicit
    // permission gate like every other admin endpoint.
    if let Err(e) = admin_user.require_permission(AdminResource::VirtualMachines, AdminAction::View)
    {
        warn!(
            "WebSocket authorization failed for user {}: {}",
            admin_user.user_id, e.error
        );
        let error_msg = WebSocketMessage::Error {
            error: "Insufficient permissions".to_string(),
        };
        if let Ok(json) = serde_json::to_string(&error_msg) {
            let _ = sender.send(Message::Text(json.into())).await;
        }
        return;
    }

    let user_id = admin_user.user_id;
    let channel_type = if let Some(ref job_id) = params.job_id {
        format!("specific job {}", job_id)
    } else {
        "global".to_string()
    };

    info!(
        "Admin user {} connected to {} job feedback WebSocket",
        user_id, channel_type
    );

    // Check if work feedback is available
    let feedback = match &this.feedback {
        Some(c) => c.clone(),
        None => {
            warn!("Redis feedback not available!");
            let error_msg = WebSocketMessage::Error {
                error: "Job feedback service is not available".to_string(),
            };
            if let Ok(json) = serde_json::to_string(&error_msg) {
                let _ = sender.send(Message::Text(json.into())).await;
            }
            return;
        }
    };

    // Determine which channel to subscribe to
    let channel_name = if let Some(ref job_id) = params.job_id {
        format!("worker:feedback:{}", job_id)
    } else {
        "worker:feedback".to_string()
    };

    // Subscribe to the appropriate feedback channel
    let mut feedback_stream = match feedback.subscribe(&channel_name).await {
        Ok(stream) => stream,
        Err(e) => {
            error!(
                "Failed to subscribe to {} feedback channel: {}",
                channel_type, e
            );
            let error_msg = WebSocketMessage::Error {
                error: format!("Failed to subscribe to job feedback: {}", e),
            };
            if let Ok(json) = serde_json::to_string(&error_msg) {
                let _ = sender.send(Message::Text(json.into())).await;
            }
            return;
        }
    };

    // Send initial connection confirmation
    let connection_message = if let Some(ref job_id) = params.job_id {
        WebSocketMessage::Connected {
            message: format!("Connected to job {} feedback stream", job_id),
        }
    } else {
        WebSocketMessage::Connected {
            message: "Job feedback stream connected".to_string(),
        }
    };

    if let Ok(json) = serde_json::to_string(&connection_message)
        && let Err(e) = sender.send(Message::Text(json.into())).await
    {
        warn!("Failed to send connection confirmation: {}", e);
        return;
    }

    loop {
        select! {
            // Handle incoming WebSocket messages
            ws_msg = receiver.next() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Received WebSocket message from admin {} ({}): {}", user_id, channel_type, text);
                        if text.trim() == "ping" {
                            let pong_msg = WebSocketMessage::Pong;
                            if let Ok(json) = serde_json::to_string(&pong_msg) {
                                let _ = sender.send(Message::Text(json.into())).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("Admin user {} disconnected from {} job feedback WebSocket", user_id, channel_type);
                        break;
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket error for admin user {} ({}): {}", user_id, channel_type, e);
                        break;
                    }
                    None => {
                        debug!("WebSocket stream ended for admin user {} ({})", user_id, channel_type);
                        break;
                    }
                    _ => {
                        // Ignore other message types
                    }
                }
            }

            // Forward job feedback messages to WebSocket
            feedback_msg = feedback_stream.next() => {
                match feedback_msg {
                    Some(Ok(feedback)) => {
                        // For specific job monitoring, only send feedback for that job
                        let should_send = if let Some(ref target_job_id) = params.job_id {
                            feedback.job_id == *target_job_id
                        } else {
                            // For global monitoring, send all feedback
                            true
                        };

                        if should_send {
                            let feedback_msg = WebSocketMessage::JobFeedback { feedback };
                            match serde_json::to_string(&feedback_msg) {
                                Ok(json) => {
                                    if let Err(e) = sender.send(Message::Text(json.into())).await {
                                        warn!("Failed to send job feedback to admin user {}: {}", user_id, e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to serialize job feedback: {}", e);
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error receiving job feedback ({}): {}", channel_type, e);
                        let error_msg = WebSocketMessage::Error {
                            error: format!("Job feedback stream error: {}", e)
                        };
                        if let Ok(json) = serde_json::to_string(&error_msg) {
                            let _ = sender.send(Message::Text(json.into())).await;
                        }
                        break;
                    }
                    None => {
                        info!("Job feedback stream ended for admin user {} ({})", user_id, channel_type);
                        break;
                    }
                }
            }
        }
    }

    info!(
        "Job feedback WebSocket closed for admin user {} ({})",
        user_id, channel_type
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `axum::extract::Query` deserialises through `serde_urlencoded`, which is
    /// fussy about `#[serde(flatten)]`. Pin the behaviour so a credential is
    /// never silently dropped (which would surface as a confusing auth failure,
    /// or worse, as an empty `AdminAuthQuery` being treated as absent).
    #[test]
    fn websocket_query_parses_ticket_and_job_id() {
        let q: WebSocketQuery = serde_urlencoded::from_str("ticket=abc&job_id=job-1").unwrap();
        assert_eq!(q.auth.ticket.as_deref(), Some("abc"));
        assert_eq!(q.auth.auth, None);
        assert_eq!(q.job_id.as_deref(), Some("job-1"));
    }

    /// The legacy `auth` form must keep parsing during the client migration.
    #[test]
    fn websocket_query_parses_legacy_auth() {
        // The value is the base64 event itself; only the URL escaping of `=` is
        // undone here.
        let q: WebSocketQuery = serde_urlencoded::from_str("auth=ZXZlbnQ%3D").unwrap();
        assert_eq!(q.auth.auth.as_deref(), Some("ZXZlbnQ="));
        assert_eq!(q.auth.ticket, None);
        assert_eq!(q.job_id, None);
    }

    /// Neither credential present must parse (and then be refused at resolve
    /// time) rather than failing to deserialise.
    #[test]
    fn websocket_query_parses_with_no_credential() {
        let q: WebSocketQuery = serde_urlencoded::from_str("job_id=x").unwrap();
        assert_eq!(q.auth.auth, None);
        assert_eq!(q.auth.ticket, None);
    }
}
