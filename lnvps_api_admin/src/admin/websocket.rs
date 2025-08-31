use crate::admin::auth::verify_admin_auth_from_token;
use crate::admin::model::WebSocketMessage;
use lnvps_api_common::{JobFeedback, WorkCommander};
use lnvps_db::LNVpsDb;
use log::{debug, error, info, warn};
use rocket::futures::{SinkExt, StreamExt};
use rocket::{get, State};
use ws::{Channel, Message, WebSocket};
use std::sync::Arc;
use tokio::select;

/// WebSocket endpoint for streaming job feedback to admin interfaces
/// Supports both global feedback and specific job feedback via query parameters
#[get("/api/admin/v1/jobs/feedback?<auth>&<job_id>")]
pub fn admin_job_feedback_websocket(
    auth: String,
    job_id: Option<String>,
    db: &State<Arc<dyn LNVpsDb>>,
    work_commander: &State<Option<WorkCommander>>,
    ws: WebSocket,
) -> Channel<'static> {
    let commander = work_commander.inner().clone();
    let db = db.inner().clone();
    
    ws.channel(move |mut stream| {
        Box::pin(async move {
            // Verify admin authentication from query parameter
            let admin_user = match verify_admin_auth_from_token(&auth, &db).await {
                Ok(user) => user,
                Err(e) => {
                    warn!("WebSocket authentication failed: {}", e);
                    let error_msg = WebSocketMessage::Error { error: "Authentication failed".to_string() };
                    if let Ok(json) = serde_json::to_string(&error_msg) {
                        let _ = stream.send(Message::Text(json)).await;
                    }
                    return Ok(());
                }
            };

            let user_id = admin_user.user_id;
            let channel_type = if let Some(ref job_id) = job_id {
                format!("specific job {}", job_id)
            } else {
                "global".to_string()
            };
            
            info!("Admin user {} connected to {} job feedback WebSocket", user_id, channel_type);

            // Check if work commander is available
            let commander = match commander {
                Some(c) => c,
                None => {
                    warn!("Work commander not available for job feedback WebSocket");
                    let error_msg = WebSocketMessage::Error { error: "Job feedback service is not available".to_string() };
                    if let Ok(json) = serde_json::to_string(&error_msg) {
                        let _ = stream.send(Message::Text(json)).await;
                    }
                    return Ok(());
                }
            };

            // Determine which channel to subscribe to
            let channel_name = if let Some(ref job_id) = job_id {
                format!("worker:feedback:{}", job_id)
            } else {
                "worker:feedback".to_string()
            };

            // Subscribe to the appropriate feedback channel
            let mut feedback_stream = match commander.subscribe_channel_message::<JobFeedback>(&channel_name).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Failed to subscribe to {} feedback channel: {}", channel_type, e);
                    let error_msg = WebSocketMessage::Error { 
                        error: format!("Failed to subscribe to job feedback: {}", e) 
                    };
                    if let Ok(json) = serde_json::to_string(&error_msg) {
                        let _ = stream.send(Message::Text(json)).await;
                    }
                    return Ok(());
                }
            };

            // Send initial connection confirmation
            let connection_message = if let Some(ref job_id) = job_id {
                WebSocketMessage::Connected { 
                    message: format!("Connected to job {} feedback stream", job_id) 
                }
            } else {
                WebSocketMessage::Connected { 
                    message: "Job feedback stream connected".to_string() 
                }
            };
            
            if let Ok(json) = serde_json::to_string(&connection_message) {
                if let Err(e) = stream.send(Message::Text(json)).await {
                    warn!("Failed to send connection confirmation: {}", e);
                    return Ok(());
                }
            }

            loop {
                select! {
                    // Handle incoming WebSocket messages
                    ws_msg = stream.next() => {
                        match ws_msg {
                            Some(Ok(Message::Text(text))) => {
                                debug!("Received WebSocket message from admin {} ({}): {}", user_id, channel_type, text);
                                if text.trim() == "ping" {
                                    let pong_msg = WebSocketMessage::Pong;
                                    if let Ok(json) = serde_json::to_string(&pong_msg) {
                                        let _ = stream.send(Message::Text(json)).await;
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
                                let should_send = if let Some(ref target_job_id) = job_id {
                                    feedback.job_id == *target_job_id
                                } else {
                                    // For global monitoring, send all feedback
                                    true
                                };

                                if should_send {
                                    let feedback_msg = WebSocketMessage::JobFeedback { feedback };
                                    match serde_json::to_string(&feedback_msg) {
                                        Ok(json) => {
                                            if let Err(e) = stream.send(Message::Text(json)).await {
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
                                    let _ = stream.send(Message::Text(json)).await;
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

            info!("Job feedback WebSocket closed for admin user {} ({})", user_id, channel_type);
            Ok(())
        })
    })
}