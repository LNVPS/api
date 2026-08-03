//! Live-chat support agent served over a WebSocket.
//!
//! One [`ChatSession`] per connection, so a slow model response for one customer
//! never blocks another. The agent runs in-process against the database, so no
//! loopback HTTP call and no admin credential is involved.
//!
//! # Protocol
//!
//! The client authenticates with a NIP-98 event in the `auth` query parameter,
//! exactly as the VM console endpoint does, then sends **plain text frames** —
//! one per message. The server replies with newline-free JSON frames, each a
//! serialized [`ChatEvent`]:
//!
//! ```text
//! {"type":"token","text":"Your VM "}
//! {"type":"tool_start","name":"list_my_vms"}
//! {"type":"tool_done","name":"list_my_vms"}
//! {"type":"final","text":"Your VM is running."}
//! ```
//!
//! Every message yields exactly one terminal frame (`final` or `error`).

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures::StreamExt;
use log::{error, info, warn};

use lnvps_agent::agent::{DbToolExecutor, SupportAgent, ToolExecutor};
use lnvps_agent::conversation::DbConversationStore;
use lnvps_agent::identity::{Requester, SenderIdentity};
use lnvps_agent::session::{ChatEvent, ChatSession};
use lnvps_api_common::Nip98Auth;
use lnvps_db::{AdminAction, AdminDb, AdminResource, LNVpsDb};

use crate::api::RouterState;

/// Whether `user_id` may see the agent's internal tool activity.
///
/// Gated on `users:view` — the same permission the admin API requires to look
/// at another customer's account. Tool names reveal how support tooling is
/// built and which internal lookups a question triggered, so ordinary customers
/// get only the reply text.
///
/// Fails closed: any error resolving permissions hides the detail.
async fn may_view_tool_activity(db: &Arc<dyn LNVpsDb>, user_id: u64) -> bool {
    match db.get_user_permissions(user_id).await {
        Ok(permissions) => {
            permissions.contains(&(AdminResource::Users as u16, AdminAction::View as u16))
        }
        Err(e) => {
            warn!("Failed to load permissions for user {}: {}", user_id, e);
            false
        }
    }
}

/// Path the NIP-98 auth event must be signed against.
pub(crate) const CHAT_PATH: &str = "/api/v1/support/chat";

/// Serialize an event as a JSON text frame.
fn frame(event: &ChatEvent) -> Message {
    // The enum is a plain tagged struct; serialization cannot realistically
    // fail, but a panic here would take down the connection.
    match serde_json::to_string(event) {
        Ok(json) => Message::Text(json.into()),
        Err(e) => {
            error!("Failed to serialize chat event: {}", e);
            Message::Text(
                r#"{"type":"error","message":"internal serialization error"}"#
                    .to_string()
                    .into(),
            )
        }
    }
}

/// Send a terminal error frame and finish.
async fn send_error(ws: &mut WebSocket, message: &str) {
    let _ = ws
        .send(frame(&ChatEvent::Error {
            message: message.to_string(),
        }))
        .await;
}

/// Handle one live-chat websocket connection.
pub(crate) async fn v1_support_chat(
    auth: crate::api::AuthQuery,
    this: RouterState,
    mut ws: WebSocket,
) {
    let Some(config) = this.settings.agent.clone() else {
        send_error(&mut ws, "The support agent is not enabled on this server").await;
        return;
    };

    // Authenticate exactly like the console endpoint: a single-use ticket (or,
    // for older clients, a NIP-98 event signed over this path) passed as a query
    // parameter, because browsers cannot set headers on a WebSocket handshake.
    let pubkey = match auth.resolve(CHAT_PATH) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            send_error(&mut ws, e).await;
            return;
        }
    };
    let uid = match this.db.upsert_user(&pubkey).await {
        Ok(uid) => uid,
        Err(e) => {
            error!("Support chat: failed to resolve user: {}", e);
            send_error(&mut ws, "Failed to resolve your account").await;
            return;
        }
    };

    let account = match this.db.get_user(uid).await {
        Ok(user) => serde_json::json!({
            "id": user.id,
            "pubkey": hex::encode(&user.pubkey),
            "email_verified": user.email_verified,
            "country_code": user.country_code,
        }),
        Err(e) => {
            error!("Support chat: failed to load user {}: {}", uid, e);
            send_error(&mut ws, "Failed to load your account").await;
            return;
        }
    };

    // A NIP-98 signature proves control of the key, and `upsert_user` means the
    // account exists by this point, so the requester is always a known customer.
    let requester = Requester::Customer {
        user_id: uid,
        account,
    };

    let executor: Arc<dyn ToolExecutor> = Arc::new(
        DbToolExecutor::new(this.db.clone(), uid)
            .with_power_actions(this.settings.provisioner.clone(), this.work_sender.clone()),
    );
    let store = Arc::new(DbConversationStore::new(this.db.clone(), Some(uid)));
    let agent = SupportAgent::detached(config.openai.clone(), store);
    let mut session = ChatSession::new(
        agent,
        &SenderIdentity::Pubkey(hex::encode(pubkey)),
        requester,
        executor,
    );
    if let Some(extra) = config.system_prompt.as_deref() {
        session = session.with_extra_prompt(extra);
    }
    let privileged = may_view_tool_activity(&this.db, uid).await;
    session = session.with_tool_activity(privileged);

    info!(
        "Support chat opened for user {} ({}, tool activity {})",
        uid,
        session.conversation_key(),
        if privileged { "visible" } else { "hidden" }
    );

    let mut turns = 0usize;
    while let Some(incoming) = ws.recv().await {
        let text = match incoming {
            Ok(Message::Text(text)) => text.to_string(),
            Ok(Message::Close(_)) => break,
            // Ping/Pong are handled by axum; anything binary is a client bug.
            Ok(Message::Binary(_)) => {
                send_error(&mut ws, "Send chat messages as text frames").await;
                continue;
            }
            Ok(_) => continue,
            Err(e) => {
                warn!("Support chat socket error for user {}: {}", uid, e);
                break;
            }
        };

        let message = text.trim();
        if message.is_empty() {
            continue;
        }
        if message.chars().count() > config.max_message_chars {
            send_error(
                &mut ws,
                &format!(
                    "That message is too long (limit {} characters). Please shorten it.",
                    config.max_message_chars
                ),
            )
            .await;
            continue;
        }

        turns += 1;
        if turns > config.max_turns_per_connection {
            send_error(
                &mut ws,
                "This chat has reached its message limit. Please reconnect to continue.",
            )
            .await;
            break;
        }

        // Relay the turn. The stream always ends with a terminal event, so the
        // client can rely on one `final` or `error` per message it sends.
        let mut events = session.send(message);
        let mut client_gone = false;
        while let Some(event) = events.next().await {
            if ws.send(frame(&event)).await.is_err() {
                client_gone = true;
                break;
            }
        }
        if client_gone {
            break;
        }
    }

    info!("Support chat closed for user {}", uid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_json_text() {
        let message = frame(&ChatEvent::Token {
            text: "hi".to_string(),
        });
        match message {
            Message::Text(text) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value["type"], "token");
                assert_eq!(value["text"], "hi");
                // Frames must stay single-line so a client can split on newline.
                assert!(!text.contains('\n'));
            }
            other => panic!("expected text frame, got {other:?}"),
        }
    }

    #[test]
    fn terminal_frames_are_distinguishable() {
        for event in [
            ChatEvent::Final {
                text: "done".to_string(),
            },
            ChatEvent::Error {
                message: "bad".to_string(),
            },
        ] {
            let Message::Text(text) = frame(&event) else {
                panic!("expected text frame");
            };
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(matches!(
                value["type"].as_str(),
                Some("final") | Some("error")
            ));
        }
    }

    /// The auth event is signed over this exact path; changing one without the
    /// other silently breaks every client.
    #[test]
    fn chat_path_matches_the_route() {
        assert_eq!(CHAT_PATH, "/api/v1/support/chat");
    }
}
