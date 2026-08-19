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
use std::time::Duration;

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

/// How often the server sends an unsolicited WebSocket ping.
///
/// A turn produces no frames while the model thinks and runs tools, which can
/// run to minutes, so an otherwise healthy connection looks idle to anything in
/// between. Reverse proxies close idle connections on a timer — nginx's
/// `proxy_read_timeout` defaults to 60s, and that default is exactly what cut
/// conversations mid-answer in production:
///
/// ```text
/// WARN Support chat socket error for user 1:
///      WebSocket protocol error: Connection reset without closing handshake
/// ```
///
/// The server has to be the end that speaks, because a browser cannot send a
/// ping frame from JavaScript — the WebSocket API exposes no such method — so
/// the client physically cannot keep this connection alive by itself.
///
/// 20s gives three pings inside a 60s window, so a single dropped or delayed
/// ping does not reach the timeout. Raising the proxy's timeout (as was done as
/// an immediate mitigation) is not a substitute: this endpoint should not
/// depend on every proxy in front of it being configured generously.
const PING_INTERVAL: Duration = Duration::from_secs(20);

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

/// The unsolicited ping the server sends to keep the connection alive.
///
/// Empty payload: a pong echoes the payload back, and nothing reads it. Built
/// here rather than inline so the two call sites cannot drift.
fn ping_frame() -> Message {
    Message::Ping(Vec::new().into())
}

/// A keepalive clock for one connection.
///
/// Wraps [`tokio::time::interval`] only to make the two decisions that are easy
/// to get wrong testable on their own: that the first tick does not fire
/// immediately (which would ping a client that has not finished connecting),
/// and that ticks are paced rather than burst after a long turn.
struct Keepalive {
    interval: tokio::time::Interval,
}

impl Keepalive {
    /// Start a keepalive that first fires `period` from now.
    fn new(period: Duration) -> Self {
        let mut interval = tokio::time::interval(period);
        // `interval` yields immediately on first poll; consume that so the
        // first ping lands a full period in rather than at connect time.
        interval.reset();
        // A turn can outrun several periods. Missed ticks must not then fire
        // back-to-back — the point is liveness, not making up lost pings.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self { interval }
    }

    /// Resolve when the next ping is due.
    async fn tick(&mut self) {
        self.interval.tick().await;
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

    // Ticks while waiting for a message *and* while a turn streams, because the
    // streaming gap is the long one.
    let mut ping = Keepalive::new(PING_INTERVAL);

    let mut turns = 0usize;
    loop {
        let incoming = tokio::select! {
            // Biased so a message already waiting is handled before a ping that
            // came due in the same poll: pings are keepalive, not work.
            biased;
            incoming = ws.recv() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            _ = ping.tick() => {
                // A failed send means the peer is gone, exactly as it does on
                // the streaming path.
                if ws.send(ping_frame()).await.is_err() {
                    break;
                }
                continue;
            }
        };

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
        //
        // Pings are interleaved here rather than only between turns because
        // this is where the socket goes quiet for minutes. A ping is a control
        // frame, so it does not appear in the client's message stream and the
        // one-terminal-frame-per-message contract is untouched.
        let mut events = session.send(message);
        let mut client_gone = false;
        loop {
            tokio::select! {
                // Biased so a ready event is always sent before a due ping;
                // reply latency is what the customer sees.
                biased;
                event = events.next() => match event {
                    Some(event) => {
                        if ws.send(frame(&event)).await.is_err() {
                            client_gone = true;
                            break;
                        }
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    if ws.send(ping_frame()).await.is_err() {
                        client_gone = true;
                        break;
                    }
                }
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

    /// The keepalive is worthless if it does not fit inside the idle timeout of
    /// whatever sits in front of the API. nginx's `proxy_read_timeout` default
    /// is 60s, which is what closed these connections in production; leave room
    /// for more than one ping inside that window so a single delayed ping is
    /// not immediately fatal.
    #[test]
    fn ping_interval_fits_inside_a_default_proxy_timeout() {
        let nginx_default = Duration::from_secs(60);
        assert!(
            PING_INTERVAL * 3 <= nginx_default,
            "PING_INTERVAL {:?} leaves no margin under a {:?} idle timeout",
            PING_INTERVAL,
            nginx_default
        );
    }

    /// A ping is a control frame, not a chat frame: it must never be something
    /// the client would try to parse as a [`ChatEvent`], or the
    /// one-terminal-frame-per-message contract would be broken by keepalive
    /// traffic.
    #[test]
    fn a_ping_is_not_a_text_frame() {
        assert!(matches!(ping_frame(), Message::Ping(_)));
    }

    /// The first ping must not go out at connect time — only after a full idle
    /// period. `tokio::time::interval` fires immediately on first poll, so this
    /// is the easy half of the bug to reintroduce.
    #[tokio::test(start_paused = true)]
    async fn the_first_ping_waits_a_full_interval() {
        let mut keepalive = Keepalive::new(PING_INTERVAL);

        // Nothing due yet, one tick short of the interval.
        tokio::time::advance(PING_INTERVAL - Duration::from_millis(1)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                .await
                .is_err(),
            "pinged before the first interval elapsed"
        );

        // Due now.
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                .await
                .is_ok(),
            "no ping after a full interval"
        );
    }

    /// A turn can run for minutes, outrunning several ping periods. The missed
    /// ticks must not then fire back to back: that would put a burst of pings
    /// on the wire the moment the turn ends, which is noise rather than
    /// liveness.
    #[tokio::test(start_paused = true)]
    async fn missed_ticks_do_not_burst() {
        let mut keepalive = Keepalive::new(PING_INTERVAL);

        // Simulate a long turn during which nothing polled the keepalive.
        tokio::time::advance(PING_INTERVAL * 5).await;

        // The first tick is due immediately — that ping was owed.
        assert!(
            tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                .await
                .is_ok()
        );

        // But the next one is a full period away, not owed four times over.
        assert!(
            tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                .await
                .is_err(),
            "missed ticks fired as a burst"
        );
        tokio::time::advance(PING_INTERVAL).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                .await
                .is_ok()
        );
    }

    /// Pings keep coming for as long as the connection is idle; a keepalive
    /// that fired once would not survive a long conversation.
    #[tokio::test(start_paused = true)]
    async fn pings_repeat_while_idle() {
        let mut keepalive = Keepalive::new(PING_INTERVAL);

        for i in 0..10 {
            tokio::time::advance(PING_INTERVAL).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(0), keepalive.tick())
                    .await
                    .is_ok(),
                "keepalive stopped firing after {i} pings"
            );
        }
    }
}
