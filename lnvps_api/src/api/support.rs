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
//! A connection carrying **no** `ticket`/`auth` parameter is an anonymous
//! (guest) session, for the logged-out visitor on the public contact page. It
//! is served only when `agent.allow-anonymous` is set, gets the public
//! catalogue tools and no account context, and is bounded by per-IP limits on
//! top of a lower per-connection message cap. The server issues an opaque
//! session id as the first frame (`{"type":"session","id":"..."}`); reconnect
//! with `?guest=<id>` to resume that transcript.
//!
//! ```text
//! {"type":"token","text":"Your VM "}
//! {"type":"tool_start","name":"list_my_vms"}
//! {"type":"tool_done","name":"list_my_vms"}
//! {"type":"final","text":"Your VM is running."}
//! ```
//!
//! Every message yields exactly one terminal frame (`final` or `error`).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use log::{error, info, warn};
use rand::RngCore;
use serde::Deserialize;

use lnvps_agent::agent::{DbToolExecutor, SupportAgent, ToolExecutor};
use lnvps_agent::conversation::DbConversationStore;
use lnvps_agent::identity::{Requester, SenderIdentity};
use lnvps_agent::session::{ChatEvent, ChatSession};
use lnvps_api_common::IpRateLimiter;
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};

use crate::api::RouterState;
use crate::settings::AgentConfig;

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

/// Query parameters accepted on the chat socket.
///
/// `ticket`/`auth` (via [`crate::api::AuthQuery`]) select an authenticated
/// customer session; their absence selects a guest session, and `guest` then
/// resumes a previously issued one.
#[derive(Deserialize, Default)]
pub(crate) struct ChatQuery {
    #[serde(flatten)]
    pub auth: crate::api::AuthQuery,
    #[serde(default)]
    pub guest: Option<String>,
}

impl ChatQuery {
    /// Whether this connection is asking for a guest session.
    ///
    /// Deliberately "no credential at all" rather than "an invalid one": a
    /// client that *tried* to authenticate and failed must be told so, not
    /// silently downgraded into a session that cannot see its own VMs.
    fn is_anonymous(&self) -> bool {
        self.auth.ticket.is_none() && self.auth.auth.is_none()
    }
}

/// Window for the per-IP guest limits.
const GUEST_LIMIT_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Length in bytes of a guest session id before hex encoding.
const GUEST_ID_BYTES: usize = 32;

/// Per-IP limits on anonymous chat.
struct GuestLimits {
    /// Bounds sockets opened, i.e. handshake and prompt-context cost.
    connections: IpRateLimiter,
    /// Bounds *messages* across connections — the real token spend, and the
    /// one a client cannot reset by reconnecting.
    messages: IpRateLimiter,
}

/// Process-wide guest limiters, built from the first connection's config.
///
/// Config is loaded once at startup and never reloaded, so initialising here
/// rather than at boot is equivalent — and keeps the limiters out of
/// [`RouterState`], which every handler would otherwise carry.
fn guest_limits(config: &AgentConfig) -> &'static GuestLimits {
    static LIMITS: OnceLock<GuestLimits> = OnceLock::new();
    LIMITS.get_or_init(|| GuestLimits {
        connections: IpRateLimiter::new(config.anonymous_connections_per_hour, GUEST_LIMIT_WINDOW),
        messages: IpRateLimiter::new(config.anonymous_messages_per_hour, GUEST_LIMIT_WINDOW),
    })
}

/// Bucket used when no client address can be resolved.
///
/// A request with no usable forwarding header must not be waved through, so it
/// is billed to one shared bucket — the same rule the HTTP limiter applies.
const UNKNOWN_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Mint an unguessable guest session id.
fn new_guest_id() -> String {
    let mut bytes = [0u8; GUEST_ID_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether `id` is shaped like an id this server issued.
///
/// The id is a bearer token for a stored transcript, so anything that is not
/// exactly what [`new_guest_id`] produces is rejected rather than used as a
/// conversation key: that keeps a client from choosing a short, guessable or
/// deliberately-colliding key (`"1"`, someone's pubkey, a path).
fn is_guest_id(id: &str) -> bool {
    id.len() == GUEST_ID_BYTES * 2 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What a plain (non-upgrade) `GET` on the chat path reports.
///
/// The frontend probes this path to decide whether to render a chat box.
/// `available` alone is not enough: with anonymous chat off, chat exists but
/// the public contact page must not offer it, so `anonymous` says whether a
/// logged-out visitor can use it.
#[derive(serde::Serialize)]
pub(crate) struct ChatAvailability {
    /// The support agent is configured on this server.
    pub available: bool,
    /// A visitor who is not logged in may open a session.
    pub anonymous: bool,
}

impl ChatAvailability {
    /// What to report for a given agent configuration, with the status code the
    /// probe should carry.
    ///
    /// 404 when the agent is not configured, so the existing "any non-404 means
    /// available" client heuristic keeps working unchanged.
    fn for_config(config: Option<&AgentConfig>) -> (StatusCode, Self) {
        match config {
            Some(config) => (
                StatusCode::OK,
                Self {
                    available: true,
                    anonymous: config.allow_anonymous,
                },
            ),
            None => (
                StatusCode::NOT_FOUND,
                Self {
                    available: false,
                    anonymous: false,
                },
            ),
        }
    }
}

/// Answer the availability probe.
pub(crate) fn chat_availability(this: &RouterState) -> Response {
    let (status, body) = ChatAvailability::for_config(this.settings.agent.as_ref());
    (status, axum::Json(body)).into_response()
}

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
    query: ChatQuery,
    client_ip: Option<IpAddr>,
    this: RouterState,
    mut ws: WebSocket,
) {
    let Some(config) = this.settings.agent.clone() else {
        send_error(&mut ws, "The support agent is not enabled on this server").await;
        return;
    };

    let anonymous = query.is_anonymous();
    let ip = client_ip.unwrap_or(UNKNOWN_CLIENT);

    // Everything that differs between a customer and a guest session, resolved
    // once so the message loop below is identical for both.
    let (identity, requester, executor, store_user, guest_id, max_turns) = if anonymous {
        if !config.allow_anonymous {
            send_error(
                &mut ws,
                "Live chat requires you to be logged in on this server",
            )
            .await;
            return;
        }
        if let Err(retry_after) = guest_limits(&config).connections.check(ip) {
            send_error(
                &mut ws,
                &format!(
                    "Too many chat sessions from your network. Please try again in {} seconds.",
                    retry_after
                ),
            )
            .await;
            return;
        }

        // Resume the transcript when the client presents an id we could have
        // issued; otherwise start a fresh one. An unusable id is replaced
        // rather than refused, because the visitor cannot fix it.
        let session_id = query
            .guest
            .filter(|id| is_guest_id(id))
            .unwrap_or_else(new_guest_id);

        // No account, so: no account context in the prompt, catalogue-only
        // tools (chosen by `ChatSession` from `Requester::Anonymous`), and an
        // executor that cannot reach a user record even if the model invents a
        // call to a tool it was not offered.
        let executor: Arc<dyn ToolExecutor> = Arc::new(DbToolExecutor::public(this.db.clone()));
        (
            SenderIdentity::Guest(session_id.clone()),
            Requester::Anonymous,
            executor,
            None,
            Some(session_id),
            config.anonymous_max_turns_per_connection,
        )
    } else {
        // Authenticate exactly like the console endpoint: a single-use ticket
        // (or, for older clients, a NIP-98 event signed over this path) passed
        // as a query parameter, because browsers cannot set headers on a
        // WebSocket handshake.
        let pubkey = match query.auth.resolve(CHAT_PATH) {
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

        let executor: Arc<dyn ToolExecutor> = Arc::new(
            DbToolExecutor::new(this.db.clone(), uid)
                .with_power_actions(this.settings.provisioner.clone(), this.work_sender.clone()),
        );
        (
            SenderIdentity::Pubkey(hex::encode(pubkey)),
            // A NIP-98 signature proves control of the key, and `upsert_user`
            // means the account exists by this point, so the requester is
            // always a known customer.
            Requester::Customer {
                user_id: uid,
                account,
            },
            executor,
            Some(uid),
            None,
            config.max_turns_per_connection,
        )
    };

    let store = Arc::new(DbConversationStore::new(this.db.clone(), store_user));
    let agent = SupportAgent::detached(config.openai.clone(), store);
    let mut session = ChatSession::new(agent, &identity, requester, executor);
    if let Some(extra) = config.system_prompt.as_deref() {
        session = session.with_extra_prompt(extra);
    }
    // A guest has no permissions to check, and nothing to reveal internals to.
    let privileged = match store_user {
        Some(uid) => may_view_tool_activity(&this.db, uid).await,
        None => false,
    };
    session = session.with_tool_activity(privileged);

    // How this connection is named in logs. Never the guest session id: it is a
    // bearer token for the transcript, so it does not belong in a log line.
    let who = match store_user {
        Some(uid) => format!("user {uid}"),
        None => "guest".to_string(),
    };

    // Tell a guest which session it got, so a reconnect can resume it. Sent
    // before any turn, and never on an authenticated connection.
    if let Some(id) = guest_id
        && ws.send(frame(&ChatEvent::Session { id })).await.is_err()
    {
        return;
    }

    info!(
        "Support chat opened for {} ({}, tool activity {})",
        who,
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
                warn!("Support chat socket error for {}: {}", who, e);
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
        if turns > max_turns {
            send_error(
                &mut ws,
                "This chat has reached its message limit. Please reconnect to continue.",
            )
            .await;
            break;
        }

        // The per-connection cap above is per *socket*; a client can reconnect.
        // This is the limit that actually bounds one source's token spend, so
        // it is checked per message and survives reconnects.
        if anonymous && let Err(retry_after) = guest_limits(&config).messages.check(ip) {
            send_error(
                &mut ws,
                &format!(
                    "You've reached the chat limit for now. Please try again in {} seconds, \
                     or email support.",
                    retry_after
                ),
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

    info!("Support chat closed for {}", who);
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

    /// A connection is a guest session only when it presents no credential at
    /// all. A client that *tried* to authenticate and failed must get an error,
    /// never a silent downgrade into a session that cannot see its own VMs.
    #[test]
    fn only_a_credential_free_connection_is_anonymous() {
        assert!(ChatQuery::default().is_anonymous());
        assert!(
            !ChatQuery {
                auth: crate::api::AuthQuery {
                    ticket: Some("anything".into()),
                    ..Default::default()
                },
                guest: None,
            }
            .is_anonymous()
        );
        assert!(
            !ChatQuery {
                auth: crate::api::AuthQuery {
                    auth: Some("anything".into()),
                    ..Default::default()
                },
                guest: None,
            }
            .is_anonymous()
        );
        // A guest id is not a credential: presenting one still yields a guest
        // session, and presenting one alongside a ticket does not.
        assert!(
            ChatQuery {
                auth: Default::default(),
                guest: Some(new_guest_id()),
            }
            .is_anonymous()
        );
    }

    /// The guest id is a bearer token for a stored transcript, so it must be
    /// long and random. A short or attacker-chosen key would let one visitor
    /// read another's conversation, or collide deliberately with a namespace.
    #[test]
    fn guest_ids_are_unguessable_and_validated() {
        let id = new_guest_id();
        assert_eq!(id.len(), GUEST_ID_BYTES * 2);
        assert!(is_guest_id(&id));
        assert_ne!(id, new_guest_id(), "guest ids must not repeat");

        for bad in [
            "",
            "1",
            &"a".repeat(GUEST_ID_BYTES * 2 - 1),
            &"a".repeat(GUEST_ID_BYTES * 2 + 1),
            &"z".repeat(GUEST_ID_BYTES * 2),
            &format!("{}/..", "a".repeat(GUEST_ID_BYTES * 2 - 3)),
        ] {
            assert!(!is_guest_id(bad), "accepted a bad guest id: {bad:?}");
        }
    }

    /// Anonymous chat is on by default, but must be cheaper to abuse than an
    /// authenticated session — that asymmetry is the whole basis for serving it
    /// without a credential.
    #[test]
    fn anonymous_defaults_are_tighter_than_authenticated() {
        use crate::settings::*;
        assert!(default_agent_allow_anonymous());
        assert!(
            default_agent_anonymous_max_turns() < default_agent_max_turns(),
            "a guest connection must allow fewer messages than an authenticated one"
        );
        assert!(default_agent_anonymous_connections_per_hour() > 0);
        assert!(default_agent_anonymous_messages_per_hour() > 0);
    }

    /// The session frame is what lets a guest resume after a dropped socket;
    /// it must be an ordinary non-terminal event the client can switch on.
    #[test]
    fn the_session_frame_carries_the_guest_id() {
        let id = new_guest_id();
        let event = ChatEvent::Session { id: id.clone() };
        assert!(!event.is_terminal());
        let Message::Text(text) = frame(&event) else {
            panic!("expected text frame");
        };
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["type"], "session");
        assert_eq!(value["id"], id);
    }

    /// The availability probe is what the public page uses to decide whether to
    /// render a chat box at all: 404 when there is no agent (so the existing
    /// "non-404 means available" heuristic holds), and `anonymous` reflecting
    /// the config gate rather than merely that chat exists.
    #[test]
    fn availability_reports_the_anonymous_gate() {
        let config = |allow_anonymous| AgentConfig {
            openai: lnvps_agent::settings::OpenAiConfig {
                base_url: "http://localhost:11434/v1".to_string(),
                api_key: None,
                model: "test".to_string(),
                max_tokens: None,
            },
            system_prompt: None,
            max_message_chars: crate::settings::default_agent_max_message_chars(),
            max_turns_per_connection: crate::settings::default_agent_max_turns(),
            allow_anonymous,
            anonymous_max_turns_per_connection: crate::settings::default_agent_anonymous_max_turns(
            ),
            anonymous_connections_per_hour:
                crate::settings::default_agent_anonymous_connections_per_hour(),
            anonymous_messages_per_hour: crate::settings::default_agent_anonymous_messages_per_hour(
            ),
        };

        // No agent: 404, so "non-404 means chat exists" stays true.
        let (status, body) = ChatAvailability::for_config(None);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.available);
        assert!(!body.anonymous);

        // Configured but gated: chat exists, guests may not use it. A client
        // that only looked at the status code would render a box that always
        // refuses — which is exactly why `anonymous` is reported separately.
        let (status, body) = ChatAvailability::for_config(Some(&config(false)));
        assert_eq!(status, StatusCode::OK);
        assert!(body.available);
        assert!(!body.anonymous);

        let (status, body) = ChatAvailability::for_config(Some(&config(true)));
        assert_eq!(status, StatusCode::OK);
        assert!(body.available);
        assert!(body.anonymous);
    }

    /// A caller with no resolvable address must not escape the guest limits
    /// entirely; it is billed to one shared bucket instead.
    #[test]
    fn an_unknown_client_still_has_a_bucket() {
        let limiter = IpRateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check(UNKNOWN_CLIENT).is_ok());
        assert!(
            limiter.check(UNKNOWN_CLIENT).is_err(),
            "unattributable connections must share one bucket, not bypass the limit"
        );
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
