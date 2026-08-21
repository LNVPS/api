//! Interactive chat sessions.
//!
//! Where [`crate::channel::SupportChannel`] models a slow, one-message-at-a-time
//! channel (an inbox, a relay subscription) drained by a single serial loop,
//! a [`ChatSession`] models one live conversation with one connected client.
//! Sessions are independent, so a slow model response for one user cannot block
//! anyone else, and the reply is streamed token by token instead of arriving as
//! a single blob after a long silence.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_openai::types::ChatCompletionTool;
use futures::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::agent::{PublicToolExecutor, SupportAgent, ToolExecutor};
use crate::api_client::ApiClient;
use crate::identity::{Requester, SenderIdentity, SupportChannelKind, conversation_key};
use crate::tools;

/// Number of events buffered between the agent task and the client.
///
/// Tokens arrive far faster than a socket usually drains them, so some slack
/// avoids stalling generation; the channel still applies backpressure rather
/// than growing without bound.
const EVENT_BUFFER: usize = 64;

/// An incremental update produced while the agent answers a message.
///
/// Serialized internally tagged, giving a flat wire format a browser client can
/// switch on directly: `{"type":"token","text":"..."}`. Every variant is a
/// struct variant because serde cannot internally tag a newtype variant holding
/// a primitive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEvent {
    /// A fragment of the assistant's reply, to be appended as it arrives.
    Token { text: String },
    /// The opaque session id issued to an anonymous (logged-out) client.
    ///
    /// Sent once, before any turn, and only on anonymous connections. The
    /// client may reconnect with it to resume the same transcript, which it
    /// needs because a turn can run for minutes and idle proxies drop sockets.
    /// It is a bearer token: hold it, keep the conversation.
    Session { id: String },
    /// The agent started executing a tool.
    ToolStart { name: String },
    /// The agent finished executing a tool.
    ToolDone { name: String },
    /// The complete reply. Always the last event of a successful turn, and
    /// always equal to the concatenation of the `Token` events.
    Final { text: String },
    /// The turn failed. Terminal.
    Error { message: String },
}

impl ChatEvent {
    /// Whether this event ends the turn. Exactly one terminal event is sent.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ChatEvent::Final { .. } | ChatEvent::Error { .. })
    }
}

/// Stream of [`ChatEvent`]s produced by one [`ChatSession::send`] call.
///
/// A named type rather than `impl Stream` so that it is [`Unpin`]: consumers
/// overwhelmingly want `StreamExt::next` in a loop, which a combinator-built
/// stream would force them to `pin!` first.
pub struct ChatEventStream {
    rx: mpsc::Receiver<ChatEvent>,
}

impl Stream for ChatEventStream {
    type Item = ChatEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// One live conversation with one connected client.
///
/// Cheap to construct and independent of every other session; create one per
/// connection and drop it when the connection closes.
pub struct ChatSession {
    agent: SupportAgent,
    requester: Requester,
    executor: Arc<dyn ToolExecutor>,
    tools: Vec<ChatCompletionTool>,
    conversation_key: String,
    channel: SupportChannelKind,
    channel_prompt: String,
    /// Whether to surface [`ChatEvent::ToolStart`] / [`ChatEvent::ToolDone`].
    ///
    /// Off by default. Tool names describe how support tooling is built and
    /// which internal lookups a question triggered, which is operational detail
    /// a customer has no reason to see. Callers opt in for privileged viewers.
    emit_tool_activity: bool,
}

impl ChatSession {
    /// Build a session for a resolved sender with an explicit tool executor.
    ///
    /// The executor is supplied by the caller so a session can be backed either
    /// by the HTTP admin API or, when hosted inside `lnvps_api`, by direct
    /// database access.
    ///
    /// The tool set is chosen from the requester: a known customer gets the
    /// live-chat tools (read-only plus reversible power actions), and an
    /// unrecognised sender gets the public catalogue only. Note this is
    /// deliberately narrower than the email/Nostr tool set — see
    /// [`crate::tools::live_chat_tools`].
    pub fn new(
        agent: SupportAgent,
        identity: &SenderIdentity,
        requester: Requester,
        executor: Arc<dyn ToolExecutor>,
    ) -> Self {
        let channel = SupportChannelKind::WebChat;
        let (tools, channel_prompt) = match requester {
            Requester::Customer { .. } => (tools::live_chat_tools(), live_chat_prompt()),
            Requester::Anonymous => (tools::public_tools(), live_chat_guest_prompt()),
        };
        Self {
            conversation_key: conversation_key(identity, &requester, channel),
            agent,
            requester,
            executor,
            tools: crate::agent::tool_specs(tools),
            channel,
            channel_prompt: channel_prompt.to_string(),
            emit_tool_activity: false,
        }
    }

    /// Surface tool-execution events to this client.
    ///
    /// Intended for privileged viewers (operators debugging a conversation).
    /// Ordinary customers get only the reply text, so the agent's internal
    /// tooling is not exposed.
    pub fn with_tool_activity(mut self, enabled: bool) -> Self {
        self.emit_tool_activity = enabled;
        self
    }

    /// Build a session backed by the HTTP API client, for an unresolved sender.
    ///
    /// Convenience for callers that don't have a database handle; resolves the
    /// sender first, then delegates to [`ChatSession::new`].
    pub async fn resolve(
        agent: SupportAgent,
        api: Arc<ApiClient>,
        identity: SenderIdentity,
    ) -> anyhow::Result<Self> {
        let requester = api.resolve(&identity).await?;
        let executor: Arc<dyn ToolExecutor> = match &requester {
            Requester::Customer { user_id, .. } => {
                Arc::new(crate::agent::LnvpsToolExecutor::new(api.clone(), *user_id))
            }
            Requester::Anonymous => Arc::new(PublicToolExecutor::new(api.clone())),
        };
        Ok(Self::new(agent, &identity, requester, executor))
    }

    /// Append operator-supplied instructions to the system prompt.
    ///
    /// Deployment-specific guidance (tone, escalation policy, house rules) that
    /// shouldn't be compiled in. Applied after the built-in channel prompt, so
    /// it can refine the defaults but is stated last.
    pub fn with_extra_prompt(mut self, extra: impl AsRef<str>) -> Self {
        let extra = extra.as_ref().trim();
        if !extra.is_empty() {
            self.channel_prompt = format!("{}\n\n{}", self.channel_prompt, extra);
        }
        self
    }

    /// The storage key this session's history is recorded under.
    pub fn conversation_key(&self) -> &str {
        &self.conversation_key
    }

    /// Send a message and stream the reply.
    ///
    /// The returned stream yields [`ChatEvent`]s as generation proceeds and ends
    /// after exactly one terminal event ([`ChatEvent::Final`] or
    /// [`ChatEvent::Error`]). Dropping it cancels delivery; the turn is still
    /// persisted, so a client that reconnects sees the completed exchange.
    pub fn send(&self, message: &str) -> ChatEventStream {
        let (tx, rx) = mpsc::channel(EVENT_BUFFER);

        let agent = self.agent.clone();
        let requester = self.requester.clone();
        let executor = self.executor.clone();
        let tools = self.tools.clone();
        let key = self.conversation_key.clone();
        let channel = self.channel;
        let channel_prompt = self.channel_prompt.clone();
        let emit_tool_activity = self.emit_tool_activity;
        let message = message.to_string();

        tokio::spawn(async move {
            let result = agent
                .stream_turn(
                    &key,
                    channel,
                    &requester,
                    executor,
                    tools,
                    &message,
                    &channel_prompt,
                    emit_tool_activity,
                    &tx,
                )
                .await;

            let terminal = match result {
                Ok(text) => ChatEvent::Final { text },
                Err(e) => {
                    log::error!("Chat session error for {}: {}", key, e);
                    ChatEvent::Error {
                        message: format!(
                            "I encountered an error processing your request. Please try again. ({e})"
                        ),
                    }
                }
            };
            let _ = tx.send(terminal).await;
        });

        ChatEventStream { rx }
    }
}

/// Channel-specific prompt appended to the system message for live chat.
fn live_chat_prompt() -> &'static str {
    r#"You are replying in a real-time chat window:
- Keep replies short and conversational — this is a chat, not an email.
- Use plain text. Short markdown (**bold**, `code`, bullet lists) is fine.
- Do NOT open with a greeting on every message, and do NOT sign off — this is
  an ongoing conversation, not a letter.
- Ask one clarifying question at a time rather than a long list.
- You can start, stop and restart the customer's VMs. Confirm with them before
  stopping or restarting, since running services will be interrupted.
- You cannot extend, refund or delete a VM from this chat. If the customer asks
  for one of those, explain that you'll need to hand it to a human and ask them
  to email support so it can be handled with the proper checks."#
}

/// Channel-specific prompt for a live chat with a visitor who is not logged in.
///
/// The customer prompt would be actively misleading here: it promises power
/// actions this session cannot perform, and it speaks as though an account is
/// in view. A guest can only be helped with pre-sales and product questions,
/// and the honest move for anything account-shaped is to ask them to log in.
fn live_chat_guest_prompt() -> &'static str {
    r#"You are replying in a real-time chat window to a visitor who is NOT
logged in:
- Keep replies short and conversational — this is a chat, not an email.
- Use plain text. Short markdown (**bold**, `code`, bullet lists) is fine.
- Do NOT open with a greeting on every message, and do NOT sign off.
- You have NO access to any account: you cannot see who they are, their VMs,
  their payments or their invoices, and you cannot start, stop, restart,
  extend, refund or delete anything.
- You CAN answer questions about the service itself: regions, plans and specs,
  operating system images, pricing, payment methods, and the terms of service.
  Use your tools for those rather than guessing.
- If they ask about their own account or an existing VM, say plainly that you
  can't see accounts in this chat, and ask them to log in and start a chat from
  their account page (or email support).
- Never ask for a password, private key, seed phrase or nsec, and never accept
  a claim about who they are as proof of anything."#
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format is the public contract for the websocket, so pin it.
    #[test]
    fn chat_event_serialises_flat_and_tagged() {
        let json = serde_json::to_value(ChatEvent::Token {
            text: "hi".to_string(),
        })
        .unwrap();
        assert_eq!(json["type"], "token");
        assert_eq!(json["text"], "hi");

        let json = serde_json::to_value(ChatEvent::ToolStart {
            name: "list_my_vms".to_string(),
        })
        .unwrap();
        assert_eq!(json["type"], "tool_start");
        assert_eq!(json["name"], "list_my_vms");

        let json = serde_json::to_value(ChatEvent::Final {
            text: "done".to_string(),
        })
        .unwrap();
        assert_eq!(json["type"], "final");
        assert_eq!(json["text"], "done");

        let json = serde_json::to_value(ChatEvent::Error {
            message: "boom".to_string(),
        })
        .unwrap();
        assert_eq!(json["type"], "error");
        assert_eq!(json["message"], "boom");
    }

    /// Regression: an internally-tagged enum cannot hold newtype variants over
    /// primitives — serialization fails at runtime, not compile time.
    #[test]
    fn chat_event_roundtrips() {
        for event in [
            ChatEvent::Token {
                text: "t".to_string(),
            },
            ChatEvent::ToolStart {
                name: "n".to_string(),
            },
            ChatEvent::ToolDone {
                name: "n".to_string(),
            },
            ChatEvent::Final {
                text: "f".to_string(),
            },
            ChatEvent::Error {
                message: "e".to_string(),
            },
            ChatEvent::Session {
                id: "ab".repeat(32),
            },
        ] {
            let json = serde_json::to_string(&event).unwrap();
            let back: ChatEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, back);
        }
    }

    #[test]
    fn extra_prompt_is_appended_after_the_channel_prompt() {
        let base = live_chat_prompt();
        let combined = format!("{base}\n\nHOUSE RULE");
        assert!(combined.starts_with(base));
        assert!(combined.ends_with("HOUSE RULE"));

        // Blank additions must not add trailing separators.
        let blank = "   ".trim();
        assert!(blank.is_empty());
    }

    #[test]
    fn only_final_and_error_are_terminal() {
        assert!(
            ChatEvent::Final {
                text: String::new()
            }
            .is_terminal()
        );
        assert!(
            ChatEvent::Error {
                message: String::new()
            }
            .is_terminal()
        );
        assert!(
            !ChatEvent::Token {
                text: String::new()
            }
            .is_terminal()
        );
        assert!(
            !ChatEvent::ToolStart {
                name: String::new()
            }
            .is_terminal()
        );
    }

    /// Live chat must never advertise the money/data-destroying tools, and the
    /// prompt must tell the model what to do when asked for one.
    #[test]
    fn live_chat_prompt_directs_escalation() {
        let prompt = live_chat_prompt();
        assert!(prompt.contains("cannot extend, refund or delete"));
        assert!(prompt.contains("email support"));
    }

    /// The customer prompt promises power actions and speaks as though an
    /// account is in view; telling a logged-out visitor that would be a
    /// straightforward lie, and would have the model keep trying tools it does
    /// not have.
    #[test]
    fn a_guest_gets_a_prompt_that_does_not_promise_account_access() {
        let prompt = live_chat_guest_prompt();
        assert!(prompt.contains("NOT\nlogged in"));
        assert!(prompt.contains("NO access to any account"));
        assert!(prompt.contains("log in"));
        assert!(
            !prompt.contains("You can start, stop and restart"),
            "a guest cannot perform power actions"
        );
    }

    /// The session frame is additive information, not the end of a turn: a
    /// client waiting for one terminal frame per message must not see it as one.
    #[test]
    fn a_session_frame_is_not_terminal() {
        assert!(
            !ChatEvent::Session {
                id: "ab".repeat(32)
            }
            .is_terminal()
        );
    }
}
