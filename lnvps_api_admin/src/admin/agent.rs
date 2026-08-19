//! Admin view of support-agent conversations.
//!
//! Two things live here: reading transcripts, and managing what the agent
//! *remembers* of them.
//!
//! Reading is the whole point — until now the only way to see what the support
//! agent told a customer was to query the database directly. The transcript is
//! append-only by design (it is also the training corpus), so nothing here
//! edits or deletes a message.
//!
//! Memory is the `summary` + `compacted_upto` pair on the conversation row.
//! Together they are what the agent replays as context: the summary stands in
//! for everything at or below the watermark, and messages above it are replayed
//! verbatim. When an agent has formed a wrong belief about a customer, the fix
//! is to rewrite or clear that memory — which is a mutation of the summary, not
//! of the transcript, and leaves the corpus intact.
//!
//! [`AdminResource::SupportAgent`] is deliberately its own resource: a
//! transcript carries whatever a customer pasted into a support request, which
//! is a wider disclosure than the account fields `users::view` implies.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, PageQuery,
};
use lnvps_db::{
    AdminAction, AdminResource, AgentConversationFilter, AgentConversationOverview, AgentMessage,
};

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/agent/conversations",
            get(admin_list_agent_conversations),
        )
        .route(
            "/api/admin/v1/agent/conversations/{id}",
            get(admin_get_agent_conversation).patch(admin_update_agent_conversation),
        )
        .route(
            "/api/admin/v1/agent/conversations/{id}/messages",
            get(admin_list_agent_messages),
        )
}

/// A support conversation as an admin sees it.
#[derive(Serialize, Debug)]
pub struct AdminAgentConversationInfo {
    pub id: u64,
    /// Namespaced sender identity, e.g. `user:42`, `email:a@b.c`,
    /// `pubkey:<hex>`, `nostr:<hex>`.
    pub conversation_key: String,
    /// The namespace part of `conversation_key`: `user`, `email`, `pubkey` or
    /// `nostr`. Sent separately so a client can group or filter without
    /// re-implementing the key format.
    pub kind: String,
    /// Resolved LNVPS account, when the sender matched one. A thread can start
    /// anonymous and become linked later.
    pub user_id: Option<u64>,
    /// The agent's running memory of everything at or below `compacted_upto`.
    /// This is model-written text about the customer, not a customer message.
    pub summary: Option<String>,
    /// Highest message id folded into `summary`; `0` when nothing has been
    /// compacted. Messages above it are replayed to the model verbatim.
    pub compacted_upto: u64,
    /// Total messages, ignoring the watermark.
    pub message_count: u64,
    /// When the newest message landed; `null` for a thread with no messages.
    pub last_message_at: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

/// The namespace part of a `conversation_key`, or `unknown` for a key that
/// carries no recognisable prefix.
fn key_kind(conversation_key: &str) -> String {
    match conversation_key.split_once(':') {
        Some((kind @ ("user" | "email" | "pubkey" | "nostr"), _)) => kind.to_string(),
        _ => "unknown".to_string(),
    }
}

impl From<AgentConversationOverview> for AdminAgentConversationInfo {
    fn from(c: AgentConversationOverview) -> Self {
        Self {
            kind: key_kind(&c.conversation_key),
            id: c.id,
            conversation_key: c.conversation_key,
            user_id: c.user_id,
            summary: c.summary,
            compacted_upto: c.compacted_upto,
            message_count: c.message_count,
            last_message_at: c.last_message_at,
            created: c.created,
            updated: c.updated,
        }
    }
}

/// One message in a transcript.
#[derive(Serialize, Debug)]
pub struct AdminAgentMessageInfo {
    pub id: u64,
    pub conversation_id: u64,
    /// `user`, `assistant` or `tool`.
    pub role: String,
    /// Which way the message travelled: `email`, `nostr` or `webchat`. Held
    /// per message because one private thread legitimately mixes channels.
    pub channel: String,
    /// Message text, decrypted. `null` for an assistant turn that only
    /// requested tool calls, which is distinct from an empty reply.
    pub content: Option<String>,
    /// Tools the assistant asked for, as stored: `[{id, name, arguments}]`.
    /// `null` for a plain message.
    pub tool_calls: Option<serde_json::Value>,
    /// For a `tool` row, the `tool_calls[].id` it answers.
    pub tool_call_id: Option<String>,
    /// Whether this message is at or below the conversation's watermark — i.e.
    /// the agent no longer replays it and sees only the summary in its place.
    pub compacted: bool,
    pub created: DateTime<Utc>,
}

impl AdminAgentMessageInfo {
    fn from_message(m: AgentMessage, compacted_upto: u64) -> Self {
        Self {
            role: m.role.to_string(),
            channel: m.channel.to_string(),
            content: m.content.as_ref().map(|c| c.as_str().to_string()),
            // The column has a `json_valid` CHECK, so a row that fails to parse
            // means something wrote around the schema. Surface `null` rather
            // than failing the whole page, which would make one bad row hide an
            // entire transcript.
            tool_calls: m
                .tool_calls
                .as_deref()
                .and_then(|raw| serde_json::from_slice(raw).ok()),
            tool_call_id: m.tool_call_id,
            compacted: m.id <= compacted_upto,
            id: m.id,
            conversation_id: m.conversation_id,
            created: m.created,
        }
    }
}

/// Rewrite what the agent remembers about a thread.
///
/// Both fields are optional and omitting one leaves it alone, so a caller can
/// clear the summary without touching the watermark.
#[derive(Deserialize, Debug, Default)]
pub struct AdminUpdateAgentConversationRequest {
    /// Replace the running summary (`"..."`) or clear it (`null`). Clearing it
    /// alone makes the agent forget the summarised past while still replaying
    /// everything above the watermark, which keeps the next prompt bounded.
    #[serde(
        default,
        deserialize_with = "lnvps_api_common::deserialize_nullable_option"
    )]
    pub summary: Option<Option<String>>,
    /// Move the compaction watermark. Must not exceed the highest message id in
    /// the conversation.
    ///
    /// Setting `0` makes the next turn replay the **entire** transcript as
    /// context, which on a long thread is slow and expensive — do it only to
    /// force a re-summarisation from scratch.
    pub compacted_upto: Option<u64>,
}

/// Query parameters for the conversation listing.
#[derive(Deserialize, Default)]
#[serde(default)]
struct ListConversationsQuery {
    #[serde(flatten)]
    page: PageQuery,
    /// Only threads belonging to this resolved account.
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str_optional")]
    user_id: Option<u64>,
    /// Substring match against `conversation_key`. Includes the namespace, so
    /// `nostr:` selects every public thread.
    ///
    /// There is deliberately no message-content search: transcripts are
    /// encrypted at rest, so the database cannot match against them.
    search: Option<String>,
}

/// List conversations, most recently active first.
async fn admin_list_agent_conversations(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ListConversationsQuery>,
) -> ApiPaginatedResult<AdminAgentConversationInfo> {
    auth.require_permission(AdminResource::SupportAgent, AdminAction::View)?;

    let limit = params.page.limit.unwrap_or(50).min(100);
    let offset = params.page.offset.unwrap_or(0);

    let filter = AgentConversationFilter {
        user_id: params.user_id,
        key_search: params
            .search
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    };
    let (conversations, total) = this
        .db
        .list_agent_conversations(&filter, limit, offset)
        .await?;

    ApiPaginatedData::ok(
        conversations
            .into_iter()
            .map(AdminAgentConversationInfo::from)
            .collect(),
        total,
        limit,
        offset,
    )
}

async fn admin_get_agent_conversation(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<AdminAgentConversationInfo> {
    auth.require_permission(AdminResource::SupportAgent, AdminAction::View)?;

    ApiData::ok(this.db.get_agent_conversation_overview(id).await?.into())
}

/// Rewrite a conversation's memory. Never touches the transcript.
async fn admin_update_agent_conversation(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<AdminUpdateAgentConversationRequest>,
) -> ApiResult<AdminAgentConversationInfo> {
    auth.require_permission(AdminResource::SupportAgent, AdminAction::Update)?;

    let conversation = this.db.get_agent_conversation(id).await?;

    // Omitted means "leave alone", so both fields fall back to what is stored.
    let summary = match &req.summary {
        Some(Some(s)) => Some(s.clone()),
        Some(None) => None,
        None => conversation.summary.clone(),
    };
    let compacted_upto = req.compacted_upto.unwrap_or(conversation.compacted_upto);

    // A watermark past the end of the log would silently suppress messages that
    // do not exist yet: every future append would land at or below it and never
    // be replayed, leaving the agent permanently blind to the thread.
    let max_id = this.db.max_agent_message_id(id).await?;
    if compacted_upto > max_id {
        return Err(ApiError::bad_request(format!(
            "compacted_upto {} is past the last message in this conversation ({})",
            compacted_upto, max_id
        )));
    }

    this.db
        .set_agent_conversation_memory(id, summary.as_deref(), compacted_upto)
        .await?;

    ApiData::ok(this.db.get_agent_conversation_overview(id).await?.into())
}

/// Page a conversation's transcript, oldest first.
///
/// Oldest first because a transcript is read as a conversation; the newest-first
/// ordering used elsewhere would show every page backwards.
async fn admin_list_agent_messages(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(params): Query<PageQuery>,
) -> ApiPaginatedResult<AdminAgentMessageInfo> {
    auth.require_permission(AdminResource::SupportAgent, AdminAction::View)?;

    // Checked so an unknown conversation is a 404 rather than an empty page,
    // which reads as "this customer never wrote in".
    let conversation = this.db.get_agent_conversation(id).await?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let messages = this
        .db
        .list_agent_messages_paginated(conversation.id, limit, offset)
        .await?;
    let total = this.db.count_agent_messages(conversation.id).await?;

    ApiPaginatedData::ok(
        messages
            .into_iter()
            .map(|m| AdminAgentMessageInfo::from_message(m, conversation.compacted_upto))
            .collect(),
        total,
        limit,
        offset,
    )
}

#[cfg(test)]
mod tests;
