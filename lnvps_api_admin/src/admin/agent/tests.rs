use std::sync::Arc;

use lnvps_api_common::{ChannelWorkCommander, MockDb, MockExchangeRate, VatClient, VmStateCache};
use lnvps_db::{AgentChannel, AgentMessageRole, LNVpsDb, NewAgentMessage};

use super::*;
use crate::admin::model::Permission;

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

/// An admin holding every action on one resource and nothing on any other.
fn auth_for(resource: AdminResource) -> AdminAuth {
    AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: [
            AdminAction::View,
            AdminAction::Create,
            AdminAction::Update,
            AdminAction::Delete,
        ]
        .into_iter()
        .map(|action| Permission { resource, action })
        .collect(),
        nip98_auth: None,
    }
}

fn user_msg(text: &str) -> NewAgentMessage {
    NewAgentMessage {
        role: AgentMessageRole::User,
        channel: AgentChannel::Email,
        content: Some(text.to_string()),
        tool_calls: None,
        tool_call_id: None,
    }
}

/// A database with one private thread carrying `count` customer messages.
async fn fixture(count: usize) -> (Arc<dyn LNVpsDb>, u64) {
    let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
    let user_id = db.upsert_user(&[7u8; 32]).await.unwrap();
    let conversation = db
        .upsert_agent_conversation(&format!("user:{user_id}"), Some(user_id))
        .await
        .unwrap();

    let messages: Vec<NewAgentMessage> = (0..count)
        .map(|i| user_msg(&format!("message {i}")))
        .collect();
    if !messages.is_empty() {
        db.append_agent_messages(conversation.id, &messages)
            .await
            .unwrap();
    }
    (db, conversation.id)
}

/// The point of the whole module: a transcript can be read, in order, with its
/// content decrypted.
#[tokio::test]
async fn a_transcript_reads_oldest_first() -> Result<(), ApiError> {
    let (db, id) = fixture(3).await;

    let got = admin_list_agent_messages(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Query(PageQuery::default()),
    )
    .await?;

    assert_eq!(got.0.total, 3);
    let rows = got.0.data;
    assert_eq!(rows[0].content.as_deref(), Some("message 0"));
    assert_eq!(rows[2].content.as_deref(), Some("message 2"));
    assert_eq!(rows[0].role, "user");
    assert_eq!(rows[0].channel, "email");
    Ok(())
}

/// An assistant turn that only requested tools has no prose, and that is
/// distinct from an empty reply — both halves of the turn must survive the
/// round trip or the transcript stops explaining what the agent did.
#[tokio::test]
async fn a_tool_turn_keeps_its_calls_and_its_result() -> Result<(), ApiError> {
    let (db, id) = fixture(0).await;
    db.append_agent_messages(
        id,
        &[
            NewAgentMessage {
                role: AgentMessageRole::Assistant,
                channel: AgentChannel::WebChat,
                content: None,
                tool_calls: Some(
                    r#"[{"id":"c1","name":"list_my_vms","arguments":"{}"}]"#.to_string(),
                ),
                tool_call_id: None,
            },
            NewAgentMessage {
                role: AgentMessageRole::Tool,
                channel: AgentChannel::WebChat,
                content: Some("[vm 5]".to_string()),
                tool_calls: None,
                tool_call_id: Some("c1".to_string()),
            },
        ],
    )
    .await?;

    let got = admin_list_agent_messages(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Query(PageQuery::default()),
    )
    .await?;

    let rows = got.0.data;
    assert_eq!(rows[0].role, "assistant");
    assert_eq!(rows[0].channel, "webchat");
    assert!(
        rows[0].content.is_none(),
        "a tool-only turn has no prose, and null is not the same as empty"
    );
    assert_eq!(
        rows[0]
            .tool_calls
            .as_ref()
            .and_then(|v| v[0]["name"].as_str()),
        Some("list_my_vms")
    );
    assert_eq!(rows[1].role, "tool");
    assert_eq!(rows[1].tool_call_id.as_deref(), Some("c1"));
    Ok(())
}

/// A row whose `tool_calls` is not valid JSON must not take the page down with
/// it: one bad row would otherwise hide an entire transcript.
#[tokio::test]
async fn a_malformed_tool_call_does_not_hide_the_transcript() -> Result<(), ApiError> {
    let (db, id) = fixture(0).await;
    db.append_agent_messages(
        id,
        &[NewAgentMessage {
            role: AgentMessageRole::Assistant,
            channel: AgentChannel::Email,
            content: Some("here you go".to_string()),
            tool_calls: Some("not json".to_string()),
            tool_call_id: None,
        }],
    )
    .await?;

    let got = admin_list_agent_messages(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Query(PageQuery::default()),
    )
    .await?;

    assert_eq!(got.0.total, 1);
    assert_eq!(got.0.data[0].content.as_deref(), Some("here you go"));
    assert!(got.0.data[0].tool_calls.is_none());
    Ok(())
}

/// Which messages the agent still replays is the difference between "the model
/// saw this" and "the model saw a summary of this" — the read is useless for
/// diagnosis without it.
#[tokio::test]
async fn messages_below_the_watermark_are_marked_compacted() -> Result<(), ApiError> {
    let (db, id) = fixture(3).await;
    db.compact_agent_conversation(id, "customer asked about billing", 2)
        .await?;

    let got = admin_list_agent_messages(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Query(PageQuery::default()),
    )
    .await?;

    let rows = got.0.data;
    assert!(rows[0].compacted);
    assert!(rows[1].compacted, "the watermark is inclusive");
    assert!(!rows[2].compacted);
    Ok(())
}

/// An unknown conversation is a 404, not an empty page — an empty page reads as
/// "this customer never wrote in".
#[tokio::test]
async fn an_unknown_conversation_is_not_an_empty_transcript() {
    let (db, _) = fixture(1).await;

    assert!(
        admin_list_agent_messages(
            auth_for(AdminResource::SupportAgent),
            State(state(&db)),
            Path(9_999),
            Query(PageQuery::default()),
        )
        .await
        .is_err()
    );
}

/// Listing carries the counters, and the key's namespace, so a client can tell
/// a public nostr thread from a private one without parsing the key.
#[tokio::test]
async fn listing_reports_counters_and_the_key_namespace() -> Result<(), ApiError> {
    let (db, _) = fixture(2).await;
    db.upsert_agent_conversation("nostr:abcd", None).await?;

    let got = admin_list_agent_conversations(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Query(ListConversationsQuery::default()),
    )
    .await?;

    assert_eq!(got.0.total, 2);
    let private = got
        .0
        .data
        .iter()
        .find(|c| c.kind == "user")
        .expect("private thread missing");
    assert_eq!(private.message_count, 2);
    assert!(private.last_message_at.is_some());

    let public = got
        .0
        .data
        .iter()
        .find(|c| c.kind == "nostr")
        .expect("public thread missing");
    assert_eq!(public.message_count, 0);
    assert!(
        public.last_message_at.is_none(),
        "a thread with no messages has no last message, which is not the epoch"
    );
    Ok(())
}

/// Filters are the difference between "find this customer's history" and
/// "page through everything".
#[tokio::test]
async fn listing_filters_by_user_and_by_key() -> Result<(), ApiError> {
    let (db, _) = fixture(1).await;
    db.upsert_agent_conversation("nostr:abcd", None).await?;
    db.upsert_agent_conversation("email:someone@example.com", None)
        .await?;

    let by_user = admin_list_agent_conversations(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Query(ListConversationsQuery {
            user_id: Some(1),
            ..Default::default()
        }),
    )
    .await?;
    assert_eq!(by_user.0.total, 1);
    assert_eq!(by_user.0.data[0].user_id, Some(1));

    // The namespace prefix is part of the key, so it selects a whole class.
    let public_only = admin_list_agent_conversations(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Query(ListConversationsQuery {
            search: Some("nostr:".to_string()),
            ..Default::default()
        }),
    )
    .await?;
    assert_eq!(public_only.0.total, 1);
    assert_eq!(public_only.0.data[0].kind, "nostr");
    Ok(())
}

/// Clearing the summary without moving the watermark is the safe reset: the
/// agent forgets what it believed, and the next prompt is still bounded by the
/// messages above the watermark.
#[tokio::test]
async fn clearing_the_summary_leaves_the_watermark_alone() -> Result<(), ApiError> {
    let (db, id) = fixture(3).await;
    db.compact_agent_conversation(id, "customer is angry about an outage", 2)
        .await?;

    let got = admin_update_agent_conversation(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Json(AdminUpdateAgentConversationRequest {
            summary: Some(None),
            compacted_upto: None,
        }),
    )
    .await?;

    assert!(got.0.data.summary.is_none());
    assert_eq!(got.0.data.compacted_upto, 2, "watermark must be untouched");
    assert_eq!(
        got.0.data.message_count, 3,
        "resetting memory must not touch the transcript"
    );
    Ok(())
}

/// The watermark must be allowed to move backwards — that is the whole point of
/// an admin reset, and it is why this does not go through the monotonic
/// compaction path.
#[tokio::test]
async fn the_watermark_can_be_wound_back() -> Result<(), ApiError> {
    let (db, id) = fixture(3).await;
    db.compact_agent_conversation(id, "summary", 3).await?;

    let got = admin_update_agent_conversation(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Json(AdminUpdateAgentConversationRequest {
            summary: Some(None),
            compacted_upto: Some(0),
        }),
    )
    .await?;

    assert_eq!(got.0.data.compacted_upto, 0);
    // Everything is replayed again, which is what makes this expensive.
    let messages = db.list_agent_messages_after_watermark(id).await?;
    assert_eq!(messages.len(), 3);
    Ok(())
}

/// A watermark past the end of the log would suppress every message appended
/// afterwards, leaving the agent permanently blind to the thread.
#[tokio::test]
async fn a_watermark_past_the_transcript_is_rejected() -> Result<(), ApiError> {
    let (db, id) = fixture(2).await;

    let denied = admin_update_agent_conversation(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Json(AdminUpdateAgentConversationRequest {
            summary: None,
            compacted_upto: Some(99),
        }),
    )
    .await;

    assert!(denied.is_err());
    let unchanged = db.get_agent_conversation(id).await?;
    assert_eq!(unchanged.compacted_upto, 0);
    Ok(())
}

/// Omitting a field leaves it alone: a caller rewriting the summary must not
/// silently reset the watermark, and vice versa.
#[tokio::test]
async fn an_omitted_field_is_left_alone() -> Result<(), ApiError> {
    let (db, id) = fixture(3).await;
    db.compact_agent_conversation(id, "original", 2).await?;

    let got = admin_update_agent_conversation(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
        Json(AdminUpdateAgentConversationRequest {
            summary: Some(Some("rewritten".to_string())),
            compacted_upto: None,
        }),
    )
    .await?;

    assert_eq!(got.0.data.summary.as_deref(), Some("rewritten"));
    assert_eq!(got.0.data.compacted_upto, 2);
    Ok(())
}

/// Reading transcripts is its own grant. Permission on another resource must
/// not open customer support history.
#[tokio::test]
async fn reading_transcripts_needs_the_support_agent_resource() {
    let (db, id) = fixture(1).await;

    assert!(
        admin_list_agent_conversations(
            auth_for(AdminResource::Users),
            State(state(&db)),
            Query(ListConversationsQuery::default()),
        )
        .await
        .is_err(),
        "users permissions must not list support transcripts"
    );

    assert!(
        admin_get_agent_conversation(auth_for(AdminResource::Users), State(state(&db)), Path(id),)
            .await
            .is_err()
    );

    assert!(
        admin_list_agent_messages(
            auth_for(AdminResource::Users),
            State(state(&db)),
            Path(id),
            Query(PageQuery::default()),
        )
        .await
        .is_err()
    );
}

/// Rewriting memory is a mutation and must not ride in on a read grant.
#[tokio::test]
async fn rewriting_memory_needs_update_not_view() -> Result<(), ApiError> {
    let (db, id) = fixture(1).await;
    let view_only = AdminAuth {
        user_id: 1,
        pubkey: vec![1u8; 32],
        permissions: [Permission {
            resource: AdminResource::SupportAgent,
            action: AdminAction::View,
        }]
        .into_iter()
        .collect(),
        nip98_auth: None,
    };

    let denied = admin_update_agent_conversation(
        view_only,
        State(state(&db)),
        Path(id),
        Json(AdminUpdateAgentConversationRequest {
            summary: Some(None),
            compacted_upto: None,
        }),
    )
    .await;

    assert!(denied.is_err());
    Ok(())
}

/// A key with no recognisable namespace must not be reported as one of the
/// real kinds — a client grouping by `kind` would file it under the wrong
/// privacy class, and `nostr` is the one that is publicly readable.
#[test]
fn an_unrecognised_key_is_not_given_a_kind() {
    assert_eq!(key_kind("user:42"), "user");
    assert_eq!(key_kind("email:a@b.c"), "email");
    assert_eq!(key_kind("pubkey:abcd"), "pubkey");
    assert_eq!(key_kind("nostr:abcd"), "nostr");
    assert_eq!(key_kind("something-else"), "unknown");
    assert_eq!(key_kind("whatever:abcd"), "unknown");
}

/// The routes must actually be mounted. A module that is written, tested at the
/// handler level and never merged into the router is a feature that does not
/// exist, and every handler test here would still pass.
#[tokio::test]
async fn the_routes_are_mounted() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let (db, id) = fixture(1).await;

    for (method, path) in [
        ("GET", "/api/admin/v1/agent/conversations".to_string()),
        ("GET", format!("/api/admin/v1/agent/conversations/{id}")),
        (
            "GET",
            format!("/api/admin/v1/agent/conversations/{id}/messages"),
        ),
        ("PATCH", format!("/api/admin/v1/agent/conversations/{id}")),
    ] {
        let response = router()
            .with_state(state(&db))
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Unauthenticated, so a mounted route answers 401/403 rather than 404.
        // What is being asserted is that the path resolves at all.
        assert_ne!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "{method} {path} is not mounted"
        );
    }
}

/// The single read carries the same counters as the listing, so a client does
/// not have to go back to the list to learn how long a thread is.
#[tokio::test]
async fn the_single_read_carries_the_counters() -> Result<(), ApiError> {
    let (db, id) = fixture(2).await;

    let got = admin_get_agent_conversation(
        auth_for(AdminResource::SupportAgent),
        State(state(&db)),
        Path(id),
    )
    .await?;

    assert_eq!(got.0.data.message_count, 2);
    assert_eq!(got.0.data.kind, "user");
    assert!(got.0.data.last_message_at.is_some());
    Ok(())
}
