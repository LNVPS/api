//! Tests for conversation compaction.
//!
//! These drive [`SupportAgent::compact`] against a mock OpenAI-compatible
//! server, because the bug being guarded against is not in how a summary is
//! rendered but in what happens when the provider does not return one: the
//! replay window has to stop growing either way.

use std::sync::Arc;

use anyhow::Result;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::SupportAgent;
use lnvps_agent::api_client::ApiClient;
use lnvps_agent::conversation::{ChatMessage, ConversationStore, MemoryStore};
use lnvps_agent::identity::SupportChannelKind;
use lnvps_agent::settings::{OpenAiConfig, Settings};

/// A throwaway nsec so `ApiClient` can be constructed; no request reaches the
/// LNVPS API in these tests.
const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

fn settings(base_url: String) -> Settings {
    Settings {
        listen: None,
        admin_api_url: "http://127.0.0.1:1".to_string(),
        user_api_url: "http://127.0.0.1:1".to_string(),
        nsec: TEST_NSEC.to_string(),
        openai: OpenAiConfig {
            base_url,
            api_key: Some("test".to_string()),
            model: "test-model".to_string(),
            max_tokens: Some(256),
        },
        system_prompt: None,
        email: None,
        kind1: None,
        conversation_history_path: None,
    }
}

fn agent_for(server: &MockServer, store: Arc<dyn ConversationStore>) -> SupportAgent {
    let settings = settings(format!("{}/v1", server.uri()));
    let api = Arc::new(ApiClient::new(&settings).expect("api client"));
    SupportAgent::new(api, settings, store)
}

/// A non-streaming chat completion response body.
fn completion(message: serde_json::Value, finish_reason: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason }],
    }))
}

/// Seed `store` with `count` messages so there is something to compact.
async fn seed(store: &Arc<MemoryStore>, count: usize) -> Result<()> {
    let messages: Vec<ChatMessage> = (0..count)
        .map(|i| ChatMessage::user(format!("message number {i} about vm 1753")))
        .collect();
    store
        .append("user:1", SupportChannelKind::WebChat, messages)
        .await
}

/// The happy path: a provider that returns a summary gets it stored, and the
/// whole replay window is cleared.
#[tokio::test]
async fn a_summary_from_the_model_is_stored() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion(
            serde_json::json!({ "role": "assistant", "content": "The customer asked about VM 1753." }),
            "stop",
        ))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    seed(&store, 10).await?;

    agent_for(&server, store.clone()).compact("user:1").await?;

    let conv = store.load("user:1").await;
    assert_eq!(
        conv.summary.as_deref(),
        Some("The customer asked about VM 1753.")
    );
    assert!(
        conv.messages.is_empty(),
        "a real summary compacts the whole window"
    );
    Ok(())
}

/// Regression for the production outage: the configured model is a reasoning
/// model whose thinking tokens are charged against `max_completion_tokens` and
/// are not returned in `content`, so a long transcript came back
/// `finish_reason: "length"` with `content: null`.
///
/// Before the fix this returned `Err("LLM returned empty summary")`, the caller
/// logged and swallowed it, and the conversation never compacted — it grew 31,
/// 33, 35, 39 messages within minutes, each turn replaying the whole history.
/// Compaction must now still bound the window.
#[tokio::test]
async fn a_reasoning_model_that_returns_no_content_still_compacts() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        // Exactly what https://yalr.v0l.io/v1 returned in production.
        .respond_with(completion(
            serde_json::json!({ "role": "assistant", "content": null }),
            "length",
        ))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    seed(&store, 40).await?;

    // The call itself must succeed: a provider that cannot summarise is not a
    // reason to leave the conversation unbounded.
    agent_for(&server, store.clone()).compact("user:1").await?;

    let conv = store.load("user:1").await;
    assert!(
        conv.summary.is_some(),
        "the fallback must leave some memory behind"
    );
    assert!(
        conv.messages.len() < 40,
        "the replay window must shrink, got {} of 40",
        conv.messages.len()
    );
    // The most recent exchange survives verbatim rather than being flattened
    // into a truncated line.
    assert!(
        !conv.messages.is_empty(),
        "a tail of recent messages is kept"
    );
    Ok(())
}

/// Compaction has to be able to run repeatedly against a broken provider
/// without the window creeping upward — this is the property whose absence
/// caused the incident.
#[tokio::test]
async fn repeated_failures_keep_the_window_bounded() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion(
            serde_json::json!({ "role": "assistant", "content": null }),
            "length",
        ))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let agent = agent_for(&server, store.clone());

    let mut sizes = Vec::new();
    for _ in 0..5 {
        // Each round adds a burst of traffic, as a busy conversation would.
        seed(&store, 20).await?;
        agent.compact("user:1").await?;
        sizes.push(store.load("user:1").await.messages.len());
    }

    // Without the fallback every round would leave all 20 new messages behind
    // and this would climb 20, 40, 60, 80, 100.
    for size in &sizes {
        assert!(
            *size <= 20,
            "replay window grew unbounded across rounds: {sizes:?}"
        );
    }
    Ok(())
}

/// A model that declines names its reason in `refusal` while `content` stays
/// `None`; the old code reported that as "empty summary".
#[tokio::test]
async fn a_refusal_is_reported_and_still_compacts() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion(
            serde_json::json!({
                "role": "assistant",
                "content": null,
                "refusal": "I cannot summarise this content."
            }),
            "stop",
        ))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    seed(&store, 40).await?;

    agent_for(&server, store.clone()).compact("user:1").await?;

    let conv = store.load("user:1").await;
    assert!(conv.summary.is_some());
    assert!(conv.messages.len() < 40);
    Ok(())
}

/// Whitespace-only content is no more usable than `None`, and providers return
/// the two interchangeably.
#[tokio::test]
async fn whitespace_only_content_is_treated_as_no_summary() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(completion(
            serde_json::json!({ "role": "assistant", "content": "   \n  " }),
            "stop",
        ))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    seed(&store, 40).await?;

    agent_for(&server, store.clone()).compact("user:1").await?;

    let conv = store.load("user:1").await;
    let summary = conv.summary.expect("fallback summary");
    assert!(
        !summary.trim().is_empty(),
        "a blank summary is not a summary"
    );
    assert!(conv.messages.len() < 40);
    Ok(())
}

/// A provider that is unreachable must fall back the same way — the window
/// cannot depend on the provider being up.
///
/// Unreachable rather than 5xx on purpose: async-openai retries server errors
/// with backoff, so a mocked 500 makes this test take ~15 minutes to assert
/// something a refused connection proves in milliseconds.
#[tokio::test]
async fn a_provider_error_still_compacts() -> Result<()> {
    let settings = settings("http://127.0.0.1:1/v1".to_string());
    let api = Arc::new(ApiClient::new(&settings).expect("api client"));
    let store = Arc::new(MemoryStore::new());
    seed(&store, 40).await?;

    SupportAgent::new(api, settings, store.clone())
        .compact("user:1")
        .await?;

    let conv = store.load("user:1").await;
    assert!(conv.summary.is_some());
    assert!(conv.messages.len() < 40);
    Ok(())
}

/// Nothing to compact is not a failure, and must not invent a summary.
#[tokio::test]
async fn an_empty_conversation_is_left_alone() -> Result<()> {
    let server = MockServer::start().await;
    let store = Arc::new(MemoryStore::new());

    agent_for(&server, store.clone()).compact("user:1").await?;

    let conv = store.load("user:1").await;
    assert!(conv.summary.is_none());
    assert!(conv.messages.is_empty());
    Ok(())
}
