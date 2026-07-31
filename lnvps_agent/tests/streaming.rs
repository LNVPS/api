//! End-to-end tests for the live-chat streaming session.
//!
//! These drive [`ChatSession::send`] against a mock OpenAI-compatible server so
//! the whole path is exercised: SSE parsing, tool-call chunk reassembly, tool
//! dispatch, event ordering, and persistence of the completed turn.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::{SupportAgent, ToolExecutor};
use lnvps_agent::api_client::ApiClient;
use lnvps_agent::conversation::{ConversationStore, MemoryStore};
use lnvps_agent::identity::{Requester, SenderIdentity};
use lnvps_agent::session::{ChatEvent, ChatSession};
use lnvps_agent::settings::{OpenAiConfig, Settings};

/// A throwaway nsec so `ApiClient` can be constructed; no request is made to
/// the LNVPS API in these tests (the sender is pre-resolved).
const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

/// Render one SSE `data:` frame containing a chat completion chunk delta.
fn sse_chunk(delta: serde_json::Value) -> String {
    let body = serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "test-model",
        "choices": [{ "index": 0, "delta": delta, "finish_reason": null }],
    });
    format!("data: {}\n\n", body)
}

/// Build a 200 response carrying an SSE body.
///
/// `set_body_string` would force `content-type: text/plain`, which the SSE
/// client rejects outright, so the type is set with the body.
fn sse_response(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.into_bytes(), "text/event-stream")
}

/// Join chunk frames into a complete SSE stream body, terminated the way the
/// OpenAI API does.
fn sse_stream(chunks: Vec<String>) -> String {
    format!("{}data: [DONE]\n\n", chunks.concat())
}

/// An SSE body that ends after a chunk carrying `finish_reason`, with **no**
/// `data: [DONE]` sentinel.
///
/// This is what vLLM and several OpenAI-compatible proxies actually emit.
fn sse_stream_without_done(chunks: Vec<String>) -> String {
    let stop = serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "test-model",
        "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
    });
    format!("{}data: {}\n\n", chunks.concat(), stop)
}

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

/// Records which tools were called and returns canned results.
#[derive(Default)]
struct RecordingExecutor {
    calls: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl ToolExecutor for RecordingExecutor {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String> {
        self.calls
            .lock()
            .await
            .push((name.to_string(), arguments.to_string()));
        Ok(format!("result of {name}"))
    }
}

/// Build an agent whose OpenAI calls hit `server`, sharing `store`.
fn agent_for(server: &MockServer, store: Arc<dyn ConversationStore>) -> SupportAgent {
    let settings = settings(format!("{}/v1", server.uri()));
    let api = Arc::new(ApiClient::new(&settings).expect("api client"));
    SupportAgent::new(api, settings, store)
}

fn customer() -> Requester {
    Requester::Customer {
        user_id: 42,
        account: serde_json::json!({ "id": 42, "pubkey": "ab" }),
    }
}

/// Drain a session's event stream into a vector.
async fn collect(session: &ChatSession, message: &str) -> Vec<ChatEvent> {
    session.send(message).collect::<Vec<_>>().await
}

#[tokio::test]
async fn streams_tokens_in_order_and_finishes_with_the_full_reply() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![
            sse_chunk(serde_json::json!({ "role": "assistant", "content": "Your VM " })),
            sse_chunk(serde_json::json!({ "content": "is " })),
            sse_chunk(serde_json::json!({ "content": "running." })),
        ])))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    );

    let events = collect(&session, "is my vm up?").await;

    let tokens: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            ChatEvent::Token { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(tokens, vec!["Your VM ", "is ", "running."]);

    // Exactly one terminal event, and it is last.
    assert_eq!(events.iter().filter(|e| e.is_terminal()).count(), 1);
    match events.last().expect("at least one event") {
        ChatEvent::Final { text } => {
            assert_eq!(text, "Your VM is running.");
            assert_eq!(*text, tokens.concat(), "final must equal the token stream");
        }
        other => panic!("expected Final, got {other:?}"),
    }
}

/// Build the two-response mock used by the tool-activity tests: a tool call,
/// then the prose answer.
async fn mount_tool_call_then_reply(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "list_my_vms", "arguments": "{}" }
                }]
            }),
        )])))
        .up_to_n_times(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({ "content": "You have one VM." }),
        )])))
        .mount(server)
        .await;
}

/// Tool activity is operational detail, so it is hidden unless the caller opts
/// in. The tool still runs — only the notification is withheld.
#[tokio::test]
async fn tool_activity_is_hidden_by_default() {
    let server = MockServer::start().await;
    mount_tool_call_then_reply(&server).await;

    let executor = Arc::new(RecordingExecutor::default());
    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        executor.clone(),
    );

    let events = collect(&session, "how many vms?").await;

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ChatEvent::ToolStart { .. } | ChatEvent::ToolDone { .. })),
        "tool events must not be sent to an ordinary customer: {events:?}"
    );
    // The lookup still happened; only the notification was withheld.
    assert_eq!(executor.calls.lock().await.len(), 1);
    match events.last().expect("terminal event") {
        ChatEvent::Final { text } => assert_eq!(text, "You have one VM."),
        other => panic!("expected Final, got {other:?}"),
    }
}

#[tokio::test]
async fn tool_activity_is_shown_when_enabled() {
    let server = MockServer::start().await;
    mount_tool_call_then_reply(&server).await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    )
    .with_tool_activity(true);

    let events = collect(&session, "how many vms?").await;

    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChatEvent::ToolStart { name } if name == "list_my_vms")),
        "privileged viewers should see tool activity: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ChatEvent::ToolDone { name } if name == "list_my_vms"))
    );
}

#[tokio::test]
async fn executes_streamed_tool_calls_and_announces_them() {
    let server = MockServer::start().await;

    // First response: a tool call split across chunks the way a provider sends
    // it. Second response: the prose reply built from the tool result.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![
            sse_chunk(serde_json::json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "get_vm_details", "arguments": "" }
                }]
            })),
            sse_chunk(serde_json::json!({
                "tool_calls": [{ "index": 0, "function": { "arguments": "{\"vm" } }]
            })),
            sse_chunk(serde_json::json!({
                "tool_calls": [{ "index": 0, "function": { "arguments": "_id\":5}" } }]
            })),
        ])))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({ "content": "VM 5 is fine." }),
        )])))
        .mount(&server)
        .await;

    let executor = Arc::new(RecordingExecutor::default());
    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        executor.clone(),
    )
    .with_tool_activity(true);

    let events = collect(&session, "check vm 5").await;

    // The reassembled arguments must be the concatenation of the deltas.
    let calls = executor.calls.lock().await.clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "get_vm_details");
    assert_eq!(calls[0].1, r#"{"vm_id":5}"#);

    // The tool run is announced, and start precedes done.
    let start = events
        .iter()
        .position(|e| matches!(e, ChatEvent::ToolStart { name } if name == "get_vm_details"))
        .expect("tool_start emitted");
    let done = events
        .iter()
        .position(|e| matches!(e, ChatEvent::ToolDone { name } if name == "get_vm_details"))
        .expect("tool_done emitted");
    assert!(start < done, "tool_start must precede tool_done");

    match events.last().expect("terminal event") {
        ChatEvent::Final { text } => assert_eq!(text, "VM 5 is fine."),
        other => panic!("expected Final, got {other:?}"),
    }
}

/// Regression: when the model narrates *before* calling a tool, that prose is
/// streamed to the client, so `Final` must include it.
///
/// Returning only the last iteration's text left clients showing something
/// different from the tokens they had already rendered.
#[tokio::test]
async fn final_includes_narration_streamed_before_a_tool_call() {
    let server = MockServer::start().await;

    // Turn 1: prose *and* a tool call in the same response.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![
            sse_chunk(serde_json::json!({ "content": "Let me check. " })),
            sse_chunk(serde_json::json!({
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "list_my_vms", "arguments": "{}" }
                }]
            })),
        ])))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Turn 2: the answer.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({ "content": "You have one VM." }),
        )])))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    );

    let events = collect(&session, "how many vms?").await;

    let streamed: String = events
        .iter()
        .filter_map(|e| match e {
            ChatEvent::Token { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(streamed, "Let me check. You have one VM.");

    match events.last().expect("terminal event") {
        ChatEvent::Final { text } => assert_eq!(
            *text, streamed,
            "final must equal everything the client was shown"
        ),
        other => panic!("expected Final, got {other:?}"),
    }
}

#[tokio::test]
async fn persists_the_turn_under_the_unified_conversation_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({ "content": "Hello." }),
        )])))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    );

    // A known customer keys on their user id, so live chat shares a thread with
    // email rather than opening a per-connection one.
    assert_eq!(session.conversation_key(), "user:42");

    collect(&session, "hi").await;

    let conversation = store.load("user:42").await;
    assert_eq!(conversation.messages.len(), 2, "user + assistant persisted");
}

/// Regression: a provider that closes the stream without `data: [DONE]` must
/// still produce a normal reply.
///
/// `async-openai` reports the resulting EOF as a `StreamError`, which used to
/// fail every single turn against such a provider.
#[tokio::test]
async fn completes_when_provider_omits_the_done_sentinel() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream_without_done(vec![
            sse_chunk(serde_json::json!({ "content": "No " })),
            sse_chunk(serde_json::json!({ "content": "sentinel." })),
        ])))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    );

    let events = collect(&session, "hello").await;
    match events.last().expect("terminal event") {
        ChatEvent::Final { text } => assert_eq!(text, "No sentinel."),
        other => panic!("expected Final despite the missing [DONE], got {other:?}"),
    }
}

#[tokio::test]
async fn reports_upstream_failure_as_a_terminal_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream exploded"))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("ab".repeat(32)),
        customer(),
        Arc::new(RecordingExecutor::default()),
    );

    let events = collect(&session, "hello").await;

    assert_eq!(events.len(), 1, "a failed turn emits only the error");
    match &events[0] {
        ChatEvent::Error { message } => assert!(!message.is_empty()),
        other => panic!("expected Error, got {other:?}"),
    }
}

/// An unrecognised sender gets the public catalogue and their own thread.
#[tokio::test]
async fn anonymous_sender_keys_on_identity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(sse_stream(vec![sse_chunk(
            serde_json::json!({ "content": "Plans start at..." }),
        )])))
        .mount(&server)
        .await;

    let store = Arc::new(MemoryStore::new());
    let session = ChatSession::new(
        agent_for(&server, store.clone()),
        &SenderIdentity::Pubkey("cd".repeat(32)),
        Requester::Anonymous,
        Arc::new(RecordingExecutor::default()),
    );

    assert_eq!(
        session.conversation_key(),
        format!("pubkey:{}", "cd".repeat(32))
    );
    let events = collect(&session, "what do you offer?").await;
    assert!(matches!(events.last(), Some(ChatEvent::Final { .. })));
}
