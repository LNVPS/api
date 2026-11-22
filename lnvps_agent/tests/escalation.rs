use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use lnvps_agent::agent::{DbToolExecutor, SupportAgent, ToolExecutor};
use lnvps_agent::conversation::{ConversationStore, MemoryStore};
use lnvps_agent::escalation::{Escalation, MailSink, OutgoingMail};
use lnvps_agent::identity::{Requester, SenderIdentity};
use lnvps_agent::session::{ChatEvent, ChatSession};
use lnvps_agent::settings::{OpenAiConfig, Settings};
use lnvps_api_common::MockDb;
use lnvps_db::LNVpsDbBase;
use lnvps_db::{
    AgentChannel, AgentMessageRole, LNVpsDb, NewAgentMessage, User, Vm, VmIpAssignment,
};

#[derive(Default)]
struct MailSinkMock {
    sent: Mutex<Vec<OutgoingMail>>,
    fail: bool,
}

#[async_trait]
impl MailSink for MailSinkMock {
    async fn send(&self, mail: OutgoingMail) -> Result<()> {
        if self.fail {
            anyhow::bail!("smtp down");
        }
        self.sent.lock().await.push(mail);
        Ok(())
    }
}

async fn stack(sink: Arc<MailSinkMock>, email: &str) -> (DbToolExecutor, Arc<MockDb>, Arc<MockDb>) {
    let db = Arc::new(MockDb::default());
    db.users.lock().await.insert(
        1,
        User {
            id: 1,
            email: email.into(),
            email_verified: true,
            ..Default::default()
        },
    );
    for (id, owner, disabled) in [(7u64, 1u64, true), (8, 1, false), (9, 99, false)] {
        db.vms.lock().await.insert(
            id,
            Vm {
                id,
                user_id: owner,
                disabled,
                ..MockDb::mock_vm()
            },
        );
    }
    db.ip_assignments.lock().await.insert(
        1,
        VmIpAssignment {
            id: 1,
            vm_id: 7,
            ip: "127.0.0.1".into(),
            ..Default::default()
        },
    );
    let dyn_db: Arc<dyn LNVpsDb> = db.clone();
    let exec = DbToolExecutor::new(dyn_db, 1).with_escalation(Escalation::new(
        sink,
        "support@lnvps.net",
        "LNVPS <noreply@lnvps.net>",
    ));
    (exec, db.clone(), db)
}

const ARGS: &str = r#"{"reason":"VM disabled by staff","summary":"Customer cannot start VM 7","vm_ids":[7],"checked":["restart_vm: refused, disabled by staff"]}"#;

#[tokio::test]
async fn refused_without_a_user_id() {
    let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
    let sink = Arc::new(MailSinkMock::default());
    let exec = DbToolExecutor::public(db).with_escalation(Escalation::new(
        sink.clone(),
        "support@lnvps.net",
        "noreply@lnvps.net",
    ));
    let err = exec.execute("escalate_to_support", ARGS).await.unwrap_err();
    assert!(err.to_string().contains("needs an account"));
    assert!(sink.sent.lock().await.is_empty());
}

#[tokio::test]
async fn sends_one_mail_with_reply_to_reference_and_history() {
    let sink = Arc::new(MailSinkMock::default());
    let (exec, db, _) = stack(sink.clone(), "bob@example.com").await;
    let conv = db
        .upsert_agent_conversation("user:1", Some(1))
        .await
        .unwrap();
    db.append_agent_messages(
        conv.id,
        &[NewAgentMessage {
            role: AgentMessageRole::User,
            channel: AgentChannel::WebChat,
            content: Some(
                "my VM wont start. my password is hunter2 and nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
            ),
            tool_calls: None,
            tool_call_id: None,
        }],
    )
    .await
    .unwrap();

    let out = exec.execute("escalate_to_support", ARGS).await.unwrap();
    assert!(out.contains("\"sent\": true"));
    assert!(out.contains("support-1"));

    let sent = sink.sent.lock().await;
    assert_eq!(sent.len(), 1);
    let mail = &sent[0];
    assert_eq!(mail.to, "support@lnvps.net");
    assert_eq!(mail.reply_to, "bob@example.com");
    assert_eq!(mail.subject, "[Support] user 1: VM disabled by staff");
    assert_eq!(mail.message_id, "<support-1@lnvps.net>");
    assert!(mail.body.contains("Reference: support-1"));
    assert!(mail.body.contains("VMs: 7"));
    assert!(mail.body.contains("my VM wont start"));
    assert!(!mail.body.contains("hunter2"));
    assert!(!mail.body.contains("nsec1qqq"));

    let stored = db.get_agent_conversation(conv.id).await.unwrap();
    assert_eq!(stored.escalation_count, 1);
    assert!(stored.escalated_at.is_some());
    assert_eq!(stored.escalation_vm_ids.as_deref(), Some("7"));
}

#[tokio::test]
async fn second_call_within_24h_sends_nothing_unless_something_is_new() {
    let sink = Arc::new(MailSinkMock::default());
    let (exec, _, _) = stack(sink.clone(), "bob@example.com").await;
    exec.execute("escalate_to_support", ARGS).await.unwrap();

    let again = exec.execute("escalate_to_support", ARGS).await.unwrap();
    assert!(again.contains("\"already_escalated\": true"));
    assert!(again.contains("support-1"));
    assert_eq!(sink.sent.lock().await.len(), 1);

    let new_vm = r#"{"reason":"second VM too","summary":"VM 8 also down","vm_ids":[7,8]}"#;
    let out = exec.execute("escalate_to_support", new_vm).await.unwrap();
    assert!(out.contains("\"sent\": true"));
    let sent = sink.sent.lock().await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].references.as_deref(), Some("<support-1@lnvps.net>"));
}

#[tokio::test]
async fn window_expires_after_a_day() {
    let sink = Arc::new(MailSinkMock::default());
    let (exec, db, _) = stack(sink.clone(), "bob@example.com").await;
    exec.execute("escalate_to_support", ARGS).await.unwrap();
    db.agent_conversations
        .lock()
        .await
        .values_mut()
        .for_each(|c| c.escalated_at = Some(chrono::Utc::now() - chrono::Duration::hours(25)));
    exec.execute("escalate_to_support", ARGS).await.unwrap();
    assert_eq!(sink.sent.lock().await.len(), 2);
}

#[tokio::test]
async fn refuses_another_customers_vm_and_missing_email() {
    let sink = Arc::new(MailSinkMock::default());
    let (exec, _, _) = stack(sink.clone(), "bob@example.com").await;
    let err = exec
        .execute(
            "escalate_to_support",
            r#"{"reason":"x","summary":"y","vm_ids":[9]}"#,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not belong"));

    let (exec, _, _) = stack(sink.clone(), "").await;
    let err = exec.execute("escalate_to_support", ARGS).await.unwrap_err();
    assert!(err.to_string().contains("no email on file"));
    assert!(sink.sent.lock().await.is_empty());
}

#[tokio::test]
async fn a_failed_send_is_reported_and_not_recorded() {
    let sink = Arc::new(MailSinkMock {
        fail: true,
        ..Default::default()
    });
    let (exec, db, _) = stack(sink, "bob@example.com").await;
    let err = exec.execute("escalate_to_support", ARGS).await.unwrap_err();
    assert!(err.to_string().contains("was not sent"));
    assert!(!err.to_string().contains("smtp down"));
    let conv = db
        .upsert_agent_conversation("user:1", Some(1))
        .await
        .unwrap();
    assert_eq!(conv.escalation_count, 0);
}

#[tokio::test]
async fn disabled_without_a_configured_mail_path() {
    let db: Arc<dyn LNVpsDb> = Arc::new(MockDb::default());
    let err = DbToolExecutor::new(db, 1)
        .execute("escalate_to_support", ARGS)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not enabled"));
}

fn sse(delta: serde_json::Value) -> String {
    let body = serde_json::json!({
        "id": "c", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{ "index": 0, "delta": delta, "finish_reason": null }],
    });
    format!("data: {body}\n\n")
}

fn sse_response(chunks: Vec<String>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(
        format!("{}data: [DONE]\n\n", chunks.concat()).into_bytes(),
        "text/event-stream",
    )
}

/// Replay of the #864 conversation 763 shape: a staff-disabled VM that cannot
/// be restarted. Before, the prompt told the model to email support@ and the
/// customer retold everything. Now the live chat session offers the tool, the
/// prompt names it, and the call produces the email.
#[tokio::test]
async fn replay_disabled_vm_is_handed_to_support_by_the_tool_conv_763() {
    let server = MockServer::start().await;
    let call = |id: &str, name: &str, args: &str| {
        sse(
            serde_json::json!({"tool_calls": [{"index": 0, "id": id, "type": "function",
            "function": {"name": name, "arguments": args}}]}),
        )
    };
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(vec![call(
            "c1",
            "restart_vm",
            r#"{"vm_id":7}"#,
        )]))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(vec![call("c2", "escalate_to_support", ARGS)]))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(sse_response(vec![sse(serde_json::json!({
            "content": "I have emailed support, reference support-1. The reply will come to your account email."
        }))]))
        .mount(&server)
        .await;

    let sink = Arc::new(MailSinkMock::default());
    let (exec, db, _) = stack(sink.clone(), "bob@example.com").await;
    let store: Arc<dyn ConversationStore> = Arc::new(MemoryStore::new());
    let settings = Settings {
        listen: None,
        db: "mock".into(),
        encryption: None,
        nsec: "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5".into(),
        openai: OpenAiConfig {
            base_url: format!("{}/v1", server.uri()),
            api_key: Some("t".into()),
            model: "m".into(),
            max_tokens: Some(256),
        },
        system_prompt: None,
        email: None,
        kind1: None,
        conversation_history_path: None,
    };
    let dyn_db: Arc<dyn LNVpsDb> = db;
    let agent = SupportAgent::new(dyn_db, settings, store);
    let session = ChatSession::new(
        agent,
        &SenderIdentity::Pubkey("ab".repeat(32)),
        Requester::Customer {
            user_id: 1,
            account: serde_json::json!({"id": 1}),
        },
        Arc::new(exec),
    );
    let events = session
        .send("my VM 7 will not start")
        .collect::<Vec<_>>()
        .await;
    match events.last().unwrap() {
        ChatEvent::Final { text } => assert!(text.contains("support-1")),
        other => panic!("{other:?}"),
    }

    let sent = sink.sent.lock().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].reply_to, "bob@example.com");
    println!(
        "AFTER escalation mail:\n{}\n{}",
        sent[0].subject, sent[0].body
    );

    let requests = server.received_requests().await.unwrap();
    let first: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let system = first["messages"][0]["content"].as_str().unwrap();
    assert!(system.contains("escalate_to_support"));
    assert!(system.contains("instead of telling them to email support@lnvps.net"));
    let tools: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap())
        .collect();
    assert!(tools.contains(&"escalate_to_support"));
}
