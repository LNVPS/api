//! Handing a logged-in customer's chat to support by email.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use regex::Regex;

pub const DEFAULT_SUPPORT_EMAIL: &str = "support@lnvps.net";
pub const ESCALATION_WINDOW_HOURS: i64 = 24;
const MAX_SUBJECT_REASON: usize = 60;
const MAX_FIELD_CHARS: usize = 1500;
const MAX_MESSAGE_CHARS: usize = 600;
const MAX_CHECKED: usize = 12;
const RECENT_MESSAGES: usize = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct OutgoingMail {
    pub to: String,
    pub reply_to: String,
    pub subject: String,
    pub message_id: String,
    pub references: Option<String>,
    pub body: String,
}

#[async_trait]
pub trait MailSink: Send + Sync {
    async fn send(&self, mail: OutgoingMail) -> Result<()>;
}

pub struct SmtpMailSink {
    server: String,
    username: String,
    password: String,
    from: String,
}

impl SmtpMailSink {
    pub fn new(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        from: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            username: username.into(),
            password: password.into(),
            from: from.into(),
        }
    }
}

#[async_trait]
impl MailSink for SmtpMailSink {
    async fn send(&self, mail: OutgoingMail) -> Result<()> {
        let from: Mailbox = self.from.parse().context("Invalid from address")?;
        let mut builder = Message::builder()
            .from(from)
            .to(mail.to.parse().context("Invalid support address")?)
            .reply_to(mail.reply_to.parse().context("Invalid reply-to address")?)
            .subject(mail.subject)
            .message_id(Some(mail.message_id))
            .header(ContentType::TEXT_PLAIN);
        if let Some(references) = mail.references {
            builder = builder
                .in_reply_to(references.clone())
                .references(references);
        }
        let email = builder.body(mail.body).context("Failed to build email")?;
        let (host, port) = crate::channel::email::parse_host_port(&self.server, 587)?;
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .context("Failed to create SMTP transport")?
            .port(port)
            .credentials(Credentials::new(
                self.username.clone(),
                self.password.clone(),
            ))
            .timeout(Some(Duration::from_secs(30)))
            .build();
        mailer.send(email).await.context("SMTP send failed")?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Escalation {
    pub sink: Arc<dyn MailSink>,
    pub support_email: String,
    pub from_domain: String,
}

impl Escalation {
    pub fn new(sink: Arc<dyn MailSink>, support_email: impl Into<String>, from: &str) -> Self {
        Self {
            sink,
            support_email: support_email.into(),
            from_domain: domain_of(from).unwrap_or("lnvps.net").to_string(),
        }
    }

    pub fn reference(&self, conversation_id: u64) -> String {
        format!("support-{conversation_id}")
    }

    pub fn thread_root(&self, conversation_id: u64) -> String {
        format!("<support-{conversation_id}@{}>", self.from_domain)
    }

    pub fn build(&self, req: &EscalationRequest) -> OutgoingMail {
        let first = req.previous_count == 0;
        let message_id = if first {
            self.thread_root(req.conversation_id)
        } else {
            format!(
                "<support-{}-{}@{}>",
                req.conversation_id, req.previous_count, self.from_domain
            )
        };
        OutgoingMail {
            to: self.support_email.clone(),
            reply_to: req.customer_email.clone(),
            subject: format!(
                "[Support] user {}: {}",
                req.user_id,
                short_reason(&req.reason)
            ),
            message_id,
            references: (!first).then(|| self.thread_root(req.conversation_id)),
            body: self.body(req),
        }
    }

    fn body(&self, req: &EscalationRequest) -> String {
        let vms = if req.vm_ids.is_empty() {
            "none named".to_string()
        } else {
            req.vm_ids
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut out = format!(
            "Escalated by the LNVPS support agent. Reply to this email to answer the customer.\n\n\
             Reference: {}\nAccount: {}\nCustomer email on file: {} (verified: {})\nVMs: {}\n\n\
             Reason: {}\n\nSummary:\n{}\n",
            self.reference(req.conversation_id),
            req.user_id,
            req.customer_email,
            if req.email_verified { "yes" } else { "no" },
            vms,
            redact(&req.reason),
            clip(&redact(&req.summary), MAX_FIELD_CHARS),
        );
        if !req.checked.is_empty() {
            out.push_str("\nAlready checked:\n");
            for item in req.checked.iter().take(MAX_CHECKED) {
                out.push_str(&format!("- {}\n", clip(&redact(item), 300)));
            }
        }
        if !req.recent_customer_messages.is_empty() {
            out.push_str("\nLast customer messages (oldest first):\n");
            for message in &req.recent_customer_messages {
                out.push_str(&format!("> {}\n", clip(&redact(message), MAX_MESSAGE_CHARS)));
            }
        }
        out
    }
}

pub struct EscalationRequest {
    pub conversation_id: u64,
    pub previous_count: u64,
    pub user_id: u64,
    pub customer_email: String,
    pub email_verified: bool,
    pub vm_ids: Vec<u64>,
    pub reason: String,
    pub summary: String,
    pub checked: Vec<String>,
    pub recent_customer_messages: Vec<String>,
}

pub fn recent_messages_limit() -> usize {
    RECENT_MESSAGES
}

pub fn within_window(escalated_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    escalated_at
        .map(|at| now - at < chrono::Duration::hours(ESCALATION_WINDOW_HOURS))
        .unwrap_or(false)
}

fn domain_of(address: &str) -> Option<&str> {
    let tail = address.rsplit('@').next()?;
    let tail = tail.trim_end_matches('>').trim();
    (!tail.is_empty() && tail != address.trim()).then_some(tail)
}

fn short_reason(reason: &str) -> String {
    let single: String = reason
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    clip(&redact(&single), MAX_SUBJECT_REASON)
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push_str("...");
    out
}

fn secret_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let p = |re: &str, rep: &'static str| (Regex::new(re).expect("valid regex"), rep);
        vec![
            p(
                r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
                "[private key removed]",
            ),
            p(r"\bnsec1[0-9a-z]{20,}", "[nostr secret removed]"),
            p(r"\blnvps_[A-Za-z0-9_\-]{12,}", "[api token removed]"),
            p(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}", "Bearer [removed]"),
            p(
                r"(?i)\b(password|passwd|passphrase|secret|token|seed(?: phrase)?)\s*(?:is|:|=)\s*\S+(?:\s+\S+){0,23}",
                "$1: [removed]",
            ),
            p(r"\b[0-9a-fA-F]{64}\b", "[hex secret removed]"),
        ]
    })
}

pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for (re, rep) in secret_patterns() {
        out = re.replace_all(&out, *rep).into_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    #[derive(Default)]
    pub struct SinkRecorder {
        pub sent: Mutex<Vec<OutgoingMail>>,
    }

    #[async_trait]
    impl MailSink for SinkRecorder {
        async fn send(&self, mail: OutgoingMail) -> Result<()> {
            self.sent.lock().await.push(mail);
            Ok(())
        }
    }

    fn escalation() -> Escalation {
        Escalation::new(
            Arc::new(SinkRecorder::default()),
            DEFAULT_SUPPORT_EMAIL,
            "LNVPS <noreply@lnvps.net>",
        )
    }

    fn request(previous_count: u64) -> EscalationRequest {
        EscalationRequest {
            conversation_id: 12,
            previous_count,
            user_id: 42,
            customer_email: "bob@example.com".into(),
            email_verified: true,
            vm_ids: vec![7],
            reason: "VM disabled\nby staff".into(),
            summary: "Customer cannot start VM 7".into(),
            checked: vec!["get_vm_details: disabled".into()],
            recent_customer_messages: vec!["please help".into()],
        }
    }

    #[test]
    fn first_mail_has_reply_to_reference_and_subject() {
        let mail = escalation().build(&request(0));
        assert_eq!(mail.to, "support@lnvps.net");
        assert_eq!(mail.reply_to, "bob@example.com");
        assert_eq!(mail.subject, "[Support] user 42: VM disabled by staff");
        assert_eq!(mail.message_id, "<support-12@lnvps.net>");
        assert_eq!(mail.references, None);
        assert!(mail.body.contains("Reference: support-12"));
        assert!(mail.body.contains("Account: 42"));
        assert!(mail.body.contains("VMs: 7"));
        assert!(mail.body.contains("> please help"));
    }

    #[test]
    fn later_mail_threads_under_the_first() {
        let mail = escalation().build(&request(1));
        assert_eq!(mail.references.as_deref(), Some("<support-12@lnvps.net>"));
        assert_ne!(mail.message_id, "<support-12@lnvps.net>");
    }

    #[test]
    fn secrets_are_removed_everywhere() {
        let mut req = request(0);
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3Nza\n-----END OPENSSH PRIVATE KEY-----";
        req.summary = format!("they pasted {key} and password: hunter2 here");
        req.recent_customer_messages = vec![
            format!("my key {key}"),
            "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
            format!("hex {}", "ab".repeat(32)),
            "token=lnvps_abcdefghijklmnop".into(),
        ];
        req.reason = "password: hunter2".into();
        let mail = escalation().build(&req);
        let all = format!("{} {}", mail.subject, mail.body);
        for leaked in ["AAAAB3Nza", "hunter2", "nsec1qqq", "abab", "lnvps_abcdef"] {
            assert!(!all.contains(leaked), "{leaked} leaked: {all}");
        }
    }

    #[test]
    fn window_logic() {
        let now = Utc::now();
        assert!(!within_window(None, now));
        assert!(within_window(Some(now - chrono::Duration::hours(2)), now));
        assert!(!within_window(Some(now - chrono::Duration::hours(25)), now));
    }

    #[test]
    fn domain_comes_from_the_from_address() {
        assert_eq!(domain_of("A <a@example.org>"), Some("example.org"));
        assert_eq!(domain_of("nodomain"), None);
    }

    #[test]
    fn long_reason_is_clipped_in_the_subject() {
        let mail = escalation().build(&EscalationRequest {
            reason: "x".repeat(300),
            ..request(0)
        });
        assert!(mail.subject.chars().count() < 100);
        assert_eq!(recent_messages_limit(), 5);
        assert_eq!(escalation().reference(3), "support-3");
    }
}
