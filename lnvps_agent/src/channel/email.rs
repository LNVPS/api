use std::collections::HashSet;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::TryStreamExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::channel::{IncomingSupportRequest, SupportChannel, SupportReply};
use crate::identity::SenderIdentity;
use crate::settings::EmailConfig;

/// Email support channel that uses IMAP IDLE for push-based email notifications.
///
/// Keeps a persistent IMAP connection open and uses the IDLE command (RFC 2177)
/// to receive instant notifications when new messages arrive. Falls back to
/// reconnecting on errors.
///
/// Senders are identified by their `From` email address; resolving that to a
/// customer account is left to the agent.
pub struct EmailSupportChannel {
    config: EmailConfig,
    /// Receive end of the channel fed by the IDLE loop.
    rx: tokio::sync::Mutex<mpsc::Receiver<IncomingSupportRequest>>,
}

impl EmailSupportChannel {
    pub fn new(config: EmailConfig) -> Self {
        let (tx, rx) = mpsc::channel::<IncomingSupportRequest>(256);

        let cfg = config.clone();

        // Spawn a background task that maintains a persistent IMAP connection
        // and uses IDLE to wait for new messages.
        tokio::spawn(async move {
            run_idle_loop(cfg, tx).await;
        });

        Self {
            config,
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    async fn send_smtp_reply(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        in_reply_to: &str,
        references: &str,
    ) -> Result<()> {
        let from: Mailbox = if let Some(ref name) = self.config.smtp_from_name {
            format!("{} <{}>", name, self.config.smtp_from)
                .parse()
                .context("Invalid from address")?
        } else {
            self.config
                .smtp_from
                .parse()
                .context("Invalid from address")?
        };

        let to_addr: Mailbox = to.parse().context("Invalid to address")?;

        let mut builder = Message::builder()
            .from(from)
            .to(to_addr)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN);

        // Set threading headers for proper email client grouping
        if !in_reply_to.is_empty() {
            builder = builder.in_reply_to(in_reply_to.to_string());
        }
        if !references.is_empty() {
            builder = builder.references(references.to_string());
        }

        let email = builder
            .body(body.to_string())
            .context("Failed to build email message")?;

        // Parse host (strip :port if present — starttls_relay needs bare hostname)
        let (host, port) = parse_host_port(&self.config.smtp_server, 587)?;

        log::info!("Connecting SMTP to {}:{}...", host, port);
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .context("Failed to create SMTP transport")?
            .port(port)
            .credentials(Credentials::new(
                self.config.smtp_username.clone(),
                self.config.smtp_password.clone(),
            ))
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build();

        log::info!("Sending email to {} (subject: {})...", to, subject);
        mailer.send(email).await.context("SMTP send failed")?;

        log::info!("SMTP send successful");

        Ok(())
    }
}

#[async_trait]
impl SupportChannel for EmailSupportChannel {
    fn channel_prompt(&self) -> &str {
        r#"Format your responses like a professional email reply:
- Use a polite greeting (e.g. "Hello", "Hi")
- Use proper paragraphs with blank lines between them
- Do NOT use markdown formatting (no **, ##, -, bullet lists with asterisks)
- Use plain text only — email clients render plain text, not markdown
- For lists, use numbered items (1. 2. 3.) on separate lines
- End with a professional sign-off (e.g. "Best regards, LNVPS Support")
- Keep the tone professional but approachable
- Do NOT include a subject line or "From" header in the body — those are set in the email envelope
- If quoting the customer's question, use "> " prefix for the quote block"#
    }

    async fn next_request(&self) -> Option<IncomingSupportRequest> {
        self.rx.lock().await.recv().await
    }

    async fn send_reply(&self, reply: SupportReply) -> Result<()> {
        let ctx: serde_json::Value = reply
            .channel_context
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let from_email = ctx
            .get("from_email")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let original_subject = ctx
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("Support request");

        let in_reply_to = ctx.get("message_id").and_then(|v| v.as_str()).unwrap_or("");

        let references = ctx.get("references").and_then(|v| v.as_str()).unwrap_or("");

        let re_subject = if original_subject.starts_with("Re: ") {
            original_subject.to_string()
        } else {
            format!("Re: {}", original_subject)
        };

        self.send_smtp_reply(
            from_email,
            &re_subject,
            &reply.response,
            in_reply_to,
            references,
        )
        .await
    }
}

// ── IMAP IDLE loop ──────────────────────────────────────────────────

/// Persistent IMAP connection loop using IDLE for push notifications.
///
/// Connects, logs in, selects the mailbox, fetches any unseen messages,
/// then enters IDLE. When IDLE signals new mail, fetches and processes
/// the new messages, then re-enters IDLE. On any error, reconnects
/// after a short delay.
async fn run_idle_loop(config: EmailConfig, tx: mpsc::Sender<IncomingSupportRequest>) {
    let mut seen = HashSet::<String>::new();

    loop {
        match idle_session(&config, &tx, &mut seen).await {
            Ok(()) => {
                // idle_session returned normally — reconnect
                log::info!("IMAP IDLE session ended, reconnecting...");
            }
            Err(e) => {
                log::warn!("IMAP IDLE error (reconnecting in 30s): {:#}", e);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        }
    }
}

/// Run a single IMAP session: connect, login, select, process unseen, IDLE loop.
async fn idle_session(
    config: &EmailConfig,
    tx: &mpsc::Sender<IncomingSupportRequest>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    use tokio::time::{Duration, timeout};

    let t = Duration::from_secs(30);
    let (host, _port) = parse_host_port(&config.imap_server, 993)?;

    log::info!("IMAP connecting to {}...", config.imap_server);
    let tcp = timeout(t, TcpStream::connect(&config.imap_server))
        .await
        .context("TCP connect timed out")?
        .context("TCP connect failed")?;

    let tls_connector = native_tls::TlsConnector::builder()
        .build()
        .context("Failed to build TLS connector")?;
    let tls_connector = tokio_native_tls::TlsConnector::from(tls_connector);
    let tls_stream = timeout(t, tls_connector.connect(&host, tcp))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;

    let client = async_imap::Client::new(tls_stream);
    let mut session = timeout(
        t,
        client.login(&config.imap_username, &config.imap_password),
    )
    .await
    .context("IMAP login timed out")?
    .map_err(|(e, _)| anyhow::anyhow!("IMAP login failed: {}", e))?;
    log::info!("IMAP logged in as {}", config.imap_username);

    let mailbox = config.imap_mailbox.as_deref().unwrap_or("INBOX");
    timeout(t, session.select(mailbox))
        .await
        .context("IMAP select timed out")?
        .context("Failed to select IMAP mailbox")?;
    log::info!("IMAP selected '{}', fetching unseen...", mailbox);

    // Process any existing unseen messages
    fetch_and_process(&mut session, tx, seen).await?;

    // IDLE loop: wait for new mail, then fetch
    loop {
        log::debug!("Entering IDLE...");
        let mut handle = session.idle();
        timeout(t, handle.init())
            .await
            .context("IDLE init timed out")?
            .context("IDLE init failed")?;

        // Wait for new data (IDLE auto-reconnects every 29 min per RFC 2177)
        let (wait_fut, _stop) = handle.wait();
        let idle_result = timeout(Duration::from_secs(29 * 60), wait_fut).await;

        // Exit IDLE and get the session back
        session = timeout(t, handle.done())
            .await
            .context("IDLE done timed out")?
            .context("IDLE done failed")?;

        match idle_result {
            Ok(Ok(_resp)) => {
                log::debug!("IDLE returned new data, fetching...");
                fetch_and_process(&mut session, tx, seen).await?;
            }
            Ok(Err(e)) => {
                // IDLE error — reconnect
                return Err(anyhow::anyhow!("IDLE wait error: {}", e));
            }
            Err(_) => {
                // Timeout — re-enter IDLE (keepalive)
                log::debug!("IDLE timeout, re-entering...");
            }
        }
    }
}

/// Search for unseen messages, process them, and send to the channel.
async fn fetch_and_process(
    session: &mut async_imap::Session<tokio_native_tls::TlsStream<TcpStream>>,
    tx: &mpsc::Sender<IncomingSupportRequest>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    use tokio::time::{Duration, timeout};

    let t = Duration::from_secs(15);

    let unseen: Vec<String> = timeout(t, session.search("UNSEEN"))
        .await
        .context("IMAP search timed out")?
        .context("IMAP search failed")?
        .into_iter()
        .map(|seq: async_imap::types::Seq| seq.to_string())
        .collect();

    if unseen.is_empty() {
        return Ok(());
    }

    log::info!("Found {} unseen messages", unseen.len());
    let fetch_range = unseen.join(",");
    let messages: Vec<async_imap::types::Fetch> =
        timeout(t, session.fetch(&fetch_range, "(FLAGS UID RFC822)"))
            .await
            .context("IMAP fetch timed out")?
            .context("IMAP fetch failed")?
            .try_collect()
            .await
            .context("Failed to collect fetch results")?;

    for fetch in &messages {
        let Some(uid) = fetch.uid else { continue };
        let Some(body) = fetch.body() else { continue };
        let raw = match std::str::from_utf8(body) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let uid_str = uid.to_string();
        if seen.contains(&uid_str) {
            continue;
        }
        seen.insert(uid_str.clone());

        // Extract threading headers
        let from_email = extract_header(&raw, "from").and_then(|v| extract_email_addr(&v));
        let subject = extract_header(&raw, "subject").unwrap_or_default();
        let message_id = extract_header(&raw, "message-id").unwrap_or_default();
        let in_reply_to = extract_header(&raw, "in-reply-to").unwrap_or_default();
        let references = extract_header(&raw, "references").unwrap_or_default();

        let Some(ref from_email) = from_email else {
            log::warn!("Message UID {} has no From address, skipping", uid);
            session.store(uid_str, "+FLAGS (\\Seen)").await.ok();
            continue;
        };

        // Extract body text
        let body_text = raw
            .find("\r\n\r\n")
            .map(|p| &raw[p + 4..])
            .or_else(|| raw.find("\n\n").map(|p| &raw[p + 2..]))
            .unwrap_or("")
            .trim()
            .to_string();

        let message = if !subject.is_empty() && !body_text.starts_with(&subject) {
            format!("{}\n\n{}", subject, body_text)
        } else {
            body_text
        };

        log::info!("Email from {} (UID {})", from_email, uid);

        let reply_references = build_reply_references(&references, &message_id);

        let req = IncomingSupportRequest {
            sender: SenderIdentity::Email(from_email.clone()),
            message: message.trim().to_string(),
            channel_context: Some(
                serde_json::json!({
                    "uid": uid,
                    "from_email": from_email,
                    "subject": subject,
                    "message_id": message_id,
                    "in_reply_to": in_reply_to,
                    "references": reply_references,
                })
                .to_string(),
            ),
        };

        if tx.send(req).await.is_err() {
            // Channel closed — agent is shutting down
            return Ok(());
        }

        session.store(uid_str, "+FLAGS (\\Seen)").await.ok();
    }

    Ok(())
}

// ── Minimal RFC822 header parser ─────────────────────────────────────

/// Extract the first value of an RFC822 header (case-insensitive).
fn extract_header(raw: &str, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    for line in raw.lines() {
        // End of headers
        if line.is_empty() {
            break;
        }
        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            if key == name_lower {
                return Some(line[colon + 1..].trim().to_string());
            }
        }
    }
    None
}

/// Extract a bare email address from "Name <addr>" or "<addr>".
fn extract_email_addr(raw: &str) -> Option<String> {
    if let Some(open) = raw.find('<')
        && let Some(close) = raw.rfind('>')
    {
        return Some(raw[open + 1..close].trim().to_string());
    }
    let trimmed = raw.trim();
    if trimmed.contains('@') {
        return Some(trimmed.to_string());
    }
    None
}

/// Parse "host:port" into (host, port).
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(pos) = s.rfind(':') {
        let port: u16 = s[pos + 1..]
            .parse()
            .context("Invalid port number in server address")?;
        Ok((s[..pos].to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Build the References header for a reply by appending the original Message-ID
/// to the existing References chain.
///
/// RFC 2822 says References should contain the full chain of Message-IDs from
/// root to immediate parent, so email clients can reconstruct the thread tree.
fn build_reply_references(existing: &str, incoming_message_id: &str) -> String {
    let incoming = incoming_message_id.trim();
    if incoming.is_empty() {
        return existing.trim().to_string();
    }

    let existing = existing.trim();
    if existing.is_empty() {
        return incoming.to_string();
    }

    // Avoid duplicating if the ID is already in the chain
    if existing.contains(incoming) {
        return existing.to_string();
    }

    format!("{} {}", existing, incoming)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_reply_references_empty_existing() {
        assert_eq!(
            build_reply_references("", "<abc@example.com>"),
            "<abc@example.com>"
        );
    }

    #[test]
    fn build_reply_references_empty_incoming() {
        assert_eq!(
            build_reply_references("<old@example.com>", ""),
            "<old@example.com>"
        );
    }

    #[test]
    fn build_reply_references_appends() {
        assert_eq!(
            build_reply_references("<root@ex.com> <mid@ex.com>", "<new@ex.com>"),
            "<root@ex.com> <mid@ex.com> <new@ex.com>"
        );
    }

    #[test]
    fn build_reply_references_deduplicates() {
        let existing = "<a@ex.com> <b@ex.com>";
        assert_eq!(
            build_reply_references(existing, "<b@ex.com>"),
            "<a@ex.com> <b@ex.com>"
        );
    }

    #[test]
    fn extract_header_finds_subject() {
        let raw =
            "From: user@example.com\nSubject: My VM is down\nMessage-ID: <abc@ex.com>\n\nBody";
        assert_eq!(
            extract_header(raw, "subject"),
            Some("My VM is down".to_string())
        );
    }

    #[test]
    fn extract_header_case_insensitive() {
        let raw = "message-id: <test@ex.com>\n\nBody";
        assert_eq!(
            extract_header(raw, "Message-ID"),
            Some("<test@ex.com>".to_string())
        );
    }

    #[test]
    fn extract_email_addr_with_name() {
        assert_eq!(
            extract_email_addr("John Doe <john@example.com>"),
            Some("john@example.com".to_string())
        );
    }

    #[test]
    fn extract_email_addr_bare() {
        assert_eq!(
            extract_email_addr("john@example.com"),
            Some("john@example.com".to_string())
        );
    }

    #[test]
    fn parse_host_port_with_port() {
        let (host, port) = parse_host_port("smtp.example.com:465", 587).unwrap();
        assert_eq!(host, "smtp.example.com");
        assert_eq!(port, 465);
    }

    #[test]
    fn parse_host_port_default_port() {
        let (host, port) = parse_host_port("smtp.example.com", 587).unwrap();
        assert_eq!(host, "smtp.example.com");
        assert_eq!(port, 587);
    }
}
