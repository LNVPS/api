//! Telegram (Bot API) notification channel.
//!
//! Sending is a simple `sendMessage` HTTP call. Account linking is handled
//! out-of-band by [`crate::notifications::telegram::TelegramBot`] which long-polls
//! `getUpdates` for `/start <token>` deep-link payloads.

use super::{Notification, NotificationChannel};
use anyhow::{Result, bail};
use async_trait::async_trait;
use lnvps_api_common::retry::OpError;
use lnvps_db::{LNVpsDb, User};
use log::{error, info, warn};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

/// Thin async client for the Telegram Bot API.
#[derive(Clone)]
pub struct TelegramClient {
    token: String,
    http: reqwest::Client,
}

impl TelegramClient {
    pub fn new(token: String, http: reqwest::Client) -> Self {
        Self { token, http }
    }

    fn method_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.token, method)
    }

    /// Send a plain-text message to a chat. Returns the parsed Telegram error
    /// (if any) so callers can decide transient vs permanent handling.
    pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<(), TelegramError> {
        let resp = self
            .http
            .post(self.method_url("sendMessage"))
            .json(&json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true,
            }))
            .send()
            .await
            .map_err(TelegramError::Http)?;

        let status = resp.status();
        let body: TgResponse<serde_json::Value> = resp.json().await.map_err(TelegramError::Http)?;
        if body.ok {
            return Ok(());
        }
        Err(TelegramError::Api {
            // 4xx (other than 429) are permanent (e.g. bot blocked, chat not found)
            permanent: status.is_client_error() && status.as_u16() != 429,
            code: body.error_code,
            description: body.description.unwrap_or_default(),
        })
    }

    /// Long-poll for updates. `offset` should be the last seen `update_id + 1`.
    pub async fn get_updates(&self, offset: i64, timeout_secs: u32) -> Result<Vec<TgUpdate>> {
        let resp = self
            .http
            .post(self.method_url("getUpdates"))
            .json(&json!({
                "offset": offset,
                "timeout": timeout_secs,
                "allowed_updates": ["message"],
            }))
            // allow the long-poll to block server-side; give a little headroom over `timeout`
            .timeout(std::time::Duration::from_secs(timeout_secs as u64 + 10))
            .send()
            .await?;
        let body: TgResponse<Vec<TgUpdate>> = resp.json().await?;
        if !body.ok {
            bail!(
                "telegram getUpdates failed: {} {}",
                body.error_code.unwrap_or_default(),
                body.description.unwrap_or_default()
            );
        }
        Ok(body.result.unwrap_or_default())
    }
}

/// Error returned by Telegram Bot API calls.
#[derive(Debug)]
pub enum TelegramError {
    Http(reqwest::Error),
    Api {
        permanent: bool,
        code: Option<i64>,
        description: String,
    },
}

impl std::fmt::Display for TelegramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TelegramError::Http(e) => write!(f, "http error: {}", e),
            TelegramError::Api {
                code, description, ..
            } => write!(
                f,
                "telegram api error {}: {}",
                code.unwrap_or_default(),
                description
            ),
        }
    }
}

impl std::error::Error for TelegramError {}

#[derive(Debug, Deserialize)]
struct TgResponse<T> {
    ok: bool,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    error_code: Option<i64>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TgUpdate {
    pub update_id: i64,
    pub message: Option<TgMessage>,
}

#[derive(Debug, Deserialize)]
pub struct TgMessage {
    pub chat: TgChat,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TgChat {
    pub id: i64,
}

/// Delivers notifications to a user's linked Telegram chat.
pub struct TelegramChannel {
    client: TelegramClient,
}

impl TelegramChannel {
    pub fn new(client: TelegramClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl NotificationChannel for TelegramChannel {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn wants(&self, user: &User) -> bool {
        user.contact_telegram && user.telegram_chat_id.is_some()
    }

    async fn send(
        &self,
        user: &User,
        notification: &Notification,
    ) -> Result<(), OpError<anyhow::Error>> {
        let Some(chat_id) = user.telegram_chat_id else {
            return Ok(());
        };
        // Telegram has no subject; prepend the title in bold-ish plain text.
        let text = match &notification.title {
            Some(t) if !t.is_empty() => format!("{}\n\n{}", t, notification.message),
            _ => notification.message.clone(),
        };
        match self.client.send_message(chat_id, &text).await {
            Ok(()) => Ok(()),
            Err(e @ TelegramError::Api { permanent: true, .. }) => {
                Err(OpError::Fatal(anyhow::Error::msg(e.to_string())))
            }
            Err(e) => Err(OpError::Transient(anyhow::Error::msg(e.to_string()))),
        }
    }
}

/// Long-polling Telegram bot that completes account linking.
///
/// Users start the bot with a deep link `https://t.me/<bot>?start=<token>`,
/// which delivers `/start <token>` as the first message. We map that one-time
/// token to the account and persist the chat id so notifications can be sent.
pub struct TelegramBot {
    client: TelegramClient,
    db: Arc<dyn LNVpsDb>,
}

impl TelegramBot {
    const POLL_TIMEOUT_SECS: u32 = 30;

    pub fn new(token: String, http: reqwest::Client, db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            client: TelegramClient::new(token, http),
            db,
        }
    }

    /// Run the long-poll loop forever. Errors are logged and retried with a
    /// short backoff so a transient API/network blip doesn't kill linking.
    pub async fn run(self) -> Result<()> {
        info!("Starting Telegram bot poller");
        let mut offset: i64 = 0;
        loop {
            match self
                .client
                .get_updates(offset, Self::POLL_TIMEOUT_SECS)
                .await
            {
                Ok(updates) => {
                    for update in updates {
                        offset = offset.max(update.update_id + 1);
                        if let Err(e) = self.handle_update(update).await {
                            warn!("Failed to handle telegram update: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("telegram getUpdates error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn handle_update(&self, update: TgUpdate) -> Result<()> {
        let Some(message) = update.message else {
            return Ok(());
        };
        let chat_id = message.chat.id;
        let text = message.text.unwrap_or_default();
        let text = text.trim();

        // Only the linking command is supported.
        let Some(rest) = text.strip_prefix("/start") else {
            return Ok(());
        };
        let token = rest.trim();
        if token.is_empty() {
            self.reply(
                chat_id,
                "👋 Welcome! To link your LNVPS account, open the link from your account settings page.",
            )
            .await;
            return Ok(());
        }

        match self.db.get_user_by_telegram_link_token(token).await {
            Ok(user) => {
                self.db.link_telegram_chat(user.id, chat_id).await?;
                info!("Linked telegram chat {} to user {}", chat_id, user.id);
                self.reply(
                    chat_id,
                    "✅ Your Telegram account is now linked. You'll receive LNVPS notifications here.",
                )
                .await;
            }
            Err(_) => {
                self.reply(
                    chat_id,
                    "⚠️ That link is invalid or has expired. Please generate a new link from your account settings.",
                )
                .await;
            }
        }
        Ok(())
    }

    async fn reply(&self, chat_id: i64, text: &str) {
        if let Err(e) = self.client.send_message(chat_id, text).await {
            warn!("Failed to send telegram reply to {}: {}", chat_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> TelegramChannel {
        TelegramChannel::new(TelegramClient::new("token".into(), reqwest::Client::new()))
    }

    #[test]
    fn wants_requires_optin_and_linked_chat() {
        let ch = channel();
        let mut user = User::default();

        // not opted in, not linked
        assert!(!ch.wants(&user));

        // opted in but no chat linked yet
        user.contact_telegram = true;
        assert!(!ch.wants(&user));

        // linked but opted out
        user.contact_telegram = false;
        user.telegram_chat_id = Some(42);
        assert!(!ch.wants(&user));

        // opted in and linked
        user.contact_telegram = true;
        assert!(ch.wants(&user));
    }
}
