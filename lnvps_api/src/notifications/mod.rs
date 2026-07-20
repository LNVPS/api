//! Pluggable notification channels.
//!
//! A [`NotificationChannel`] knows how to decide whether a given user wants to
//! be contacted on that channel ([`NotificationChannel::wants`]) and how to
//! actually deliver a [`Notification`] ([`NotificationChannel::send`]).
//!
//! The worker holds a list of channels and, when dispatching a notification,
//! iterates every channel the user has opted into. New channels (Telegram,
//! WhatsApp, ...) can be added by implementing this trait and registering the
//! channel in [`build_channels`].

mod email;
mod nip17;
mod telegram;
mod whatsapp;

pub use email::{EmailChannel, send_email, send_email_with_reply_to};
pub use nip17::Nip17Channel;
pub use telegram::{TelegramBot, TelegramChannel, TelegramClient};
pub use whatsapp::{WhatsAppChannel, WhatsAppClient, normalize_number};

use crate::worker::WorkerSettings;
use async_trait::async_trait;
use lnvps_api_common::retry::OpError;
use lnvps_db::User;
use nostr_sdk::Client;
use std::sync::Arc;

/// A single notification to deliver to a user.
#[derive(Debug, Clone)]
pub struct Notification {
    /// Optional title/subject line.
    pub title: Option<String>,
    /// Plain-text message body.
    pub message: String,
    /// Optional HTML body for channels that support rich content (e.g. email).
    /// When `None`, channels fall back to [`Notification::message`].
    pub html: Option<String>,
}

impl Notification {
    pub fn new(title: Option<String>, message: String) -> Self {
        Self {
            title,
            message,
            html: None,
        }
    }

    /// Subject to use, falling back to a generic default.
    pub fn subject(&self) -> &str {
        self.title.as_deref().unwrap_or("Notification")
    }
}

/// A delivery channel for user notifications (email, NIP-17, Telegram, ...).
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Short channel name, used for logging.
    fn name(&self) -> &'static str;

    /// Whether this channel should be used for the given user, based on their
    /// contact preferences and the data required to reach them.
    fn wants(&self, user: &User) -> bool;

    /// Deliver the notification to the user.
    ///
    /// Returning [`OpError::Transient`] aborts the notification job so it can be
    /// retried; [`OpError::Fatal`] is logged and skipped (other channels still run).
    async fn send(
        &self,
        user: &User,
        notification: &Notification,
    ) -> Result<(), OpError<anyhow::Error>>;
}

/// Build the set of notification channels from the worker settings.
///
/// Channels are tried in registration order. A channel is only registered when
/// its backend is configured; per-user opt-in is checked later via
/// [`NotificationChannel::wants`].
pub fn build_channels(
    settings: &WorkerSettings,
    nostr: Option<&Client>,
    http: &reqwest::Client,
) -> Vec<Arc<dyn NotificationChannel>> {
    let mut channels: Vec<Arc<dyn NotificationChannel>> = Vec::new();

    if let Some(smtp) = settings.smtp.as_ref() {
        channels.push(Arc::new(EmailChannel::new(smtp.clone())));
    }

    if let Some(client) = nostr {
        channels.push(Arc::new(Nip17Channel::new(client.clone())));
    }

    if let Some(tg) = settings.telegram.as_ref() {
        let client = TelegramClient::new(tg.token.clone(), http.clone());
        channels.push(Arc::new(TelegramChannel::new(client)));
    }

    if let Some(wa) = settings.whatsapp.as_ref() {
        channels.push(Arc::new(WhatsAppChannel::new(wa, http.clone())));
    }

    channels
}
