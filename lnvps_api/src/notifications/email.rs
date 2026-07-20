//! Email (SMTP) notification channel.

use super::{Notification, NotificationChannel};
use crate::settings::SmtpConfig;
use async_trait::async_trait;
use chrono::{Datelike, Utc};
use lettre::message::{MessageBuilder, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use lnvps_api_common::retry::OpError;
use lnvps_db::User;
use std::time::Duration;

/// Send an email via SMTP using the HTML email template.
///
/// If `html_message` is provided, it will be used in the HTML template instead
/// of `plain_message`. Returns [`OpError::Fatal`] for permanent SMTP errors
/// (5xx) and [`OpError::Transient`] for temporary failures.
pub async fn send_email(
    smtp: &SmtpConfig,
    to: &str,
    subject: &str,
    plain_message: &str,
    html_message: Option<&str>,
) -> Result<(), OpError<anyhow::Error>> {
    send_email_with_reply_to(smtp, to, None, subject, plain_message, html_message).await
}

/// Send an email via SMTP, optionally setting a `Reply-To` header.
///
/// Behaves like [`send_email`] but additionally sets the `Reply-To` header to
/// `reply_to` when provided. This is useful for support/contact emails so
/// replies are directed at the original sender rather than the SMTP `from`
/// address.
pub async fn send_email_with_reply_to(
    smtp: &SmtpConfig,
    to: &str,
    reply_to: Option<&str>,
    subject: &str,
    plain_message: &str,
    html_message: Option<&str>,
) -> Result<(), OpError<anyhow::Error>> {
    #[derive(serde::Serialize)]
    struct EmailData {
        message: String,
        year: String,
    }
    let template = mustache::compile_str(include_str!("../../email.html"))
        .map_err(|e| OpError::Fatal(e.into()))?;
    let data = EmailData {
        message: html_message.unwrap_or(plain_message).to_string(),
        year: Utc::now().year().to_string(),
    };
    let rendered = template
        .render_to_string(&data)
        .map_err(|e| OpError::Fatal(e.into()))?;
    let html = MultiPart::alternative_plain_html(plain_message.to_string(), rendered);
    let mut b = MessageBuilder::new()
        .to(to
            .parse()
            .map_err(|e: lettre::address::AddressError| OpError::Fatal(e.into()))?)
        .subject(subject);
    if let Some(f) = &smtp.from {
        b = b.from(
            f.parse()
                .map_err(|e: lettre::address::AddressError| OpError::Fatal(e.into()))?,
        );
    }
    if let Some(rt) = reply_to {
        b = b.reply_to(
            rt.parse()
                .map_err(|e: lettre::address::AddressError| OpError::Fatal(e.into()))?,
        );
    }
    let msg = b.multipart(html).map_err(|e| OpError::Fatal(e.into()))?;
    let sender = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.server)
        .map_err(|e| OpError::Transient(e.into()))?
        .credentials(Credentials::new(
            smtp.username.to_string(),
            smtp.password.to_string(),
        ))
        .timeout(Some(Duration::from_secs(10)))
        .build();
    sender.send(msg).await.map_err(|e| {
        if e.is_permanent() {
            OpError::Fatal(e.into())
        } else {
            OpError::Transient(e.into())
        }
    })?;
    Ok(())
}

/// Delivers notifications to a user's verified email address via SMTP.
pub struct EmailChannel {
    smtp: SmtpConfig,
}

impl EmailChannel {
    pub fn new(smtp: SmtpConfig) -> Self {
        Self { smtp }
    }
}

#[async_trait]
impl NotificationChannel for EmailChannel {
    fn name(&self) -> &'static str {
        "email"
    }

    fn wants(&self, user: &User) -> bool {
        user.contact_email && !user.email.is_empty()
    }

    async fn send(
        &self,
        user: &User,
        notification: &Notification,
    ) -> Result<(), OpError<anyhow::Error>> {
        let to = user.email.as_str();
        send_email(
            &self.smtp,
            to,
            notification.subject(),
            &notification.message,
            notification.html.as_deref(),
        )
        .await
    }
}
