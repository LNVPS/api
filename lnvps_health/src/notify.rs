use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

/// SMTP configuration for sending alert emails
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SmtpConfig {
    /// SMTP server hostname
    pub host: String,
    /// SMTP server port (default: 587 for STARTTLS)
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// SMTP username
    pub username: String,
    /// SMTP password
    pub password: String,
    /// Sender email address
    pub from: String,
    /// Recipient email addresses for alerts
    pub to: Vec<String>,
    /// Use STARTTLS (default: true)
    #[serde(default = "default_starttls")]
    pub starttls: bool,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_starttls() -> bool {
    true
}

/// Email notifier for sending health check alerts
pub struct EmailNotifier {
    config: SmtpConfig,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailNotifier {
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let mailer = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .context("Failed to create SMTP transport")?
                .port(config.port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .context("Failed to create SMTP transport")?
                .port(config.port)
                .credentials(creds)
                .build()
        };

        Ok(Self { config, mailer })
    }

    /// Send an alert email
    pub async fn send_alert(&self, subject: &str, body: &str) -> Result<()> {
        for recipient in &self.config.to {
            let email = Message::builder()
                .from(
                    self.config
                        .from
                        .parse()
                        .context("Invalid from address")?,
                )
                .to(recipient.parse().context("Invalid recipient address")?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())
                .context("Failed to build email")?;

            debug!("Sending alert email to {}", recipient);

            match self.mailer.send(email).await {
                Ok(_) => {
                    info!("Alert email sent to {}", recipient);
                }
                Err(e) => {
                    error!("Failed to send email to {}: {}", recipient, e);
                }
            }
        }

        Ok(())
    }
}

/// Trait for notification backends
#[async_trait::async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, title: &str, message: &str) -> Result<()>;
}

#[async_trait::async_trait]
impl Notifier for EmailNotifier {
    async fn send(&self, title: &str, message: &str) -> Result<()> {
        self.send_alert(title, message).await
    }
}

/// A notifier that does nothing (for when notifications are disabled)
pub struct NoopNotifier;

#[async_trait::async_trait]
impl Notifier for NoopNotifier {
    async fn send(&self, _title: &str, _message: &str) -> Result<()> {
        Ok(())
    }
}
