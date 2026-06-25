//! WhatsApp (Meta Cloud API) notification channel.
//!
//! WhatsApp business-initiated messages must use pre-approved templates. Both
//! notifications and verification codes are delivered through configurable
//! templates that take a single body parameter `{{1}}`.

use super::{Notification, NotificationChannel};
use crate::settings::WhatsAppConfig;
use async_trait::async_trait;
use lnvps_api_common::retry::OpError;
use lnvps_db::User;
use serde::Deserialize;
use serde_json::json;

/// Thin async client for the WhatsApp Cloud API.
#[derive(Clone)]
pub struct WhatsAppClient {
    access_token: String,
    phone_number_id: String,
    api_version: String,
    http: reqwest::Client,
}

impl WhatsAppClient {
    pub fn new(config: &WhatsAppConfig, http: reqwest::Client) -> Self {
        Self {
            access_token: config.access_token.clone(),
            phone_number_id: config.phone_number_id.clone(),
            api_version: config.api_version.clone(),
            http,
        }
    }

    /// Send a template message with a single-body-parameter template.
    ///
    /// `to` is normalised to digits-only international format as required by the
    /// Cloud API. Returns [`WhatsAppError`] so callers can decide transient vs
    /// permanent handling.
    pub async fn send_template(
        &self,
        to: &str,
        template: &str,
        lang: &str,
        body_param: &str,
    ) -> Result<(), WhatsAppError> {
        let to = normalize_number(to);
        let url = format!(
            "https://graph.facebook.com/{}/{}/messages",
            self.api_version, self.phone_number_id
        );
        let payload = json!({
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": {
                "name": template,
                "language": { "code": lang },
                "components": [{
                    "type": "body",
                    "parameters": [{ "type": "text", "text": body_param }],
                }],
            },
        });

        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(WhatsAppError::Http)?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        // Try to surface the Graph API error detail.
        let body: GraphErrorResponse = resp.json().await.unwrap_or_default();
        let (code, message) = body
            .error
            .map(|e| (e.code, e.message))
            .unwrap_or((None, String::new()));
        Err(WhatsAppError::Api {
            // 4xx (other than 429) are permanent (invalid number, bad template, ...)
            permanent: status.is_client_error() && status.as_u16() != 429,
            code,
            message,
        })
    }
}

/// Normalise a phone number to the digits-only international form the Cloud API
/// expects (no `+`, spaces or punctuation).
pub fn normalize_number(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Error returned by WhatsApp Cloud API calls.
#[derive(Debug)]
pub enum WhatsAppError {
    Http(reqwest::Error),
    Api {
        permanent: bool,
        code: Option<i64>,
        message: String,
    },
}

impl std::fmt::Display for WhatsAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhatsAppError::Http(e) => write!(f, "http error: {}", e),
            WhatsAppError::Api { code, message, .. } => {
                write!(
                    f,
                    "whatsapp api error {}: {}",
                    code.unwrap_or_default(),
                    message
                )
            }
        }
    }
}

impl std::error::Error for WhatsAppError {}

#[derive(Debug, Default, Deserialize)]
struct GraphErrorResponse {
    #[serde(default)]
    error: Option<GraphError>,
}

#[derive(Debug, Deserialize)]
struct GraphError {
    #[serde(default)]
    code: Option<i64>,
    #[serde(default)]
    message: String,
}

/// Delivers notifications to a user's verified WhatsApp number.
pub struct WhatsAppChannel {
    client: WhatsAppClient,
    template: String,
    template_lang: String,
}

impl WhatsAppChannel {
    pub fn new(config: &WhatsAppConfig, http: reqwest::Client) -> Self {
        Self {
            client: WhatsAppClient::new(config, http),
            template: config.message_template.clone(),
            template_lang: config.message_template_lang.clone(),
        }
    }
}

#[async_trait]
impl NotificationChannel for WhatsAppChannel {
    fn name(&self) -> &'static str {
        "whatsapp"
    }

    fn wants(&self, user: &User) -> bool {
        user.contact_whatsapp && user.whatsapp_verified && user.whatsapp_number.is_some()
    }

    async fn send(
        &self,
        user: &User,
        notification: &Notification,
    ) -> Result<(), OpError<anyhow::Error>> {
        let Some(number) = user.whatsapp_number.as_deref() else {
            return Ok(());
        };
        // The template has a single body param; fold the title into the text.
        let text = match &notification.title {
            Some(t) if !t.is_empty() => format!("{}: {}", t, notification.message),
            _ => notification.message.clone(),
        };
        match self
            .client
            .send_template(number, &self.template, &self.template_lang, &text)
            .await
        {
            Ok(()) => Ok(()),
            Err(e @ WhatsAppError::Api { permanent: true, .. }) => {
                Err(OpError::Fatal(anyhow::Error::msg(e.to_string())))
            }
            Err(e) => Err(OpError::Transient(anyhow::Error::msg(e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> WhatsAppConfig {
        WhatsAppConfig {
            access_token: "token".into(),
            phone_number_id: "123".into(),
            api_version: "v21.0".into(),
            message_template: "notify".into(),
            message_template_lang: "en".into(),
            verify_template: "verify".into(),
            verify_template_lang: "en".into(),
        }
    }

    #[test]
    fn normalize_strips_non_digits() {
        assert_eq!(normalize_number("+1 (555) 123-4567"), "15551234567");
    }

    #[test]
    fn wants_requires_optin_verified_and_number() {
        let ch = WhatsAppChannel::new(&config(), reqwest::Client::new());
        let mut user = User::default();
        assert!(!ch.wants(&user));

        user.contact_whatsapp = true;
        assert!(!ch.wants(&user)); // no number / not verified

        user.whatsapp_number = Some("+15551234567".into());
        assert!(!ch.wants(&user)); // not verified

        user.whatsapp_verified = true;
        assert!(ch.wants(&user));

        user.contact_whatsapp = false;
        assert!(!ch.wants(&user)); // opted out
    }
}
