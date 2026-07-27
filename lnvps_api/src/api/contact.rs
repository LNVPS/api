use crate::api::RouterState;
use crate::notifications::send_email_with_reply_to;
use crate::settings::CaptchaConfig;
use anyhow::Result;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use lnvps_api_common::{ApiData, ApiResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct ContactFormRequest {
    subject: String,
    message: String,
    email: String,
    name: String,
    user_pubkey: Option<String>,
    timestamp: String,
    turnstile_token: String,
}

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/v1/contact", post(v1_submit_contact_form))
}

/// Verify Cloudflare Turnstile token
async fn verify_turnstile(token: &str, secret_key: &str) -> Result<bool> {
    #[derive(Serialize)]
    struct TurnstileRequest {
        secret: String,
        response: String,
    }

    #[derive(Deserialize)]
    struct TurnstileResponse {
        success: bool,
    }

    let client = reqwest::Client::new();
    let response = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&TurnstileRequest {
            secret: secret_key.to_string(),
            response: token.to_string(),
        })
        .send()
        .await?;

    let result: TurnstileResponse = response.json().await?;
    Ok(result.success)
}

/// Submit contact form
///
/// This endpoint accepts contact form submissions and sends them to the admin.
/// Requires a valid Cloudflare Turnstile token.
async fn v1_submit_contact_form(
    State(state): State<RouterState>,
    Json(req): Json<ContactFormRequest>,
) -> ApiResult<()> {
    // Validate required fields
    if req.subject.trim().is_empty() {
        return ApiData::err("Subject is required");
    }
    if req.message.trim().is_empty() {
        return ApiData::err("Message is required");
    }
    if req.name.trim().is_empty() {
        return ApiData::err("Name is required");
    }
    if req.email.trim().is_empty() {
        return ApiData::err("Email is required");
    }

    // Basic email validation
    if !req.email.contains('@') || !req.email.contains('.') {
        return ApiData::err("Invalid email address");
    }

    // Verify Turnstile token
    match &state.settings.captcha {
        Some(CaptchaConfig::Turnstile { secret_key }) => {
            match verify_turnstile(&req.turnstile_token, secret_key).await {
                Ok(true) => {
                    // Verification successful, continue
                }
                Ok(false) => {
                    return ApiData::err("Captcha verification failed");
                }
                Err(e) => {
                    log::error!("Failed to verify Turnstile token: {}", e);
                    return ApiData::err("Failed to verify captcha");
                }
            }
        }
        None => {
            return ApiData::err("Captcha not configured");
        }
    }

    // Format the message for the support inbox
    let support_message = format!(
        "New Contact Form Submission\n\
        \n\
        Name: {}\n\
        Email: {}\n\
        User Pubkey: {}\n\
        Timestamp: {}\n\
        \n\
        Subject: {}\n\
        \n\
        Message:\n\
        {}\n\
        \n\
        ---\n\
        Reply to: {}",
        req.name,
        req.email,
        req.user_pubkey.as_deref().unwrap_or("N/A"),
        req.timestamp,
        req.subject,
        req.message,
        req.email
    );

    // Deliver the support email to the company's support inbox. The sender's
    // email is set as the Reply-To header (with their name) so replies go
    // straight back to them.
    let Some(smtp) = &state.settings.smtp else {
        log::error!("Cannot send contact form: SMTP is not configured");
        return ApiData::err("Contact form is not available");
    };
    let support_email = match state.db.list_companies().await {
        Ok(companies) => companies.into_iter().find_map(|c| c.email),
        Err(e) => {
            log::error!("Failed to load company for contact form: {}", e);
            None
        }
    };
    let Some(support_email) = support_email else {
        log::error!("Cannot send contact form: no company email configured");
        return ApiData::err("Contact form is not available");
    };

    // Sanitize header-bound values: lettre rejects CRLF in addresses, but the
    // display name and subject are attacker-controlled text placed into a mail
    // that leaves our infrastructure with valid DKIM/SPF. Strip control chars
    // so a submission can't inject extra headers or spoof the thread, and cap
    // the subject length. The sender's address goes in the Reply-To (no user
    // display name) so replies reach them without lending our From-domain's
    // credibility to an attacker-chosen identity.
    let safe_name = sanitize_header_value(&req.name);
    let safe_subject: String = sanitize_header_value(&req.subject)
        .chars()
        .take(200)
        .collect();
    let reply_to = format!("{} <{}>", safe_name, req.email.trim());
    if let Err(e) = send_email_with_reply_to(
        smtp,
        &support_email,
        Some(&reply_to),
        &format!("Contact Form: {}", safe_subject),
        &support_message,
        None,
    )
    .await
    {
        log::error!("Failed to send contact form email: {}", e);
        return ApiData::err("Failed to send message");
    }

    ApiData::ok(())
}

/// Strip control characters (CR/LF/NUL etc.) from a value destined for an
/// email header, preventing header injection and collapsing odd whitespace.
fn sanitize_header_value(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_header_value_strips_crlf_and_control_chars() {
        assert_eq!(
            sanitize_header_value("Evil\r\nBcc: victim@example.com\0"),
            "EvilBcc: victim@example.com"
        );
    }

    #[test]
    fn sanitize_header_value_trims_and_keeps_normal_text() {
        assert_eq!(sanitize_header_value("  Alice Example  "), "Alice Example");
        assert_eq!(
            sanitize_header_value("Invoice #42 (urgent)"),
            "Invoice #42 (urgent)"
        );
    }
}
