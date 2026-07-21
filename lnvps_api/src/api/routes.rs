use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::response::{Html, IntoResponse};
use axum::routing::{any, delete, get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Utc};
use futures::future::join_all;
use isocountry::CountryCode;
use lnurl::pay::{LnURLPayInvoice, PayResponse};
use lnurl::{LnUrlResponse, Tag};
use log::{error, info};
use nostr_sdk::{ToBech32, Url};
use payments_rs::currency::CurrencyAmount;
use serde::Serialize;
use ssh_key::PublicKey;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::str::FromStr;

use lnvps_api_common::retry::{OpError, Pipeline, RetryPolicy};
use lnvps_api_common::{
    ApiCurrency, ApiData, ApiError, ApiResult, ApiUserSshKey, ApiVmOsImage,
    ApiVmTemplate, ClientIp, Nip98Auth, PageQuery, TraderDetails, UpgradeConfig, VatClient,
    WorkJob,
};
use lnvps_db::{
    LNVpsDb, PaymentMethod, Vm, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
    VmHostRegion,
};

use crate::api::model::{
    AccountPatchRequest, AccountPatchResult, AccountTaxInfo, AddNwcPaymentMethodRequest,
    ApiCompany, ApiCustomTemplateParams, ApiCustomVmOrder, ApiCustomVmPrice, ApiCustomVmRequest,
    ApiInvoiceItem,
    ApiPaymentInfo, ApiPaymentMethod, ApiTemplatesResponse, ApiVmFirewallPolicy, ApiVmFirewallRule,
    ApiVmHistory, ApiVmPayment, ApiVmStatus, ApiVmUpgradeQuote, ApiVmUpgradeRequest, CreateSshKey,
    CreateVmFirewallRule, CreateVmRequest, PatchPaymentMethodRequest, PatchVmFirewallPolicy,
    PatchVmFirewallRule, PaymentMethodResponse, VMPatchRequest, validate_firewall_cidr,
    validate_firewall_ports, vm_to_status,
};
use crate::api::{AmountQuery, AuthQuery, PaymentMethodQuery, RouterState};
use crate::host::{FullVmInfo, TimeSeries, TimeSeriesData, get_host_client};
use crate::provisioner::{HostCapacityService, PricingEngine};

pub fn routes() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/account",
            get(v1_get_account).patch(v1_patch_account),
        )
        .route("/api/v1/account/verify-email", get(v1_verify_email))
        .route(
            "/api/v1/payment-methods",
            get(v1_list_payment_methods).post(v1_add_nwc_payment_method),
        )
        .route(
            "/api/v1/payment-methods/{id}",
            patch(v1_patch_payment_method).delete(v1_delete_payment_method),
        )
        .route(
            "/api/v1/account/telegram/link",
            post(v1_telegram_link).delete(v1_telegram_unlink),
        )
        .route(
            "/api/v1/account/whatsapp/verify",
            post(v1_whatsapp_verify).delete(v1_whatsapp_unlink),
        )
        .route(
            "/api/v1/account/whatsapp/confirm",
            post(v1_whatsapp_confirm),
        )
        .route(
            "/api/v1/notification/channels",
            get(v1_notification_channels),
        )
        .route("/api/v1/vm", get(v1_list_vms))
        .route("/api/v1/vm/{id}", get(v1_get_vm).patch(v1_patch_vm))
        .route("/api/v1/image", get(v1_list_vm_images))
        .route("/api/v1/vm/templates", get(v1_list_vm_templates))
        .route(
            "/api/v1/vm/custom-template/price",
            post(v1_custom_template_calc),
        )
        .route(
            "/api/v1/vm/custom-template",
            post(v1_create_custom_vm_order),
        )
        .route(
            "/api/v1/ssh-key",
            get(v1_list_ssh_keys).post(v1_add_ssh_key),
        )
        .route("/api/v1/ssh-key/{id}", delete(v1_delete_ssh_key))
        .route("/api/v1/vm", post(v1_create_vm_order))
        .route("/api/v1/vm/{id}/renew", get(v1_renew_vm))
        .route("/api/v1/vm/{id}/renew-lnurlp", get(v1_renew_vm_lnurlp))
        .route("/.well-known/lnurlp/{id}", get(v1_lnurlp))
        .route("/api/v1/vm/{id}/start", patch(v1_start_vm))
        .route("/api/v1/vm/{id}/stop", patch(v1_stop_vm))
        .route("/api/v1/vm/{id}/restart", patch(v1_restart_vm))
        .route("/api/v1/vm/{id}/re-install", patch(v1_reinstall_vm))
        .route("/api/v1/vm/{id}/time-series", get(v1_time_series))
        .route(
            "/api/v1/vm/{id}/console",
            any(
                async move |ws: WebSocketUpgrade,
                            Path(id): Path<u64>,
                            Query(q): Query<AuthQuery>,
                            State(this): State<RouterState>| {
                    ws.on_upgrade(async move |s| {
                        if let Err(e) = v1_terminal_proxy(id, q.auth, this, s).await {
                            error!("Failed to proxy terminal proxy: {}", e);
                        }
                    })
                },
            ),
        )
        .route("/api/v1/payment/methods", get(v1_get_payment_methods))
        .route("/api/v1/payment/{id}", get(v1_get_payment))
        .route("/api/v1/payment/{id}/invoice", get(v1_get_payment_invoice))
        .route("/api/v1/vm/{id}/payments", get(v1_payment_history))
        .route("/api/v1/vm/{id}/history", get(v1_get_vm_history))
        .route("/api/v1/vm/{id}/upgrade/quote", post(v1_vm_upgrade_quote))
        .route("/api/v1/vm/{id}/upgrade", post(v1_vm_upgrade))
        .route(
            "/api/v1/vm/{id}/firewall",
            get(v1_list_firewall_rules).post(v1_create_firewall_rule),
        )
        .route(
            "/api/v1/vm/{id}/firewall/policy",
            get(v1_get_firewall_policy).patch(v1_patch_firewall_policy),
        )
        .route(
            "/api/v1/vm/{id}/firewall/{rule_id}",
            patch(v1_patch_firewall_rule).delete(v1_delete_firewall_rule),
        )
}

/// Capture IP-derived geolocation for a user as an independent place-of-supply
/// evidence signal for EU VAT. Best-effort: never blocks or fails the caller.
///
/// Invoked on every path where a user acts (account edits *and* VM orders) so
/// that a customer who never touches the account API still has a resolved
/// country recorded at purchase time.
async fn capture_client_geo(this: &RouterState, uid: u64, client_ip: ClientIp) {
    if let (Some(ip), Some(geoip)) = (client_ip.0, this.geoip.as_ref()) {
        let country = geoip.resolve(ip);
        if let Err(e) = this
            .db
            .set_user_geo(uid, country.as_deref(), &ip.to_string())
            .await
        {
            error!("Failed to store geolocation for user {}: {}", uid, e);
        }
    }
}

/// Update user account
async fn v1_patch_account(
    auth: Nip98Auth,
    client_ip: ClientIp,
    State(this): State<RouterState>,
    req: Json<AccountPatchRequest>,
) -> ApiResult<AccountPatchResult> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    capture_client_geo(&this, uid, client_ip).await;

    // validate and handle email change
    let mut pending_verification: Option<String> = None;
    if let Some(new_email_opt) = &req.email {
        if let Some(new_email) = new_email_opt {
            // Validate email format
            if new_email.trim().is_empty() {
                return ApiData::err("Email address cannot be empty");
            }
            if !new_email.contains('@') || !new_email.contains('.') {
                return ApiData::err("Invalid email address");
            }
            // Check if email is changing
            let old_email = user.email.as_str().to_string();
            let email_changed = old_email != new_email.as_str();
            user.email = new_email.clone().into();
            if email_changed {
                // Mark email as unverified and generate a verification token
                let token = hex::encode(rand::random::<[u8; 32]>());
                user.email_verified = false;
                user.email_verify_token = token.clone();
                pending_verification = Some(token);
            } else if !user.email_verified && user.email_verify_token.is_empty() {
                // Email is the same but was never verified and no token exists
                // Generate a new token and send verification email
                let token = hex::encode(rand::random::<[u8; 32]>());
                user.email_verify_token = token.clone();
                pending_verification = Some(token);
            }
        } else {
            return ApiData::err("Email address is required and cannot be removed");
        }
    }

    // If contact_email is enabled, email must be set
    if req.contact_email && user.email.is_empty() {
        return ApiData::err("An email address is required to enable email notifications");
    }

    // Telegram notifications require a linked chat
    if req.contact_telegram && user.telegram_chat_id.is_none() {
        return ApiData::err("Link your Telegram account before enabling Telegram notifications");
    }

    // WhatsApp notifications require a verified number
    if req.contact_whatsapp && !user.whatsapp_verified {
        return ApiData::err("Verify your WhatsApp number before enabling WhatsApp notifications");
    }

    // NIP-17 DMs require a real Nostr key; OAuth accounts have a synthetic pubkey.
    if req.contact_nip17 && user.account_type != lnvps_db::AccountType::Nostr {
        return ApiData::err("Nostr DM notifications are only available for Nostr accounts");
    }

    user.contact_nip17 = req.contact_nip17;
    user.contact_email = req.contact_email;
    user.contact_telegram = req.contact_telegram;
    user.contact_whatsapp = req.contact_whatsapp;
    if let Some(country_code) = &req.country_code {
        user.country_code = country_code
            .as_ref()
            .and_then(|c| CountryCode::for_alpha3(c).ok())
            .map(|c| c.alpha3().to_string());
    }
    if let Some(name) = &req.name {
        user.billing_name = name.clone();
    }
    if let Some(address_1) = &req.address_1 {
        user.billing_address_1 = address_1.clone();
    }
    if let Some(address_2) = &req.address_2 {
        user.billing_address_2 = address_2.clone();
    }
    if let Some(city) = &req.city {
        user.billing_city = city.clone();
    }
    if let Some(state) = &req.state {
        user.billing_state = state.clone();
    }
    if let Some(postcode) = &req.postcode {
        user.billing_postcode = postcode.clone();
    }
    if let Some(tax_id) = &req.tax_id {
        user.billing_tax_id = tax_id.clone();
    }

    // Validate the tax ID (VAT number) against VIES when one is set, and ask
    // VIES to match the customer's billing name/address against the registered
    // values. An invalid VAT number is a hard error; name/address mismatches are
    // surfaced as non-fatal warnings so the account is still saved.
    let mut warnings: Vec<String> = Vec::new();
    if let Some(tax_id) = user
        .billing_tax_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let trader = TraderDetails {
            name: user.billing_name.clone(),
            street: match (&user.billing_address_1, &user.billing_address_2) {
                (Some(a1), Some(a2)) if !a2.trim().is_empty() => Some(format!("{} {}", a1, a2)),
                (Some(a1), _) => Some(a1.clone()),
                (None, Some(a2)) => Some(a2.clone()),
                _ => None,
            },
            postal_code: user.billing_postcode.clone(),
            city: user.billing_city.clone(),
            company_type: None,
        };
        let result = VatClient::new()
            .validate_vat_number_with_trader(tax_id, None, Some(&trader))
            .await
            .map_err(|e| ApiError::bad_request(format!("Failed to validate tax ID: {}", e)))?;
        if !result.valid {
            return ApiData::err("Invalid tax ID");
        }
        let mismatches = result.mismatched_fields();
        if !mismatches.is_empty() {
            warnings.push(format!(
                "The following billing details do not match the VAT registration: {}",
                mismatches.join(", ")
            ));
        }
    }

    this.db.update_user(&user).await?;

    // Queue verification email after successful save
    if let Some(token) = pending_verification {
        let verify_url = format!(
            "{}/api/v1/account/verify-email?token={}",
            this.settings.public_url, token
        );
        if let Err(e) = this
            .work_sender
            .send(WorkJob::SendEmailVerification {
                user_id: uid,
                verify_url,
            })
            .await
        {
            error!("Failed to queue email verification: {}", e);
        }
    }

    ApiData::ok(AccountPatchResult { warnings })
}

#[derive(serde::Serialize)]
struct VerifyEmailPage {
    title: String,
    message: String,
    color: String,
}

/// Verify email address using the token sent to the user's email
async fn v1_verify_email(
    State(this): State<RouterState>,
    Query(params): Query<VerifyEmailQuery>,
) -> impl IntoResponse {
    let make_page = |title: &str, message: &str, color: &str| {
        let template = mustache::compile_str(include_str!("../../verify-email.html"))
            .expect("valid verify-email template");
        let data = VerifyEmailPage {
            title: title.to_string(),
            message: message.to_string(),
            color: color.to_string(),
        };
        let rendered = template
            .render_to_string(&data)
            .unwrap_or_else(|_| format!("<h1>{title}</h1><p>{message}</p>"));
        Html(rendered)
    };

    if params.token.trim().is_empty() {
        return make_page(
            "Invalid Link",
            "The verification link is missing a token.",
            "#e74c3c",
        );
    }
    let mut user = match this.db.get_user_by_email_verify_token(&params.token).await {
        Ok(u) => u,
        Err(_) => {
            return make_page(
                "Invalid or Expired Link",
                "This verification link is invalid or has already been used.",
                "#e74c3c",
            );
        }
    };
    user.email_verified = true;
    user.email_verify_token = String::new();
    if let Err(e) = this.db.update_user(&user).await {
        error!("Failed to mark email verified: {}", e);
        return make_page(
            "Error",
            "An error occurred. Please try again later.",
            "#e74c3c",
        );
    }
    make_page(
        "Email Verified",
        "Your email address has been successfully verified.",
        "#2ecc71",
    )
}

#[derive(serde::Deserialize)]
struct VerifyEmailQuery {
    token: String,
}

/// Get user account detail
async fn v1_get_account(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<AccountPatchRequest> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let user = this.db.get_user(uid).await?;
    let mut rsp: AccountPatchRequest = user.into();
    rsp.tax = Some(
        build_account_tax_info(this.db.as_ref(), &this.sub_handler.pricing_engine(), uid).await,
    );
    ApiData::ok(rsp)
}

/// Determine the tax (VAT) that would currently be charged to a user for each
/// seller company, so the frontend can show the expected tax rate up-front.
/// Companies whose determination fails are skipped (best effort).
async fn build_account_tax_info(
    db: &dyn LNVpsDb,
    pricing: &PricingEngine,
    uid: u64,
) -> Vec<AccountTaxInfo> {
    let companies = db.list_companies().await.unwrap_or_default();
    let mut out = Vec::with_capacity(companies.len());
    for company in companies {
        if let Ok(d) = pricing.determine_tax(uid, 0, company.id).await {
            out.push(AccountTaxInfo::from_determination(&company, &d));
        }
    }
    out
}

/// List the user's saved payment methods for automatic renewals.
async fn v1_list_payment_methods(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<PaymentMethodResponse>> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let methods = this.db.list_user_payment_methods(uid, None).await?;
    ApiData::ok(methods.into_iter().map(Into::into).collect())
}

/// Add a Nostr Wallet Connect connection as a saved payment method.
async fn v1_add_nwc_payment_method(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    req: Json<AddNwcPaymentMethodRequest>,
) -> ApiResult<PaymentMethodResponse> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let nwc = req.nwc_connection_string.trim().to_string();
    if nwc.is_empty() {
        return ApiData::err("NWC connection string cannot be empty");
    }

    // Validate the NWC connection and ensure it can pay invoices.
    #[cfg(feature = "nostr-nwc")]
    match nwc::prelude::NostrWalletConnectUri::parse(&nwc) {
        Ok(s) => {
            let client = nwc::NostrWalletConnect::new(s);
            let info = client
                .get_info()
                .await
                .map_err(|e| ApiError::bad_request(format!("Failed to connect to NWC: {}", e)))?;
            if !info.methods.contains(&nwc::prelude::Method::PayInvoice) {
                return ApiData::err("NWC connection must allow pay_invoice");
            }
        }
        Err(e) => return ApiData::err(&format!("Failed to parse NWC url: {}", e)),
    }

    // First method for the user becomes the default.
    let existing = this.db.list_user_payment_methods(uid, None).await?;
    let pm = lnvps_db::UserPaymentMethod {
        id: 0,
        user_id: uid,
        created: chrono::Utc::now(),
        provider: "nwc".to_string(),
        name: req
            .name
            .as_ref()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty()),
        external_customer_id: None,
        external_id: nwc.into(),
        card_brand: None,
        card_last_four: None,
        exp_month: None,
        exp_year: None,
        is_default: existing.is_empty(),
        enabled: true,
    };
    let id = this.db.insert_user_payment_method(&pm).await?;
    let saved = this.db.get_user_payment_method(id).await?;
    ApiData::ok(saved.into())
}

/// Update a saved payment method: set it as default and/or enable-disable it.
async fn v1_patch_payment_method(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    req: Json<PatchPaymentMethodRequest>,
) -> ApiResult<PaymentMethodResponse> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    let mut method = this.db.get_user_payment_method(id).await?;
    if method.user_id != uid {
        return ApiData::err("Payment method not found");
    }

    if let Some(enabled) = req.enabled {
        method.enabled = enabled;
    }
    if let Some(name) = &req.name {
        method.name = name
            .clone()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty());
    }
    if req.is_default == Some(true) {
        // Only one default: clear the flag on the user's other methods.
        for mut other in this.db.list_user_payment_methods(uid, None).await? {
            if other.id != id && other.is_default {
                other.is_default = false;
                this.db.update_user_payment_method(&other).await?;
            }
        }
        method.is_default = true;
    } else if req.is_default == Some(false) {
        method.is_default = false;
    }
    this.db.update_user_payment_method(&method).await?;
    ApiData::ok(this.db.get_user_payment_method(id).await?.into())
}

/// Delete a saved payment method.
async fn v1_delete_payment_method(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let method = this.db.get_user_payment_method(id).await?;
    if method.user_id != uid {
        return ApiData::err("Payment method not found");
    }
    this.db.delete_user_payment_method(id).await?;
    ApiData::ok(())
}

/// Notification channels configured on this server. The UI can use this to
/// show/hide the relevant contact inputs since there's no point offering a
/// channel that isn't configured on the backend.
#[derive(serde::Serialize)]
struct NotificationChannels {
    /// Nostr NIP-17 direct messages
    nip17: bool,
    /// Email (SMTP) notifications
    email: bool,
    /// Telegram bot notifications
    telegram: bool,
    /// WhatsApp Cloud API notifications
    whatsapp: bool,
}

/// List which notification channels are configured on this server.
async fn v1_notification_channels(
    State(this): State<RouterState>,
) -> ApiResult<NotificationChannels> {
    ApiData::ok(NotificationChannels {
        nip17: this.settings.nostr.is_some(),
        email: this.settings.smtp.is_some(),
        telegram: this.settings.telegram.is_some(),
        whatsapp: this.settings.whatsapp.is_some(),
    })
}

#[derive(serde::Serialize)]
struct TelegramLinkResponse {
    /// Deep link the user should open to link their Telegram chat
    url: String,
    /// One-time token embedded in the deep link
    token: String,
}

/// Generate a Telegram account-linking deep link.
///
/// Stores a fresh one-time token on the user; the bot completes linking when
/// the user opens the returned URL and presses Start.
async fn v1_telegram_link(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<TelegramLinkResponse> {
    let Some(tg) = this.settings.telegram.as_ref() else {
        return ApiData::err("Telegram notifications are not enabled on this server");
    };
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    let token = hex::encode(rand::random::<[u8; 16]>());
    user.telegram_link_token = Some(token.clone());
    this.db.update_user(&user).await?;

    ApiData::ok(TelegramLinkResponse {
        url: format!("https://t.me/{}?start={}", tg.username, token),
        token,
    })
}

/// Unlink the user's Telegram chat and disable Telegram notifications.
async fn v1_telegram_unlink(auth: Nip98Auth, State(this): State<RouterState>) -> ApiResult<()> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    user.telegram_chat_id = None;
    user.telegram_link_token = None;
    user.contact_telegram = false;
    this.db.update_user(&user).await?;

    ApiData::ok(())
}

#[derive(serde::Deserialize)]
struct WhatsappVerifyRequest {
    /// Phone number in E.164 format, e.g. `+15551234567`
    number: String,
}

#[derive(serde::Deserialize)]
struct WhatsappConfirmRequest {
    code: String,
}

/// Start WhatsApp verification: store the number, generate a code and send it
/// via the configured verification template.
async fn v1_whatsapp_verify(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<WhatsappVerifyRequest>,
) -> ApiResult<()> {
    let Some(wa) = this.settings.whatsapp.as_ref() else {
        return ApiData::err("WhatsApp notifications are not enabled on this server");
    };
    let number = req.number.trim();
    if crate::notifications::normalize_number(number).len() < 6 {
        return ApiData::err("A valid phone number in international format is required");
    }

    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    // 6-digit numeric code
    let code = format!("{:06}", rand::random::<u32>() % 1_000_000);
    user.whatsapp_number = Some(number.to_string());
    user.whatsapp_verified = false;
    user.whatsapp_verify_code = Some(code.clone());
    this.db.update_user(&user).await?;

    let client = crate::notifications::WhatsAppClient::new(wa, reqwest::Client::new());
    if let Err(e) = client
        .send_template(number, &wa.verify_template, &wa.verify_template_lang, &code)
        .await
    {
        error!("Failed to send WhatsApp verification to {}: {}", number, e);
        return ApiData::err("Failed to send verification code, please check the number");
    }

    ApiData::ok(())
}

/// Confirm WhatsApp verification by matching the code; enables the number.
async fn v1_whatsapp_confirm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<WhatsappConfirmRequest>,
) -> ApiResult<()> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    let code = req.code.trim();
    match &user.whatsapp_verify_code {
        Some(expected) if !expected.is_empty() && expected == code => {
            user.whatsapp_verified = true;
            user.whatsapp_verify_code = None;
            user.contact_whatsapp = true;
            this.db.update_user(&user).await?;
            ApiData::ok(())
        }
        _ => ApiData::err("Invalid or expired verification code"),
    }
}

/// Remove the user's WhatsApp number and disable WhatsApp notifications.
async fn v1_whatsapp_unlink(auth: Nip98Auth, State(this): State<RouterState>) -> ApiResult<()> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let mut user = this.db.get_user(uid).await?;

    user.whatsapp_number = None;
    user.whatsapp_verified = false;
    user.whatsapp_verify_code = None;
    user.contact_whatsapp = false;
    this.db.update_user(&user).await?;

    ApiData::ok(())
}

/// List VMs belonging to user
async fn v1_list_vms(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiVmStatus>> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vms = this.db.list_user_vms(uid).await?;
    let mut ret = vec![];
    for vm in vms {
        let vm_id = vm.id;
        ret.push(
            vm_to_status(
                &this.db,
                vm,
                this.state.get_state(vm_id).await,
                this.settings.delete_after,
                this.settings.max_prepay_days,
            )
            .await?,
        );
    }

    ApiData::ok(ret)
}

/// Get status of a VM
async fn v1_get_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiVmStatus> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;
    ApiData::ok(
        vm_to_status(
            &this.db,
            vm,
            this.state.get_state(id).await,
            this.settings.delete_after,
            this.settings.max_prepay_days,
        )
        .await?,
    )
}

/// Update a VM config
async fn v1_patch_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(data): Json<VMPatchRequest>,
) -> ApiResult<()> {
    let (uid, old_vm) = get_user_vm(&auth, &this, id).await?;

    let mut vm = old_vm.clone();
    let mut vm_config = false;
    let mut host_config = false;
    if let Some(k) = data.ssh_key_id {
        let ssh_key = this.db.get_user_ssh_key(k).await?;
        if ssh_key.user_id != uid {
            return Err(ApiError::forbidden("SSH key doesnt belong to you"));
        }
        vm.ssh_key_id = Some(ssh_key.id);
        vm_config = true;
        host_config = true;
    }

    if let Some(ptr) = &data.reverse_dns {
        let mut ips = this.db.list_vm_ip_assignments(vm.id).await?;
        for ip in ips.iter_mut() {
            ip.dns_reverse = Some(ptr.to_string());
            this.sub_handler
                .vm_provisioner()
                .network
                .update_reverse_ip_dns(ip)
                .await?;
            this.db.update_vm_ip_assignment(ip).await?;
        }
    }

    // Handle auto-renewal setting change — stored on the subscription, not the VM
    if let Some(auto_renewal) = data.auto_renewal_enabled {
        let mut sub = this
            .db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await?;
        sub.auto_renewal_enabled = auto_renewal;
        this.db.update_subscription(&sub).await?;
    }

    if vm_config {
        this.db.update_vm(&vm).await?;
    }
    if host_config {
        let info = FullVmInfo::load(vm.id, this.db.clone()).await?;
        let host = this.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, &this.settings.provisioner)?;
        client.configure_vm(&info).await?;

        // Log VM configuration change
        let _ = this
            .history
            .log_vm_configuration_changed(vm.id, Some(uid), &old_vm, &vm, None)
            .await;
    }

    ApiData::ok(())
}

/// List available VM OS images
async fn v1_list_vm_images(State(this): State<RouterState>) -> ApiResult<Vec<ApiVmOsImage>> {
    let images = this.db.list_os_image().await?;

    // Compute popularity as the fraction of active VMs using each image
    let counts: HashMap<u64, u64> = this.db.count_vms_by_os_image().await?.into_iter().collect();
    let total: u64 = counts.values().sum();

    let ret = images
        .into_iter()
        .filter(|i| i.enabled)
        .map(|i| {
            let count = counts.get(&i.id).copied().unwrap_or(0);
            let mut image: ApiVmOsImage = i.into();
            image.popularity = if total > 0 {
                count as f32 / total as f32
            } else {
                0.0
            };
            image
        })
        .collect();
    ApiData::ok(ret)
}

/// List available VM templates (Offers)
async fn v1_list_vm_templates(State(this): State<RouterState>) -> ApiResult<ApiTemplatesResponse> {
    let hc = HostCapacityService::new(this.db.clone());
    let templates = hc.list_available_vm_templates().await?;

    let cost_plans: HashSet<u64> = templates.iter().map(|t| t.cost_plan_id).collect();
    let regions: HashMap<u64, VmHostRegion> = this
        .db
        .list_host_region()
        .await?
        .into_iter()
        .map(|h| (h.id, h))
        .collect();

    let cost_plans: Vec<_> = cost_plans
        .into_iter()
        .map(|i| this.db.get_cost_plan(i))
        .collect();

    let cost_plans: HashMap<u64, lnvps_db::VmCostPlan> = join_all(cost_plans)
        .await
        .into_iter()
        .filter_map(|c| {
            let c = c.ok()?;
            Some((c.id, c))
        })
        .collect();

    let ret = templates
        .iter()
        .filter_map(|i| {
            let cp = cost_plans.get(&i.cost_plan_id)?;
            let hr = regions.get(&i.region_id)?;
            ApiVmTemplate::from_standard_data(i, cp, hr).ok()
        })
        .collect();
    let custom_templates: Vec<VmCustomPricing> =
        join_all(regions.keys().map(|k| this.db.list_custom_pricing(*k)))
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .flatten()
            .filter(|r| r.enabled)
            .collect();

    let custom_template_disks: Vec<VmCustomPricingDisk> = join_all(
        custom_templates
            .iter()
            .map(|t| this.db.list_custom_pricing_disk(t.id)),
    )
    .await
    .into_iter()
    .filter_map(|r| r.ok())
    .flatten()
    .collect();

    let mut rsp = ApiTemplatesResponse {
        templates: ret,
        custom_template: if custom_templates.is_empty() {
            None
        } else {
            let api_templates: Vec<ApiCustomTemplateParams> = custom_templates
                .into_iter()
                .filter_map(|t| {
                    let region = regions.get(&t.region_id)?;
                    Some(ApiCustomTemplateParams::from(
                        &t,
                        &custom_template_disks,
                        region,
                    ))
                })
                .collect();

            Some(hc.apply_host_capacity_limits(&api_templates).await?)
        },
    };
    rsp.expand_pricing(&this.rates).await?;
    ApiData::ok(rsp)
}

/// Get a price for a custom order
async fn v1_custom_template_calc(
    State(this): State<RouterState>,
    Json(req): Json<ApiCustomVmRequest>,
) -> ApiResult<ApiCustomVmPrice> {
    // create a fake template from the request to generate the price
    let template: VmCustomTemplate = req.into();

    // Reject out-of-range specs so the order form surfaces the error early.
    PricingEngine::validate_custom_vm_spec(&this.db, &template).await?;

    let price = PricingEngine::get_custom_vm_cost_amount(&this.db, 0, &template).await?;
    let amount = CurrencyAmount::from_u64(price.currency, price.total());
    // Include conversions to the other supported currencies, like the template
    // listing's `other_price`.
    ApiData::ok(ApiCustomVmPrice::from_amount(amount, &this.rates).await?)
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 1 hour
async fn v1_create_custom_vm_order(
    auth: Nip98Auth,
    client_ip: ClientIp,
    State(this): State<RouterState>,
    Json(req): Json<ApiCustomVmOrder>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Capture place-of-supply evidence at purchase time (see capture_client_geo).
    capture_client_geo(&this, uid, client_ip).await;

    let user = this.db.get_user(uid).await?;
    // Email verification is only enforced when SMTP is configured; otherwise
    // there's no way to send the verification email, so the requirement is
    // skipped to keep ordering usable on installs without email.
    if this.settings.smtp.is_some() && !user.email_verified {
        return Err(ApiError::forbidden(
            "Email verification is required before creating a VM",
        ));
    }

    // create a fake template from the request to generate the order
    let template = req.spec.clone().into();

    let rsp = this
        .sub_handler
        .vm_provisioner()
        .provision_custom(uid, template, req.image_id, req.ssh_key_id, req.ref_code)
        .await?;

    // Log VM creation
    this.history
        .log_vm_created(&rsp, Some(uid), None)
        .await
        .ok();

    ApiData::ok(vm_to_status(&this.db, rsp, None, this.settings.delete_after, this.settings.max_prepay_days).await?)
}

/// List user SSH keys
async fn v1_list_ssh_keys(
    auth: Nip98Auth,
    State(this): State<RouterState>,
) -> ApiResult<Vec<ApiUserSshKey>> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;
    let vms = this.db.list_user_vms(uid).await?;
    let ret = this
        .db
        .list_user_ssh_key(uid)
        .await?
        .into_iter()
        .map(|i| {
            let mut key: ApiUserSshKey = i.into();
            key.vms = vms
                .iter()
                .filter(|vm| !vm.deleted && vm.ssh_key_id == Some(key.id))
                .map(|vm| vm.id)
                .collect();
            key
        })
        .collect();
    ApiData::ok(ret)
}

/// Add new SSH key to account
async fn v1_add_ssh_key(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Json(req): Json<CreateSshKey>,
) -> ApiResult<ApiUserSshKey> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;

    let pk: PublicKey = req
        .key_data
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid SSH public key format"))?;
    let key_name = if !req.name.is_empty() {
        &req.name
    } else {
        pk.comment()
    };
    let mut new_key = lnvps_db::UserSshKey {
        name: key_name.to_string(),
        user_id: uid,
        key_data: pk
            .to_openssh()
            .map_err(|e| ApiError::internal(format!("Failed to encode SSH key: {}", e)))?
            .into(),
        ..Default::default()
    };
    let key_id = this.db.insert_user_ssh_key(&new_key).await?;
    new_key.id = key_id;

    ApiData::ok(new_key.into())
}

/// Delete an SSH key from account
async fn v1_delete_ssh_key(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let uid = this.db.upsert_user(&auth.pubkey()).await?;

    let ssh_key = this.db.get_user_ssh_key(id).await?;
    if ssh_key.user_id != uid {
        return ApiData::err("SSH key not found");
    }

    // Prevent deleting a key that is still in use by an active VM, otherwise the
    // database foreign key constraint (fk_vm_ssh_key_id) would fail with an
    // opaque internal error.
    let vms = this.db.list_user_vms(uid).await?;
    if vms.iter().any(|vm| vm.ssh_key_id == Some(id)) {
        return ApiData::err("SSH key is in use by one or more VMs and cannot be deleted");
    }

    this.db.delete_user_ssh_key(id).await?;
    ApiData::ok(())
}

/// Create a new VM order
///
/// After order is created please use /api/v1/vm/{id}/renew to pay for VM,
/// VM's are initially created in "expired" state
///
/// Unpaid VM orders will be deleted after 1 hour
async fn v1_create_vm_order(
    auth: Nip98Auth,
    client_ip: ClientIp,
    State(this): State<RouterState>,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<ApiVmStatus> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;

    // Capture place-of-supply evidence at purchase time (see capture_client_geo).
    capture_client_geo(&this, uid, client_ip).await;

    let user = this.db.get_user(uid).await?;
    // Email verification is only enforced when SMTP is configured (see
    // v1_create_custom_vm_order for rationale).
    if this.settings.smtp.is_some() && !user.email_verified {
        return Err(ApiError::forbidden(
            "Email verification is required before creating a VM",
        ));
    }

    let rsp = this
        .sub_handler
        .vm_provisioner()
        .provision(
            uid,
            req.template_id,
            req.image_id,
            req.ssh_key_id,
            req.ref_code,
        )
        .await?;

    // Log VM creation
    this.history
        .log_vm_created(&rsp, Some(uid), None)
        .await
        .ok();

    ApiData::ok(vm_to_status(&this.db, rsp, None, this.settings.delete_after, this.settings.max_prepay_days).await?)
}

/// Renew(Extend) a VM
async fn v1_renew_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
) -> ApiResult<ApiVmPayment> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let intervals = q.intervals.unwrap_or(1);
    let vm_line = this
        .db
        .get_subscription_line_item(vm.subscription_line_item_id)
        .await?;

    let (method, mode) = crate::api::resolve_payment_mode(&this, uid, &q).await?;
    let payment = this
        .sub_handler
        .renew_subscription_with_mode(vm_line.subscription_id, method, intervals, mode)
        .await?;

    ApiData::ok(ApiVmPayment::from_subscription_payment(payment, id)?)
}

/// Extend a VM by LNURL payment
async fn v1_renew_vm_lnurlp(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<AmountQuery>,
) -> Result<Json<LnURLPayInvoice>, Json<lnurl::Response>> {
    let vm = this.db.get_vm(id).await.map_err(|_| {
        Json(lnurl::Response::Error {
            reason: "VM not found".to_string(),
        })
    })?;
    if vm.deleted {
        return Err(lnurl::Response::Error {
            reason: "VM not found".to_string(),
        }
        .into());
    }
    if q.amount < 1000 {
        return Err(lnurl::Response::Error {
            reason: "Amount must be greater than 1000".to_string(),
        }
        .into());
    }
    let rsp = this
        .sub_handler
        .renew_amount(
            id,
            CurrencyAmount::millisats(q.amount),
            PaymentMethod::Lightning,
        )
        .await
        .map_err(|_| {
            Json(lnurl::Response::Error {
                reason: "Error generating invoice".to_string(),
            })
        })?;

    // external_data is pr for lightning payment method
    Ok(Json(LnURLPayInvoice::new(rsp.external_data.into())))
}

/// LNURL ad-hoc extend vm
async fn v1_lnurlp(
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> Result<Json<PayResponse>, &'static str> {
    let vm = this.db.get_vm(id).await.map_err(|_| "VM not found")?;
    if vm.deleted {
        return Err("VM not found");
    }

    let meta = vec![vec!["text/plain".to_string(), format!("Extend VM {}", id)]];
    let rsp = PayResponse {
        callback: Url::parse(&this.settings.public_url)
            .map_err(|_| "Invalid public url")?
            .join(&format!("/api/v1/vm/{}/renew-lnurlp", id))
            .map_err(|_| "Could not get callback url")?
            .to_string(),
        max_sendable: 1_000_000_000,
        min_sendable: 100_000, // TODO: calc min by using 1s extend time
        tag: Tag::PayRequest,
        metadata: serde_json::to_string(&meta).map_err(|_e| "Failed to serialize metadata")?,
        comment_allowed: None,
        allows_nostr: None,
        nostr_pubkey: None,
    };
    Ok(Json(rsp))
}

/// Start a VM
async fn v1_start_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    client.start_vm(&vm).await?;

    // Log VM start
    this.history.log_vm_started(id, Some(uid), None).await.ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

/// Stop a VM
async fn v1_stop_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    client.stop_vm(&vm).await?;

    // Log VM stop
    this.history.log_vm_stopped(id, Some(uid), None).await.ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

/// Restart a VM
async fn v1_restart_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<()> {
    let (uid, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    // Hard reset (restart) the VM — previously this only issued a stop, leaving
    // the VM powered off.
    client.reset_vm(&vm).await?;

    // Log VM restart
    this.history
        .log_vm_restarted(id, Some(uid), None)
        .await
        .ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ReinstallRequest {
    /// Optionally switch to a different OS image during the reinstall
    image_id: Option<u64>,
}

/// Re-install a VM
async fn v1_reinstall_vm(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    body: Option<Json<ReinstallRequest>>,
) -> ApiResult<()> {
    let (uid, mut vm) = get_user_vm(&auth, &this, id).await?;
    let req = body.map(|Json(b)| b).unwrap_or_default();

    // Reject re-install on an expired VM. The VM may already be stopped/removed
    // on the host, so running the reinstall pipeline would fail with a 500.
    // The expiry is authoritative on the VM's subscription.
    let vm_expires = this
        .db
        .get_subscription_by_line_item_id(vm.subscription_line_item_id)
        .await
        .ok()
        .and_then(|s| s.expires);
    if is_vm_expired(vm_expires, Utc::now()) {
        return Err(ApiError::payment_required(
            "Cannot re-install an expired VM, please renew it first",
        ));
    }

    let old_image_id = vm.image_id;

    // Optionally switch to a different OS image. Persist the change before
    // loading FullVmInfo so the reinstall pipeline provisions the new image.
    if let Some(new_image_id) = req.image_id
        && new_image_id != old_image_id
    {
        let image = this.db.get_os_image(new_image_id).await?;
        if !image.enabled {
            return Err(ApiError::forbidden("OS image is not available"));
        }
        vm.image_id = new_image_id;
        this.db.update_vm(&vm).await?;
    }
    let new_image_id = vm.image_id;

    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    let info = FullVmInfo::load(vm.id, this.db.clone()).await?;

    struct ReinstallContext {
        vm_id: u64,
        client: std::sync::Arc<dyn crate::host::VmHostClient>,
        info: FullVmInfo,
    }

    let ctx = ReinstallContext {
        vm_id: vm.id,
        client,
        info,
    };

    Pipeline::new(ctx)
        .with_retry_policy(RetryPolicy::default())
        .step("stop_vm", |ctx| {
            Box::pin(async move {
                info!("Stopping VM {} for reinstall", ctx.vm_id);
                ctx.client.stop_vm(&ctx.info.vm).await
            })
        })
        .step("unlink_disk", |ctx| {
            Box::pin(async move {
                info!("Unlinking disk for VM {}", ctx.vm_id);
                ctx.client.unlink_primary_disk(&ctx.info.vm).await
            })
        })
        .step("import_template_disk", |ctx| {
            Box::pin(async move {
                // import_template_disk already imports AND resizes the primary
                // disk to the template size; a separate resize step here would
                // ask Proxmox to resize to the same size, which it rejects as a
                // disallowed shrink and surfaces as a 500 (see issue #142).
                info!("Importing template disk for VM {}", ctx.vm_id);
                ctx.client.import_template_disk(&ctx.info).await
            })
        })
        .step("start_vm", |ctx| {
            Box::pin(async move {
                info!("Starting VM {} after reinstall", ctx.vm_id);
                ctx.client.start_vm(&ctx.info.vm).await
            })
        })
        .execute()
        .await?;

    // Log VM reinstall (records image change if the user switched images)
    this.history
        .log_vm_reinstalled(id, Some(uid), old_image_id, new_image_id, None)
        .await
        .ok();

    this.work_sender
        .send(WorkJob::CheckVm { vm_id: id })
        .await?;
    ApiData::ok(())
}

async fn v1_time_series(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<TimeSeriesData>> {
    let (_, vm) = get_user_vm(&auth, &this, id).await?;
    let host = this.db.get_host(vm.host_id).await?;
    let client = get_host_client(&host, &this.settings.provisioner)?;
    ApiData::ok(client.get_time_series_data(&vm, TimeSeries::Hourly).await?)
}

#[allow(unused)]
async fn v1_terminal_proxy(
    id: u64,
    auth: String,
    this: RouterState,
    mut ws: WebSocket,
) -> Result<(), &'static str> {
    let auth = Nip98Auth::from_base64(&auth).map_err(|_| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/vm/{id}/console"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.pubkey();
    let uid = this
        .db
        .upsert_user(&pubkey)
        .await
        .map_err(|_| "Insert failed")?;
    let vm = this.db.get_vm(id).await.map_err(|_| "VM not found")?;
    if uid != vm.user_id {
        return Err("VM does not belong to you");
    }

    let host = this
        .db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "VM host not found")?;
    let client = get_host_client(&host, &this.settings.provisioner)
        .map_err(|_| "Failed to get host client")?;

    let mut terminal = client.connect_terminal(&vm).await.map_err(|e| {
        error!("Failed to start terminal proxy: {}", e);
        "Failed to open terminal proxy"
    })?;

    // Bidirectional relay: WebSocket ↔ TerminalStream
    loop {
        tokio::select! {
            // Data arriving from the VM serial port → forward to WebSocket client
            msg = terminal.rx.recv() => {
                match msg {
                    Some(data) => {
                        if ws.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break, // terminal channel closed
                }
            }
            // Data arriving from the WebSocket client → forward to VM serial port
            frame = ws.recv() => {
                match frame {
                    Some(Ok(Message::Binary(data))) => {
                        if terminal.tx.send(data.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if terminal.tx.send(text.as_bytes().to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {} // ping/pong handled by axum automatically
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn v1_get_payment_methods(State(this): State<RouterState>) -> ApiResult<Vec<ApiPaymentInfo>> {
    let configs = this.db.list_payment_method_configs().await?;
    ApiData::ok(build_payment_methods_response(configs))
}

fn build_payment_methods_response(
    configs: Vec<lnvps_db::PaymentMethodConfig>,
) -> Vec<ApiPaymentInfo> {
    let has_lightning = configs
        .iter()
        .any(|c| c.enabled && c.payment_method == PaymentMethod::Lightning);

    let mut ret: Vec<ApiPaymentInfo> = configs
        .into_iter()
        .filter(|c| c.enabled)
        .map(|config| {
            // Use supported_currencies from DB if set, otherwise fall back to defaults
            let currencies = if config.supported_currencies.is_empty() {
                default_currencies_for_method(config.payment_method)
            } else {
                parse_currencies(&config.supported_currencies)
            };
            ApiPaymentInfo {
                name: config.payment_method.into(),
                metadata: HashMap::new(),
                currencies,
                processing_fee_rate: config.processing_fee_rate,
                processing_fee_base: config.processing_fee_base,
                processing_fee_currency: config.processing_fee_currency,
                min_amount: config.min_amount,
                min_amount_currency: config.min_amount_currency,
            }
        })
        .collect();

    // NWC and LNURL are client-side payment methods available when Lightning is enabled
    if has_lightning {
        ret.push(ApiPaymentInfo {
            name: ApiPaymentMethod::NWC,
            metadata: HashMap::new(),
            currencies: vec![ApiCurrency::BTC],
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
        });
        ret.push(ApiPaymentInfo {
            name: ApiPaymentMethod::LNURL,
            metadata: HashMap::new(),
            currencies: vec![ApiCurrency::BTC],
            processing_fee_rate: None,
            processing_fee_base: None,
            processing_fee_currency: None,
            min_amount: None,
            min_amount_currency: None,
        });
    }

    ret
}

/// Parse currency codes into ApiCurrency list, skipping invalid ones
fn parse_currencies(codes: &[String]) -> Vec<ApiCurrency> {
    use payments_rs::currency::Currency;
    codes
        .iter()
        .filter_map(|c| Currency::from_str(c).ok())
        .map(ApiCurrency::from)
        .collect()
}

/// Get default currencies for a payment method type
fn default_currencies_for_method(method: PaymentMethod) -> Vec<ApiCurrency> {
    match method {
        PaymentMethod::Lightning => vec![ApiCurrency::BTC],
        PaymentMethod::OnChain => vec![ApiCurrency::BTC],
        PaymentMethod::Revolut => vec![ApiCurrency::EUR, ApiCurrency::USD],
        PaymentMethod::Paypal => vec![ApiCurrency::EUR, ApiCurrency::USD],
        PaymentMethod::Stripe => vec![ApiCurrency::EUR, ApiCurrency::USD],
    }
}

/// Get payment status (for polling)
async fn v1_get_payment(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<String>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let id = if let Ok(i) = hex::decode(&id) {
        i
    } else {
        return ApiData::err("Invalid payment id");
    };

    let payment = this.db.get_subscription_payment(&id).await?;
    let vm = this
        .db
        .get_vm_by_subscription(payment.subscription_id)
        .await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }

    ApiData::ok(ApiVmPayment::from_subscription_payment(payment, vm.id)?)
}

/// Map a payment's stored tax fields to invoice display fields:
/// `(rate_label, is_reverse_charge, is_out_of_scope, note)`.
///
/// `rate_label` (e.g. `"23% (IRL)"`) is produced for lines that carried tax. The
/// reverse-charge and out-of-scope notes are EU-specific and only emitted when
/// the seller is established in the EU VAT area (`seller_in_eu`); a non-EU
/// seller shows no such note.
fn invoice_vat_display(
    treatment: Option<&str>,
    tax: u64,
    rate: Option<f32>,
    country: Option<&str>,
    seller_in_eu: bool,
) -> (Option<String>, bool, bool, Option<String>) {
    match treatment {
        Some("reverse_charge") if seller_in_eu => (
            None,
            true,
            false,
            Some(
                "VAT reverse charged — the recipient is liable to account for VAT \
                 (Article 196, Council Directive 2006/112/EC)."
                    .to_string(),
            ),
        ),
        Some("out_of_scope") if seller_in_eu => (
            None,
            false,
            true,
            Some("Outside the scope of EU VAT.".to_string()),
        ),
        // Any taxed line (domestic / oss_b2c / undetermined_default, or a mixed
        // payment whose summary is null but which carried tax): show the rate.
        _ => {
            let label = if tax > 0 {
                Some(match (rate, country) {
                    (Some(r), Some(cc)) => format!("{:.0}% ({})", r, cc),
                    (Some(r), None) => format!("{:.0}%", r),
                    _ => "VAT".to_string(),
                })
            } else {
                None
            };
            (label, false, false, None)
        }
    }
}

async fn v1_get_payment_invoice(
    State(this): State<RouterState>,
    Path(id): Path<String>,
    Query(q): Query<AuthQuery>,
) -> Result<Html<String>, &'static str> {
    let auth = Nip98Auth::from_base64(&q.auth).map_err(|_e| "Missing or invalid auth param")?;
    if auth
        .check(&format!("/api/v1/payment/{id}/invoice"), "GET")
        .is_err()
    {
        return Err("Invalid auth event");
    }
    let pubkey = auth.pubkey();
    let uid = this
        .db
        .upsert_user(&pubkey)
        .await
        .map_err(|_| "Insert failed")?;
    let id = if let Ok(i) = hex::decode(id) {
        i
    } else {
        return Err("Invalid payment id");
    };

    let payment = this
        .db
        .get_subscription_payment(&id)
        .await
        .map_err(|_| "Payment not found")?;
    let vm = this
        .db
        .get_vm_by_subscription(payment.subscription_id)
        .await
        .map_err(|_| "VM not found")?;
    if vm.user_id != uid {
        return Err("VM does not belong to you");
    }
    let vm_id_for_payment = vm.id;

    if !payment.is_paid {
        return Err("Payment is not paid, can't generate invoice");
    }

    #[derive(Serialize)]
    struct PaymentInfo {
        year: i32,
        current_date: DateTime<Utc>,
        vm: ApiVmStatus,
        payment: ApiVmPayment,
        invoice_item: ApiInvoiceItem,
        user: AccountPatchRequest,
        /// Billing email shown on the invoice (empty when the account has none).
        email: String,
        /// Whether an email is present, so the template can hide the line.
        has_email: bool,
        total: u64,
        total_formatted: String,
        company: Option<ApiCompany>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upgrade_details: Option<UpgradeDetails>,
        vat: InvoiceVat,
    }

    /// VAT presentation derived from the payment's frozen determination.
    #[derive(Serialize, Default)]
    struct InvoiceVat {
        /// Human label for the applied rate line, e.g. "23% (IRL)". Present only
        /// when VAT was actually charged.
        #[serde(skip_serializing_if = "Option::is_none")]
        rate_label: Option<String>,
        /// True for an EU B2B reverse-charge supply (0%, recipient accounts).
        is_reverse_charge: bool,
        /// True for a supply outside the scope of EU VAT (non-EU customer).
        is_out_of_scope: bool,
        /// Legal note to print under the totals (reverse charge / out of scope).
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }

    #[derive(Serialize)]
    struct UpgradeDetails {
        #[serde(skip_serializing_if = "Option::is_none")]
        cpu_upgrade: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        memory_upgrade: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disk_upgrade: Option<u64>,
    }

    let host = this
        .db
        .get_host(vm.host_id)
        .await
        .map_err(|_| "Host not found")?;
    let region = this
        .db
        .get_host_region(host.region_id)
        .await
        .map_err(|_| "Region not found")?;
    let company = this.db.get_company(region.company_id).await.ok();
    let user = this.db.get_user(uid).await.map_err(|_| "User not found")?;
    #[cfg(debug_assertions)]
    let template =
        mustache::compile_path("lnvps_api/invoice.html").map_err(|_| "Invalid template")?;
    #[cfg(not(debug_assertions))]
    let template = mustache::compile_str(include_str!("../../invoice.html"))
        .map_err(|_| "Invalid template")?;

    // Parse upgrade details if this is an upgrade payment
    let upgrade_details = if payment.payment_type == lnvps_db::SubscriptionPaymentType::Upgrade {
        payment
            .metadata
            .as_ref()
            .and_then(|m| serde_json::from_value::<UpgradeConfig>(m.clone()).ok())
            .map(|c| UpgradeDetails {
                cpu_upgrade: c.new_cpu,
                memory_upgrade: c.new_memory.map(|m| m / crate::GB),
                disk_upgrade: c.new_disk.map(|m| m / crate::GB),
            })
    } else {
        None
    };

    let now = Utc::now();
    let invoice_item = ApiInvoiceItem::from_subscription_payment(&payment)
        .map_err(|_| "Failed to create formatted invoice item")?;

    // Present the tax fields stored on the payment. EU-specific notes are only
    // shown for a seller established in the EU VAT area.
    let seller_in_eu = company
        .as_ref()
        .and_then(|c| c.country_code.as_deref())
        .map(lnvps_api_common::is_eu_vat_country)
        .unwrap_or(false);
    let (rate_label, is_reverse_charge, is_out_of_scope, note) = invoice_vat_display(
        payment.tax_treatment.as_deref(),
        payment.tax,
        payment.tax_rate,
        payment.tax_country_code.as_deref(),
        seller_in_eu,
    );
    let vat = InvoiceVat {
        rate_label,
        is_reverse_charge,
        is_out_of_scope,
        note,
    };

    let mut html = Cursor::new(Vec::new());
    template
        .render(
            &mut html,
            &PaymentInfo {
                year: now.year(),
                current_date: now,
                vm: vm_to_status(&this.db, vm, None, this.settings.delete_after, this.settings.max_prepay_days)
                    .await
                    .map_err(|_| "Failed to get VM state")?,
                total: payment.amount + payment.tax + payment.processing_fee,
                total_formatted: CurrencyAmount::from_u64(
                    payment.currency.parse().map_err(|_| "Invalid currency")?,
                    payment.amount + payment.tax + payment.processing_fee,
                )
                .to_string(),
                payment: ApiVmPayment::from_subscription_payment(payment, vm_id_for_payment)
                    .map_err(|_| "Failed to parse payment data")?,
                invoice_item,
                email: user.email.as_str().to_string(),
                has_email: !user.email.is_empty(),
                user: user.into(),
                company: company.map(|c| c.into()),
                upgrade_details,
                vat,
            },
        )
        .map_err(|_| "Failed to generate invoice")?;
    Ok(Html(String::from_utf8(html.into_inner()).unwrap()))
}

/// List payment history of a VM
async fn v1_payment_history(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Vec<ApiVmPayment>> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }

    let payments = {
        let limit = q.limit.unwrap_or(50);
        let offset = q.offset.unwrap_or(0);
        this.db
            .list_vm_subscription_payments_paginated(id, limit, offset)
            .await?
    };
    ApiData::ok(
        payments
            .into_iter()
            .map(|p| ApiVmPayment::from_subscription_payment(p, id))
            .collect::<anyhow::Result<Vec<_>>>()?,
    )
}

/// List action history of a VM
async fn v1_get_vm_history(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Vec<ApiVmHistory>> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }

    let history = match (q.limit, q.offset) {
        (Some(limit), Some(offset)) => this.db.list_vm_history_paginated(id, limit, offset).await?,
        _ => this.db.list_vm_history(id).await?,
    };

    ApiData::ok(
        history
            .into_iter()
            .map(|h| ApiVmHistory::from_with_owner(h, vm.user_id))
            .collect(),
    )
}

/// Get a quote for upgrading a VM
async fn v1_vm_upgrade_quote(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmUpgradeRequest>,
) -> ApiResult<ApiVmUpgradeQuote> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }

    // Create UpgradeConfig from request
    let cfg = UpgradeConfig {
        new_cpu: req.cpu,
        new_memory: req.memory,
        new_disk: req.disk,
    };

    // Calculate the upgrade cost and new renewal cost
    match this
        .sub_handler
        .pricing_engine()
        .calculate_vm_upgrade_cost(
            id,
            &cfg,
            q.method
                .and_then(|m| PaymentMethod::from_str(&m).ok())
                .unwrap_or(PaymentMethod::Lightning),
        )
        .await
    {
        Ok(quote) => {
            let currency = quote.upgrade.amount.currency();
            ApiData::ok(ApiVmUpgradeQuote {
                cost_difference: quote.upgrade.amount.into(),
                new_renewal_cost: quote.renewal.amount.into(),
                discount: quote.discount.amount.into(),
                tax: CurrencyAmount::from_u64(currency, quote.tax.amount).into(),
                processing_fee: CurrencyAmount::from_u64(currency, quote.processing_fee).into(),
            })
        }
        Err(e) => ApiData::err(e.to_string().as_str()),
    }
}

/// Upgrade a VM (requires payment first)
async fn v1_vm_upgrade(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Query(q): Query<PaymentMethodQuery>,
    Json(req): Json<ApiVmUpgradeRequest>,
) -> ApiResult<ApiVmPayment> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if vm.user_id != uid {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }

    // Create UpgradeConfig from request
    let cfg = UpgradeConfig {
        new_cpu: req.cpu,
        new_memory: req.memory,
        new_disk: req.disk,
    };

    // Same payment resolution as renewals/purchases: interactive, saved NWC
    // wallet, or saved Revolut card — collected on the spot for saved methods.
    let (method, mode) = crate::api::resolve_payment_mode(&this, uid, &q).await?;
    let payment = this
        .sub_handler
        .create_vm_upgrade_payment(id, &cfg, method, mode)
        .await?;

    // Note: The actual upgrade happens after payment is confirmed
    ApiData::ok(ApiVmPayment::from_subscription_payment(payment, id)?)
}

/// Default maximum number of user firewall rules per VM when no template limit is set.
const DEFAULT_FIREWALL_RULE_LIMIT: u16 = 20;

/// Resolve the firewall rule limit for a VM from its (custom) template,
/// falling back to the global default.
async fn vm_firewall_rule_limit(this: &RouterState, vm: &Vm) -> Result<u16, ApiError> {
    let limit = if let Some(t) = vm.template_id {
        this.db.get_vm_template(t).await?.firewall_rule_limit
    } else if let Some(t) = vm.custom_template_id {
        this.db.get_custom_vm_template(t).await?.firewall_rule_limit
    } else {
        None
    };
    Ok(limit.unwrap_or(DEFAULT_FIREWALL_RULE_LIMIT))
}

/// List firewall rules for a VM
async fn v1_list_firewall_rules(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<Vec<ApiVmFirewallRule>> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;
    let rules = this.db.list_vm_firewall_rules(vm.id).await?;
    ApiData::ok(rules.into_iter().map(ApiVmFirewallRule::from).collect())
}

/// Get the per-VM default firewall policy
async fn v1_get_firewall_policy(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
) -> ApiResult<ApiVmFirewallPolicy> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;
    ApiData::ok(ApiVmFirewallPolicy {
        policy_in: vm.fw_policy_in.map(Into::into),
        policy_out: vm.fw_policy_out.map(Into::into),
    })
}

/// Update the per-VM default firewall policy
async fn v1_patch_firewall_policy(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<PatchVmFirewallPolicy>,
) -> ApiResult<ApiVmFirewallPolicy> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;

    let policy_in = match req.policy_in {
        Some(v) => v.map(Into::into),
        None => vm.fw_policy_in,
    };
    let policy_out = match req.policy_out {
        Some(v) => v.map(Into::into),
        None => vm.fw_policy_out,
    };

    this.db
        .update_vm_firewall_policy(vm.id, policy_in, policy_out)
        .await?;
    apply_firewall(&this, vm.id).await?;

    ApiData::ok(ApiVmFirewallPolicy {
        policy_in: policy_in.map(Into::into),
        policy_out: policy_out.map(Into::into),
    })
}

/// Create a firewall rule for a VM
async fn v1_create_firewall_rule(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(id): Path<u64>,
    Json(req): Json<CreateVmFirewallRule>,
) -> ApiResult<ApiVmFirewallRule> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;

    // Enforce the per-VM rule limit
    let limit = vm_firewall_rule_limit(&this, &vm).await?;
    let existing = this.db.list_vm_firewall_rules(vm.id).await?;
    if existing.len() as u16 >= limit {
        return ApiData::err(&format!("Firewall rule limit reached ({})", limit));
    }

    // Validate inputs
    if let Some(cidr) = &req.src_cidr {
        if let Err(e) = validate_firewall_cidr(cidr) {
            return ApiData::err(&e);
        }
    }
    let (dst_port_start, dst_port_end) =
        match validate_firewall_ports(req.dst_port_start, req.dst_port_end) {
            Ok(v) => v,
            Err(e) => return ApiData::err(&e),
        };

    let rule = lnvps_db::VmFirewallRule {
        id: 0,
        vm_id: vm.id,
        priority: req.priority,
        direction: req.direction.into(),
        protocol: req.protocol.into(),
        action: req.action.into(),
        src_cidr: req.src_cidr,
        dst_port_start,
        dst_port_end,
        enabled: req.enabled.unwrap_or(true),
        created: Utc::now(),
        updated: Utc::now(),
    };
    let rule_id = this.db.insert_vm_firewall_rule(&rule).await?;

    apply_firewall(&this, vm.id).await?;

    let created = this.db.get_vm_firewall_rule(rule_id).await?;
    ApiData::ok(ApiVmFirewallRule::from(created))
}

/// Update a firewall rule
async fn v1_patch_firewall_rule(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path((id, rule_id)): Path<(u64, u64)>,
    Json(req): Json<PatchVmFirewallRule>,
) -> ApiResult<ApiVmFirewallRule> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;

    let mut rule = this.db.get_vm_firewall_rule(rule_id).await?;
    if rule.vm_id != vm.id {
        return Err(ApiError::not_found(
            "Firewall rule does not belong to this VM",
        ));
    }

    if let Some(p) = req.priority {
        rule.priority = p;
    }
    if let Some(d) = req.direction {
        rule.direction = d.into();
    }
    if let Some(p) = req.protocol {
        rule.protocol = p.into();
    }
    if let Some(a) = req.action {
        rule.action = a.into();
    }
    if let Some(c) = req.src_cidr {
        if let Some(cidr) = &c {
            if let Err(e) = validate_firewall_cidr(cidr) {
                return ApiData::err(&e);
            }
        }
        rule.src_cidr = c;
    }
    if let Some(s) = req.dst_port_start {
        rule.dst_port_start = s;
    }
    if let Some(e) = req.dst_port_end {
        rule.dst_port_end = e;
    }
    match validate_firewall_ports(rule.dst_port_start, rule.dst_port_end) {
        Ok((s, e)) => {
            rule.dst_port_start = s;
            rule.dst_port_end = e;
        }
        Err(e) => return ApiData::err(&e),
    }
    if let Some(en) = req.enabled {
        rule.enabled = en;
    }

    this.db.update_vm_firewall_rule(&rule).await?;
    apply_firewall(&this, vm.id).await?;

    let updated = this.db.get_vm_firewall_rule(rule_id).await?;
    ApiData::ok(ApiVmFirewallRule::from(updated))
}

/// Delete a firewall rule
async fn v1_delete_firewall_rule(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path((id, rule_id)): Path<(u64, u64)>,
) -> ApiResult<()> {
    let (_uid, vm) = get_user_vm(&auth, &this, id).await?;

    let rule = this.db.get_vm_firewall_rule(rule_id).await?;
    if rule.vm_id != vm.id {
        return Err(ApiError::not_found(
            "Firewall rule does not belong to this VM",
        ));
    }

    this.db.delete_vm_firewall_rule(rule_id).await?;
    apply_firewall(&this, vm.id).await?;
    ApiData::ok(())
}

/// Queue a firewall re-apply job for the VM.
async fn apply_firewall(this: &RouterState, vm_id: u64) -> Result<(), ApiError> {
    this.work_sender
        .send(WorkJob::ApplyVmFirewall { vm_id })
        .await
        .map_err(|e| ApiError::internal(format!("Failed to queue firewall update: {}", e)))?;
    Ok(())
}

async fn get_user_vm(auth: &Nip98Auth, this: &RouterState, id: u64) -> Result<(u64, Vm), ApiError> {
    let pubkey = auth.pubkey();
    let uid = this.db.upsert_user(&pubkey).await?;
    let vm = this.db.get_vm(id).await?;
    if uid != vm.user_id {
        return Err(ApiError::forbidden("VM does not belong to you"));
    }
    if vm.deleted {
        return Err(ApiError::not_found("VM not found"));
    }
    Ok((uid, vm))
}

/// Determine whether a VM is expired based on its subscription expiry.
///
/// A `None` expiry means the VM has never been paid for and is treated as
/// expired. An expiry at or before `now` is also expired.
fn is_vm_expired(expires: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    expires.map(|e| e <= now).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lnvps_db::PaymentMethodConfig;

    fn make_config(
        id: u64,
        method: PaymentMethod,
        enabled: bool,
        fee_rate: Option<f32>,
        fee_base: Option<u64>,
        fee_currency: Option<&str>,
    ) -> PaymentMethodConfig {
        make_config_with_currencies(
            id,
            method,
            enabled,
            fee_rate,
            fee_base,
            fee_currency,
            vec![],
        )
    }

    fn make_config_with_currencies(
        id: u64,
        method: PaymentMethod,
        enabled: bool,
        fee_rate: Option<f32>,
        fee_base: Option<u64>,
        fee_currency: Option<&str>,
        supported_currencies: Vec<&str>,
    ) -> PaymentMethodConfig {
        PaymentMethodConfig {
            id,
            company_id: 1,
            payment_method: method,
            name: format!("{:?}", method),
            enabled,
            provider_type: "test".to_string(),
            config: None,
            processing_fee_rate: fee_rate,
            processing_fee_base: fee_base,
            processing_fee_currency: fee_currency.map(String::from),
            min_amount: None,
            min_amount_currency: None,
            supported_currencies: lnvps_db::CommaSeparated::new(
                supported_currencies.into_iter().map(String::from).collect(),
            ),
            created: Utc::now(),
            modified: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_build_account_tax_info_eu_seller() {
        use lnvps_db::LNVpsDbBase;
        let mock = std::sync::Arc::new(lnvps_api_common::MockDb::default());
        {
            // Make the default company an EU (Irish) seller.
            let mut companies = mock.companies.lock().await;
            companies.get_mut(&1).unwrap().country_code = Some("IRL".to_string());
        }
        let uid = mock.upsert_user(&[1; 32]).await.unwrap();
        {
            // EU (Irish) customer with no VAT number -> domestic rate.
            let mut users = mock.users.lock().await;
            users.get_mut(&uid).unwrap().country_code = Some("IRL".to_string());
        }
        let db: std::sync::Arc<dyn LNVpsDb> = mock;
        let vat = VatClient::with_rates(HashMap::from([(CountryCode::IRL, 23.0)]));
        let pricing = PricingEngine::new(
            db.clone(),
            std::sync::Arc::new(lnvps_api_common::MockExchangeRate::new()),
            vat,
        );
        let info = build_account_tax_info(db.as_ref(), &pricing, uid).await;
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].company_id, 1);
        assert_eq!(info[0].company_name, "Default Company");
        assert_eq!(info[0].rate, 23.0);
        assert_eq!(info[0].country_code.as_deref(), Some("IRL"));
        assert_eq!(info[0].treatment, "domestic");
    }

    #[tokio::test]
    async fn test_build_account_tax_info_non_eu_seller() {
        // Default mock company has no country / VAT number -> out of scope, 0%.
        let db: std::sync::Arc<dyn LNVpsDb> =
            std::sync::Arc::new(lnvps_api_common::MockDb::default());
        let uid = db.upsert_user(&[1; 32]).await.unwrap();
        let pricing = PricingEngine::new(
            db.clone(),
            std::sync::Arc::new(lnvps_api_common::MockExchangeRate::new()),
            VatClient::default(),
        );
        let info = build_account_tax_info(db.as_ref(), &pricing, uid).await;
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].rate, 0.0);
        assert_eq!(info[0].treatment, "out_of_scope");
    }

    #[test]
    fn test_payment_methods_empty_configs() {
        let result = build_payment_methods_response(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_payment_methods_lightning_includes_nwc_and_lnurl() {
        let configs = vec![make_config(
            1,
            PaymentMethod::Lightning,
            true,
            None,
            None,
            None,
        )];
        let result = build_payment_methods_response(configs);

        assert_eq!(result.len(), 3);
        assert!(matches!(result[0].name, ApiPaymentMethod::Lightning));
        assert!(matches!(result[1].name, ApiPaymentMethod::NWC));
        assert!(matches!(result[2].name, ApiPaymentMethod::LNURL));
        assert_eq!(result[0].currencies, vec![ApiCurrency::BTC]);
        assert_eq!(result[1].currencies, vec![ApiCurrency::BTC]);
        assert_eq!(result[2].currencies, vec![ApiCurrency::BTC]);
    }

    #[test]
    fn test_payment_methods_disabled_lightning_no_nwc() {
        let configs = vec![make_config(
            1,
            PaymentMethod::Lightning,
            false,
            None,
            None,
            None,
        )];
        let result = build_payment_methods_response(configs);

        assert!(result.is_empty());
    }

    #[test]
    fn test_payment_methods_fiat_only_no_nwc() {
        let configs = vec![make_config(
            1,
            PaymentMethod::Revolut,
            true,
            Some(2.5),
            Some(30),
            Some("EUR"),
        )];
        let result = build_payment_methods_response(configs);

        assert_eq!(result.len(), 1);
        assert!(matches!(result[0].name, ApiPaymentMethod::Revolut));
        assert_eq!(
            result[0].currencies,
            vec![ApiCurrency::EUR, ApiCurrency::USD]
        );
        // No NWC since no Lightning
    }

    #[test]
    fn test_payment_methods_processing_fees_included() {
        let configs = vec![make_config(
            1,
            PaymentMethod::Stripe,
            true,
            Some(2.9),
            Some(30),
            Some("USD"),
        )];
        let result = build_payment_methods_response(configs);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].processing_fee_rate, Some(2.9));
        assert_eq!(result[0].processing_fee_base, Some(30));
        assert_eq!(result[0].processing_fee_currency, Some("USD".to_string()));
    }

    #[test]
    fn test_payment_methods_mixed_enabled_disabled() {
        let configs = vec![
            make_config(1, PaymentMethod::Lightning, true, None, None, None),
            make_config(2, PaymentMethod::Revolut, false, Some(1.5), None, None),
            make_config(
                3,
                PaymentMethod::Stripe,
                true,
                Some(2.9),
                Some(30),
                Some("EUR"),
            ),
        ];
        let result = build_payment_methods_response(configs);

        // Lightning + Stripe + NWC + LNURL (because Lightning is enabled)
        assert_eq!(result.len(), 4);

        let names: Vec<_> = result.iter().map(|p| p.name).collect();
        assert!(names.contains(&ApiPaymentMethod::Lightning));
        assert!(names.contains(&ApiPaymentMethod::Stripe));
        assert!(names.contains(&ApiPaymentMethod::NWC));
        assert!(names.contains(&ApiPaymentMethod::LNURL));
        assert!(!names.contains(&ApiPaymentMethod::Revolut)); // disabled
    }

    #[test]
    fn test_payment_methods_all_payment_types_currencies() {
        let configs = vec![
            make_config(1, PaymentMethod::Lightning, true, None, None, None),
            make_config(2, PaymentMethod::Revolut, true, None, None, None),
            make_config(3, PaymentMethod::Paypal, true, None, None, None),
            make_config(4, PaymentMethod::Stripe, true, None, None, None),
        ];
        let result = build_payment_methods_response(configs);

        // 4 methods + NWC + LNURL = 6
        assert_eq!(result.len(), 6);

        for info in &result {
            match info.name {
                ApiPaymentMethod::Lightning
                | ApiPaymentMethod::NWC
                | ApiPaymentMethod::LNURL
                | ApiPaymentMethod::OnChain => {
                    assert_eq!(info.currencies, vec![ApiCurrency::BTC]);
                }
                ApiPaymentMethod::Revolut | ApiPaymentMethod::Paypal | ApiPaymentMethod::Stripe => {
                    assert_eq!(info.currencies, vec![ApiCurrency::EUR, ApiCurrency::USD]);
                }
            }
        }
    }

    #[test]
    fn test_payment_methods_custom_currencies() {
        let configs = vec![make_config_with_currencies(
            1,
            PaymentMethod::Stripe,
            true,
            None,
            None,
            None,
            vec!["GBP", "CHF", "EUR"],
        )];
        let result = build_payment_methods_response(configs);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].currencies,
            vec![ApiCurrency::GBP, ApiCurrency::CHF, ApiCurrency::EUR]
        );
    }

    #[test]
    fn test_payment_methods_custom_currencies_invalid_ignored() {
        let configs = vec![make_config_with_currencies(
            1,
            PaymentMethod::Stripe,
            true,
            None,
            None,
            None,
            vec!["EUR", "INVALID", "USD"],
        )];
        let result = build_payment_methods_response(configs);

        assert_eq!(result.len(), 1);
        // INVALID should be skipped
        assert_eq!(
            result[0].currencies,
            vec![ApiCurrency::EUR, ApiCurrency::USD]
        );
    }

    // Regression test for issue #141: re-installing an expired VM must be
    // rejected up-front (mapped to 402 PaymentRequired) instead of running the
    // reinstall pipeline that fails with a 500.
    #[test]
    fn test_is_vm_expired() {
        let now = Utc::now();

        // Never paid (no subscription expiry) -> expired
        assert!(is_vm_expired(None, now));

        // Expired in the past -> expired
        assert!(is_vm_expired(Some(now - chrono::Duration::hours(1)), now));

        // Exactly now -> expired (boundary)
        assert!(is_vm_expired(Some(now), now));

        // Future expiry -> not expired
        assert!(!is_vm_expired(Some(now + chrono::Duration::hours(1)), now));
    }

    #[test]
    fn test_expired_vm_reinstall_error_is_payment_required() {
        let err = ApiError::payment_required("Cannot re-install an expired VM");
        assert_eq!(err.code, axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn invoice_vat_display_domestic_shows_rate_line() {
        let (label, rc, oos, note) =
            invoice_vat_display(Some("domestic"), 230, Some(23.0), Some("IRL"), true);
        assert_eq!(label.as_deref(), Some("23% (IRL)"));
        assert!(!rc && !oos);
        assert!(note.is_none());
    }

    #[test]
    fn invoice_vat_display_oss_shows_destination_rate() {
        let (label, rc, oos, _note) =
            invoice_vat_display(Some("oss_b2c"), 1900, Some(19.0), Some("DEU"), true);
        assert_eq!(label.as_deref(), Some("19% (DEU)"));
        assert!(!rc && !oos);
    }

    #[test]
    fn invoice_vat_display_reverse_charge_has_note_no_rate() {
        let (label, rc, oos, note) =
            invoice_vat_display(Some("reverse_charge"), 0, None, Some("DEU"), true);
        assert!(label.is_none());
        assert!(rc && !oos);
        assert!(note.unwrap().contains("Article 196"));
    }

    #[test]
    fn invoice_vat_display_out_of_scope_note_only_for_eu_seller() {
        // EU seller selling to a non-EU customer: out-of-scope note shown.
        let (label, rc, oos, note) =
            invoice_vat_display(Some("out_of_scope"), 0, None, Some("USA"), true);
        assert!(label.is_none());
        assert!(!rc && oos);
        assert_eq!(note.as_deref(), Some("Outside the scope of EU VAT."));

        // Non-EU (e.g. US) seller: no EU note at all.
        let (label, rc, oos, note) =
            invoice_vat_display(Some("out_of_scope"), 0, None, Some("USA"), false);
        assert!(label.is_none());
        assert!(!rc && !oos);
        assert!(note.is_none());
    }

    #[test]
    fn invoice_vat_display_no_tax_no_line() {
        // No treatment recorded and no tax -> nothing shown.
        let (label, rc, oos, note) = invoice_vat_display(None, 0, None, None, true);
        assert!(label.is_none());
        assert!(!rc && !oos);
        assert!(note.is_none());
    }

    #[test]
    fn invoice_vat_display_mixed_summary_null_but_taxed() {
        // Mixed payment: summary rate/country are null but tax was charged.
        let (label, _rc, _oos, _note) = invoice_vat_display(None, 500, None, None, true);
        assert_eq!(label.as_deref(), Some("VAT"));
    }
}
