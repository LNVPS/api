use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use axum::routing::get;
use base64::Engine;
use chrono::Utc;
use isocountry::CountryCode;
use nostr_sdk::ToBech32;
use serde::{Deserialize, Serialize};
use std::io::Cursor;

use lnvps_api_common::{ApiData, ApiError, ApiResult, Nip98Auth};

use crate::api::RouterState;

/// Query parameters for generating an unsigned Sponsoring LIR Agreement
#[derive(Deserialize)]
pub struct SponsoringLirAgreementQuery {
    /// Base64-encoded JSON of AgreementData
    pub data: String,
}

/// Agreement data for Sponsoring LIR Agreement
#[derive(Serialize, Deserialize, Clone)]
pub struct AgreementData {
    // Agreement metadata
    pub effective_date: String,
    pub document_reference: String,

    // Provider details (from company)
    pub provider_trading_name: String,
    pub provider_legal_name: String,
    pub provider_address: String,
    pub provider_register: String,

    // End user details (from user account)
    pub end_user_name: String,
    pub end_user_legal_form: String,
    pub end_user_address: String,
    pub end_user_registration_number: String,
    pub end_user_email: String,

    // Financial
    pub currency: String,
    pub administration_fee: String,
    pub maintenance_fee: String,
    pub maintenance_fee_frequency: String,
    pub maintenance_fee_invoicing: String,

    // Legal
    pub governing_law_country: String,
    pub jurisdiction_country: String,

    // Resources (optional, can be filled in later)
    pub resources: Vec<ResourceRequest>,
    pub technical_justification: String,

    // Signature placeholders
    pub provider_signatory_name: String,
    pub provider_signatory_title: String,
    pub provider_signature_date: String,
    pub end_user_signatory_name: String,
    pub end_user_signatory_title: String,
    pub end_user_signature_date: String,

    // Nostr keys
    pub end_user_npub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_npub: Option<String>,

    // Cryptographic proof (optional, only if nostr config is available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_proof: Option<CryptographicProof>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptographicProof {
    pub provider_npub: String,
    pub end_user_npub: String,
    pub generated_at: String,
    pub event_id: String,
    pub signature: String,
    // The JSON data that was signed
    pub signed_json: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResourceRequest {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub quantity: String,
    pub purpose: String,
}

/// Response containing the signed agreement URL
#[derive(Serialize)]
pub struct SignedAgreementUrlResponse {
    pub url: String,
    pub agreement_data: AgreementData,
}

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/v1/legal/sponsoring-lir-agreement",
            get(v1_get_sponsoring_lir_agreement),
        )
        .route(
            "/api/v1/legal/sponsoring-lir-agreement/from-subscription/{subscription_id}",
            get(v1_generate_lir_agreement_from_subscription),
        )
}

/// Render Sponsoring LIR Agreement HTML from AgreementData
fn render_lir_agreement(data: &AgreementData) -> Result<Html<String>, &'static str> {
    #[cfg(debug_assertions)]
    let template = mustache::compile_path("legal/Sponsoring_LIR_Agreement.html")
        .map_err(|_| "Invalid template")?;
    #[cfg(not(debug_assertions))]
    let template =
        mustache::compile_str(include_str!("../../../legal/Sponsoring_LIR_Agreement.html"))
            .map_err(|_| "Invalid template")?;

    let mut html = Cursor::new(Vec::new());
    template
        .render(&mut html, &data)
        .map_err(|_| "Failed to generate agreement")?;
    Ok(Html(String::from_utf8(html.into_inner()).unwrap()))
}

/// Generate unsigned Sponsoring LIR Agreement from base64-encoded data
async fn v1_get_sponsoring_lir_agreement(
    Query(q): Query<SponsoringLirAgreementQuery>,
) -> Result<Html<String>, &'static str> {
    // Decode base64-encoded JSON
    let json_bytes = base64::Engine::decode(&base64::prelude::BASE64_URL_SAFE, &q.data)
        .map_err(|_| "Invalid base64 encoding")?;
    let data: AgreementData =
        serde_json::from_slice(&json_bytes).map_err(|_| "Invalid agreement data JSON")?;

    // Ensure there's no cryptographic proof in unsigned agreements
    if data.cryptographic_proof.is_some() {
        return Err("Cannot generate unsigned agreement with cryptographic proof");
    }

    render_lir_agreement(&data)
}

/// Generate signed LIR Agreement from a subscription
async fn v1_generate_lir_agreement_from_subscription(
    auth: Nip98Auth,
    State(this): State<RouterState>,
    Path(subscription_id): Path<u64>,
) -> ApiResult<SignedAgreementUrlResponse> {
    use nostr::{EventBuilder, Keys, Kind, Tag, TagKind, TagStandard, ToBech32};
    use nostr_sdk::PublicKey as NostrSdkPublicKey;

    let end_user_pubkey = auth.event.pubkey;
    let pubkey_bytes = end_user_pubkey.to_bytes();
    let uid = this.db.upsert_user(&pubkey_bytes).await?;
    let user = this.db.get_user(uid).await?;

    // Get subscription
    let subscription = this.db.get_subscription(subscription_id).await?;
    if subscription.user_id != uid {
        return ApiData::err("Subscription does not belong to you");
    }

    // Get company for this subscription
    let company = this.db.get_company(subscription.company_id).await?;

    // Get line items for this subscription
    let line_items = this
        .db
        .list_subscription_line_items(subscription_id)
        .await?;

    // Build provider address from company fields
    let provider_address = [
        company.address_1.as_deref(),
        company.address_2.as_deref(),
        company.city.as_deref(),
        company.state.as_deref(),
        company.postcode.as_deref(),
        company.country_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ");

    // Build end user address from user billing fields
    let end_user_address = [
        user.billing_address_1.as_deref(),
        user.billing_address_2.as_deref(),
        user.billing_city.as_deref(),
        user.billing_state.as_deref(),
        user.billing_postcode.as_deref(),
        user.country_code.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ");

    // Get country name for governing law
    let governing_law_country = company
        .country_code
        .as_ref()
        .and_then(|cc| CountryCode::for_alpha2(cc).ok())
        .map(|c| c.name().to_string())
        .unwrap_or_else(|| "Ireland".to_string());

    let now = Utc::now();
    let document_reference = format!(
        "LNVPS-LIR-{}-{}",
        subscription_id,
        now.format("%Y%m%d%H%M%S")
    );

    // Calculate total recurring fees
    let total_recurring: u64 = line_items.iter().map(|li| li.amount).sum();
    let total_setup: u64 = line_items.iter().map(|li| li.setup_amount).sum();

    // Build resources list from line items
    let resources: Vec<ResourceRequest> = line_items
        .iter()
        .map(|li| {
            let resource_type = match li.subscription_type {
                lnvps_db::SubscriptionType::IpRange => {
                    // Try to extract IP range info from configuration
                    li.configuration
                        .as_ref()
                        .and_then(|cfg| cfg.get("cidr").and_then(|c| c.as_str()))
                        .map(|cidr| {
                            if cidr.contains(':') {
                                "IPv6 PI"
                            } else {
                                "IPv4 PI"
                            }
                        })
                        .unwrap_or("IP Range")
                        .to_string()
                }
                lnvps_db::SubscriptionType::AsnSponsoring => "AS Number".to_string(),
                lnvps_db::SubscriptionType::DnsHosting => "DNS Hosting".to_string(),
            };

            let quantity = li
                .configuration
                .as_ref()
                .and_then(|cfg| cfg.get("cidr").and_then(|c| c.as_str()))
                .unwrap_or("—")
                .to_string();

            ResourceRequest {
                resource_type,
                quantity,
                purpose: li.description.clone().unwrap_or_else(|| li.name.clone()),
            }
        })
        .collect();

    // Get end user npub - convert from nostr::PublicKey to nostr_sdk::PublicKey for bech32
    let end_user_npub = NostrSdkPublicKey::from_slice(&pubkey_bytes)
        .ok()
        .and_then(|pk| pk.to_bech32().ok())
        .unwrap_or_else(|| hex::encode(pubkey_bytes));

    // Convert amounts to currency display
    let currency = &subscription.currency;
    let administration_fee = if total_setup > 0 {
        format!("{:.2}", total_setup as f64 / 100.0)
    } else {
        "—".to_string()
    };
    let maintenance_fee = if total_recurring > 0 {
        format!("{:.2}", total_recurring as f64 / 100.0)
    } else {
        "—".to_string()
    };

    let mut data = AgreementData {
        effective_date: subscription.created.format("%Y-%m-%d").to_string(),
        document_reference: document_reference.clone(),

        provider_trading_name: company.name.clone(),
        provider_legal_name: company.name.clone(),
        provider_address,
        provider_register: company.tax_id.clone().unwrap_or_else(|| "—".to_string()),

        end_user_name: user.billing_name.clone().unwrap_or_else(|| "—".to_string()),
        end_user_legal_form: "—".to_string(),
        end_user_address,
        end_user_registration_number: user
            .billing_tax_id
            .clone()
            .unwrap_or_else(|| "—".to_string()),
        end_user_email: user.email.as_str().to_string(),

        currency: currency.clone(),
        administration_fee,
        maintenance_fee,
        maintenance_fee_frequency: "Monthly".to_string(),
        maintenance_fee_invoicing: "monthly in advance".to_string(),

        governing_law_country: governing_law_country.clone(),
        jurisdiction_country: governing_law_country,

        resources,
        technical_justification: subscription.description.clone().unwrap_or_default(),

        provider_signatory_name: "—".to_string(),
        provider_signatory_title: "—".to_string(),
        provider_signature_date: now.format("%Y-%m-%d").to_string(),
        end_user_signatory_name: user.billing_name.clone().unwrap_or_default(),
        end_user_signatory_title: "—".to_string(),
        end_user_signature_date: now.format("%Y-%m-%d").to_string(),

        end_user_npub,
        provider_npub: None,
        cryptographic_proof: None,
    };

    // Sign the agreement data with provider's Nostr key
    if let Some(ref nostr_config) = this.settings.nostr {
        let keys = Keys::parse(&nostr_config.nsec)
            .map_err(|e| ApiError::internal(format!("Invalid nostr key: {}", e)))?;
        let provider_pubkey = keys.public_key();
        let provider_npub = provider_pubkey
            .to_bech32()
            .unwrap_or_else(|_| hex::encode(provider_pubkey.to_bytes()));
        data.provider_npub = Some(provider_npub.clone());

        // Serialize the data WITHOUT the proof section for the signature
        let signed_json = serde_json::to_string(&data).map_err(|e| {
            ApiError::internal(format!("Failed to serialize agreement data: {}", e))
        })?;

        // Create a Nostr event signing the JSON data
        let event = EventBuilder::new(Kind::TextNote, signed_json.clone())
            .tags([
                Tag::identifier(&document_reference),
                Tag::from_standardized(TagStandard::PublicKey {
                    public_key: end_user_pubkey,
                    relay_url: None,
                    alias: None,
                    uppercase: false,
                }),
                Tag::custom(TagKind::from("type"), ["sponsoring-lir-agreement"]),
            ])
            .sign_with_keys(&keys)
            .map_err(|e| ApiError::internal(format!("Failed to sign event: {}", e)))?;

        data.cryptographic_proof = Some(CryptographicProof {
            provider_npub,
            end_user_npub: data.end_user_npub.clone(),
            generated_at: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            event_id: hex::encode(event.id.to_bytes()),
            signature: hex::encode(event.sig.as_ref()),
            signed_json,
        });
    } else {
        return ApiData::err("Nostr configuration not available for signing");
    }

    // Encode the signed data as base64 URL-safe
    let json_bytes = serde_json::to_vec(&data)
        .map_err(|e| ApiError::internal(format!("Failed to serialize agreement: {}", e)))?;
    let encoded = base64::Engine::encode(&base64::prelude::BASE64_URL_SAFE, &json_bytes);

    // Build the full URL to the signed agreement
    let url = format!("/api/v1/legal/sponsoring-lir-agreement?data={}", encoded);

    ApiData::ok(SignedAgreementUrlResponse {
        url,
        agreement_data: data,
    })
}
