use crate::admin::auth::AdminAuth;
use chrono::NaiveDate;
use lnvps_api_common::{ApiData, ApiResult, Currency};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::{get, State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct ReferralReport {
    pub vm_id: u64,
    pub ref_code: String,
    pub created: String,
    pub amount: u64,
    pub currency: String,
    pub rate: f32,
    pub base_currency: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReferralTimeSeriesReport {
    pub start_date: String,
    pub end_date: String,
    pub referrals: Vec<ReferralReport>,
}

#[derive(Serialize, Deserialize)]
pub struct TimeSeriesPayment {
    id: String, // Hex-encoded payment ID
    vm_id: u64,
    created: String, // ISO 8601 timestamp
    expires: String, // ISO 8601 timestamp
    amount: u64,     // Amount in smallest currency unit
    currency: String,
    payment_method: String,
    external_id: Option<String>,
    is_paid: bool,
    rate: f32,       // Exchange rate to company's base currency
    time_value: u64, // Seconds this payment adds to VM expiry
    tax: u64,        // Tax amount in smallest currency unit
    // Company information
    company_id: u64,
    company_name: String,
    company_base_currency: String,
}

#[derive(Serialize, Deserialize)]
pub struct TimeSeriesPeriodSummary {
    period: String,         // Period identifier (e.g., "2025-01", "2025-Q1")
    currency: String,       // Currency for this period summary
    payment_count: u32,     // Number of payments in this period/currency
    net_total: u64,         // Total net amount (excluding tax) in smallest currency unit
    tax_total: u64,         // Total tax collected in smallest currency unit
    base_currency_net: u64, // Total net amount converted to company's base currency in smallest unit
    base_currency_tax: u64, // Total tax amount converted to company's base currency in smallest unit
}

#[derive(Serialize, Deserialize)]
pub struct TimeSeriesReport {
    start_date: String,               // Start date of the report period
    end_date: String,                 // End date of the report period
    payments: Vec<TimeSeriesPayment>, // Raw payment data
}

#[get("/api/admin/v1/reports/time-series?<start_date>&<end_date>&<company_id>&<currency>")]
pub async fn admin_time_series_report(
    auth: AdminAuth,
    start_date: String,       // ISO 8601 date (e.g., "2025-01-01")
    end_date: String,         // ISO 8601 date (e.g., "2025-12-31")
    company_id: u64,          // Required: company ID to generate report for
    currency: Option<String>, // Optional: filter by specific currency
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<TimeSeriesReport> {
    // Check permissions
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    // Parse and validate dates
    let start_date_parsed = NaiveDate::parse_from_str(&start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date_parsed = NaiveDate::parse_from_str(&end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;

    if start_date_parsed >= end_date_parsed {
        return Err(anyhow::anyhow!("start_date must be before end_date").into());
    }

    // Validate currency if provided
    if let Some(ref currency_str) = currency {
        currency_str
            .parse::<Currency>()
            .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency_str))?;
    }

    // Convert dates to UTC datetime for database query
    let start_datetime = start_date_parsed.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_datetime = end_date_parsed.and_hms_opt(23, 59, 59).unwrap().and_utc();

    // Use the new optimized database query
    let payments = db
        .admin_get_payments_with_company_info(
            start_datetime,
            end_datetime,
            company_id,
            currency.as_deref(),
        )
        .await?;

    // Process payments and build raw data
    let mut time_series_payments = Vec::new();

    for payment in payments {
        time_series_payments.push(TimeSeriesPayment {
            id: hex::encode(&payment.id),
            vm_id: payment.vm_id,
            created: payment.created.to_rfc3339(),
            expires: payment.expires.to_rfc3339(),
            amount: payment.amount,
            currency: payment.currency,
            payment_method: payment.payment_method.to_string().to_lowercase(),
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            rate: payment.rate,
            time_value: payment.time_value,
            tax: payment.tax,
            company_id: payment.company_id,
            company_name: payment.company_name.clone(),
            company_base_currency: payment.company_base_currency.clone(),
        });
    }

    // Sort payments by created timestamp
    time_series_payments.sort_by(|a, b| a.created.cmp(&b.created));

    let report = TimeSeriesReport {
        start_date,
        end_date,
        payments: time_series_payments,
    };

    ApiData::ok(report)
}

#[get("/api/admin/v1/reports/referral-usage/time-series?<start_date>&<end_date>&<company_id>&<ref_code>")]
pub async fn admin_referral_time_series_report(
    auth: AdminAuth,
    start_date: String,
    end_date: String,
    company_id: u64,
    ref_code: Option<String>,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<ReferralTimeSeriesReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    // Parse and validate dates
    let start_date_parsed = NaiveDate::parse_from_str(&start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date_parsed = NaiveDate::parse_from_str(&end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;

    if start_date_parsed >= end_date_parsed {
        return Err(anyhow::anyhow!("start_date must be before end_date").into());
    }

    // Convert dates to UTC datetime for database query
    let start_datetime = start_date_parsed.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_datetime = end_date_parsed.and_hms_opt(23, 59, 59).unwrap().and_utc();

    let referral_data = db
        .admin_get_referral_usage_by_date_range(
            start_datetime,
            end_datetime,
            company_id,
            ref_code.as_deref(),
        )
        .await?;

    let mut referrals: Vec<ReferralReport> = referral_data
        .into_iter()
        .map(|data| ReferralReport {
            vm_id: data.vm_id,
            ref_code: data.ref_code,
            created: data.created.to_rfc3339(),
            amount: data.amount,
            currency: data.currency,
            rate: data.rate,
            base_currency: data.base_currency,
        })
        .collect();

    // Sort referrals by created timestamp
    referrals.sort_by(|a, b| a.created.cmp(&b.created));

    let report = ReferralTimeSeriesReport {
        start_date,
        end_date,
        referrals,
    };

    ApiData::ok(report)
}
