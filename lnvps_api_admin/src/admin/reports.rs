use crate::admin::auth::AdminAuth;
use chrono::{Duration, Datelike, NaiveDate};
use lnvps_api_common::{ApiData, ApiResult, Currency, CurrencyAmount};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::{get, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;


#[derive(Serialize, Deserialize)]
pub struct TimeSeriesPayment {
    id: String,                       // Hex-encoded payment ID
    vm_id: u64,
    created: String,                  // ISO 8601 timestamp
    expires: String,                  // ISO 8601 timestamp
    amount: u64,                      // Amount in smallest currency unit
    currency: String,
    payment_method: String,
    external_id: Option<String>,
    is_paid: bool,
    rate: f32,                        // Exchange rate to company's base currency
    time_value: u64,                  // Seconds this payment adds to VM expiry
    tax: u64,                         // Tax amount in smallest currency unit
    // Company information
    company_id: u64,
    company_name: String,
    company_base_currency: String,
    // Time series grouping
    period: String,                   // Calculated period based on interval
}

#[derive(Serialize, Deserialize)]
pub struct TimeSeriesPeriodSummary {
    period: String,                   // Period identifier (e.g., "2025-01", "2025-Q1")
    currency: String,                 // Currency for this period summary
    payment_count: u32,               // Number of payments in this period/currency
    net_total: u64,                   // Total net amount (excluding tax) in smallest currency unit
    tax_total: u64,                   // Total tax collected in smallest currency unit
    base_currency_net: u64,           // Total net amount converted to company's base currency in smallest unit
    base_currency_tax: u64,           // Total tax amount converted to company's base currency in smallest unit
}

#[derive(Serialize, Deserialize)]
pub struct TimeSeriesReport {
    start_date: String,               // Start date of the report period
    end_date: String,                 // End date of the report period
    interval: String,                 // "daily", "weekly", "monthly", "quarterly", "yearly"
    company_id: u64,                  // Company ID for this report
    company_name: String,             // Company name
    company_base_currency: String,    // Company's base currency
    period_summaries: Vec<TimeSeriesPeriodSummary>, // Aggregated data by period and currency
    payments: Vec<TimeSeriesPayment>, // Raw payment data with period grouping (optional detail)
}


#[get("/api/admin/v1/reports/time-series?<start_date>&<end_date>&<interval>&<company_id>&<currency>")]
pub async fn admin_time_series_report(
    auth: AdminAuth,
    start_date: String,          // ISO 8601 date (e.g., "2025-01-01")
    end_date: String,            // ISO 8601 date (e.g., "2025-12-31")
    interval: String,            // "daily", "weekly", "monthly", "quarterly", "yearly"
    company_id: u64,             // Required: company ID to generate report for
    currency: Option<String>,    // Optional: filter by specific currency
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
    
    // Validate interval
    let valid_intervals = ["daily", "weekly", "monthly", "quarterly", "yearly"];
    if !valid_intervals.contains(&interval.as_str()) {
        return Err(anyhow::anyhow!("Invalid interval. Must be one of: {}", valid_intervals.join(", ")).into());
    }
    
    // Validate currency if provided
    if let Some(ref currency_str) = currency {
        currency_str.parse::<Currency>()
            .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency_str))?;
    }
    
    // Convert dates to UTC datetime for database query
    let start_datetime = start_date_parsed.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_datetime = end_date_parsed.and_hms_opt(23, 59, 59).unwrap().and_utc();
    
    // Use the new optimized database query
    let payments = db.admin_get_payments_with_company_info(
        start_datetime, 
        end_datetime, 
        company_id,
        currency.as_deref()
    ).await?;
    
    // Process payments and build both raw data and period aggregations
    let mut time_series_payments = Vec::new();
    let mut period_aggregations: HashMap<(String, String), (u32, u64, u64, u64, u64)> = HashMap::new(); // (period, currency) -> (count, net, tax, base_net, base_tax)
    let mut company_info: Option<(u64, String, String)> = None;
    
    for payment in payments {
        // Calculate period string based on interval
        let period_str = match interval.as_str() {
            "daily" => payment.created.format("%Y-%m-%d").to_string(),
            "weekly" => {
                // Week starting Monday
                let days_since_monday = payment.created.weekday().num_days_from_monday();
                let week_start = payment.created.date_naive() - Duration::days(days_since_monday as i64);
                week_start.format("%Y-%m-%d").to_string()
            },
            "monthly" => payment.created.format("%Y-%m").to_string(),
            "quarterly" => {
                let quarter = (payment.created.month() - 1) / 3 + 1;
                format!("{}-Q{}", payment.created.year(), quarter)
            },
            "yearly" => payment.created.format("%Y").to_string(),
            _ => unreachable!() // Already validated above
        };
        
        // Store company info (same for all payments since we filter by company)
        if company_info.is_none() {
            company_info = Some((payment.company_id, payment.company_name.clone(), payment.company_base_currency.clone()));
        }
        
        // Calculate separate base currency conversions for net and tax amounts
        let payment_currency = Currency::from_str(&payment.currency)
            .map_err(|_| anyhow::anyhow!("Invalid payment currency: {}", payment.currency))?;
        let base_currency = Currency::from_str(&payment.company_base_currency)
            .map_err(|_| anyhow::anyhow!("Invalid base currency: {}", payment.company_base_currency))?;
        
        let (base_currency_net, base_currency_tax) = if payment_currency == base_currency {
            // No conversion needed - use original amounts
            (payment.amount, payment.tax)
        } else {
            // Convert net amount to base currency
            let net_amount_decimal = CurrencyAmount::from_u64(payment_currency, payment.amount);
            let base_net_decimal = net_amount_decimal.value_f32() * payment.rate;
            let base_currency_net = CurrencyAmount::from_f32(base_currency, base_net_decimal).value();
            
            // Convert tax amount to base currency
            let tax_amount_decimal = CurrencyAmount::from_u64(payment_currency, payment.tax);
            let base_tax_decimal = tax_amount_decimal.value_f32() * payment.rate;
            let base_currency_tax = CurrencyAmount::from_f32(base_currency, base_tax_decimal).value();
            
            (base_currency_net, base_currency_tax)
        };
        
        // Aggregate by period and currency
        let key = (period_str.clone(), payment.currency.clone());
        let entry = period_aggregations.entry(key).or_insert((0, 0, 0, 0, 0));
        entry.0 += 1; // payment count
        entry.1 += payment.amount; // net total
        entry.2 += payment.tax; // tax total
        entry.3 += base_currency_net; // base currency net total
        entry.4 += base_currency_tax; // base currency tax total
        
        // Convert payment method enum to string
        let payment_method_str = match payment.payment_method {
            lnvps_db::PaymentMethod::Lightning => "lightning",
            lnvps_db::PaymentMethod::Revolut => "revolut", 
            lnvps_db::PaymentMethod::Paypal => "paypal",
        }.to_string();
        
        time_series_payments.push(TimeSeriesPayment {
            id: hex::encode(&payment.id),
            vm_id: payment.vm_id,
            created: payment.created.to_rfc3339(),
            expires: payment.expires.to_rfc3339(),
            amount: payment.amount,
            currency: payment.currency,
            payment_method: payment_method_str,
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            rate: payment.rate,
            time_value: payment.time_value,
            tax: payment.tax,
            company_id: payment.company_id,
            company_name: payment.company_name.clone(),
            company_base_currency: payment.company_base_currency.clone(),
            period: period_str,
        });
    }
    
    // Convert aggregations to period summaries
    let mut period_summaries: Vec<TimeSeriesPeriodSummary> = period_aggregations
        .into_iter()
        .map(|((period, currency), (payment_count, net_total, tax_total, base_currency_net, base_currency_tax))| {
            TimeSeriesPeriodSummary {
                period,
                currency,
                payment_count,
                net_total,
                tax_total,
                base_currency_net,
                base_currency_tax,
            }
        })
        .collect();
    
    // Sort period summaries by period, then currency
    period_summaries.sort_by(|a, b| {
        a.period.cmp(&b.period).then_with(|| a.currency.cmp(&b.currency))
    });
    
    // Sort payments by created timestamp
    time_series_payments.sort_by(|a, b| a.created.cmp(&b.created));
    
    // Extract company info or use defaults
    let (company_id_val, company_name_val, company_base_currency_val) = company_info
        .unwrap_or((company_id, "Unknown Company".to_string(), "EUR".to_string()));
    
    let report = TimeSeriesReport {
        start_date,
        end_date,
        interval,
        company_id: company_id_val,
        company_name: company_name_val,
        company_base_currency: company_base_currency_val,
        period_summaries,
        payments: time_series_payments,
    };
    
    ApiData::ok(report)
}