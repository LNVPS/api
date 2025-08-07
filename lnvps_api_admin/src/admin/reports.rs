use crate::admin::auth::AdminAuth;
use chrono::NaiveDate;
use lnvps_api_common::{ApiData, ApiResult, Currency, CurrencyAmount};
use lnvps_db::{AdminAction, AdminResource, LNVpsDb};
use rocket::{get, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct SalesReportItem {
    description: String,
    currency: String,
    qty: i32,
    rate: f64,
    tax: f64,
}

#[derive(Serialize, Deserialize)]
pub struct SalesReport {
    date: String,
    exchange_rate: HashMap<String, f64>,
    items: Vec<SalesReportItem>,
}

#[get("/api/admin/v1/reports/monthly-sales/<year>/<month>")]
pub async fn admin_monthly_sales_report(
    auth: AdminAuth,
    year: u32,
    month: u32,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<SalesReport> {
    // Check permissions
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;
    
    // Validate month
    if month < 1 || month > 12 {
        return Err(anyhow::anyhow!("Invalid month. Must be between 1 and 12.").into());
    }
    
    // Create date range for the month
    let start_date = NaiveDate::from_ymd_opt(year as i32, month, 1)
        .ok_or_else(|| anyhow::anyhow!("Invalid date"))?
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid time"))?
        .and_utc();
    
    let end_date = if month == 12 {
        NaiveDate::from_ymd_opt(year as i32 + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(year as i32, month + 1, 1)
    }
    .ok_or_else(|| anyhow::anyhow!("Invalid date"))?
    .and_hms_opt(0, 0, 0)
    .ok_or_else(|| anyhow::anyhow!("Invalid time"))?
    .and_utc();

    // Get all payments for the month
    let payments = db.get_payments_by_date_range(start_date, end_date).await?;

    // Group payments by currency and calculate net totals and tax rates
    let mut currency_net_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_gross_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_tax_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_rates: HashMap<String, Vec<f32>> = HashMap::new();
    let mut exchange_rates = HashMap::new();
    
    for payment in &payments {
        // Parse currency using the existing system
        if let Ok(currency) = Currency::from_str(&payment.currency) {
            // Create CurrencyAmount for gross amount, tax, and net amount
            let gross_amount = CurrencyAmount::from_u64(currency, payment.amount);
            let tax_amount = CurrencyAmount::from_u64(currency, payment.tax);
            let net_amount = CurrencyAmount::from_u64(currency, payment.amount.saturating_sub(payment.tax));
            
            // Accumulate totals by currency
            currency_gross_totals.insert(
                currency,
                currency_gross_totals.get(&currency)
                    .map(|existing| CurrencyAmount::from_u64(currency, existing.value() + gross_amount.value()))
                    .unwrap_or(gross_amount)
            );
            
            currency_tax_totals.insert(
                currency,
                currency_tax_totals.get(&currency)
                    .map(|existing| CurrencyAmount::from_u64(currency, existing.value() + tax_amount.value()))
                    .unwrap_or(tax_amount)
            );
            
            currency_net_totals.insert(
                currency,
                currency_net_totals.get(&currency)
                    .map(|existing| CurrencyAmount::from_u64(currency, existing.value() + net_amount.value()))
                    .unwrap_or(net_amount)
            );
            
            // Collect rates for averaging (only for non-EUR currencies)
            if currency != Currency::EUR {
                currency_rates.entry(format!("{}_EUR", currency)).or_insert_with(Vec::new).push(payment.rate);
            }
        }
    }

    // Calculate average exchange rates for each currency
    for (rate_key, rates) in currency_rates {
        if !rates.is_empty() {
            let average_rate = rates.iter().sum::<f32>() / rates.len() as f32;
            exchange_rates.insert(rate_key, average_rate as f64);
        }
    }

    // Create line items for each currency using the currency system
    let mut items = Vec::new();
    for currency in currency_net_totals.keys() {
        let net_total = currency_net_totals.get(currency).unwrap();
        let tax_total = currency_tax_totals.get(currency).unwrap();
        
        // Calculate tax rate as percentage: (tax_total / net_total) * 100
        let tax_rate = if net_total.value() > 0 {
            (tax_total.value_f32() / net_total.value_f32() * 100.0) as f64
        } else {
            0.0
        };
        
        items.push(SalesReportItem {
            description: "LNVPS Sales".to_string(),
            currency: currency.to_string(),
            qty: 1,
            rate: net_total.value_f32() as f64, // Net amount only
            tax: tax_rate, // Tax rate as percentage
        });
    }

    // Use the last day of the month for the report date
    let report_date = if month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        // Leap year February
        format!("{}-{:02}-29", year, month)
    } else if month == 2 {
        format!("{}-{:02}-28", year, month)
    } else if month == 4 || month == 6 || month == 9 || month == 11 {
        format!("{}-{:02}-30", year, month)
    } else {
        format!("{}-{:02}-31", year, month)
    };

    let report = SalesReport {
        date: report_date,
        exchange_rate: exchange_rates,
        items,
    };

    ApiData::ok(report)
}