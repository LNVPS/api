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
}

#[derive(Serialize, Deserialize)]
pub struct SalesReport {
    date: String,
    exchange_rate: HashMap<String, f64>,
    items: Vec<SalesReportItem>,
}

#[get("/api/admin/v1/reports/monthly-sales/<year>/<month>/<company_id>")]
pub async fn admin_monthly_sales_report(
    auth: AdminAuth,
    year: u32,
    month: u32,
    company_id: u64,
    db: &State<Arc<dyn LNVpsDb>>,
) -> ApiResult<SalesReport> {
    // Check permissions
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;
    
    // Validate month
    if month < 1 || month > 12 {
        return Err(anyhow::anyhow!("Invalid month. Must be between 1 and 12.").into());
    }

    // Get company and its base currency
    let company = db.get_company(company_id).await?;
    let base_currency: Currency = company.base_currency.parse()
        .map_err(|_| anyhow::anyhow!("Invalid base currency: {}", company.base_currency))?;
    
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

    // Get all payments for the month for this company
    let payments = db.admin_get_payments_by_date_range_and_company(start_date, end_date, company_id).await?;

    // Group payments by currency and calculate totals
    let mut currency_net_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_tax_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_gross_totals: HashMap<Currency, CurrencyAmount> = HashMap::new();
    let mut currency_base_equivalents: HashMap<Currency, f64> = HashMap::new();
    let mut exchange_rates = HashMap::new();
    
    for payment in &payments {
        // Parse currency using the existing system
        if let Ok(currency) = Currency::from_str(&payment.currency) {
            // Create CurrencyAmount for tax, net, and gross amounts
            let tax_amount = CurrencyAmount::from_u64(currency, payment.tax);
            let net_amount = CurrencyAmount::from_u64(currency, payment.amount); // payment.amount is already net
            let gross_amount = CurrencyAmount::from_u64(currency, payment.amount + payment.tax);
            
            // Accumulate totals by currency
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
            
            currency_gross_totals.insert(
                currency,
                currency_gross_totals.get(&currency)
                    .map(|existing| CurrencyAmount::from_u64(currency, existing.value() + gross_amount.value()))
                    .unwrap_or(gross_amount)
            );
            
            // Calculate base currency equivalent for this payment (gross_amount * rate)
            if currency != base_currency {
                let base_equivalent = gross_amount.value_f32() * payment.rate;
                *currency_base_equivalents.entry(currency).or_insert(0.0) += base_equivalent as f64;
            }
        }
    }

    // Calculate correct exchange rates that ensure (net + tax) * rate = total_base_equivalent
    for (currency, base_total) in currency_base_equivalents {
        if let Some(gross_total) = currency_gross_totals.get(&currency) {
            let gross_amount = gross_total.value_f32() as f64;
            if gross_amount > 0.0 {
                let calculated_rate = base_total / gross_amount;
                exchange_rates.insert(format!("{}_{}", currency, base_currency), calculated_rate);
            }
        }
    }

    // Create line items for each currency - separate items for sales and taxes
    let mut items = Vec::new();
    
    // Add net sales line items
    for (currency, net_total) in &currency_net_totals {
        if net_total.value() > 0 {
            items.push(SalesReportItem {
                description: "LNVPS Sales".to_string(),
                currency: currency.to_string(),
                qty: 1,
                rate: net_total.value_f32() as f64,
            });
        }
    }
    
    // Add tax line items
    for (currency, tax_total) in &currency_tax_totals {
        if tax_total.value() > 0 {
            items.push(SalesReportItem {
                description: "Tax Collected".to_string(),
                currency: currency.to_string(),
                qty: 1,
                rate: tax_total.value_f32() as f64,
            });
        }
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