use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use lnvps_api_common::{ApiData, ApiError, ApiResult, Ticker, TickerRate};
use lnvps_db::{AdminAction, AdminResource, CostResourceType, CostType, IntervalType};
use payments_rs::currency::{Currency, CurrencyAmount};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

pub fn router() -> Router<RouterState> {
    Router::new()
        .route(
            "/api/admin/v1/reports/time-series",
            get(admin_time_series_report),
        )
        .route(
            "/api/admin/v1/reports/referral-usage/time-series",
            get(admin_referral_time_series_report),
        )
        .route(
            "/api/admin/v1/reports/profit-loss",
            get(admin_profit_loss_report),
        )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TimeSeriesQuery {
    start_date: String,
    end_date: String,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    company_id: u64,
    currency: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ReferralTimeSeriesQuery {
    start_date: String,
    end_date: String,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    company_id: u64,
    ref_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ReferralReport {
    vm_id: u64,
    ref_code: String,
    created: String,
    amount: u64,
    currency: String,
    rate: f32,
    base_currency: String,
}

#[derive(Serialize, Deserialize)]
struct ReferralTimeSeriesReport {
    start_date: String,
    end_date: String,
    referrals: Vec<ReferralReport>,
}

#[derive(Serialize, Deserialize)]
struct TimeSeriesPayment {
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
    // Tax fields recorded on the payment. Summary fields are null when the
    // payment's lines differ; `tax_breakdown` holds the per-line values.
    tax_rate: Option<f32>,                    // Rate (%) when uniform
    tax_country_code: Option<String>,         // Country (ISO alpha-3) when uniform
    tax_treatment: Option<String>,            // Treatment label when uniform
    tax_breakdown: Option<serde_json::Value>, // Per-line-item VAT breakdown
    // Company information
    company_id: u64,
    company_name: String,
    company_base_currency: String,
    // User information
    user_id: u64,
    // Host information
    host_id: u64,
    host_name: String,
    // Region information
    region_id: u64,
    region_name: String,
}

#[derive(Serialize, Deserialize)]
struct TimeSeriesPeriodSummary {
    period: String,         // Period identifier (e.g., "2025-01", "2025-Q1")
    currency: String,       // Currency for this period summary
    payment_count: u32,     // Number of payments in this period/currency
    net_total: u64,         // Total net amount (excluding tax) in smallest currency unit
    tax_total: u64,         // Total tax collected in smallest currency unit
    base_currency_net: u64, // Total net amount converted to company's base currency in smallest unit
    base_currency_tax: u64, // Total tax amount converted to company's base currency in smallest unit
}

#[derive(Serialize, Deserialize)]
struct TimeSeriesReport {
    start_date: String,               // Start date of the report period
    end_date: String,                 // End date of the report period
    payments: Vec<TimeSeriesPayment>, // Raw payment data
}

async fn admin_time_series_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<TimeSeriesQuery>,
) -> ApiResult<TimeSeriesReport> {
    // Check permissions
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    // Parse and validate dates
    let start_date_parsed = NaiveDate::parse_from_str(&params.start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date_parsed = NaiveDate::parse_from_str(&params.end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;

    if start_date_parsed >= end_date_parsed {
        return Err(ApiError::bad_request("start_date must be before end_date"));
    }

    // Validate currency if provided
    if let Some(ref currency_str) = params.currency {
        currency_str
            .parse::<payments_rs::currency::Currency>()
            .map_err(|_| anyhow::anyhow!("Invalid currency: {}", currency_str))?;
    }

    // Convert dates to UTC datetime for database query
    let start_datetime = start_date_parsed.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_datetime = end_date_parsed.and_hms_opt(23, 59, 59).unwrap().and_utc();

    // Use the new optimized database query
    let payments = this
        .db
        .admin_get_payments_with_company_info(
            start_datetime,
            end_datetime,
            params.company_id,
            params.currency.as_deref(),
        )
        .await?;

    // Process payments and build raw data
    let mut time_series_payments = Vec::new();

    for payment in payments {
        time_series_payments.push(TimeSeriesPayment {
            id: hex::encode(&payment.id),
            vm_id: payment.vm_id.unwrap_or(0),
            created: payment.created.to_rfc3339(),
            expires: payment.expires.to_rfc3339(),
            amount: payment.amount,
            currency: payment.currency,
            payment_method: payment.payment_method.to_string().to_lowercase(),
            external_id: payment.external_id,
            is_paid: payment.is_paid,
            rate: payment.rate,
            time_value: payment.time_value.unwrap_or(0),
            tax: payment.tax,
            tax_rate: payment.tax_rate,
            tax_country_code: payment.tax_country_code.clone(),
            tax_treatment: payment.tax_treatment.clone(),
            tax_breakdown: payment.tax_breakdown.clone(),
            company_id: payment.company_id,
            company_name: payment.company_name.clone(),
            company_base_currency: payment.company_base_currency.clone(),
            user_id: payment.user_id,
            host_id: payment.host_id.unwrap_or(0),
            host_name: payment.host_name.clone().unwrap_or_default(),
            region_id: payment.region_id.unwrap_or(0),
            region_name: payment.region_name.clone().unwrap_or_default(),
        });
    }

    // Sort payments by created timestamp
    time_series_payments.sort_by(|a, b| a.created.cmp(&b.created));

    let report = TimeSeriesReport {
        start_date: params.start_date,
        end_date: params.end_date,
        payments: time_series_payments,
    };

    ApiData::ok(report)
}

async fn admin_referral_time_series_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ReferralTimeSeriesQuery>,
) -> ApiResult<ReferralTimeSeriesReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    // Parse and validate dates
    let start_date_parsed = NaiveDate::parse_from_str(&params.start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date_parsed = NaiveDate::parse_from_str(&params.end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;

    if start_date_parsed >= end_date_parsed {
        return Err(ApiError::bad_request("start_date must be before end_date"));
    }

    // Convert dates to UTC datetime for database query
    let start_datetime = start_date_parsed.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_datetime = end_date_parsed.and_hms_opt(23, 59, 59).unwrap().and_utc();

    let referral_data = this
        .db
        .admin_get_referral_usage_by_date_range(
            start_datetime,
            end_datetime,
            params.company_id,
            params.ref_code.as_deref(),
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
        start_date: params.start_date,
        end_date: params.end_date,
        referrals,
    };

    ApiData::ok(report)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ProfitLossQuery {
    start_date: String,
    end_date: String,
    /// "month" (default) or "year"
    group_by: Option<String>,
    /// Optional company filter for the revenue side; 0 / omitted = all companies.
    /// Costs are global (not company-scoped) in this version.
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    company_id: u64,
    /// Optional region filter; 0 / omitted = all regions. Filters both revenue
    /// (payment's VM region) and costs (host/ip_range region).
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    region_id: u64,
    /// Target currency for the report. Defaults to the selected company's base
    /// currency; required when `company_id` is omitted (all companies).
    currency: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ProfitLossPeriod {
    /// Period identifier ("2026-01" for month grouping, "2026" for year)
    period: String,
    /// Paid revenue net of tax, in smallest currency units
    revenue_net: u64,
    /// Tax collected, in smallest currency units
    revenue_tax: u64,
    /// Recurring costs attributable to this period (normalized), smallest units
    cost_recurring: u64,
    /// One-time (capital) costs booked in this period, smallest units
    cost_one_time: u64,
    /// cost_recurring + cost_one_time
    cost_total: u64,
    /// revenue_net - cost_total (same currency only); may be negative
    profit: i64,
}

#[derive(Serialize, Deserialize)]
struct ProfitLossReport {
    start_date: String,
    end_date: String,
    group_by: String,
    /// Currency all amounts in this report are expressed in (the company's base
    /// currency, or an explicit `currency` override).
    currency: String,
    /// Per-period profit/loss rows, sorted by period. All revenue and costs are
    /// converted into `currency` using current exchange rates.
    periods: Vec<ProfitLossPeriod>,
}

#[derive(Default)]
struct PlAccumulator {
    revenue_net: u64,
    revenue_tax: u64,
    cost_recurring_f: f64,
    cost_one_time: u64,
}

/// Fraction of a recurring cost `amount` attributable to one calendar month.
fn per_month_fraction(interval_amount: u64, interval_type: IntervalType) -> f64 {
    if interval_amount == 0 {
        return 0.0;
    }
    let n = interval_amount as f64;
    match interval_type {
        // ~average days per month divided by the interval length in days
        IntervalType::Day => 30.436875 / n,
        IntervalType::Month => 1.0 / n,
        IntervalType::Year => 1.0 / (n * 12.0),
    }
}

fn period_key(date: DateTime<Utc>, group_by_year: bool) -> String {
    if group_by_year {
        format!("{:04}", date.year())
    } else {
        format!("{:04}-{:02}", date.year(), date.month())
    }
}

/// Reconstruct the base-currency value of a payment using its stored historical
/// `rate`. Lightning payments are stored in BTC (rate = <base> per BTC); Revolut
/// payments are already in the base currency (rate = 1). Never uses live rates.
fn payment_base_amount(amount: u64, pay_cur: Currency, base: Currency, rate: f32) -> Option<u64> {
    if amount == 0 || pay_cur == base {
        return Some(amount);
    }
    if pay_cur == Currency::BTC {
        // BTC -> base fiat using the stored rate
        return TickerRate {
            ticker: Ticker(Currency::BTC, base),
            rate,
        }
        .convert(CurrencyAmount::from_u64(Currency::BTC, amount))
        .ok()
        .map(|c| c.value());
    }
    if base == Currency::BTC {
        // fiat payment -> BTC base using the stored rate
        return TickerRate {
            ticker: Ticker(Currency::BTC, pay_cur),
            rate,
        }
        .convert(CurrencyAmount::from_u64(pay_cur, amount))
        .ok()
        .map(|c| c.value());
    }
    None
}

/// Convert `amount` (smallest units of `from`) into `to`, pivoting through BTC
/// using the supplied BTC/<fiat> rate map. Returns `None` if a required rate is
/// missing. `rates` maps each fiat currency to the price of 1 BTC in it.
fn convert_amount(
    amount: u64,
    from: Currency,
    to: Currency,
    rates: &HashMap<Currency, f32>,
) -> Option<u64> {
    if from == to {
        return Some(amount);
    }
    let src = CurrencyAmount::from_u64(from, amount);
    // Step 1: source -> BTC
    let btc = if from == Currency::BTC {
        src
    } else {
        let r = *rates.get(&from)?;
        TickerRate {
            ticker: Ticker(Currency::BTC, from),
            rate: r,
        }
        .convert(src)
        .ok()?
    };
    // Step 2: BTC -> target
    let out = if to == Currency::BTC {
        btc
    } else {
        let r = *rates.get(&to)?;
        TickerRate {
            ticker: Ticker(Currency::BTC, to),
            rate: r,
        }
        .convert(btc)
        .ok()?
    };
    Some(out.value())
}

async fn admin_profit_loss_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<ProfitLossQuery>,
) -> ApiResult<ProfitLossReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    let group_by = params
        .group_by
        .clone()
        .unwrap_or_else(|| "month".to_string())
        .to_lowercase();
    let group_by_year = match group_by.as_str() {
        "month" | "year" => group_by == "year",
        _ => return Err(ApiError::bad_request("group_by must be 'month' or 'year'")),
    };

    let start_date = NaiveDate::parse_from_str(&params.start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date = NaiveDate::parse_from_str(&params.end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;
    if start_date >= end_date {
        return Err(ApiError::bad_request("start_date must be before end_date"));
    }

    let start_dt = start_date.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_dt = end_date.and_hms_opt(23, 59, 59).unwrap().and_utc();

    // Resolve the target currency: explicit override, else the company's base
    // currency. Required when reporting across all companies.
    let target_str = if let Some(c) = &params.currency {
        c.trim().to_uppercase()
    } else if params.company_id != 0 {
        this.db
            .admin_get_company(params.company_id)
            .await?
            .base_currency
    } else {
        return Err(ApiError::bad_request(
            "currency is required when company_id is omitted",
        ));
    };
    let target: Currency = Currency::from_str(&target_str)
        .map_err(|_| anyhow::anyhow!("Invalid currency: {}", target_str))?;

    // Snapshot current BTC/<fiat> rates for conversion into the target currency.
    let rates: HashMap<Currency, f32> = this
        .exchange
        .list_rates()
        .await?
        .into_iter()
        .filter(|r| r.ticker.0 == Currency::BTC)
        .map(|r| (r.ticker.1, r.rate))
        .collect();

    let mut acc: BTreeMap<String, PlAccumulator> = BTreeMap::new();

    // --- Revenue side (paid payments, converted to target currency) ---
    let company_ids: Vec<u64> = if params.company_id != 0 {
        vec![params.company_id]
    } else {
        let (companies, _) = this.db.admin_list_companies(10_000, 0).await?;
        companies.into_iter().map(|c| c.id).collect()
    };
    for cid in company_ids {
        let payments = this
            .db
            .admin_get_payments_with_company_info(start_dt, end_dt, cid, None)
            .await?;
        for p in payments {
            if params.region_id != 0 && p.region_id != Some(params.region_id) {
                continue;
            }
            let (Ok(pay_cur), Ok(base_cur)) = (
                Currency::from_str(&p.currency),
                Currency::from_str(&p.company_base_currency),
            ) else {
                continue;
            };
            let net = p.amount.saturating_sub(p.tax);
            // 1) payment -> its company base currency using the stored historical rate
            let (Some(net_base), Some(tax_base)) = (
                payment_base_amount(net, pay_cur, base_cur, p.rate),
                payment_base_amount(p.tax, pay_cur, base_cur, p.rate),
            ) else {
                continue;
            };
            // 2) base -> report target (no-op when they match; live rate only
            //    needed when aggregating companies with differing base currencies)
            let (Some(net_c), Some(tax_c)) = (
                convert_amount(net_base, base_cur, target, &rates),
                convert_amount(tax_base, base_cur, target, &rates),
            ) else {
                continue;
            };
            let e = acc.entry(period_key(p.created, group_by_year)).or_default();
            e.revenue_net = e.revenue_net.saturating_add(net_c);
            e.revenue_tax = e.revenue_tax.saturating_add(tax_c);
        }
    }

    // --- Cost side ---
    let costs = this
        .db
        .admin_list_resource_costs_active_between(start_dt, end_dt)
        .await?;

    // Cache assigned-IP counts per ip_range so per-IP recurring costs scale correctly.
    let mut ip_counts: HashMap<u64, u64> = HashMap::new();
    for c in &costs {
        if c.resource_type == CostResourceType::IpRange && !ip_counts.contains_key(&c.resource_id) {
            let n = this
                .db
                .admin_count_ip_range_assignments(c.resource_id)
                .await
                .unwrap_or(0);
            ip_counts.insert(c.resource_id, n);
        }
    }

    for c in &costs {
        // Region filter: resolve the cost's resource region and skip mismatches.
        if params.region_id != 0 {
            let region = match c.resource_type {
                CostResourceType::VmHost => this
                    .db
                    .get_host(c.resource_id)
                    .await
                    .ok()
                    .map(|h| h.region_id),
                CostResourceType::IpRange => this
                    .db
                    .admin_get_ip_range(c.resource_id)
                    .await
                    .ok()
                    .map(|r| r.region_id),
                // Generic costs aren't tied to a region; exclude when filtering.
                CostResourceType::Generic => None,
            };
            if region != Some(params.region_id) {
                continue;
            }
        }
        let Ok(from) = Currency::from_str(&c.currency) else {
            continue;
        };
        let Some(amount_c) = convert_amount(c.amount, from, target, &rates) else {
            continue;
        };
        match c.cost_type {
            CostType::OneTime => {
                // Book the whole amount in the period containing billing_start.
                if let Some(bs) = c.billing_start
                    && bs >= start_dt
                    && bs <= end_dt
                {
                    let e = acc.entry(period_key(bs, group_by_year)).or_default();
                    e.cost_one_time = e.cost_one_time.saturating_add(amount_c);
                }
            }
            CostType::Recurring => {
                let units = if c.resource_type == CostResourceType::IpRange {
                    *ip_counts.get(&c.resource_id).unwrap_or(&0)
                } else {
                    1
                };
                if units == 0 {
                    continue;
                }
                let (Some(ia), Some(it)) = (c.interval_amount, c.interval_type) else {
                    continue;
                };
                let monthly = amount_c as f64 * per_month_fraction(ia, it) * units as f64;
                let active_start = c.billing_start.unwrap_or(DateTime::<Utc>::MIN_UTC);
                let active_end = c.billing_end.unwrap_or(DateTime::<Utc>::MAX_UTC);

                // Walk each calendar month in the report window and add the
                // monthly-normalized cost for every month the cost is active.
                let mut y = start_date.year();
                let mut m = start_date.month();
                loop {
                    let month_start = Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).unwrap();
                    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                    let month_end = Utc.with_ymd_and_hms(ny, nm, 1, 0, 0, 0).unwrap()
                        - chrono::Duration::seconds(1);

                    if active_start <= month_end && active_end >= month_start {
                        acc.entry(period_key(month_start, group_by_year))
                            .or_default()
                            .cost_recurring_f += monthly;
                    }

                    if (y, m) == (end_date.year(), end_date.month()) {
                        break;
                    }
                    y = ny;
                    m = nm;
                }
            }
        }
    }

    let periods = acc
        .into_iter()
        .map(|(period, a)| {
            let cost_recurring = a.cost_recurring_f.round() as u64;
            let cost_total = cost_recurring.saturating_add(a.cost_one_time);
            ProfitLossPeriod {
                period,
                revenue_net: a.revenue_net,
                revenue_tax: a.revenue_tax,
                cost_recurring,
                cost_one_time: a.cost_one_time,
                cost_total,
                profit: a.revenue_net as i64 - cost_total as i64,
            }
        })
        .collect();

    ApiData::ok(ProfitLossReport {
        start_date: params.start_date,
        end_date: params.end_date,
        group_by,
        currency: target_str,
        periods,
    })
}
