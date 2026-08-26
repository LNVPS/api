use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;
use crate::admin::model::AdminVmTrafficTotal;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::get;
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use lnvps_api_common::{
    ApiData, ApiError, ApiPaginatedData, ApiPaginatedResult, ApiResult, TaxLine, TaxTreatment,
    Ticker, TickerRate, resolve_traffic_range,
};
use lnvps_db::{
    AdminAction, AdminResource, CostResourceType, CostType, IntervalType, RenewalSource,
    SubscriptionPaymentType,
};
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
        .route("/api/admin/v1/reports/oss", get(admin_oss_report))
        .route("/api/admin/v1/reports/renewals", get(admin_renewals_report))
        .route("/api/admin/v1/reports/traffic", get(admin_traffic_report))
}

/// Range and paging for the fleet traffic report.
#[derive(Deserialize, Default)]
#[serde(default)]
struct TrafficReportQuery {
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
    limit: Option<u64>,
    offset: Option<u64>,
}

/// Which VMs are pushing the traffic, heaviest sender first.
///
/// The operational question behind per-VM accounting: transit is bought in
/// aggregate, so when the bill or the pipe moves, the answer needed is which
/// handful of guests moved it. Ordered by outbound bytes, since that is the
/// direction that costs and the direction an allowance bounds.
async fn admin_traffic_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<TrafficReportQuery>,
) -> ApiPaginatedResult<AdminVmTrafficTotal> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    let today = Utc::now().date_naive();
    let (start, end) = resolve_traffic_range(params.start, params.end, today)
        .map_err(|e| ApiError::bad_request(&e))?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let (rows, total) = this
        .db
        .list_vm_traffic_totals(start, end, limit, offset)
        .await?;

    ApiPaginatedData::ok(
        rows.into_iter()
            .map(|r| AdminVmTrafficTotal {
                vm_id: r.vm_id,
                user_id: r.user_id,
                bytes_in: r.bytes_in,
                bytes_out: r.bytes_out,
            })
            .collect(),
        total,
        limit as u64,
        offset,
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
    /// Effective commission rate applied (referrer override or company default), %.
    effective_rate: f32,
    /// Commission earned = amount * effective_rate%, in `currency` smallest units.
    commission: u64,
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
    /// "purchase" | "renewal" | "upgrade" | "refund". A **refund** row's
    /// `amount`/`tax` are the magnitude returned to the customer, so any total
    /// built from these rows must subtract them (issue #193).
    payment_type: String,
    /// For a refund row, the hex id of the payment it reverses; null otherwise.
    refunded_payment_id: Option<String>,
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
            payment_type: payment.payment_type.to_string().to_lowercase(),
            refunded_payment_id: payment.refunded_payment_id.as_ref().map(hex::encode),
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
        .map(|data| {
            let commission = data.commission();
            ReferralReport {
                vm_id: data.vm_id,
                ref_code: data.ref_code,
                created: data.created.to_rfc3339(),
                amount: data.amount,
                currency: data.currency,
                rate: data.rate,
                base_currency: data.base_currency,
                effective_rate: data.effective_rate,
                commission,
            }
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
    /// Paid revenue net of tax, in smallest currency units, **net of refunds
    /// recorded in this period**. Negative when a period refunded more than it
    /// sold (issue #193).
    revenue_net: i64,
    /// Tax collected, in smallest currency units, net of refunded tax. Negative
    /// under the same conditions as `revenue_net`.
    revenue_tax: i64,
    /// Recurring operating costs attributable to this period (normalized),
    /// smallest units
    cost_recurring: u64,
    /// Depreciation charged in this period, smallest units. One-time costs with
    /// a `depreciation_months` useful life are expensed straight-line over that
    /// life from their purchase date; those without one are charged in full in
    /// the purchase period.
    cost_depreciation: u64,
    /// Capital expenditure *paid* in this period, smallest units. This is a cash
    /// figure and sits below the line — it is deliberately NOT part of
    /// `cost_total` or `profit`, which are accrual measures.
    cost_one_time: u64,
    /// cost_recurring + cost_depreciation (the accrual expense total)
    cost_total: u64,
    /// Accrual profit: revenue_net - cost_total (same currency only); may be
    /// negative
    profit: i64,
    /// Cash movement: revenue_net - cost_recurring - cost_one_time. Differs from
    /// `profit` exactly when capex is being depreciated.
    cash_flow: i64,
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
    /// Signed: refund rows subtract (see `SubscriptionPaymentType::signum`).
    revenue_net: i64,
    revenue_tax: i64,
    cost_recurring_f: f64,
    cost_depreciation_f: f64,
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

/// Every calendar month start contained in `[start_date, end_date]`, inclusive
/// of both endpoint months.
fn window_months(start_date: NaiveDate, end_date: NaiveDate) -> Vec<DateTime<Utc>> {
    let mut out = Vec::new();
    let (mut y, mut m) = (start_date.year(), start_date.month());
    loop {
        out.push(Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).unwrap());
        if (y, m) == (end_date.year(), end_date.month()) {
            break;
        }
        (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    }
    out
}

/// Whole months from `from` to `to` (negative when `to` precedes `from`),
/// counting calendar months only — the day of month is ignored.
fn months_between(from: DateTime<Utc>, to: DateTime<Utc>) -> i64 {
    (to.year() as i64 - from.year() as i64) * 12 + (to.month() as i64 - from.month() as i64)
}

/// Straight-line depreciation charged in the calendar month starting at
/// `month_start` for an `amount` asset purchased at `purchase` with a `life`
/// month useful life. Zero outside the depreciation schedule.
fn depreciation_for_month(
    amount: u64,
    purchase: DateTime<Utc>,
    life: u64,
    month_start: DateTime<Utc>,
) -> f64 {
    if life == 0 {
        return 0.0;
    }
    let idx = months_between(purchase, month_start);
    if idx < 0 || idx as u64 >= life {
        return 0.0;
    }
    amount as f64 / life as f64
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
            // A refund row stores the magnitude returned, so it subtracts here
            // rather than adding — the columns are unsigned and the sign lives
            // in the payment type (issue #193).
            let sign = p.payment_type.signum();
            let e = acc.entry(period_key(p.created, group_by_year)).or_default();
            e.revenue_net = e.revenue_net.saturating_add(sign * net_c as i64);
            e.revenue_tax = e.revenue_tax.saturating_add(sign * tax_c as i64);
        }
    }

    // --- Cost side ---
    let costs = this
        .db
        .admin_list_resource_costs_active_between(start_dt, end_dt)
        .await?;

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
                // Generic costs overload `resource_id` as the region id
                // (0 = global/no region, excluded when filtering by region).
                CostResourceType::Generic => {
                    if c.resource_id != 0 {
                        Some(c.resource_id)
                    } else {
                        None
                    }
                }
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
                let Some(bs) = c.billing_start else {
                    continue;
                };
                if bs > end_dt {
                    continue;
                }
                // Cash side: the whole outlay lands in the purchase period.
                if bs >= start_dt {
                    let e = acc.entry(period_key(bs, group_by_year)).or_default();
                    e.cost_one_time = e.cost_one_time.saturating_add(amount_c);
                }
                // Accrual side: capitalise and expense over the useful life. No
                // useful life set = expensed immediately (legacy behaviour).
                match c.depreciation_months {
                    None | Some(0) => {
                        if bs >= start_dt {
                            acc.entry(period_key(bs, group_by_year))
                                .or_default()
                                .cost_depreciation_f += amount_c as f64;
                        }
                    }
                    Some(life) => {
                        // Straight-line: 1/life of the cost per month for `life`
                        // months from the purchase month. Assets bought before
                        // the window still charge their remaining months into it.
                        for month_start in window_months(start_date, end_date) {
                            let charge = depreciation_for_month(amount_c, bs, life, month_start);
                            if charge > 0.0 {
                                acc.entry(period_key(month_start, group_by_year))
                                    .or_default()
                                    .cost_depreciation_f += charge;
                            }
                        }
                    }
                }
            }
            CostType::Recurring => {
                // Recurring costs are the full amount for the resource (for an
                // ip_range this is the cost of the entire block, regardless of
                // how many IPs are assigned — we pay for the block either way).
                let (Some(ia), Some(it)) = (c.interval_amount, c.interval_type) else {
                    continue;
                };
                let monthly = amount_c as f64 * per_month_fraction(ia, it);
                let active_start = c.billing_start.unwrap_or(DateTime::<Utc>::MIN_UTC);
                let active_end = c.billing_end.unwrap_or(DateTime::<Utc>::MAX_UTC);

                // Walk each calendar month in the report window and add the
                // monthly-normalized cost for every month the cost is active.
                for month_start in window_months(start_date, end_date) {
                    let month_end = month_start
                        .checked_add_months(chrono::Months::new(1))
                        .unwrap()
                        - chrono::Duration::seconds(1);

                    if active_start <= month_end && active_end >= month_start {
                        acc.entry(period_key(month_start, group_by_year))
                            .or_default()
                            .cost_recurring_f += monthly;
                    }
                }
            }
        }
    }

    let periods = acc
        .into_iter()
        .map(|(period, a)| {
            let cost_recurring = a.cost_recurring_f.round() as u64;
            let cost_depreciation = a.cost_depreciation_f.round() as u64;
            // Accrual expense: capex is represented by depreciation, never by
            // the cash outlay.
            let cost_total = cost_recurring.saturating_add(cost_depreciation);
            ProfitLossPeriod {
                period,
                revenue_net: a.revenue_net,
                revenue_tax: a.revenue_tax,
                cost_recurring,
                cost_depreciation,
                cost_one_time: a.cost_one_time,
                cost_total,
                profit: a.revenue_net - cost_total as i64,
                cash_flow: a.revenue_net - cost_recurring as i64 - a.cost_one_time as i64,
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

#[derive(Deserialize, Default)]
#[serde(default)]
struct OssReportQuery {
    start_date: String,
    end_date: String,
    /// Optional company filter; 0 / omitted = all companies. Each company is a
    /// separate VAT-registered entity, so rows are always keyed by company and
    /// expressed in that company's base currency.
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    company_id: u64,
    /// Filing period grouping: "quarter" (default, the OSS standard) or
    /// "bimonthly" (two-month buckets).
    period: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct OssReportRow {
    /// Period identifier ("2025-Q1" for quarter, "2025-B1" for bimonthly).
    period: String,
    /// Seller company id.
    company_id: u64,
    /// Seller company name.
    company_name: String,
    /// Currency all amounts in this row are expressed in (company base currency).
    currency: String,
    /// Destination member state (ISO 3166-1 alpha-3).
    country_code: String,
    /// VAT rate applied for this country/rate bucket, as a percentage.
    vat_rate: f32,
    /// Net (pre-tax) sales to this country, in `currency` smallest units,
    /// **net of refunds recorded in the period** — VAT is only owed on money
    /// kept, so a refund reduces the declared base (issue #193). Negative when
    /// refunds exceed sales for the bucket.
    net_total: i64,
    /// VAT for this country, in `currency` smallest units, net of refunded VAT.
    tax_total: i64,
    /// Number of payments contributing to this row, refunds included.
    transaction_count: u32,
}

#[derive(Serialize, Deserialize)]
struct OssReport {
    start_date: String,
    end_date: String,
    /// Period grouping used ("quarter" or "bimonthly").
    period: String,
    /// Aggregated OSS B2C rows, sorted by period, company, country then rate.
    rows: Vec<OssReportRow>,
}

/// Build the OSS period key for a date. Quarters are calendar Q1-Q4; bimonthly
/// buckets are B1=Jan-Feb, B2=Mar-Apr, ... B6=Nov-Dec.
fn oss_period_key(date: DateTime<Utc>, bimonthly: bool) -> String {
    let m = date.month();
    if bimonthly {
        format!("{:04}-B{}", date.year(), (m - 1) / 2 + 1)
    } else {
        format!("{:04}-Q{}", date.year(), (m - 1) / 3 + 1)
    }
}

/// Accumulator key for one OSS declaration line: a distinct
/// (period, company, destination country, VAT rate) bucket.
#[derive(Clone, PartialEq, Eq, Hash)]
struct OssKey {
    period: String,
    company_id: u64,
    country_code: String,
    /// VAT rate stored as raw bits so it can be a map key.
    rate_bits: u32,
}

#[derive(Default)]
struct OssAcc {
    /// Signed: refund rows subtract (see `SubscriptionPaymentType::signum`).
    net_total: i64,
    tax_total: i64,
    transaction_count: u32,
    company_name: String,
    currency: String,
}

/// OSS (One-Stop Shop) VAT report.
///
/// Aggregates cross-border EU B2C sales (`tax_treatment = oss_b2c`) by filing
/// period and destination member state, so the totals can be transcribed onto a
/// quarterly (or bi-monthly) OSS VAT return. Only paid payments are included;
/// amounts are expressed in each seller company's base currency using the
/// exchange rate frozen on the payment at sale time.
async fn admin_oss_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<OssReportQuery>,
) -> ApiResult<OssReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    let period = params
        .period
        .clone()
        .unwrap_or_else(|| "quarter".to_string())
        .to_lowercase();
    let bimonthly = match period.as_str() {
        "quarter" | "bimonthly" => period == "bimonthly",
        _ => {
            return Err(ApiError::bad_request(
                "period must be 'quarter' or 'bimonthly'",
            ));
        }
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

    // Resolve the set of companies to report on.
    let company_ids: Vec<u64> = if params.company_id != 0 {
        vec![params.company_id]
    } else {
        let (companies, _) = this.db.admin_list_companies(10_000, 0).await?;
        companies.into_iter().map(|c| c.id).collect()
    };

    let mut acc: HashMap<OssKey, OssAcc> = HashMap::new();

    for cid in company_ids {
        let payments = this
            .db
            .admin_get_payments_with_company_info(start_dt, end_dt, cid, None)
            .await?;
        for p in payments {
            let (Ok(pay_cur), Ok(base_cur)) = (
                Currency::from_str(&p.currency),
                Currency::from_str(&p.company_base_currency),
            ) else {
                continue;
            };

            // Extract the OSS B2C lines for this payment: prefer the frozen
            // per-line breakdown, else synthesise a single line from the
            // summary fields when the whole payment was treated as oss_b2c.
            let lines: Vec<TaxLine> = if let Some(bd) = &p.tax_breakdown {
                match serde_json::from_value::<Vec<TaxLine>>(bd.clone()) {
                    Ok(lines) => lines
                        .into_iter()
                        .filter(|l| l.treatment == TaxTreatment::OssB2c)
                        .collect(),
                    Err(_) => continue,
                }
            } else if p.tax_treatment.as_deref() == Some(TaxTreatment::OssB2c.as_str()) {
                vec![TaxLine {
                    net: p.amount.saturating_sub(p.tax),
                    tax: p.tax,
                    rate: p.tax_rate.unwrap_or(0.0),
                    country_code: p.tax_country_code.clone(),
                    treatment: TaxTreatment::OssB2c,
                }]
            } else {
                continue;
            };

            // Fold this payment's OSS lines into per-bucket contributions,
            // converting to the company base currency using the frozen rate.
            let period_key = oss_period_key(p.created, bimonthly);
            // Refund rows carry the same frozen country/rate as the payment
            // they reverse, so they net against exactly the bucket that
            // declared the VAT (issue #193).
            let sign = p.payment_type.signum();
            let mut per_payment: HashMap<OssKey, (i64, i64)> = HashMap::new();
            for l in lines {
                let Some(country) = l.country_code.clone() else {
                    continue;
                };
                let (Some(net_base), Some(tax_base)) = (
                    payment_base_amount(l.net, pay_cur, base_cur, p.rate),
                    payment_base_amount(l.tax, pay_cur, base_cur, p.rate),
                ) else {
                    continue;
                };
                let key = OssKey {
                    period: period_key.clone(),
                    company_id: p.company_id,
                    country_code: country,
                    rate_bits: l.rate.to_bits(),
                };
                let e = per_payment.entry(key).or_default();
                e.0 = e.0.saturating_add(sign * net_base as i64);
                e.1 = e.1.saturating_add(sign * tax_base as i64);
            }

            for (key, (net, tax)) in per_payment {
                let e = acc.entry(key).or_default();
                e.net_total = e.net_total.saturating_add(net);
                e.tax_total = e.tax_total.saturating_add(tax);
                e.transaction_count = e.transaction_count.saturating_add(1);
                e.company_name = p.company_name.clone();
                e.currency = p.company_base_currency.clone();
            }
        }
    }

    let mut rows: Vec<OssReportRow> = acc
        .into_iter()
        .map(|(key, a)| OssReportRow {
            period: key.period,
            company_id: key.company_id,
            company_name: a.company_name,
            currency: a.currency,
            country_code: key.country_code,
            vat_rate: f32::from_bits(key.rate_bits),
            net_total: a.net_total,
            tax_total: a.tax_total,
            transaction_count: a.transaction_count,
        })
        .collect();

    rows.sort_by(|a, b| {
        a.period
            .cmp(&b.period)
            .then(a.company_id.cmp(&b.company_id))
            .then(a.country_code.cmp(&b.country_code))
            .then(
                a.vat_rate
                    .partial_cmp(&b.vat_rate)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });

    ApiData::ok(OssReport {
        start_date: params.start_date,
        end_date: params.end_date,
        period,
        rows,
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RenewalsQuery {
    start_date: String,
    end_date: String,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    company_id: u64,
    #[serde(deserialize_with = "lnvps_api_common::deserialize_from_str")]
    region_id: u64,
}

/// One month of renewal activity: what is due, what renewed, and what was lost.
///
/// A subscription's `expires` moves forward every time it renews, so a
/// subscription still carrying an expiry in a **past** month is one that
/// reached its renewal date and never came back — that is the churn event, and
/// it is dated by that expiry. In a **future** month the same count is the
/// renewal outlook. The two are reported separately so neither is mistaken for
/// the other.
#[derive(Serialize, Deserialize)]
struct RenewalsPeriod {
    /// "2026-09"
    period: String,
    /// True once the month is over, i.e. its counts are final.
    complete: bool,

    // --- Subscriptions whose expiry falls in this month ---
    /// Subscriptions expiring in this period.
    due: u64,
    /// Of `due`: auto-renewal enabled AND the user has an enabled saved payment
    /// method — i.e. the worker will actually attempt a charge.
    due_auto_capable: u64,
    /// Of `due`: auto-renewal enabled but **no** saved payment method. These
    /// look safe on the subscription record and are not: the worker falls
    /// through to a manual expiry warning.
    due_auto_without_method: u64,
    /// Of `due`: auto-renewal off. Renews only if the customer acts.
    due_manual: u64,

    // --- Churn: only meaningful for a completed month ---
    /// Subscriptions that expired in this month and have not renewed since.
    /// Zero for the current and future months, where an expiry is not yet a
    /// loss. Paid customers only.
    lapsed: u64,
    /// Expired without the first payment ever being confirmed: an abandoned
    /// signup rather than a lost customer. Kept out of `lapsed` and out of the
    /// churn rate so it cannot flatter or inflate them.
    lapsed_never_paid: u64,
    /// Distinct subscriptions that renewed in this month.
    renewed_subscriptions: u64,
    /// `lapsed / (lapsed + renewed_subscriptions)` as a percentage: of the
    /// subscriptions that reached a renewal decision this month, the share that
    /// walked away. `None` for months that are not complete, or where nothing
    /// was up for decision.
    churn_rate: Option<f32>,

    // --- Renewal payments collected in this month ---
    /// Paid renewal payments created in this period (payments, not
    /// subscriptions: one subscription may renew more than once).
    renewed: u64,
    /// Of `renewed`: charged by the worker against a saved method.
    renewed_auto: u64,
    /// Of `renewed`: paid by the customer.
    renewed_manual: u64,
    /// Of `renewed`: created before renewal source was recorded, so genuinely
    /// unknown. Never folded into either bucket.
    renewed_unknown: u64,
}

#[derive(Serialize, Deserialize)]
struct RenewalsReport {
    start_date: String,
    end_date: String,
    /// Date from which `renewal_source` is recorded, so a client can grey out
    /// the auto/manual split for earlier periods instead of showing zeroes that
    /// look like "nothing auto-renewed".
    source_tracking_since: Option<String>,
    periods: Vec<RenewalsPeriod>,
}

/// Bucket subscriptions and renewal payments into one row per calendar month.
///
/// `now` decides which months are complete: a subscription expiring later this
/// month has not churned, it simply has not been asked yet. Only a month that
/// has finished can turn its expiries into losses, which is why `lapsed` is
/// zero for the current and future months rather than counting down as the
/// month elapses.
///
/// Pure so the classification is testable without a database.
fn build_renewal_periods(
    outlook: &[lnvps_db::SubscriptionRenewalOutlook],
    renewals: &[(u64, DateTime<Utc>, Option<RenewalSource>)],
    now: DateTime<Utc>,
) -> Vec<RenewalsPeriod> {
    let current = period_key(now, false);
    let mut acc: BTreeMap<String, RenewalsPeriod> = BTreeMap::new();
    let mut renewed_subs: BTreeMap<String, std::collections::HashSet<u64>> = BTreeMap::new();

    let row = |acc: &mut BTreeMap<String, RenewalsPeriod>, at: DateTime<Utc>| -> String {
        let key = period_key(at, false);
        let complete = key < current;
        acc.entry(key.clone()).or_insert_with(|| RenewalsPeriod {
            period: key.clone(),
            complete,
            due: 0,
            due_auto_capable: 0,
            due_auto_without_method: 0,
            due_manual: 0,
            lapsed: 0,
            lapsed_never_paid: 0,
            renewed_subscriptions: 0,
            churn_rate: None,
            renewed: 0,
            renewed_auto: 0,
            renewed_manual: 0,
            renewed_unknown: 0,
        });
        key
    };

    for o in outlook {
        let key = row(&mut acc, o.expires);
        let complete = acc[&key].complete;
        let e = acc.get_mut(&key).unwrap();
        e.due += 1;
        match (o.auto_renewal_enabled, o.has_payment_method) {
            // Auto-renewal only fires when the worker has a method to charge;
            // the flag on its own is not a prediction.
            (true, true) => e.due_auto_capable += 1,
            (true, false) => e.due_auto_without_method += 1,
            (false, _) => e.due_manual += 1,
        }
        // Past expiry that is still the subscription's expiry = it never
        // renewed. Renewal advances `expires`, so a renewed subscription has
        // already moved out of this month.
        if complete {
            if o.is_setup {
                e.lapsed += 1;
            } else {
                e.lapsed_never_paid += 1;
            }
        }
    }

    for (sub_id, created, source) in renewals {
        let key = row(&mut acc, *created);
        renewed_subs.entry(key.clone()).or_default().insert(*sub_id);
        let e = acc.get_mut(&key).unwrap();
        e.renewed += 1;
        match source {
            Some(RenewalSource::Auto) => e.renewed_auto += 1,
            Some(RenewalSource::Manual) => e.renewed_manual += 1,
            None => e.renewed_unknown += 1,
        }
    }

    for (key, period) in acc.iter_mut() {
        period.renewed_subscriptions = renewed_subs.get(key).map(|s| s.len() as u64).unwrap_or(0);
        // Churn rate compares like with like: subscriptions that faced a
        // renewal decision this month, and what share of them was lost. Payment
        // counts are the wrong denominator — a subscription can renew twice in
        // a month, which would understate churn.
        let decided = period.lapsed + period.renewed_subscriptions;
        period.churn_rate = if period.complete && decided > 0 {
            Some((period.lapsed as f32 / decided as f32) * 100.0)
        } else {
            None
        };
    }

    acc.into_values().collect()
}

/// Renewal outlook and churn, per month.
///
/// Two halves that must not be conflated: what is *due* to renew (from
/// subscription expiry dates, forward looking) and what *did* renew (from paid
/// renewal payments, backward looking). A month in the future has `due` counts
/// and no renewals; a month in the past has both, and the gap between them is
/// churn.
async fn admin_renewals_report(
    auth: AdminAuth,
    State(this): State<RouterState>,
    Query(params): Query<RenewalsQuery>,
) -> ApiResult<RenewalsReport> {
    auth.require_permission(AdminResource::Analytics, AdminAction::View)?;

    let start_date = NaiveDate::parse_from_str(&params.start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date format. Use YYYY-MM-DD"))?;
    let end_date = NaiveDate::parse_from_str(&params.end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date format. Use YYYY-MM-DD"))?;
    if start_date >= end_date {
        return Err(ApiError::bad_request("start_date must be before end_date"));
    }
    if params.company_id == 0 {
        return Err(ApiError::bad_request("company_id is required"));
    }
    let start_dt = start_date.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let end_dt = end_date.and_hms_opt(23, 59, 59).unwrap().and_utc();
    let region = (params.region_id != 0).then_some(params.region_id);

    let outlook = this
        .db
        .admin_list_subscription_renewal_outlook(start_dt, end_dt, params.company_id, region)
        .await?;

    let renewals: Vec<(u64, DateTime<Utc>, Option<RenewalSource>)> = this
        .db
        .admin_get_payments_with_company_info(start_dt, end_dt, params.company_id, None)
        .await?
        .into_iter()
        .filter(|p| p.payment_type == SubscriptionPaymentType::Renewal)
        .filter(|p| region.is_none_or(|rid| p.region_id == Some(rid)))
        .map(|p| (p.subscription_id, p.created, p.renewal_source))
        .collect();

    ApiData::ok(RenewalsReport {
        start_date: params.start_date,
        end_date: params.end_date,
        source_tracking_since: Some(RENEWAL_SOURCE_TRACKED_FROM.to_string()),
        periods: build_renewal_periods(&outlook, &renewals, Utc::now()),
    })
}

/// Date the `renewal_source` column was deployed. Renewal payments created
/// before this carry no source and are reported as unknown.
const RENEWAL_SOURCE_TRACKED_FROM: &str = "2026-08-26";

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dt(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    fn outlook(
        expires: DateTime<Utc>,
        auto: bool,
        method: bool,
    ) -> lnvps_db::SubscriptionRenewalOutlook {
        lnvps_db::SubscriptionRenewalOutlook {
            subscription_id: 1,
            user_id: 1,
            company_id: 1,
            expires,
            auto_renewal_enabled: auto,
            has_payment_method: method,
            region_id: Some(1),
            is_active: true,
            is_setup: true,
        }
    }

    /// "Now" for the churn tests: mid-September 2026, so August is complete and
    /// September is not.
    fn now() -> DateTime<Utc> {
        dt(2026, 9, 15)
    }

    #[test]
    fn test_renewal_periods_split_due_by_what_will_actually_charge() {
        let sep = dt(2026, 9, 20);
        let rows = vec![
            outlook(sep, true, true),   // will auto-renew
            outlook(sep, true, false),  // flag on, but nothing to charge
            outlook(sep, false, true),  // manual by choice
            outlook(sep, false, false), // manual
        ];
        let p = build_renewal_periods(&rows, &[], now());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].period, "2026-09");
        assert_eq!(p[0].due, 4);
        assert_eq!(p[0].due_auto_capable, 1);
        assert_eq!(
            p[0].due_auto_without_method, 1,
            "auto-renewal with no saved method is at risk, not safe"
        );
        assert_eq!(p[0].due_manual, 2);
    }

    #[test]
    fn test_expiry_in_a_finished_month_is_churn() {
        // Renewal advances `expires`, so a subscription still sitting in a past
        // month never renewed.
        let rows = vec![
            outlook(dt(2026, 8, 3), false, false),
            outlook(dt(2026, 8, 9), true, false),
        ];
        let p = build_renewal_periods(&rows, &[], now());
        assert_eq!(p[0].period, "2026-08");
        assert!(p[0].complete);
        assert_eq!(p[0].lapsed, 2);
        assert_eq!(p[0].churn_rate, Some(100.0), "nothing renewed, all lost");
    }

    #[test]
    fn test_current_and_future_months_are_not_churn() {
        // An expiry later this month has not been asked yet; a future one even
        // less so. Counting either as lost would invent churn that has not
        // happened.
        let rows = vec![
            outlook(dt(2026, 9, 30), false, false),
            outlook(dt(2026, 10, 4), false, false),
        ];
        let p = build_renewal_periods(&rows, &[], now());
        assert_eq!(p.len(), 2);
        for row in &p {
            assert!(!row.complete);
            assert_eq!(row.lapsed, 0);
            assert_eq!(row.churn_rate, None);
            assert_eq!(row.due, 1);
        }
    }

    #[test]
    fn test_churn_rate_uses_distinct_subscriptions_not_payments() {
        let mut lost = outlook(dt(2026, 8, 5), false, false);
        lost.subscription_id = 99;
        // One subscription renewing twice in the month is one retained
        // customer, not two — counting payments would halve the churn rate.
        let renewals = vec![
            (7, dt(2026, 8, 6), Some(RenewalSource::Auto)),
            (7, dt(2026, 8, 20), Some(RenewalSource::Auto)),
        ];
        let p = build_renewal_periods(&[lost], &renewals, now());
        assert_eq!(p[0].renewed, 2, "two payments");
        assert_eq!(p[0].renewed_subscriptions, 1, "one subscription");
        assert_eq!(p[0].lapsed, 1);
        assert_eq!(p[0].churn_rate, Some(50.0));
    }

    #[test]
    fn test_never_paid_signups_are_not_counted_as_churn() {
        let mut abandoned = outlook(dt(2026, 8, 2), false, false);
        abandoned.is_setup = false;
        let p = build_renewal_periods(&[abandoned], &[], now());
        assert_eq!(p[0].lapsed, 0, "never paid, so no customer was lost");
        assert_eq!(p[0].lapsed_never_paid, 1);
        assert_eq!(p[0].churn_rate, None, "nothing reached a renewal decision");
    }

    #[test]
    fn test_renewal_periods_never_fold_unknown_into_manual() {
        let renewals = vec![
            (1, dt(2026, 8, 2), Some(RenewalSource::Auto)),
            (2, dt(2026, 8, 3), Some(RenewalSource::Manual)),
            // Pre-migration row: not attributable, must stay its own bucket.
            (3, dt(2026, 8, 4), None),
        ];
        let p = build_renewal_periods(&[], &renewals, now());
        assert_eq!(p[0].renewed, 3);
        assert_eq!(p[0].renewed_auto, 1);
        assert_eq!(p[0].renewed_manual, 1);
        assert_eq!(p[0].renewed_unknown, 1);
    }

    #[test]
    fn test_renewal_periods_cover_months_from_either_side() {
        let rows = vec![outlook(dt(2026, 9, 20), true, true)];
        let renewals = vec![(1, dt(2026, 7, 9), Some(RenewalSource::Auto))];
        let p = build_renewal_periods(&rows, &renewals, now());
        let keys: Vec<&str> = p.iter().map(|x| x.period.as_str()).collect();
        assert_eq!(keys, vec!["2026-07", "2026-09"]);
        assert_eq!(p[0].renewed, 1);
        assert_eq!(p[0].due, 0);
        assert_eq!(p[1].due, 1);
        assert_eq!(p[1].renewed, 0);
    }

    #[test]
    fn test_oss_period_key_quarter() {
        assert_eq!(oss_period_key(dt(2025, 1, 15), false), "2025-Q1");
        assert_eq!(oss_period_key(dt(2025, 3, 31), false), "2025-Q1");
        assert_eq!(oss_period_key(dt(2025, 4, 1), false), "2025-Q2");
        assert_eq!(oss_period_key(dt(2025, 7, 1), false), "2025-Q3");
        assert_eq!(oss_period_key(dt(2025, 12, 31), false), "2025-Q4");
    }

    fn nd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn test_window_months_inclusive_of_both_endpoints() {
        let keys: Vec<String> = window_months(nd(2025, 11, 15), nd(2026, 2, 3))
            .iter()
            .map(|m| period_key(*m, false))
            .collect();
        assert_eq!(keys, vec!["2025-11", "2025-12", "2026-01", "2026-02"]);

        // A window inside one month still yields that month.
        let single: Vec<String> = window_months(nd(2026, 3, 2), nd(2026, 3, 28))
            .iter()
            .map(|m| period_key(*m, false))
            .collect();
        assert_eq!(single, vec!["2026-03"]);
    }

    #[test]
    fn test_months_between() {
        assert_eq!(months_between(dt(2025, 1, 31), dt(2025, 1, 1)), 0);
        assert_eq!(months_between(dt(2025, 1, 1), dt(2025, 4, 1)), 3);
        assert_eq!(months_between(dt(2025, 1, 1), dt(2024, 11, 1)), -2);
        assert_eq!(months_between(dt(2024, 6, 1), dt(2026, 6, 1)), 24);
    }

    #[test]
    fn test_depreciation_for_month_straight_line_window() {
        let purchase = dt(2025, 6, 20);
        // Purchase month is charged, as is the last month of the useful life.
        assert_eq!(
            depreciation_for_month(36_000, purchase, 36, dt(2025, 6, 1)),
            1000.0
        );
        assert_eq!(
            depreciation_for_month(36_000, purchase, 36, dt(2028, 5, 1)),
            1000.0
        );
        // Before the purchase and after the life has run out: nothing.
        assert_eq!(
            depreciation_for_month(36_000, purchase, 36, dt(2025, 5, 1)),
            0.0
        );
        assert_eq!(
            depreciation_for_month(36_000, purchase, 36, dt(2028, 6, 1)),
            0.0
        );
        // A zero life would divide by zero; treated as no depreciation (the
        // caller expenses those immediately instead).
        assert_eq!(
            depreciation_for_month(36_000, purchase, 0, dt(2025, 6, 1)),
            0.0
        );
    }

    #[test]
    fn test_depreciation_sums_to_the_full_cost() {
        let purchase = dt(2025, 1, 10);
        let total: f64 = window_months(nd(2024, 1, 1), nd(2030, 12, 1))
            .iter()
            .map(|m| depreciation_for_month(120_000, purchase, 24, *m))
            .sum();
        assert!((total - 120_000.0).abs() < 1e-6);
    }

    #[test]
    fn test_oss_period_key_bimonthly() {
        assert_eq!(oss_period_key(dt(2025, 1, 1), true), "2025-B1");
        assert_eq!(oss_period_key(dt(2025, 2, 28), true), "2025-B1");
        assert_eq!(oss_period_key(dt(2025, 3, 1), true), "2025-B2");
        assert_eq!(oss_period_key(dt(2025, 11, 1), true), "2025-B6");
        assert_eq!(oss_period_key(dt(2025, 12, 31), true), "2025-B6");
    }
}
