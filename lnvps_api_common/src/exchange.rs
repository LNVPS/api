use crate::RedisConfig;
use anyhow::{Result, anyhow, ensure};
use async_trait::async_trait;
use log::{error, info, trace};
use payments_rs::currency::{Currency, CurrencyAmount};
use redis::{AsyncCommands, Client as RedisClient};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Create the exchange service using redis or in-memory as fallback
pub fn make_exchange_service(redis: &Option<RedisConfig>) -> Arc<dyn ExchangeRateService> {
    if let Some(redis_config) = redis {
        match RedisExchangeRateService::new(&redis_config.url) {
            Ok(redis_service) => {
                info!("Using Redis exchange rate service");
                Arc::new(redis_service)
            }
            Err(e) => {
                error!(
                    "Failed to initialize Redis exchange rate service: {}, falling back to in-memory cache",
                    e
                );
                Arc::new(InMemoryRateCache::default())
            }
        }
    } else {
        info!("Using in-memory exchange rate cache");
        Arc::new(InMemoryRateCache::default())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ticker(pub Currency, pub Currency);

impl Ticker {
    pub fn btc_rate(cur: &str) -> Result<Self> {
        let to_cur: Currency = cur.parse().map_err(|_| anyhow!("Invalid currency"))?;
        Ok(Ticker(Currency::BTC, to_cur))
    }
}

impl Display for Ticker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct TickerRate {
    pub ticker: Ticker,
    pub rate: f32,
}

/// A currency amount converted into a new amount using exchange rates
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConvertedCurrencyAmount {
    pub amount: CurrencyAmount,
    pub rate: TickerRate,
}

impl Sub for ConvertedCurrencyAmount {
    type Output = Result<ConvertedCurrencyAmount>;

    fn sub(self, rhs: Self) -> Self::Output {
        ensure!(self.rate.ticker == rhs.rate.ticker, "Exchange doesnt match");
        Ok(ConvertedCurrencyAmount {
            amount: (self.amount - rhs.amount)?,
            rate: self.rate,
        })
    }
}

impl TickerRate {
    pub fn can_convert(&self, currency: Currency) -> bool {
        currency == self.ticker.0 || currency == self.ticker.1
    }

    /// Convert from the source currency into the target currency.
    ///
    /// The math is done in `f64` on the integer smallest-unit values (cents /
    /// milli-sats) and only rounded to `u64` at the end. Routing through
    /// `f32`/`value_f32()` (as an earlier version did) lost precision — e.g.
    /// €1.00 at 100,000 EUR/BTC produced 999,999 msat instead of 1,000,000.
    pub fn convert(&self, source: CurrencyAmount) -> Result<CurrencyAmount> {
        ensure!(
            self.can_convert(source.currency()),
            "Cant convert, currency doesnt match"
        );
        let rate = self.rate as f64;
        let (target, factor) = if source.currency() == self.ticker.0 {
            (self.ticker.1, rate)
        } else {
            (self.ticker.0, 1.0 / rate)
        };
        let src_standard = source.value() as f64 / Self::scale(source.currency());
        let dst_standard = src_standard * factor;
        let dst_smallest = (dst_standard * Self::scale(target)).round() as u64;
        Ok(CurrencyAmount::from_u64(target, dst_smallest))
    }

    /// Number of smallest units per standard unit for a currency, matching
    /// `payments_rs` (BTC = 1e11 milli-sats, all fiat = 100 cents).
    fn scale(currency: Currency) -> f64 {
        match currency {
            Currency::BTC => 1.0e11,
            _ => 100.0,
        }
    }

    pub fn passthrough(currency: Currency) -> Self {
        Self {
            ticker: Ticker(currency, currency),
            rate: 1.0,
        }
    }

    /// Convert from the source currency into the target currency and return ConvertedCurrencyAmount
    pub fn convert_with_rate(&self, source: CurrencyAmount) -> Result<ConvertedCurrencyAmount> {
        let converted_amount = self.convert(source)?;
        Ok(ConvertedCurrencyAmount {
            amount: converted_amount,
            rate: *self,
        })
    }
}

#[async_trait]
pub trait ExchangeRateService: Send + Sync {
    async fn fetch_rates(&self) -> Result<Vec<TickerRate>>;
    async fn set_rate(&self, ticker: Ticker, amount: f32);
    async fn get_rate(&self, ticker: Ticker) -> Option<f32>;
    async fn list_rates(&self) -> Result<Vec<TickerRate>>;
}

/// Get alternative prices based on a source price
/// Convert `source` into every other supported currency we have a rate path for.
///
/// Two passes are used:
/// 1. **Direct** — any rate touching the source currency (e.g. `source -> BTC`
///    and any direct fiat FX such as `EUR -> USD`).
/// 2. **Cross** — hop through each direct result (chiefly `source -> BTC -> fiat`)
///    to reach currencies we have no direct rate for.
///
/// Results are de-duplicated per target currency, **preferring a direct rate**
/// over a BTC round-trip: ECB fiat FX is more accurate for fiat<->fiat than
/// hopping through BTC, and the source's BTC counterpart comes from the direct
/// pass anyway. The source currency itself is never included.
pub fn alt_prices(rates: &Vec<TickerRate>, source: CurrencyAmount) -> Vec<CurrencyAmount> {
    // Pass 1: direct conversions from the source currency.
    let direct: Vec<CurrencyAmount> = rates
        .iter()
        .filter_map(|r| r.convert(source).ok())
        .filter(|c| c.currency() != source.currency())
        .collect();

    // Pass 2: cross conversions via each direct result.
    let mut cross = vec![];
    for y in rates.iter() {
        for x in direct.iter() {
            if let Ok(r1) = y.convert(*x)
                && r1.currency() != source.currency()
            {
                cross.push(r1);
            }
        }
    }

    // De-duplicate per target currency, keeping the first occurrence. Direct
    // results are considered before cross results, so a direct fiat FX rate wins
    // over the BTC round-trip for the same currency.
    let mut seen = HashSet::new();
    let mut ret = Vec::new();
    for amount in direct.into_iter().chain(cross) {
        if seen.insert(amount.currency()) {
            ret.push(amount);
        }
    }
    ret
}

/// Fetch fiat FX rates for `base` against each of `symbols` from frankfurter.app
/// (ECB reference rates, free, no API key). Returns `Ticker(base, X)` rates
/// where the value is the amount of `X` per 1 unit of `base`.
///
/// The `base` is the caller's currency of interest (a company's billing
/// currency), never a hardcoded value. BTC is skipped — BTC prices come from
/// mempool.space, not an FX feed.
pub async fn fetch_fiat_fx_rates(base: Currency, symbols: &[Currency]) -> Result<Vec<TickerRate>> {
    let symbol_list = symbols
        .iter()
        .filter(|c| **c != base && **c != Currency::BTC)
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if base == Currency::BTC || symbol_list.is_empty() {
        return Ok(vec![]);
    }
    let url = format!("https://api.frankfurter.app/latest?base={base}&symbols={symbol_list}");
    let rsp = reqwest::get(&url).await?.text().await?;
    let parsed: FrankfurterRates = serde_json::from_str(&rsp)?;
    let mut ret = Vec::new();
    for cur in symbols {
        if let Some(rate) = parsed.rates.get(&cur.to_string()) {
            ret.push(TickerRate {
                ticker: Ticker(base, *cur),
                rate: *rate,
            });
        }
    }
    Ok(ret)
}

/// Fetch fiat FX rates covering every ordered pair among `currencies` (each
/// currency as a base against all the others). Errors for individual bases are
/// logged and skipped. Use this to keep direct rates between the set of
/// currencies actually in use (e.g. distinct company billing currencies).
pub async fn fetch_fx_for_currencies(currencies: &[Currency]) -> Vec<TickerRate> {
    let mut ret = Vec::new();
    for base in currencies {
        match fetch_fiat_fx_rates(*base, currencies).await {
            Ok(mut fx) => ret.append(&mut fx),
            Err(e) => error!("Failed to fetch fiat FX for base {}: {}", base, e),
        }
    }
    ret
}

#[derive(Clone, Default)]
pub struct InMemoryRateCache {
    cache: Arc<RwLock<HashMap<Ticker, f32>>>,
}

#[async_trait]
impl ExchangeRateService for InMemoryRateCache {
    async fn fetch_rates(&self) -> Result<Vec<TickerRate>> {
        let rsp = reqwest::get("https://mempool.space/api/v1/prices")
            .await?
            .text()
            .await?;
        let rates: MempoolRates = serde_json::from_str(&rsp)?;

        let mut ret = vec![];
        if let Some(usd) = rates.usd {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::USD),
                rate: usd,
            });
        }
        if let Some(eur) = rates.eur {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::EUR),
                rate: eur,
            });
        }
        if let Some(gbp) = rates.gbp {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::GBP),
                rate: gbp,
            });
        }
        if let Some(cad) = rates.cad {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::CAD),
                rate: cad,
            });
        }
        if let Some(chf) = rates.chf {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::CHF),
                rate: chf,
            });
        }
        if let Some(aud) = rates.aud {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::AUD),
                rate: aud,
            });
        }
        if let Some(jpy) = rates.jpy {
            ret.push(TickerRate {
                ticker: Ticker(Currency::BTC, Currency::JPY),
                rate: jpy,
            });
        }

        Ok(ret)
    }

    async fn set_rate(&self, ticker: Ticker, amount: f32) {
        let mut cache = self.cache.write().await;
        trace!("{}: {}", &ticker, amount);
        cache.insert(ticker, amount);
    }

    async fn get_rate(&self, ticker: Ticker) -> Option<f32> {
        let cache = self.cache.read().await;
        cache.get(&ticker).cloned()
    }

    async fn list_rates(&self) -> Result<Vec<TickerRate>> {
        let cache = self.cache.read().await;
        Ok(cache
            .iter()
            .map(|(k, v)| TickerRate {
                ticker: *k,
                rate: *v,
            })
            .collect())
    }
}

/// Redis-backed exchange rate service that fetches from mempool.space and caches in Redis
#[derive(Clone)]
pub struct RedisExchangeRateService {
    redis_client: RedisClient,
    cache_ttl: Duration,
}

impl RedisExchangeRateService {
    /// Create a new RedisExchangeRateService
    pub fn new(redis_url: &str) -> Result<Self> {
        let redis_client = RedisClient::open(redis_url)?;
        Ok(Self {
            redis_client,
            cache_ttl: Duration::from_secs(300), // 5 minutes default TTL
        })
    }

    /// Create with custom cache TTL
    pub fn with_ttl(redis_url: &str, cache_ttl: Duration) -> Result<Self> {
        let mut service = Self::new(redis_url)?;
        service.cache_ttl = cache_ttl;
        Ok(service)
    }

    /// Create with custom key prefix and TTL
    pub fn with_config(redis_url: &str, cache_ttl: Duration) -> Result<Self> {
        let redis_client = RedisClient::open(redis_url)?;
        Ok(Self {
            redis_client,
            cache_ttl,
        })
    }

    fn ticker_key(&self, ticker: &Ticker) -> String {
        format!("exchange_rate:{}", ticker)
    }

    /// Fetch rates from mempool.space and cache them
    async fn fetch_and_cache_from_mempool(&self) -> Result<Vec<TickerRate>> {
        let rsp = reqwest::get("https://mempool.space/api/v1/prices")
            .await?
            .text()
            .await?;
        let rates: MempoolRates = serde_json::from_str(&rsp)?;

        let mut ret = vec![];
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;

        // Process each currency rate and cache in Redis
        if let Some(usd) = rates.usd {
            let ticker = Ticker(Currency::BTC, Currency::USD);
            let ticker_rate = TickerRate { ticker, rate: usd };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), usd, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(eur) = rates.eur {
            let ticker = Ticker(Currency::BTC, Currency::EUR);
            let ticker_rate = TickerRate { ticker, rate: eur };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), eur, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(gbp) = rates.gbp {
            let ticker = Ticker(Currency::BTC, Currency::GBP);
            let ticker_rate = TickerRate { ticker, rate: gbp };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), gbp, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(cad) = rates.cad {
            let ticker = Ticker(Currency::BTC, Currency::CAD);
            let ticker_rate = TickerRate { ticker, rate: cad };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), cad, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(chf) = rates.chf {
            let ticker = Ticker(Currency::BTC, Currency::CHF);
            let ticker_rate = TickerRate { ticker, rate: chf };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), chf, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(aud) = rates.aud {
            let ticker = Ticker(Currency::BTC, Currency::AUD);
            let ticker_rate = TickerRate { ticker, rate: aud };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), aud, self.cache_ttl.as_secs())
                .await?;
        }
        if let Some(jpy) = rates.jpy {
            let ticker = Ticker(Currency::BTC, Currency::JPY);
            let ticker_rate = TickerRate { ticker, rate: jpy };
            ret.push(ticker_rate);

            let _: () = conn
                .set_ex(self.ticker_key(&ticker), jpy, self.cache_ttl.as_secs())
                .await?;
        }

        trace!("Fetched and cached {} rates from mempool.space", ret.len());
        Ok(ret)
    }
}

#[async_trait]
impl ExchangeRateService for RedisExchangeRateService {
    async fn fetch_rates(&self) -> Result<Vec<TickerRate>> {
        self.fetch_and_cache_from_mempool().await
    }

    async fn set_rate(&self, ticker: Ticker, amount: f32) {
        trace!("{}: {}", &ticker, amount);
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await {
            let _: Result<(), redis::RedisError> = conn
                .set_ex(self.ticker_key(&ticker), amount, self.cache_ttl.as_secs())
                .await;
        }
    }

    async fn get_rate(&self, ticker: Ticker) -> Option<f32> {
        if let Ok(mut conn) = self.redis_client.get_multiplexed_async_connection().await
            && let Ok(rate) = conn.get::<_, f32>(&self.ticker_key(&ticker)).await
        {
            return Some(rate);
        }
        None
    }

    async fn list_rates(&self) -> Result<Vec<TickerRate>> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await?;
        let keys: Vec<String> = conn.keys("exchange_rate:*").await?;

        let mut rates = Vec::new();
        for key in keys {
            if let Ok(rate) = conn.get::<_, f32>(&key).await {
                // Extract ticker from key by removing prefix
                let ticker_str = key.strip_prefix("exchange_rate:").unwrap_or(&key);

                // Parse ticker string back to Ticker struct using split("/") and and_then
                let mut parts = ticker_str.split('/');
                let from_currency = parts.next().and_then(|s| s.parse::<Currency>().ok());
                let to_currency = parts.next().and_then(|s| s.parse::<Currency>().ok());

                if let (Some(from), Some(to)) = (from_currency, to_currency) {
                    rates.push(TickerRate {
                        ticker: Ticker(from, to),
                        rate,
                    });
                }
            }
        }

        Ok(rates)
    }
}

#[derive(Deserialize)]
struct FrankfurterRates {
    #[serde(default)]
    pub rates: HashMap<String, f32>,
}

#[derive(Deserialize)]
struct MempoolRates {
    #[serde(rename = "USD")]
    pub usd: Option<f32>,
    #[serde(rename = "EUR")]
    pub eur: Option<f32>,
    #[serde(rename = "CAD")]
    pub cad: Option<f32>,
    #[serde(rename = "GBP")]
    pub gbp: Option<f32>,
    #[serde(rename = "CHF")]
    pub chf: Option<f32>,
    #[serde(rename = "AUD")]
    pub aud: Option<f32>,
    #[serde(rename = "JPY")]
    pub jpy: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: f32 = 95_000.0;
    #[test]
    fn convert() {
        let ticker = Ticker::btc_rate("EUR").unwrap();
        let f = TickerRate { ticker, rate: RATE };

        // €5.00 / 95,000 = 5.263157894...e-5 BTC = 5,263,157.89 msat -> 5,263,158
        assert_eq!(
            f.convert(CurrencyAmount::from_u64(Currency::EUR, 500))
                .unwrap(),
            CurrencyAmount::millisats(5_263_158)
        );
        // 0.001 BTC * 95,000 = €95.00 = 9500 cents
        assert_eq!(
            f.convert(CurrencyAmount::millisats(100_000_000)).unwrap(),
            CurrencyAmount::from_u64(Currency::EUR, 9500)
        );
        assert!(!f.can_convert(Currency::USD));
        assert!(f.can_convert(Currency::EUR));
        assert!(f.can_convert(Currency::BTC));
    }

    #[tokio::test]
    async fn fx_fetch_noop_cases() {
        // No symbols -> no request, empty result
        assert!(
            fetch_fiat_fx_rates(Currency::USD, &[])
                .await
                .unwrap()
                .is_empty()
        );
        // Only self / BTC symbols -> filtered out -> empty
        assert!(
            fetch_fiat_fx_rates(Currency::EUR, &[Currency::EUR, Currency::BTC])
                .await
                .unwrap()
                .is_empty()
        );
        // BTC base is never fetched via FX
        assert!(
            fetch_fiat_fx_rates(Currency::BTC, &[Currency::USD])
                .await
                .unwrap()
                .is_empty()
        );
        // A single currency has no pairs to fetch
        assert!(fetch_fx_for_currencies(&[Currency::EUR]).await.is_empty());
    }

    #[tokio::test]
    async fn fx_fetch_real_pair_uses_requested_base() -> Result<()> {
        // Hits frankfurter.app (ECB). base=EUR must yield a Ticker(EUR, USD).
        let rates = fetch_fiat_fx_rates(Currency::EUR, &[Currency::USD]).await?;
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].ticker, Ticker(Currency::EUR, Currency::USD));
        assert!(rates[0].rate > 0.0);
        Ok(())
    }

    /// Regression: conversions must be integer-precise, not lose a unit to f32.
    #[test]
    fn convert_precise_no_f32_loss() {
        let f = TickerRate {
            ticker: Ticker::btc_rate("EUR").unwrap(),
            rate: 100_000.0,
        };
        // €1.00 at 100,000 EUR/BTC = exactly 1e-5 BTC = 1,000,000 msat
        assert_eq!(
            f.convert(CurrencyAmount::from_u64(Currency::EUR, 100))
                .unwrap(),
            CurrencyAmount::millisats(1_000_000)
        );
        // Round-trip back to EUR is exact
        assert_eq!(
            f.convert(CurrencyAmount::millisats(1_000_000)).unwrap(),
            CurrencyAmount::from_u64(Currency::EUR, 100)
        );
    }

    /// alt_prices yields at most one entry per target currency, never repeats the
    /// source, and prefers a direct fiat FX rate over the BTC round-trip.
    #[test]
    fn alt_prices_dedups_and_prefers_direct_fx() {
        // BTC priced in both EUR and USD, plus a direct EUR/USD FX rate. Without
        // dedup, USD would appear twice (direct EUR->USD and EUR->BTC->USD).
        let rates = vec![
            TickerRate {
                ticker: Ticker(Currency::BTC, Currency::EUR),
                rate: 100_000.0,
            },
            TickerRate {
                ticker: Ticker(Currency::BTC, Currency::USD),
                rate: 110_000.0,
            },
            // Direct FX: 1 EUR = 1.20 USD. (Note the BTC cross implies ~1.10.)
            TickerRate {
                ticker: Ticker(Currency::EUR, Currency::USD),
                rate: 1.20,
            },
        ];

        let out = alt_prices(&rates, CurrencyAmount::from_u64(Currency::EUR, 100));

        // One entry per currency, no source (EUR), no duplicates.
        let mut currencies: Vec<Currency> = out.iter().map(|c| c.currency()).collect();
        currencies.sort_by_key(|c| c.to_string());
        assert_eq!(currencies, vec![Currency::BTC, Currency::USD]);

        // USD came from the direct FX rate (1.20), not the BTC round-trip (~1.10).
        let usd = out
            .iter()
            .find(|c| c.currency() == Currency::USD)
            .unwrap();
        assert_eq!(*usd, CurrencyAmount::from_u64(Currency::USD, 120));
    }
}
