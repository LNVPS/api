use anyhow::{Result, anyhow, ensure};
use async_trait::async_trait;
use log::trace;
use payments_rs::currency::{Currency, CurrencyAmount};
use redis::{AsyncCommands, Client as RedisClient};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::ops::Sub;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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

    /// Convert from the source currency into the target currency
    pub fn convert(&self, source: CurrencyAmount) -> Result<CurrencyAmount> {
        ensure!(
            self.can_convert(source.currency()),
            "Cant convert, currency doesnt match"
        );
        if source.currency() == self.ticker.0 {
            Ok(CurrencyAmount::from_f32(
                self.ticker.1,
                source.value_f32() * self.rate,
            ))
        } else {
            Ok(CurrencyAmount::from_f32(
                self.ticker.0,
                source.value_f32() / self.rate,
            ))
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
pub fn alt_prices(rates: &Vec<TickerRate>, source: CurrencyAmount) -> Vec<CurrencyAmount> {
    let mut ret: Vec<CurrencyAmount> = rates
        .iter()
        .filter_map(|r| r.convert(source).ok())
        .collect();

    let mut ret2 = vec![];
    for y in rates.iter() {
        for x in ret.iter() {
            if let Ok(r1) = y.convert(*x)
                && r1.currency() != source.currency() {
                    ret2.push(r1);
                }
        }
    }
    ret.append(&mut ret2);
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
            && let Ok(rate) = conn.get::<_, f32>(&self.ticker_key(&ticker)).await {
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
        let f = TickerRate {
            ticker: ticker,
            rate: RATE,
        };

        assert_eq!(
            f.convert(CurrencyAmount::from_f32(Currency::EUR, 5.0))
                .unwrap(),
            CurrencyAmount::from_f32(Currency::BTC, 5.0 / RATE)
        );
        assert_eq!(
            f.convert(CurrencyAmount::from_f32(Currency::BTC, 0.001))
                .unwrap(),
            CurrencyAmount::from_f32(Currency::EUR, RATE * 0.001)
        );
        assert!(!f.can_convert(Currency::USD));
        assert!(f.can_convert(Currency::EUR));
        assert!(f.can_convert(Currency::BTC));
    }
}
