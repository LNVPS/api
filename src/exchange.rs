use anyhow::{anyhow, ensure, Context, Error, Result};
use lnvps_db::async_trait;
use log::info;
use rocket::serde::Deserialize;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Clone, Copy, JsonSchema)]
pub enum Currency {
    EUR,
    BTC,
    USD,
}

impl Display for Currency {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Currency::EUR => write!(f, "EUR"),
            Currency::BTC => write!(f, "BTC"),
            Currency::USD => write!(f, "USD"),
        }
    }
}

impl FromStr for Currency {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "eur" => Ok(Currency::EUR),
            "usd" => Ok(Currency::USD),
            "btc" => Ok(Currency::BTC),
            _ => Err(()),
        }
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

#[derive(Debug, PartialEq)]
pub struct TickerRate(pub Ticker, pub f32);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurrencyAmount(pub Currency, pub f32);

impl TickerRate {
    pub fn can_convert(&self, currency: Currency) -> bool {
        currency == self.0 .0 || currency == self.0 .1
    }

    /// Convert from the source currency into the target currency
    pub fn convert(&self, source: CurrencyAmount) -> Result<CurrencyAmount> {
        ensure!(
            self.can_convert(source.0),
            "Cant convert, currency doesnt match"
        );
        if source.0 == self.0 .0 {
            Ok(CurrencyAmount(self.0 .1, source.1 * self.1))
        } else {
            Ok(CurrencyAmount(self.0 .0, source.1 / self.1))
        }
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
    // TODO: return all alt prices by cross-converting all currencies
    rates
        .iter()
        .filter_map(|r| r.convert(source).ok())
        .collect()
}

#[derive(Clone, Default)]
pub struct DefaultRateCache {
    cache: Arc<RwLock<HashMap<Ticker, f32>>>,
}

#[async_trait]
impl ExchangeRateService for DefaultRateCache {
    async fn fetch_rates(&self) -> Result<Vec<TickerRate>> {
        let rsp = reqwest::get("https://mempool.space/api/v1/prices")
            .await?
            .text()
            .await?;
        let rates: MempoolRates = serde_json::from_str(&rsp)?;

        let mut ret = vec![];
        if let Some(usd) = rates.usd {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::USD), usd));
        }
        if let Some(eur) = rates.eur {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::EUR), eur));
        }

        Ok(ret)
    }

    async fn set_rate(&self, ticker: Ticker, amount: f32) {
        let mut cache = self.cache.write().await;
        info!("{}: {}", &ticker, amount);
        cache.insert(ticker, amount);
    }

    async fn get_rate(&self, ticker: Ticker) -> Option<f32> {
        let cache = self.cache.read().await;
        cache.get(&ticker).cloned()
    }

    async fn list_rates(&self) -> Result<Vec<TickerRate>> {
        let cache = self.cache.read().await;
        Ok(cache.iter().map(|(k, v)| TickerRate(*k, *v)).collect())
    }
}

#[derive(Deserialize)]
struct MempoolRates {
    #[serde(rename = "USD")]
    pub usd: Option<f32>,
    #[serde(rename = "EUR")]
    pub eur: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: f32 = 95_000.0;
    #[test]
    fn convert() {
        let ticker = Ticker::btc_rate("EUR").unwrap();
        let f = TickerRate(ticker, RATE);

        assert_eq!(
            f.convert(CurrencyAmount(Currency::EUR, 5.0)).unwrap(),
            CurrencyAmount(Currency::BTC, 5.0 / RATE)
        );
        assert_eq!(
            f.convert(CurrencyAmount(Currency::BTC, 0.001)).unwrap(),
            CurrencyAmount(Currency::EUR, RATE * 0.001)
        );
        assert!(!f.can_convert(Currency::USD));
        assert!(f.can_convert(Currency::EUR));
        assert!(f.can_convert(Currency::BTC));
    }
}
