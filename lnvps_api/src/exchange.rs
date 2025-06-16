use anyhow::{anyhow, ensure, Result};
use lnvps_db::async_trait;
use log::{info, trace};
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
    GBP,
    CAD,
    CHF,
    AUD,
    JPY,
}

impl Display for Currency {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Currency::EUR => write!(f, "EUR"),
            Currency::BTC => write!(f, "BTC"),
            Currency::USD => write!(f, "USD"),
            Currency::GBP => write!(f, "GBP"),
            Currency::CAD => write!(f, "CAD"),
            Currency::CHF => write!(f, "CHF"),
            Currency::AUD => write!(f, "AUD"),
            Currency::JPY => write!(f, "JPY"),
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
            "gbp" => Ok(Currency::GBP),
            "cad" => Ok(Currency::CAD),
            "chf" => Ok(Currency::CHF),
            "aud" => Ok(Currency::AUD),
            "jpy" => Ok(Currency::JPY),
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
pub struct CurrencyAmount(Currency, u64);

impl CurrencyAmount {
    const MILLI_SATS: f64 = 1.0e11;

    pub fn millisats(amount: u64) -> Self {
        CurrencyAmount(Currency::BTC, amount)
    }

    pub fn from_u64(currency: Currency, amount: u64) -> Self {
        CurrencyAmount(currency, amount)
    }

    pub fn from_f32(currency: Currency, amount: f32) -> Self {
        CurrencyAmount(
            currency,
            match currency {
                Currency::BTC => (amount as f64 * Self::MILLI_SATS) as u64, // milli-sats
                _ => (amount * 100.0) as u64,                               // cents
            },
        )
    }

    pub fn value(&self) -> u64 {
        self.1
    }

    pub fn value_f32(&self) -> f32 {
        match self.0 {
            Currency::BTC => (self.1 as f64 / Self::MILLI_SATS) as f32,
            _ => self.1 as f32 / 100.0,
        }
    }

    pub fn currency(&self) -> Currency {
        self.0
    }
}

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
            Ok(CurrencyAmount::from_f32(
                self.0 .1,
                source.value_f32() * self.1,
            ))
        } else {
            Ok(CurrencyAmount::from_f32(
                self.0 .0,
                source.value_f32() / self.1,
            ))
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
    let mut ret: Vec<CurrencyAmount> = rates
        .iter()
        .filter_map(|r| r.convert(source).ok())
        .collect();

    let mut ret2 = vec![];
    for y in rates.iter() {
        for x in ret.iter() {
            if let Ok(r1) = y.convert(*x) {
                if r1.0 != source.0 {
                    ret2.push(r1);
                }
            }
        }
    }
    ret.append(&mut ret2);
    ret
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
        if let Some(gbp) = rates.gbp {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::GBP), gbp));
        }
        if let Some(cad) = rates.cad {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::CAD), cad));
        }
        if let Some(chf) = rates.chf {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::CHF), chf));
        }
        if let Some(aud) = rates.aud {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::AUD), aud));
        }
        if let Some(jpy) = rates.jpy {
            ret.push(TickerRate(Ticker(Currency::BTC, Currency::JPY), jpy));
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
        Ok(cache.iter().map(|(k, v)| TickerRate(*k, *v)).collect())
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
        let f = TickerRate(ticker, RATE);

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
