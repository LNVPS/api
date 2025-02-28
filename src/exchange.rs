use anyhow::{Error, Result};
use lnvps_db::async_trait;
use log::info;
use rocket::serde::Deserialize;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Ticker(Currency, Currency);

impl Ticker {
    pub fn btc_rate(cur: &str) -> Result<Self> {
        let to_cur: Currency = cur.parse().map_err(|_| Error::msg(""))?;
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

#[async_trait]
pub trait ExchangeRateService: Send + Sync {
    async fn fetch_rates(&self) -> Result<Vec<TickerRate>>;
    async fn set_rate(&self, ticker: Ticker, amount: f32);
    async fn get_rate(&self, ticker: Ticker) -> Option<f32>;
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
}

#[derive(Deserialize)]
struct MempoolRates {
    #[serde(rename = "USD")]
    pub usd: Option<f32>,
    #[serde(rename = "EUR")]
    pub eur: Option<f32>,
}
