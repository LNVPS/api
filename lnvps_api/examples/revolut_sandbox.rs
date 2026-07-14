//! Interactive Revolut sandbox harness for the saved-payment-method /
//! off-session auto-renewal flow (issue #159).
//!
//! This exercises the real `payments-rs` Revolut integration against the
//! Revolut **sandbox**. It is NOT a unit test — it talks to the live sandbox
//! API and (for `create`) produces a hosted checkout URL that must be paid once
//! with a test card before an off-session charge can be made.
//!
//! Credentials are read from a YAML file (default `config.local.yaml`, which is
//! gitignored) with a top-level `revolut:` section:
//!
//! ```yaml
//! revolut:
//!   url: "https://sandbox-merchant.revolut.com"
//!   api-version: "2024-09-01"
//!   token: "sk_sandbox_..."
//!   public-key: "pk_sandbox_..."
//! ```
//!
//! Flow:
//!   1. cargo run --example revolut_sandbox --features revolut -- create 9.99 EUR
//!        -> prints ORDER_ID and CHECKOUT_URL
//!      (pay the CHECKOUT_URL once with a Revolut test card, e.g. 4111 1111 1111 1111)
//!   2. cargo run --example revolut_sandbox --features revolut -- status <ORDER_ID>
//!        -> prints state + CUSTOMER_ID + PAYMENT_METHOD_ID once the checkout completes
//!   3. cargo run --example revolut_sandbox --features revolut -- charge <CUSTOMER_ID> <PAYMENT_METHOD_ID> 9.99 EUR
//!        -> off-session (merchant-initiated) charge; prints final order state

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::{Config, File};
use payments_rs::currency::{Currency, CurrencyAmount};
use payments_rs::fiat::{FiatPaymentService, RevolutApi, RevolutConfig};
use serde::Deserialize;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
#[command(about = "Revolut sandbox saved-card / off-session test harness")]
struct Args {
    /// Path to a YAML config file containing a `revolut:` section
    #[arg(long, default_value = "config.local.yaml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a savable subscription checkout (returns a checkout URL to pay once)
    Create {
        /// Amount in major units (e.g. 9.99)
        amount: f32,
        /// Currency code (e.g. EUR)
        currency: String,
        /// Customer email (a customer must be attached to save the payment method)
        #[arg(default_value = "test@lnvps.net")]
        email: String,
    },
    /// Fetch an order's current state + any saved customer/payment-method ids
    Status {
        /// Revolut order id
        order_id: String,
    },
    /// Off-session (merchant-initiated) charge against a saved payment method
    Charge {
        customer_id: String,
        payment_method_id: String,
        amount: f32,
        currency: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct HarnessConfig {
    revolut: RevolutConfig,
}

fn load_api(path: &PathBuf) -> Result<RevolutApi> {
    let cfg: HarnessConfig = Config::builder()
        .add_source(File::from(path.clone()))
        .build()
        .with_context(|| format!("failed to load config from {}", path.display()))?
        .try_deserialize()
        .context("config missing a valid `revolut:` section")?;
    RevolutApi::new(cfg.revolut).context("failed to build RevolutApi")
}

fn parse_amount(amount: f32, currency: &str) -> Result<CurrencyAmount> {
    let c = Currency::from_str(currency).map_err(|_| anyhow::anyhow!("bad currency"))?;
    if c == Currency::BTC {
        bail!("BTC is not a fiat currency");
    }
    Ok(CurrencyAmount::from_f32(c, amount))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let api = load_api(&args.config)?;

    match args.cmd {
        Cmd::Create {
            amount,
            currency,
            email,
        } => {
            let amt = parse_amount(amount, &currency)?;
            // Exercises the real code path: create_subscription attaches a
            // customer (via email) + save_payment_method_for=merchant so the
            // card is saved for future off-session charges.
            let info = api
                .create_subscription(
                    "LNVPS auto-renewal sandbox test",
                    amt,
                    Some(email),
                    None,
                )
                .await?;
            println!("ORDER_ID={}", info.external_id);
            println!(
                "CUSTOMER_ID={}",
                info.customer_id.clone().unwrap_or_else(|| "<none>".into())
            );
            let checkout_url = info.checkout_url.clone().unwrap_or_default();
            // The widget needs the order's public token (last path segment of the checkout url)
            let token = checkout_url.rsplit('/').next().unwrap_or("").to_string();
            println!("TOKEN={}", token);
            println!("CHECKOUT_URL={}", checkout_url);
            println!("--> Save a card via the widget (savePaymentMethodFor=merchant), then run `status`.");
        }
        Cmd::Status { order_id } => {
            let order = api.get_order(&order_id).await?;
            println!("STATE={:?}", order.state);
            let customer_id = order.customer_id();
            println!(
                "CUSTOMER_ID={}",
                customer_id.clone().unwrap_or_else(|| "<none>".into())
            );
            // The reusable saved payment method is fetched from the customer
            // endpoint (not the order).
            if let Some(cust) = customer_id {
                let methods = api.get_customer_payment_methods(&cust, true).await?;
                if methods.is_empty() {
                    println!("PAYMENT_METHOD_ID=<none> (no merchant-initiated method saved yet)");
                }
                for m in methods {
                    println!("PAYMENT_METHOD_ID={} TYPE={:?} SAVED_FOR={:?}", m.id, m.kind, m.saved_for);
                }
            }
        }
        Cmd::Charge {
            customer_id,
            payment_method_id,
            amount,
            currency,
        } => {
            let amt = parse_amount(amount, &currency)?;
            let order = api
                .create_off_session_order(
                    &customer_id,
                    &payment_method_id,
                    payments_rs::fiat::RevolutSavedPaymentMethodType::Card,
                    amt,
                    Some("LNVPS off-session auto-renewal sandbox test".to_string()),
                )
                .await?;
            println!("ORDER_ID={}", order.id);
            println!("STATE={:?}", order.state);
            println!("OUTSTANDING={}", order.outstanding_amount);
        }
    }
    Ok(())
}
