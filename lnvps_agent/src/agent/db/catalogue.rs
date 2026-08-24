//! Catalogue tools: what LNVPS sells and what it costs.
//!
//! Nothing in this module reads an account, which is why the whole group is
//! offered to logged-out visitors: pre-sales is who asks. Prices are read from
//! the same tables the order endpoints price against, and custom quotes run
//! through the real validator, so a quote the agent relays can be ordered.

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use lnvps_api_common::{CUSTOM_VM_INTERVAL_AMOUNT, PricingEngine, alt_prices};
use lnvps_db::{
    DiskInterface, DiskType, VmCostPlan, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate,
};
use payments_rs::currency::{Currency, CurrencyAmount};

use super::{DbToolExecutor, currency, money, required_gb_as_bytes, required_u64};

/// Human-readable billing interval of a cost plan, e.g. "1 month".
fn interval(plan: &VmCostPlan) -> String {
    format!(
        "{} {}",
        plan.interval_amount,
        format!("{:?}", plan.interval_type).to_lowercase()
    )
}

/// The performance caps a plan or custom pricing applies.
///
/// `None` means uncapped, and is reported as such: an omitted field reads to a
/// model as "unknown", which is the opposite of what it means here.
fn limits(
    disk_iops_read: Option<u32>,
    disk_iops_write: Option<u32>,
    disk_mbps_read: Option<u32>,
    disk_mbps_write: Option<u32>,
    network_mbps: Option<u32>,
    cpu_limit: Option<f32>,
) -> Value {
    fn cap<T: Into<Value>>(v: Option<T>) -> Value {
        v.map(Into::into)
            .unwrap_or(Value::String("uncapped".into()))
    }
    json!({
        "disk_iops_read": cap(disk_iops_read),
        "disk_iops_write": cap(disk_iops_write),
        "disk_mbps_read": cap(disk_mbps_read),
        "disk_mbps_write": cap(disk_mbps_write),
        "network_mbps": cap(network_mbps),
        "cpu_limit": cap(cpu_limit),
    })
}

impl DbToolExecutor {
    pub(super) async fn regions(&self) -> Result<Value> {
        let mut out = Vec::new();
        for region in self
            .db
            .list_host_region()
            .await?
            .into_iter()
            .filter(|r| r.enabled)
        {
            // The operating company is the contracting entity named on the
            // invoice, so identity and country are useful and public. Contact
            // and tax details are not copied out.
            let company = self.db.get_company(region.company_id).await.ok();
            out.push(json!({
                "id": region.id,
                "name": region.name,
                "company": company.map(|c| json!({
                    "name": c.name,
                    "country_code": c.country_code,
                    "base_currency": c.base_currency,
                })),
            }));
        }
        Ok(Value::Array(out))
    }

    /// Fixed plans, each with its cost plan resolved into a real price.
    ///
    /// A template without a readable cost plan is dropped rather than listed
    /// without a price: an unpriced plan in the model's context is exactly the
    /// input that makes it invent one.
    pub(super) async fn templates(&self) -> Result<Value> {
        let regions: HashMap<u64, String> = self
            .db
            .list_host_region()
            .await?
            .into_iter()
            .map(|r| (r.id, r.name))
            .collect();

        let mut out = Vec::new();
        for t in self
            .db
            .list_vm_templates()
            .await?
            .into_iter()
            .filter(|t| t.enabled)
        {
            let Ok(plan) = self.db.get_cost_plan(t.cost_plan_id).await else {
                log::warn!("Template {} has no readable cost plan, skipping", t.id);
                continue;
            };
            let Ok(plan_currency) = plan.currency.parse::<Currency>() else {
                log::warn!(
                    "Cost plan {} has unknown currency {}",
                    plan.id,
                    plan.currency
                );
                continue;
            };
            out.push(json!({
                "id": t.id,
                "name": t.name,
                "cpu": t.cpu,
                "memory_bytes": t.memory,
                "disk_bytes": t.disk_size,
                "disk_type": t.disk_type.to_string(),
                "disk_interface": t.disk_interface.to_string(),
                "cpu_mfg": t.cpu_mfg.to_string(),
                "cpu_arch": t.cpu_arch.to_string(),
                "cpu_features": t.cpu_features.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ip4_count": t.ip4_count,
                "ip6_count": t.ip6_count,
                "limits": limits(
                    t.disk_iops_read,
                    t.disk_iops_write,
                    t.disk_mbps_read,
                    t.disk_mbps_write,
                    t.network_mbps,
                    t.cpu_limit,
                ),
                "region": { "id": t.region_id, "name": regions.get(&t.region_id) },
                "price": {
                    "per_interval": self.priced(CurrencyAmount::from_u64(plan_currency, plan.amount)).await,
                    "interval": interval(&plan),
                },
            }));
        }
        Ok(Value::Array(out))
    }

    /// Per-unit "build your own" pricing, one entry per enabled pricing row.
    pub(super) async fn custom_pricing(&self) -> Result<Value> {
        let regions: HashMap<u64, String> = self
            .db
            .list_host_region()
            .await?
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| (r.id, r.name))
            .collect();

        let mut out = Vec::new();
        for (region_id, region_name) in regions {
            for pricing in self
                .db
                .list_custom_pricing(region_id)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|p| p.enabled)
            {
                let disks = self
                    .db
                    .list_custom_pricing_disk(pricing.id)
                    .await
                    .unwrap_or_default();
                out.push(
                    self.custom_pricing_entry(&pricing, &disks, &region_name)
                        .await,
                );
            }
        }
        Ok(Value::Array(out))
    }

    /// One custom pricing row: unit costs and the ranges they may be ordered in.
    pub(super) async fn custom_pricing_entry(
        &self,
        pricing: &VmCustomPricing,
        disks: &[VmCustomPricingDisk],
        region_name: &str,
    ) -> Value {
        let Ok(currency) = pricing.currency.parse::<Currency>() else {
            return json!({
                "id": pricing.id,
                "error": format!("unknown currency {}", pricing.currency),
            });
        };
        let unit = |amount: u64| CurrencyAmount::from_u64(currency, amount);

        let mut disk_options = Vec::with_capacity(disks.len());
        for d in disks.iter().filter(|d| d.pricing_id == pricing.id) {
            disk_options.push(json!({
                "disk_type": d.kind.to_string(),
                "disk_interface": d.interface.to_string(),
                "cost_per_gb": self.priced(unit(d.cost)).await,
                "min_disk_bytes": d.min_disk_size,
                "max_disk_bytes": d.max_disk_size,
            }));
        }

        json!({
            "id": pricing.id,
            "name": pricing.name,
            "region": { "id": pricing.region_id, "name": region_name },
            "currency": pricing.currency,
            "billing_interval": format!("{} month(s)", CUSTOM_VM_INTERVAL_AMOUNT),
            "cost_per_cpu_core": self.priced(unit(pricing.cpu_cost)).await,
            "cost_per_gb_memory": self.priced(unit(pricing.memory_cost)).await,
            "cost_per_ip4": self.priced(unit(pricing.ip4_cost)).await,
            "cost_per_ip6": self.priced(unit(pricing.ip6_cost)).await,
            "disk_options": disk_options,
            "min_cpu": pricing.min_cpu,
            "max_cpu": pricing.max_cpu,
            "min_memory_bytes": pricing.min_memory,
            "max_memory_bytes": pricing.max_memory,
            "min_ip4": pricing.min_ip4,
            "max_ip4": pricing.max_ip4,
            "min_ip6": pricing.min_ip6,
            "max_ip6": pricing.max_ip6,
            "cpu_mfg": pricing.cpu_mfg.to_string(),
            "cpu_arch": pricing.cpu_arch.to_string(),
            "cpu_features": pricing.cpu_features.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "limits": limits(
                pricing.disk_iops_read,
                pricing.disk_iops_write,
                pricing.disk_mbps_read,
                pricing.disk_mbps_write,
                pricing.network_mbps,
                pricing.cpu_limit,
            ),
        })
    }

    /// Quote a custom configuration.
    ///
    /// The spec is validated with the same code path the order endpoint uses,
    /// so a quote the model relays can actually be ordered — an out-of-range
    /// spec produces the range in the error rather than a fictional price.
    pub(super) async fn price_custom_vm(&self, args: &HashMap<String, Value>) -> Result<Value> {
        let pricing_id = required_u64(args, "pricing_id")?;
        let pricing = self.db.get_custom_pricing(pricing_id).await?;
        if !pricing.enabled {
            bail!("Custom pricing {} is no longer offered", pricing_id);
        }
        let disks = self.db.list_custom_pricing_disk(pricing_id).await?;
        let default_disk = disks
            .first()
            .ok_or_else(|| anyhow!("Custom pricing {} has no disk options", pricing_id))?;

        let disk_type = match args.get("disk_type").and_then(|v| v.as_str()) {
            Some(s) => s.parse::<DiskType>()?,
            None => default_disk.kind,
        };
        let disk_interface = match args.get("disk_interface").and_then(|v| v.as_str()) {
            Some(s) => s.parse::<DiskInterface>()?,
            None => default_disk.interface,
        };

        let template = VmCustomTemplate {
            id: 0,
            cpu: required_u64(args, "cpu")?.try_into()?,
            memory: required_gb_as_bytes(args, "memory_gb")?,
            disk_size: required_gb_as_bytes(args, "disk_gb")?,
            disk_type,
            disk_interface,
            pricing_id,
            // Default to the minimum the region sells rather than to zero: a
            // quote for a VM with no addresses is not a VM anyone can order.
            ip4_count: args
                .get("ip4_count")
                .and_then(|v| v.as_u64())
                .map(u16::try_from)
                .transpose()?
                .unwrap_or(pricing.min_ip4),
            ip6_count: args
                .get("ip6_count")
                .and_then(|v| v.as_u64())
                .map(u16::try_from)
                .transpose()?
                .unwrap_or(pricing.min_ip6),
            cpu_mfg: pricing.cpu_mfg,
            cpu_arch: pricing.cpu_arch,
            cpu_features: pricing.cpu_features.clone(),
            disk_iops_read: pricing.disk_iops_read,
            disk_iops_write: pricing.disk_iops_write,
            disk_mbps_read: pricing.disk_mbps_read,
            disk_mbps_write: pricing.disk_mbps_write,
            network_mbps: pricing.network_mbps,
            cpu_limit: pricing.cpu_limit,
            firewall_rule_limit: None,
            transfer_gb: pricing.transfer_gb,
        };

        PricingEngine::validate_custom_vm_spec(&self.db, &template).await?;
        let price = PricingEngine::get_custom_vm_cost_amount(&self.db, &template).await?;
        let part = |amount: u64| CurrencyAmount::from_u64(price.currency, amount);

        Ok(json!({
            "pricing_id": pricing_id,
            "region": { "id": pricing.region_id, "name": pricing.name },
            "spec": {
                "cpu": template.cpu,
                "memory_bytes": template.memory,
                "disk_bytes": template.disk_size,
                "disk_type": template.disk_type.to_string(),
                "disk_interface": template.disk_interface.to_string(),
                "ip4_count": template.ip4_count,
                "ip6_count": template.ip6_count,
            },
            "billing_interval": format!("{} month(s)", CUSTOM_VM_INTERVAL_AMOUNT),
            "breakdown": {
                "cpu": money(part(price.cpu_cost)),
                "memory": money(part(price.memory_cost)),
                "disk": money(part(price.disk_cost)),
                "ip4": money(part(price.ip4_cost)),
                "ip6": money(part(price.ip6_cost)),
            },
            "total": self.priced(part(price.total())).await,
            "note": "Price excludes any tax and payment processing fee, which depend on the customer's country and payment method.",
        }))
    }

    /// Convert an amount between supported currencies.
    pub(super) async fn exchange_rate(&self, args: &HashMap<String, Value>) -> Result<Value> {
        let rates = self
            .rates
            .as_ref()
            .ok_or_else(|| anyhow!("Currency conversion is not available in this session"))?;
        let from = currency(
            args.get("from")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("from required"))?,
        )?;
        let to = currency(
            args.get("to")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("to required"))?,
        )?;
        let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(1.0);
        if !amount.is_finite() || amount < 0.0 {
            bail!("amount must be a positive number");
        }
        let source = CurrencyAmount::from_f32(from, amount as f32);

        if from == to {
            return Ok(json!({ "source": money(source), "converted": money(source) }));
        }
        let converted = alt_prices(&rates.list_rates().await?, source)
            .into_iter()
            .find(|c| c.currency() == to)
            .ok_or_else(|| anyhow!("No exchange rate available for {} to {}", from, to))?;
        Ok(json!({
            "source": money(source),
            "converted": money(converted),
        }))
    }

    pub(super) async fn os_images(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_os_image()
                .await?
                .into_iter()
                .filter(|i| i.enabled)
                .map(|i| {
                    json!({
                        "id": i.id,
                        "distribution": i.distribution.to_string(),
                        "flavour": i.flavour,
                        "version": i.version,
                        "cpu_arch": i.cpu_arch.to_string(),
                        "release_date": i.release_date,
                        "default_username": i.default_username,
                    })
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::super::{DbToolExecutor, parse_args};
    use super::*;
    use crate::agent::ToolExecutor;
    use crate::diag::{Diagnostics, LookingGlass, PolicyDocs};
    use lnvps_api_common::{ExchangeRateService, GB, MockDb, MockExchangeRate, Ticker};
    use lnvps_db::LNVpsDb;
    use std::sync::Arc;

    /// The point of a guest session: catalogue questions still work.
    #[tokio::test]
    pub(super) async fn anonymous_executor_serves_the_catalogue() {
        let db = Arc::new(MockDb::default());
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::public(dyn_db);

        for tool in ["list_regions", "list_templates", "list_os_images"] {
            let out = exec
                .execute(tool, "{}")
                .await
                .unwrap_or_else(|e| panic!("{tool} must work without an account: {e}"));
            assert!(out.starts_with('['), "{tool} returned {out}");
        }
    }

    #[tokio::test]
    pub(super) async fn catalogue_tools_return_arrays() {
        let (_db, exec) = executor(1).await;
        for tool in [
            "list_regions",
            "list_templates",
            "list_custom_pricing",
            "list_os_images",
        ] {
            let out = exec.execute(tool, "{}").await.unwrap();
            let parsed: Value = serde_json::from_str(&out).unwrap();
            assert!(parsed.is_array(), "{tool} must return an array");
        }
    }

    /// A plan listed without a price is the input that makes a model invent
    /// one, so every listed template must carry its cost plan.
    #[tokio::test]
    pub(super) async fn templates_carry_a_price_and_interval() {
        let (_db, exec) = executor(1).await;
        let out = exec.execute("list_templates", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let first = &parsed[0];

        assert_eq!(first["price"]["per_interval"]["amount"], 132);
        assert_eq!(first["price"]["per_interval"]["currency"], "EUR");
        assert_eq!(first["price"]["interval"], "1 month");
        // Product details the pre-sales questions actually turn on.
        assert_eq!(first["ip4_count"], 1);
        assert_eq!(first["disk_interface"], "pcie");
        assert_eq!(first["limits"]["network_mbps"], "uncapped");
        assert!(first["region"]["name"].is_string());
    }

    #[tokio::test]
    pub(super) async fn custom_pricing_lists_unit_costs_and_limits() {
        let (db, exec) = executor(1).await;
        seed_custom_pricing(&db).await;

        let out = exec.execute("list_custom_pricing", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let entry = &parsed[0];

        assert_eq!(entry["id"], 1);
        assert_eq!(entry["cost_per_cpu_core"]["amount"], 100);
        assert_eq!(entry["cost_per_gb_memory"]["amount"], 50);
        assert_eq!(entry["disk_options"][0]["cost_per_gb"]["amount"], 5);
        assert_eq!(entry["disk_options"][0]["disk_type"], "ssd");
        assert_eq!(entry["max_cpu"], 8);
        assert_eq!(entry["max_memory_bytes"], 16 * GB);
    }

    /// The quote must match the pricing engine's arithmetic exactly, because
    /// the customer can order at this price.
    #[tokio::test]
    pub(super) async fn price_custom_vm_quotes_the_full_spec() {
        let (db, exec) = executor(1).await;
        seed_custom_pricing(&db).await;

        let out = exec
            .execute(
                "price_custom_vm",
                r#"{"pricing_id":1,"cpu":3,"memory_gb":4,"disk_gb":40}"#,
            )
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();

        // 3*100 + 4*50 + 40*5 + 1*300 + 1*10 = 1010 cents
        assert_eq!(parsed["breakdown"]["cpu"]["amount"], 300);
        assert_eq!(parsed["breakdown"]["memory"]["amount"], 200);
        assert_eq!(parsed["breakdown"]["disk"]["amount"], 200);
        assert_eq!(parsed["total"]["amount"], 1010);
        assert_eq!(parsed["total"]["currency"], "EUR");
        // Unspecified disk/IP selection falls back to what the region sells.
        assert_eq!(parsed["spec"]["disk_type"], "ssd");
        assert_eq!(parsed["spec"]["ip4_count"], 1);
        assert!(parsed["note"].as_str().unwrap().contains("tax"));
    }

    /// An out-of-range spec must fail with the range in the message, not be
    /// quoted at a price nobody can order at.
    #[tokio::test]
    pub(super) async fn price_custom_vm_rejects_an_unorderable_spec() {
        let (db, exec) = executor(1).await;
        seed_custom_pricing(&db).await;

        let err = exec
            .execute(
                "price_custom_vm",
                r#"{"pricing_id":1,"cpu":64,"memory_gb":4,"disk_gb":40}"#,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");

        // A disk type the region does not sell has no price at all.
        let err = exec
            .execute(
                "price_custom_vm",
                r#"{"pricing_id":1,"cpu":2,"memory_gb":4,"disk_gb":40,"disk_type":"hdd"}"#,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("No disk price found"), "{err}");
    }

    #[tokio::test]
    pub(super) async fn price_custom_vm_requires_a_spec() {
        let (db, exec) = executor(1).await;
        seed_custom_pricing(&db).await;
        let err = exec
            .execute("price_custom_vm", r#"{"pricing_id":1,"cpu":2}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("memory_gb required"), "{err}");
    }

    /// Conversion is optional wiring; without it the tool must refuse rather
    /// than let the model do the arithmetic.
    #[tokio::test]
    pub(super) async fn exchange_rate_requires_configured_rates() {
        let (_db, exec) = executor(1).await;
        let err = exec
            .execute("get_exchange_rate", r#"{"from":"EUR","to":"BTC"}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not available"), "{err}");
    }

    #[tokio::test]
    pub(super) async fn exchange_rate_converts_and_prices_alternatives() {
        let rates = Arc::new(MockExchangeRate::new());
        // 1 BTC = 100,000 EUR
        rates
            .set_rate(Ticker::btc_rate("EUR").unwrap(), 100_000.0)
            .await;

        let db = Arc::new(MockDb::default());
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, 1).with_exchange_rates(rates);

        let out = exec
            .execute(
                "get_exchange_rate",
                r#"{"from":"EUR","to":"BTC","amount":1000}"#,
            )
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["converted"]["currency"], "BTC");
        // 1000 EUR = 0.01 BTC = 1,000,000 sats = 1e9 millisats.
        assert_eq!(parsed["converted"]["amount"], 1_000_000_000u64);

        // The same rates give every listed plan a bitcoin price.
        let out = exec.execute("list_templates", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let others = &parsed[0]["price"]["per_interval"]["other_currencies"];
        assert!(
            others
                .as_array()
                .expect("other currencies")
                .iter()
                .any(|c| c["currency"] == "BTC"),
            "{others}"
        );
    }

    #[tokio::test]
    pub(super) async fn regions_name_the_billing_company() {
        let (_db, exec) = executor(1).await;
        let out = exec.execute("list_regions", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed[0]["company"]["name"].is_string(), "{parsed}");
        // Company contact/tax details are not a customer's business.
        assert!(!out.contains("tax_id"));
        assert!(!out.contains("phone"));
    }

    /// The catalogue is what a logged-out visitor is there for, pricing
    /// included.
    #[tokio::test]
    pub(super) async fn anonymous_executor_can_quote_custom_pricing() {
        let db = Arc::new(MockDb::default());
        seed_custom_pricing(&db).await;
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::public(dyn_db);

        let out = exec
            .execute(
                "price_custom_vm",
                r#"{"pricing_id":1,"cpu":1,"memory_gb":1,"disk_gb":10}"#,
            )
            .await
            .expect("pre-sales quotes need no account");
        assert!(out.contains("\"total\""));
    }

    #[test]
    fn gb_arguments_must_be_positive() {
        let args = parse_args(r#"{"disk_gb":0,"memory_gb":2}"#);
        assert!(required_gb_as_bytes(&args, "disk_gb").is_err());
        assert_eq!(
            required_gb_as_bytes(&args, "memory_gb").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert!(required_gb_as_bytes(&args, "missing").is_err());
    }

    #[test]
    fn unknown_currency_is_named_in_the_error() {
        assert!(currency("XYZ").unwrap_err().to_string().contains("XYZ"));
        assert!(currency("eur").is_ok());
    }

    /// The in-process executor must be able to quote policy too, not just the
    /// HTTP-backed one used by the email/Nostr channels.
    #[tokio::test]
    pub(super) async fn serves_the_terms_of_service() {
        let site = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/tos"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(format!(
                    "<body><h1>Terms</h1><p>{}</p></body>",
                    "No port scanning. ".repeat(50)
                )),
            )
            .mount(&site)
            .await;

        let (_db, exec) = executor(1).await;
        let exec = exec.with_diagnostics(Diagnostics::new(
            LookingGlass::default(),
            PolicyDocs::new(site.uri()),
        ));
        let out = exec.execute("get_terms_of_service", "{}").await.unwrap();
        assert!(out.contains("No port scanning."));
    }
}
