use crate::exchange::{Currency, CurrencyAmount, ExchangeRateService, Ticker, TickerRate};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Days, Months, TimeDelta, Utc};
use ipnetwork::IpNetwork;
use isocountry::CountryCode;
use lnvps_db::{
    LNVpsDb, PaymentMethod, Vm, VmCostPlan, VmCostPlanIntervalType, VmCustomTemplate, VmPayment,
};
use log::info;
use std::collections::HashMap;
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;

/// Pricing engine is used to calculate billing amounts for
/// different resource allocations
#[derive(Clone)]
pub struct PricingEngine {
    db: Arc<dyn LNVpsDb>,
    rates: Arc<dyn ExchangeRateService>,
    tax_rates: HashMap<CountryCode, f32>,
}

impl PricingEngine {
    pub fn new(
        db: Arc<dyn LNVpsDb>,
        rates: Arc<dyn ExchangeRateService>,
        tax_rates: HashMap<CountryCode, f32>,
    ) -> Self {
        Self {
            db,
            rates,
            tax_rates,
        }
    }

    /// Get VM cost (for renewal)
    pub async fn get_vm_cost(&self, vm_id: u64, method: PaymentMethod) -> Result<CostResult> {
        let vm = self.db.get_vm(vm_id).await?;

        // Reuse existing payment until expired
        let payments = self.db.list_vm_payment(vm.id).await?;
        if let Some(px) = payments
            .into_iter()
            .find(|p| p.expires > Utc::now() && !p.is_paid && p.payment_method == method)
        {
            return Ok(CostResult::Existing(px));
        }

        if vm.template_id.is_some() {
            Ok(self.get_template_vm_cost(&vm, method).await?)
        } else {
            Ok(self.get_custom_vm_cost(&vm, method).await?)
        }
    }

    /// Get the cost amount as (Currency,amount)
    pub async fn get_custom_vm_cost_amount(
        db: &Arc<dyn LNVpsDb>,
        vm_id: u64,
        template: &VmCustomTemplate,
    ) -> Result<PricingData> {
        let pricing = db.get_custom_pricing(template.pricing_id).await?;
        let pricing_disk = db.list_custom_pricing_disk(pricing.id).await?;
        let ips = db.list_vm_ip_assignments(vm_id).await?;
        let v4s = ips
            .iter()
            .filter(|i| {
                IpNetwork::from_str(&i.ip)
                    .map(|i| i.is_ipv4())
                    .unwrap_or(false)
            })
            .count()
            .max(1); // must have at least 1
        let v6s = ips
            .iter()
            .filter(|i| {
                IpNetwork::from_str(&i.ip)
                    .map(|i| i.is_ipv6())
                    .unwrap_or(false)
            })
            .count()
            .max(1); // must have at least 1
        let disk_pricing =
            if let Some(p) = pricing_disk.iter().find(|p| p.kind == template.disk_type) {
                p
            } else {
                bail!("No disk price found")
            };
        let disk_cost = (template.disk_size / crate::GB) as f32 * disk_pricing.cost;
        let cpu_cost = pricing.cpu_cost * template.cpu as f32;
        let memory_cost = pricing.memory_cost * (template.memory / crate::GB) as f32;
        let ip4_cost = pricing.ip4_cost * v4s as f32;
        let ip6_cost = pricing.ip6_cost * v6s as f32;

        let currency: Currency = if let Ok(p) = pricing.currency.parse() {
            p
        } else {
            bail!("Invalid currency")
        };
        Ok(PricingData {
            currency,
            cpu_cost,
            memory_cost,
            ip6_cost,
            ip4_cost,
            disk_cost,
        })
    }

    async fn get_custom_vm_cost(&self, vm: &Vm, method: PaymentMethod) -> Result<CostResult> {
        let template_id = if let Some(i) = vm.custom_template_id {
            i
        } else {
            bail!("Not a custom template vm")
        };

        let template = self.db.get_custom_vm_template(template_id).await?;
        let price = Self::get_custom_vm_cost_amount(&self.db, vm.id, &template).await?;
        info!("Custom pricing for {} = {:?}", vm.id, price);

        // custom templates are always 1-month intervals
        let time_value = (vm.expires.add(Months::new(1)) - vm.expires).num_seconds() as u64;
        let (currency, amount, rate) = self
            .get_amount_and_rate(
                CurrencyAmount::from_f32(price.currency, price.total()),
                method,
            )
            .await?;
        Ok(CostResult::New {
            amount,
            tax: self.get_tax_for_user(vm.user_id, amount).await?,
            currency,
            rate,
            time_value,
            new_expiry: vm.expires.add(TimeDelta::seconds(time_value as i64)),
        })
    }

    async fn get_tax_for_user(&self, user_id: u64, amount: u64) -> Result<u64> {
        let user = self.db.get_user(user_id).await?;
        if let Some(cc) = user
            .country_code
            .and_then(|c| CountryCode::for_alpha3(&c).ok())
        {
            if let Some(c) = self.tax_rates.get(&cc) {
                return Ok((amount as f64 * (*c as f64 / 100f64)).floor() as u64);
            }
        }
        Ok(0)
    }

    async fn get_ticker(&self, currency: Currency) -> Result<TickerRate> {
        let ticker = Ticker(Currency::BTC, currency);
        if let Some(r) = self.rates.get_rate(ticker).await {
            Ok(TickerRate(ticker, r))
        } else {
            bail!("No exchange rate found")
        }
    }

    async fn get_msats_amount(&self, amount: CurrencyAmount) -> Result<(u64, f32)> {
        let rate = self.get_ticker(amount.0).await?;
        let cost_btc = amount.value_f32() / rate.1;
        let cost_msats = (cost_btc as f64 * crate::BTC_SATS) as u64 * 1000;
        Ok((cost_msats, rate.1))
    }

    fn next_template_expire(vm: &Vm, cost_plan: &VmCostPlan) -> u64 {
        let next_expire = match cost_plan.interval_type {
            VmCostPlanIntervalType::Day => vm.expires.add(Days::new(cost_plan.interval_amount)),
            VmCostPlanIntervalType::Month => vm
                .expires
                .add(Months::new(cost_plan.interval_amount as u32)),
            VmCostPlanIntervalType::Year => vm
                .expires
                .add(Months::new((12 * cost_plan.interval_amount) as u32)),
        };

        (next_expire - vm.expires).num_seconds() as u64
    }

    async fn get_template_vm_cost(&self, vm: &Vm, method: PaymentMethod) -> Result<CostResult> {
        let template_id = if let Some(i) = vm.template_id {
            i
        } else {
            bail!("Not a standard template vm");
        };
        let template = self.db.get_vm_template(template_id).await?;
        let cost_plan = self.db.get_cost_plan(template.cost_plan_id).await?;

        let currency = cost_plan.currency.parse().expect("Invalid currency");
        let (currency, amount, rate) = self
            .get_amount_and_rate(CurrencyAmount::from_f32(currency, cost_plan.amount), method)
            .await?;
        let time_value = Self::next_template_expire(vm, &cost_plan);
        Ok(CostResult::New {
            amount,
            tax: self.get_tax_for_user(vm.user_id, amount).await?,
            currency,
            rate,
            time_value,
            new_expiry: vm.expires.add(TimeDelta::seconds(time_value as i64)),
        })
    }

    async fn get_amount_and_rate(
        &self,
        list_price: CurrencyAmount,
        method: PaymentMethod,
    ) -> Result<(Currency, u64, f32)> {
        Ok(match (list_price.0, method) {
            (c, PaymentMethod::Lightning) if c != Currency::BTC => {
                let new_price = self.get_msats_amount(list_price).await?;
                (Currency::BTC, new_price.0, new_price.1)
            }
            (cur, PaymentMethod::Revolut) if cur != Currency::BTC => {
                (cur, list_price.value(), 0.01)
            }
            (c, m) => bail!("Cannot create payment for method {} and currency {}", m, c),
        })
    }
}

#[derive(Clone)]
pub enum CostResult {
    /// An existing payment already exists and should be used
    Existing(VmPayment),
    /// A new payment can be created with the specified amount
    New {
        /// The cost
        amount: u64,
        /// Currency
        currency: Currency,
        /// The exchange rate used to calculate the price
        rate: f32,
        /// The time to extend the vm expiry in seconds
        time_value: u64,
        /// The absolute expiry time of the vm if renewed
        new_expiry: DateTime<Utc>,
        /// Taxes to charge
        tax: u64,
    },
}

#[derive(Clone, Debug)]
pub struct PricingData {
    pub currency: Currency,
    pub cpu_cost: f32,
    pub memory_cost: f32,
    pub ip4_cost: f32,
    pub ip6_cost: f32,
    pub disk_cost: f32,
}

impl PricingData {
    pub fn total(&self) -> f32 {
        self.cpu_cost + self.memory_cost + self.ip4_cost + self.ip6_cost + self.disk_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::{MockDb, MockExchangeRate};
    use lnvps_db::{DiskType, User, VmCustomPricing, VmCustomPricingDisk, VmCustomTemplate};
    const MOCK_RATE: f32 = 100_000.0;

    async fn add_custom_pricing(db: &MockDb) {
        let mut p = db.custom_pricing.lock().await;
        p.insert(
            1,
            VmCustomPricing {
                id: 1,
                name: "mock-custom".to_string(),
                enabled: true,
                created: Utc::now(),
                expires: None,
                region_id: 1,
                currency: "EUR".to_string(),
                cpu_cost: 1.5,
                memory_cost: 0.5,
                ip4_cost: 0.5,
                ip6_cost: 0.05,
            },
        );
        let mut p = db.custom_template.lock().await;
        p.insert(
            1,
            VmCustomTemplate {
                id: 1,
                cpu: 2,
                memory: 2 * crate::GB,
                disk_size: 80 * crate::GB,
                disk_type: DiskType::SSD,
                disk_interface: Default::default(),
                pricing_id: 1,
            },
        );
        let mut d = db.custom_pricing_disk.lock().await;
        d.insert(
            1,
            VmCustomPricingDisk {
                id: 1,
                pricing_id: 1,
                kind: DiskType::SSD,
                interface: Default::default(),
                cost: 0.05,
            },
        );
    }
    #[tokio::test]
    async fn custom_pricing() -> Result<()> {
        let db = MockDb::default();
        add_custom_pricing(&db).await;
        let db: Arc<dyn LNVpsDb> = Arc::new(db);

        let template = db.get_custom_vm_template(1).await?;
        let price = PricingEngine::get_custom_vm_cost_amount(&db, 1, &template).await?;
        assert_eq!(3.0, price.cpu_cost);
        assert_eq!(1.0, price.memory_cost);
        assert_eq!(0.5, price.ip4_cost);
        assert_eq!(0.05, price.ip6_cost);
        assert_eq!(4.0, price.disk_cost);
        assert_eq!(8.55, price.total());

        Ok(())
    }

    #[tokio::test]
    async fn standard_pricing() -> Result<()> {
        let db = MockDb::default();
        let rates = Arc::new(MockExchangeRate::new());
        rates.set_rate(Ticker::btc_rate("EUR")?, MOCK_RATE).await;

        // add basic vm
        {
            let mut v = db.vms.lock().await;
            v.insert(1, MockDb::mock_vm());
            v.insert(
                2,
                Vm {
                    user_id: 2,
                    ..MockDb::mock_vm()
                },
            );

            let mut u = db.users.lock().await;
            u.insert(
                1,
                User {
                    id: 1,
                    pubkey: vec![],
                    created: Default::default(),
                    email: None,
                    contact_nip17: false,
                    contact_email: false,
                    country_code: Some("USA".to_string()),
                },
            );
            u.insert(
                2,
                User {
                    id: 2,
                    pubkey: vec![],
                    created: Default::default(),
                    email: None,
                    contact_nip17: false,
                    contact_email: false,
                    country_code: Some("IRL".to_string()),
                },
            );
        }

        let db: Arc<dyn LNVpsDb> = Arc::new(db);

        let taxes = HashMap::from([(CountryCode::IRL, 23.0)]);

        let pe = PricingEngine::new(db.clone(), rates, taxes);
        let plan = MockDb::mock_cost_plan();

        let price = pe.get_vm_cost(1, PaymentMethod::Lightning).await?;
        match price {
            CostResult::New { amount, tax, .. } => {
                let expect_price = (plan.amount / MOCK_RATE * 1.0e11) as u64;
                assert_eq!(expect_price, amount);
                assert_eq!(0, tax);
            }
            _ => bail!("??"),
        }

        // with taxes
        let price = pe.get_vm_cost(2, PaymentMethod::Lightning).await?;
        match price {
            CostResult::New { amount, tax, .. } => {
                let expect_price = (plan.amount / MOCK_RATE * 1.0e11) as u64;
                assert_eq!(expect_price, amount);
                assert_eq!((expect_price as f64 * 0.23).floor() as u64, tax);
            }
            _ => bail!("??"),
        }

        Ok(())
    }
}
