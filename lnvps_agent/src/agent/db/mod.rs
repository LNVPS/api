//! Tool execution backed directly by the database.
//!
//! "Db" names the **backend**: every tool call is answered by reading the
//! database. It is the only backend — hosted inside `lnvps_api` and in the
//! standalone binary that serves the email and Nostr channels alike. The agent
//! holds no admin credential and makes no call to the admin API, so a prompt
//! injection has nothing to reach for: it is bounded by what these projections
//! read and by the ownership checks below, not by an API token's permissions.
//!
//! Every projection here is **hand-built**. Serialising the database structs
//! wholesale would leak secrets into the model's context (and from there into a
//! reply): `User` carries verification tokens, `VmHost` carries an API token and
//! SSH key, `SubscriptionPayment` carries encrypted external payment data,
//! `AppDeployment` carries the app's own configured secrets, and
//! `UserPaymentMethod` carries processor references. Only fields a customer may
//! see are copied out.
//!
//! The tools are grouped one module per subject area, and each module owns its
//! projections *and* the tests that pin what they may disclose:
//!
//! | Module | Tools |
//! |---|---|
//! | [`account`] | account record, SSH keys, saved payment methods |
//! | [`vms`] | VM listing/details/payments/history, power, firewall, metrics |
//! | [`catalogue`] | regions, plans, custom pricing, quotes, exchange rates, OS images |
//! | [`billing`] | subscriptions, their payments, IP-space subscriptions |
//! | [`apps`] | managed app catalogue and the customer's deployments |
//! | [`partners`] | referral programme, marketplace operator enrolment |
//!
//! Dispatch stays here, in one `match`, because the authorisation story is only
//! readable in one place: a tool that reaches a user record calls
//! [`DbToolExecutor::require_user`] (directly or through an ownership check),
//! and one that does not is catalogue data anyone may read.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};

use lnvps_api_common::host::config::ProvisionerConfig;
use lnvps_api_common::{ExchangeRateService, VmHistoryLogger, WorkCommander, alt_prices};
use lnvps_db::{AppDeploymentDesiredState, LNVpsDb};
use payments_rs::currency::{Currency, CurrencyAmount};

use crate::agent::ToolExecutor;
use crate::diag::Diagnostics;

use vms::PowerAction;

pub mod account;
pub mod apps;
pub mod billing;
pub mod catalogue;
pub mod partners;
pub mod vms;

// ── Shared argument handling ────────────────────────────────────────

/// Parse a tool's JSON arguments into a map (empty on parse failure).
pub(super) fn parse_args(arguments: &str) -> HashMap<String, Value> {
    serde_json::from_str(arguments).unwrap_or_default()
}

/// Extract a required `u64` argument by key.
pub(super) fn required_u64(args: &HashMap<String, Value>, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("{} required", key))
}

/// Extract a required size argument given in gigabytes, as bytes.
///
/// Accepts a float so the model can quote `1.5` GB; sizes below one byte are
/// rejected rather than silently priced as zero.
pub(super) fn required_gb_as_bytes(args: &HashMap<String, Value>, key: &str) -> Result<u64> {
    let gb = args
        .get(key)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| anyhow!("{} required", key))?;
    let bytes = (gb * lnvps_api_common::GB as f64).round();
    if !(1.0..=u64::MAX as f64).contains(&bytes) {
        bail!("{} must be a positive size in GB", key);
    }
    Ok(bytes as u64)
}

/// Serialize a value as a pretty string for the LLM to read.
pub(super) fn pretty(value: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Read the optional `ipv6` family selector, defaulting to IPv4.
pub(super) fn wants_ipv6(args: &HashMap<String, Value>) -> bool {
    args.get("ipv6").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Parse a currency code, naming the supported set on failure.
pub(super) fn currency(code: &str) -> Result<Currency> {
    code.parse::<Currency>()
        .map_err(|_| anyhow!("Unknown currency '{}' (try BTC, EUR, USD)", code))
}

/// Render an enum that has no `Display`, as a lower-case tag.
pub(super) fn tag<T: std::fmt::Debug>(value: T) -> String {
    format!("{:?}", value).to_lowercase()
}

/// Money as the model should see it: minor units (what the database stores),
/// the major-unit value, and the currency.
///
/// Both are given because every amount in this codebase is in minor units
/// (cents / millisats) and a model shown only `599` will report "599 EUR".
pub(super) fn money(amount: CurrencyAmount) -> Value {
    json!({
        "amount": amount.value(),
        "value": amount.value_f32(),
        "currency": amount.currency().to_string(),
        "formatted": amount.to_string(),
    })
}

// ── The executor ────────────────────────────────────────────────────

/// Executes tools against the database, scoped to a single user.
///
/// Power actions are optional: without a [`ProvisionerConfig`] and a work
/// commander the executor is read-only, which is the right default for any
/// caller that cannot reach the hypervisors.
///
/// The scoped user is optional too: [`DbToolExecutor::public`] builds an
/// executor for a logged-out visitor, which can answer catalogue questions
/// (regions, plans, pricing, apps, terms) and nothing else. Every user-scoped
/// tool checks for the account *here* rather than relying on the smaller tool
/// list advertised to the model, because a model can invent a call to a tool it
/// was never offered.
pub struct DbToolExecutor {
    db: Arc<dyn LNVpsDb>,
    /// `None` for an anonymous (guest) session — see [`DbToolExecutor::public`].
    user_id: Option<u64>,
    history: VmHistoryLogger,
    /// Hypervisor configuration; `None` disables the power and metrics tools.
    provisioner: Option<ProvisionerConfig>,
    /// Queue used to reconcile VM state after a power action.
    work_sender: Option<Arc<dyn WorkCommander>>,
    /// Exchange rates; `None` drops the alternative-currency prices and
    /// disables `get_exchange_rate`.
    rates: Option<Arc<dyn ExchangeRateService>>,
    /// Looking-glass and policy clients backing the diagnostic tools.
    diag: Diagnostics,
}

impl DbToolExecutor {
    /// Create a read-only executor scoped to `user_id`.
    pub fn new(db: Arc<dyn LNVpsDb>, user_id: u64) -> Self {
        Self {
            history: VmHistoryLogger::new(db.clone()),
            db,
            user_id: Some(user_id),
            provisioner: None,
            work_sender: None,
            rates: None,
            diag: Diagnostics::default(),
        }
    }

    /// Create an executor for a caller with no account.
    ///
    /// Serves only the public catalogue tools; every account-scoped tool fails
    /// with a message the model can relay. Note [`Self::with_power_actions`]
    /// cannot make this dangerous — the power tools resolve their VM through
    /// the ownership check, which no anonymous caller can pass — but callers
    /// should still not enable them.
    pub fn public(db: Arc<dyn LNVpsDb>) -> Self {
        Self {
            history: VmHistoryLogger::new(db.clone()),
            db,
            user_id: None,
            provisioner: None,
            work_sender: None,
            rates: None,
            diag: Diagnostics::default(),
        }
    }

    /// The scoped user, or an error naming what the caller must do instead.
    ///
    /// The message is written for the model to relay to a logged-out visitor.
    fn require_user(&self) -> Result<u64> {
        self.user_id.ok_or_else(|| {
            anyhow!(
                "That needs an account. Ask the visitor to log in at lnvps.net \
                 to see their VMs, billing or account details."
            )
        })
    }

    /// Enable the `start_vm` / `stop_vm` / `restart_vm` and `get_vm_metrics`
    /// tools, which need to reach the hypervisor.
    pub fn with_power_actions(
        mut self,
        provisioner: ProvisionerConfig,
        work_sender: Arc<dyn WorkCommander>,
    ) -> Self {
        self.provisioner = Some(provisioner);
        self.work_sender = Some(work_sender);
        self
    }

    /// Point the diagnostics at different endpoints than the production
    /// looking glass and website (tests, staging deployments).
    pub fn with_diagnostics(mut self, diag: Diagnostics) -> Self {
        self.diag = diag;
        self
    }

    /// Enable currency conversion: alternative prices on every quote, and the
    /// `get_exchange_rate` tool.
    pub fn with_exchange_rates(mut self, rates: Arc<dyn ExchangeRateService>) -> Self {
        self.rates = Some(rates);
        self
    }

    /// A price, plus the same price in every other currency we hold a rate for.
    ///
    /// Conversion is best-effort: a rate service outage must not stop the agent
    /// quoting the real, stored price.
    async fn priced(&self, amount: CurrencyAmount) -> Value {
        let mut out = money(amount);
        let Some(rates) = self.rates.as_ref() else {
            return out;
        };
        let Ok(all) = rates.list_rates().await else {
            return out;
        };
        let others: Vec<Value> = alt_prices(&all, amount).into_iter().map(money).collect();
        if let (Some(object), false) = (out.as_object_mut(), others.is_empty()) {
            object.insert("other_currencies".to_string(), Value::Array(others));
        }
        out
    }
}

#[async_trait]
impl ToolExecutor for DbToolExecutor {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String> {
        let args = parse_args(arguments);

        match name {
            // ── Account ──────────────────────────────────────────────
            "get_my_account" => pretty(&self.account().await?),
            "list_my_ssh_keys" => pretty(&self.ssh_keys().await?),
            "list_my_payment_methods" => pretty(&self.payment_methods().await?),

            // ── VMs ──────────────────────────────────────────────────
            "list_my_vms" => pretty(&self.list_vms().await?),
            "get_vm_details" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.vm_details(&vm).await)
            }
            "list_vm_payments" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.vm_payments(&vm).await?)
            }
            "list_vm_history" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.vm_history(&vm).await?)
            }
            "list_vm_firewall_rules" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.firewall(&vm).await?)
            }
            "get_vm_metrics" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.vm_metrics(&vm).await?)
            }
            "start_vm" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.power(&vm, PowerAction::Start).await?)
            }
            "stop_vm" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.power(&vm, PowerAction::Stop).await?)
            }
            "restart_vm" => {
                let vm = self.owned_vm(&args).await?;
                pretty(&self.power(&vm, PowerAction::Restart).await?)
            }

            // ── Billing ──────────────────────────────────────────────
            "list_my_subscriptions" => pretty(&self.subscriptions().await?),
            "get_subscription_details" => {
                let subscription = self.owned_subscription(&args).await?;
                pretty(&self.subscription_view(&subscription).await)
            }
            "list_subscription_payments" => {
                let subscription = self.owned_subscription(&args).await?;
                pretty(&self.subscription_payments(&subscription).await?)
            }
            "list_my_ip_subscriptions" => pretty(&self.ip_subscriptions().await?),

            // ── Managed apps ─────────────────────────────────────────
            "list_apps" => pretty(&self.apps().await?),
            "get_app_details" => pretty(&self.app_details(&args).await?),
            "list_app_tags" => pretty(&self.app_tags().await?),
            "list_my_app_deployments" => pretty(&self.deployments().await?),
            "get_app_deployment_details" => {
                let deployment = self.owned_deployment(&args).await?;
                pretty(&self.deployment_view(&deployment).await)
            }
            "start_app_deployment" => {
                let deployment = self.owned_deployment(&args).await?;
                pretty(
                    &self
                        .set_deployment_state(&deployment, AppDeploymentDesiredState::Running)
                        .await?,
                )
            }
            "stop_app_deployment" => {
                let deployment = self.owned_deployment(&args).await?;
                pretty(
                    &self
                        .set_deployment_state(&deployment, AppDeploymentDesiredState::Stopped)
                        .await?,
                )
            }

            // ── Partner programmes ───────────────────────────────────
            "get_my_referral" => pretty(&self.referral().await?),
            "list_referral_usage" => pretty(&self.referral_usage().await?),
            "get_my_marketplace_operator" => pretty(&self.marketplace_operator().await?),

            // ── Catalogue (no account required) ───────────────────────
            "list_regions" => pretty(&self.regions().await?),
            "list_templates" => pretty(&self.templates().await?),
            "list_custom_pricing" => pretty(&self.custom_pricing().await?),
            "price_custom_vm" => pretty(&self.price_custom_vm(&args).await?),
            "get_exchange_rate" => pretty(&self.exchange_rate(&args).await?),
            "list_os_images" => pretty(&self.os_images().await?),
            "get_terms_of_service" => Ok(self.diag.terms_of_service().await?.to_string()),

            // ── Diagnostics ──────────────────────────────────────────
            "ping_vm" => {
                let vm = self.owned_vm(&args).await?;
                let ips = self.vm_ips(&vm).await;
                pretty(&serde_json::to_value(
                    self.diag.ping(&ips, wants_ipv6(&args)).await?,
                )?)
            }
            "traceroute_vm" => {
                let vm = self.owned_vm(&args).await?;
                let ips = self.vm_ips(&vm).await;
                pretty(&serde_json::to_value(
                    self.diag.traceroute(&ips, wants_ipv6(&args)).await?,
                )?)
            }
            "check_vm_port" => {
                let port = required_u64(&args, "port")?;
                let vm = self.owned_vm(&args).await?;
                let ips = self.vm_ips(&vm).await;
                pretty(&serde_json::to_value(
                    self.diag.check_port(&ips, wants_ipv6(&args), port).await?,
                )?)
            }

            // Not offered in any tool set: granting paid time, moving money
            // and destroying data are subscription-lifecycle operations that
            // live in the API. Reaching this arm means the model invented the
            // call, so name the escalation path rather than failing opaquely.
            "extend_vm" | "refund_vm" | "delete_vm" => {
                bail!(
                    "{} is not something the agent can do — a human on support@lnvps.net has to",
                    name
                )
            }
            _ => bail!("Unknown tool: {}", name),
        }
    }
}

/// Fixtures shared by the per-group test modules.
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use lnvps_api_common::{GB, MockDb};
    use lnvps_db::{DiskInterface, DiskType, Vm, VmCustomPricing, VmCustomPricingDisk};

    /// Executor scoped to the mock DB's seeded user.
    pub(crate) async fn executor(user_id: u64) -> (Arc<MockDb>, DbToolExecutor) {
        let db = Arc::new(MockDb::default());
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        (db.clone(), DbToolExecutor::new(dyn_db, user_id))
    }

    /// Executor for a logged-out visitor, sharing `db` with the caller.
    pub(crate) fn public_executor(db: &Arc<MockDb>) -> DbToolExecutor {
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        DbToolExecutor::public(dyn_db)
    }

    /// Seed a VM owned by `user_id`.
    pub(crate) async fn seed_vm(db: &Arc<MockDb>, vm_id: u64, user_id: u64) {
        let mut vms = db.vms.lock().await;
        vms.insert(
            vm_id,
            Vm {
                id: vm_id,
                user_id,
                ..MockDb::mock_vm()
            },
        );
    }

    /// Seed a custom pricing row (with one SSD/PCIe disk option) on the mock.
    ///
    /// Costs are deliberately round numbers so a quote can be checked by hand:
    /// 3 cores + 4 GB + 40 GB disk + 1 IPv4 + 1 IPv6.
    pub(crate) async fn seed_custom_pricing(db: &Arc<MockDb>) {
        db.custom_pricing.lock().await.insert(
            1,
            VmCustomPricing {
                id: 1,
                name: "custom-mock".to_string(),
                enabled: true,
                region_id: 1,
                currency: "EUR".to_string(),
                cpu_cost: 100,
                memory_cost: 50,
                ip4_cost: 300,
                ip6_cost: 10,
                min_cpu: 1,
                max_cpu: 8,
                min_memory: GB,
                max_memory: 16 * GB,
                min_ip4: 1,
                max_ip4: 2,
                min_ip6: 1,
                max_ip6: 2,
                ..Default::default()
            },
        );
        db.custom_pricing_disk.lock().await.insert(
            1,
            VmCustomPricingDisk {
                id: 1,
                pricing_id: 1,
                kind: DiskType::SSD,
                interface: DiskInterface::PCIe,
                cost: 5,
                min_disk_size: 10 * GB,
                max_disk_size: 500 * GB,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use lnvps_api_common::MockDb;

    /// A guest (logged-out) session must not be able to reach *any* account
    /// data, whichever tool the model calls. The narrower tool list it is
    /// offered is not the control — a model can name a tool it was never given,
    /// and prompt injection makes that likely rather than hypothetical.
    #[tokio::test]
    async fn anonymous_executor_refuses_every_account_tool() {
        let db = Arc::new(MockDb::default());
        seed_vm(&db, 42, 1).await;
        let exec = public_executor(&db);

        for (tool, args) in [
            ("get_my_account", "{}"),
            ("list_my_ssh_keys", "{}"),
            ("list_my_payment_methods", "{}"),
            ("list_my_vms", "{}"),
            ("get_vm_details", r#"{"vm_id":42}"#),
            ("list_vm_payments", r#"{"vm_id":42}"#),
            ("list_vm_history", r#"{"vm_id":42}"#),
            ("list_vm_firewall_rules", r#"{"vm_id":42}"#),
            ("get_vm_metrics", r#"{"vm_id":42}"#),
            ("start_vm", r#"{"vm_id":42}"#),
            ("stop_vm", r#"{"vm_id":42}"#),
            ("restart_vm", r#"{"vm_id":42}"#),
            ("ping_vm", r#"{"vm_id":42}"#),
            ("traceroute_vm", r#"{"vm_id":42}"#),
            ("check_vm_port", r#"{"vm_id":42,"port":22}"#),
            ("list_my_subscriptions", "{}"),
            ("get_subscription_details", r#"{"subscription_id":1}"#),
            ("list_subscription_payments", r#"{"subscription_id":1}"#),
            ("list_my_ip_subscriptions", "{}"),
            ("list_my_app_deployments", "{}"),
            ("get_app_deployment_details", r#"{"deployment_id":1}"#),
            ("start_app_deployment", r#"{"deployment_id":1}"#),
            ("stop_app_deployment", r#"{"deployment_id":1}"#),
            ("get_my_referral", "{}"),
            ("list_referral_usage", "{}"),
            ("get_my_marketplace_operator", "{}"),
        ] {
            let err = exec
                .execute(tool, args)
                .await
                .expect_err(&format!("{tool} must be refused without an account"));
            assert!(
                err.to_string().contains("needs an account"),
                "{tool}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_tool_errors() {
        let (_db, exec) = executor(1).await;
        assert!(exec.execute("rm_rf", "{}").await.is_err());
    }

    #[test]
    fn arg_parsing_is_lenient_but_typed() {
        assert!(parse_args("not json").is_empty());
        let args = parse_args(r#"{"vm_id":5}"#);
        assert_eq!(required_u64(&args, "vm_id").unwrap(), 5);
        assert!(required_u64(&args, "days").is_err());
    }

    #[test]
    fn wants_ipv6_defaults_to_v4() {
        assert!(!wants_ipv6(&parse_args("{}")));
        assert!(wants_ipv6(&parse_args(r#"{"ipv6":true}"#)));
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
}
