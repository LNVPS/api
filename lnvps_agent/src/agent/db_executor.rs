//! Tool execution backed directly by the database.
//!
//! Used when the agent runs inside `lnvps_api`. Compared to
//! [`crate::agent::LnvpsToolExecutor`], which calls the admin API over HTTP with
//! an admin nsec, this reads the database directly — no loopback request and no
//! god-mode credential in the API process.
//!
//! Every projection here is **hand-built**. Serialising the database structs
//! wholesale would leak secrets into the model's context (and from there into a
//! reply): `User` carries verification tokens, `VmHost` carries an API token and
//! SSH key, and `SubscriptionPayment` carries encrypted external payment data.
//! Only fields a customer may see are copied out.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::{Value, json};

use lnvps_api_common::host::config::ProvisionerConfig;
use lnvps_api_common::host::get_host_client;
use lnvps_api_common::{VmHistoryLogger, WorkCommander, WorkJob};
use lnvps_db::{LNVpsDb, Vm};

use crate::agent::ToolExecutor;
use crate::diag::Diagnostics;

/// Parse a tool's JSON arguments into a map (empty on parse failure).
fn parse_args(arguments: &str) -> HashMap<String, Value> {
    serde_json::from_str(arguments).unwrap_or_default()
}

/// Extract a required `u64` argument by key.
fn required_u64(args: &HashMap<String, Value>, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("{} required", key))
}

/// Serialize a value as a pretty string for the LLM to read.
fn pretty(value: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Read the optional `ipv6` family selector, defaulting to IPv4.
fn wants_ipv6(args: &HashMap<String, Value>) -> bool {
    args.get("ipv6").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// What a VM power action does to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PowerAction {
    Start,
    Stop,
    Restart,
}

impl PowerAction {
    fn as_str(&self) -> &'static str {
        match self {
            PowerAction::Start => "started",
            PowerAction::Stop => "stopped",
            PowerAction::Restart => "restarted",
        }
    }
}

/// Executes tools against the database, scoped to a single user.
///
/// Power actions are optional: without a [`ProvisionerConfig`] and a work
/// commander the executor is read-only, which is the right default for any
/// caller that cannot reach the hypervisors.
pub struct DbToolExecutor {
    db: Arc<dyn LNVpsDb>,
    user_id: u64,
    history: VmHistoryLogger,
    /// Hypervisor configuration; `None` disables the power tools.
    provisioner: Option<ProvisionerConfig>,
    /// Queue used to reconcile VM state after a power action.
    work_sender: Option<Arc<dyn WorkCommander>>,
    /// Looking-glass and policy clients backing the diagnostic tools.
    diag: Diagnostics,
}

impl DbToolExecutor {
    /// Create a read-only executor scoped to `user_id`.
    pub fn new(db: Arc<dyn LNVpsDb>, user_id: u64) -> Self {
        Self {
            history: VmHistoryLogger::new(db.clone()),
            db,
            user_id,
            provisioner: None,
            work_sender: None,
            diag: Diagnostics::default(),
        }
    }

    /// Enable the `start_vm` / `stop_vm` / `restart_vm` tools.
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

    /// Load a VM, confirming the scoped user owns it.
    ///
    /// This is the authorisation boundary for every VM-scoped tool. It is
    /// enforced here rather than by the prompt, because the model's `vm_id`
    /// argument is attacker-influencable: a customer can ask about any id.
    async fn owned_vm(&self, args: &HashMap<String, Value>) -> Result<Vm> {
        let vm_id = required_u64(args, "vm_id")?;
        let vm = self.db.get_vm(vm_id).await?;
        if vm.user_id != self.user_id {
            // Deliberately does not reveal the real owner.
            bail!("VM {} does not belong to you", vm_id);
        }
        Ok(vm)
    }

    /// The customer's own account, with verification tokens stripped.
    async fn account(&self) -> Result<Value> {
        let user = self.db.get_user(self.user_id).await?;
        Ok(json!({
            "id": user.id,
            "pubkey": hex::encode(&user.pubkey),
            "account_type": user.account_type.to_string(),
            "created": user.created,
            "email": user.email.as_str(),
            "email_verified": user.email_verified,
            "country_code": user.country_code,
            "billing_name": user.billing_name,
            "billing_city": user.billing_city,
            "billing_state": user.billing_state,
            "billing_postcode": user.billing_postcode,
            "billing_tax_id": user.billing_tax_id,
            "contact_email": user.contact_email,
            "contact_nip17": user.contact_nip17,
            "contact_telegram": user.contact_telegram,
            "contact_whatsapp": user.contact_whatsapp,
            "telegram_linked": user.telegram_chat_id.is_some(),
            "whatsapp_number": user.whatsapp_number,
            "whatsapp_verified": user.whatsapp_verified,
        }))
    }

    /// Summary view of a VM, as shown in a list.
    async fn vm_summary(&self, vm: &Vm) -> Value {
        let image = self.db.get_os_image(vm.image_id).await.ok();
        let template = match vm.template_id {
            Some(id) => self.db.get_vm_template(id).await.ok(),
            None => None,
        };
        let region = match template.as_ref() {
            Some(t) => self.db.get_host_region(t.region_id).await.ok(),
            None => None,
        };
        let ips: Vec<String> = self
            .db
            .list_vm_ip_assignments(vm.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| !a.deleted)
            .map(|a| a.ip)
            .collect();

        // Billing lives on the subscription the VM's line item belongs to.
        let subscription = self
            .db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await
            .ok();

        json!({
            "id": vm.id,
            "deleted": vm.deleted,
            "disabled": vm.disabled,
            "mac_address": vm.mac_address,
            "ip_addresses": ips,
            "os_image": image.map(|i| format!("{} {} {}", i.distribution, i.flavour, i.version)),
            "template": template.as_ref().map(|t| json!({
                "id": t.id,
                "name": t.name,
                "cpu": t.cpu,
                "memory_bytes": t.memory,
                "disk_bytes": t.disk_size,
            })),
            "region": region.map(|r| json!({ "id": r.id, "name": r.name })),
            "expires": subscription.as_ref().and_then(|s| s.expires),
            "auto_renewal_enabled": subscription.as_ref().map(|s| s.auto_renewal_enabled),
            "is_active": subscription.as_ref().map(|s| s.is_active),
        })
    }

    /// Detailed view of a single VM. Host identity is included by name only —
    /// never its address, API token or SSH key.
    async fn vm_details(&self, vm: &Vm) -> Value {
        let mut detail = self.vm_summary(vm).await;
        let host = self.db.get_host(vm.host_id).await.ok();
        if let Some(object) = detail.as_object_mut() {
            object.insert(
                "host".to_string(),
                json!(host.map(|h| json!({ "name": h.name, "kind": h.kind.to_string() }))),
            );
            object.insert("ssh_host_keys".to_string(), json!(vm.ssh_host_keys));
            object.insert(
                "custom_template_id".to_string(),
                json!(vm.custom_template_id),
            );
        }
        detail
    }

    async fn list_vms(&self) -> Result<Value> {
        let vms = self.db.list_user_vms(self.user_id).await?;
        let mut out = Vec::with_capacity(vms.len());
        for vm in vms.iter().filter(|v| !v.deleted) {
            out.push(self.vm_summary(vm).await);
        }
        Ok(Value::Array(out))
    }

    /// Payment history for a VM. Excludes `external_data` (encrypted payment
    /// instrument) and `external_id` (processor reference).
    async fn vm_payments(&self, vm: &Vm) -> Result<Value> {
        let subscription = self
            .db
            .get_subscription_by_line_item_id(vm.subscription_line_item_id)
            .await?;
        let payments = self
            .db
            .list_vm_subscription_payments_paginated(vm.id, 50, 0)
            .await?;

        Ok(Value::Array(
            payments
                .into_iter()
                .map(|p| {
                    json!({
                        "id": hex::encode(&p.id),
                        "created": p.created,
                        "expires": p.expires,
                        // Minor units (cents / milli-sats), as everywhere else.
                        "amount": p.amount,
                        "tax": p.tax,
                        "currency": p.currency,
                        "payment_method": format!("{:?}", p.payment_method),
                        "is_paid": p.is_paid,
                        "paid_at": p.paid_at,
                    })
                })
                .collect::<Vec<_>>(),
        ))
        .map(|payments| {
            json!({
                "subscription_expires": subscription.expires,
                "payments": payments,
            })
        })
    }

    async fn vm_history(&self, vm: &Vm) -> Result<Value> {
        let history = self.db.list_vm_history(vm.id).await?;
        Ok(Value::Array(
            history
                .into_iter()
                .map(|h| {
                    json!({
                        "timestamp": h.timestamp,
                        "action": h.action_type.to_string(),
                        "description": h.description,
                    })
                })
                .collect(),
        ))
    }

    async fn regions(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_host_region()
                .await?
                .into_iter()
                .filter(|r| r.enabled)
                .map(|r| json!({ "id": r.id, "name": r.name }))
                .collect(),
        ))
    }

    async fn templates(&self) -> Result<Value> {
        Ok(Value::Array(
            self.db
                .list_vm_templates()
                .await?
                .into_iter()
                .filter(|t| t.enabled)
                .map(|t| {
                    json!({
                        "id": t.id,
                        "name": t.name,
                        "cpu": t.cpu,
                        "memory_bytes": t.memory,
                        "disk_bytes": t.disk_size,
                        "disk_type": format!("{:?}", t.disk_type),
                        "region_id": t.region_id,
                    })
                })
                .collect(),
        ))
    }

    async fn os_images(&self) -> Result<Value> {
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
                        "default_username": i.default_username,
                    })
                })
                .collect(),
        ))
    }

    /// Live IP assignments of a VM, as probe targets.
    async fn vm_ips(&self, vm: &Vm) -> Vec<String> {
        self.db
            .list_vm_ip_assignments(vm.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| !a.deleted)
            .map(|a| a.ip)
            .collect()
    }

    /// Apply a power action to an owned VM.
    async fn power(&self, vm: &Vm, action: PowerAction) -> Result<Value> {
        let (Some(provisioner), Some(work_sender)) =
            (self.provisioner.as_ref(), self.work_sender.as_ref())
        else {
            bail!("VM power controls are not available in this session");
        };

        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, provisioner)?;

        match action {
            PowerAction::Start => client.start_vm(vm).await?,
            PowerAction::Stop => client.stop_vm(vm).await?,
            // Hard reset, matching the REST endpoint: a plain stop would leave
            // the VM powered off rather than restarted.
            PowerAction::Restart => client.reset_vm(vm).await?,
        }

        // Each logger method returns a distinct opaque future, so they are
        // awaited in-arm rather than unified into one binding.
        let logged = match action {
            PowerAction::Start => {
                self.history
                    .log_vm_started(vm.id, Some(self.user_id), None)
                    .await
            }
            PowerAction::Stop => {
                self.history
                    .log_vm_stopped(vm.id, Some(self.user_id), None)
                    .await
            }
            PowerAction::Restart => {
                self.history
                    .log_vm_restarted(vm.id, Some(self.user_id), None)
                    .await
            }
        };
        // History is an audit trail, not a precondition — never fail the action
        // the customer asked for because logging it failed.
        if let Err(e) = logged {
            log::warn!("Failed to log VM {} {}: {}", vm.id, action.as_str(), e);
        }

        if let Err(e) = work_sender.send(WorkJob::CheckVm { vm_id: vm.id }).await {
            log::warn!("Failed to queue state check for VM {}: {}", vm.id, e);
        }

        Ok(json!({
            "vm_id": vm.id,
            "result": format!("VM {} {}", vm.id, action.as_str()),
        }))
    }
}

#[async_trait]
impl ToolExecutor for DbToolExecutor {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String> {
        let args = parse_args(arguments);

        match name {
            "get_my_account" => pretty(&self.account().await?),
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
            "list_regions" => pretty(&self.regions().await?),
            "list_templates" => pretty(&self.templates().await?),
            "list_os_images" => pretty(&self.os_images().await?),
            "get_terms_of_service" => Ok(self.diag.terms_of_service().await?.to_string()),
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
            // Billing-sensitive tools are never offered to live chat; reaching
            // this arm means the model invented the call.
            "extend_vm" | "refund_vm" | "delete_vm" => {
                bail!(
                    "{} is not available in live chat — ask the customer to email support",
                    name
                )
            }
            _ => bail!("Unknown tool: {}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnvps_api_common::MockDb;

    /// Executor scoped to the mock DB's seeded user.
    async fn executor(user_id: u64) -> (Arc<MockDb>, DbToolExecutor) {
        let db = Arc::new(MockDb::default());
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        (db.clone(), DbToolExecutor::new(dyn_db, user_id))
    }

    /// Seed a VM owned by `user_id` and return its id.
    async fn seed_vm(db: &Arc<MockDb>, vm_id: u64, user_id: u64) {
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

    /// The authorisation boundary: a customer must not be able to read another
    /// customer's VM by guessing an id.
    #[tokio::test]
    async fn rejects_vms_owned_by_another_user() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 99, 2).await;

        for tool in [
            "get_vm_details",
            "list_vm_payments",
            "list_vm_history",
            "start_vm",
            "stop_vm",
            "restart_vm",
            // Probes must fail the ownership check *before* any packet is
            // sent, or support chat becomes a scanner aimed by vm_id.
            "ping_vm",
            "traceroute_vm",
        ] {
            let err = exec
                .execute(tool, r#"{"vm_id":99}"#)
                .await
                .expect_err(&format!("{tool} must reject a VM owned by someone else"));
            let message = err.to_string();
            assert!(
                message.contains("does not belong to you"),
                "{tool}: {message}"
            );
            // The real owner must not be disclosed.
            assert!(
                !message.contains('2') || !message.contains("owner"),
                "{message}"
            );
        }
    }

    #[tokio::test]
    async fn vm_scoped_tools_require_a_vm_id() {
        let (_db, exec) = executor(1).await;
        let err = exec.execute("get_vm_details", "{}").await.unwrap_err();
        assert!(err.to_string().contains("vm_id required"));
    }

    /// Live chat must refuse the billing-sensitive tools even if the model
    /// hallucinates a call to one.
    #[tokio::test]
    async fn refuses_billing_tools() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;

        for tool in ["extend_vm", "refund_vm", "delete_vm"] {
            let err = exec
                .execute(tool, r#"{"vm_id":5,"days":30}"#)
                .await
                .expect_err("billing tools must be refused");
            assert!(err.to_string().contains("not available in live chat"));
        }
    }

    #[tokio::test]
    async fn unknown_tool_errors() {
        let (_db, exec) = executor(1).await;
        assert!(exec.execute("rm_rf", "{}").await.is_err());
    }

    /// check_vm_port validates its port argument before touching the network.
    #[tokio::test]
    async fn check_vm_port_rejects_a_missing_or_foreign_vm() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 99, 2).await;

        let err = exec
            .execute("check_vm_port", r#"{"vm_id":5}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("port required"));

        let err = exec
            .execute("check_vm_port", r#"{"vm_id":99,"port":22}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not belong to you"));
    }

    /// Freed assignments must not be probed — the address may already belong to
    /// another customer's VM.
    #[tokio::test]
    async fn vm_ips_skips_released_assignments() {
        let db = Arc::new(MockDb::default());
        seed_vm(&db, 7, 1).await;
        {
            let mut ips = db.ip_assignments.lock().await;
            ips.insert(
                1,
                lnvps_db::VmIpAssignment {
                    id: 1,
                    vm_id: 7,
                    ip: "10.0.0.5".to_string(),
                    ..Default::default()
                },
            );
            ips.insert(
                2,
                lnvps_db::VmIpAssignment {
                    id: 2,
                    vm_id: 7,
                    ip: "10.0.0.6".to_string(),
                    deleted: true,
                    ..Default::default()
                },
            );
        }
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, 1);
        let vm = db.vms.lock().await.get(&7).cloned().unwrap();
        assert_eq!(exec.vm_ips(&vm).await, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn wants_ipv6_defaults_to_v4() {
        assert!(!wants_ipv6(&parse_args("{}")));
        assert!(wants_ipv6(&parse_args(r#"{"ipv6":true}"#)));
    }

    /// The in-process executor must be able to quote policy too, not just the
    /// HTTP-backed one used by the email/Nostr channels.
    #[tokio::test]
    async fn serves_the_terms_of_service() {
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
            crate::diag::LookingGlass::default(),
            crate::diag::PolicyDocs::new(site.uri()),
        ));
        let out = exec.execute("get_terms_of_service", "{}").await.unwrap();
        assert!(out.contains("No port scanning."));
    }

    /// Power actions are unavailable unless explicitly wired up, so a read-only
    /// deployment cannot touch a hypervisor.
    #[tokio::test]
    async fn power_actions_disabled_without_configuration() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;

        let err = exec
            .execute("start_vm", r#"{"vm_id":5}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not available in this session"));
    }

    /// The account projection must never carry verification secrets.
    #[tokio::test]
    async fn account_projection_omits_secrets() {
        let db = Arc::new(MockDb::default());
        let user_id = {
            let mut users = db.users.lock().await;
            let id = 1u64;
            users.insert(
                id,
                lnvps_db::User {
                    id,
                    pubkey: vec![0xab; 32],
                    email: "bob@example.com".into(),
                    email_verify_token: "SECRET-EMAIL-TOKEN".to_string(),
                    telegram_link_token: Some("SECRET-TG-TOKEN".to_string()),
                    whatsapp_verify_code: Some("SECRET-WA-CODE".to_string()),
                    ..Default::default()
                },
            );
            id
        };
        let dyn_db: Arc<dyn LNVpsDb> = db.clone();
        let exec = DbToolExecutor::new(dyn_db, user_id);

        let out = exec.execute("get_my_account", "{}").await.unwrap();
        assert!(out.contains("bob@example.com"), "own email is fine to show");
        for secret in ["SECRET-EMAIL-TOKEN", "SECRET-TG-TOKEN", "SECRET-WA-CODE"] {
            assert!(!out.contains(secret), "leaked {secret}");
        }
        // Field names must not appear either, so a future struct change can't
        // silently reintroduce them.
        for field in [
            "email_verify_token",
            "telegram_link_token",
            "whatsapp_verify_code",
        ] {
            assert!(!out.contains(field), "leaked field {field}");
        }
    }

    /// VM details name the host but must never expose its credentials.
    ///
    /// The host is seeded with real secret values, so this fails on a value
    /// leak as well as on the whole struct being serialised.
    #[tokio::test]
    async fn vm_details_omit_host_credentials() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;
        {
            let mut hosts = db.hosts.lock().await;
            let host = hosts.get_mut(&1).expect("mock host");
            host.api_token = "SECRET-HOST-API-TOKEN".into();
            host.ssh_key = Some("SECRET-HOST-SSH-KEY".into());
        }

        let out = exec
            .execute("get_vm_details", r#"{"vm_id":5}"#)
            .await
            .unwrap();

        // The host is identified by name, which is safe and useful context.
        assert!(out.contains("\"host\""));
        for leaked in [
            "SECRET-HOST-API-TOKEN",
            "SECRET-HOST-SSH-KEY",
            "api_token",
            "ssh_key",
            "ssh_user",
        ] {
            assert!(!out.contains(leaked), "leaked {leaked}");
        }
    }

    #[tokio::test]
    async fn catalogue_tools_return_arrays() {
        let (_db, exec) = executor(1).await;
        for tool in ["list_regions", "list_templates", "list_os_images"] {
            let out = exec.execute(tool, "{}").await.unwrap();
            let parsed: Value = serde_json::from_str(&out).unwrap();
            assert!(parsed.is_array(), "{tool} must return an array");
        }
    }

    #[tokio::test]
    async fn lists_only_the_scoped_users_vms() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 1, 1).await;
        seed_vm(&db, 2, 2).await;

        let out = exec.execute("list_my_vms", "{}").await.unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<u64> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, vec![1], "must not include another user's VM");
    }

    #[test]
    fn arg_parsing_is_lenient_but_typed() {
        assert!(parse_args("not json").is_empty());
        let args = parse_args(r#"{"vm_id":5}"#);
        assert_eq!(required_u64(&args, "vm_id").unwrap(), 5);
        assert!(required_u64(&args, "days").is_err());
    }

    #[test]
    fn power_action_labels_are_past_tense() {
        assert_eq!(PowerAction::Start.as_str(), "started");
        assert_eq!(PowerAction::Stop.as_str(), "stopped");
        assert_eq!(PowerAction::Restart.as_str(), "restarted");
    }
}
