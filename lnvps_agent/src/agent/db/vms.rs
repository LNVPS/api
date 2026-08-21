//! VM tools: listing, details, payments, history, power control, firewall
//! rules and hypervisor metrics.
//!
//! Every tool here resolves its VM through [`DbToolExecutor::owned_vm`], which
//! is the authorisation boundary for the whole group: the `vm_id` argument
//! comes from the model and a customer can ask about any id.

use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use lnvps_api_common::WorkJob;
use lnvps_api_common::host::{TimeSeries, get_host_client};
use lnvps_db::Vm;

use super::{DbToolExecutor, required_u64, tag};

/// What a VM power action does to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PowerAction {
    Start,
    Stop,
    Restart,
}

impl PowerAction {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            PowerAction::Start => "started",
            PowerAction::Stop => "stopped",
            PowerAction::Restart => "restarted",
        }
    }
}

impl DbToolExecutor {
    /// Load a VM, confirming the scoped user owns it.
    ///
    /// This is the authorisation boundary for every VM-scoped tool. It is
    /// enforced here rather than by the prompt, because the model's `vm_id`
    /// argument is attacker-influencable: a customer can ask about any id.
    pub(super) async fn owned_vm(&self, args: &HashMap<String, Value>) -> Result<Vm> {
        let user_id = self.require_user()?;
        let vm_id = required_u64(args, "vm_id")?;
        let vm = self.db.get_vm(vm_id).await?;
        if vm.user_id != user_id {
            // Deliberately does not reveal the real owner.
            bail!("VM {} does not belong to you", vm_id);
        }
        Ok(vm)
    }

    /// Summary view of a VM, as shown in a list.
    pub(super) async fn vm_summary(&self, vm: &Vm) -> Value {
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
    pub(super) async fn vm_details(&self, vm: &Vm) -> Value {
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

    pub(super) async fn list_vms(&self) -> Result<Value> {
        let vms = self.db.list_user_vms(self.require_user()?).await?;
        let mut out = Vec::with_capacity(vms.len());
        for vm in vms.iter().filter(|v| !v.deleted) {
            out.push(self.vm_summary(vm).await);
        }
        Ok(Value::Array(out))
    }

    /// Payment history for a VM. Excludes `external_data` (encrypted payment
    /// instrument) and `external_id` (processor reference).
    pub(super) async fn vm_payments(&self, vm: &Vm) -> Result<Value> {
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

    pub(super) async fn vm_history(&self, vm: &Vm) -> Result<Value> {
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

    /// Live IP assignments of a VM, as probe targets.
    pub(super) async fn vm_ips(&self, vm: &Vm) -> Vec<String> {
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
    pub(super) async fn power(&self, vm: &Vm, action: PowerAction) -> Result<Value> {
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
            PowerAction::Start => self.history.log_vm_started(vm.id, self.user_id, None).await,
            PowerAction::Stop => self.history.log_vm_stopped(vm.id, self.user_id, None).await,
            PowerAction::Restart => {
                self.history
                    .log_vm_restarted(vm.id, self.user_id, None)
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

    /// A VM's firewall rules and default policy.
    ///
    /// Worth having next to `check_vm_port`: a port that times out because the
    /// customer's own rule drops it looks identical, from the edge, to one
    /// nothing is listening on.
    pub(super) async fn firewall(&self, vm: &Vm) -> Result<Value> {
        let rules = self.db.list_vm_firewall_rules(vm.id).await?;
        Ok(json!({
            "vm_id": vm.id,
            "default_policy_in": vm.fw_policy_in.map(tag),
            "default_policy_out": vm.fw_policy_out.map(tag),
            "policy_note": "A null default policy means the host default applies.",
            "rules": rules.into_iter().map(|r| json!({
                "id": r.id,
                "priority": r.priority,
                "direction": tag(r.direction),
                "protocol": tag(r.protocol),
                "action": tag(r.action),
                "src_cidr": r.src_cidr,
                "dst_port_start": r.dst_port_start,
                "dst_port_end": r.dst_port_end,
                "enabled": r.enabled,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Hourly CPU / memory / disk / network samples for a VM, read from the
    /// hypervisor.
    ///
    /// Answers "is my VM slow / out of memory", which the reachability probes
    /// cannot. Requires the hypervisor wiring, like the power actions.
    pub(super) async fn vm_metrics(&self, vm: &Vm) -> Result<Value> {
        let Some(provisioner) = self.provisioner.as_ref() else {
            bail!("VM metrics are not available in this session");
        };
        let host = self.db.get_host(vm.host_id).await?;
        let client = get_host_client(&host, provisioner)?;
        let series = client.get_time_series_data(vm, TimeSeries::Hourly).await?;
        Ok(json!({
            "vm_id": vm.id,
            "resolution": "hourly",
            "samples": series.into_iter().map(|s| json!({
                "timestamp": s.timestamp,
                "cpu": s.cpu,
                "memory": s.memory,
                "memory_size": s.memory_size,
                "net_in_bytes": s.net_in,
                "net_out_bytes": s.net_out,
                "disk_read_bytes": s.disk_read,
                "disk_write_bytes": s.disk_write,
            })).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::*;
    use crate::agent::ToolExecutor;
    use lnvps_api_common::MockDb;
    use lnvps_db::LNVpsDb;
    use std::sync::Arc;

    /// The authorisation boundary: a customer must not be able to read another
    /// customer's VM by guessing an id.
    #[tokio::test]
    pub(super) async fn rejects_vms_owned_by_another_user() {
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
    pub(super) async fn vm_scoped_tools_require_a_vm_id() {
        let (_db, exec) = executor(1).await;
        let err = exec.execute("get_vm_details", "{}").await.unwrap_err();
        assert!(err.to_string().contains("vm_id required"));
    }

    /// Live chat must refuse the billing-sensitive tools even if the model
    /// hallucinates a call to one.
    #[tokio::test]
    pub(super) async fn refuses_billing_tools() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;

        for tool in ["extend_vm", "refund_vm", "delete_vm"] {
            let err = exec
                .execute(tool, r#"{"vm_id":5,"days":30}"#)
                .await
                .expect_err("billing tools must be refused");
            assert!(err.to_string().contains("has to"), "{err}");
        }
    }

    /// check_vm_port validates its port argument before touching the network.
    #[tokio::test]
    pub(super) async fn check_vm_port_rejects_a_missing_or_foreign_vm() {
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
    pub(super) async fn vm_ips_skips_released_assignments() {
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

    /// Power actions are unavailable unless explicitly wired up, so a read-only
    /// deployment cannot touch a hypervisor.
    #[tokio::test]
    pub(super) async fn power_actions_disabled_without_configuration() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;

        let err = exec
            .execute("start_vm", r#"{"vm_id":5}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not available in this session"));
    }

    /// VM details name the host but must never expose its credentials.
    ///
    /// The host is seeded with real secret values, so this fails on a value
    /// leak as well as on the whole struct being serialised.
    #[tokio::test]
    pub(super) async fn vm_details_omit_host_credentials() {
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
    pub(super) async fn lists_only_the_scoped_users_vms() {
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
    fn power_action_labels_are_past_tense() {
        assert_eq!(PowerAction::Start.as_str(), "started");
        assert_eq!(PowerAction::Stop.as_str(), "stopped");
        assert_eq!(PowerAction::Restart.as_str(), "restarted");
    }

    /// The firewall view pairs with the port probe: a customer's own DROP rule
    /// looks exactly like nothing listening, from outside.
    #[tokio::test]
    async fn firewall_rules_report_the_default_policy_too() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;
        db.firewall_rules.lock().await.insert(
            1,
            lnvps_db::VmFirewallRule {
                id: 1,
                vm_id: 5,
                priority: 10,
                direction: lnvps_db::VmFirewallDirection::Inbound,
                protocol: lnvps_db::VmFirewallProtocol::Tcp,
                action: lnvps_db::VmFirewallRuleAction::Drop,
                src_cidr: Some("0.0.0.0/0".to_string()),
                dst_port_start: Some(22),
                dst_port_end: Some(22),
                enabled: true,
                ..Default::default()
            },
        );

        let out = exec
            .execute("list_vm_firewall_rules", r#"{"vm_id":5}"#)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["rules"][0]["action"], "drop");
        assert_eq!(parsed["rules"][0]["dst_port_start"], 22);
        // A null default policy must be explained, not left to be guessed.
        assert!(
            parsed["policy_note"]
                .as_str()
                .unwrap()
                .contains("host default")
        );
    }

    /// Metrics need the hypervisor, so a read-only deployment must refuse
    /// rather than fabricate a series.
    #[tokio::test]
    async fn metrics_disabled_without_configuration() {
        let (db, exec) = executor(1).await;
        seed_vm(&db, 5, 1).await;

        let err = exec
            .execute("get_vm_metrics", r#"{"vm_id":5}"#)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not available in this session"));
    }
}
