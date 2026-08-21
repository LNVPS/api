//! Tool specifications advertised to the model, grouped by subject area.
//!
//! One module per group, mirroring [`crate::agent::db`]'s layout, so a tool's
//! spec and its implementation are found in the same place:
//!
//! | Module | Tools |
//! |---|---|
//! | [`account`] | account record, SSH keys, saved payment methods |
//! | [`vms`] | VM listing/details/payments/history, power, firewall, metrics |
//! | [`catalogue`] | regions, plans, custom pricing, quotes, exchange rates, images, app catalogue |
//! | [`billing`] | subscriptions, their payments, IP-space subscriptions |
//! | [`apps`] | the customer's managed app deployments |
//! | [`partners`] | referral programme, marketplace operator enrolment |
//! | [`diagnostics`] | ping, traceroute, port check |
//!
//! The **sets** at the bottom are the security surface: which tools a channel
//! is offered depends on who is asking and on what the executor behind that
//! channel can actually serve. They are assembled here rather than in the
//! modules so the whole policy is readable in one screen.

use async_openai::types::FunctionObject;

pub mod account;
pub mod apps;
pub mod billing;
pub mod catalogue;
pub mod diagnostics;
pub mod partners;
pub mod vms;

// ── Spec builders ───────────────────────────────────────────────────

/// Build a function spec from an explicit JSON schema.
pub(crate) fn tool(name: &str, description: &str, parameters: serde_json::Value) -> FunctionObject {
    use async_openai::types::FunctionObjectArgs;
    FunctionObjectArgs::default()
        .name(name)
        .description(description)
        .parameters(parameters)
        .build()
        .expect("valid tool definition")
}

/// Build a function spec taking no arguments.
pub(crate) fn nullary(name: &str, description: &str) -> FunctionObject {
    tool(
        name,
        description,
        serde_json::json!({ "type": "object", "properties": {} }),
    )
}

/// Build a function spec taking a single required integer id.
pub(crate) fn id_scoped(name: &str, description: &str, key: &str, what: &str) -> FunctionObject {
    tool(
        name,
        description,
        serde_json::json!({
            "type": "object",
            "properties": { key: { "type": "integer", "description": what } },
            "required": [key]
        }),
    )
}

// ── Tool sets ───────────────────────────────────────────────────────

/// Everything that needs no account: what LNVPS sells, what it costs, and the
/// published policy.
///
/// The terms of service belong here rather than in the customer sets: the
/// document is published on the website, so answering "am I allowed to run
/// this?" needs no account, and pre-sales askers are exactly who asks.
fn catalogue_tools() -> Vec<FunctionObject> {
    vec![
        catalogue::list_regions(),
        catalogue::list_templates(),
        catalogue::list_custom_pricing(),
        catalogue::price_custom_vm(),
        catalogue::get_exchange_rate(),
        catalogue::list_os_images(),
        catalogue::list_apps(),
        catalogue::get_app_details(),
        catalogue::list_app_tags(),
        catalogue::get_terms_of_service(),
    ]
}

/// Every read-only tool scoped to the authenticated customer.
///
/// One list, because there is one executor: every channel reads the same
/// database, so a tool available on live chat is available on email too.
fn customer_read_tools() -> Vec<FunctionObject> {
    vec![
        account::get_my_account(),
        account::list_my_ssh_keys(),
        account::list_my_payment_methods(),
        vms::list_my_vms(),
        vms::get_vm_details(),
        vms::list_vm_payments(),
        vms::list_vm_history(),
        vms::list_vm_firewall_rules(),
        vms::get_vm_metrics(),
        billing::list_my_subscriptions(),
        billing::get_subscription_details(),
        billing::list_subscription_payments(),
        billing::list_my_ip_subscriptions(),
        apps::list_my_app_deployments(),
        apps::get_app_deployment_details(),
        partners::get_my_referral(),
        partners::list_referral_usage(),
        partners::get_my_marketplace_operator(),
    ]
}

/// Network probes against the requester's own VM.
///
/// Every probe resolves its target from an ownership-checked VM record — no
/// tool here accepts a hostname or address, so support chat cannot be steered
/// into scanning third parties.
fn diagnostic_tools() -> Vec<FunctionObject> {
    vec![
        diagnostics::ping_vm(),
        diagnostics::traceroute_vm(),
        diagnostics::check_vm_port(),
    ]
}

/// Reversible state changes: they interrupt a workload but destroy nothing and
/// move no money, and the customer can already make them through the REST API.
fn power_tools() -> Vec<FunctionObject> {
    vec![
        vms::start_vm(),
        vms::stop_vm(),
        vms::restart_vm(),
        apps::start_app_deployment(),
        apps::stop_app_deployment(),
    ]
}

/// All tools the asynchronous support channels (email, Nostr) have access to.
///
/// These are user-scoped — no tool accepts a pubkey or user_id parameter;
/// the executor is already bound to the user identified by the support channel.
///
/// Read-only, plus the catalogue. There is deliberately no `extend_vm`,
/// `refund_vm` or `delete_vm`: granting paid time, moving money and destroying
/// data are subscription-lifecycle operations that live in the API, and
/// re-implementing them against the database would mean a second, divergent
/// copy of the billing rules driven by a language model. Escalate instead.
pub fn support_tools() -> Vec<FunctionObject> {
    let mut tools = customer_read_tools();
    tools.extend(diagnostic_tools());
    tools.extend(catalogue_tools());
    tools
}

/// Tools available to non-customer/general support requests.
/// Subset of [`support_tools`] that doesn't require an authenticated user.
pub fn public_tools() -> Vec<FunctionObject> {
    catalogue_tools()
}

/// Tools available over the interactive live-chat websocket for an
/// authenticated customer.
///
/// Adds the reversible workload controls to [`support_tools`]: powering a VM
/// or a deployment interrupts a workload but destroys nothing, moves no money,
/// and the customer can already do it through the REST API. Live chat is where
/// they are useful, being the channel with a human waiting on the other end.
pub fn live_chat_tools() -> Vec<FunctionObject> {
    let mut tools = customer_read_tools();
    tools.extend(power_tools());
    tools.extend(diagnostic_tools());
    tools.extend(catalogue_tools());
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(tools: &[FunctionObject]) -> Vec<&str> {
        tools.iter().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn public_tools_are_catalogue_only() {
        let tools = public_tools();
        assert_eq!(
            names(&tools),
            vec![
                "list_regions",
                "list_templates",
                "list_custom_pricing",
                "price_custom_vm",
                "get_exchange_rate",
                "list_os_images",
                "list_apps",
                "get_app_details",
                "list_app_tags",
                "get_terms_of_service"
            ]
        );
    }

    /// No catalogue tool may take an account-scoped identifier: the public set
    /// is served by an executor with no user, so such an argument could only
    /// ever be an invitation for the model to guess one.
    #[test]
    fn catalogue_tools_take_no_account_identifiers() {
        for tool in public_tools() {
            let params = tool.parameters.expect("parameters");
            let Some(properties) = params["properties"].as_object() else {
                continue;
            };
            for key in properties.keys() {
                assert!(
                    ![
                        "vm_id",
                        "user_id",
                        "pubkey",
                        "subscription_id",
                        "deployment_id"
                    ]
                    .contains(&key.as_str()),
                    "{} exposes {}",
                    tool.name,
                    key
                );
            }
        }
    }

    /// Diagnostics need an owned VM, so an anonymous requester must not get
    /// them — otherwise the probe target would have to come from the model.
    #[test]
    fn public_tools_exclude_vm_probes() {
        let tools = public_tools();
        let names = names(&tools);
        for forbidden in ["ping_vm", "traceroute_vm", "check_vm_port"] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden} must not be public"
            );
        }
    }

    #[test]
    fn customer_sets_include_diagnostics() {
        for set in [support_tools(), live_chat_tools()] {
            let names = names(&set);
            for expected in ["ping_vm", "traceroute_vm", "check_vm_port"] {
                assert!(names.contains(&expected), "missing {expected}");
            }
        }
    }

    #[test]
    fn every_set_can_quote_the_terms() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            assert!(names(&set).contains(&"get_terms_of_service"));
        }
        // The catalogue set is shared, so a regression would hit all three.
    }

    /// Pre-sales questions are the common case for a logged-out visitor, so
    /// every set must be able to quote fixed plans, custom VMs and apps.
    #[test]
    fn every_set_can_quote_pricing() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            let names = names(&set);
            for expected in [
                "list_templates",
                "list_custom_pricing",
                "price_custom_vm",
                "get_exchange_rate",
                "list_apps",
                "get_app_details",
            ] {
                assert!(names.contains(&expected), "missing {expected}");
            }
        }
    }

    /// The account-scoped products a customer can hold must be reachable from
    /// both customer channels, or support has to answer from memory.
    #[test]
    fn customer_sets_cover_every_product() {
        for set in [support_tools(), live_chat_tools()] {
            let names = names(&set);
            for expected in [
                "list_my_vms",
                "list_my_subscriptions",
                "list_subscription_payments",
                "list_my_app_deployments",
                "get_my_referral",
                "get_my_marketplace_operator",
            ] {
                assert!(names.contains(&expected), "missing {expected}");
            }
        }
    }

    /// Every channel reads the same database, so nothing account-scoped may be
    /// live-chat-only except the workload controls.
    #[test]
    fn both_customer_sets_read_the_same_data() {
        let support_set = support_tools();
        let chat_set = live_chat_tools();
        let support = names(&support_set);
        let chat = names(&chat_set);
        for tool in names(&customer_read_tools()) {
            assert!(support.contains(&tool), "{tool} missing from support");
            assert!(chat.contains(&tool), "{tool} missing from live chat");
        }
    }

    /// No set may offer a tool that grants paid time, moves money or destroys
    /// data. Those live in the API's subscription lifecycle; a model-driven
    /// second implementation against the database would be a divergent copy of
    /// the billing rules.
    #[test]
    fn no_set_offers_destructive_billing_actions() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            let names = names(&set);
            for forbidden in ["extend_vm", "refund_vm", "delete_vm"] {
                assert!(
                    !names.contains(&forbidden),
                    "{forbidden} must not be offered"
                );
            }
        }
    }

    /// Reversible workload control is live-chat only: it is the channel with a
    /// human waiting, where "start my VM" is worth doing in the conversation
    /// rather than in a reply hours later.
    #[test]
    fn workload_controls_are_live_chat_only() {
        let support_set = support_tools();
        let chat_set = live_chat_tools();
        let support = names(&support_set);
        let chat = names(&chat_set);
        for action in [
            "start_vm",
            "stop_vm",
            "restart_vm",
            "start_app_deployment",
            "stop_app_deployment",
        ] {
            assert!(
                !support.contains(&action),
                "{action} must not be in support"
            );
            assert!(chat.contains(&action), "{action} missing from live chat");
        }
    }

    #[test]
    fn every_tool_set_has_unique_names() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            let mut names = names(&set);
            let total = names.len();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), total, "duplicate tool names in set");
        }
    }

    /// Every advertised spec must be a well-formed object schema, or the model
    /// silently drops the tool.
    #[test]
    fn every_spec_is_an_object_schema() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            for tool in set {
                let params = tool
                    .parameters
                    .unwrap_or_else(|| panic!("{} has no parameters", tool.name));
                assert_eq!(params["type"], "object", "{}", tool.name);
                assert!(params["properties"].is_object(), "{}", tool.name);
                assert!(
                    !tool.description.unwrap_or_default().is_empty(),
                    "{} has no description",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn id_scoped_specs_require_their_id() {
        let spec = id_scoped("x", "d", "thing_id", "the thing");
        let params = spec.parameters.expect("parameters");
        assert_eq!(params["required"][0], "thing_id");
        assert_eq!(params["properties"]["thing_id"]["type"], "integer");
    }

    #[test]
    fn nullary_tools_have_no_required_args() {
        let params = catalogue::list_regions().parameters.expect("parameters");
        assert!(params.get("required").is_none());
    }
}
