use async_openai::types::FunctionObject;
use serde_json::json;

/// Build a function spec taking no arguments.
fn nullary(name: &str, description: &str) -> FunctionObject {
    tool(
        name,
        description,
        json!({ "type": "object", "properties": {} }),
    )
}

/// Build a function spec taking a single required `vm_id` integer.
fn vm_scoped(name: &str, description: &str) -> FunctionObject {
    tool(
        name,
        description,
        json!({
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "integer",
                    "description": "The numeric VM ID"
                }
            },
            "required": ["vm_id"]
        }),
    )
}

// ── Individual tool specs ───────────────────────────────────────────

fn get_my_account() -> FunctionObject {
    nullary(
        "get_my_account",
        "Get the current user's account information: billing details, contact preferences, email verification status, and NWC auto-renewal status.",
    )
}

fn list_my_vms() -> FunctionObject {
    nullary(
        "list_my_vms",
        "List all VMs belonging to the current user. Shows VM IDs, names, status, specs, IPs, expiry dates, and region info.",
    )
}

fn get_vm_details() -> FunctionObject {
    vm_scoped(
        "get_vm_details",
        "Get detailed information about a specific VM owned by the current user. Includes host, region, IP assignments, full specs, payment status, and exact expiry date.",
    )
}

fn list_vm_payments() -> FunctionObject {
    vm_scoped(
        "list_vm_payments",
        "List all payments for a specific VM owned by the current user. Shows amounts, currencies, paid/unpaid status, dates, and payment methods.",
    )
}

fn list_vm_history() -> FunctionObject {
    vm_scoped(
        "list_vm_history",
        "List the activity history for a specific VM. Shows creation, start/stop events, reinstallations, upgrades, and configuration changes with timestamps.",
    )
}

fn extend_vm() -> FunctionObject {
    tool(
        "extend_vm",
        "Extend (renew) a VM owned by the current user for a certain number of days. Use this when a customer asks for extra time or a manual renewal.",
        json!({
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "integer",
                    "description": "The numeric VM ID to extend"
                },
                "days": {
                    "type": "integer",
                    "description": "Number of days to extend the VM for"
                }
            },
            "required": ["vm_id", "days"]
        }),
    )
}

fn refund_vm() -> FunctionObject {
    vm_scoped(
        "refund_vm",
        "Process a refund for a VM. This is irreversible — always confirm with the user before executing. Only works on VMs owned by the current user.",
    )
}

fn delete_vm() -> FunctionObject {
    vm_scoped(
        "delete_vm",
        "Delete a VM owned by the current user. Use this only when explicitly requested and after confirming with the customer.",
    )
}

fn start_vm() -> FunctionObject {
    vm_scoped(
        "start_vm",
        "Power on a VM owned by the current user. Safe and reversible — use when the customer reports their VM is offline or asks to boot it.",
    )
}

fn stop_vm() -> FunctionObject {
    vm_scoped(
        "stop_vm",
        "Power off a VM owned by the current user. Confirm with the customer first, as running services will be interrupted.",
    )
}

fn restart_vm() -> FunctionObject {
    vm_scoped(
        "restart_vm",
        "Hard reset (restart) a VM owned by the current user. Confirm with the customer first. Often resolves an unresponsive VM.",
    )
}

fn list_regions() -> FunctionObject {
    nullary(
        "list_regions",
        "List all available hosting regions with their names and IDs. Use this to answer questions about where VMs can be provisioned or where an existing VM is located.",
    )
}

fn list_templates() -> FunctionObject {
    nullary(
        "list_templates",
        "List all available VM templates with specifications and pricing. Shows CPU, memory, storage, pricing plans, and which region each template belongs to. Use this to answer questions about available plans and pricing.",
    )
}

fn list_os_images() -> FunctionObject {
    nullary(
        "list_os_images",
        "List all available operating system images that can be installed on VMs. Shows image names, versions, OS types, and supported platforms.",
    )
}

fn get_terms_of_service() -> FunctionObject {
    nullary(
        "get_terms_of_service",
        "Fetch the current LNVPS Terms of Service and Acceptable Use Policy as plain text. Use this for ANY question about what is allowed, refunds, suspension, abuse handling, liability, data retention, or company details — quote the document rather than answering from memory.",
    )
}

/// A VM-scoped tool that also takes an optional address family.
fn vm_probe(name: &str, description: &str) -> FunctionObject {
    tool(
        name,
        description,
        json!({
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "integer",
                    "description": "The numeric VM ID to probe"
                },
                "ipv6": {
                    "type": "boolean",
                    "description": "Probe the VM's IPv6 address instead of its IPv4 address. Defaults to false."
                }
            },
            "required": ["vm_id"]
        }),
    )
}

fn ping_vm() -> FunctionObject {
    vm_probe(
        "ping_vm",
        "Check whether a VM owned by the current user answers from the network edge. Returns reachability, packet loss and round-trip time. Use this first when a customer says their VM is unreachable or offline.",
    )
}

fn traceroute_vm() -> FunctionObject {
    vm_probe(
        "traceroute_vm",
        "Trace the network path from the LNVPS edge router to a VM owned by the current user. Returns every hop with loss and latency. Use this when ping_vm shows the VM unreachable or the customer reports packet loss, to see where the path breaks.",
    )
}

fn check_vm_port() -> FunctionObject {
    tool(
        "check_vm_port",
        "Test whether a TCP port on a VM owned by the current user accepts connections (e.g. 22 for SSH, 80/443 for web). Distinguishes 'open', 'refused' (VM up, nothing listening) and 'timeout' (filtered or down) — far more useful than ping when a specific service is unreachable.",
        json!({
            "type": "object",
            "properties": {
                "vm_id": {
                    "type": "integer",
                    "description": "The numeric VM ID to probe"
                },
                "port": {
                    "type": "integer",
                    "description": "TCP port to test (1-65535)"
                },
                "ipv6": {
                    "type": "boolean",
                    "description": "Probe the VM's IPv6 address instead of its IPv4 address. Defaults to false."
                }
            },
            "required": ["vm_id", "port"]
        }),
    )
}

// ── Tool sets ───────────────────────────────────────────────────────

/// Catalogue tools that expose no customer data and need no authentication.
///
/// The terms of service belong here rather than in the customer sets: the
/// document is published on the website, so answering "am I allowed to run
/// this?" needs no account, and pre-sales askers are exactly who asks.
fn catalogue_tools() -> Vec<FunctionObject> {
    vec![
        list_regions(),
        list_templates(),
        list_os_images(),
        get_terms_of_service(),
    ]
}

/// Network probes against the requester's own VM.
///
/// Every probe resolves its target from an ownership-checked VM record — no
/// tool here accepts a hostname or address, so support chat cannot be steered
/// into scanning third parties.
fn diagnostic_tools() -> Vec<FunctionObject> {
    vec![ping_vm(), traceroute_vm(), check_vm_port()]
}

/// Read-only tools scoped to the authenticated customer.
fn customer_read_tools() -> Vec<FunctionObject> {
    vec![
        get_my_account(),
        list_my_vms(),
        get_vm_details(),
        list_vm_payments(),
        list_vm_history(),
    ]
}

/// All tools the asynchronous support channels (email, Nostr) have access to.
///
/// These are user-scoped — no tool accepts a pubkey or user_id parameter;
/// the executor is already bound to the user identified by the support channel.
/// Includes the billing-sensitive actions (`extend_vm`, `refund_vm`,
/// `delete_vm`) because those channels are slow, auditable, and reviewable.
pub fn support_tools() -> Vec<FunctionObject> {
    let mut tools = customer_read_tools();
    tools.extend([extend_vm(), refund_vm(), delete_vm()]);
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
/// Deliberately excludes `extend_vm`, `refund_vm` and `delete_vm`: those grant
/// paid time, move money, or destroy data, and "the model asked the user to
/// confirm" is not an authorisation control on a public, low-latency,
/// prompt-injectable surface. Power actions are included because they are
/// reversible and already available to the customer via the REST API.
pub fn live_chat_tools() -> Vec<FunctionObject> {
    let mut tools = customer_read_tools();
    tools.extend([start_vm(), stop_vm(), restart_vm()]);
    tools.extend(diagnostic_tools());
    tools.extend(catalogue_tools());
    tools
}

fn tool(name: &str, description: &str, parameters: serde_json::Value) -> FunctionObject {
    use async_openai::types::FunctionObjectArgs;
    FunctionObjectArgs::default()
        .name(name)
        .description(description)
        .parameters(parameters)
        .build()
        .expect("valid tool definition")
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
                "list_os_images",
                "get_terms_of_service"
            ]
        );
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

    #[test]
    fn check_vm_port_requires_a_port() {
        let params = check_vm_port().parameters.expect("parameters");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "vm_id"));
        assert!(required.iter().any(|v| v == "port"));
        // The family selector is a hint, never mandatory.
        assert!(!required.iter().any(|v| v == "ipv6"));
        assert!(params["properties"]["ipv6"].is_object());
    }

    #[test]
    fn support_tools_include_billing_actions() {
        let tools = support_tools();
        let names = names(&tools);
        for expected in ["extend_vm", "refund_vm", "delete_vm", "get_my_account"] {
            assert!(names.contains(&expected), "missing {expected}");
        }
    }

    /// Live chat must never be offered the money/data-destroying tools.
    #[test]
    fn live_chat_tools_exclude_destructive_actions() {
        let tools = live_chat_tools();
        let names = names(&tools);
        for forbidden in ["extend_vm", "refund_vm", "delete_vm"] {
            assert!(
                !names.contains(&forbidden),
                "{forbidden} must not be exposed to live chat"
            );
        }
        for expected in ["start_vm", "stop_vm", "restart_vm", "list_my_vms"] {
            assert!(names.contains(&expected), "missing {expected}");
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

    #[test]
    fn vm_scoped_tools_require_vm_id() {
        let spec = get_vm_details();
        let params = spec.parameters.expect("parameters");
        assert_eq!(params["required"][0], "vm_id");
    }

    #[test]
    fn extend_vm_requires_days() {
        let params = extend_vm().parameters.expect("parameters");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "days"));
    }

    #[test]
    fn nullary_tools_have_no_required_args() {
        let params = list_regions().parameters.expect("parameters");
        assert!(params.get("required").is_none());
    }
}
