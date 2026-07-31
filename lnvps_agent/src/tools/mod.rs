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

// ── Tool sets ───────────────────────────────────────────────────────

/// Catalogue tools that expose no customer data and need no authentication.
fn catalogue_tools() -> Vec<FunctionObject> {
    vec![list_regions(), list_templates(), list_os_images()]
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
            vec!["list_regions", "list_templates", "list_os_images"]
        );
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
