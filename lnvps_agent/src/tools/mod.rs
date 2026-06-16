use async_openai::types::FunctionObject;
use serde_json::json;

/// All tools the support agent has access to, defined as OpenAI function specs.
/// These are user-scoped — no tool accepts a pubkey or user_id parameter;
/// the executor is already bound to the user identified by the support channel.
pub fn support_tools() -> Vec<FunctionObject> {
    vec![
        tool(
            "get_my_account",
            "Get the current user's account information: billing details, contact preferences, email verification status, and NWC auto-renewal status.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "list_my_vms",
            "List all VMs belonging to the current user. Shows VM IDs, names, status, specs, IPs, expiry dates, and region info.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "get_vm_details",
            "Get detailed information about a specific VM owned by the current user. Includes host, region, IP assignments, full specs, payment status, and exact expiry date.",
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
        ),
        tool(
            "list_vm_payments",
            "List all payments for a specific VM owned by the current user. Shows amounts, currencies, paid/unpaid status, dates, and payment methods.",
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
        ),
        tool(
            "list_vm_history",
            "List the activity history for a specific VM. Shows creation, start/stop events, reinstallations, upgrades, and configuration changes with timestamps.",
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
        ),
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
        ),
        tool(
            "refund_vm",
            "Process a refund for a VM. This is irreversible — always confirm with the user before executing. Only works on VMs owned by the current user.",
            json!({
                "type": "object",
                "properties": {
                    "vm_id": {
                        "type": "integer",
                        "description": "The numeric VM ID to refund"
                    }
                },
                "required": ["vm_id"]
            }),
        ),
        tool(
            "delete_vm",
            "Delete a VM owned by the current user. Use this only when explicitly requested and after confirming with the customer.",
            json!({
                "type": "object",
                "properties": {
                    "vm_id": {
                        "type": "integer",
                        "description": "The numeric VM ID to delete"
                    }
                },
                "required": ["vm_id"]
            }),
        ),
        tool(
            "list_regions",
            "List all available hosting regions with their names and IDs. Use this to answer questions about where VMs can be provisioned or where an existing VM is located.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "list_templates",
            "List all available VM templates with specifications and pricing. Shows CPU, memory, storage, pricing plans, and which region each template belongs to. Use this to answer questions about available plans and pricing.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "list_os_images",
            "List all available operating system images that can be installed on VMs. Shows image names, versions, OS types, and supported platforms.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
    ]
}

/// Tools available to non-customer/general support requests.
/// Subset of support_tools that don't require an authenticated user.
pub fn public_tools() -> Vec<FunctionObject> {
    vec![
        tool(
            "list_regions",
            "List all available hosting regions with their names and IDs. Use this to answer questions about where VMs can be provisioned.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "list_templates",
            "List all available VM templates with specifications and pricing. Shows CPU, memory, storage, pricing plans, and which region each template belongs to. Use this to answer questions about available plans and pricing.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
        tool(
            "list_os_images",
            "List all available operating system images that can be installed on VMs. Shows image names, versions, OS types, and supported platforms.",
            json!({
                "type": "object",
                "properties": {}
            }),
        ),
    ]
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
