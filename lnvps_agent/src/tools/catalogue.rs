//! Tools describing what LNVPS sells: regions, plans, custom pricing, quotes,
//! exchange rates, OS images, the managed-app catalogue, and the terms.
//!
//! Every tool in this module is offered to logged-out visitors, so none may
//! take an account-scoped identifier — a test in the parent module enforces
//! that. Pricing questions are the reason the set exists: an agent that cannot
//! read a price answers from memory, which is how a wrong price reaches a
//! customer.

use async_openai::types::FunctionObject;
use serde_json::json;

use super::{nullary, tool};

pub fn list_regions() -> FunctionObject {
    nullary(
        "list_regions",
        "List all available hosting regions with their names, IDs and the operating company (name and country) that bills VMs in that region. Use this to answer questions about where VMs can be provisioned, where an existing VM is located, or who the contracting entity is.",
    )
}

pub fn list_templates() -> FunctionObject {
    nullary(
        "list_templates",
        "List the fixed VM plans that can be ordered, with full specifications AND price. Each entry gives CPU cores, memory, disk size/type/interface, included IPv4/IPv6 addresses, CPU architecture/manufacturer/features, any disk IOPS, disk throughput, network bandwidth or CPU limits, the region, and the cost plan (amount, currency, billing interval) plus conversions to other currencies. Use this for ANY question about what plans exist or what they cost.",
    )
}

pub fn list_custom_pricing() -> FunctionObject {
    nullary(
        "list_custom_pricing",
        "List the 'build your own' (custom VM) pricing available per region: the price per CPU core, per GB of memory, per GB of each disk type/interface, and per IPv4/IPv6 address, together with the minimum and maximum each configuration allows. Custom VMs bill monthly. Use this when a customer asks for a spec that no fixed plan matches, or asks how custom pricing works — then use price_custom_vm to quote an exact configuration.",
    )
}

pub fn price_custom_vm() -> FunctionObject {
    tool(
        "price_custom_vm",
        "Quote the monthly price of a specific custom (build your own) VM configuration. Validates the spec against the region's allowed limits and returns the per-component breakdown plus the total, with conversions to other currencies. Call list_custom_pricing first to get a pricing_id and the allowed ranges.",
        json!({
            "type": "object",
            "properties": {
                "pricing_id": {
                    "type": "integer",
                    "description": "Custom pricing id from list_custom_pricing (selects the region)"
                },
                "cpu": { "type": "integer", "description": "Number of CPU cores" },
                "memory_gb": { "type": "number", "description": "Memory in gigabytes" },
                "disk_gb": { "type": "number", "description": "Disk size in gigabytes" },
                "disk_type": {
                    "type": "string",
                    "description": "Disk type: 'ssd' or 'hdd'. Defaults to the first disk option in the pricing."
                },
                "disk_interface": {
                    "type": "string",
                    "description": "Disk interface: 'pcie', 'scsi' or 'sata'. Defaults to the first disk option in the pricing."
                },
                "ip4_count": {
                    "type": "integer",
                    "description": "IPv4 addresses to include. Defaults to the pricing minimum."
                },
                "ip6_count": {
                    "type": "integer",
                    "description": "IPv6 addresses to include. Defaults to the pricing minimum."
                }
            },
            "required": ["pricing_id", "cpu", "memory_gb", "disk_gb"]
        }),
    )
}

pub fn get_exchange_rate() -> FunctionObject {
    tool(
        "get_exchange_rate",
        "Convert a money amount between the currencies LNVPS supports (e.g. EUR, USD, BTC). Use this when a customer asks what a listed price is in their own currency or in bitcoin — never do the conversion yourself.",
        json!({
            "type": "object",
            "properties": {
                "from": { "type": "string", "description": "Source currency code, e.g. 'EUR' or 'BTC'" },
                "to": { "type": "string", "description": "Target currency code, e.g. 'USD' or 'BTC'" },
                "amount": {
                    "type": "number",
                    "description": "Amount in major units of the source currency (euros, dollars, whole bitcoin). Defaults to 1."
                }
            },
            "required": ["from", "to"]
        }),
    )
}

pub fn list_os_images() -> FunctionObject {
    nullary(
        "list_os_images",
        "List all operating system images that can be installed on a VM. Shows distribution, flavour, version, CPU architecture, release date and the default login username.",
    )
}

pub fn list_apps() -> FunctionObject {
    nullary(
        "list_apps",
        "List the managed applications LNVPS hosts for customers (one-click deployments such as Nostr relays and media servers), with their price, billing interval, setup fee, category, tags and resource footprint. These are managed deployments on LNVPS's Kubernetes clusters, NOT VMs — the customer does not administer a server.",
    )
}

pub fn get_app_details() -> FunctionObject {
    tool(
        "get_app_details",
        "Get one managed application from the catalogue by id or by name, including its price and — computed from real cluster capacity — the regions it can currently be deployed to. Use this before telling a customer an app is available somewhere.",
        json!({
            "type": "object",
            "properties": {
                "app_id": { "type": "integer", "description": "Catalogue app id, from list_apps" },
                "name": {
                    "type": "string",
                    "description": "Catalogue app slug (e.g. 'nostr-relay'), if the id is not known"
                }
            }
        }),
    )
}

pub fn list_app_tags() -> FunctionObject {
    nullary(
        "list_app_tags",
        "List the categories (tags) used to group the managed application catalogue, with how many apps carry each. Use this to answer 'what kinds of apps do you host?' before listing every app.",
    )
}

pub fn get_terms_of_service() -> FunctionObject {
    nullary(
        "get_terms_of_service",
        "Fetch the current LNVPS Terms of Service and Acceptable Use Policy as plain text. Use this for ANY question about what is allowed, refunds, suspension, abuse handling, liability, data retention, or company details — quote the document rather than answering from memory.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_custom_vm_requires_a_full_spec() {
        let params = price_custom_vm().parameters.expect("parameters");
        let required = params["required"].as_array().unwrap();
        for key in ["pricing_id", "cpu", "memory_gb", "disk_gb"] {
            assert!(required.iter().any(|v| v == key), "{key} must be required");
        }
        // Disk selection and IP counts fall back to the pricing defaults.
        for key in ["disk_type", "disk_interface", "ip4_count", "ip6_count"] {
            assert!(!required.iter().any(|v| v == key), "{key} must be optional");
            assert!(params["properties"][key].is_object());
        }
    }

    #[test]
    fn get_exchange_rate_requires_both_currencies() {
        let params = get_exchange_rate().parameters.expect("parameters");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "from"));
        assert!(required.iter().any(|v| v == "to"));
        assert!(!required.iter().any(|v| v == "amount"));
    }

    /// Either identifier works, so neither may be mandatory — a `required`
    /// here would make the model invent the one it does not have.
    #[test]
    fn get_app_details_accepts_either_identifier() {
        let params = get_app_details().parameters.expect("parameters");
        assert!(params.get("required").is_none());
        assert!(params["properties"]["app_id"].is_object());
        assert!(params["properties"]["name"].is_object());
    }
}
