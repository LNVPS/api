//! Network probe tools.
//!
//! No probe accepts a hostname or an address: each takes a `vm_id` that the
//! executor resolves through an ownership check, so support chat cannot be
//! steered into scanning a third party.

use async_openai::types::FunctionObject;
use serde_json::json;

use super::tool;

/// A VM-scoped probe that also takes an optional address family.
fn vm_probe(name: &str, description: &str) -> FunctionObject {
    tool(
        name,
        description,
        json!({
            "type": "object",
            "properties": {
                "vm_id": { "type": "integer", "description": "The numeric VM ID to probe" },
                "ipv6": {
                    "type": "boolean",
                    "description": "Probe the VM's IPv6 address instead of its IPv4 address. Defaults to false."
                }
            },
            "required": ["vm_id"]
        }),
    )
}

pub fn ping_vm() -> FunctionObject {
    vm_probe(
        "ping_vm",
        "Check whether a VM owned by the current user answers from the network edge. Returns reachability, packet loss and round-trip time. Use this first when a customer says their VM is unreachable or offline.",
    )
}

pub fn traceroute_vm() -> FunctionObject {
    vm_probe(
        "traceroute_vm",
        "Trace the network path from the LNVPS edge router to a VM owned by the current user. Returns every hop with loss and latency. Use this when ping_vm shows the VM unreachable or the customer reports packet loss, to see where the path breaks.",
    )
}

pub fn check_vm_port() -> FunctionObject {
    tool(
        "check_vm_port",
        "Test whether a TCP port on a VM owned by the current user accepts connections (e.g. 22 for SSH, 80/443 for web). Distinguishes 'open', 'refused' (VM up, nothing listening) and 'timeout' (filtered or down) — far more useful than ping when a specific service is unreachable.",
        json!({
            "type": "object",
            "properties": {
                "vm_id": { "type": "integer", "description": "The numeric VM ID to probe" },
                "port": { "type": "integer", "description": "TCP port to test (1-65535)" },
                "ipv6": {
                    "type": "boolean",
                    "description": "Probe the VM's IPv6 address instead of its IPv4 address. Defaults to false."
                }
            },
            "required": ["vm_id", "port"]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A probe that took a hostname would turn support chat into a scanner.
    #[test]
    fn probes_only_accept_a_vm_id() {
        for spec in [ping_vm(), traceroute_vm(), check_vm_port()] {
            let name = spec.name.clone();
            let params = spec.parameters.expect("parameters");
            let properties = params["properties"].as_object().unwrap();
            assert!(properties.contains_key("vm_id"), "{name}");
            for forbidden in ["host", "hostname", "ip", "address", "target"] {
                assert!(!properties.contains_key(forbidden), "{name}: {forbidden}");
            }
        }
    }
}
