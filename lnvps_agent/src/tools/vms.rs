//! Tools that read or act on one of the customer's VMs.
//!
//! Every spec here takes a `vm_id`, which is the one argument in the whole
//! surface a customer can freely choose. Ownership is therefore re-checked in
//! the executor on every call, never assumed from the fact the model was
//! offered the tool.

use async_openai::types::FunctionObject;

use super::{id_scoped, nullary};

/// Build a spec taking a single required `vm_id`.
pub(crate) fn vm_scoped(name: &str, description: &str) -> FunctionObject {
    id_scoped(name, description, "vm_id", "The numeric VM ID")
}

pub fn list_my_vms() -> FunctionObject {
    nullary(
        "list_my_vms",
        "List all VMs belonging to the current user. Shows VM IDs, names, status, specs, IPs, expiry dates, and region info.",
    )
}

pub fn get_vm_details() -> FunctionObject {
    vm_scoped(
        "get_vm_details",
        "Get detailed information about a specific VM owned by the current user. Includes host, region, IP assignments, full specs, payment status, and exact expiry date.",
    )
}

pub fn list_vm_payments() -> FunctionObject {
    vm_scoped(
        "list_vm_payments",
        "List all payments for a specific VM owned by the current user. Shows amounts, currencies, paid/unpaid status, dates, and payment methods.",
    )
}

pub fn list_vm_history() -> FunctionObject {
    vm_scoped(
        "list_vm_history",
        "List the activity history for a specific VM. Shows creation, start/stop events, reinstallations, upgrades, and configuration changes with timestamps.",
    )
}

pub fn list_vm_firewall_rules() -> FunctionObject {
    vm_scoped(
        "list_vm_firewall_rules",
        "List the LNVPS-managed firewall rules and default in/out policy for a VM owned by the current user. Check this whenever a port is unreachable: a rule the customer added drops traffic in a way that looks identical, from outside, to nothing listening. This is the network-level firewall only — it says nothing about a firewall running inside the VM.",
    )
}

pub fn get_vm_metrics() -> FunctionObject {
    vm_scoped(
        "get_vm_metrics",
        "Get hourly CPU, memory, disk and network usage samples for a VM owned by the current user, read from the hypervisor. Use this when a customer reports their VM is slow, out of memory or using unexpected bandwidth — the network probes only say whether it answers, not how hard it is working.",
    )
}

pub fn start_vm() -> FunctionObject {
    vm_scoped(
        "start_vm",
        "Power on a VM owned by the current user. Safe and reversible — use when the customer reports their VM is offline or asks to boot it.",
    )
}

pub fn stop_vm() -> FunctionObject {
    vm_scoped(
        "stop_vm",
        "Power off a VM owned by the current user. Confirm with the customer first, as running services will be interrupted.",
    )
}

pub fn restart_vm() -> FunctionObject {
    vm_scoped(
        "restart_vm",
        "Hard reset (restart) a VM owned by the current user. Confirm with the customer first. Often resolves an unresponsive VM.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_scoped_tools_require_vm_id() {
        for spec in [
            get_vm_details(),
            list_vm_payments(),
            list_vm_history(),
            list_vm_firewall_rules(),
            get_vm_metrics(),
            start_vm(),
            stop_vm(),
            restart_vm(),
        ] {
            let name = spec.name.clone();
            let params = spec.parameters.expect("parameters");
            assert_eq!(params["required"][0], "vm_id", "{name}");
        }
    }
}
