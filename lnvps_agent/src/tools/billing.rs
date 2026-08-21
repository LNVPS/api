//! Tools for the objects that actually bill: subscriptions, their payments and
//! the IP-space products.
//!
//! A VM's payments are reachable through `list_vm_payments`, but that answers
//! only for one VM. The subscription is what expires, renews and carries
//! auto-renewal, and an account can hold several — including products that are
//! not VMs at all.

use async_openai::types::FunctionObject;

use super::{id_scoped, nullary};

/// Build a spec taking a single required `subscription_id`.
fn subscription_scoped(name: &str, description: &str) -> FunctionObject {
    id_scoped(
        name,
        description,
        "subscription_id",
        "The numeric subscription ID, from list_my_subscriptions",
    )
}

pub fn list_my_subscriptions() -> FunctionObject {
    nullary(
        "list_my_subscriptions",
        "List every subscription on the current user's account with its billing state, expiry, currency, billing interval, auto-renewal setting and the line items it bills for (each resolved to the VM, app deployment, IP range or ASN it pays for). Use this for any question about renewals, expiry or what a customer is being charged for — a customer may hold several subscriptions, and only this shows all of them. 'unpaid' means the first payment never settled; 'expired' means it was paid and has lapsed — they need opposite answers.",
    )
}

pub fn get_subscription_details() -> FunctionObject {
    subscription_scoped(
        "get_subscription_details",
        "Get one subscription owned by the current user, with its line items and what each one bills for.",
    )
}

pub fn list_subscription_payments() -> FunctionObject {
    subscription_scoped(
        "list_subscription_payments",
        "List payments against one subscription owned by the current user: amount, tax, processing fee, currency, method, paid status and dates. Use this to explain what was charged and when, or why a renewal has not been credited.",
    )
}

pub fn list_my_ip_subscriptions() -> FunctionObject {
    nullary(
        "list_my_ip_subscriptions",
        "List the current user's IP-space products: leased IP ranges (BYOIP/LIR, with CIDR, origin ASN and whether the announcement is active) and sponsored ASNs (with registry and assignment status). Nothing to do with the IPv4/IPv6 addresses attached to a VM — use get_vm_details for those.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_scoped_tools_require_a_subscription_id() {
        for spec in [get_subscription_details(), list_subscription_payments()] {
            let name = spec.name.clone();
            let params = spec.parameters.expect("parameters");
            assert_eq!(params["required"][0], "subscription_id", "{name}");
        }
    }

    /// The account-wide listings must not take an id: the executor is bound to
    /// one user already.
    #[test]
    fn account_wide_listings_take_no_arguments() {
        for spec in [list_my_subscriptions(), list_my_ip_subscriptions()] {
            let params = spec.parameters.expect("parameters");
            assert!(params["properties"].as_object().unwrap().is_empty());
        }
    }
}
