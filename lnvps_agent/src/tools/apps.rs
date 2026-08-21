//! Tools for the customer's managed app deployments.
//!
//! The catalogue side of managed apps lives in [`super::catalogue`] because it
//! needs no account; everything here is scoped to one customer's deployments.
//! Start and stop are included for the same reason the VM power tools are:
//! they are reversible, destroy nothing, and the customer can already make the
//! same change through the REST API.

use async_openai::types::FunctionObject;

use super::{id_scoped, nullary};

/// Build a spec taking a single required `deployment_id`.
fn deployment_scoped(name: &str, description: &str) -> FunctionObject {
    id_scoped(
        name,
        description,
        "deployment_id",
        "The numeric deployment ID, from list_my_app_deployments",
    )
}

pub fn list_my_app_deployments() -> FunctionObject {
    nullary(
        "list_my_app_deployments",
        "List the managed application deployments belonging to the current user: app, region, hostname, any custom domain and whether it has been verified, the state the customer asked for, the state the cluster reports, resource usage and billing state. Managed apps are not VMs — they have no console and no SSH.",
    )
}

pub fn get_app_deployment_details() -> FunctionObject {
    deployment_scoped(
        "get_app_deployment_details",
        "Get one managed app deployment owned by the current user. Report both desired_state (what the customer asked for) and status (what the cluster did): 'error' carries the reason in status_message, and 'stopped' with an unpaid billing state means it is awaiting payment rather than stopped by the customer.",
    )
}

pub fn start_app_deployment() -> FunctionObject {
    deployment_scoped(
        "start_app_deployment",
        "Start a managed app deployment owned by the current user (sets its desired state to running). Reversible. The cluster reconciles asynchronously, so the reported status may take a minute to follow. This does not pay an outstanding invoice — a deployment that has never been paid for will not start.",
    )
}

pub fn stop_app_deployment() -> FunctionObject {
    deployment_scoped(
        "stop_app_deployment",
        "Stop a managed app deployment owned by the current user (sets its desired state to stopped, scaling it to zero replicas). Confirm with the customer first — the app goes offline. Data volumes are kept and billing continues; stopping is not cancelling.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_tools_require_a_deployment_id() {
        for spec in [
            get_app_deployment_details(),
            start_app_deployment(),
            stop_app_deployment(),
        ] {
            let name = spec.name.clone();
            let params = spec.parameters.expect("parameters");
            assert_eq!(params["required"][0], "deployment_id", "{name}");
        }
    }

    /// Stopping takes an app offline, so the spec must say so — the model has
    /// nothing else to go on when deciding whether to confirm first.
    #[test]
    fn stop_warns_and_start_does_not() {
        assert!(
            stop_app_deployment()
                .description
                .unwrap()
                .contains("Confirm with the customer")
        );
        assert!(
            list_my_app_deployments().parameters.expect("parameters")["properties"]
                .as_object()
                .unwrap()
                .is_empty()
        );
    }
}
