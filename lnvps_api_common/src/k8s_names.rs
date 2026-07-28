//! Kubernetes object names for managed app deployments.
//!
//! The operator renders these objects and the API stores the namespace on the
//! deployment row, so the formats are a contract between two crates rather
//! than an operator detail. Metrics and usage attribution also parse or
//! reconstruct them: a name built inline somewhere else silently stops
//! matching instead of failing to compile.

/// The namespace a deployment's objects live in.
pub fn deployment_namespace(deployment_id: u64) -> String {
    format!("app-{deployment_id}")
}

/// The deployment id a namespace belongs to, if it is one of ours.
pub fn deployment_id_from_namespace(ns: &str) -> Option<u64> {
    let id: u64 = ns.strip_prefix("app-")?.parse().ok()?;
    // Round-trip so only the canonical spelling matches: `app-007` parses as 7
    // but is not a namespace anything here ever created.
    (deployment_namespace(id) == ns).then_some(id)
}

/// Placeholder namespace held between insert and the row getting its id.
///
/// The column is unique and the final name needs an id the insert has not
/// returned yet, so this reserves the row against the line item instead.
pub fn pending_deployment_namespace(line_item_id: u64) -> String {
    format!("app-pending-{line_item_id}")
}

/// PVC (and pod volume) name for a compose volume.
///
/// Not injective: service `a` volume `b-data` and service `a-b` volume `data`
/// produce the same name. Resolve a claim back to a volume through the compose
/// service/volume pairs, never by splitting on the dash.
pub fn deployment_volume(service: &str, volume: &str) -> String {
    format!("{service}-{volume}")
}

/// ConfigMap holding a service's non-sensitive files.
pub fn deployment_files_configmap(service: &str) -> String {
    format!("{service}-files")
}

/// Secret holding a service's generated values and sensitive files.
pub fn deployment_secret(service: &str) -> String {
    format!("{service}-secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These names are written to the database and to a live cluster, so a
    /// changed format orphans existing objects rather than renaming them.
    #[test]
    fn names_keep_their_wire_format() {
        assert_eq!(deployment_namespace(7), "app-7");
        assert_eq!(pending_deployment_namespace(42), "app-pending-42");
        assert_eq!(deployment_volume("web", "data"), "web-data");
        assert_eq!(deployment_files_configmap("web"), "web-files");
        assert_eq!(deployment_secret("web"), "web-secret");
    }

    #[test]
    fn namespace_round_trips_only_in_its_canonical_spelling() {
        assert_eq!(deployment_id_from_namespace("app-12"), Some(12));
        assert_eq!(deployment_id_from_namespace("app-007"), None);
        assert_eq!(deployment_id_from_namespace("app-"), None);
        assert_eq!(deployment_id_from_namespace("kube-system"), None);
        assert_eq!(deployment_id_from_namespace("myapp-1"), None);
        assert_eq!(
            deployment_id_from_namespace(&pending_deployment_namespace(3)),
            None
        );
    }

    #[test]
    fn volume_name_is_not_injective() {
        assert_eq!(
            deployment_volume("a", "b-data"),
            deployment_volume("a-b", "data")
        );
    }
}
