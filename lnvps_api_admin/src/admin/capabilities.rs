use axum::Router;
use axum::routing::get;
use lnvps_api_common::{ApiData, ApiError, ApiResult};
use serde::Serialize;

use crate::admin::RouterState;
use crate::admin::auth::AdminAuth;

pub const VM_MIGRATE_VERSION: u32 = 2;
pub const VM_MIGRATE_OPTIONS: [&str; 5] = [
    "ip_policy",
    "keep_source",
    "target_disk_id",
    "dry_run",
    "timeout_secs_per_gb",
];

pub fn router() -> Router<RouterState> {
    Router::new().route("/api/admin/v1/capabilities", get(admin_capabilities))
}

#[derive(Serialize)]
pub struct VmMigrateCapability {
    pub version: u32,
    pub options: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct AdminCapabilities {
    pub vm_migrate: VmMigrateCapability,
}

impl AdminCapabilities {
    pub fn current() -> Self {
        Self {
            vm_migrate: VmMigrateCapability {
                version: VM_MIGRATE_VERSION,
                options: VM_MIGRATE_OPTIONS.to_vec(),
            },
        }
    }
}

async fn admin_capabilities(auth: AdminAuth) -> ApiResult<AdminCapabilities> {
    if auth.permissions.is_empty() {
        return Err(ApiError::forbidden("Admin permission required"));
    }
    ApiData::ok(AdminCapabilities::current())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::model::Permission;
    use lnvps_db::{AdminAction, AdminResource};

    fn auth(permissions: Vec<Permission>) -> AdminAuth {
        AdminAuth {
            user_id: 1,
            pubkey: vec![1u8; 32],
            permissions: permissions.into_iter().collect(),
            nip98_auth: None,
            step_up: false,
        }
    }

    #[tokio::test]
    async fn capabilities_list_vm_migrate_options() {
        let a = auth(vec![Permission {
            resource: AdminResource::Users,
            action: AdminAction::View,
        }]);
        let out = admin_capabilities(a).await.unwrap();
        let body = serde_json::to_value(&out.0.data).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"vm_migrate": {"version": 2, "options": [
                "ip_policy", "keep_source", "target_disk_id", "dry_run", "timeout_secs_per_gb"
            ]}})
        );
    }

    #[tokio::test]
    async fn capabilities_require_admin_permission() {
        let err = admin_capabilities(auth(vec![])).await.err().unwrap();
        assert!(err.error.contains("Admin permission"), "{}", err.error);
    }
}
