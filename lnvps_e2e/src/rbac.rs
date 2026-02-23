//! RBAC permission tests for the admin API.
//!
//! These tests verify that different admin roles grant the correct
//! level of access and that users without roles are denied.

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use nostr::Keys;
    use reqwest::StatusCode;

    use crate::client::*;
    use crate::db;

    // ========================================================================
    // Stable per-role keys (one user per role for the entire test run)
    // ========================================================================

    fn no_role_keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(Keys::generate)
    }

    fn read_only_keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(Keys::generate)
    }

    fn vm_manager_keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(Keys::generate)
    }

    fn payment_manager_keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(Keys::generate)
    }

    fn super_admin_keys() -> &'static Keys {
        static K: OnceLock<Keys> = OnceLock::new();
        K.get_or_init(Keys::generate)
    }

    /// Bootstrap all RBAC test users once. Idempotent.
    async fn setup_rbac() {
        // Also ensure the main admin is set up (other test modules depend on it)
        bootstrap_admin().await.unwrap();

        let pool = db::connect().await.unwrap();
        // no-role user: just ensure the row exists, no role assigned
        db::ensure_user(&pool, no_role_keys()).await.unwrap();
        db::ensure_user_with_role(&pool, read_only_keys(), "read_only")
            .await
            .unwrap();
        db::ensure_user_with_role(&pool, vm_manager_keys(), "vm_manager")
            .await
            .unwrap();
        db::ensure_user_with_role(&pool, payment_manager_keys(), "payment_manager")
            .await
            .unwrap();
        db::ensure_user_with_role(&pool, super_admin_keys(), "super_admin")
            .await
            .unwrap();
        pool.close().await;
    }

    // ========================================================================
    // No-role user should be denied access to everything
    // ========================================================================

    #[tokio::test]
    async fn test_no_role_denied_users() {
        setup_rbac().await;
        let client = admin_client_with_keys(no_role_keys().clone());
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient permissions"));
    }

    #[tokio::test]
    async fn test_no_role_denied_vms() {
        setup_rbac().await;
        let client = admin_client_with_keys(no_role_keys().clone());
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient permissions"));
    }

    // ========================================================================
    // read_only role: can view, cannot create/update/delete
    // ========================================================================

    #[tokio::test]
    async fn test_read_only_can_view_users() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_read_only_can_view_vms() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_read_only_can_view_hosts() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());
        let resp = client.get_auth("/api/admin/v1/hosts").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_read_only_cannot_create_region() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());
        let body = serde_json::json!({
            "name": "rbac-test-region",
            "enabled": false,
            "company_id": 1
        });
        let resp = client
            .post_auth("/api/admin/v1/regions", &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let text = resp.text().await.unwrap();
        assert!(text.contains("Insufficient permissions"));
    }

    #[tokio::test]
    async fn test_read_only_cannot_create_role() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());
        let body = serde_json::json!({
            "name": "rbac-fake-role",
            "permissions": ["users::view"]
        });
        let resp = client
            .post_auth("/api/admin/v1/roles", &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ========================================================================
    // vm_manager role: can manage VMs/hosts, cannot manage roles
    // ========================================================================

    #[tokio::test]
    async fn test_vm_manager_can_view_vms() {
        setup_rbac().await;
        let client = admin_client_with_keys(vm_manager_keys().clone());
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_vm_manager_can_view_hosts() {
        setup_rbac().await;
        let client = admin_client_with_keys(vm_manager_keys().clone());
        let resp = client.get_auth("/api/admin/v1/hosts").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_vm_manager_can_view_users() {
        setup_rbac().await;
        let client = admin_client_with_keys(vm_manager_keys().clone());
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_vm_manager_cannot_create_role() {
        setup_rbac().await;
        let client = admin_client_with_keys(vm_manager_keys().clone());
        let body = serde_json::json!({
            "name": "rbac-fake-role-2",
            "permissions": ["users::view"]
        });
        let resp = client
            .post_auth("/api/admin/v1/roles", &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ========================================================================
    // super_admin role: full access
    // ========================================================================

    #[tokio::test]
    async fn test_super_admin_can_view_users() {
        setup_rbac().await;
        let client = admin_client_with_keys(super_admin_keys().clone());
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_super_admin_can_create_and_delete_role() {
        setup_rbac().await;
        let client = admin_client_with_keys(super_admin_keys().clone());

        let body = serde_json::json!({
            "name": "rbac-e2e-super-test",
            "permissions": ["users::view"]
        });
        let resp = client
            .post_auth("/api/admin/v1/roles", &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let role_id = data["data"]["id"].as_u64().unwrap();

        let resp = client
            .delete_auth(&format!("/api/admin/v1/roles/{role_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // payment_manager role: can manage payments, cannot manage VMs
    // ========================================================================

    #[tokio::test]
    async fn test_payment_manager_cannot_view_vms() {
        setup_rbac().await;
        let client = admin_client_with_keys(payment_manager_keys().clone());
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_payment_manager_can_view_users() {
        setup_rbac().await;
        let client = admin_client_with_keys(payment_manager_keys().clone());
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Role removal: verify access is revoked when roles are removed.
    // This is the one test that needs a dedicated throwaway user.
    // ========================================================================

    #[tokio::test]
    async fn test_role_removal_revokes_access() {
        setup_rbac().await;
        let keys = Keys::generate();
        let pool = db::connect().await.unwrap();
        let user_id = db::ensure_user_with_role(&pool, &keys, "read_only")
            .await
            .unwrap();

        let client = admin_client_with_keys(keys);

        // Should work with read_only role
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Remove all roles
        db::remove_all_roles(&pool, user_id).await.unwrap();
        pool.close().await;

        // Should now be denied
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient permissions"));
    }
}
