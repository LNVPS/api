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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient permissions"));
    }

    #[tokio::test]
    async fn test_no_role_denied_vms() {
        setup_rbac().await;
        let client = admin_client_with_keys(no_role_keys().clone());
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A vm_manager has VM Delete permission but is not a super_admin, so it
    /// cannot request a permanent purge (`purge = true`). The purge
    /// authorization is checked before the VM lookup, so a non-existent VM id
    /// still yields 403 rather than 404.
    #[tokio::test]
    async fn test_vm_manager_cannot_purge_vm() {
        setup_rbac().await;
        let client = admin_client_with_keys(vm_manager_keys().clone());
        let body = serde_json::json!({ "purge": true });
        let resp = client
            .delete_auth_body("/api/admin/v1/vms/999999999", &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let text = resp.text().await.unwrap();
        assert!(text.contains("Only super admins can permanently purge"));
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Insufficient permissions"));
    }

    /// Catalog SEO metadata is admin-only data (issue #239): writing it needs
    /// `app::create` / `app::update`, which `read_only` does not carry. The
    /// permission check runs before request validation, so a body that is
    /// invalid anyway still yields 403 rather than leaking that it was.
    #[tokio::test]
    async fn test_read_only_cannot_write_app_category() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());

        let create = serde_json::json!({
            "name": "e2e-rbac-seo",
            "display_name": "RBAC SEO",
            "category": "Nostr relay",
            "compose": "services:\n  relay:\n    image: example/relay:latest\n",
            "amount": 1000,
            "currency": "usd",
            "interval_amount": 1,
            "interval_type": "month",
            "setup_amount": 0
        });
        let resp = client
            .post_auth("/api/admin/v1/apps", &create)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.text().await.unwrap().contains("Insufficient permissions"));

        // Same for patching an existing app's category — 403 before the lookup,
        // so a non-existent id is still 403 and not 404.
        let resp = client
            .patch_auth(
                "/api/admin/v1/apps/999999999",
                &serde_json::json!({ "category": "Personal Nostr relay" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // `App` permissions were only ever granted to super_admin
        // (20260724150132_app_rbac_permissions.sql), so read_only cannot even
        // view the catalog through the admin API — the customer-facing
        // `GET /api/v1/apps` is the public read surface (#227).
        let resp = client.get_auth("/api/admin/v1/apps").await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // super_admin does carry them, so the same create succeeds there —
        // this is a permission boundary, not a broken route.
        let admin = admin_client_with_keys(super_admin_keys().clone());
        let resp = admin.post_auth("/api/admin/v1/apps", &create).await.unwrap();
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST,
            "super_admin reaches validation, not the permission gate: {}",
            resp.status()
        );
        if resp.status() == StatusCode::OK {
            let body: serde_json::Value =
                serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            let id = body["data"]["id"].as_u64().expect("app id");
            assert_eq!(body["data"]["category"].as_str(), Some("Nostr relay"));
            let _ = admin.delete_auth(&format!("/api/admin/v1/apps/{id}")).await;
        }
    }

    /// The tag vocabulary reuses `AdminResource::App` (issue #240), so it is
    /// gated by exactly the permissions the catalog already had — no new enum
    /// value and no RBAC migration. `read_only` therefore cannot read or write
    /// any of it, while the public facet endpoint stays open to everyone.
    #[tokio::test]
    async fn test_read_only_cannot_manage_app_tags() {
        setup_rbac().await;
        let client = admin_client_with_keys(read_only_keys().clone());

        // View is `app::view`, which only super_admin holds — so even reading
        // the vocabulary through the admin API is 403.
        let resp = client.get_auth("/api/admin/v1/app-tags").await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = client.get_auth("/api/admin/v1/app-tags/1").await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": "e2e-rbac-tag", "display_name": "RBAC" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.text().await.unwrap().contains("Insufficient permissions"));

        // Patch and delete are checked before the lookup, so a non-existent id
        // is still 403 and not 404 — the permission gate must not double as an
        // existence oracle.
        let resp = client
            .patch_auth(
                "/api/admin/v1/app-tags/999999999",
                &serde_json::json!({ "display_name": "RBAC" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = client
            .delete_auth("/api/admin/v1/app-tags/999999999")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Assigning tags to an app rides on the app's own create/update
        // permissions, which read_only also lacks.
        let resp = client
            .patch_auth(
                "/api/admin/v1/apps/999999999",
                &serde_json::json!({ "tags": ["nostr"] }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // super_admin does hold them, so the same create reaches validation —
        // this is a permission boundary, not a broken route.
        let admin = admin_client_with_keys(super_admin_keys().clone());
        let slug = format!(
            "e2e-rbac-{}",
            &nostr::Keys::generate().public_key().to_hex()[..8]
        );
        let resp = admin
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": &slug, "display_name": "RBAC" }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let id = body["data"]["id"].as_u64().expect("tag id");
        let _ = admin
            .delete_auth(&format!("/api/admin/v1/app-tags/{id}"))
            .await;

        // The public facet endpoint is unauthenticated, like the catalog it
        // describes (#227) — the admin gate above must not have closed it.
        let resp = crate::client::user_client_no_auth()
            .get("/api/v1/app-tags")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// `app_deployment::delete` is enough to delete a deployment but not to
    /// purge one — that stays super_admin-only. Like the VM purge, the check
    /// runs before the lookup, so a non-existent id still yields 403.
    #[tokio::test]
    async fn test_app_deleter_cannot_purge_app_deployment() {
        setup_rbac().await;

        // A role that can delete deployments but is not super_admin.
        let admin = admin_client_with_keys(super_admin_keys().clone());
        let role_name = "e2e-app-deleter";
        let create = serde_json::json!({
            "name": role_name,
            "description": "E2E: delete but not purge deployments",
            "permissions": ["app_deployment::view", "app_deployment::delete"]
        });
        let resp = admin
            .post_auth("/api/admin/v1/roles", &create)
            .await
            .unwrap();
        // The role survives between runs against the same database.
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST,
            "unexpected role create status: {}",
            resp.status()
        );

        let keys = Keys::generate();
        let pool = db::connect().await.unwrap();
        db::ensure_user_with_role(&pool, &keys, role_name)
            .await
            .unwrap();
        pool.close().await;

        let client = admin_client_with_keys(keys);
        let resp = client
            .delete_auth_body(
                "/api/admin/v1/app-deployments/999999999",
                &serde_json::json!({ "purge": true }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            resp.text()
                .await
                .unwrap()
                .contains("Only super admins can permanently purge")
        );

        // The same role reaches the lookup on a plain delete (404, not 403).
        let resp = client
            .delete_auth_body(
                "/api/admin/v1/app-deployments/999999999",
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
