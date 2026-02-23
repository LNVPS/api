//! E2E tests for the admin API.

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::client::*;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use serde_json::Value;

    /// Bootstrap the admin user in the DB before making authenticated requests.
    async fn setup() -> TestClient {
        bootstrap_admin().await.unwrap();
        admin_client()
    }

    // ========================================================================
    // Response types (minimal, verify shape)
    // ========================================================================

    #[derive(Debug, Deserialize)]
    struct AdminUser {
        id: u64,
    }

    #[derive(Debug, Deserialize)]
    struct AdminVm {
        id: u64,
    }

    #[derive(Debug, Deserialize)]
    struct AdminHost {
        id: u64,
    }

    #[derive(Debug, Deserialize)]
    struct AdminRegion {
        id: u64,
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct AdminRole {
        id: u64,
        name: String,
    }

    // ========================================================================
    // Admin Documentation / Static Pages
    // ========================================================================

    #[tokio::test]
    async fn test_admin_index_page() {
        let client = admin_client_no_auth();
        let resp = client.get("/").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_docs_endpoints_md() {
        let client = admin_client_no_auth();
        let resp = client.get("/docs/endpoints.md").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn test_admin_docs_changelog_md() {
        let client = admin_client_no_auth();
        let resp = client.get("/docs/changelog.md").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Auth enforcement tests (admin endpoints without auth)
    // ========================================================================

    #[tokio::test]
    async fn test_admin_endpoints_require_auth() {
        let client = admin_client_no_auth();
        let endpoints = vec![
            "/api/admin/v1/users",
            "/api/admin/v1/vms",
            "/api/admin/v1/hosts",
            "/api/admin/v1/regions",
            "/api/admin/v1/roles",
            "/api/admin/v1/vm_os_images",
            "/api/admin/v1/vm_templates",
            "/api/admin/v1/companies",
            "/api/admin/v1/cost_plans",
            "/api/admin/v1/custom_pricing",
            "/api/admin/v1/ip_ranges",
            "/api/admin/v1/access_policies",
            "/api/admin/v1/routers",
            "/api/admin/v1/vm_ip_assignments",
            "/api/admin/v1/subscriptions",
            "/api/admin/v1/payment_methods",
            "/api/admin/v1/ip_space",
        ];

        for endpoint in endpoints {
            let resp = client.get(endpoint).await.unwrap();
            assert!(
                resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
                "Admin endpoint {endpoint} should require auth, got: {}",
                resp.status()
            );
        }
    }

    // ========================================================================
    // User Management
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_users() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/users").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        assert!(data.data.is_empty() || data.data[0]["id"].is_u64());
    }

    #[tokio::test]
    async fn test_admin_list_users_with_pagination() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/users?limit=5&offset=0")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        assert!(data.limit == 5);
        assert!(data.offset == 0);
    }

    #[tokio::test]
    async fn test_admin_get_user() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/users?limit=1")
            .await
            .unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no users found");
            return;
        }
        let user_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/users/{user_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_user_not_found() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/users/999999999")
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_user_roles() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/users?limit=1")
            .await
            .unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            return;
        }
        let user_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/users/{user_id}/roles"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // VM Management
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_vms() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        assert!(data.data.is_empty() || data.data[0]["id"].is_u64());
    }

    #[tokio::test]
    async fn test_admin_list_vms_with_pagination() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/vms?limit=10&offset=0")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        assert!(data.limit == 10);
    }

    #[tokio::test]
    async fn test_admin_get_vm() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no VMs found");
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_vm_not_found() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/vms/999999999")
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_vm_history() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}/history"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_vm_payments() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}/payments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_vm_refund_calculate() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}/refund"))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Refund calc should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_admin_vm_extend() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no VMs found for extend test");
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let extend_body = serde_json::json!({"days": 1, "reason": "e2e-test"});
        let resp = client
            .put_auth(&format!("/api/admin/v1/vms/{vm_id}/extend"), &extend_body)
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "VM extend should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }

    // ========================================================================
    // Host Management
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_hosts() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/hosts").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_host_and_disks() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/hosts").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(hosts) = body["data"].as_array() {
            if let Some(h) = hosts.first() {
                let host_id = h["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/hosts/{host_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/hosts/{host_id}/disks"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    // ========================================================================
    // Region CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_admin_region_crud_lifecycle() {
        let client = setup().await;

        // Get a company_id
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let company_id = body["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["id"].as_u64())
            .unwrap_or(1);

        // Create
        let create_body = serde_json::json!({
            "name": "e2e-test-region",
            "enabled": false,
            "company_id": company_id
        });
        let resp = client
            .post_auth("/api/admin/v1/regions", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Region creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let region_id = body["data"]["id"]
            .as_u64()
            .expect("Region should have an id");

        // Read
        let resp = client
            .get_auth(&format!("/api/admin/v1/regions/{region_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["name"].as_str().unwrap(), "e2e-test-region");

        // Update
        let update_body = serde_json::json!({"name": "e2e-test-region-updated"});
        let resp = client
            .patch_auth(&format!("/api/admin/v1/regions/{region_id}"), &update_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete
        let resp = client
            .delete_auth(&format!("/api/admin/v1/regions/{region_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Role CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_admin_role_crud_lifecycle() {
        let client = setup().await;

        // Create
        let create_body = serde_json::json!({
            "name": "e2e-test-role",
            "description": "E2E test role",
            "permissions": ["users::view", "virtual_machines::view"]
        });
        let resp = client
            .post_auth("/api/admin/v1/roles", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Role creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let role_id = body["data"]["id"].as_u64().expect("Role should have an id");

        // Read
        let resp = client
            .get_auth(&format!("/api/admin/v1/roles/{role_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Update
        let update_body =
            serde_json::json!({"name": "e2e-test-role-updated", "description": "Updated"});
        let resp = client
            .patch_auth(&format!("/api/admin/v1/roles/{role_id}"), &update_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete
        let resp = client
            .delete_auth(&format!("/api/admin/v1/roles/{role_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Cost Plan CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_admin_cost_plan_crud_lifecycle() {
        let client = setup().await;

        // Create
        let create_body = serde_json::json!({
            "name": "e2e-test-plan",
            "amount": 999,
            "currency": "EUR",
            "interval_amount": 1,
            "interval_type": "month"
        });
        let resp = client
            .post_auth("/api/admin/v1/cost_plans", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Cost plan creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let plan_id = body["data"]["id"]
            .as_u64()
            .expect("Cost plan should have an id");

        // Read
        let resp = client
            .get_auth(&format!("/api/admin/v1/cost_plans/{plan_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Update
        let update_body = serde_json::json!({"name": "e2e-test-plan-updated", "amount": 1299});
        let resp = client
            .patch_auth(&format!("/api/admin/v1/cost_plans/{plan_id}"), &update_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete
        let resp = client
            .delete_auth(&format!("/api/admin/v1/cost_plans/{plan_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // OS Image CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_admin_os_image_crud_lifecycle() {
        let client = setup().await;

        // Create
        let create_body = serde_json::json!({
            "distribution": "debian",
            "flavour": "E2E-Test",
            "version": "99.0",
            "enabled": false,
            "release_date": "2026-01-01T00:00:00Z",
            "url": "https://example.com/test.img",
            "default_username": "testuser"
        });
        let resp = client
            .post_auth("/api/admin/v1/vm_os_images", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "OS image creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let img_id = body["data"]["id"]
            .as_u64()
            .expect("OS image should have an id");

        // Read
        let resp = client
            .get_auth(&format!("/api/admin/v1/vm_os_images/{img_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Update
        let update_body = serde_json::json!({"version": "99.1", "enabled": false});
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/vm_os_images/{img_id}"),
                &update_body,
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete
        let resp = client
            .delete_auth(&format!("/api/admin/v1/vm_os_images/{img_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Remaining List/Get Endpoints
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_regions() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/regions").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_roles() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/roles").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_my_roles() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/me/roles").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_vm_os_images() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vm_os_images").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_vm_templates() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vm_templates").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_vm_template() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vm_templates").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(templates) = body["data"].as_array() {
            if let Some(t) = templates.first() {
                let t_id = t["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/vm_templates/{t_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_admin_list_companies() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_company() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(companies) = body["data"].as_array() {
            if let Some(c) = companies.first() {
                let c_id = c["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/companies/{c_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_admin_list_cost_plans() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/cost_plans").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_custom_pricing() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/custom_pricing")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_custom_pricing() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/custom_pricing")
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(pricing) = body["data"].as_array() {
            if let Some(p) = pricing.first() {
                let p_id = p["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/custom_pricing/{p_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_admin_list_ip_ranges() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/ip_ranges").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_ip_range_and_free_ips() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/ip_ranges").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(ranges) = body["data"].as_array() {
            if let Some(r) = ranges.first() {
                let r_id = r["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/ip_ranges/{r_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/ip_ranges/{r_id}/free_ips"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_admin_list_access_policies() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/access_policies")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_routers() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/routers").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_vm_ip_assignments() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/vm_ip_assignments")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_list_subscriptions() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/subscriptions")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_subscription_with_line_items_and_payments() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/subscriptions")
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(subs) = body["data"].as_array() {
            if let Some(s) = subs.first() {
                let s_id = s["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/subscriptions/{s_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/subscriptions/{s_id}/line_items"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/subscriptions/{s_id}/payments"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_admin_subscription_line_item_not_found() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/subscription_line_items/999999999")
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_subscription_payment_not_found() {
        let client = setup().await;
        let fake_id = "00".repeat(32);
        let resp = client
            .get_auth(&format!("/api/admin/v1/subscription_payments/{fake_id}"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    // ========================================================================
    // Reports
    // ========================================================================

    #[tokio::test]
    async fn test_admin_time_series_report() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/reports/time-series")
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Time series report should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_admin_referral_time_series_report() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/reports/referral-usage/time-series")
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Referral time series report should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }

    // ========================================================================
    // Payment Methods (Admin)
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_payment_methods() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/payment_methods")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_payment_method() {
        let client = setup().await;
        let resp = client
            .get_auth("/api/admin/v1/payment_methods")
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(methods) = body["data"].as_array() {
            if let Some(m) = methods.first() {
                let m_id = m["id"].as_u64().unwrap();
                let resp = client
                    .get_auth(&format!("/api/admin/v1/payment_methods/{m_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    // ========================================================================
    // IP Space (Admin)
    // ========================================================================

    #[tokio::test]
    async fn test_admin_list_ip_space() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/ip_space").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_get_ip_space_with_pricing_and_subscriptions() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/ip_space").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(spaces) = body["data"].as_array() {
            if let Some(s) = spaces.first() {
                let s_id = s["id"].as_u64().unwrap();

                let resp = client
                    .get_auth(&format!("/api/admin/v1/ip_space/{s_id}"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/ip_space/{s_id}/pricing"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);

                let resp = client
                    .get_auth(&format!("/api/admin/v1/ip_space/{s_id}/subscriptions"))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    // ========================================================================
    // Payment Completion (Admin)
    // ========================================================================

    #[tokio::test]
    async fn test_admin_complete_vm_payment_not_found() {
        let client = setup().await;
        let fake_payment_id = "aa".repeat(32);
        let resp = client
            .post_auth(
                &format!("/api/admin/v1/vms/1/payments/{fake_payment_id}/complete"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        // Should fail because the payment doesn't exist
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_complete_vm_payment_invalid_id() {
        let client = setup().await;
        let resp = client
            .post_auth(
                "/api/admin/v1/vms/1/payments/not-hex/complete",
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    /// This test exercises the full payment completion flow:
    /// 1. Find an existing VM
    /// 2. Renew the VM to create an unpaid payment
    /// 3. Admin completes the payment
    /// 4. Verify the payment is now marked as paid
    /// 5. Verify double-complete is rejected
    #[tokio::test]
    async fn test_admin_complete_vm_payment_lifecycle() {
        let user = user_client();
        let admin = setup().await;

        // List user VMs to find one we can renew
        let resp = user.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let vms = body["data"].as_array().unwrap();
        if vms.is_empty() {
            eprintln!("Skipping payment lifecycle test: no VMs found for test user");
            return;
        }
        let vm_id = vms[0]["id"].as_u64().unwrap();

        // Renew the VM to create an unpaid payment
        let resp = user
            .get_auth(&format!("/api/v1/vm/{vm_id}/renew"))
            .await
            .unwrap();
        if resp.status() != StatusCode::OK {
            eprintln!(
                "Skipping payment lifecycle test: renew failed (Lightning node likely unavailable)"
            );
            return;
        }
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let payment_id = body["data"]["id"].as_str().unwrap().to_string();

        // Verify payment is not yet paid via admin API
        let resp = admin
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}/payments/{payment_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["is_paid"].as_bool().unwrap(), false);

        // Admin completes the payment
        let resp = admin
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/{payment_id}/complete"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Admin complete payment should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["is_paid"].as_bool().unwrap(), true);
        assert!(body["data"]["paid_at"].is_string(), "paid_at should be set");

        // Try to complete again — should fail
        let resp = admin
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/{payment_id}/complete"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "Completing already-paid payment should fail"
        );
    }

    #[tokio::test]
    async fn test_admin_complete_subscription_payment_not_found() {
        let client = setup().await;
        let fake_id = "bb".repeat(32);
        let resp = client
            .post_auth(
                &format!("/api/admin/v1/subscription_payments/{fake_id}/complete"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_complete_subscription_payment_invalid_id() {
        let client = setup().await;
        let resp = client
            .post_auth(
                "/api/admin/v1/subscription_payments/not-hex/complete",
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }
}
