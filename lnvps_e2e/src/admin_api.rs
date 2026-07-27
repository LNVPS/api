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
            "/api/admin/v1/apps",
            "/api/admin/v1/app-tags",
            "/api/admin/v1/app-deployments",
            "/api/admin/v1/app_clusters",
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
    async fn test_admin_list_users_with_filters() {
        let client = setup().await;

        // has_vms filter (both variants should succeed)
        for has_vms in ["true", "false"] {
            let resp = client
                .get_auth(&format!("/api/admin/v1/users?has_vms={has_vms}"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
            let expect_vms = has_vms == "true";
            for u in &data.data {
                let has = u["vm_count"].as_u64().unwrap_or(0) > 0;
                assert_eq!(
                    has, expect_vms,
                    "has_vms={has_vms} returned mismatched user"
                );
            }
        }

        // region_id filter
        let resp = client
            .get_auth("/api/admin/v1/users?region_id=1")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // role filter
        let resp = client
            .get_auth("/api/admin/v1/users?role=admin")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        for u in &data.data {
            assert_eq!(u["is_admin"], Value::Bool(true));
        }
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

    /// Purge a freshly-created user via `DELETE /api/admin/v1/users/{id}` and
    /// confirm the account is gone afterwards.
    #[tokio::test]
    async fn test_admin_delete_user() {
        use nostr::Keys;

        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();

        // A throwaway user with no VMs is safe to purge.
        let keys = Keys::generate();
        let user_id = crate::db::ensure_user(&pool, &keys).await.unwrap();

        let resp = client
            .delete_auth(&format!("/api/admin/v1/users/{user_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The user no longer exists.
        let resp = client
            .get_auth(&format!("/api/admin/v1/users/{user_id}"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
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
                || resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::CONFLICT
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Refund calc should return 200, 400, 404, 409, or 500, got: {}",
            resp.status()
        );
    }

    /// The automated refund endpoint refuses with 501 (issue #193). It used to
    /// queue a work job whose only handler bails and answer 200 with the job
    /// id, so an operator was told a refund had been dispatched while no money
    /// moved and no record was written. The request is still validated first,
    /// so a malformed one is still a 400.
    #[tokio::test]
    async fn test_admin_vm_refund_process_is_refused() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no VMs found for refund test");
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();

        // A well-formed request is refused, and the refusal says why.
        let body = serde_json::json!({
            "payment_method": "lightning",
            "lightning_invoice": "lnbc1e2etestinvoice",
            "reason": "e2e-test"
        });
        let resp = client
            .post_auth(&format!("/api/admin/v1/vms/{vm_id}/refund"), &body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let text = resp.text().await.unwrap();
        assert!(text.contains("not implemented"), "{text}");
        assert!(text.contains("no funds are moved"), "{text}");

        // Validation still runs ahead of the refusal.
        let bad = serde_json::json!({ "payment_method": "carrier-pigeon" });
        let resp = client
            .post_auth(&format!("/api/admin/v1/vms/{vm_id}/refund"), &bad)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A lightning refund without an invoice is still a 400, not a 501.
        let no_invoice = serde_json::json!({ "payment_method": "lightning" });
        let resp = client
            .post_auth(&format!("/api/admin/v1/vms/{vm_id}/refund"), &no_invoice)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
                || resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::CONFLICT
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "VM extend should return 200, 400, 404, 409, or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_admin_vm_extend_all() {
        let client = setup().await;
        let body = serde_json::json!({"days": 1, "reason": "e2e-test-bulk"});
        let resp = client
            .post_auth("/api/admin/v1/vms/extend-all", &body)
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "VM extend-all should return 200, 400, or 500, got: {}",
            resp.status()
        );
        // Validate error case: 0 days must be rejected
        let bad = serde_json::json!({"days": 0});
        let resp = client
            .post_auth("/api/admin/v1/vms/extend-all", &bad)
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "extend-all with days=0 must not succeed"
        );
    }

    #[tokio::test]
    async fn test_admin_vm_transfer() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no VMs found for transfer test");
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();
        let current_user = data.data[0]["user_id"].as_u64().unwrap_or(0);
        // Transfer to the same user is rejected (409); an unknown user is 404.
        let body = serde_json::json!({"user_id": current_user, "reason": "e2e-test"});
        let resp = client
            .post_auth(&format!("/api/admin/v1/vms/{vm_id}/transfer"), &body)
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::CONFLICT
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "VM transfer should return 200, 400, 404, 409, or 500, got: {}",
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
    // App catalog + cluster CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_admin_app_and_cluster_crud() {
        let client = setup().await;

        // --- App catalog ---
        let create_app = serde_json::json!({
            "name": "e2e-relay",
            "display_name": "E2E Relay",
            "description": "test relay app",
            "repo_url": "https://github.com/example/relay",
            "category": "Nostr relay",
            "compose": "services:\n  relay:\n    image: example/relay:latest\n    ports:\n      - { name: ws, container: 7777, protocol: http, expose: ingress }\n",
            "amount": 1000,
            "currency": "usd",
            "interval_amount": 1,
            "interval_type": "month",
            "setup_amount": 0
        });
        let resp = client
            .post_auth("/api/admin/v1/apps", &create_app)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "app creation should succeed");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = body["data"]["id"].as_u64().expect("app id");
        // currency is normalised to upper-case.
        assert_eq!(body["data"]["currency"].as_str().unwrap(), "USD");
        // Footprint is computed from the compose (one service, default 250m).
        assert_eq!(body["data"]["cpu_milli"].as_u64(), Some(250));
        // Source repo URL is stored and echoed back (issue #229).
        assert_eq!(
            body["data"]["repo_url"].as_str(),
            Some("https://github.com/example/relay")
        );
        // Category is required and echoed back; the SEO overrides default to
        // null (issue #239).
        assert_eq!(body["data"]["category"].as_str(), Some("Nostr relay"));
        assert!(body["data"]["seo_title"].is_null());
        assert!(body["data"]["seo_description"].is_null());

        // Duplicate name is rejected.
        let resp = client
            .post_auth("/api/admin/v1/apps", &create_app)
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "duplicate app name rejected");

        // Invalid slug rejected.
        // `category` is present so the request reaches slug validation: making
        // it required (#239) means omitting it fails deserialization with 422
        // first, which would pass an assert_ne but stop testing the slug rule.
        let bad = serde_json::json!({
            "name": "Bad Name",
            "display_name": "x",
            "category": "Nostr relay",
            "compose": "services: {}",
            "amount": 1,
            "currency": "usd",
            "interval_amount": 1,
            "interval_type": "month"
        });
        let resp = client.post_auth("/api/admin/v1/apps", &bad).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "bad slug rejected");

        // Read.
        let resp = client
            .get_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["display_name"].as_str().unwrap(), "E2E Relay");

        // List includes it.
        let resp = client.get_auth("/api/admin/v1/apps").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["id"].as_u64() == Some(app_id))
        );

        // Update (disable + rename).
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({"display_name": "Renamed", "enabled": false}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["display_name"].as_str().unwrap(), "Renamed");
        assert_eq!(body["data"]["enabled"].as_bool().unwrap(), false);

        // --- App cluster (needs a region) ---
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let company_id = body["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["id"].as_u64())
            .unwrap_or(1);
        let resp = client
            .post_auth(
                "/api/admin/v1/regions",
                &serde_json::json!({"name": "e2e-app-region", "enabled": true, "company_id": company_id}),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let region_id = body["data"]["id"].as_u64().expect("region id");

        // Cluster with a non-existent region is rejected.
        let resp = client
            .post_auth(
                "/api/admin/v1/app_clusters",
                &serde_json::json!({"name": "bad", "region_id": 99999999u64, "ingress_domain": "x.example.com"}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "unknown region rejected");

        // Create cluster.
        let resp = client
            .post_auth(
                "/api/admin/v1/app_clusters",
                &serde_json::json!({"name": "e2e-cluster", "region_id": region_id, "ingress_domain": "apps.e2e.example.com", "capacity_cpu_milli": 8000, "capacity_memory_bytes": 8589934592u64, "capacity_storage_bytes": 107374182400u64}),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cluster creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let cluster_id = body["data"]["id"].as_u64().expect("cluster id");
        assert_eq!(body["data"]["capacity_cpu_milli"].as_u64(), Some(8000));

        // Read / list / update.
        let resp = client
            .get_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client.get_auth("/api/admin/v1/app_clusters").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/app_clusters/{cluster_id}"),
                &serde_json::json!({"ingress_domain": "apps2.e2e.example.com", "enabled": false}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["ingress_domain"].as_str().unwrap(),
            "apps2.e2e.example.com"
        );

        // Cleanup: delete cluster, region, app.
        let resp = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = client
            .delete_auth(&format!("/api/admin/v1/regions/{region_id}"))
            .await;
        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A service can declare `init:` setup steps (issue #244), and a step whose
    /// command interpolates a `${…}` is refused at create/update rather than
    /// becoming a deployment that runs customer text through a shell.
    #[tokio::test]
    async fn test_admin_app_compose_init_steps() {
        let client = setup().await;
        let suffix = nostr::Keys::generate().public_key().to_hex()[..8].to_string();
        let slug = format!("e2e-init-{suffix}");

        let compose = |name: &str, cmd: &str| {
            format!(
                "services:\n  s3:\n    image: rustfs/rustfs:latest\n    ports:\n      \
                 - {{ name: s3, container: 9000, protocol: http, expose: none }}\n  \
                 app:\n    image: example/app:latest\n    depends_on: [s3]\n    ports:\n      \
                 - {{ name: http, container: 3000, protocol: http, expose: ingress }}\n    \
                 init:\n      - name: {name}\n        image: minio/mc:latest\n        \
                 env:\n          MC_HOST_s3: http://k:${{S3_KEY}}@s3:9000\n        \
                 command: [\"sh\", \"-c\", \"{cmd}\"]\n\
                 secrets:\n  - {{ name: S3_KEY, generate: token }}\n"
            )
        };
        let ok = || compose("create-bucket", "mc mb -p s3/media");
        let body = |compose: String| {
            serde_json::json!({
                "name": slug,
                "display_name": "Init App",
                "category": "Media server",
                "compose": compose,
                "amount": 1000,
                "currency": "usd",
                "interval_amount": 1,
                "interval_type": "month",
                "setup_amount": 0
            })
        };

        // A `${…}` in the command is shell injection waiting to happen: refused.
        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &body(compose("create-bucket", "mc mb -p s3/${S3_KEY}")),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = resp.text().await.unwrap();
        assert!(err.contains("must not contain"), "{err}");

        // The step name becomes a container name, so it has to be a DNS label.
        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &body(compose("Create_Bucket", "mc mb -p s3/media")),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = resp.text().await.unwrap();
        assert!(err.contains("init name"), "{err}");

        // Valid: accepted and stored verbatim.
        let resp = client
            .post_auth("/api/admin/v1/apps", &body(ok()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let created: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = created["data"]["id"].as_u64().expect("app id");
        assert!(
            created["data"]["compose"]
                .as_str()
                .unwrap()
                .contains("init:")
        );

        // The same rule applies on update.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "compose": compose("create-bucket", "mc mb -p s3/${S3_KEY}") }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A service can declare `scratch:` paths (issue #264) — writable
    /// `emptyDir`s a database image needs under the read-only root filesystem —
    /// and a declaration that would cost the customer data or the node its disk
    /// is refused at create and at update, not discovered in a crash loop.
    #[tokio::test]
    async fn test_admin_app_compose_scratch_paths() {
        let client = setup().await;
        let suffix = nostr::Keys::generate().public_key().to_hex()[..8].to_string();
        let slug = format!("e2e-scratch-{suffix}");

        let compose = |scratch: &str| {
            format!(
                "services:\n  db:\n    image: mariadb:11\n    user: \"999\"\n    \
                 volumes:\n      - {{ name: data, path: /var/lib/mysql, size: 5Gi }}\n    \
                 scratch:\n{scratch}  \
                 app:\n    image: example/app:latest\n    user: \"1000\"\n    \
                 depends_on: [db]\n    ports:\n      \
                 - {{ name: http, container: 3000, protocol: http, expose: ingress }}\n"
            )
        };
        let ok = || compose("      - { path: /tmp }\n      - { path: /run/mysqld, size: 32Mi }\n");
        let body = |compose: String| {
            serde_json::json!({
                "name": slug,
                "display_name": "Scratch App",
                "category": "Media server",
                "compose": compose,
                "amount": 1000,
                "currency": "usd",
                "interval_amount": 1,
                "interval_type": "month",
                "setup_amount": 0
            })
        };

        // Scratch inside a data volume would shadow the customer's data with an
        // empty directory on every restart.
        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &body(compose("      - { path: /var/lib/mysql/tmp }\n")),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = resp.text().await.unwrap();
        assert!(err.contains("shadow persisted data"), "{err}");

        // Node-local disk is shared with every other tenant, so it is bounded.
        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &body(compose("      - { path: /tmp, size: 4Gi }\n")),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = resp.text().await.unwrap();
        assert!(err.contains("scratch"), "{err}");

        // Valid: accepted and stored verbatim.
        let resp = client
            .post_auth("/api/admin/v1/apps", &body(ok()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let created: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = created["data"]["id"].as_u64().expect("app id");
        assert!(
            created["data"]["compose"]
                .as_str()
                .unwrap()
                .contains("scratch:")
        );

        // The same rules apply on update.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "compose": compose("      - { path: /var/lib }\n") }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A generated secret can declare its byte length (issue #243), and an
    /// unusable length is refused when the app is created or updated rather
    /// than becoming an app that deploys and crash-loops on its own key.
    #[tokio::test]
    async fn test_admin_app_compose_secret_bytes() {
        let client = setup().await;
        // Unique slug so the test can be re-run against the same database.
        let suffix = nostr::Keys::generate().public_key().to_hex()[..8].to_string();
        let slug = format!("e2e-secret-bytes-{suffix}");

        let compose = |bytes: &str| {
            format!(
                "services:\n  relay:\n    image: example/relay:latest\n    env:\n      \
                 KEY: ${{RELAY_KEY}}\nsecrets:\n  - {{ name: RELAY_KEY, generate: token{bytes} }}\n"
            )
        };
        let body = |compose: String| {
            serde_json::json!({
                "name": slug,
                "display_name": "Secret Bytes Relay",
                "category": "Nostr relay",
                "compose": compose,
                "amount": 1000,
                "currency": "usd",
                "interval_amount": 1,
                "interval_type": "month",
                "setup_amount": 0
            })
        };

        // Out of range is rejected, naming the bound.
        let resp = client
            .post_auth("/api/admin/v1/apps", &body(compose(", bytes: 4")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = resp.text().await.unwrap();
        assert!(err.contains("bytes must be between"), "{err}");

        // 32 bytes is accepted and stored verbatim.
        let resp = client
            .post_auth("/api/admin/v1/apps", &body(compose(", bytes: 32")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let created: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = created["data"]["id"].as_u64().expect("app id");
        assert!(
            created["data"]["compose"]
                .as_str()
                .unwrap()
                .contains("bytes: 32")
        );

        // Omitting it still works — every compose written before this existed
        // keeps parsing.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "compose": compose("") }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // And the same bound applies on update.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "compose": compose(", bytes: 4096") }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Catalog SEO metadata (issue #239): `category` is required and cannot be
    /// blanked, the two overrides are nullable and clearable, and all three
    /// reach the public catalog — which is what the app page templates its
    /// title from instead of a hardcoded per-slug map in the frontend.
    #[tokio::test]
    async fn test_admin_app_seo_metadata() {
        let client = setup().await;
        // Unique slug so the test can be re-run against the same database.
        let suffix = nostr::Keys::generate().public_key().to_hex()[..8].to_string();
        let slug = format!("e2e-seo-{suffix}");

        let base = |category: Option<&str>| {
            let mut v = serde_json::json!({
                "name": slug,
                "display_name": "SEO Relay",
                "compose": "services:\n  relay:\n    image: example/relay:latest\n",
                "amount": 1000,
                "currency": "usd",
                "interval_amount": 1,
                "interval_type": "month",
                "setup_amount": 0
            });
            if let Some(c) = category {
                v["category"] = serde_json::json!(c);
            }
            v
        };

        // Omitted category is rejected: it is required precisely so that a
        // newly-onboarded app cannot reach a crawler with a generic title.
        let resp = client
            .post_auth("/api/admin/v1/apps", &base(None))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "category is required on create"
        );

        // Whitespace-only is rejected too — "" is the same silent failure as
        // NULL, so it must not be storable through the trim.
        let resp = client
            .post_auth("/api/admin/v1/apps", &base(Some("   ")))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "blank category rejected"
        );
        assert!(resp.text().await.unwrap().contains("category is required"));

        // Create with padding: stored trimmed, since the raw string is what
        // ends up inside <title>.
        let create = {
            let mut v = base(Some("  Community Nostr relay  "));
            v["seo_description"] = serde_json::json!("  ");
            v
        };
        let resp = client
            .post_auth("/api/admin/v1/apps", &create)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = body["data"]["id"].as_u64().expect("app id");
        assert_eq!(
            body["data"]["category"].as_str(),
            Some("Community Nostr relay"),
            "category stored trimmed"
        );
        // A blank optional override collapses to null rather than "".
        assert!(body["data"]["seo_description"].is_null());

        // Patch: category changes, and the overrides can be set.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({
                    "category": "Personal Nostr relay",
                    "seo_title": "Bespoke Relay Hosting",
                    "seo_description": "Bespoke description for a flagship app."
                }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["category"].as_str(),
            Some("Personal Nostr relay")
        );
        assert_eq!(
            body["data"]["seo_title"].as_str(),
            Some("Bespoke Relay Hosting")
        );

        // Omitting category leaves it unchanged (it is Option<String>, not
        // Option<Option<String>>: there is no null to clear to).
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "display_name": "SEO Relay Renamed" }),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["category"].as_str(),
            Some("Personal Nostr relay"),
            "omitted category unchanged"
        );

        // Explicit null is refused rather than silently ignored: a client
        // asking to clear a NOT NULL column must not get 200 and no change.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "category": null }),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "category cannot be nulled"
        );
        assert!(resp.text().await.unwrap().contains("category cannot be null"));

        // Blanking it via patch is refused, and leaves the stored value alone.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "category": "  " }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = client
            .get_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["category"].as_str(),
            Some("Personal Nostr relay"),
            "rejected patch left category untouched"
        );

        // The overrides clear to null (unlike category, they are nullable).
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "seo_title": null, "seo_description": null }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"]["seo_title"].is_null());
        assert!(body["data"]["seo_description"].is_null());

        // The public catalog is where this actually gets consumed, and it is
        // unauthenticated (#227). category is a string, never null.
        let public = user_client_no_auth();
        let resp = public.get(&format!("/api/v1/apps/{app_id}")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["category"].as_str(),
            Some("Personal Nostr relay")
        );
        assert!(body["data"]["seo_title"].is_null());

        let resp = public.get("/api/v1/apps").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let listed = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"].as_u64() == Some(app_id))
            .expect("app in public catalog");
        assert_eq!(listed["category"].as_str(), Some("Personal Nostr relay"));

        // Cleanup.
        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// App tags (issue #240): the vocabulary CRUD, replace-set assignment on
    /// an app, rejection of unknown slugs, the delete cascade, and all of it
    /// reaching the public catalog — including the `?tag=` filter, which is
    /// what a tag landing page is actually built on.
    #[tokio::test]
    async fn test_admin_app_tags() {
        let client = setup().await;
        // Unique slugs and app names so the test can be re-run against the
        // same database, and so it cannot collide with the seeded vocabulary.
        let suffix = nostr::Keys::generate().public_key().to_hex()[..8].to_string();
        let tag_a = format!("e2e-alpha-{suffix}");
        let tag_b = format!("e2e-beta-{suffix}");

        // --- Vocabulary CRUD -------------------------------------------------
        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": &tag_a, "display_name": "  Alpha  " }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let tag_a_id = body["data"]["id"].as_u64().expect("tag id");
        assert_eq!(body["data"]["display_name"].as_str(), Some("Alpha"));
        assert!(body["data"]["description"].is_null());
        assert_eq!(body["data"]["app_count"].as_u64(), Some(0));

        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({
                    "slug": &tag_b,
                    "display_name": "NIP-96",
                    "description": "Beta tag"
                }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let tag_b_id = body["data"]["id"].as_u64().expect("tag id");
        // display_name is stored verbatim, not derived: title-casing `nip-96`
        // in a client would yield `Nip-96`.
        assert_eq!(body["data"]["display_name"].as_str(), Some("NIP-96"));

        // Duplicate slug is refused — the vocabulary is controlled, so two
        // tags reading the same is the drift the table exists to prevent.
        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": &tag_a, "display_name": "Alpha again" }),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "duplicate slug refused");

        // Slug must be URL-safe: it is a path segment and a query value.
        for bad in ["Alpha", "with space", "under_score", "-lead", "trail-", "  "] {
            let resp = client
                .post_auth(
                    "/api/admin/v1/app-tags",
                    &serde_json::json!({ "slug": bad, "display_name": "X" }),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "slug {bad:?} should be rejected"
            );
        }
        // display_name is required, not derivable.
        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": format!("{tag_a}-x"), "display_name": "  " }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // PATCH: omitted leaves unchanged, description clears to null.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/app-tags/{tag_b_id}"),
                &serde_json::json!({ "description": null }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"]["description"].is_null());
        assert_eq!(
            body["data"]["slug"].as_str(),
            Some(tag_b.as_str()),
            "omitted slug unchanged"
        );

        // --- Assignment on an app -------------------------------------------
        let app_body = |tags: Option<Value>| {
            let mut v = serde_json::json!({
                "name": format!("e2e-tags-{suffix}"),
                "display_name": "E2E Tagged",
                "category": "Nostr relay",
                "compose": "services:\n  relay:\n    image: example/relay:latest\n",
                "amount": 1000,
                "currency": "usd",
                "interval_amount": 1,
                "interval_type": "month",
                "setup_amount": 0
            });
            if let Some(t) = tags {
                v["tags"] = t;
            }
            v
        };

        // An unknown slug fails the whole create — naming the slug, and
        // without leaving a created-but-untagged app behind.
        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &app_body(Some(serde_json::json!([&tag_a, "no-such-tag"]))),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(resp.text().await.unwrap().contains("no-such-tag"));

        let resp = client
            .post_auth(
                "/api/admin/v1/apps",
                &app_body(Some(serde_json::json!([&tag_a, &tag_b]))),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the rejected create must not have consumed the app name"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let app_id = body["data"]["id"].as_u64().expect("app id");
        let slugs = |v: &Value| -> Vec<String> {
            v["tags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["slug"].as_str().unwrap().to_string())
                .collect()
        };
        // Ordered by slug, and `-alpha-` sorts before `-beta-`.
        assert_eq!(slugs(&body["data"]), vec![tag_a.clone(), tag_b.clone()]);

        // Counts pick the assignment up.
        let resp = client.get_auth("/api/admin/v1/app-tags").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let count_of = |body: &Value, id: u64| -> u64 {
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"].as_u64() == Some(id))
                .expect("tag in vocabulary")["app_count"]
                .as_u64()
                .unwrap()
        };
        assert_eq!(count_of(&body, tag_a_id), 1);
        assert_eq!(count_of(&body, tag_b_id), 1);

        // Replace-set: the sent list becomes exact, not merged.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "tags": [&tag_b] }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_b.clone()]);

        // Omitting `tags` leaves the set alone — it must not read as "clear".
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "display_name": "E2E Tagged Renamed" }),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_b.clone()], "omitted = unchanged");

        // An unknown slug on PATCH leaves the existing set untouched rather
        // than half-applying.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "tags": [&tag_a, "no-such-tag"] }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = client
            .get_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_b.clone()]);

        // `[]` clears.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "tags": [] }),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(slugs(&body["data"]).is_empty());
        // Restore both for the public-surface checks below.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "tags": [&tag_a, &tag_b, &tag_a] }),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            slugs(&body["data"]),
            vec![tag_a.clone(), tag_b.clone()],
            "a repeated slug is one assignment, not a duplicate-key error"
        );

        // --- Public surface --------------------------------------------------
        let public = user_client_no_auth();

        let resp = public.get(&format!("/api/v1/apps/{app_id}")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_a.clone(), tag_b.clone()]);
        // display_name rides along: a client cannot recover `NIP-96` from a slug.
        let beta = body["data"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"].as_str() == Some(tag_b.as_str()))
            .unwrap();
        assert_eq!(beta["display_name"].as_str(), Some("NIP-96"));

        // The facet endpoint is public, like the catalog it describes.
        let resp = public.get("/api/v1/app-tags").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let public_tag = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"].as_str() == Some(tag_a.as_str()))
            .expect("tag in public vocabulary");
        assert_eq!(public_tag["app_count"].as_u64(), Some(1));

        // The filter, in both spellings a client might build. Percent-decoding
        // is axum's half of `tag_filter`, so it is exercised here rather than
        // in the unit test.
        let listed_ids = |body: &Value| -> Vec<u64> {
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["id"].as_u64().unwrap())
                .collect()
        };
        for query in [
            format!("?tag={tag_a}&tag={tag_b}"),
            format!("?tag={tag_a}%2C{tag_b}"),
        ] {
            let resp = public.get(&format!("/api/v1/apps{query}")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            assert!(
                listed_ids(&body).contains(&app_id),
                "AND filter should match an app carrying both tags ({query})"
            );
        }

        // AND, not OR: adding a tag the app does not carry excludes it.
        let resp = client
            .post_auth(
                "/api/admin/v1/app-tags",
                &serde_json::json!({ "slug": format!("e2e-gamma-{suffix}"), "display_name": "Gamma" }),
            )
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let tag_c_id = body["data"]["id"].as_u64().expect("tag id");
        let resp = public
            .get(&format!("/api/v1/apps?tag={tag_a}&tag=e2e-gamma-{suffix}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(!listed_ids(&body).contains(&app_id), "AND, not OR");

        // An unknown or retired slug is an empty list with 200, not a 404: the
        // caller is a filter UI and a stale chip should degrade to "no
        // results", not to an error page.
        let resp = public.get("/api/v1/apps?tag=no-such-tag").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"].as_array().unwrap().is_empty());

        // A cleared filter means "no filter", not "the empty-string tag".
        let resp = public.get("/api/v1/apps?tag=").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(
            listed_ids(&body).contains(&app_id),
            "?tag= must not filter everything out"
        );

        // A disabled app leaves the public catalog and stops being counted,
        // but keeps its assignments for when it is re-enabled.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/apps/{app_id}"),
                &serde_json::json!({ "enabled": false }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_a.clone(), tag_b.clone()]);
        let resp = public.get("/api/v1/app-tags").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let public_tag = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"].as_str() == Some(tag_a.as_str()))
            .expect("tag still in vocabulary");
        assert_eq!(
            public_tag["app_count"].as_u64(),
            Some(0),
            "disabled apps are not counted"
        );

        // --- Delete cascade --------------------------------------------------
        let resp = client
            .delete_auth(&format!("/api/admin/v1/app-tags/{tag_a_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["assignments_removed"].as_u64(),
            Some(1),
            "the cascade is otherwise invisible, so it is reported"
        );
        let resp = client
            .get_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(slugs(&body["data"]), vec![tag_b.clone()]);

        // Deleting a tag nothing carries reports zero, and a non-existent one
        // is a 404 rather than a 200 claiming it removed nothing.
        let resp = client
            .delete_auth(&format!("/api/admin/v1/app-tags/{tag_c_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["assignments_removed"].as_u64(), Some(0));
        let resp = client
            .delete_auth("/api/admin/v1/app-tags/999999999")
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "unknown tag id is not a 200");

        // Deleting the app cascades the other way: the tag survives, its
        // assignment does not.
        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client
            .get_auth(&format!("/api/admin/v1/app-tags/{tag_b_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["app_count"].as_u64(), Some(0));

        // Cleanup.
        let _ = client
            .delete_auth(&format!("/api/admin/v1/app-tags/{tag_b_id}"))
            .await;
    }

    /// Top-level admin listing of all app deployments (oversight/support).
    #[tokio::test]
    async fn test_admin_list_app_deployments() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (_app_id, _cluster_id, dep_id) =
            crate::db::seed_app_deployment(&pool, uid, "admin-list")
                .await
                .unwrap();

        let resp = client
            .get_auth("/api/admin/v1/app-deployments")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let found = body["data"]
            .as_array()
            .expect("data array")
            .iter()
            .find(|d| d["id"].as_u64() == Some(dep_id))
            .expect("seeded deployment is listed");
        assert_eq!(found["user_id"].as_u64(), Some(uid));
        assert!(!found["namespace"].as_str().unwrap().is_empty());
        assert!(!found["status"].as_str().unwrap().is_empty());
        // Standard paginated envelope.
        assert!(body["total"].as_u64().unwrap() >= 1);
        assert_eq!(body["limit"].as_u64(), Some(50));
        assert_eq!(body["offset"].as_u64(), Some(0));

        pool.close().await;
    }

    /// Filters and pagination on the admin deployment listing (#235).
    #[tokio::test]
    async fn test_admin_list_app_deployments_filters() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) =
            crate::db::seed_app_deployment(&pool, uid, "filter-target")
                .await
                .unwrap();
        // A second deployment for the same user, on its own app + cluster.
        let (other_app, other_cluster, other_dep) =
            crate::db::seed_app_deployment(&pool, uid, "filter-other")
                .await
                .unwrap();

        let ids = |body: &Value| -> Vec<u64> {
            body["data"]
                .as_array()
                .expect("data array")
                .iter()
                .filter_map(|d| d["id"].as_u64())
                .collect()
        };

        // user_id: both, and nothing belonging to anyone else.
        let resp = client
            .get_auth(&format!("/api/admin/v1/app-deployments?user_id={uid}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(2));
        let mut found = ids(&body);
        found.sort_unstable();
        let mut expected = vec![dep_id, other_dep];
        expected.sort_unstable();
        assert_eq!(found, expected);

        // app_id / cluster_id narrow to the one deployment.
        for query in [
            format!("app_id={app_id}"),
            format!("cluster_id={cluster_id}"),
        ] {
            let resp = client
                .get_auth(&format!("/api/admin/v1/app-deployments?{query}"))
                .await
                .unwrap();
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            assert_eq!(ids(&body), vec![dep_id], "filter {query}");
        }

        // search matches the deployment name.
        let resp = client
            .get_auth("/api/admin/v1/app-deployments?search=filter-target")
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(ids(&body), vec![dep_id]);

        // status: seeded deployments are pending; `running` excludes them.
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/app-deployments?user_id={uid}&status=pending"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(2));
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/app-deployments?user_id={uid}&status=running"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(0));

        // limit/offset page through the filtered set; total stays the full count.
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/app-deployments?user_id={uid}&limit=1&offset=1"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(2));
        assert_eq!(body["limit"].as_u64(), Some(1));
        assert_eq!(body["offset"].as_u64(), Some(1));
        assert_eq!(
            ids(&body),
            vec![dep_id],
            "id DESC, so offset 1 is the older"
        );

        // include_deleted is the only way to see a torn-down deployment.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client
            .get_auth(&format!("/api/admin/v1/app-deployments?user_id={uid}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(ids(&body), vec![other_dep], "deleted row is hidden");
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/app-deployments?user_id={uid}&include_deleted=true"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(2));
        let deleted = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"].as_u64() == Some(dep_id))
            .expect("deleted deployment is listed");
        assert_eq!(deleted["deleted"].as_bool(), Some(true));

        // Cleanup: purge both, then the catalog rows they pinned.
        for id in [dep_id, other_dep] {
            let resp = client
                .delete_auth_body(
                    &format!("/api/admin/v1/app-deployments/{id}"),
                    &serde_json::json!({ "purge": true }),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        for id in [cluster_id, other_cluster] {
            let _ = client
                .delete_auth(&format!("/api/admin/v1/app_clusters/{id}"))
                .await;
        }
        for id in [app_id, other_app] {
            let _ = client
                .delete_auth(&format!("/api/admin/v1/apps/{id}"))
                .await;
        }

        pool.close().await;
    }

    /// Paginated envelope + filters on the catalog app listing (#235).
    #[tokio::test]
    async fn test_admin_list_apps_paginated() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "apps-page")
            .await
            .unwrap();
        let app_name: String = sqlx::query_scalar("SELECT name FROM app WHERE id = ?")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        let resp = client.get_auth("/api/admin/v1/apps?limit=1").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        assert!(body["total"].as_u64().unwrap() >= 1);
        assert_eq!(body["limit"].as_u64(), Some(1));

        // search finds the seeded app; enabled=false excludes it (seeded enabled).
        let resp = client
            .get_auth(&format!("/api/admin/v1/apps?search={app_name}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"][0]["id"].as_u64(), Some(app_id));
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/apps?search={app_name}&enabled=false"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(0));

        // Clusters list carries the same envelope and a region filter.
        let region_id: u64 = sqlx::query_scalar("SELECT region_id FROM app_cluster WHERE id = ?")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let resp = client
            .get_auth(&format!("/api/admin/v1/app_clusters?region_id={region_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(1));
        assert_eq!(body["data"][0]["id"].as_u64(), Some(cluster_id));

        // Cleanup.
        let _ = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({ "purge": true }),
            )
            .await;
        let _ = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await;
        let _ = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await;

        pool.close().await;
    }

    /// Admin delete of an ever-paid deployment soft-deletes and stops billing;
    /// a repeat delete conflicts; `purge` removes the row and its billing (#234).
    #[tokio::test]
    async fn test_admin_delete_and_purge_app_deployment() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "purge-me")
            .await
            .unwrap();
        // seed_app_deployment marks the subscription set up (ever paid).
        let sub_id: u64 = sqlx::query_scalar(
            "SELECT li.subscription_id FROM app_deployment d \
             JOIN subscription_line_item li ON li.id = d.subscription_line_item_id \
             WHERE d.id = ?",
        )
        .bind(dep_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Plain delete: soft-delete + billing deactivated, row retained.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let (deleted, is_active, auto_renew): (bool, bool, bool) = sqlx::query_as(
            "SELECT d.deleted, s.is_active, s.auto_renewal_enabled FROM app_deployment d \
             JOIN subscription s ON s.id = ? WHERE d.id = ?",
        )
        .bind(sub_id)
        .bind(dep_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(deleted, "soft-deleted");
        assert!(!is_active, "billing deactivated");
        assert!(!auto_renew, "auto-renewal off");

        // Deleting again without purge conflicts.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Purge: an already soft-deleted deployment can still be purged, and it
        // takes its subscription and line items with it.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({ "purge": true }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_deployment WHERE id = ?")
            .bind(dep_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "row purged");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription WHERE id = ?")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(subs, 0, "subscription purged");
        let items: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscription_line_item WHERE subscription_id = ?",
        )
        .bind(sub_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(items, 0, "line items cascaded");

        // A purged deployment is gone even with include_deleted.
        let resp = client
            .get_auth(&format!(
                "/api/admin/v1/app-deployments?user_id={uid}&include_deleted=true"
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["total"].as_u64(), Some(0));

        let _ = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await;
        let _ = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await;
        pool.close().await;
    }

    /// Deleting an app or cluster is refused while *any* deployment row still
    /// references it, soft-deleted included — the foreign key does not look at
    /// `deleted`, so counting only live deployments turned the FK rejection
    /// into a 500 (#238). Purging the dead rows unblocks both deletes.
    #[tokio::test]
    async fn test_admin_delete_app_blocked_until_deployments_purged() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "guard-me")
            .await
            .unwrap();

        // Live deployment: both deletes refused, counts named.
        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.text().await.unwrap();
        assert!(body.contains("1 active"), "{body}");
        let resp = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Soft-delete the deployment: the row and its foreign keys survive, so
        // the deletes stay refused — with a 400 naming the purge, not a 500.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.text().await.unwrap();
        assert!(body.contains("1 soft-deleted"), "{body}");
        assert!(body.contains("purge"), "{body}");
        let resp = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.text().await.unwrap();
        assert!(body.contains("1 soft-deleted"), "{body}");

        // Purge, then both deletes succeed — the guard and the FK now agree in
        // both directions.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({ "purge": true }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let apps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app WHERE id = ?")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(apps, 0, "app deleted once nothing references it");
        let clusters: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_cluster WHERE id = ?")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(clusters, 0, "cluster deleted once nothing references it");
        pool.close().await;
    }

    /// A deployment whose first payment was never confirmed is removed entirely
    /// by a plain delete — the same never-paid rule VMs use (#234).
    #[tokio::test]
    async fn test_admin_delete_never_paid_app_deployment_purges() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "never-paid")
            .await
            .unwrap();
        let sub_id: u64 = sqlx::query_scalar(
            "SELECT li.subscription_id FROM app_deployment d \
             JOIN subscription_line_item li ON li.id = d.subscription_line_item_id \
             WHERE d.id = ?",
        )
        .bind(dep_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Never paid: the first payment was never confirmed.
        sqlx::query("UPDATE subscription SET is_setup = 0 WHERE id = ?")
            .bind(sub_id)
            .execute(&pool)
            .await
            .unwrap();

        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/app-deployments/{dep_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_deployment WHERE id = ?")
            .bind(dep_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "never-paid deployment is purged, not soft-deleted");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription WHERE id = ?")
            .bind(sub_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(subs, 0);

        let _ = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await;
        let _ = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await;
        pool.close().await;
    }

    /// `purge` bypasses the paid-payments guard on subscription delete (#234).
    #[tokio::test]
    async fn test_admin_purge_subscription_with_paid_payments() {
        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();
        let keys = nostr::Keys::generate();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "sub-purge")
            .await
            .unwrap();
        let sub_id: u64 = sqlx::query_scalar(
            "SELECT li.subscription_id FROM app_deployment d \
             JOIN subscription_line_item li ON li.id = d.subscription_line_item_id \
             WHERE d.id = ?",
        )
        .bind(dep_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO subscription_payment (id, subscription_id, user_id, created, expires, \
                 amount, currency, payment_method, payment_type, external_data, is_paid, rate, \
                 tax, processing_fee) \
             VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR), 1000, 'EUR', 0, 0, '', 1, 1.0, 0, 0)",
        )
        .bind(vec![9u8; 16])
        .bind(sub_id)
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();

        // The deployment still references a line item, so a purge is refused.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/subscriptions/{sub_id}"),
                &serde_json::json!({ "purge": true }),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(resp.text().await.unwrap().contains("app deployment"));

        // Soft-delete the deployment row out of the way (the purge guard looks
        // at the FK, so the row itself must go).
        sqlx::query("DELETE FROM app_deployment WHERE id = ?")
            .bind(dep_id)
            .execute(&pool)
            .await
            .unwrap();

        // Without purge the paid payment still blocks the delete.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/subscriptions/{sub_id}"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(resp.text().await.unwrap().contains("paid payments exist"));

        // With purge it goes, taking payments and line items with it.
        let resp = client
            .delete_auth_body(
                &format!("/api/admin/v1/subscriptions/{sub_id}"),
                &serde_json::json!({ "purge": true }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        for (table, column) in [
            ("subscription", "id"),
            ("subscription_line_item", "subscription_id"),
            ("subscription_payment", "subscription_id"),
        ] {
            let rows: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?"))
                    .bind(sub_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(rows, 0, "{table} purged");
        }

        let _ = client
            .delete_auth(&format!("/api/admin/v1/app_clusters/{cluster_id}"))
            .await;
        let _ = client
            .delete_auth(&format!("/api/admin/v1/apps/{app_id}"))
            .await;
        pool.close().await;
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
    async fn test_admin_list_router_bgp_routes() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/routers").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(routers) = body["data"].as_array()
            && let Some(r) = routers.first()
        {
            let r_id = r["id"].as_u64().unwrap();
            let resp = client
                .get_auth(&format!("/api/admin/v1/routers/{r_id}/bgp/routes"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_admin_set_default_route_validation() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/routers").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(routers) = body["data"].as_array()
            && let Some(r) = routers.first()
        {
            let r_id = r["id"].as_u64().unwrap();
            // Invalid next_hop is rejected by the handler.
            let resp = client
                .post_auth(
                    &format!("/api/admin/v1/routers/{r_id}/routes/default"),
                    &serde_json::json!({ "next_hop": "not-an-ip" }),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            assert!(!body["success"].as_bool().unwrap_or(true));
        }
    }

    #[tokio::test]
    async fn test_admin_clear_default_route() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/routers").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(routers) = body["data"].as_array()
            && let Some(r) = routers.first()
        {
            let r_id = r["id"].as_u64().unwrap();
            let resp = client
                .delete_auth(&format!("/api/admin/v1/routers/{r_id}/routes/default"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_admin_toggle_tunnel() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/routers").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        if let Some(routers) = body["data"].as_array()
            && let Some(r) = routers.first()
        {
            let r_id = r["id"].as_u64().unwrap();
            let resp = client
                .post_auth(
                    &format!("/api/admin/v1/routers/{r_id}/tunnels/gre1/toggle"),
                    &serde_json::json!({ "enabled": false }),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
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

    /// Renaming a referral code relinks a user's enrollment to a historical
    /// `vm.ref_code`. Verify the PATCH persists the new code, rejects an empty
    /// code, and rejects a code already taken by another referral.
    #[tokio::test]
    async fn test_admin_update_referral_code() {
        use nostr::Keys;

        let client = setup().await;
        let pool = crate::db::connect().await.unwrap();

        // Two separate referrers, each with their own auto-generated code.
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let user_a = crate::db::ensure_user(&pool, &keys_a).await.unwrap();
        let user_b = crate::db::ensure_user(&pool, &keys_b).await.unwrap();
        // Unique, <=20 char codes derived from the random pubkeys.
        let suffix = hex::encode(keys_a.public_key().to_bytes());
        let code_a = format!("A{}", &suffix[..7]);
        let code_b = format!("B{}", &suffix[..7]);
        let historical = format!("H{}", &suffix[..7]);

        let ref_a = crate::db::insert_referral(&pool, user_a, &code_a, None)
            .await
            .unwrap();
        let ref_b = crate::db::insert_referral(&pool, user_b, &code_b, None)
            .await
            .unwrap();

        // Empty code is rejected.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/referrals/{ref_a}"),
                &serde_json::json!({ "code": "  " }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A code already used by another referral is rejected.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/referrals/{ref_a}"),
                &serde_json::json!({ "code": code_b }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Renaming to a free historical code succeeds and persists.
        let resp = client
            .patch_auth(
                &format!("/api/admin/v1/referrals/{ref_a}"),
                &serde_json::json!({ "code": historical }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["code"].as_str().unwrap(), historical);

        crate::db::hard_delete_referral(&pool, ref_a).await.unwrap();
        crate::db::hard_delete_referral(&pool, ref_b).await.unwrap();
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

    /// Regression: creating IP space must persist company_id. The INSERT
    /// previously omitted the NOT-NULL company_id column, so this endpoint
    /// always failed at the DB layer.
    #[tokio::test]
    async fn test_admin_create_ip_space_persists_company_id() {
        let client = setup().await;

        // Pick an existing company id.
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let company_id = body["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["id"].as_u64())
            .unwrap_or(1);

        // min_prefix_size is the smallest subdivision (largest prefix number) and
        // must be >= max_prefix_size; for a /24 RIPE block that is min=/32, max=/24.
        let create_body = serde_json::json!({
            "company_id": company_id,
            "cidr": "203.0.113.0/24",
            "min_prefix_size": 32,
            "max_prefix_size": 24,
            "registry": 1
        });
        let resp = client
            .post_auth("/api/admin/v1/ip_space", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "IP space creation should succeed and persist company_id"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["company_id"].as_u64(),
            Some(company_id),
            "created IP space should carry the requested company_id"
        );
    }

    #[tokio::test]
    async fn test_admin_get_ip_space_with_pricing_and_subscriptions() {
        let client = setup().await;

        // Create a dedicated IP space and query THAT id, rather than picking
        // `spaces.first()` off the shared list: other tests create/delete IP
        // spaces concurrently, so the first-listed id could be deleted between
        // the sub-calls (a TOCTOU that made this test flaky under parallel
        // load). A self-owned space with a unique CIDR is deterministic.
        let resp = client.get_auth("/api/admin/v1/companies").await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let company_id = body["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|c| c["id"].as_u64())
            .unwrap_or(1);

        let create_body = serde_json::json!({
            "company_id": company_id,
            "cidr": "198.51.100.0/24",
            "min_prefix_size": 32,
            "max_prefix_size": 24,
            "registry": 1
        });
        let resp = client
            .post_auth("/api/admin/v1/ip_space", &create_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "create IP space");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let s_id = body["data"]["id"].as_u64().expect("created IP space id");

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

    /// Recording a refund against a paid payment (issue #193, part 2).
    ///
    /// Builds its own fixture the same way the complete-payment lifecycle test
    /// does — renew a VM to create an unpaid payment, complete it as admin —
    /// then refunds it in two halves and checks the ledger arithmetic on the
    /// way: the running total, the ceiling, the duplicate guard, and that the
    /// refund shows up as a refund row rather than another payment.
    #[tokio::test]
    async fn test_admin_record_payment_refund_lifecycle() {
        let user = user_client();
        let admin = setup().await;

        let resp = user.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let vms = body["data"].as_array().unwrap();
        if vms.is_empty() {
            eprintln!("Skipping refund test: no VMs found for test user");
            return;
        }
        let vm_id = vms[0]["id"].as_u64().unwrap();

        let resp = user
            .get_auth(&format!("/api/v1/vm/{vm_id}/renew"))
            .await
            .unwrap();
        if resp.status() != StatusCode::OK {
            eprintln!("Skipping refund test: renew failed (Lightning node likely unavailable)");
            return;
        }
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let payment_id = body["data"]["id"].as_str().unwrap().to_string();

        let resp = admin
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/{payment_id}/complete"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "complete payment");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let amount = body["data"]["amount"].as_u64().unwrap();
        let tax = body["data"]["tax"].as_u64().unwrap();
        assert!(amount > 1, "need a payment big enough to halve");

        // Nothing refunded yet: the whole payment is refundable.
        let refunds_url = format!("/api/admin/v1/vms/{vm_id}/payments/{payment_id}/refund");
        let resp = admin.get_auth(&refunds_url).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["refunded_total"].as_u64().unwrap(), 0);
        assert_eq!(
            body["data"]["refundable_remaining"].as_u64().unwrap(),
            amount
        );

        // Refund half of it, at a fixed timestamp so the duplicate guard below
        // is deterministic.
        let half = amount / 2;
        let at = 1_760_000_000i64;
        let first = serde_json::json!({
            "amount": half,
            "reason": "e2e-test partial refund",
            "external_ref": "e2e-preimage",
            "refunded_at": at
        });
        let resp = admin.post_auth(&refunds_url, &first).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "record refund");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let refund = &body["data"];
        assert_eq!(refund["payment_type"].as_str().unwrap(), "Refund");
        assert_eq!(
            refund["refunded_payment_id"].as_str().unwrap(),
            payment_id,
            "refund links to the payment it reverses"
        );
        assert_eq!(refund["amount"].as_u64().unwrap(), half);
        assert!(refund["is_paid"].as_bool().unwrap());
        // Tax is a slice of the tax actually charged, never more than it.
        assert!(refund["tax"].as_u64().unwrap() <= tax);

        // The same refund submitted twice is a conflict, not a second refund.
        let resp = admin.post_auth(&refunds_url, &first).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "duplicate refund");

        // More than what is left is refused.
        let too_much = serde_json::json!({ "amount": amount, "refunded_at": at + 1 });
        let resp = admin.post_auth(&refunds_url, &too_much).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "over-refund");

        // The running total moved by exactly what was refunded.
        let resp = admin.get_auth(&refunds_url).await.unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["refunded_total"].as_u64().unwrap(), half);
        assert_eq!(
            body["data"]["refundable_remaining"].as_u64().unwrap(),
            amount - half
        );
        assert_eq!(body["data"]["refunds"].as_array().unwrap().len(), 1);

        // Refund the remainder (amount omitted = everything still refundable),
        // then the payment is closed to further refunds.
        let rest = serde_json::json!({ "refunded_at": at + 2 });
        let resp = admin.post_auth(&refunds_url, &rest).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "refund the remainder");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["amount"].as_u64().unwrap(), amount - half);

        let resp = admin
            .post_auth(&refunds_url, &serde_json::json!({ "refunded_at": at + 3 }))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "fully refunded");

        // A refund cannot be refunded: it is not a sale.
        let refund_id = refund["id"].as_str().unwrap();
        let resp = admin
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/{refund_id}/refund"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "refund of a refund");

        // The refund rows are visible on the VM's payment list, typed, so a
        // client cannot mistake them for money the customer paid.
        let resp = admin
            .get_auth(&format!("/api/admin/v1/vms/{vm_id}/payments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let rows = body["data"].as_array().unwrap();
        let refunds: Vec<&Value> = rows
            .iter()
            .filter(|p| p["payment_type"].as_str() == Some("Refund"))
            .collect();
        assert!(refunds.len() >= 2, "both refunds listed: {}", rows.len());
    }

    /// A payment id that does not belong to the VM in the path cannot be
    /// refunded through it, and a malformed one is a 400 rather than a lookup.
    #[tokio::test]
    async fn test_admin_record_refund_rejects_bad_payment_ids() {
        let client = setup().await;
        let resp = client.get_auth("/api/admin/v1/vms?limit=1").await.unwrap();
        let data: ApiPaginatedData<Value> = parse_paginated(resp).await.unwrap();
        if data.data.is_empty() {
            eprintln!("Skipping: no VMs found for refund id test");
            return;
        }
        let vm_id = data.data[0]["id"].as_u64().unwrap();

        let fake = "0".repeat(64);
        let resp = client
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/{fake}/refund"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "unknown payment");

        let resp = client
            .post_auth(
                &format!("/api/admin/v1/vms/{vm_id}/payments/not-hex/refund"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "malformed id");
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
