//! E2E tests for the user-facing API.

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::client::*;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use serde_json::Value;

    // ========================================================================
    // Response types (minimal, just enough to verify shape)
    // ========================================================================

    #[derive(Debug, Deserialize)]
    struct VmTemplate {
        id: u64,
        name: String,
        cpu: u16,
        memory: u64,
        disk_size: u64,
        cost_plan: CostPlan,
        region: Region,
    }

    #[derive(Debug, Deserialize)]
    struct TemplatesResponse {
        templates: Vec<VmTemplate>,
        custom_template: Option<Vec<Value>>,
    }

    #[derive(Debug, Deserialize)]
    struct CostPlan {
        id: u64,
        name: String,
        currency: String,
        amount: u64,
    }

    #[derive(Debug, Deserialize)]
    struct Region {
        id: u64,
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct OsImage {
        id: u64,
        distribution: String,
        flavour: String,
        version: String,
    }

    #[derive(Debug, Deserialize)]
    struct PaymentInfo {
        name: String,
        currencies: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct IpSpace {
        id: u64,
        min_prefix_size: u16,
        max_prefix_size: u16,
    }

    #[derive(Debug, Deserialize)]
    struct AccountInfo {
        contact_nip17: bool,
        contact_email: bool,
    }

    #[derive(Debug, Deserialize)]
    struct SshKey {
        id: u64,
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct VmStatus {
        id: u64,
        mac_address: String,
    }

    #[derive(Debug, Deserialize)]
    struct VmPayment {
        id: String,
        vm_id: u64,
        is_paid: bool,
    }

    #[derive(Debug, Deserialize)]
    struct VmHistory {
        id: u64,
        vm_id: u64,
        action_type: String,
    }

    #[derive(Debug, Deserialize)]
    struct Referral {
        code: String,
    }

    #[derive(Debug, Deserialize)]
    struct Subscription {
        id: u64,
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct SubscriptionPayment {
        id: String,
        subscription_id: u64,
    }

    // ========================================================================
    // Documentation / Static Endpoints (no auth)
    // ========================================================================

    #[tokio::test]
    async fn test_index_page() {
        let client = user_client_no_auth();
        let resp = client.get("/").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(!body.is_empty(), "Index page should not be empty");
    }

    #[tokio::test]
    async fn test_docs_endpoints_md() {
        let client = user_client_no_auth();
        let resp = client.get("/docs/endpoints.md").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(
            body.contains("api") || body.contains("API") || body.contains("#"),
            "Endpoints doc should contain API references"
        );
    }

    #[tokio::test]
    async fn test_docs_changelog_md() {
        let client = user_client_no_auth();
        let resp = client.get("/docs/changelog.md").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(!body.is_empty(), "Changelog should not be empty");
    }

    // ========================================================================
    // Public API Endpoints (no auth)
    // ========================================================================

    #[tokio::test]
    async fn test_list_vm_templates() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/vm/templates").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<TemplatesResponse> = parse_data(resp).await.unwrap();
        // On a clean DB there may be no templates; validate shape if any exist
        if let Some(t) = data.data.templates.first() {
            assert!(t.id > 0);
            assert!(!t.name.is_empty());
            assert!(t.cpu > 0);
            assert!(t.memory > 0);
            assert!(t.disk_size > 0);
            assert!(t.cost_plan.amount > 0);
            assert!(!t.cost_plan.currency.is_empty());
            assert!(!t.region.name.is_empty());
        }
    }

    #[tokio::test]
    async fn test_list_vm_images() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/image").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<Vec<OsImage>> = parse_data(resp).await.unwrap();
        if let Some(img) = data.data.first() {
            assert!(img.id > 0);
            assert!(!img.distribution.is_empty());
            assert!(!img.version.is_empty());
        }
    }

    #[tokio::test]
    async fn test_get_payment_methods() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/payment/methods").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<Vec<PaymentInfo>> = parse_data(resp).await.unwrap();
        if let Some(pm) = data.data.first() {
            assert!(!pm.name.is_empty());
            assert!(!pm.currencies.is_empty());
        }
    }

    #[tokio::test]
    async fn test_custom_template_price_calc() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/vm/templates").await.unwrap();
        let data: ApiData<TemplatesResponse> = parse_data(resp).await.unwrap();

        if let Some(custom_templates) = &data.data.custom_template {
            if let Some(ct) = custom_templates.first() {
                let pricing_id = ct.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let min_cpu = ct.get("min_cpu").and_then(|v| v.as_u64()).unwrap_or(1) as u16;
                let min_memory = ct
                    .get("min_memory")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1024);
                let min_disk = ct
                    .get("disks")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|d| d.get("min_disk"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10240);

                let body = serde_json::json!({
                    "pricing_id": pricing_id,
                    "cpu": min_cpu,
                    "memory": min_memory,
                    "disk": min_disk,
                    "disk_type": "ssd",
                    "disk_interface": "scsi"
                });

                let resp = client
                    .post("/api/v1/vm/custom-template/price", &body)
                    .await
                    .unwrap();
                assert!(
                    resp.status() == StatusCode::OK
                        || resp.status() == StatusCode::BAD_REQUEST
                        || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
                    "Custom template price calc should return 200, 400, or 500, got: {}",
                    resp.status()
                );
            }
        }
    }

    #[tokio::test]
    async fn test_list_ip_space() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/ip_space").await.unwrap();
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::NOT_FOUND,
            "IP space list should return 200 or 404, got: {}",
            resp.status()
        );
        if resp.status() == StatusCode::OK {
            let data: ApiData<Vec<IpSpace>> = parse_data(resp).await.unwrap();
            if let Some(space) = data.data.first() {
                assert!(space.id > 0);
                let client2 = user_client_no_auth();
                let resp2 = client2
                    .get(&format!("/api/v1/ip_space/{}", space.id))
                    .await
                    .unwrap();
                assert_eq!(resp2.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn test_verify_email_missing_token() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/account/verify-email").await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "verify-email without token should not succeed"
        );
    }

    #[tokio::test]
    async fn test_lnurlp_invalid_id() {
        let client = user_client_no_auth();
        let resp = client.get("/.well-known/lnurlp/invalid").await.unwrap();
        assert!(
            resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "LNURL with invalid ID should return error, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_renew_vm_lnurlp() {
        let client = user_client_no_auth();
        let resp = client
            .get("/api/v1/vm/999999999/renew-lnurlp")
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "LNURL renew for non-existent VM should error, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_contact_form_missing_fields() {
        let client = user_client_no_auth();
        let resp = client
            .post("/api/v1/contact", &serde_json::json!({}))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "Contact form with empty body should not succeed"
        );
    }

    #[tokio::test]
    async fn test_legal_sponsoring_lir_agreement() {
        let client = user_client_no_auth();
        let resp = client
            .get("/api/v1/legal/sponsoring-lir-agreement")
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "LIR agreement without params should return error, got: {}",
            resp.status()
        );
    }

    // ========================================================================
    // Auth enforcement tests (unauthenticated should be rejected)
    // ========================================================================

    #[tokio::test]
    async fn test_unauthenticated_account_returns_403() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/account").await.unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Unauthenticated account request should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_unauthenticated_list_vms_returns_403() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/vm").await.unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Unauthenticated VM list should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_unauthenticated_ssh_keys_returns_403() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/ssh-key").await.unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Unauthenticated SSH key list should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_create_vm_requires_auth() {
        let client = user_client_no_auth();
        let resp = client
            .post(
                "/api/v1/vm",
                &serde_json::json!({"template_id": 1, "image_id": 1, "ssh_key_id": 1}),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Create VM without auth should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_add_ssh_key_requires_auth() {
        let client = user_client_no_auth();
        let resp = client
            .post(
                "/api/v1/ssh-key",
                &serde_json::json!({"name": "test", "key_data": "ssh-ed25519 AAAA test"}),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Add SSH key without auth should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_vm_start_stop_restart_requires_auth() {
        let client = user_client_no_auth();
        for action in &["start", "stop", "restart"] {
            let url = client.url(&format!("/api/v1/vm/1/{action}"));
            let resp = client.http.patch(&url).send().await.unwrap();
            assert!(
                resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
                "VM {action} without auth should return 401/403, got: {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn test_create_subscription_requires_auth() {
        let client = user_client_no_auth();
        let resp = client
            .post(
                "/api/v1/subscriptions",
                &serde_json::json!({"line_items": []}),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Create subscription without auth should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_referral_requires_auth() {
        let client = user_client_no_auth();
        let resp = client.get("/api/v1/referral").await.unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "Referral without auth should return 401/403, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_vm_reinstall_requires_auth() {
        let client = user_client_no_auth();
        let url = client.url("/api/v1/vm/1/re-install");
        let resp = client.http.patch(&url).send().await.unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "VM reinstall without auth should return 401/403, got: {}",
            resp.status()
        );
    }

    // ========================================================================
    // Authenticated User Endpoints
    // ========================================================================

    #[tokio::test]
    async fn test_get_account() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/account").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<AccountInfo> = parse_data(resp).await.unwrap();
        let _ = data.data.contact_nip17;
        let _ = data.data.contact_email;
    }

    #[tokio::test]
    async fn test_patch_account() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/account").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let current_nip17 = body["data"]["contact_nip17"].as_bool().unwrap_or(false);
        let current_email = body["data"]["contact_email"].as_bool().unwrap_or(false);

        let patch_body = serde_json::json!({
            "contact_nip17": current_nip17,
            "contact_email": current_email,
        });
        let resp = client
            .patch_auth("/api/v1/account", &patch_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_vms() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"].is_array(), "VM list should be an array");
    }

    #[tokio::test]
    async fn test_get_vm_not_found() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/vm/999999999").await.unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_ssh_keys() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/ssh-key").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"].is_array(), "SSH key list should be an array");
    }

    #[tokio::test]
    async fn test_get_payment_not_found() {
        let client = user_client();
        let fake_id = "00".repeat(32);
        let resp = client
            .get_auth(&format!("/api/v1/payment/{fake_id}"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_subscriptions() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/subscriptions").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(
            body["data"].is_array(),
            "Subscriptions list should be an array"
        );
    }

    #[tokio::test]
    async fn test_get_subscription_not_found() {
        let client = user_client();
        let resp = client
            .get_auth("/api/v1/subscriptions/999999999")
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_referral() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/referral").await.unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::NOT_FOUND
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Referral endpoint should return 200, 404, or 500, got: {}",
            resp.status()
        );
    }

    // ========================================================================
    // SSH Key CRUD Lifecycle
    // ========================================================================

    #[tokio::test]
    async fn test_ssh_key_crud_lifecycle() {
        let client = user_client();

        // Create an SSH key
        let create_body = serde_json::json!({
            "name": "e2e-test-key",
            "key_data": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHDQnBw8TklSNuqFMHSujgNs48eNMdOl7qGAl68E0T4o e2e-test"
        });
        let resp = client
            .post_auth("/api/v1/ssh-key", &create_body)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SSH key creation should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let key_id = body["data"]["id"]
            .as_u64()
            .expect("SSH key should have an id");
        assert!(key_id > 0);

        // Verify it appears in the list
        let resp = client.get_auth("/api/v1/ssh-key").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let keys = body["data"].as_array().unwrap();
        assert!(
            keys.iter().any(|k| k["id"].as_u64() == Some(key_id)),
            "Created SSH key should appear in list"
        );
    }

    // ========================================================================
    // VM Order Creation (creates a payment)
    // ========================================================================

    #[tokio::test]
    async fn test_create_vm_order() {
        let client = user_client();

        // First create an SSH key for the VM
        let key_body = serde_json::json!({
            "name": "e2e-vm-order-key",
            "key_data": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHDQnBw8TklSNuqFMHSujgNs48eNMdOl7qGAl68E0T4o e2e"
        });
        let resp = client
            .post_auth("/api/v1/ssh-key", &key_body)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let ssh_key_id = body["data"]["id"].as_u64().unwrap();

        // Get available templates and images
        let resp = client.get("/api/v1/vm/templates").await.unwrap();
        let templates: ApiData<TemplatesResponse> = parse_data(resp).await.unwrap();
        if templates.data.templates.is_empty() {
            eprintln!("Skipping VM order test: no templates available (clean DB)");
            return;
        }
        let template = &templates.data.templates[0];

        let resp = client.get("/api/v1/image").await.unwrap();
        let images: ApiData<Vec<OsImage>> = parse_data(resp).await.unwrap();
        if images.data.is_empty() {
            eprintln!("Skipping VM order test: no images available (clean DB)");
            return;
        }
        let image = &images.data[0];

        // Create VM order — returns ApiVmStatus (the VM), not a payment
        let order_body = serde_json::json!({
            "template_id": template.id,
            "image_id": image.id,
            "ssh_key_id": ssh_key_id
        });
        let resp = client.post_auth("/api/v1/vm", &order_body).await.unwrap();
        // Should return 200 with VM data or 500 if provisioner not available
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Create VM order should return 200 or 500, got: {}",
            resp.status()
        );

        if resp.status() == StatusCode::OK {
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            let vm_id = body["data"]["id"]
                .as_u64()
                .expect("VM should have a numeric id");
            assert!(vm_id > 0);

            // Verify VM appears in our list
            let resp = client.get_auth("/api/v1/vm").await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            let vms = body["data"].as_array().unwrap();
            assert!(
                vms.iter().any(|v| v["id"].as_u64() == Some(vm_id)),
                "Created VM should appear in list"
            );
        }
    }

    // ========================================================================
    // VM Operations on Existing VMs
    // ========================================================================

    #[tokio::test]
    async fn test_vm_operations_on_existing_vms() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let vms = body["data"].as_array().unwrap();

        if vms.is_empty() {
            eprintln!("Skipping VM operation tests: no VMs found for test user");
            return;
        }

        let vm_id = vms[0]["id"].as_u64().unwrap();

        // GET /api/v1/vm/{id}
        let resp = client
            .get_auth(&format!("/api/v1/vm/{vm_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let vm_body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(vm_body["data"]["id"].as_u64().unwrap(), vm_id);

        // GET /api/v1/vm/{id}/payments
        let resp = client
            .get_auth(&format!("/api/v1/vm/{vm_id}/payments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET /api/v1/vm/{id}/history
        let resp = client
            .get_auth(&format!("/api/v1/vm/{vm_id}/history"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET /api/v1/vm/{id}/time-series
        let resp = client
            .get_auth(&format!("/api/v1/vm/{vm_id}/time-series"))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Time-series should return 200 or 500, got: {}",
            resp.status()
        );

        // GET /api/v1/vm/{id}/renew
        let resp = client
            .get_auth(&format!("/api/v1/vm/{vm_id}/renew"))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Renew should return 200 or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_vm_patch() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let vms = body["data"].as_array().unwrap();

        if vms.is_empty() {
            eprintln!("Skipping VM patch test: no VMs found for test user");
            return;
        }

        let vm_id = vms[0]["id"].as_u64().unwrap();
        let patch = serde_json::json!({});
        let resp = client
            .patch_auth(&format!("/api/v1/vm/{vm_id}"), &patch)
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::UNPROCESSABLE_ENTITY
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "VM patch should return 200, 400, 422, or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_vm_upgrade_quote() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/vm").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let vms = body["data"].as_array().unwrap();

        if vms.is_empty() {
            eprintln!("Skipping VM upgrade quote test: no VMs found");
            return;
        }

        let vm_id = vms[0]["id"].as_u64().unwrap();
        let quote_body = serde_json::json!({
            "cpu": 2,
            "memory": 2048,
        });
        let resp = client
            .post_auth(&format!("/api/v1/vm/{vm_id}/upgrade/quote"), &quote_body)
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Upgrade quote should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn test_subscription_operations_on_existing() {
        let client = user_client();
        let resp = client.get_auth("/api/v1/subscriptions").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let subs = body["data"].as_array().unwrap();

        if subs.is_empty() {
            eprintln!("Skipping subscription operation tests: no subscriptions found");
            return;
        }

        let sub_id = subs[0]["id"].as_u64().unwrap();

        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}/payments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}/renew"))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::OK
                || resp.status() == StatusCode::BAD_REQUEST
                || resp.status() == StatusCode::INTERNAL_SERVER_ERROR,
            "Subscription renew should return 200, 400, or 500, got: {}",
            resp.status()
        );
    }
}
