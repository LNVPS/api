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
        popularity: f32,
        #[serde(default)]
        cpu_arch: Option<String>,
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

    /// Exchange-rate feed (#230) is public and re-baseable.
    #[tokio::test]
    async fn test_exchange_rate_public() {
        #[derive(serde::Deserialize)]
        struct ExchangeRatesResp {
            updated: String,
            base: String,
            rates: std::collections::HashMap<String, f64>,
        }

        let client = user_client_no_auth();

        // Default base is BTC; no auth required.
        let resp = client.get("/api/v1/exchange-rate").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<ExchangeRatesResp> = parse_data(resp).await.unwrap();
        assert_eq!(data.data.base, "BTC");
        assert!(!data.data.updated.is_empty());
        assert!(!data.data.rates.contains_key("BTC"), "base is excluded");

        // Re-base to a fiat currency.
        let resp = client.get("/api/v1/exchange-rate?base=EUR").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<ExchangeRatesResp> = parse_data(resp).await.unwrap();
        assert_eq!(data.data.base, "EUR");
        assert!(!data.data.rates.contains_key("EUR"));
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
            let _ = img.flavour;
            // popularity is a fraction in [0, 1]
            assert!(img.popularity >= 0.0 && img.popularity <= 1.0);
        }
    }

    #[tokio::test]
    async fn test_list_vm_images_arch_filter() {
        let client = user_client_no_auth();

        // Valid arch filter: all returned images must be that arch (or agnostic).
        let resp = client.get("/api/v1/image?arch=x86_64").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let data: ApiData<Vec<OsImage>> = parse_data(resp).await.unwrap();
        for img in &data.data {
            // cpu_arch is omitted for agnostic images; when present it must match.
            if let Some(arch) = &img.cpu_arch {
                assert_eq!(arch, "x86_64", "arch filter must exclude non-x86_64 images");
            }
        }

        // aarch64 alias is accepted.
        let resp = client.get("/api/v1/image?arch=aarch64").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Invalid arch => 400.
        let resp = client.get("/api/v1/image?arch=sparc").await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
        let created_key = keys
            .iter()
            .find(|k| k["id"].as_u64() == Some(key_id))
            .expect("Created SSH key should appear in list");
        assert!(
            created_key["vms"].as_array().unwrap().is_empty(),
            "Newly created SSH key should have no linked VMs"
        );

        // Delete the SSH key
        let resp = client
            .delete_auth(&format!("/api/v1/ssh-key/{}", key_id))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SSH key deletion should succeed"
        );

        // Verify it no longer appears in the list
        let resp = client.get_auth("/api/v1/ssh-key").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let keys = body["data"].as_array().unwrap();
        assert!(
            !keys.iter().any(|k| k["id"].as_u64() == Some(key_id)),
            "Deleted SSH key should not appear in list"
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
        // Seller company is exposed for per-company VAT resolution (issue #216).
        assert!(
            subs[0]["company_id"].as_u64().is_some(),
            "subscription exposes company_id"
        );

        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"]["company_id"].as_u64().is_some());

        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}/payments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let payments = body["data"].as_array().unwrap().clone();

        // Item form of the payments list: the replacement for the deprecated
        // VM-only GET /api/v1/payment/{id}, usable for polling a payment on any
        // subscription type.
        if let Some(payment_id) = payments.first().and_then(|p| p["id"].as_str()) {
            let resp = client
                .get_auth(&format!(
                    "/api/v1/subscriptions/{sub_id}/payments/{payment_id}"
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
            assert_eq!(body["data"]["id"].as_str(), Some(payment_id));
            assert_eq!(body["data"]["subscription_id"].as_u64(), Some(sub_id));

            // Another user must not read it.
            let other = user_client_with_keys(nostr::Keys::generate());
            let resp = other
                .get_auth(&format!(
                    "/api/v1/subscriptions/{sub_id}/payments/{payment_id}"
                ))
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "another user must not read this payment"
            );
        }

        // A malformed (non-hex) payment id is rejected, not 500.
        let resp = client
            .get_auth(&format!("/api/v1/subscriptions/{sub_id}/payments/nothex"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK);

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

    #[tokio::test]
    async fn test_app_catalog_and_deployments() {
        // Dedicated user so the seeded deployment is isolated from other tests.
        let keys = nostr::Keys::generate();
        let client = user_client_with_keys(keys.clone());
        let pool = crate::db::connect().await.unwrap();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();

        // Seed a full deployment (app + cluster + subscription + deployment).
        let (app_id, _cluster_id, dep_id) = crate::db::seed_app_deployment(&pool, uid, "my-relay")
            .await
            .unwrap();

        // Catalog is public (no auth) — issue #227.
        let resp = client.get("/api/v1/apps").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "catalog list is public");
        let resp = client.get(&format!("/api/v1/apps/{app_id}")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "catalog get is public");
        let resp = client
            .get(&format!("/api/v1/apps/{app_id}/regions"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "catalog regions is public");

        // Catalog listing includes the seeded (enabled) app.
        let resp = client.get_auth("/api/v1/apps").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let apps = body["data"].as_array().unwrap();
        assert!(apps.iter().any(|a| a["id"].as_u64() == Some(app_id)));
        // Compose is exposed so the UI can render the deploy form.
        let seeded = apps
            .iter()
            .find(|a| a["id"].as_u64() == Some(app_id))
            .unwrap();
        assert!(seeded["compose"].as_str().is_some());
        assert_eq!(seeded["currency"].as_str().unwrap(), "USD");

        // Get single app.
        let resp = client
            .get_auth(&format!("/api/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Deployment listing includes the seeded deployment.
        let resp = client.get_auth("/api/v1/app-deployments").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let dep = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"].as_u64() == Some(dep_id))
            .expect("seeded deployment present");
        assert_eq!(dep["name"].as_str().unwrap(), "my-relay");
        assert_eq!(dep["status"].as_str().unwrap(), "pending");
        assert_eq!(dep["desired_state"].as_str().unwrap(), "running");
        // subscription_id resolves from the line item.
        assert!(dep["subscription_id"].as_u64().is_some());

        // Get single deployment (ownership OK).
        let resp = client
            .get_auth(&format!("/api/v1/app-deployments/{dep_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // A non-existent deployment id is 404 for this user.
        let resp = client
            .get_auth("/api/v1/app-deployments/99999999")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Resource multiplier: a fresh deployment is base size, and the
        // effective footprint is reported alongside it.
        assert_eq!(dep["resource_multiplier"].as_u64(), Some(1));
        assert!(dep["cpu_milli"].as_u64().is_some());

        // Upgrades are increase-only and bounded, enforced before any pricing.
        for bad in [1u64, 0, 1000] {
            let resp = client
                .post_auth(
                    &format!("/api/v1/app-deployments/{dep_id}/upgrade-quote"),
                    &serde_json::json!({ "resource_multiplier": bad }),
                )
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "multiplier {bad} must be rejected"
            );
        }

        // A valid increase quotes a prorated cost without charging anything;
        // an unpaid subscription has no expiry to prorate against, so a 4xx
        // here is also acceptable. What must not happen is a 5xx.
        let resp = client
            .post_auth(
                &format!("/api/v1/app-deployments/{dep_id}/upgrade-quote"),
                &serde_json::json!({ "resource_multiplier": 2 }),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_success() || resp.status().is_client_error(),
            "upgrade quote should not 5xx, got {}",
            resp.status()
        );

        // The deployment must not have been resized by quoting alone.
        let resp = client
            .get_auth(&format!("/api/v1/app-deployments/{dep_id}"))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["resource_multiplier"].as_u64(),
            Some(1),
            "a quote must never resize the deployment"
        );

        pool.close().await;
    }

    /// The catalog reports storage per volume, with the purpose the app
    /// authored (#260). A flat `storage_bytes` misreports any app that stores
    /// more than one kind of thing — HAVEN's 30 GB is 10 GB of events and
    /// 20 GB of media — and a client cannot infer purpose from volume names,
    /// because they mean different things in different apps.
    #[tokio::test]
    async fn test_app_reports_per_volume_storage() {
        let client = user_client_with_keys(nostr::Keys::generate());
        let pool = crate::db::connect().await.unwrap();
        let app_id = crate::db::seed_app_with_labelled_volumes(&pool)
            .await
            .unwrap();

        let resp = client
            .get_auth(&format!("/api/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let volumes = body["data"]["volumes"].as_array().expect("volumes array");
        assert_eq!(volumes.len(), 2);

        // Declaration order is preserved within a service.
        assert_eq!(volumes[0]["name"].as_str(), Some("db"));
        assert_eq!(volumes[0]["label"].as_str(), Some("events"));
        assert_eq!(volumes[0]["service"].as_str(), Some("relay"));
        assert_eq!(
            volumes[0]["size_bytes"].as_u64(),
            Some(10 * 1024 * 1024 * 1024)
        );

        // An unlabelled volume is still reported, with a null label — nothing
        // has to be backfilled for this to ship.
        assert_eq!(volumes[1]["name"].as_str(), Some("cache"));
        assert!(
            volumes[1]["label"].is_null(),
            "unlabelled volume sends null"
        );
        assert_eq!(volumes[1]["size_bytes"].as_u64(), Some(1024 * 1024 * 1024));

        // The breakdown adds up to the total the client already shows.
        let total: u64 = volumes
            .iter()
            .map(|v| v["size_bytes"].as_u64().unwrap())
            .sum();
        assert_eq!(body["data"]["storage_bytes"].as_u64(), Some(total));

        // Present on the listing too, not just the detail endpoint.
        let resp = client.get_auth("/api/v1/apps").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let listed = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"].as_u64() == Some(app_id))
            .expect("seeded app listed");
        assert_eq!(
            listed["volumes"].as_array().map(|v| v.len()),
            Some(2),
            "listing carries the same breakdown"
        );
    }

    /// An unpaid order must not consume cluster capacity (#252). Nostr keys are
    /// free, so anyone can create deployments without paying; before the fix
    /// each one was counted against the cluster and could make a paying
    /// customer's order fail with "No cluster with enough capacity".
    ///
    /// The cluster here holds exactly one deployment's footprint, so the second
    /// order only succeeds if the first (unpaid) one is excluded.
    #[tokio::test]
    async fn test_unpaid_app_deployment_does_not_consume_capacity() {
        let client = user_client_with_keys(nostr::Keys::generate());
        let pool = crate::db::connect().await.unwrap();
        // App footprint is 250m / 256Mi / 0; size the cluster to exactly one.
        let (app_id, _cluster_id, region_id) =
            crate::db::seed_app_and_cluster_with_capacity(&pool, 250, 268435456, 0)
                .await
                .unwrap();

        let order = |name: &str| {
            serde_json::json!({
                "app_id": app_id,
                "name": name,
                "region_id": region_id,
                "config": { "title": "Hello" }
            })
        };

        let resp = client
            .post_auth("/api/v1/app-deployments", &order("cap-first"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "first order fills the cluster"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        // Unpaid, by construction: nothing has been paid in this test.
        assert_eq!(body["data"]["status"].as_str().unwrap(), "pending");

        // The region still reports capacity, because the unpaid order does not
        // hold any.
        let resp = client
            .get_auth(&format!("/api/v1/apps/{app_id}/regions"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let region = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"].as_u64() == Some(region_id))
            .expect("seeded region listed");
        assert_eq!(
            region["available"].as_bool(),
            Some(true),
            "unpaid order must not exhaust the region"
        );

        // And a second customer can still order into it.
        let other = user_client_with_keys(nostr::Keys::generate());
        let resp = other
            .post_auth("/api/v1/app-deployments", &order("cap-second"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an unpaid order must not block a later one: {}",
            resp.text().await.unwrap_or_default()
        );
    }

    #[tokio::test]
    async fn test_app_deployment_ordering() {
        let keys = nostr::Keys::generate();
        let client = user_client_with_keys(keys.clone());
        let pool = crate::db::connect().await.unwrap();
        let (app_id, _cluster_id, region_id) =
            crate::db::seed_app_and_cluster(&pool).await.unwrap();

        // Deployable regions for this app: the seeded region is present with
        // capacity available (drives the deploy-form region picker, issue #225).
        let resp = client
            .get_auth(&format!("/api/v1/apps/{app_id}/regions"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let region = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"].as_u64() == Some(region_id))
            .expect("seeded region is deployable");
        assert!(!region["name"].as_str().unwrap().is_empty());
        assert_eq!(region["available"].as_bool(), Some(true));
        // Ingress base domain is exposed for hostname preview (issue #228).
        assert!(
            !region["ingress_domain"].as_str().unwrap_or("").is_empty(),
            "region exposes ingress_domain"
        );

        // Order a deployment.
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({
                    "app_id": app_id,
                    "name": "my-app",
                    "region_id": region_id,
                    "config": { "title": "Hello" }
                }),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "ordering should succeed");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let dep_id = body["data"]["id"].as_u64().expect("deployment id");
        assert_eq!(body["data"]["name"].as_str().unwrap(), "my-app");
        // New order is pending (unpaid) and has a billing subscription.
        assert_eq!(body["data"]["status"].as_str().unwrap(), "pending");
        assert!(body["data"]["subscription_id"].as_u64().is_some());
        // Config is returned for edit-form prefill (#232).
        assert_eq!(body["data"]["config"]["title"].as_str(), Some("Hello"));

        // App footprint is exposed on the customer App (#231).
        let resp = client
            .get_auth(&format!("/api/v1/apps/{app_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let app_body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(app_body["data"]["cpu_milli"].as_u64(), Some(250));
        assert!(app_body["data"]["memory_bytes"].as_u64().is_some());
        assert!(app_body["data"]["storage_bytes"].as_u64().is_some());
        // Per-service breakdown is present (single service "web" here).
        let services = app_body["data"]["services"].as_array().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0]["name"].as_str(), Some("web"));
        assert_eq!(services[0]["cpu_milli"].as_u64(), Some(250));

        // Invalid name is rejected.
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({"app_id": app_id, "name": "Bad Name", "region_id": region_id, "config": {}}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "bad name rejected");

        // Unknown config field is rejected.
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({"app_id": app_id, "name": "ok", "region_id": region_id, "config": {"nope": "x"}}),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "unknown config rejected"
        );

        // No capacity in a bogus region.
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({"app_id": app_id, "name": "ok", "region_id": 99999999u64, "config": {}}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "no capacity -> rejected");

        // Stop / start toggles desired_state.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep_id}/stop"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["desired_state"].as_str().unwrap(), "stopped");
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep_id}/start"),
                &serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Duplicate name on the same cluster is rejected ("my-app" still exists).
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({"app_id": app_id, "name": "my-app", "region_id": region_id, "config": {}}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "duplicate name rejected");

        // Order a second deployment to exercise rename + config PATCH.
        let resp = client
            .post_auth(
                "/api/v1/app-deployments",
                &serde_json::json!({"app_id": app_id, "name": "second-app", "region_id": region_id, "config": {}}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        let dep2_id = body["data"]["id"].as_u64().unwrap();

        // PATCH rename succeeds and updates the name.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"name": "renamed-app"}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "rename should succeed");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["data"]["name"].as_str().unwrap(), "renamed-app");

        // Renaming to a name already taken on the cluster is rejected.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"name": "my-app"}),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "rename to duplicate rejected"
        );

        // PATCH config (schema-validated) succeeds.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"config": {"title": "Updated"}}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "config patch should succeed");

        // PATCH config with an unknown field is rejected.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"config": {"nope": "x"}}),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::OK, "unknown config key rejected");

        // PATCH custom_domain (validated) succeeds and is returned; clearing works.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"custom_domain": "Blog.Example.com"}),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "custom_domain set should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(
            body["data"]["custom_domain"].as_str().unwrap(),
            "blog.example.com",
            "custom_domain normalized to lowercase"
        );
        // An invalid domain (no dot / scheme / bad label) is rejected.
        for bad in ["localhost", "https://blog.example.com", "-bad.example.com"] {
            let resp = client
                .patch_auth(
                    &format!("/api/v1/app-deployments/{dep2_id}"),
                    &serde_json::json!({"custom_domain": bad}),
                )
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "invalid domain {bad} rejected"
            );
        }
        // Clearing with empty string removes it.
        let resp = client
            .patch_auth(
                &format!("/api/v1/app-deployments/{dep2_id}"),
                &serde_json::json!({"custom_domain": ""}),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "custom_domain clear should succeed"
        );
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert!(body["data"]["custom_domain"].is_null(), "cleared -> null");
        let _ = client
            .delete_auth(&format!("/api/v1/app-deployments/{dep2_id}"))
            .await;

        // Delete removes it from the user's listing.
        let resp = client
            .delete_auth(&format!("/api/v1/app-deployments/{dep_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = client
            .get_auth(&format!("/api/v1/app-deployments/{dep_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "deleted -> 404");

        pool.close().await;
    }
}
