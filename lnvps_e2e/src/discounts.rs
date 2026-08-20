//! E2E tests for the discount admin API.
//!
//! The customer-facing half — applying a code to a real order, VAT following
//! the discount, and redemption at settlement — is exercised by the lifecycle
//! test, which is the only place with a paid subscription to discount.

#[cfg(test)]
mod tests {
    use crate::client::*;
    use reqwest::StatusCode;
    use serde_json::{Value, json};

    async fn setup() -> TestClient {
        bootstrap_admin().await.unwrap();
        admin_client()
    }

    async fn json_ok(resp: reqwest::Response) -> Value {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "Expected 200, body: {body}");
        serde_json::from_str(&body).unwrap()
    }

    fn suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }

    /// A company to own the discounts created here.
    async fn company(admin: &TestClient, ts: u128) -> u64 {
        json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/companies",
                    &json!({
                        "name": format!("discount-e2e-{ts}"),
                        "email": format!("discount-{ts}@example.com"),
                        "base_currency": "EUR"
                    }),
                )
                .await
                .unwrap(),
        )
        .await["data"]["id"]
            .as_u64()
            .unwrap()
    }

    async fn create(admin: &TestClient, company_id: u64, code: &str, rule: &str) -> Value {
        json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts",
                    &json!({
                        "company_id": company_id,
                        "code": code,
                        "name": "e2e",
                        "rule": rule
                    }),
                )
                .await
                .unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn test_discount_endpoints_require_auth() {
        let client = admin_client_no_auth();
        for endpoint in ["/api/admin/v1/discounts", "/api/admin/v1/discounts/1"] {
            let resp = client.get(endpoint).await.unwrap();
            assert!(
                resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
                "{endpoint} should require auth, got {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn test_discount_crud_lifecycle() {
        let admin = setup().await;
        let ts = suffix();
        let company_id = company(&admin, ts).await;
        let code = format!("CRUD{ts}");

        let created = create(&admin, company_id, &code, "{'percent': 10}").await;
        let id = created["data"]["id"].as_u64().unwrap();
        assert_eq!(created["data"]["code"].as_str().unwrap(), code);
        assert!(created["data"]["active"].as_bool().unwrap());
        assert_eq!(created["data"]["used_count"].as_u64().unwrap(), 0);
        assert!(
            created["data"]["given_away"].as_array().unwrap().is_empty(),
            "a new campaign has cost nothing"
        );

        let fetched = json_ok(
            admin
                .get_auth(&format!("/api/admin/v1/discounts/{id}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(fetched["data"]["rule"].as_str().unwrap(), "{'percent': 10}");

        // Listing is per-company and paginated.
        let listed = json_ok(
            admin
                .get_auth(&format!(
                    "/api/admin/v1/discounts?company_id={company_id}&limit=10&offset=0"
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(listed["total"].as_u64().unwrap(), 1);
        assert!(
            listed["data"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["id"].as_u64() == Some(id))
        );

        let updated = json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/discounts/{id}"),
                    &json!({"rule": "{'percent': 25}", "usage_limit": 3, "active": false}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(updated["data"]["rule"].as_str().unwrap(), "{'percent': 25}");
        assert_eq!(updated["data"]["usage_limit"].as_u64().unwrap(), 3);
        assert!(!updated["data"]["active"].as_bool().unwrap());

        // Never redeemed, so it can still be deleted.
        let deleted = admin
            .delete_auth(&format!("/api/admin/v1/discounts/{id}"))
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::OK);
        let gone = admin
            .get_auth(&format!("/api/admin/v1/discounts/{id}"))
            .await
            .unwrap();
        assert_ne!(gone.status(), StatusCode::OK, "deleted discount is gone");
    }

    /// A code identifies one discount, or it is ambiguous when a customer
    /// types it.
    #[tokio::test]
    async fn test_duplicate_code_is_rejected() {
        let admin = setup().await;
        let ts = suffix();
        let company_id = company(&admin, ts).await;
        let code = format!("DUP{ts}");

        create(&admin, company_id, &code, "{'percent': 10}").await;
        let again = admin
            .post_auth(
                "/api/admin/v1/discounts",
                &json!({
                    "company_id": company_id,
                    "code": code,
                    "name": "e2e",
                    "rule": "{'percent': 10}"
                }),
            )
            .await
            .unwrap();
        assert_ne!(again.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_discounts_are_rejected() {
        let admin = setup().await;
        let ts = suffix();
        let company_id = company(&admin, ts).await;

        let cases = [
            // An unparseable rule must never reach a customer's order.
            json!({"company_id": company_id, "code": format!("BAD{ts}A"), "name": "e2e", "rule": "not cel {{"}),
            // Phase 1 is codes only; a code-less row would apply automatically,
            // which nothing evaluates yet.
            json!({"company_id": company_id, "code": "", "name": "e2e", "rule": "{'percent': 10}"}),
            json!({"company_id": company_id, "code": format!("BAD{ts}B"), "name": "  ", "rule": "{'percent': 10}"}),
            // A window that ends before it starts is never valid.
            json!({
                "company_id": company_id,
                "code": format!("BAD{ts}C"),
                "name": "e2e",
                "rule": "{'percent': 10}",
                "valid_from": "2030-01-01T00:00:00Z",
                "valid_to": "2029-01-01T00:00:00Z"
            }),
            // No such company.
            json!({"company_id": 9_999_999, "code": format!("BAD{ts}D"), "name": "e2e", "rule": "{'percent': 10}"}),
        ];
        for body in cases {
            let resp = admin
                .post_auth("/api/admin/v1/discounts", &body)
                .await
                .unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "should have been rejected: {body}"
            );
        }
    }

    /// The preview endpoint is what makes raw CEL safe to expose: it reports
    /// the clamped decision, and the reason for a failure, without saving.
    #[tokio::test]
    async fn test_rule_preview() {
        let admin = setup().await;

        let flat = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts/preview",
                    &json!({"rule": "{'percent': 10}"}),
                )
                .await
                .unwrap(),
        )
        .await;
        // The default sample order is 100.00 EUR.
        assert!(flat["data"]["applies"].as_bool().unwrap());
        assert_eq!(flat["data"]["amount_off"].as_u64().unwrap(), 1_000);

        // Over-100% is reported as what it will actually do.
        let clamped = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts/preview",
                    &json!({"rule": "{'percent': 900}"}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(clamped["data"]["percent"].as_u64().unwrap(), 100);
        assert_eq!(clamped["data"]["amount_off"].as_u64().unwrap(), 10_000);

        // A tiered rule against a supplied sample order.
        let tiered = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts/preview",
                    &json!({
                        "rule": "order.intervals >= 12 ? {'percent': 15} : {}",
                        "order": {"intervals": 12, "amount": 20000}
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(tiered["data"]["amount_off"].as_u64().unwrap(), 3_000);

        // A rule that declines is not an error.
        let declines = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts/preview",
                    &json!({"rule": "order.amount >= 999999 ? {'percent': 10} : {}"}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(!declines["data"]["applies"].as_bool().unwrap());
        assert!(declines["data"]["error"].is_null());

        // A broken rule reports why, rather than 500ing.
        let broken = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/discounts/preview",
                    &json!({"rule": "secrets.api_key"}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(!broken["data"]["applies"].as_bool().unwrap());
        assert!(
            broken["data"]["error"]
                .as_str()
                .unwrap()
                .contains("secrets")
        );

        // Returning something that is not a decision is a mistake worth
        // showing, not a 10% discount.
        let wrong_type = json_ok(
            admin
                .post_auth("/api/admin/v1/discounts/preview", &json!({"rule": "10"}))
                .await
                .unwrap(),
        )
        .await;
        assert!(!wrong_type["data"]["applies"].as_bool().unwrap());
        assert!(
            wrong_type["data"]["error"]
                .as_str()
                .unwrap()
                .contains("map")
        );
    }

    /// A rule can only see the fields the engine deliberately exposes.
    #[tokio::test]
    async fn test_rule_cannot_read_outside_its_context() {
        let admin = setup().await;
        for rule in [
            "user.pubkey",
            "user.billing_tax_id",
            "order.password",
            "db.users",
        ] {
            let out = json_ok(
                admin
                    .post_auth("/api/admin/v1/discounts/preview", &json!({"rule": rule}))
                    .await
                    .unwrap(),
            )
            .await;
            assert!(
                !out["data"]["applies"].as_bool().unwrap()
                    && out["data"]["error"].as_str().is_some(),
                "rule {rule} should not resolve"
            );
        }
    }
}
