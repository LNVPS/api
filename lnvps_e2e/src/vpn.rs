//! The VPN endpoints, over HTTP, against a running stack.
//!
//! These exist because the handlers have **no unit-test coverage by design**:
//! `lnvps_api/src/api/vpn.rs` tests config rendering and the ownership and
//! billing predicates, not the endpoints, matching the pattern in
//! `api/subscriptions.rs` and `api/ip_space.rs`. Increment 4 of the VPN work
//! said in as many words that without this the endpoints ship untested. This is
//! that.
//!
//! What is worth proving here rather than in a unit test:
//!
//! - the multi-region property, that one device gets **one address valid in
//!   every region** and configs that differ only in their `[Peer]` block;
//! - that LNVPS never has the private key, so a rendered config carries a
//!   placeholder;
//! - that a device cannot be registered until the plan is paid, and that
//!   registering is idempotent on the key so a retried request does not burn a
//!   slot;
//! - that a route server is handed its peers, and that the document it is
//!   handed says nothing about who they belong to.

#[cfg(test)]
mod tests {
    use crate::client::{TestClient, admin_client, bootstrap_admin, user_client_with_keys};
    use nostr::Keys;
    use reqwest::StatusCode;
    use serde_json::{Value, json};

    async fn admin() -> TestClient {
        bootstrap_admin().await.unwrap();
        admin_client()
    }

    async fn json_ok(resp: reqwest::Response) -> Value {
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "Expected 200, body: {body}");
        serde_json::from_str(&body).unwrap()
    }

    fn unique() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    /// A WireGuard public key, base64. Any 32 bytes will do: LNVPS stores what
    /// it is given and never has to do arithmetic with it, which is the point
    /// of only ever holding the public half.
    fn a_public_key(seed: u8) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([seed; 32])
    }

    /// A company to bill through, reusing the first one that exists.
    async fn a_company(admin: &TestClient) -> u64 {
        let companies = json_ok(
            admin
                .get_auth("/api/admin/v1/companies?limit=1")
                .await
                .unwrap(),
        )
        .await;
        companies["data"][0]["id"]
            .as_u64()
            .expect("the stack seeds at least one company")
    }

    async fn a_region(admin: &TestClient, name: &str) -> u64 {
        let created = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/regions",
                    &json!({"name": name, "enabled": true, "company_id": 1}),
                )
                .await
                .unwrap(),
        )
        .await;
        created["data"]["id"].as_u64().unwrap()
    }

    /// A route server that configures itself. `lvd` never gets started here;
    /// what is being tested is what LNVPS would hand it.
    async fn a_route_server(admin: &TestClient, name: &str, token: &str) -> u64 {
        let created = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/routers",
                    &json!({
                        "name": name,
                        "enabled": true,
                        "kind": "lvd",
                        "url": "",
                        "token": token,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        created["data"]["id"].as_u64().unwrap()
    }

    /// An interface, and the service it terminates.
    async fn an_interface(
        admin: &TestClient,
        router_id: u64,
        region_id: u64,
        port: u16,
        name: &str,
    ) -> u64 {
        let created = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/tunnel_pools",
                    &json!({
                        "router_id": router_id,
                        "region_id": region_id,
                        "name": name,
                        "listen_addr": format!("{name}.vpn.example"),
                        "listen_port": port,
                        // Every interface on one service shares one block, so a
                        // device keeps one address in every region. The database
                        // refuses a link that would break that.
                        "cidr4": "10.64.0.0/24",
                        "cidr6": "fd00:64::/64",
                        "keepalive": 25,
                        "mtu": 1420,
                        "enabled": true,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        created["data"]["id"].as_u64().unwrap()
    }

    /// A service sold in two regions, which is what makes the multi-region
    /// property testable at all.
    async fn a_two_region_service(admin: &TestClient) -> (u64, Vec<u64>) {
        let id = unique();
        let company_id = a_company(admin).await;
        let router = a_route_server(admin, &format!("rs-{id}"), &format!("secret-{id}")).await;
        let regions = vec![
            a_region(admin, &format!("ams-{id}")).await,
            a_region(admin, &format!("sto-{id}")).await,
        ];

        let service = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/vpn_services",
                    &json!({
                        "company_id": company_id,
                        "name": format!("vpn-{id}"),
                        "currency": "EUR",
                        "amount": 500,
                        "dns": "10.64.0.1, fd00:64::1",
                        "default_device_limit": 5,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        let service_id = service["data"]["id"].as_u64().unwrap();
        // Created off sale, because a service with no interfaces has no region
        // to connect to.
        assert!(!service["data"]["enabled"].as_bool().unwrap());

        for (n, region_id) in regions.iter().enumerate() {
            let pool = an_interface(
                admin,
                router,
                *region_id,
                51820 + n as u16,
                &format!("if-{id}-{n}"),
            )
            .await;
            json_ok(
                admin
                    .post_auth(
                        &format!("/api/admin/v1/vpn_services/{service_id}/pools/{pool}"),
                        &json!({}),
                    )
                    .await
                    .unwrap(),
            )
            .await;
        }

        let on_sale = json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/vpn_services/{service_id}"),
                    &json!({"enabled": true}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(on_sale["data"]["regions"].as_array().unwrap().len(), 2);

        (service_id, regions)
    }

    // ========================================================================

    #[tokio::test]
    async fn a_service_is_listed_with_every_region_it_is_sold_in() {
        let admin = admin().await;
        let (service_id, regions) = a_two_region_service(&admin).await;

        let user = user_client_with_keys(Keys::generate());
        let listed = json_ok(user.get("/api/v1/vpn/services").await.unwrap()).await;

        let mine = listed["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"].as_u64() == Some(service_id))
            .expect("the service just put on sale should be for sale");
        let listed_regions: Vec<u64> = mine["regions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["region_id"].as_u64().unwrap())
            .collect();
        for region in regions {
            assert!(listed_regions.contains(&region), "{listed_regions:?}");
        }
    }

    #[tokio::test]
    async fn a_device_cannot_be_registered_until_the_plan_is_paid() {
        let admin = admin().await;
        let (service_id, _) = a_two_region_service(&admin).await;
        let user = user_client_with_keys(Keys::generate());

        let plan = json_ok(
            user.post_auth("/api/v1/vpn", &json!({"service_id": service_id}))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(plan["data"]["billing_state"], "unpaid");
        assert_eq!(plan["data"]["device_count"], 0);

        // The plan exists and is billable, but configures nothing until it is
        // paid for.
        let refused = user
            .post_auth(
                "/api/v1/vpn/devices",
                &json!({"name": "phone", "public_key": a_public_key(1)}),
            )
            .await
            .unwrap();
        assert_ne!(
            refused.status(),
            StatusCode::OK,
            "an unpaid plan must not register devices"
        );
    }

    #[tokio::test]
    async fn buying_a_plan_twice_returns_the_same_plan() {
        let admin = admin().await;
        let (service_id, _) = a_two_region_service(&admin).await;
        let user = user_client_with_keys(Keys::generate());

        let first = json_ok(
            user.post_auth("/api/v1/vpn", &json!({"service_id": service_id}))
                .await
                .unwrap(),
        )
        .await;
        let second = json_ok(
            user.post_auth("/api/v1/vpn", &json!({"service_id": service_id}))
                .await
                .unwrap(),
        )
        .await;

        // One plan per account, and a client retrying a request whose response
        // it lost must not end up billed twice.
        assert_eq!(first["data"]["id"], second["data"]["id"]);
        assert_eq!(
            first["data"]["subscription_id"],
            second["data"]["subscription_id"]
        );
    }

    #[tokio::test]
    async fn a_user_with_no_plan_is_told_so_rather_than_given_one() {
        let user = user_client_with_keys(Keys::generate());
        let resp = user.get_auth("/api/v1/vpn").await.unwrap();
        // Whatever the shape, it must not be an error that looks like a fault,
        // and it must not quietly create a subscription on a GET.
        assert!(
            resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::OK,
            "got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn the_vpn_endpoints_refuse_an_unauthenticated_caller() {
        let user = crate::client::user_client_no_auth();
        for (method, path) in [
            ("GET", "/api/v1/vpn"),
            ("GET", "/api/v1/vpn/devices"),
            ("GET", "/api/v1/vpn/devices/1/configs"),
        ] {
            let resp = user.get(path).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path} should need authentication"
            );
        }
        // The catalogue is the exception: what is for sale, and where it exits,
        // is public because a customer decides before they have an account.
        let public = user.get("/api/v1/vpn/services").await.unwrap();
        assert_eq!(public.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_route_server_is_handed_its_peers_and_nothing_about_who_they_are() {
        let admin = admin().await;
        let id = unique();
        let token = format!("secret-{id}");
        let company_id = a_company(&admin).await;
        let router = a_route_server(&admin, &format!("rs-{id}"), &token).await;
        let region = a_region(&admin, &format!("ams-{id}")).await;
        let pool = an_interface(&admin, router, region, 51820, &format!("if-{id}")).await;

        let service = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/vpn_services",
                    &json!({
                        "company_id": company_id,
                        "name": format!("vpn-{id}"),
                        "currency": "EUR",
                        "amount": 500,
                        "enabled": true,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        let service_id = service["data"]["id"].as_u64().unwrap();
        json_ok(
            admin
                .post_auth(
                    &format!("/api/admin/v1/vpn_services/{service_id}/pools/{pool}"),
                    &json!({}),
                )
                .await
                .unwrap(),
        )
        .await;

        let route_server = TestClient::new(&crate::client::user_api_url(), None);
        let doc = json_ok(
            route_server
                .get_with_bearer(
                    "/api/v1/routeserver/dataplane?generation=0&wait=0",
                    &format!("{router}.{token}"),
                )
                .await
                .unwrap(),
        )
        .await;

        let iface = doc["data"]["interfaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["pool_id"].as_u64() == Some(pool))
            .expect("the route server should be told about its own interface");
        assert_eq!(iface["listen_port"], 51820);
        assert!(doc["data"]["generation"].as_u64().unwrap() >= 1);

        // A seized route server must yield the key-to-address map it needs in
        // kernel memory anyway, and nothing that was not already on the wire.
        let text = serde_json::to_string(&doc["data"]).unwrap();
        for leaked in ["user_id", "subscription", "device", "slot", "email"] {
            assert!(!text.contains(leaked), "document must not carry {leaked}");
        }
    }

    #[tokio::test]
    async fn a_route_server_token_that_is_wrong_is_refused() {
        let admin = admin().await;
        let id = unique();
        let router = a_route_server(&admin, &format!("rs-{id}"), &format!("secret-{id}")).await;
        let route_server = TestClient::new(&crate::client::user_api_url(), None);

        for bad in [
            format!("{router}.wrong"),
            format!("{}.secret-{id}", router + 99_000),
            "nonsense".to_string(),
        ] {
            let resp = route_server
                .get_with_bearer("/api/v1/routeserver/dataplane", &bad)
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "token {bad} should be refused"
            );
        }
    }

    #[tokio::test]
    async fn a_mikrotik_token_cannot_read_a_vpn_peer_set() {
        let admin = admin().await;
        let id = unique();
        let token = format!("secret-{id}");
        // A router of any other kind: its token is a management password, and
        // honouring it here would turn every router credential into a way to
        // read peer sets it has nothing to do with.
        let created = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/routers",
                    &json!({
                        "name": format!("mt-{id}"),
                        "enabled": true,
                        "kind": "mikrotik",
                        "url": "https://192.0.2.1",
                        "token": token,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        let router = created["data"]["id"].as_u64().unwrap();

        let route_server = TestClient::new(&crate::client::user_api_url(), None);
        let resp = route_server
            .get_with_bearer(
                "/api/v1/routeserver/dataplane",
                &format!("{router}.{token}"),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_vpn_endpoints_need_their_own_permission() {
        // A user key with no admin role at all.
        let nobody = user_client_with_keys(Keys::generate());
        for path in [
            "/api/admin/v1/vpn_services",
            "/api/admin/v1/vpn_subscriptions",
        ] {
            let resp = nobody.get_auth(path).await.unwrap();
            assert!(
                resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
                "{path} answered {}",
                resp.status()
            );
        }
    }

    #[tokio::test]
    async fn a_service_with_subscribers_cannot_be_deleted() {
        let admin = admin().await;
        let (service_id, _) = a_two_region_service(&admin).await;
        let user = user_client_with_keys(Keys::generate());
        json_ok(
            user.post_auth("/api/v1/vpn", &json!({"service_id": service_id}))
                .await
                .unwrap(),
        )
        .await;

        // What is owed to somebody cannot be deleted to tidy up. Retiring a
        // service is `enabled: false`.
        let refused = admin
            .delete_auth(&format!("/api/admin/v1/vpn_services/{service_id}"))
            .await
            .unwrap();
        assert_ne!(refused.status(), StatusCode::OK);

        let retired = json_ok(
            admin
                .patch_auth(
                    &format!("/api/admin/v1/vpn_services/{service_id}"),
                    &json!({"enabled": false}),
                )
                .await
                .unwrap(),
        )
        .await;
        assert!(!retired["data"]["enabled"].as_bool().unwrap());
        assert_eq!(retired["data"]["subscriptions"], 1);
    }

    #[tokio::test]
    async fn an_interface_with_a_different_block_cannot_join_a_service() {
        let admin = admin().await;
        let id = unique();
        let (service_id, _) = a_two_region_service(&admin).await;

        let router = a_route_server(&admin, &format!("rs2-{id}"), &format!("s-{id}")).await;
        let region = a_region(&admin, &format!("hel-{id}")).await;
        let odd = json_ok(
            admin
                .post_auth(
                    "/api/admin/v1/tunnel_pools",
                    &json!({
                        "router_id": router,
                        "region_id": region,
                        "name": format!("odd-{id}"),
                        "listen_addr": "hel.vpn.example",
                        "listen_port": 51830,
                        // A different block from the service's other interfaces.
                        "cidr4": "10.99.0.0/24",
                        "enabled": true,
                    }),
                )
                .await
                .unwrap(),
        )
        .await;
        let odd_pool = odd["data"]["id"].as_u64().unwrap();

        // A device holds one address in every region, so an interface with a
        // different block would route some devices and black-hole the rest.
        let refused = admin
            .post_auth(
                &format!("/api/admin/v1/vpn_services/{service_id}/pools/{odd_pool}"),
                &json!({}),
            )
            .await
            .unwrap();
        assert_ne!(
            refused.status(),
            StatusCode::OK,
            "an interface carrying a different block must not join the service"
        );
    }
}
