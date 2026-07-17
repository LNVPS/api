//! E2E tests for passwordless WebAuthn / passkey login.
//!
//! These exercise the real ceremonies against the live server using the
//! software authenticator in [`crate::soft_authenticator`], which supports the
//! discoverable (resident-key) credentials the server's usernameless login
//! requires.
//!
//! Covered flows:
//! - passwordless account **signup** then usernameless **login**
//! - **add a passkey** to an existing Nostr account then usernameless login
//!   resolving back to that same account
//!
//! The server must be configured with a `webauthn` + `session` block (see
//! `.github/e2e/api-config.yaml`). If passkeys are not configured the tests
//! skip with a message.

#[cfg(test)]
mod tests {
    use crate::client::{ApiData, TestClient, parse_data, user_api_url, user_client_with_keys};
    use crate::soft_authenticator::SoftAuthenticator;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use webauthn_rs_proto::{CreationChallengeResponse, RequestChallengeResponse};

    #[derive(Debug, Deserialize)]
    struct RegisterStartResp {
        challenge: CreationChallengeResponse,
        state: String,
    }

    #[derive(Debug, Deserialize)]
    struct LoginStartResp {
        challenge: RequestChallengeResponse,
        state: String,
    }

    #[derive(Debug, Deserialize)]
    struct TokenResp {
        token: String,
        token_type: String,
        #[allow(dead_code)]
        expires_in: u64,
    }

    #[derive(Debug, Deserialize)]
    struct CredInfo {
        id: u64,
        name: Option<String>,
    }

    /// The origin the authenticator reports; must match the server's
    /// configured `rp_origin` (the API's public origin).
    fn origin() -> String {
        user_api_url()
    }

    /// GET an endpoint using a passkey/OAuth session Bearer token.
    async fn get_bearer(path: &str, token: &str) -> reqwest::Response {
        let url = format!("{}{}", user_api_url().trim_end_matches('/'), path);
        reqwest::Client::new()
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("bearer GET failed")
    }

    /// Returns true (and prints a skip note) when passkeys aren't configured
    /// server-side, so the suite degrades gracefully in that environment.
    async fn passkeys_unconfigured(client: &TestClient) -> bool {
        let resp = client
            .post("/api/v1/webauthn/register/start", &json!({}))
            .await
            .expect("register/start request failed");
        if resp.status().is_success() {
            return false;
        }
        let body = resp.text().await.unwrap_or_default();
        if body.contains("WebAuthn not configured") {
            eprintln!("SKIP: WebAuthn not configured on server: {body}");
            true
        } else {
            panic!("register/start failed unexpectedly: {body}");
        }
    }

    /// Full passwordless flow: register a new account, then usernameless login.
    #[tokio::test]
    async fn test_passkey_signup_and_login() {
        let anon = TestClient::new(&user_api_url(), None);
        if passkeys_unconfigured(&anon).await {
            return;
        }

        let mut authenticator = SoftAuthenticator::new(&origin());

        // --- Registration (signup) ---
        let resp = anon
            .post(
                "/api/v1/webauthn/register/start",
                &json!({ "name": "e2e-passkey-user" }),
            )
            .await
            .unwrap();
        let start: ApiData<RegisterStartResp> = parse_data(resp).await.unwrap();

        let credential = authenticator
            .register(&start.data.challenge)
            .expect("authenticator registration");

        let resp = anon
            .post(
                "/api/v1/webauthn/register/finish",
                &json!({
                    "state": start.data.state,
                    "credential": credential,
                    "name": "e2e-yubikey",
                }),
            )
            .await
            .unwrap();
        let reg_token: ApiData<TokenResp> = parse_data(resp).await.unwrap();
        assert_eq!(reg_token.data.token_type, "Bearer");
        assert!(!reg_token.data.token.is_empty());

        // The registration session is a fresh webauthn account.
        let acct: ApiData<Value> =
            parse_data(get_bearer("/api/v1/account", &reg_token.data.token).await)
                .await
                .unwrap();
        assert_eq!(acct.data["account_type"], "webauthn");

        // The added passkey is listed on the account.
        let creds: ApiData<Vec<CredInfo>> =
            parse_data(get_bearer("/api/v1/webauthn/credentials", &reg_token.data.token).await)
                .await
                .unwrap();
        assert_eq!(creds.data.len(), 1);
        assert_eq!(creds.data[0].name.as_deref(), Some("e2e-yubikey"));

        // --- Usernameless (discoverable) login ---
        let resp = anon
            .post("/api/v1/webauthn/login/start", &json!({}))
            .await
            .unwrap();
        let login_start: ApiData<LoginStartResp> = parse_data(resp).await.unwrap();

        let assertion = authenticator
            .authenticate(&login_start.data.challenge)
            .expect("authenticator assertion");

        let resp = anon
            .post(
                "/api/v1/webauthn/login/finish",
                &json!({
                    "state": login_start.data.state,
                    "credential": assertion,
                }),
            )
            .await
            .unwrap();
        let login_token: ApiData<TokenResp> = parse_data(resp).await.unwrap();
        assert!(!login_token.data.token.is_empty());

        // The login session resolves to the same account (same single passkey).
        let creds2: ApiData<Vec<CredInfo>> =
            parse_data(get_bearer("/api/v1/webauthn/credentials", &login_token.data.token).await)
                .await
                .unwrap();
        assert_eq!(creds2.data.len(), 1);
        assert_eq!(creds2.data[0].id, creds.data[0].id);
    }

    /// Add a passkey to an existing Nostr account, then usernameless login must
    /// resolve back to that same account.
    #[tokio::test]
    async fn test_add_passkey_to_nostr_account_and_login() {
        // A per-test Nostr identity so the credential set is deterministic.
        let keys = nostr::Keys::generate();
        let nostr_client = user_client_with_keys(keys);

        if passkeys_unconfigured(&nostr_client).await {
            return;
        }

        // Ensure the account exists.
        let resp = nostr_client.get_auth("/api/v1/account").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut authenticator = SoftAuthenticator::new(&origin());

        // --- Add a passkey to the Nostr account (NIP-98 authenticated) ---
        let resp = nostr_client
            .post_auth(
                "/api/v1/webauthn/credentials/start",
                &json!({ "name": "e2e-nostr-key" }),
            )
            .await
            .unwrap();
        let start: ApiData<RegisterStartResp> = parse_data(resp).await.unwrap();

        let credential = authenticator
            .register(&start.data.challenge)
            .expect("authenticator registration");

        let resp = nostr_client
            .post_auth(
                "/api/v1/webauthn/credentials/finish",
                &json!({
                    "state": start.data.state,
                    "credential": credential,
                    "name": "e2e-nostr-key",
                }),
            )
            .await
            .unwrap();
        let added: ApiData<CredInfo> = parse_data(resp).await.unwrap();
        assert_eq!(added.data.name.as_deref(), Some("e2e-nostr-key"));

        // The Nostr account (NIP-98) now lists the credential.
        let resp = nostr_client
            .get_auth("/api/v1/webauthn/credentials")
            .await
            .unwrap();
        let nostr_creds: ApiData<Vec<CredInfo>> = parse_data(resp).await.unwrap();
        let added_id = added.data.id;
        assert!(nostr_creds.data.iter().any(|c| c.id == added_id));

        // --- Usernameless login with that passkey ---
        let anon = TestClient::new(&user_api_url(), None);
        let resp = anon
            .post("/api/v1/webauthn/login/start", &json!({}))
            .await
            .unwrap();
        let login_start: ApiData<LoginStartResp> = parse_data(resp).await.unwrap();

        let assertion = authenticator
            .authenticate(&login_start.data.challenge)
            .expect("authenticator assertion");

        let resp = anon
            .post(
                "/api/v1/webauthn/login/finish",
                &json!({
                    "state": login_start.data.state,
                    "credential": assertion,
                }),
            )
            .await
            .unwrap();
        let login_token: ApiData<TokenResp> = parse_data(resp).await.unwrap();
        assert!(!login_token.data.token.is_empty());

        // The passkey session must resolve to the SAME Nostr account: it sees
        // the exact credential we added.
        let bearer_creds: ApiData<Vec<CredInfo>> =
            parse_data(get_bearer("/api/v1/webauthn/credentials", &login_token.data.token).await)
                .await
                .unwrap();
        assert!(bearer_creds.data.iter().any(|c| c.id == added_id));

        // And its account type remains nostr (a passkey was merely attached).
        let acct: ApiData<Value> =
            parse_data(get_bearer("/api/v1/account", &login_token.data.token).await)
                .await
                .unwrap();
        assert_eq!(acct.data["account_type"], "nostr");
    }
}
