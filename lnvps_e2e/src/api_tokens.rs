#[cfg(test)]
mod tests {
    use crate::client::*;
    use crate::db;
    use nostr::Keys;
    use reqwest::StatusCode;
    use serde_json::{Value, json};
    use sqlx::Row;

    async fn actions_for(uid: u64) -> Vec<String> {
        let pool = db::connect().await.unwrap();
        let rows = sqlx::query("select action from audit_log where actor_id = ? order by id")
            .bind(uid)
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        rows.iter().map(|r| r.get::<String, _>(0)).collect()
    }

    #[tokio::test]
    async fn test_read_api_token_lifecycle_and_audit() {
        let keys = Keys::generate();
        let pool = db::connect().await.unwrap();
        let uid = db::ensure_user(&pool, &keys).await.unwrap();
        pool.close().await;
        let client = user_client_with_keys(keys);

        let resp = client
            .post_auth(
                "/api/v1/account/tokens",
                &json!({"name": "e2e", "scope": "read", "expires_in_days": 7}),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = resp.json().await.unwrap();
        let token = body["data"]["token"].as_str().unwrap().to_string();
        let id = body["data"]["id"].as_u64().unwrap();
        assert!(token.starts_with("lnvps_"));

        let anon = user_client_no_auth();
        let read = anon.get_with_bearer("/api/v1/account", &token).await.unwrap();
        assert_eq!(read.status(), StatusCode::OK);

        let write = reqwest::Client::new()
            .post(anon.url("/api/v1/ssh-key"))
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({"name": "k", "key_data": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl t"}))
            .send()
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::FORBIDDEN);

        let listed: Value = client
            .get_auth("/api/v1/account/tokens")
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let row = &listed["data"][0];
        assert_eq!(row["id"].as_u64(), Some(id));
        assert!(row["last_used"].is_string(), "last use must be recorded");

        let del = client
            .delete_auth(&format!("/api/v1/account/tokens/{id}"))
            .await
            .unwrap();
        assert_eq!(del.status(), StatusCode::OK);

        let after = anon.get_with_bearer("/api/v1/account", &token).await.unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);

        assert_eq!(
            actions_for(uid).await,
            vec!["auth.token.create", "auth.token.revoke"]
        );
    }
}
