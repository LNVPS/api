#[cfg(test)]
mod tests {
    use crate::client::{TestClient, user_client_with_keys};
    use lnvps_api_common::object_store::{ObjectStore, ObjectStoreConfig};
    use reqwest::StatusCode;
    use serde_json::Value;
    use std::time::Duration;

    const COMPOSE: &str = "services:\n  relay:\n    image: x\n    user: \"1000\"\n    volumes:\n      - { name: db, path: /db, size: 1Gi }\n    backup: { volume: db, artifact: relay-db }\n";

    fn store() -> ObjectStore {
        ObjectStore::new(ObjectStoreConfig {
            endpoint: std::env::var("LNVPS_TEST_S3_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:9400".to_string()),
            region: "us-east-1".to_string(),
            bucket: "lnvps-e2e-app-backups".to_string(),
            access_key: std::env::var("LNVPS_TEST_S3_ACCESS_KEY")
                .unwrap_or_else(|_| "e2eaccesskey".to_string()),
            secret_key: std::env::var("LNVPS_TEST_S3_SECRET_KEY")
                .unwrap_or_else(|_| "e2esecretkey".to_string()),
            path_style: true,
        })
        .unwrap()
    }

    async fn json(resp: reqwest::Response) -> Value {
        serde_json::from_str(&resp.text().await.unwrap()).unwrap()
    }

    async fn post(client: &TestClient, path: &str) -> reqwest::Response {
        client
            .post_auth(path, &serde_json::json!({}))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_app_backup_download_round_trip() {
        let keys = nostr::Keys::generate();
        let client = user_client_with_keys(keys.clone());
        let stranger = user_client_with_keys(nostr::Keys::generate());
        let pool = crate::db::connect().await.unwrap();
        let uid = crate::db::ensure_user(&pool, &keys).await.unwrap();
        let (app_id, _, dep_id) = crate::db::seed_app_deployment(&pool, uid, "backups")
            .await
            .unwrap();
        sqlx::query("UPDATE app SET compose = ? WHERE id = ?")
            .bind(COMPOSE)
            .bind(app_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE app_deployment SET status = 1 WHERE id = ?")
            .bind(dep_id)
            .execute(&pool)
            .await
            .unwrap();
        let base = format!("/api/v1/app-deployments/{dep_id}/backups");

        let resp = client.get_auth(&base).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json(resp).await["total"].as_u64(), Some(0));

        let resp = post(&client, &base).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let run = json(resp).await;
        let backup = &run["data"][0];
        let backup_id = backup["id"].as_u64().unwrap();
        assert_eq!(backup["artifact"].as_str(), Some("relay-db.tar.gz"));
        assert_eq!(backup["state"].as_str(), Some("pending"));
        assert_eq!(post(&client, &base).await.status(), StatusCode::CONFLICT);
        assert_eq!(
            stranger.get_auth(&base).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );

        let download = format!("{base}/{backup_id}/download");
        assert_eq!(
            client.get_auth(&download).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );

        let s = store();
        s.create_bucket().await.unwrap();
        let key = format!(
            "deployments/{dep_id}/{}/relay-db.tar.gz",
            backup["run_id"].as_str().unwrap()
        );
        let http = reqwest::Client::new();
        let put = s.presign_put(&key, Duration::from_secs(300)).unwrap();
        let payload = b"not really a tarball".to_vec();
        assert!(
            http.put(&put)
                .body(payload.clone())
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        sqlx::query(
            "UPDATE app_deployment_backup SET state = 2, object_key = ?, size_bytes = ? WHERE id = ?",
        )
        .bind(&key)
        .bind(payload.len() as u64)
        .bind(backup_id)
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(
            stranger.get_auth(&download).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let resp = client.get_auth(&download).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let link = json(resp).await;
        assert_eq!(link["data"]["filename"].as_str(), Some("relay-db.tar.gz"));
        let fetched = http
            .get(link["data"]["url"].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert!(fetched.status().is_success());
        assert!(
            fetched
                .headers()
                .get("content-disposition")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("relay-db.tar.gz"))
        );
        assert_eq!(fetched.bytes().await.unwrap().to_vec(), payload);

        let resp = client
            .delete_auth(&format!("{base}/{backup_id}"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(s.size(&key).await.unwrap(), None);
        assert_eq!(
            json(client.get_auth(&base).await.unwrap()).await["total"].as_u64(),
            Some(0)
        );
    }
}
