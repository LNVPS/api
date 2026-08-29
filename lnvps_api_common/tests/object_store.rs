//! [`ObjectStore`] against a real S3-compatible server.
//!
//! The unit tests pin the signature against AWS's published vector, which
//! proves the arithmetic. They cannot prove that a *server* accepts what we
//! produce: the canonical request has to match byte for byte, and a difference
//! in path encoding, query ordering or the signed-headers list fails as an
//! opaque 403 at the bucket rather than as a wrong hex string in CI.
//!
//! So these run against the `rustfs` service in `docker-compose.e2e.yaml`,
//! which is the same S3 implementation the app catalog ships to customers.
//!
//! - `LNVPS_TEST_S3_ENDPOINT`   — e.g. `http://localhost:9400`
//! - `LNVPS_TEST_S3_ACCESS_KEY` / `LNVPS_TEST_S3_SECRET_KEY`
//!
//! Skipped when unset, so `cargo test --workspace` on a machine without the
//! stack does not fail.

use std::time::Duration;

use anyhow::{Result, bail};
use lnvps_api_common::{ObjectStore, ObjectStoreConfig};

fn store() -> Option<ObjectStore> {
    let endpoint = std::env::var("LNVPS_TEST_S3_ENDPOINT").ok()?;
    let access_key = std::env::var("LNVPS_TEST_S3_ACCESS_KEY").ok()?;
    let secret_key = std::env::var("LNVPS_TEST_S3_SECRET_KEY").ok()?;
    ObjectStore::new(ObjectStoreConfig {
        endpoint,
        region: "us-east-1".to_string(),
        // One bucket per run: a test that deletes objects must not race another
        // run's, and creating it is part of what is being checked.
        bucket: format!("lnvps-backup-test-{}", run_id()),
        access_key,
        secret_key,
        path_style: true,
    })
    .ok()
}

fn run_id() -> String {
    std::env::var("LNVPS_E2E_RUN_ID").unwrap_or_else(|_| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string())
    })
}

macro_rules! store_or_skip {
    () => {
        match store() {
            Some(s) => s,
            None => {
                eprintln!("skipping: LNVPS_TEST_S3_ENDPOINT / _ACCESS_KEY / _SECRET_KEY not set");
                return Ok(());
            }
        }
    };
}

/// Upload the way a backup Job does — an HTTP `PUT` to a presigned URL, with
/// no credentials of its own — then read the artifact back the way the customer
/// API will, and prune it the way retention does.
#[tokio::test]
async fn an_artifact_round_trips_through_a_presigned_url() -> Result<()> {
    let store = store_or_skip!();
    store.create_bucket().await?;
    // Creating a bucket that exists is the normal case on every run after the
    // first, and must not be an error.
    store.create_bucket().await?;

    let key = "deployments/12/run-a/route96.sql.gz";
    // Not tiny: a single byte would pass a signature that mishandled the body.
    let body: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();

    let put = store.presign_put(key, Duration::from_secs(300))?;
    let uploaded = reqwest::Client::new()
        .put(&put)
        .body(body.clone())
        .send()
        .await?;
    if !uploaded.status().is_success() {
        bail!(
            "upload failed: {} {}",
            uploaded.status(),
            uploaded.text().await.unwrap_or_default()
        );
    }

    // The bucket is the authority on artifact size, since the uploader is a
    // stock container with nothing to report back through.
    assert_eq!(store.size(key).await?, Some(body.len() as u64));

    let get = store.presign_get(key, Duration::from_secs(300), Some("route96.sql.gz"))?;
    let fetched = reqwest::Client::new().get(&get).send().await?;
    assert!(fetched.status().is_success(), "{}", fetched.status());
    // The download name is signed into the URL, so the server is what applies
    // it — the customer's browser saves the artifact, not the object key's tail.
    let disposition = fetched
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        disposition.contains("route96.sql.gz"),
        "content-disposition was {disposition:?}"
    );
    assert_eq!(fetched.bytes().await?.to_vec(), body, "bytes changed");

    store.delete(key).await?;
    assert_eq!(store.size(key).await?, None, "delete left the object");
    // Retention re-runs against rows whose objects are already gone.
    store.delete(key).await?;
    Ok(())
}

/// The URL handed to a backup pod is a write to one key, and nothing else. The
/// pod runs in the customer's namespace beside their app, so this is the
/// boundary that makes it safe to put there at all.
#[tokio::test]
async fn an_upload_url_grants_nothing_beyond_its_own_object() -> Result<()> {
    let store = store_or_skip!();
    store.create_bucket().await?;

    let key = "deployments/13/run-b/db.sql.gz";
    let put = store.presign_put(key, Duration::from_secs(300))?;
    let client = reqwest::Client::new();
    client.put(&put).body(vec![1u8; 16]).send().await?;

    // The method is signed: an upload URL cannot read the object back.
    let replayed = client.get(&put).send().await?;
    assert!(
        replayed.status().is_client_error(),
        "a PUT URL served a GET: {}",
        replayed.status()
    );

    // The key is signed: pointing the same signature at another deployment's
    // object is refused.
    let elsewhere = put.replace("deployments/13", "deployments/99");
    let stolen = client.put(&elsewhere).body(vec![2u8; 16]).send().await?;
    assert!(
        stolen.status().is_client_error(),
        "a signature was reused for another key: {}",
        stolen.status()
    );

    store.delete(key).await?;
    Ok(())
}

/// Expiry is what bounds a leaked URL. A server that ignored `X-Amz-Expires`
/// would turn every backup upload into a standing grant, and nothing in the
/// unit tests would notice.
#[tokio::test]
async fn a_url_stops_working_when_it_expires() -> Result<()> {
    let store = store_or_skip!();
    store.create_bucket().await?;

    let key = "deployments/14/run-c/expiring.gz";
    let put = store.presign_put(key, Duration::from_secs(1))?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let late = reqwest::Client::new()
        .put(&put)
        .body(vec![3u8; 16])
        .send()
        .await?;
    assert!(
        late.status().is_client_error(),
        "an expired URL still uploaded: {}",
        late.status()
    );
    assert_eq!(store.size(key).await?, None);
    Ok(())
}
