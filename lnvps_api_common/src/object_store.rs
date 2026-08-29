//! Minimal S3-compatible object storage client, used to hold app-deployment
//! backup artifacts (`work/app-deployments.md` increment 6).
//!
//! Every operation is a **presigned URL**, including the ones this process
//! issues itself. That is not a shortcut, it is the point: the pod that
//! captures a backup runs in the customer's own namespace, and handing it a
//! URL that is valid for one key, one method and a few hours is what keeps a
//! long-lived storage credential out of a namespace the tenant's workload can
//! read. Signing one way for everything also means the signer is exercised by
//! every call rather than only by the rare one.
//!
//! Only what backups need is implemented: `PUT` (upload), `GET` (download),
//! `HEAD` (observe an artifact's size) and `DELETE` (retention pruning). There
//! is no multipart upload, so one artifact is capped at the 5 GiB single-`PUT`
//! limit.

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// Signing algorithm identifier, and the payload literal that tells S3 not to
/// expect a body hash in the signature (a presigned URL cannot know the body).
const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Longest life SigV4 permits for a presigned URL.
pub const MAX_PRESIGN_EXPIRY: Duration = Duration::from_secs(7 * 24 * 3600);

/// S3-compatible bucket that backup artifacts are written to.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ObjectStoreConfig {
    /// Service endpoint, e.g. `https://s3.eu-central-1.amazonaws.com` or a
    /// self-hosted `https://minio.internal:9000`.
    pub endpoint: String,
    /// Signing region. S3-compatible services that have no regions still sign
    /// with one; `us-east-1` is the conventional filler.
    #[serde(default = "default_region")]
    pub region: String,
    pub bucket: String,
    /// Credentials. Defaulted so a deployment can keep them out of a config
    /// file that lives in a ConfigMap and supply them from a Secret through the
    /// environment instead; `ObjectStore::new` rejects a pair that is still
    /// empty by then.
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    /// Address the bucket as a path (`endpoint/bucket/key`) rather than as a
    /// subdomain. Defaults to true, because that is what self-hosted services
    /// (MinIO, Garage, SeaweedFS) accept without wildcard DNS and a wildcard
    /// certificate.
    #[serde(default = "default_path_style")]
    pub path_style: bool,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_path_style() -> bool {
    true
}

/// Signs requests against one bucket.
pub struct ObjectStore {
    config: ObjectStoreConfig,
    client: reqwest::Client,
}

impl ObjectStore {
    pub fn new(config: ObjectStoreConfig) -> Result<Self> {
        if config.endpoint.trim().is_empty() || config.bucket.trim().is_empty() {
            bail!("object storage needs an endpoint and a bucket");
        }
        if config.access_key.trim().is_empty() || config.secret_key.trim().is_empty() {
            bail!("object storage needs an access key and a secret key");
        }
        if !config.endpoint.starts_with("http://") && !config.endpoint.starts_with("https://") {
            bail!(
                "object storage endpoint '{}' must include a scheme",
                config.endpoint
            );
        }
        Ok(Self {
            config,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Create the bucket, tolerating one that already exists.
    ///
    /// For provisioning a fresh store (and for tests against a real
    /// S3-compatible server). Deliberately **not** called on the operator's
    /// startup path: creating buckets is a permission the operator's key should
    /// not need to hold just to write objects into a bucket somebody else made.
    pub async fn create_bucket(&self) -> Result<()> {
        let url = self.presign("PUT", "", Duration::from_secs(60), &[], Utc::now())?;
        let resp = self
            .client
            .put(&url)
            .send()
            .await
            .with_context(|| format!("could not create bucket '{}'", self.config.bucket))?;
        // 409 is the bucket already existing, which is the desired end state.
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::CONFLICT {
            return Ok(());
        }
        bail!(
            "creating bucket '{}' returned {}",
            self.config.bucket,
            resp.status()
        )
    }

    /// A URL the holder may upload exactly one object to.
    pub fn presign_put(&self, key: &str, expires_in: Duration) -> Result<String> {
        check_key(key)?;
        self.presign("PUT", key, expires_in, &[], Utc::now())
    }

    /// A URL the holder may download one object from.
    ///
    /// `filename` sets `Content-Disposition` on the response, so a browser
    /// following the link saves `route96.sql.gz` rather than the object key's
    /// last segment. It is signed along with the rest of the query, so the
    /// holder cannot change it.
    pub fn presign_get(
        &self,
        key: &str,
        expires_in: Duration,
        filename: Option<&str>,
    ) -> Result<String> {
        let disposition = filename.map(|f| {
            (
                "response-content-disposition".to_string(),
                format!("attachment; filename=\"{}\"", sanitise_filename(f)),
            )
        });
        check_key(key)?;
        let extra: Vec<(String, String)> = disposition.into_iter().collect();
        self.presign("GET", key, expires_in, &extra, Utc::now())
    }

    /// Size of an object, or `None` when it does not exist.
    ///
    /// This is how a completed backup learns how big it is: the uploader is a
    /// stock `curl` container with nothing to report back through, so the
    /// authoritative size is whatever the bucket ended up holding.
    pub async fn size(&self, key: &str) -> Result<Option<u64>> {
        check_key(key)?;
        let url = self.presign("HEAD", key, Duration::from_secs(60), &[], Utc::now())?;
        let resp = self
            .client
            .head(&url)
            .send()
            .await
            .with_context(|| format!("HEAD failed for object '{key}'"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("HEAD '{key}' returned {}", resp.status());
        }
        // The header, not `content_length()`: a HEAD response carries no body,
        // and the decoded-body length an HTTP client reports for one is zero.
        Ok(resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok()))
    }

    /// Remove an object. Deleting one that is already gone succeeds: retention
    /// pruning has to be safe to retry.
    pub async fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        let url = self.presign("DELETE", key, Duration::from_secs(60), &[], Utc::now())?;
        let resp = self
            .client
            .delete(&url)
            .send()
            .await
            .with_context(|| format!("DELETE failed for object '{key}'"))?;
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        bail!("DELETE '{key}' returned {}", resp.status())
    }

    /// Sign one request as a query-string-authenticated URL.
    ///
    /// `now` is a parameter so the signer can be checked against the published
    /// SigV4 test vectors, which fix the timestamp.
    fn presign(
        &self,
        method: &str,
        key: &str,
        expires_in: Duration,
        extra_query: &[(String, String)],
        now: DateTime<Utc>,
    ) -> Result<String> {
        if expires_in.is_zero() || expires_in > MAX_PRESIGN_EXPIRY {
            bail!(
                "presign expiry must be between 1 second and {} seconds",
                MAX_PRESIGN_EXPIRY.as_secs()
            );
        }

        let (host, path) = self.host_and_path(key)?;
        let date = now.format("%Y%m%d").to_string();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region);

        let mut query: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), ALGORITHM.into()),
            (
                "X-Amz-Credential".into(),
                format!("{}/{scope}", self.config.access_key),
            ),
            ("X-Amz-Date".into(), timestamp.clone()),
            ("X-Amz-Expires".into(), expires_in.as_secs().to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ];
        query.extend(extra_query.iter().cloned());
        // SigV4 canonicalises the query by encoded name, then encoded value.
        let mut encoded: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode(k), uri_encode(v)))
            .collect();
        encoded.sort();
        let canonical_query = encoded
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request =
            format!("{method}\n{path}\n{canonical_query}\nhost:{host}\n\nhost\n{UNSIGNED_PAYLOAD}");
        let string_to_sign = format!(
            "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signature = hex::encode(
            self.signing_key(&date)?
                .chain_update(string_to_sign)
                .finalize()
                .into_bytes(),
        );

        Ok(format!(
            "{}://{host}{path}?{canonical_query}&X-Amz-Signature={signature}",
            self.scheme()?
        ))
    }

    /// The date-, region- and service-scoped key SigV4 derives from the secret,
    /// primed and ready to take the string to sign.
    fn signing_key(&self, date: &str) -> Result<HmacSha256> {
        let mut mac = hmac(format!("AWS4{}", self.config.secret_key).as_bytes(), date)?;
        mac = hmac(&mac.finalize().into_bytes(), &self.config.region)?;
        mac = hmac(&mac.finalize().into_bytes(), "s3")?;
        mac = hmac(&mac.finalize().into_bytes(), "aws4_request")?;
        hmac_key(&mac.finalize().into_bytes())
    }

    fn scheme(&self) -> Result<&str> {
        if self.config.endpoint.starts_with("https://") {
            Ok("https")
        } else {
            Ok("http")
        }
    }

    /// Split the configured endpoint into the host to sign and the request
    /// path, honouring path-style versus virtual-hosted addressing.
    fn host_and_path(&self, key: &str) -> Result<(String, String)> {
        let host = self
            .config
            .endpoint
            .split_once("://")
            .map(|(_, rest)| rest.trim_end_matches('/'))
            .filter(|h| !h.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "object storage endpoint '{}' has no host",
                    self.config.endpoint
                )
            })?;
        // Each path segment is encoded, but the separators are not. An empty
        // key addresses the bucket itself, which is what creating one does.
        let encoded_key = key.split('/').map(uri_encode).collect::<Vec<_>>().join("/");
        if self.config.path_style {
            Ok((
                host.to_string(),
                format!("/{}/{encoded_key}", uri_encode(&self.config.bucket)),
            ))
        } else {
            Ok((
                format!("{}.{host}", self.config.bucket),
                format!("/{encoded_key}"),
            ))
        }
    }
}

fn hmac(key: &[u8], data: &str) -> Result<HmacSha256> {
    let mut mac = hmac_key(key)?;
    mac.update(data.as_bytes());
    Ok(mac)
}

fn hmac_key(key: &[u8]) -> Result<HmacSha256> {
    HmacSha256::new_from_slice(key).map_err(|e| anyhow!("invalid HMAC key: {e}"))
}

/// An object is always addressed by a key; only bucket-level calls have none.
fn check_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("object key is empty");
    }
    Ok(())
}

/// RFC 3986 percent-encoding as SigV4 defines it: everything outside the
/// unreserved set is escaped, in uppercase hex. Applied per path segment, so
/// `/` is always escaped here and the separators are rejoined by the caller.
fn uri_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reduce a download filename to something that cannot break out of the
/// `Content-Disposition` header it is quoted into.
fn sanitise_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if cleaned.is_empty() {
        "backup".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// AWS's published SigV4 example for a presigned GET
    /// (`docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html`),
    /// which is written against the virtual-hosted URL
    /// `examplebucket.s3.amazonaws.com/test.txt`. Anything that changes this
    /// signature has broken every URL we issue, so the vector is pinned
    /// exactly as published.
    #[test]
    fn signs_the_published_aws_vector() {
        let store = ObjectStore::new(ObjectStoreConfig {
            endpoint: "https://s3.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "examplebucket".to_string(),
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            path_style: false,
        })
        .unwrap();

        let at = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = store
            .presign("GET", "test.txt", Duration::from_secs(86400), &[], at)
            .unwrap();

        assert!(url.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"));
        assert!(url.contains(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
        ));
        assert!(url.contains("X-Amz-Date=20130524T000000Z"));
        assert!(url.contains("X-Amz-Expires=86400"));
        assert!(url.contains("X-Amz-SignedHeaders=host"));
        assert!(
            url.ends_with(
                "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "signature does not match the AWS vector: {url}"
        );
    }

    /// Path-style addressing puts the bucket in the path instead of the host,
    /// and both are part of the canonical request — so the two styles sign
    /// differently, and a wrong choice fails at the service with an opaque 403.
    #[test]
    fn path_style_moves_the_bucket_out_of_the_host() {
        let cfg = |path_style: bool| ObjectStoreConfig {
            endpoint: "https://s3.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "examplebucket".to_string(),
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            path_style,
        };
        let at = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let virt = ObjectStore::new(cfg(false))
            .unwrap()
            .presign("GET", "test.txt", Duration::from_secs(86400), &[], at)
            .unwrap();
        assert!(virt.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"));

        let path = ObjectStore::new(cfg(true))
            .unwrap()
            .presign("GET", "test.txt", Duration::from_secs(86400), &[], at)
            .unwrap();
        assert_ne!(
            signature_of(&virt),
            signature_of(&path),
            "the host is signed, so the two styles cannot share a signature"
        );
    }

    /// The method is signed, so a URL handed to a backup pod for upload cannot
    /// be replayed to read or delete the object.
    #[test]
    fn each_method_and_key_gets_its_own_signature() {
        let store = test_store();
        let key = "deployments/12/run-a/db.sql.gz";
        let put = store.presign_put(key, Duration::from_secs(3600)).unwrap();
        let get = store
            .presign_get(key, Duration::from_secs(3600), None)
            .unwrap();
        let other = store
            .presign_put("deployments/13/run-a/db.sql.gz", Duration::from_secs(3600))
            .unwrap();

        assert_ne!(signature_of(&put), signature_of(&get));
        assert_ne!(signature_of(&put), signature_of(&other));
        // The key's separators stay separators; only the segments are encoded.
        assert!(put.contains("/backups/deployments/12/run-a/db.sql.gz?"));
    }

    /// A download filename reaches the customer's browser, so it is signed
    /// (not appendable by the holder) and stripped of anything that would
    /// break out of the quoted header value.
    #[test]
    fn download_filename_is_signed_and_sanitised() {
        let store = test_store();
        let plain = store
            .presign_get(
                "deployments/12/run-a/db.sql.gz",
                Duration::from_secs(60),
                None,
            )
            .unwrap();
        let named = store
            .presign_get(
                "deployments/12/run-a/db.sql.gz",
                Duration::from_secs(60),
                Some("route96.sql.gz"),
            )
            .unwrap();
        assert!(named.contains("response-content-disposition="));
        assert_ne!(signature_of(&plain), signature_of(&named));

        let hostile = store
            .presign_get(
                "deployments/12/run-a/db.sql.gz",
                Duration::from_secs(60),
                Some("a\"; rm -rf /\n.sql"),
            )
            .unwrap();
        // Quote, space, slash and newline are all gone before encoding.
        assert!(hostile.contains("attachment%3B%20filename%3D%22arm-rf.sql%22"));
    }

    /// Bad configuration and impossible expiries fail where they are set, not
    /// at the service with a 403.
    #[test]
    fn rejects_unusable_configuration() {
        let mut cfg = ObjectStoreConfig {
            endpoint: "https://s3.example.com".to_string(),
            region: "us-east-1".to_string(),
            bucket: "backups".to_string(),
            access_key: "k".to_string(),
            secret_key: "s".to_string(),
            path_style: true,
        };
        cfg.endpoint = "s3.example.com".to_string();
        assert!(ObjectStore::new(cfg.clone()).is_err(), "scheme is required");
        cfg.endpoint = "https://s3.example.com".to_string();
        cfg.bucket = String::new();
        assert!(ObjectStore::new(cfg.clone()).is_err(), "bucket is required");
        cfg.bucket = "backups".to_string();
        cfg.secret_key = String::new();
        assert!(
            ObjectStore::new(cfg.clone()).is_err(),
            "credentials left to the environment must actually arrive"
        );

        let store = test_store();
        assert!(store.presign_put("", Duration::from_secs(60)).is_err());
        assert!(store.presign_put("k", Duration::ZERO).is_err());
        assert!(
            store
                .presign_put("k", MAX_PRESIGN_EXPIRY + Duration::from_secs(1))
                .is_err()
        );
        assert!(store.presign_put("k", MAX_PRESIGN_EXPIRY).is_ok());
    }

    /// Defaults exist so a config only has to carry what is site-specific.
    #[test]
    fn config_defaults_cover_the_self_hosted_case() {
        let cfg: ObjectStoreConfig =
            serde_yaml_ng::from_str("endpoint: https://minio.internal:9000\nbucket: backups\n")
                .unwrap();
        assert_eq!(cfg.region, "us-east-1");
        // Credentials may arrive from the environment rather than the file.
        assert!(cfg.access_key.is_empty());
        assert!(cfg.path_style, "self-hosted services need path style");
        let store = ObjectStore::new(ObjectStoreConfig {
            access_key: "k".to_string(),
            secret_key: "s".to_string(),
            ..cfg
        })
        .unwrap();
        assert_eq!(store.bucket(), "backups");
    }

    /// A completed backup's size comes from the bucket, because the uploader is
    /// a stock container with no way to report back. A missing object is a
    /// `None`, not an error: it is the normal answer for a run that failed
    /// before it uploaded anything.
    #[tokio::test]
    async fn size_reads_the_object_and_tolerates_a_missing_one() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/backups/deployments/12/run-a/db.sql.gz"))
            // What S3 answers a HEAD with: the object's size in the header,
            // and no body.
            .respond_with(ResponseTemplate::new(200).append_header("content-length", "4096"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/backups/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let store = store_at(&server.uri());
        assert_eq!(
            store.size("deployments/12/run-a/db.sql.gz").await.unwrap(),
            Some(4096)
        );
        assert_eq!(store.size("missing").await.unwrap(), None);
    }

    /// Retention pruning runs repeatedly against the same list until the rows
    /// are gone, so deleting an object that is already absent has to succeed.
    /// Anything else is an error, or a prune would silently believe it worked.
    #[tokio::test]
    async fn delete_is_idempotent_but_still_reports_real_failures() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/backups/present"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/backups/gone"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/backups/denied"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let store = store_at(&server.uri());
        assert!(store.delete("present").await.is_ok());
        assert!(store.delete("gone").await.is_ok());
        assert!(store.delete("denied").await.is_err());
    }

    fn store_at(endpoint: &str) -> ObjectStore {
        ObjectStore::new(ObjectStoreConfig {
            endpoint: endpoint.to_string(),
            region: "us-east-1".to_string(),
            bucket: "backups".to_string(),
            access_key: "AKIAEXAMPLE".to_string(),
            secret_key: "secret".to_string(),
            path_style: true,
        })
        .unwrap()
    }

    fn test_store() -> ObjectStore {
        ObjectStore::new(ObjectStoreConfig {
            endpoint: "https://s3.example.com".to_string(),
            region: "eu-central-1".to_string(),
            bucket: "backups".to_string(),
            access_key: "AKIAEXAMPLE".to_string(),
            secret_key: "secret".to_string(),
            path_style: true,
        })
        .unwrap()
    }

    fn signature_of(url: &str) -> String {
        url.split("X-Amz-Signature=").nth(1).unwrap().to_string()
    }
}
