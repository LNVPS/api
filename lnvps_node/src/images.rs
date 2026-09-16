//! Fetching an OS image onto the node, over the operator's own connection.
//!
//! libvirt can only be *given* bytes — its storage API has an upload call and
//! nothing that fetches a URL — so without this LNVPS downloads every image
//! into its own datacentre and pushes it down the tunnel, paying for the same
//! gigabyte twice and limiting the transfer to what the tunnel carries. The
//! machine that wants the image has a perfectly good connection of its own.
//!
//! What makes delegating safe is that LNVPS names the digest. The node fetches
//! whatever it likes from wherever it likes; a file that does not hash to what
//! was asked for never becomes a volume.
//!
//! The pool is a directory pool, so an image is a file in it. No libvirt client
//! is needed here, which is the same reason the rest of this daemon writes
//! configuration files rather than driving libvirtd's API.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

/// The largest image the node will write.
///
/// A cap rather than trust: the pool lives on the operator's filesystem, and
/// without one a URL that streams forever fills their root partition. Cloud
/// images are one to three gigabytes; ten is room for an outlier and still far
/// from a disk.
pub const MAX_IMAGE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// What LNVPS asks the node to fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    /// Where to get it. HTTPS only: the digest catches tampering, but a plain
    /// HTTP fetch also reveals to the operator's network which image is being
    /// downloaded for whom.
    pub url: String,
    /// Lowercase hex SHA-256 of the file. Without one there is nothing to check
    /// the download against, so there is no request.
    pub sha256: String,
    /// The volume file name, as LNVPS's libvirt client will look it up.
    pub name: String,
}

/// What the node did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchOutcome {
    /// Already present and already correct; nothing was transferred.
    Present,
    /// Downloaded and verified.
    Fetched { bytes: u64 },
}

/// Fetch `req` into `pool_dir`, unless it is already there and correct.
pub async fn fetch(pool_dir: &Path, req: &FetchRequest) -> Result<FetchOutcome> {
    let target = pool_dir.join(volume_file_name(&req.name)?);
    let expected = checksum(&req.sha256)?;
    if !req.url.starts_with("https://") {
        bail!("An image URL must be https");
    }

    if target.exists() {
        // Re-hashing beats trusting the name: a truncated file from an
        // interrupted run is the case this exists to catch, and it is
        // indistinguishable from a good one by size alone once the pool has
        // been written to since.
        if digest_file(&target).await? == expected {
            return Ok(FetchOutcome::Present);
        }
        tokio::fs::remove_file(&target)
            .await
            .with_context(|| format!("removing the bad image at {}", target.display()))?;
    }

    // A sibling temp file, so an interrupted transfer is never mistaken for a
    // complete image by the pool listing.
    let part = target.with_extension("part");
    let bytes = download(&req.url, &part, &expected)
        .await
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&part);
        })?;

    tokio::fs::rename(&part, &target)
        .await
        .with_context(|| format!("moving the image into {}", target.display()))?;
    Ok(FetchOutcome::Fetched { bytes })
}

/// Stream `url` into `part`, hashing as it goes, and fail unless it matches.
async fn download(url: &str, part: &Path, expected: &[u8; 32]) -> Result<u64> {
    let response = reqwest::Client::builder()
        .build()?
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    if !response.status().is_success() {
        bail!("{url} returned {}", response.status());
    }

    let mut file = tokio::fs::File::create(part)
        .await
        .with_context(|| format!("creating {}", part.display()))?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut response = response;
    while let Some(chunk) = response.chunk().await.context("reading the image")? {
        total += chunk.len() as u64;
        if total > MAX_IMAGE_BYTES {
            bail!("{url} is larger than the {MAX_IMAGE_BYTES} byte limit");
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("writing the image")?;
    }
    file.flush().await.context("flushing the image")?;

    if hasher.finalize().as_slice() != expected {
        bail!("{url} does not match the digest LNVPS asked for");
    }
    Ok(total)
}

async fn digest_file(path: &Path) -> Result<[u8; 32]> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buf).await.context("reading the image")?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

fn checksum(hex_digest: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(hex_digest.trim()).context("The digest is not hex")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("A SHA-256 digest is 32 bytes, got {}", raw.len()))
}

/// A volume name the node is willing to write.
///
/// The name comes from LNVPS, but it lands on the operator's filesystem: a name
/// with a slash or a `..` in it would write outside the pool, which is the one
/// thing this daemon must not let anyone do to the machine it is a guest on.
fn volume_file_name(name: &str) -> Result<PathBuf> {
    let trimmed = name.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 128
        && trimmed != "."
        && trimmed != ".."
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid {
        bail!("{name:?} is not a volume name this node will write");
    }
    Ok(PathBuf::from(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_escapes_the_pool_is_refused() {
        for bad in [
            "../../etc/passwd",
            "/etc/passwd",
            "a/b",
            "..",
            "",
            "os image.raw",
        ] {
            assert!(
                volume_file_name(bad).is_err(),
                "{bad:?} must not be written"
            );
        }
        assert_eq!(
            volume_file_name("os-image-3.raw").unwrap(),
            PathBuf::from("os-image-3.raw")
        );
    }

    #[test]
    fn a_digest_must_be_thirty_two_bytes() {
        assert!(checksum("aabb").is_err());
        assert!(checksum("zz".repeat(32).as_str()).is_err());
        assert!(checksum(&"ab".repeat(32)).is_ok());
    }

    /// An image already in the pool is not fetched again, and one whose bytes
    /// do not match what LNVPS asked for is replaced rather than kept.
    #[tokio::test]
    async fn a_correct_image_is_left_alone() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let body = b"an image";
        let sha = hex::encode(Sha256::digest(body));
        tokio::fs::write(dir.path().join("os-image-1.raw"), body).await?;

        let outcome = fetch(
            dir.path(),
            &FetchRequest {
                // Never dialled: the file is already right.
                url: "https://example.invalid/image".to_string(),
                sha256: sha,
                name: "os-image-1.raw".to_string(),
            },
        )
        .await?;
        assert_eq!(outcome, FetchOutcome::Present);
        Ok(())
    }

    #[tokio::test]
    async fn a_plain_http_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = fetch(
            dir.path(),
            &FetchRequest {
                url: "http://example.invalid/image".to_string(),
                sha256: "ab".repeat(32),
                name: "os-image-1.raw".to_string(),
            },
        )
        .await
        .expect_err("http must be refused");
        assert!(err.to_string().contains("https"), "{err}");
    }
}
