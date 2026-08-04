//! OS image download and verification.
//!
//! Hypervisors are not assumed to have internet access, so the API fetches the
//! image itself, verifies it, and pushes it to the host over the libvirt
//! connection (see [`super::storage::upload_volume`]).

use crate::retry::{OpError, OpResult};
use crate::shasum::{ShasumAlgorithm, fetch_checksum_for_file};
use anyhow::anyhow;
use futures::StreamExt;
use lnvps_db::VmOsImage;
use log::{info, warn};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Local filename an image is cached under. Includes the image id so two
/// distributions that both publish `disk.qcow2` cannot collide.
pub fn cache_file_name(image: &VmOsImage) -> String {
    format!("os-image-{}-{}", image.id, url_file_name(&image.url))
}

/// Last path segment of a URL, with query/fragment stripped.
pub fn url_file_name(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or("image");
    if name.is_empty() {
        "image".to_string()
    } else {
        name.to_string()
    }
}

/// Download `image` into `cache_dir`, verifying its checksum, and return the
/// path to the verified file.
///
/// A previously downloaded file is reused only when it still passes
/// verification — a truncated or corrupted cache entry is re-fetched rather
/// than cloned into a customer's VM.
pub async fn download_to_cache(image: &VmOsImage, cache_dir: &Path) -> OpResult<PathBuf> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| OpError::Fatal(anyhow!("cannot create {}: {}", cache_dir.display(), e)))?;

    let target = cache_dir.join(cache_file_name(image));
    let expected = expected_checksum(image).await;

    if target.exists() {
        match &expected {
            Some((algo, sum)) => match verify_file(&target, algo, sum).await {
                Ok(true) => {
                    info!("re-using verified cached image {}", target.display());
                    return Ok(target);
                }
                Ok(false) => warn!(
                    "cached image {} failed checksum verification, re-downloading",
                    target.display()
                ),
                Err(e) => warn!("cannot verify cached image {}: {}", target.display(), e),
            },
            None => {
                // Without a published checksum there is nothing to verify
                // against, so a non-empty cached file is accepted as-is.
                if file_len(&target).await.unwrap_or(0) > 0 {
                    return Ok(target);
                }
            }
        }
    }

    // Download to a sibling temp file so an interrupted transfer can never be
    // mistaken for a complete image.
    let part = target.with_extension("part");
    download(&image.url, &part).await?;

    if let Some((algo, sum)) = &expected {
        if !verify_file(&part, algo, sum)
            .await
            .map_err(|e| OpError::Transient(anyhow!("{}", e)))?
        {
            let _ = tokio::fs::remove_file(&part).await;
            // A mismatch is either corruption in transit or a tampered mirror;
            // retrying a different mirror/attempt can legitimately succeed.
            return Err(OpError::Transient(anyhow!(
                "checksum mismatch for {} (expected {} {})",
                image.url,
                algo.as_str(),
                sum
            )));
        }
    } else {
        warn!(
            "OS image {} has no published checksum, skipping verification",
            image.url
        );
    }

    tokio::fs::rename(&part, &target)
        .await
        .map_err(|e| OpError::Transient(anyhow!("cannot move downloaded image: {}", e)))?;
    Ok(target)
}

async fn file_len(path: &Path) -> Option<u64> {
    tokio::fs::metadata(path).await.ok().map(|m| m.len())
}

/// Resolve the checksum to verify against: the one recorded on the image if
/// present, otherwise the entry for this file in the published sums file.
async fn expected_checksum(image: &VmOsImage) -> Option<(ShasumAlgorithm, String)> {
    if let Some(sum) = image.sha2.as_ref().filter(|s| !s.is_empty()) {
        if let Some(algo) = ShasumAlgorithm::from_hex_len(sum.len()) {
            return Some((algo, sum.to_lowercase()));
        }
        warn!("image {} has a sha2 of unknown length, ignoring", image.id);
    }

    let sha2_url = image.sha2_url.as_ref().filter(|s| !s.is_empty())?;
    match fetch_checksum_for_file(sha2_url, &url_file_name(&image.url)).await {
        Ok(entry) => Some((entry.algorithm, entry.checksum.to_lowercase())),
        Err(e) => {
            warn!("could not fetch checksum for image {}: {}", image.id, e);
            None
        }
    }
}

async fn download(url: &str, target: &Path) -> OpResult<()> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| OpError::Transient(anyhow!("failed to fetch {}: {}", url, e)))?;

    let status = response.status();
    if !status.is_success() {
        // 4xx means the catalog entry is wrong and no amount of retrying helps.
        let err = anyhow!("failed to fetch {}: HTTP {}", url, status);
        return Err(if status.is_client_error() {
            OpError::Fatal(err)
        } else {
            OpError::Transient(err)
        });
    }

    let mut file = tokio::fs::File::create(target)
        .await
        .map_err(|e| OpError::Fatal(anyhow!("cannot create {}: {}", target.display(), e)))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| OpError::Transient(anyhow!("download of {} failed: {}", url, e)))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| OpError::Transient(anyhow!("cannot write image: {}", e)))?;
    }
    file.flush()
        .await
        .map_err(|e| OpError::Transient(anyhow!("cannot flush image: {}", e)))?;
    Ok(())
}

/// Hash a file and compare against the expected hex digest.
pub async fn verify_file(
    path: &Path,
    algorithm: &ShasumAlgorithm,
    expected: &str,
) -> anyhow::Result<bool> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; 1024 * 1024];

    // Separate hasher instances rather than a trait object: the digest types
    // have different output sizes and don't share an object-safe supertrait.
    let mut sha256 = Sha256::new();
    let mut sha384 = Sha384::new();
    let mut sha512 = Sha512::new();

    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        match algorithm {
            ShasumAlgorithm::Sha256 => sha256.update(&buf[..read]),
            ShasumAlgorithm::Sha384 => sha384.update(&buf[..read]),
            ShasumAlgorithm::Sha512 => sha512.update(&buf[..read]),
        }
    }

    let actual = match algorithm {
        ShasumAlgorithm::Sha256 => hex::encode(sha256.finalize()),
        ShasumAlgorithm::Sha384 => hex::encode(sha384.finalize()),
        ShasumAlgorithm::Sha512 => hex::encode(sha512.finalize()),
    };
    Ok(actual.eq_ignore_ascii_case(expected.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn file_name_from_url() {
        assert_eq!(
            url_file_name("https://x/y/debian-12.qcow2"),
            "debian-12.qcow2"
        );
        assert_eq!(
            url_file_name("https://x/y/debian-12.qcow2?token=abc"),
            "debian-12.qcow2"
        );
        assert_eq!(url_file_name("https://x/y/"), "image");
        assert_eq!(url_file_name("image.raw"), "image.raw");
    }

    #[tokio::test]
    async fn verify_file_detects_mismatch() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("lnvps-img-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join("data.bin");
        tokio::fs::write(&path, b"hello world").await?;

        // sha256("hello world")
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_file(&path, &ShasumAlgorithm::Sha256, expected).await?);
        assert!(!verify_file(&path, &ShasumAlgorithm::Sha256, &"0".repeat(64)).await?);

        // Case differences in the published digest must not cause a false alarm.
        assert!(verify_file(&path, &ShasumAlgorithm::Sha256, &expected.to_uppercase()).await?);

        tokio::fs::remove_dir_all(&dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn verify_file_supports_sha512() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("lnvps-img-test512-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await?;
        let path = dir.join("data.bin");
        tokio::fs::write(&path, b"hello world").await?;

        let expected = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        assert!(verify_file(&path, &ShasumAlgorithm::Sha512, expected).await?);

        tokio::fs::remove_dir_all(&dir).await?;
        Ok(())
    }
}
