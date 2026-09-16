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
use sha2::{Digest, Sha256, Sha384, Sha512};
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
    /// Lowercase hex SHA-2 digest of the file: SHA-256, SHA-384 or SHA-512,
    /// told apart by length, because that is what distributions publish and
    /// LNVPS passes on whichever one it found. Without a digest there is
    /// nothing to check the download against, so there is no request.
    pub sha2: String,
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
    let expected = Digestion::parse(&req.sha2)?;
    if !req.url.starts_with("https://") {
        bail!("An image URL must be https");
    }

    if target.exists() {
        // Re-hashing beats trusting the name: a truncated file from an
        // interrupted run is the case this exists to catch, and it is
        // indistinguishable from a good one by size alone once the pool has
        // been written to since.
        if expected.matches_file(&target).await? {
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
async fn download(url: &str, part: &Path, expected: &Digestion) -> Result<u64> {
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
    let mut hasher = expected.hasher();
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

    if !expected.matches(hasher) {
        bail!("{url} does not match the digest LNVPS asked for");
    }
    Ok(total)
}

/// The digest to check a download against, and the algorithm to do it with.
///
/// The algorithm comes from the length rather than from a field: that is how
/// every SHASUMS file LNVPS reads states it, so a separate field would be a
/// second thing that could disagree with the digest itself.
enum Digestion {
    Sha256([u8; 32]),
    Sha384(Box<[u8; 48]>),
    Sha512(Box<[u8; 64]>),
}

/// The running hash for one of the three algorithms.
enum Hashing {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hashing {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }
}

impl Digestion {
    fn parse(hex_digest: &str) -> Result<Self> {
        let raw = hex::decode(hex_digest.trim()).context("The digest is not hex")?;
        Ok(match raw.len() {
            32 => Self::Sha256(raw.try_into().unwrap()),
            48 => Self::Sha384(Box::new(raw.try_into().unwrap())),
            64 => Self::Sha512(Box::new(raw.try_into().unwrap())),
            other => bail!("A SHA-2 digest is 32, 48 or 64 bytes, got {other}"),
        })
    }

    fn hasher(&self) -> Hashing {
        match self {
            Self::Sha256(_) => Hashing::Sha256(Sha256::new()),
            Self::Sha384(_) => Hashing::Sha384(Sha384::new()),
            Self::Sha512(_) => Hashing::Sha512(Sha512::new()),
        }
    }

    fn matches(&self, hashing: Hashing) -> bool {
        match (self, hashing) {
            (Self::Sha256(want), Hashing::Sha256(h)) => h.finalize().as_slice() == want,
            (Self::Sha384(want), Hashing::Sha384(h)) => h.finalize().as_slice() == want.as_slice(),
            (Self::Sha512(want), Hashing::Sha512(h)) => h.finalize().as_slice() == want.as_slice(),
            // Unreachable: the hasher is built from this digest.
            _ => false,
        }
    }

    async fn matches_file(&self, path: &Path) -> Result<bool> {
        use tokio::io::AsyncReadExt;
        let mut file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("reading {}", path.display()))?;
        let mut hashing = self.hasher();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buf).await.context("reading the image")?;
            if read == 0 {
                break;
            }
            hashing.update(&buf[..read]);
        }
        Ok(self.matches(hashing))
    }
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

    /// All three lengths, because LNVPS passes on whichever digest the
    /// distribution published: Debian and Alpine publish SHA-512, Ubuntu
    /// SHA-256. Rejecting the long ones meant those images always took the slow
    /// upload path.
    #[test]
    fn a_digest_is_sha256_sha384_or_sha512() {
        assert!(Digestion::parse(&"ab".repeat(32)).is_ok());
        assert!(Digestion::parse(&"ab".repeat(48)).is_ok());
        assert!(Digestion::parse(&"ab".repeat(64)).is_ok());
        assert!(Digestion::parse("aabb").is_err());
        assert!(Digestion::parse(&"zz".repeat(32)).is_err());
    }

    /// An image already in the pool is not fetched again, and one whose bytes
    /// do not match what LNVPS asked for is replaced rather than kept.
    #[tokio::test]
    async fn a_correct_image_is_left_alone() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let body = b"an image";
        let sha = hex::encode(Sha512::digest(body));
        tokio::fs::write(dir.path().join("os-image-1.raw"), body).await?;

        let outcome = fetch(
            dir.path(),
            &FetchRequest {
                // Never dialled: the file is already right.
                url: "https://example.invalid/image".to_string(),
                sha2: sha,
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
                sha2: "ab".repeat(32),
                name: "os-image-1.raw".to_string(),
            },
        )
        .await
        .expect_err("http must be refused");
        assert!(err.to_string().contains("https"), "{err}");
    }
}
