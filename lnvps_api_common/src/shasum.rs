use anyhow::{Result, bail};

/// A single entry parsed from a SHASUMS-style file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShasumEntry {
    pub algorithm: ShasumAlgorithm,
    pub checksum: String,
    pub filename: String,
}

/// The hash algorithm inferred from the digest length or file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShasumAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ShasumAlgorithm {
    /// Infer the algorithm from a hex digest length.
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            64 => Some(Self::Sha256),
            96 => Some(Self::Sha384),
            128 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

/// Parse the contents of a SHASUMS file and return all entries.
///
/// Supported formats:
///
/// **GNU coreutils** (`sha256sum`, `sha512sum` output):
/// ```text
/// <checksum>  <filename>
/// <checksum> *<filename>
/// ```
///
/// **BSD / RPM** (`shasum -a 256`, `openssl dgst`):
/// ```text
/// SHA256 (<filename>) = <checksum>
/// SHA512 (<filename>) = <checksum>
/// ```
///
/// Lines that are blank, start with `#`, or do not match any known format
/// are silently skipped.
pub fn parse_shasum_file(content: &str) -> Vec<ShasumEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(entry) = parse_bsd_line(line).or_else(|| parse_gnu_line(line)) {
            entries.push(entry);
        }
    }
    entries
}

/// Find the checksum for a specific filename within parsed entries.
///
/// The match is performed on the bare filename, allowing for path prefixes
/// stored in the SUMS file (e.g. `./images/foo.qcow2` matches `foo.qcow2`).
///
/// Pass the original URL filename (e.g. `foo.qcow2`), not the host-storage
/// name (`foo.img`) — the `.img` rename is a Proxmox implementation detail.
pub fn find_checksum<'a>(entries: &'a [ShasumEntry], filename: &str) -> Option<&'a ShasumEntry> {
    entries.iter().find(|e| {
        e.filename == filename
            || e.filename.ends_with(&format!("/{filename}"))
            || e.filename.ends_with(&format!("\\{filename}"))
    })
}

/// Fetch a SHASUMS file from a URL and return the checksum entry for the
/// given filename.
///
/// Returns an error if the URL cannot be fetched or the filename is not
/// present in the file.
pub async fn fetch_checksum_for_file(sha2_url: &str, filename: &str) -> Result<ShasumEntry> {
    let body = reqwest::get(sha2_url)
        .await?
        .error_for_status()?
        .text()
        .await?;
    let entries = parse_shasum_file(&body);
    match find_checksum(&entries, filename) {
        Some(e) => Ok(e.clone()),
        None => bail!("Checksum for '{}' not found in {}", filename, sha2_url),
    }
}

/// Follow HTTP redirects for the given URL and return the final resolved URL.
///
/// Issues a HEAD request (falling back to GET if HEAD is not supported) and
/// returns the URL of the last response after all redirects have been followed.
/// If the request fails the original `url` is returned unchanged.
pub async fn resolve_redirect(url: &str) -> String {
    // reqwest follows redirects by default (up to 10).  The final response URL
    // is the resolved location after all hops.
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return url.to_owned(),
    };

    // Try HEAD first (lightweight — no body transfer).
    let result = client.head(url).send().await;
    let response = match result {
        Ok(r) => r,
        // Some servers reject HEAD; fall back to GET.
        Err(_) => match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return url.to_owned(),
        },
    };

    // If HEAD returned Method Not Allowed / Not Implemented, retry with GET.
    let response = if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
        || response.status() == reqwest::StatusCode::NOT_IMPLEMENTED
    {
        match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return url.to_owned(),
        }
    } else {
        response
    };

    response.url().to_string()
}

/// Well-known shared SHASUMS filenames probed in the image's directory.
/// Ordered from strongest to weakest algorithm.
const CANDIDATE_SUMS_FILES: &[&str] = &[
    "SHA512SUMS",
    "SHA256SUMS",
    "SHA512SUMS.txt",
    "SHA256SUMS.txt",
];

/// Per-file sidecar extensions appended directly to the image filename
/// (e.g. `foo.qcow2.SHA256`).  Ordered from strongest to weakest.
const CANDIDATE_SIDECAR_EXTS: &[&str] = &[".SHA512", ".SHA256", ".sha512", ".sha256"];

/// Given an image download URL and its filename, attempt to locate and fetch a
/// checksum by probing:
/// 1. Well-known shared SHASUMS files in the same directory (`SHA512SUMS`, `SHA256SUMS`, …)
/// 2. Per-file sidecar files appended to the image URL (`<url>.SHA256`, `<url>.SHA512`, …)
///
/// Returns `None` if no matching file is found.
pub async fn probe_checksum_from_image_url(
    image_url: &str,
    filename: &str,
) -> Option<(ShasumEntry, String)> {
    // Build the base directory URL by stripping the last path segment
    let base = {
        let trimmed = image_url.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(i) => &trimmed[..=i],
            None => return None,
        }
    };

    // 1. Shared SHASUMS files in the same directory
    for candidate in CANDIDATE_SUMS_FILES {
        let sums_url = format!("{}{}", base, candidate);
        if let Ok(entry) = fetch_checksum_for_file(&sums_url, filename).await {
            return Some((entry, sums_url));
        }
    }

    // 2. Per-file sidecar: <image_url>.<EXT>
    for ext in CANDIDATE_SIDECAR_EXTS {
        let sums_url = format!("{}{}", image_url, ext);
        if let Ok(entry) = fetch_checksum_for_file(&sums_url, filename).await {
            return Some((entry, sums_url));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Internal parsers
// ---------------------------------------------------------------------------

/// Parse a GNU coreutils line: `<checksum>  <filename>` or `<checksum> *<filename>`
fn parse_gnu_line(line: &str) -> Option<ShasumEntry> {
    // Split on the first whitespace run; the second token may start with `*`
    let (checksum, rest) = line.split_once(|c: char| c.is_ascii_whitespace())?;
    let filename = rest.trim().trim_start_matches('*').trim();
    if filename.is_empty() {
        return None;
    }
    let checksum = checksum.trim();
    if !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let algorithm = ShasumAlgorithm::from_hex_len(checksum.len())?;
    Some(ShasumEntry {
        algorithm,
        checksum: checksum.to_lowercase(),
        filename: filename.to_owned(),
    })
}

/// Parse a BSD/RPM line: `SHA256 (<filename>) = <checksum>`
fn parse_bsd_line(line: &str) -> Option<ShasumEntry> {
    // Must start with a known algorithm prefix
    let (algo_str, rest) = line.split_once(' ')?;
    let algorithm = match algo_str.to_uppercase().as_str() {
        "MD5" | "SHA1" => return None, // ignored weak algorithms
        "SHA256" => ShasumAlgorithm::Sha256,
        "SHA384" => ShasumAlgorithm::Sha384,
        "SHA512" => ShasumAlgorithm::Sha512,
        _ => return None,
    };
    // rest should be `(<filename>) = <checksum>`
    let rest = rest.trim();
    let inner = rest.strip_prefix('(')?.split_once(')')?;
    let filename = inner.0.trim();
    let checksum = inner.1.trim().strip_prefix('=')?.trim();
    if !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(ShasumEntry {
        algorithm,
        checksum: checksum.to_lowercase(),
        filename: filename.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GNU format --------------------------------------------------------

    #[test]
    fn test_gnu_two_spaces() {
        let content = "4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bca924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c  debian-12-generic-amd64.qcow2\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "debian-12-generic-amd64.qcow2");
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha512);
        assert_eq!(entries[0].checksum.len(), 128);
    }

    #[test]
    fn test_gnu_asterisk_binary_marker() {
        let content = "4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bca924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c *debian-12-generic-amd64.qcow2\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "debian-12-generic-amd64.qcow2");
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha512);
    }

    #[test]
    fn test_gnu_sha256() {
        let content = "049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b *noble-server-cloudimg-amd64.img\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(entries[0].filename, "noble-server-cloudimg-amd64.img");
    }

    // ---- BSD/RPM format ----------------------------------------------------

    #[test]
    fn test_bsd_sha256() {
        let content = "SHA256 (CentOS-Stream-9-latest-x86_64-dvd1.iso) = 045b30d6cc7574b3bf6b373a8693e73cdfd7b840070c15c6d5818a45235128c7\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].filename,
            "CentOS-Stream-9-latest-x86_64-dvd1.iso"
        );
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(
            entries[0].checksum,
            "045b30d6cc7574b3bf6b373a8693e73cdfd7b840070c15c6d5818a45235128c7"
        );
    }

    #[test]
    fn test_bsd_sha512() {
        let content = "SHA512 (somefile.img) = 4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bca924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bc\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha512);
    }

    // ---- Comment / blank lines ---------------------------------------------

    #[test]
    fn test_skips_comments_and_blank_lines() {
        let content = "# generated by sha512sum\n\n049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b *noble.img\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
    }

    // ---- find_checksum -----------------------------------------------------

    #[test]
    fn test_find_checksum_exact() {
        let entries = parse_shasum_file(
            "049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b *noble.img\n",
        );
        assert!(find_checksum(&entries, "noble.img").is_some());
        assert!(find_checksum(&entries, "other.img").is_none());
    }

    #[test]
    fn test_find_checksum_with_path_prefix() {
        let entries = parse_shasum_file(
            "049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b  ./images/noble.img\n",
        );
        assert!(find_checksum(&entries, "noble.img").is_some());
    }

    // ---- Mixed file --------------------------------------------------------

    #[test]
    fn test_mixed_file() {
        let content = "\
# Comment line
SHA256 (file-a.iso) = 049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b
4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bca924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c  file-b.qcow2
049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b *file-c.img
";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 3);
        assert!(find_checksum(&entries, "file-a.iso").is_some());
        assert!(find_checksum(&entries, "file-b.qcow2").is_some());
        assert!(find_checksum(&entries, "file-c.img").is_some());
    }

    // ---- resolve_redirect --------------------------------------------------

    #[tokio::test]
    async fn test_resolve_redirect_no_redirect() {
        // A stable HTTPS URL that should not redirect further.
        let url = "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS";
        let resolved = resolve_redirect(url).await;
        // The resolved URL must be non-empty and a valid URL.
        assert!(!resolved.is_empty());
        assert!(resolved.starts_with("https://"));
    }

    #[tokio::test]
    async fn test_resolve_redirect_follows_redirect() {
        // github.com redirects HTTP -> HTTPS.  Verify that resolve_redirect
        // follows the redirect and returns the https:// URL.
        let url = "http://github.com/";
        let resolved = resolve_redirect(url).await;
        assert!(
            resolved.starts_with("https://"),
            "expected https redirect, got: {resolved}"
        );
    }

    #[tokio::test]
    async fn test_resolve_redirect_debian_raw_image() {
        // cloud.debian.org issues a 302 redirect to a mirror for raw images.
        // Verify that resolve_redirect follows it and returns a different (mirror) URL.
        let url = "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.raw";
        let resolved = resolve_redirect(url).await;
        assert_ne!(
            resolved, url,
            "expected a redirect to a mirror, but URL was unchanged"
        );
        assert!(
            resolved.starts_with("https://"),
            "resolved URL should still be https://, got: {resolved}"
        );
    }

    // ---- Network test against real Debian SHA512SUMS -----------------------

    #[tokio::test]
    async fn test_fetch_checksum_debian_bookworm() -> anyhow::Result<()> {
        let url = "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS";
        let filename = "debian-12-generic-amd64.qcow2";

        let entry = fetch_checksum_for_file(url, filename).await?;

        assert_eq!(entry.filename, filename);
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        assert_eq!(entry.checksum.len(), 128);
        assert!(entry.checksum.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_checksum_ubuntu_noble() -> anyhow::Result<()> {
        let url = "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS";
        let filename = "noble-server-cloudimg-amd64.img";

        let entry = fetch_checksum_for_file(url, filename).await?;

        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(entry.checksum.len(), 64);
        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_checksum_missing_filename_errors() {
        let url = "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS";
        let result = fetch_checksum_for_file(url, "nonexistent-file.qcow2").await;
        assert!(result.is_err());
    }

    // ---- probe_checksum_from_image_url -------------------------------------

    #[tokio::test]
    async fn test_probe_checksum_debian_image_url() -> anyhow::Result<()> {
        // No sha2_url provided — should auto-discover SHA512SUMS in the same directory.
        // Use the original URL filename (qcow2), not the host-stored .img variant.
        let image_url =
            "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2";
        let filename = "debian-12-generic-amd64.qcow2";

        let result = probe_checksum_from_image_url(image_url, filename).await;
        let (entry, sums_url) = result.expect("should find a SHASUMS file");

        assert!(
            sums_url.contains("SHA512SUMS") || sums_url.contains("SHA256SUMS"),
            "unexpected sums_url: {sums_url}"
        );
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        assert_eq!(entry.checksum.len(), 128);
        Ok(())
    }

    #[tokio::test]
    async fn test_probe_checksum_ubuntu_image_url() -> anyhow::Result<()> {
        let image_url =
            "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img";
        let filename = "noble-server-cloudimg-amd64.img";

        let result = probe_checksum_from_image_url(image_url, filename).await;
        let (entry, sums_url) = result.expect("should find a SHASUMS file");

        assert!(
            sums_url.contains("SHA256SUMS") || sums_url.contains("SHA512SUMS"),
            "unexpected sums_url: {sums_url}"
        );
        assert_eq!(entry.checksum.len(), 64, "Ubuntu uses SHA-256");
        Ok(())
    }

    #[tokio::test]
    async fn test_probe_checksum_arch_sidecar() -> anyhow::Result<()> {
        // Arch Linux uses a per-file sidecar: <image>.qcow2.SHA256
        let image_url =
            "https://mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2";
        let filename = "Arch-Linux-x86_64-cloudimg.qcow2";

        let result = probe_checksum_from_image_url(image_url, filename).await;
        let (entry, sums_url) = result.expect("should find sidecar SHA256 file");

        assert!(
            sums_url.ends_with(".SHA256"),
            "unexpected sums_url: {sums_url}"
        );
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(entry.checksum.len(), 64);
        Ok(())
    }

    #[test]
    fn test_probe_base_url_stripping() {
        // Verify the base-URL derivation logic inline (no network needed)
        let image_url = "https://example.com/images/latest/some-image.qcow2";
        let base = {
            let trimmed = image_url.trim_end_matches('/');
            let i = trimmed.rfind('/').unwrap();
            trimmed[..=i].to_owned()
        };
        assert_eq!(base, "https://example.com/images/latest/");
    }
}
