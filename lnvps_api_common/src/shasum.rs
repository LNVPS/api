use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Result, bail};

/// User-Agent sent with all checksum-related HTTP requests.
///
/// Some CDNs (e.g. CloudFront in front of cloud.centos.org) return 403 for
/// requests without a User-Agent header, which reqwest omits by default.
const USER_AGENT: &str = concat!("lnvps/", env!("CARGO_PKG_VERSION"));

/// Maximum size of a downloaded SHASUMS file (1 MiB).  Prevents accidentally
/// slurping a large binary into memory if a probed candidate URL resolves to
/// something that is not a checksum file.
const MAX_SUMS_FILE_SIZE: u64 = 1024 * 1024;

/// Shared HTTP client with a User-Agent, timeouts and redirect following.
fn http_client() -> Result<&'static reqwest::Client> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::limited(10))
        .connect_timeout(Duration::from_secs(10))
        // Generous: some distro mirrors are slow to answer HEAD on large
        // files; this only needs to bound indefinite hangs.
        .timeout(Duration::from_secs(60))
        .build()?;
    Ok(CLIENT.get_or_init(|| client))
}

/// Fetch the body of a SHASUMS file, enforcing [`MAX_SUMS_FILE_SIZE`].
///
/// Returns `Ok(None)` if the server definitively reports the file as absent
/// (404 Not Found), and `Err` for any other failure (network error, other
/// HTTP error status, or file too large).
async fn fetch_sums_text(url: &str) -> Result<Option<String>> {
    let resp = http_client()?.get(url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let mut resp = resp.error_for_status()?;
    if let Some(len) = resp.content_length()
        && len > MAX_SUMS_FILE_SIZE
    {
        bail!("Checksum file at {} is too large ({} bytes)", url, len);
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if (body.len() + chunk.len()) as u64 > MAX_SUMS_FILE_SIZE {
            bail!(
                "Checksum file at {} exceeds {} bytes",
                url,
                MAX_SUMS_FILE_SIZE
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(String::from_utf8_lossy(&body).into_owned()))
}

/// Fetch a SHASUMS file and look up `filename`.
///
/// - `Ok(Some(entry))` — checksum found
/// - `Ok(None)` — file definitively absent (404) or `filename` not listed
/// - `Err(_)` — transient/other failure (network error, 5xx, too large)
async fn try_fetch_checksum(sha2_url: &str, filename: &str) -> Result<Option<ShasumEntry>> {
    let Some(body) = fetch_sums_text(sha2_url).await? else {
        return Ok(None);
    };
    let entries = parse_shasum_file(&body);
    if let Some(e) = find_checksum(&entries, filename) {
        return Ok(Some(e.clone()));
    }
    // Digest-only sidecar files (e.g. Alpine's `<image>.qcow2.sha512`) contain
    // a bare hash with no filename.  If the file holds exactly one such entry,
    // attribute it to the requested filename.
    let mut bare = entries.iter().filter(|e| e.filename.is_empty());
    if let (Some(e), None) = (bare.next(), bare.next()) {
        let mut e = e.clone();
        e.filename = filename.to_owned();
        return Ok(Some(e));
    }
    Ok(None)
}

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
/// **Digest-only** (per-file sidecars, e.g. Alpine's `<image>.sha512`):
/// ```text
/// <checksum>
/// ```
/// These entries have an empty `filename`.
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
        if let Some(entry) = parse_bsd_line(line)
            .or_else(|| parse_gnu_line(line))
            .or_else(|| parse_bare_digest_line(line))
        {
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
    match try_fetch_checksum(sha2_url, filename).await? {
        Some(e) => Ok(e),
        None => bail!("Checksum for '{}' not found in {}", filename, sha2_url),
    }
}

/// Follow HTTP redirects for the given URL and return the final resolved URL.
///
/// Issues a HEAD request (falling back to GET if HEAD is not supported) and
/// returns the URL of the last response after all redirects have been followed.
/// If the request fails the original `url` is returned unchanged.
pub async fn resolve_redirect(url: &str) -> String {
    // The client follows redirects (up to 10).  The final response URL
    // is the resolved location after all hops.
    let client = match http_client() {
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
    // CentOS / Fedora cloud images use a BSD-format "CHECKSUM" file
    "CHECKSUM",
    // FreeBSD VM images publish BSD-format "CHECKSUM.SHA512"/"CHECKSUM.SHA256"
    "CHECKSUM.SHA512",
    "CHECKSUM.SHA256",
];

/// Per-file sidecar extensions appended directly to the image filename
/// (e.g. `foo.qcow2.SHA256`).  Ordered from strongest to weakest.
const CANDIDATE_SIDECAR_EXTS: &[&str] = &[
    ".SHA512",
    ".SHA256",
    ".sha512",
    ".sha256",
    // CentOS cloud images publish e.g. `<image>.qcow2.SHA256SUM`
    ".SHA512SUM",
    ".SHA256SUM",
    // Rocky Linux publishes e.g. `<image>.qcow2.CHECKSUM` (BSD format)
    ".CHECKSUM",
];

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

    // Candidate URLs in priority order: shared SUMS files, then sidecars.
    let candidates: Vec<String> = CANDIDATE_SUMS_FILES
        .iter()
        .map(|c| format!("{}{}", base, c))
        .chain(
            CANDIDATE_SIDECAR_EXTS
                .iter()
                .map(|e| format!("{}{}", image_url, e)),
        )
        .collect();

    // Fetch candidates with limited concurrency (politer to mirrors than a
    // full burst), then pick the first hit in priority order.  Transient
    // failures are logged so a valid source is not silently skipped.
    //
    // Each future owns its data (no borrows across await) so the combined
    // future stays `Send` regardless of caller lifetimes.
    use futures::StreamExt;
    let results: Vec<(String, Result<Option<ShasumEntry>>)> =
        futures::stream::iter(candidates.into_iter().map(|url| {
            let filename = filename.to_owned();
            async move {
                let result = try_fetch_checksum(&url, &filename).await;
                (url, result)
            }
        }))
        .buffered(4)
        .collect()
        .await;

    for (url, result) in results {
        match result {
            Ok(Some(entry)) => return Some((entry, url)),
            Ok(None) => {}
            Err(e) => log::warn!("Failed to fetch checksum candidate {}: {}", url, e),
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

/// Parse a digest-only line: `<checksum>` with no filename.
///
/// Used by per-file sidecars that contain just the bare hash (e.g. Alpine's
/// `<image>.qcow2.sha512`).  The resulting entry has an empty `filename`.
fn parse_bare_digest_line(line: &str) -> Option<ShasumEntry> {
    if !line.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let algorithm = ShasumAlgorithm::from_hex_len(line.len())?;
    Some(ShasumEntry {
        algorithm,
        checksum: line.to_lowercase(),
        filename: String::new(),
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
    // Split on the *last* `)` so filenames containing parentheses parse correctly
    let inner = rest.strip_prefix('(')?.rsplit_once(')')?;
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
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serve `body` for a GET of `route`; anything else 404s.
    async fn mock_get(server: &MockServer, route: impl Into<String>, body: impl Into<String>) {
        Mock::given(method("GET"))
            .and(path(route.into()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.into()))
            .mount(server)
            .await;
    }

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

    // ---- Digest-only sidecar format ----------------------------------------

    #[test]
    fn test_bare_digest_sha512() {
        let content = "bb509092cda3548c11bc48a2168ce950d654b50db006e98939c06a5d86487f4e53cbb7954fafbba9ab5c8098008a9f304421ffc3397b0bc1d87b6aa309239b98\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].algorithm, ShasumAlgorithm::Sha512);
        assert!(entries[0].filename.is_empty());
    }

    #[test]
    fn test_bare_digest_rejects_invalid() {
        // Not hex
        assert!(
            parse_bare_digest_line(
                "zz09861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b"
            )
            .is_none()
        );
        // Wrong length
        assert!(parse_bare_digest_line("deadbeef").is_none());
    }

    #[test]
    fn test_bsd_filename_with_parens() {
        let content = "SHA256 (image (1).qcow2) = 049d861863ad093da0d1e97a49e4d4f57329b86b56e66e3c0578e788c4fa3c2b\n";
        let entries = parse_shasum_file(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "image (1).qcow2");
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

    // ---- Fixtures ----------------------------------------------------------
    //
    // The shapes below are copies of what real mirrors publish.  They are
    // served from a local mock so the parsing, probing and header logic is
    // covered without depending on anyone else's infrastructure staying up.

    /// GNU coreutils format, as published by Debian's `SHA512SUMS`.
    const GNU_SHA512SUMS: &str = concat!(
        "4586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bc",
        "a924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c",
        "  debian-12-generic-amd64.qcow2\n",
        "5586d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bc",
        "a924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c",
        "  debian-12-nocloud-amd64.qcow2\n",
    );

    /// GNU coreutils format with SHA-256 digests, as published by Ubuntu.
    const GNU_SHA256SUMS: &str = concat!(
        "31b0e1c2f0b8a0e6bd0f9a1f3a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
        " *noble-server-cloudimg-amd64.img\n",
    );

    /// BSD format, as published by CentOS Stream's shared `CHECKSUM`.
    const BSD_CHECKSUM: &str = concat!(
        "# CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2: 1234567890 bytes\n",
        "SHA256 (CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2) = ",
        "aa0e1c2f0b8a0e6bd0f9a1f3a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6\n",
    );

    /// BSD format sidecar, as published by Rocky Linux (`<image>.CHECKSUM`).
    const BSD_SIDECAR: &str = concat!(
        "SHA256 (Rocky-9-GenericCloud.latest.x86_64.qcow2) = ",
        "bb0e1c2f0b8a0e6bd0f9a1f3a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6\n",
    );

    /// Digest-only sidecar, as published by Alpine (`<image>.sha512`).
    const BARE_DIGEST_SIDECAR: &str = concat!(
        "cc86d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bc",
        "a924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c\n",
    );

    // ---- resolve_redirect --------------------------------------------------

    #[tokio::test]
    async fn test_resolve_redirect_no_redirect() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/images/SHA512SUMS"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url = format!("{}/images/SHA512SUMS", server.uri());
        assert_eq!(resolve_redirect(&url).await, url);
    }

    #[tokio::test]
    async fn test_resolve_redirect_follows_redirect() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/images/image.raw"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/mirror/image.raw"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/mirror/image.raw"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url = format!("{}/images/image.raw", server.uri());
        let resolved = resolve_redirect(&url).await;
        assert_eq!(resolved, format!("{}/mirror/image.raw", server.uri()));
    }

    /// Servers that reject HEAD must be retried with GET rather than reported
    /// as unresolvable.
    #[tokio::test]
    async fn test_resolve_redirect_falls_back_to_get_when_head_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/images/image.raw"))
            .respond_with(ResponseTemplate::new(405))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/images/image.raw"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/mirror/image.raw"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/mirror/image.raw"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let url = format!("{}/images/image.raw", server.uri());
        let resolved = resolve_redirect(&url).await;
        assert_eq!(resolved, format!("{}/mirror/image.raw", server.uri()));
    }

    /// An unreachable host leaves the caller with the URL it passed in.
    #[tokio::test]
    async fn test_resolve_redirect_unreachable_returns_input() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let url = format!("http://{addr}/images/image.raw");
        assert_eq!(resolve_redirect(&url).await, url);
    }

    // ---- fetch_checksum_for_file -------------------------------------------

    /// Regression test: some CDNs return 403 for requests without a
    /// User-Agent, which reqwest omits by default.
    #[tokio::test]
    async fn test_fetch_checksum_sends_user_agent() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/images/CHECKSUM"))
            .and(header_exists("user-agent"))
            .respond_with(ResponseTemplate::new(200).set_body_string(BSD_CHECKSUM))
            .mount(&server)
            .await;
        // Matched only when the header is absent, so a header-less request
        // fails the test instead of falling through to the 200.
        Mock::given(method("GET"))
            .and(path("/images/CHECKSUM"))
            .and(|req: &wiremock::Request| !req.headers.contains_key("user-agent"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let url = format!("{}/images/CHECKSUM", server.uri());
        let entry =
            fetch_checksum_for_file(&url, "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2")
                .await?;

        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(entry.checksum.len(), 64);
        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_checksum_gnu_sums_file() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA512SUMS", GNU_SHA512SUMS).await;

        let url = format!("{}/images/SHA512SUMS", server.uri());
        let entry = fetch_checksum_for_file(&url, "debian-12-generic-amd64.qcow2").await?;

        assert_eq!(entry.filename, "debian-12-generic-amd64.qcow2");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        assert_eq!(entry.checksum.len(), 128);
        assert!(entry.checksum.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_checksum_bsd_checksum_file() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/CHECKSUM", BSD_CHECKSUM).await;

        let url = format!("{}/images/CHECKSUM", server.uri());
        let filename = "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2";
        let entry = fetch_checksum_for_file(&url, filename).await?;

        assert_eq!(entry.filename, filename);
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        Ok(())
    }

    /// A digest-only sidecar carries no filename, so the requested one is
    /// attributed to it.
    #[tokio::test]
    async fn test_fetch_checksum_bare_digest_sidecar() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/alpine.qcow2.sha512", BARE_DIGEST_SIDECAR).await;

        let url = format!("{}/images/alpine.qcow2.sha512", server.uri());
        let entry = fetch_checksum_for_file(&url, "alpine.qcow2").await?;

        assert_eq!(entry.filename, "alpine.qcow2");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        Ok(())
    }

    #[tokio::test]
    async fn test_fetch_checksum_missing_filename_errors() {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA512SUMS", GNU_SHA512SUMS).await;

        let url = format!("{}/images/SHA512SUMS", server.uri());
        assert!(
            fetch_checksum_for_file(&url, "nonexistent-file.qcow2")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_fetch_checksum_absent_file_errors() {
        let server = MockServer::start().await;
        let url = format!("{}/images/SHA512SUMS", server.uri());
        assert!(
            fetch_checksum_for_file(&url, "anything.qcow2")
                .await
                .is_err()
        );
    }

    /// Spawn a local HTTP server that serves an over-sized body.
    ///
    /// - `/with-length` — advertises a 10 MiB `Content-Length`
    /// - `/no-length` — streams ~2 MiB with connection-close framing (no length)
    async fn spawn_large_file_server() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let with_length = req.starts_with("GET /with-length");
                    let header = if with_length {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                            10 * 1024 * 1024
                        )
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
                            .to_string()
                    };
                    let _ = sock.write_all(header.as_bytes()).await;
                    let chunk = vec![b'a'; 64 * 1024];
                    // 2 MiB of body — more than MAX_SUMS_FILE_SIZE
                    for _ in 0..32 {
                        if sock.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    /// A response advertising Content-Length > cap is rejected before download.
    #[tokio::test]
    async fn test_fetch_checksum_rejects_large_content_length() {
        let addr = spawn_large_file_server().await;
        let url = format!("http://{}/with-length", addr);
        let err = fetch_checksum_for_file(&url, "whatever.qcow2")
            .await
            .expect_err("should refuse to download a huge file");
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }

    /// A response without Content-Length is aborted once the cap is exceeded.
    #[tokio::test]
    async fn test_fetch_checksum_rejects_large_unbounded_body() {
        let addr = spawn_large_file_server().await;
        let url = format!("http://{}/no-length", addr);
        let err = fetch_checksum_for_file(&url, "whatever.qcow2")
            .await
            .expect_err("should abort an unbounded body at the cap");
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

    // ---- probe_checksum_from_image_url -------------------------------------

    #[tokio::test]
    async fn test_probe_finds_shared_sums_file() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA512SUMS", GNU_SHA512SUMS).await;

        let image_url = format!("{}/images/debian-12-generic-amd64.qcow2", server.uri());
        let (entry, sums_url) =
            probe_checksum_from_image_url(&image_url, "debian-12-generic-amd64.qcow2")
                .await
                .expect("should find a SHASUMS file");

        assert!(sums_url.ends_with("/SHA512SUMS"), "unexpected: {sums_url}");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        assert_eq!(entry.checksum.len(), 128);
        Ok(())
    }

    /// Both digests published: the stronger shared file wins regardless of
    /// which response arrives first.
    #[tokio::test]
    async fn test_probe_prefers_sha512_over_sha256() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA512SUMS", GNU_SHA512SUMS).await;
        mock_get(
            &server,
            "/images/SHA256SUMS",
            concat!(
                "31b0e1c2f0b8a0e6bd0f9a1f3a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
                "  debian-12-generic-amd64.qcow2\n"
            ),
        )
        .await;

        let image_url = format!("{}/images/debian-12-generic-amd64.qcow2", server.uri());
        let (entry, sums_url) =
            probe_checksum_from_image_url(&image_url, "debian-12-generic-amd64.qcow2")
                .await
                .expect("should find a SHASUMS file");

        assert!(sums_url.ends_with("/SHA512SUMS"), "unexpected: {sums_url}");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        Ok(())
    }

    /// A `SHA256SUMS` listing a `.img` artifact, as Ubuntu publishes.
    #[tokio::test]
    async fn test_probe_finds_sha256sums() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA256SUMS", GNU_SHA256SUMS).await;

        let image_url = format!("{}/images/noble-server-cloudimg-amd64.img", server.uri());
        let (entry, sums_url) =
            probe_checksum_from_image_url(&image_url, "noble-server-cloudimg-amd64.img")
                .await
                .expect("should find a SHASUMS file");

        assert!(sums_url.ends_with("/SHA256SUMS"), "unexpected: {sums_url}");
        assert_eq!(entry.checksum.len(), 64);
        Ok(())
    }

    /// A shared BSD-format `CHECKSUM` file, as CentOS Stream publishes.
    #[tokio::test]
    async fn test_probe_finds_bsd_checksum_file() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        mock_get(&server, "/images/CHECKSUM", BSD_CHECKSUM).await;

        let filename = "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2";
        let image_url = format!("{}/images/{filename}", server.uri());
        let (entry, sums_url) = probe_checksum_from_image_url(&image_url, filename)
            .await
            .expect("should find CHECKSUM file");

        assert!(sums_url.ends_with("/CHECKSUM"), "unexpected: {sums_url}");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        Ok(())
    }

    /// `CHECKSUM.SHA512` in the image directory, as FreeBSD publishes.
    #[tokio::test]
    async fn test_probe_finds_checksum_sha512_in_directory() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let filename = "FreeBSD-15.0-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz";
        mock_get(
            &server,
            "/images/CHECKSUM.SHA512",
            format!(
                "SHA512 ({filename}) = {}{}\n",
                "dd86d96ba3604c05b1772c9fef74a6957402688eb9c075f212068d5a29afe6bc",
                "a924afaa4d12b8e0e593deea18b8b200f606a94ad4a0aa5361e75ffacb12087c"
            ),
        )
        .await;

        let image_url = format!("{}/images/{filename}", server.uri());
        let (entry, sums_url) = probe_checksum_from_image_url(&image_url, filename)
            .await
            .expect("should find CHECKSUM.SHA512");

        assert!(
            sums_url.ends_with("/CHECKSUM.SHA512"),
            "unexpected: {sums_url}"
        );
        assert_eq!(entry.filename, filename);
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        Ok(())
    }

    /// A digest-only per-file sidecar, as Alpine publishes.
    #[tokio::test]
    async fn test_probe_finds_bare_digest_sidecar() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let filename = "nocloud_alpine-3.21.0-x86_64-bios-cloudinit-r0.qcow2";
        mock_get(
            &server,
            format!("/images/{filename}.sha512"),
            BARE_DIGEST_SIDECAR,
        )
        .await;

        let image_url = format!("{}/images/{filename}", server.uri());
        let (entry, sums_url) = probe_checksum_from_image_url(&image_url, filename)
            .await
            .expect("should find bare-digest sidecar");

        assert!(sums_url.ends_with(".sha512"), "unexpected: {sums_url}");
        assert_eq!(entry.filename, filename);
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        Ok(())
    }

    /// A BSD-format per-file `.CHECKSUM` sidecar, as Rocky Linux publishes.
    #[tokio::test]
    async fn test_probe_finds_bsd_sidecar() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let filename = "Rocky-9-GenericCloud.latest.x86_64.qcow2";
        mock_get(&server, format!("/images/{filename}.CHECKSUM"), BSD_SIDECAR).await;

        let image_url = format!("{}/images/{filename}", server.uri());
        let (entry, sums_url) = probe_checksum_from_image_url(&image_url, filename)
            .await
            .expect("should find .CHECKSUM sidecar");

        assert!(sums_url.ends_with(".CHECKSUM"), "unexpected: {sums_url}");
        assert_eq!(entry.filename, filename);
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        Ok(())
    }

    /// An uppercase `.SHA256` sidecar, as Arch Linux publishes.
    #[tokio::test]
    async fn test_probe_finds_uppercase_sha256_sidecar() -> anyhow::Result<()> {
        let server = MockServer::start().await;
        let filename = "Arch-Linux-x86_64-cloudimg.qcow2";
        mock_get(
            &server,
            format!("/images/{filename}.SHA256"),
            format!(
                "ee0e1c2f0b8a0e6bd0f9a1f3a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6  {filename}\n"
            ),
        )
        .await;

        let image_url = format!("{}/images/{filename}", server.uri());
        let (entry, sums_url) = probe_checksum_from_image_url(&image_url, filename)
            .await
            .expect("should find sidecar SHA256 file");

        assert!(sums_url.ends_with(".SHA256"), "unexpected: {sums_url}");
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        assert_eq!(entry.checksum.len(), 64);
        Ok(())
    }

    /// Nothing published: probing reports no checksum rather than erroring.
    #[tokio::test]
    async fn test_probe_returns_none_when_no_candidate_exists() {
        let server = MockServer::start().await;
        let image_url = format!("{}/images/mystery.qcow2", server.uri());
        assert!(
            probe_checksum_from_image_url(&image_url, "mystery.qcow2")
                .await
                .is_none()
        );
    }

    /// A candidate that lists other files but not this one is not a match.
    #[tokio::test]
    async fn test_probe_ignores_sums_file_without_the_filename() {
        let server = MockServer::start().await;
        mock_get(&server, "/images/SHA512SUMS", GNU_SHA512SUMS).await;

        let image_url = format!("{}/images/not-listed.qcow2", server.uri());
        assert!(
            probe_checksum_from_image_url(&image_url, "not-listed.qcow2")
                .await
                .is_none()
        );
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

    // ---- Live mirror canaries ----------------------------------------------
    //
    // These hit third-party mirrors, so they are not part of the default run:
    // a failure here means someone else changed their layout, not that this
    // code broke.  Run deliberately with
    // `cargo test -p lnvps_api_common -- --ignored live_mirror`.

    #[tokio::test]
    #[ignore = "hits live mirrors"]
    async fn live_mirror_debian_sha512sums() -> anyhow::Result<()> {
        let entry = fetch_checksum_for_file(
            "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS",
            "debian-12-generic-amd64.qcow2",
        )
        .await?;
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha512);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "hits live mirrors"]
    async fn live_mirror_centos_checksum() -> anyhow::Result<()> {
        let entry = fetch_checksum_for_file(
            "https://cloud.centos.org/centos/9-stream/x86_64/images/CHECKSUM",
            "CentOS-Stream-GenericCloud-9-latest.x86_64.qcow2",
        )
        .await?;
        assert_eq!(entry.algorithm, ShasumAlgorithm::Sha256);
        Ok(())
    }
}
