//! Published policy documents (Terms of Service / Acceptable Use).
//!
//! Fetched from the website at runtime rather than vendored here, so the agent
//! always quotes what the customer can actually read, and a policy change does
//! not require a release of this service. Exactly one document is exposed
//! rather than a generic "fetch a page" tool: the rest of lnvps.net is
//! client-rendered and would come back as an empty shell.
//!
//! The request asks for `text/markdown`, which the site serves as the raw
//! source of the page — the same text the browser renders, minus the chrome.
//! HTML is still handled as a fallback so this keeps working against a
//! deployment that predates that negotiation, and during a rollout where some
//! nodes have it and some do not.
//!
//! No URL comes from the model: the document set is a closed enum. A tool that
//! fetched an arbitrary URL and fed it to the model would be both an SSRF
//! primitive and a prompt-injection channel.

use anyhow::{Context, Result, bail};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Where the published policies live.
pub const DEFAULT_BASE_URL: &str = "https://lnvps.net";

/// Path of the combined Terms of Service / Acceptable Use document.
const TOS_PATH: &str = "/tos";

/// Policies change rarely; an hour of staleness is invisible to a customer and
/// keeps a busy support queue from hammering the website.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Upper bound on what is handed to the model. The document is ~2k words; the
/// cap exists so an unexpectedly large or malformed page cannot blow out the
/// context window mid-conversation.
const MAX_CHARS: usize = 40_000;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Markdown is listed alone so it out-ranks HTML: the site serves the raw
/// source only when markdown is explicitly preferred, and a wildcard never
/// counts as a preference.
const ACCEPT: &str = "text/markdown";

/// Cached fetcher for the published policy documents.
#[derive(Debug)]
pub struct PolicyDocs {
    http: reqwest::Client,
    base_url: String,
    cached: Mutex<Option<(Instant, Arc<str>)>>,
}

impl Default for PolicyDocs {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL)
    }
}

impl PolicyDocs {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            cached: Mutex::new(None),
        }
    }

    /// Terms of Service and Acceptable Use, as markdown (or stripped HTML from
    /// a deployment that does not negotiate it).
    pub async fn terms_of_service(&self) -> Result<Arc<str>> {
        let mut cached = self.cached.lock().await;
        if let Some((fetched, text)) = cached.as_ref()
            && fetched.elapsed() < CACHE_TTL
        {
            return Ok(text.clone());
        }

        let url = format!("{}{}", self.base_url, TOS_PATH);
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, ACCEPT)
            .send()
            .await
            .context("failed to fetch the terms of service")?;
        if !response.status().is_success() {
            bail!("terms of service page returned {}", response.status());
        }
        let markdown = serves_markdown(&response);
        let body = response
            .text()
            .await
            .context("failed to read policy page")?;
        // Markdown passes through untouched: its syntax is meaningful to the
        // model (headings locate a clause, lists keep enumerated terms apart),
        // and the HTML stripper would flatten it.
        let text = if markdown {
            body.trim().to_string()
        } else {
            html_to_text(&body)
        };
        if text.len() < 500 {
            // A short body means the document moved or the render broke.
            // Serving that to the model would let it state policy from an
            // effectively empty document.
            bail!("terms of service page returned no readable text");
        }
        let text: Arc<str> = Arc::from(truncate(&text, MAX_CHARS));
        *cached = Some((Instant::now(), text.clone()));
        Ok(text)
    }
}

/// Whether the response body is markdown rather than HTML.
///
/// Decided by the response's own content type, not by what was asked for: a
/// server that ignores the `Accept` header still answers HTML, and treating
/// that as markdown would hand the model a page of tags.
fn serves_markdown(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let media_type = value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            // Deliberately not `text/plain`: that is what a server falls back
            // to when it does not know what it is serving, and trusting it
            // would pass raw HTML through as if it were markdown.
            matches!(media_type.as_str(), "text/markdown" | "text/x-markdown")
        })
        .unwrap_or(false)
}

/// Cut at a character boundary and say so, so the model never silently quotes
/// a half-sentence as the whole clause.
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n[document truncated]", &text[..end])
}

/// Render HTML as plain text: drop `head`, `script` and `style` content, keep
/// block structure as newlines, and collapse the resulting whitespace.
fn html_to_text(html: &str) -> String {
    let body = match html.find("<body") {
        Some(index) => &html[index..],
        None => html,
    };
    let mut out = String::with_capacity(body.len() / 2);
    let mut rest = body;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        rest = &rest[open..];
        let lower = rest.to_ascii_lowercase();
        if let Some(skip) = skip_block(&lower, "script").or_else(|| skip_block(&lower, "style")) {
            rest = &rest[skip..];
            continue;
        }
        let close = match rest.find('>') {
            Some(index) => index,
            None => break,
        };
        // Any tag boundary is a potential line break; the whitespace collapse
        // below turns runs of them back into single breaks.
        out.push('\n');
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    collapse(&decode_entities(&out))
}

/// If `lower` opens with `<tag`, return how far to skip past `</tag>`.
fn skip_block(lower: &str, tag: &str) -> Option<usize> {
    if !lower.starts_with(&format!("<{tag}")) {
        return None;
    }
    let end = format!("</{tag}>");
    match lower.find(&end) {
        Some(index) => Some(index + end.len()),
        // Unterminated block: swallow the rest rather than emit markup.
        None => Some(lower.len()),
    }
}

/// Decode the entities a server-rendered page actually emits.
pub(crate) fn decode_entities(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&raquo;", "»")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        // Ampersand last: decoding it first would let `&amp;lt;` become `<`.
        .replace("&amp;", "&")
}

/// Trim each line and drop blank runs.
fn collapse(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(body: &str) -> String {
        format!(
            "<!doctype html><html><head><title>t</title><script>var x = 1;</script></head><body>{body}</body></html>"
        )
    }

    fn long_body() -> String {
        format!("<h1>Terms</h1><p>{}</p>", "policy text. ".repeat(60))
    }

    #[test]
    fn extracts_text_and_drops_scripts() {
        let text = html_to_text(&page("<h1>Terms</h1><p>Be nice &amp; pay.</p>"));
        assert!(text.contains("Terms"));
        assert!(text.contains("Be nice & pay."));
        assert!(!text.contains("var x"));
        assert!(!text.contains("<"));
    }

    #[test]
    fn drops_style_blocks_and_head() {
        let html = "<head><title>x</title></head><body><style>a{color:red}</style><p>Hi</p></body>";
        let text = html_to_text(html);
        assert!(!text.contains("color:red"));
        assert!(!text.contains("<title>"));
        assert_eq!(text, "Hi");
    }

    #[test]
    fn unterminated_script_is_swallowed() {
        let text = html_to_text("<body><p>Hi</p><script>var y = 2;");
        assert_eq!(text, "Hi");
    }

    #[test]
    fn entities_decode_without_double_decoding() {
        assert_eq!(decode_entities("&amp;lt;"), "&lt;");
        assert_eq!(decode_entities("a &quot;b&quot;"), "a \"b\"");
    }

    #[test]
    fn truncate_marks_the_cut() {
        let out = truncate(&"x".repeat(100), 10);
        assert!(out.starts_with(&"x".repeat(10)));
        assert!(out.contains("[document truncated]"));
        assert_eq!(truncate("short", 10), "short");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let text = "é".repeat(10); // two bytes per char
        let out = truncate(&text, 5);
        assert!(out.starts_with("éé"));
    }

    /// The markdown body is returned verbatim: headings and lists are what let
    /// the model cite a specific clause.
    #[tokio::test]
    async fn serves_markdown_verbatim_when_negotiated() {
        let server = wiremock::MockServer::start().await;
        let markdown = format!("# Terms\n\n- No port scanning\n\n{}", "body. ".repeat(100));
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/tos"))
            .and(wiremock::matchers::header("accept", "text/markdown"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(markdown, "text/markdown; charset=utf-8"),
            )
            .mount(&server)
            .await;

        let text = PolicyDocs::new(server.uri())
            .terms_of_service()
            .await
            .unwrap();
        assert!(text.starts_with("# Terms"));
        assert!(text.contains("- No port scanning"));
    }

    /// A server that ignores the header still answers HTML; the fallback must
    /// strip it rather than hand the model a page of tags.
    #[tokio::test]
    async fn falls_back_to_stripping_html() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/tos"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_raw(page(&long_body()), "text/html"),
            )
            .mount(&server)
            .await;

        let text = PolicyDocs::new(server.uri())
            .terms_of_service()
            .await
            .unwrap();
        assert!(text.contains("Terms"));
        assert!(!text.contains('<'));
    }

    #[tokio::test]
    async fn fetches_and_caches_the_document() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/tos"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(page(&long_body())))
            .expect(1) // second call must be served from cache
            .mount(&server)
            .await;

        let docs = PolicyDocs::new(server.uri());
        let first = docs.terms_of_service().await.unwrap();
        assert!(first.contains("Terms"));
        let second = docs.terms_of_service().await.unwrap();
        assert_eq!(first, second);
    }

    /// An empty SPA shell must fail loudly rather than let the model state
    /// policy from a blank page.
    #[tokio::test]
    async fn rejects_an_empty_render() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(page("<div></div>")))
            .mount(&server)
            .await;
        let err = PolicyDocs::new(server.uri())
            .terms_of_service()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no readable text"));
    }

    #[tokio::test]
    async fn surfaces_http_errors() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(
            PolicyDocs::new(server.uri())
                .terms_of_service()
                .await
                .is_err()
        );
    }

    /// Live canary: the published document is reachable and negotiates
    /// markdown. Ignored by default — the website being down is not this
    /// repository failing.
    #[tokio::test]
    #[ignore = "hits the live website; run with --ignored"]
    async fn live_site_serves_markdown() {
        let text = PolicyDocs::default().terms_of_service().await.unwrap();
        assert!(
            text.starts_with('#'),
            "expected markdown, got: {:.80}",
            text
        );
        assert!(text.contains("Acceptable Use"));
    }

    #[test]
    fn default_targets_the_public_site() {
        let docs = PolicyDocs::default();
        assert_eq!(docs.base_url, DEFAULT_BASE_URL);
    }
}
