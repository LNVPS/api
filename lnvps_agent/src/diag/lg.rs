//! Looking-glass client (bird-lg-go at `lg.lnvps.cloud`).
//!
//! Only the traceroute endpoint is used. The frontend advertises a ping action
//! but `/ping/<server>/<target>` answers `302 -> /summary/<server>`, so a ping
//! tool has to be derived from the traceroute: the mtr report already carries
//! per-hop loss and RTT, and the final hop being the target *is* the ping
//! answer. That also keeps one round trip where two would otherwise hit a
//! rate-limited public service that forks a process per query.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

/// Public looking glass frontend.
pub const DEFAULT_BASE_URL: &str = "https://lg.lnvps.cloud";

/// The edge router's alias on the looking glass.
///
/// An alias on purpose: it keeps the router's internal address out of every
/// URL and out of anything the agent might quote back to a customer.
pub const DEFAULT_SERVER: &str = "edge1";

/// mtr to an unresponsive host runs the full cycle before reporting, which
/// takes roughly 30s; the ceiling is set well above that so a dead target
/// returns "unreachable" rather than a client timeout the model must guess at.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(2);
#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(1);

/// One line of the mtr report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Hop {
    /// Distance from the edge router, starting at 1.
    pub hop: u8,
    /// Address or hostname that answered, or `???` when nothing did.
    pub host: String,
    /// Percentage of probes lost at this hop.
    pub loss_percent: f32,
    /// Round-trip time of the last probe, absent when the hop stayed silent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f32>,
}

impl Hop {
    /// Whether this hop answered at all.
    pub fn responded(&self) -> bool {
        self.host != "???" && self.rtt_ms.is_some() && self.loss_percent < 100.0
    }
}

/// A parsed traceroute, shaped for the model to read directly.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Traceroute {
    /// Address that was probed.
    pub target: String,
    /// Vantage point the probe ran from.
    pub from: String,
    /// Whether the target itself answered.
    pub reached: bool,
    /// Loss at the target, when it appeared in the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_percent: Option<f32>,
    /// RTT to the target, when it answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f32>,
    /// Full path, so the model can point at where a path dies.
    pub hops: Vec<Hop>,
    /// `no_reply_from_vm` when the looking glass answered but the report held
    /// no hop at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meaning: Option<&'static str>,
}

pub const NO_REPLY_FROM_VM: &str = "no_reply_from_vm";
pub const NO_REPLY_MEANING: &str = "The edge router got no reply from this VM on its local network. The looking glass itself is working. The VM is off, its network is down, or its firewall drops everything.";

/// Client for the public looking glass.
#[derive(Debug, Clone)]
pub struct LookingGlass {
    http: reqwest::Client,
    base_url: String,
    server: String,
}

impl Default for LookingGlass {
    fn default() -> Self {
        Self::new(DEFAULT_BASE_URL, DEFAULT_SERVER)
    }
}

impl LookingGlass {
    /// Build a client against a specific frontend and server alias.
    pub fn new(base_url: impl Into<String>, server: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            server: server.into(),
        }
    }

    /// Run an mtr from the edge router towards `target`.
    ///
    /// `target` is an [`IpAddr`] rather than a string so no caller can smuggle
    /// a hostname, a second path segment, or a BIRD command into the URL.
    pub async fn traceroute(&self, target: IpAddr) -> Result<Traceroute> {
        match self.traceroute_once(target).await {
            Ok(trace) => Ok(trace),
            Err(_) => {
                tokio::time::sleep(RETRY_DELAY).await;
                self.traceroute_once(target).await
            }
        }
    }

    async fn traceroute_once(&self, target: IpAddr) -> Result<Traceroute> {
        let url = format!("{}/traceroute/{}/{}", self.base_url, self.server, target);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .context("looking glass unavailable: request failed")?;
        if !response.status().is_success() {
            bail!("looking glass unavailable: returned {}", response.status());
        }
        let body = response
            .text()
            .await
            .context("looking glass unavailable: read failed")?;
        parse_mtr(&strip_html(&body), target, &self.server)
    }
}

/// Strip tags and the handful of entities bird-lg-go emits.
///
/// A tag-aware strip rather than a line filter because the report is embedded
/// in a full HTML page; the hop lines survive intact either way, but the page
/// chrome would otherwise reach the model.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    super::policy::decode_entities(&out)
}

/// Parse the mtr report out of a de-tagged looking-glass page.
///
/// Hop lines look like:
///
/// ```text
///   1.|-- 185.18.221.87  0.0%     1    0.2   0.2   0.2   0.2   0.0
/// ```
///
/// Everything else on the page (nav, the query form, the inline script) is
/// ignored by requiring the `N.|--` marker.
fn parse_mtr(text: &str, target: IpAddr, server: &str) -> Result<Traceroute> {
    let hops: Vec<Hop> = text.lines().filter_map(parse_hop).collect();
    if hops.is_empty() {
        if text.lines().any(|l| l.trim_start().starts_with("HOST:")) {
            return Ok(Traceroute {
                target: target.to_string(),
                from: server.to_string(),
                reached: false,
                loss_percent: None,
                rtt_ms: None,
                hops,
                status: Some(NO_REPLY_FROM_VM),
                meaning: Some(NO_REPLY_MEANING),
            });
        }
        bail!(
            "looking glass unavailable: no traceroute report for {} in its answer",
            target
        );
    }
    let final_hop = hops
        .last()
        .filter(|h| h.host == target.to_string() || is_vm_hostname(&h.host));
    Ok(Traceroute {
        target: target.to_string(),
        from: server.to_string(),
        reached: final_hop.map(Hop::responded).unwrap_or(false),
        loss_percent: final_hop.map(|h| h.loss_percent),
        rtt_ms: final_hop.filter(|h| h.responded()).and_then(|h| h.rtt_ms),
        hops,
        status: None,
        meaning: None,
    })
}

fn is_vm_hostname(host: &str) -> bool {
    host.starts_with("vm-") && host.ends_with(".lnvps.cloud")
}

/// Parse a single `N.|-- host loss% snt last ...` line.
fn parse_hop(line: &str) -> Option<Hop> {
    let mut fields = line.split_whitespace();
    let index = fields.next()?;
    let hop: u8 = index.strip_suffix(".|--")?.parse().ok()?;
    let host = fields.next()?.to_string();
    // A silent hop still reports 100.0% loss, so loss is always present; the
    // RTT columns are the ones that go missing.
    let loss_percent = fields
        .next()
        .and_then(|f| f.strip_suffix('%'))
        .and_then(|f| f.parse().ok())
        .unwrap_or(100.0);
    let rtt_ms = fields
        .nth(1) // skip Snt, take Last
        .and_then(|f| f.parse().ok());
    Some(Hop {
        hop,
        host,
        loss_percent,
        rtt_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"
	edge1: 185.18.221.87
Start: 2026-08-20T13:55:06+0000
HOST: router        Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0
  2.|-- ???          100.0%     5    0.0   0.0   0.0   0.0   0.0
  3.|-- 185.18.221.87  0.0%     5    0.2   0.2   0.2   0.2   0.0
"#;

    fn target() -> IpAddr {
        "185.18.221.87".parse().unwrap()
    }

    #[test]
    fn parses_report_into_hops() {
        let tr = parse_mtr(REPORT, target(), "edge1").unwrap();
        assert_eq!(tr.hops.len(), 3);
        assert!(tr.reached);
        assert_eq!(tr.rtt_ms, Some(0.2));
        assert_eq!(tr.loss_percent, Some(0.0));
        assert_eq!(tr.hops[0].host, "10.0.0.1");
        assert_eq!(tr.from, "edge1");
    }

    #[test]
    fn silent_hop_is_not_a_response() {
        let tr = parse_mtr(REPORT, target(), "edge1").unwrap();
        assert!(!tr.hops[1].responded());
        assert_eq!(tr.hops[1].loss_percent, 100.0);
        assert!(tr.hops[0].responded());
    }

    /// The path can run to its end without the target ever answering; that is
    /// the "your VM is down" case and must not read as reached.
    #[test]
    fn unreachable_target_reports_not_reached() {
        let report = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- ???          100.0%     5    0.0   0.0   0.0   0.0   0.0\n";
        let tr = parse_mtr(report, target(), "edge1").unwrap();
        assert!(!tr.reached);
        assert_eq!(tr.rtt_ms, None);
    }

    const HEADER_ONLY_PAGE: &str = "<div class=\"container\">\n\t<h2>edge1: 185.18.221.221</h2>\n<pre>Start: 2026-11-19T16:37:07+0000\nHOST: router Loss%   Snt   Last   Avg  Best  Wrst StDev\n</pre>\n\n</div>";

    #[test]
    fn header_only_report_is_no_reply_from_vm() {
        let tr = parse_mtr(&strip_html(HEADER_ONLY_PAGE), target(), "edge1").unwrap();
        assert_eq!(tr.status, Some("no_reply_from_vm"));
        assert!(tr.meaning.unwrap().contains("no reply from this VM"));
        assert!(!tr.reached);
        assert!(tr.hops.is_empty());
    }

    #[tokio::test]
    async fn header_only_answer_is_not_an_unavailable_looking_glass() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(HEADER_ONLY_PAGE))
            .expect(1)
            .mount(&server)
            .await;
        let lg = LookingGlass::new(server.uri(), "edge1");
        let tr = lg.traceroute(target()).await.unwrap();
        assert_eq!(tr.status, Some(NO_REPLY_FROM_VM));
    }

    #[tokio::test]
    async fn http_failure_is_the_only_unavailable_case() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(502))
            .mount(&server)
            .await;
        let err = LookingGlass::new(server.uri(), "edge1")
            .traceroute(target())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("looking glass unavailable"));
    }

    #[test]
    fn empty_output_is_an_error() {
        assert!(parse_mtr("no hops here", target(), "edge1").is_err());
    }

    #[test]
    fn ignores_page_chrome() {
        let page = format!("{REPORT}\nfunction goto() {{ let action = 1.0; }}\n");
        let tr = parse_mtr(&page, target(), "edge1").unwrap();
        assert_eq!(tr.hops.len(), 3);
    }

    #[test]
    fn strip_html_removes_tags_and_entities() {
        assert_eq!(strip_html("<b>a</b> &amp; b"), "a & b");
        assert_eq!(strip_html("<pre>1.|-- x</pre>"), "1.|-- x");
    }

    #[test]
    fn parse_hop_rejects_non_hop_lines() {
        assert!(parse_hop("HOST: router  Loss%  Snt").is_none());
        assert!(parse_hop("Start: 2026-08-20T13:55:06+0000").is_none());
        assert!(parse_hop("").is_none());
    }

    #[test]
    fn client_trims_trailing_slash() {
        let lg = LookingGlass::new("https://lg.example/", "edge1");
        assert_eq!(lg.base_url, "https://lg.example");
        assert_eq!(LookingGlass::default().server, DEFAULT_SERVER);
    }

    #[tokio::test]
    async fn traceroute_parses_served_report() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/traceroute/edge1/185.18.221.87"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("<pre>{REPORT}</pre>")),
            )
            .mount(&server)
            .await;

        let lg = LookingGlass::new(server.uri(), "edge1");
        let tr = lg.traceroute(target()).await.unwrap();
        assert!(tr.reached);
        assert_eq!(tr.hops.len(), 3);
    }

    #[tokio::test]
    async fn traceroute_surfaces_http_errors() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(502))
            .mount(&server)
            .await;
        let lg = LookingGlass::new(server.uri(), "edge1");
        assert!(lg.traceroute(target()).await.is_err());
    }

    #[test]
    fn a_hop_with_total_loss_is_not_a_response() {
        let report = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- vm-1.lnvps.cloud 100.0%     5    1.0   1.0   1.0   1.0   0.0\n";
        let tr = parse_mtr(report, target(), "edge1").unwrap();
        assert!(!tr.hops[1].responded());
        assert!(!tr.reached);
    }

    #[test]
    fn a_vm_hostname_as_final_hop_is_the_target() {
        let report = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- vm-1.lnvps.cloud  0.0%     5    0.3   0.3   0.3   0.3   0.0\n";
        let tr = parse_mtr(report, target(), "edge1").unwrap();
        assert!(tr.reached);
        assert_eq!(tr.rtt_ms, Some(0.3));
    }

    #[test]
    fn a_transit_router_name_is_not_the_target() {
        let report = "  1.|-- 10.0.0.1       0.0%     5    0.4   0.5   0.4   0.6   0.0\n  2.|-- core.example.net  0.0%     5    0.3   0.3   0.3   0.3   0.0\n";
        assert!(!parse_mtr(report, target(), "edge1").unwrap().reached);
    }

    #[tokio::test]
    async fn traceroute_retries_once_when_the_first_answer_is_empty() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("<pre></pre>"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("<pre>{REPORT}</pre>")),
            )
            .mount(&server)
            .await;
        let lg = LookingGlass::new(server.uri(), "edge1");
        assert!(lg.traceroute(target()).await.unwrap().reached);
    }
}
