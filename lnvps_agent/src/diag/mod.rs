//! Customer-facing diagnostics: network probes and published policy documents.
//!
//! Two hard rules govern everything here, because these tools sit behind a
//! model that a customer can talk to directly:
//!
//! 1. **No free-form targets.** Every probe takes a VM id; the caller resolves
//!    the address from that VM's own assignment records after an ownership
//!    check. Accepting a hostname from the model would turn support chat into
//!    an open ping/port-scan relay for anyone who can type into it, and a
//!    prompt injection is enough to aim it.
//! 2. **No privileged vantage point.** The traceroute runs on the public
//!    looking glass, which anyone can drive from a browser, so the tool
//!    exposes nothing that was not already public.
//!
//! ICMP is not sent from this process. A raw socket needs `CAP_NET_RAW`, and
//! probing from wherever the agent happens to run answers the wrong question
//! anyway — the customer wants to know whether *the internet* reaches their
//! VM, and the interesting failures (the AVS/GSL scrubbing path) sit upstream
//! of the API network. The looking glass sits at the network edge, so it
//! answers the question the customer actually asked.

pub mod lg;
pub mod policy;
pub mod port;

use anyhow::{Result, bail};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::Arc;

pub use lg::{Hop, LookingGlass, Traceroute};
pub use policy::PolicyDocs;
pub use port::{PortCheck, check_port};

/// Diagnostics shared by every tool executor.
///
/// Holds the looking-glass and policy clients so their connection pools and
/// the policy cache are reused across a conversation instead of being rebuilt
/// per tool call.
#[derive(Debug, Default)]
pub struct Diagnostics {
    lg: LookingGlass,
    policy: PolicyDocs,
}

/// Condensed reachability answer, derived from the traceroute.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Reachability {
    pub target: String,
    pub from: String,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f32>,
    /// Where the path stopped answering, when the target did not reply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_responding_hop: Option<String>,
}

impl Diagnostics {
    /// Build diagnostics against specific endpoints.
    ///
    /// [`Default`] targets the production looking glass and website; this is
    /// the seam for tests and for pointing a staging deployment elsewhere.
    pub fn new(lg: LookingGlass, policy: PolicyDocs) -> Self {
        Self { lg, policy }
    }

    /// Trace the path from the edge router to one of `ips`.
    pub async fn traceroute(&self, ips: &[String], prefer_v6: bool) -> Result<Traceroute> {
        self.lg.traceroute(select_target(ips, prefer_v6)?).await
    }

    /// Reachability only, without the hop list.
    ///
    /// Same probe as [`Self::traceroute`] because the looking glass exposes no
    /// ping endpoint; the hops are dropped so a simple "is it up?" question
    /// does not spend context on a full path.
    pub async fn ping(&self, ips: &[String], prefer_v6: bool) -> Result<Reachability> {
        Ok(summarise(self.traceroute(ips, prefer_v6).await?))
    }

    /// TCP connect test against one of `ips`.
    pub async fn check_port(
        &self,
        ips: &[String],
        prefer_v6: bool,
        port: u64,
    ) -> Result<PortCheck> {
        let port = u16::try_from(port)
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| anyhow::anyhow!("port must be between 1 and 65535"))?;
        Ok(port::check_port(select_target(ips, prefer_v6)?, port).await)
    }

    /// The published Terms of Service / Acceptable Use text.
    pub async fn terms_of_service(&self) -> Result<Arc<str>> {
        self.policy.terms_of_service().await
    }
}

/// Pick the address to probe from a VM's assigned IPs.
///
/// Assignments are stored as bare addresses in some code paths and as
/// `addr/prefix` in others, so the prefix is stripped before parsing rather
/// than assuming either shape. `prefer_v6` selects the family when the VM has
/// both; otherwise the first parsable address of any family wins, so a
/// v6-only VM is still diagnosable.
pub fn select_target(ips: &[String], prefer_v6: bool) -> Result<IpAddr> {
    let parsed: Vec<IpAddr> = ips.iter().filter_map(|ip| parse_assignment(ip)).collect();
    if parsed.is_empty() {
        bail!("VM has no usable IP address assigned — it may not be provisioned yet");
    }
    let wanted = parsed
        .iter()
        .find(|ip| ip.is_ipv6() == prefer_v6)
        .or_else(|| parsed.first());
    Ok(*wanted.expect("non-empty"))
}

/// Reduce a traceroute to a reachability answer, naming the last hop that
/// answered when the target did not — that hop is where the operator looks.
fn summarise(trace: Traceroute) -> Reachability {
    let last_responding_hop = if trace.reached {
        None
    } else {
        trace
            .hops
            .iter()
            .rev()
            .find(|h| h.responded())
            .map(|h| format!("hop {} ({})", h.hop, h.host))
    };
    Reachability {
        target: trace.target,
        from: trace.from,
        reachable: trace.reached,
        loss_percent: trace.loss_percent,
        rtt_ms: trace.rtt_ms,
        last_responding_hop,
    }
}

/// Parse one assignment string, tolerating a `/prefix` suffix.
fn parse_assignment(value: &str) -> Option<IpAddr> {
    let trimmed = value.trim();
    let addr = trimmed.split('/').next().unwrap_or(trimmed);
    addr.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_and_cidr_assignments() {
        assert_eq!(
            parse_assignment("185.18.221.87"),
            Some("185.18.221.87".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_assignment(" 185.18.221.87/24 "),
            Some("185.18.221.87".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_assignment("2a13:aac0::1/64"),
            Some("2a13:aac0::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parse_assignment("not-an-ip"), None);
    }

    #[test]
    fn select_target_prefers_requested_family() {
        let ips = vec!["2a13:aac0::1".to_string(), "185.18.221.87".to_string()];
        assert!(select_target(&ips, false).unwrap().is_ipv4());
        assert!(select_target(&ips, true).unwrap().is_ipv6());
    }

    /// A v6-only VM must still be diagnosable when v4 was requested.
    #[test]
    fn select_target_falls_back_to_other_family() {
        let ips = vec!["2a13:aac0::1".to_string()];
        assert!(select_target(&ips, false).unwrap().is_ipv6());
    }

    #[test]
    fn select_target_errors_without_usable_ip() {
        assert!(select_target(&[], false).is_err());
        assert!(select_target(&["pending".to_string()], false).is_err());
    }

    /// Port validation happens before any network call, so a bad port is a
    /// clear error rather than a connect to port 0.
    #[tokio::test]
    async fn check_port_rejects_out_of_range_ports() {
        let diag = Diagnostics::default();
        let ips = vec!["127.0.0.1".to_string()];
        assert!(diag.check_port(&ips, false, 0).await.is_err());
        assert!(diag.check_port(&ips, false, 70_000).await.is_err());
    }

    fn trace(reached: bool) -> Traceroute {
        Traceroute {
            target: "185.18.221.87".to_string(),
            from: "edge1".to_string(),
            reached,
            loss_percent: reached.then_some(0.0),
            rtt_ms: reached.then_some(0.2),
            hops: vec![
                Hop {
                    hop: 1,
                    host: "10.0.0.1".to_string(),
                    loss_percent: 0.0,
                    rtt_ms: Some(0.4),
                },
                Hop {
                    hop: 2,
                    host: "???".to_string(),
                    loss_percent: 100.0,
                    rtt_ms: None,
                },
            ],
        }
    }

    #[test]
    fn summarise_points_at_the_last_live_hop_when_unreachable() {
        let summary = summarise(trace(false));
        assert!(!summary.reachable);
        assert_eq!(
            summary.last_responding_hop.as_deref(),
            Some("hop 1 (10.0.0.1)")
        );
    }

    #[test]
    fn summarise_omits_the_hop_pointer_when_reachable() {
        let summary = summarise(trace(true));
        assert!(summary.reachable);
        assert_eq!(summary.last_responding_hop, None);
        assert_eq!(summary.rtt_ms, Some(0.2));
    }

    /// End-to-end through the client layer: a served mtr report becomes both a
    /// full traceroute and a condensed reachability answer.
    #[tokio::test]
    async fn probes_run_against_the_configured_looking_glass() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/traceroute/edge1/127.0.0.1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string(
                    "<pre>  1.|-- 127.0.0.1  0.0%  5  0.2  0.2  0.2  0.2  0.0</pre>",
                ),
            )
            .mount(&server)
            .await;

        let diag = Diagnostics::new(
            LookingGlass::new(server.uri(), "edge1"),
            PolicyDocs::new(server.uri()),
        );
        let ips = vec!["127.0.0.1".to_string()];
        assert!(diag.traceroute(&ips, false).await.unwrap().reached);
        let summary = diag.ping(&ips, false).await.unwrap();
        assert!(summary.reachable);
        assert_eq!(summary.rtt_ms, Some(0.2));
    }

    #[tokio::test]
    async fn terms_of_service_reads_the_configured_site() {
        let server = wiremock::MockServer::start().await;
        let body = format!(
            "<body><h1>Terms</h1><p>{}</p></body>",
            "policy text. ".repeat(60)
        );
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/tos"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let diag = Diagnostics::new(LookingGlass::default(), PolicyDocs::new(server.uri()));
        assert!(diag.terms_of_service().await.unwrap().contains("Terms"));
    }

    /// A live port is reported open through the same entry point the tools use.
    #[tokio::test]
    async fn check_port_reports_a_listening_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let check = Diagnostics::default()
            .check_port(&[addr.ip().to_string()], false, addr.port() as u64)
            .await
            .unwrap();
        assert!(check.open);
    }

    #[tokio::test]
    async fn probes_fail_before_the_network_when_no_ip_is_assigned() {
        let diag = Diagnostics::default();
        assert!(diag.check_port(&[], false, 22).await.is_err());
        assert!(diag.traceroute(&[], false).await.is_err());
        assert!(diag.ping(&[], false).await.is_err());
    }
}
