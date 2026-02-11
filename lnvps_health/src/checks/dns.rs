use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use log::debug;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::{CheckResult, HealthCheck};

/// Configuration for a DNS check
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCheckConfig {
    /// Human-readable name for this check
    pub name: String,
    /// DNS server to query via IPv4 (IP address)
    pub server: Option<String>,
    /// DNS server to query via IPv6 (IP address)
    pub server_v6: Option<String>,
    /// Domain to resolve
    pub query: String,
    /// Expected IP addresses (optional - if empty, just checks resolution works)
    #[serde(default)]
    pub expected_ips: Vec<String>,
    /// Query timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    5
}

#[derive(Debug, Clone, Copy)]
pub enum DnsAddrFamily {
    V4,
    V6,
}

/// DNS health check - verifies DNS resolution works correctly
pub struct DnsCheck {
    config: DnsCheckConfig,
    addr_family: DnsAddrFamily,
}

impl DnsCheck {
    pub fn new(config: DnsCheckConfig, addr_family: DnsAddrFamily) -> Self {
        Self {
            config,
            addr_family,
        }
    }

    /// Create checks for both IPv4 and IPv6 from a single config
    pub fn from_config(config: DnsCheckConfig) -> Vec<Box<dyn HealthCheck>> {
        let mut checks: Vec<Box<dyn HealthCheck>> = Vec::new();

        if config.server.is_some() {
            checks.push(Box::new(DnsCheck::new(config.clone(), DnsAddrFamily::V4)));
        }
        if config.server_v6.is_some() {
            checks.push(Box::new(DnsCheck::new(config, DnsAddrFamily::V6)));
        }

        checks
    }

    fn server_addr(&self) -> Option<&str> {
        match self.addr_family {
            DnsAddrFamily::V4 => self.config.server.as_deref(),
            DnsAddrFamily::V6 => self.config.server_v6.as_deref(),
        }
    }

    fn family_suffix(&self) -> &'static str {
        match self.addr_family {
            DnsAddrFamily::V4 => "v4",
            DnsAddrFamily::V6 => "v6",
        }
    }

    fn create_resolver(&self, server_ip: IpAddr) -> Result<Resolver<TokioConnectionProvider>> {
        let name_servers = NameServerConfigGroup::from_ips_clear(&[server_ip], 53, true);
        let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(self.config.timeout_secs);
        opts.attempts = 2;

        let mut builder = Resolver::builder_with_config(
            resolver_config,
            TokioConnectionProvider::default(),
        );
        *builder.options_mut() = opts;
        Ok(builder.build())
    }
}

#[async_trait]
impl HealthCheck for DnsCheck {
    async fn check(&self) -> Result<CheckResult> {
        let name = format!("{} ({})", self.config.name, self.family_suffix());
        let query = &self.config.query;

        let server_str = match self.server_addr() {
            Some(s) => s,
            None => {
                return Ok(CheckResult::ok(
                    &name,
                    format!("Skipped: no {} server configured", self.family_suffix()),
                ));
            }
        };

        let server_ip: IpAddr = server_str
            .parse()
            .context("Invalid DNS server IP")?;

        let resolver = self.create_resolver(server_ip)?;

        debug!("Querying {} via {} ({})", query, server_str, self.family_suffix());

        let start = Instant::now();
        let lookup = match resolver.lookup_ip(query.as_str()).await {
            Ok(lookup) => lookup,
            Err(e) => {
                return Ok(CheckResult::fail(
                    &name,
                    format!("DNS lookup failed: {}", e),
                )
                .with_details(format!(
                    "Server: {} ({})\nQuery: {}\nError: {}",
                    server_str,
                    self.family_suffix(),
                    query,
                    e
                )));
            }
        };
        let latency = start.elapsed();

        let resolved_ips: Vec<IpAddr> = lookup.iter().collect();

        if resolved_ips.is_empty() {
            return Ok(CheckResult::fail(&name, "DNS lookup returned no results")
                .with_details(format!(
                    "Server: {} ({})\nQuery: {}",
                    server_str,
                    self.family_suffix(),
                    query
                )));
        }

        // If expected IPs are configured, verify them
        if !self.config.expected_ips.is_empty() {
            let expected: Vec<IpAddr> = self
                .config
                .expected_ips
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            let all_match = expected.iter().all(|exp| resolved_ips.contains(exp));

            if !all_match {
                let resolved_str: Vec<String> =
                    resolved_ips.iter().map(|ip| ip.to_string()).collect();
                return Ok(CheckResult::fail(
                    &name,
                    format!(
                        "DNS mismatch: got [{}], expected [{}]",
                        resolved_str.join(", "),
                        self.config.expected_ips.join(", ")
                    ),
                )
                .with_details(format!(
                    "Server: {} ({})\nQuery: {}",
                    server_str,
                    self.family_suffix(),
                    query
                )));
            }
        }

        let resolved_str: Vec<String> = resolved_ips.iter().map(|ip| ip.to_string()).collect();
        Ok(CheckResult::ok(
            &name,
            format!(
                "DNS OK: {} -> [{}] via {} ({:.1}ms)",
                query,
                resolved_str.join(", "),
                server_str,
                latency.as_secs_f64() * 1000.0
            ),
        )
        .with_metric(latency.as_secs_f64()))
    }

    fn id(&self) -> String {
        let server = self.server_addr().unwrap_or("none");
        format!("dns:{}:{}:{}", server, self.config.query, self.family_suffix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_check_google_v4() {
        let config = DnsCheckConfig {
            name: "Google DNS Test".to_string(),
            server: Some("8.8.8.8".to_string()),
            server_v6: None,
            query: "google.com".to_string(),
            expected_ips: vec![],
            timeout_secs: 5,
        };

        let check = DnsCheck::new(config, DnsAddrFamily::V4);
        match check.check().await {
            Ok(result) => {
                println!("Check result: {:?}", result);
                assert!(result.passed, "Expected check to pass: {}", result.message);
            }
            Err(e) => {
                println!("Check failed (may be expected in some environments): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_dns_check_google_v6() {
        let config = DnsCheckConfig {
            name: "Google DNS Test".to_string(),
            server: None,
            server_v6: Some("2001:4860:4860::8888".to_string()),
            query: "google.com".to_string(),
            expected_ips: vec![],
            timeout_secs: 5,
        };

        let check = DnsCheck::new(config, DnsAddrFamily::V6);
        match check.check().await {
            Ok(result) => {
                println!("Check result: {:?}", result);
                // May fail if no IPv6 connectivity
                assert!(result.passed, "Expected check to pass: {}", result.message);
            }
            Err(e) => {
                println!("Check failed (may be expected in some environments): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_dns_check_dual_stack() {
        let config = DnsCheckConfig {
            name: "Cloudflare DNS".to_string(),
            server: Some("1.1.1.1".to_string()),
            server_v6: Some("2606:4700:4700::1111".to_string()),
            query: "one.one.one.one".to_string(),
            expected_ips: vec!["1.1.1.1".to_string()],
            timeout_secs: 5,
        };

        let checks = DnsCheck::from_config(config);
        assert_eq!(checks.len(), 2, "Should create 2 checks for dual-stack config");

        for check in checks {
            match check.check().await {
                Ok(result) => {
                    println!("Check result: {:?}", result);
                }
                Err(e) => {
                    println!("Check failed: {}", e);
                }
            }
        }
    }
}
