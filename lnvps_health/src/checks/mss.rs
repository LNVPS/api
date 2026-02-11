use anyhow::{Context, Result};
use async_trait::async_trait;
use log::debug;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

use super::{CheckResult, HealthCheck};

/// Configuration for an MSS probe target
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MssCheckConfig {
    /// Human-readable name for this target
    pub name: String,
    /// Target address (IP or hostname)
    pub host: String,
    /// Target port
    pub port: u16,
    /// Expected minimum MSS for IPv4 (default: 1460 for standard ethernet)
    #[serde(default = "default_expected_mss")]
    pub expected_mss: u16,
    /// Expected minimum MSS for IPv6 (default: 1440, 20 bytes less than IPv4 due to larger header)
    #[serde(default = "default_expected_mss_v6")]
    pub expected_mss_v6: Option<u16>,
}

fn default_expected_mss() -> u16 {
    1460
}

fn default_expected_mss_v6() -> Option<u16> {
    None // Will use expected_mss - 20 if not specified
}

/// MSS health check - verifies TCP MSS is at expected levels for both IPv4 and IPv6
pub struct MssCheck {
    config: MssCheckConfig,
    addr_family: AddrFamily,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub enum AddrFamily {
    V4,
    V6,
}

impl MssCheck {
    pub fn new(config: MssCheckConfig, addr_family: AddrFamily) -> Self {
        Self {
            config,
            addr_family,
            timeout: Duration::from_secs(10),
        }
    }

    /// Create checks for both IPv4 and IPv6 from a single config
    pub fn from_config(config: MssCheckConfig) -> Vec<Box<dyn HealthCheck>> {
        vec![
            Box::new(MssCheck::new(config.clone(), AddrFamily::V4)),
            Box::new(MssCheck::new(config, AddrFamily::V6)),
        ]
    }

    async fn resolve_target(&self) -> Result<Option<SocketAddr>> {
        let addrs: Vec<SocketAddr> =
            tokio::net::lookup_host(format!("{}:{}", self.config.host, self.config.port))
                .await
                .context("DNS lookup failed")?
                .collect();

        let addr = match self.addr_family {
            AddrFamily::V4 => addrs.iter().find(|a| a.is_ipv4()).copied(),
            AddrFamily::V6 => addrs.iter().find(|a| a.is_ipv6()).copied(),
        };

        Ok(addr)
    }

    fn expected_mss(&self) -> u16 {
        match self.addr_family {
            AddrFamily::V4 => self.config.expected_mss,
            AddrFamily::V6 => {
                // IPv6 header is 20 bytes larger than IPv4, so MSS is typically 20 bytes less
                self.config
                    .expected_mss_v6
                    .unwrap_or_else(|| self.config.expected_mss.saturating_sub(20))
            }
        }
    }

    fn family_suffix(&self) -> &'static str {
        match self.addr_family {
            AddrFamily::V4 => "v4",
            AddrFamily::V6 => "v6",
        }
    }
}

#[async_trait]
impl HealthCheck for MssCheck {
    async fn check(&self) -> Result<CheckResult> {
        let name = format!("{} ({})", self.config.name, self.family_suffix());
        let expected_mss = self.expected_mss();

        let addr = match self.resolve_target().await? {
            Some(addr) => addr,
            None => {
                // No address of this family - skip check (not a failure)
                debug!(
                    "No {} address found for {}, skipping",
                    self.family_suffix(),
                    self.config.host
                );
                return Ok(CheckResult::ok(
                    &name,
                    format!("Skipped: no {} address", self.family_suffix()),
                ));
            }
        };

        let timeout = self.timeout;
        let host = self.config.host.clone();
        let port = self.config.port;

        let result = tokio::task::spawn_blocking(move || probe_mss(addr, timeout))
            .await
            .context("Probe task panicked")??;

        match result.mss {
            Some(mss) if mss >= expected_mss => Ok(CheckResult::ok(
                &name,
                format!(
                    "MSS OK: {} bytes (expected >= {}) [{}]",
                    mss,
                    expected_mss,
                    result.target
                ),
            )),
            Some(mss) => Ok(CheckResult::fail(
                &name,
                format!(
                    "MSS too low: {} bytes (expected >= {}) [{}]",
                    mss, expected_mss, result.target
                ),
            )
            .with_details(format!(
                "Target: {}:{} ({})\nThis may cause connectivity issues for customers.\n\
                 Consider checking MTU settings on the network path.",
                host, port, result.target
            ))),
            None => Ok(CheckResult::fail(
                &name,
                "Could not determine MSS (connection succeeded but no MSS info)".to_string(),
            )),
        }
    }

    fn id(&self) -> String {
        format!(
            "mss:{}:{}:{}",
            self.config.host,
            self.config.port,
            self.family_suffix()
        )
    }
}

/// Result of an MSS probe
#[derive(Debug, Clone)]
struct MssProbeResult {
    mss: Option<u16>,
    target: SocketAddr,
}

fn probe_mss(target: SocketAddr, timeout: Duration) -> Result<MssProbeResult> {
    let domain = if target.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("Failed to create socket")?;

    socket
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("Failed to set write timeout")?;

    socket
        .connect_timeout(&target.into(), timeout)
        .context("Connection failed")?;

    let mss = get_tcp_mss(socket.as_raw_fd())?;

    let _ = socket.shutdown(std::net::Shutdown::Both);

    Ok(MssProbeResult { mss, target })
}

/// Get the TCP MSS value from a connected socket
fn get_tcp_mss(fd: i32) -> Result<Option<u16>> {
    const TCP_MAXSEG: i32 = 2;

    let mut mss: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_MAXSEG,
            &mut mss as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 && mss > 0 {
        debug!("TCP_MAXSEG returned: {}", mss);
        Ok(Some(mss as u16))
    } else if result == 0 {
        debug!("TCP_MAXSEG returned 0");
        Ok(None)
    } else {
        let err = std::io::Error::last_os_error();
        debug!("getsockopt(TCP_MAXSEG) failed: {}", err);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mss_check_google_v4() {
        let config = MssCheckConfig {
            name: "Google DNS".to_string(),
            host: "8.8.8.8".to_string(),
            port: 443,
            expected_mss: 1000,
            expected_mss_v6: None,
        };

        let check = MssCheck::new(config, AddrFamily::V4);
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
    async fn test_mss_check_google_v6() {
        let config = MssCheckConfig {
            name: "Google".to_string(),
            host: "google.com".to_string(),
            port: 443,
            expected_mss: 1000,
            expected_mss_v6: Some(980),
        };

        let check = MssCheck::new(config, AddrFamily::V6);
        match check.check().await {
            Ok(result) => {
                println!("Check result: {:?}", result);
                // May be skipped if no IPv6 connectivity
                assert!(
                    result.passed,
                    "Expected check to pass or skip: {}",
                    result.message
                );
            }
            Err(e) => {
                println!("Check failed (may be expected in some environments): {}", e);
            }
        }
    }
}
