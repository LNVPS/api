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

        // Calculate max MSS allowed by PMTU (PMTU - IP header - TCP header)
        // IPv4: 20 + 20 = 40 bytes, IPv6: 40 + 20 = 60 bytes
        let header_overhead: u16 = match self.addr_family {
            AddrFamily::V4 => 40,
            AddrFamily::V6 => 60,
        };
        let max_mss_from_pmtu = result.pmtu.map(|p| p.saturating_sub(header_overhead));

        // Check if MSS exceeds what PMTU allows
        let mss_exceeds_pmtu = match (result.mss, max_mss_from_pmtu) {
            (Some(mss), Some(max_mss)) => mss > max_mss,
            _ => false,
        };

        let pmtu_info = result
            .pmtu
            .map(|p| format!(", PMTU: {}", p))
            .unwrap_or_default();

        match result.mss {
            Some(mss) if mss_exceeds_pmtu => {
                let max_mss = max_mss_from_pmtu.unwrap();
                let mut check_result = CheckResult::fail(
                    &name,
                    format!(
                        "MSS {} exceeds PMTU limit {} (PMTU: {}) [{}]",
                        mss, max_mss, result.pmtu.unwrap(), result.target
                    ),
                )
                .with_details(format!(
                    "Target: {}:{} ({})\nMSS: {} bytes\nPMTU: {} bytes\nMax MSS for PMTU: {} bytes\n\n\
                     The negotiated MSS is larger than what the path MTU allows.\n\
                     This will cause packet fragmentation or drops.",
                    host, port, result.target, mss, result.pmtu.unwrap(), max_mss
                ))
                .with_metric(mss as f64);
                if let Some(pmtu) = result.pmtu {
                    check_result = check_result.with_pmtu(pmtu as f64);
                }
                Ok(check_result)
            }
            Some(mss) if mss >= expected_mss => {
                let mut check_result = CheckResult::ok(
                    &name,
                    format!(
                        "MSS OK: {} bytes (expected >= {}){} [{}]",
                        mss, expected_mss, pmtu_info, result.target
                    ),
                )
                .with_metric(mss as f64);
                if let Some(pmtu) = result.pmtu {
                    check_result = check_result.with_pmtu(pmtu as f64);
                }
                Ok(check_result)
            }
            Some(mss) => {
                let mut check_result = CheckResult::fail(
                    &name,
                    format!(
                        "MSS too low: {} bytes (expected >= {}){} [{}]",
                        mss, expected_mss, pmtu_info, result.target
                    ),
                )
                .with_details(format!(
                    "Target: {}:{} ({})\nMSS: {} bytes{}\n\
                     This may cause connectivity issues for customers.\n\
                     Consider checking MTU settings on the network path.",
                    host, port, result.target, mss, pmtu_info
                ))
                .with_metric(mss as f64);
                if let Some(pmtu) = result.pmtu {
                    check_result = check_result.with_pmtu(pmtu as f64);
                }
                Ok(check_result)
            }
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
    pmtu: Option<u16>,
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

    // Enable PMTU discovery
    let is_v6 = target.is_ipv6();
    if is_v6 {
        let val: i32 = libc::IPV6_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    } else {
        let val: i32 = libc::IP_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
    }

    socket
        .connect_timeout(&target.into(), timeout)
        .context("Connection failed")?;

    let mss = get_tcp_mss(socket.as_raw_fd())?;
    let pmtu = get_ip_mtu(socket.as_raw_fd(), is_v6)?;

    let _ = socket.shutdown(std::net::Shutdown::Both);

    Ok(MssProbeResult { mss, pmtu, target })
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

/// Get the path MTU from a connected socket
fn get_ip_mtu(fd: i32, is_v6: bool) -> Result<Option<u16>> {
    const IP_MTU: i32 = 14;
    const IPV6_MTU: i32 = 24;

    let mut mtu: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    let (level, optname) = if is_v6 {
        (libc::IPPROTO_IPV6, IPV6_MTU)
    } else {
        (libc::IPPROTO_IP, IP_MTU)
    };

    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut mtu as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 && mtu > 0 {
        debug!("IP_MTU returned: {}", mtu);
        Ok(Some(mtu as u16))
    } else if result == 0 {
        debug!("IP_MTU returned 0");
        Ok(None)
    } else {
        let err = std::io::Error::last_os_error();
        debug!("getsockopt(IP_MTU) failed: {}", err);
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
