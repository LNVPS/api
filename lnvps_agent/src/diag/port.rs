//! TCP reachability check for a customer's own VM.
//!
//! The looking glass cannot do this — its proxy only permits BIRD `show`
//! queries plus ping/traceroute — so the connect is made from this process.
//! That vantage point is stated in the result: a success here proves the VM is
//! listening and reachable *from the LNVPS network*, which is not the same
//! claim as reachable from the public internet (return-path and scrubbing
//! problems live upstream of us — see the asymmetric-return trap where ICMP
//! passes cleanly while every TCP connect times out). Saying where the probe
//! ran from is what stops the model turning "port open" into a guarantee.
//!
//! Only a connect is attempted: no banner is read, nothing is sent. The
//! address always comes from an ownership-checked VM assignment, never from
//! the model.

use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// A slow handshake is a useful answer, an indefinite hang is not.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a single TCP connect attempt.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PortCheck {
    pub target: String,
    pub port: u16,
    /// True when the handshake completed.
    pub open: bool,
    /// How the attempt ended: `open`, `timeout`, `refused`, or the OS error.
    pub result: String,
    pub elapsed_ms: u64,
    /// Where the probe ran from, so the result is not over-read.
    pub probed_from: &'static str,
    pub meaning: &'static str,
}

fn meaning_of(open: bool, result: &str) -> &'static str {
    if open {
        "A service accepted the connection. If the customer still cannot connect, the problem is on their side of the path or in their own firewall."
    } else if result.starts_with("refused") {
        "The VM is up and answering, but nothing listens on this port. Check the service and the port it is configured to use."
    } else if result.starts_with("timeout") {
        "No answer. Either a firewall drops the port or the VM is not answering at all. Check list_vm_firewall_rules and scan_vm_ports before concluding it is down."
    } else {
        "The edge could not reach the VM's address at layer 2 or 3. Other ports may still be reachable, so scan_vm_ports before concluding the VM is down; a stopped or unconfigured VM looks the same."
    }
}

/// Attempt a TCP connect to `ip:port`.
///
/// Never returns `Err`: a refused or timed-out connect is the diagnostic
/// answer, not a tool failure, and surfacing it as an error would make the
/// model report a broken tool instead of a closed port.
pub async fn check_port(ip: IpAddr, port: u16) -> PortCheck {
    let started = Instant::now();
    let addr = SocketAddr::new(ip, port);
    let outcome = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
    let (open, result) = match outcome {
        Ok(Ok(_)) => (true, "open".to_string()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            // Refused means something answered: the host is up and nothing is
            // listening, which is a different fix from a filtered port.
            (
                false,
                "refused (host reachable, nothing listening)".to_string(),
            )
        }
        Ok(Err(e)) => (false, e.to_string()),
        Err(_) => (
            false,
            format!(
                "timeout after {}s (filtered or host down)",
                CONNECT_TIMEOUT.as_secs()
            ),
        ),
    };
    let meaning = meaning_of(open, &result);
    PortCheck {
        target: ip.to_string(),
        port,
        open,
        meaning,
        result,
        elapsed_ms: started.elapsed().as_millis() as u64,
        probed_from: "the LNVPS network (not the public internet)",
    }
}

pub const MAX_SCAN_PORTS: usize = 1024;
const SCAN_CONCURRENCY: usize = 128;
const SCAN_TIMEOUT: Duration = Duration::from_secs(2);

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2222, 3000, 3306, 5432, 8000, 8080,
    8443, 9000, 19009,
];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PortScan {
    pub target: String,
    pub scanned: usize,
    pub open_ports: Vec<u16>,
    pub refused: usize,
    pub unanswered: usize,
    pub probed_from: &'static str,
    pub meaning: &'static str,
}

pub async fn scan_ports(ip: IpAddr, ports: &[u16]) -> PortScan {
    use futures::StreamExt;
    let outcomes: Vec<(u16, Option<bool>)> = futures::stream::iter(ports.iter().copied())
        .map(|port| async move {
            let addr = SocketAddr::new(ip, port);
            let outcome = tokio::time::timeout(SCAN_TIMEOUT, TcpStream::connect(addr)).await;
            let state = match outcome {
                Ok(Ok(_)) => Some(true),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(false),
                _ => None,
            };
            (port, state)
        })
        .buffer_unordered(SCAN_CONCURRENCY)
        .collect()
        .await;
    let mut open_ports: Vec<u16> = outcomes
        .iter()
        .filter(|(_, s)| *s == Some(true))
        .map(|(p, _)| *p)
        .collect();
    open_ports.sort_unstable();
    let refused = outcomes.iter().filter(|(_, s)| *s == Some(false)).count();
    let unanswered = outcomes.iter().filter(|(_, s)| s.is_none()).count();
    let meaning = if !open_ports.is_empty() {
        "These ports accept connections. If the customer expected a different port, the service is listening elsewhere than they think, for example sshd moved off port 22."
    } else if refused > 0 {
        "The VM answers but none of the scanned ports has a listener. The service may use a port outside the scanned set."
    } else {
        "No scanned port answered. The VM is down, not configured, or a firewall drops everything."
    };
    PortScan {
        target: ip.to_string(),
        scanned: ports.len(),
        open_ports,
        refused,
        unanswered,
        probed_from: "the LNVPS network (not the public internet)",
        meaning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn reports_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let check = check_port(addr.ip(), addr.port()).await;
        assert!(check.open);
        assert_eq!(check.result, "open");
        assert_eq!(check.port, addr.port());
    }

    /// A closed port must come back as a normal result, not an error, or the
    /// model will report the tool as broken.
    #[tokio::test]
    async fn reports_closed_port_without_erroring() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let check = check_port(addr.ip(), addr.port()).await;
        assert!(!check.open);
        assert!(check.result.contains("refused") || check.result.contains("timeout"));
    }

    #[test]
    fn every_outcome_carries_an_interpretation() {
        assert!(meaning_of(true, "open").contains("accepted"));
        assert!(meaning_of(false, "refused (host reachable, nothing listening)").contains("nothing listens"));
        assert!(meaning_of(false, "timeout after 5s (filtered or host down)").contains("scan_vm_ports"));
        assert!(meaning_of(false, "No route to host (os error 113)").contains("scan_vm_ports"));
    }

    #[tokio::test]
    async fn scan_finds_a_listener_on_a_non_standard_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let scan = scan_ports("127.0.0.1".parse().unwrap(), &[open, closed]).await;
        assert_eq!(scan.open_ports, vec![open]);
        assert_eq!(scan.refused, 1);
        assert_eq!(scan.scanned, 2);
        assert!(scan.meaning.contains("listening elsewhere"));
    }

    #[tokio::test]
    async fn scan_with_nothing_listening_says_so() {
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let scan = scan_ports("127.0.0.1".parse().unwrap(), &[closed]).await;
        assert!(scan.open_ports.is_empty());
        assert!(scan.meaning.contains("none of the scanned ports"));
    }

    #[tokio::test]
    async fn result_states_the_vantage_point() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let check = check_port(addr.ip(), addr.port()).await;
        assert!(check.probed_from.contains("not the public internet"));
    }
}
