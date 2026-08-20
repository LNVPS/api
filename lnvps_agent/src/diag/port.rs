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
    PortCheck {
        target: ip.to_string(),
        port,
        open,
        result,
        elapsed_ms: started.elapsed().as_millis() as u64,
        probed_from: "the LNVPS network (not the public internet)",
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

    #[tokio::test]
    async fn result_states_the_vantage_point() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let check = check_port(addr.ip(), addr.port()).await;
        assert!(check.probed_from.contains("not the public internet"));
    }
}
