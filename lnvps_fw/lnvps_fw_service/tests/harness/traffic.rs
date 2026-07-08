//! Traffic generators that run inside a chosen network namespace.
//!
//! Each generator runs on a dedicated thread that first `setns`es into the
//! target namespace (network namespaces are a per-thread property on Linux),
//! so the main test thread's namespace is left untouched. Standard-library
//! sockets are used for UDP/TCP; a small raw-socket sender crafts TCP SYNs
//! for flood tests.

use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::time::Duration;

use nix::sched::{CloneFlags, setns};

/// Run `f` on a thread pinned into the network namespace at `ns_path`
/// (e.g. `/var/run/netns/<name>`), returning its result. The calling
/// thread's namespace is unaffected.
pub fn in_netns<F, R>(ns_path: &str, f: F) -> io::Result<R>
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    let path = ns_path.to_string();
    std::thread::scope(|s| {
        s.spawn(move || {
            let file = File::open(&path)?;
            setns(file.as_fd(), CloneFlags::CLONE_NEWNET)
                .map_err(|e| io::Error::other(format!("setns({path}): {e}")))?;
            Ok::<R, io::Error>(f())
        })
        .join()
        .map_err(|_| io::Error::other("netns worker thread panicked"))?
    })
}

/// Bind a UDP socket in `ns_path` to `bind`, wait up to `timeout` for a single
/// datagram, and return the received bytes (or `None` on timeout). Runs the
/// blocking recv on the pinned thread.
pub fn udp_recv_once(
    ns_path: &str,
    bind: SocketAddr,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    in_netns(ns_path, move || {
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => Ok(Some(buf[..n].to_vec())),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    })?
}

/// Send a single UDP datagram from `ns_path` to `dst`.
pub fn udp_send(ns_path: &str, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
    let payload = payload.to_vec();
    in_netns(ns_path, move || {
        let bind: SocketAddr = match dst {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let sock = UdpSocket::bind(bind)?;
        sock.send_to(&payload, dst)?;
        Ok(())
    })?
}

/// Send `count` TCP SYN packets from `ns_path` to `dst`, cycling the source
/// port so each looks like a fresh connection attempt. Uses a raw IPv4 socket
/// with `IP_HDRINCL`, so it only supports IPv4 destinations. Returns the
/// number of packets the kernel accepted for transmission.
pub fn syn_flood_v4(
    ns_path: &str,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dst_port: u16,
    count: u32,
) -> io::Result<u32> {
    in_netns(ns_path, move || raw_syn_flood_v4(src, dst, dst_port, count))?
}

fn raw_syn_flood_v4(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, count: u32) -> io::Result<u32> {
    // SAFETY: standard libc socket setup; fd is closed on drop of `Fd`.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = Fd(fd);

    let one: libc::c_int = 1;
    // SAFETY: setting IP_HDRINCL so we provide our own IP header.
    let rc = unsafe {
        libc::setsockopt(
            fd.0,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = dst_port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());

    let mut sent = 0u32;
    for i in 0..count {
        let sport = 1024u16.wrapping_add((i % 60000) as u16);
        let pkt = build_syn_v4(src, dst, sport, dst_port, 0x1000_0000u32.wrapping_add(i));
        // SAFETY: sending a well-formed buffer to a sockaddr_in.
        let n = unsafe {
            libc::sendto(
                fd.0,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n >= 0 {
            sent += 1;
        }
    }
    Ok(sent)
}

/// Build a 40-byte IPv4 + TCP SYN packet.
fn build_syn_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> [u8; 40] {
    let mut p = [0u8; 40];
    // --- IPv4 header (20 bytes) ---
    p[0] = 0x45; // version 4, IHL 5
    p[1] = 0; // DSCP/ECN
    p[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
    p[4..6].copy_from_slice(&((seq & 0xffff) as u16).to_be_bytes()); // id
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    p[8] = 64; // ttl
    p[9] = 6; // protocol = TCP
    // checksum (p[10..12]) left zero for now
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ip_csum = checksum(&p[0..20]);
    p[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // --- TCP header (20 bytes) ---
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..28].copy_from_slice(&seq.to_be_bytes());
    // ack number zero
    p[32] = 5 << 4; // data offset = 5 words, no flags in low nibble
    p[33] = 0x02; // SYN
    p[34..36].copy_from_slice(&64240u16.to_be_bytes()); // window
    // TCP checksum over pseudo-header + header
    let tcp_csum = tcp_checksum_v4(src, dst, &p[20..40]);
    p[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
    p
}

/// One's-complement internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum with the IPv4 pseudo-header.
fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(6); // protocol
    buf.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp);
    checksum(&buf)
}

/// RAII wrapper for a raw file descriptor.
struct Fd(libc::c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: fd owned by this wrapper.
        unsafe { libc::close(self.0) };
    }
}

/// Convenience: build a `SocketAddr` from an `IpAddr` and port.
pub fn sa(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}
