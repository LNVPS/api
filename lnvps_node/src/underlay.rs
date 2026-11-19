use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const SMALLEST: u32 = 576;
const LARGEST: u32 = 1500;
const ATTEMPTS: usize = 2;
const WAIT: Duration = Duration::from_millis(800);

pub async fn path_mtu(target: IpAddr) -> Option<u32> {
    tokio::task::spawn_blocking(move || match measure(target) {
        Ok(mtu) => mtu,
        Err(e) => {
            log::warn!("Could not measure the path MTU to {target}: {e:#}");
            None
        }
    })
    .await
    .ok()
    .flatten()
}

fn measure(target: IpAddr) -> Result<Option<u32>> {
    let mut prober = Prober::open(target)?;
    if !prober.fits(SMALLEST)? {
        return Ok(None);
    }
    Ok(Some(largest_that_fits(SMALLEST, LARGEST, |size| {
        prober.fits(size)
    })?))
}

pub fn largest_that_fits(
    mut fits_at: u32,
    mut fails_above: u32,
    mut fits: impl FnMut(u32) -> Result<bool>,
) -> Result<u32> {
    if fits(fails_above)? {
        return Ok(fails_above);
    }
    while fails_above - fits_at > 1 {
        let mid = fits_at + (fails_above - fits_at) / 2;
        if fits(mid)? {
            fits_at = mid;
        } else {
            fails_above = mid;
        }
    }
    Ok(fits_at)
}

struct Prober {
    socket: Socket,
    target: IpAddr,
    id: u16,
    seq: u16,
}

impl Prober {
    fn open(target: IpAddr) -> Result<Self> {
        let (domain, protocol) = match target {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
        };
        let socket = Socket::new(domain, Type::RAW, Some(protocol))
            .context("Cannot open a raw ICMP socket; the node must run as root")?;
        let fd = socket.as_raw_fd();
        match target {
            IpAddr::V4(_) => set_int(
                fd,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MTU_DISCOVER,
                nix::libc::IP_PMTUDISC_PROBE,
            )?,
            IpAddr::V6(_) => {
                set_int(
                    fd,
                    nix::libc::IPPROTO_IPV6,
                    nix::libc::IPV6_MTU_DISCOVER,
                    nix::libc::IPV6_PMTUDISC_PROBE,
                )?;
                set_int(fd, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_DONTFRAG, 1)?;
            }
        }
        socket.set_read_timeout(Some(WAIT))?;
        Ok(Self {
            socket,
            target,
            id: rand::random(),
            seq: 0,
        })
    }

    fn fits(&mut self, size: u32) -> Result<bool> {
        for _ in 0..ATTEMPTS {
            self.seq = self.seq.wrapping_add(1);
            let packet = echo_request(self.target, self.id, self.seq, size)?;
            let to = SockAddr::from(SocketAddr::new(self.target, 0));
            match self.socket.send_to(&packet, &to) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(nix::libc::EMSGSIZE) => return Ok(false),
                Err(e) => return Err(e).context("Cannot send an ICMP echo"),
            }
            if self.await_reply()? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn await_reply(&self) -> Result<bool> {
        let deadline = Instant::now() + WAIT;
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
        while Instant::now() < deadline {
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(false);
                }
                Err(e) => return Err(e).context("Cannot read an ICMP reply"),
            };
            if from.as_socket().map(|s| s.ip()) != Some(self.target) {
                continue;
            }
            let bytes: Vec<u8> = buf[..len]
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();
            if is_our_reply(self.target, &bytes, self.id, self.seq) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn set_int(fd: i32, level: i32, name: i32, value: i32) -> Result<()> {
    let rc = unsafe {
        nix::libc::setsockopt(
            fd,
            level,
            name,
            &value as *const i32 as *const nix::libc::c_void,
            std::mem::size_of::<i32>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        bail!(
            "setsockopt({level}, {name}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn echo_request(target: IpAddr, id: u16, seq: u16, size: u32) -> Result<Vec<u8>> {
    let header = match target {
        IpAddr::V4(_) => 20,
        IpAddr::V6(_) => 40,
    };
    let Some(payload) = (size as usize).checked_sub(header + 8) else {
        bail!("{size} bytes is smaller than an ICMP echo");
    };
    let kind = match target {
        IpAddr::V4(_) => 8,
        IpAddr::V6(_) => 128,
    };
    let mut packet = vec![kind, 0, 0, 0];
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.resize(8 + payload, 0xa5);
    if target.is_ipv4() {
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    Ok(packet)
}

pub fn is_our_reply(target: IpAddr, bytes: &[u8], id: u16, seq: u16) -> bool {
    let (icmp, reply_kind) = match target {
        IpAddr::V4(_) => {
            let Some(first) = bytes.first() else {
                return false;
            };
            let ihl = usize::from(first & 0x0f) * 4;
            (bytes.get(ihl..).unwrap_or_default(), 0)
        }
        IpAddr::V6(_) => (bytes, 129),
    };
    icmp.len() >= 8
        && icmp[0] == reply_kind
        && icmp[4..6] == id.to_be_bytes()
        && icmp[6..8] == seq.to_be_bytes()
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests;
