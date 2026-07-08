#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::macros::{classifier, xdp};
use aya_ebpf::programs::{TcContext, XdpContext};
use lnvps_fw_common::{PROTO_TCP, PROTO_UDP, PortKeyV4, PortKeyV6};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

mod maps;

use maps::{
    OPEN_PORTS_V4, OPEN_PORTS_V6, counters_v4, counters_v6, learn_port_v4, learn_port_v6,
    syn_allowed_v4, syn_allowed_v6,
};

/// Normalized L4 metadata extracted from a packet, shared between the v4 and
/// v6 paths so the protection logic only exists once.
struct L4Meta {
    /// IP protocol number (PROTO_TCP / PROTO_UDP / icmp / other)
    proto: u8,
    /// True for a genuine connection-initiating SYN (SYN set, ACK clear)
    is_syn: bool,
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    unsafe { Ok(&*ptr) }
}

#[xdp]
pub fn xdp_lnvps(ctx: XdpContext) -> u32 {
    match try_handle(&ctx) {
        Ok(r) => r,
        // Fail open: a parse error (truncated/garbage packet) must never
        // abort; the kernel stack will discard malformed packets anyway.
        Err(()) => XDP_PASS,
    }
}

#[inline(always)]
fn try_handle(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    match eth_hdr.ether_type() {
        Ok(EtherType::Ipv4) => handle_ipv4(ctx),
        Ok(EtherType::Ipv6) => handle_ipv6(ctx),
        _ => Ok(XDP_PASS),
    }
}

#[inline(always)]
fn handle_ipv4(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    let dst = ip.dst_addr;

    // NOTE: assumes a 20-byte IPv4 header (no options). Packets with IP
    // options are rare; their L4 fields would be misread, so skip L4
    // inspection for them and just count the packet.
    let ihl = ip.ihl() as usize;
    let meta = if ihl == Ipv4Hdr::LEN {
        let proto = ip.proto;
        let is_syn = if proto == PROTO_TCP {
            let tcp = ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            tcp.syn() != 0 && tcp.ack() == 0
        } else {
            false
        };
        L4Meta { proto, is_syn }
    } else {
        L4Meta {
            proto: 255,
            is_syn: false,
        }
    };

    let counters = counters_v4(&dst);
    let mut verdict = XDP_PASS;
    if meta.is_syn && !syn_allowed_v4(&dst) {
        verdict = XDP_DROP;
    }
    account(ctx, counters, &meta, IpProto::Icmp as u8, verdict);
    Ok(verdict)
}

#[inline(always)]
fn handle_ipv6(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN)?;
    let dst = ip.dst_addr;

    // NOTE: no extension-header walking; packets whose first next-header is
    // not directly TCP/UDP/ICMPv6 are counted but not L4-inspected.
    let proto = ip.next_hdr;
    let is_syn = if proto == PROTO_TCP {
        let tcp = ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
        tcp.syn() != 0 && tcp.ack() == 0
    } else {
        false
    };
    let meta = L4Meta { proto, is_syn };

    let counters = counters_v6(&dst);
    let mut verdict = XDP_PASS;
    if meta.is_syn && !syn_allowed_v6(&dst) {
        verdict = XDP_DROP;
    }
    account(ctx, counters, &meta, IpProto::Ipv6Icmp as u8, verdict);
    Ok(verdict)
}

/// Update per-destination counters for one packet.
#[inline(always)]
fn account(
    ctx: &XdpContext,
    counters: Option<*mut lnvps_fw_common::DestCounters>,
    meta: &L4Meta,
    icmp_proto: u8,
    verdict: u32,
) {
    let Some(c) = counters else { return };
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;
    let c = unsafe { &mut *c };
    c.packets += 1;
    c.bytes += pkt_len;
    if meta.proto == PROTO_TCP {
        c.tcp_packets += 1;
        if meta.is_syn {
            c.syn_packets += 1;
        }
    } else if meta.proto == PROTO_UDP {
        c.udp_packets += 1;
    } else if meta.proto == icmp_proto {
        c.icmp_packets += 1;
    }
    if verdict == XDP_DROP {
        c.dropped += 1;
    }
}

/// A local service learned from an outbound packet: its source port (host
/// byte order) and protocol. The XDP ingress lookup decodes ports the same
/// way, so the two sides stay consistent regardless of endianness.
struct EgressService {
    port: u16,
    proto: u8,
}

/// TC egress classifier: passively learns which ports each local IP actually
/// serves by observing outbound traffic. A TCP SYN-ACK from `src ip:port`
/// marks that TCP port open; any outbound UDP from `ip:port` marks a UDP
/// service. Never modifies or drops packets (always `TC_ACT_OK`).
///
/// UDP note: outbound UDP from an ephemeral client port is indistinguishable
/// here from a real UDP service, so client ports are learned too. Short TTLs
/// (userspace GC) plus attack-time relearning keep this pollution bounded;
/// see docs/agents/fw-testing.md and work/ddos-protection.md.
#[classifier]
pub fn tc_lnvps_egress(ctx: TcContext) -> i32 {
    let _ = try_learn(&ctx);
    TC_ACT_OK
}

#[inline(always)]
fn tc_ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn try_learn(ctx: &TcContext) -> Result<(), ()> {
    let eth = unsafe { &*tc_ptr_at::<EthHdr>(ctx, 0)? };
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => learn_ipv4(ctx),
        Ok(EtherType::Ipv6) => learn_ipv6(ctx),
        _ => Ok(()),
    }
}

/// Extract the learnable service from an L4 header at `l4_off`, if any.
#[inline(always)]
fn egress_service(ctx: &TcContext, proto: u8, l4_off: usize) -> Result<Option<EgressService>, ()> {
    if proto == PROTO_TCP {
        let tcp = unsafe { &*tc_ptr_at::<TcpHdr>(ctx, l4_off)? };
        // A SYN-ACK is the server's half of the handshake: proof the local
        // src port is an open, listening TCP service.
        if tcp.syn() != 0 && tcp.ack() != 0 {
            return Ok(Some(EgressService {
                port: u16::from_be_bytes(tcp.source),
                proto: PROTO_TCP,
            }));
        }
        Ok(None)
    } else if proto == PROTO_UDP {
        let udp = unsafe { &*tc_ptr_at::<UdpHdr>(ctx, l4_off)? };
        Ok(Some(EgressService {
            port: u16::from_be_bytes(udp.src),
            proto: PROTO_UDP,
        }))
    } else {
        Ok(None)
    }
}

#[inline(always)]
fn learn_ipv4(ctx: &TcContext) -> Result<(), ()> {
    let ip = unsafe { &*tc_ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)? };
    // Options-bearing headers are skipped (rare); L4 offset would be wrong.
    if ip.ihl() as usize != Ipv4Hdr::LEN {
        return Ok(());
    }
    if let Some(svc) = egress_service(ctx, ip.proto, EthHdr::LEN + Ipv4Hdr::LEN)? {
        let key = PortKeyV4 {
            addr: ip.src_addr,
            port: svc.port,
            proto: svc.proto,
            _pad: 0,
        };
        learn_port_v4(&OPEN_PORTS_V4, &key);
    }
    Ok(())
}

#[inline(always)]
fn learn_ipv6(ctx: &TcContext) -> Result<(), ()> {
    let ip = unsafe { &*tc_ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN)? };
    // Only inspect packets whose first next-header is directly TCP/UDP.
    if let Some(svc) = egress_service(ctx, ip.next_hdr, EthHdr::LEN + Ipv6Hdr::LEN)? {
        let key = PortKeyV6 {
            addr: ip.src_addr,
            port: svc.port,
            proto: svc.proto,
            _pad: 0,
        };
        learn_port_v6(&OPEN_PORTS_V6, &key);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
