#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::macros::{classifier, xdp};
use aya_ebpf::programs::{TcContext, XdpContext};
use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, PROTO_ICMP, PROTO_ICMPV6,
    PROTO_TCP, PROTO_UDP, PortKeyV4, PortKeyV6,
};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

mod maps;

use maps::{
    OPEN_PORTS_V4, OPEN_PORTS_V6, cidr_blocked_v4, cidr_blocked_v6, count_src_v4, count_src_v6,
    counters_v4, counters_v6, dest_mode_v4, dest_mode_v6, learn_port_v4, learn_port_v6,
    port_is_open_v4, port_is_open_v6,
};

/// Normalized L4 metadata extracted from a packet, shared between the v4 and
/// v6 paths so the protection logic only exists once.
struct L4Meta {
    /// IP protocol number (PROTO_TCP / PROTO_UDP / icmp / other)
    proto: u8,
    /// True for a genuine connection-initiating SYN (SYN set, ACK clear)
    is_syn: bool,
    /// True if this is a non-first IP fragment (no usable L4 header)
    is_fragment: bool,
    /// Destination port in host byte order (valid only when `has_port`)
    dst_port: u16,
    /// Whether a TCP/UDP destination port was parsed
    has_port: bool,
}

impl L4Meta {
    #[inline(always)]
    fn new(proto: u8, is_fragment: bool) -> Self {
        Self {
            proto,
            is_syn: false,
            is_fragment,
            dst_port: 0,
            has_port: false,
        }
    }
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

/// Parse the TCP/UDP destination port and SYN flag into `meta`, if the packet
/// carries a TCP or UDP header at `l4_off`.
#[inline(always)]
fn fill_l4(ctx: &XdpContext, meta: &mut L4Meta, l4_off: usize) -> Result<(), ()> {
    if meta.proto == PROTO_TCP {
        let tcp = ptr_at::<TcpHdr>(ctx, l4_off)?;
        meta.is_syn = tcp.syn() != 0 && tcp.ack() == 0;
        meta.dst_port = u16::from_be_bytes(tcp.dest);
        meta.has_port = true;
    } else if meta.proto == PROTO_UDP {
        let udp = ptr_at::<UdpHdr>(ctx, l4_off)?;
        meta.dst_port = u16::from_be_bytes(udp.dst);
        meta.has_port = true;
    }
    Ok(())
}

#[inline(always)]
fn handle_ipv4(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    let dst = ip.dst_addr;

    // Non-first fragments carry no L4 header; options-bearing headers would
    // misplace L4 fields. Count them, but only inspect L4 for plain 20-byte,
    // unfragmented headers.
    let is_fragment = ip.frag_offset() != 0;
    let mut meta = L4Meta::new(ip.proto, is_fragment);
    if !is_fragment && ip.ihl() as usize == Ipv4Hdr::LEN {
        fill_l4(ctx, &mut meta, EthHdr::LEN + Ipv4Hdr::LEN)?;
    }

    // Steady state is pass-all (just count + learn). Enforcement happens only
    // once userspace sets one or more protection flags on this destination.
    let counters = counters_v4(&dst);
    let mut verdict = XDP_PASS;
    let flags = dest_mode_v4(&dst);
    if flags != DEST_MODE_NORMAL {
        verdict = mitigate_v4(&dst, &ip.src_addr, &meta, flags);
    }
    account(ctx, counters, &meta, PROTO_ICMP, verdict);
    Ok(verdict)
}

#[inline(always)]
fn handle_ipv6(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN)?;
    let dst = ip.dst_addr;

    // NOTE: no extension-header walking; packets whose first next-header is
    // not directly TCP/UDP/ICMPv6 are counted but not L4-inspected (and are
    // dropped under mitigation as "not a learned service").
    let mut meta = L4Meta::new(ip.next_hdr, false);
    fill_l4(ctx, &mut meta, EthHdr::LEN + Ipv6Hdr::LEN)?;

    let counters = counters_v6(&dst);
    let mut verdict = XDP_PASS;
    let flags = dest_mode_v6(&dst);
    if flags != DEST_MODE_NORMAL {
        verdict = mitigate_v6(&dst, &ip.src_addr, &meta, flags);
    }
    account(ctx, counters, &meta, PROTO_ICMPV6, verdict);
    Ok(verdict)
}

/// Mitigation verdict for a destination whose protection `flags` bitmask is
/// non-empty. The eBPF side only counts and enforces userspace-decided policy;
/// each flag is applied independently:
/// - always: count this source (bounded LRU) so userspace can compute
///   per-source rates / cardinality and decide which flags to set — no decision
///   here;
/// - SOURCE_BLOCK: drop sources matching a blocked CIDR (the LPM trie userspace
///   only populates for bounded/real offenders; last resort);
/// - PORT_FILTER: drop non-first fragments and traffic to non-learned ports
///   (ICMP passes); this sheds the bulk of reflection/carpet-bomb floods.
#[inline(always)]
fn mitigate_v4(dst: &[u8; 4], src: &[u8; 4], meta: &L4Meta, flags: u32) -> u32 {
    count_src_v4(src);
    if flags & DEST_MODE_SOURCE_BLOCK != 0 && cidr_blocked_v4(*src) {
        return XDP_DROP;
    }
    if flags & DEST_MODE_PORT_FILTER != 0 {
        if meta.is_fragment {
            return XDP_DROP;
        }
        return dest_policy_v4(dst, meta);
    }
    XDP_PASS
}

/// Destination-port policy under mitigation (after source checks pass).
#[inline(always)]
fn dest_policy_v4(dst: &[u8; 4], meta: &L4Meta) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_is_open_v4(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else {
            XDP_DROP
        }
    } else if meta.proto == PROTO_ICMP {
        XDP_PASS
    } else {
        XDP_DROP
    }
}

#[inline(always)]
fn mitigate_v6(dst: &[u8; 16], src: &[u8; 16], meta: &L4Meta, flags: u32) -> u32 {
    count_src_v6(src);
    if flags & DEST_MODE_SOURCE_BLOCK != 0 && cidr_blocked_v6(*src) {
        return XDP_DROP;
    }
    if flags & DEST_MODE_PORT_FILTER != 0 {
        if meta.is_fragment {
            return XDP_DROP;
        }
        return dest_policy_v6(dst, meta);
    }
    XDP_PASS
}

#[inline(always)]
fn dest_policy_v6(dst: &[u8; 16], meta: &L4Meta) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_is_open_v6(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else {
            XDP_DROP
        }
    } else if meta.proto == PROTO_ICMPV6 {
        XDP_PASS
    } else {
        XDP_DROP
    }
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
