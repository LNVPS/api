#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use lnvps_fw_common::{PROTO_TCP, PROTO_UDP};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;

mod maps;

use maps::{counters_v4, counters_v6, syn_allowed_v4, syn_allowed_v6};

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
