#![no_std]
#![no_main]

use crate::maps::Bucket;
use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS};
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{error, info};
use network_types::eth::{EthHdr, EtherType};
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

mod maps;

/// Packet to handle
enum L4Packet<'a> {
    TcpV4 {
        eth: &'a EthHdr,
        ip: &'a Ipv4Hdr,
        tcp: &'a TcpHdr,
    },
    UdpV4 {
        eth: &'a EthHdr,
        ip: &'a Ipv4Hdr,
        udp: &'a UdpHdr,
    },
    IcmpV4 {
        eth: &'a EthHdr,
        ip: &'a Ipv4Hdr,
        icmp: &'a IcmpHdr,
    },
    TcpV6 {
        eth: &'a EthHdr,
        ip: &'a Ipv6Hdr,
        tcp: &'a TcpHdr,
    },
    UdpV6 {
        eth: &'a EthHdr,
        ip: &'a Ipv6Hdr,
        udp: &'a UdpHdr,
    },
    IcmpV6 {
        eth: &'a EthHdr,
        ip: &'a Ipv6Hdr,
        icmp: &'a IcmpHdr,
    },
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&T, &'static str> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err("not enough data");
    }

    let ptr = (start + offset) as *const T;
    unsafe { Ok(&*ptr) }
}

#[xdp]
pub fn xdp_lnvps(ctx: XdpContext) -> u32 {
    match try_parse_packet(&ctx) {
        Ok(r) => r,
        Err(e) => {
            error!(&ctx, "{}", e);
            XDP_ABORTED
        }
    }
}

#[inline(always)]
fn try_parse_packet(ctx: &XdpContext) -> Result<u32, &'static str> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => handle_ipv4(ctx),
        EtherType::Ipv6 => handle_ipv6(ctx),
        _ => Ok(XDP_PASS),
    }
}

#[inline(always)]
fn handle_ipv4(ctx: &XdpContext) -> Result<u32, &'static str> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let ip = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;

    match ip.proto {
        IpProto::Tcp => {
            let tcp = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            handle_l4(ctx, L4Packet::TcpV4 { eth, ip, tcp })
        }
        IpProto::Udp => {
            let udp = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            handle_l4(ctx, L4Packet::UdpV4 { eth, ip, udp })
        }
        IpProto::Ipv6Icmp => {
            let icmp = ptr_at::<IcmpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            handle_l4(ctx, L4Packet::IcmpV4 { eth, ip, icmp })
        }
        _ => Ok(XDP_PASS),
    }
}

#[inline(always)]
fn handle_ipv6(ctx: &XdpContext) -> Result<u32, &'static str> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let ip = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;

    match ip.next_hdr {
        IpProto::Tcp => {
            let tcp = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            handle_l4(ctx, L4Packet::TcpV6 { eth, ip, tcp })
        }
        IpProto::Udp => {
            let udp = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            handle_l4(ctx, L4Packet::UdpV6 { eth, ip, udp })
        }
        IpProto::Ipv6Icmp => {
            let icmp = ptr_at::<IcmpHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
            handle_l4(ctx, L4Packet::IcmpV6 { eth, ip, icmp })
        }
        _ => Ok(XDP_PASS),
    }
}

#[inline(always)]
fn handle_l4(ctx: &XdpContext, pkt: L4Packet<'_>) -> Result<u32, &'static str> {
    match pkt {
        L4Packet::TcpV4 { ip, tcp, .. } => {
            let syn_flag = tcp.syn();
            // Is only SYN flag set
            if syn_flag != 0 && syn_flag == syn_flag {
                // test SYN rate limits
                if !Bucket::syn_dest_v4(ctx, ip)? {
                    info!(ctx, "L4 TCPv4 SYN DROP");
                    return Ok(XDP_DROP);
                }
            }
        }
        L4Packet::UdpV4 { .. } => {}
        L4Packet::IcmpV4 { .. } => {}
        L4Packet::TcpV6 { .. } => {}
        L4Packet::UdpV6 { .. } => {}
        L4Packet::IcmpV6 { .. } => {}
    }
    Ok(XDP_PASS)
}

/// Tail program for L4 packets
/*#[xdp]
fn lnvps_xdp_l4(ctx: XdpContext) -> u32 {
    XDP_PASS
}*/

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
