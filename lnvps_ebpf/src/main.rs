#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action::{XDP_ABORTED, XDP_PASS};
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::{error, info};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

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

fn try_parse_packet(ctx: &XdpContext) -> Result<u32, &'static str> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => return handle_ipv4(ctx),
        EtherType::Arp => {}
        EtherType::Ipv6 => {}
        _ => {}
    }

    Ok(XDP_PASS)
}

fn handle_ipv4(ctx: &XdpContext) -> Result<u32, &'static str> {
    let hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;

    info!(
        ctx,
        "Got IPv4 header: {}.{}.{}.{} -> {}.{}.{}.{}",
        hdr.src_addr[0],
        hdr.src_addr[1],
        hdr.src_addr[2],
        hdr.src_addr[3],
        hdr.dst_addr[0],
        hdr.dst_addr[1],
        hdr.dst_addr[2],
        hdr.dst_addr[3],
    );
    Ok(XDP_PASS)
}

fn handle_ipv6(ctx: &XdpContext) -> Result<u32, &'static str> {
    let hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;

    Ok(XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
