#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS, XDP_TX};
use aya_ebpf::helpers::bpf_xdp_get_buff_len;
use aya_ebpf::macros::{classifier, xdp};
use aya_ebpf::programs::{TcContext, XdpContext};
use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY,
    PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, PortKeyV4, PortKeyV6,
    SLOT_SYN_PROXY_V4, SLOT_SYN_PROXY_V6, syn_cookie_v4, syn_cookie_v6,
};

/// GRE inner protocol type for IPv4 / IPv6 payloads (ethertypes).
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

mod maps;

use maps::{
    OPEN_PORTS_V4, OPEN_PORTS_V6, SYN_PROXY_JUMP, cookie_secrets, counters_v4, counters_v6,
    dest_mode_v4, dest_mode_v6, learn_budget_v4, learn_budget_v6, learn_leak_v4, learn_leak_v6,
    port_open_refresh_v4, port_open_refresh_v6, src_gate_v4, src_gate_v6,
    learn_port_v4, learn_port_v6, manual_blocked_v4, manual_blocked_v6, mark_verified_v4,
    mark_verified_v6, port_is_open_v4, port_is_open_v6, protected_v4, protected_v6, scoped,
    src_verified_v4, src_verified_v6, tx_counters_v4, tx_counters_v6,
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
    /// True if this UDP packet is a WireGuard handshake-initiation (type 1,
    /// 148-byte payload). Fast-pathed by the learning leak so a WG tunnel can
    /// re-establish through PORT_FILTER even when its port is unlearned.
    is_wg_init: bool,
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
            is_wg_init: false,
        }
    }
}

/// WireGuard message type for a handshake initiation (first payload byte). The
/// message is exactly 148 bytes (UDP length 156).
const WG_MSG_HANDSHAKE_INIT: u8 = 1;
const WG_HANDSHAKE_INIT_UDP_LEN: u16 = 156;

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

// `frags` marks the program multi-buffer aware (section `xdp.frags`,
// BPF_F_XDP_HAS_FRAGS). Without it the kernel refuses a *native* attach on a
// jumbo-MTU NIC (mlx5: "MTU > 3498, too big for an XDP program not aware of
// multi buffer") and silently falls back to the slow generic/SKB path. All
// header parsing reads the linear head (bounds-checked against data_end, which
// in frags mode is the end of the linear segment) and fails open if a header
// somehow spans a fragment, so this is safe.
#[xdp(frags)]
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
        Ok(EtherType::Ipv4) => handle_outer_ipv4(ctx),
        Ok(EtherType::Ipv6) => handle_ipv6(ctx, EthHdr::LEN, true),
        _ => Ok(XDP_PASS),
    }
}

/// Outer IPv4 dispatch: if this is a GRE tunnel packet (proto 47) carrying an
/// inner IP datagram, decapsulate and filter on the *inner* header (this is how
/// a router protects VMs reached over BGP-in-GRE underlays, and sheds the flood
/// before the kernel spends CPU decapsulating + routing it). Otherwise filter
/// the packet directly. SYN-proxy is disabled on the decapsulated path (its
/// tail-call program re-parses from fixed L2 offsets and cannot re-encapsulate
/// a reply).
#[inline(always)]
fn handle_outer_ipv4(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    if ip.proto == PROTO_GRE && ip.ihl() as usize == Ipv4Hdr::LEN && ip.frag_offset() == 0 {
        let gre_off = EthHdr::LEN + Ipv4Hdr::LEN;
        let gre = ptr_at::<[u8; 4]>(ctx, gre_off)?;
        let flags0 = gre[0];
        let version = gre[1] & 0x07;
        // Standard GRE (version 0), no deprecated Routing-Present field (whose
        // variable SRE list we do not parse). C/K/S each add a 4-byte field.
        if version == 0 && (flags0 & 0x40) == 0 {
            let c = (flags0 & 0x80) != 0;
            let k = (flags0 & 0x20) != 0;
            let s = (flags0 & 0x10) != 0;
            let gre_len = 4 + if c { 4 } else { 0 } + if k { 4 } else { 0 } + if s { 4 } else { 0 };
            let ptype = ((gre[2] as u16) << 8) | gre[3] as u16;
            let inner_off = gre_off + gre_len;
            match ptype {
                ETH_P_IP => return handle_ipv4(ctx, inner_off, false),
                ETH_P_IPV6 => return handle_ipv6(ctx, inner_off, false),
                _ => {}
            }
        }
    }
    handle_ipv4(ctx, EthHdr::LEN, true)
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
        // WireGuard handshake-initiation fast-path signal: message type 1 with
        // exactly 148 payload bytes (UDP length 156). Cheap to check; forged
        // matches are crypto-rejected by WireGuard, so leaking them is safe.
        if u16::from_be_bytes(udp.len) == WG_HANDSHAKE_INIT_UDP_LEN
            && let Ok(t) = ptr_at::<u8>(ctx, l4_off + UdpHdr::LEN)
            && unsafe { *t } == WG_MSG_HANDSHAKE_INIT
        {
            meta.is_wg_init = true;
        }
    }
    Ok(())
}

/// Filter an IPv4 datagram whose header starts at `ip_off` (0-based from the
/// packet start). `ip_off` is `EthHdr::LEN` for a normal L2 frame, or the
/// post-GRE offset for a decapsulated tunnel packet. `allow_syn_proxy` is false
/// on the decapsulated path.
#[inline(always)]
fn handle_ipv4(ctx: &XdpContext, ip_off: usize, allow_syn_proxy: bool) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_off)?;
    let dst = ip.dst_addr;

    // Scope to protected destinations: pass anything we do not defend without
    // counting or mitigating it (a router must never touch transit traffic).
    if scoped() && !protected_v4(dst) {
        return Ok(XDP_PASS);
    }

    // Non-first fragments carry no L4 header; options-bearing headers would
    // misplace L4 fields. Count them, but only inspect L4 for plain 20-byte,
    // unfragmented headers.
    let is_fragment = ip.frag_offset() != 0;
    let mut meta = L4Meta::new(ip.proto, is_fragment);
    if !is_fragment && ip.ihl() as usize == Ipv4Hdr::LEN {
        fill_l4(ctx, &mut meta, ip_off + Ipv4Hdr::LEN)?;
    }

    // Steady state is pass-all (just count + learn). Enforcement happens only
    // once userspace sets one or more protection flags on this destination.
    let src = ip.src_addr;
    let counters = counters_v4(&dst);
    let mut verdict = XDP_PASS;
    let mut accounted = false;
    // Manual source blocks drop unconditionally (independent of dest mitigation).
    if manual_blocked_v4(src) {
        verdict = XDP_DROP;
    } else {
        let flags = dest_mode_v4(&dst);
        if flags != DEST_MODE_NORMAL {
            let (v, a) = mitigate_v4(ctx, &dst, &src, &meta, flags, allow_syn_proxy, counters);
            verdict = v;
            accounted = a;
        }
    }
    // The SYN-proxy path accounts before its tail-call (which never returns
    // here), so only account now if it didn't.
    if !accounted {
        account(ctx, counters, &meta, PROTO_ICMP, verdict);
    }
    Ok(verdict)
}

#[inline(always)]
fn handle_ipv6(ctx: &XdpContext, ip_off: usize, allow_syn_proxy: bool) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, ip_off)?;
    let dst = ip.dst_addr;

    if scoped() && !protected_v6(dst) {
        return Ok(XDP_PASS);
    }

    // NOTE: no extension-header walking; packets whose first next-header is
    // not directly TCP/UDP/ICMPv6 are counted but not L4-inspected (and are
    // dropped under mitigation as "not a learned service").
    let mut meta = L4Meta::new(ip.next_hdr, false);
    fill_l4(ctx, &mut meta, ip_off + Ipv6Hdr::LEN)?;

    let counters = counters_v6(&dst);
    let mut verdict = XDP_PASS;
    let mut accounted = false;
    if manual_blocked_v6(ip.src_addr) {
        verdict = XDP_DROP;
    } else {
        let flags = dest_mode_v6(&dst);
        if flags != DEST_MODE_NORMAL {
            let (v, a) =
                mitigate_v6(ctx, &dst, &ip.src_addr, &meta, flags, allow_syn_proxy, counters);
            verdict = v;
            accounted = a;
        }
    }
    if !accounted {
        account(ctx, counters, &meta, PROTO_ICMPV6, verdict);
    }
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
/// Returns `(verdict, accounted)`. `accounted` is true only when this function
/// already updated the destination counters (the SYN-proxy tail-call path,
/// which does not return to the caller), so the caller must not double-count.
#[inline(always)]
fn mitigate_v4(
    ctx: &XdpContext,
    dst: &[u8; 4],
    src: &[u8; 4],
    meta: &L4Meta,
    flags: u32,
    allow_syn_proxy: bool,
    counters: Option<*mut lnvps_fw_common::DestCounters>,
) -> (u32, bool) {
    // In-kernel per-source rate machine: counts this packet against the
    // source's window and drops while the source is blocked (enforcement is
    // gated on the dest's SOURCE_BLOCK escalation, counting is not).
    if src_gate_v4(src, flags & DEST_MODE_SOURCE_BLOCK != 0) {
        return (XDP_DROP, false);
    }
    if allow_syn_proxy
        && flags & DEST_MODE_SYN_PROXY != 0
        && meta.proto == PROTO_TCP
        && meta.has_port
        && port_is_open_v4(*dst, meta.dst_port, PROTO_TCP)
        && !src_verified_v4(src)
    {
        // Account this packet as a dropped SYN *before* the tail-call, which
        // replaces this program and never returns here.
        account(ctx, counters, meta, PROTO_ICMP, XDP_DROP);
        unsafe { SYN_PROXY_JUMP.tail_call(ctx, SLOT_SYN_PROXY_V4) };
        // Only reached if the tail-call failed (jump slot unset): the packet is
        // already accounted, so report accounted=true to avoid double-counting.
        return (XDP_DROP, true);
    }
    if flags & DEST_MODE_PORT_FILTER != 0 {
        if meta.is_fragment {
            return (XDP_DROP, false);
        }
        return (dest_policy_v4(dst, meta), false);
    }
    (XDP_PASS, false)
}

/// Destination-port policy under mitigation (after source checks pass).
#[inline(always)]
fn dest_policy_v4(dst: &[u8; 4], meta: &L4Meta) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_open_refresh_v4(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else if meta.proto == PROTO_TCP && meta.is_syn && learn_leak_v4(dst, meta.dst_port, PROTO_TCP)
        {
            // Leak a bounded rate of SYNs to unlearned ports so a genuinely-
            // open port can answer (SYN-ACK) and be passively learned even
            // while mitigating — otherwise the port filter black-holes any
            // open port not learned before the flood began.
            XDP_PASS
        } else if meta.proto == PROTO_UDP && meta.is_wg_init && learn_budget_v4(dst) {
            // WireGuard handshake-init fast-path: bypass the first-touch
            // suppression (rate-capped only) so a tunnel re-establishes even
            // under a garbage flood to its port.
            XDP_PASS
        } else if meta.proto == PROTO_UDP && learn_leak_v4(dst, meta.dst_port, PROTO_UDP) {
            // General UDP first-touch: probe an unlearned port once so a
            // request/response service (DNS, game servers, WG data) can answer
            // and be learned.
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

/// See [`mitigate_v4`] for the `(verdict, accounted)` contract.
#[inline(always)]
fn mitigate_v6(
    ctx: &XdpContext,
    dst: &[u8; 16],
    src: &[u8; 16],
    meta: &L4Meta,
    flags: u32,
    allow_syn_proxy: bool,
    counters: Option<*mut lnvps_fw_common::DestCounters>,
) -> (u32, bool) {
    if src_gate_v6(src, flags & DEST_MODE_SOURCE_BLOCK != 0) {
        return (XDP_DROP, false);
    }
    if allow_syn_proxy
        && flags & DEST_MODE_SYN_PROXY != 0
        && meta.proto == PROTO_TCP
        && meta.has_port
        && port_is_open_v6(*dst, meta.dst_port, PROTO_TCP)
        && !src_verified_v6(src)
    {
        account(ctx, counters, meta, PROTO_ICMPV6, XDP_DROP);
        unsafe { SYN_PROXY_JUMP.tail_call(ctx, SLOT_SYN_PROXY_V6) };
        return (XDP_DROP, true);
    }
    if flags & DEST_MODE_PORT_FILTER != 0 {
        if meta.is_fragment {
            return (XDP_DROP, false);
        }
        return (dest_policy_v6(dst, meta), false);
    }
    (XDP_PASS, false)
}

#[inline(always)]
fn dest_policy_v6(dst: &[u8; 16], meta: &L4Meta) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_open_refresh_v6(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else if meta.proto == PROTO_TCP && meta.is_syn && learn_leak_v6(dst, meta.dst_port, PROTO_TCP)
        {
            XDP_PASS
        } else if meta.proto == PROTO_UDP && meta.is_wg_init && learn_budget_v6(dst) {
            XDP_PASS
        } else if meta.proto == PROTO_UDP && learn_leak_v6(dst, meta.dst_port, PROTO_UDP) {
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
    // Full on-wire length including any non-linear fragments (multi-buffer XDP);
    // `data_end - data` would only cover the linear head on a jumbo packet.
    let pkt_len = unsafe { bpf_xdp_get_buff_len(ctx.ctx) };
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

/// Account one outbound packet against the local source IP's TX counters.
/// Proto breakdown is derived from the IP header alone (no L4 parse), so it is
/// cheap and works for fragments/options too. `icmp_proto` distinguishes ICMP
/// (v4) from ICMPv6.
#[inline(always)]
fn tx_account(c: *mut lnvps_fw_common::DestCounters, pkt_len: u64, proto: u8, icmp_proto: u8) {
    let c = unsafe { &mut *c };
    c.packets += 1;
    c.bytes += pkt_len;
    if proto == PROTO_TCP {
        c.tcp_packets += 1;
    } else if proto == PROTO_UDP {
        c.udp_packets += 1;
    } else if proto == icmp_proto {
        c.icmp_packets += 1;
    }
}

#[inline(always)]
fn learn_ipv4(ctx: &TcContext) -> Result<(), ()> {
    let ip = unsafe { &*tc_ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)? };
    // Only account/learn for protected servers (keeps state clean on a router
    // that forwards for many networks).
    if scoped() && !protected_v4(ip.src_addr) {
        return Ok(());
    }
    // TX accounting for every outbound packet from this source (before the
    // options-header early-out below, which only affects L4 port learning).
    if let Some(c) = tx_counters_v4(&ip.src_addr) {
        tx_account(c, ctx.len() as u64, ip.proto, PROTO_ICMP);
    }
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
    if scoped() && !protected_v6(ip.src_addr) {
        return Ok(());
    }
    // TX accounting for every outbound packet from this source.
    if let Some(c) = tx_counters_v6(&ip.src_addr) {
        tx_account(c, ctx.len() as u64, ip.next_hdr, PROTO_ICMPV6);
    }
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

// --- SYN-proxy tail-call program (IPv4) ---
const TCP_OFF: usize = EthHdr::LEN + Ipv4Hdr::LEN;

// Must match the caller's frags flag: tail-call targets in the same program
// array must agree on multi-buffer awareness.
#[xdp(frags)]
pub fn xdp_syn_proxy(ctx: XdpContext) -> u32 {
    match try_syn_proxy(&ctx) {
        Ok(v) => v,
        Err(()) => XDP_DROP,
    }
}

#[inline(always)]
fn try_syn_proxy(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)?;
    let src = ip.src_addr;
    let dst = ip.dst_addr;
    let tcp = ptr_at::<TcpHdr>(ctx, TCP_OFF)?;
    let syn = tcp.syn() != 0;
    let ack = tcp.ack() != 0;
    let sport = tcp.source;
    let dport = tcp.dest;
    let client_ack = u32::from_be_bytes(tcp.ack_seq);
    let (cur, prev) = cookie_secrets();

    if syn && !ack {
        let cookie = syn_cookie_v4(cur, src, dst, sport, dport);
        return Ok(tx_synack_v4(ctx, cookie));
    }
    if ack && !syn {
        let echoed = client_ack.wrapping_sub(1);
        let c_cur = syn_cookie_v4(cur, src, dst, sport, dport);
        let c_prev = syn_cookie_v4(prev, src, dst, sport, dport);
        if echoed == c_cur || echoed == c_prev {
            mark_verified_v4(&src);
        }
        return Ok(XDP_DROP);
    }
    Ok(XDP_DROP)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn fold(sum: u32) -> u16 {
    // Loop-free: folding a sum of at most ~10 16-bit words twice always brings
    // it within 16 bits. Data-dependent `while` loops are rejected by the XDP
    // verifier here (they surface as an opaque EFAULT at load).
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}
/// Big-endian u16 from two bytes.
#[inline(always)]
fn be16(hi: u8, lo: u8) -> u32 {
    ((hi as u32) << 8) | lo as u32
}

/// Rewrite the in-place IPv4 TCP SYN into a SYN-ACK carrying `cookie`. Every
/// operation is byte-wise on bounds-checked typed header pointers: whole-array
/// field assignments lower to `memmove`/`memcpy` on packet memory, which blow
/// up the XDP verifier's state space, so we avoid them entirely. Checksums are
/// computed from field bytes. Returns XDP_TX, or XDP_PASS if truncated.
#[inline(always)]
fn tx_synack_v4(ctx: &XdpContext, cookie: u32) -> u32 {
    let eth = match ptr_at_mut::<EthHdr>(ctx, 0) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };
    let ip = match ptr_at_mut::<Ipv4Hdr>(ctx, EthHdr::LEN) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };
    let tcp = match ptr_at_mut::<TcpHdr>(ctx, TCP_OFF) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };

    // Swap MAC + IPv4 addresses byte-wise (whole-array assignment lowers to
    // memmove on packet memory, which explodes the verifier state space).
    {
        let t = eth.dst_addr[0];
        eth.dst_addr[0] = eth.src_addr[0];
        eth.src_addr[0] = t;
    }
    {
        let t = eth.dst_addr[1];
        eth.dst_addr[1] = eth.src_addr[1];
        eth.src_addr[1] = t;
    }
    {
        let t = eth.dst_addr[2];
        eth.dst_addr[2] = eth.src_addr[2];
        eth.src_addr[2] = t;
    }
    {
        let t = eth.dst_addr[3];
        eth.dst_addr[3] = eth.src_addr[3];
        eth.src_addr[3] = t;
    }
    {
        let t = eth.dst_addr[4];
        eth.dst_addr[4] = eth.src_addr[4];
        eth.src_addr[4] = t;
    }
    {
        let t = eth.dst_addr[5];
        eth.dst_addr[5] = eth.src_addr[5];
        eth.src_addr[5] = t;
    }
    {
        let t = ip.src_addr[0];
        ip.src_addr[0] = ip.dst_addr[0];
        ip.dst_addr[0] = t;
    }
    {
        let t = ip.src_addr[1];
        ip.src_addr[1] = ip.dst_addr[1];
        ip.dst_addr[1] = t;
    }
    {
        let t = ip.src_addr[2];
        ip.src_addr[2] = ip.dst_addr[2];
        ip.dst_addr[2] = t;
    }
    {
        let t = ip.src_addr[3];
        ip.src_addr[3] = ip.dst_addr[3];
        ip.dst_addr[3] = t;
    }
    ip.tot_len[0] = 0;
    ip.tot_len[1] = 40; // 20 IP + 20 TCP
    ip.ttl = 64;
    ip.check[0] = 0;
    ip.check[1] = 0;
    let ipsum = be16(ip.vihl, ip.tos)
        + be16(ip.tot_len[0], ip.tot_len[1])
        + be16(ip.id[0], ip.id[1])
        + be16(ip.frags[0], ip.frags[1])
        + be16(ip.ttl, ip.proto)
        + be16(ip.src_addr[0], ip.src_addr[1])
        + be16(ip.src_addr[2], ip.src_addr[3])
        + be16(ip.dst_addr[0], ip.dst_addr[1])
        + be16(ip.dst_addr[2], ip.dst_addr[3]);
    let ipck = fold(ipsum);
    ip.check[0] = (ipck >> 8) as u8;
    ip.check[1] = ipck as u8;

    // Swap TCP ports byte-wise.
    {
        let a = tcp.source[0];
        let b = tcp.source[1];
        tcp.source[0] = tcp.dest[0];
        tcp.source[1] = tcp.dest[1];
        tcp.dest[0] = a;
        tcp.dest[1] = b;
    }
    let client_seq = ((tcp.seq[0] as u32) << 24)
        | ((tcp.seq[1] as u32) << 16)
        | ((tcp.seq[2] as u32) << 8)
        | tcp.seq[3] as u32;
    let ackn = client_seq.wrapping_add(1);
    tcp.seq[0] = (cookie >> 24) as u8;
    tcp.seq[1] = (cookie >> 16) as u8;
    tcp.seq[2] = (cookie >> 8) as u8;
    tcp.seq[3] = cookie as u8;
    tcp.ack_seq[0] = (ackn >> 24) as u8;
    tcp.ack_seq[1] = (ackn >> 16) as u8;
    tcp.ack_seq[2] = (ackn >> 8) as u8;
    tcp.ack_seq[3] = ackn as u8;
    // Data offset (5 words) + flags (SYN|ACK) as the two wire bytes at TCP
    // offset 12/13, via the validated typed pointer.
    let tb = tcp as *mut TcpHdr as *mut u8;
    unsafe {
        *tb.add(12) = 0x50;
        *tb.add(13) = 0x12;
    }
    tcp.window[0] = 0xff;
    tcp.window[1] = 0xff;
    tcp.urg_ptr[0] = 0;
    tcp.urg_ptr[1] = 0;
    tcp.check[0] = 0;
    tcp.check[1] = 0;
    let tsum = be16(ip.src_addr[0], ip.src_addr[1])
        + be16(ip.src_addr[2], ip.src_addr[3])
        + be16(ip.dst_addr[0], ip.dst_addr[1])
        + be16(ip.dst_addr[2], ip.dst_addr[3])
        + PROTO_TCP as u32
        + 20u32
        + be16(tcp.source[0], tcp.source[1])
        + be16(tcp.dest[0], tcp.dest[1])
        + (cookie >> 16)
        + (cookie & 0xffff)
        + (ackn >> 16)
        + (ackn & 0xffff)
        + 0x5012u32
        + 0xffffu32;
    let tck = fold(tsum);
    tcp.check[0] = (tck >> 8) as u8;
    tcp.check[1] = tck as u8;
    XDP_TX
}

// --- SYN-proxy tail-call program (IPv6) ---
const TCP_OFF_V6: usize = EthHdr::LEN + Ipv6Hdr::LEN;

#[xdp(frags)]
pub fn xdp_syn_proxy_v6(ctx: XdpContext) -> u32 {
    match try_syn_proxy_v6(&ctx) {
        Ok(v) => v,
        Err(()) => XDP_DROP,
    }
}

#[inline(always)]
fn try_syn_proxy_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN)?;
    let src = ip.src_addr;
    let dst = ip.dst_addr;
    let tcp = ptr_at::<TcpHdr>(ctx, TCP_OFF_V6)?;
    let syn = tcp.syn() != 0;
    let ack = tcp.ack() != 0;
    let sport = tcp.source;
    let dport = tcp.dest;
    let client_ack = u32::from_be_bytes(tcp.ack_seq);
    let (cur, prev) = cookie_secrets();

    if syn && !ack {
        let cookie = syn_cookie_v6(cur, src, dst, sport, dport);
        return Ok(tx_synack_v6(ctx, cookie));
    }
    if ack && !syn {
        let echoed = client_ack.wrapping_sub(1);
        let c_cur = syn_cookie_v6(cur, src, dst, sport, dport);
        let c_prev = syn_cookie_v6(prev, src, dst, sport, dport);
        if echoed == c_cur || echoed == c_prev {
            mark_verified_v6(&src);
        }
        return Ok(XDP_DROP);
    }
    Ok(XDP_DROP)
}

/// IPv6 counterpart of [`tx_synack_v4`]. IPv6 has no header checksum, but the
/// TCP checksum covers a 128-bit pseudo-header. All packet writes are byte-wise
/// on bounds-checked typed pointers (see `tx_synack_v4` for why).
#[inline(always)]
fn tx_synack_v6(ctx: &XdpContext, cookie: u32) -> u32 {
    let eth = match ptr_at_mut::<EthHdr>(ctx, 0) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };
    let ip = match ptr_at_mut::<Ipv6Hdr>(ctx, EthHdr::LEN) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };
    let tcp = match ptr_at_mut::<TcpHdr>(ctx, TCP_OFF_V6) {
        Ok(p) => unsafe { &mut *p },
        Err(()) => return XDP_PASS,
    };

    // Swap MAC addresses byte-wise (whole-array assignment lowers to memmove).
    let mut i = 0usize;
    while i < 6 {
        let t = eth.dst_addr[i];
        eth.dst_addr[i] = eth.src_addr[i];
        eth.src_addr[i] = t;
        i += 1;
    }
    // Swap the 16-byte IPv6 addresses byte-wise.
    let mut j = 0usize;
    while j < 16 {
        let t = ip.src_addr[j];
        ip.src_addr[j] = ip.dst_addr[j];
        ip.dst_addr[j] = t;
        j += 1;
    }
    ip.payload_len[0] = 0;
    ip.payload_len[1] = 20; // TCP header only
    ip.hop_limit = 64;
    // next_hdr stays PROTO_TCP.

    // IPv6 pseudo-header address word sum (commutes over the src/dst swap).
    let addr_sum = be16(ip.src_addr[0], ip.src_addr[1])
        + be16(ip.src_addr[2], ip.src_addr[3])
        + be16(ip.src_addr[4], ip.src_addr[5])
        + be16(ip.src_addr[6], ip.src_addr[7])
        + be16(ip.src_addr[8], ip.src_addr[9])
        + be16(ip.src_addr[10], ip.src_addr[11])
        + be16(ip.src_addr[12], ip.src_addr[13])
        + be16(ip.src_addr[14], ip.src_addr[15])
        + be16(ip.dst_addr[0], ip.dst_addr[1])
        + be16(ip.dst_addr[2], ip.dst_addr[3])
        + be16(ip.dst_addr[4], ip.dst_addr[5])
        + be16(ip.dst_addr[6], ip.dst_addr[7])
        + be16(ip.dst_addr[8], ip.dst_addr[9])
        + be16(ip.dst_addr[10], ip.dst_addr[11])
        + be16(ip.dst_addr[12], ip.dst_addr[13])
        + be16(ip.dst_addr[14], ip.dst_addr[15]);

    // Swap TCP ports byte-wise.
    {
        let a = tcp.source[0];
        let b = tcp.source[1];
        tcp.source[0] = tcp.dest[0];
        tcp.source[1] = tcp.dest[1];
        tcp.dest[0] = a;
        tcp.dest[1] = b;
    }
    let client_seq = ((tcp.seq[0] as u32) << 24)
        | ((tcp.seq[1] as u32) << 16)
        | ((tcp.seq[2] as u32) << 8)
        | tcp.seq[3] as u32;
    let ackn = client_seq.wrapping_add(1);
    tcp.seq[0] = (cookie >> 24) as u8;
    tcp.seq[1] = (cookie >> 16) as u8;
    tcp.seq[2] = (cookie >> 8) as u8;
    tcp.seq[3] = cookie as u8;
    tcp.ack_seq[0] = (ackn >> 24) as u8;
    tcp.ack_seq[1] = (ackn >> 16) as u8;
    tcp.ack_seq[2] = (ackn >> 8) as u8;
    tcp.ack_seq[3] = ackn as u8;
    let tb = tcp as *mut TcpHdr as *mut u8;
    unsafe {
        *tb.add(12) = 0x50; // data offset 5 words
        *tb.add(13) = 0x12; // SYN|ACK
    }
    tcp.window[0] = 0xff;
    tcp.window[1] = 0xff;
    tcp.urg_ptr[0] = 0;
    tcp.urg_ptr[1] = 0;
    tcp.check[0] = 0;
    tcp.check[1] = 0;
    let tsum = addr_sum
        + PROTO_TCP as u32 // pseudo-header next-header
        + 20u32 // pseudo-header upper-layer length
        + be16(tcp.source[0], tcp.source[1])
        + be16(tcp.dest[0], tcp.dest[1])
        + (cookie >> 16)
        + (cookie & 0xffff)
        + (ackn >> 16)
        + (ackn & 0xffff)
        + 0x5012u32
        + 0xffffu32;
    let tck = fold(tsum);
    tcp.check[0] = (tck >> 8) as u8;
    tcp.check[1] = tck as u8;
    XDP_TX
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
