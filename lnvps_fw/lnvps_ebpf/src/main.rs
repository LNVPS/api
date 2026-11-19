#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS, XDP_TX};
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::helpers::bpf_xdp_get_buff_len;
use aya_ebpf::macros::{classifier, xdp};
use aya_ebpf::programs::{TcContext, XdpContext};
use lnvps_fw_common::{
    DEST_MODE_NORMAL, DEST_MODE_PORT_FILTER, DEST_MODE_SOURCE_BLOCK, DEST_MODE_SYN_PROXY,
    GlobalConfig, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, PortKeyV4, PortKeyV6,
    SLOT_SYN_PROXY_V4, SLOT_SYN_PROXY_V6, SNI_HASH_INIT, sni_hash_byte, syn_cookie_v4,
    syn_cookie_v6,
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
    dest_mode_v4, dest_mode_v6, global_cfg, learn_budget_v4, learn_budget_v6, learn_leak_v4,
    learn_leak_v6, learn_port_v4, learn_port_v6, manual_blocked_v4, manual_blocked_v6,
    mark_verified_v4, mark_verified_v6, port_is_open_v4, port_is_open_v6, port_open_refresh_v4,
    port_open_refresh_v6, protected_v4, protected_v6, sni_block_hit, sni_port, src_gate_v4,
    src_gate_v6, src_verified_v4, src_verified_v6, tx_counters_v4, tx_counters_v6,
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

/// 802.1Q / 802.1ad tag EtherTypes, in the raw (network-order) form the
/// `EthHdr::ether_type` field carries.
const ETH_P_8021Q_BE: u16 = 0x8100u16.to_be();
const ETH_P_8021AD_BE: u16 = 0x88A8u16.to_be();
const ETH_P_IP_BE: u16 = ETH_P_IP.to_be();
const ETH_P_IPV6_BE: u16 = ETH_P_IPV6.to_be();

/// Skip up to two VLAN tags (802.1ad outer + 802.1Q inner) after the Ethernet
/// header, returning the L2 length and the encapsulated EtherType (raw,
/// network order). A filter hook on a VLAN trunk port sees tagged frames
/// whenever the NIC is not stripping tags in hardware; without this every
/// tagged frame would fall through as "not IP" and pass unfiltered.
#[inline(always)]
fn skip_vlan_tags(ctx: &XdpContext) -> Result<(usize, u16), ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let mut off = EthHdr::LEN;
    let mut ty = eth.ether_type;
    // Bounded: at most two tags are ever consumed.
    let mut i = 0;
    while i < 2 && (ty == ETH_P_8021Q_BE || ty == ETH_P_8021AD_BE) {
        // 802.1Q tag: 2 bytes TCI, 2 bytes encapsulated EtherType.
        let tag = ptr_at::<[u8; 4]>(ctx, off)?;
        ty = u16::from_ne_bytes([tag[2], tag[3]]);
        off += 4;
        i += 1;
    }
    Ok((off, ty))
}

#[inline(always)]
fn try_handle(ctx: &XdpContext) -> Result<u32, ()> {
    let (l2_len, ty) = skip_vlan_tags(ctx)?;
    // The SYN-proxy tail-call program re-parses from fixed untagged L2
    // offsets and XDP_TXes a reply, so it is only offered to untagged frames.
    let plain = l2_len == EthHdr::LEN;
    match ty {
        ETH_P_IP_BE => handle_outer_ipv4(ctx, l2_len, plain),
        ETH_P_IPV6_BE => handle_ipv6(ctx, l2_len, plain),
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
fn handle_outer_ipv4(ctx: &XdpContext, l2_len: usize, allow_syn_proxy: bool) -> Result<u32, ()> {
    let ip = ptr_at::<Ipv4Hdr>(ctx, l2_len)?;
    if ip.proto == PROTO_GRE && ip.ihl() as usize == Ipv4Hdr::LEN && ip.frag_offset() == 0 {
        let gre_off = l2_len + Ipv4Hdr::LEN;
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
    handle_ipv4(ctx, l2_len, allow_syn_proxy)
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

    // One consolidated config lookup for the whole packet (scoping, per-source
    // rate config, learn-leak budget, verified TTL, manual-block presence).
    let cfg = global_cfg();

    // Scope to protected destinations: pass anything we do not defend without
    // counting or mitigating it (a router must never touch transit traffic).
    if cfg.scoped != 0 && !protected_v4(dst) {
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
    // Manual source blocks drop unconditionally (independent of dest
    // mitigation). Skip the per-packet LPM lookup entirely when none exist.
    if cfg.manual_blocks != 0 && manual_blocked_v4(src) {
        verdict = XDP_DROP;
    } else {
        let flags = dest_mode_v4(&dst);
        if flags != DEST_MODE_NORMAL {
            let (v, a) = mitigate_v4(
                ctx,
                &dst,
                &src,
                &meta,
                flags,
                allow_syn_proxy,
                counters,
                &cfg,
            );
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

    let cfg = global_cfg();

    if cfg.scoped != 0 && !protected_v6(dst) {
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
    if cfg.manual_blocks != 0 && manual_blocked_v6(ip.src_addr) {
        verdict = XDP_DROP;
    } else {
        let flags = dest_mode_v6(&dst);
        if flags != DEST_MODE_NORMAL {
            let (v, a) = mitigate_v6(
                ctx,
                &dst,
                &ip.src_addr,
                &meta,
                flags,
                allow_syn_proxy,
                counters,
                &cfg,
            );
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
///   here. A source is only *flagged blocked* while SOURCE_BLOCK is engaged, so
///   PORT_FILTER alone never source-drops (nor shows a source as `dropping`).
/// - SOURCE_BLOCK: drop sources over the per-source rate limit (and those
///   matching a blocked CIDR trie userspace populates for bounded/real
///   offenders). Applies to any traffic — including to a learned open port — so
///   a source flooding an open service is dropped once escalated.
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
    cfg: &GlobalConfig,
) -> (u32, bool) {
    // In-kernel per-source rate machine: counts this packet against the
    // source's window and drops while the source is blocked. Both the flagging
    // and the drop are gated on the dest's SOURCE_BLOCK escalation; counting
    // still happens without it so userspace has per-source rates.
    if src_gate_v4(src, &cfg.src_rate, flags & DEST_MODE_SOURCE_BLOCK != 0) {
        return (XDP_DROP, false);
    }
    if allow_syn_proxy
        && flags & DEST_MODE_SYN_PROXY != 0
        && meta.proto == PROTO_TCP
        && meta.has_port
        && port_is_open_v4(*dst, meta.dst_port, PROTO_TCP)
        && !src_verified_v4(src, cfg.verified_ttl_ns)
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
        return (dest_policy_v4(dst, meta, cfg.learn_leak_pps), false);
    }
    (XDP_PASS, false)
}

/// Destination-port policy under mitigation (after source checks pass).
#[inline(always)]
fn dest_policy_v4(dst: &[u8; 4], meta: &L4Meta, leak_budget: u32) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_open_refresh_v4(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else if meta.proto == PROTO_TCP
            && meta.is_syn
            && learn_leak_v4(dst, meta.dst_port, PROTO_TCP, leak_budget)
        {
            // Leak a bounded rate of SYNs to unlearned ports so a genuinely-
            // open port can answer (SYN-ACK) and be passively learned even
            // while mitigating — otherwise the port filter black-holes any
            // open port not learned before the flood began.
            XDP_PASS
        } else if meta.proto == PROTO_UDP && meta.is_wg_init && learn_budget_v4(dst, leak_budget) {
            // WireGuard handshake-init fast-path: bypass the first-touch
            // suppression (rate-capped only) so a tunnel re-establishes even
            // under a garbage flood to its port.
            XDP_PASS
        } else if meta.proto == PROTO_UDP
            && learn_leak_v4(dst, meta.dst_port, PROTO_UDP, leak_budget)
        {
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
    cfg: &GlobalConfig,
) -> (u32, bool) {
    if src_gate_v6(src, &cfg.src_rate, flags & DEST_MODE_SOURCE_BLOCK != 0) {
        return (XDP_DROP, false);
    }
    if allow_syn_proxy
        && flags & DEST_MODE_SYN_PROXY != 0
        && meta.proto == PROTO_TCP
        && meta.has_port
        && port_is_open_v6(*dst, meta.dst_port, PROTO_TCP)
        && !src_verified_v6(src, cfg.verified_ttl_ns)
    {
        account(ctx, counters, meta, PROTO_ICMPV6, XDP_DROP);
        unsafe { SYN_PROXY_JUMP.tail_call(ctx, SLOT_SYN_PROXY_V6) };
        return (XDP_DROP, true);
    }
    if flags & DEST_MODE_PORT_FILTER != 0 {
        if meta.is_fragment {
            return (XDP_DROP, false);
        }
        return (dest_policy_v6(dst, meta, cfg.learn_leak_pps), false);
    }
    (XDP_PASS, false)
}

#[inline(always)]
fn dest_policy_v6(dst: &[u8; 16], meta: &L4Meta, leak_budget: u32) -> u32 {
    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        if meta.has_port && port_open_refresh_v6(*dst, meta.dst_port, meta.proto) {
            XDP_PASS
        } else if meta.proto == PROTO_TCP
            && meta.is_syn
            && learn_leak_v6(dst, meta.dst_port, PROTO_TCP, leak_budget)
        {
            XDP_PASS
        } else if meta.proto == PROTO_UDP && meta.is_wg_init && learn_budget_v6(dst, leak_budget) {
            XDP_PASS
        } else if meta.proto == PROTO_UDP
            && learn_leak_v6(dst, meta.dst_port, PROTO_UDP, leak_budget)
        {
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
/// uses by observing outbound traffic. Any outbound TCP or UDP packet from
/// `src ip:port` marks that port as a live local service/flow.
///
/// This is also the enforcement point for the operator **TLS-SNI egress
/// blocklist**: a guest's ClientHello to a blocked server name is shot here
/// (`TC_ACT_SHOT`). The hook sees VM egress as plain L2 before NAT/routing --
/// on a router it is the `learn` role's TC *ingress* (VM traffic entering the
/// VM-facing NIC), on a single-NIC host the NIC's TC *egress* -- so one
/// program covers the whole fleet in either topology. Everything else is
/// passed untouched (`TC_ACT_OK`), and any parse failure fails open.
///
/// Why learn on *every* outbound segment (not just a TCP SYN-ACK): PORT_FILTER
/// drops inbound traffic to non-learned ports, and the return traffic of a
/// VM-initiated *outbound* connection lands on the VM's ephemeral source port.
/// If we only learned the server half (SYN-ACK), that ephemeral port would
/// stay unlearned and its inbound replies (SYN-ACK, then data) would be
/// black-holed under mitigation — silently breaking every outbound connection.
/// Learning the local source port of any outbound packet (a bare client SYN, or
/// an already-established flow's next segment) keeps outbound working: the
/// ephemeral port is learned before/with the first reply. This mirrors what UDP
/// already did, and is why the SYN-ACK-only rule was insufficient.
///
/// Ephemeral-port note: outbound from a client ephemeral port is
/// indistinguishable here from a real listening service, so client ports are
/// learned too. Short TTLs (userspace GC) plus the 1M-entry LRU keep this
/// pollution bounded; see docs/agents/fw-testing.md and work/ddos-protection.md.
#[classifier]
pub fn tc_lnvps_egress(ctx: TcContext) -> i32 {
    match try_learn(&ctx) {
        Ok(verdict) => verdict,
        // Fail open: a truncated/garbage packet is never dropped here.
        Err(()) => TC_ACT_OK,
    }
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

/// TC twin of [`skip_vlan_tags`]: a learn hook on a VLAN trunk (or an egress
/// hook emitting tagged frames) sees the tag inline whenever it is not carried
/// as skb metadata.
#[inline(always)]
fn tc_skip_vlan_tags(ctx: &TcContext) -> Result<(usize, u16), ()> {
    let eth = unsafe { &*tc_ptr_at::<EthHdr>(ctx, 0)? };
    let mut off = EthHdr::LEN;
    let mut ty = eth.ether_type;
    let mut i = 0;
    while i < 2 && (ty == ETH_P_8021Q_BE || ty == ETH_P_8021AD_BE) {
        let tag = unsafe { &*tc_ptr_at::<[u8; 4]>(ctx, off)? };
        ty = u16::from_ne_bytes([tag[2], tag[3]]);
        off += 4;
        i += 1;
    }
    Ok((off, ty))
}

#[inline(always)]
fn try_learn(ctx: &TcContext) -> Result<i32, ()> {
    let (l2_len, ty) = tc_skip_vlan_tags(ctx)?;
    match ty {
        ETH_P_IP_BE => learn_ipv4(ctx, l2_len),
        ETH_P_IPV6_BE => learn_ipv6(ctx, l2_len),
        _ => Ok(TC_ACT_OK),
    }
}

/// Extract the learnable local (source) port from an L4 header at `l4_off`, if
/// this is a TCP or UDP packet. The local source port of *any* outbound
/// TCP/UDP packet is learned — both the server half of a handshake (a listening
/// service) and a client's ephemeral port (so inbound return traffic for a
/// VM-initiated connection is not dropped by PORT_FILTER). See
/// [`tc_lnvps_egress`] for the full rationale.
#[inline(always)]
fn egress_service(ctx: &TcContext, proto: u8, l4_off: usize) -> Result<Option<EgressService>, ()> {
    if proto == PROTO_TCP {
        let tcp = unsafe { &*tc_ptr_at::<TcpHdr>(ctx, l4_off)? };
        Ok(Some(EgressService {
            port: u16::from_be_bytes(tcp.source),
            proto: PROTO_TCP,
        }))
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

// --- TLS SNI egress blocking (TC) ---

/// TLS record content type for a handshake record.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS handshake message type for ClientHello.
const TLS_HS_CLIENT_HELLO: u8 = 0x01;
/// TLS extension type `server_name` (RFC 6066).
const TLS_EXT_SERVER_NAME: usize = 0x0000;
/// `NameType` for a DNS hostname inside the server_name extension.
const SNI_NAME_TYPE_HOST: u8 = 0x00;
/// Longest hostname hashed. A DNS name is at most 253 bytes, so anything
/// longer is not a name we could have been asked to block.
const SNI_MAX_LEN: usize = 253;
/// Extensions walked before giving up. A real ClientHello carries well under
/// 20; the bound keeps the loop trivially finite for the verifier. A hello
/// that buries its SNI behind more than this many extensions is passed (fail
/// open) — see the evasion note on [`sni_blocked`].
const SNI_MAX_EXTENSIONS: usize = 64;
/// How far past the start of the TCP payload the ClientHello is parsed. Every
/// running offset is clamped to this window, which both caps the work per
/// packet and — crucially — keeps each offset a *bounded* scalar, without
/// which the verifier rejects the pointer arithmetic outright.
const SNI_SCAN_WINDOW: usize = 2048;

/// Read one payload byte at `off`.
///
/// The ClientHello walk uses `bpf_skb_load_bytes` rather than direct packet
/// access for two reasons: the offsets are packet-derived (variable), and the
/// verifier cannot carry a usable range across variable pointer arithmetic
/// (`math between pkt pointer and register with unbounded min value`); and the
/// payload of a large hello may live in the skb's non-linear fragments, which
/// direct access cannot reach at all. The helper handles both, and reads the
/// same bytes the guest actually sent.
#[inline(always)]
fn tc_u8(ctx: &TcContext, off: usize) -> Result<u8, ()> {
    ctx.load::<u8>(off).map_err(|_| ())
}

/// Read a big-endian u16 payload field at `off`.
#[inline(always)]
fn tc_be16(ctx: &TcContext, off: usize) -> Result<usize, ()> {
    let b = ctx.load::<[u8; 2]>(off).map_err(|_| ())?;
    Ok(((b[0] as usize) << 8) | b[1] as usize)
}

/// Clamp a running parse offset to the scan window (see [`SNI_SCAN_WINDOW`]),
/// bounding the work a single hello can cost. `Err` aborts the parse, which
/// fails open.
#[inline(always)]
fn sni_bounded(off: usize, end: usize) -> Result<usize, ()> {
    if off > end { Err(()) } else { Ok(off) }
}

/// True if this packet is a TLS ClientHello, sent to a configured inspection
/// port, whose server name is on the operator blocklist — in which case the
/// hit has already been counted and the caller must shoot the packet.
///
/// No per-flow state is needed: the ClientHello appears once per connection
/// (and again, with the same SNI, on resumption), so matching it is enough to
/// stop the connection — the guest cannot lie about the SNI without breaking
/// certificate validation at the far end, which is exactly why this is the
/// un-bypassable enforcement point for a root-controlled guest.
///
/// Fails open on every parse failure (`Err` from a bounds check, a truncated
/// hello, a hello split across segments, SNI buried behind more than
/// [`SNI_MAX_EXTENSIONS`] extensions, or TLS 1.3 Encrypted Client Hello, which
/// hides the name outright).
#[inline(always)]
fn sni_blocked(ctx: &TcContext, cfg: &GlobalConfig, proto: u8, l4_off: usize) -> bool {
    if cfg.sni_blocks == 0 || proto != PROTO_TCP {
        return false;
    }
    try_sni_blocked(ctx, l4_off).unwrap_or(false)
}

#[inline(always)]
fn try_sni_blocked(ctx: &TcContext, l4_off: usize) -> Result<bool, ()> {
    let tcp = unsafe { &*tc_ptr_at::<TcpHdr>(ctx, l4_off)? };
    if !sni_port(u16::from_be_bytes(tcp.dest)) {
        return Ok(false);
    }
    // Honour the TCP data offset: a hello segment may carry options
    // (timestamps), which would otherwise shift the payload out from under us.
    let doff = tcp.doff() as usize * 4;
    if doff < TcpHdr::LEN {
        return Ok(false);
    }
    // TLS record header: type(1) legacy_version(2) length(2).
    let rec = l4_off + doff;
    let end = rec + SNI_SCAN_WINDOW;
    if tc_u8(ctx, rec)? != TLS_RECORD_HANDSHAKE {
        return Ok(false);
    }
    // Handshake header: msg_type(1) length(3).
    let hs = rec + 5;
    if tc_u8(ctx, hs)? != TLS_HS_CLIENT_HELLO {
        return Ok(false);
    }
    // ClientHello body: legacy_version(2) random(32) then variable fields.
    let mut p = hs + 4 + 2 + 32;
    // legacy_session_id: len(1) + bytes.
    p = sni_bounded(p + 1 + tc_u8(ctx, p)? as usize, end)?;
    // cipher_suites: len(2) + bytes.
    p = sni_bounded(p + 2 + tc_be16(ctx, p)?, end)?;
    // legacy_compression_methods: len(1) + bytes.
    p = sni_bounded(p + 1 + tc_u8(ctx, p)? as usize, end)?;
    // extensions: len(2) + list.
    let ext_end = sni_bounded(p + 2 + tc_be16(ctx, p)?, end)?;
    p = sni_bounded(p + 2, end)?;
    for _ in 0..SNI_MAX_EXTENSIONS {
        // extension: type(2) len(2) + body.
        if p + 4 > ext_end {
            return Ok(false);
        }
        let etype = tc_be16(ctx, p)?;
        let elen = tc_be16(ctx, p + 2)?;
        p = sni_bounded(p + 4, end)?;
        if p + elen > ext_end {
            return Ok(false);
        }
        if etype == TLS_EXT_SERVER_NAME {
            return sni_ext_blocked(ctx, p, elen);
        }
        p = sni_bounded(p + elen, end)?;
    }
    Ok(false)
}

/// Check the first DNS hostname in a `server_name` extension body (`len` bytes
/// at `off`) against the blocklist. Only the first entry is considered: the
/// list has been restricted to a single `host_name` since RFC 6066.
#[inline(always)]
fn sni_ext_blocked(ctx: &TcContext, off: usize, len: usize) -> Result<bool, ()> {
    // ServerNameList: list_len(2) [ name_type(1) name_len(2) name ].
    if len < 5 {
        return Ok(false);
    }
    let list_len = tc_be16(ctx, off)?;
    if list_len + 2 > len || tc_u8(ctx, off + 2)? != SNI_NAME_TYPE_HOST {
        return Ok(false);
    }
    let name_len = tc_be16(ctx, off + 3)?;
    if name_len == 0 || name_len > SNI_MAX_LEN || name_len + 3 > list_len {
        return Ok(false);
    }
    // Hash the name one byte at a time. A bulk `bpf_skb_load_bytes` would need
    // a variable length, which the verifier rejects as a possibly-zero-sized
    // read however the bound is expressed; a fixed-size bulk read would fail
    // whenever the name sits near the end of the packet. Per-byte loads are
    // constant-sized, and the loop runs only for the name's actual length
    // (~20 bytes for a real hostname), once per inspected ClientHello.
    let name = off + 5;
    let mut h = SNI_HASH_INIT;
    for i in 0..SNI_MAX_LEN {
        if i >= name_len {
            break;
        }
        h = sni_hash_byte(h, tc_u8(ctx, name + i)?);
    }
    Ok(sni_block_hit(h))
}

#[inline(always)]
fn learn_ipv4(ctx: &TcContext, l2_len: usize) -> Result<i32, ()> {
    let ip = unsafe { &*tc_ptr_at::<Ipv4Hdr>(ctx, l2_len)? };
    let cfg = global_cfg();
    // Only account/learn for protected servers (keeps state clean on a router
    // that forwards for many networks). The SNI blocklist honours the same
    // scope, so a router never inspects third-party transit traffic.
    if cfg.scoped != 0 && !protected_v4(ip.src_addr) {
        return Ok(TC_ACT_OK);
    }
    // Options-bearing / fragmented headers put L4 somewhere else, so neither
    // the SNI check nor port learning can read it (both simply skip).
    let plain_l4 = ip.ihl() as usize == Ipv4Hdr::LEN && ip.frag_offset() == 0;
    // SNI egress block first: a shot packet is neither accounted nor learned
    // (its flow never completes, so there is no service to remember).
    if plain_l4 && sni_blocked(ctx, &cfg, ip.proto, l2_len + Ipv4Hdr::LEN) {
        return Ok(TC_ACT_SHOT);
    }
    // TX accounting for every outbound packet from this source (before the
    // options-header early-out below, which only affects L4 port learning).
    if let Some(c) = tx_counters_v4(&ip.src_addr) {
        tx_account(c, ctx.len() as u64, ip.proto, PROTO_ICMP);
    }
    if !plain_l4 {
        return Ok(TC_ACT_OK);
    }
    if let Some(svc) = egress_service(ctx, ip.proto, l2_len + Ipv4Hdr::LEN)? {
        let key = PortKeyV4 {
            addr: ip.src_addr,
            port: svc.port,
            proto: svc.proto,
            _pad: 0,
        };
        learn_port_v4(&OPEN_PORTS_V4, &key);
    }
    Ok(TC_ACT_OK)
}

#[inline(always)]
fn learn_ipv6(ctx: &TcContext, l2_len: usize) -> Result<i32, ()> {
    let ip = unsafe { &*tc_ptr_at::<Ipv6Hdr>(ctx, l2_len)? };
    let cfg = global_cfg();
    if cfg.scoped != 0 && !protected_v6(ip.src_addr) {
        return Ok(TC_ACT_OK);
    }
    // SNI egress block (see `learn_ipv4`). As with learning, only packets whose
    // first next-header is directly TCP are inspected; extension-header chains
    // are passed.
    if sni_blocked(ctx, &cfg, ip.next_hdr, l2_len + Ipv6Hdr::LEN) {
        return Ok(TC_ACT_SHOT);
    }
    // TX accounting for every outbound packet from this source.
    if let Some(c) = tx_counters_v6(&ip.src_addr) {
        tx_account(c, ctx.len() as u64, ip.next_hdr, PROTO_ICMPV6);
    }
    // Only inspect packets whose first next-header is directly TCP/UDP.
    if let Some(svc) = egress_service(ctx, ip.next_hdr, l2_len + Ipv6Hdr::LEN)? {
        let key = PortKeyV6 {
            addr: ip.src_addr,
            port: svc.port,
            proto: svc.proto,
            _pad: 0,
        };
        learn_port_v6(&OPEN_PORTS_V6, &key);
    }
    Ok(TC_ACT_OK)
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
