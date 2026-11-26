//! Exit nodes: a selected app's internet traffic carried over fips to an exit
//! node, which sends it on to the internet, instead of leaving through the
//! phone's own connection (the userspace forwarder).
//!
//! fips only delivers packets addressed to `fd00::/8`, so an app's IPv4 packet
//! is carried inside an IPv6 packet from this node's address to the exit's
//! (IPv4-in-IPv6, next header 4, no tunnel header — what Linux's `ip6tnl`
//! speaks). Replies come back the same way and are unwrapped before the TUN.
//! This phone sends IPv4 only for now: IPv6 internet traffic is refused while
//! an exit is selected (see [`Outbound::Refuse`]). The transport leaves room
//! for IPv6-in-IPv6 (next header 41) to be added later.
//!
//! Each phone sends from its own inner address in `100.64.0.0/10`, derived
//! from its node address ([`inner_ipv4`]) so the exit can compute it from the
//! npub with nothing negotiated. It is also the tunnel's own IPv4 address
//! (Kotlin gets it from `deriveIdentity`), so packets go out and replies come
//! back with no address rewriting, and an ICMP error quoting a packet matches
//! the app's socket. The formula is the contract with the exit side
//! (`exit-node/exitctl.py`, and `fips-exit`); do not change it.
//!
//! Replies are not trusted because they come from the exit: the exit's
//! operator could otherwise open connections to any app listening on the
//! phone. [`ExitSwitch`] keeps its own flow table and admits only replies to
//! flows the apps opened — no port allowlist, no off switch.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::filter::{FlowKey, FlowTable};

/// IPv6 next header for an encapsulated IPv4 packet.
pub const IPPROTO_IPIP: u8 = 4;
const IPV6_HEADER: usize = 40;
const HOP_LIMIT: u8 = 64;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// TCP MSS for IPv4 through an exit, both directions. Planned for a mesh
/// packet of 1280 bytes, the smallest any fips hop carries: 1280 − 40
/// (outer IPv6) = 1240 for the inner packet, − 20 (IPv4) − 20 (TCP) = 1200.
/// The exit clamps to the same value in its forward chain. (IPv6-in-IPv6
/// would be 1180.)
pub const MSS_IPV4: u16 = 1200;

/// This node's inner IPv4 address, from its fips address (`fd` + 15 bytes):
/// `100.64.0.0/10` with the low 22 bits taken from address bytes 1..4.
///
/// ```text
/// inner = 0x64400000 | ((a[1] << 16 | a[2] << 8 | a[3]) & 0x3fffff)
/// ```
pub fn inner_ipv4(fips_addr: &[u8; 16]) -> Ipv4Addr {
    let bits =
        (u32::from(fips_addr[1]) << 16 | u32::from(fips_addr[2]) << 8 | u32::from(fips_addr[3]))
            & 0x003f_ffff;
    Ipv4Addr::from(0x6440_0000 | bits)
}

/// True for an IPv4 packet (what goes to an exit).
pub fn is_ipv4(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4
}

/// The IPv4 header length of a well-formed packet: version 4, IHL at least
/// 5, a total length that covers the header and fits `packet`. `None` for
/// anything else, so no port is ever read from inside a header.
fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    if !is_ipv4(packet) {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    (ihl >= 20 && total >= ihl && total <= packet.len()).then_some(ihl)
}

/// True for a fragment other than the first: it carries no transport header.
fn later_fragment(packet: &[u8]) -> bool {
    u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0
}

/// Wrap an IPv4 packet for the exit at `exit`, sent from `ours`.
pub fn wrap(inner: &[u8], ours: &[u8; 16], exit: &[u8; 16]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(IPV6_HEADER + inner.len());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    pkt.push(IPPROTO_IPIP);
    pkt.push(HOP_LIMIT);
    pkt.extend_from_slice(ours);
    pkt.extend_from_slice(exit);
    pkt.extend_from_slice(inner);
    pkt
}

/// True for an IPv6 packet carrying IPv4 (next header 4), from anyone.
fn is_ipip(packet: &[u8]) -> bool {
    packet.len() >= IPV6_HEADER && packet[0] >> 4 == 6 && packet[6] == IPPROTO_IPIP
}

/// The IPv4 packet inside `packet`, if it is one wrapped by the exit at `exit`
/// for this node: IPv6 from `exit`, next header 4, a well-formed IPv4 packet
/// inside. Anything else — another node, another protocol — is `None`.
pub fn unwrap<'a>(packet: &'a [u8], exit: &[u8; 16]) -> Option<&'a [u8]> {
    if !is_ipip(packet) || packet[8..24] != exit[..] {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let inner = packet.get(IPV6_HEADER..IPV6_HEADER + len)?;
    ipv4_header_len(inner)?;
    let total = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    Some(&inner[..total])
}

/// Lower the MSS option of an IPv4 TCP SYN to `max`, fixing the TCP checksum
/// (RFC 1624 incremental update). The app then never sends a segment the
/// mesh would refuse once wrapped — the same job fips's own clamp does for
/// mesh-bound IPv6. Anything else is left alone.
pub fn clamp_mss(packet: &mut [u8], max: u16) {
    let Some(ihl) = ipv4_header_len(packet) else {
        return;
    };
    if packet[9] != PROTO_TCP || later_fragment(packet) {
        return;
    }
    let Some(tcp) = packet.get_mut(ihl..) else {
        return;
    };
    if tcp.len() < 20 || tcp[13] & 0x02 == 0 {
        return; // not a SYN
    }
    let data_off = usize::from(tcp[12] >> 4) * 4;
    if data_off < 20 || data_off > tcp.len() {
        return;
    }
    let mut i = 20;
    while i < data_off {
        match tcp[i] {
            0 => return, // end of options
            1 => i += 1, // no-op
            kind => {
                let Some(&len) = tcp.get(i + 1) else { return };
                let len = usize::from(len);
                if len < 2 || i + len > data_off {
                    return;
                }
                if kind == 2 && len == 4 {
                    let old = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                    if old > max {
                        tcp[i + 2..i + 4].copy_from_slice(&max.to_be_bytes());
                        let sum = u16::from_be_bytes([tcp[16], tcp[17]]);
                        let mut acc = u32::from(!sum) + u32::from(!old) + u32::from(max);
                        while acc > 0xffff {
                            acc = (acc & 0xffff) + (acc >> 16);
                        }
                        tcp[16..18].copy_from_slice(&(!(acc as u16)).to_be_bytes());
                    }
                    return;
                }
                i += len;
            }
        }
    }
}

/// An IPv4 address as the flow table stores it (IPv4-mapped).
fn mapped(v4: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12..16].copy_from_slice(&v4[..4]);
    a
}

/// The flow an IPv4 packet this phone sends belongs to, as the flow table
/// keys it: TCP and UDP by ports, an ICMP echo request by its identifier.
/// `None` for a later fragment, another protocol or a truncated header.
/// `packet` may be a quoted header inside an ICMP error, whose total length
/// describes the original packet, not the bytes quoted: only the IHL is
/// checked here, and only the 8 transport bytes every error quotes are read.
fn sent_flow(packet: &[u8]) -> Option<FlowKey> {
    if !is_ipv4(packet) || later_fragment(packet) {
        return None;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let l4 = packet.get(ihl..ihl + 8)?;
    let remote_addr = mapped(&packet[16..20]);
    let port = |at: usize| u16::from_be_bytes([l4[at], l4[at + 1]]);
    match packet[9] {
        proto @ (PROTO_TCP | PROTO_UDP) => Some(FlowKey {
            proto,
            local_port: port(0),
            remote_addr,
            remote_port: port(2),
        }),
        PROTO_ICMP if l4[0] == 8 => Some(FlowKey {
            proto: PROTO_ICMP,
            local_port: port(4),
            remote_addr,
            remote_port: 0,
        }),
        _ => None,
    }
}

/// What the reader does with a packet that is not for the mesh.
#[derive(Debug, PartialEq)]
pub enum Outbound {
    /// No exit selected: the phone's own connection (the forwarder).
    Forwarder,
    /// Wrapped for the exit; hand it to the node.
    Mesh(Vec<u8>),
    /// An exit is selected but this cannot go through it (IPv6, or a
    /// malformed IPv4 packet): refused, so nothing leaves around the exit.
    /// For IPv6 it carries the ICMPv6 "administratively prohibited" to write
    /// back to the app, so it falls back to IPv4 at once instead of waiting
    /// out a connect timeout (`None` for a packet that must not be answered:
    /// an ICMPv6 error itself, or garbage).
    Refuse(Option<Vec<u8>>),
}

/// What the bridge does with a packet from the mesh.
#[derive(Debug, PartialEq)]
pub enum Inbound {
    /// Not IPv4-in-IPv6: the normal inbound path (the mesh firewall).
    NotTunnel,
    /// A reply from the selected exit to a flow an app opened: the IPv4
    /// packet to write to the TUN.
    Deliver(Vec<u8>),
    /// IPv4-in-IPv6 that is not that: dropped here, whatever the mesh
    /// firewall's settings, since nothing else on the phone expects it.
    Drop,
}

/// ICMPv6 Destination Unreachable, code 1 (administratively prohibited), for
/// an IPv6 packet the app sent: from the address it was sent to, quoting as
/// much of it as fits in 1280 bytes (RFC 4443 §2.4). `None` for an ICMPv6
/// error message (never answer an error with an error) or a non-IPv6 packet.
pub fn icmpv6_prohibited(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < IPV6_HEADER || packet[0] >> 4 != 6 {
        return None;
    }
    if packet[6] == 58 && packet.get(IPV6_HEADER).is_some_and(|t| *t < 128) {
        return None;
    }
    let quoted = &packet[..packet.len().min(1280 - IPV6_HEADER - 8)];
    let mut icmp = Vec::with_capacity(8 + quoted.len());
    icmp.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    icmp.extend_from_slice(quoted);
    let (src, dst) = (&packet[24..40], &packet[8..24]);
    let mut sum = 0u32;
    for chunk in [
        src,
        dst,
        &(icmp.len() as u32).to_be_bytes()[..],
        &[0, 0, 0, 58][..],
        &icmp,
    ] {
        for c in chunk.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    icmp[2..4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    let mut out = Vec::with_capacity(IPV6_HEADER + icmp.len());
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    out.push(58);
    out.push(HOP_LIMIT);
    out.extend_from_slice(src);
    out.extend_from_slice(dst);
    out.extend_from_slice(&icmp);
    Some(out)
}

struct Route {
    npub: String,
    addr: [u8; 16],
}

/// The live exit selection, shared by the pump's reader (outbound), its
/// bridge (replies) and the engine (which switches it without a restart).
pub struct ExitSwitch {
    route: RwLock<Option<Route>>,
    /// This node's fips address and the inner IPv4 derived from it.
    ours: [u8; 16],
    inner: [u8; 4],
    /// Flows the apps opened through the current exit: the only replies let
    /// in. Cleared when the exit changes.
    flows: FlowTable,
    /// The local `.fips` responder, asked to register the exit's identity.
    responder: SocketAddr,
    /// Unix seconds of the last registration (rate limit for [`Self::refused`]).
    registered_at: AtomicU64,
}

impl ExitSwitch {
    pub fn new(ours: [u8; 16], responder: SocketAddr) -> Self {
        Self {
            route: RwLock::new(None),
            ours,
            inner: inner_ipv4(&ours).octets(),
            flows: FlowTable::default(),
            responder,
            registered_at: AtomicU64::new(0),
        }
    }

    /// Select the exit with this npub, or none (`None`/empty: the phone's own
    /// connection). Registers the exit's identity with the node in the
    /// background. An npub that does not parse, or this node's own, selects
    /// nothing and is an error, so a typo never silently sends traffic out
    /// of the phone.
    pub fn set(&self, npub: Option<&str>) -> Result<(), String> {
        let npub = npub.map(str::trim).filter(|n| !n.is_empty());
        let route = match npub {
            None => None,
            Some(n) => {
                let peer = fips::identity::PeerIdentity::from_npub(n)
                    .map_err(|e| format!("exit node npub: {e}"))?;
                let addr = *peer.address().as_bytes();
                if addr == self.ours {
                    return Err("exit node npub: that is this phone's own npub".into());
                }
                Some(Route {
                    npub: peer.npub(),
                    addr,
                })
            }
        };
        let register = route.as_ref().map(|r| r.npub.clone());
        {
            let mut current = self.route.write().unwrap();
            let changed = current.as_ref().map(|r| &r.npub) != route.as_ref().map(|r| &r.npub);
            if changed {
                // A flow opened through one exit is not answered by another.
                self.flows.clear();
                match &route {
                    Some(r) => {
                        tracing::info!(exit = %r.npub, "internet traffic now goes through the exit node")
                    }
                    None => {
                        tracing::info!("internet traffic now goes through the phone's connection")
                    }
                }
            }
            *current = route;
        }
        if let Some(npub) = register {
            self.register(npub);
        }
        Ok(())
    }

    /// The selected exit's npub, if any.
    pub fn selected(&self) -> Option<String> {
        self.route.read().unwrap().as_ref().map(|r| r.npub.clone())
    }

    /// The selected exit's fips address, if any.
    pub fn selected_addr(&self) -> Option<std::net::Ipv6Addr> {
        self.route.read().unwrap().as_ref().map(|r| r.addr.into())
    }

    /// This node's inner IPv4 address (the tunnel's IPv4 address, and what
    /// the exit sees as the source).
    pub fn inner(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.inner)
    }

    /// Decide a packet that is not for the mesh.
    pub fn outbound(&self, packet: &[u8]) -> Outbound {
        let route = self.route.read().unwrap();
        let Some(route) = route.as_ref() else {
            return Outbound::Forwarder;
        };
        if !is_ipv4(packet) {
            return Outbound::Refuse(icmpv6_prohibited(packet));
        }
        // Malformed, or not from the tunnel's address (which is the inner
        // address): nothing an app sends, and nothing the exit would take.
        if ipv4_header_len(packet).is_none() || packet[12..16] != self.inner {
            return Outbound::Refuse(None);
        }
        if let Some(flow) = sent_flow(packet) {
            self.flows.note(flow);
        }
        let mut inner = packet.to_vec();
        clamp_mss(&mut inner, MSS_IPV4);
        Outbound::Mesh(wrap(&inner, &self.ours, &route.addr))
    }

    /// Decide a packet from the mesh: a reply from the selected exit is
    /// delivered only if it belongs to a flow an app opened (see the module
    /// docs); any other IPv4-in-IPv6 is dropped.
    pub fn inbound(&self, packet: &[u8]) -> Inbound {
        if !is_ipip(packet) {
            return Inbound::NotTunnel;
        }
        let route = self.route.read().unwrap();
        let Some(inner) = route.as_ref().and_then(|r| unwrap(packet, &r.addr)) else {
            return Inbound::Drop;
        };
        if inner[16..20] != self.inner || later_fragment(inner) || !self.admits(inner) {
            return Inbound::Drop;
        }
        let mut out = inner.to_vec();
        // The far end's SYN-ACK sets what the app may send: clamp it too, or
        // the app's segments, once wrapped, outgrow the mesh.
        clamp_mss(&mut out, MSS_IPV4);
        Inbound::Deliver(out)
    }

    /// True if `inner` (a well-formed first-fragment IPv4 packet to us)
    /// answers a flow in the table: TCP or UDP by its reversed ports, an
    /// echo reply by its identifier, an ICMP error (destination unreachable,
    /// time exceeded, parameter problem) by the packet it quotes, which must
    /// be one this phone sent. Any other ICMP is dropped.
    ///
    /// Nothing here refreshes a flow: only what the apps send does
    /// ([`Self::outbound`]). The sender on this path is the exit, and a
    /// table it could keep alive by sending would let it hold a port open
    /// after the app closed its socket, for whichever app binds it next.
    fn admits(&self, inner: &[u8]) -> bool {
        let ihl = usize::from(inner[0] & 0x0f) * 4;
        let Some(l4) = inner.get(ihl..) else {
            return false;
        };
        let remote_addr = mapped(&inner[12..16]);
        let port = |at: usize| l4.get(at..at + 2).map(|p| u16::from_be_bytes([p[0], p[1]]));
        match inner[9] {
            proto @ (PROTO_TCP | PROTO_UDP) => {
                let (Some(sport), Some(dport)) = (port(0), port(2)) else {
                    return false;
                };
                self.flows.contains(&FlowKey {
                    proto,
                    local_port: dport,
                    remote_addr,
                    remote_port: sport,
                })
            }
            PROTO_ICMP => match l4.first() {
                Some(0) => port(4).is_some_and(|id| {
                    self.flows.contains(&FlowKey {
                        proto: PROTO_ICMP,
                        local_port: id,
                        remote_addr,
                        remote_port: 0,
                    })
                }),
                Some(3 | 11 | 12) => l4
                    .get(8..)
                    .filter(|quoted| quoted.len() >= 20 && quoted[12..16] == self.inner)
                    .and_then(sent_flow)
                    .is_some_and(|flow| self.flows.contains(&flow)),
                _ => false,
            },
            _ => false,
        }
    }

    /// The exit's resolver did not answer: register its identity with the
    /// node again (it may have been forgotten, or not be known yet), at most
    /// every 5 s.
    pub fn refused(&self) {
        if let Some(npub) = self.selected() {
            let now = unix_secs();
            let last = self.registered_at.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= 5 {
                self.register(npub);
            }
        }
    }

    fn register(&self, npub: String) {
        self.registered_at.store(unix_secs(), Ordering::Relaxed);
        let responder = self.responder;
        let _ = std::thread::Builder::new()
            .name("fips-exit-register".into())
            .spawn(move || crate::meshhttp::register_identity(responder, &npub));
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One's-complement sum over `data` (for checksum checks).
    fn csum(parts: &[&[u8]]) -> u16 {
        let mut sum = 0u32;
        for data in parts {
            for c in data.chunks(2) {
                sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
            }
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An IPv4 packet with a valid header checksum around `l4`; for TCP and
    /// UDP the transport checksum is filled in too.
    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], mut l4: Vec<u8>) -> Vec<u8> {
        let at = match proto {
            PROTO_TCP => Some(16),
            PROTO_UDP => Some(6),
            _ => None,
        };
        if let Some(at) = at {
            l4[at..at + 2].copy_from_slice(&[0, 0]);
            let len = (l4.len() as u16).to_be_bytes();
            let pseudo = [&src[..], &dst[..], &[0, proto, len[0], len[1]]].concat();
            let c = csum(&[&pseudo, &l4]);
            l4[at..at + 2].copy_from_slice(&c.to_be_bytes());
        } else if proto == PROTO_ICMP {
            l4[2..4].copy_from_slice(&[0, 0]);
            let c = csum(&[&l4]);
            l4[2..4].copy_from_slice(&c.to_be_bytes());
        }
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let c = csum(&[&ip]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&l4);
        ip
    }

    /// A TCP header with `flags` and, if given, an MSS option.
    fn tcp(sport: u16, dport: u16, flags: u8, mss: Option<u16>) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        if let Some(mss) = mss {
            t[12] = 6 << 4;
            t.extend_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        }
        t
    }

    fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut u = vec![0u8; 12];
        u[0..2].copy_from_slice(&sport.to_be_bytes());
        u[2..4].copy_from_slice(&dport.to_be_bytes());
        u[4..6].copy_from_slice(&12u16.to_be_bytes());
        u[8..12].copy_from_slice(b"ping");
        u
    }

    fn icmp(kind: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
        [&[kind, 0, 0, 0][..], &rest, body].concat()
    }

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;
    const ACK: u8 = 0x10;
    const SERVER: [u8; 4] = [1, 2, 3, 4];

    /// IPv4 TCP SYN 100.64.0.1 → 1.2.3.4 with an MSS option.
    fn ipv4_syn(mss: u16) -> Vec<u8> {
        ipv4(
            PROTO_TCP,
            [100, 64, 0, 1],
            SERVER,
            tcp(40000, 443, SYN, Some(mss)),
        )
    }

    fn tcp_checksum_ok(pkt: &[u8]) -> bool {
        let tcp = &pkt[20..];
        let pseudo = [&pkt[12..20], &[0, 6, 0, tcp.len() as u8]].concat();
        csum(&[&pseudo, tcp]) == 0
    }

    fn mss_of(pkt: &[u8]) -> u16 {
        u16::from_be_bytes([pkt[42], pkt[43]])
    }

    #[test]
    fn inner_ipv4_is_in_cgnat_range_and_follows_the_formula() {
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[1..4].copy_from_slice(&[0xab, 0xcd, 0xef]);
        // 0xabcdef & 0x3fffff = 0x2bcdef → 0x64400000 | that = 100.107.205.239
        assert_eq!(inner_ipv4(&a), Ipv4Addr::new(100, 107, 205, 239));
        a[1..4].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(inner_ipv4(&a), Ipv4Addr::new(100, 127, 255, 255));
        a[1..4].copy_from_slice(&[0, 0, 0]);
        assert_eq!(inner_ipv4(&a), Ipv4Addr::new(100, 64, 0, 0));
    }

    /// Prints a fresh npub with its fips address and inner IPv4, for checking
    /// `exit-node/exitctl.py` (the exit side's copy of the contract; its vectors are in `exit-node/test_exitctl.py`):
    /// `cargo test exit::tests::print_vector -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn print_vector() {
        let id = fips::Identity::generate();
        let addr = *id.address().as_bytes();
        println!(
            "VECTOR {} {} {}",
            id.npub(),
            std::net::Ipv6Addr::from(addr),
            inner_ipv4(&addr)
        );
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let ours = [0xfd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let exit = [0xfd, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let inner = ipv4_syn(1460);
        let outer = wrap(&inner, &ours, &exit);
        assert_eq!(outer.len(), 40 + inner.len());
        assert_eq!(outer[6], IPPROTO_IPIP);
        // The exit's reply has the addresses the other way round.
        let reply = wrap(&inner, &exit, &ours);
        assert_eq!(unwrap(&reply, &exit), Some(&inner[..]));
        // Not from the exit, not IPv4-in-IPv6, or truncated: not ours.
        assert_eq!(unwrap(&reply, &ours), None);
        let mut udp = reply.clone();
        udp[6] = 17;
        assert_eq!(unwrap(&udp, &exit), None);
        assert_eq!(unwrap(&reply[..reply.len() - 1], &exit), None);
        // An IHL below 5, or a payload too short for an IPv4 header.
        let mut short_ihl = reply.clone();
        short_ihl[40] = 0x44;
        assert_eq!(unwrap(&short_ihl, &exit), None);
        let mut tiny = wrap(&inner[..8], &exit, &ours);
        assert_eq!(unwrap(&tiny, &exit), None);
        tiny[5] = 200; // a payload length past the end
        assert_eq!(unwrap(&tiny, &exit), None);
    }

    #[test]
    fn clamp_lowers_mss_and_keeps_the_checksum_valid() {
        let mut syn = ipv4_syn(1460);
        assert!(tcp_checksum_ok(&syn));
        clamp_mss(&mut syn, 1200);
        assert_eq!(mss_of(&syn), 1200);
        assert!(tcp_checksum_ok(&syn));
        // Already below: untouched.
        let mut small = ipv4_syn(1000);
        let before = small.clone();
        clamp_mss(&mut small, 1200);
        assert_eq!(small, before);
        // Not a SYN: untouched.
        let mut ack = ipv4_syn(1460);
        ack[33] = ACK;
        let before = ack.clone();
        clamp_mss(&mut ack, 1200);
        assert_eq!(ack, before);
    }

    struct Setup {
        sw: ExitSwitch,
        exit: [u8; 16],
        npub: String,
        /// The tunnel's IPv4 address: the inner address.
        me: [u8; 4],
    }

    fn switch() -> Setup {
        let ours = *fips::Identity::generate().address().as_bytes();
        let exit_id = fips::Identity::generate();
        let sw = ExitSwitch::new(ours, "[::1]:9".parse().unwrap());
        let me = sw.inner().octets();
        Setup {
            sw,
            exit: *exit_id.address().as_bytes(),
            npub: exit_id.npub(),
            me,
        }
    }

    fn selected() -> Setup {
        let s = switch();
        s.sw.set(Some(&s.npub)).unwrap();
        s
    }

    impl Setup {
        /// Send `pkt` (from the app) and expect it to go to the exit.
        fn send(&self, pkt: &[u8]) -> Vec<u8> {
            match self.sw.outbound(pkt) {
                Outbound::Mesh(outer) => {
                    assert_eq!(&outer[24..40], &self.exit[..]);
                    outer[40..].to_vec()
                }
                other => panic!("expected the exit, got {other:?}"),
            }
        }

        /// `inner` as the exit would send it to us.
        fn reply(&self, inner: &[u8]) -> Inbound {
            self.sw.inbound(&wrap(inner, &self.exit, &self.sw.ours))
        }
    }

    #[test]
    fn no_exit_means_the_forwarder() {
        let s = switch();
        assert_eq!(s.sw.outbound(&ipv4_syn(1460)), Outbound::Forwarder);
        assert_eq!(s.sw.selected(), None);
    }

    #[test]
    fn a_bad_npub_or_our_own_is_an_error_and_selects_nothing() {
        let s = switch();
        assert!(s.sw.set(Some("npub1nonsense")).is_err());
        assert_eq!(s.sw.outbound(&ipv4_syn(1460)), Outbound::Forwarder);

        let id = fips::Identity::generate();
        let own = ExitSwitch::new(*id.address().as_bytes(), "[::1]:9".parse().unwrap());
        assert!(own.set(Some(&id.npub())).is_err());
        assert_eq!(own.selected(), None);
    }

    #[test]
    fn with_an_exit_ipv4_is_wrapped_unchanged_but_clamped_and_ipv6_is_refused() {
        let s = selected();
        assert_eq!(s.sw.selected(), Some(s.npub.clone()));

        // The app sends from the tunnel's address, which is the inner one:
        // nothing is rewritten, only the MSS lowered.
        let syn = ipv4(PROTO_TCP, s.me, SERVER, tcp(40000, 443, SYN, Some(1460)));
        let inner = s.send(&syn);
        assert_eq!(&inner[12..20], &syn[12..20]);
        assert_eq!(mss_of(&inner), MSS_IPV4);
        assert!(tcp_checksum_ok(&inner));

        // A SYN-ACK offering 1460 comes back clamped as well.
        let synack = ipv4(
            PROTO_TCP,
            SERVER,
            s.me,
            tcp(443, 40000, SYN_ACK, Some(1460)),
        );
        let Inbound::Deliver(back) = s.reply(&synack) else {
            panic!("the SYN-ACK of a flow the app opened");
        };
        assert_eq!(mss_of(&back), MSS_IPV4);
        assert!(tcp_checksum_ok(&back));

        // Not from the tunnel's address, or malformed: refused, unanswered.
        let other_src = ipv4(
            PROTO_TCP,
            [10, 111, 222, 1],
            SERVER,
            tcp(40000, 443, SYN, None),
        );
        assert_eq!(s.sw.outbound(&other_src), Outbound::Refuse(None));
        let mut bad_ihl = syn.clone();
        bad_ihl[0] = 0x44;
        assert_eq!(s.sw.outbound(&bad_ihl), Outbound::Refuse(None));

        // IPv6 internet traffic does not go around the exit.
        let v6 = crate::packet::build_ipv6_udp([0x20; 16], [0x26; 16], 1, 2, b"x");
        let Outbound::Refuse(Some(icmp)) = s.sw.outbound(&v6) else {
            panic!("IPv6 internet traffic must be refused with an ICMPv6 error");
        };
        // From the address the app tried, to the app, type 1 code 1, and a
        // checksum that verifies over the pseudo-header.
        assert_eq!(&icmp[8..24], &v6[24..40]);
        assert_eq!(&icmp[24..40], &v6[8..24]);
        assert_eq!((icmp[6], icmp[40], icmp[41]), (58, 1, 1));
        let len = (icmp.len() - 40) as u32;
        let pseudo = [&icmp[8..40], &len.to_be_bytes()[..], &[0, 0, 0, 58][..]].concat();
        assert_eq!(csum(&[&pseudo, &icmp[40..]]), 0);
        // An ICMPv6 error is never answered with another.
        assert_eq!(icmpv6_prohibited(&icmp), None);

        // Back to the phone's connection.
        s.sw.set(None).unwrap();
        assert_eq!(s.sw.outbound(&syn), Outbound::Forwarder);
        assert_eq!(s.reply(&synack), Inbound::Drop);
    }

    #[test]
    fn an_unsolicited_connection_from_the_exit_is_dropped() {
        let s = selected();
        // A SYN to a port an app listens on, from anywhere, as the exit's
        // operator could send it: nothing on the phone asked for it.
        let syn = ipv4(
            PROTO_TCP,
            [5, 6, 7, 8],
            s.me,
            tcp(50000, 8080, SYN, Some(1460)),
        );
        assert_eq!(s.reply(&syn), Inbound::Drop);
        let dgram = ipv4(PROTO_UDP, [5, 6, 7, 8], s.me, udp(53, 5353));
        assert_eq!(s.reply(&dgram), Inbound::Drop);
        let ping = ipv4(PROTO_ICMP, [5, 6, 7, 8], s.me, icmp(8, [0, 7, 0, 1], b"x"));
        assert_eq!(s.reply(&ping), Inbound::Drop);
        // The same from any other node, or IPv4-in-IPv6 with no exit at all.
        let stranger = [0xfd; 16];
        assert_eq!(
            s.sw.inbound(&wrap(&syn, &stranger, &s.sw.ours)),
            Inbound::Drop
        );
        s.sw.set(None).unwrap();
        assert_eq!(s.reply(&syn), Inbound::Drop);
        // Anything that is not IPv4-in-IPv6 is not the exit's to decide.
        let mesh = crate::packet::build_ipv6_udp(s.exit, s.sw.ours, 1, 2, b"x");
        assert_eq!(s.sw.inbound(&mesh), Inbound::NotTunnel);
    }

    #[test]
    fn replies_pass_only_for_the_flow_the_app_opened() {
        let s = selected();
        s.send(&ipv4(PROTO_TCP, s.me, SERVER, tcp(40000, 443, SYN, None)));
        s.send(&ipv4(PROTO_UDP, s.me, SERVER, udp(41000, 53)));

        let reply = ipv4(PROTO_TCP, SERVER, s.me, tcp(443, 40000, ACK, None));
        assert!(matches!(s.reply(&reply), Inbound::Deliver(p) if p == reply));
        let answer = ipv4(PROTO_UDP, SERVER, s.me, udp(53, 41000));
        assert!(matches!(s.reply(&answer), Inbound::Deliver(_)));

        // Another port on our side, another remote port, another remote, the
        // other protocol: none of them is the flow.
        for (proto, src, sport, dport) in [
            (PROTO_TCP, SERVER, 443, 40001),
            (PROTO_TCP, SERVER, 444, 40000),
            (PROTO_TCP, [1, 2, 3, 5], 443, 40000),
            (PROTO_UDP, SERVER, 443, 40000),
        ] {
            let l4 = if proto == PROTO_TCP {
                tcp(sport, dport, ACK, None)
            } else {
                udp(sport, dport)
            };
            assert_eq!(s.reply(&ipv4(proto, src, s.me, l4)), Inbound::Drop);
        }
        // Addressed to another inner address: not ours.
        let elsewhere = ipv4(
            PROTO_TCP,
            SERVER,
            [100, 64, 0, 9],
            tcp(443, 40000, ACK, None),
        );
        assert_eq!(s.reply(&elsewhere), Inbound::Drop);
    }

    #[test]
    fn a_reply_after_the_idle_limit_is_dropped() {
        let s = selected();
        s.send(&ipv4(PROTO_UDP, s.me, SERVER, udp(41000, 53)));
        s.send(&ipv4(PROTO_TCP, s.me, SERVER, tcp(40000, 443, SYN, None)));
        s.sw.flows
            .backdate(crate::filter::UDP_IDLE + Duration::from_secs(1));
        // UDP has expired; TCP's limit is longer and has not.
        assert_eq!(
            s.reply(&ipv4(PROTO_UDP, SERVER, s.me, udp(53, 41000))),
            Inbound::Drop
        );
        let tcp_reply = ipv4(PROTO_TCP, SERVER, s.me, tcp(443, 40000, ACK, None));
        assert!(matches!(s.reply(&tcp_reply), Inbound::Deliver(_)));
        s.sw.flows
            .backdate(crate::filter::TCP_IDLE + Duration::from_secs(1));
        assert_eq!(s.reply(&tcp_reply), Inbound::Drop);
    }

    /// The exit cannot keep a flow alive by sending on it: only the app's
    /// own packets refresh it.
    #[test]
    fn replies_do_not_keep_a_flow_alive() {
        let s = selected();
        let query = ipv4(PROTO_UDP, s.me, SERVER, udp(41000, 53));
        let answer = ipv4(PROTO_UDP, SERVER, s.me, udp(53, 41000));
        s.send(&query);
        // Two thirds of the limit pass, twice, with a reply in between.
        let step = crate::filter::UDP_IDLE * 2 / 3;
        s.sw.flows.backdate(step);
        assert!(matches!(s.reply(&answer), Inbound::Deliver(_)));
        s.sw.flows.backdate(step);
        assert_eq!(s.reply(&answer), Inbound::Drop, "the reply did not refresh it");
        // The app sending again does.
        s.send(&query);
        s.sw.flows.backdate(step);
        assert!(matches!(s.reply(&answer), Inbound::Deliver(_)));
    }

    #[test]
    fn icmp_passes_only_for_an_echo_or_a_flow_the_app_opened() {
        let s = selected();
        let ping = ipv4(PROTO_ICMP, s.me, SERVER, icmp(8, [0, 7, 0, 1], b"x"));
        s.send(&ping);
        let pong = ipv4(PROTO_ICMP, SERVER, s.me, icmp(0, [0, 7, 0, 1], b"x"));
        assert!(matches!(s.reply(&pong), Inbound::Deliver(_)));
        let other_id = ipv4(PROTO_ICMP, SERVER, s.me, icmp(0, [0, 8, 0, 1], b"x"));
        assert_eq!(s.reply(&other_id), Inbound::Drop);

        // Errors quoting a packet the app sent, from a router on the way.
        let syn = ipv4(PROTO_TCP, s.me, SERVER, tcp(40000, 443, SYN, None));
        s.send(&syn);
        let router = [9, 9, 9, 9];
        for kind in [3, 11, 12] {
            let err = ipv4(PROTO_ICMP, router, s.me, icmp(kind, [0; 4], &syn[..28]));
            assert!(matches!(s.reply(&err), Inbound::Deliver(_)), "type {kind}");
        }
        let echo_err = ipv4(PROTO_ICMP, router, s.me, icmp(11, [0; 4], &ping[..28]));
        assert!(matches!(s.reply(&echo_err), Inbound::Deliver(_)));

        // Quoting a flow nobody opened, or a packet not from us.
        let unknown = ipv4(PROTO_TCP, s.me, SERVER, tcp(40001, 443, SYN, None));
        let err = ipv4(PROTO_ICMP, router, s.me, icmp(3, [0; 4], &unknown[..28]));
        assert_eq!(s.reply(&err), Inbound::Drop);
        let not_ours = ipv4(
            PROTO_TCP,
            [100, 64, 0, 9],
            SERVER,
            tcp(40000, 443, SYN, None),
        );
        let err = ipv4(PROTO_ICMP, router, s.me, icmp(3, [0; 4], &not_ours[..28]));
        assert_eq!(s.reply(&err), Inbound::Drop);
        // Quoting too little to know the flow.
        let err = ipv4(PROTO_ICMP, router, s.me, icmp(3, [0; 4], &syn[..24]));
        assert_eq!(s.reply(&err), Inbound::Drop);
        // Any other ICMP: a redirect, a timestamp, an echo request.
        for kind in [5, 13, 8] {
            let other = ipv4(
                PROTO_ICMP,
                SERVER,
                s.me,
                icmp(kind, [0, 7, 0, 1], &syn[..28]),
            );
            assert_eq!(s.reply(&other), Inbound::Drop, "type {kind}");
        }
    }

    #[test]
    fn later_fragments_and_short_headers_are_dropped() {
        let s = selected();
        s.send(&ipv4(PROTO_UDP, s.me, SERVER, udp(41000, 53)));
        let answer = ipv4(PROTO_UDP, SERVER, s.me, udp(53, 41000));
        // A first fragment (more-fragments set, offset 0) has its ports.
        let mut first = answer.clone();
        first[6] = 0x20;
        assert!(matches!(s.reply(&first), Inbound::Deliver(_)));
        // A later one has none, whatever its first bytes look like.
        let mut later = answer.clone();
        later[6..8].copy_from_slice(&[0x00, 0x10]);
        assert_eq!(s.reply(&later), Inbound::Drop);
        // IHL below 5: never read as ports.
        let mut short = answer.clone();
        short[0] = 0x44;
        assert_eq!(s.reply(&short), Inbound::Drop);
    }

    #[test]
    fn switching_exits_empties_the_flow_table() {
        let s = selected();
        s.send(&ipv4(PROTO_TCP, s.me, SERVER, tcp(40000, 443, SYN, None)));
        assert_eq!(s.sw.flows.len(), 1);
        // Selecting the same exit again changes nothing.
        s.sw.set(Some(&s.npub)).unwrap();
        assert_eq!(s.sw.flows.len(), 1);
        let other = fips::Identity::generate();
        s.sw.set(Some(&other.npub())).unwrap();
        assert_eq!(s.sw.flows.len(), 0);
        // So the new exit cannot answer the old exit's flow.
        let reply = ipv4(PROTO_TCP, SERVER, s.me, tcp(443, 40000, ACK, None));
        let from_new = wrap(&reply, other.address().as_bytes(), &s.sw.ours);
        assert_eq!(s.sw.inbound(&from_new), Inbound::Drop);
        s.sw.set(None).unwrap();
        assert_eq!(s.sw.flows.len(), 0);
    }

    /// The premise of the whole feature: fips carries an IPv4-in-IPv6 packet
    /// (next header 4) between two nodes unchanged. Two in-process nodes
    /// over loopback UDP, as in the smoke test.
    #[test]
    fn fips_carries_ipv4_in_ipv6_between_nodes() {
        use fips::identity::encode_nsec;
        use std::time::{Duration, Instant};

        fn config(
            id: &fips::Identity,
            port: u16,
            peer: Option<fips::config::PeerConfig>,
        ) -> fips::Config {
            let mut c = fips::Config::new();
            c.node.identity.nsec = Some(encode_nsec(&id.keypair().secret_key()));
            c.transports.udp = fips::config::TransportInstances::Single(fips::config::UdpConfig {
                bind_addr: Some(format!("127.0.0.1:{port}")),
                ..Default::default()
            });
            c.tun.enabled = true;
            c.dns.enabled = false;
            c.node.control.enabled = false;
            c.peers.extend(peer);
            c
        }
        let free_port = || {
            std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let (port_a, port_b) = (free_port(), free_port());
        let id_a = fips::Identity::generate();
        let id_b = fips::Identity::generate();
        let addr_a = *id_a.address().as_bytes();
        let addr_b = *id_b.address().as_bytes();
        let peer = fips::config::PeerConfig::new(id_a.npub(), "udp", format!("127.0.0.1:{port_a}"));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let delivered = rt.block_on(async move {
            let mut a = fips::Node::new(config(&id_a, port_a, None)).unwrap();
            let mut b = fips::Node::new(config(&id_b, port_b, Some(peer))).unwrap();
            let (a_out, _a_in) = a.enable_app_owned_tun();
            let (_b_out, b_in) = b.enable_app_owned_tun();
            a.start().await.unwrap();
            b.start().await.unwrap();

            let inner = ipv4_syn(1460);
            let outer = wrap(&inner, &addr_a, &addr_b);
            let processor = a.tun_packet_processor();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<bool>();
            let expect = outer.clone();
            let receiver = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    if let Ok(pkt) = b_in.recv_timeout(Duration::from_millis(200))
                        && unwrap(&pkt, &addr_a).is_some()
                    {
                        let _ = done_tx.send(pkt == expect);
                        return;
                    }
                }
                let _ = done_tx.send(false);
            });
            let sender = tokio::spawn(async move {
                loop {
                    let mut pkt = outer.clone();
                    match processor.process(&mut pkt) {
                        fips::TunPacketAction::Forward => {
                            if a_out.send(pkt).await.is_err() {
                                return;
                            }
                        }
                        other => panic!("processor must forward IPv4-in-IPv6, got {other:?}"),
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });
            let (stop_a, stop_a_rx) = tokio::sync::oneshot::channel::<()>();
            let (stop_b, stop_b_rx) = tokio::sync::oneshot::channel::<()>();
            let loops = async {
                tokio::join!(
                    a.run_rx_loop_with_shutdown(async {
                        let _ = stop_a_rx.await;
                    }),
                    b.run_rx_loop_with_shutdown(async {
                        let _ = stop_b_rx.await;
                    }),
                )
            };
            let supervise = async {
                let ok = done_rx.await.unwrap_or(false);
                let _ = stop_a.send(());
                let _ = stop_b.send(());
                ok
            };
            let (_, ok) = tokio::join!(loops, supervise);
            sender.abort();
            a.finish_shutdown().await;
            b.finish_shutdown().await;
            receiver.join().unwrap();
            ok
        });
        assert!(
            delivered,
            "IPv4-in-IPv6 packet did not arrive intact at node B"
        );
    }
}
