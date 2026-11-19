//! Exit nodes: a selected app's internet traffic carried over fips to an exit
//! node, which sends it on to the internet, instead of leaving through the
//! phone's own connection (the userspace forwarder).
//!
//! fips only delivers packets addressed to `fd00::/8`, so an app's IPv4 packet
//! is carried inside an IPv6 packet from this node's address to the exit's
//! (IPv4-in-IPv6, next header 4 — what Linux's `ip6tnl` speaks, so the exit
//! needs no program of its own: a tunnel per client and a NAT). Replies come
//! back the same way and are unwrapped before the TUN. Only IPv4 goes through
//! an exit: a wrapped IPv6 packet carrying QUIC's 1200-byte minimum would not
//! fit the mesh.
//!
//! Each phone sends from its own inner address in `100.64.0.0/10`, derived
//! from its node address ([`inner_ipv4`]) so the exit can compute it from the
//! npub with nothing negotiated and two phones never collide in its NAT.
//! The formula is the contract with the exit side; do not change it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// IPv6 next header for an encapsulated IPv4 packet.
pub const IPPROTO_IPIP: u8 = 4;
const IPV6_HEADER: usize = 40;
const HOP_LIMIT: u8 = 64;

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

/// The IPv4 packet inside `packet`, if it is one wrapped by the exit at `exit`
/// for this node: IPv6 from `exit`, next header 4, a well-formed IPv4 packet
/// inside. Anything else — another node, another protocol — is `None` and
/// takes the normal inbound path.
pub fn unwrap<'a>(packet: &'a [u8], exit: &[u8; 16]) -> Option<&'a [u8]> {
    if packet.len() < IPV6_HEADER + 20
        || packet[0] >> 4 != 6
        || packet[6] != IPPROTO_IPIP
        || packet[8..24] != exit[..]
    {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let inner = packet.get(IPV6_HEADER..IPV6_HEADER + len)?;
    let total = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    if !is_ipv4(inner) || total < 20 || total > inner.len() {
        return None;
    }
    Some(&inner[..total])
}

/// Largest TCP MSS an inner IPv4 packet may carry through an exit when the
/// node admits IPv6 packets of up to `ipv6_mtu` bytes (outer IPv6 header,
/// inner IPv4 header, TCP header).
pub fn mss_ceiling(ipv6_mtu: u16) -> u16 {
    ipv6_mtu.saturating_sub(40 + 20 + 20)
}

/// Lower the MSS option of an IPv4 TCP SYN to `max`, fixing the TCP checksum
/// (RFC 1624 incremental update). The app then never sends a segment the
/// mesh would refuse once wrapped — the same job fips's own clamp does for
/// mesh-bound IPv6. Anything else is left alone.
pub fn clamp_mss(packet: &mut [u8], max: u16) {
    if !is_ipv4(packet) || packet[9] != 6 {
        return;
    }
    // A non-first fragment carries no TCP header.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0 {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
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

/// One's-complement update of a 16-bit checksum for `old` → `new` words
/// (RFC 1624, eqn. 3).
fn update_checksum(sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = u32::from(!sum);
    for (o, n) in old.chunks(2).zip(new.chunks(2)) {
        acc += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        acc += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Replace the IPv4 source (`at` = 12) or destination (`at` = 16) address,
/// fixing the header checksum and, in a first fragment, the TCP or UDP
/// checksum (both cover the address through the pseudo-header; ICMP does
/// not). A UDP checksum of zero means "none" and stays zero.
fn rewrite_ipv4_addr(packet: &mut [u8], at: usize, new: [u8; 4]) {
    let old: [u8; 4] = packet[at..at + 4].try_into().unwrap();
    if old == new {
        return;
    }
    packet[at..at + 4].copy_from_slice(&new);
    let hc = update_checksum(u16::from_be_bytes([packet[10], packet[11]]), &old, &new);
    packet[10..12].copy_from_slice(&hc.to_be_bytes());
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0 {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    let off = match packet[9] {
        6 => ihl + 16,
        17 => ihl + 6,
        _ => return,
    };
    let Some(field) = packet.get(off..off + 2) else {
        return;
    };
    let sum = u16::from_be_bytes([field[0], field[1]]);
    if packet[9] == 17 && sum == 0 {
        return;
    }
    let mut c = update_checksum(sum, &old, &new);
    if packet[9] == 17 && c == 0 {
        c = 0xffff;
    }
    packet[off..off + 2].copy_from_slice(&c.to_be_bytes());
}

/// What the reader does with a packet that is not for the mesh.
#[derive(Debug, PartialEq)]
pub enum Outbound {
    /// No exit selected: the phone's own connection (the forwarder).
    Forwarder,
    /// Wrapped for the exit; hand it to the node.
    Mesh(Vec<u8>),
    /// An exit is selected but this cannot go through it (IPv6): refused,
    /// so nothing leaves around the exit. Carries the ICMPv6 "administratively
    /// prohibited" to write back to the app, so it falls back to IPv4 at once
    /// instead of waiting out a connect timeout (`None` for a packet that
    /// must not be answered: an ICMPv6 error itself, or garbage).
    Refuse(Option<Vec<u8>>),
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
    mss: u16,
    /// The IPv4 source the apps use (the tunnel's address), learned from
    /// outbound packets: replies are rewritten back to it.
    tun_src: AtomicU32,
    /// The local `.fips` responder, asked to register the exit's identity.
    responder: SocketAddr,
    /// Unix seconds of the last registration (rate limit for [`Self::refused`]).
    registered_at: AtomicU64,
}

impl ExitSwitch {
    /// `ipv6_mtu` is the node's effective IPv6 MTU (`Node::effective_ipv6_mtu`).
    pub fn new(ours: [u8; 16], ipv6_mtu: u16, responder: SocketAddr) -> Self {
        Self {
            route: RwLock::new(None),
            ours,
            inner: inner_ipv4(&ours).octets(),
            mss: mss_ceiling(ipv6_mtu),
            tun_src: AtomicU32::new(0),
            responder,
            registered_at: AtomicU64::new(0),
        }
    }

    /// Select the exit with this npub, or none (`None`/empty: the phone's own
    /// connection). Registers the exit's identity with the node in the
    /// background. An npub that does not parse selects nothing and is an
    /// error, so a typo never silently sends traffic out of the phone.
    pub fn set(&self, npub: Option<&str>) -> Result<(), String> {
        let npub = npub.map(str::trim).filter(|n| !n.is_empty());
        let route = match npub {
            None => None,
            Some(n) => {
                let peer = fips::identity::PeerIdentity::from_npub(n)
                    .map_err(|e| format!("exit node npub: {e}"))?;
                Some(Route {
                    npub: peer.npub(),
                    addr: *peer.address().as_bytes(),
                })
            }
        };
        let changed = {
            let current = self.route.read().unwrap();
            current.as_ref().map(|r| &r.npub) != route.as_ref().map(|r| &r.npub)
        };
        if changed {
            match &route {
                Some(r) => {
                    tracing::info!(exit = %r.npub, "internet traffic now goes through the exit node")
                }
                None => tracing::info!("internet traffic now goes through the phone's connection"),
            }
        }
        let register = route.as_ref().map(|r| r.npub.clone());
        *self.route.write().unwrap() = route;
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

    /// This node's inner IPv4 address (what the exit sees as the source).
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
        let mut inner = packet.to_vec();
        let src = u32::from_be_bytes(inner[12..16].try_into().unwrap());
        if src != u32::from_be_bytes(self.inner) {
            self.tun_src.store(src, Ordering::Relaxed);
        }
        rewrite_ipv4_addr(&mut inner, 12, self.inner);
        clamp_mss(&mut inner, self.mss);
        Outbound::Mesh(wrap(&inner, &self.ours, &route.addr))
    }

    /// The app-side packet inside a reply from the selected exit, addressed
    /// back to the tunnel's IPv4 address; `None` for anything else.
    pub fn inbound(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let route = self.route.read().unwrap();
        let inner = unwrap(packet, &route.as_ref()?.addr)?;
        if inner[16..20] != self.inner {
            return None;
        }
        let mut out = inner.to_vec();
        let tun = self.tun_src.load(Ordering::Relaxed);
        if tun != 0 {
            rewrite_ipv4_addr(&mut out, 16, tun.to_be_bytes());
        }
        // The far end's SYN-ACK sets what the app may send: clamp it too, or
        // the app's segments, once wrapped, outgrow the mesh.
        clamp_mss(&mut out, self.mss);
        Some(out)
    }

    /// The node refused a packet for the exit (it does not know the
    /// identity, or has no route yet): register it again, at most every 5 s.
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

    /// IPv4 TCP SYN 100.64.0.1 → 1.2.3.4 with an MSS option and a valid
    /// TCP checksum.
    fn ipv4_syn(mss: u16) -> Vec<u8> {
        let src = [100, 64, 0, 1];
        let dst = [1, 2, 3, 4];
        let mut tcp = vec![0u8; 24];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 6 << 4; // data offset 24
        tcp[13] = 0x02; // SYN
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..24].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        let pseudo = [&src[..], &dst[..], &[0, 6, 0, tcp.len() as u8]].concat();
        let c = csum(&[&pseudo, &tcp]);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());

        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0];
        ip[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let c = csum(&[&ip]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&tcp);
        ip
    }

    fn tcp_checksum_ok(pkt: &[u8]) -> bool {
        let tcp = &pkt[20..];
        let pseudo = [&pkt[12..20], &[0, 6, 0, tcp.len() as u8]].concat();
        csum(&[&pseudo, tcp]) == 0
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
    }

    #[test]
    fn clamp_lowers_mss_and_keeps_the_checksum_valid() {
        let mut syn = ipv4_syn(1460);
        assert!(tcp_checksum_ok(&syn));
        clamp_mss(&mut syn, 1200);
        assert_eq!(u16::from_be_bytes([syn[42], syn[43]]), 1200);
        assert!(tcp_checksum_ok(&syn));
        // Already below: untouched.
        let mut small = ipv4_syn(1000);
        let before = small.clone();
        clamp_mss(&mut small, 1200);
        assert_eq!(small, before);
        // Not a SYN: untouched.
        let mut ack = ipv4_syn(1460);
        ack[33] = 0x10;
        let before = ack.clone();
        clamp_mss(&mut ack, 1200);
        assert_eq!(ack, before);
    }

    fn ipv4_checksum_ok(pkt: &[u8]) -> bool {
        csum(&[&pkt[..20]]) == 0
    }

    fn switch() -> (ExitSwitch, [u8; 16], String) {
        let ours = *fips::Identity::generate().address().as_bytes();
        let exit_id = fips::Identity::generate();
        let sw = ExitSwitch::new(ours, 1395, "[::1]:9".parse().unwrap());
        (sw, *exit_id.address().as_bytes(), exit_id.npub())
    }

    #[test]
    fn no_exit_means_the_forwarder() {
        let (sw, _, _) = switch();
        assert_eq!(sw.outbound(&ipv4_syn(1460)), Outbound::Forwarder);
        assert_eq!(sw.selected(), None);
    }

    #[test]
    fn a_bad_npub_is_an_error_and_selects_nothing() {
        let (sw, _, _) = switch();
        assert!(sw.set(Some("npub1nonsense")).is_err());
        assert_eq!(sw.outbound(&ipv4_syn(1460)), Outbound::Forwarder);
    }

    #[test]
    fn with_an_exit_ipv4_is_wrapped_and_ipv6_is_dropped() {
        let (sw, exit, npub) = switch();
        sw.set(Some(&npub)).unwrap();
        assert_eq!(sw.selected(), Some(npub));

        // The app's packet leaves from the tunnel address 10.111.222.1.
        let mut app = ipv4_syn(1460);
        rewrite_ipv4_addr(&mut app, 12, [10, 111, 222, 1]);
        assert!(ipv4_checksum_ok(&app) && tcp_checksum_ok(&app));
        let Outbound::Mesh(outer) = sw.outbound(&app) else {
            panic!("IPv4 must go to the exit");
        };
        assert_eq!(&outer[24..40], &exit[..]);
        let inner = &outer[40..];
        assert_eq!(&inner[12..16], &sw.inner().octets()[..]);
        assert!(ipv4_checksum_ok(inner) && tcp_checksum_ok(inner));
        assert_eq!(
            u16::from_be_bytes([inner[42], inner[43]]),
            mss_ceiling(1395)
        );

        // The exit's reply (addresses swapped) comes back to 10.111.222.1.
        let mut reply = inner.to_vec();
        let (src, dst) = (reply[12..16].to_vec(), reply[16..20].to_vec());
        reply[12..16].copy_from_slice(&dst);
        reply[16..20].copy_from_slice(&src);
        let from_exit = wrap(&reply, &exit, &[0; 16]);
        let back = sw.inbound(&from_exit).expect("reply from the exit");
        assert_eq!(&back[16..20], &[10, 111, 222, 1]);
        assert!(ipv4_checksum_ok(&back) && tcp_checksum_ok(&back));
        // A SYN-ACK offering 1460 comes back clamped as well.
        let mut synack = ipv4_syn(1460);
        rewrite_ipv4_addr(&mut synack, 12, [1, 2, 3, 4]);
        rewrite_ipv4_addr(&mut synack, 16, sw.inner().octets());
        synack[33] = 0x12; // SYN+ACK
        let ack_fix = {
            let tcp = &synack[20..];
            let pseudo = [&synack[12..20], &[0, 6, 0, tcp.len() as u8]].concat();
            let mut t = tcp.to_vec();
            t[16..18].copy_from_slice(&[0, 0]);
            csum(&[&pseudo, &t])
        };
        synack[36..38].copy_from_slice(&ack_fix.to_be_bytes());
        let back = sw
            .inbound(&wrap(&synack, &exit, &[0; 16]))
            .expect("SYN-ACK");
        assert_eq!(u16::from_be_bytes([back[42], back[43]]), mss_ceiling(1395));
        assert!(tcp_checksum_ok(&back));

        // IPv6 internet traffic does not go around the exit.
        let v6 = crate::packet::build_ipv6_udp([0x20; 16], [0x26; 16], 1, 2, b"x");
        let Outbound::Refuse(Some(icmp)) = sw.outbound(&v6) else {
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
        sw.set(None).unwrap();
        assert_eq!(sw.outbound(&app), Outbound::Forwarder);
        assert_eq!(sw.inbound(&from_exit), None);
    }

    #[test]
    fn udp_checksum_follows_the_rewrite_and_zero_stays_zero() {
        let src = [10, 111, 222, 1];
        let dst = [9, 9, 9, 9];
        let mut udp = vec![0u8; 12];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        udp[8..12].copy_from_slice(b"ping");
        let pseudo = [&src[..], &dst[..], &[0, 17, 0, 12]].concat();
        let c = csum(&[&pseudo, &udp]);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        let mut ip = vec![0x45, 0, 0, 32, 0, 0, 0x40, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let c = csum(&[&ip]);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&udp);

        let mut pkt = ip.clone();
        rewrite_ipv4_addr(&mut pkt, 12, [100, 99, 1, 2]);
        let pseudo = [&pkt[12..20], &[0, 17, 0, 12]].concat();
        assert!(ipv4_checksum_ok(&pkt));
        assert_eq!(csum(&[&pseudo, &pkt[20..]]), 0);

        let mut none = ip.clone();
        none[26..28].copy_from_slice(&[0, 0]);
        rewrite_ipv4_addr(&mut none, 12, [100, 99, 1, 2]);
        assert_eq!(&none[26..28], &[0, 0]);
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
