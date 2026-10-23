//! In-process HTTP GET to a mesh node — the "Mesh names" sync from a node
//! running fips-ui (its `/api/hosts`, served on the node's fips0 address).
//!
//! The app cannot simply open a socket to an `fd00::/8` address: with mesh
//! apps selected, fips2go's own UID is outside its tunnel (see
//! `FipsVpnService.establishTunnel` for why it must stay out), and a VPN
//! network refuses `bindSocket` from a UID it does not cover. So the request
//! never touches the kernel: a small userspace TCP stack (smoltcp) speaks
//! from the node's own address, its packets go through the node's
//! `TunPacketProcessor` exactly like an app's, and the pump's bridge hands
//! the replies back through [`Divert`] instead of writing them to the TUN.
//!
//! The same property fips-ui relies on holds here: FIPS delivers packets for
//! a node's fips0 address only to that node's npub, so the answer is genuine,
//! and the far side sees this node's address, i.e. its npub.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fips::{TunPacketAction, TunPacketProcessor};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// Tunnel MTU (the smoltcp interface sends nothing bigger).
const MTU: usize = 1280;
/// Largest response body accepted. A fips-ui `/api/hosts` answer carries at
/// most 2000 names three times over (effective, local, synced): well under.
const MAX_BODY: usize = 4 << 20;
/// Local ports for in-process flows: above Linux's ephemeral range
/// (32768–60999), so a kernel-chosen app port never shares a flow key.
const LOCAL_PORTS: std::ops::RangeInclusive<u16> = 61000..=65535;
/// ICMPv6 "destination unreachable" replies to our SYN before giving up.
/// The first can be a race (the identity registration and the SYN reach the
/// node on different channels), the node's SYN retransmits settle it.
const UNREACHABLE_LIMIT: usize = 3;

/// What the engine lends a request: the node's outbound pipeline and the
/// reply tap. Cloned out of the engine so no lock is held while fetching.
pub struct MeshLink {
    pub our_addr: Ipv6Addr,
    pub processor: TunPacketProcessor,
    pub outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub divert: Arc<Divert>,
    /// The in-process `.fips` responder: asking it for `<npub>.fips` is what
    /// registers the destination's identity with the node.
    pub responder: SocketAddr,
    /// The engine's `running` flag. A rebind replaces the whole engine, and
    /// a request still holding this link would otherwise sit out its full
    /// timeout (the replies now reach the new engine's divert) and report
    /// the node as unreachable.
    pub running: Arc<AtomicBool>,
}

/// (remote address, remote port, local port) of an in-process TCP or UDP
/// flow (the two never share a key: local ports are handed out once).
type FlowKey = ([u8; 16], u16, u16);

/// Mesh→app packets that belong to an in-process flow, taken out of the
/// bridge before the inbound firewall and the TUN.
#[derive(Default)]
pub struct Divert {
    /// Fast path: the bridge skips parsing entirely while no flow is open.
    active: AtomicUsize,
    flows: Mutex<HashMap<FlowKey, Sender<Vec<u8>>>>,
}

impl Divert {
    /// Hand `packet` to its in-process flow; gives it back when it is not
    /// one (the caller then treats it as ordinary app traffic).
    pub fn claim(&self, packet: Vec<u8>) -> Option<Vec<u8>> {
        if self.active.load(Ordering::Relaxed) == 0 {
            return Some(packet);
        }
        let Some(key) = flow_key(&packet) else {
            return Some(packet);
        };
        let flows = self.flows.lock().unwrap();
        match flows.get(&key) {
            Some(tx) => {
                let _ = tx.send(packet);
                None
            }
            None => Some(packet),
        }
    }

    /// Open a flow on a free local port; it closes when the guard drops.
    pub(crate) fn open(self: &Arc<Self>, remote: Ipv6Addr, remote_port: u16) -> Option<FlowGuard> {
        let mut flows = self.flows.lock().unwrap();
        let span = (LOCAL_PORTS.end() - LOCAL_PORTS.start()) as u64 + 1;
        let first = random_u64() % span;
        for i in 0..span {
            let port = LOCAL_PORTS.start() + ((first + i) % span) as u16;
            let key = (remote.octets(), remote_port, port);
            if flows.contains_key(&key) {
                continue;
            }
            let (tx, rx) = std::sync::mpsc::channel();
            flows.insert(key, tx);
            self.active.fetch_add(1, Ordering::Relaxed);
            return Some(FlowGuard {
                divert: self.clone(),
                key,
                rx,
            });
        }
        None
    }
}

pub(crate) struct FlowGuard {
    divert: Arc<Divert>,
    pub(crate) key: FlowKey,
    pub(crate) rx: Receiver<Vec<u8>>,
}

impl FlowGuard {
    /// Hand the flow's packets to another thread (`meshtcp.rs`), keeping the
    /// guard — and with it the flow — where it is. The receiver then ends
    /// when the guard drops.
    pub(crate) fn take_rx(&mut self) -> Receiver<Vec<u8>> {
        std::mem::replace(&mut self.rx, std::sync::mpsc::channel().1)
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.divert.flows.lock().unwrap().remove(&self.key);
        self.divert.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The flow a mesh→app packet belongs to: a TCP segment or UDP datagram by
/// its ports (both carry them at the same offsets), an ICMPv6 echo reply by
/// its identifier (allocated from the same port range, remote port 0), or
/// an ICMPv6 error by the packet it quotes (which we sent, so the ports are
/// swapped). No extension headers: the far side's stack and the node send
/// none on this path.
fn flow_key(p: &[u8]) -> Option<FlowKey> {
    if p.len() < 44 || p[0] >> 4 != 6 {
        return None;
    }
    let addr = |b: &[u8]| -> [u8; 16] { b.try_into().unwrap() };
    let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    match p[6] {
        6 | 17 => Some((addr(&p[8..24]), port(&p[40..42]), port(&p[42..44]))),
        // Echo reply: type, code, checksum, identifier, sequence.
        58 if p[40] == 129 && p.len() >= 48 => Some((addr(&p[8..24]), 0, port(&p[44..46]))),
        // Destination unreachable: 8-byte ICMP header, then our packet.
        58 if p[40] == 1 && p.len() >= 48 + 44 && matches!(p[48 + 6], 6 | 17) => {
            let q = &p[48..];
            Some((addr(&q[24..40]), port(&q[42..44]), port(&q[40..42])))
        }
        _ => None,
    }
}

pub(crate) fn is_icmp_unreachable(p: &[u8]) -> bool {
    p.len() > 40 && p[6] == 58 && p[40] == 1
}

/// Per-process random bits (std seeds `RandomState` from the OS once and
/// perturbs it per instance) — enough for a port pick and an ISN seed,
/// without `getrandom(2)`, which bionic only has from API 28.
pub(crate) fn random_u64() -> u64 {
    let mut h = std::hash::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

/// Failure of a request. `unreachable` marks the cases where the node could
/// not be reached at all (no route, nothing listening, timeout) as opposed
/// to one that answered badly — the caller backs off differently.
/// `restarted`: the engine stopped or was rebuilt under the request — says
/// nothing about the far node; worth a prompt retry.
#[derive(Debug)]
pub struct FetchError {
    pub message: String,
    pub unreachable: bool,
    pub restarted: bool,
}

impl FetchError {
    pub(crate) fn other(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unreachable: false,
            restarted: false,
        }
    }
    pub(crate) fn unreachable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unreachable: true,
            restarted: false,
        }
    }
    pub(crate) fn restarted() -> Self {
        Self {
            message: "the node restarted during the request".into(),
            unreachable: false,
            restarted: true,
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// `GET http://[addr]:port<path>` over the mesh with the extra `headers`.
/// Blocking; the caller's thread runs the TCP stack.
pub fn get(
    link: &MeshLink,
    npub: &str,
    addr: Ipv6Addr,
    port: u16,
    path: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<Response, FetchError> {
    if addr == link.our_addr {
        return Err(FetchError::other("that is this node's own address"));
    }
    register_identity(link.responder, npub);
    let flow = link
        .divert
        .open(addr, port)
        .ok_or_else(|| FetchError::other("no free local port"))?;
    let local_port = flow.key.2;
    let processor = link.processor.clone();
    let outbound = link.outbound_tx.clone();
    let egress = move |mut packet: Vec<u8>| -> Result<(), FetchError> {
        match processor.process(&mut packet) {
            TunPacketAction::Forward => outbound
                .blocking_send(packet)
                .map_err(|_| FetchError::restarted()),
            TunPacketAction::Hairpin => Err(FetchError::other("that is this node's own address")),
            TunPacketAction::Respond(_) => Err(FetchError::unreachable(format!(
                "the node refused to send to {addr}"
            ))),
            TunPacketAction::Drop => Ok(()),
        }
    };
    let request = build_request(addr, port, path, headers);
    exchange(
        egress,
        &flow.rx,
        (link.our_addr, local_port),
        (addr, port),
        &request,
        Instant::now() + timeout,
        &link.running,
    )
}

/// Ask the local `.fips` responder for `<npub>.fips` and wait for its answer:
/// the responder registers the identity with the node before it replies, and
/// without it the node answers the SYN with "destination unreachable".
/// Best effort — the node may know the identity already.
pub(crate) fn register_identity(responder: SocketAddr, npub: &str) {
    let Ok(socket) = UdpSocket::bind(if responder.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    }) else {
        return;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
    let id = (random_u64() & 0xffff) as u16;
    if socket
        .send_to(&aaaa_query(id, &format!("{npub}.fips")), responder)
        .is_ok()
    {
        let mut buf = [0u8; 512];
        let _ = socket.recv(&mut buf);
    }
}

/// A minimal DNS query message: one AAAA/IN question, recursion desired.
pub(crate) fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.extend_from_slice(&[0, 0, 28, 0, 1]);
    q
}

fn build_request(addr: Ipv6Addr, port: u16, path: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut r = format!(
        "GET {path} HTTP/1.1\r\nHost: [{addr}]:{port}\r\nAccept: application/json\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        // Header injection is the caller's own foot to shoot, but a stray
        // newline would silently corrupt the request: drop such headers.
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            continue;
        }
        r.push_str(&format!("{name}: {value}\r\n"));
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// smoltcp device: received packets queue in `rx`, transmitted ones go to
/// `egress` at once. The first egress failure is kept and ends the exchange.
/// Shared with `meshudp.rs`.
pub(crate) struct Device<E> {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) egress: E,
    pub(crate) failed: Option<FetchError>,
}

pub(crate) struct RxToken(Vec<u8>);
pub(crate) struct TxToken<'a, E>(&'a mut Device<E>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<E: FnMut(Vec<u8>) -> Result<(), FetchError>> phy::TxToken for TxToken<'_, E> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if self.0.failed.is_none()
            && let Err(e) = (self.0.egress)(packet)
        {
            self.0.failed = Some(e);
        }
        result
    }
}

impl<E: FnMut(Vec<u8>) -> Result<(), FetchError>> phy::Device for Device<E> {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, E>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(self)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// One request/response over a fresh smoltcp connection from `local` to
/// `remote`: `rx` delivers the far side's packets, `egress` carries ours.
fn exchange<E: FnMut(Vec<u8>) -> Result<(), FetchError>>(
    egress: E,
    rx: &Receiver<Vec<u8>>,
    local: (Ipv6Addr, u16),
    remote: (Ipv6Addr, u16),
    request: &[u8],
    deadline: Instant,
    alive: &AtomicBool,
) -> Result<Response, FetchError> {
    let start = Instant::now();
    let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
    let mut device = Device {
        rx: VecDeque::new(),
        egress,
        failed: None,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = random_u64();
    let mut iface = Interface::new(config, &mut device, now());
    // The whole mesh prefix on-link: Medium::Ip needs no neighbour discovery.
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(local.0), 8));
    });
    let socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0; 8 * 1024]),
    );
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv6(remote.0), remote.1),
            local.1,
        )
        .map_err(|e| FetchError::other(format!("connect: {e}")))?;

    let where_ = format!("[{}]:{}", remote.0, remote.1);
    let mut sent = 0;
    let mut established = false;
    let mut unreachable = 0;
    let mut data = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];

    let finish = |data: &[u8]| parse_response(data).map_err(FetchError::other);
    loop {
        if !alive.load(Ordering::Relaxed) {
            return Err(FetchError::restarted());
        }
        iface.poll(now(), &mut device, &mut sockets);
        if let Some(e) = device.failed.take() {
            return Err(e);
        }
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if socket.is_active() && socket.state() != tcp::State::SynSent {
            established = true;
        }
        if sent < request.len() && socket.can_send() {
            sent += socket.send_slice(&request[sent..]).unwrap_or(0);
        }
        while socket.can_recv() {
            let n = socket.recv_slice(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            if data.len() > MAX_BODY {
                socket.abort();
                return Err(FetchError::other("response too large"));
            }
        }
        // Done: the server closed (Connection: close), or said how long its
        // body is and all of it is here.
        if established && (!socket.may_recv() || is_complete(&data)) {
            socket.close();
            iface.poll(now(), &mut device, &mut sockets); // our FIN, best effort
            return finish(&data);
        }
        if !socket.is_open() {
            return Err(if established {
                FetchError::other(format!("{where_} closed the connection early"))
            } else {
                FetchError::unreachable(format!(
                    "{where_} refused the connection (nothing listening on that port?)"
                ))
            });
        }

        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FetchError::unreachable(if established {
                format!("{where_} did not finish answering in time")
            } else if unreachable > 0 {
                format!("no route to {where_} over the mesh")
            } else {
                format!("{where_} did not answer (is the node online?)")
            }));
        }
        let wait = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100))
            .min(left);
        let mut handle_packet = |packet: Vec<u8>| {
            if is_icmp_unreachable(&packet) {
                unreachable += 1;
            } else {
                device.rx.push_back(packet);
            }
        };
        match rx.recv_timeout(wait) {
            Ok(packet) => {
                handle_packet(packet);
                while let Ok(packet) = rx.try_recv() {
                    handle_packet(packet);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(FetchError::restarted()),
        }
        if unreachable >= UNREACHABLE_LIMIT && !established {
            return Err(FetchError::unreachable(format!(
                "no route to {where_} over the mesh (the node does not know a path to it)"
            )));
        }
    }
}

/// Header block end, if present.
fn header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// A `Content-Length` response whose body has fully arrived.
fn is_complete(data: &[u8]) -> bool {
    let Some(end) = header_end(data) else {
        return false;
    };
    let head = String::from_utf8_lossy(&data[..end]);
    header_value(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|len| data.len() >= end + len)
}

fn parse_response(data: &[u8]) -> Result<Response, String> {
    let end = header_end(data).ok_or("no HTTP response (connection closed before the headers)")?;
    let head = String::from_utf8_lossy(&data[..end]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1."))
        .and_then(|l| l.get(2..5))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("not an HTTP response")?;
    let raw = &data[end..];
    let chunked = header_value(&head, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(raw)?
    } else if let Some(len) = header_value(&head, "content-length").and_then(|v| v.parse().ok()) {
        raw.get(..len).ok_or("response body cut short")?.to_vec()
    } else {
        raw.to_vec()
    };
    Ok(Response { status, body })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("chunked body cut short")?;
        let size_str = String::from_utf8_lossy(&raw[..line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "bad chunk size")?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(raw.get(..size).ok_or("chunked body cut short")?);
        raw = raw.get(size + 2..).ok_or("chunked body cut short")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_and_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA").unwrap();
        assert_eq!((r.status, &r.body[..]), (200, &b"hello"[..]));
        let r = parse_response(
            b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((r.status, &r.body[..]), (403, &b"abcde"[..]));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
        assert!(is_complete(
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"
        ));
        assert!(!is_complete(
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok"
        ));
    }

    #[test]
    fn request_drops_headers_with_newlines() {
        let addr: Ipv6Addr = "fd01::1".parse().unwrap();
        let headers = vec![
            (
                "x-fips-ui-sync".to_string(),
                "version=1;interval=5".to_string(),
            ),
            ("x-evil".to_string(), "a\r\nHost: b".to_string()),
        ];
        let r = String::from_utf8(build_request(addr, 8321, "/api/hosts", &headers)).unwrap();
        assert!(r.starts_with("GET /api/hosts HTTP/1.1\r\nHost: [fd01::1]:8321\r\n"));
        assert!(r.contains("x-fips-ui-sync: version=1;interval=5\r\n"));
        assert!(!r.contains("x-evil"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn divert_claims_only_its_flow() {
        let divert = Arc::new(Divert::default());
        let remote: Ipv6Addr = "fd01::2".parse().unwrap();
        let tcp = |src: Ipv6Addr, sport: u16, dport: u16| {
            let mut p = vec![0u8; 60];
            p[0] = 0x60;
            p[6] = 6;
            p[8..24].copy_from_slice(&src.octets());
            p[40..42].copy_from_slice(&sport.to_be_bytes());
            p[42..44].copy_from_slice(&dport.to_be_bytes());
            p
        };
        // Nothing open: everything passes through untouched.
        assert!(divert.claim(tcp(remote, 8321, 61000)).is_some());
        let flow = divert.open(remote, 8321).unwrap();
        let port = flow.key.2;
        assert!(LOCAL_PORTS.contains(&port));
        assert!(divert.claim(tcp(remote, 8321, port)).is_none());
        assert!(flow.rx.try_recv().is_ok());
        assert!(divert.claim(tcp(remote, 8322, port)).is_some());
        assert!(
            divert
                .claim(tcp("fd01::3".parse().unwrap(), 8321, port))
                .is_some()
        );

        // An echo reply is claimed by its identifier.
        let echo_flow = divert.open(remote, 0).unwrap();
        let mut reply = vec![0u8; 48];
        reply[0] = 0x60;
        reply[6] = 58;
        reply[8..24].copy_from_slice(&remote.octets());
        reply[40] = 129;
        reply[44..46].copy_from_slice(&echo_flow.key.2.to_be_bytes());
        assert!(divert.claim(reply.clone()).is_none());
        assert!(echo_flow.rx.try_recv().is_ok());
        reply[44..46].copy_from_slice(&[0, 1]);
        assert!(
            divert.claim(reply).is_some(),
            "another identifier passes through"
        );
        drop(echo_flow);

        // An ICMPv6 unreachable quoting our SYN reaches the flow too.
        let mut icmp = vec![0u8; 48];
        icmp[0] = 0x60;
        icmp[6] = 58;
        icmp[40] = 1;
        let mut quoted = tcp("fd01::9".parse().unwrap(), port, 8321);
        quoted[24..40].copy_from_slice(&remote.octets());
        icmp.extend_from_slice(&quoted);
        assert!(divert.claim(icmp).is_none());
        assert!(is_icmp_unreachable(&flow.rx.try_recv().unwrap()));

        drop(flow);
        assert!(divert.claim(tcp(remote, 8321, port)).is_some());
    }

    /// The whole client loop against a smoltcp server on the far end of two
    /// channels: handshake, request, a chunked answer, close.
    #[test]
    fn exchange_against_a_userspace_server() {
        let client_addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let server_addr: Ipv6Addr = "fd00::2".parse().unwrap();
        let (to_server, server_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (to_client, client_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        let server = std::thread::spawn(move || {
            let start = Instant::now();
            let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
            let mut device = Device {
                rx: VecDeque::new(),
                egress: move |p: Vec<u8>| {
                    let _ = to_client.send(p);
                    Ok(())
                },
                failed: None,
            };
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::Ipv6(server_addr), 8));
            });
            let mut sockets = SocketSet::new(Vec::new());
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 8192]),
                tcp::SocketBuffer::new(vec![0; 8192]),
            );
            sock.listen(8321).unwrap();
            let h = sockets.add(sock);
            let mut request = Vec::new();
            let mut answered = false;
            while start.elapsed() < Duration::from_secs(10) {
                while let Ok(p) = server_rx.try_recv() {
                    device.rx.push_back(p);
                }
                iface.poll(now(), &mut device, &mut sockets);
                let s = sockets.get_mut::<tcp::Socket>(h);
                let mut b = [0u8; 1024];
                while let Ok(n @ 1..) = s.recv_slice(&mut b) {
                    request.extend_from_slice(&b[..n]);
                }
                if !answered && header_end(&request).is_some() && s.can_send() {
                    s.send_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n")
                        .unwrap();
                    s.close();
                    answered = true;
                }
                if answered && !s.is_open() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            String::from_utf8(request).unwrap()
        });

        let request = build_request(server_addr, 8321, "/api/hosts", &[]);
        let response = exchange(
            move |p| {
                let _ = to_server.send(p);
                Ok(())
            },
            &client_rx,
            (client_addr, 61234),
            (server_addr, 8321),
            &request,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"a\":1}");
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("GET /api/hosts HTTP/1.1\r\n")
        );
    }

    /// Nothing answers: the client gives up at the deadline and calls it
    /// unreachable (the sync then backs off), not a bad answer.
    #[test]
    fn silence_is_unreachable() {
        let (_tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let err = exchange(
            |_| Ok(()),
            &rx,
            ("fd00::1".parse().unwrap(), 61000),
            ("fd00::2".parse().unwrap(), 8321),
            b"GET / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_millis(300),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(err.unreachable, "{err:?}");
    }

    /// The engine stopped under the request (a rebind): given up at once
    /// and reported as a restart, never as the far node being unreachable.
    #[test]
    fn engine_stop_is_a_restart_not_unreachable() {
        let (_tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let alive = Arc::new(AtomicBool::new(true));
        let flag = alive.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            flag.store(false, Ordering::Relaxed);
        });
        let started = Instant::now();
        let err = exchange(
            |_| Ok(()),
            &rx,
            ("fd00::1".parse().unwrap(), 61000),
            ("fd00::2".parse().unwrap(), 8321),
            b"GET / HTTP/1.1\r\n\r\n",
            Instant::now() + Duration::from_secs(10),
            &alive,
        )
        .unwrap_err();
        assert!(err.restarted && !err.unreachable, "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
