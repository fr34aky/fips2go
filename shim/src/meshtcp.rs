//! A long-lived TCP stream to a mesh node, piped to a local socket — how
//! the public-names resolver reaches Nostr relays that run on fips nodes.
//!
//! nostr-sdk opens ordinary sockets, and the app's own sockets cannot reach
//! `fd00::/8` (see `meshhttp.rs` for why). So each mesh relay gets a
//! listener on loopback; every connection accepted there is carried over a
//! userspace TCP stack (smoltcp, the same device and packet path as
//! `meshhttp.rs`) to the relay's fips address.
//!
//! Loopback is shared by every app on the device, and a connection through
//! here leaves from this node's fips address. So the listener only serves
//! whoever knows its secret path — the resolver in this process: the first
//! request line must be `GET /<token>…`, checked (and the token stripped)
//! before anything reaches the mesh. At most [`MAX_CONNECTIONS`] at a time.
//!
//! Idle cost matters on a phone: a relay connection stays open, so the pipe
//! blocks on one event channel (mesh packets and local reads alike) until
//! something arrives or smoltcp has a timer due, and the listener blocks in
//! `accept` until a connection comes or the proxy is dropped.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fips::TunPacketAction;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use crate::meshhttp::{
    Device, FetchError, MeshLink, is_icmp_unreachable, random_u64, register_identity,
};

/// How long a connection may take to be accepted by the far node.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait with nothing to do: bounds how late a rebuilt engine is
/// noticed on an idle connection.
const IDLE_WAIT: Duration = Duration::from_secs(30);
/// Keep-alive on the mesh side, so a relay connection that went quiet is
/// found dead instead of hanging on.
const KEEPALIVE: Duration = Duration::from_secs(60);
/// Local bytes read but not yet taken by the mesh socket before the local
/// reader pauses — backpressure towards the local client.
const TO_MESH_LIMIT: usize = 256 * 1024;
/// Mesh bytes not yet written to the local side before the pipe stops
/// taking data off the mesh socket (its window then closes).
const TO_LOCAL_LIMIT: usize = 64 * 1024;
/// A stalled local reader holds the pipe at most this long per attempt.
const LOCAL_WRITE_TIMEOUT: Duration = Duration::from_millis(200);
/// Concurrent connections per relay; the resolver needs one.
const MAX_CONNECTIONS: usize = 4;
/// The request head the token is read from.
const MAX_HEAD: usize = 8 * 1024;

/// A relay on the mesh, served on a loopback port for the lifetime of the
/// value; dropping it stops the listener (open connections end with it).
pub struct MeshRelayProxy {
    /// `ws://127.0.0.1:<port>/<token><path>` — what the resolver dials.
    pub local_url: String,
    stop: Arc<AtomicBool>,
    local: SocketAddr,
}

impl Drop for MeshRelayProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the blocking accept so the thread sees `stop`.
        let _ = TcpStream::connect_timeout(&self.local, Duration::from_millis(200));
    }
}

/// A mesh relay URL: `ws://<npub>.fips[:port][/path]`. Other forms (a
/// public `wss://` relay, an `[fd…]` literal) are not mesh relays here.
pub fn parse_mesh_relay(url: &str) -> Option<(pubdom_core::Npub, u16, String)> {
    let rest = url.strip_prefix("ws://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p != 0)?),
        None => (hostport, 80),
    };
    let npub = host.to_ascii_lowercase().strip_suffix(".fips")?.to_string();
    Some((pubdom_core::Npub::parse(&npub).ok()?, port, path))
}

impl MeshRelayProxy {
    /// Listen on loopback for `url` (a `ws://<npub>.fips…` relay).
    pub fn start(link: Arc<MeshLink>, url: &str) -> Result<Self, String> {
        let (npub, port, path) =
            parse_mesh_relay(url).ok_or_else(|| format!("{url}: not a ws://<npub>.fips relay"))?;
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| format!("{url}: listen: {e}"))?;
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        let token = format!("{:016x}{:016x}", random_u64(), random_u64());
        let stop = Arc::new(AtomicBool::new(false));
        let relay = Relay {
            link,
            npub: npub.to_string(),
            addr: npub.fips_address(),
            port,
            path: path.clone(),
            token: token.clone(),
            stop: stop.clone(),
            name: url.to_string(),
            active: AtomicUsize::new(0),
        };
        std::thread::Builder::new()
            .name("mesh-relay".into())
            .spawn(move || accept_loop(listener, Arc::new(relay)))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            local_url: format!("ws://{local}/{token}{path}"),
            stop,
            local,
        })
    }
}

struct Relay {
    link: Arc<MeshLink>,
    npub: String,
    addr: Ipv6Addr,
    port: u16,
    /// The relay's own path, what the token is replaced by.
    path: String,
    token: String,
    stop: Arc<AtomicBool>,
    name: String,
    active: AtomicUsize,
}

fn accept_loop(listener: TcpListener, relay: Arc<Relay>) {
    loop {
        let accepted = listener.accept();
        if relay.stop.load(Ordering::Relaxed) || !relay.link.running.load(Ordering::Relaxed) {
            return;
        }
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(relay = %relay.name, error = %e, "mesh relay listener failed");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        if relay.active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
            relay.active.fetch_sub(1, Ordering::Relaxed);
            continue; // dropped: closes the connection
        }
        let r = relay.clone();
        let spawned = std::thread::Builder::new().name("mesh-relay-conn".into()).spawn(move || {
            match pipe(&r, stream) {
                Ok(()) => {}
                Err(e) => tracing::info!(relay = %r.name, error = %e.message, "mesh relay connection ended"),
            }
            r.active.fetch_sub(1, Ordering::Relaxed);
        });
        if spawned.is_err() {
            relay.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The request head with the token checked and replaced by the relay's
/// path, plus whatever followed it; `None` for anyone without the token.
fn admit(head: &[u8], token: &str, path: &str) -> Option<Vec<u8>> {
    head.windows(4).position(|w| w == b"\r\n\r\n")?;
    let line_end = head.iter().position(|b| *b == b'\n')?;
    let line = std::str::from_utf8(&head[..line_end])
        .ok()?
        .trim_end_matches('\r');
    let target = line.strip_prefix("GET ")?.strip_suffix(" HTTP/1.1")?;
    let rest = target.strip_prefix('/')?.strip_prefix(token)?;
    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
        return None;
    }
    // The resolver dials `/<token><path>`; the relay sees `<path>`.
    let rest = rest.strip_prefix(path).unwrap_or(rest);
    let mut target = format!("{path}{rest}");
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let mut out = format!("GET {target} HTTP/1.1\r\n").into_bytes();
    out.extend_from_slice(&head[line_end + 1..]);
    Some(out)
}

/// Read the request head (up to its blank line) within a few seconds.
fn read_head(local: &mut TcpStream) -> Option<Vec<u8>> {
    local.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > MAX_HEAD {
            return None;
        }
        match local.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    local.set_read_timeout(None).ok()?;
    Some(head)
}

enum Event {
    Mesh(Vec<u8>),
    Local(Vec<u8>),
    LocalClosed,
}

/// Local bytes in flight towards the mesh: the reader waits while there
/// are more than [`TO_MESH_LIMIT`].
#[derive(Default)]
struct Backlog {
    bytes: Mutex<usize>,
    room: Condvar,
}

impl Backlog {
    fn add(&self, n: usize, give_up: &AtomicBool) -> bool {
        let mut b = self.bytes.lock().unwrap();
        while *b > TO_MESH_LIMIT {
            if give_up.load(Ordering::Relaxed) {
                return false;
            }
            b = self.room.wait_timeout(b, Duration::from_secs(1)).unwrap().0;
        }
        *b += n;
        true
    }
    fn sent(&self, n: usize) {
        let mut b = self.bytes.lock().unwrap();
        *b = b.saturating_sub(n);
        self.room.notify_all();
    }
}

/// Carry `local` to the relay over the mesh until either side closes.
fn pipe(relay: &Relay, mut local: TcpStream) -> Result<(), FetchError> {
    let link = &relay.link;
    let (addr, port) = (relay.addr, relay.port);
    if addr == link.our_addr {
        return Err(FetchError::other("that is this node's own address"));
    }
    // The token first: nothing reaches the mesh for a caller without it.
    let Some(first) = read_head(&mut local).and_then(|h| admit(&h, &relay.token, &relay.path))
    else {
        tracing::debug!(relay = %relay.name, "refused a loopback connection without the token");
        return Ok(());
    };
    let _ = local.set_nodelay(true);
    let _ = local.set_write_timeout(Some(LOCAL_WRITE_TIMEOUT));
    register_identity(link.responder, &relay.npub);
    let mut flow = link
        .divert
        .open(addr, port)
        .ok_or_else(|| FetchError::other("no free local port"))?;
    let local_port = flow.key.2;

    let (tx, events) = mpsc::channel::<Event>();
    let backlog = Arc::new(Backlog::default());
    let done = Arc::new(AtomicBool::new(false));
    {
        let (tx, rx) = (tx.clone(), flow.take_rx());
        std::thread::spawn(move || {
            while let Ok(p) = rx.recv() {
                if tx.send(Event::Mesh(p)).is_err() {
                    break;
                }
            }
        });
    }
    {
        let mut reader = local
            .try_clone()
            .map_err(|e| FetchError::other(e.to_string()))?;
        let (tx, backlog, done) = (tx.clone(), backlog.clone(), done.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.send(Event::LocalClosed);
                        break;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => {
                        let _ = tx.send(Event::LocalClosed);
                        break;
                    }
                    Ok(n) => {
                        if !backlog.add(n, &done)
                            || tx.send(Event::Local(buf[..n].to_vec())).is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
    }
    drop(tx);

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
    let result = run(
        egress,
        &events,
        first,
        &backlog,
        (link.our_addr, local_port),
        (addr, port),
        &local,
        &link.running,
        &relay.stop,
    );
    done.store(true, Ordering::Relaxed);
    backlog.sent(usize::MAX);
    let _ = local.shutdown(Shutdown::Both);
    drop(flow);
    result
}

#[allow(clippy::too_many_arguments)]
fn run<E: FnMut(Vec<u8>) -> Result<(), FetchError>>(
    egress: E,
    events: &mpsc::Receiver<Event>,
    first: Vec<u8>,
    backlog: &Backlog,
    local_addr: (Ipv6Addr, u16),
    remote: (Ipv6Addr, u16),
    mut local: &TcpStream,
    alive: &AtomicBool,
    stop: &AtomicBool,
) -> Result<(), FetchError> {
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
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(local_addr.0), 8));
    });
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
    );
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
        KEEPALIVE.as_secs(),
    )));
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);
    sockets
        .get_mut::<tcp::Socket>(handle)
        .connect(
            iface.context(),
            (IpAddress::Ipv6(remote.0), remote.1),
            local_addr.1,
        )
        .map_err(|e| FetchError::other(format!("connect: {e}")))?;

    let where_ = format!("[{}]:{}", remote.0, remote.1);
    let connect_deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut established = false;
    let mut unreachable = 0;
    // The admitted request head goes first; it was never counted in the
    // backlog, which only tracks the reader thread's bytes.
    let mut first_left = first.len();
    let mut to_mesh: VecDeque<u8> = first.into();
    let mut to_local: VecDeque<u8> = VecDeque::new();
    let mut local_closed = false;
    let mut close_sent = false;
    let mut local_shut = false;
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        if !alive.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            // Engine rebuilt or proxy dropped: reset the relay's side rather
            // than leave it waiting.
            sockets.get_mut::<tcp::Socket>(handle).abort();
            iface.poll(now(), &mut device, &mut sockets);
            return if alive.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(FetchError::restarted())
            };
        }
        iface.poll(now(), &mut device, &mut sockets);
        if let Some(e) = device.failed.take() {
            return Err(e);
        }
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if socket.is_active() && socket.state() != tcp::State::SynSent {
            established = true;
        }
        if local_closed && !established {
            // The local client gave up before the relay answered.
            socket.abort();
            iface.poll(now(), &mut device, &mut sockets);
            return Ok(());
        }
        // Local → mesh.
        while !to_mesh.is_empty() && socket.can_send() {
            let (a, _) = to_mesh.as_slices();
            let n = socket.send_slice(a).unwrap_or(0);
            if n == 0 {
                break;
            }
            to_mesh.drain(..n);
            let from_first = n.min(first_left);
            first_left -= from_first;
            backlog.sent(n - from_first);
        }
        if local_closed && to_mesh.is_empty() && !close_sent {
            socket.close();
            close_sent = true;
        }
        // Mesh → local, bounded; a stalled local reader holds the loop at
        // most LOCAL_WRITE_TIMEOUT per pass.
        while to_local.len() < TO_LOCAL_LIMIT && socket.can_recv() {
            let n = socket.recv_slice(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            to_local.extend(&buf[..n]);
        }
        while !to_local.is_empty() {
            let (a, _) = to_local.as_slices();
            match local.write(a) {
                Ok(0) => break,
                Ok(n) => {
                    to_local.drain(..n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(_) => {
                    socket.abort();
                    iface.poll(now(), &mut device, &mut sockets);
                    return Ok(());
                }
            }
        }
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        // The relay finished sending: pass that on once everything it sent
        // is delivered, and close our side once ours is out (below).
        if established
            && !socket.may_recv()
            && !socket.can_recv()
            && to_local.is_empty()
            && !local_shut
        {
            let _ = local.shutdown(Shutdown::Write);
            local_shut = true;
            if !close_sent && to_mesh.is_empty() {
                socket.close();
                close_sent = true;
            }
        }
        if !socket.is_open() {
            return if established {
                Ok(())
            } else {
                Err(FetchError::unreachable(format!(
                    "{where_} refused the connection (nothing listening on that port?)"
                )))
            };
        }
        if !established && Instant::now() >= connect_deadline {
            return Err(FetchError::unreachable(if unreachable > 0 {
                format!("no route to {where_} over the mesh")
            } else {
                format!("{where_} did not answer (is the node online?)")
            }));
        }

        let mut wait = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(IDLE_WAIT)
            .min(IDLE_WAIT);
        if !to_local.is_empty() {
            wait = wait.min(Duration::from_millis(50));
        }
        let mut handle_event = |ev: Event, device: &mut Device<E>| match ev {
            Event::Mesh(p) if is_icmp_unreachable(&p) => unreachable += 1,
            Event::Mesh(p) => device.rx.push_back(p),
            Event::Local(bytes) => to_mesh.extend(bytes),
            Event::LocalClosed => local_closed = true,
        };
        match events.recv_timeout(wait) {
            Ok(ev) => {
                handle_event(ev, &mut device);
                while let Ok(ev) = events.try_recv() {
                    handle_event(ev, &mut device);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if unreachable >= 3 && !established {
            return Err(FetchError::unreachable(format!(
                "no route to {where_} over the mesh (the node does not know a path to it)"
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_relay_urls() {
        let npub = pubdom_core::Npub::from_bytes([7; 32]);
        assert_eq!(
            parse_mesh_relay(&format!("ws://{npub}.fips:7777/nostr")),
            Some((npub, 7777, "/nostr".into()))
        );
        assert_eq!(
            parse_mesh_relay(&format!("ws://{}.FIPS", npub.to_string().to_uppercase())),
            Some((npub, 80, String::new()))
        );
        assert_eq!(
            parse_mesh_relay(&format!("wss://{npub}.fips")),
            None,
            "no TLS on the mesh"
        );
        assert_eq!(parse_mesh_relay("ws://relay.example.org"), None);
        assert_eq!(parse_mesh_relay("ws://[fd00::1]:80"), None);
        assert_eq!(parse_mesh_relay(&format!("ws://{npub}.fips:0")), None);
    }

    #[test]
    fn only_the_token_holder_is_admitted() {
        let head = |target: &str| {
            format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:1\r\nUpgrade: websocket\r\n\r\nrest")
        };
        let ok = admit(head("/abc").as_bytes(), "abc", "").unwrap();
        assert!(ok.starts_with(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"));
        assert!(
            ok.ends_with(b"\r\n\r\nrest"),
            "bytes after the head pass through"
        );
        // The relay's own path replaces the token.
        let ok = admit(head("/abc/nostr").as_bytes(), "abc", "/nostr").unwrap();
        assert!(ok.starts_with(b"GET /nostr HTTP/1.1\r\n"));
        for bad in ["/", "/ab", "/abcd", "/xyz/abc", "abc"] {
            assert!(admit(head(bad).as_bytes(), "abc", "").is_none(), "{bad}");
        }
        assert!(admit(b"POST /abc HTTP/1.1\r\n\r\n", "abc", "").is_none());
        assert!(
            admit(b"GET /abc HTTP/1.1\r\n", "abc", "").is_none(),
            "incomplete head"
        );
    }

    /// The pipe between a real loopback socket and a smoltcp echo server on
    /// the far end of two channels: bytes both ways, then a clean close
    /// started from the local side.
    #[test]
    fn pipe_against_a_userspace_echo_server() {
        let client_addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let server_addr: Ipv6Addr = "fd00::2".parse().unwrap();
        let (to_server, server_rx) = mpsc::channel::<Vec<u8>>();
        let (events_tx, events) = mpsc::channel::<Event>();

        let to_client = events_tx.clone();
        let server = std::thread::spawn(move || {
            let start = Instant::now();
            let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
            let mut device = Device {
                rx: VecDeque::new(),
                egress: move |p: Vec<u8>| {
                    let _ = to_client.send(Event::Mesh(p));
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
            sock.listen(7777).unwrap();
            let h = sockets.add(sock);
            let mut echoed = 0;
            while start.elapsed() < Duration::from_secs(10) {
                while let Ok(p) = server_rx.try_recv() {
                    device.rx.push_back(p);
                }
                iface.poll(now(), &mut device, &mut sockets);
                let s = sockets.get_mut::<tcp::Socket>(h);
                let mut b = [0u8; 1024];
                while let Ok(n @ 1..) = s.recv_slice(&mut b) {
                    s.send_slice(&b[..n]).unwrap();
                    echoed += n;
                }
                // The client finished sending: close our side too.
                if echoed > 0 && !s.may_recv() && s.state() == tcp::State::CloseWait {
                    s.close();
                }
                if echoed > 0 && !s.is_open() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            echoed
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut app = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (piped, _) = listener.accept().unwrap();
        {
            let mut reader = piped.try_clone().unwrap();
            let tx = events_tx.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => {
                            let _ = tx.send(Event::LocalClosed);
                            break;
                        }
                        Ok(n) => {
                            let _ = tx.send(Event::Local(buf[..n].to_vec()));
                        }
                    }
                }
            });
        }
        drop(events_tx);
        let pipe = std::thread::spawn(move || {
            run(
                move |p| {
                    let _ = to_server.send(p);
                    Ok(())
                },
                &events,
                Vec::new(),
                &Backlog::default(),
                (client_addr, 61234),
                (server_addr, 7777),
                &piped,
                &AtomicBool::new(true),
                &AtomicBool::new(false),
            )
        });

        app.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let msg: &[u8] = br#"["REQ","x",{}]"#;
        app.write_all(msg).unwrap();
        let mut got = vec![0u8; msg.len()];
        app.read_exact(&mut got).unwrap();
        assert_eq!(got, msg);
        // Local close: FIN over the mesh, the server closes, the pipe ends.
        app.shutdown(Shutdown::Write).unwrap();
        assert!(pipe.join().unwrap().is_ok());
        assert_eq!(server.join().unwrap(), msg.len());
    }
}
