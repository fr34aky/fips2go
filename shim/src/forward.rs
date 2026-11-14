//! Userspace forwarder for non-mesh traffic (the "clearnet" side of the
//! split tunnel).
//!
//! Android's `VpnService` confines every covered app to the tunnel's routes,
//! so to let selected apps keep normal internet we route ALL their traffic
//! into the tun, peel off `fd00::/8` for the mesh (in the pump), and hand
//! everything else to a userspace TCP/IP stack (`ipstack`). Each accepted
//! flow is dialed out on a real, VPN-protected socket and copied through —
//! i.e. a tun2socks-style forwarder scoped to the apps the user opted in.
//!
//! Only the selected apps' non-mesh traffic reaches here; mesh and DNS are
//! handled earlier in the pump — except DNS over TCP to the tunnel's
//! resolver, which needs a TCP stack to end the connection and so comes
//! here too: see [`DnsOverTcp`].

use std::io;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender as StdSender;
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Notify;

use fips::SocketProtect;

use crate::dns::DnsProxy;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the app side gets to take the FIN that tells it its server is
/// gone (see [`forward_tcp`]).
const APP_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_DATAGRAM: usize = 65535;
/// A DNS-over-TCP connection with nothing to read is closed after this.
const DNS_TCP_IDLE: Duration = Duration::from_secs(10);
/// One exchange with one upstream over TCP: connect, ask, read the answer.
const DNS_TCP_UPSTREAM: Duration = Duration::from_secs(5);

/// DNS over TCP to the tunnel's resolver. A resolver that got a truncated
/// answer over UDP asks again over TCP, at the same address — the in-tunnel
/// sentinel, which no host has. The stack here accepts that connection and
/// each message on it is answered by the DNS proxy, the way a UDP query is.
#[derive(Clone)]
pub struct DnsOverTcp {
    /// `[sentinel]:53`, the destination that marks such a connection.
    pub addr: std::net::SocketAddr,
    pub proxy: Arc<DnsProxy>,
}

/// The `ipstack` "device": an `AsyncRead`/`AsyncWrite` of raw IP packets.
/// Reads the non-mesh packets the pump classifier feeds it; writes the
/// stack's response packets straight to the TUN writer channel.
struct ForwardDevice {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    to_tun: StdSender<Vec<u8>>,
    leftover: Vec<u8>,
    pos: usize,
}

impl AsyncRead for ForwardDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.leftover.len() {
            let n = std::cmp::min(buf.remaining(), self.leftover.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.leftover[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        match self.inbound.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = std::cmp::min(buf.remaining(), pkt.len());
                buf.put_slice(&pkt[..n]);
                if n < pkt.len() {
                    self.leftover = pkt;
                    self.pos = n;
                }
                Poll::Ready(Ok(()))
            }
            // Classifier dropped its sender → engine is stopping. Ending the
            // read ends the ipstack loop (and thus `accept()`).
            Poll::Ready(None) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ForwardDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // ipstack writes one whole IP packet per call.
        let _ = self.to_tun.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn protect_fd<S: AsRawFd>(socket: &S, protect: &Option<SocketProtect>) {
    if let Some(hook) = protect {
        hook(socket.as_raw_fd());
    }
}

/// Owns the forwarder thread + its runtime.
pub struct Forwarder {
    thread: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
    /// Signals (by send or disconnect) that the thread reached its last line.
    done_rx: std::sync::mpsc::Receiver<()>,
}

impl Forwarder {
    /// Spawn the forwarder. `inbound` receives non-mesh IP packets from the
    /// pump classifier; `to_tun` is the TUN writer channel; outbound sockets
    /// are dialed through `protect` so they bypass the VPN.
    pub fn spawn(
        inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
        to_tun: StdSender<Vec<u8>>,
        protect: Option<SocketProtect>,
        running: Arc<AtomicBool>,
        mtu: u16,
        dns: Option<DnsOverTcp>,
    ) -> io::Result<Self> {
        let shutdown = Arc::new(Notify::new());
        let shutdown_rx = shutdown.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("fips-forwarder".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "forwarder runtime build failed");
                        return;
                    }
                };
                rt.block_on(run(inbound, to_tun, protect, running, shutdown_rx, mtu, dns));
                // A plain `drop(rt)` waits unboundedly for blocking-pool
                // threads; on-device one parked such thread kept this join —
                // and the app's whole disconnect — hanging. Bound the wait;
                // per-flow tasks and stragglers are torn down/abandoned.
                rt.shutdown_timeout(Duration::from_secs(2));
                tracing::info!("forwarder stopped");
                let _ = done_tx.send(());
            })?;
        Ok(Self {
            thread: Some(thread),
            shutdown,
            done_rx,
        })
    }

    /// Signal shutdown, then wait a BOUNDED time for the thread.
    ///
    /// The forwarder has wedged in several distinct ways on-device (ipstack
    /// drains keeping `accept()` pending, runtime drop waiting on its
    /// blocking pool, tokio internals parked through the shutdown notify) —
    /// and an unbounded join turns any of them into a disconnect that never
    /// completes and a tunnel that never closes. If the thread won't die in
    /// time, abandon it: the engine is tearing down anyway, and a leaked
    /// parked thread is strictly better than a hung `stop()`.
    pub fn join(mut self) {
        self.shutdown.notify_one();
        match self.done_rx.recv_timeout(Duration::from_secs(3)) {
            // Reached its last line (send) or died earlier (disconnect):
            // the actual join is now instant or near-instant.
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(t) = self.thread.take() {
                    let _ = t.join();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!("forwarder did not stop in 3s; abandoning its thread");
                self.thread.take(); // drop the handle → detach
            }
        }
    }
}

impl Drop for Forwarder {
    /// If the forwarder is dropped without `join` (engine start-error paths),
    /// still wake the loop so the thread exits instead of leaking.
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

async fn run(
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    to_tun: StdSender<Vec<u8>>,
    protect: Option<SocketProtect>,
    running: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    mtu: u16,
    dns: Option<DnsOverTcp>,
) {
    let device = ForwardDevice {
        inbound,
        to_tun,
        leftover: Vec::new(),
        pos: 0,
    };
    let mut config = IpStackConfig::default();
    config.mtu_unchecked(mtu);
    config.packet_information(false);
    config.udp_timeout(UDP_IDLE_TIMEOUT);

    let mut stack = IpStack::new(config, device);
    tracing::info!(mtu, "clearnet forwarder started");

    while running.load(Ordering::Relaxed) {
        let accepted = tokio::select! {
            r = stack.accept() => r,
            // `notify_one` stores a permit, so a signal sent while we were
            // busy in the accept arm still ends the next iteration.
            _ = shutdown.notified() => break,
        };
        match accepted {
            Ok(IpStackStream::Tcp(tcp)) => {
                if let Some(dns) = dns.as_ref().filter(|d| d.addr == tcp.peer_addr()) {
                    let proxy = dns.proxy.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_dns_tcp(tcp, proxy).await {
                            tracing::debug!(error = %e, "DNS-over-TCP connection ended");
                        }
                    });
                    continue;
                }
                let protect = protect.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_tcp(tcp, protect).await {
                        tracing::debug!(error = %e, "tcp flow ended");
                    }
                });
            }
            Ok(IpStackStream::Udp(udp)) => {
                let protect = protect.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_udp(udp, protect).await {
                        tracing::debug!(error = %e, "udp flow ended");
                    }
                });
            }
            // ICMP / unparsable — no forwarding (ping to clearnet won't work,
            // but TCP/UDP — everything that matters — does).
            Ok(_) => {}
            Err(_) => break, // device closed → shutting down
        }
    }
}

async fn forward_tcp(
    mut client: ipstack::IpStackTcpStream,
    protect: Option<SocketProtect>,
) -> io::Result<()> {
    let dst = client.peer_addr();
    let socket = if dst.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect_fd(&socket, &protect);
    let mut server = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, socket.connect(dst)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(close_app_side(client, e).await),
        Err(_) => {
            let e = io::Error::new(io::ErrorKind::TimedOut, "connect timeout");
            return Err(close_app_side(client, e).await);
        }
    };
    match tokio::io::copy_bidirectional(&mut client, &mut server).await {
        Ok(_) => Ok(()),
        Err(e) => Err(close_app_side(client, e).await),
    }
}

/// The server side of a forwarded connection failed — on a phone most often
/// because the network it was dialed on went away (Android aborts a protected
/// socket when its network is lost), or, for a new connection, because the
/// dial itself failed. ipstack has already accepted the app's connection.
/// Dropping the app-side stream alone tells the app nothing: ipstack forgets
/// the session and answers only the app's next segment, and an app that has
/// sent its request and waits for the answer sends none, so it waited out its
/// own timeout — DuckDuckGo a full minute after a Wi-Fi to LTE switch,
/// holding a page reload behind it. A FIN ends the connection on the app's
/// side now and it reconnects. ipstack offers no reset, which would say
/// "aborted" rather than "closed"; and it sends the FIN only from an open,
/// idle connection, otherwise the timeout passes and the old silent drop
/// remains.
async fn close_app_side(mut client: ipstack::IpStackTcpStream, error: io::Error) -> io::Error {
    use tokio::io::AsyncWriteExt;
    let _ = tokio::time::timeout(APP_CLOSE_TIMEOUT, client.shutdown()).await;
    error
}

/// Serve DNS over TCP on `client` (RFC 1035 §4.2.2: each message behind a
/// two-byte length) until it closes, goes idle, or sends something that is
/// not a DNS message.
async fn serve_dns_tcp<S>(mut client: S, proxy: Arc<DnsProxy>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(DNS_TCP_IDLE, client.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            // Closed between messages, or idle: the ordinary ends.
            Ok(Err(_)) | Err(_) => break,
        }
        let len = u16::from_be_bytes(len) as usize;
        if len < 12 {
            break; // shorter than a DNS header
        }
        let mut query = vec![0u8; len];
        match tokio::time::timeout(DNS_TCP_IDLE, client.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
        let Some(answer) = answer_dns_tcp(&proxy, query).await else {
            break;
        };
        let Ok(answer_len) = u16::try_from(answer.len()) else {
            break;
        };
        // One write: some resolvers read the length and the message at once.
        let mut framed = Vec::with_capacity(2 + answer.len());
        framed.extend_from_slice(&answer_len.to_be_bytes());
        framed.extend_from_slice(&answer);
        client.write_all(&framed).await?;
    }
    let _ = tokio::time::timeout(APP_CLOSE_TIMEOUT, client.shutdown()).await;
    Ok(())
}

/// The answer to one message that arrived over TCP. The proxy decides as
/// it does for UDP (`.fips`, public names over fips, the upstreams), and
/// asks the upstreams over UDP; when what comes back is truncated — the
/// case a resolver turns to TCP for — the upstreams are asked again over
/// TCP and that answer is the one sent. It is sent as the upstream gave it:
/// a TTL cap the proxy put on the truncated answer is not carried over.
async fn answer_dns_tcp(proxy: &Arc<DnsProxy>, query: Vec<u8>) -> Option<Vec<u8>> {
    // The proxy's lookup blocks, for seconds when the upstreams are slow.
    let Some(slot) = proxy.slot() else {
        return crate::dns::servfail_for(&query);
    };
    let (p, q) = (proxy.clone(), query.clone());
    let answer = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        p.answer(&q)
    })
    .await
    .ok()
    .flatten()?;
    let truncated = answer.get(2).is_some_and(|flags| flags & 0x02 != 0);
    if truncated {
        for &upstream in &proxy.upstreams {
            let asked = ask_upstream_tcp(upstream, &query, &proxy.protect);
            if let Ok(Ok(full)) = tokio::time::timeout(DNS_TCP_UPSTREAM, asked).await {
                return Some(full);
            }
        }
    }
    Some(answer)
}

/// One query to `upstream` over TCP, on a protected socket.
async fn ask_upstream_tcp(
    upstream: std::net::SocketAddr,
    query: &[u8],
    protect: &Option<SocketProtect>,
) -> io::Result<Vec<u8>> {
    let socket = if upstream.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect_fd(&socket, protect);
    let mut server = socket.connect(upstream).await?;
    let len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    server.write_all(&framed).await?;
    let mut len = [0u8; 2];
    server.read_exact(&mut len).await?;
    let mut answer = vec![0u8; u16::from_be_bytes(len) as usize];
    server.read_exact(&mut answer).await?;
    if answer.len() < 12 || answer[..2] != query[..2] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not the answer to this query"));
    }
    Ok(answer)
}

async fn forward_udp(
    mut client: ipstack::IpStackUdpStream,
    protect: Option<SocketProtect>,
) -> io::Result<()> {
    let dst = client.peer_addr();
    // Bind to a parsed SocketAddr, NOT a &str: string binds go through
    // tokio's spawn_blocking resolver and summon the blocking pool, whose
    // threads a runtime drop then waits on (see the shutdown_timeout above).
    let bind: std::net::SocketAddr = if dst.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let server = UdpSocket::bind(bind).await?;
    protect_fd(&server, &protect);
    server.connect(dst).await?;

    let mut from_client = vec![0u8; UDP_MAX_DATAGRAM];
    let mut from_server = vec![0u8; UDP_MAX_DATAGRAM];
    loop {
        tokio::select! {
            r = client.read(&mut from_client) => {
                let n = r?;
                if n == 0 {
                    return Ok(()); // idle-timeout close from ipstack
                }
                server.send(&from_client[..n]).await?;
            }
            r = server.recv(&mut from_server) => {
                let n = r?;
                client.write_all(&from_server[..n]).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `join()` must return promptly even when the device stays idle-pending
    /// (a live inbound sender, no packets) — the state a real disconnect left
    /// the forwarder in, which used to hang `engine::stop()` forever.
    #[test]
    fn join_returns_promptly_while_device_pends() {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        let (to_tun, _to_tun_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let running = Arc::new(AtomicBool::new(true));
        let forwarder =
            Forwarder::spawn(inbound_rx, to_tun, None, running.clone(), 1280, None).unwrap();

        running.store(false, Ordering::Relaxed);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            forwarder.join();
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("forwarder join hung despite shutdown signal");
        drop(inbound_tx); // keep the sender alive until after the join
    }

    /// A minimal query: id, RD, one question (`example.com A`).
    fn query(id: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    /// The query turned into a response, truncated or not, with `marker`
    /// appended so the test can tell which transport's answer it got.
    fn response(query: &[u8], truncated: bool, marker: u8) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] |= 0x80 | if truncated { 0x02 } else { 0 };
        r.push(marker);
        r
    }

    /// An upstream on one port over both transports: UDP answers with
    /// `udp_truncated`, TCP always in full.
    fn upstream(udp_truncated: bool) -> std::net::SocketAddr {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = std::net::TcpListener::bind(addr).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                let _ = udp.send_to(&response(&buf[..n], udp_truncated, b'U'), from);
            }
        });
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            while let Ok((mut conn, _)) = tcp.accept() {
                let mut len = [0u8; 2];
                if conn.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if conn.read_exact(&mut q).is_err() {
                    continue;
                }
                let r = response(&q, false, b'T');
                let mut framed = (r.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&r);
                let _ = conn.write_all(&framed);
            }
        });
        addr
    }

    fn proxy(upstream: std::net::SocketAddr) -> Arc<DnsProxy> {
        let (writer_tx, _) = std::sync::mpsc::channel();
        Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(),
            upstreams: vec![upstream],
            writer_tx,
            protect: None,
            hosts: None,
            names: None,
            in_flight: Default::default(),
        })
    }

    /// Two framed queries on one connection, each answered in its frame.
    fn ask_twice(proxy: Arc<DnsProxy>) -> Vec<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (mut app, served) = tokio::io::duplex(4096);
            let server = tokio::spawn(serve_dns_tcp(served, proxy));
            let mut answers = Vec::new();
            for id in [0x1111u16, 0x2222] {
                let q = query(id);
                let mut framed = (q.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&q);
                app.write_all(&framed).await.unwrap();
                let mut len = [0u8; 2];
                app.read_exact(&mut len).await.unwrap();
                let mut a = vec![0u8; u16::from_be_bytes(len) as usize];
                app.read_exact(&mut a).await.unwrap();
                assert_eq!(a[..2], id.to_be_bytes());
                answers.push(a);
            }
            // Closing the app's side ends the connection cleanly.
            drop(app);
            server.await.unwrap().unwrap();
            answers
        })
    }

    /// An answer that fits is the proxy's own, as over UDP.
    #[test]
    fn dns_over_tcp_is_answered_by_the_proxy() {
        for a in ask_twice(proxy(upstream(false))) {
            assert_eq!(a[2] & 0x02, 0, "not truncated");
            assert_eq!(a.last(), Some(&b'U'), "the UDP upstream's answer");
        }
    }

    /// A truncated answer is what TCP was asked for: the upstream is asked
    /// again over TCP and the full answer goes back.
    #[test]
    fn a_truncated_answer_is_fetched_again_over_tcp() {
        for a in ask_twice(proxy(upstream(true))) {
            assert_eq!(a[2] & 0x02, 0, "not truncated");
            assert_eq!(a.last(), Some(&b'T'), "the TCP upstream's answer");
        }
    }
}
