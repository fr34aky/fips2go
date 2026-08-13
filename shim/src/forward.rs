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
//! handled earlier in the pump.

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

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_DATAGRAM: usize = 65535;

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
                rt.block_on(run(inbound, to_tun, protect, running, shutdown_rx, mtu));
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
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
    };
    tokio::io::copy_bidirectional(&mut client, &mut server)
        .await
        .map(|_| ())
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
            Forwarder::spawn(inbound_rx, to_tun, None, running.clone(), 1280).unwrap();

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
}
