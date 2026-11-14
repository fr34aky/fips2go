//! The TUN fd pump: bridges the VpnService fd to the node's app-owned TUN
//! channels, with the node's own `TunPacketProcessor` deciding each outbound
//! packet (system-TUN parity) and the DNS proxy intercepting queries.
//!
//! Threads (all owned here). Idle threads make ZERO wakeups — measured
//! on-device, the previous 250 ms stop-flag ticks were 12 wake/s across the
//! three threads, ~62% of the whole process's idle wakeups. Each thread has
//! an explicit wake for shutdown instead:
//! - **reader** — `poll()`+`read()` the fd (infinite timeout); DNS intercept
//!   → processor → forward / write-back / drop. Woken by an eventfd that
//!   [`Pump::join`] and [`Pump::swap_fd`] write.
//! - **writer** — single writer of the fd; blocking-drains `writer_rx`.
//!   Woken by an empty-`Vec` sentinel (no real packet is empty: DNS replies,
//!   forwarder output, and mesh packets are all ≥ 40 bytes).
//!
//! Reader and writer are the only threads that touch the fd, and they form
//! one generation: [`Pump::swap_fd`] stops them and starts the next on a new
//! fd (a new tunnel after an IPv6-route flip or a changed app selection)
//! while the bridge and everything upstream keep running.
//! - **bridge** — forwards mesh→app packets from the node's inbound receiver
//!   into `writer_rx`, so the writer is the fd's only writer (replies to the
//!   shim's own mesh flows are diverted to them instead). Ends when the
//!   node drops its inbound sender during drain.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fips::{TunPacketAction, TunPacketProcessor};

use crate::dns::DnsProxy;

/// Max IPv6 packet we accept from the fd (jumbo-safe; VpnService MTU is
/// far below this).
const READ_BUF: usize = 65536;
/// How long [`Pump::join`] waits for the threads before abandoning them.
/// Must cover the node's drain (2 s), which is what releases the bridge.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Writes failed in a row before the writer gives up: the fd is then dead
/// in a way no errno said, and looping on it would only burn the battery.
const MAX_WRITE_FAILURES: u32 = 256;
/// How long a write waits for a full TUN queue to drain before the packet
/// is dropped. Short: the writer is the only path back to the apps, and a
/// late packet is worth less than the ones queued behind it.
const WRITE_WAIT_MS: libc::c_int = 100;

/// Why a packet was not written to the TUN fd.
#[derive(Debug)]
enum WriteError {
    /// This packet is lost, the fd is still good: the kernel refused the
    /// packet (`EINVAL`), was out of buffers (`ENOBUFS`/`ENOMEM`), or its
    /// queue stayed full past [`WRITE_WAIT_MS`].
    Dropped(std::io::Error),
    /// The fd itself is gone (closed, or the tunnel behind it torn down).
    Fatal(std::io::Error),
}

/// Write one packet to the TUN fd. The fd is the `VpnService`'s and so
/// non-blocking: a full queue is waited out briefly, and an error about
/// this one packet costs this one packet — the writer used to end on any
/// error, and with it every reply to the apps until a reconnect, while the
/// engine went on reporting itself running.
fn write_packet(fd: RawFd, pkt: &[u8]) -> Result<(), WriteError> {
    let mut waited = false;
    loop {
        let n = unsafe { libc::write(fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) if !waited => {
                waited = true;
                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                unsafe { libc::poll(&mut pfd, 1, WRITE_WAIT_MS) };
                if pfd.revents & libc::POLLNVAL != 0 {
                    return Err(WriteError::Fatal(err));
                }
            }
            Some(libc::EBADF) | Some(libc::EBADFD) => return Err(WriteError::Fatal(err)),
            _ => return Err(WriteError::Dropped(err)),
        }
    }
}

pub struct Pump {
    /// The reader and writer on the current fd; replaced by [`Pump::swap_fd`].
    /// `None` only after a swap failed to stop them.
    io: Option<Io>,
    bridge: JoinHandle<()>,
    /// The bridge sends one marker as its last statement.
    bridge_done: Receiver<()>,
    /// Kept to send the writer its empty-`Vec` stop sentinel.
    writer_tx: Sender<Vec<u8>>,
    /// What every reader generation is built from.
    reader: ReaderCtx,
    running: Arc<AtomicBool>,
}

/// One reader/writer pair on one fd. A swap stops it and starts the next on
/// the new fd; the bridge, the writer channel and everything upstream of
/// them carry on, so packets queued meanwhile are written to the new fd.
struct Io {
    reader: JoinHandle<()>,
    /// Hands the writer channel's receiver back for the next generation.
    writer: JoinHandle<Receiver<Vec<u8>>>,
    /// eventfd the reader polls alongside the TUN fd; written to break the
    /// reader out of its otherwise-unbounded `poll()`.
    wake_fd: OwnedFd,
    /// Cleared to retire this generation. The writer ignores a stop
    /// sentinel while it is set: one left over from a previous generation
    /// must not stop the next.
    live: Arc<AtomicBool>,
    /// Reader and writer each send one marker as their last statement.
    done_rx: Receiver<()>,
}

#[derive(Clone)]
struct ReaderCtx {
    processor: TunPacketProcessor,
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    writer_tx: Sender<Vec<u8>>,
    dns_addr: [u8; 16],
    dns: Arc<DnsProxy>,
    forward_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    filter: Option<Arc<crate::filter::InboundFilter>>,
}

pub struct PumpConfig {
    /// The dup'd TUN fd (the pump does NOT own closing it; the engine does,
    /// after the threads have been joined).
    pub tun_fd: RawFd,
    pub running: Arc<AtomicBool>,
    pub processor: TunPacketProcessor,
    /// app → mesh (drained by the node's rx_loop).
    pub outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// mesh → app (fed by the node).
    pub inbound_rx: Receiver<Vec<u8>>,
    /// Replies to the shim's own in-process mesh flows ([`crate::meshhttp`]),
    /// taken out before the firewall and the TUN.
    pub divert: Arc<crate::meshhttp::Divert>,
    /// Stateful inbound firewall for the mesh→app direction (`None` = off).
    /// The reader feeds it outbound flows; the bridge asks it for verdicts.
    pub filter: Option<Arc<crate::filter::InboundFilter>>,
    /// The in-tunnel DNS server address (the `fd00::/8` sentinel we advertise
    /// to Android, NOT the node's own tun address). Packets to `dns_addr:53`
    /// are peeled off to the DNS proxy.
    pub dns_addr: [u8; 16],
    pub dns: Arc<DnsProxy>,
    /// Non-mesh packets (clearnet) go here, to the userspace forwarder. `None`
    /// disables forwarding (such packets are dropped) — used when the VPN only
    /// routes `fd00::/8` and no clearnet is expected.
    pub forward_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// The writer channel pair (the sender is also held by the DNS proxy).
    pub writer_tx: Sender<Vec<u8>>,
    pub writer_rx: Receiver<Vec<u8>>,
}

impl Pump {
    pub fn spawn(config: PumpConfig) -> std::io::Result<Self> {
        let PumpConfig {
            tun_fd,
            running,
            processor,
            outbound_tx,
            inbound_rx,
            divert,
            filter,
            dns_addr,
            dns,
            forward_tx,
            writer_tx,
            writer_rx,
        } = config;
        let reader = ReaderCtx {
            processor,
            outbound_tx,
            writer_tx: writer_tx.clone(),
            dns_addr,
            dns,
            forward_tx,
            filter: filter.clone(),
        };
        let io = spawn_io(tun_fd, &reader, &running, writer_rx)?;

        // Bridge: node inbound → writer channel. No tick: recv() blocks until
        // the node drops its inbound sender (end of drain) or the writer dies.
        // It never touches the fd, so it lives across fd swaps.
        let (bridge_done_tx, bridge_done) = std::sync::mpsc::channel();
        let bridge = {
            let running = running.clone();
            let writer_tx = writer_tx.clone();
            std::thread::Builder::new()
                .name("fips-tun-bridge".into())
                .spawn(move || {
                    // First-drop-per-port logging so a blocked service
                    // is visible in Diagnostics without log flooding.
                    let mut logged_ports = std::collections::HashSet::new();
                    while running.load(Ordering::Relaxed) {
                        match inbound_rx.recv() {
                            Ok(pkt) => {
                                let Some(pkt) = divert.claim(pkt) else {
                                    continue; // an in-process flow's reply
                                };
                                if let Some(f) = filter.as_deref()
                                    && !f.allow_inbound(&pkt)
                                {
                                    let (proto, port, src) =
                                        crate::filter::InboundFilter::describe(&pkt);
                                    if logged_ports.len() < 64 && logged_ports.insert(port) {
                                        tracing::info!(
                                            proto, port, src = %src,
                                            "inbound firewall: denied unsolicited mesh packet (allow the port in Settings if this is a service you run)"
                                        );
                                    }
                                    continue;
                                }
                                if writer_tx.send(pkt).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break, // node dropped its sender
                        }
                    }
                    tracing::info!("TUN bridge stopped");
                    let _ = bridge_done_tx.send(());
                })?
        };

        Ok(Self {
            io: Some(io),
            bridge,
            bridge_done,
            writer_tx,
            reader,
            running,
        })
    }

    /// Move the reader and writer onto `new_fd` (a dup the engine owns),
    /// leaving the node, the bridge and the writer channel running: what an
    /// IPv6-route flip or a changed app selection needs, since Android fixes
    /// a VPN's routes and allowed apps at `establish()` and so hands over a
    /// new tunnel. Packets the bridge queues meanwhile are written to the
    /// new fd. On success the old fd is unused and the caller may close it.
    /// An error means the old threads could not be stopped in time; the
    /// pump is then fd-less and the caller restarts the engine.
    pub fn swap_fd(&mut self, new_fd: RawFd) -> Result<(), String> {
        let io = self.io.take().ok_or("no reader/writer to swap")?;
        let writer_rx = stop_io(io, &self.writer_tx, SWAP_TIMEOUT)
            .ok_or("TUN reader/writer did not stop for the swap")?;
        let io = spawn_io(new_fd, &self.reader, &self.running, writer_rx)
            .map_err(|e| format!("spawn TUN reader/writer: {e}"))?;
        self.io = Some(io);
        Ok(())
    }

    /// Wake all pump threads and join them, bounded (call after clearing the
    /// `running` flag). On timeout the stragglers are abandoned — the engine
    /// is tearing down anyway, and a leaked parked thread beats a disconnect
    /// that never completes.
    pub fn join(self) {
        let Pump {
            io,
            bridge,
            bridge_done,
            writer_tx,
            ..
        } = self;
        let deadline = Instant::now() + JOIN_TIMEOUT;
        if let Some(io) = io
            && stop_io(io, &writer_tx, JOIN_TIMEOUT).is_none()
        {
            tracing::warn!("TUN reader/writer did not stop in time; abandoning");
        }
        // Bridge: released by the node dropping its inbound sender during
        // drain.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || bridge_done.recv_timeout(left).is_err() {
            tracing::warn!("TUN bridge did not stop in time; abandoning");
            return; // drop the handle → detach
        }
        let _ = bridge.join();
    }
}

/// How long a swap waits for the old reader and writer. They stop at once
/// unless a write is blocked; the engine's full restart is the fallback.
const SWAP_TIMEOUT: Duration = Duration::from_secs(2);

/// Start a reader/writer generation on `fd`.
fn spawn_io(
    fd: RawFd,
    ctx: &ReaderCtx,
    running: &Arc<AtomicBool>,
    writer_rx: Receiver<Vec<u8>>,
) -> std::io::Result<Io> {
    // Shutdown and swap wake for the reader's unbounded poll().
    let wake_fd = unsafe {
        let raw = libc::eventfd(0, libc::EFD_CLOEXEC);
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(raw)
    };
    let wake_raw = wake_fd.as_raw_fd();
    let live = Arc::new(AtomicBool::new(true));
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    // Reader: fd → (dns | mesh | clearnet-forward | write-back)
    let reader = {
        let ctx = ctx.clone();
        let running = running.clone();
        let live = live.clone();
        let done_tx = done_tx.clone();
        std::thread::Builder::new()
            .name("fips-tun-reader".into())
            .spawn(move || {
                run_reader(
                    fd,
                    wake_raw,
                    &running,
                    &live,
                    &ctx.processor,
                    &ctx.outbound_tx,
                    &ctx.writer_tx,
                    &ctx.dns_addr,
                    &ctx.dns,
                    ctx.forward_tx.as_ref(),
                    ctx.filter.as_deref(),
                );
                tracing::info!("TUN reader stopped");
                let _ = done_tx.send(());
            })?
    };

    // Writer: writer channel → fd. No tick: recv() blocks until the
    // empty-Vec stop sentinel (or all senders drop).
    let writer = {
        let running = running.clone();
        let writer_live = live.clone();
        let spawned = std::thread::Builder::new()
            .name("fips-tun-writer".into())
            .spawn(move || {
                let live = writer_live;
                // Writes failed in a row, reset by one that works.
                let mut failures = 0u32;
                while running.load(Ordering::Relaxed) && live.load(Ordering::Relaxed) {
                    match writer_rx.recv() {
                        // A stop sentinel: ours (the loop head then sees the
                        // flags cleared), or one a previous generation left
                        // behind, which is not.
                        Ok(pkt) if pkt.is_empty() => continue,
                        Ok(pkt) => match write_packet(fd, &pkt) {
                            Ok(()) => failures = 0,
                            Err(WriteError::Fatal(err)) => {
                                tracing::error!(error = %err, "TUN fd gone; stopping writer");
                                break;
                            }
                            Err(WriteError::Dropped(err)) => {
                                failures += 1;
                                // First of a run, then every power of two:
                                // visible, not a flood.
                                if failures.is_power_of_two() {
                                    tracing::warn!(error = %err, len = pkt.len(), failures, "TUN write failed; packet dropped");
                                }
                                if failures >= MAX_WRITE_FAILURES {
                                    tracing::error!(failures, "TUN writes keep failing; stopping writer");
                                    break;
                                }
                            }
                        },
                        Err(_) => break,
                    }
                }
                tracing::info!("TUN writer stopped");
                let _ = done_tx.send(());
                writer_rx
            });
        match spawned {
            Ok(handle) => handle,
            Err(e) => {
                // The reader is already up: retire it, or it would read a
                // fd nothing writes.
                // Joined before the caller may close the fd under it.
                live.store(false, Ordering::Relaxed);
                wake(&wake_fd);
                let _ = reader.join();
                return Err(e);
            }
        }
    };

    Ok(Io {
        reader,
        writer,
        wake_fd,
        live,
        done_rx,
    })
}

/// Retire a generation: wake the reader, send the writer its sentinel, and
/// wait (bounded) for both. Returns the writer channel's receiver for the
/// next generation, or `None` if they did not stop in time (abandoned).
fn stop_io(io: Io, writer_tx: &Sender<Vec<u8>>, timeout: Duration) -> Option<Receiver<Vec<u8>>> {
    let Io {
        reader,
        writer,
        wake_fd,
        live,
        done_rx,
    } = io;
    live.store(false, Ordering::Relaxed);
    // Reader: eventfd wake out of poll(). Writer: empty-Vec sentinel (queued
    // behind any real packets, which still get written).
    wake(&wake_fd);
    let _ = writer_tx.send(Vec::new());
    let deadline = Instant::now() + timeout;
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || done_rx.recv_timeout(left).is_err() {
            return None; // drop the handles → detach
        }
    }
    let _ = reader.join();
    writer.join().ok()
}

fn wake(wake_fd: &OwnedFd) {
    let one: u64 = 1;
    let _ = unsafe {
        libc::write(
            wake_fd.as_raw_fd(),
            (&raw const one).cast::<libc::c_void>(),
            8,
        )
    };
}

/// IPv6 mesh prefix (`fd00::/8`); anything else is clearnet.
const MESH_PREFIX: u8 = fips::identity::IPV6_ADDRESS_PREFIX;

/// Destination address of an IPv6 packet, for log lines (`::` if too short).
fn dst_of(packet: &[u8]) -> std::net::Ipv6Addr {
    let mut dst = [0u8; 16];
    if let Some(bytes) = packet.get(24..40) {
        dst.copy_from_slice(bytes);
    }
    std::net::Ipv6Addr::from(dst)
}

/// True if this is an IPv6 packet destined for the mesh (`fd00::/8`).
fn is_mesh_bound(packet: &[u8]) -> bool {
    packet.len() >= 40 && packet[0] >> 4 == 6 && packet[24] == MESH_PREFIX
}

#[allow(clippy::too_many_arguments)]
fn run_reader(
    fd: RawFd,
    wake_fd: RawFd,
    running: &AtomicBool,
    live: &AtomicBool,
    processor: &TunPacketProcessor,
    outbound_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    writer_tx: &Sender<Vec<u8>>,
    dns_addr: &[u8; 16],
    dns: &Arc<DnsProxy>,
    forward_tx: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
    filter: Option<&crate::filter::InboundFilter>,
) {
    let mut buf = vec![0u8; READ_BUF];
    while running.load(Ordering::Relaxed) && live.load(Ordering::Relaxed) {
        // Infinite poll — zero wakeups while the tunnel is idle. Shutdown
        // arrives on `wake_fd` (an eventfd written by `Pump::join`).
        let mut pfds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(error = %err, "TUN poll failed; stopping reader");
            break;
        }
        if pfds[1].revents != 0 {
            break; // shutdown or swap wake
        }
        let pfd = pfds[0];
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            tracing::info!("TUN fd closed; stopping reader");
            break;
        }
        if pfd.revents & libc::POLLIN == 0 {
            continue;
        }

        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted
                || err.kind() == std::io::ErrorKind::WouldBlock
            {
                continue;
            }
            tracing::warn!(error = %err, "TUN read failed; stopping reader");
            break;
        }
        if n == 0 {
            continue;
        }
        let packet = &mut buf[..n as usize];

        // DNS queries addressed to our resolver never enter the mesh.
        if DnsProxy::intercepts(packet, dns_addr) {
            dns.handle(packet.to_vec());
            continue;
        }
        // Nor does DNS over TCP (a resolver's retry after a truncated
        // answer): the sentinel is in fd00::/8, so it used to go to the
        // node as mesh traffic for an address nobody has, and the name
        // failed. The forwarder's stack ends the connection instead.
        if let Some(fwd) = forward_tx
            && DnsProxy::intercepts_tcp(packet, dns_addr)
        {
            if fwd.blocking_send(packet.to_vec()).is_err() {
                tracing::debug!("forwarder channel closed; dropping DNS-over-TCP packet");
            }
            continue;
        }

        // Clearnet (non-mesh) traffic → userspace forwarder, if enabled.
        // No forwarder: drop (the VPN shouldn't route clearnet to us then).
        if !is_mesh_bound(packet) {
            if let Some(fwd) = forward_tx
                && fwd.blocking_send(packet.to_vec()).is_err()
            {
                break; // forwarder gone
            }
            continue;
        }

        // Mesh-bound: run the node's outbound pipeline (filter/clamp/hairpin).
        match processor.process(packet) {
            TunPacketAction::Forward => {
                // Track the flow so the peer's replies pass the inbound
                // firewall (packet is post-processor but pre-encryption:
                // ports are still readable here).
                if let Some(f) = filter {
                    f.note_outbound(packet);
                }
                if outbound_tx.blocking_send(packet.to_vec()).is_err() {
                    break; // node gone
                }
            }
            TunPacketAction::Hairpin => {
                if writer_tx.send(packet.to_vec()).is_err() {
                    break;
                }
            }
            // Respond/Drop are the node refusing an outbound packet (no
            // route, filtered) — rare, and exactly what a "mesh site won't
            // load" report needs visible, so log at info.
            TunPacketAction::Respond(response) => {
                tracing::info!(dst = %dst_of(packet), "mesh outbound refused: ICMPv6 sent back");
                if writer_tx.send(response).is_err() {
                    break;
                }
            }
            TunPacketAction::Drop => {
                tracing::info!(dst = %dst_of(packet), "mesh outbound dropped by node processor");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe_nonblocking() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// A full queue costs the packet, not the writer; a dead fd ends it.
    #[test]
    fn a_write_error_is_per_packet_unless_the_fd_is_gone() {
        let (rx, tx) = pipe_nonblocking();
        assert!(write_packet(tx.as_raw_fd(), &[0u8; 64]).is_ok());

        // Fill the pipe: the next write would block.
        let chunk = [0u8; 4096];
        while unsafe { libc::write(tx.as_raw_fd(), chunk.as_ptr().cast(), chunk.len()) } > 0 {}
        let started = Instant::now();
        assert!(matches!(
            write_packet(tx.as_raw_fd(), &chunk),
            Err(WriteError::Dropped(_))
        ));
        assert!(started.elapsed() >= Duration::from_millis(WRITE_WAIT_MS as u64 / 2), "waited for room");

        // Room again: the same fd writes again.
        let mut sink = vec![0u8; 1 << 20];
        while unsafe { libc::read(rx.as_raw_fd(), sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
        assert!(write_packet(tx.as_raw_fd(), &[0u8; 64]).is_ok());

        // An fd that is not open is the end of the writer. (-1, not a
        // closed pipe end: another test could be handed that number.)
        assert!(matches!(write_packet(-1, &[0u8; 64]), Err(WriteError::Fatal(_))));
    }
}
