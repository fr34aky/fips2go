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
//!   [`Pump::join`] writes.
//! - **writer** — single writer of the fd; blocking-drains `writer_rx`.
//!   Woken by an empty-`Vec` sentinel (no real packet is empty: DNS replies,
//!   forwarder output, and mesh packets are all ≥ 40 bytes).
//! - **bridge** — forwards mesh→app packets from the node's inbound receiver
//!   into `writer_rx`, so the writer is the fd's only writer. Ends when the
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

pub struct Pump {
    threads: Vec<JoinHandle<()>>,
    /// eventfd the reader polls alongside the TUN fd; `join()` writes it to
    /// break the reader out of its otherwise-unbounded `poll()`.
    wake_fd: OwnedFd,
    /// Kept to send the writer its empty-`Vec` stop sentinel.
    writer_tx: Sender<Vec<u8>>,
    /// Each thread sends one marker as its last statement.
    done_rx: Receiver<()>,
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
            filter,
            dns_addr,
            dns,
            forward_tx,
            writer_tx,
            writer_rx,
        } = config;

        // Shutdown wake for the reader's unbounded poll().
        let wake_fd = unsafe {
            let fd = libc::eventfd(0, libc::EFD_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };
        let wake_raw = wake_fd.as_raw_fd();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let mut threads = Vec::new();

        // Reader: fd → (dns | mesh | clearnet-forward | write-back)
        {
            let running = running.clone();
            let writer_tx = writer_tx.clone();
            let done_tx = done_tx.clone();
            let filter = filter.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-reader".into())
                    .spawn(move || {
                        run_reader(
                            tun_fd,
                            wake_raw,
                            &running,
                            &processor,
                            &outbound_tx,
                            &writer_tx,
                            &dns_addr,
                            &dns,
                            forward_tx.as_ref(),
                            filter.as_deref(),
                        );
                        tracing::info!("TUN reader stopped");
                        let _ = done_tx.send(());
                    })?,
            );
        }

        // Bridge: node inbound → writer channel. No tick: recv() blocks until
        // the node drops its inbound sender (end of drain) or the writer dies.
        {
            let running = running.clone();
            let writer_tx = writer_tx.clone();
            let done_tx = done_tx.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-bridge".into())
                    .spawn(move || {
                        // First-drop-per-port logging so a blocked service
                        // is visible in Diagnostics without log flooding.
                        let mut logged_ports = std::collections::HashSet::new();
                        while running.load(Ordering::Relaxed) {
                            match inbound_rx.recv() {
                                Ok(pkt) => {
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
                        let _ = done_tx.send(());
                    })?,
            );
        }

        // Writer: writer channel → fd. No tick: recv() blocks until the
        // empty-Vec stop sentinel from join() (or all senders drop).
        {
            let running = running.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-writer".into())
                    .spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            match writer_rx.recv() {
                                Ok(pkt) if pkt.is_empty() => break, // stop sentinel
                                Ok(pkt) => {
                                    let n = unsafe {
                                        libc::write(
                                            tun_fd,
                                            pkt.as_ptr() as *const libc::c_void,
                                            pkt.len(),
                                        )
                                    };
                                    if n < 0 {
                                        let err = std::io::Error::last_os_error();
                                        tracing::warn!(error = %err, "TUN write failed; stopping writer");
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        tracing::info!("TUN writer stopped");
                        let _ = done_tx.send(());
                    })?,
            );
        }

        Ok(Self {
            threads,
            wake_fd,
            writer_tx,
            done_rx,
        })
    }

    /// Wake all pump threads and join them, bounded (call after clearing the
    /// `running` flag). On timeout the stragglers are abandoned — the engine
    /// is tearing down anyway, and a leaked parked thread beats a disconnect
    /// that never completes.
    pub fn join(self) {
        let Pump {
            threads,
            wake_fd,
            writer_tx,
            done_rx,
        } = self;

        // Reader: eventfd wake out of poll(). Writer: empty-Vec sentinel
        // (queued behind any real packets, which still get written). Bridge:
        // released by the node dropping its inbound sender during drain.
        let one: u64 = 1;
        let _ = unsafe {
            libc::write(
                wake_fd.as_raw_fd(),
                (&raw const one).cast::<libc::c_void>(),
                8,
            )
        };
        let _ = writer_tx.send(Vec::new());

        let deadline = Instant::now() + JOIN_TIMEOUT;
        let mut done = 0;
        while done < threads.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || done_rx.recv_timeout(left).is_err() {
                break;
            }
            done += 1;
        }
        if done < threads.len() {
            tracing::warn!(
                stuck = threads.len() - done,
                "pump thread(s) did not stop in time; abandoning"
            );
            return; // drop handles → detach; wake_fd closes on drop
        }
        for handle in threads {
            let _ = handle.join();
        }
    }
}

/// IPv6 mesh prefix (`fd00::/8`); anything else is clearnet.
const MESH_PREFIX: u8 = fips::identity::FIPS_ADDRESS_PREFIX;

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
    processor: &TunPacketProcessor,
    outbound_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    writer_tx: &Sender<Vec<u8>>,
    dns_addr: &[u8; 16],
    dns: &Arc<DnsProxy>,
    forward_tx: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
    filter: Option<&crate::filter::InboundFilter>,
) {
    let mut buf = vec![0u8; READ_BUF];
    while running.load(Ordering::Relaxed) {
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
            break; // shutdown wake
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
