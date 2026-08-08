//! The TUN fd pump: bridges the VpnService fd to the node's app-owned TUN
//! channels, with the node's own `TunPacketProcessor` deciding each outbound
//! packet (system-TUN parity) and the DNS proxy intercepting queries.
//!
//! Threads (all owned here, all stop via the shared `running` flag):
//! - **reader** — `poll()`+`read()` the fd; DNS intercept → processor →
//!   forward / write-back / drop.
//! - **writer** — single writer of the fd; drains `writer_rx`.
//! - **bridge** — forwards mesh→app packets from the node's inbound receiver
//!   into `writer_rx`, so the writer is the fd's only writer.

use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use fips::{TunPacketAction, TunPacketProcessor};

use crate::dns::DnsProxy;

const POLL_INTERVAL_MS: i32 = 250;
const RECV_TICK: Duration = Duration::from_millis(250);
/// Max IPv6 packet we accept from the fd (jumbo-safe; VpnService MTU is
/// far below this).
const READ_BUF: usize = 65536;

pub struct Pump {
    threads: Vec<JoinHandle<()>>,
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
    pub our_addr: [u8; 16],
    pub dns: Arc<DnsProxy>,
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
            our_addr,
            dns,
            writer_tx,
            writer_rx,
        } = config;

        let mut threads = Vec::new();

        // Reader: fd → (dns | mesh | write-back)
        {
            let running = running.clone();
            let writer_tx = writer_tx.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-reader".into())
                    .spawn(move || {
                        run_reader(
                            tun_fd,
                            &running,
                            &processor,
                            &outbound_tx,
                            &writer_tx,
                            &our_addr,
                            &dns,
                        );
                        tracing::info!("TUN reader stopped");
                    })?,
            );
        }

        // Bridge: node inbound → writer channel
        {
            let running = running.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-bridge".into())
                    .spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            match inbound_rx.recv_timeout(RECV_TICK) {
                                Ok(pkt) => {
                                    if writer_tx.send(pkt).is_err() {
                                        break;
                                    }
                                }
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                        tracing::info!("TUN bridge stopped");
                    })?,
            );
        }

        // Writer: writer channel → fd
        {
            let running = running.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("fips-tun-writer".into())
                    .spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            match writer_rx.recv_timeout(RECV_TICK) {
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
                                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                        tracing::info!("TUN writer stopped");
                    })?,
            );
        }

        Ok(Self { threads })
    }

    /// Join all pump threads (call after clearing the `running` flag).
    pub fn join(self) {
        for handle in self.threads {
            let _ = handle.join();
        }
    }
}

fn run_reader(
    fd: RawFd,
    running: &AtomicBool,
    processor: &TunPacketProcessor,
    outbound_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    writer_tx: &Sender<Vec<u8>>,
    our_addr: &[u8; 16],
    dns: &Arc<DnsProxy>,
) {
    let mut buf = vec![0u8; READ_BUF];
    while running.load(Ordering::Relaxed) {
        // poll() with a timeout so the `running` flag is honored even when
        // the fd is quiet; blocking read() alone would pin the thread.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, POLL_INTERVAL_MS) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(error = %err, "TUN poll failed; stopping reader");
            break;
        }
        if ready == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            tracing::info!("TUN fd closed; stopping reader");
            break;
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

        // DNS queries addressed to us never enter the mesh.
        if DnsProxy::intercepts(packet, our_addr) {
            dns.handle(packet.to_vec());
            continue;
        }

        match processor.process(packet) {
            TunPacketAction::Forward => {
                if outbound_tx.blocking_send(packet.to_vec()).is_err() {
                    break; // node gone
                }
            }
            TunPacketAction::Hairpin => {
                if writer_tx.send(packet.to_vec()).is_err() {
                    break;
                }
            }
            TunPacketAction::Respond(response) => {
                if writer_tx.send(response).is_err() {
                    break;
                }
            }
            TunPacketAction::Drop => {}
        }
    }
}
