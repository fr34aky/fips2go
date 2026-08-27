//! Engine: one embedded FIPS node per process, started/stopped from JNI.
//!
//! `start()` builds the node from an in-memory config, wires the app-owned
//! TUN seam and socket-protect hook, runs the node on a dedicated
//! current-thread tokio runtime, and spawns the fd pump. `stop()` unwinds it
//! all and closes the dup'd fd last.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fips::control::ControlCommandHandle;
use fips::control::read_handle::ControlReadHandle;

use crate::config::ShimConfig;
use crate::dns::DnsProxy;
use crate::forward::Forwarder;
use crate::pump::{Pump, PumpConfig};

/// Clearnet forwarder MTU — matches the tunnel MTU.
const FORWARD_MTU: u16 = 1280;

/// How long `start()` waits for the node to reach a started state.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// The in-process FIPS DNS responder (`dns.enabled` default bind).
const LOCAL_RESPONDER: &str = "[::1]:5354";

/// The DNS server address advertised into the tunnel (`fd00::53`).
///
/// It must sit inside the routed `fd00::/8` range but must NOT be the node's
/// own `/128` tun address: a packet to the interface's own address is
/// delivered locally by the kernel and never written to the TUN fd, so our
/// reader would never see the query. A sentinel that isn't assigned to the
/// interface is instead routed *out* the fd, where the pump peels off
/// `:53` traffic to the DNS proxy. Kept in sync with the Kotlin side via
/// [`dns_server_string`] (exposed over JNI).
pub const DNS_SENTINEL: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53];

/// The sentinel as an IPv6 string, for `VpnService.Builder.addDnsServer`.
pub fn dns_server_string() -> String {
    std::net::Ipv6Addr::from(DNS_SENTINEL).to_string()
}

/// Cap the FMP encrypt/decrypt worker pools for mobile before the node
/// starts. FIPS reads `FIPS_ENCRYPT_WORKERS` / `FIPS_DECRYPT_WORKERS` at
/// `start()` (else `available_parallelism()` → ~8 each). We set them here,
/// respecting any value already present in the environment.
///
/// Called on the connect thread before the node thread is spawned, so the
/// write happens-before any FIPS reader — no concurrent `getenv` for these
/// keys is in flight, which is what makes the `set_var` sound.
fn apply_worker_thread_caps(worker_threads: usize) {
    for key in ["FIPS_ENCRYPT_WORKERS", "FIPS_DECRYPT_WORKERS"] {
        if std::env::var_os(key).is_none() {
            // SAFETY: single-threaded w.r.t. these keys — see doc comment.
            unsafe { std::env::set_var(key, worker_threads.to_string()) };
        }
    }
    tracing::info!(worker_threads, "capped FMP worker pools for mobile");
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// Serializes start / stop / network_changed end-to-end. Without it, a start
/// can run while a previous engine is still tearing down (the `ENGINE` slot
/// is already empty mid-stop) and race the old node for `[::1]:5354` — the
/// new node then starts DEGRADED with no `.fips` responder (observed
/// on-device: `Address already in use` → every `.fips` lookup SERVFAILs).
/// Never held by status/query reads, so UI polls stay responsive.
static LIFECYCLE: Mutex<()> = Mutex::new(());
/// Guards the (lock-free) startup window so `status()`/`stop()` from the UI
/// thread never block behind a slow `start()` holding the `ENGINE` mutex.
static STARTING: AtomicBool = AtomicBool::new(false);

struct Engine {
    running: Arc<AtomicBool>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    node_thread: Option<std::thread::JoinHandle<()>>,
    pump: Option<Pump>,
    forwarder: Option<Forwarder>,
    read_handle: ControlReadHandle,
    /// Mutating twin of `read_handle`: routes `connect` / `disconnect` onto
    /// the node's rx_loop (Diagnostics' manual dial of mDNS-seen peers).
    cmd_handle: ControlCommandHandle,
    npub: String,
    address: String,
    /// Our dup of the VpnService TUN fd; closed after the pump joins.
    tun_fd: RawFd,
    /// Kept so [`network_changed`] can rebuild the node (fresh, re-protected
    /// underlay socket on the new network) on the same TUN fd.
    config_json: String,
    protect: Option<fips::SocketProtect>,
}

/// What `start()` reports back to Kotlin.
#[derive(serde::Serialize)]
pub struct StartInfo {
    pub npub: String,
    pub address: String,
}

pub fn is_running() -> bool {
    ENGINE.lock().unwrap().is_some()
}

/// Start the embedded node. `tun_fd` is borrowed (dup'd internally); the
/// caller keeps ownership of its own fd. `protect` receives every underlay
/// socket fd (wire it to `VpnService.protect`).
///
/// The `ENGINE` mutex is held only for the final install, not for the whole
/// (possibly slow) node startup — `status()` polls stay responsive.
pub fn start(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<fips::SocketProtect>,
) -> Result<StartInfo, String> {
    let _lifecycle = LIFECYCLE.lock().unwrap();
    start_locked(config_json, tun_fd, protect)
}

/// [`start`] body; caller must hold [`LIFECYCLE`].
fn start_locked(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<fips::SocketProtect>,
) -> Result<StartInfo, String> {
    if ENGINE.lock().unwrap().is_some() {
        return Err("already running".into());
    }
    if STARTING.swap(true, Ordering::SeqCst) {
        return Err("start already in progress".into());
    }
    let result = start_inner(config_json, tun_fd, protect);
    let outcome = match result {
        Ok((engine, info)) => {
            *ENGINE.lock().unwrap() = Some(engine);
            Ok(info)
        }
        Err(e) => Err(e),
    };
    STARTING.store(false, Ordering::SeqCst);
    outcome
}

fn start_inner(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<fips::SocketProtect>,
) -> Result<(Engine, StartInfo), String> {
    let shim_config = ShimConfig::from_json(config_json)?;
    crate::init_logging(shim_config.log_level.as_deref());
    apply_worker_thread_caps(shim_config.worker_threads);
    let fips_config = shim_config.to_fips_config()?;

    let mut node = fips::Node::new(fips_config).map_err(|e| format!("node init: {e}"))?;
    let npub = node.npub();
    let our_fips_addr = *node.identity().address();
    let address = our_fips_addr.to_ipv6().to_string();

    // The Android seam: app-owned TUN channels, before start().
    let (outbound_tx, inbound_rx) = node.enable_app_owned_tun();
    // Keep a clone for rebuilds on network change (the original is moved into
    // the DNS proxy below).
    let engine_protect = protect.clone();
    if let Some(hook) = protect.clone() {
        node.set_socket_protect(hook);
    }
    let read_handle = node.control_read_handle();
    let cmd_handle = node.control_command_handle();

    // Node thread: current-thread runtime, same shape as the fips binary.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let node_thread = std::thread::Builder::new()
        .name("fips-node".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("tokio runtime: {e}")));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(e) = node.start().await {
                    let _ = ready_tx.send(Err(format!("node start: {e}")));
                    return;
                }
                // Processor needs the started transports' MTU floor.
                let _ = ready_tx.send(Ok(node.tun_packet_processor()));
                let result = node
                    .run_rx_loop_with_shutdown(async {
                        let _ = stop_rx.await;
                    })
                    .await;
                if let Err(e) = result {
                    tracing::error!(error = %e, "rx loop exited with error");
                }
                node.finish_shutdown().await;
            });
            // A plain `drop(runtime)` waits for ALL blocking-pool tasks
            // (nostr-sdk / DNS lookups use spawn_blocking, and a stray one
            // can sit in a long syscall timeout) — which hangs this thread,
            // and with it `stop()`'s join and the app's disconnect. Bound
            // the wait; stragglers are abandoned as detached threads.
            runtime.shutdown_timeout(Duration::from_secs(2));
            tracing::info!("node thread exited");
        })
        .map_err(|e| format!("spawn node thread: {e}"))?;

    let processor = match ready_rx.recv_timeout(START_TIMEOUT) {
        Ok(Ok(processor)) => processor,
        Ok(Err(e)) => {
            let _ = node_thread.join();
            return Err(e);
        }
        Err(RecvTimeoutError::Timeout) => return Err("node start timed out".into()),
        Err(RecvTimeoutError::Disconnected) => {
            let _ = node_thread.join();
            return Err("node thread died during start".into());
        }
    };

    // Own a dup of the fd so Kotlin's ParcelFileDescriptor lifetime and ours
    // are independent.
    let owned_fd = unsafe { libc::fcntl(tun_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if owned_fd < 0 {
        let _ = stop_tx.send(());
        let _ = node_thread.join();
        return Err(format!("dup tun fd: {}", std::io::Error::last_os_error()));
    }

    let running = Arc::new(AtomicBool::new(true));
    let (writer_tx, writer_rx) = std::sync::mpsc::channel();
    let dns = Arc::new(DnsProxy {
        local_responder: LOCAL_RESPONDER.parse().unwrap(),
        upstreams: shim_config.upstream_addrs(),
        writer_tx: writer_tx.clone(),
        protect: engine_protect.clone(),
    });

    // Clearnet forwarder (split-tunnel): non-mesh packets from the pump go
    // through a userspace stack and out on protected sockets.
    let (forwarder, forward_tx) = if shim_config.forward_clearnet {
        let (forward_tx, forward_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let forwarder = Forwarder::spawn(
            forward_rx,
            writer_tx.clone(),
            engine_protect.clone(),
            running.clone(),
            FORWARD_MTU,
        )
        .map_err(|e| {
            unsafe { libc::close(owned_fd) };
            format!("spawn forwarder: {e}")
        })?;
        (Some(forwarder), Some(forward_tx))
    } else {
        (None, None)
    };

    let pump = Pump::spawn(PumpConfig {
        tun_fd: owned_fd,
        running: running.clone(),
        processor,
        outbound_tx,
        inbound_rx,
        dns_addr: DNS_SENTINEL,
        dns,
        forward_tx,
        writer_tx,
        writer_rx,
    })
    .map_err(|e| {
        unsafe { libc::close(owned_fd) };
        format!("spawn pump: {e}")
    })?;

    tracing::info!(npub = %npub, address = %address, "fips engine started");
    let engine = Engine {
        running,
        stop_tx: Some(stop_tx),
        node_thread: Some(node_thread),
        pump: Some(pump),
        forwarder,
        read_handle,
        cmd_handle,
        npub: npub.clone(),
        address: address.clone(),
        tun_fd: owned_fd,
        config_json: config_json.to_string(),
        protect: engine_protect,
    };
    Ok((engine, StartInfo { npub, address }))
}

/// Stop the engine: drain the node, stop the pump, close our fd. Idempotent.
pub fn stop() {
    let _lifecycle = LIFECYCLE.lock().unwrap();
    stop_locked();
}

/// [`stop`] body; caller must hold [`LIFECYCLE`].
fn stop_locked() {
    let engine = ENGINE.lock().unwrap().take();
    let Some(mut engine) = engine else {
        return;
    };
    tracing::info!("fips engine stopping");
    if let Some(stop_tx) = engine.stop_tx.take() {
        let _ = stop_tx.send(());
    }
    engine.running.store(false, Ordering::Relaxed);
    if let Some(pump) = engine.pump.take() {
        pump.join(); // reader exits and drops forward_tx
    }
    if let Some(forwarder) = engine.forwarder.take() {
        // join() signals the forwarder's shutdown Notify: accept() can pend
        // indefinitely while ipstack drains old flows, so the closed device
        // alone must not be relied on to end the loop.
        forwarder.join();
    }
    if let Some(handle) = engine.node_thread.take() {
        let _ = handle.join();
    }
    unsafe { libc::close(engine.tun_fd) };
    tracing::info!("fips engine stopped");
}

/// Guards against overlapping / re-entrant rebuilds from a burst of network
/// callbacks.
static REBINDING: AtomicBool = AtomicBool::new(false);

/// Rebuild the node after an underlying-network change (Wi-Fi ↔ cellular).
///
/// The node has no runtime socket-rebind hook and, as observed on-device, does
/// not recover on its own: its UDP socket keeps a stale source/NAT binding and
/// the mesh silently black-holes. So we restart the node on the given TUN fd:
/// usually the same fd passed to [`start`], but Kotlin may pass a replacement
/// when it re-established the tunnel with different routes (e.g. dropping or
/// adding `::/0` as underlay IPv6 comes and goes) — we dup whatever we get.
/// The fd is owned by the Kotlin `ParcelFileDescriptor` either way. No-op when
/// not running.
///
/// `config_json`: when `Some`, replaces the stored config for the rebuilt
/// node — Kotlin regenerates it on every rebind so per-network state (the
/// FIPS Hotspot transport overlay) rides the same coalesced path; `None`
/// keeps the config from the previous start.
pub fn network_changed(tun_fd: RawFd, config_json: Option<&str>) -> Result<(), String> {
    if REBINDING.swap(true, Ordering::SeqCst) {
        // A rebuild is already running; the network state it reads will be the
        // latest, so coalescing this callback into it is correct.
        return Ok(());
    }
    let result = {
        let _lifecycle = LIFECYCLE.lock().unwrap();
        // Snapshot what we need to rebuild; bail if not running (e.g. a
        // disconnect won the lock first).
        let rebuild = {
            let slot = ENGINE.lock().unwrap();
            slot.as_ref()
                .map(|e| (e.config_json.clone(), e.protect.clone()))
        };
        match rebuild {
            None => Ok(()),
            Some((stored_config, protect)) => {
                let config_json = config_json.unwrap_or(&stored_config);
                tracing::info!("underlying network changed; restarting node on the tun fd");
                stop_locked();
                start_locked(config_json, tun_fd, protect).map(|_| ())
            }
        }
    };
    REBINDING.store(false, Ordering::SeqCst);
    if let Err(e) = &result {
        tracing::error!(error = %e, "node rebuild after network change failed");
    }
    result
}

/// Compact status JSON for the UI. Always answers, running or not.
pub fn status_json() -> String {
    let slot = ENGINE.lock().unwrap();
    let value = match slot.as_ref() {
        None => serde_json::json!({ "running": false }),
        Some(engine) => serde_json::json!({
            "running": true,
            "npub": engine.npub,
            "address": engine.address,
            "status": engine.read_handle.query("show_status", None)
                .and_then(|mut v| v.get_mut("data").map(serde_json::Value::take)),
        }),
    };
    value.to_string()
}

/// Generic read-only query passthrough (any snapshot-served `show_*`).
pub fn query_json(command: &str, params_json: &str) -> String {
    let slot = ENGINE.lock().unwrap();
    let Some(engine) = slot.as_ref() else {
        return r#"{"status":"error","message":"not running"}"#.to_string();
    };
    let params = if params_json.trim().is_empty() {
        None
    } else {
        match serde_json::from_str(params_json) {
            Ok(v) => Some(v),
            Err(e) => {
                return serde_json::json!({
                    "status": "error",
                    "message": format!("bad params: {e}"),
                })
                .to_string();
            }
        }
    };
    match engine.read_handle.query(command, params) {
        Some(response) => response.to_string(),
        None => serde_json::json!({
            "status": "error",
            "message": format!("unknown or non-snapshot command: {command}"),
        })
        .to_string(),
    }
}

/// Manual dial (Diagnostics "Connect" on an mDNS-seen peer): round-trip a
/// `connect` command through the node's rx_loop. Blocking — call off the UI
/// thread. The `ENGINE` lock is dropped before the round-trip so status
/// polls never queue behind a slow handshake initiation.
pub fn connect_peer_json(npub: &str, address: &str) -> String {
    let handle = ENGINE.lock().unwrap().as_ref().map(|e| e.cmd_handle.clone());
    let Some(handle) = handle else {
        return r#"{"status":"error","message":"not running"}"#.to_string();
    };
    let params = serde_json::json!({
        "npub": npub,
        "address": address,
        "transport": "udp",
    });
    match handle.command_blocking("connect", Some(params)) {
        Ok(response) => response.to_string(),
        Err(e) => serde_json::json!({ "status": "error", "message": e }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full lifecycle on the host: a pipe stands in for the TUN fd, a
    /// loopback UDP transport stands in for the network. Start → status →
    /// query → stop, twice (restartability).
    #[test]
    fn engine_lifecycle_on_host() {
        let identity = crate::config::derive_identity("").unwrap();
        let config = serde_json::json!({
            "nsec": identity.nsec,
            "peers": [],
            "enable_nostr": false,
            "enable_fips_dns": false, // avoid [::1]:5354 collisions on the host
            "forward_clearnet": false, // no tun/clearnet in the host test
            "battery_saver": false, // keep the 1s tick so the snapshot publishes fast
            "log_level": "warn",
        })
        .to_string();

        for round in 0..2 {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let [read_fd, write_fd] = fds;

            let protected = Arc::new(AtomicBool::new(false));
            let sink = protected.clone();
            let info = start(
                &config,
                read_fd,
                Some(Arc::new(move |_fd| {
                    sink.store(true, Ordering::Relaxed);
                })),
            )
            .unwrap_or_else(|e| panic!("start (round {round}): {e}"));
            assert_eq!(info.npub, identity.npub);
            assert!(is_running());
            assert!(
                protected.load(Ordering::Relaxed),
                "protect hook saw the UDP socket"
            );
            assert!(start(&config, read_fd, None).is_err(), "double start");

            let status: serde_json::Value = serde_json::from_str(&status_json()).unwrap();
            assert_eq!(status["running"], true);
            assert_eq!(status["address"], identity.address);
            assert!(
                status["status"].is_object(),
                "show_status snapshot present: {status}"
            );

            let peers = query_json("show_stats_list", "");
            let peers: serde_json::Value = serde_json::from_str(&peers).unwrap();
            assert_eq!(peers["status"], "ok");

            // The mDNS-sightings query is snapshot-served (empty registry on
            // the host — no LAN discovery in this test, only the shape).
            let lan = query_json("show_lan_peers", "");
            let lan: serde_json::Value = serde_json::from_str(&lan).unwrap();
            assert_eq!(lan["status"], "ok");
            assert!(lan["data"]["lan_peers"].is_array(), "lan_peers array: {lan}");

            // Command round-trip through the rx_loop: a bad npub must come
            // back as a structured error — proves the embedder command
            // channel is served, not just that the JSON was well-formed.
            let bad = connect_peer_json("npub1notvalid", "127.0.0.1:1");
            let bad: serde_json::Value = serde_json::from_str(&bad).unwrap();
            assert_eq!(bad["status"], "error", "bad npub rejected: {bad}");

            stop();
            assert!(!is_running());
            stop(); // idempotent
            unsafe { libc::close(write_fd) };
            unsafe { libc::close(read_fd) };
        }
    }
}
