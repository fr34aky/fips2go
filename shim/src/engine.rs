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

use fips::control::read_handle::ControlReadHandle;

use crate::config::ShimConfig;
use crate::dns::DnsProxy;
use crate::pump::{Pump, PumpConfig};

/// How long `start()` waits for the node to reach a started state.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// The in-process FIPS DNS responder (`dns.enabled` default bind).
const LOCAL_RESPONDER: &str = "[::1]:5354";

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);
/// Guards the (lock-free) startup window so `status()`/`stop()` from the UI
/// thread never block behind a slow `start()` holding the `ENGINE` mutex.
static STARTING: AtomicBool = AtomicBool::new(false);

struct Engine {
    running: Arc<AtomicBool>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    node_thread: Option<std::thread::JoinHandle<()>>,
    pump: Option<Pump>,
    read_handle: ControlReadHandle,
    npub: String,
    address: String,
    /// Our dup of the VpnService TUN fd; closed after the pump joins.
    tun_fd: RawFd,
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
    let fips_config = shim_config.to_fips_config()?;

    let mut node = fips::Node::new(fips_config).map_err(|e| format!("node init: {e}"))?;
    let npub = node.npub();
    let our_fips_addr = *node.identity().address();
    let address = our_fips_addr.to_ipv6().to_string();

    // The Android seam: app-owned TUN channels, before start().
    let (outbound_tx, inbound_rx) = node.enable_app_owned_tun();
    if let Some(hook) = protect.clone() {
        node.set_socket_protect(hook);
    }
    let read_handle = node.control_read_handle();

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
        protect,
    });

    let pump = Pump::spawn(PumpConfig {
        tun_fd: owned_fd,
        running: running.clone(),
        processor,
        outbound_tx,
        inbound_rx,
        our_addr: *our_fips_addr.as_bytes(),
        dns,
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
        read_handle,
        npub: npub.clone(),
        address: address.clone(),
        tun_fd: owned_fd,
    };
    Ok((engine, StartInfo { npub, address }))
}

/// Stop the engine: drain the node, stop the pump, close our fd. Idempotent.
pub fn stop() {
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
        pump.join();
    }
    if let Some(handle) = engine.node_thread.take() {
        let _ = handle.join();
    }
    unsafe { libc::close(engine.tun_fd) };
    tracing::info!("fips engine stopped");
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

            stop();
            assert!(!is_running());
            stop(); // idempotent
            unsafe { libc::close(write_fd) };
            unsafe { libc::close(read_fd) };
        }
    }
}
