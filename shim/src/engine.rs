//! Engine: one embedded FIPS node per process, started/stopped from JNI.
//!
//! `start()` builds the node from an in-memory config, wires the app-owned
//! TUN seam, hands the node's UDP sockets to the protect hook, runs the node
//! on a dedicated current-thread tokio runtime, and spawns the fd pump. `stop()` unwinds it
//! all and closes the dup'd fd last.

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::SocketProtect;
use crate::config::ShimConfig;
use crate::control::{Cached, Control};
use crate::dns::DnsProxy;
use crate::forward::Forwarder;
use crate::pump::{Pump, PumpConfig};

/// Clearnet forwarder MTU — matches the tunnel MTU.
const FORWARD_MTU: u16 = 1280;

/// How long `start()` waits for the node to reach a started state.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long `start()` then waits for the node's control socket, which the
/// node binds on a task of its own once its rx loop runs. Milliseconds in
/// practice; past this the engine runs with no node status to show.
const CONTROL_WAIT: Duration = Duration::from_secs(2);
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
/// every `start()` (else `available_parallelism()` → ~8 each). We set them
/// here on every engine start, so a changed setting applies on the next
/// connect — except for a key that was already in the environment before
/// the first start, which is someone else's choice and is left alone.
///
/// Called under `LIFECYCLE` before the node thread is spawned, so no FIPS
/// reader of these keys is running. Other threads of the process are alive
/// (always were: the JVM's), and `setenv` is not safe against a concurrent
/// `getenv` elsewhere, so the write is skipped whenever the value already
/// matches — it happens on the first start and after a settings change only.
fn apply_worker_thread_caps(worker_threads: usize) {
    const KEYS: [&str; 2] = ["FIPS_ENCRYPT_WORKERS", "FIPS_DECRYPT_WORKERS"];
    // Which keys came from outside, decided once, before we write any.
    static EXTERNAL: std::sync::OnceLock<[bool; 2]> = std::sync::OnceLock::new();
    let external = EXTERNAL.get_or_init(|| KEYS.map(|key| std::env::var_os(key).is_some()));
    let wanted = worker_threads.to_string();
    for (key, external) in KEYS.iter().zip(external) {
        if *external {
            tracing::info!(key, "worker pool size taken from the environment, setting ignored");
            continue;
        }
        if std::env::var_os(key).is_some_and(|v| v == wanted.as_str()) {
            continue;
        }
        // SAFETY: no reader of these keys is running — see doc comment.
        unsafe { std::env::set_var(key, &wanted) };
    }
    tracing::info!(worker_threads, "capped FMP worker pools for mobile");
}

/// Where the node's control socket goes when the config names no place
/// (`control_path`): the system's temporary directory, one file per start.
/// The app always names one — an app cannot write to Android's temporary
/// directory — so this is for the host (tests, the smoke run).
fn default_control_path() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir()
        .join(format!(
            "fips2go-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
        .to_string_lossy()
        .into_owned()
}

/// Lock a mutex whether or not a thread panicked while holding it. Nothing
/// guarded here is left half-written by a panic (the `ENGINE` slot is only
/// ever replaced whole), and refusing a poisoned lock would turn one caught
/// panic into an engine that can never be stopped or queried again.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Clears a "busy" flag when dropped, so a panic cannot leave it set.
struct ClearOnDrop(&'static AtomicBool);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
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
    /// Which start this is (see [`STARTS`]); read by the tests.
    #[cfg_attr(not(test), allow(dead_code))]
    start: u64,
    running: Arc<AtomicBool>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    node_thread: Option<std::thread::JoinHandle<()>>,
    pump: Option<Pump>,
    forwarder: Option<Forwarder>,
    /// The node's control socket: every `show_*` query (answered from the
    /// last reply, see [`Cached`]: Kotlin polls on its main thread), and the
    /// `connect` command (Diagnostics' manual dial of mDNS-seen peers).
    control: Arc<Cached>,
    npub: String,
    address: String,
    /// Our dup of the VpnService TUN fd; closed after the pump joins.
    tun_fd: RawFd,
    /// Kept so [`network_changed`] can tell a new tunnel (same config: swap
    /// the pump's fd) from a changed config (restart the node).
    config_json: String,
    protect: Option<SocketProtect>,
    /// Wakes the node's medium-change detector (`node.netmon.*`) — see
    /// [`network_hint`]. Per node: refreshed on every (re)start.
    netmon: fips::NetmonTrigger,
    /// Live view of the Nostr relay pool (URL + connection state). The pool
    /// can only be awaited on the node runtime, so a task there refreshes
    /// this slot — but only when poked by `status_json` (the UI's 2 s poll
    /// while the Overview is on screen), never on its own timer: nothing
    /// should wake the data-path runtime for a value nobody is reading.
    /// Empty while Nostr is disabled.
    relay_status: Arc<Mutex<Vec<fips::nostr::RelayStatusView>>>,
    relay_refresh: Arc<tokio::sync::Notify>,
    /// What [`mesh_http_get_json`] borrows to speak TCP over the mesh from
    /// inside the process (the Mesh names sync).
    mesh: Arc<crate::meshhttp::MeshLink>,
    /// Public domain names over fips, when on; its caches are flushed on a
    /// network hint since "offline" and "online" decisions differ.
    names: Option<Arc<crate::names::Names>>,
    /// Exit-node selection (internet traffic via an exit, or the phone's
    /// own connection); switched in place by [`network_changed`].
    exit: Arc<crate::exit::ExitSwitch>,
}

/// What `start()` reports back to Kotlin.
#[derive(serde::Serialize)]
pub struct StartInfo {
    pub npub: String,
    pub address: String,
}

pub fn is_running() -> bool {
    lock(&ENGINE).is_some()
}

/// Start the embedded node. `tun_fd` is borrowed (dup'd internally); the
/// caller keeps ownership of its own fd. `protect` receives the fd of each
/// UDP listen socket of the node and of every socket the shim itself dials
/// (wire it to `VpnService.protect`).
///
/// The `ENGINE` mutex is held only for the final install, not for the whole
/// (possibly slow) node startup — `status()` polls stay responsive.
pub fn start(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<SocketProtect>,
) -> Result<StartInfo, String> {
    let _lifecycle = lock(&LIFECYCLE);
    start_locked(config_json, tun_fd, protect)
}

/// [`start`] body; caller must hold [`LIFECYCLE`].
fn start_locked(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<SocketProtect>,
) -> Result<StartInfo, String> {
    if lock(&ENGINE).is_some() {
        return Err("already running".into());
    }
    if STARTING.swap(true, Ordering::SeqCst) {
        return Err("start already in progress".into());
    }
    let _starting = ClearOnDrop(&STARTING);
    let (engine, info) = start_inner(config_json, tun_fd, protect)?;
    *lock(&ENGINE) = Some(engine);
    Ok(info)
}

fn start_inner(
    config_json: &str,
    tun_fd: RawFd,
    protect: Option<SocketProtect>,
) -> Result<(Engine, StartInfo), String> {
    let shim_config = ShimConfig::from_json(config_json)?;
    crate::init_logging(shim_config.log_level.as_deref());
    apply_worker_thread_caps(shim_config.worker_threads);
    #[allow(unused_mut)]
    let mut fips_config = shim_config.to_fips_config()?;
    // The app's radio exists on Android only. Anywhere else (host tests)
    // fips would open the machine's own Bluetooth adapter instead.
    #[cfg(not(target_os = "android"))]
    {
        fips_config.transports.ble = Default::default();
    }
    // Whatever a previous node left: its slot is not this node's.
    crate::ble::GLOBAL.detach();
    #[allow(unused_variables)]
    let has_ble = !fips_config.transports.ble.is_empty();

    // The control socket is how the shim asks the running node anything.
    let control = Arc::new(Control::new(
        shim_config
            .control_path
            .clone()
            .unwrap_or_else(default_control_path),
    ));
    fips_config.node.control.enabled = true;
    fips_config.node.control.socket_path = control.path().to_string_lossy().into_owned();
    let control = Arc::new(Cached::new(control));

    let mut node = fips::Node::new(fips_config).map_err(|e| format!("node init: {e}"))?;
    // The Bluetooth seam, before start(): the transport is built over this
    // slot, and runs with or without a radio in it (`ble.rs`).
    // Armed for any Bluetooth transport in the config, so one declared in
    // `fips_yaml` gets its radio too.
    #[cfg(target_os = "android")]
    if has_ble {
        let slot = node.enable_app_owned_ble_radio();
        crate::ble::GLOBAL.attach(Arc::new(crate::ble::android::Slot(slot)));
    }
    let npub = node.npub();
    let our_fips_addr = *node.identity().address();
    let address = our_fips_addr.to_ipv6().to_string();

    // The Android seam: app-owned TUN channels, before start().
    let (outbound_tx, inbound_rx) = node.enable_app_owned_tun();
    // Keep a clone for rebuilds on network change (the original is moved into
    // the DNS proxy below).
    let engine_protect = protect.clone();
    // The node's UDP sockets, one per transport instance that binds. The
    // hook is what moves the FIPS Hotspot instance's socket onto the hotspot
    // network (Kotlin's `protectFd` tells it by its bound address); for the
    // others `VpnService.protect` changes nothing while this app's UID is
    // outside its own tunnel or captured for `fd00::/8` only, which is
    // always. fips's other sockets (TCP transport, netmon probes, STUN, and
    // the hole-punch sockets a traversed link runs over) are not announced
    // and for the same reason need not be.
    let udp_sockets = node.enable_app_owned_udp_fd();
    let node_protect = protect.clone();
    let netmon = node.netmon_trigger();

    let relay_status: Arc<Mutex<Vec<fips::nostr::RelayStatusView>>> = Arc::default();
    let relay_slot = relay_status.clone();
    let relay_refresh = Arc::new(tokio::sync::Notify::new());
    let relay_wake = relay_refresh.clone();
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
                // Every UDP transport that bound has sent its fd by now.
                // Handled here, before the rx loop: a FIPS Hotspot peer is
                // found by mDNS, which runs in that loop, so the hotspot
                // socket is on its network before the node dials through
                // it. (A configured peer is dialed inside `start`, through
                // the main socket, for which the hook changes nothing.)
                let announce = move |socket: fips::AppOwnedUdpSocket| {
                    tracing::debug!(fd = socket.fd, instance = ?socket.instance, "node UDP socket");
                    if let Some(hook) = &node_protect {
                        hook(socket.fd);
                    }
                };
                while let Ok(socket) = udp_sockets.try_recv() {
                    announce(socket);
                }
                // A socket the node binds later is sent on the same channel.
                // Blocked in recv until then; ends when the node is dropped.
                let later = std::thread::Builder::new()
                    .name("fips-udp-fd".into())
                    .spawn(move || {
                        while let Ok(socket) = udp_sockets.recv() {
                            announce(socket);
                        }
                    });
                if let Err(e) = later {
                    tracing::warn!(error = %e, "no thread for later UDP sockets");
                }
                let _ = ready_tx.send(Ok(()));
                // Relay-pool refresher for the UI: the pool lives inside the
                // Nostr runtime, which only this runtime may await on. Runs
                // once per status poll (Notify permit), so it costs nothing
                // while no screen is asking.
                let relay_poll = node.nostr_rendezvous_arc().map(|nostr| {
                    tokio::spawn(async move {
                        loop {
                            let rows = nostr.relay_status().await;
                            *lock(&relay_slot) = rows;
                            relay_wake.notified().await;
                        }
                    })
                });
                let result = node
                    .run_rx_loop_with_shutdown(async {
                        let _ = stop_rx.await;
                    })
                    .await;
                if let Err(e) = result {
                    tracing::error!(error = %e, "rx loop exited with error");
                }
                if let Some(task) = relay_poll {
                    task.abort();
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

    match ready_rx.recv_timeout(START_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = node_thread.join();
            return Err(e);
        }
        Err(RecvTimeoutError::Timeout) => return Err("node start timed out".into()),
        Err(RecvTimeoutError::Disconnected) => {
            let _ = node_thread.join();
            return Err("node thread died during start".into());
        }
    }
    let processor = crate::meshout::MeshOut::new(*our_fips_addr.as_bytes());
    if !control.wait_ready(CONTROL_WAIT) {
        tracing::warn!(
            path = %control.control().path().display(),
            "node control socket did not come up: no node status, no queries"
        );
    }

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
    // In slots from here on, so a later failure can take them for
    // `abort_start` and success can take them for the engine.
    let (mut stop_tx_slot, mut node_slot) = (Some(stop_tx), Some(node_thread));

    // Exit node: chosen before the pump moves a single packet, so selected
    // apps' internet traffic never starts out through the phone. A bad npub
    // fails the start rather than quietly falling back to the phone.
    let exit = Arc::new(crate::exit::ExitSwitch::new(
        *our_fips_addr.as_bytes(),
        LOCAL_RESPONDER.parse().unwrap(),
    ));
    if let Err(e) = exit.set(shim_config.exit_node.as_deref()) {
        abort_start(stop_tx_slot.take(), &running, None, node_slot.take(), owned_fd);
        return Err(e);
    }

    let divert = Arc::new(crate::meshhttp::Divert::default());
    let mesh = Arc::new(crate::meshhttp::MeshLink {
        our_addr: our_fips_addr.to_ipv6(),
        processor: processor.clone(),
        outbound_tx: outbound_tx.clone(),
        divert: divert.clone(),
        responder: LOCAL_RESPONDER.parse().unwrap(),
        running: running.clone(),
    });

    // Public domain names over fips: needs the mesh link for step 3. A
    // failure to set it up (unreadable pin file) costs the feature, never
    // the connection.
    let names = match shim_config.names_pins_path.as_deref() {
        Some(path) => match crate::names::Names::start(&shim_config, mesh.clone(), path) {
            Ok(n) => {
                tracing::info!(pins = path, "public domain names over fips on");
                // A rebind rebuilt the resolver; Kotlin last spoke when the
                // answer changed, which may be long ago.
                n.set_internet_validated(INTERNET_VALIDATED.load(Ordering::SeqCst));
                // Pins only while an exit is selected (`select_exit`).
                n.set_exit_selected(exit.selected().is_some());
                Some(n)
            }
            Err(e) => {
                tracing::warn!(error = %e, "public domain names over fips off");
                None
            }
        },
        None => None,
    };

    let dns = Arc::new(DnsProxy {
        local_responder: LOCAL_RESPONDER.parse().unwrap(),
        upstreams: shim_config.upstream_addrs(),
        writer_tx: writer_tx.clone(),
        protect: engine_protect.clone(),
        hosts: crate::dns::hosts_reloader(shim_config.hosts_path.as_deref()),
        names: names.clone().map(|n| n as Arc<dyn crate::names::Lookup>),
        exit: Some(crate::dns::ExitDns {
            switch: exit.clone(),
            link: Some(mesh.clone()),
        }),
        in_flight: Default::default(),
    });

    // Clearnet forwarder (split-tunnel): non-mesh packets from the pump go
    // through a userspace stack and out on protected sockets.
    let (mut forwarder, forward_tx) = if shim_config.forward_clearnet {
        let (forward_tx, forward_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        let forwarder = Forwarder::spawn(
            forward_rx,
            writer_tx.clone(),
            engine_protect.clone(),
            running.clone(),
            FORWARD_MTU,
            Some(crate::forward::DnsOverTcp {
                addr: (std::net::Ipv6Addr::from(DNS_SENTINEL), 53).into(),
                proxy: dns.clone(),
            }),
        )
        .map_err(|e| {
            abort_start(stop_tx_slot.take(), &running, None, node_slot.take(), owned_fd);
            format!("spawn forwarder: {e}")
        })?;
        (Some(forwarder), Some(forward_tx))
    } else {
        (None, None)
    };

    let filter = if shim_config.inbound_filter {
        tracing::info!(
            allowed_ports = ?shim_config.inbound_ports,
            "inbound firewall on (default-deny; replies + ICMPv6 pass)"
        );
        Some(std::sync::Arc::new(crate::filter::InboundFilter::new(
            shim_config.inbound_ports.clone(),
        )))
    } else {
        tracing::warn!("inbound firewall disabled — all mesh traffic reaches local ports");
        None
    };

    let pump = Pump::spawn(PumpConfig {
        tun_fd: owned_fd,
        running: running.clone(),
        processor,
        outbound_tx,
        inbound_rx,
        divert,
        filter,
        dns_addr: DNS_SENTINEL,
        dns,
        forward_tx,
        exit: exit.clone(),
        writer_tx,
        writer_rx,
    })
    .map_err(|e| {
        abort_start(stop_tx_slot.take(), &running, forwarder.take(), node_slot.take(), owned_fd);
        format!("spawn pump: {e}")
    })?;
    let (stop_tx, node_thread) = (stop_tx_slot.take(), node_slot.take());

    tracing::info!(npub = %npub, address = %address, "fips engine started");
    let engine = Engine {
        start: STARTS.fetch_add(1, Ordering::SeqCst),
        running,
        stop_tx,
        node_thread,
        pump: Some(pump),
        forwarder,
        control,
        npub: npub.clone(),
        address: address.clone(),
        tun_fd: owned_fd,
        config_json: config_json.to_string(),
        protect: engine_protect,
        netmon,
        relay_status,
        relay_refresh,
        mesh,
        names,
        exit,
    };
    Ok((engine, StartInfo { npub, address }))
}

/// Stop the engine: drain the node, stop the pump, close our fd. Idempotent.
pub fn stop() {
    let _lifecycle = lock(&LIFECYCLE);
    stop_locked();
}

/// [`stop`] body; caller must hold [`LIFECYCLE`].
fn stop_locked() {
    let engine = lock(&ENGINE).take();
    let Some(mut engine) = engine else {
        return;
    };
    tracing::info!("fips engine stopping");
    crate::ble::GLOBAL.detach();
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

/// Undo a start that failed after the node came up: what `stop_locked` does,
/// for the parts that exist so far. The error paths used to close the fd and
/// return, which left the node draining on its own after `LIFECYCLE` was
/// released — a retry could then meet it still holding `[::1]:5354` and
/// start with no `.fips` responder, the very race `LIFECYCLE` is there to
/// prevent — and left `running` set for whatever had already started.
fn abort_start(
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    running: &AtomicBool,
    forwarder: Option<Forwarder>,
    node_thread: Option<std::thread::JoinHandle<()>>,
    owned_fd: RawFd,
) {
    if let Some(stop_tx) = stop_tx {
        let _ = stop_tx.send(());
    }
    running.store(false, Ordering::Relaxed);
    if let Some(forwarder) = forwarder {
        forwarder.join();
    }
    if let Some(handle) = node_thread {
        let _ = handle.join();
    }
    unsafe { libc::close(owned_fd) };
}

/// Numbers each engine start, so a test can tell a kept node from a new one.
static STARTS: AtomicU64 = AtomicU64::new(0);

/// Follow a rebind from Kotlin: a new tunnel (its `::/0` route or allowed
/// apps changed, both fixed at `establish()`) or a changed config (the FIPS
/// Hotspot transport overlay).
///
/// With the config unchanged only the tunnel is new, and the node never sees
/// it: the pump's reader and writer move onto `tun_fd` ([`Pump::swap_fd`])
/// and the node, its links and sessions carry on. A changed config, or a swap
/// that fails, restarts the node on `tun_fd` — fips has no runtime way to add
/// or drop a transport. Either way we dup the fd; the Kotlin
/// `ParcelFileDescriptor` keeps owning it. No-op when not running.
///
/// `config_json`: when `Some`, replaces the stored config for the rebuilt
/// node — Kotlin regenerates it on every rebind so per-network state (the
/// FIPS Hotspot transport overlay) rides the same coalesced path; `None`
/// keeps the config from the previous start.
///
/// A call that arrives while another is at work waits for it and is then
/// applied. It used to return `Ok` at once on the assumption that the one
/// in flight would see the latest state — but each call carries its own fd
/// and config, so the later tunnel was simply dropped and the engine left
/// on the earlier one, which Kotlin then closes. Kotlin serialises its
/// rebinds on one worker, so this never ran; `LIFECYCLE` now makes the
/// order hold here too instead of depending on that.
pub fn network_changed(tun_fd: RawFd, config_json: Option<&str>) -> Result<(), String> {
    let result = {
        let _lifecycle = lock(&LIFECYCLE);
        // Snapshot what we need to rebuild; bail if not running (e.g. a
        // disconnect won the lock first).
        let rebuild = {
            let slot = lock(&ENGINE);
            slot.as_ref()
                .map(|e| (e.config_json.clone(), e.protect.clone()))
        };
        match rebuild {
            None => Ok(()),
            Some((stored_config, protect)) => {
                let config_json = config_json.unwrap_or(&stored_config);
                // Same config: what changed is the tunnel (its IPv6 route or
                // its allowed apps, both fixed at `establish()`), which the
                // node never sees — it exchanges packets with the pump. Move
                // the pump onto the new fd and keep the node, its links and
                // sessions. A changed config (a FIPS Hotspot joined or left)
                // still rebuilds the node, and so does a swap that fails.
                // A config that differs only in `exit_node` is the same node:
                // switch the exit in place, then swap the tunnel (Kotlin
                // rebuilds it, since its IPv6 routes follow the exit). An
                // exit that cannot be selected takes the restart path, whose
                // start refuses it — never the old route.
                let mut same_node = config_json == stored_config;
                if !same_node && same_but_exit(config_json, &stored_config) {
                    let parts = lock(&ENGINE)
                        .as_ref()
                        .map(|e| (e.exit.clone(), e.names.clone()));
                    let switched = match (parts, ShimConfig::from_json(config_json)) {
                        (Some((exit, names)), Ok(c)) => {
                            select_exit(&exit, names.as_deref(), c.exit_node.as_deref())
                        }
                        (None, _) => Err("engine gone".into()),
                        (_, Err(e)) => Err(e),
                    };
                    match switched {
                        Ok(()) => {
                            if let Some(engine) = lock(&ENGINE).as_mut() {
                                engine.config_json = config_json.to_string();
                            }
                            same_node = true;
                        }
                        Err(e) => tracing::error!(error = %e, "exit node change failed"),
                    }
                }
                let swapped = if same_node {
                    swap_tun_locked(tun_fd)
                        .map_err(|e| {
                            tracing::warn!(error = %e, "tunnel swap failed; restarting node on the tun fd");
                        })
                        .is_ok()
                } else {
                    tracing::info!("config changed; restarting node on the tun fd");
                    false
                };
                if swapped {
                    Ok(())
                } else {
                    stop_locked();
                    start_locked(config_json, tun_fd, protect).map(|_| ())
                }
            }
        }
    };
    if let Err(e) = &result {
        tracing::error!(error = %e, "node rebuild after network change failed");
    }
    result
}

/// Switch the running engine's exit, keeping the names resolver in step:
/// while an exit is selected the DNS proxy hands it pinned names only, and
/// it answers those from the pins (offline) — online it would ask the
/// phone's upstreams for the domain's TXT record, around the exit. Offline
/// goes on before the exit, online comes back after it, so no pinned query
/// is ever looked up online with an exit selected.
fn select_exit(
    exit: &crate::exit::ExitSwitch,
    names: Option<&crate::names::Names>,
    npub: Option<&str>,
) -> Result<(), String> {
    let selecting = npub.is_some_and(|n| !n.trim().is_empty());
    if selecting && let Some(n) = names {
        n.set_exit_selected(true);
    }
    let result = exit.set(npub);
    if let Some(n) = names {
        n.set_exit_selected(exit.selected().is_some());
    }
    result
}

/// True when two config JSONs differ at most in `exit_node`.
fn same_but_exit(a: &str, b: &str) -> bool {
    let strip = |s: &str| {
        serde_json::from_str::<serde_json::Value>(s).ok().map(|mut v| {
            if let Some(o) = v.as_object_mut() {
                o.remove("exit_node");
            }
            v
        })
    };
    matches!((strip(a), strip(b)), (Some(x), Some(y)) if x == y)
}

/// Move the running engine's pump onto `tun_fd` (dup'd here) and close the
/// old dup. The node keeps running; its medium-change detector and the names
/// resolver are told the network moved, since a new tunnel usually comes
/// with a new underlying network. Holds `LIFECYCLE` (caller) and `ENGINE`.
fn swap_tun_locked(tun_fd: RawFd) -> Result<(), String> {
    let owned_fd = unsafe { libc::fcntl(tun_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if owned_fd < 0 {
        return Err(format!("dup tun fd: {}", std::io::Error::last_os_error()));
    }
    // The swap waits for the old reader and writer (up to SWAP_TIMEOUT), so
    // it runs with the pump taken out of the slot: the UI thread's
    // isRunning/status and the network callback's hint read ENGINE, and
    // must not wait for it. LIFECYCLE (held by the caller) keeps start and
    // stop out meanwhile; nothing else touches the pump.
    let mut pump = {
        let mut slot = lock(&ENGINE);
        let Some(pump) = slot.as_mut().and_then(|e| e.pump.take()) else {
            unsafe { libc::close(owned_fd) };
            return Err("not running".into());
        };
        pump
    };
    let swapped = pump.swap_fd(owned_fd);
    let mut slot = lock(&ENGINE);
    let engine = slot.as_mut().expect("held by LIFECYCLE");
    // Back in the slot either way: after a failed swap the restart joins it.
    engine.pump = Some(pump);
    if let Err(e) = swapped {
        unsafe { libc::close(owned_fd) };
        return Err(e);
    }
    let old_fd = std::mem::replace(&mut engine.tun_fd, owned_fd);
    unsafe { libc::close(old_fd) };
    engine.netmon.poke();
    if let Some(names) = &engine.names {
        names.network_changed();
    }
    tracing::info!("tunnel replaced; node kept running");
    Ok(())
}

/// Wake the node's medium-change detector now: Kotlin calls this from the
/// `ConnectivityManager` callback when the underlying network changed but
/// nothing needs a rebind (same `::/0` decision, no hotspot transition).
///
/// The detector's own kernel event source is refused to an app on Android
/// (the netlink group bind fails under the app SELinux policy, observed on a
/// Pixel 9 Pro: "Kernel medium-change events unavailable; falling back to
/// polling"), which leaves it on a 5 s poll. `ConnectivityManager` knows the
/// exact moment the default network moved, so this turns a poll-period
/// latency into a debounce-period one. Cheap and non-blocking (a `Notify`
/// permit); safe on the main thread. No-op when not running.
pub fn network_hint() {
    let slot = lock(&ENGINE);
    if let Some(engine) = slot.as_ref() {
        engine.netmon.poke();
        if let Some(names) = &engine.names {
            names.network_changed();
        }
    }
}

/// Whether a validated (captive-portal-free) Internet network exists, as
/// Kotlin last said. Remembered here because a rebind rebuilds the names
/// resolver, which starts out assuming the Internet is there; Kotlin only
/// speaks up when the answer changes.
static INTERNET_VALIDATED: AtomicBool = AtomicBool::new(true);

/// Kotlin calls this at start and whenever the answer changes. Applied to
/// the running resolver now and to every resolver built later.
pub fn names_online(validated: bool) {
    INTERNET_VALIDATED.store(validated, Ordering::SeqCst);
    let slot = lock(&ENGINE);
    if let Some(engine) = slot.as_ref()
        && let Some(names) = &engine.names
    {
        names.set_internet_validated(validated);
    }
}

/// Compact status JSON for the UI. Always answers, running or not, and
/// without waiting for the node once it has answered a first time. `relays`
/// lists the Nostr relay pool with per-relay connection state (empty when
/// Nostr is off or the node has not published a snapshot yet); each call
/// also asks the node runtime for a fresh snapshot, served by the next call.
pub fn status_json() -> String {
    // The node is asked with the `ENGINE` lock released: the answer comes
    // over its control socket, and a stop must not wait behind that.
    let (mut value, control) = {
        let slot = lock(&ENGINE);
        let Some(engine) = slot.as_ref() else {
            return serde_json::json!({ "running": false }).to_string();
        };
        engine.relay_refresh.notify_one();
        let value = serde_json::json!({
            "running": true,
            "npub": engine.npub,
            "address": engine.address,
            "relays": lock(&engine.relay_status).clone(),
            "exit": engine.exit.selected().map(|npub| serde_json::json!({
                "npub": npub,
                "inner_ipv4": engine.exit.inner().to_string(),
            })),
        });
        (value, engine.control.clone())
    };
    // The last answer at once, refreshed for the next poll. A node that
    // never answered (its control socket did not come up) is still a
    // running node: an empty status, which the Overview shows as connected
    // with no figures, not null, which it shows as still starting.
    value["status"] = control
        .query("show_status", None)
        .ok()
        .and_then(|mut v| v.get_mut("data").map(serde_json::Value::take))
        .unwrap_or_else(|| serde_json::json!({}));
    value.to_string()
}

/// Generic read-only query passthrough (any `show_*`). A query asked within
/// the last few seconds is answered at once from the last reply and
/// refreshed behind it; otherwise it waits for the node, up to
/// [`crate::control::QUERY_TIMEOUT`]. The `ENGINE` lock is not held meanwhile.
pub fn query_json(command: &str, params_json: &str) -> String {
    let Some(control) = lock(&ENGINE).as_ref().map(|e| e.control.clone()) else {
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
    match control.query(command, params) {
        Ok(response) => response.to_string(),
        Err(e) => serde_json::json!({ "status": "error", "message": e }).to_string(),
    }
}

/// Manual dial (Diagnostics "Connect" on an mDNS-seen peer): round-trip a
/// `connect` command through the node's rx_loop, over its control socket.
/// Blocking, up to [`crate::control::COMMAND_TIMEOUT`] — call off the UI
/// thread. The `ENGINE` lock is dropped before the round-trip so status
/// polls never queue behind a slow handshake initiation.
pub fn connect_peer_json(npub: &str, address: &str) -> String {
    let handle = lock(&ENGINE).as_ref().map(|e| e.control.clone());
    let Some(handle) = handle else {
        return r#"{"status":"error","message":"not running"}"#.to_string();
    };
    let params = serde_json::json!({
        "npub": npub,
        "address": address,
        "transport": "udp",
    });
    match handle
        .control()
        .request("connect", Some(params), crate::control::COMMAND_TIMEOUT)
    {
        Ok(response) => response.to_string(),
        Err(e) => serde_json::json!({ "status": "error", "message": e }).to_string(),
    }
}

/// Can the selected exit be used right now? Two echoes to its fips address
/// through the node ([`crate::meshudp::ping_sized`]): a small one, and one
/// that is a full-size mesh packet. Blocking, up to twice `timeout` — call
/// off the UI thread; the `ENGINE` lock is not held while it runs. Answers
/// `{"exit": <npub> | null, "reachable": <bool>, "full_size": <bool>}` or
/// `{"error": "..."}`.
///
/// `reachable` with `full_size` false is the state nothing else in the app
/// shows: the exit answers, its DNS answers, the route card says "through
/// exit node", and no page loads, because the route between the two loses
/// packets near 1280 bytes (a hop that carries less, and a node on the way
/// too old to split for it). Seen on a Pixel 9 Pro against a node on an
/// older fips: echoes up to 1198 bytes arrived, none from 1228.
pub fn exit_probe_json(timeout: Duration) -> String {
    let error = |message: String| serde_json::json!({ "error": message }).to_string();
    let Some((link, exit)) = lock(&ENGINE)
        .as_ref()
        .map(|e| (e.mesh.clone(), e.exit.clone()))
    else {
        return error("not connected".into());
    };
    let (Some(npub), Some(addr)) = (exit.selected(), exit.selected_addr()) else {
        return serde_json::json!({ "exit": null, "reachable": false, "full_size": false })
            .to_string();
    };
    let ping = |payload| crate::meshudp::ping_sized(&link, addr, payload, timeout);
    // The small one first: without it a failed large one says nothing.
    let reachable = match ping(24) {
        Ok(answered) => answered,
        Err(e) if e.restarted => return error("the engine restarted".into()),
        Err(_) => false,
    };
    let full_size = reachable && ping(crate::meshudp::FULL_PAYLOAD).unwrap_or(false);
    serde_json::json!({ "exit": npub, "reachable": reachable, "full_size": full_size }).to_string()
}

/// Look for exit adverts on the relays (see [`crate::exitfind`]). Blocking,
/// up to about `timeout` — call off the UI thread; the `ENGINE` lock is not
/// held while searching. Answers `{"exits": [{npub, name, about, access,
/// created_at, expires}], "mesh_relays": n, "public_relays": n}` or
/// `{"error": "..."}`.
pub fn find_exits_json(timeout: Duration) -> String {
    let error = |message: String| serde_json::json!({ "error": message }).to_string();
    let Some((link, config_json, own_npub)) = lock(&ENGINE)
        .as_ref()
        .map(|e| (e.mesh.clone(), e.config_json.clone(), e.npub.clone()))
    else {
        return error("not connected".into());
    };
    let config = match ShimConfig::from_json(&config_json) {
        Ok(c) => c,
        Err(e) => return error(e),
    };
    // The same public relays the names resolver uses: the user's list, or
    // the library's defaults.
    let public = if config.nostr_relays.is_empty() {
        pubdom_resolve::ResolverConfig::default().public_relays
    } else {
        config.nostr_relays.clone()
    };
    let online = INTERNET_VALIDATED.load(Ordering::SeqCst);
    match crate::exitfind::find(
        &link,
        &config.names_mesh_relays,
        &public,
        online,
        &own_npub,
        timeout,
    ) {
        Ok(found) => serde_json::to_string(&found).unwrap_or_else(|e| error(e.to_string())),
        Err(e) => error(e),
    }
}

/// `GET http://[<npub's address>]:<port><path>` over the mesh, from inside
/// the process (see [`crate::meshhttp`]). Blocking — call off the UI thread;
/// the `ENGINE` lock is not held while fetching. `headers_json` is an object
/// of extra request headers. Answers `{"status": <code>, "body": "<text>"}`
/// or `{"error": "...", "unreachable": <bool>, "restarted": <bool>}` —
/// `unreachable` meaning the node could not be reached at all, as opposed to
/// answering badly; `restarted` that this engine stopped or was rebuilt
/// under the request (a rebind), which says nothing about the far node.
pub fn mesh_http_get_json(
    npub: &str,
    port: u16,
    path: &str,
    headers_json: &str,
    timeout: Duration,
) -> String {
    let error = |message: String, unreachable: bool| {
        serde_json::json!({ "error": message, "unreachable": unreachable }).to_string()
    };
    let Some(link) = lock(&ENGINE).as_ref().map(|e| e.mesh.clone()) else {
        return error("not connected".into(), false);
    };
    let (npub, address) = match crate::config::resolve_npub(npub) {
        Ok(v) => v,
        Err(e) => return error(e, false),
    };
    let Ok(addr) = address.parse() else {
        return error(format!("bad mesh address {address}"), false);
    };
    if port == 0 || !path.starts_with('/') {
        return error("bad port or path".into(), false);
    }
    let headers_json = if headers_json.trim().is_empty() {
        "{}"
    } else {
        headers_json
    };
    let headers: Vec<(String, String)> =
        match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(headers_json) {
            Ok(map) => map
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k, v.to_string())))
                .collect(),
            Err(e) => return error(format!("bad headers: {e}"), false),
        };
    match crate::meshhttp::get(&link, &npub, addr, port, path, &headers, timeout) {
        Ok(r) => serde_json::json!({
            "status": r.status,
            "body": String::from_utf8_lossy(&r.body),
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "error": e.message,
            "unreachable": e.unreachable,
            "restarted": e.restarted,
        })
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_exit_change_keeps_the_node() {
        let base = r#"{"nsec":"x","peers":[],"exit_node":null}"#;
        let exit = r#"{"exit_node":"npub1abc","peers":[],"nsec":"x"}"#;
        let other = r#"{"nsec":"x","peers":[],"exit_node":"npub1abc","hotspot":{}}"#;
        assert!(same_but_exit(base, exit));
        assert!(same_but_exit(r#"{"nsec":"x"}"#, exit.replace(r#""peers":[],"#, "").as_str()));
        assert!(!same_but_exit(base, other));
        assert!(!same_but_exit(base, "not json"));
    }

    #[test]
    fn a_panic_under_a_lock_or_flag_leaves_both_usable() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let slot = Arc::new(Mutex::new(7));
        let held = slot.clone();
        let panicked = std::thread::spawn(move || {
            let _guard = lock(&held);
            FLAG.store(true, Ordering::SeqCst);
            let _busy = ClearOnDrop(&FLAG);
            panic!("while holding the lock");
        })
        .join();
        assert!(panicked.is_err());
        assert!(slot.is_poisoned());
        assert_eq!(*lock(&slot), 7);
        assert!(!FLAG.load(Ordering::SeqCst));
    }

    /// The engine is a process singleton, and cargo runs tests in parallel:
    /// every test that starts one holds this for its whole run.
    static ENGINE_TEST: Mutex<()> = Mutex::new(());

    fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
        ENGINE_TEST.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// With Nostr on and the pool pointed at a loopback websocket server,
    /// `status_json` reports that relay as connected within a few seconds —
    /// the Overview's relay list end to end, minus the UI. No public
    /// network: the relay list is overridden and STUN points at a dead
    /// loopback port.
    #[test]
    fn status_reports_loopback_relay_connected() {
        let _serial = engine_test_lock();
        // Minimal "relay": accept the upgrade, swallow frames.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    if let Ok(mut ws) = tungstenite::accept(stream) {
                        while ws.read().is_ok() {}
                    }
                });
            }
        });

        let identity = crate::config::derive_identity("").unwrap();
        let relay = format!("ws://127.0.0.1:{port}");
        let config = serde_json::json!({
            "nsec": identity.nsec,
            "enable_nostr": true,
            "nostr_relays": [relay],
            "stun_servers": ["127.0.0.1:9"],
            "enable_fips_dns": false,
            "forward_clearnet": false,
            "battery_saver": false,
            "log_level": "warn",
        })
        .to_string();

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let [read_fd, write_fd] = fds;
        start(&config, read_fd, None).unwrap_or_else(|e| panic!("start: {e}"));

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut last;
        let connected = loop {
            last = status_json();
            let status: serde_json::Value = serde_json::from_str(&last).unwrap();
            let relays = status["relays"].as_array().cloned().unwrap_or_default();
            if relays.len() == 1 && relays[0]["connected"] == true {
                assert_eq!(relays[0]["url"], relay);
                assert_eq!(relays[0]["status"], "Connected");
                break true;
            }
            if std::time::Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        stop();
        unsafe { libc::close(write_fd) };
        unsafe { libc::close(read_fd) };
        assert!(connected, "loopback relay never reported connected: {last}");
    }

    /// Full lifecycle on the host: a pipe stands in for the TUN fd, a
    /// loopback UDP transport stands in for the network. Start → status →
    /// query → stop, twice (restartability).
    #[test]
    fn engine_lifecycle_on_host() {
        let _serial = engine_test_lock();
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
            assert!(
                status["relays"].as_array().is_some_and(|r| r.is_empty()),
                "relay list present and empty with Nostr off: {status}"
            );

            // The netmon hint must be callable at any time without effect on
            // the lifecycle (a poke is a `Notify` permit, nothing more).
            network_hint();

            let peers = query_json("show_stats_list", "");
            let peers: serde_json::Value = serde_json::from_str(&peers).unwrap();
            assert_eq!(peers["status"], "ok");

            // The mDNS-sightings query is snapshot-served (empty registry on
            // the host — no LAN discovery in this test, only the shape).
            let lan = query_json("show_lan_peers", "");
            let lan: serde_json::Value = serde_json::from_str(&lan).unwrap();
            assert_eq!(lan["status"], "ok");
            assert!(
                lan["data"]["lan_peers"].is_array(),
                "lan_peers array: {lan}"
            );

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

    /// A new tunnel with the same config (an IPv6-route flip, a changed app
    /// selection) moves the pump onto the new fd and keeps the node: same
    /// engine, and traffic flows through the new fd both ways — a packet
    /// read from it reaches the node, whose ICMPv6 answer is written back to
    /// it. A changed config still rebuilds the node.
    #[test]
    fn a_new_tunnel_with_the_same_config_keeps_the_node() {
        let _serial = engine_test_lock();
        let identity = crate::config::derive_identity("").unwrap();
        let config = serde_json::json!({
            "nsec": identity.nsec,
            "peers": [],
            "enable_nostr": false,
            "enable_fips_dns": false,
            "forward_clearnet": false,
            "battery_saver": false,
            "log_level": "warn",
        })
        .to_string();
        let pair = || {
            let mut fds = [0i32; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr())
                },
                0
            );
            (fds[0], fds[1])
        };
        let engine_id = || lock(&ENGINE).as_ref().expect("running").start;

        let (old_tun, old_app) = pair();
        start(&config, old_tun, None).unwrap_or_else(|e| panic!("start: {e}"));
        let first = engine_id();

        let (new_tun, new_app) = pair();
        network_changed(new_tun, None).expect("swap");
        assert_eq!(engine_id(), first, "same node after the swap");

        // A mesh destination nobody serves: the node answers Destination
        // Unreachable from its own address, on the new fd.
        let src: std::net::Ipv6Addr = identity.address.parse().unwrap();
        let dst: std::net::Ipv6Addr = "fd12:3456::1".parse().unwrap();
        let probe = crate::packet::build_ipv6_udp(src.octets(), dst.octets(), 40000, 9, b"swap");
        let sent = unsafe { libc::write(new_app, probe.as_ptr().cast(), probe.len()) };
        assert_eq!(sent, probe.len() as isize);
        let mut pfd = libc::pollfd {
            fd: new_app,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut pfd, 1, 5000) },
            1,
            "an answer on the new fd"
        );
        let mut buf = [0u8; 2048];
        let n = unsafe { libc::read(new_app, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 40, "an IPv6 packet");
        assert_eq!(buf[6], 58, "ICMPv6");
        assert_eq!(buf[40], 1, "Destination Unreachable");

        // The old fd is no longer served: a probe written to it gets nothing.
        let sent = unsafe { libc::write(old_app, probe.as_ptr().cast(), probe.len()) };
        assert_eq!(sent, probe.len() as isize);
        let mut old = libc::pollfd {
            fd: old_app,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut old, 1, 500) },
            0,
            "nothing on the old fd"
        );

        // A changed config rebuilds the node.
        let changed = config.replace("\"log_level\":\"warn\"", "\"log_level\":\"error\"");
        assert_ne!(changed, config);
        network_changed(new_tun, Some(&changed)).expect("restart");
        assert_ne!(engine_id(), first, "a new node for a new config");

        stop();
        for fd in [old_tun, old_app, new_tun, new_app] {
            unsafe { libc::close(fd) };
        }
    }

    /// An exit node that cannot be reached blocks: DNS gets SERVFAIL and the
    /// phone's own upstream resolver hears nothing, while mesh traffic keeps
    /// its own path. Switching back to the phone keeps the node and sends
    /// DNS to the upstream again.
    #[test]
    fn an_unreachable_exit_blocks_but_the_mesh_still_works() {
        let _serial = engine_test_lock();
        let identity = crate::config::derive_identity("").unwrap();
        let exit = crate::config::derive_identity("").unwrap();
        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let config = |exit_node: Option<&str>| {
            serde_json::json!({
                "nsec": identity.nsec,
                "peers": [],
                "enable_nostr": false,
                "enable_fips_dns": true,
                "forward_clearnet": false,
                "battery_saver": false,
                "log_level": "warn",
                "dns_upstreams": [upstream.local_addr().unwrap().to_string()],
                "exit_node": exit_node,
            })
            .to_string()
        };
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
            0
        );
        let [tun, app] = fds;
        start(&config(Some(&exit.npub)), tun, None).unwrap_or_else(|e| panic!("start: {e}"));
        struct StopOnDrop(i32, i32);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                stop();
                unsafe { libc::close(self.0) };
                unsafe { libc::close(self.1) };
            }
        }
        let _stop = StopOnDrop(tun, app);
        let status: serde_json::Value = serde_json::from_str(&status_json()).unwrap();
        assert_eq!(status["exit"]["npub"], exit.npub);

        let me: std::net::Ipv6Addr = identity.address.parse().unwrap();
        let read_reply = |timeout_ms: i32| -> Option<Vec<u8>> {
            let mut pfd = libc::pollfd { fd: app, events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, timeout_ms) } != 1 {
                return None;
            }
            let mut buf = vec![0u8; 4096];
            let n = unsafe { libc::read(app, buf.as_mut_ptr().cast(), buf.len()) };
            buf.truncate(n.max(0) as usize);
            Some(buf)
        };
        let send = |pkt: &[u8]| {
            assert_eq!(unsafe { libc::write(app, pkt.as_ptr().cast(), pkt.len()) }, pkt.len() as isize);
        };
        let dns_query = crate::packet::build_ipv6_udp(
            me.octets(),
            DNS_SENTINEL,
            40999,
            53,
            &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1],
        );

        // DNS: SERVFAIL from the proxy, nothing at the phone's upstream.
        send(&dns_query);
        let reply = read_reply(15_000).expect("a DNS reply");
        let parsed = crate::packet::parse_ipv6_udp(&reply).expect("IPv6/UDP");
        assert_eq!(parsed.payload[3] & 0x0f, 2, "SERVFAIL");
        let mut buf = [0u8; 512];
        assert!(upstream.recv_from(&mut buf).is_err(), "the upstream must not be asked");

        // Mesh traffic is not the exit's: the node answers for itself.
        let dst: std::net::Ipv6Addr = "fd12:3456::1".parse().unwrap();
        send(&crate::packet::build_ipv6_udp(me.octets(), dst.octets(), 40000, 9, b"mesh"));
        let reply = loop {
            let r = read_reply(5000).expect("the node's answer");
            if r.len() > 40 && r[6] == 58 {
                break r;
            }
        };
        assert_eq!(reply[40], 1, "Destination Unreachable from the node");

        // Back to the phone: same node, DNS goes upstream again.
        let first = lock(&ENGINE).as_ref().unwrap().start;
        let (tun2, app2) = {
            let mut f = [0i32; 2];
            assert_eq!(
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, f.as_mut_ptr()) },
                0
            );
            (f[0], f[1])
        };
        network_changed(tun2, Some(&config(None))).expect("switch");
        assert_eq!(lock(&ENGINE).as_ref().unwrap().start, first, "same node");
        let status: serde_json::Value = serde_json::from_str(&status_json()).unwrap();
        assert!(status["exit"].is_null());
        assert_eq!(unsafe { libc::write(app2, dns_query.as_ptr().cast(), dns_query.len()) }, dns_query.len() as isize);
        upstream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        assert!(upstream.recv_from(&mut buf).is_ok(), "the upstream is asked again");
        unsafe {
            libc::close(tun2);
            libc::close(app2);
        }
    }

    /// A start refused for a bad exit npub stops the node it had started
    /// (`abort_start`): nothing is left running, and the next start gets the
    /// `.fips` responder port and comes up.
    #[test]
    fn a_bad_exit_npub_fails_the_start_and_leaves_nothing_behind() {
        let _serial = engine_test_lock();
        let identity = crate::config::derive_identity("").unwrap();
        let config = |exit_node: Option<&str>| {
            serde_json::json!({
                "nsec": identity.nsec,
                "peers": [],
                "enable_nostr": false,
                "enable_fips_dns": true,
                "forward_clearnet": false,
                "battery_saver": false,
                "log_level": "warn",
                "exit_node": exit_node,
            })
            .to_string()
        };
        let pair = || {
            let mut fds = [0i32; 2];
            assert_eq!(
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
                0
            );
            (fds[0], fds[1])
        };
        let (tun, app) = pair();
        let Err(err) = start(&config(Some("npub1typo")), tun, None) else {
            panic!("started with a bad exit npub");
        };
        assert!(err.contains("exit node"), "{err}");
        assert!(!is_running());
        assert!(lock(&ENGINE).is_none());

        let (tun2, app2) = pair();
        start(&config(None), tun2, None).unwrap_or_else(|e| panic!("the next start: {e}"));
        assert!(is_running());
        stop();
        for fd in [tun, app, tun2, app2] {
            unsafe { libc::close(fd) };
        }
    }

    /// A rebind that arrives while another is at work is applied after it,
    /// not dropped: the engine ends up on the later call's tunnel.
    #[test]
    fn a_rebind_during_a_rebind_is_applied() {
        let _serial = engine_test_lock();
        let identity = crate::config::derive_identity("").unwrap();
        let config = serde_json::json!({
            "nsec": identity.nsec,
            "peers": [],
            "enable_nostr": false,
            "enable_fips_dns": false,
            "forward_clearnet": false,
            "battery_saver": false,
            "log_level": "warn",
        })
        .to_string();
        let pair = || {
            let mut fds = [0i32; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr())
                },
                0
            );
            (fds[0], fds[1])
        };
        let (first_tun, first_app) = pair();
        start(&config, first_tun, None).unwrap_or_else(|e| panic!("start: {e}"));
        let first = lock(&ENGINE).as_ref().expect("running").start;

        // The first rebind restarts the node (a changed config), which takes
        // long enough for the second to arrive in the middle of it.
        let changed = config.replace("\"log_level\":\"warn\"", "\"log_level\":\"error\"");
        let (second_tun, second_app) = pair();
        let restart = {
            let changed = changed.clone();
            std::thread::spawn(move || network_changed(second_tun, Some(&changed)))
        };
        // Under way once the old engine is out of the slot. (Or already
        // over, on a fast host: the later rebind is then merely the next
        // one, and must be applied all the same.)
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock(&ENGINE).as_ref().is_some_and(|e| e.start == first) {
            assert!(std::time::Instant::now() < deadline, "the restart never began");
            std::thread::yield_now();
        }
        let (third_tun, third_app) = pair();
        network_changed(third_tun, Some(&changed)).expect("the later rebind");
        restart.join().unwrap().expect("the earlier rebind");

        // The node answers on the later tunnel.
        let src: std::net::Ipv6Addr = identity.address.parse().unwrap();
        let dst: std::net::Ipv6Addr = "fd12:3456::1".parse().unwrap();
        let probe = crate::packet::build_ipv6_udp(src.octets(), dst.octets(), 40000, 9, b"late");
        let sent = unsafe { libc::write(third_app, probe.as_ptr().cast(), probe.len()) };
        assert_eq!(sent, probe.len() as isize);
        let mut pfd = libc::pollfd {
            fd: third_app,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut pfd, 1, 5000) },
            1,
            "an answer on the later tunnel"
        );

        stop();
        for fd in [first_tun, first_app, second_tun, second_app, third_tun, third_app] {
            unsafe { libc::close(fd) };
        }
    }

    /// The FIPS Hotspot overlay must bring up BOTH UDP transports. The config
    /// test next door only proves the two instances are *described* on one
    /// port; nothing bound them, which is how a fips change (reuse flags moved
    /// after bind) shipped in 0.4.0 unnoticed: on a phone the main transport
    /// failed with EADDRINUSE, the node started DEGRADED on the hotspot
    /// transport alone, and joining "!FIPS" took it off the rest of the mesh.
    /// 127.0.0.1 stands in for the hotspot interface address.
    #[test]
    fn hotspot_overlay_starts_both_transports() {
        let _serial = engine_test_lock();
        let identity = crate::config::derive_identity("").unwrap();
        let config = serde_json::json!({
            "nsec": identity.nsec,
            "peers": [],
            "enable_nostr": false,
            "enable_fips_dns": false,
            "forward_clearnet": false,
            "battery_saver": false,
            "log_level": "warn",
            "hotspot": { "addr": "127.0.0.1", "prefix_len": 8 },
        })
        .to_string();

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let [read_fd, write_fd] = fds;
        // The protect hook must be handed both sockets, and be able to tell
        // the hotspot one by its bound address: that is how Kotlin's
        // `protectFd` finds the socket to move onto the hotspot network.
        let seen: Arc<Mutex<Vec<std::net::SocketAddr>>> = Arc::default();
        let sink = seen.clone();
        let hook: crate::SocketProtect = Arc::new(move |fd| {
            use std::os::fd::{FromRawFd, IntoRawFd};
            // Borrowed: read the address, give the fd back unclosed.
            let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            if let Ok(addr) = socket.local_addr() {
                lock(&sink).push(addr);
            }
            let _ = socket.into_raw_fd();
        });
        start(&config, read_fd, Some(hook)).expect("start with the hotspot overlay");
        // Stop the engine however this test ends: a panic that left it running
        // would fail every other engine test with "already running".
        struct StopOnDrop(i32, i32);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                stop();
                unsafe { libc::close(self.1) };
                unsafe { libc::close(self.0) };
            }
        }
        let _stop = StopOnDrop(read_fd, write_fd);
        {
            let seen = lock(&seen);
            assert_eq!(seen.len(), 2, "one fd per UDP instance: {seen:?}");
            assert_eq!(
                seen.iter().filter(|a| a.ip().to_string() == "127.0.0.1").count(),
                1,
                "the hotspot instance's socket, bound to its address: {seen:?}"
            );
            assert_eq!(seen[0].port(), seen[1].port(), "one shared port: {seen:?}");
        }

        // `show_transports` is served from the tick-published snapshot, which
        // is empty until the first tick (1 s here).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let reply = loop {
            let reply: serde_json::Value =
                serde_json::from_str(&query_json("show_transports", "")).unwrap();
            assert_eq!(reply["status"], "ok", "show_transports: {reply}");
            let published = reply["data"]["transports"]
                .as_array()
                .is_some_and(|t| !t.is_empty());
            if published || std::time::Instant::now() > deadline {
                break reply;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        let transports = reply["data"]["transports"]
            .as_array()
            .unwrap_or_else(|| panic!("transports array: {reply}"));
        let udp: Vec<_> = transports.iter().filter(|t| t["type"] == "udp").collect();
        assert_eq!(udp.len(), 2, "main + hotspot must both be up: {reply}");
        for t in &udp {
            assert_eq!(
                t["state"], "up",
                "every UDP instance must have started: {reply}"
            );
        }

        let ports: std::collections::HashSet<u16> = udp
            .iter()
            .map(|t| {
                t["local_addr"]
                    .as_str()
                    .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                    .unwrap_or_else(|| panic!("local_addr on a started transport: {t}"))
                    .port()
            })
            .collect();
        assert_eq!(
            ports.len(),
            1,
            "one shared port across both instances: {reply}"
        );
    }
}
