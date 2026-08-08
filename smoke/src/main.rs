//! Phase 1 smoke test for the FIPS Android port.
//!
//! Exercises the exact embedding shape an Android `VpnService` will use:
//! `Config` built in memory (no files), identity injected via
//! `node.identity.nsec`, `enable_app_owned_tun()` instead of a system TUN,
//! and a plain oneshot as the shutdown future (no signals).
//!
//! Two nodes run on one current-thread tokio runtime, linked over loopback
//! UDP. Node A pushes a hand-crafted IPv6/UDP packet into its app-owned TUN
//! sender; success is that packet arriving on node B's app-owned TUN
//! receiver — which requires FMP handshake, coordinate lookup, FSP session
//! establishment, header compression, and routing to all work.

use std::time::{Duration, Instant};

use fips::identity::encode_nsec;
use fips::{Config, Identity, Node};

const PORT_A: u16 = 39411;
const PORT_B: u16 = 39412;
const MARKER: &[u8] = b"FIPS_ANDROID_SMOKE_PING";
const TIMEOUT: Duration = Duration::from_secs(30);

/// Build a config the way the Android shim will: entirely in memory.
fn build_config(identity: &Identity, port: u16, peer: Option<fips::config::PeerConfig>) -> Config {
    let mut config = Config::new();
    config.node.identity.nsec = Some(encode_nsec(&identity.keypair().secret_key()));
    config.transports.udp = fips::config::TransportInstances::Single(fips::config::UdpConfig {
        bind_addr: Some(format!("127.0.0.1:{port}")),
        ..Default::default()
    });
    config.tun.enabled = true; // satisfied by the app-owned seam, no device
    config.dns.enabled = false;
    config.node.control.enabled = false;
    config.peers.extend(peer);
    config
}

/// IPv6 + UDP packet with a correct UDP checksum (mandatory over IPv6).
fn build_ipv6_udp(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&40000u16.to_be_bytes()); // src port
    udp.extend_from_slice(&40001u16.to_be_bytes()); // dst port
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum placeholder
    udp.extend_from_slice(payload);

    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    };
    add(&src);
    add(&dst);
    add(&(udp_len as u32).to_be_bytes());
    add(&[0, 0, 0, 17]);
    add(&udp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = match !(sum as u16) {
        0 => 0xffff,
        c => c,
    };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut pkt = Vec::with_capacity(40 + udp_len);
    pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, TC 0, flow 0
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.push(17); // next header: UDP
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&udp);
    pkt
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    println!("node A: {} @ {}", id_a.npub(), id_a.address().to_ipv6());
    println!("node B: {} @ {}", id_b.npub(), id_b.address().to_ipv6());

    // B dials A; links are bidirectional once the FMP handshake completes.
    let config_a = build_config(&id_a, PORT_A, None);
    let config_b = build_config(
        &id_b,
        PORT_B,
        Some(fips::config::PeerConfig::new(
            id_a.npub(),
            "udp",
            format!("127.0.0.1:{PORT_A}"),
        )),
    );

    let mut node_a = Node::new(config_a).expect("node A construction");
    let mut node_b = Node::new(config_b).expect("node B construction");

    // The Android seam: must be called after Node::new, before start().
    let (a_outbound_tx, _a_inbound_rx) = node_a.enable_app_owned_tun();
    let (_b_outbound_tx, b_inbound_rx) = node_b.enable_app_owned_tun();

    // Socket-protect hook (Phase 2): on Android this would call
    // VpnService.protect(fd); here we count announcements to prove every
    // underlay socket is surfaced before traffic flows.
    let protected = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = protected.clone();
    node_a.set_socket_protect(std::sync::Arc::new(move |fd| {
        sink.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        println!("protect hook: underlay socket fd {fd}");
    }));

    node_a.start().await.expect("node A start");
    node_b.start().await.expect("node B start");
    let protect_calls = protected.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        protect_calls >= 1,
        "protect hook must fire for the UDP listen socket"
    );
    println!(
        "both nodes started (no system TUN, no DNS, no control socket); \
         node A protect hook fired {protect_calls}x"
    );

    // App-side receive loop for B (a VpnService would write these to its fd).
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<bool>();
    let receiver = std::thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            match b_inbound_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(pkt) => {
                    if pkt.windows(MARKER.len()).any(|w| w == MARKER) {
                        let _ = done_tx.send(true);
                        return;
                    }
                    println!("node B app rx: {} bytes (not the marker), ignoring", pkt.len());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = done_tx.send(false);
    });

    // App-side send loop for A: retry until the mesh path is up (first sends
    // queue behind coordinate lookup + session establishment). Each packet
    // runs through the outbound processor (Phase 2) exactly like the Android
    // pump would — it must decide Forward for a mesh-destined packet.
    let processor = node_a.tun_packet_processor();
    let packet = build_ipv6_udp(
        *id_a.address().as_bytes(),
        *id_b.address().as_bytes(),
        MARKER,
    );
    let send_task = tokio::spawn(async move {
        let deadline = Instant::now() + TIMEOUT;
        while Instant::now() < deadline {
            let mut pkt = packet.clone();
            match processor.process(&mut pkt) {
                fips::TunPacketAction::Forward => {
                    if a_outbound_tx.send(pkt).await.is_err() {
                        return;
                    }
                }
                other => panic!("processor must Forward mesh-destined packets, got {other:?}"),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let (stop_a_tx, stop_a_rx) = tokio::sync::oneshot::channel::<()>();
    let (stop_b_tx, stop_b_rx) = tokio::sync::oneshot::channel::<()>();

    let loops = async {
        tokio::join!(
            node_a.run_rx_loop_with_shutdown(async {
                let _ = stop_a_rx.await;
            }),
            node_b.run_rx_loop_with_shutdown(async {
                let _ = stop_b_rx.await;
            }),
        )
    };
    let supervise = async {
        let ok = done_rx.await.unwrap_or(false);
        let _ = stop_a_tx.send(());
        let _ = stop_b_tx.send(());
        ok
    };

    let ((res_a, res_b), delivered) = tokio::join!(loops, supervise);
    res_a.expect("node A rx loop");
    res_b.expect("node B rx loop");
    send_task.abort();
    node_a.finish_shutdown().await;
    node_b.finish_shutdown().await;
    receiver.join().expect("receiver thread");

    if delivered {
        println!("PASS: packet from A traversed the mesh to B's app-owned TUN");
    } else {
        println!("FAIL: marker packet never arrived within {TIMEOUT:?}");
        std::process::exit(1);
    }
}
