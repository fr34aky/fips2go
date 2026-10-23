//! One UDP request/response over the mesh from the node's own address — the
//! step 3 DNS query of public names over fips (`names.rs`), asked of the
//! domain's server on its fips address.
//!
//! Same shape and reason as `meshhttp.rs`: the app's UID sits outside its
//! own tunnel, so no kernel socket can reach `fd00::/8`; a smoltcp UDP socket
//! speaks from the node's address, its datagram goes through the node's
//! `TunPacketProcessor` like an app's, and the reply comes back through
//! [`Divert`] keyed on (remote, remote port, local port).

use std::collections::VecDeque;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use fips::{TunPacketAction, TunPacketProcessor};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{icmp, udp};
use smoltcp::wire::{
    HardwareAddress, Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpEndpoint,
};

use crate::meshhttp::{Device, FetchError, MeshLink, is_icmp_unreachable, random_u64};

/// Largest reply accepted: a DNS answer over the mesh is well under the
/// 1280-byte MTU (spec §6 of fips-names); anything bigger is truncated by
/// the sender and re-asked over TCP by the caller — not supported on the
/// phone yet, see `names.rs`.
const MAX_REPLY: usize = 4096;
/// Resends of the datagram after an ICMPv6 unreachable, before giving up.
/// The first can be a race: the identity registration and the datagram
/// reach the node on different channels (see `meshhttp::register_identity`).
const RESENDS: usize = 2;

/// Send `msg` to `[addr]:port` and return the first datagram that comes back
/// from there, within `timeout`. Blocking; the caller's thread runs the
/// stack.
pub fn query(
    link: &MeshLink,
    addr: Ipv6Addr,
    port: u16,
    msg: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, FetchError> {
    if addr == link.our_addr {
        return Err(FetchError::other("that is this node's own address"));
    }
    let flow = link
        .divert
        .open(addr, port)
        .ok_or_else(|| FetchError::other("no free local port"))?;
    let local_port = flow.key.2;
    let processor: TunPacketProcessor = link.processor.clone();
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
    exchange(
        egress,
        &flow.rx,
        (link.our_addr, local_port),
        (addr, port),
        msg,
        Instant::now() + timeout,
        &link.running,
    )
}

fn exchange<E: FnMut(Vec<u8>) -> Result<(), FetchError>>(
    egress: E,
    rx: &Receiver<Vec<u8>>,
    local: (Ipv6Addr, u16),
    remote: (Ipv6Addr, u16),
    msg: &[u8],
    deadline: Instant,
    alive: &AtomicBool,
) -> Result<Vec<u8>, FetchError> {
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
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(local.0), 8));
    });
    let socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; MAX_REPLY]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
    );
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);
    sockets
        .get_mut::<udp::Socket>(handle)
        .bind(local.1)
        .map_err(|e| FetchError::other(format!("bind: {e}")))?;
    let endpoint = IpEndpoint::new(IpAddress::Ipv6(remote.0), remote.1);
    let where_ = format!("[{}]:{}", remote.0, remote.1);

    let mut sends = 0;
    let mut unreachable = 0;
    let mut buf = vec![0u8; MAX_REPLY];
    loop {
        if !alive.load(Ordering::Relaxed) {
            return Err(FetchError::restarted());
        }
        if sends == 0 || (unreachable > 0 && sends <= RESENDS && unreachable >= sends) {
            sockets
                .get_mut::<udp::Socket>(handle)
                .send_slice(msg, endpoint)
                .map_err(|e| FetchError::other(format!("send: {e}")))?;
            sends += 1;
        }
        iface.poll(now(), &mut device, &mut sockets);
        if let Some(e) = device.failed.take() {
            return Err(e);
        }
        let socket = sockets.get_mut::<udp::Socket>(handle);
        while socket.can_recv() {
            let Ok((n, meta)) = socket.recv_slice(&mut buf) else {
                break;
            };
            // Only the server we asked; anything else on this port is noise.
            if meta.endpoint == endpoint {
                return Ok(buf[..n].to_vec());
            }
        }
        if unreachable > RESENDS {
            return Err(FetchError::unreachable(format!(
                "no route to {where_} over the mesh (the node does not know a path to it)"
            )));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FetchError::unreachable(format!(
                "{where_} did not answer (is the node online?)"
            )));
        }
        let wait = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100))
            .min(left);
        let mut handle_packet = |packet: Vec<u8>| {
            if is_icmp_unreachable(&packet) {
                unreachable += 1;
            } else {
                device.rx.push_back(packet);
            }
        };
        match rx.recv_timeout(wait) {
            Ok(packet) => {
                handle_packet(packet);
                while let Ok(packet) = rx.try_recv() {
                    handle_packet(packet);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(FetchError::restarted()),
        }
    }
}

/// Is `addr` reachable through the node right now? An ICMPv6 echo from the
/// node's own address; the reply comes back through [`Divert`] keyed on the
/// identifier. fips drops traffic for a node it has no path to silently, so
/// this is the only positive signal short of a full session (the public
/// names resolver asks before handing an application a node's address).
pub fn ping(link: &MeshLink, addr: Ipv6Addr, timeout: Duration) -> Result<bool, FetchError> {
    if addr == link.our_addr {
        return Ok(true);
    }
    let flow = link
        .divert
        .open(addr, 0)
        .ok_or_else(|| FetchError::other("no free local port"))?;
    let ident = flow.key.2;
    let processor: TunPacketProcessor = link.processor.clone();
    let outbound = link.outbound_tx.clone();
    let egress = move |mut packet: Vec<u8>| -> Result<(), FetchError> {
        match processor.process(&mut packet) {
            TunPacketAction::Forward => outbound
                .blocking_send(packet)
                .map_err(|_| FetchError::restarted()),
            TunPacketAction::Hairpin => Ok(()),
            TunPacketAction::Respond(_) => Err(FetchError::unreachable(format!(
                "the node refused to send to {addr}"
            ))),
            TunPacketAction::Drop => Ok(()),
        }
    };
    echo(
        egress,
        &flow.rx,
        link.our_addr,
        addr,
        ident,
        Instant::now() + timeout,
        &link.running,
    )
}

fn echo<E: FnMut(Vec<u8>) -> Result<(), FetchError>>(
    egress: E,
    rx: &Receiver<Vec<u8>>,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ident: u16,
    deadline: Instant,
    alive: &AtomicBool,
) -> Result<bool, FetchError> {
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
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(local), 8));
    });
    let socket = icmp::Socket::new(
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 1024]),
        icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 4], vec![0; 1024]),
    );
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);
    sockets
        .get_mut::<icmp::Socket>(handle)
        .bind(icmp::Endpoint::Ident(ident))
        .map_err(|e| FetchError::other(format!("icmp bind: {e:?}")))?;
    let send = |sockets: &mut SocketSet, seq_no: u16| -> Result<(), FetchError> {
        let repr = Icmpv6Repr::EchoRequest {
            ident,
            seq_no,
            data: b"fips-pubdom reachability",
        };
        let mut buf = vec![0u8; repr.buffer_len()];
        // The socket recomputes the checksum on dispatch.
        repr.emit(
            &local,
            &remote,
            &mut Icmpv6Packet::new_unchecked(&mut buf),
            &ChecksumCapabilities::ignored(),
        );
        sockets
            .get_mut::<icmp::Socket>(handle)
            .send_slice(&buf, IpAddress::Ipv6(remote))
            .map_err(|e| FetchError::other(format!("icmp send: {e:?}")))
    };
    send(&mut sockets, 0)?;
    let mut resent = false;
    let mut buf = vec![0u8; 1024];
    loop {
        if !alive.load(Ordering::Relaxed) {
            return Err(FetchError::restarted());
        }
        iface.poll(now(), &mut device, &mut sockets);
        if let Some(e) = device.failed.take() {
            return Err(e);
        }
        let socket = sockets.get_mut::<icmp::Socket>(handle);
        while socket.can_recv() {
            let Ok((n, from)) = socket.recv_slice(&mut buf) else {
                break;
            };
            if from == IpAddress::Ipv6(remote)
                && let Ok(p) = Icmpv6Packet::new_checked(&buf[..n])
                && p.msg_type() == Icmpv6Message::EchoReply
            {
                return Ok(true);
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        // A second request halfway: the first can race the path setup.
        if !resent && start.elapsed() * 2 >= deadline.saturating_duration_since(start) {
            send(&mut sockets, 1)?;
            resent = true;
        }
        let wait = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100))
            .min(left);
        match rx.recv_timeout(wait) {
            Ok(packet) => {
                // Unreachable errors are not a reply; everything else feeds the stack.
                if !is_icmp_unreachable(&packet) {
                    device.rx.push_back(packet);
                }
                while let Ok(packet) = rx.try_recv() {
                    if !is_icmp_unreachable(&packet) {
                        device.rx.push_back(packet);
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(FetchError::restarted()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The client loop against a smoltcp UDP echo server on the far end of
    /// two channels: the reply comes back from the asked endpoint.
    #[test]
    fn exchange_against_a_userspace_server() {
        let client_addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let server_addr: Ipv6Addr = "fd00::2".parse().unwrap();
        let (to_server, server_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (to_client, client_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        let server = std::thread::spawn(move || {
            let start = Instant::now();
            let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
            let mut device = Device {
                rx: VecDeque::new(),
                egress: move |p: Vec<u8>| {
                    let _ = to_client.send(p);
                    Ok(())
                },
                failed: None,
            };
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::Ipv6(server_addr), 8));
            });
            let mut sockets = SocketSet::new(Vec::new());
            let mut sock = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            );
            sock.bind(5355).unwrap();
            let h = sockets.add(sock);
            let mut got = None;
            while start.elapsed() < Duration::from_secs(10) {
                while let Ok(p) = server_rx.try_recv() {
                    device.rx.push_back(p);
                }
                iface.poll(now(), &mut device, &mut sockets);
                let s = sockets.get_mut::<udp::Socket>(h);
                let mut b = [0u8; 512];
                if let Ok((n, meta)) = s.recv_slice(&mut b) {
                    let mut reply = b[..n].to_vec();
                    reply[2] |= 0x80; // QR
                    s.send_slice(&reply, meta.endpoint).unwrap();
                    got = Some(reply);
                }
                if got.is_some() {
                    iface.poll(now(), &mut device, &mut sockets);
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            got
        });

        let query = vec![
            0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 28, 0, 1,
        ];
        let reply = exchange(
            move |p| {
                let _ = to_server.send(p);
                Ok(())
            },
            &client_rx,
            (client_addr, 61234),
            (server_addr, 5355),
            &query,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert_eq!(reply[..2], query[..2]);
        assert_eq!(reply[2] & 0x80, 0x80);
        assert_eq!(server.join().unwrap().unwrap(), reply);
    }

    /// A smoltcp interface answers echo requests for its own address by
    /// itself, so the far side of two channels is a complete peer.
    #[test]
    fn echo_is_answered_by_a_userspace_peer_and_not_by_silence() {
        let client_addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let server_addr: Ipv6Addr = "fd00::2".parse().unwrap();
        let (to_server, server_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (to_client, client_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = stop.clone();
        let server = std::thread::spawn(move || {
            let start = Instant::now();
            let now = || smoltcp::time::Instant::from_millis(start.elapsed().as_millis() as i64);
            let mut device = Device {
                rx: VecDeque::new(),
                egress: move |p: Vec<u8>| {
                    let _ = to_client.send(p);
                    Ok(())
                },
                failed: None,
            };
            let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
            iface.update_ip_addrs(|a| {
                let _ = a.push(IpCidr::new(IpAddress::Ipv6(server_addr), 8));
            });
            let mut sockets = SocketSet::new(Vec::new());
            while !stop_server.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(10)
            {
                while let Ok(p) = server_rx.try_recv() {
                    device.rx.push_back(p);
                }
                iface.poll(now(), &mut device, &mut sockets);
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let ok = echo(
            move |p| {
                let _ = to_server.send(p);
                Ok(())
            },
            &client_rx,
            client_addr,
            server_addr,
            61234,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(true),
        )
        .unwrap();
        stop.store(true, Ordering::Relaxed);
        server.join().unwrap();
        assert!(ok, "the userspace peer answers the echo");

        let (_tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let ok = echo(
            |_| Ok(()),
            &rx,
            client_addr,
            "fd00::9".parse().unwrap(),
            61235,
            Instant::now() + Duration::from_millis(300),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(!ok, "silence is not reachability");
    }

    #[test]
    fn silence_is_unreachable() {
        let (_tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let err = exchange(
            |_| Ok(()),
            &rx,
            ("fd00::1".parse().unwrap(), 61000),
            ("fd00::2".parse().unwrap(), 5355),
            &[0u8; 12],
            Instant::now() + Duration::from_millis(300),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(err.unreachable, "{err:?}");
    }
}
