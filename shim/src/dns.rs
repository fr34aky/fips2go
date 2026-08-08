//! DNS proxy for the tunnel.
//!
//! The `VpnService` advertises the node's own fips address as the device DNS
//! server, so every query from covered apps arrives in the TUN pump as an
//! IPv6/UDP packet to `<our-addr>:53`. The pump hands those here:
//!
//! - `*.fips` names → the in-process FIPS responder on `[::1]:5354`
//! - everything else → the configured upstream resolvers, over a socket run
//!   through the protect hook so the query itself bypasses the tunnel
//!
//! Each query is served on a short-lived thread (blocking send/recv with a
//! timeout); DNS is low-rate and this keeps the pump loop non-blocking.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Duration;

use crate::packet;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE: usize = 4096;

/// Shared context for the DNS proxy.
pub struct DnsProxy {
    /// The in-process FIPS responder (`[::1]:5354`).
    pub local_responder: SocketAddr,
    /// Upstream resolvers for non-`.fips` names, tried in order.
    pub upstreams: Vec<SocketAddr>,
    /// Writes response packets back to the TUN fd.
    pub writer_tx: Sender<Vec<u8>>,
    /// Socket-protect hook — upstream queries must bypass the tunnel.
    pub protect: Option<fips::SocketProtect>,
}

impl DnsProxy {
    /// Whether `packet` is a DNS query the proxy should intercept
    /// (plain UDP to `<our_addr>:53`).
    pub fn intercepts(packet: &[u8], our_addr: &[u8; 16]) -> bool {
        packet::parse_ipv6_udp(packet)
            .map(|p| p.dst_port == 53 && &p.dst == our_addr)
            .unwrap_or(false)
    }

    /// Serve one intercepted query on a short-lived thread.
    pub fn handle(self: &Arc<Self>, packet: Vec<u8>) {
        let proxy = self.clone();
        std::thread::Builder::new()
            .name("fips-dns".into())
            .spawn(move || proxy.serve(&packet))
            .ok();
    }

    fn serve(&self, packet: &[u8]) {
        let Some(query) = packet::parse_ipv6_udp(packet) else {
            return;
        };
        let qname = parse_qname(query.payload).unwrap_or_default();
        let is_fips = qname == "fips" || qname.ends_with(".fips");

        let response_payload = if is_fips {
            self.forward(query.payload, self.local_responder, false)
        } else {
            self.upstreams
                .iter()
                .find_map(|&upstream| self.forward(query.payload, upstream, true))
        };

        let payload = match response_payload {
            Some(p) => p,
            None => {
                tracing::debug!(qname = %qname, "DNS forward failed; returning SERVFAIL");
                match servfail_for(query.payload) {
                    Some(p) => p,
                    None => return,
                }
            }
        };

        // Swap the flow back toward the querier.
        let response = packet::build_ipv6_udp(query.dst, query.src, 53, query.src_port, &payload);
        let _ = self.writer_tx.send(response);
    }

    /// One blocking query/response exchange with `server`.
    fn forward(&self, query: &[u8], server: SocketAddr, protect: bool) -> Option<Vec<u8>> {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(bind).ok()?;
        if protect && let Some(hook) = &self.protect {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                hook(socket.as_raw_fd());
            }
        }
        socket.set_read_timeout(Some(QUERY_TIMEOUT)).ok()?;
        socket.send_to(query, server).ok()?;
        let mut buf = vec![0u8; MAX_RESPONSE];
        // Take the first response whose transaction id matches the query.
        for _ in 0..3 {
            let (n, _from) = socket.recv_from(&mut buf).ok()?;
            if n >= 2 && query.len() >= 2 && buf[..2] == query[..2] {
                buf.truncate(n);
                return Some(buf);
            }
        }
        None
    }
}

/// Extract the first question name from a DNS message, lowercase, without a
/// trailing dot. `None` when the message is malformed (compression pointers
/// don't appear in the question of a query).
pub fn parse_qname(message: &[u8]) -> Option<String> {
    if message.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut name = String::new();
    let mut pos = 12usize;
    loop {
        let len = *message.get(pos)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || name.len() + len + 1 > 255 {
            return None; // compression pointer or oversized name
        }
        let label = message.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|b| (*b as char).to_ascii_lowercase()));
        pos += 1 + len;
    }
    Some(name)
}

/// Turn a query into a minimal SERVFAIL response (QR=1, RCODE=2, counts
/// zeroed except the echoed question).
fn servfail_for(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut response = query.to_vec();
    response[2] |= 0x80; // QR = response
    response[2] &= !0x04; // clear AA
    response[3] = (response[3] & 0xf0) | 0x02; // RCODE = SERVFAIL
    response[6] = 0; // ANCOUNT
    response[7] = 0;
    response[8] = 0; // NSCOUNT
    response[9] = 0;
    response[10] = 0; // ARCOUNT
    response[11] = 0;
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard query for `name`, A record, id 0xbeef.
    fn query_for(name: &str) -> Vec<u8> {
        let mut msg = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
        msg
    }

    #[test]
    fn qname_parses() {
        assert_eq!(
            parse_qname(&query_for("Example.FIPS")).as_deref(),
            Some("example.fips")
        );
        assert_eq!(parse_qname(&query_for("a.b.c")).as_deref(), Some("a.b.c"));
        assert!(parse_qname(&[0u8; 5]).is_none());
    }

    #[test]
    fn servfail_shape() {
        let q = query_for("nope.example");
        let r = servfail_for(&q).unwrap();
        assert_eq!(r[..2], q[..2], "transaction id preserved");
        assert_eq!(r[2] & 0x80, 0x80, "QR set");
        assert_eq!(r[3] & 0x0f, 2, "SERVFAIL");
    }

    /// End-to-end through a fake upstream: a query to the proxy must come
    /// back on writer_tx as a full IPv6/UDP packet with the upstream's answer.
    #[test]
    fn proxies_to_upstream_and_wraps_response() {
        // Fake upstream resolver that echoes the query with QR set.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = upstream.recv_from(&mut buf) {
                buf[2] |= 0x80;
                let _ = upstream.send_to(&buf[..n], from);
            }
        });

        let (writer_tx, writer_rx) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(), // unused here
            upstreams: vec![upstream_addr],
            writer_tx,
            protect: None,
        });

        let our = [0xfd; 16];
        let mut phone = [0xfd; 16];
        phone[15] = 9;
        let query_pkt = packet::build_ipv6_udp(phone, our, 40123, 53, &query_for("example.com"));
        assert!(DnsProxy::intercepts(&query_pkt, &our));
        proxy.handle(query_pkt);

        let response = writer_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("proxied response");
        let parsed = packet::parse_ipv6_udp(&response).expect("valid IPv6/UDP");
        assert_eq!(parsed.src, our);
        assert_eq!(parsed.dst, phone);
        assert_eq!(parsed.src_port, 53);
        assert_eq!(parsed.dst_port, 40123);
        assert_eq!(parsed.payload[0..2], [0xbe, 0xef]);
        assert_eq!(parsed.payload[2] & 0x80, 0x80, "answer bit set");
    }

    /// Unresolvable upstreams must yield SERVFAIL, not silence.
    #[test]
    fn servfail_when_upstreams_dead() {
        let (writer_tx, writer_rx) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(),
            upstreams: vec![], // nothing to try
            writer_tx,
            protect: None,
        });
        let our = [0xfd; 16];
        let mut phone = [0xfd; 16];
        phone[15] = 9;
        let query_pkt = packet::build_ipv6_udp(phone, our, 40123, 53, &query_for("example.com"));
        proxy.handle(query_pkt);
        let response = writer_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("SERVFAIL response");
        let parsed = packet::parse_ipv6_udp(&response).unwrap();
        assert_eq!(parsed.payload[3] & 0x0f, 2, "SERVFAIL rcode");
    }
}
