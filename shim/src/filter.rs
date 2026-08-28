//! Stateful inbound firewall for the mesh→app TUN path.
//!
//! Being on the mesh is otherwise equivalent to sharing a LAN with every
//! authorized node: the bridge writes every decrypted inbound packet into
//! the TUN and the kernel delivers by destination port, with no filter. This
//! module closes that: **new** inbound TCP/UDP flows are denied unless their
//! destination port is allowlisted, while
//! - return traffic of outbound-initiated flows always passes (a flow table
//!   keyed on the outbound 4-tuple, refreshed by traffic in both directions),
//! - ICMPv6 always passes (ping, path errors — connectivity diagnostics and
//!   PMTU depend on it).
//!
//! fips itself needs no inbound TUN ports: the mesh protocol rides the UDP
//! underlay sockets, and the in-process DNS responder binds loopback — so
//! the default allowlist is empty (pure default-deny).
//!
//! Packets whose IPv6 next-header is anything other than TCP/UDP/ICMPv6
//! (extension headers, fragments) are dropped inbound and ignored outbound —
//! app traffic on the mesh never carries them in practice, and parsing
//! header chains would give the filter an attack surface of its own.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// Idle timeouts after which a tracked flow no longer admits inbound
/// traffic. TCP gets the longer window (idle-but-established connections);
/// UDP "flows" are request/response shaped.
const TCP_IDLE: Duration = Duration::from_secs(600);
const UDP_IDLE: Duration = Duration::from_secs(180);

/// Bound on tracked flows; beyond it, expired entries are purged and — if
/// still full — the oldest entry is evicted. 4096 is far above what a
/// phone's covered apps hold open concurrently.
const MAX_FLOWS: usize = 4096;

/// An outbound-initiated flow, from our side's perspective.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    /// Our port (the packet's source port outbound, destination inbound).
    local_port: u16,
    /// The peer's mesh address.
    remote_addr: [u8; 16],
    /// The peer's port.
    remote_port: u16,
}

/// The parsed transport header of a plain (extension-header-free) IPv6
/// packet.
struct Parsed {
    proto: u8,
    src_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
}

/// Parse proto + addresses + ports out of an IPv6 packet with the transport
/// header directly after the fixed header. Returns `None` for anything else
/// (non-IPv6, truncated, extension headers). ICMPv6 parses with ports 0.
fn parse(packet: &[u8]) -> Option<Parsed> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let proto = packet[6];
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&packet[8..24]);
    match proto {
        PROTO_ICMPV6 => Some(Parsed {
            proto,
            src_addr,
            src_port: 0,
            dst_port: 0,
        }),
        PROTO_TCP | PROTO_UDP => {
            let l4 = packet.get(40..44)?;
            Some(Parsed {
                proto,
                src_addr,
                src_port: u16::from_be_bytes([l4[0], l4[1]]),
                dst_port: u16::from_be_bytes([l4[2], l4[3]]),
            })
        }
        _ => None,
    }
}

fn idle_limit(proto: u8) -> Duration {
    if proto == PROTO_TCP { TCP_IDLE } else { UDP_IDLE }
}

/// See the module docs. One instance per engine start, shared by the pump's
/// reader (outbound flow tracking) and bridge (inbound verdicts) threads.
pub struct InboundFilter {
    allowed_ports: Vec<u16>,
    flows: Mutex<HashMap<FlowKey, Instant>>,
}

impl InboundFilter {
    pub fn new(mut allowed_ports: Vec<u16>) -> Self {
        allowed_ports.sort_unstable();
        allowed_ports.dedup();
        Self {
            allowed_ports,
            flows: Mutex::new(HashMap::new()),
        }
    }

    /// Record/refresh the flow of an outbound mesh packet (call for packets
    /// the node's processor forwards into the mesh).
    pub fn note_outbound(&self, packet: &[u8]) {
        let Some(p) = parse(packet) else { return };
        if p.proto == PROTO_ICMPV6 {
            return;
        }
        let mut dst_addr = [0u8; 16];
        dst_addr.copy_from_slice(&packet[24..40]);
        let key = FlowKey {
            proto: p.proto,
            local_port: p.src_port,
            remote_addr: dst_addr,
            remote_port: p.dst_port,
        };
        let now = Instant::now();
        let mut flows = self.flows.lock().unwrap();
        if flows.len() >= MAX_FLOWS && !flows.contains_key(&key) {
            flows.retain(|k, seen| now.duration_since(*seen) < idle_limit(k.proto));
            if flows.len() >= MAX_FLOWS {
                // Still full of live flows: evict the stalest one.
                if let Some(oldest) = flows.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k) {
                    flows.remove(&oldest);
                }
            }
        }
        flows.insert(key, now);
    }

    /// Verdict for a mesh→app packet about to be written to the TUN.
    pub fn allow_inbound(&self, packet: &[u8]) -> bool {
        let Some(p) = parse(packet) else {
            return false; // extension headers / non-IPv6: default-deny
        };
        if p.proto == PROTO_ICMPV6 {
            return true;
        }
        if self.allowed_ports.binary_search(&p.dst_port).is_ok() {
            return true;
        }
        let key = FlowKey {
            proto: p.proto,
            local_port: p.dst_port,
            remote_addr: p.src_addr,
            remote_port: p.src_port,
        };
        let now = Instant::now();
        let mut flows = self.flows.lock().unwrap();
        match flows.get_mut(&key) {
            Some(seen) if now.duration_since(*seen) < idle_limit(p.proto) => {
                *seen = now; // inbound traffic keeps the flow alive
                true
            }
            Some(_) => {
                flows.remove(&key);
                false
            }
            None => false,
        }
    }

    /// `(proto, dst_port, src)` of a denied packet, for the drop log.
    pub fn describe(packet: &[u8]) -> (u8, u16, std::net::Ipv6Addr) {
        match parse(packet) {
            Some(p) => (p.proto, p.dst_port, std::net::Ipv6Addr::from(p.src_addr)),
            None => (
                packet.get(6).copied().unwrap_or(0),
                0,
                std::net::Ipv6Addr::UNSPECIFIED,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[15] = last;
        a
    }

    /// Minimal IPv6 packet: fixed header + 4 bytes of ports (enough for the
    /// filter's parser; real payloads don't change verdicts).
    fn pkt(proto: u8, src: [u8; 16], sport: u16, dst: [u8; 16], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 6 << 4;
        p[6] = proto;
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p
    }

    const US: u8 = 1;
    const PEER: u8 = 2;

    #[test]
    fn default_deny_new_inbound() {
        let f = InboundFilter::new(vec![]);
        assert!(!f.allow_inbound(&pkt(PROTO_TCP, addr(PEER), 40000, addr(US), 8080)));
        assert!(!f.allow_inbound(&pkt(PROTO_UDP, addr(PEER), 40000, addr(US), 5000)));
    }

    #[test]
    fn allowlisted_port_admits_both_protocols() {
        let f = InboundFilter::new(vec![8080]);
        assert!(f.allow_inbound(&pkt(PROTO_TCP, addr(PEER), 40000, addr(US), 8080)));
        assert!(f.allow_inbound(&pkt(PROTO_UDP, addr(PEER), 40000, addr(US), 8080)));
        assert!(!f.allow_inbound(&pkt(PROTO_TCP, addr(PEER), 40000, addr(US), 8081)));
    }

    #[test]
    fn icmpv6_always_allowed() {
        let f = InboundFilter::new(vec![]);
        assert!(f.allow_inbound(&pkt(PROTO_ICMPV6, addr(PEER), 0, addr(US), 0)));
    }

    #[test]
    fn outbound_flow_admits_return_traffic_only_from_that_peer() {
        let f = InboundFilter::new(vec![]);
        f.note_outbound(&pkt(PROTO_TCP, addr(US), 40000, addr(PEER), 80));
        // Exact reverse tuple: allowed.
        assert!(f.allow_inbound(&pkt(PROTO_TCP, addr(PEER), 80, addr(US), 40000)));
        // Same ports from a different peer: denied.
        assert!(!f.allow_inbound(&pkt(PROTO_TCP, addr(3), 80, addr(US), 40000)));
        // Different source port from the right peer: denied.
        assert!(!f.allow_inbound(&pkt(PROTO_TCP, addr(PEER), 81, addr(US), 40000)));
        // Wrong protocol: denied.
        assert!(!f.allow_inbound(&pkt(PROTO_UDP, addr(PEER), 80, addr(US), 40000)));
    }

    #[test]
    fn extension_headers_denied() {
        let f = InboundFilter::new(vec![0]); // even a 0 allowlist entry is moot
        let frag = pkt(44, addr(PEER), 0, addr(US), 0); // fragment header
        assert!(!f.allow_inbound(&frag));
        let v4 = vec![0x45u8; 44];
        assert!(!f.allow_inbound(&v4));
    }

    #[test]
    fn flow_expires_after_idle() {
        let f = InboundFilter::new(vec![]);
        f.note_outbound(&pkt(PROTO_UDP, addr(US), 40000, addr(PEER), 53));
        // Backdate the entry past the UDP idle limit.
        {
            let mut flows = f.flows.lock().unwrap();
            for t in flows.values_mut() {
                *t = Instant::now() - UDP_IDLE - Duration::from_secs(1);
            }
        }
        assert!(!f.allow_inbound(&pkt(PROTO_UDP, addr(PEER), 53, addr(US), 40000)));
    }

    #[test]
    fn flow_table_bounded() {
        let f = InboundFilter::new(vec![]);
        for i in 0..(MAX_FLOWS + 100) {
            let port = 1024 + (i % 60000) as u16;
            let peer = addr((i % 250) as u8);
            f.note_outbound(&pkt(PROTO_UDP, addr(US), port, peer, 9999));
        }
        assert!(f.flows.lock().unwrap().len() <= MAX_FLOWS);
    }
}
