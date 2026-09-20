//! DNS proxy for the tunnel.
//!
//! The `VpnService` advertises the node's own fips address as the device DNS
//! server, so every query from covered apps arrives in the TUN pump as an
//! IPv6/UDP packet to `<our-addr>:53`. The pump hands those here:
//!
//! - `*.fips` names → the in-process FIPS responder on `[::1]:5354`; a name
//!   from the app's hosts file (`home.fips`) is first translated to its
//!   `<npub>.fips` form — see [`DnsProxy::hosts`]
//! - everything else → the configured upstream resolvers, over a socket run
//!   through the protect hook so the query itself bypasses the tunnel
//!
//! Each query is served on a short-lived thread (blocking send/recv with a
//! timeout); DNS is low-rate and this keeps the pump loop non-blocking.

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fips::upper::hosts::{HostMap, HostMapReloader};

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
    /// The app's hosts file (readable name → npub), `None` when the config
    /// names none. fips has the same feature but only for its hardcoded
    /// `/etc/fips/hosts`, which an app cannot write — so the names are
    /// resolved here: the query is re-asked as `<npub>.fips` (the responder
    /// must still see it, since answering is also what registers the identity
    /// with the node) and the answer is re-issued under the name the app used.
    /// Checked for a changed mtime on every `.fips` query (one stat), so an
    /// edit in the app applies without a node restart.
    pub hosts: Option<Mutex<HostMapReloader>>,
}

/// Reloader for the hosts file at `path` (see [`DnsProxy::hosts`]). A file
/// that does not exist yet is an empty map, picked up once it appears.
pub fn hosts_reloader(path: Option<&str>) -> Option<Mutex<HostMapReloader>> {
    let path = path.map(str::trim).filter(|p| !p.is_empty())?;
    Some(Mutex::new(HostMapReloader::new(
        HostMap::new(),
        path.into(),
    )))
}

impl DnsProxy {
    /// Whether `packet` is a DNS query the proxy should intercept
    /// (plain UDP to `<dns_addr>:53`, where `dns_addr` is the advertised
    /// in-tunnel DNS sentinel).
    pub fn intercepts(packet: &[u8], dns_addr: &[u8; 16]) -> bool {
        packet::parse_ipv6_udp(packet)
            .map(|p| p.dst_port == 53 && &p.dst == dns_addr)
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
            let resp = match self.hosts_npub(&qname) {
                Some(npub) => {
                    // debug: a lookup is three queries (A, AAAA, HTTPS) and
                    // each already logs its outcome at info below.
                    tracing::debug!(qname = %qname, npub = %npub, "hosts entry matched");
                    npub_query(query.payload, &npub)
                        .and_then(|q| self.forward(&q, self.local_responder, false))
                        .and_then(|r| answer_as_asked(query.payload, &r))
                }
                None => self.forward(query.payload, self.local_responder, false),
            };
            // `.fips` lookups are rare and load-bearing — log the outcome at
            // info so "mesh site won't load" reports show whether resolution
            // happened and what the responder said.
            match &resp {
                Some(r) => tracing::info!(
                    qname = %qname,
                    qtype = qtype_of(query.payload),
                    rcode = r.get(3).map_or(0xff, |b| b & 0x0f),
                    answers = u16::from_be_bytes([
                        r.get(6).copied().unwrap_or(0),
                        r.get(7).copied().unwrap_or(0),
                    ]),
                    ".fips query answered"
                ),
                None => tracing::warn!(qname = %qname, ".fips responder unreachable"),
            }
            resp
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

    /// The npub the hosts file maps `qname` (lowercase, `<name>.fips`) to.
    fn hosts_npub(&self, qname: &str) -> Option<String> {
        let name = qname.strip_suffix(".fips")?;
        let mut hosts = self.hosts.as_ref()?.lock().ok()?;
        hosts.check_reload();
        hosts.hosts().lookup_npub(name).map(str::to_owned)
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

/// Offset just past the first question (name, QTYPE, QCLASS). `None` when
/// malformed; a question name is never compressed.
fn question_end(message: &[u8]) -> Option<usize> {
    let mut pos = 12usize;
    loop {
        match *message.get(pos)? {
            0 => break,
            len if len & 0xc0 == 0 => pos += 1 + len as usize,
            _ => return None,
        }
    }
    (message.len() >= pos + 5).then_some(pos + 5)
}

/// QTYPE of the first question (0 when malformed) — for log lines.
fn qtype_of(message: &[u8]) -> u16 {
    question_end(message).map_or(0, |end| {
        u16::from_be_bytes([message[end - 4], message[end - 3]])
    })
}

const TYPE_AAAA: u16 = 28;

/// `query` re-asked for `<npub>.fips`: same id, flags, QTYPE and QCLASS, and
/// nothing after the question (an EDNS OPT record is not carried over; a
/// reply without one is what a pre-EDNS server sends anyway).
fn npub_query(query: &[u8], npub: &str) -> Option<Vec<u8>> {
    let end = question_end(query)?;
    if npub.is_empty() || npub.len() > 63 {
        return None;
    }
    let mut msg = query[..4].to_vec();
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question, no records
    msg.push(npub.len() as u8);
    msg.extend_from_slice(npub.as_bytes());
    msg.extend_from_slice(b"\x04fips\x00");
    msg.extend_from_slice(&query[end - 4..end]);
    Some(msg)
}

/// The responder's reply to [`npub_query`], re-issued for the question the app
/// asked: a resolver discards a reply whose question is not its own. Flags
/// and RCODE are the responder's; its AAAA records are re-pointed at the
/// asked name. `None` (→ SERVFAIL) when the reply does not parse.
fn answer_as_asked(query: &[u8], reply: &[u8]) -> Option<Vec<u8>> {
    let mut out = query[..question_end(query)?].to_vec();
    out[2..4].copy_from_slice(reply.get(2..4)?);
    out[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);

    let mut pos = question_end(reply)?;
    let mut answers = 0u16;
    for _ in 0..u16::from_be_bytes([reply[6], reply[7]]) {
        // Owner name: labels, ended by a zero or a 2-byte compression pointer.
        loop {
            match *reply.get(pos)? {
                0 => {
                    pos += 1;
                    break;
                }
                len if len & 0xc0 == 0xc0 => {
                    pos += 2;
                    break;
                }
                len => pos += 1 + len as usize,
            }
        }
        let fixed = reply.get(pos..pos + 10)?; // TYPE, CLASS, TTL, RDLENGTH
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let rdata = reply.get(pos + 10..pos + 10 + rdlen)?;
        if u16::from_be_bytes([fixed[0], fixed[1]]) == TYPE_AAAA && rdlen == 16 {
            out.extend_from_slice(&[0xc0, 0x0c]); // the question's name, offset 12
            out.extend_from_slice(fixed);
            out.extend_from_slice(rdata);
            answers += 1;
        }
        pos += 10 + rdlen;
    }
    out[6..8].copy_from_slice(&answers.to_be_bytes());
    Some(out)
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
        typed_query_for(name, 1)
    }

    fn typed_query_for(name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&[0, 1]); // QCLASS IN
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
            hosts: None,
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
            hosts: None,
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

    /// Stand-in for the node's `.fips` responder: fips's real packet handler
    /// with an EMPTY host map, so a readable name only resolves if the proxy
    /// translated it first — and the reply has the real wire shape
    /// (compressed owner names) for `answer_as_asked` to parse.
    fn fips_responder() -> SocketAddr {
        let socket = UdpSocket::bind("[::1]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                if let Some((reply, _)) =
                    fips::upper::dns::handle_dns_packet(&buf[..n], 300, &HostMap::new())
                {
                    let _ = socket.send_to(&reply, from);
                }
            }
        });
        addr
    }

    /// One query through the proxy; the DNS payload of what comes back.
    fn ask(
        proxy: &Arc<DnsProxy>,
        replies: &std::sync::mpsc::Receiver<Vec<u8>>,
        query: &[u8],
    ) -> Vec<u8> {
        let our = [0xfd; 16];
        let mut phone = [0xfd; 16];
        phone[15] = 9;
        proxy.handle(packet::build_ipv6_udp(phone, our, 40123, 53, query));
        let response = replies
            .recv_timeout(Duration::from_secs(5))
            .expect("a response");
        packet::parse_ipv6_udp(&response).unwrap().payload.to_vec()
    }

    /// `home.fips` from the hosts file must come back as an AAAA for the
    /// mapped npub's address under the name that was ASKED, follow an edit of
    /// the file without a restart, and leave every other name alone.
    #[test]
    fn hosts_file_names_resolve_and_follow_edits() {
        let peer = |nsec: &str| crate::config::derive_identity(nsec).unwrap();
        let (home, moved) = (peer(""), peer(""));
        let path = std::env::temp_dir().join(format!("fips-hosts-test-{}", std::process::id()));
        std::fs::write(&path, format!("# my nodes\nhome  {}\n", home.npub)).unwrap();

        let (writer_tx, replies) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: fips_responder(),
            upstreams: vec![],
            writer_tx,
            protect: None,
            hosts: hosts_reloader(path.to_str()),
        });

        let query = typed_query_for("Home.fips", TYPE_AAAA);
        let reply = ask(&proxy, &replies, &query);
        let asked = question_end(&query).unwrap();
        assert_eq!(reply[..2], query[..2], "transaction id preserved");
        assert_eq!(reply[2] & 0x80, 0x80, "QR set");
        assert_eq!(reply[3] & 0x0f, 0, "NOERROR");
        assert_eq!(reply[4..8], [0, 1, 0, 1], "one question, one answer");
        assert_eq!(reply[12..asked], query[12..asked], "the question as asked");
        let addr = |reply: &[u8]| {
            let rdata: [u8; 16] = reply[reply.len() - 16..].try_into().unwrap();
            std::net::Ipv6Addr::from(rdata).to_string()
        };
        assert_eq!(reply.len(), asked + 12 + 16, "exactly one AAAA record");
        assert_eq!(addr(&reply), home.address);

        // An A query for the same name: exists, but no A records.
        let reply = ask(&proxy, &replies, &query_for("home.fips"));
        assert_eq!((reply[3] & 0x0f, reply[6], reply[7]), (0, 0, 0));

        // A name the file does not have goes to the responder untouched.
        let reply = ask(&proxy, &replies, &typed_query_for("away.fips", TYPE_AAAA));
        assert_eq!(reply[3] & 0x0f, 3, "NXDOMAIN");

        // Re-point the name. The pause keeps the two mtimes apart on a
        // filesystem that stamps from the coarse clock.
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(&path, format!("home {}\n", moved.npub)).unwrap();
        assert_eq!(addr(&ask(&proxy, &replies, &query)), moved.address);

        let _ = std::fs::remove_file(&path);
    }

    /// A reply that does not parse must become SERVFAIL, not a panic.
    #[test]
    fn truncated_reply_is_rejected() {
        let query = typed_query_for("home.fips", TYPE_AAAA);
        let mut reply = query.clone();
        reply[7] = 1; // claims an answer that is not there
        assert!(answer_as_asked(&query, &reply).is_none());
        assert!(answer_as_asked(&query, &reply[..8]).is_none());
    }
}
