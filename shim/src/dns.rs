//! DNS proxy for the tunnel.
//!
//! The `VpnService` advertises the node's own fips address as the device DNS
//! server, so every query from covered apps arrives in the TUN pump as an
//! IPv6/UDP packet to `<our-addr>:53`. The pump hands those here:
//!
//! - `*.fips` names → the in-process FIPS responder on `[::1]:5354`; a name
//!   from the app's hosts file (`home.fips`) is first translated to its
//!   `<npub>.fips` form — see [`DnsProxy::hosts`]
//! - everything else → first the public-names resolver ([`DnsProxy::names`]:
//!   a domain bound to a mesh node answers with that node's `fd…` address),
//!   otherwise the configured upstream resolvers, over a socket run through
//!   the protect hook so the query itself bypasses the tunnel
//!
//! Each query is served on a short-lived thread (blocking send/recv with a
//! timeout); DNS is low-rate and this keeps the pump loop non-blocking.
//! Where the public-names resolver allows it (no pinned domain above the
//! name, a validated Internet) a second thread asks the upstreams while
//! the resolver decides, so a name that is not over fips does not wait
//! for both in turn.

use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fips::hosts::{HostMap, HostMapReloader};

use crate::packet;

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a released lookup's decision is waited for between looks at
/// whether its legacy answer has arrived.
const EARLY_POLL: Duration = Duration::from_millis(5);
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
    /// Public domain names over fips (`names.rs`), `None` when off. Asked
    /// before the upstreams for every non-`.fips` name; `Legacy` from it
    /// means "not over fips" and the query goes upstream unchanged,
    /// `Capped(n)` that it goes upstream but with the answer's TTLs capped
    /// at `n` seconds (the lookup still deciding, or a server unreachable).
    pub names: Option<Arc<dyn crate::names::Lookup>>,
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

    fn serve(self: &Arc<Self>, packet: &[u8]) {
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
            use crate::names::{Decided, Outcome};
            // The legacy answer, fetched while the lookup decides — started
            // by the lookup itself, once it knows it will not settle at
            // once and the resolver allows it — so a name not over fips
            // does not pay for the decision and the upstream one after the
            // other.
            let slot: std::sync::OnceLock<std::sync::mpsc::Receiver<Option<Vec<u8>>>> =
                std::sync::OnceLock::new();
            let start_prefetch = || {
                slot.get_or_init(|| {
                    let (tx, rx) = std::sync::mpsc::channel();
                    let (proxy, q) = (self.clone(), query.payload.to_vec());
                    // A thread that cannot be spawned drops `tx` with its
                    // closure: a disconnected channel, asked inline instead.
                    let _ = std::thread::Builder::new()
                        .name("fips-dns-legacy".into())
                        .spawn(move || {
                            let _ = tx.send(proxy.forward_upstreams(&q));
                        });
                    rx
                });
            };
            let clamp_to = |legacy: Vec<u8>, cap: u32| {
                // A reply the clamp cannot parse (truncated above
                // MAX_RESPONSE, malformed) goes out as it came: the
                // app's resolver may still use it, and a name not
                // over fips must not fail for a slow lookup.
                pubdom_core::synth::clamp_ttls(&legacy, cap).unwrap_or(legacy)
            };
            let forward = |prefetched: Option<std::sync::mpsc::Receiver<Option<Vec<u8>>>>| match prefetched {
                // A dead fetching thread must not cost the answer.
                Some(rx) => rx.recv().unwrap_or_else(|_| self.forward_upstreams(query.payload)),
                None => self.forward_upstreams(query.payload),
            };
            let outcome = self.names.as_ref().map(|n| n.lookup(query.payload, &start_prefetch));
            let prefetched = slot.into_inner();
            match outcome {
                Some(Outcome::Answer(a)) => {
                    // Rare and load-bearing, like `.fips`: say so at info.
                    tracing::info!(qname = %qname, qtype = qtype_of(query.payload), "public name answered over fips");
                    Some(a)
                }
                Some(Outcome::Capped(cap)) => {
                    // Two cases, told apart by the cap: the overrun TTL
                    // while the lookup is still deciding, longer when the
                    // name is over fips but its server is unreachable.
                    if cap == pubdom_core::OVERRUN_TTL_SECS {
                        tracing::info!(qname = %qname, qtype = qtype_of(query.payload), "public name still deciding; legacy answer for a few seconds");
                    } else {
                        tracing::info!(qname = %qname, qtype = qtype_of(query.payload), cap, "public name's server unreachable; legacy answer until the retry");
                    }
                    forward(prefetched).map(|legacy| clamp_to(legacy, cap))
                }
                Some(Outcome::Early(mut decided)) => {
                    // Wait for the legacy answer and the decision at once.
                    // A decision that was cached is in right away; one
                    // that arrives before the upstream's answer is the
                    // answer, so a name over fips never sits behind a slow
                    // upstream; and when the upstreams give nothing, the
                    // decision is all that is left to wait for.
                    let give_up = std::time::Instant::now() + crate::names::BUDGET;
                    let mut outcome = decided(EARLY_POLL);
                    let mut legacy: Option<Option<Vec<u8>>> = None;
                    while outcome.is_none() {
                        match &legacy {
                            None => {
                                legacy = Some(match &prefetched {
                                    Some(rx) => match rx.try_recv() {
                                        Ok(reply) => reply,
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                                            outcome = decided(EARLY_POLL);
                                            continue;
                                        }
                                        // The fetching thread died: ask here.
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => self.forward_upstreams(query.payload),
                                    },
                                    None => self.forward_upstreams(query.payload),
                                });
                                outcome = decided(Duration::ZERO);
                            }
                            Some(Some(_)) => break,
                            Some(None) if std::time::Instant::now() >= give_up => break,
                            Some(None) => outcome = decided(EARLY_POLL),
                        }
                    }
                    match outcome {
                        Some(Decided::Answer(a)) => {
                            tracing::info!(qname = %qname, qtype = qtype_of(query.payload), "public name answered over fips");
                            Some(a)
                        }
                        Some(Decided::Legacy) => legacy.unwrap_or_else(|| forward(prefetched)),
                        Some(Decided::Capped(cap)) => {
                            tracing::info!(qname = %qname, qtype = qtype_of(query.payload), cap, "public name's server unreachable; legacy answer until the retry");
                            legacy
                                .unwrap_or_else(|| forward(prefetched))
                                .map(|l| clamp_to(l, cap))
                        }
                        None => {
                            tracing::debug!(qname = %qname, "public name released on an upstream's denial; legacy answer for a few seconds");
                            legacy.flatten().map(|l| clamp_to(l, pubdom_core::OVERRUN_TTL_SECS))
                        }
                    }
                }
                Some(Outcome::Legacy) | None => forward(prefetched),
            }
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

    /// The upstreams in order, the first that answers.
    fn forward_upstreams(&self, query: &[u8]) -> Option<Vec<u8>> {
        self.upstreams
            .iter()
            .find_map(|&upstream| self.forward(query, upstream, true))
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
            names: None,
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
            names: None,
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
                if let Some((reply, _)) = fips::ipv6tun::dns::handle_dns_packet(
                    &buf[..n],
                    from.port(),
                    300,
                    &HostMap::new(),
                ) {
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
            names: None,
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

    /// A public name the names resolver answers must come back wrapped
    /// for the app — with the upstreams never asked — and one it declines
    /// must go upstream exactly as before.
    #[test]
    fn public_names_answer_before_upstreams_and_fall_through() {
        use crate::names::Outcome;
        struct Bound;
        impl crate::names::Lookup for Bound {
            fn lookup(&self, query: &[u8], _: &dyn Fn()) -> Outcome {
                let Some(q) = pubdom_core::synth::parse_query(query) else {
                    return Outcome::Legacy;
                };
                if q.name != "www.example.org" {
                    return Outcome::Legacy;
                }
                match pubdom_core::synth::build_answer(&q, pubdom_core::Npub::from_bytes([7; 32]), 30) {
                    Some(a) => Outcome::Answer(a),
                    None => Outcome::Legacy,
                }
            }
        }
        // An upstream that would answer anything it is asked, so a leak of
        // the bound name is visible as an answer with the wrong shape.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = upstream.recv_from(&mut buf) {
                buf[2] |= 0x80;
                buf[3] = (buf[3] & 0xf0) | 3; // NXDOMAIN: the upstream's voice
                let _ = upstream.send_to(&buf[..n], from);
            }
        });
        let (writer_tx, replies) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(),
            upstreams: vec![upstream_addr],
            writer_tx,
            protect: None,
            hosts: None,
            names: Some(Arc::new(Bound)),
        });
        let reply = ask(&proxy, &replies, &typed_query_for("www.example.org", TYPE_AAAA));
        assert_eq!(reply[3] & 0x0f, 0, "answered over fips, not by the upstream");
        assert_eq!(reply[6..8], [0, 2], "CNAME + AAAA");
        let fd: [u8; 16] = reply[reply.len() - 16..].try_into().unwrap();
        assert_eq!(fd, pubdom_core::Npub::from_bytes([7; 32]).fips_address().octets());

        let reply = ask(&proxy, &replies, &typed_query_for("www.example.net", TYPE_AAAA));
        assert_eq!(reply[3] & 0x0f, 3, "not over fips: the upstream's answer");
    }

    /// While the names resolver is still deciding (its budget ran out),
    /// the upstream's answer is handed out with short TTLs: the app's
    /// resolver must ask again once the decision is cached, not keep the
    /// legacy address for the record's own TTL.
    #[test]
    fn pending_public_name_gets_the_legacy_answer_short_lived() {
        use crate::names::Outcome;
        struct Slow;
        impl crate::names::Lookup for Slow {
            fn lookup(&self, _: &[u8], _: &dyn Fn()) -> Outcome {
                Outcome::Capped(pubdom_core::OVERRUN_TTL_SECS)
            }
        }
        // An upstream answering every question with one A record, TTL 300.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = upstream.recv_from(&mut buf) {
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[6..8].copy_from_slice(&[0, 1]);
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // name ptr, A, IN
                reply.extend_from_slice(&300u32.to_be_bytes());
                reply.extend_from_slice(&[0, 4, 217, 26, 48, 101]);
                let _ = upstream.send_to(&reply, from);
            }
        });
        let (writer_tx, replies) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(),
            upstreams: vec![upstream_addr],
            writer_tx,
            protect: None,
            hosts: None,
            names: Some(Arc::new(Slow)),
        });
        let reply = ask(&proxy, &replies, &typed_query_for("relay.example.org", 1));
        assert_eq!(reply[3] & 0x0f, 0);
        assert_eq!(reply[6..8], [0, 1], "the upstream's one A record");
        let n = reply.len();
        assert_eq!(&reply[n - 4..], &[217, 26, 48, 101], "the upstream's address");
        let ttl = u32::from_be_bytes(reply[n - 10..n - 6].try_into().unwrap());
        assert_eq!(ttl, pubdom_core::OVERRUN_TTL_SECS, "TTL capped while the lookup is pending");
    }

    /// An upstream answering every question with one A record, TTL 300,
    /// after `delay`.
    fn slow_upstream(delay: Duration) -> SocketAddr {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = upstream.recv_from(&mut buf) {
                std::thread::sleep(delay);
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[6..8].copy_from_slice(&[0, 1]);
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // name ptr, A, IN
                reply.extend_from_slice(&300u32.to_be_bytes());
                reply.extend_from_slice(&[0, 4, 217, 26, 48, 101]);
                let _ = upstream.send_to(&reply, from);
            }
        });
        addr
    }

    /// A lookup released early (one upstream denied the record): the
    /// legacy answer goes out short-lived while nothing is decided,
    /// unchanged once the decision is "not over fips", and gives way to an
    /// answer over fips that arrives first — without waiting for the
    /// upstream.
    #[test]
    fn an_early_release_follows_the_decision_that_arrives_meanwhile() {
        use crate::names::{Decided, Outcome};
        /// `after`: how many times the decision is asked before it is in.
        struct Released {
            after: usize,
            over_fips: bool,
            /// Decided "over fips, but unreachable now": the cap.
            capped: Option<u32>,
        }
        impl crate::names::Lookup for Released {
            fn lookup(&self, query: &[u8], pending: &dyn Fn()) -> Outcome {
                pending();
                let (after, over_fips, capped) = (self.after, self.over_fips, self.capped);
                let mut asked = 0;
                let q = pubdom_core::synth::parse_query(query).unwrap();
                Outcome::Early(Box::new(move |_wait| {
                    asked += 1;
                    if asked <= after {
                        return None;
                    }
                    Some(if let Some(cap) = capped {
                        Decided::Capped(cap)
                    } else if over_fips {
                        Decided::Answer(pubdom_core::synth::build_answer(&q, pubdom_core::Npub::from_bytes([7; 32]), 30).unwrap())
                    } else {
                        Decided::Legacy
                    })
                }))
            }
        }
        let proxy_for = |upstream: SocketAddr, names: Released| {
            let (writer_tx, replies) = std::sync::mpsc::channel();
            let proxy = Arc::new(DnsProxy {
                local_responder: "[::1]:1".parse().unwrap(),
                upstreams: vec![upstream],
                writer_tx,
                protect: None,
                hosts: None,
                names: Some(Arc::new(names)),
            });
            (proxy, replies)
        };
        let ttl = |reply: &[u8]| u32::from_be_bytes(reply[reply.len() - 10..reply.len() - 6].try_into().unwrap());
        let query = typed_query_for("www.example.org", 1);

        // Never decided: the upstream's answer, TTL capped.
        let (proxy, replies) = proxy_for(slow_upstream(Duration::ZERO), Released { after: usize::MAX, over_fips: false, capped: None });
        let reply = ask(&proxy, &replies, &query);
        assert_eq!(&reply[reply.len() - 4..], &[217, 26, 48, 101]);
        assert_eq!(ttl(&reply), pubdom_core::OVERRUN_TTL_SECS);

        // Decided "not over fips" at once (a cached decision): as the
        // upstream sent it.
        let (proxy, replies) = proxy_for(slow_upstream(Duration::from_millis(50)), Released { after: 0, over_fips: false, capped: None });
        let reply = ask(&proxy, &replies, &query);
        assert_eq!(ttl(&reply), 300);

        // Decided "over fips" while the upstream is still thinking: the
        // fips answer, long before the upstream's.
        let (proxy, replies) = proxy_for(slow_upstream(Duration::from_secs(2)), Released { after: 2, over_fips: true, capped: None });
        let started = std::time::Instant::now();
        let reply = ask(&proxy, &replies, &typed_query_for("www.example.org", 28));
        assert!(started.elapsed() < Duration::from_secs(1), "waited for the upstream");
        assert_eq!(reply[6..8], [0, 2], "our CNAME and AAAA, not the upstream's one A");

        // No upstream answers at all: the decision is waited for, and an
        // answer over fips still arrives instead of SERVFAIL.
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let (proxy, replies) = proxy_for(dead, Released { after: 40, over_fips: true, capped: None });
        let reply = ask(&proxy, &replies, &typed_query_for("www.example.org", 28));
        assert_eq!(reply[6..8], [0, 2]);

        // Decided "unavailable" after the release: the legacy answer, TTL
        // capped at the time to the retry.
        let (proxy, replies) = proxy_for(slow_upstream(Duration::ZERO), Released { after: 0, over_fips: false, capped: Some(60) });
        let reply = ask(&proxy, &replies, &query);
        assert_eq!(ttl(&reply), 60);
    }

    /// A name over fips whose servers are unreachable right now: the
    /// legacy answer, with its TTLs capped at the time to the next attempt.
    #[test]
    fn an_unavailable_public_name_gets_the_legacy_answer_until_the_retry() {
        use crate::names::Outcome;
        struct Unavailable;
        impl crate::names::Lookup for Unavailable {
            fn lookup(&self, _: &[u8], _: &dyn Fn()) -> Outcome {
                Outcome::Capped(20)
            }
        }
        let (writer_tx, replies) = std::sync::mpsc::channel();
        let proxy = Arc::new(DnsProxy {
            local_responder: "[::1]:1".parse().unwrap(),
            upstreams: vec![slow_upstream(Duration::ZERO)],
            writer_tx,
            protect: None,
            hosts: None,
            names: Some(Arc::new(Unavailable)),
        });
        let reply = ask(&proxy, &replies, &typed_query_for("www.example.org", 1));
        let n = reply.len();
        assert_eq!(&reply[n - 4..], &[217, 26, 48, 101], "the upstream's address");
        assert_eq!(u32::from_be_bytes(reply[n - 10..n - 6].try_into().unwrap()), 20);
    }

    /// The legacy fetch is started by the lookup, or not at all: a lookup
    /// that asks for it and ends `Capped` gets the prefetched reply (one
    /// upstream query, not two); one that settles without asking leaves
    /// the upstream to the proxy afterwards (one query, no thread).
    #[test]
    fn the_lookup_decides_whether_the_legacy_answer_is_prefetched() {
        use crate::names::Outcome;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Asks(bool);
        impl crate::names::Lookup for Asks {
            fn lookup(&self, _: &[u8], pending: &dyn Fn()) -> Outcome {
                if self.0 {
                    pending();
                    Outcome::Capped(pubdom_core::OVERRUN_TTL_SECS)
                } else {
                    Outcome::Legacy
                }
            }
        }
        // An upstream that counts its questions.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = upstream.local_addr().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = upstream.recv_from(&mut buf) {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[6..8].copy_from_slice(&[0, 1]);
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                reply.extend_from_slice(&300u32.to_be_bytes());
                reply.extend_from_slice(&[0, 4, 217, 26, 48, 101]);
                let _ = upstream.send_to(&reply, from);
            }
        });
        for (asks, expect_ttl) in [(true, pubdom_core::OVERRUN_TTL_SECS), (false, 300)] {
            let (writer_tx, replies) = std::sync::mpsc::channel();
            let proxy = Arc::new(DnsProxy {
                local_responder: "[::1]:1".parse().unwrap(),
                upstreams: vec![addr],
                writer_tx,
                protect: None,
                hosts: None,
                names: Some(Arc::new(Asks(asks))),
            });
            let before = asked.load(Ordering::SeqCst);
            let reply = ask(&proxy, &replies, &typed_query_for("www.example.org", 1));
            let n = reply.len();
            assert_eq!(u32::from_be_bytes(reply[n - 10..n - 6].try_into().unwrap()), expect_ttl);
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(asked.load(Ordering::SeqCst) - before, 1, "one upstream query, asks={asks}");
        }
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
