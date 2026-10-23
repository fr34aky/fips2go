//! Public domain names over fips (`www.example.org` → a mesh node), the
//! phone half of fr34aky/fips-pub-domains: `pubdom-core` decides,
//! `pubdom-resolve` talks to relays and the legacy DNS, and this module
//! supplies what only
//! the phone can — the mesh transport (`meshudp.rs`) and the identity
//! registration through the in-process responder — and runs the lookup
//! from the DNS proxy's blocking per-query thread.
//!
//! Order of business for a non-`.fips` name (fips-pub-domains spec §5–§7):
//! local pins, then — online — the `_fips-dns.<domain>` TXT record from the
//! configured upstreams, a claim from the relays only after a TXT hit (or,
//! offline, a claim from a relay on the mesh whose DNSSEC proof verifies),
//! step
//! 3 to the domain's server over the mesh, and a synthesized answer with the
//! node's `fd…` address. Everything else is [`Outcome::Legacy`], and the
//! proxy forwards to the upstreams exactly as before — or
//! [`Outcome::Capped`] when the lookup overran its budget and is still
//! deciding, or the name is over fips but nobody is reachable right now —
//! which forwards too but with the answer's TTLs capped (5 s, or until
//! the next attempt) — or
//! [`Outcome::Early`] when one upstream has already denied the record and
//! the legacy answer need not wait for the rest. A name that is not over
//! fips is never made unreachable by this code.

use std::net::{IpAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use pubdom_core::Npub;
use pubdom_resolve::FilePinStore;
use pubdom_resolve::config::MaybeTxt;
use pubdom_resolve::mesh::MeshDns;
use pubdom_resolve::relay::RelayClient;
use pubdom_resolve::resolver::{LookupResult, Probe, Resolver, ResolverConfig, TxtSource};

use crate::config::ShimConfig;
use crate::meshhttp::MeshLink;
use crate::meshtcp::MeshRelayProxy;

/// The whole lookup must fit inside what an app's resolver waits for (5 s on
/// bionic) with room for the legacy fallback after it.
pub(crate) const BUDGET: Duration = Duration::from_millis(3500);

/// What the DNS proxy asks: a complete reply, or what to do with the
/// legacy one.
pub enum Outcome {
    /// A complete reply for the application.
    Answer(Vec<u8>),
    /// Not over fips: the upstreams' answer, unchanged.
    Legacy,
    /// The upstreams' answer with its TTLs capped at this many seconds,
    /// so the application's resolver asks again by then instead of keeping
    /// the legacy address for the record's own TTL (Android kept a parked
    /// wildcard's 300 s, and the cached decision was never asked for).
    /// Two cases: the lookup overran its budget and is still deciding
    /// (`pubdom_core::OVERRUN_TTL_SECS`), or the name is over fips but no
    /// server or target node is reachable right now
    /// (`LookupResult::Unavailable`, the cap being the time to the next
    /// attempt — a node that just connected sees this on its first lookup,
    /// before its session to the server is up).
    Capped(u32),
    /// Still deciding, but one upstream has already said that no domain
    /// this name could belong to has a record: the upstreams' answer goes
    /// out now instead of after the slowest upstream has agreed. The
    /// closure waits up to the given time for the decision — asked while
    /// and after the legacy answer is fetched, it turns this into `Answer`
    /// or `Legacy` after all; while it returns `None` the answer goes out
    /// short-lived, as `Capped`. (A decision that was cached also
    /// arrives this way, and is in at the first ask.)
    Early(Box<dyn FnMut(Duration) -> Option<Decided> + Send>),
}

/// What a lookup that was [`Outcome::Early`] turned out to be.
pub enum Decided {
    Answer(Vec<u8>),
    Legacy,
    /// As [`Outcome::Capped`].
    Capped(u32),
}

pub trait Lookup: Send + Sync {
    /// Resolve `query`. `pending` is called, at most once, when the lookup
    /// did not settle at its first poll and the legacy answer may be
    /// fetched alongside it: almost every name is not over fips and its
    /// answer should not wait for us to find that out. It is not called
    /// for a name under a pinned domain (answered from the pin while its
    /// server is reachable; the upstream hears of it only when the server
    /// is not, and then after the fact), nor where no early release can
    /// follow, nor when the lookup settled at once — a cached decision, a
    /// record type never over fips — where the answer is back before the
    /// upstream would be.
    fn lookup(&self, query: &[u8], pending: &dyn Fn()) -> Outcome;
}

/// What a finished lookup means to the proxy — the one mapping, whether
/// the lookup finished in time or after an early release.
fn decided(result: LookupResult) -> Decided {
    match result {
        LookupResult::Answer(a) => Decided::Answer(a),
        LookupResult::Passthrough => Decided::Legacy,
        LookupResult::Unavailable { retry_in } => {
            tracing::debug!(
                retry_in_s = retry_in.as_secs(),
                "public name's server unreachable; legacy answer until the retry"
            );
            Decided::Capped(pubdom_core::unavailable_ttl(retry_in))
        }
    }
}

fn settled(result: LookupResult) -> Outcome {
    match decided(result) {
        Decided::Answer(a) => Outcome::Answer(a),
        Decided::Legacy => Outcome::Legacy,
        Decided::Capped(cap) => Outcome::Capped(cap),
    }
}

pub struct Names {
    /// One worker thread: hickory and nostr-sdk need an async runtime, the
    /// proxy is blocking, and `block_on` from its thread drives the future
    /// while the worker keeps the relay pool alive.
    rt: Option<tokio::runtime::Runtime>,
    resolver: Arc<Resolver<PhoneTxt, RelayClient>>,
    /// The mesh relays' loopback listeners; they stop when this drops.
    _relays: Vec<MeshRelayProxy>,
}

impl Names {
    /// Build the resolver over `link`; `pins_path` is the app-private JSON
    /// pin file (shared schema with the desktop daemon).
    pub fn start(
        config: &ShimConfig,
        link: Arc<MeshLink>,
        pins_path: &str,
    ) -> Result<Arc<Self>, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("fips-names")
            .enable_all()
            .build()
            .map_err(|e| format!("names runtime: {e}"))?;
        // Relays on the mesh (`ws://<npub>.fips:port`): nostr-sdk's sockets
        // cannot reach fd00::/8 from this app, so each gets a loopback
        // listener carried over the in-process TCP stack (`meshtcp.rs`).
        let proxies: Vec<MeshRelayProxy> = config
            .names_mesh_relays
            .iter()
            .filter_map(|url| match MeshRelayProxy::start(link.clone(), url) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(error = %e, "mesh relay not used");
                    None
                }
            })
            .collect();
        let upstreams: Vec<IpAddr> = config
            .upstream_addrs()
            .into_iter()
            .map(|a| a.ip())
            .collect();
        // A witness that does not parse is dropped with a warning rather
        // than failing the start: the app validates on the way out, and a
        // name-resolution feature must not keep the tunnel from coming up.
        // The line itself is not logged: the log ring is shareable from
        // Diagnostics, and a pasted secret must not end up in it.
        let witnesses: Vec<Npub> = config
            .names_witnesses
            .iter()
            .enumerate()
            .filter_map(|(i, w)| match Npub::parse_any(w.trim()) {
                Ok(n) => Some(n),
                Err(e) => {
                    tracing::warn!(line = i + 1, len = w.len(), error = %e, "ignoring witness: not an npub");
                    None
                }
            })
            .collect();
        let defaults = ResolverConfig::default();
        let rc = ResolverConfig {
            public_relays: if config.nostr_relays.is_empty() {
                defaults.public_relays.clone()
            } else {
                config.nostr_relays.clone()
            },
            mesh_relays: proxies.iter().map(|p| p.local_url.clone()).collect(),
            allow_unverified_offline: config.names_allow_unverified_offline,
            witnesses,
            attestation_threshold: config
                .names_attestation_threshold
                .unwrap_or(defaults.attestation_threshold),
            dnssec: config.names_dnssec.unwrap_or(defaults.dnssec),
            ..defaults
        };
        let pins = FilePinStore::open(pins_path).map_err(|e| format!("pins {pins_path}: {e}"))?;
        // The upstreams are fixed for the engine's lifetime: a network change
        // rebinds the whole engine with a fresh config, so nothing swaps them
        // at run time here.
        let txt = MaybeTxt::new(&upstreams, rc.dnssec, rc.txt_timeout)?;
        let resolver = rt.block_on(async {
            let relays =
                RelayClient::new(&rc.public_relays, &rc.mesh_relays, rc.relay_timeout).await;
            Resolver::new(
                rc,
                Arc::new(pins),
                PhoneTxt(txt),
                relays,
                Arc::new(PhoneMesh { link }),
            )
        });
        let names = Arc::new(Self {
            rt: Some(rt),
            resolver: Arc::new(resolver),
            _relays: proxies,
        });
        names.warm_soon();
        Ok(names)
    }

    /// The network moved: what was "unreachable" may answer now, and vice
    /// versa. Pins are untouched.
    pub fn network_changed(&self) {
        self.resolver.flush_caches();
    }

    /// Start the mesh path to the pinned servers (`Resolver::warm`) soon
    /// after the resolver starts — a connect or a node restart — so the
    /// first lookup finds it up: on a Pixel 9 Pro, discovery of a server
    /// three hops away took 14 s after a connect, past the lookup budget,
    /// and the app got the public address. Twice, at `WARM_AT`: a
    /// discovery started before the first peers' filters arrive fails on
    /// the spot ("no tree peers with bloom match", a second after a start),
    /// and on a slow link the first may come too early.
    ///
    /// Not on a network change: the node, its links and its sessions
    /// survive one (netmon re-pins them, a new tunnel swaps the pump's fd),
    /// so the path is already up, and a hand-over's burst of hints would
    /// each send a round of echoes to every pinned server over a waking
    /// radio.
    fn warm_soon(&self) {
        let Some(rt) = self.rt.as_ref() else {
            return;
        };
        let resolver = self.resolver.clone();
        rt.spawn(async move {
            let mut waited = Duration::ZERO;
            for at in WARM_AT {
                tokio::time::sleep(at - waited).await;
                waited = at;
                resolver.warm().await;
            }
        });
    }

    /// What the VpnService knows and the resolver cannot: whether a
    /// validated Internet network exists. Without one the TXT lookup gets
    /// a short wait, so a first offline lookup fails into the mesh path
    /// within the budget instead of resolving only on the retry. The
    /// lookup is shortened, not skipped: a network that works but was never
    /// validated (a captive-portal probe blocked) must still verify online,
    /// and the resolver keeps believing it is online, so its relay scope
    /// stays mesh-only without a TXT hit — no public relay learns a domain.
    /// It also decides whether a domain with no pin is probed plainly first
    /// ([`PhoneTxt`]).
    pub fn set_internet_validated(&self, validated: bool) {
        let want = if validated {
            TXT_TIMEOUT_ONLINE
        } else {
            TXT_TIMEOUT_UNVALIDATED
        };
        if self.resolver.txt().0.timeout() == want {
            return;
        }
        tracing::info!(
            validated,
            txt_timeout_ms = want.as_millis(),
            "public names: internet validation changed"
        );
        if let Err(e) = self.resolver.txt().0.set_timeout(want) {
            tracing::warn!(error = %e, "could not change the TXT verifier's timeout");
            return;
        }
        self.resolver.flush_caches();
    }
}

/// When after the names resolver starts the pinned servers are warmed
/// ([`Names::warm_soon`]).
const WARM_AT: [Duration; 2] = [Duration::from_secs(3), Duration::from_secs(10)];

/// The library's TXT wait while a validated Internet network exists.
const TXT_TIMEOUT_ONLINE: Duration = Duration::from_millis(1500);
/// Without one: long enough for a LAN resolver that answers, short enough
/// that a first offline lookup — this, the mesh relay, step 3, the echo —
/// fits the 3.5 s budget.
const TXT_TIMEOUT_UNVALIDATED: Duration = Duration::from_millis(500);

/// The library's TXT source, with its plain probe (fips-pub-domains 0.2.4:
/// a domain with no pin is asked for its record without validation first,
/// and "no record" ends the lookup) used only while a validated Internet
/// network exists. Without one the resolvers that still answer are a
/// router with no uplink or a captive portal, and their plain "no record"
/// would end in the legacy answer where the validated lookup fails and
/// sends the resolver to the mesh relays — the offline path this app
/// exists for. It would also make an offline lookup wait twice, once for
/// the probe and once for the lookup, which the budget has no room for.
struct PhoneTxt(MaybeTxt);

impl PhoneTxt {
    fn probes(&self) -> bool {
        self.0.timeout() > TXT_TIMEOUT_UNVALIDATED
    }
}

// Every method forwarded: a wrapper that forwards `lookup` alone loses the
// library's early release without a compiler word about it.
impl TxtSource for PhoneTxt {
    async fn lookup(&self, domain: &str) -> (pubdom_core::policy::TxtLookup, Option<u32>) {
        self.0.lookup(domain).await
    }

    async fn lookup_with(
        &self,
        domain: &str,
        first_denial: &(dyn Fn() + Sync),
    ) -> (pubdom_core::policy::TxtLookup, Option<u32>) {
        self.0.lookup_with(domain, first_denial).await
    }

    async fn probe(&self, domain: &str, first_denial: &(dyn Fn() + Sync)) -> Probe {
        if self.probes() {
            self.0.probe(domain, first_denial).await
        } else {
            Probe::Unknown
        }
    }
}

impl Lookup for Names {
    fn lookup(&self, query: &[u8], pending: &dyn Fn()) -> Outcome {
        let Some(rt) = self.rt.as_ref() else {
            return Outcome::Legacy;
        };
        let mut fut = Box::pin({
            let (resolver, q) = (self.resolver.clone(), query.to_vec());
            async move { resolver.lookup(&q).await }
        });
        // One poll first: a cached decision, a name that is no hostname or
        // a record type never over fips settle here, with no task and no
        // upstream asked ahead of them.
        if let Ok(result) =
            rt.block_on(async { tokio::time::timeout(Duration::ZERO, &mut fut).await })
        {
            return settled(result);
        }
        if self.resolver.txt().probes() && !self.resolver.has_pin_for(query) {
            pending();
        }
        // Spawned, not awaited in place: when the budget runs out the app
        // gets the legacy answer (short-lived, see `Outcome::Capped`), but
        // the lookup carries on and caches its decision — so the query the
        // resolver makes after that is answered at once. Cancelling it
        // instead meant a slow path (offline: TXT timeout, then a mesh
        // relay) never finished, however often it was asked.
        let mut task = rt.spawn(fut);
        let outcome = rt.block_on(async {
            tokio::select! {
                biased;
                joined = tokio::time::timeout(BUDGET, &mut task) => Some(joined),
                // One upstream's "no record" for every candidate domain
                // (only with the plain probe, so only with a validated
                // Internet — `PhoneTxt`): do not hold the legacy answer
                // back for the other upstreams.
                _ = self.resolver.denied_by_an_upstream(query), if self.resolver.txt().probes() => None,
            }
        });
        match outcome {
            Some(Ok(Ok(result))) => settled(result),
            Some(Ok(Err(e))) => {
                tracing::warn!(error = %e, "public-name lookup failed; using the legacy answer");
                Outcome::Legacy
            }
            Some(Err(_)) => {
                tracing::info!(
                    "public-name lookup still running after its budget; using the legacy answer briefly"
                );
                Outcome::Capped(pubdom_core::OVERRUN_TTL_SECS)
            }
            None => {
                let handle = rt.handle().clone();
                let mut task = Some(task);
                Outcome::Early(Box::new(move |wait| {
                    let running = task.as_mut()?;
                    let joined = handle
                        .block_on(async { tokio::time::timeout(wait, running).await })
                        .ok()?;
                    task = None;
                    Some(match joined {
                        Ok(result) => decided(result),
                        Err(e) => {
                            tracing::warn!(error = %e, "public-name lookup failed; using the legacy answer");
                            Decided::Legacy
                        }
                    })
                }))
            }
        }
    }
}

impl Drop for Names {
    fn drop(&mut self) {
        // Never wait for stragglers in the blocking pool (see the node
        // thread's shutdown_timeout in engine.rs for why).
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// The mesh transport: `meshudp` for step 3, the responder for registration.
struct PhoneMesh {
    link: Arc<MeshLink>,
}

impl MeshDns for PhoneMesh {
    fn query_udp(
        &self,
        server: SocketAddrV6,
        msg: &[u8],
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        crate::meshudp::query(&self.link, *server.ip(), server.port(), msg, timeout)
            .map_err(|e| std::io::Error::other(e.message))
    }

    fn query_tcp(&self, _: SocketAddrV6, _: &[u8], _: Duration) -> std::io::Result<Vec<u8>> {
        // A step 3 answer is one CNAME; nothing truncates it. The TCP
        // fallback rides on meshhttp's stack in a later milestone.
        Err(std::io::Error::other(
            "TCP fallback not available on the phone",
        ))
    }

    fn reachable(&self, npub: Npub, timeout: Duration) -> bool {
        crate::meshudp::ping(&self.link, npub.fips_address(), timeout).unwrap_or(false)
    }

    fn register(&self, npub: Npub, timeout: Duration) -> bool {
        // Same exchange as meshhttp::register_identity, but the outcome
        // matters here: it doubles as the reachability signal (spec §7).
        let Ok(socket) = UdpSocket::bind(if self.link.responder.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        }) else {
            return false;
        };
        let _ = socket.set_read_timeout(Some(timeout));
        let id = (crate::meshhttp::random_u64() & 0xffff) as u16;
        let query = crate::meshhttp::aaaa_query(id, &npub.fips_name());
        if socket.send_to(&query, self.link.responder).is_err() {
            return false;
        }
        let mut buf = [0u8; 512];
        match socket.recv(&mut buf) {
            Ok(n) if n >= 12 && buf[..2] == id.to_be_bytes() => buf[3] & 0x0f == 0,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain probe runs only with a validated Internet: without one a
    /// plain "no record" from whatever still answers must not end the
    /// lookup before the mesh path.
    #[test]
    fn the_plain_probe_needs_a_validated_internet() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let txt = PhoneTxt(MaybeTxt::new(&[], true, TXT_TIMEOUT_UNVALIDATED).unwrap());
        assert_eq!(
            rt.block_on(txt.probe("example.org", &|| {})),
            Probe::Unknown
        );
        // Validated: the library's probe answers (no upstreams here, so
        // "unreachable" — the point is that it was asked).
        txt.0.set_timeout(TXT_TIMEOUT_ONLINE).unwrap();
        assert_eq!(
            rt.block_on(txt.probe("example.org", &|| {})),
            Probe::Unreachable
        );
    }
}
