//! Shim configuration (JSON from Kotlin) → in-memory `fips::Config`.

use serde::{Deserialize, Serialize};

/// Configuration the Kotlin side sends to `start()` as JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct ShimConfig {
    /// Node identity secret (nsec bech32 or hex). Obtain via
    /// [`derive_identity`] and persist on the Kotlin side.
    pub nsec: String,
    /// Static peers to connect to on start.
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
    /// Upstream resolvers for non-`.fips` DNS (host:port). All device DNS is
    /// routed to us while the VPN is up, so these carry the normal traffic.
    #[serde(default = "default_dns_upstreams")]
    pub dns_upstreams: Vec<String>,
    /// Enable Nostr rendezvous (relay discovery + NAT traversal).
    #[serde(default)]
    pub enable_nostr: bool,
    /// Open peer discovery over Nostr (fips `policy: open`): dial nodes that
    /// advertise in the app namespace, not only configured ones. Off by
    /// default. fips's own bounds are server-sized (a queue of 64, links up
    /// to `max_peers` = 128), so the shim ceilings the overlay pool at
    /// [`Self::nostr_discovery_max_peers`] — every link is a heartbeat every
    /// 20 s on a phone. Needs `enable_nostr`.
    #[serde(default)]
    pub nostr_discovery: bool,
    /// Ceiling on peers found by open discovery (queued, connecting or
    /// connected), see [`Self::nostr_discovery`]. `0` falls back to the
    /// default rather than "unlimited".
    #[serde(default = "default_nostr_discovery_max_peers")]
    pub nostr_discovery_max_peers: usize,
    /// Run the in-process FIPS DNS responder on `[::1]:5354` (the `.fips`
    /// half of the DNS proxy). On by default; the host test suite turns it
    /// off to avoid colliding with a daemon on the same machine.
    #[serde(default = "default_true")]
    pub enable_fips_dns: bool,
    /// Cap for the FMP encrypt/decrypt worker thread pools. Unset lets FIPS
    /// default to `available_parallelism()` (8+8 on a Pixel 9 Pro — far more
    /// than a phone needs and a needless battery/wakeup cost). The shim caps
    /// both pools to this before the node starts; `0` gives one encrypt worker
    /// and in-line decrypt on the rx_loop (fewest threads).
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    /// Forward non-mesh (clearnet) traffic through the userspace stack so
    /// captured apps keep normal internet (the split-tunnel forwarder). On by
    /// default; the host tests disable it (no clearnet to forward).
    #[serde(default = "default_true")]
    pub forward_clearnet: bool,
    /// Relax node timers for mobile to cut CPU/radio wakeups: maintenance tick
    /// 1→5s, link heartbeat 10→20s, link-dead 30→60s. Heartbeat stays under
    /// the ~30s aggressive-NAT UDP timeout so mappings don't expire. On by
    /// default; pair with a battery-optimization exemption so Doze doesn't
    /// kill the service.
    #[serde(default = "default_true")]
    pub battery_saver: bool,
    /// mDNS LAN peer discovery. Off by default: the required MulticastLock
    /// disables the Wi-Fi chip's hardware multicast filtering, so every LAN
    /// multicast frame (Chromecast, SSDP, …) then wakes the CPU — a real
    /// battery cost on chatty networks. The Kotlin side only holds the lock
    /// while this is enabled AND the underlying network is Wi-Fi.
    #[serde(default)]
    pub enable_lan_mdns: bool,
    /// tracing filter, e.g. "info" or "fips=debug".
    #[serde(default)]
    pub log_level: Option<String>,
    /// Nostr relays (used for both advert and DM relays) when `enable_nostr`
    /// is set. Empty → FIPS built-in defaults.
    #[serde(default)]
    pub nostr_relays: Vec<String>,
    /// STUN servers for NAT traversal. Empty → FIPS built-in defaults.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// UDP transport bind address (e.g. "0.0.0.0:2121"). Empty → ephemeral
    /// "0.0.0.0:0" (pure-client, no fixed inbound port).
    #[serde(default)]
    pub udp_bind: Option<String>,
    /// TCP transport bind address (e.g. "0.0.0.0:8443"). Empty → no TCP
    /// transport.
    #[serde(default)]
    pub tcp_bind: Option<String>,
    /// Stateful inbound firewall on the mesh→app TUN path (see
    /// `filter.rs`). Default ON: new inbound flows are denied unless their
    /// destination port is in [`Self::inbound_ports`]; replies to
    /// outbound-initiated flows and ICMPv6 always pass. fips itself needs no
    /// inbound TUN ports (the mesh protocol rides the UDP underlay), so the
    /// default allowlist is empty.
    #[serde(default = "default_true")]
    pub inbound_filter: bool,
    /// TCP/UDP destination ports open to unsolicited inbound mesh traffic.
    #[serde(default)]
    pub inbound_ports: Vec<u16>,
    /// FIPS Hotspot: the device joined a local-only secondary Wi-Fi network
    /// (SSID "!FIPS") and this is our interface address on it. Adds a second,
    /// dial-scoped UDP transport bound to that address on the SAME port as
    /// the main transport (both instances set `share_port`, which is what makes
    /// fips put SO_REUSEPORT/SO_REUSEADDR on BEFORE bind — by default it sets
    /// them after, and the second instance then fails with EADDRINUSE; Linux
    /// delivers unicast to the most-specific bound socket), so the
    /// single mDNS-advertised port works on every interface, and forces LAN
    /// mDNS on. The Kotlin side sets this while the hotspot network is up and
    /// `Network.bindSocket`s the matching fd in `protectFd`. Ignored (with a
    /// warning) in `fips_yaml` advanced mode — declare the instance in the
    /// YAML instead.
    #[serde(default)]
    pub hotspot: Option<HotspotConfig>,
    /// App-owned hosts file mapping readable names to npubs (`home npub1…`,
    /// one per line — the format of fips's `/etc/fips/hosts`), so covered
    /// apps can use `home.fips`. fips only reads its hardcoded system path,
    /// which an Android app cannot write, so the DNS proxy resolves these
    /// names itself (see `dns.rs`). The file is re-read when its mtime
    /// changes: an edit takes effect on the next query, no node restart.
    #[serde(default)]
    pub hosts_path: Option<String>,
    /// Advanced: a full `fips.yaml`. When non-empty it becomes the base
    /// `fips::Config` (all fips parameters — transports, node.*, rendezvous,
    /// dns, lookup, …); the shim then forces the non-negotiable Android bits
    /// (Keystore identity, app-owned TUN, control socket off) and layers on the
    /// runtime knobs it owns. When empty, the structured fields above build the
    /// config programmatically.
    #[serde(default)]
    pub fips_yaml: Option<String>,
}

/// Resolve the main and hotspot bind addresses to a shared concrete port.
///
/// The main transport keeps its configured host; the hotspot instance binds
/// the interface address on the SAME port so the single mDNS-advertised port
/// is valid on every interface. When the configured port is 0 (the default
/// pure-client posture), a throwaway wildcard bind picks a free port. The
/// probe socket is dropped before fips binds, so there is a tiny window in
/// which another process could take the port; fips would then fail to start
/// that instance loudly. Returns `(main_bind, hotspot_bind, dial_prefix)`.
fn hotspot_binds(
    udp_bind: &str,
    hs: &HotspotConfig,
) -> Result<(String, String, String), String> {
    let addr: std::net::IpAddr = hs
        .addr
        .trim()
        .parse()
        .map_err(|e| format!("bad hotspot addr {:?}: {e}", hs.addr))?;
    let max_len: u8 = if addr.is_ipv4() { 32 } else { 128 };
    if hs.prefix_len > max_len {
        return Err(format!("bad hotspot prefix_len {}", hs.prefix_len));
    }
    let main: std::net::SocketAddr = udp_bind
        .parse()
        .map_err(|e| format!("bad udp_bind {udp_bind:?}: {e}"))?;
    let port = if main.port() != 0 {
        main.port()
    } else {
        std::net::UdpSocket::bind((main.ip(), 0))
            .and_then(|s| s.local_addr())
            .map(|a| a.port())
            .map_err(|e| format!("port probe: {e}"))?
    };
    let hotspot_bind = std::net::SocketAddr::new(addr, port).to_string();
    let main_bind = std::net::SocketAddr::new(main.ip(), port).to_string();
    let dial_prefix = format!("{}/{}", addr, hs.prefix_len);
    Ok((main_bind, hotspot_bind, dial_prefix))
}

/// Interface address on the joined FIPS Hotspot network (see
/// [`ShimConfig::hotspot`]).
#[derive(Debug, Clone, Deserialize)]
pub struct HotspotConfig {
    /// Our address on the hotspot link, e.g. "192.168.49.23".
    pub addr: String,
    /// On-link prefix length from `LinkProperties`, e.g. 24.
    pub prefix_len: u8,
}

/// Resolve an npub to its `.fips` mesh address (pure computation). Returns
/// `(npub, address)`.
pub fn resolve_npub(npub: &str) -> Result<(String, String), String> {
    let peer = fips::identity::PeerIdentity::from_npub(npub.trim())
        .map_err(|e| format!("invalid npub: {e}"))?;
    Ok((peer.npub(), peer.address().to_ipv6().to_string()))
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerEntry {
    /// Peer identity (npub bech32 or hex).
    pub npub: String,
    /// Transport endpoint, e.g. "203.0.113.7:21200".
    pub endpoint: String,
    /// Transport kind: "udp" (default) or "tcp".
    #[serde(default = "default_transport")]
    pub transport: String,
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_true() -> bool {
    true
}

/// Mobile default: one encrypt worker + one decrypt worker (2 threads vs the
/// ~16 `available_parallelism()` would spawn). Plenty for phone-scale mesh
/// traffic and much lighter on battery.
fn default_worker_threads() -> usize {
    1
}

/// Three open-discovery links on top of the configured bootstraps: enough
/// that the mesh is reachable when every bootstrap is down, small enough
/// that the heartbeats do not show on the battery graph.
fn default_nostr_discovery_max_peers() -> usize {
    3
}

fn default_dns_upstreams() -> Vec<String> {
    vec!["1.1.1.1:53".to_string(), "9.9.9.9:53".to_string()]
}

/// Identity triple handed to Kotlin (it persists `nsec`, shows `npub`, and
/// uses `address` for `VpnService.Builder.addAddress`/`addDnsServer`).
#[derive(Debug, Serialize)]
pub struct IdentityInfo {
    pub nsec: String,
    pub npub: String,
    pub address: String,
}

/// Derive (or generate, when `nsec` is empty) the node identity.
pub fn derive_identity(nsec: &str) -> Result<IdentityInfo, String> {
    let identity = if nsec.trim().is_empty() {
        fips::Identity::generate()
    } else {
        fips::Identity::from_secret_str(nsec.trim()).map_err(|e| format!("invalid nsec: {e}"))?
    };
    Ok(IdentityInfo {
        nsec: fips::identity::encode_nsec(&identity.keypair().secret_key()),
        npub: identity.npub(),
        address: identity.address().to_ipv6().to_string(),
    })
}

impl ShimConfig {
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("config parse: {e}"))
    }

    /// Build the in-memory `fips::Config` the same way `fips.yaml` would:
    /// one wildcard-ephemeral UDP transport, in-process DNS responder on
    /// `[::1]:5354`, app-owned TUN, no control socket, no key files.
    pub fn to_fips_config(&self) -> Result<fips::Config, String> {
        let identity = derive_identity(&self.nsec)?;

        // Advanced mode: a full fips.yaml is the base; only force the Android
        // non-negotiables on top (structured fips fields are not applied).
        if let Some(yaml) = self
            .fips_yaml
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let mut config: fips::Config =
                serde_yaml::from_str(yaml).map_err(|e| format!("fips.yaml parse: {e}"))?;
            config.node.identity.nsec = Some(identity.nsec); // Keystore, not YAML
            config.tun.enabled = true; // app-owned seam
            config.node.control.enabled = false; // no unix control socket
            if config.transports.udp.is_empty() {
                config.transports.udp =
                    fips::config::TransportInstances::Single(fips::config::UdpConfig {
                        bind_addr: Some("0.0.0.0:0".to_string()),
                        ..Default::default()
                    });
            }
            if self.hotspot.is_some() {
                tracing::warn!(
                    "hotspot overlay is ignored in fips_yaml mode — declare a dial-scoped \
                     UDP instance in the YAML instead"
                );
            }
            if self.nostr_discovery {
                tracing::warn!(
                    "nostr_discovery is ignored in fips_yaml mode — set \
                     node.rendezvous.nostr.policy: open in the YAML instead"
                );
            }
            config
                .validate()
                .map_err(|e| format!("config validate: {e}"))?;
            return Ok(config);
        }

        let mut config = fips::Config::new();
        let own_address = identity.address;
        config.node.identity.nsec = Some(identity.nsec);
        let udp_bind = self
            .udp_bind
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "0.0.0.0:0".to_string());
        config.transports.udp = match &self.hotspot {
            None => fips::config::TransportInstances::Single(fips::config::UdpConfig {
                bind_addr: Some(udp_bind),
                ..Default::default()
            }),
            Some(hs) => {
                let (main_bind, hotspot_bind, dial_prefix) =
                    hotspot_binds(&udp_bind, hs).map_err(|e| format!("hotspot config: {e}"))?;
                tracing::info!(
                    main = %main_bind,
                    hotspot = %hotspot_bind,
                    prefix = %dial_prefix,
                    "FIPS Hotspot: second dial-scoped UDP transport"
                );
                let mut map = std::collections::HashMap::new();
                map.insert(
                    "main".to_string(),
                    fips::config::UdpConfig {
                        bind_addr: Some(main_bind),
                        // BOTH instances: whichever binds second is the one
                        // that needs the flags before its bind, and the start
                        // order is fips's business, not ours.
                        share_port: Some(true),
                        ..Default::default()
                    },
                );
                map.insert(
                    "hotspot".to_string(),
                    fips::config::UdpConfig {
                        bind_addr: Some(hotspot_bind),
                        dial_prefixes: Some(vec![dial_prefix]),
                        share_port: Some(true),
                        ..Default::default()
                    },
                );
                fips::config::TransportInstances::Named(map)
            }
        };
        if let Some(tcp) = self.tcp_bind.clone().filter(|s| !s.trim().is_empty()) {
            config.transports.tcp =
                fips::config::TransportInstances::Single(fips::config::TcpConfig {
                    bind_addr: Some(tcp),
                    ..Default::default()
                });
        }
        config.tun.enabled = true; // satisfied by the app-owned seam
        config.dns.enabled = self.enable_fips_dns; // in-process responder, [::1]:5354
        config.node.control.enabled = false;
        config.node.rendezvous.nostr.enabled = self.enable_nostr;
        if self.nostr_discovery && !self.enable_nostr {
            tracing::warn!("nostr_discovery needs enable_nostr; ignored");
        }
        if self.enable_nostr && self.nostr_discovery {
            let cap = match self.nostr_discovery_max_peers {
                0 => default_nostr_discovery_max_peers(),
                n => n,
            };
            let nostr = &mut config.node.rendezvous.nostr;
            nostr.policy = fips::config::NostrRendezvousPolicy::Open;
            // Both bounds: the queue can never hold more than the pool may
            // grow by, and the pool itself is ceilinged (fips fork knob).
            nostr.open_discovery_max_pending = cap;
            nostr.open_discovery_max_peers = cap;
            tracing::info!(max_peers = cap, "Nostr open peer discovery enabled");
        }
        // Joining a FIPS Hotspot without LAN discovery would be pointless, so
        // the hotspot overlay forces mDNS on for the duration of the join
        // (the Kotlin side holds the MulticastLock accordingly).
        let lan_mdns = self.enable_lan_mdns || self.hotspot.is_some();
        config.node.rendezvous.lan.enabled = lan_mdns;
        if lan_mdns {
            // Keep the tunnel's own addresses out of the mDNS adverts:
            // the node's mesh ULA is an identity disclosure on the LAN, and
            // the clearnet-source IPv4 (TUN_IPV4 in FipsVpnService.kt — keep
            // in sync) is unreachable from other hosts anyway.
            let own_addr: std::net::IpAddr = own_address
                .parse()
                .map_err(|e| format!("own address unparseable: {e}"))?;
            config.node.rendezvous.lan.exclude_addrs =
                vec![own_addr, "10.111.222.1".parse().unwrap()];
            tracing::info!("LAN mDNS discovery enabled (tunnel addrs excluded)");
        }
        if !self.nostr_relays.is_empty() {
            config.node.rendezvous.nostr.advert_relays = self.nostr_relays.clone();
            config.node.rendezvous.nostr.dm_relays = self.nostr_relays.clone();
        }
        if !self.stun_servers.is_empty() {
            config.node.rendezvous.nostr.stun_servers = self.stun_servers.clone();
        }
        if self.battery_saver {
            // Fewer CPU/radio wakeups on mobile; heartbeat stays < the ~30s
            // aggressive-NAT UDP timeout so mappings don't expire.
            config.node.tick_interval_secs = 5;
            config.node.heartbeat_interval_secs = 20;
            config.node.link_dead_timeout_secs = 60;
            tracing::info!(
                tick_secs = config.node.tick_interval_secs,
                heartbeat_secs = config.node.heartbeat_interval_secs,
                link_dead_secs = config.node.link_dead_timeout_secs,
                "battery saver: relaxed node timers",
            );
        }
        for peer in &self.peers {
            let mut peer_config = fips::config::PeerConfig::new(
                peer.npub.clone(),
                peer.transport.clone(),
                peer.endpoint.clone(),
            );
            // The static address is still dialed first; the peer's Nostr
            // advert is appended as a fallback, so a bootstrap that moves to
            // a new IP or port is found again without a config change. fips
            // rejects `via_nostr` on a peer while Nostr is off, hence the tie.
            peer_config.via_nostr = self.enable_nostr;
            config.peers.push(peer_config);
        }
        config
            .validate()
            .map_err(|e| format!("config validate: {e}"))?;
        Ok(config)
    }

    /// Parsed upstream resolver addresses (invalid entries dropped with a log).
    pub fn upstream_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.dns_upstreams
            .iter()
            .filter_map(|s| match s.parse() {
                Ok(addr) => Some(addr),
                Err(_) => {
                    tracing::warn!(upstream = %s, "ignoring unparseable DNS upstream");
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip() {
        let generated = derive_identity("").unwrap();
        let rederived = derive_identity(&generated.nsec).unwrap();
        assert_eq!(generated.npub, rederived.npub);
        assert_eq!(generated.address, rederived.address);
        assert!(generated.address.starts_with("fd"), "fips fd::/8 address");
    }

    /// Every configured peer follows its Nostr advert as a fallback once
    /// Nostr is on — and never while it is off, which fips's validation
    /// would reject.
    #[test]
    fn peers_follow_their_nostr_advert_when_nostr_is_on() {
        let nsec = derive_identity("").unwrap().nsec;
        let peer = derive_identity("").unwrap().npub;
        for (nostr, expect) in [(true, true), (false, false)] {
            let json = format!(
                r#"{{"nsec": "{nsec}", "enable_nostr": {nostr}, "enable_fips_dns": false,
                     "peers": [{{"npub": "{peer}", "endpoint": "boot.example:2121"}}]}}"#
            );
            let config = ShimConfig::from_json(&json)
                .unwrap()
                .to_fips_config()
                .unwrap();
            assert_eq!(config.peers.len(), 1);
            assert_eq!(config.peers[0].via_nostr, expect, "enable_nostr={nostr}");
        }
    }

    /// The discovery toggle flips fips to `policy: open` with BOTH bounds
    /// set to the phone-sized cap; off (the default) leaves fips's
    /// `configured_only` policy and its server-sized bounds untouched.
    #[test]
    fn nostr_discovery_toggle_sets_open_policy_with_a_capped_pool() {
        use fips::config::NostrRendezvousPolicy;
        let nsec = derive_identity("").unwrap().nsec;
        let build = |nostr: bool, extra: &str| {
            let json = format!(
                r#"{{"nsec": "{nsec}", "enable_nostr": {nostr}, "enable_fips_dns": false{extra}}}"#
            );
            let config = ShimConfig::from_json(&json)
                .unwrap()
                .to_fips_config()
                .unwrap();
            config.node.rendezvous.nostr
        };
        let off = build(true, "");
        assert_eq!(off.policy, NostrRendezvousPolicy::ConfiguredOnly);
        assert_eq!(off.open_discovery_max_peers, 0);
        let server_sized =
            fips::config::NostrRendezvousConfig::default().open_discovery_max_pending;
        assert_eq!(
            off.open_discovery_max_pending, server_sized,
            "fips's own queue bound kept"
        );

        let on = build(true, r#", "nostr_discovery": true"#);
        assert_eq!(on.policy, NostrRendezvousPolicy::Open);
        assert_eq!(on.open_discovery_max_peers, 3);
        assert_eq!(on.open_discovery_max_pending, 3);

        let five = build(
            true,
            r#", "nostr_discovery": true, "nostr_discovery_max_peers": 5"#,
        );
        assert_eq!(five.open_discovery_max_peers, 5);
        let zero = build(
            true,
            r#", "nostr_discovery": true, "nostr_discovery_max_peers": 0"#,
        );
        assert_eq!(zero.open_discovery_max_peers, 3, "0 is not unlimited");

        // Without Nostr there is nothing to discover through: inert.
        let no_nostr = build(false, r#", "nostr_discovery": true"#);
        assert_eq!(no_nostr.policy, NostrRendezvousPolicy::ConfiguredOnly);
        assert_eq!(no_nostr.open_discovery_max_peers, 0);
        assert_eq!(no_nostr.open_discovery_max_pending, server_sized);
    }

    #[test]
    fn config_builds_and_validates() {
        let json = r#"{
            "nsec": "",
            "peers": [{"npub": "", "endpoint": "192.0.2.1:21200"}],
            "enable_nostr": false
        }"#;
        // Empty npub is invalid — validate must reject it.
        let shim = {
            let mut c = ShimConfig::from_json(json).unwrap();
            let id = derive_identity("").unwrap();
            c.nsec = id.nsec.clone();
            c.peers[0].npub = derive_identity("").unwrap().npub;
            c
        };
        let config = shim.to_fips_config().unwrap();
        assert!(config.dns.enabled);
        assert!(!config.node.control.enabled);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(shim.upstream_addrs().len(), 2, "default upstreams parse");
        assert_eq!(shim.worker_threads, 1, "mobile worker cap defaults to 1");
        assert!(!config.node.rendezvous.lan.enabled, "mDNS defaults off");
    }

    /// `enable_lan_mdns` flips the fips knob and excludes both tunnel
    /// addresses (the node's own mesh ULA and the clearnet-source IPv4)
    /// from the mDNS adverts.
    #[test]
    fn lan_mdns_knob_excludes_tunnel_addrs() {
        let id = derive_identity("").unwrap();
        let json = format!(r#"{{ "nsec": "{}", "enable_lan_mdns": true }}"#, id.nsec);
        let config = ShimConfig::from_json(&json)
            .unwrap()
            .to_fips_config()
            .unwrap();
        assert!(config.node.rendezvous.lan.enabled);
        let excl = &config.node.rendezvous.lan.exclude_addrs;
        assert_eq!(excl.len(), 2);
        assert!(excl.contains(&id.address.parse().unwrap()), "own mesh ULA");
        assert!(excl.contains(&"10.111.222.1".parse().unwrap()), "TUN_IPV4");
    }

    #[test]
    fn worker_threads_override_parses() {
        let shim = ShimConfig::from_json(r#"{"nsec": "", "worker_threads": 3}"#).unwrap();
        assert_eq!(shim.worker_threads, 3);
    }

    /// The hotspot overlay yields two named UDP instances sharing one
    /// concrete port — "main" on the configured wildcard host, "hotspot"
    /// dial-scoped to the link prefix — and forces LAN mDNS on.
    #[test]
    fn hotspot_overlay_builds_two_instances_on_shared_port() {
        let id = derive_identity("").unwrap();
        let json = format!(
            r#"{{ "nsec": "{}", "hotspot": {{ "addr": "192.168.49.23", "prefix_len": 24 }} }}"#,
            id.nsec
        );
        let config = ShimConfig::from_json(&json)
            .unwrap()
            .to_fips_config()
            .unwrap();

        let instances: std::collections::HashMap<_, _> = config
            .transports
            .udp
            .iter()
            .map(|(name, cfg)| (name.unwrap_or("").to_string(), cfg.clone()))
            .collect();
        assert_eq!(instances.len(), 2);

        let main: std::net::SocketAddr = instances["main"].bind_addr().parse().unwrap();
        let hotspot: std::net::SocketAddr = instances["hotspot"].bind_addr().parse().unwrap();
        assert!(main.ip().is_unspecified(), "main stays wildcard");
        assert_eq!(hotspot.ip(), "192.168.49.23".parse::<std::net::IpAddr>().unwrap());
        assert_ne!(main.port(), 0, "shared port must be concrete");
        assert_eq!(main.port(), hotspot.port(), "one mDNS-advertised port for all interfaces");

        assert_eq!(instances["hotspot"].dial_prefixes(), ["192.168.49.23/24"]);
        assert!(instances["main"].dial_prefixes().is_empty());
        // Without it on BOTH, the second bind fails with EADDRINUSE and the
        // node starts degraded (engine::tests has the end-to-end check).
        assert!(instances["main"].share_port(), "main must opt in to sharing");
        assert!(instances["hotspot"].share_port(), "hotspot must opt in to sharing");
        assert!(config.node.rendezvous.lan.enabled, "hotspot forces LAN mDNS");
    }

    /// An explicit udp_bind port is adopted verbatim by both instances.
    #[test]
    fn hotspot_overlay_respects_explicit_port() {
        let id = derive_identity("").unwrap();
        let json = format!(
            r#"{{ "nsec": "{}", "udp_bind": "0.0.0.0:21299",
                 "hotspot": {{ "addr": "10.20.30.40", "prefix_len": 16 }} }}"#,
            id.nsec
        );
        let config = ShimConfig::from_json(&json)
            .unwrap()
            .to_fips_config()
            .unwrap();
        for (_, cfg) in config.transports.udp.iter() {
            let addr: std::net::SocketAddr = cfg.bind_addr().parse().unwrap();
            assert_eq!(addr.port(), 21299);
        }
    }

    /// Malformed hotspot input errors out instead of silently dropping the
    /// second transport.
    #[test]
    fn hotspot_overlay_rejects_bad_addr() {
        let id = derive_identity("").unwrap();
        let json = format!(
            r#"{{ "nsec": "{}", "hotspot": {{ "addr": "not-an-ip", "prefix_len": 24 }} }}"#,
            id.nsec
        );
        let err = ShimConfig::from_json(&json)
            .unwrap()
            .to_fips_config()
            .unwrap_err();
        assert!(err.contains("hotspot"), "unexpected error: {err}");
    }
}
