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
    /// Nostr relays discovered on the local network (the app browses DNS-SD
    /// for `_nostr._tcp`), appended to the ADVERT relay set on top of
    /// whatever it is (fips built-in defaults or [`Self::nostr_relays`]).
    /// Deliberately not the DM set: fips publishes `dm_relays` under the
    /// node's npub as its public inbox-relay list (kind 10050) and fans every
    /// traversal signal to them, and a URL taken off an untrusted LAN must
    /// neither end up in the identity's published record nor receive its
    /// signaling. Adverts are public, self-signed documents, so a LAN relay
    /// carrying them costs nothing. Each must be a `ws://`/`wss://` URL: a
    /// malformed entry is dropped here with a warning instead of passed on,
    /// because a failing `add_relay` aborts fips's whole Nostr runtime at
    /// start. Deduplicated on `RelayUrl` equality and capped at
    /// [`MAX_EXTRA_RELAYS`].
    #[serde(default)]
    pub extra_nostr_relays: Vec<String>,
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
    /// the main transport (fips sets SO_REUSEADDR/SO_REUSEPORT before bind,
    /// and Linux delivers unicast to the most-specific bound socket), so the
    /// single mDNS-advertised port works on every interface, and forces LAN
    /// mDNS on. The Kotlin side sets this while the hotspot network is up and
    /// `Network.bindSocket`s the matching fd in `protectFd`. Ignored (with a
    /// warning) in `fips_yaml` advanced mode — declare the instance in the
    /// YAML instead.
    #[serde(default)]
    pub hotspot: Option<HotspotConfig>,
    /// Advanced: a full `fips.yaml`. When non-empty it becomes the base
    /// `fips::Config` (all fips parameters — transports, node.*, rendezvous,
    /// dns, lookup, …); the shim then forces the non-negotiable Android bits
    /// (Keystore identity, app-owned TUN, control socket off) and layers on the
    /// runtime knobs it owns. When empty, the structured fields above build the
    /// config programmatically.
    #[serde(default)]
    pub fips_yaml: Option<String>,
}

/// Upper bound on LAN-discovered relays passed to the node. A relay pool
/// entry costs a websocket plus reconnect timers; a LAN has no business
/// offering more than a handful, and a runaway advertiser must not be able
/// to balloon the pool.
pub const MAX_EXTRA_RELAYS: usize = 8;

/// Resolve the main and hotspot bind addresses to a shared concrete port.
///
/// The main transport keeps its configured host; the hotspot instance binds
/// the interface address on the SAME port so the single mDNS-advertised port
/// is valid on every interface. When the configured port is 0 (the default
/// pure-client posture), a throwaway wildcard bind picks a free port — the
/// tiny claim/rebind race is harmless because fips sets SO_REUSEADDR before
/// its own bind. Returns `(main_bind, hotspot_bind, dial_prefix)`.
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
            config
                .validate()
                .map_err(|e| format!("config validate: {e}"))?;
            return Ok(config);
        }

        let mut config = fips::Config::new();
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
                        ..Default::default()
                    },
                );
                map.insert(
                    "hotspot".to_string(),
                    fips::config::UdpConfig {
                        bind_addr: Some(hotspot_bind),
                        dial_prefixes: Some(vec![dial_prefix]),
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
            let own_addr: std::net::IpAddr = derive_identity(&self.nsec)?
                .address
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
        if self.enable_nostr {
            let advert = &mut config.node.rendezvous.nostr.advert_relays;
            let base: Vec<nostr::RelayUrl> = advert
                .iter()
                .filter_map(|r| nostr::RelayUrl::parse(r).ok())
                .collect();
            for url in self.extra_relay_urls() {
                if base.contains(&url) {
                    continue;
                }
                tracing::info!(relay = %url, "LAN-discovered Nostr relay added to advert relays");
                advert.push(url.to_string());
            }
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
            config.peers.push(fips::config::PeerConfig::new(
                peer.npub.clone(),
                peer.transport.clone(),
                peer.endpoint.clone(),
            ));
        }
        config
            .validate()
            .map_err(|e| format!("config validate: {e}"))?;
        Ok(config)
    }

    /// The [`Self::extra_nostr_relays`] that parse as relay URLs, rendered
    /// in `RelayUrl` form, deduplicated, in input order, at most
    /// [`MAX_EXTRA_RELAYS`]. Malformed entries are logged and skipped.
    pub fn valid_extra_relays(&self) -> Vec<String> {
        self.extra_relay_urls()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// [`Self::valid_extra_relays`] as parsed values. `RelayUrl` equality
    /// ignores a trailing slash (its `Display` keeps it), so dedup happens
    /// on the parsed value, never on the rendered string.
    fn extra_relay_urls(&self) -> Vec<nostr::RelayUrl> {
        let mut seen: Vec<nostr::RelayUrl> = Vec::new();
        for raw in &self.extra_nostr_relays {
            if seen.len() >= MAX_EXTRA_RELAYS {
                tracing::warn!(cap = MAX_EXTRA_RELAYS, "too many LAN relays; ignoring the rest");
                break;
            }
            match nostr::RelayUrl::parse(raw.trim()) {
                Ok(url) => {
                    if !seen.contains(&url) {
                        seen.push(url);
                    }
                }
                Err(e) => {
                    tracing::warn!(relay = %raw, error = %e, "ignoring malformed LAN relay URL");
                }
            }
        }
        seen
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

    /// LAN-discovered relays are appended to the ADVERT set only, on top of
    /// the fips defaults (never replacing them), normalized, deduplicated
    /// (including against a default given with a trailing slash), with
    /// malformed ones dropped rather than handed to fips. The DM set — the
    /// identity's published inbox list and the signaling fan-out — must not
    /// gain anything from the LAN.
    #[test]
    fn extra_relays_append_to_advert_defaults_only_and_drop_bad_ones() {
        let id = derive_identity("").unwrap();
        let json = format!(
            r#"{{ "nsec": "{}", "enable_nostr": true, "extra_nostr_relays": [
                "ws://192.168.1.20:7777", "ws://192.168.1.20:7777/",
                "http://not-a-relay", "garbage", "wss://relay.damus.io/",
                "ws://[fd12::5]:4848"
            ] }}"#,
            id.nsec
        );
        let shim = ShimConfig::from_json(&json).unwrap();
        assert_eq!(
            shim.valid_extra_relays(),
            ["ws://192.168.1.20:7777", "wss://relay.damus.io/", "ws://[fd12::5]:4848"]
        );
        let defaults = fips::Config::new().node.rendezvous.nostr;
        let config = shim.to_fips_config().unwrap();
        let nostr = &config.node.rendezvous.nostr;

        assert_eq!(nostr.dm_relays, defaults.dm_relays, "DM set untouched by the LAN");

        let advert = &nostr.advert_relays;
        assert_eq!(advert.len(), defaults.advert_relays.len() + 2, "{advert:?}");
        for d in &defaults.advert_relays {
            assert_eq!(advert.iter().filter(|r| *r == d).count(), 1, "default {d} kept once");
        }
        assert!(advert.contains(&"ws://192.168.1.20:7777".to_string()), "{advert:?}");
        assert!(advert.contains(&"ws://[fd12::5]:4848".to_string()), "{advert:?}");
        assert!(!advert.iter().any(|r| r.contains("not-a-relay") || r == "garbage"));
    }

    #[test]
    fn extra_relays_are_capped() {
        let relays: Vec<String> = (0..20).map(|i| format!("ws://10.0.0.{i}:7777")).collect();
        let shim = ShimConfig {
            extra_nostr_relays: relays,
            ..ShimConfig::from_json(r#"{"nsec": ""}"#).unwrap()
        };
        assert_eq!(shim.valid_extra_relays().len(), MAX_EXTRA_RELAYS);
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
