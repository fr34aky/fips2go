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
    /// tracing filter, e.g. "info" or "fips=debug".
    #[serde(default)]
    pub log_level: Option<String>,
    /// Advanced: a full `fips.yaml`. When non-empty it becomes the base
    /// `fips::Config` (all fips parameters — transports, node.*, rendezvous,
    /// dns, lookup, …); the shim then forces the non-negotiable Android bits
    /// (Keystore identity, app-owned TUN, control socket off) and layers on the
    /// runtime knobs it owns. When empty, the structured fields above build the
    /// config programmatically.
    #[serde(default)]
    pub fips_yaml: Option<String>,
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
            config
                .validate()
                .map_err(|e| format!("config validate: {e}"))?;
            return Ok(config);
        }

        let mut config = fips::Config::new();
        config.node.identity.nsec = Some(identity.nsec);
        config.transports.udp = fips::config::TransportInstances::Single(fips::config::UdpConfig {
            bind_addr: Some("0.0.0.0:0".to_string()),
            ..Default::default()
        });
        config.tun.enabled = true; // satisfied by the app-owned seam
        config.dns.enabled = self.enable_fips_dns; // in-process responder, [::1]:5354
        config.node.control.enabled = false;
        config.node.rendezvous.nostr.enabled = self.enable_nostr;
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
    }

    #[test]
    fn worker_threads_override_parses() {
        let shim = ShimConfig::from_json(r#"{"nsec": "", "worker_threads": 3}"#).unwrap();
        assert_eq!(shim.worker_threads, 3);
    }
}
