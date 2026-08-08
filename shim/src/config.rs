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
    /// tracing filter, e.g. "info" or "fips=debug".
    #[serde(default)]
    pub log_level: Option<String>,
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
    }
}
