package org.fips.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Single source of truth for all app/config preferences and for turning them
 * into the shim's config JSON. Structured fields cover the common parameters;
 * the "advanced" raw `fips.yaml` (when set) gives access to every fips
 * parameter and supersedes the structured fips settings.
 */
object ConfigStore {
    const val PREFS = "fips"

    // Structured (common) keys.
    const val PEER_NPUB = "peer_npub"
    const val PEER_ENDPOINT = "peer_endpoint"
    const val PEER_TRANSPORT = "peer_transport"
    const val NOSTR = "nostr"
    const val NOSTR_RELAYS = "nostr_relays"
    const val STUN_SERVERS = "stun_servers"
    const val UDP_BIND = "udp_bind"
    const val TCP_BIND = "tcp_bind"
    const val DNS_UPSTREAMS = "dns_upstreams"
    const val ENABLE_FIPS_DNS = "enable_fips_dns"
    const val WORKER_THREADS = "worker_threads"
    const val FORWARD_CLEARNET = "forward_clearnet"
    const val BATTERY_SAVER = "battery_saver"
    const val LAN_MDNS = "enable_lan_mdns"
    const val HOTSPOT = "hotspot_enabled"
    const val LOG_LEVEL = "log_level"
    const val FIPS_YAML = "fips_yaml"

    fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Public test-mesh bootstrap servers, operated by the FIPS project as
     * new-user on-ramps (they accept inbound peering from arbitrary npubs).
     * Mirrors the project's /etc/fips/hosts; hostnames are publicly
     * resolvable under .fips.network, all on the default fips UDP port.
     */
    data class BootstrapPeer(val name: String, val npub: String) {
        val endpoint get() = "$name.fips.network:2121"
    }

    val BOOTSTRAP_PEERS = listOf(
        BootstrapPeer("test-us01", "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"),
        BootstrapPeer("test-us02", "npub10yffd020a4ag8zcy75f9pruq3rnghvvhd5hphl9s62zgp35s560qrksp9u"),
        BootstrapPeer("test-us03", "npub136yqae6na688fs75g95ppps3lxe07fvxefj77938zf47uhm6074sxw8ctm"),
        BootstrapPeer("test-us03-next", "npub15m6c4ghuegx4pcde6tra8f7smn8vfv2wundyxwhkjynuerkrzmgsy09sh3"),
        BootstrapPeer("test-us04", "npub1gd7ye2qp2lphhzx75fynnjzaxx4dqanddecet0wtt5ss5ek8h9ps62wdkf"),
        BootstrapPeer("test-de01", "npub1260n42s06vzc7796w0fh3ny7zcpw6tlk4gq3940gmfrzl5c9pv2s3657q8"),
        BootstrapPeer("test-es01", "npub17lpmzulpc98d8ff727k6e98atxn3phzupzsqqwe54ytduym747ws4tw5zm"),
        BootstrapPeer("test-uk01", "npub1u0z26dc4qeneu5rvwvmpfhtwh3522ed6rlgxr9jarrfnjrc6ew4qxjysrs"),
    )

    /** Dropdown entry for a manually configured peer. */
    const val BOOTSTRAP_CUSTOM = "custom"

    /** A commented Android-appropriate fips.yaml the Advanced editor seeds from. */
    const val DEFAULT_YAML_TEMPLATE = """# Advanced fips.yaml — edit any parameter. When non-empty this fully
# defines the fips config; the app still forces the Keystore identity,
# app-owned TUN, and disables the control socket. Structured fips settings
# above are superseded while this is set.
node:
  # leaf_only: false
  # tick_interval_secs: 5
  # heartbeat_interval_secs: 20
  # link_dead_timeout_secs: 60
  # lookup:
  #   ttl: 64
  #   attempt_timeouts_secs: [1, 2, 4, 8]
  rendezvous:
    nostr:
      enabled: false
      advertise: true
      advert_relays: ["wss://relay.damus.io", "wss://nos.lol"]
      dm_relays: ["wss://relay.damus.io", "wss://nos.lol"]
      # stun_servers: ["stun:stun.l.google.com:19302"]
    lan:
      enabled: false
tun:
  enabled: true
  mtu: 1280
dns:
  enabled: true
  port: 5354
transports:
  udp:
    bind_addr: "0.0.0.0:0"
  # tcp:
  #   bind_addr: "0.0.0.0:8443"
peers: []
"""

    /**
     * Build the shim config JSON from prefs + the (decrypted) nsec. Mirrors
     * the shim's `ShimConfig`. [hotspotAddr]/[hotspotPrefixLen] describe our
     * interface address on a joined FIPS Hotspot ("!FIPS") network; the
     * service passes them while that local-only network is up, and the shim
     * then runs a second dial-scoped UDP transport bound to it.
     */
    fun buildConfigJson(
        context: Context,
        nsec: String,
        hotspotAddr: String? = null,
        hotspotPrefixLen: Int = 0,
    ): String {
        val p = prefs(context)

        val peers = JSONArray()
        val npub = p.getString(PEER_NPUB, "")?.trim() ?: ""
        val endpoint = p.getString(PEER_ENDPOINT, "")?.trim() ?: ""
        if (npub.isNotEmpty() && endpoint.isNotEmpty()) {
            peers.put(
                JSONObject()
                    .put("npub", npub)
                    .put("endpoint", endpoint)
                    .put("transport", p.getString(PEER_TRANSPORT, "udp"))
            )
        }

        val config = JSONObject()
            .put("nsec", nsec)
            .put("peers", peers)
            .put("enable_nostr", p.getBoolean(NOSTR, false))
            .put("enable_fips_dns", p.getBoolean(ENABLE_FIPS_DNS, true))
            .put("worker_threads", p.getInt(WORKER_THREADS, 1))
            .put("forward_clearnet", p.getBoolean(FORWARD_CLEARNET, true))
            .put("battery_saver", p.getBoolean(BATTERY_SAVER, true))
            .put("enable_lan_mdns", p.getBoolean(LAN_MDNS, false))
            .put("log_level", p.getString(LOG_LEVEL, "info"))

        val upstreams = toList(p.getString(DNS_UPSTREAMS, ""))
        if (upstreams.length() > 0) config.put("dns_upstreams", upstreams)
        val relays = toList(p.getString(NOSTR_RELAYS, ""))
        if (relays.length() > 0) config.put("nostr_relays", relays)
        val stun = toList(p.getString(STUN_SERVERS, ""))
        if (stun.length() > 0) config.put("stun_servers", stun)
        p.getString(UDP_BIND, "")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { config.put("udp_bind", it) }
        p.getString(TCP_BIND, "")?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { config.put("tcp_bind", it) }

        if (hotspotAddr != null) {
            config.put(
                "hotspot",
                JSONObject().put("addr", hotspotAddr).put("prefix_len", hotspotPrefixLen)
            )
        }

        val yaml = p.getString(FIPS_YAML, "")?.trim() ?: ""
        if (yaml.isNotEmpty()) config.put("fips_yaml", yaml)

        return config.toString()
    }

    /** Split newline/comma-separated text into a JSON array of trimmed entries. */
    private fun toList(text: String?): JSONArray {
        val arr = JSONArray()
        (text ?: "").split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }
            .forEach { arr.put(it) }
        return arr
    }
}
