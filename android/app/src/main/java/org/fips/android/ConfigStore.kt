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
    const val LOG_LEVEL = "log_level"
    const val FIPS_YAML = "fips_yaml"

    fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

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
     * the shim's `ShimConfig`.
     */
    fun buildConfigJson(context: Context, nsec: String): String {
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
