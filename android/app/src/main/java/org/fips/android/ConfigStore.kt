package org.fips.android

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Single source of truth for all app/config preferences and for turning them
 * into the shim's config JSON.
 *
 * Every setting has a working default and [applyDefaults] seeds them on first
 * run, so a fresh install can connect to the mesh without the user opening
 * Settings at all. Defaults live here as `DEF_*` constants — read them through
 * these rather than repeating a literal at each `getBoolean` call site, or the
 * service and the UI drift apart.
 */
object ConfigStore {
    const val PREFS = "fips"

    // Structured (common) keys.
    const val PEER_NPUB = "peer_npub"
    const val PEER_ENDPOINT = "peer_endpoint"
    const val PEER_TRANSPORT = "peer_transport"
    const val WORKER_THREADS = "worker_threads"
    const val FORWARD_CLEARNET = "forward_clearnet"
    const val BATTERY_SAVER = "battery_saver"
    const val LAN_MDNS = "enable_lan_mdns"
    const val HOTSPOT = "hotspot_enabled"
    const val INBOUND_FILTER = "inbound_filter"
    const val INBOUND_PORTS = "inbound_ports"
    const val LOG_LEVEL = "log_level"

    /**
     * User-edited Nostr relay list, one URL per line. ABSENT means "never
     * customised": nothing is passed to the shim and fips uses its built-in
     * relays — so an untouched install keeps following fips's defaults across
     * pin bumps. Deliberately not seeded by [applyDefaults] for that reason.
     *
     * NOT "nostr_relays": that name belongs to the pre-0.3 setting and sits in
     * [RETIRED_KEYS], so applyDefaults would delete this list on every launch.
     */
    const val NOSTR_RELAYS = "relay_list"

    /** App-side only (not part of the shim config JSON). */
    const val AUTO_UPDATE = "auto_update_check"

    /** One-shot marker: the hotspot location rationale has been shown. */
    const val ASKED_HOTSPOT_LOCATION = "asked_hotspot_location"

    /**
     * Epoch millis before which the battery-optimisation card stays hidden.
     * The card is dismissible but not permanently: Doze freezes the service
     * and silently drops the mesh, so a node left unexempted is quietly
     * unreliable and worth raising again later.
     */
    const val BATTERY_PROMPT_SNOOZED_UNTIL = "battery_prompt_snoozed_until"

    /** How long "Not now" hides the battery-optimisation card. */
    const val BATTERY_PROMPT_SNOOZE_MS = 7L * 24 * 60 * 60 * 1000

    // Defaults. Chosen so a fresh install is usable and reasonably private
    // out of the box: bootstrapped onto the public test mesh, inbound
    // firewall closed, discovery on, battery timers relaxed.
    const val DEF_PEER_TRANSPORT = "udp"
    const val DEF_INBOUND_FILTER = true
    const val DEF_BATTERY_SAVER = true
    const val DEF_LAN_MDNS = true
    const val DEF_HOTSPOT = true
    const val DEF_AUTO_UPDATE = true
    const val DEF_FORWARD_CLEARNET = true
    const val DEF_WORKER_THREADS = 1
    const val DEF_LOG_LEVEL = "info"

    /**
     * Settings the app no longer exposes. Nostr rendezvous and the in-app
     * `.fips` resolver are now always on, transports/DNS/relays/STUN use the
     * fips built-in defaults, and the raw-YAML escape hatch is gone. They are
     * deleted on first run because a stale value would otherwise keep taking
     * effect with no UI left to change it — `fips_yaml` most of all, since a
     * non-empty one supersedes the entire structured config.
     */
    private val RETIRED_KEYS = listOf(
        "nostr", "nostr_relays", "stun_servers",
        "udp_bind", "tcp_bind",
        "dns_upstreams", "enable_fips_dns",
        "fips_yaml",
    )

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

    /** Seeded on first run so the app connects without any configuration. */
    const val DEFAULT_BOOTSTRAP = "test-de01"

    /** Dropdown entry for a manually configured peer. */
    const val BOOTSTRAP_CUSTOM = "custom"

    /**
     * What an uncustomised node uses — a DISPLAY mirror of fips's built-in
     * `advert_relays`/`dm_relays` default (fips `src/config/node.rs`), shown
     * in the relay editor and on Overview while disconnected. It is never sent
     * to the shim; check it against fips when bumping the pin.
     */
    val DEFAULT_RELAYS = listOf("wss://relay.damus.io", "wss://nos.lol", "wss://offchain.pub")

    /** Every relay is a standing websocket; keep the list phone-sized. */
    const val MAX_RELAYS = 8

    /** The customised list, or null when the node runs on fips's defaults. */
    fun customRelays(context: Context): List<String>? {
        val p = prefs(context)
        if (!p.contains(NOSTR_RELAYS)) return null
        return (p.getString(NOSTR_RELAYS, "") ?: "").lines()
            .mapNotNull { normalizeRelay(it) }.distinct().ifEmpty { null }
    }

    /** The relays the next node start will use. */
    fun effectiveRelays(context: Context): List<String> = customRelays(context) ?: DEFAULT_RELAYS

    /** Store a customised list; null or empty returns to fips's defaults. */
    fun setCustomRelays(context: Context, relays: List<String>?) {
        val e = prefs(context).edit()
        if (relays.isNullOrEmpty()) e.remove(NOSTR_RELAYS)
        else e.putString(NOSTR_RELAYS, relays.joinToString("\n"))
        e.apply()
    }

    /**
     * Canonical form of a user-typed relay, or null if it is not one. Strict
     * on purpose: fips adds every configured relay with `add_relay(..)?`, so a
     * single URL nostr-sdk rejects fails the whole Nostr bootstrap — NAT
     * traversal and npub lookup gone, with only a log line to show for it. A
     * bare host gets `wss://`; `ws://` stays allowed for LAN/test relays.
     */
    fun normalizeRelay(input: String): String? {
        val raw = input.trim()
        if (raw.isEmpty() || raw.any { it.isWhitespace() }) return null
        val withScheme = if ("://" in raw) raw else "wss://$raw"
        val uri = runCatching { java.net.URI(withScheme) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        val host = uri.host?.lowercase() ?: return null
        if (scheme != "wss" && scheme != "ws") return null
        if (uri.userInfo != null || uri.fragment != null) return null
        if (!host.contains('.') && host != "localhost" && !host.startsWith("[")) return null
        // -1 = none given. Anything else out of range is a typo, not a default.
        if (uri.port != -1 && uri.port !in 1..65535) return null
        val port = if (uri.port == -1) "" else ":${uri.port}"
        val path = (uri.rawPath ?: "").trimEnd('/')
        val query = uri.rawQuery?.let { "?$it" } ?: ""
        return "$scheme://$host$port$path$query"
    }

    /**
     * Seed the defaults for any setting the user has never saved, and drop
     * the retired keys. Idempotent, and safe on an existing install: a key
     * that is present — including one the user deliberately blanked — is left
     * exactly as it is, because [SettingsFragment] writes every key on save.
     *
     * Call before anything reads the prefs: both the activity and the service
     * do, since the service can start without the UI (always-on VPN).
     */
    fun applyDefaults(context: Context) {
        val p = prefs(context)
        val e = p.edit()
        if (!p.contains(PEER_NPUB) && !p.contains(PEER_ENDPOINT)) {
            val boot = BOOTSTRAP_PEERS.first { it.name == DEFAULT_BOOTSTRAP }
            e.putString(PEER_NPUB, boot.npub).putString(PEER_ENDPOINT, boot.endpoint)
        }
        if (!p.contains(PEER_TRANSPORT)) e.putString(PEER_TRANSPORT, DEF_PEER_TRANSPORT)
        if (!p.contains(INBOUND_FILTER)) e.putBoolean(INBOUND_FILTER, DEF_INBOUND_FILTER)
        if (!p.contains(BATTERY_SAVER)) e.putBoolean(BATTERY_SAVER, DEF_BATTERY_SAVER)
        if (!p.contains(LAN_MDNS)) e.putBoolean(LAN_MDNS, DEF_LAN_MDNS)
        if (!p.contains(HOTSPOT)) e.putBoolean(HOTSPOT, DEF_HOTSPOT)
        if (!p.contains(AUTO_UPDATE)) e.putBoolean(AUTO_UPDATE, DEF_AUTO_UPDATE)
        if (!p.contains(FORWARD_CLEARNET)) e.putBoolean(FORWARD_CLEARNET, DEF_FORWARD_CLEARNET)
        if (!p.contains(WORKER_THREADS)) e.putInt(WORKER_THREADS, DEF_WORKER_THREADS)
        if (!p.contains(LOG_LEVEL)) e.putString(LOG_LEVEL, DEF_LOG_LEVEL)
        RETIRED_KEYS.filter { p.contains(it) }.forEach { e.remove(it) }
        e.apply()
    }

    /** LAN mDNS discovery, honouring the default. */
    fun lanMdns(context: Context) = prefs(context).getBoolean(LAN_MDNS, DEF_LAN_MDNS)

    /** FIPS Hotspot auto-join, honouring the default. */
    fun hotspotEnabled(context: Context) = prefs(context).getBoolean(HOTSPOT, DEF_HOTSPOT)

    /**
     * Build the shim config JSON from prefs + the (decrypted) nsec. Mirrors
     * the shim's `ShimConfig`. [hotspotAddr]/[hotspotPrefixLen] describe our
     * interface address on a joined FIPS Hotspot ("!FIPS") network; the
     * service passes them while that local-only network is up, and the shim
     * then runs a second dial-scoped UDP transport bound to it.
     *
     * Fields the app no longer exposes are simply omitted, which leaves the
     * shim (and fips) on their own defaults: built-in Nostr relays and STUN
     * servers, an ephemeral UDP bind with no TCP transport, and the system
     * upstream resolvers for non-`.fips` DNS.
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
                    .put("transport", p.getString(PEER_TRANSPORT, DEF_PEER_TRANSPORT))
            )
        }

        val config = JSONObject()
            .put("nsec", nsec)
            .put("peers", peers)
            // Always on: relay discovery + NAT traversal is what lets a phone
            // behind CGNAT reach peers it has no route to, and the in-app
            // resolver is the only thing that answers .fips names.
            .put("enable_nostr", true)
            .put("enable_fips_dns", true)
            .put("worker_threads", p.getInt(WORKER_THREADS, DEF_WORKER_THREADS))
            .put("forward_clearnet", p.getBoolean(FORWARD_CLEARNET, DEF_FORWARD_CLEARNET))
            .put("battery_saver", p.getBoolean(BATTERY_SAVER, DEF_BATTERY_SAVER))
            .put("enable_lan_mdns", p.getBoolean(LAN_MDNS, DEF_LAN_MDNS))
            .put("inbound_filter", p.getBoolean(INBOUND_FILTER, DEF_INBOUND_FILTER))
            .put("log_level", p.getString(LOG_LEVEL, DEF_LOG_LEVEL))
            // Always sent, file or no file: the shim watches the path, so the
            // first name added while connected resolves without a rebind.
            .put("hosts_path", HostsStore.file(context).absolutePath)

        // Only a customised list is sent; omitted → fips's built-in relays
        // (the shim treats an empty array the same way). Re-normalised on the
        // way out, so nothing unvalidated reaches `add_relay` even if the
        // stored string was written by an older build.
        customRelays(context)?.let { relays ->
            config.put("nostr_relays", JSONArray(relays.take(MAX_RELAYS)))
        }

        val inboundPorts = JSONArray()
        (p.getString(INBOUND_PORTS, "") ?: "").split('\n', ',', ' ')
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
            .forEach { inboundPorts.put(it) }
        config.put("inbound_ports", inboundPorts)

        if (hotspotAddr != null) {
            config.put(
                "hotspot",
                JSONObject().put("addr", hotspotAddr).put("prefix_len", hotspotPrefixLen)
            )
        }

        return config.toString()
    }
}
