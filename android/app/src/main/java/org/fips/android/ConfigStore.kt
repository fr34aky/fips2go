package org.fips.android

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
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
    /** Public domain names over fips (www.example.ch → a mesh node), see the shim's `names.rs`. */
    const val PUBLIC_NAMES = "public_names"
    /**
     * Relays on the mesh for public names, one `ws://<npub>.fips[:port]` per
     * line, as typed; [meshRelays] validates on the way out. Blank = none.
     */
    const val NAMES_MESH_RELAYS = "names_mesh_relays"
    /**
     * Witnesses for public names, one `npub1…` per line, as typed;
     * [witnesses] validates on the way out. Their attestations let a domain
     * never seen resolve offline when its claim carries no DNSSEC proof.
     * Blank = attestations unused.
     */
    const val NAMES_WITNESSES = "names_witnesses"
    /** How many witnesses must attest a server (k). */
    const val NAMES_ATTESTATION_K = "names_attestation_k"
    /**
     * Also trust the nodes the phone already trusts for names — the node
     * the Mesh names sync from and every name's node in the hosts file —
     * as witnesses. Opt-in: a name's node is trusted to serve that name,
     * which is not yet trust in its word about other domains.
     */
    const val NAMES_WITNESSES_FROM_HOSTS = "names_witnesses_from_hosts"
    /**
     * Keep a direct link to the servers of the public domains in use (the
     * most recently verified, up to [NAMES_DIRECT_SERVER_COUNT]): after a
     * connect the mesh took up to 30 s to find such a server, which a
     * direct link skips. On by default; the server's operator then sees the
     * phone's public IP and when it comes online, and the public relays
     * which servers it links to, so it is a switch.
     */
    const val NAMES_DIRECT_SERVERS = "names_direct_servers"
    /**
     * DNSSEC for public names: validate the domain's DNS record and accept
     * the DNSSEC proof in its claim. Off, only witnesses vouch offline for a
     * domain never seen. On by default; off is for testing the witness path.
     */
    const val NAMES_DNSSEC = "names_dnssec"
    const val HOTSPOT = "hotspot_enabled"
    const val INBOUND_FILTER = "inbound_filter"
    const val INBOUND_PORTS = "inbound_ports"
    const val LOG_LEVEL = "log_level"
    /** `dark` (the default), `light` or `system`: the app's colour scheme. */
    const val THEME = "theme"

    /**
     * Also peer with two more public bootstrap servers ([FALLBACK_BOOTSTRAPS])
     * besides the configured one. With a single peer the phone has exactly
     * one link into the mesh — everything else is routed through it — so
     * that server going down means no mesh until it is back. Two more links
     * cost a heartbeat every 20 s each.
     */
    const val BOOTSTRAP_FALLBACKS = "bootstrap_fallbacks"

    /**
     * Open peer discovery over Nostr: also dial nodes that advertise
     * themselves, not only the configured bootstraps. The shim ceilings it at
     * a few links (see `nostr_discovery_max_peers` there). Off by default:
     * three bootstraps already make the mesh redundant, and every link is a
     * standing heartbeat.
     */
    const val NOSTR_DISCOVERY = "nostr_discovery"

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

    /**
     * Mesh names sync ([HostsSync]): pull the name list of a node running
     * fips-ui into the hosts file. App-side only; off unless configured —
     * it needs a node the user controls, so there is nothing to seed.
     */
    const val HOSTS_SYNC = "hosts_sync_enabled"
    const val HOSTS_SYNC_FROM = "hosts_sync_from"
    const val HOSTS_SYNC_PORT = "hosts_sync_port"
    const val HOSTS_SYNC_INTERVAL = "hosts_sync_interval_min"

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
    const val DEF_PUBLIC_NAMES = true
    /** The library's default too (pubdom-resolve `ResolverConfig`). */
    const val DEF_NAMES_ATTESTATION_K = 2
    const val DEF_NAMES_DNSSEC = true
    const val DEF_NAMES_WITNESSES_FROM_HOSTS = false
    const val DEF_NAMES_DIRECT_SERVERS = true
    /** How many servers [NAMES_DIRECT_SERVERS] links: each is one kept-alive link. */
    const val NAMES_DIRECT_SERVER_COUNT = 2
    const val DEF_HOTSPOT = true
    const val DEF_AUTO_UPDATE = true
    const val DEF_FORWARD_CLEARNET = true
    const val DEF_WORKER_THREADS = 1
    const val DEF_LOG_LEVEL = "info"
    const val DEF_THEME = "dark"
    /** The dropdown's entries too (`SettingsFragment.load`): one list. */
    val THEMES = listOf("dark", "light", "system")
    const val DEF_BOOTSTRAP_FALLBACKS = true
    const val DEF_NOSTR_DISCOVERY = false
    const val DEF_HOSTS_SYNC = false
    /** fips-ui's default "Web UI over the mesh" port. */
    const val DEF_HOSTS_SYNC_PORT = 8321
    /**
     * Hourly. fips-ui's own default is 5 minutes, but a phone pays for every
     * wake-up in battery and a name list changes rarely; "Sync now" is there
     * for an edit that should arrive at once.
     */
    const val DEF_HOSTS_SYNC_INTERVAL_MIN = 60

    /**
     * Ceiling on links found by Nostr discovery, sent to the shim as
     * `nostr_discovery_max_peers` and quoted in the Settings summary — one
     * constant, so the promise on screen and the bound in the node cannot
     * drift apart.
     */
    const val DEF_NOSTR_DISCOVERY_MAX_PEERS = 3

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
     * Candidates for the extra links when [BOOTSTRAP_FALLBACKS] is on, in
     * order; the first [FALLBACK_COUNT] whose npub differs from the configured
     * peer are used. Spread across regions on purpose, so the default
     * (`test-de01`) plus these do not share one hosting failure.
     */
    val FALLBACK_BOOTSTRAPS = listOf("test-uk01", "test-us01", "test-es01", "test-de01")
    const val FALLBACK_COUNT = 2

    /** The extra bootstrap peers the next node start will dial, if any. */
    fun fallbackPeers(context: Context): List<BootstrapPeer> {
        val p = prefs(context)
        if (!p.getBoolean(BOOTSTRAP_FALLBACKS, DEF_BOOTSTRAP_FALLBACKS)) return emptyList()
        val primary = p.getString(PEER_NPUB, "")?.trim() ?: ""
        return FALLBACK_BOOTSTRAPS
            .mapNotNull { name -> BOOTSTRAP_PEERS.firstOrNull { it.name == name } }
            .filter { it.npub != primary }
            .take(FALLBACK_COUNT)
    }

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

    /** The mesh relays for public names, validated; at most [MAX_RELAYS]. */
    fun meshRelays(context: Context): List<String> =
        (prefs(context).getString(NAMES_MESH_RELAYS, "") ?: "").lines()
            .mapNotNull { normalizeMeshRelay(it) }.distinct().take(MAX_RELAYS)

    /**
     * A relay on the mesh: `ws://<npub>.fips[:port][/path]` (the scheme may
     * be left out). No `wss`: the mesh is already encrypted and authenticated,
     * and nothing on it holds a certificate for an npub name. Null for
     * anything else, including public relays — those go in the relay list.
     */
    fun normalizeMeshRelay(input: String): String? {
        val raw = input.trim()
        if (raw.isEmpty() || raw.any { it.isWhitespace() }) return null
        val withScheme = if ("://" in raw) raw else "ws://$raw"
        val uri = runCatching { java.net.URI(withScheme) }.getOrNull() ?: return null
        if (uri.scheme?.lowercase() != "ws") return null
        if (uri.userInfo != null || uri.fragment != null || uri.rawQuery != null) return null
        val host = uri.host?.lowercase() ?: return null
        val label = host.removeSuffix(".fips")
        if (label == host || !isNpub(label)) return null
        if (uri.port != -1 && uri.port !in 1..65535) return null
        val port = if (uri.port == -1) "" else ":${uri.port}"
        val path = (uri.rawPath ?: "").trimEnd('/')
        return "ws://$host$port$path"
    }

    /** Lines of [text] that are not a valid mesh relay (for the Settings hint). */
    fun invalidMeshRelays(text: String): List<String> =
        text.lines().map { it.trim() }.filter { it.isNotEmpty() && normalizeMeshRelay(it) == null }

    /** Witnesses a phone can usefully type; k is bounded by it too. */
    const val MAX_WITNESSES = 8
    /** Typed and hosts-file witnesses together: every one is named in the
     *  filter the resolver sends to the mesh relays. */
    const val MAX_WITNESSES_TOTAL = 32

    fun namesWitnessesFromHosts(context: Context) =
        prefs(context).getBoolean(NAMES_WITNESSES_FROM_HOSTS, DEF_NAMES_WITNESSES_FROM_HOSTS)

    fun namesDirectServers(context: Context) =
        prefs(context).getBoolean(NAMES_DIRECT_SERVERS, DEF_NAMES_DIRECT_SERVERS)

    /**
     * The witnesses the hosts file implies: the node the names sync from
     * (the configured source while the sync is on, else the one recorded
     * in the file's synced block) first, then each name's node, each
     * once, in file order. One read of the file. fips accepts an
     * upper-case NPUB1… line, so the key is lower-cased before checking.
     */
    fun hostWitnesses(context: Context): List<String> {
        val p = prefs(context)
        val (master, hosts) = HostsStore.masterAndEffective(context)
        val source = if (p.getBoolean(HOSTS_SYNC, DEF_HOSTS_SYNC)) p.getString(HOSTS_SYNC_FROM, "") else null
        val out = mutableListOf<String>()
        for (candidate in listOf(source, master) + hosts.map { it.npub }) {
            val n = candidate?.trim()?.lowercase() ?: continue
            if (isNpub(n)) out += n
        }
        return out.distinct()
    }

    /** Typed and (opt-in) hosts-file witnesses as one list: typed first,
     *  each once, capped at [MAX_WITNESSES_TOTAL]. What the shim gets. */
    fun combinedWitnesses(typed: List<String>, fromHosts: List<String>): List<String> =
        (typed + fromHosts).distinct().take(MAX_WITNESSES_TOTAL)

    /** Every witness sent to the shim, from the saved settings. */
    fun allWitnesses(context: Context): List<String> {
        val derived = if (namesWitnessesFromHosts(context)) hostWitnesses(context) else emptyList()
        return combinedWitnesses(witnesses(context), derived)
    }

    /** The witnesses for public names, validated npubs; at most [MAX_WITNESSES]. */
    fun witnesses(context: Context): List<String> =
        validWitnesses(prefs(context).getString(NAMES_WITNESSES, "") ?: "")

    fun validWitnesses(text: String): List<String> =
        text.lines().map { it.trim() }.filter { isNpub(it) }.distinct().take(MAX_WITNESSES)

    /** Lines of [text] that are not an npub (for the Settings hint). */
    fun invalidWitnesses(text: String): List<String> =
        text.lines().map { it.trim() }.filter { it.isNotEmpty() && !isNpub(it) }

    /**
     * k as typed in Settings: blank is the default, anything else clamped
     * to 0 (off) .. [MAX_WITNESSES]. One parser for save and for the
     * unsaved-changes check, so the two cannot drift.
     */
    fun parseAttestationThreshold(text: String): Int {
        val t = text.trim()
        if (t.isEmpty()) return DEF_NAMES_ATTESTATION_K
        val n = t.toLongOrNull() ?: return DEF_NAMES_ATTESTATION_K
        return n.coerceIn(0L, MAX_WITNESSES.toLong()).toInt()
    }

    /** k, clamped to what makes sense: 0 (off) to [MAX_WITNESSES]. */
    fun attestationThreshold(context: Context): Int =
        prefs(context).getInt(NAMES_ATTESTATION_K, DEF_NAMES_ATTESTATION_K).coerceIn(0, MAX_WITNESSES)

    private const val BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    /** A bech32 `npub1…` with a valid checksum (BIP-173) and a 32-byte key. */
    fun isNpub(s: String): Boolean {
        if (s.length != 63 || !s.startsWith("npub1")) return false
        val data = s.substring(5).map { BECH32.indexOf(it).takeIf { i -> i >= 0 } ?: return false }
        val hrp = "npub"
        val values = hrp.map { it.code shr 5 } + 0 + hrp.map { it.code and 31 } + data
        var chk = 1
        val gen = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        for (v in values) {
            val top = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) if ((top ushr i) and 1 == 1) chk = chk xor gen[i]
        }
        return chk == 1
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
        if (!p.contains(PUBLIC_NAMES)) e.putBoolean(PUBLIC_NAMES, DEF_PUBLIC_NAMES)
        if (!p.contains(HOTSPOT)) e.putBoolean(HOTSPOT, DEF_HOTSPOT)
        if (!p.contains(AUTO_UPDATE)) e.putBoolean(AUTO_UPDATE, DEF_AUTO_UPDATE)
        if (!p.contains(FORWARD_CLEARNET)) e.putBoolean(FORWARD_CLEARNET, DEF_FORWARD_CLEARNET)
        if (!p.contains(WORKER_THREADS)) e.putInt(WORKER_THREADS, DEF_WORKER_THREADS)
        if (!p.contains(LOG_LEVEL)) e.putString(LOG_LEVEL, DEF_LOG_LEVEL)
        if (!p.contains(THEME)) e.putString(THEME, DEF_THEME)
        if (!p.contains(BOOTSTRAP_FALLBACKS)) {
            e.putBoolean(BOOTSTRAP_FALLBACKS, DEF_BOOTSTRAP_FALLBACKS)
        }
        if (!p.contains(NOSTR_DISCOVERY)) e.putBoolean(NOSTR_DISCOVERY, DEF_NOSTR_DISCOVERY)
        RETIRED_KEYS.filter { p.contains(it) }.forEach { e.remove(it) }
        e.apply()
    }

    /** LAN mDNS discovery, honouring the default. */
    fun lanMdns(context: Context) = prefs(context).getBoolean(LAN_MDNS, DEF_LAN_MDNS)

    /** Public domain names over fips, honouring the default. */
    fun publicNames(context: Context) = prefs(context).getBoolean(PUBLIC_NAMES, DEF_PUBLIC_NAMES)

    /** The verified-domain pins (fips-pub-domains' pin file), next to the hosts file. */
    fun namesPinsFile(context: Context): java.io.File =
        HostsStore.file(context).resolveSibling("names-pins.json")

    /**
     * Forget every verified domain: the next lookup verifies again from the
     * DNS record, a claim's proof, or the witnesses. Takes effect on the
     * next connect, which rebuilds the resolver over an absent file; the
     * running one keeps its pins in memory until then.
     */
    fun forgetNamesPins(context: Context): Boolean = namesPinsFile(context).delete()
    fun namesDnssec(context: Context) = prefs(context).getBoolean(NAMES_DNSSEC, DEF_NAMES_DNSSEC)

    fun theme(context: Context): String =
        prefs(context).getString(THEME, DEF_THEME)?.takeIf { it in THEMES } ?: DEF_THEME

    /**
     * Apply the stored colour scheme to every activity. Called before the
     * first activity is created ([FipsApplication]) and when Settings saves
     * a change, which recreates the visible activity.
     */
    fun applyTheme(context: Context) {
        AppCompatDelegate.setDefaultNightMode(
            when (theme(context)) {
                "light" -> AppCompatDelegate.MODE_NIGHT_NO
                "system" -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
                else -> AppCompatDelegate.MODE_NIGHT_YES
            }
        )
    }

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
        // Extra links so one bootstrap outage does not empty the mesh; the
        // public servers all speak UDP on the default port. Every peer is
        // also marked via_nostr by the shim, so one that moves is re-found.
        for (fallback in fallbackPeers(context)) {
            peers.put(
                JSONObject()
                    .put("npub", fallback.npub)
                    .put("endpoint", fallback.endpoint)
                    .put("transport", DEF_PEER_TRANSPORT)
            )
        }

        val config = JSONObject()
            .put("nsec", nsec)
            .put("peers", peers)
            // Always on: relay discovery + NAT traversal is what lets a phone
            // behind CGNAT reach peers it has no route to, and the in-app
            // resolver is the only thing that answers .fips names.
            .put("enable_nostr", true)
            .put("nostr_discovery", p.getBoolean(NOSTR_DISCOVERY, DEF_NOSTR_DISCOVERY))
            .put("nostr_discovery_max_peers", DEF_NOSTR_DISCOVERY_MAX_PEERS)
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

        // Public domain names over fips: the pin file next to the hosts file.
        // Sending the path is what turns the feature on in the shim; a name
        // without a verified binding is forwarded to the upstreams as before.
        if (publicNames(context)) {
            config.put("names_pins_path", namesPinsFile(context).absolutePath)
            meshRelays(context).takeIf { it.isNotEmpty() }?.let {
                config.put("names_mesh_relays", JSONArray(it))
            }
            // Witnesses only with k: the shim's default for k is the
            // library's, so k is sent whenever the list is.
            allWitnesses(context).takeIf { it.isNotEmpty() }?.let {
                config.put("names_witnesses", JSONArray(it))
                config.put("names_attestation_threshold", attestationThreshold(context))
            }
            // Sent whenever public names are on, so the switch means what
            // it shows whatever the library's default becomes.
            config.put("names_dnssec", namesDnssec(context))
            // Always sent with public names, off included: the shim's own
            // default is on.
            config.put(
                "names_server_peers",
                if (namesDirectServers(context)) NAMES_DIRECT_SERVER_COUNT else 0
            )
        }

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
