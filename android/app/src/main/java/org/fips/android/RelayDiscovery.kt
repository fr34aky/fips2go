package org.fips.android

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.ArrayDeque

/**
 * Finds Nostr relays on the local network and reports them as websocket
 * URLs.
 *
 * Browses DNS-SD for `_nostr._tcp` — the service type local relays
 * advertise (the NIP draft for local relay discovery, and what relay
 * software with mDNS support registers) — through the platform's
 * [NsdManager], so the app needs no multicast socket of its own. Each
 * sighting is resolved to host + port + TXT and turned into
 * `ws://host:port/path` (`wss://` when the TXT record says `tls=1`); the
 * set of resolved URLs goes to [onChanged] whenever it changes, and
 * [onStateChanged] reports whether a browse is actually active (a start can
 * fail asynchronously; it is then retried with backoff while wanted).
 *
 * Runs against the default network only (what `NsdManager` browses), so the
 * owner stops it while the underlay is not a LAN and restarts it after a
 * network switch. Every browse is a *session*: callbacks from a session that
 * has been stopped are discarded, including a resolve that was in flight, so
 * a relay of the previous LAN can never land in the new session's set.
 * Resolution is serialized because the pre-34 resolver rejects concurrent
 * requests. Main-thread confined: call [start]/[stop] from the main thread;
 * callbacks arrive there too.
 */
class RelayDiscovery(
    context: Context,
    private val onChanged: (Set<String>) -> Unit,
    private val onStateChanged: (running: Boolean) -> Unit = {},
) {
    companion object {
        private const val TAG = "RelayDiscovery"
        const val SERVICE_TYPE = "_nostr._tcp."
        /** Resolve retries per service before giving up until it is re-announced. */
        private const val MAX_RESOLVE_RETRIES = 2
        private const val START_BACKOFF_MIN_MS = 5_000L
        private const val START_BACKOFF_MAX_MS = 60_000L
    }

    private val nsd: NsdManager? = context.getSystemService(NsdManager::class.java)
    private val main = Handler(Looper.getMainLooper())

    /** The active browse session; null while none is running. */
    private var listener: NsdManager.DiscoveryListener? = null
    /** Whether the owner wants a browse (drives the start retry). */
    private var wanted = false
    private var startBackoffMs = START_BACKOFF_MIN_MS
    private var startRetry: Runnable? = null

    /** Resolved relays by service name (a service that vanished is removed by name). */
    private val relays = LinkedHashMap<String, String>()
    private val resolveQueue = ArrayDeque<NsdServiceInfo>()
    private val resolveRetries = HashMap<String, Int>()
    private var resolving = false

    /** Whether a browse is active. */
    val isRunning: Boolean get() = listener != null

    /** Snapshot of the currently resolved relay URLs. */
    val current: Set<String> get() = LinkedHashSet(relays.values)

    /** Start browsing (retrying on failure); no-op while already running or without NSD. */
    fun start() {
        wanted = true
        if (listener != null) return
        val nsd = nsd ?: run {
            Log.w(TAG, "NsdManager unavailable; local relay discovery off")
            return
        }
        val l = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String) {
                Log.i(TAG, "browsing $serviceType for local relays")
                main.post { if (listener === this) startBackoffMs = START_BACKOFF_MIN_MS }
            }
            override fun onServiceFound(info: NsdServiceInfo) {
                main.post { if (listener === this) enqueueResolve(info) }
            }
            override fun onServiceLost(info: NsdServiceInfo) {
                main.post {
                    if (listener !== this) return@post
                    resolveQueue.removeAll { it.serviceName == info.serviceName }
                    resolveRetries.remove(info.serviceName)
                    if (relays.remove(info.serviceName) != null) {
                        Log.i(TAG, "local relay gone: ${info.serviceName}")
                        onChanged(current)
                    }
                }
            }
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.w(TAG, "discovery start failed: $errorCode")
                main.post { if (listener === this) onSessionDead() }
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                Log.w(TAG, "discovery stop failed: $errorCode")
            }
        }
        listener = l
        try {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, l)
            onStateChanged(true)
        } catch (e: Exception) {
            Log.w(TAG, "discoverServices failed", e)
            listener = null
            onSessionDead()
        }
    }

    /** The browse could not be started: report it and retry later while still wanted. */
    private fun onSessionDead() {
        listener = null
        onStateChanged(false)
        if (!wanted || startRetry != null) return
        val delay = startBackoffMs
        startBackoffMs = (startBackoffMs * 2).coerceAtMost(START_BACKOFF_MAX_MS)
        val retry = Runnable {
            startRetry = null
            if (wanted && listener == null) start()
        }
        startRetry = retry
        main.postDelayed(retry, delay)
        Log.i(TAG, "retrying local relay browse in ${delay / 1000}s")
    }

    /** Stop browsing and forget everything found; reports an empty set if it was not. */
    fun stop() {
        wanted = false
        startRetry?.let { main.removeCallbacks(it) }
        startRetry = null
        startBackoffMs = START_BACKOFF_MIN_MS
        listener?.let { l ->
            listener = null
            try {
                nsd?.stopServiceDiscovery(l)
            } catch (e: Exception) {
                Log.w(TAG, "stopServiceDiscovery failed", e)
            }
            onStateChanged(false)
        }
        // An in-flight resolve belongs to the dead session; its callback
        // sees `listener !== session` and is dropped.
        resolveQueue.clear()
        resolveRetries.clear()
        resolving = false
        if (relays.isNotEmpty()) {
            relays.clear()
            onChanged(emptySet())
        }
    }

    /** Fresh browse, e.g. after the underlying network changed. */
    fun restart() {
        stop()
        start()
    }

    private fun enqueueResolve(info: NsdServiceInfo) {
        resolveQueue.removeAll { it.serviceName == info.serviceName }
        resolveQueue.add(info)
        drainResolveQueue()
    }

    /**
     * One resolve at a time: the legacy resolver returns
     * FAILURE_ALREADY_ACTIVE otherwise. The callbacks are fenced on the
     * session they were issued in, so a stale one neither touches
     * [resolving] nor delivers a relay into a later session.
     */
    private fun drainResolveQueue() {
        if (resolving) return
        val session = listener ?: return
        val info = resolveQueue.poll() ?: return
        val nsd = nsd ?: return
        resolving = true
        val cb = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                main.post {
                    if (listener !== session) return@post
                    resolving = false
                    val tries = (resolveRetries[info.serviceName] ?: 0) + 1
                    if (tries <= MAX_RESOLVE_RETRIES) {
                        Log.w(TAG, "resolve failed for ${info.serviceName}: $errorCode; retry $tries")
                        resolveRetries[info.serviceName] = tries
                        resolveQueue.add(info)
                    } else {
                        Log.w(TAG, "resolve failed for ${info.serviceName}: $errorCode; giving up")
                    }
                    drainResolveQueue()
                }
            }
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                main.post {
                    if (listener !== session) return@post
                    resolving = false
                    resolveRetries.remove(info.serviceName)
                    onResolved(serviceInfo)
                    drainResolveQueue()
                }
            }
        }
        try {
            @Suppress("DEPRECATION")
            nsd.resolveService(info, cb)
        } catch (e: Exception) {
            Log.w(TAG, "resolveService failed", e)
            resolving = false
        }
    }

    private fun onResolved(info: NsdServiceInfo) {
        val url = relayUrl(info)
        if (url == null) {
            Log.i(TAG, "ignoring ${info.serviceName}: no usable address")
            return
        }
        if (relays.put(info.serviceName, url) != url) {
            Log.i(TAG, "local relay: ${info.serviceName} -> $url")
            onChanged(current)
        }
    }

    /**
     * `ws://host:port/path` for a resolved service, or null when it offers
     * no address we can dial: IPv4 first, then a routable IPv6 literal.
     * Link-local IPv6 is skipped (its zone id has no place in a URL).
     */
    private fun relayUrl(info: NsdServiceInfo): String? {
        val addrs: List<InetAddress> =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                info.hostAddresses
            } else {
                @Suppress("DEPRECATION")
                listOfNotNull(info.host)
            }
        val host = addrs.firstOrNull { it is Inet4Address }?.hostAddress
            ?: addrs.firstOrNull { it is Inet6Address && !it.isLinkLocalAddress }
                ?.hostAddress?.substringBefore('%')?.let { "[$it]" }
            ?: return null
        val port = info.port
        if (port !in 1..65535) return null
        val txt = info.attributes ?: emptyMap()
        fun attr(key: String) = txt[key]?.let { String(it, Charsets.UTF_8).trim() } ?: ""
        val tls = attr("tls").let { it == "1" || it.equals("true", ignoreCase = true) }
        val path = attr("path").let { if (it.isEmpty() || it.startsWith("/")) it else "/$it" }
        return (if (tls) "wss" else "ws") + "://$host:$port$path"
    }
}
