package org.fips.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.Manifest
import android.content.pm.PackageManager as PM
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSpecifier
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.json.JSONObject

/**
 * Owns the VpnService session and hands its TUN fd to the Rust engine.
 *
 * The tunnel captures all traffic of the selected apps: `fd00::/8` goes to
 * the mesh, everything else reaches the shim's userspace forwarder, which
 * sends it back out on protected sockets. The IPv6 default route (`::/0`) is
 * claimed only while the underlying network actually has IPv6 internet:
 * the forwarder's userspace TCP stack SYN-ACKs a captured app's connect
 * before dialing the real destination, so a claimed-but-undeliverable `::/0`
 * would turn every IPv6 connect into a hang (Happy Eyeballs sees a working
 * connection and never falls back to IPv4) instead of a fast v4 fallback.
 */
class FipsVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "org.fips.android.CONNECT"
        const val ACTION_DISCONNECT = "org.fips.android.DISCONNECT"
        private const val TAG = "FipsVpnService"
        private const val CHANNEL_ID = "fips_vpn"
        private const val NOTIFICATION_ID = 1
        private const val MESH_MTU = 1280
        // The tun's IPv4 source address for captured apps' clearnet (any
        // private range not on the LAN; forwarded flows are re-sourced to the
        // real egress IP anyway).
        private const val TUN_IPV4 = "10.111.222.1"
        // A Wi-Fi ↔ cellular hand-over emits a burst of network callbacks over
        // several seconds; wait this long before rebinding so one node restart
        // serves the whole burst.
        private const val REBIND_SETTLE_MS = 1500L
        // FIPS Hotspot: an open AP other fips nodes run (e.g. an offline mesh
        // island). Auto-joined while the toggle is armed — via suggestion
        // and/or local-only specifier, see startHotspot().
        private const val HOTSPOT_SSID = "!FIPS"
        // After the user dismissed the specifier approval dialog, don't
        // re-file (and re-prompt) on every scan sighting for this long.
        private const val SPECIFIER_BACKOFF_MS = 15 * 60_000L
        // While armed and not joined, actively kick a Wi-Fi scan this often:
        // the system barely scans on its own when connected with the screen
        // off, which would leave "!FIPS" unseen for many minutes. Android
        // allows a foreground app ~4 scans per 2 minutes.
        private const val SCAN_KICK_MS = 60_000L

        /**
         * UI-visible hotspot state: "addr on !FIPS" while joined, null
         * otherwise. Written only by the service.
         */
        @Volatile var hotspotStatus: String? = null
            private set
    }

    private var tunFd: ParcelFileDescriptor? = null

    private var connectivity: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentUnderlying: Network? = null
    private val rebinding = AtomicBoolean(false)
    /** Set by every rebind request; cleared by the worker as it serves them. */
    private val rebindRequested = AtomicBoolean(false)
    /** The mesh address the current tunnel was established with. */
    @Volatile private var meshAddress: String? = null
    /** Whether the current tunnel claims `::/0` (IPv6 clearnet via forwarder). */
    @Volatile private var tunnelHasIpv6Clearnet = false

    // FIPS Hotspot ("!FIPS") state — see [startHotspot] for the two join
    // paths. A specifier-joined network is local-only (no INTERNET
    // capability) and never enters [availableNetworks]; a suggestion-joined
    // one is a regular Wi-Fi network that claims INTERNET until validation
    // fails, so [preferredUnderlying] excludes [hotspotNetwork] explicitly.
    private var hotspotCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var hotspotNetwork: Network? = null
    @Volatile private var hotspotAddr: String? = null
    @Volatile private var hotspotPrefixLen: Int = 0
    /** The Wi-Fi suggestion filed for city-scale auto-join (null = none). */
    private var hotspotSuggestions: List<WifiNetworkSuggestion>? = null
    /** Watches all Wi-Fi networks to spot a suggestion-joined "!FIPS". */
    private var wifiWatcher: ConnectivityManager.NetworkCallback? = null
    /** Re-files the specifier when a scan actually sees "!FIPS". */
    private var scanWatcher: WifiManager.ScanResultsCallback? = null
    /** Until when specifier re-filing is suppressed (user dismissed dialog). */
    @Volatile private var specifierBackoffUntil = 0L
    /** Periodic scan kick while armed & unjoined (null = stopped). */
    private var scanKick: Runnable? = null

    /**
     * Held only while LAN mDNS is enabled AND the underlay is Wi-Fi. The lock
     * disables the Wi-Fi chip's hardware multicast filtering, so every LAN
     * multicast frame (Chromecast, SSDP, …) wakes the CPU — don't pay that
     * when discovery is off or can't work (cellular). Null when mDNS is off.
     */
    private var multicastLock: WifiManager.MulticastLock? = null

    private fun updateMulticastLock(network: Network?) {
        val lock = multicastLock ?: return
        val onWifi = network != null && connectivity?.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        // mDNS runs when the user enabled it (and the underlay is Wi-Fi) OR
        // while a FIPS Hotspot is joined (the shim forces LAN discovery on
        // for the hotspot link — that's the point of joining).
        val want = (onWifi && ConfigStore.lanMdns(this)) ||
            hotspotNetwork != null
        if (want && !lock.isHeld) {
            lock.acquire()
            Log.i(TAG, "multicast lock acquired (mDNS active)")
        } else if (!want && lock.isHeld) {
            lock.release()
            Log.i(TAG, "multicast lock released (mDNS idle)")
        }
    }

    private fun releaseMulticastLock() {
        multicastLock?.takeIf { it.isHeld }?.release()
        multicastLock = null
    }

    private fun prefs() = getSharedPreferences("fips", Context.MODE_PRIVATE)

    /** Called from Rust (JNI) for every underlay socket the node creates. */
    fun protectFd(fd: Int): Boolean {
        val ok = protect(fd)
        // The shim's hotspot transport binds our address on the "!FIPS"
        // link; Android routes wildcard/protected sockets via the default
        // network only, so that socket must be explicitly moved onto the
        // local-only hotspot network or its packets egress the wrong
        // interface. Identify it by its bound source address.
        val network = hotspotNetwork
        val want = hotspotAddr
        if (ok && network != null && want != null) {
            try {
                ParcelFileDescriptor.fromFd(fd).use { dup ->
                    val local = Os.getsockname(dup.fileDescriptor) as? InetSocketAddress
                    if (local?.address?.hostAddress == want) {
                        network.bindSocket(dup.fileDescriptor)
                        Log.i(TAG, "hotspot socket bound to $network ($want)")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "hotspot bindSocket failed", e)
            }
        }
        return ok
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // The service can start without the UI ever running (always-on VPN),
        // so seed the first-run defaults here too — notably the bootstrap
        // peer, which has no in-code fallback the way the toggles do.
        ConfigStore.applyDefaults(this)
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                // Decrypt the Keystore nsec and build the config here so the
                // secret never rides in an Intent.
                val nsec = IdentityStore.getOrCreate(this)
                val identity = JSONObject(FipsNative.deriveIdentity(nsec))
                if (identity.has("error")) {
                    Log.e(TAG, "identity error: ${identity.getString("error")}")
                    return START_NOT_STICKY
                }
                val address = identity.getString("address")
                val config = ConfigStore.buildConfigJson(this, nsec)
                startForegroundWithNotification(address)
                thread(name = "fips-connect") { connect(config, address) }
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun connect(config: String, address: String) {
        if (FipsNative.isRunning()) {
            Log.w(TAG, "already running")
            return
        }
        connectivity = getSystemService(ConnectivityManager::class.java)
        meshAddress = address
        if (ConfigStore.lanMdns(this) ||
            ConfigStore.hotspotEnabled(this)
        ) {
            val wifi = applicationContext.getSystemService(WifiManager::class.java)
            multicastLock = wifi?.createMulticastLock("fips-mdns")
                ?.apply { setReferenceCounted(false) }
            updateMulticastLock(connectivity?.activeNetwork)
        }
        // Initial guess from the current default network; the first network
        // callback corrects the routes if this was wrong (or changes later).
        val wantIpv6 = hasIpv6Internet(connectivity?.activeNetwork)

        val pfd = establishTunnel(address, wantIpv6)
        if (pfd == null) {
            Log.e(TAG, "VPN not prepared or establish() returned null")
            shutdown()
            return
        }
        tunFd = pfd
        tunnelHasIpv6Clearnet = wantIpv6

        val error = FipsNative.start(config, pfd.fd, this)
        if (error.isNotEmpty()) {
            Log.e(TAG, "engine start failed: $error")
            shutdown()
        } else {
            Log.i(TAG, "fips engine running, address $address, ipv6Clearnet=$wantIpv6")
            registerNetworkMonitoring()
            startHotspot()
        }
    }

    private fun hasFineLocation(): Boolean =
        checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PM.PERMISSION_GRANTED

    /**
     * Arm the FIPS Hotspot machinery (SSID "!FIPS", open network). Two
     * complementary join paths feed the same [updateHotspot]/[clearHotspot]
     * overlay, each transition riding the coalesced rebind path so the node
     * gains/loses its hotspot-bound transport:
     *
     * - **Suggestion** (API 31+, fine location): `WifiNetworkSuggestion` lets
     *   the platform auto-join ANY "!FIPS" AP anywhere — silently, in the
     *   background, re-joining after loss and roaming like a saved network —
     *   whenever the primary Wi-Fi slot is free (it never steals a working
     *   Wi-Fi, and an internet-less "!FIPS" never becomes the default
     *   network, so internet stays on cellular). The [wifiWatcher] spots the
     *   join by SSID (needs fine location to read it).
     * - **Specifier** (API 29+): a local-only secondary connection that works
     *   IN ADDITION to a connected Wi-Fi on dual-STA devices. Its system
     *   dialog blocks the app while "searching", so it is only filed when a
     *   scan actually shows "!FIPS" in range ([scanWatcher]) — and a session
     *   is one-shot: after a loss [clearHotspot] tears it down and the scan
     *   watcher re-files on the next beacon sighting. Approval is remembered
     *   per AP (SSID+BSSID), so known APs re-join silently; a NEW AP shows
     *   the one-time dialog. Without fine location, scans are unreadable and
     *   this degrades to filing once at connect (dialog lingers if out of
     *   range — the Settings subtitle asks for the permission instead).
     */
    private fun startHotspot() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        if (!ConfigStore.hotspotEnabled(this)) return
        addHotspotSuggestion()
        registerWifiWatcher()
        if (!hasFineLocation()) {
            // Both join paths need it: the suggestion above already bailed,
            // and scans are unreadable. Filing the specifier blind would pop
            // the system Wi-Fi picker on every connect and leave it spinning
            // for an SSID we cannot confirm is in range — worse than doing
            // nothing. Settings explains how to grant it.
            Log.i(TAG, "hotspot armed but fine location missing; auto-join disabled")
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            registerScanWatcher()
            startScanKick()
            maybeFileSpecifier() // covers "!FIPS already in the last scan"
        } else {
            fileSpecifierRequest() // legacy path: no scans to gate on
        }
    }

    /** Suggest "!FIPS" to the platform for background auto-join (API 31+). */
    private fun addHotspotSuggestion() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !hasFineLocation()) return
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        val suggestions = listOf(
            WifiNetworkSuggestion.Builder().setSsid(HOTSPOT_SSID).build()
        )
        val status = try {
            wifi.addNetworkSuggestions(suggestions)
        } catch (e: Exception) {
            Log.w(TAG, "addNetworkSuggestions failed", e)
            return
        }
        when (status) {
            WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS,
            WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE -> {
                hotspotSuggestions = suggestions
                Log.i(TAG, "FIPS hotspot suggestion active (auto-join)")
            }
            else -> Log.w(TAG, "hotspot suggestion rejected, status=$status")
        }
    }

    private fun removeHotspotSuggestion() {
        val suggestions = hotspotSuggestions ?: return
        hotspotSuggestions = null
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        try {
            wifi.removeNetworkSuggestions(suggestions)
        } catch (e: Exception) {
            Log.w(TAG, "removeNetworkSuggestions failed", e)
        }
    }

    /**
     * Watch all Wi-Fi networks for a suggestion-joined "!FIPS" (identified by
     * SSID via `WifiInfo`, which needs `FLAG_INCLUDE_LOCATION_INFO` + fine
     * location + the service's `location` foreground type).
     */
    private fun registerWifiWatcher() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !hasFineLocation()) return
        val cm = connectivity ?: return
        val cb = object : ConnectivityManager.NetworkCallback(
            FLAG_INCLUDE_LOCATION_INFO
        ) {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val ssid = (caps.transportInfo as? WifiInfo)?.ssid?.removeSurrounding("\"")
                if (ssid == HOTSPOT_SSID) {
                    updateHotspot(network, cm.getLinkProperties(network))
                }
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                if (network == hotspotNetwork) updateHotspot(network, lp)
            }
            override fun onLost(network: Network) {
                if (network == hotspotNetwork) clearHotspot("lost")
            }
        }
        wifiWatcher = cb
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()
        try {
            cm.registerNetworkCallback(req, cb, Handler(Looper.getMainLooper()))
        } catch (e: Exception) {
            Log.w(TAG, "wifi watcher registration failed", e)
            wifiWatcher = null
        }
    }

    /**
     * Keep scans coming while armed and not joined. `startScan()` is
     * deprecated-but-functional and throttled by the platform; failures are
     * fine — the watcher also rides every scan any other requester triggers.
     * Stops itself once joined; [clearHotspot] restarts it.
     */
    private fun startScanKick() {
        if (scanKick != null) return
        val handler = Handler(Looper.getMainLooper())
        val task = object : Runnable {
            override fun run() {
                if (scanKick !== this) return
                if (hotspotNetwork != null || !FipsNative.isRunning()) {
                    scanKick = null
                    return
                }
                try {
                    @Suppress("DEPRECATION")
                    applicationContext.getSystemService(WifiManager::class.java)?.startScan()
                } catch (e: Exception) {
                    Log.w(TAG, "scan kick failed", e)
                }
                handler.postDelayed(this, SCAN_KICK_MS)
            }
        }
        scanKick = task
        handler.post(task)
    }

    private fun stopScanKick() {
        scanKick = null
    }

    /** Piggy-back on every completed system scan to gate specifier filing. */
    private fun registerScanWatcher() {
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        val cb = object : WifiManager.ScanResultsCallback() {
            override fun onScanResultsAvailable() {
                maybeFileSpecifier()
            }
        }
        scanWatcher = cb
        try {
            wifi.registerScanResultsCallback(mainExecutor, cb)
        } catch (e: Exception) {
            Log.w(TAG, "scan watcher registration failed", e)
            scanWatcher = null
        }
    }

    /**
     * File the specifier request iff it would actually connect right away:
     * "!FIPS" visible in the latest scan, nothing joined yet, no request in
     * flight, not inside the post-dismissal backoff — and only while another
     * Wi-Fi is the underlay (the dual-STA case; on cellular the suggestion
     * path owns the free Wi-Fi slot and joins without any dialog).
     */
    private fun maybeFileSpecifier() {
        if (hotspotCallback != null || hotspotNetwork != null) return
        if (System.currentTimeMillis() < specifierBackoffUntil) return
        if (!ConfigStore.hotspotEnabled(this)) return
        val underlayWifi = currentUnderlying?.let { net ->
            connectivity?.getNetworkCapabilities(net)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        } ?: false
        if (!underlayWifi) return
        val wifi = applicationContext.getSystemService(WifiManager::class.java) ?: return
        val best = try {
            wifi.scanResults.filter { it.SSID == HOTSPOT_SSID }.maxByOrNull { it.level }
        } catch (e: SecurityException) {
            null
        }
        if (best != null) {
            Log.i(TAG, "\"$HOTSPOT_SSID\" seen in scan (${best.BSSID}); filing specifier request")
            fileSpecifierRequest(best.BSSID)
        }
    }

    /**
     * The raw local-only specifier request (see [startHotspot] for policy).
     *
     * When the target AP's BSSID is known (from the gating scan result), it
     * is pinned into the specifier: the platform's silent-reconnect bypass
     * for previously approved APs only fires reliably for single-access-
     * point requests — an SSID-only request re-prompts even for an approved
     * BSSID (observed on Android 17: "No approved access point found"). A
     * pinned request means: known AP → silent join; new AP → one dialog,
     * remembered per BSSID. Re-filing after a loss re-picks the strongest
     * beacon, which stands in for roaming between "!FIPS" APs.
     */
    private fun fileSpecifierRequest(bssid: String? = null) {
        if (hotspotCallback != null) return
        val cm = connectivity ?: return
        val specifier = WifiNetworkSpecifier.Builder().setSsid(HOTSPOT_SSID).apply {
            bssid?.let {
                try {
                    setBssid(android.net.MacAddress.fromString(it))
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "bad BSSID $it; filing SSID-only", e)
                }
            }
        }.build()
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .setNetworkSpecifier(specifier)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // LinkProperties may lag onAvailable; onLinkPropertiesChanged
                // fills in the DHCP address when it does.
                updateHotspot(network, cm.getLinkProperties(network))
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                updateHotspot(network, lp)
            }
            override fun onLost(network: Network) {
                clearHotspot("lost")
            }
            override fun onUnavailable() {
                // The user dismissed the approval dialog or the OS gave up.
                // Back off so the scan watcher doesn't re-prompt on every
                // scan while the (declined) SSID stays in range.
                specifierBackoffUntil = System.currentTimeMillis() + SPECIFIER_BACKOFF_MS
                clearHotspot("unavailable")
                teardownSpecifierRequest()
            }
        }
        hotspotCallback = cb
        try {
            cm.requestNetwork(request, cb, Handler(Looper.getMainLooper()))
            Log.i(TAG, "FIPS hotspot specifier request filed (SSID $HOTSPOT_SSID)")
        } catch (e: Exception) {
            Log.w(TAG, "hotspot requestNetwork failed", e)
            hotspotCallback = null
        }
    }

    private fun updateHotspot(network: Network, lp: LinkProperties?) {
        val la = lp?.linkAddresses?.firstOrNull { it.address is Inet4Address } ?: return
        val addr = la.address.hostAddress ?: return
        if (hotspotNetwork == network && hotspotAddr == addr &&
            hotspotPrefixLen == la.prefixLength
        ) return
        hotspotNetwork = network
        hotspotAddr = addr
        hotspotPrefixLen = la.prefixLength
        hotspotStatus = "$addr on $HOTSPOT_SSID"
        Log.i(TAG, "FIPS hotspot joined: $addr/${la.prefixLength}; rebinding node")
        stopScanKick()
        updateMulticastLock(currentUnderlying)
        rebindNode()
    }

    private fun clearHotspot(why: String) {
        if (hotspotNetwork == null) return
        hotspotNetwork = null
        hotspotAddr = null
        hotspotPrefixLen = 0
        hotspotStatus = null
        Log.i(TAG, "FIPS hotspot $why; rebinding node")
        updateMulticastLock(currentUnderlying)
        rebindNode()
        // A specifier session is one-shot: the platform never retries it, and
        // re-filing while the SSID is out of range pops the system picker
        // dialog over the app ("searching…") — so tear the dead request down
        // and let the scan watcher file a fresh one the next time a "!FIPS"
        // beacon is actually visible (kicking scans, since the system barely
        // scans on its own while connected). The suggestion path needs
        // nothing: the platform auto-rejoins suggestions on its own.
        teardownSpecifierRequest()
        if (hasFineLocation() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            startScanKick()
        }
    }

    /** Unregister the specifier request/callback (not the suggestion). */
    private fun teardownSpecifierRequest() {
        hotspotCallback?.let { cb ->
            try {
                connectivity?.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "hotspot specifier unregister failed", e)
            }
        }
        hotspotCallback = null
    }

    /** Full hotspot teardown: specifier, watchers, suggestion, state. */
    private fun stopHotspot() {
        teardownSpecifierRequest()
        wifiWatcher?.let { cb ->
            try {
                connectivity?.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "wifi watcher unregister failed", e)
            }
        }
        wifiWatcher = null
        scanWatcher?.let { cb ->
            try {
                applicationContext.getSystemService(WifiManager::class.java)
                    ?.unregisterScanResultsCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "scan watcher unregister failed", e)
            }
        }
        scanWatcher = null
        // Withdraw the suggestion so the phone doesn't keep auto-joining an
        // internet-less network while the mesh isn't even running.
        removeHotspotSuggestion()
        stopScanKick()
        hotspotNetwork = null
        hotspotAddr = null
        hotspotPrefixLen = 0
        hotspotStatus = null
    }

    /** Build and establish the TUN. `ipv6Clearnet` decides whether `::/0` is claimed. */
    private fun establishTunnel(address: String, ipv6Clearnet: Boolean): ParcelFileDescriptor? {
        val meshApps = prefs()
            .getStringSet(AppPickerActivity.KEY_MESH_APPS, emptySet()) ?: emptySet()
        return try {
            val builder = Builder()
                .setSession("FIPS Mesh")
                .setMtu(MESH_MTU)
                .addAddress(address, 128)          // mesh IPv6 address
                .addAddress(TUN_IPV4, 32)          // IPv4 source for clearnet
                // Capture everything for the selected apps: fd00::/8 goes to the
                // mesh, the rest reaches the userspace forwarder which sends it
                // out on protected sockets.
                .addRoute("fd00::", 8)
                .addRoute("0.0.0.0", 0)
                // DNS server = the fd00::/8 sentinel the pump intercepts (NOT our
                // own tun /128, which the kernel would deliver locally).
                .addDnsServer(FipsNative.dnsServer())
            // `::/0` only when the underlay can deliver it (see class doc).
            if (ipv6Clearnet) {
                builder.addRoute("::", 0)
            } else {
                // Keep the resolver asking AAAA: netd emulates AI_ADDRCONFIG
                // with a UDP connect() probe to 2000:: and skips AAAA queries
                // entirely when it fails — which kills `.fips` (AAAA-only
                // names). A /128 to the probe address flips that check while
                // claiming no real destination, so apps' global-IPv6 connects
                // still fail fast and fall back to IPv4.
                builder.addRoute("2000::", 128)
                // Chromium (WebView, so most browsers) runs its OWN AAAA
                // gate above netd: a UDP connect() probe to Google DNS,
                // cached 60 s. Without this route, `.fips` browsing dies
                // exactly one minute after landing on a v4-only underlay.
                // connect() alone sends no packets; an app genuinely
                // dialing this address gets captured and dropped, which
                // IPv6-capable apps treat as any unreachable v6 route.
                builder.addRoute("2001:4860:4860::8888", 128)
            }

            // Per-app split tunnel: only the chosen apps are captured; every
            // other app keeps the normal network untouched. With no selection,
            // capture only ourselves (a no-op) so nothing else is affected.
            if (meshApps.isEmpty()) {
                builder.addAllowedApplication(packageName)
            } else {
                for (pkg in meshApps) {
                    try {
                        builder.addAllowedApplication(pkg)
                    } catch (e: PackageManager.NameNotFoundException) {
                        Log.w(TAG, "mesh app not installed, skipping: $pkg")
                    }
                }
            }
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        }
    }

    /**
     * True when `network` has usable IPv6 internet: an IPv6 default route and
     * a global unicast address. Wi-Fi with SLAAC addresses but no default
     * route (expired RA) is common — addresses alone are not enough.
     */
    private fun hasIpv6Internet(network: Network?): Boolean {
        if (network == null) return false
        val lp = connectivity?.getLinkProperties(network) ?: return false
        val hasDefaultRoute = lp.routes.any { r ->
            r.destination.prefixLength == 0 && r.destination.address is Inet6Address
        }
        if (!hasDefaultRoute) return false
        return lp.linkAddresses.any { la ->
            val a = la.address
            a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress &&
                (a.address[0].toInt() and 0xfe) != 0xfc // exclude ULA (fc00::/7)
        }
    }

    private val availableNetworks = LinkedHashSet<Network>()

    /**
     * Watch the underlying (non-VPN) internet networks. On a switch
     * (Wi-Fi ↔ cellular) the node's UDP socket keeps a stale binding and the
     * mesh black-holes, so we update the tunnel's underlying network and ask
     * the engine to rebuild on the same fd (fresh, re-protected socket).
     *
     * `registerSystemDefaultNetworkCallback` would name the exact default, but
     * it's a `@SystemApi` gated on `NETWORK_SETTINGS`. Instead we track all
     * non-VPN internet networks (the request excludes VPN by default) and pick
     * a preferred one (Wi-Fi > Ethernet > cellular) — the same approach other
     * VPN apps use.
     */
    private fun registerNetworkMonitoring() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        connectivity = cm
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                synchronized(availableNetworks) { availableNetworks.add(network) }
                updateUnderlying()
            }
            override fun onLost(network: Network) {
                synchronized(availableNetworks) { availableNetworks.remove(network) }
                updateUnderlying()
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                // IPv6 can appear (late RA after Wi-Fi connect) or vanish on
                // the same network — re-evaluate the `::/0` decision.
                updateUnderlying()
            }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                // Validation (NET_CAPABILITY_VALIDATED) arrives here — the
                // moment the system actually moves its default network during
                // a hand-over. Cheap when nothing relevant changed:
                // onUnderlyingNetwork only rebinds on a real decision flip.
                updateUnderlying()
            }
        }
        networkCallback = cb
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            cm.registerNetworkCallback(req, cb, Handler(Looper.getMainLooper()))
        } catch (e: Exception) {
            Log.w(TAG, "registerNetworkCallback failed", e)
        }
    }

    /**
     * The non-VPN network we should egress on. Validated networks beat
     * unvalidated ones (a dying Wi-Fi keeps its transport for 10–30 s after it
     * stops passing traffic, while the OS default has already moved to the
     * validated cellular network — follow the OS), then Wi-Fi > Ethernet >
     * cellular.
     */
    private fun preferredUnderlying(): Network? {
        val cm = connectivity ?: return null
        val snapshot = synchronized(availableNetworks) { availableNetworks.toList() }
            .filter { it != hotspotNetwork } // never egress internet via "!FIPS"
        return snapshot.maxByOrNull { net ->
            val caps = cm.getNetworkCapabilities(net) ?: return@maxByOrNull 0
            val transport = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 2
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                else -> 0
            }
            val validated =
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            if (validated) transport + 4 else transport
        }
    }

    private fun updateUnderlying() {
        val network = preferredUnderlying() ?: return
        onUnderlyingNetwork(network)
    }

    private fun onUnderlyingNetwork(network: Network) {
        val previous = currentUnderlying
        // Point the tunnel's accounting/routing at the new underlying network
        // (skip the binder call on the frequent no-change capability ticks).
        if (previous != network) {
            try {
                setUnderlyingNetworks(arrayOf(network))
            } catch (e: Exception) {
                Log.w(TAG, "setUnderlyingNetworks failed", e)
            }
        }
        currentUnderlying = network
        updateMulticastLock(network)
        val wantIpv6 = hasIpv6Internet(network)
        when {
            previous == null -> {
                Log.i(TAG, "baseline underlying network: $network, ipv6=$wantIpv6")
                // The tunnel was established from `activeNetwork` before the
                // callback baseline; fix the routes if that guess was wrong.
                if (wantIpv6 != tunnelHasIpv6Clearnet) rebindNode()
            }
            previous == network && wantIpv6 == tunnelHasIpv6Clearnet -> {} // nothing to rebuild
            else -> {
                Log.i(
                    TAG,
                    "underlying network changed $previous -> $network (ipv6=$wantIpv6); rebinding node"
                )
                rebindNode()
            }
        }
    }

    /**
     * Request a node restart so its underlay sockets rebind on the current
     * network. A restart takes seconds while a hand-over emits callbacks for
     * many more, so requests are queued on [rebindRequested] and served by a
     * single worker that re-checks after every pass — the last callback in a
     * burst always results in a rebind against final network state (the old
     * drop-when-busy guard lost it, leaving the node bound to a dead network
     * until a manual reconnect).
     */
    private fun rebindNode() {
        rebindRequested.set(true)
        if (!rebinding.compareAndSet(false, true)) {
            Log.i(TAG, "rebind in flight; request queued")
            return
        }
        thread(name = "fips-rebind") {
            try {
                while (true) {
                    if (rebindRequested.get()) {
                        // Let the callback burst settle; everything that
                        // arrived up to here is covered by this pass.
                        Thread.sleep(REBIND_SETTLE_MS)
                        rebindRequested.set(false)
                        rebindOnce()
                        continue
                    }
                    rebinding.set(false)
                    // Close the race with a request that arrived after the
                    // check above but before we released the worker slot.
                    if (rebindRequested.get() && rebinding.compareAndSet(false, true)) continue
                    return@thread
                }
            } catch (t: Throwable) {
                Log.e(TAG, "rebind worker died", t)
                rebinding.set(false)
            }
        }
    }

    /**
     * One rebind pass. When the IPv6-clearnet decision no longer matches the
     * tunnel's routes, establish a replacement tunnel first (Android tears the
     * old session down when the new one comes up) and move the engine onto the
     * fresh fd.
     */
    private fun rebindOnce() {
        // Regenerate the config so the rebuilt node reflects current
        // per-network state (the FIPS Hotspot transport overlay). The nsec
        // is re-decrypted from the Keystore — it must not linger in a field.
        val config = try {
            ConfigStore.buildConfigJson(
                this, IdentityStore.getOrCreate(this), hotspotAddr, hotspotPrefixLen
            )
        } catch (e: Exception) {
            Log.e(TAG, "config rebuild failed; rebinding with previous config", e)
            ""
        }
        val wantIpv6 = hasIpv6Internet(currentUnderlying)
        if (wantIpv6 != tunnelHasIpv6Clearnet) {
            val address = meshAddress ?: return
            Log.i(TAG, "re-establishing tunnel, ipv6Clearnet=$wantIpv6")
            val fresh = establishTunnel(address, wantIpv6)
            if (fresh == null) {
                Log.e(TAG, "re-establish for route change failed; keeping old tunnel")
                return
            }
            val old = tunFd
            tunFd = fresh
            tunnelHasIpv6Clearnet = wantIpv6
            FipsNative.onNetworkChanged(fresh.fd, config)
            old?.close()
        } else {
            val fd = tunFd?.fd ?: return
            FipsNative.onNetworkChanged(fd, config)
        }
    }

    private fun unregisterNetworkMonitoring() {
        networkCallback?.let { cb ->
            try {
                connectivity?.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                Log.w(TAG, "unregisterNetworkCallback failed", e)
            }
        }
        networkCallback = null
        currentUnderlying = null
        synchronized(availableNetworks) { availableNetworks.clear() }
    }

    private fun shutdown() {
        stopHotspot()
        unregisterNetworkMonitoring()
        releaseMulticastLock()
        thread(name = "fips-disconnect") {
            FipsNative.stop()
            tunFd?.close()
            tunFd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        stopHotspot()
        unregisterNetworkMonitoring()
        releaseMulticastLock()
        FipsNative.stop()
        tunFd?.close()
        tunFd = null
        super.onDestroy()
    }

    override fun onRevoke() {
        // Another VPN took over or the user disabled us from settings.
        shutdown()
        super.onRevoke()
    }

    private fun startForegroundWithNotification(address: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "FIPS VPN", NotificationManager.IMPORTANCE_LOW)
        )
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("FIPS mesh connected")
            .setContentText(address)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // The `location` type lets the hotspot Wi-Fi watcher read SSIDs
            // (location-gated) while we run as a service; only legal to
            // declare at startForeground when the permission is granted.
            var types = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            if (hasFineLocation()) {
                types = types or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
            }
            startForeground(NOTIFICATION_ID, notification, types)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }
}
