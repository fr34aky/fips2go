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
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.Inet6Address
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
        if (onWifi && !lock.isHeld) {
            lock.acquire()
            Log.i(TAG, "multicast lock acquired (mDNS on Wi-Fi)")
        } else if (!onWifi && lock.isHeld) {
            lock.release()
            Log.i(TAG, "multicast lock released (underlay not Wi-Fi)")
        }
    }

    private fun releaseMulticastLock() {
        multicastLock?.takeIf { it.isHeld }?.release()
        multicastLock = null
    }

    private fun prefs() = getSharedPreferences("fips", Context.MODE_PRIVATE)

    /** Called from Rust (JNI) for every underlay socket the node creates. */
    fun protectFd(fd: Int): Boolean = protect(fd)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        if (prefs().getBoolean(ConfigStore.LAN_MDNS, false)) {
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
        }
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
            FipsNative.onNetworkChanged(fresh.fd)
            old?.close()
        } else {
            val fd = tunFd?.fd ?: return
            FipsNative.onNetworkChanged(fd)
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
            startForeground(
                NOTIFICATION_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }
}
