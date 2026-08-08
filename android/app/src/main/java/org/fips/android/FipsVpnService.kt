package org.fips.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Owns the VpnService session and hands its TUN fd to the Rust engine.
 *
 * The tunnel claims only `fd00::/8` (the FIPS mesh range), so ordinary
 * traffic of other apps bypasses the VPN entirely — but their DNS goes to
 * our in-tunnel resolver (the node's own address), where the Rust shim
 * splits `.fips` names to the mesh responder and everything else upstream.
 */
class FipsVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "org.fips.android.CONNECT"
        const val ACTION_DISCONNECT = "org.fips.android.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_ADDRESS = "address"
        private const val TAG = "FipsVpnService"
        private const val CHANNEL_ID = "fips_vpn"
        private const val NOTIFICATION_ID = 1
        private const val MESH_MTU = 1280
    }

    private var tunFd: ParcelFileDescriptor? = null

    private var connectivity: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentUnderlying: Network? = null
    private val rebinding = AtomicBoolean(false)

    /** Called from Rust (JNI) for every underlay socket the node creates. */
    fun protectFd(fd: Int): Boolean = protect(fd)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                shutdown()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                val address = intent.getStringExtra(EXTRA_ADDRESS) ?: return START_NOT_STICKY
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
        val pfd = try {
            Builder()
                .setSession("FIPS Mesh")
                .setMtu(MESH_MTU)
                .addAddress(address, 128)
                .addRoute("fd00::", 8)
                // The DNS server must be a routed fd00::/8 sentinel the pump
                // sees on the fd — NOT `address` (our own tun /128), which the
                // kernel would deliver locally and never surface to the reader.
                .addDnsServer(FipsNative.dnsServer())
                .establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        }
        if (pfd == null) {
            Log.e(TAG, "VPN not prepared or establish() returned null")
            shutdown()
            return
        }
        tunFd = pfd

        val error = FipsNative.start(config, pfd.fd, this)
        if (error.isNotEmpty()) {
            Log.e(TAG, "engine start failed: $error")
            shutdown()
        } else {
            Log.i(TAG, "fips engine running, address $address")
            registerNetworkMonitoring()
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

    /** The non-VPN network we should egress on: Wi-Fi > Ethernet > cellular. */
    private fun preferredUnderlying(): Network? {
        val cm = connectivity ?: return null
        val snapshot = synchronized(availableNetworks) { availableNetworks.toList() }
        return snapshot.maxByOrNull { net ->
            val caps = cm.getNetworkCapabilities(net)
            when {
                caps == null -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 3
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 2
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                else -> 0
            }
        }
    }

    private fun updateUnderlying() {
        val network = preferredUnderlying() ?: return
        onUnderlyingNetwork(network)
    }

    private fun onUnderlyingNetwork(network: Network) {
        // Point the tunnel's accounting/routing at the new underlying network.
        try {
            setUnderlyingNetworks(arrayOf(network))
        } catch (e: Exception) {
            Log.w(TAG, "setUnderlyingNetworks failed", e)
        }

        val previous = currentUnderlying
        currentUnderlying = network
        when {
            previous == null -> Log.i(TAG, "baseline underlying network: $network")
            previous == network -> {} // same network — nothing to rebuild
            else -> {
                Log.i(TAG, "underlying network changed $previous -> $network; rebinding node")
                val fd = tunFd?.fd ?: return
                if (rebinding.compareAndSet(false, true)) {
                    thread(name = "fips-rebind") {
                        try {
                            FipsNative.onNetworkChanged(fd)
                        } finally {
                            rebinding.set(false)
                        }
                    }
                }
            }
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
