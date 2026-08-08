package org.fips.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
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
                .addDnsServer(address)
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
        }
    }

    private fun shutdown() {
        thread(name = "fips-disconnect") {
            FipsNative.stop()
            tunFd?.close()
            tunFd = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
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
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
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
