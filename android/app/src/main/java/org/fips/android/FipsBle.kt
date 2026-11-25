package org.fips.android

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * The Bluetooth radio fips drives (see `shim/src/ble.rs`): fips nodes in
 * radio range find each other by a BLE advert and link over an L2CAP channel,
 * with no network at all. fips decides what to dial and carries the traffic;
 * this class owns everything Android only gives an app — the advertiser, the
 * scanner and the sockets.
 *
 * **When the chip is used is decided here, for the battery.** fips asks for
 * scanning for as long as its transport runs and connects to every advert it
 * is shown. So:
 *
 * - Scanning runs only while it can help: the node has no link at all, or
 *   the app is on screen ([foreground]). With a link over Wi-Fi or mobile
 *   data there is nothing to look for, the scanner is off, and no advert
 *   reaches fips, so it makes no Bluetooth link either. Checked every
 *   [POLICY_MS] on a timer that does not run while the phone sleeps.
 * - A scan is filtered on the FIPS service UUID and low power, so matching
 *   happens in the Bluetooth controller and this process sleeps until a hit.
 * - Advertising is low power (about one advert a second) for as long as the
 *   radio is up: being found costs far less than looking.
 *
 * One instance per radio session. [shutdown] ends it for good; the service
 * makes a new one when Bluetooth comes back.
 */
@RequiresApi(Build.VERSION_CODES.Q)
@SuppressLint("MissingPermission") // checked in [usable]; a revocation is caught per call
class FipsBle(context: Context) : FipsNative.BleRadio {

    private val adapter: BluetoothAdapter? =
        context.getSystemService(BluetoothManager::class.java)?.adapter
    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()

    @Volatile private var closed = false
    private var server: BluetoothServerSocket? = null
    private var advertising = false
    private var scanWanted = false
    private var scanning = false

    /** Open channels by the id fips gave them. */
    private val channels = ConcurrentHashMap<Long, BluetoothSocket>()

    /**
     * Devices by address, from their adverts. A dial needs the scanner's own
     * `BluetoothDevice`: it knows the address is a random one, which
     * `getRemoteDevice` would assume it is not.
     */
    private val seen = object : LinkedHashMap<String, BluetoothDevice>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, BluetoothDevice>) = size > MAX_SEEN
    }

    /** When each address was last passed on to fips ([REPORT_MS]). */
    private val reported = HashMap<String, Long>()

    init {
        current = this
    }

    // ---- fips's commands ---------------------------------------------------

    override fun bleListen(): Int = synchronized(lock) {
        if (closed) return 0
        server?.let { return it.psm }
        val socket = try {
            adapter?.listenUsingInsecureL2capChannel()
        } catch (e: Exception) { // IOException, SecurityException
            Log.w(TAG, "L2CAP listen failed: $e")
            null
        } ?: return 0
        server = socket
        thread(name = "fips-ble-accept", isDaemon = true) { acceptLoop(socket) }
        Log.i(TAG, "listening, PSM ${socket.psm}")
        socket.psm
    }

    override fun bleConnect(connectId: Long, addr: ByteArray, psm: Int) {
        thread(name = "fips-ble-dial", isDaemon = true) {
            var socket: BluetoothSocket? = null
            val ok = try {
                val mac = macString(addr)
                val device = synchronized(lock) { seen[mac] } ?: adapter!!.getRemoteDevice(mac)
                socket = device.createInsecureL2capChannel(psm)
                socket.connect()
                !closed
            } catch (e: Exception) {
                Log.d(TAG, "dial failed: $e")
                false
            }
            // Always answered: fips holds a slot for this dial until then.
            val chId = FipsNative.bleConnectResult(
                connectId, ok, addr,
                socket?.takeIf { ok }?.maxTransmitPacketSize ?: 0,
                socket?.takeIf { ok }?.maxReceivePacketSize ?: 0,
            )
            if (chId != 0L && socket != null) startChannel(chId, socket) else socket?.closeQuietly()
        }
    }

    override fun bleStartAdvertising(psm: Int) {
        main.post {
            synchronized(lock) {
                if (closed) return@post
                val advertiser = adapter?.bluetoothLeAdvertiser ?: return@post
                if (advertising) runCatching { advertiser.stopAdvertising(advertiseCallback) }
                val settings = AdvertiseSettings.Builder()
                    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                    .setConnectable(true)
                    .build()
                // The whole advert: flags (3) + the service UUID (18) + the
                // listener's PSM as service data (6) = 27 of 31 bytes. There
                // is no room for a name, and the scan response is not used:
                // a peer must learn the PSM without asking.
                val data = AdvertiseData.Builder()
                    .setIncludeDeviceName(false)
                    .setIncludeTxPowerLevel(false)
                    .addServiceUuid(SERVICE)
                    .addServiceData(PSM_DATA, byteArrayOf(psm.toByte(), (psm shr 8).toByte()))
                    .build()
                try {
                    advertiser.startAdvertising(settings, data, advertiseCallback)
                    advertising = true
                } catch (e: Exception) {
                    Log.w(TAG, "advertising failed: $e")
                }
            }
        }
    }

    override fun bleStopAdvertising() {
        main.post {
            synchronized(lock) {
                if (!advertising) return@post
                advertising = false
                runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
            }
        }
    }

    override fun bleStartScanning() {
        synchronized(lock) { scanWanted = true }
        main.post(policy)
    }

    override fun bleStopScanning() {
        synchronized(lock) { scanWanted = false }
        main.post(policy)
    }

    override fun bleCloseChannel(chId: Long) {
        // Closing the socket ends its reader, which reports the close.
        channels.remove(chId)?.closeQuietly()
    }

    // ---- when to scan ------------------------------------------------------

    private val policy = object : Runnable {
        override fun run() {
            main.removeCallbacks(this)
            if (closed) return
            val want = synchronized(lock) { scanWanted } && (foreground || !nodeHasLink())
            setScanning(want)
            // uptimeMillis: this does not fire, or wake anything, in sleep.
            main.postDelayed(this, POLICY_MS)
        }
    }

    private fun nodeHasLink(): Boolean = try {
        (JSONObject(FipsNative.status()).optJSONObject("status")?.optInt("link_count", 0) ?: 0) > 0
    } catch (e: Exception) {
        false
    }

    private fun setScanning(on: Boolean) {
        synchronized(lock) {
            if (on == scanning) return
            val scanner = adapter?.bluetoothLeScanner ?: return
            try {
                if (on) {
                    val filter = ScanFilter.Builder().setServiceUuid(SERVICE).build()
                    val settings = ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                        .build()
                    scanner.startScan(listOf(filter), settings, scanCallback)
                } else {
                    scanner.stopScan(scanCallback)
                }
                scanning = on
                Log.i(TAG, if (on) "scanning for fips nodes" else "scan stopped")
            } catch (e: Exception) {
                Log.w(TAG, "scan ${if (on) "start" else "stop"} failed: $e")
            }
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val mac = result.device.address
            val addr = macBytes(mac) ?: return
            val now = SystemClock.elapsedRealtime()
            synchronized(lock) {
                if (closed || !scanning) return
                seen[mac] = result.device
                // A neighbour adverts every second; fips needs to hear of it
                // far less often (it keeps its own retry timer).
                if (now - (reported[mac] ?: 0L) < REPORT_MS) return
                if (reported.size >= MAX_SEEN) reported.clear()
                reported[mac] = now
            }
            val data = result.scanRecord?.getServiceData(PSM_DATA)
            val psm = if (data != null && data.size >= 2) {
                (data[0].toInt() and 0xff) or ((data[1].toInt() and 0xff) shl 8)
            } else 0
            FipsNative.bleScan(addr, psm, result.rssi)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "scan failed: $errorCode")
            synchronized(lock) { scanning = false }
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "advertising failed: $errorCode")
            synchronized(lock) { advertising = false }
        }
    }

    // ---- channels ----------------------------------------------------------

    private fun acceptLoop(socket: BluetoothServerSocket) {
        while (!closed) {
            val peer = try {
                socket.accept()
            } catch (e: IOException) {
                break // closed by shutdown, or Bluetooth went off
            }
            val addr = macBytes(peer.remoteDevice.address)
            val chId = if (addr == null) 0L else FipsNative.bleInbound(
                addr, peer.maxTransmitPacketSize, peer.maxReceivePacketSize,
            )
            if (chId != 0L) startChannel(chId, peer) else peer.closeQuietly()
        }
    }

    /**
     * One reader and one writer thread per channel. Both block — the reader
     * in the socket, the writer in the shim until fips has a packet — so an
     * idle link costs no wake-ups of its own.
     */
    private fun startChannel(chId: Long, socket: BluetoothSocket) {
        channels[chId] = socket
        if (closed) {
            endChannel(chId, socket)
            return
        }
        thread(name = "fips-ble-rx", isDaemon = true) {
            val buf = ByteArray(maxOf(socket.maxReceivePacketSize, MIN_READ))
            try {
                val input = socket.inputStream
                while (true) {
                    val n = input.read(buf)
                    if (n < 0 || !FipsNative.bleRecv(chId, buf, n)) break
                }
            } catch (e: IOException) {
                // the peer left, or the socket was closed under us
            }
            endChannel(chId, socket)
        }
        thread(name = "fips-ble-tx", isDaemon = true) {
            try {
                val output = socket.outputStream
                while (true) {
                    val packet = FipsNative.bleNextSend(chId, SEND_WAIT_MS)
                    if (packet != null) {
                        output.write(packet)
                    } else if (!FipsNative.bleChannelOpen(chId)) {
                        break
                    }
                }
            } catch (e: IOException) {
                // as above
            }
            endChannel(chId, socket)
        }
    }

    private fun endChannel(chId: Long, socket: BluetoothSocket) {
        channels.remove(chId, socket)
        socket.closeQuietly()
        FipsNative.bleChannelClosed(chId)
    }

    /** End this radio: nothing on the air, every socket closed. */
    fun shutdown() {
        synchronized(lock) {
            if (closed) return
            closed = true
            scanWanted = false
        }
        if (current === this) current = null
        main.removeCallbacks(policy)
        setScanning(false)
        synchronized(lock) {
            if (advertising) {
                advertising = false
                runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
            }
            runCatching { server?.close() }
            server = null
        }
        channels.values.toList().forEach { it.closeQuietly() }
    }

    private fun BluetoothSocket.closeQuietly() {
        runCatching { close() }
    }

    companion object {
        private const val TAG = "FipsBle"

        /** fips's BLE service (`fips::transport::ble`, `FIPS_SERVICE_UUID`). */
        private val SERVICE = ParcelUuid(UUID.fromString("9c90b790-2cc5-42c0-9f87-c9cc40648f4c"))

        /** The 16-bit UUID 0x9C90 keying the PSM in the advert's service data. */
        private val PSM_DATA = ParcelUuid(UUID.fromString("00009c90-0000-1000-8000-00805f9b34fb"))

        /** How often the scan decision is looked at again. */
        private const val POLICY_MS = 30_000L

        /** One advert per address is passed to fips at most this often. */
        private const val REPORT_MS = 10_000L
        private const val MAX_SEEN = 64

        /** The writer's wait for a packet; a closed channel ends it sooner. */
        private const val SEND_WAIT_MS = 10_000
        private const val MIN_READ = 2048

        /**
         * The app is on screen: look for neighbours whatever the node has,
         * so opening the app is how to ask for a Bluetooth link.
         */
        @Volatile var foreground = false
            private set

        /** The radio in use, for [setForeground]. */
        @Volatile private var current: FipsBle? = null

        /** The app came on screen or left it; decide about scanning now. */
        fun setForeground(on: Boolean) {
            foreground = on
            current?.let { it.main.post(it.policy) }
        }

        /** L2CAP channels exist from Android 10. */
        fun supported(context: Context) =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)

        /** The runtime permissions the radio needs on this Android version. */
        fun permissions(): Array<String> =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                arrayOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_CONNECT,
                )
            } else {
                // Before Android 12 a BLE scan is gated by location.
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }

        fun granted(context: Context) = permissions().all {
            context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }

        /** Supported, permitted, and Bluetooth is switched on. */
        fun usable(context: Context): Boolean {
            if (!supported(context) || !granted(context)) return false
            return try {
                context.getSystemService(BluetoothManager::class.java)?.adapter?.isEnabled == true
            } catch (e: SecurityException) {
                false
            }
        }

        private fun macString(addr: ByteArray) =
            addr.joinToString(":") { "%02X".format(it.toInt() and 0xff) }

        private fun macBytes(mac: String): ByteArray? {
            val parts = mac.split(':')
            if (parts.size != 6) return null
            return try {
                ByteArray(6) { parts[it].toInt(16).toByte() }
            } catch (e: NumberFormatException) {
                null
            }
        }
    }
}
