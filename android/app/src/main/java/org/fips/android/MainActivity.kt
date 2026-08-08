package org.fips.android

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var identityView: TextView
    private lateinit var statusView: TextView
    private lateinit var peerNpub: EditText
    private lateinit var peerEndpoint: EditText
    private lateinit var nostrSwitch: Switch

    private var npub = ""
    private var address = ""

    private val statusPoller = Handler(Looper.getMainLooper())

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpn()
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        identityView = findViewById(R.id.identity)
        statusView = findViewById(R.id.status)
        peerNpub = findViewById(R.id.peer_npub)
        peerEndpoint = findViewById(R.id.peer_endpoint)
        nostrSwitch = findViewById(R.id.nostr_switch)

        ensureIdentity()
        loadPeerPrefs()

        findViewById<Button>(R.id.connect).setOnClickListener {
            savePeerPrefs()
            requestNotificationsIfNeeded()
            val prepare = VpnService.prepare(this)
            if (prepare != null) vpnPermission.launch(prepare) else startVpn()
        }
        findViewById<Button>(R.id.disconnect).setOnClickListener {
            startService(
                Intent(this, FipsVpnService::class.java)
                    .setAction(FipsVpnService.ACTION_DISCONNECT)
            )
        }
    }

    override fun onResume() {
        super.onResume()
        statusPoller.post(pollStatus)
    }

    override fun onPause() {
        statusPoller.removeCallbacks(pollStatus)
        super.onPause()
    }

    private val pollStatus = object : Runnable {
        override fun run() {
            statusView.text = renderStatus()
            statusPoller.postDelayed(this, 2000)
        }
    }

    private fun renderStatus(): String {
        return try {
            val status = JSONObject(FipsNative.status())
            if (!status.optBoolean("running")) return "Disconnected"
            val detail = status.optJSONObject("status")
            buildString {
                append("Connected\n")
                detail?.let {
                    it.optInt("mesh_size", -1).takeIf { n -> n >= 0 }
                        ?.let { n -> append("mesh size: $n\n") }
                    append(it.toString(2))
                }
            }
        } catch (e: Exception) {
            "status error: ${e.message}"
        }
    }

    private fun prefs() = getSharedPreferences("fips", Context.MODE_PRIVATE)

    private fun ensureIdentity() {
        val stored = prefs().getString("nsec", "") ?: ""
        val info = JSONObject(FipsNative.deriveIdentity(stored))
        if (info.has("error")) {
            // Stored key unusable — regenerate rather than brick the app.
            val fresh = JSONObject(FipsNative.deriveIdentity(""))
            applyIdentity(fresh)
        } else {
            applyIdentity(info)
        }
    }

    private fun applyIdentity(info: JSONObject) {
        npub = info.getString("npub")
        address = info.getString("address")
        prefs().edit().putString("nsec", info.getString("nsec")).apply()
        identityView.text = "$npub\n$address"
    }

    private fun loadPeerPrefs() {
        peerNpub.setText(prefs().getString("peer_npub", ""))
        peerEndpoint.setText(prefs().getString("peer_endpoint", ""))
        nostrSwitch.isChecked = prefs().getBoolean("nostr", false)
    }

    private fun savePeerPrefs() {
        prefs().edit()
            .putString("peer_npub", peerNpub.text.toString().trim())
            .putString("peer_endpoint", peerEndpoint.text.toString().trim())
            .putBoolean("nostr", nostrSwitch.isChecked)
            .apply()
    }

    private fun buildConfig(): String {
        val peers = JSONArray()
        val npubText = peerNpub.text.toString().trim()
        val endpointText = peerEndpoint.text.toString().trim()
        if (npubText.isNotEmpty() && endpointText.isNotEmpty()) {
            peers.put(
                JSONObject()
                    .put("npub", npubText)
                    .put("endpoint", endpointText)
                    .put("transport", "udp")
            )
        }
        return JSONObject()
            .put("nsec", prefs().getString("nsec", ""))
            .put("peers", peers)
            .put("enable_nostr", nostrSwitch.isChecked)
            .put("log_level", "info")
            .toString()
    }

    private fun startVpn() {
        val intent = Intent(this, FipsVpnService::class.java)
            .setAction(FipsVpnService.ACTION_CONNECT)
            .putExtra(FipsVpnService.EXTRA_CONFIG, buildConfig())
            .putExtra(FipsVpnService.EXTRA_ADDRESS, address)
        startForegroundService(intent)
    }

    private fun requestNotificationsIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
