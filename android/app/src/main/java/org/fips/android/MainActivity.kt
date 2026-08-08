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
        findViewById<Button>(R.id.pick_apps).setOnClickListener {
            startActivity(Intent(this, AppPickerActivity::class.java))
        }
        findViewById<Button>(R.id.regenerate).setOnClickListener {
            confirmRegenerate()
        }
    }

    override fun onStart() {
        super.onStart()
        val n = prefs().getStringSet(AppPickerActivity.KEY_MESH_APPS, emptySet())?.size ?: 0
        findViewById<Button>(R.id.pick_apps).text =
            if (n == 0) "Select mesh apps (none — all apps stay off the mesh)"
            else "Select mesh apps ($n selected)"
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
        // Decrypts (or creates + migrates) the Keystore-protected nsec.
        val nsec = IdentityStore.getOrCreate(this)
        showIdentity(JSONObject(FipsNative.deriveIdentity(nsec)))
    }

    /** Update the displayed npub/address (the nsec is held by IdentityStore). */
    private fun showIdentity(info: JSONObject) {
        npub = info.getString("npub")
        address = info.getString("address")
        identityView.text = "$npub\n$address"
    }

    private fun confirmRegenerate() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Regenerate identity?")
            .setMessage(
                "This creates a new node identity (npub and .fips address). " +
                    "The current identity is permanently replaced. Disconnect first if connected."
            )
            .setPositiveButton("Regenerate") { _, _ ->
                val nsec = IdentityStore.regenerate(this)
                showIdentity(JSONObject(FipsNative.deriveIdentity(nsec)))
            }
            .setNegativeButton("Cancel", null)
            .show()
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

    private fun startVpn() {
        // No config/nsec in the Intent — the service reads peer prefs and
        // decrypts the nsec from the Keystore itself.
        val intent = Intent(this, FipsVpnService::class.java)
            .setAction(FipsVpnService.ACTION_CONNECT)
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
