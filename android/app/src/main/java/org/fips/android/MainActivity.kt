package org.fips.android

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlin.concurrent.thread

/**
 * Host activity: a Material toolbar + bottom navigation over three pages
 * (Overview, Settings, Diagnostics). Owns the connect/disconnect flow because
 * it needs the VPN-consent and permission activity-results.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById<Toolbar>(R.id.toolbar))

        val nav = findViewById<BottomNavigationView>(R.id.bottom_nav)
        nav.setOnItemSelectedListener { item ->
            // Leaving Settings replaces the fragment, dropping unsaved edits;
            // let it confirm first. On Save/Discard it re-selects the target
            // tab, which re-enters this listener with a clean state.
            val current = supportFragmentManager.findFragmentById(R.id.fragment_container)
            if (current is SettingsFragment && item.itemId != R.id.nav_settings &&
                current.interceptUnsaved { nav.selectedItemId = item.itemId }
            ) {
                return@setOnItemSelectedListener false
            }
            val fragment: Fragment = when (item.itemId) {
                R.id.nav_settings -> SettingsFragment()
                R.id.nav_troubleshoot -> TroubleshootFragment()
                else -> OverviewFragment()
            }
            supportFragmentManager.beginTransaction()
                .replace(R.id.fragment_container, fragment)
                .commit()
            true
        }
        if (savedInstanceState == null) {
            nav.selectedItemId = R.id.nav_overview
            autoUpdateCheck()
        }
    }

    /**
     * Silent update check on app start (not on rotation/recreation), gated by
     * the Settings toggle. A found release gets the shared install-or-later
     * dialog; failures stay in the log — this is a background convenience,
     * and Diagnostics' manual "Check for updates" keeps working either way.
     */
    private fun autoUpdateCheck() {
        if (!ConfigStore.prefs(this).getBoolean(ConfigStore.AUTO_UPDATE, true)) return
        val current = packageManager.getPackageInfo(packageName, 0).versionName ?: return
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: return
        thread(name = "fips-update-check") {
            val result = runCatching { Updater.check(current, abi) }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                result.fold(
                    onSuccess = { update ->
                        if (update != null) {
                            UpdateUi.offer(this, findViewById(R.id.fragment_container), update)
                        }
                    },
                    onFailure = { Log.i("MainActivity", "auto update check failed: ${it.message}") },
                )
            }
        }
    }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) startVpn()
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    /** Begin the connect flow (consent + permissions), then start the VPN. */
    fun connect() {
        requestNotificationsIfNeeded()
        requestBatteryExemptionIfNeeded()
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else startVpn()
    }

    fun disconnect() {
        startService(
            Intent(this, FipsVpnService::class.java).setAction(FipsVpnService.ACTION_DISCONNECT)
        )
    }

    private fun startVpn() {
        startForegroundService(
            Intent(this, FipsVpnService::class.java).setAction(FipsVpnService.ACTION_CONNECT)
        )
    }

    private fun requestNotificationsIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /**
     * A long-lived VPN needs a battery-optimization exemption or Doze/App
     * Standby freezes the service and drops the mesh. No-op if already exempt.
     */
    private fun requestBatteryExemptionIfNeeded() {
        val pm = getSystemService(PowerManager::class.java) ?: return
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        try {
            @SuppressLint("BatteryLife")
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                .setData(Uri.parse("package:$packageName"))
            startActivity(intent)
        } catch (e: Exception) {
            Log.w("MainActivity", "battery-optimization request failed", e)
        }
    }
}
