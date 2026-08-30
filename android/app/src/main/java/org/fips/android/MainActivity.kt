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
import com.google.android.material.dialog.MaterialAlertDialogBuilder
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
        // Before anything reads prefs: a fresh install is fully configured
        // from here on, so the user can connect without visiting Settings.
        ConfigStore.applyDefaults(this)

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
        if (!ConfigStore.prefs(this).getBoolean(ConfigStore.AUTO_UPDATE, ConfigStore.DEF_AUTO_UPDATE)) return
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

    /**
     * Fine location for FIPS Hotspot auto-join. Whatever the answer, the
     * connect flow continues — a denial only degrades the hotspot feature to
     * joining once per connect.
     */
    private val hotspotLocationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { continueConnect() }

    /** Begin the connect flow (consent + permissions), then start the VPN. */
    fun connect() {
        // The hotspot rationale goes first: the two calls below raise a system
        // permission dialog and a system settings screen, and our own dialog
        // would end up stacked behind them on a first run.
        if (askHotspotLocationIfNeeded()) return
        continueConnect()
    }

    private fun continueConnect() {
        requestNotificationsIfNeeded()
        requestBatteryExemptionIfNeeded()
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else startVpn()
    }

    /**
     * FIPS Hotspot is on by default, and Android hides Wi-Fi names (so the
     * "!FIPS" auto-join cannot work) without fine location. Settings only asks
     * when that page is opened, which a user who never configures anything
     * never does — so explain and ask once, on the first connect.
     *
     * Returns true when it took over the flow; [continueConnect] then runs from
     * the permission result or the "Not now" button. Asked at most once ever:
     * the toggle's own listener in Settings covers a later change of mind.
     */
    private fun askHotspotLocationIfNeeded(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return false
        val prefs = ConfigStore.prefs(this)
        if (!ConfigStore.hotspotEnabled(this)) return false
        if (prefs.getBoolean(ConfigStore.ASKED_HOTSPOT_LOCATION, false)) return false
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        prefs.edit().putBoolean(ConfigStore.ASKED_HOTSPOT_LOCATION, true).apply()
        MaterialAlertDialogBuilder(this)
            .setTitle("Find nearby FIPS hotspots?")
            .setMessage(
                "FIPS can auto-join open \u201c!FIPS\u201d Wi-Fi hotspots to reach nearby " +
                    "peers. Android requires the location permission to see Wi-Fi names.\n\n" +
                    "Your internet stays on your normal network, and your location is never " +
                    "stored or sent anywhere. You can turn this off in Settings."
            )
            .setPositiveButton("Continue") { _, _ ->
                hotspotLocationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION)
            }
            .setNegativeButton("Not now") { _, _ -> continueConnect() }
            .setOnCancelListener { continueConnect() }
            .show()
        return true
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
