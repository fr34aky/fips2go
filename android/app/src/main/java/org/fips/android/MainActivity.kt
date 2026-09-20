package org.fips.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
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

    /**
     * Pre-flight steps for a connect, run STRICTLY ONE AT A TIME.
     *
     * They used to be fired back-to-back in a single call stack: none waited
     * for the one before, so Android queued three dialogs/Activities at once
     * and stacked them in whatever order it liked — the battery-optimisation
     * screen could land on top of the VPN consent and swallow the tap, and the
     * connect silently did nothing. Each step now resumes [advanceConnect] from
     * its own result callback.
     *
     * Only [VPN_CONSENT] is actually required to bring the tunnel up. The
     * notification prompt is deliberately last, after the tunnel has started —
     * it only governs whether the foreground-service notification is visible —
     * and the battery-optimisation exemption left this flow entirely for a
     * dismissible card on Overview.
     */
    private enum class Gate { HOTSPOT_LOCATION, VPN_CONSENT, NOTIFICATIONS }

    /** Gates already offered during THIS connect attempt; stops re-asking a
     *  gate the user just declined, since a declined permission still reads as
     *  "not granted" and would otherwise be offered forever. */
    private val attemptedGates = mutableSetOf<Gate>()
    private var vpnStarted = false

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                vpnStarted = true
                startVpn()
                advanceConnect()
            }
            // Declined: the tunnel cannot come up, so the chain stops here.
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { advanceConnect() }

    /**
     * Fine location for FIPS Hotspot auto-join. Whatever the answer, the
     * connect flow continues — a denial only degrades the hotspot feature.
     */
    private val hotspotLocationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { advanceConnect() }

    /** Begin the connect flow (consent + permissions), then start the VPN. */
    fun connect() {
        attemptedGates.clear()
        vpnStarted = false
        advanceConnect()
    }

    /**
     * Run the first outstanding gate and return; whatever handles it calls
     * back here. Re-derived from scratch each time rather than tracked as a
     * position, so returning from a system screen that destroyed this Activity
     * resumes correctly.
     */
    private fun advanceConnect() {
        if (isFinishing || isDestroyed) return

        // 1. Explain the hotspot location permission before Android asks.
        if (Gate.HOTSPOT_LOCATION !in attemptedGates &&
            ConfigStore.hotspotEnabled(this) && HotspotLocation.shouldAsk(this)
        ) {
            attemptedGates += Gate.HOTSPOT_LOCATION
            HotspotLocation.markAsked(this)
            HotspotLocation.explain(
                this,
                onContinue = {
                    hotspotLocationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION)
                },
                onDismiss = { advanceConnect() },
            )
            return
        }

        // 2. VPN consent — the only step the tunnel genuinely needs.
        if (!vpnStarted) {
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                if (Gate.VPN_CONSENT in attemptedGates) return // declined; stop
                attemptedGates += Gate.VPN_CONSENT
                vpnPermission.launch(prepare)
                return
            }
            vpnStarted = true
            startVpn()
        }

        // 3. Notifications, once the tunnel is on its way up.
        if (Gate.NOTIFICATIONS !in attemptedGates &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            attemptedGates += Gate.NOTIFICATIONS
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
    }

    fun disconnect() {
        connectStartedAt = 0L
        startService(
            Intent(this, FipsVpnService::class.java).setAction(FipsVpnService.ACTION_DISCONNECT)
        )
    }

    private fun startVpn() {
        connectStartedAt = SystemClock.elapsedRealtime()
        startForegroundService(
            Intent(this, FipsVpnService::class.java).setAction(FipsVpnService.ACTION_CONNECT)
        )
    }

    /**
     * Bridges the moment between the tap and the service picking the intent
     * up (`FipsVpnService.tunnelActive`, which then carries the state until
     * the node reports running). Overview's single toggle needs it: in that
     * gap a second tap has to mean "cancel", not "connect again". Static so a
     * rotation mid-connect keeps it; a UI hint only, deliberately short, so a
     * start the service rejected does not read as "Connecting…" for long.
     */
    companion object {
        private const val CONNECT_GRACE_MS = 3_000L

        @Volatile private var connectStartedAt = 0L

        fun isConnecting(): Boolean {
            val since = connectStartedAt
            return since != 0L && SystemClock.elapsedRealtime() - since < CONNECT_GRACE_MS
        }

        /** The node reported running (or was stopped): the gap is over. */
        fun connectSettled() {
            connectStartedAt = 0L
        }
    }
}
