package org.fips.android

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/**
 * The fine-location permission the FIPS Hotspot needs, and the one-time
 * explanation shown before Android's own prompt.
 *
 * The permission is only ever requested behind this rationale. FIPS Hotspot
 * defaults on, so an unexplained system location dialog would otherwise be
 * the first thing a new user sees — asking for location in a mesh VPN needs
 * a reason attached. Both entry points (first connect, and opening Settings
 * with the toggle already on) share the text and the one-shot flag, so the
 * user is asked once, not once per screen.
 */
object HotspotLocation {

    /** The hotspot feature exists at all on this OS version. */
    fun supported() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    fun granted(context: Context) =
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    fun alreadyAsked(context: Context) =
        ConfigStore.prefs(context).getBoolean(ConfigStore.ASKED_HOTSPOT_LOCATION, false)

    fun markAsked(context: Context) {
        ConfigStore.prefs(context).edit()
            .putBoolean(ConfigStore.ASKED_HOTSPOT_LOCATION, true).apply()
    }

    /**
     * True when it is worth explaining and asking: the feature works here,
     * the permission is missing, and we have not already used our one shot.
     */
    fun shouldAsk(context: Context) =
        supported() && !granted(context) && !alreadyAsked(context)

    /**
     * Show the rationale. [onContinue] runs on "Continue" and should launch
     * the system permission prompt; [onDismiss] runs on "Not now" or a
     * back-press, and must carry on with whatever the caller was doing.
     */
    fun explain(context: Context, onContinue: () -> Unit, onDismiss: () -> Unit = {}) {
        MaterialAlertDialogBuilder(context)
            .setTitle("Find nearby FIPS hotspots?")
            .setMessage(
                "FIPS can auto-join open “!FIPS” Wi-Fi hotspots to reach nearby " +
                    "peers. Android requires the location permission to see Wi-Fi names.\n\n" +
                    "Your internet stays on your normal network, and your location is never " +
                    "stored or sent anywhere. You can turn this off in Settings."
            )
            .setPositiveButton("Continue") { _, _ -> onContinue() }
            .setNegativeButton("Not now") { _, _ -> onDismiss() }
            .setOnCancelListener { onDismiss() }
            .show()
    }
}
