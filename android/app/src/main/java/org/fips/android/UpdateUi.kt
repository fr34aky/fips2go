package org.fips.android

import android.content.Intent
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import java.io.File
import kotlin.concurrent.thread

/**
 * The user-facing half of the updater, shared by the manual "Check for
 * updates" button (Diagnostics) and the automatic check on app start:
 * offer dialog → verified download → hand-off to the system installer.
 *
 * Downloading is fine while connected (the app itself is not routed through
 * the tunnel), but the install is only launched with the VPN down —
 * replacing the app kills the service mid-tunnel and can leak netd routing
 * state otherwise.
 */
object UpdateUi {

    /** Offer [update] with install / postpone choices. */
    fun offer(activity: AppCompatActivity, root: View, update: Updater.Update) {
        MaterialAlertDialogBuilder(activity)
            .setTitle("Update available: v${update.version}")
            .setMessage(
                update.notes.lineSequence().take(12).joinToString("\n").trim() +
                    "\n\nThe download is verified against the release checksum. " +
                    "Installing keeps your identity and settings, but the VPN " +
                    "must be disconnected first."
            )
            .setPositiveButton("Download & install") { _, _ ->
                downloadAndInstall(activity, root, update)
            }
            .setNegativeButton("Later", null)
            .show()
    }

    fun downloadAndInstall(activity: AppCompatActivity, root: View, update: Updater.Update) {
        Snackbar.make(root, "Downloading v${update.version}…", Snackbar.LENGTH_SHORT).show()
        thread {
            val result = runCatching { Updater.fetch(activity.applicationContext, update) }
            activity.runOnUiThread {
                if (activity.isFinishing || activity.isDestroyed) return@runOnUiThread
                result.fold(
                    onSuccess = { apk -> launchInstall(activity, update, apk) },
                    onFailure = {
                        Snackbar.make(root, "Download failed: ${it.message}", Snackbar.LENGTH_LONG)
                            .show()
                    },
                )
            }
        }
    }

    private fun launchInstall(activity: AppCompatActivity, update: Updater.Update, apk: File) {
        if (FipsNative.isRunning()) {
            MaterialAlertDialogBuilder(activity)
                .setTitle("Disconnect first")
                .setMessage(
                    "v${update.version} is downloaded and verified. Disconnect " +
                        "the VPN, then check for updates again to install " +
                        "(the download is kept)."
                )
                .setPositiveButton("OK", null)
                .show()
            return
        }
        val uri = FileProvider.getUriForFile(
            activity, "org.fips.android.fileprovider", apk
        )
        activity.startActivity(
            Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        )
    }
}
