package org.fips.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.view.View
import com.google.android.material.snackbar.Snackbar

/** Small UI helpers shared by the pages. */
object Ui {

    /**
     * Snackbar anchored above the bottom navigation. A plain Snackbar attaches
     * to the CoordinatorLayout's bottom edge, which is where the navigation
     * bar sits — it covered the tabs for as long as it was showing.
     */
    fun snack(anchor: View, message: String, long: Boolean = false) {
        val bar = Snackbar.make(
            anchor, message, if (long) Snackbar.LENGTH_LONG else Snackbar.LENGTH_SHORT
        )
        anchor.rootView.findViewById<View>(R.id.bottom_nav)?.let { bar.anchorView = it }
        bar.show()
    }

    /**
     * Copy a NON-secret value (npub, address, logs). Android 13+ shows its own
     * "copied" confirmation, so ours would only stack a second one on top.
     * The nsec does not come through here — see OverviewFragment.copySecret.
     */
    fun copy(anchor: View, label: String, text: CharSequence, confirmation: String) {
        val cm = anchor.context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) snack(anchor, confirmation)
    }
}
