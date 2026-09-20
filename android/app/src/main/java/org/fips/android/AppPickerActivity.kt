package org.fips.android

import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.appbar.MaterialToolbar

/**
 * Lets the user pick which apps route through the FIPS mesh (VpnService
 * `addAllowedApplication`). Only selected apps are captured — mesh traffic
 * goes through the tunnel and their other traffic is forwarded back out;
 * every other app on the phone is left on the normal network untouched.
 *
 * The selection is persisted as a package-name set in the shared prefs the
 * service reads at connect time. Every toggle is written immediately: the
 * screen used to persist only on an explicit Save, and leaving it with Back
 * silently discarded the change while the rows still showed the new state —
 * the user believed an app was selected that the tunnel never captured
 * (issue #26). There is no confirm button any more — the toolbar's back arrow
 * closes the screen, and its subtitle shows the live selection count.
 *
 * The tunnel takes this set only when it is (re-)established, so a change made
 * while connected is applied by asking the service for a replacement tunnel
 * ([FipsVpnService.requestRebind]). That restarts the node (~2 s of
 * "Reconnecting…"), so it is sent ONCE, when the screen is left with a
 * selection that differs from the one it was opened with — not per toggle,
 * which would bounce the mesh on every tap. The service compares the stored
 * set against the live tunnel's itself, so a redundant nudge is a no-op. While
 * connected the picker shows a note saying so, recomputed on every resume
 * rather than latched, so it disappears once the user disconnects.
 */
class AppPickerActivity : AppCompatActivity() {

    companion object {
        const val PREFS = "fips"
        const val KEY_MESH_APPS = "mesh_apps"
        private const val STATE_APPLIED = "applied_selection"
    }

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable)

    /** The selection as of the last nudge (or of opening the screen). */
    private var appliedSelection: Set<String> = emptySet()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_picker)

        val pm = packageManager
        val entries = pm.queryIntentActivities(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0
        )
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != packageName } // never route our own app through the mesh
            .mapNotNull { pkg ->
                runCatching {
                    val info = pm.getApplicationInfo(pkg, 0)
                    AppEntry(pkg, pm.getApplicationLabel(info).toString(), pm.getApplicationIcon(info))
                }.getOrNull()
            }

        val selected =
            (prefs().getStringSet(KEY_MESH_APPS, emptySet()) ?: emptySet()).toMutableSet()

        // Selected apps first, as of opening the screen. The order is NOT
        // re-sorted on toggle: a row jumping away under the finger is worse
        // than a list that is only tidy on the next visit.
        val picked = selected.toSet()
        // Across a rotation "what the tunnel has" is NOT what is stored now.
        appliedSelection = savedInstanceState?.getStringArrayList(STATE_APPLIED)?.toSet() ?: picked
        val sorted = entries.sortedWith(
            compareBy({ it.pkg !in picked }, { it.label.lowercase() })
        )

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }
        val showCount = {
            toolbar.subtitle = when (selected.size) {
                0 -> "None selected"
                else -> "${selected.size} selected"
            }
        }
        showCount()

        // Custom rows (icon + label + package + checkbox); selection is kept
        // in `selected` directly rather than ListView's choice mode. The
        // adapter owns a filtered copy of `sorted`, so rows bind via getItem.
        val adapter = object : ArrayAdapter<AppEntry>(this, 0, ArrayList(sorted)) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val row = convertView
                    ?: layoutInflater.inflate(R.layout.item_app, parent, false)
                val e = getItem(position) ?: return row
                row.findViewById<ImageView>(R.id.app_icon).setImageDrawable(e.icon)
                row.findViewById<TextView>(R.id.app_label).text = e.label
                row.findViewById<TextView>(R.id.app_pkg).text = e.pkg
                val check = row.findViewById<CheckBox>(R.id.app_check)
                check.isChecked = e.pkg in selected
                row.setOnClickListener {
                    if (!selected.remove(e.pkg)) selected.add(e.pkg)
                    check.isChecked = e.pkg in selected
                    persist(selected)
                    showCount()
                }
                return row
            }
        }
        val list = findViewById<ListView>(R.id.app_list)
        list.adapter = adapter
        val empty = findViewById<View>(R.id.app_list_empty)

        // Match on the label or the package name. Filtered by hand rather than
        // through ArrayAdapter's Filter, which matches toString() prefixes.
        findViewById<EditText>(R.id.app_search).doAfterTextChanged { text ->
            val query = text?.toString()?.trim()?.lowercase().orEmpty()
            val matches = if (query.isEmpty()) sorted else sorted.filter {
                it.label.lowercase().contains(query) || it.pkg.lowercase().contains(query)
            }
            adapter.clear()
            adapter.addAll(matches)
            list.visibility = if (matches.isEmpty()) View.GONE else View.VISIBLE
            empty.visibility = if (matches.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-read the live fact each time, like the Overview battery card does:
        // a disconnect from the notification while this screen is open is
        // reflected as soon as the user comes back to it.
        findViewById<TextView>(R.id.reconnect_hint).visibility =
            if (FipsVpnService.tunnelActive) View.VISIBLE else View.GONE
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(STATE_APPLIED, ArrayList(appliedSelection))
    }

    /**
     * Leaving the screen (Back, or the app going to the background) applies a
     * changed selection to a live tunnel. onPause rather than onStop/onDestroy:
     * the app is still in the foreground here, so startService is always legal.
     * A rotation is not leaving: restarting the node under someone who is
     * still choosing is exactly what "once per visit" is meant to avoid.
     */
    override fun onPause() {
        super.onPause()
        if (isChangingConfigurations) return
        val now = (prefs().getStringSet(KEY_MESH_APPS, emptySet()) ?: emptySet()).toSet()
        if (now == appliedSelection) return
        appliedSelection = now
        FipsVpnService.requestRebind(this)
    }

    private fun prefs() = getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Write the selection now. The copy is defensive: the Editor contract does not
     * promise one. The aliasing hazard that matters is on the *read* side — the set
     * returned by getStringSet must never be mutated, which is why the load above
     * goes through toMutableSet().
     */
    private fun persist(selected: Set<String>) {
        prefs().edit().putStringSet(KEY_MESH_APPS, selected.toSet()).apply()
    }
}
