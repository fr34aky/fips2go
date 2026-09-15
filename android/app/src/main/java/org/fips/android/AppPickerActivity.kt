package org.fips.android

import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

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
 * (issue #26). The bottom button now just closes the screen.
 */
class AppPickerActivity : AppCompatActivity() {

    companion object {
        const val PREFS = "fips"
        const val KEY_MESH_APPS = "mesh_apps"
    }

    private data class AppEntry(val pkg: String, val label: String, val icon: Drawable)

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
            .sortedBy { it.label.lowercase() }

        val selected =
            (prefs().getStringSet(KEY_MESH_APPS, emptySet()) ?: emptySet()).toMutableSet()

        // Custom rows (icon + label + package + checkbox); selection is kept
        // in `selected` directly rather than ListView's choice mode.
        findViewById<ListView>(R.id.app_list).adapter =
            object : ArrayAdapter<AppEntry>(this, 0, entries) {
                override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                    val row = convertView
                        ?: layoutInflater.inflate(R.layout.item_app, parent, false)
                    val e = entries[position]
                    row.findViewById<ImageView>(R.id.app_icon).setImageDrawable(e.icon)
                    row.findViewById<TextView>(R.id.app_label).text = e.label
                    row.findViewById<TextView>(R.id.app_pkg).text = e.pkg
                    val check = row.findViewById<CheckBox>(R.id.app_check)
                    check.isChecked = e.pkg in selected
                    row.setOnClickListener {
                        if (!selected.remove(e.pkg)) selected.add(e.pkg)
                        check.isChecked = e.pkg in selected
                        persist(selected)
                    }
                    return row
                }
            }

        findViewById<Button>(R.id.done).setOnClickListener { finish() }
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
