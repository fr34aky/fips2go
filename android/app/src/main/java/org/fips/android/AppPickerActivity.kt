package org.fips.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import androidx.appcompat.app.AppCompatActivity

/**
 * Lets the user pick which apps route through the FIPS mesh (VpnService
 * `addAllowedApplication`). Only selected apps are captured — mesh traffic
 * goes through the tunnel and their other traffic is forwarded back out;
 * every other app on the phone is left on the normal network untouched.
 *
 * The selection is persisted as a package-name set in the shared prefs the
 * service reads at connect time.
 */
class AppPickerActivity : AppCompatActivity() {

    companion object {
        const val PREFS = "fips"
        const val KEY_MESH_APPS = "mesh_apps"
    }

    private lateinit var listView: ListView
    private val packages = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_picker)
        listView = findViewById(R.id.app_list)
        listView.choiceMode = ListView.CHOICE_MODE_MULTIPLE

        val pm = packageManager
        val launchable = pm.queryIntentActivities(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0
        )
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != packageName } // never route our own app through the mesh
            .mapNotNull { pkg ->
                runCatching {
                    pkg to pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                }.getOrNull()
            }
            .sortedBy { it.second.lowercase() }

        packages.clear()
        packages.addAll(launchable.map { it.first })
        val labels = launchable.map { "${it.second}\n${it.first}" }

        listView.adapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_multiple_choice, labels
        )

        val selected = prefs().getStringSet(KEY_MESH_APPS, emptySet()) ?: emptySet()
        packages.forEachIndexed { i, pkg ->
            listView.setItemChecked(i, pkg in selected)
        }

        findViewById<Button>(R.id.save).setOnClickListener {
            val chosen = mutableSetOf<String>()
            val checked = listView.checkedItemPositions
            for (i in packages.indices) {
                if (checked[i]) chosen.add(packages[i])
            }
            prefs().edit().putStringSet(KEY_MESH_APPS, chosen).apply()
            finish()
        }
    }

    private fun prefs() = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
