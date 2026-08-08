package org.fips.android

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import org.json.JSONObject

/** Overview page: identity, live status, connect/disconnect, mesh apps. */
class OverviewFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var headline: TextView
    private lateinit var detail: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_overview, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        headline = view.findViewById(R.id.status_headline)
        detail = view.findViewById(R.id.status_detail)

        showIdentity()

        view.findViewById<MaterialButton>(R.id.connect).setOnClickListener {
            (activity as? MainActivity)?.connect()
        }
        view.findViewById<MaterialButton>(R.id.disconnect).setOnClickListener {
            (activity as? MainActivity)?.disconnect()
        }
        view.findViewById<MaterialButton>(R.id.regenerate).setOnClickListener {
            confirmRegenerate()
        }
        view.findViewById<MaterialButton>(R.id.pick_apps).setOnClickListener {
            startActivity(Intent(requireContext(), AppPickerActivity::class.java))
        }
    }

    private fun showIdentity() {
        val nsec = IdentityStore.getOrCreate(requireContext())
        val info = JSONObject(FipsNative.deriveIdentity(nsec))
        view?.findViewById<TextView>(R.id.identity_npub)?.text = info.optString("npub")
        view?.findViewById<TextView>(R.id.identity_address)?.text = info.optString("address")
    }

    private fun confirmRegenerate() {
        AlertDialog.Builder(requireContext())
            .setTitle("Regenerate identity?")
            .setMessage(
                "This creates a new node identity (npub and .fips address). The " +
                    "current identity is permanently replaced. Disconnect first if connected."
            )
            .setPositiveButton("Regenerate") { _, _ ->
                IdentityStore.regenerate(requireContext())
                showIdentity()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    override fun onResume() {
        super.onResume()
        updateMeshApps()
        poller.post(pollStatus)
    }

    override fun onPause() {
        poller.removeCallbacks(pollStatus)
        super.onPause()
    }

    private fun updateMeshApps() {
        val n = ConfigStore.prefs(requireContext())
            .getStringSet(AppPickerActivity.KEY_MESH_APPS, emptySet())?.size ?: 0
        view?.findViewById<TextView>(R.id.mesh_apps_summary)?.text = when (n) {
            0 -> "No apps selected — no app can reach the mesh yet."
            1 -> "1 app routes through the mesh."
            else -> "$n apps route through the mesh."
        }
    }

    private val pollStatus = object : Runnable {
        override fun run() {
            renderStatus()
            poller.postDelayed(this, 2000)
        }
    }

    private fun renderStatus() {
        try {
            val status = JSONObject(FipsNative.status())
            if (!status.optBoolean("running")) {
                headline.text = "Disconnected"
                detail.text = "The mesh node is not running."
                return
            }
            headline.text = "Connected"
            val s = status.optJSONObject("status")
            if (s == null) {
                detail.text = "Starting…"
                return
            }
            val mesh = s.optInt("estimated_mesh_size", s.optInt("mesh_size", -1))
            val links = s.optInt("link_count", -1)
            val leaf = s.optBoolean("is_leaf_only", false)
            detail.text = buildString {
                if (mesh >= 0) append("Mesh: $mesh nodes")
                if (links >= 0) {
                    if (isNotEmpty()) append("  ·  ")
                    append("$links link" + if (links == 1) "" else "s")
                }
                append("\n")
                append(if (leaf) "Leaf node" else "Interior node")
            }
        } catch (e: Exception) {
            detail.text = "status error: ${e.message}"
        }
    }
}
