package org.fips.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.PowerManager
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.snackbar.Snackbar
import org.json.JSONArray
import org.json.JSONObject

/** Overview page: identity, live status, connect/disconnect, mesh apps. */
class OverviewFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var relaysSummary: TextView
    private lateinit var relaysList: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_overview, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        headline = view.findViewById(R.id.status_headline)
        detail = view.findViewById(R.id.status_detail)
        relaysSummary = view.findViewById(R.id.relays_summary)
        relaysList = view.findViewById(R.id.relays_list)

        showIdentity()

        view.findViewById<MaterialButton>(R.id.connect).setOnClickListener {
            (activity as? MainActivity)?.connect()
        }
        view.findViewById<MaterialButton>(R.id.disconnect).setOnClickListener {
            (activity as? MainActivity)?.disconnect()
        }
        view.findViewById<MaterialButton>(R.id.backup_identity).setOnClickListener {
            showBackup()
        }
        view.findViewById<MaterialButton>(R.id.restore_identity).setOnClickListener {
            if (requireDisconnected()) showRestore()
        }
        view.findViewById<MaterialButton>(R.id.regenerate).setOnClickListener {
            if (requireDisconnected()) confirmRegenerate()
        }
        view.findViewById<MaterialButton>(R.id.pick_apps).setOnClickListener {
            startActivity(Intent(requireContext(), AppPickerActivity::class.java))
        }
        view.findViewById<MaterialButton>(R.id.battery_allow).setOnClickListener {
            requestBatteryExemption()
        }
        view.findViewById<MaterialButton>(R.id.battery_dismiss).setOnClickListener {
            ConfigStore.prefs(requireContext()).edit()
                .putLong(
                    ConfigStore.BATTERY_PROMPT_SNOOZED_UNTIL,
                    System.currentTimeMillis() + ConfigStore.BATTERY_PROMPT_SNOOZE_MS,
                )
                .apply()
            updateBatteryCard()
        }
    }

    // ---- Battery-optimisation exemption -----------------------------------

    /**
     * Returning from the exemption screen re-checks rather than trusting the
     * result code: ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS reports
     * RESULT_CANCELED even when the user granted it.
     */
    private val batteryExemption =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            updateBatteryCard()
        }

    @SuppressLint("BatteryLife")
    private fun requestBatteryExemption() {
        try {
            batteryExemption.launch(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:${requireContext().packageName}"))
            )
        } catch (e: Exception) {
            toast("Could not open battery settings: ${e.message}")
        }
    }

    private fun isBatteryExempt(): Boolean {
        val pm = requireContext().getSystemService(PowerManager::class.java) ?: return true
        return pm.isIgnoringBatteryOptimizations(requireContext().packageName)
    }

    /**
     * Show the card only while it is actionable: the app is not exempt and the
     * user has not snoozed it recently. Because the exemption is re-read every
     * time, a revoked exemption brings the card back on its own.
     */
    private fun updateBatteryCard() {
        val card = view?.findViewById<View>(R.id.battery_card) ?: return
        val snoozedUntil = ConfigStore.prefs(requireContext()).getLong(ConfigStore.BATTERY_PROMPT_SNOOZED_UNTIL, 0L)
        val show = !isBatteryExempt() && System.currentTimeMillis() >= snoozedUntil
        card.visibility = if (show) View.VISIBLE else View.GONE
    }

    private fun showIdentity() {
        val nsec = IdentityStore.getOrCreate(requireContext())
        val info = JSONObject(FipsNative.deriveIdentity(nsec))
        view?.findViewById<TextView>(R.id.identity_npub)?.text = info.optString("npub")
        view?.findViewById<TextView>(R.id.identity_address)?.text = info.optString("address")
    }

    // ---- Identity backup / restore ----------------------------------------

    /** Reveal the nsec so it can be copied somewhere safe. */
    private fun showBackup() {
        val nsec = IdentityStore.getOrCreate(requireContext())
        val info = JSONObject(FipsNative.deriveIdentity(nsec))
        val npub = info.optString("npub")
        val body = layoutInflater.inflate(R.layout.dialog_identity_backup, null)
        body.findViewById<TextView>(R.id.backup_nsec).text = nsec
        body.findViewById<TextView>(R.id.backup_npub).text = "Identity: $npub"
        AlertDialog.Builder(requireContext())
            .setTitle("Back up identity")
            .setView(body)
            .setPositiveButton("Copy") { _, _ -> copySecret(nsec) }
            .setNegativeButton("Done", null)
            .show()
    }

    /**
     * Copy the nsec, flagged sensitive so Android 13+ keeps it out of the
     * clipboard preview toast and out of clipboard history.
     */
    private fun copySecret(nsec: String) {
        val clip = ClipData.newPlainText("fips nsec", nsec)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        requireContext().getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
        toast("Secret key copied — paste it somewhere safe, then clear the clipboard")
    }

    /** Prompt for a pasted nsec. */
    private fun showRestore() {
        val body = layoutInflater.inflate(R.layout.dialog_identity_restore, null)
        val input = body.findViewById<EditText>(R.id.restore_nsec)
        val dialog = AlertDialog.Builder(requireContext())
            .setTitle("Restore identity")
            .setView(body)
            .setPositiveButton("Restore", null)
            .setNegativeButton("Cancel", null)
            .create()
        dialog.show()
        // Overridden after show() so a bad key leaves the dialog open.
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val key = input.text.toString().trim()
            if (key.isEmpty()) {
                input.error = "Enter a secret key"
            } else {
                dialog.dismiss()
                confirmRestore(key)
            }
        }
    }

    /**
     * Validate the key through the shim and show the identity it resolves to
     * before overwriting the current one — the npub is the only way the user
     * can tell they are restoring the backup they meant.
     */
    private fun confirmRestore(key: String) {
        // Never hand deriveIdentity an empty string: it treats that as "make me
        // a new identity" and would return a freshly generated one, which we
        // would then present as the restored key.
        if (key.isBlank()) {
            toast("No key found")
            return
        }
        val info = runCatching { JSONObject(FipsNative.deriveIdentity(key)) }.getOrNull()
        if (info == null || info.has("error")) {
            AlertDialog.Builder(requireContext())
                .setTitle("Not a valid key")
                .setMessage(
                    info?.optString("error")?.takeIf { it.isNotEmpty() }
                        ?: "That does not look like a valid nsec."
                )
                .setPositiveButton("OK", null)
                .show()
            return
        }
        AlertDialog.Builder(requireContext())
            .setTitle("Restore this identity?")
            .setMessage(
                "This device will become:\n\n${info.optString("npub")}\n" +
                    "${info.optString("address")}\n\n" +
                    "The identity currently on this device is permanently replaced. " +
                    "Back it up first if you still need it."
            )
            .setPositiveButton("Restore") { _, _ ->
                // Persist the normalized nsec deriveIdentity echoed back, not
                // the raw input — the shim also accepts a hex secret, and this
                // keeps what is stored identical in form to a generated one.
                IdentityStore.store(requireContext(), info.optString("nsec").ifEmpty { key })
                showIdentity()
                toast("Identity restored — connect to use it")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * Changing the identity under a running node would leave the mesh talking
     * to the old key until the next restart, so make the user disconnect.
     */
    private fun requireDisconnected(): Boolean {
        if (!runCatching { FipsNative.isRunning() }.getOrDefault(false)) return true
        AlertDialog.Builder(requireContext())
            .setTitle("Disconnect first")
            .setMessage("Disconnect from the mesh before changing this device's identity.")
            .setPositiveButton("OK", null)
            .show()
        return false
    }

    private fun toast(message: String) {
        view?.let { Snackbar.make(it, message, Snackbar.LENGTH_LONG).show() }
    }

    private fun confirmRegenerate() {
        AlertDialog.Builder(requireContext())
            .setTitle("Regenerate identity?")
            .setMessage(
                "This creates a new node identity (npub and .fips address). The " +
                    "current identity is permanently replaced — back it up first if " +
                    "you still need it."
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
        updateBatteryCard()
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
            renderRelays(status)
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

    /**
     * "Nostr relays" card: the node's relay pool (`status.relays`, refreshed
     * by the shim on every status poll) with per-relay connection state —
     * the only place short of logcat that shows whether rendezvous is
     * actually working.
     */
    private fun renderRelays(status: JSONObject) {
        val running = status.optBoolean("running")
        val relays = status.optJSONArray("relays") ?: JSONArray()
        var connected = 0
        val lines = ArrayList<String>()
        for (i in 0 until relays.length()) {
            val r = relays.getJSONObject(i)
            val url = r.optString("url")
            val up = r.optBoolean("connected")
            if (up) connected++
            lines.add(
                (if (up) "● " else "○ ") +
                    url.removePrefix("wss://").removePrefix("ws://") +
                    "  " + r.optString("status").lowercase()
            )
        }
        relaysList.visibility = if (lines.isEmpty()) View.GONE else View.VISIBLE
        relaysList.text = lines.joinToString("\n")
        relaysSummary.text = when {
            !running -> "Relays connect when the node is running."
            lines.isEmpty() -> "Connecting to relays…"
            else -> "$connected of ${lines.size} connected."
        }
    }
}
