package org.fips.android

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.annotation.SuppressLint
import android.content.Intent
import android.content.res.ColorStateList
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
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.json.JSONArray
import org.json.JSONObject

/** Overview page: identity, live status, connect/disconnect, mesh apps. */
class OverviewFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var statusDot: View
    private lateinit var halo: View
    private lateinit var toggle: MaterialButton
    private lateinit var statsRow: View
    private lateinit var relaysSummary: TextView
    private lateinit var relaysCount: TextView
    private lateinit var relaysList: LinearLayout

    /** What the connection card is showing; drives the toggle's meaning. */
    private enum class Link { OFF, STARTING, UP }

    private var link: Link? = null

    /** STARTING was entered from UP: a rebind (network flip, hotspot,
     *  changed mesh apps), not a first connect. */
    private var reconnecting = false
    private var haloPulse: ObjectAnimator? = null

    /** Structural fingerprint of the rendered relay rows (see [renderRelays]). */
    private var lastRelaysKey = ""

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_overview, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        headline = view.findViewById(R.id.status_headline)
        detail = view.findViewById(R.id.status_detail)
        statusDot = view.findViewById(R.id.status_dot)
        halo = view.findViewById(R.id.power_halo)
        toggle = view.findViewById(R.id.connect_toggle)
        statsRow = view.findViewById(R.id.stats_row)
        relaysSummary = view.findViewById(R.id.relays_summary)
        relaysCount = view.findViewById(R.id.relays_count)
        relaysList = view.findViewById(R.id.relays_list)
        // A recreated view starts from the layout's defaults.
        link = null
        lastRelaysKey = ""

        showIdentity()

        toggle.setOnClickListener {
            val main = activity as? MainActivity ?: return@setOnClickListener
            // While starting, the tap means "cancel": only OFF may connect,
            // so a repeated tap never stacks a second ACTION_CONNECT.
            // (link is null only if no status has rendered; ask the engine.)
            val off = link?.let { it == Link.OFF }
                ?: !(FipsVpnService.tunnelActive ||
                    runCatching { FipsNative.isRunning() }.getOrDefault(false))
            if (off) main.connect() else main.disconnect()
            renderStatus()
            // The 2 s poll is too slow to acknowledge a tap.
            for (delay in FOLLOW_UP_POLLS_MS) poller.postDelayed(followUp, delay)
        }
        view.findViewById<MaterialButton>(R.id.copy_npub).setOnClickListener {
            val npub = view.findViewById<TextView>(R.id.identity_npub).text
            Ui.copy(view, "npub", npub, "Public key copied")
        }
        view.findViewById<MaterialButton>(R.id.copy_address).setOnClickListener {
            val address = view.findViewById<TextView>(R.id.identity_address).text
            Ui.copy(view, "fips address", address, "Mesh address copied")
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
        val pickApps = View.OnClickListener {
            startActivity(Intent(requireContext(), AppPickerActivity::class.java))
        }
        view.findViewById<View>(R.id.pick_apps).setOnClickListener(pickApps)
        view.findViewById<View>(R.id.mesh_apps_card).setOnClickListener(pickApps)
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
        MaterialAlertDialogBuilder(requireContext())
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
        val dialog = MaterialAlertDialogBuilder(requireContext())
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
            MaterialAlertDialogBuilder(requireContext())
                .setTitle("Not a valid key")
                .setMessage(
                    info?.optString("error")?.takeIf { it.isNotEmpty() }
                        ?: "That does not look like a valid nsec."
                )
                .setPositiveButton("OK", null)
                .show()
            return
        }
        MaterialAlertDialogBuilder(requireContext())
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
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Disconnect first")
            .setMessage("Disconnect from the mesh before changing this device's identity.")
            .setPositiveButton("OK", null)
            .show()
        return false
    }

    private fun toast(message: String) {
        view?.let { Ui.snack(it, message, long = true) }
    }

    private fun confirmRegenerate() {
        MaterialAlertDialogBuilder(requireContext())
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
        poller.removeCallbacks(followUp)
        // An infinite animator on a paused page is pure battery; onResume's
        // first render restarts it if the node is still starting.
        haloPulse?.cancel()
        haloPulse = null
        link = null
        super.onPause()
    }

    private fun updateMeshApps() {
        val root = view ?: return
        val selected = ConfigStore.prefs(requireContext())
            .getStringSet(AppPickerActivity.KEY_MESH_APPS, emptySet()) ?: emptySet()
        val n = selected.size
        root.findViewById<TextView>(R.id.mesh_apps_summary).text = when (n) {
            0 -> "No apps selected — no app can reach the mesh yet."
            1 -> "1 app routes through the mesh."
            else -> "$n apps route through the mesh."
        }
        root.findViewById<MaterialButton>(R.id.pick_apps).text =
            if (n == 0) "Select mesh apps" else "Change"

        // Icons of the first few selected apps, then "+N". A package that was
        // uninstalled since it was picked has no icon and is skipped here; it
        // still counts above, exactly as the tunnel setup sees the set.
        val icons = root.findViewById<LinearLayout>(R.id.mesh_apps_icons)
        icons.removeAllViews()
        val pm = requireContext().packageManager
        val size = (MESH_APP_ICON_DP * resources.displayMetrics.density).toInt()
        val gap = (MESH_APP_ICON_GAP_DP * resources.displayMetrics.density).toInt()
        var shown = 0
        for (pkg in selected.sorted()) {
            if (shown == MAX_MESH_APP_ICONS) break
            val icon = runCatching { pm.getApplicationIcon(pkg) }.getOrNull() ?: continue
            icons.addView(
                ImageView(requireContext()).apply {
                    setImageDrawable(icon)
                    importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                },
                LinearLayout.LayoutParams(size, size).apply { marginEnd = gap },
            )
            shown++
        }
        if (n > shown && shown > 0) {
            icons.addView(
                TextView(requireContext()).apply {
                    text = "+${n - shown}"
                    setTextAppearance(
                        com.google.android.material.R.style.TextAppearance_Material3_LabelLarge
                    )
                }
            )
        }
        icons.visibility = if (shown > 0) View.VISIBLE else View.GONE
    }

    /** One-shot re-render after a tap; the steady poll is [pollStatus]. */
    private val followUp = Runnable { renderStatus() }

    private val pollStatus = object : Runnable {
        override fun run() {
            renderStatus()
            poller.postDelayed(this, 2000)
        }
    }

    private fun renderStatus() {
        val root = view ?: return
        try {
            val status = JSONObject(FipsNative.status())
            renderRelays(status)
            val running = status.optBoolean("running")
            val s = status.optJSONObject("status")
            if (running) MainActivity.connectSettled()
            when {
                // Running without a snapshot yet is still "starting" to the user.
                running && s != null -> {
                    showLink(Link.UP)
                    val mesh = s.optInt("estimated_mesh_size", s.optInt("mesh_size", -1))
                    val links = s.optInt("link_count", -1)
                    root.findViewById<TextView>(R.id.stat_mesh).text =
                        if (mesh >= 0) mesh.toString() else "–"
                    root.findViewById<TextView>(R.id.stat_links).text =
                        if (links >= 0) links.toString() else "–"
                    root.findViewById<TextView>(R.id.stat_role).text =
                        if (s.optBoolean("is_leaf_only", false)) "Leaf" else "Interior"
                }
                // Not (fully) up, but the service holds a tunnel: a first
                // start, or a rebind restarting the node on the same tun fd.
                // Either way the toggle has to mean "disconnect".
                running || FipsVpnService.tunnelActive || MainActivity.isConnecting() ->
                    showLink(Link.STARTING)
                else -> showLink(Link.OFF)
            }
        } catch (e: Exception) {
            detail.text = "status error: ${e.message}"
        }
    }

    /**
     * Put the connection card into [state]. The toggle's colours come from
     * XML state lists (activated = up, selected = starting). Everything here
     * is idempotent except the halo animation, which only restarts on an
     * actual state change — the poll calls this every 2 s.
     */
    private fun showLink(state: Link) {
        if (state != link) reconnecting = state == Link.STARTING && link == Link.UP
        headline.text = when (state) {
            Link.OFF -> "Disconnected"
            Link.STARTING -> if (reconnecting) "Reconnecting…" else "Connecting…"
            Link.UP -> "Connected"
        }
        detail.text = when (state) {
            Link.OFF -> "Tap to connect to the mesh"
            Link.STARTING ->
                if (reconnecting) "Applying changes — restarting the node"
                else "Starting the mesh node — tap to cancel"
            Link.UP -> "Tap to disconnect"
        }
        statsRow.visibility = if (state == Link.UP) View.VISIBLE else View.GONE
        if (state == link) return
        link = state

        toggle.isActivated = state == Link.UP
        toggle.isSelected = state == Link.STARTING
        toggle.contentDescription =
            if (state == Link.OFF) "Connect to the mesh" else "Disconnect from the mesh"
        statusDot.backgroundTintList = ColorStateList.valueOf(
            requireContext().getColor(
                when (state) {
                    Link.OFF -> R.color.status_off
                    Link.STARTING -> R.color.status_warn
                    Link.UP -> R.color.status_ok
                }
            )
        )

        haloPulse?.cancel()
        haloPulse = null
        when (state) {
            Link.OFF -> halo.animate().alpha(0f).setDuration(HALO_FADE_MS).start()
            Link.UP -> halo.animate().alpha(HALO_ALPHA).setDuration(HALO_FADE_MS).start()
            Link.STARTING -> {
                halo.animate().cancel()
                haloPulse = ObjectAnimator.ofFloat(halo, View.ALPHA, 0.04f, HALO_ALPHA).apply {
                    duration = HALO_PULSE_MS
                    repeatMode = ValueAnimator.REVERSE
                    repeatCount = ValueAnimator.INFINITE
                    start()
                }
            }
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
        val rows = ArrayList<Triple<String, String, Boolean>>()
        for (i in 0 until relays.length()) {
            val r = relays.getJSONObject(i)
            val up = r.optBoolean("connected")
            if (up) connected++
            rows.add(
                Triple(
                    r.optString("url").removePrefix("wss://").removePrefix("ws://"),
                    r.optString("status").lowercase(),
                    up,
                )
            )
        }
        relaysList.visibility = if (rows.isEmpty()) View.GONE else View.VISIBLE
        relaysCount.visibility = relaysList.visibility
        relaysCount.text = "$connected/${rows.size}"
        relaysSummary.text = when {
            !running -> "Relays connect when the node is running."
            rows.isEmpty() -> "Connecting to relays…"
            connected == 0 -> "No relay connected yet — peers cannot find this node by npub."
            else -> "Where peers look up this node's current address."
        }

        // Rebuild only on change: this runs every 2 s.
        val key = rows.joinToString("|")
        if (key == lastRelaysKey) return
        lastRelaysKey = key
        relaysList.removeAllViews()
        for ((host, state, up) in rows) {
            val row = layoutInflater.inflate(R.layout.item_relay, relaysList, false)
            row.findViewById<TextView>(R.id.relay_host).text = host
            row.findViewById<TextView>(R.id.relay_state).text = state
            row.findViewById<View>(R.id.relay_dot).backgroundTintList = ColorStateList.valueOf(
                requireContext().getColor(
                    when {
                        up -> R.color.status_ok
                        state in RELAY_PENDING_STATES -> R.color.status_warn
                        else -> R.color.status_off
                    }
                )
            )
            relaysList.addView(row)
        }
    }

    private companion object {
        /** Extra renders after a toggle tap, until the 2 s poll takes over. */
        val FOLLOW_UP_POLLS_MS = longArrayOf(400, 1000, 2000, 3500)

        const val HALO_ALPHA = 0.16f
        const val HALO_FADE_MS = 250L
        const val HALO_PULSE_MS = 900L

        const val MAX_MESH_APP_ICONS = 6
        const val MESH_APP_ICON_DP = 32
        const val MESH_APP_ICON_GAP_DP = 8

        /** nostr-sdk relay states that are on their way up, not down. */
        val RELAY_PENDING_STATES = setOf("initialized", "pending", "connecting")
    }
}
