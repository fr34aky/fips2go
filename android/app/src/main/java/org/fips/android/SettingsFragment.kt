package org.fips.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import androidx.activity.result.contract.ActivityResultContracts
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import androidx.activity.OnBackPressedCallback
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import org.fips.android.ConfigStore as CS

/**
 * Settings page. Everything here has a working default seeded by
 * [ConfigStore.applyDefaults], so the page exists to change your mind, not to
 * get connected. The expert knobs sit in a collapsed "Advanced" group.
 */
class SettingsFragment : Fragment() {

    /** Survives rotation so an opened Advanced group does not snap shut. */
    private var advancedExpanded = false

    /**
     * Fine location, requested when the FIPS Hotspot toggle is switched on:
     * Android gates Wi-Fi scan results and SSIDs behind it, and without them
     * the hotspot feature can neither auto-join "!FIPS" via suggestions nor
     * safely re-file its direct request. Denial keeps the toggle usable in a
     * degraded join-once mode.
     */
    private val locationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            view?.let {
                Ui.snack(
                    it,
                    "Without location, !FIPS hotspots are only joined once per connect",
                    long = true,
                )
            }
        }
    }

    private fun ensureLocationPermission() {
        if (requireContext().checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            locationPermission.launch(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_settings, container, false)

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_ADVANCED, advancedExpanded)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        advancedExpanded = savedInstanceState?.getBoolean(STATE_ADVANCED) ?: false
        load(view)
        setupBootstrapDropdown(view)
        setupAdvancedToggle(view)
        sw(view, R.id.hotspot).setOnCheckedChangeListener { _, checked ->
            // Flipping the toggle on is an explicit request for the feature,
            // so the system prompt needs no preamble.
            if (checked) {
                HotspotLocation.markAsked(requireContext())
                ensureLocationPermission()
            }
            syncSaveButton(view)
        }
        // Merely opening Settings is not a request for anything. The toggle
        // now defaults to on, so prompting off the back of "isChecked" would
        // throw a bare system location dialog at every new user — explain
        // first, and only once (shared one-shot with the connect flow).
        if (sw(view, R.id.hotspot).isChecked && HotspotLocation.shouldAsk(requireContext())) {
            HotspotLocation.markAsked(requireContext())
            HotspotLocation.explain(requireContext(), onContinue = { ensureLocationPermission() })
        }
        view.findViewById<View>(R.id.save).setOnClickListener {
            save(view)
            Ui.snack(view, savedMessage())
            syncSaveButton(view)
        }
        watchForEdits(view)
        // Backing out of the activity destroys unsaved edits too.
        requireActivity().onBackPressedDispatcher.addCallback(
            viewLifecycleOwner,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    val leave = {
                        isEnabled = false
                        requireActivity().onBackPressedDispatcher.onBackPressed()
                    }
                    if (!interceptUnsaved(leave)) leave()
                }
            }
        )
    }

    /**
     * If the widgets differ from the persisted settings, ask Save / Discard /
     * Cancel and return true; [proceed] runs unless cancelled (Discard reverts
     * the widgets first, so a re-entered check comes up clean). Returns false
     * when there is nothing unsaved — the caller just proceeds itself.
     */
    fun interceptUnsaved(proceed: () -> Unit): Boolean {
        val v = view ?: return false
        if (!hasUnsavedChanges(v)) return false
        MaterialAlertDialogBuilder(requireContext())
            .setTitle("Unsaved settings")
            .setMessage("Edits only take effect once saved (and applied on the next connect).")
            .setPositiveButton("Save") { _, _ ->
                save(v)
                Ui.snack(v, savedMessage())
                proceed()
            }
            .setNegativeButton("Discard") { _, _ ->
                load(v)
                proceed()
            }
            .setNeutralButton("Cancel", null)
            .show()
        return true
    }

    /** Settings are read at connect time, so a running node needs a reconnect. */
    private fun savedMessage() =
        if (FipsVpnService.tunnelActive ||
            runCatching { FipsNative.isRunning() }.getOrDefault(false)
        ) {
            "Saved — reconnect to apply"
        } else {
            "Saved"
        }

    /**
     * The Save button doubles as the unsaved-edits indicator: it is on screen
     * exactly while [hasUnsavedChanges] holds. Every widget reports into
     * [syncSaveButton], which re-derives that from scratch rather than
     * tracking a dirty flag — so flipping a switch back, [load] on Discard,
     * and the view-state restore after a rotation all come out right.
     */
    private fun watchForEdits(view: View) {
        for (id in SWITCHES) {
            // The hotspot switch already reports from its own listener.
            if (id != R.id.hotspot) {
                sw(view, id).setOnCheckedChangeListener { _, _ -> syncSaveButton(view) }
            }
        }
        // Dropdowns are EditTexts too; a picked item arrives as a text change.
        for (id in TEXT_FIELDS) edit(view, id).doAfterTextChanged { syncSaveButton(view) }
        syncSaveButton(view)
    }

    private fun syncSaveButton(view: View) {
        val save = view.findViewById<ExtendedFloatingActionButton>(R.id.save)
        if (hasUnsavedChanges(view)) save.show() else save.hide()
    }

    /** Compare widgets against prefs, mirroring save()'s normalization. */
    private fun hasUnsavedChanges(view: View): Boolean {
        val p = CS.prefs(requireContext())
        fun e(id: Int) = edit(view, id).text.toString().trim()
        return e(R.id.peer_npub) != p.getString(CS.PEER_NPUB, "") ||
            e(R.id.peer_endpoint) != p.getString(CS.PEER_ENDPOINT, "") ||
            e(R.id.peer_transport).ifEmpty { CS.DEF_PEER_TRANSPORT } !=
            p.getString(CS.PEER_TRANSPORT, CS.DEF_PEER_TRANSPORT) ||
            sw(view, R.id.inbound_filter).isChecked !=
            p.getBoolean(CS.INBOUND_FILTER, CS.DEF_INBOUND_FILTER) ||
            e(R.id.inbound_ports) != p.getString(CS.INBOUND_PORTS, "") ||
            sw(view, R.id.battery_saver).isChecked !=
            p.getBoolean(CS.BATTERY_SAVER, CS.DEF_BATTERY_SAVER) ||
            sw(view, R.id.lan_mdns).isChecked != CS.lanMdns(requireContext()) ||
            sw(view, R.id.hotspot).isChecked != CS.hotspotEnabled(requireContext()) ||
            sw(view, R.id.auto_update).isChecked !=
            p.getBoolean(CS.AUTO_UPDATE, CS.DEF_AUTO_UPDATE) ||
            sw(view, R.id.forward_clearnet).isChecked !=
            p.getBoolean(CS.FORWARD_CLEARNET, CS.DEF_FORWARD_CLEARNET) ||
            (e(R.id.worker_threads).toIntOrNull() ?: CS.DEF_WORKER_THREADS).coerceIn(0, 16) !=
            p.getInt(CS.WORKER_THREADS, CS.DEF_WORKER_THREADS) ||
            e(R.id.log_level).ifEmpty { CS.DEF_LOG_LEVEL } !=
            p.getString(CS.LOG_LEVEL, CS.DEF_LOG_LEVEL)
    }

    private fun edit(view: View, id: Int) = view.findViewById<EditText>(id)
    private fun sw(view: View, id: Int) = view.findViewById<MaterialSwitch>(id)

    // Dropdown fields need setText(value, false) — plain setText would run the
    // autocomplete filter and shrink the dropdown to the current value.
    private fun drop(view: View, id: Int) = view.findViewById<MaterialAutoCompleteTextView>(id)

    /** Expand/collapse the Advanced group, flipping the chevron with it. */
    private fun setupAdvancedToggle(view: View) {
        val content = view.findViewById<LinearLayout>(R.id.advanced_content)
        val chevron = view.findViewById<ImageView>(R.id.advanced_chevron)
        setAdvancedExpanded(content, chevron, advancedExpanded)
        view.findViewById<View>(R.id.advanced_header).setOnClickListener {
            setAdvancedExpanded(content, chevron, !advancedExpanded)
        }
    }

    private fun setAdvancedExpanded(content: View, chevron: ImageView, expanded: Boolean) {
        advancedExpanded = expanded
        content.visibility = if (expanded) View.VISIBLE else View.GONE
        chevron.rotation = if (expanded) 180f else 0f
        chevron.contentDescription =
            if (expanded) "Collapse advanced settings" else "Expand advanced settings"
    }

    /**
     * Bootstrap dropdown: picking a public test-mesh server fills the npub and
     * endpoint fields; "custom" reveals them for manual entry. Hand-editing
     * either field flips the selection back to whatever now matches.
     *
     * The custom fields sit directly under the dropdown rather than in
     * Advanced: whenever they are what the node is actually peering with, they
     * have to be visible and editable where the server is chosen.
     */
    private fun setupBootstrapDropdown(view: View) {
        val dd = drop(view, R.id.bootstrap_server)
        dd.setSimpleItems(
            (CS.BOOTSTRAP_PEERS.map { it.name } + CS.BOOTSTRAP_CUSTOM).toTypedArray()
        )
        val npubField = edit(view, R.id.peer_npub)
        val endpointField = edit(view, R.id.peer_endpoint)
        val customGroup = view.findViewById<View>(R.id.custom_peer_group)
        fun matchedPeer() = CS.BOOTSTRAP_PEERS.firstOrNull {
            it.npub == npubField.text.toString().trim() &&
                it.endpoint == endpointField.text.toString().trim()
        }
        // One rule drives both the label and the fields: anything that is not
        // exactly a listed server is "custom" and must be visible. A half-typed
        // entry matches nothing, so the fields cannot vanish mid-edit.
        val syncSelection = {
            val match = matchedPeer()
            dd.setText(match?.name ?: CS.BOOTSTRAP_CUSTOM, false)
            customGroup.visibility = if (match == null) View.VISIBLE else View.GONE
        }
        syncSelection()
        dd.setOnItemClickListener { _, _, pos, _ ->
            val peer = CS.BOOTSTRAP_PEERS.getOrNull(pos)
            if (peer != null) {
                npubField.setText(peer.npub)
                endpointField.setText(peer.endpoint)
            } else {
                // Switching a preset → custom starts from an empty pair, so the
                // preset's values are not left looking like the user's own. An
                // existing custom entry is left alone to be edited.
                if (matchedPeer() != null) {
                    npubField.setText("")
                    endpointField.setText("")
                }
                syncSelection()
                npubField.requestFocus()
            }
        }
        npubField.doAfterTextChanged { syncSelection() }
        endpointField.doAfterTextChanged { syncSelection() }
    }

    private fun load(view: View) {
        val p = CS.prefs(requireContext())
        edit(view, R.id.peer_npub).setText(p.getString(CS.PEER_NPUB, ""))
        edit(view, R.id.peer_endpoint).setText(p.getString(CS.PEER_ENDPOINT, ""))
        drop(view, R.id.peer_transport)
            .setText(p.getString(CS.PEER_TRANSPORT, CS.DEF_PEER_TRANSPORT), false)
        sw(view, R.id.inbound_filter).isChecked =
            p.getBoolean(CS.INBOUND_FILTER, CS.DEF_INBOUND_FILTER)
        edit(view, R.id.inbound_ports).setText(p.getString(CS.INBOUND_PORTS, ""))
        sw(view, R.id.battery_saver).isChecked =
            p.getBoolean(CS.BATTERY_SAVER, CS.DEF_BATTERY_SAVER)
        sw(view, R.id.lan_mdns).isChecked = CS.lanMdns(requireContext())
        sw(view, R.id.hotspot).isChecked = CS.hotspotEnabled(requireContext())
        sw(view, R.id.auto_update).isChecked = p.getBoolean(CS.AUTO_UPDATE, CS.DEF_AUTO_UPDATE)
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q) {
            sw(view, R.id.hotspot).isEnabled = false
        }
        sw(view, R.id.forward_clearnet).isChecked =
            p.getBoolean(CS.FORWARD_CLEARNET, CS.DEF_FORWARD_CLEARNET)
        edit(view, R.id.worker_threads)
            .setText(p.getInt(CS.WORKER_THREADS, CS.DEF_WORKER_THREADS).toString())
        drop(view, R.id.log_level).setText(p.getString(CS.LOG_LEVEL, CS.DEF_LOG_LEVEL), false)
    }

    private fun save(view: View) {
        val workers = edit(view, R.id.worker_threads).text.toString().trim().toIntOrNull()
            ?: CS.DEF_WORKER_THREADS
        CS.prefs(requireContext()).edit()
            .putString(CS.PEER_NPUB, edit(view, R.id.peer_npub).text.toString().trim())
            .putString(CS.PEER_ENDPOINT, edit(view, R.id.peer_endpoint).text.toString().trim())
            .putString(
                CS.PEER_TRANSPORT,
                edit(view, R.id.peer_transport).text.toString().trim()
                    .ifEmpty { CS.DEF_PEER_TRANSPORT }
            )
            .putBoolean(CS.INBOUND_FILTER, sw(view, R.id.inbound_filter).isChecked)
            .putString(CS.INBOUND_PORTS, edit(view, R.id.inbound_ports).text.toString().trim())
            .putBoolean(CS.BATTERY_SAVER, sw(view, R.id.battery_saver).isChecked)
            .putBoolean(CS.LAN_MDNS, sw(view, R.id.lan_mdns).isChecked)
            .putBoolean(CS.HOTSPOT, sw(view, R.id.hotspot).isChecked)
            .putBoolean(CS.AUTO_UPDATE, sw(view, R.id.auto_update).isChecked)
            .putBoolean(CS.FORWARD_CLEARNET, sw(view, R.id.forward_clearnet).isChecked)
            .putInt(CS.WORKER_THREADS, workers.coerceIn(0, 16))
            .putString(
                CS.LOG_LEVEL,
                edit(view, R.id.log_level).text.toString().trim().ifEmpty { CS.DEF_LOG_LEVEL }
            )
            .apply()
    }

    private companion object {
        const val STATE_ADVANCED = "advanced_expanded"

        /** Every persisted widget; [watchForEdits] must see all of them. */
        val SWITCHES = intArrayOf(
            R.id.inbound_filter, R.id.lan_mdns, R.id.hotspot, R.id.battery_saver,
            R.id.auto_update, R.id.forward_clearnet,
        )
        val TEXT_FIELDS = intArrayOf(
            R.id.peer_npub, R.id.peer_endpoint, R.id.peer_transport, R.id.inbound_ports,
            R.id.worker_threads, R.id.log_level,
        )
    }
}
