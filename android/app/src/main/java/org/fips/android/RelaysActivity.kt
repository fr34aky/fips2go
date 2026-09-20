package org.fips.android

import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputLayout
import org.fips.android.ConfigStore as CS

/**
 * Add / remove the Nostr relays the node uses for rendezvous.
 *
 * Until the user changes something the node runs on fips's built-in relays and
 * nothing is stored ([ConfigStore.customRelays] is null); the list shown is
 * then [ConfigStore.DEFAULT_RELAYS], a display mirror. The first edit turns
 * that list into a stored one; "Reset to defaults" deletes it again, which is
 * different from re-adding the same three URLs: only the unset state keeps
 * following fips's defaults across pin bumps.
 *
 * Input is validated through [ConfigStore.normalizeRelay] before it is stored,
 * because one URL nostr-sdk rejects fails the node's whole Nostr bootstrap. The
 * last relay cannot be removed: the shim reads an empty list as "use the
 * defaults", so an empty editor would be lying about what the node does.
 *
 * Like the mesh-app picker, every edit is persisted immediately and a live
 * tunnel is nudged ONCE ([FipsVpnService.requestRebind]), on leaving the
 * screen with a changed list — fips
 * fixes its relay pool at node start, so applying means a node restart.
 */
class RelaysActivity : AppCompatActivity() {

    /** What the running node was (or the next one would have been) given. */
    private var appliedRelays: List<String> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_relays)
        findViewById<MaterialToolbar>(R.id.toolbar).setNavigationOnClickListener { finish() }
        // Across a rotation "what the node has" is NOT what is stored now.
        appliedRelays = savedInstanceState?.getStringArrayList(STATE_APPLIED)
            ?: CS.effectiveRelays(this)

        val input = findViewById<EditText>(R.id.relay_input)
        val inputLayout = findViewById<TextInputLayout>(R.id.relay_input_layout)
        val add = {
            val error = addRelay(input.text.toString())
            inputLayout.error = error
            if (error == null) input.setText("")
        }
        findViewById<MaterialButton>(R.id.relay_add).setOnClickListener { add() }
        input.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) add()
            action == EditorInfo.IME_ACTION_DONE
        }
        findViewById<MaterialButton>(R.id.relay_reset).setOnClickListener {
            CS.setCustomRelays(this, null)
            inputLayout.error = null
            render()
        }
        render()
    }

    /** Returns the error to show under the field, or null when added. */
    private fun addRelay(typed: String): String? {
        if (typed.isBlank()) return "Enter a relay address"
        val relay = CS.normalizeRelay(typed)
            ?: return "Not a relay address — expected wss://host or ws://host"
        val current = CS.effectiveRelays(this)
        if (relay in current) return "Already in the list"
        if (current.size >= CS.MAX_RELAYS) {
            return "At most ${CS.MAX_RELAYS} relays — each one is a standing connection"
        }
        CS.setCustomRelays(this, current + relay)
        render()
        return null
    }

    private fun render() {
        val custom = CS.customRelays(this)
        val relays = custom ?: CS.DEFAULT_RELAYS
        findViewById<TextView>(R.id.relay_list_label).text =
            if (custom == null) "Default relays" else "Your relays"
        findViewById<View>(R.id.relay_reset).visibility =
            if (custom == null) View.GONE else View.VISIBLE

        val list = findViewById<LinearLayout>(R.id.relay_list)
        list.removeAllViews()
        for (relay in relays) {
            val row = layoutInflater.inflate(R.layout.item_relay_edit, list, false)
            row.findViewById<TextView>(R.id.relay_url).text = relay
            val remove = row.findViewById<MaterialButton>(R.id.relay_remove)
            remove.contentDescription = "Remove $relay"
            // See the class doc: an empty list would silently mean "defaults".
            remove.isEnabled = relays.size > 1
            remove.setOnClickListener {
                CS.setCustomRelays(this, CS.effectiveRelays(this) - relay)
                render()
            }
            list.addView(row)
        }
    }

    override fun onResume() {
        super.onResume()
        findViewById<View>(R.id.reconnect_hint).visibility =
            if (FipsVpnService.tunnelActive) View.VISIBLE else View.GONE
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(STATE_APPLIED, ArrayList(appliedRelays))
    }

    /**
     * onPause, not onStop: still in the foreground, so startService is legal.
     * A rotation is not leaving the screen — see AppPickerActivity.onPause.
     */
    override fun onPause() {
        super.onPause()
        if (isChangingConfigurations) return
        val now = CS.effectiveRelays(this)
        if (now == appliedRelays) return
        appliedRelays = now
        FipsVpnService.requestRebind(this)
    }

    private companion object {
        const val STATE_APPLIED = "applied_relays"
    }
}
