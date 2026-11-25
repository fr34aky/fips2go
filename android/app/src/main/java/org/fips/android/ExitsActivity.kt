package org.fips.android

import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputLayout
import org.json.JSONObject
import kotlin.concurrent.thread
import org.fips.android.ConfigStore as CS

/**
 * Internet route: the mesh apps' internet traffic leaves through the phone's
 * own connection (the shim's forwarder) or through an exit node over the mesh
 * (`shim/src/exit.rs`). Mesh traffic is never affected.
 *
 * Every edit is stored at once. A live tunnel is nudged ONCE, on leaving the
 * screen with a changed selection ([FipsVpnService.requestRebind]); the shim
 * switches the exit in the running node — a config that differs only in
 * `exit_node` keeps the node — and the service rebuilds the tunnel because
 * its IPv6 route follows the selection ([FipsVpnService.wantIpv6Route]).
 */
class ExitsActivity : AppCompatActivity() {

    /** The exit npub the running node was given (null = the phone). */
    private var appliedExit: String? = null

    /** The last search's answer ([FipsNative.findExits]), kept across a rotation. */
    private var foundJson: String? = null
    @Volatile private var searching = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_exits)
        findViewById<MaterialToolbar>(R.id.toolbar).setNavigationOnClickListener { finish() }
        appliedExit = if (savedInstanceState?.containsKey(STATE_APPLIED) == true) {
            savedInstanceState.getString(STATE_APPLIED)
        } else {
            CS.selectedExit(this)?.npub
        }

        val ownNpub = ownNpub()
        findViewById<TextView>(R.id.exit_own_npub).text = ownNpub
        findViewById<MaterialButton>(R.id.exit_copy_npub).setOnClickListener {
            Ui.copy(it, "npub", ownNpub, "Public key copied")
        }

        val name = findViewById<EditText>(R.id.exit_name)
        val npub = findViewById<EditText>(R.id.exit_npub)
        val npubLayout = findViewById<TextInputLayout>(R.id.exit_npub_layout)
        val add = {
            val error = addExit(name.text.toString(), npub.text.toString(), ownNpub)
            npubLayout.error = error
            if (error == null) {
                name.setText("")
                npub.setText("")
            }
        }
        findViewById<MaterialButton>(R.id.exit_add).setOnClickListener { add() }
        npub.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) add()
            action == EditorInfo.IME_ACTION_DONE
        }
        foundJson = savedInstanceState?.getString(STATE_FOUND)
        findViewById<MaterialButton>(R.id.exit_find).setOnClickListener { search() }
        render()
        renderFound()
    }

    /**
     * Ask the relays for exit adverts (`shim/src/exitfind.rs`). Only ever
     * from this button: the search tells a public relay that this phone is
     * looking for an exit.
     */
    private fun search() {
        if (searching) return
        val status = findViewById<TextView>(R.id.exit_find_status)
        if (!FipsNative.isRunning()) {
            status.text = "Connect to the mesh first: the search runs through the node."
            status.visibility = View.VISIBLE
            return
        }
        searching = true
        findViewById<MaterialButton>(R.id.exit_find).isEnabled = false
        status.text = "Searching…"
        status.visibility = View.VISIBLE
        thread(name = "fips-find-exits") {
            val json = try {
                FipsNative.findExits(SEARCH_MS)
            } catch (e: Throwable) {
                JSONObject().put("error", e.toString()).toString()
            }
            runOnUiThread {
                searching = false
                foundJson = json
                if (!isFinishing && !isDestroyed) {
                    findViewById<MaterialButton>(R.id.exit_find).isEnabled = true
                    renderFound()
                }
            }
        }
    }

    /** Show [foundJson]: the adverts, or why there are none. */
    private fun renderFound() {
        val status = findViewById<TextView>(R.id.exit_find_status)
        val card = findViewById<View>(R.id.exit_found_card)
        val list = findViewById<LinearLayout>(R.id.exit_found)
        list.removeAllViews()
        val found = try {
            foundJson?.let { JSONObject(it) }
        } catch (e: Exception) {
            null
        }
        if (found == null) {
            card.visibility = View.GONE
            if (!searching) status.visibility = View.GONE
            return
        }
        val exits = found.optJSONArray("exits")
        val meshRelays = found.optInt("mesh_relays")
        val publicRelays = found.optInt("public_relays")
        status.visibility = View.VISIBLE
        status.text = when {
            found.has("error") -> "Search failed: ${found.optString("error")}"
            meshRelays + publicRelays == 0 ->
                "No relay to ask. This phone has no internet right now and no mesh relay is " +
                    "set: add one under Settings → Mesh relays for public names."
            exits == null || exits.length() == 0 ->
                "No exit is advertising on the ${relayCount(meshRelays, publicRelays)} asked."
            else -> "${exits.length()} found on the ${relayCount(meshRelays, publicRelays)} asked."
        }
        if (exits == null || exits.length() == 0) {
            card.visibility = View.GONE
            return
        }
        card.visibility = View.VISIBLE
        val ownNpub = ownNpub()
        for (i in 0 until exits.length()) {
            val exit = exits.optJSONObject(i) ?: continue
            val npub = exit.optString("npub")
            val name = exit.optString("name")
            val open = exit.optString("access") == "open"
            val v = layoutInflater.inflate(R.layout.item_found_exit, list, false)
            v.findViewById<TextView>(R.id.found_title).text =
                name.ifEmpty { CS.exitLabel(CS.ExitNode("", npub)) }
            v.findViewById<TextView>(R.id.found_access).text = if (open) {
                "Says it is open to anyone"
            } else {
                "Allow-list: its operator has to add this phone's npub"
            }
            v.findViewById<TextView>(R.id.found_about).apply {
                text = exit.optString("about")
                visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
            }
            v.findViewById<TextView>(R.id.found_npub).text = npub
            val add = v.findViewById<MaterialButton>(R.id.found_add)
            val known = CS.exitNodes(this).any { it.npub == npub }
            add.isEnabled = !known
            add.text = if (known) "Added" else "Add"
            add.contentDescription = "Add ${name.ifEmpty { npub }}"
            add.setOnClickListener {
                // Adds to the list above; choosing it stays a separate tap.
                val error = addExit(name, npub, ownNpub)
                if (error != null) Ui.snack(it, error) else renderFound()
            }
            list.addView(v)
        }
    }

    private fun relayCount(mesh: Int, public: Int): String {
        val parts = listOfNotNull(
            mesh.takeIf { it > 0 }?.let { "$it mesh relay${if (it == 1) "" else "s"}" },
            public.takeIf { it > 0 }?.let { "$it public relay${if (it == 1) "" else "s"}" },
        )
        return parts.joinToString(" and ")
    }

    private fun ownNpub(): String = try {
        JSONObject(FipsNative.deriveIdentity(IdentityStore.getOrCreate(this))).optString("npub")
    } catch (e: Exception) {
        ""
    }

    /** Returns the error to show under the npub field, or null when added. */
    private fun addExit(typedName: String, typedNpub: String, ownNpub: String): String? {
        if (typedNpub.isBlank()) return "Enter the exit node's npub"
        val info = JSONObject(FipsNative.resolveNpub(typedNpub.trim()))
        if (info.has("error")) return "Not an npub"
        val npub = info.getString("npub")
        if (npub == ownNpub) return "That is this phone"
        val current = CS.exitNodes(this)
        if (current.any { it.npub == npub }) return "Already in the list"
        if (current.size >= CS.MAX_EXITS) return "At most ${CS.MAX_EXITS} exit nodes"
        CS.setExitNodes(this, current + CS.ExitNode(typedName.trim(), npub))
        render()
        return null
    }

    private fun render() {
        val list = findViewById<LinearLayout>(R.id.exit_list)
        list.removeAllViews()
        val selected = CS.selectedExit(this)?.npub

        fun row(title: String, detail: String, checked: Boolean, onRemove: (() -> Unit)?, onPick: () -> Unit) {
            val v = layoutInflater.inflate(R.layout.item_exit, list, false)
            v.findViewById<TextView>(R.id.exit_title).text = title
            v.findViewById<TextView>(R.id.exit_detail).text = detail
            v.findViewById<RadioButton>(R.id.exit_radio).isChecked = checked
            val remove = v.findViewById<MaterialButton>(R.id.exit_remove)
            if (onRemove == null) {
                remove.visibility = View.INVISIBLE
            } else {
                remove.contentDescription = "Remove $title"
                remove.setOnClickListener { onRemove() }
            }
            v.setOnClickListener { onPick() }
            list.addView(v)
        }

        row("This phone's connection", "Mesh apps go online like any other app", selected == null, null) {
            CS.selectExit(this, null)
            render()
        }
        for (node in CS.exitNodes(this)) {
            row(CS.exitLabel(node), node.npub, node.npub == selected, {
                CS.setExitNodes(this, CS.exitNodes(this).filter { it.npub != node.npub })
                render()
            }) {
                CS.selectExit(this, node.npub)
                render()
            }
        }
        updateHint()
        // An exit removed above can be added again from the list below.
        if (foundJson != null) renderFound()
    }

    private fun updateHint() {
        val changed = CS.selectedExit(this)?.npub != appliedExit
        findViewById<View>(R.id.exit_apply_hint).visibility =
            if (FipsVpnService.tunnelActive && changed) View.VISIBLE else View.GONE
    }

    override fun onResume() {
        super.onResume()
        updateHint()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_APPLIED, appliedExit)
        outState.putString(STATE_FOUND, foundJson)
    }

    /** onPause: still in the foreground, so startService is legal; see RelaysActivity. */
    override fun onPause() {
        super.onPause()
        if (isChangingConfigurations) return
        val now = CS.selectedExit(this)?.npub
        if (now == appliedExit) return
        appliedExit = now
        FipsVpnService.requestRebind(this)
    }

    private companion object {
        const val STATE_APPLIED = "applied_exit"
        const val STATE_FOUND = "found_exits"
        const val SEARCH_MS = 8000
    }
}
