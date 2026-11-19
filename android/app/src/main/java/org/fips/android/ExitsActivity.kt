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
        render()
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
    }
}
