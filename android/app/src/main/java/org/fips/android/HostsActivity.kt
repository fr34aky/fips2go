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

/**
 * The mesh-name address book: `home` → npub, so mesh apps can open
 * `home.fips`. See [HostsStore] for where the names live and why an edit
 * needs no reconnect — which is also why, unlike [RelaysActivity], there is
 * no "applied on leaving" hint and no rebind in onPause.
 *
 * Saving a name that already exists re-points it (tapping a row loads it into
 * the fields for exactly that); several names may share one npub.
 */
class HostsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_hosts)
        findViewById<MaterialToolbar>(R.id.toolbar).setNavigationOnClickListener { finish() }

        findViewById<MaterialButton>(R.id.host_add).setOnClickListener { add() }
        findViewById<EditText>(R.id.host_npub).setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) add()
            action == EditorInfo.IME_ACTION_DONE
        }
        render()
    }

    private fun add() {
        val nameField = findViewById<EditText>(R.id.host_name)
        val npubField = findViewById<EditText>(R.id.host_npub)
        val nameLayout = findViewById<TextInputLayout>(R.id.host_name_layout)
        val npubLayout = findViewById<TextInputLayout>(R.id.host_npub_layout)

        val name = HostsStore.normalizeName(nameField.text.toString())
        val npub = HostsStore.normalizeNpub(npubField.text.toString())
        val current = HostsStore.load(this)
        val replacing = current.any { it.name == name }
        nameLayout.error = HostsStore.nameError(name)
            ?: "At most ${HostsStore.MAX_HOSTS} names".takeIf {
                !replacing && current.size >= HostsStore.MAX_HOSTS
            }
        npubLayout.error = if (npub == null) "Not an npub — expected npub1…" else null
        if (nameLayout.error != null || npub == null) return

        val entry = HostsStore.Host(name, npub)
        val updated =
            if (replacing) current.map { if (it.name == name) entry else it } else current + entry
        if (!store(updated)) return
        nameField.setText("")
        npubField.setText("")
        nameField.requestFocus()
        if (replacing) Ui.snack(nameField, "$name.fips now points to ${shortNpub(npub)}")
        render()
    }

    /** False (with a message) when the file could not be written. */
    private fun store(hosts: List<HostsStore.Host>): Boolean {
        val failure = runCatching { HostsStore.save(this, hosts) }.exceptionOrNull() ?: return true
        Ui.snack(findViewById(R.id.host_list), "Could not save: ${failure.message}", long = true)
        return false
    }

    private fun render() {
        val hosts = HostsStore.load(this)
        findViewById<View>(R.id.host_empty).visibility =
            if (hosts.isEmpty()) View.VISIBLE else View.GONE
        findViewById<View>(R.id.host_list_card).visibility =
            if (hosts.isEmpty()) View.GONE else View.VISIBLE

        val list = findViewById<LinearLayout>(R.id.host_list)
        list.removeAllViews()
        for (host in hosts) {
            val fqdn = "${host.name}.fips"
            val row = layoutInflater.inflate(R.layout.item_host_edit, list, false)
            row.findViewById<TextView>(R.id.host_row_name).text = fqdn
            row.findViewById<TextView>(R.id.host_row_npub).text = host.npub
            row.setOnClickListener {
                findViewById<EditText>(R.id.host_name).setText(host.name)
                findViewById<EditText>(R.id.host_npub).setText(host.npub)
            }
            val copy = row.findViewById<MaterialButton>(R.id.host_copy)
            copy.contentDescription = "Copy $fqdn"
            copy.setOnClickListener { Ui.copy(row, "fips name", fqdn, "$fqdn copied") }
            val remove = row.findViewById<MaterialButton>(R.id.host_remove)
            remove.contentDescription = "Remove $fqdn"
            remove.setOnClickListener {
                if (store(HostsStore.load(this).filter { it.name != host.name })) render()
            }
            list.addView(row)
        }
    }

    private fun shortNpub(npub: String): String =
        if (npub.length > 20) "${npub.take(10)}…${npub.takeLast(6)}" else npub
}
