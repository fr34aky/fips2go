package org.fips.android

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.snackbar.Snackbar
import org.fips.android.ConfigStore as CS

/** Settings page: structured common parameters + a raw fips.yaml override. */
class SettingsFragment : Fragment() {

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_settings, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        load(view)
        view.findViewById<MaterialButton>(R.id.load_template).setOnClickListener {
            view.findViewById<EditText>(R.id.fips_yaml).setText(CS.DEFAULT_YAML_TEMPLATE)
        }
        view.findViewById<MaterialButton>(R.id.save).setOnClickListener {
            save(view)
            Snackbar.make(view, "Saved — reconnect to apply", Snackbar.LENGTH_SHORT).show()
        }
    }

    private fun edit(view: View, id: Int) = view.findViewById<EditText>(id)
    private fun sw(view: View, id: Int) = view.findViewById<MaterialSwitch>(id)

    private fun load(view: View) {
        val p = CS.prefs(requireContext())
        edit(view, R.id.peer_npub).setText(p.getString(CS.PEER_NPUB, ""))
        edit(view, R.id.peer_endpoint).setText(p.getString(CS.PEER_ENDPOINT, ""))
        edit(view, R.id.peer_transport).setText(p.getString(CS.PEER_TRANSPORT, "udp"))
        sw(view, R.id.nostr).isChecked = p.getBoolean(CS.NOSTR, false)
        edit(view, R.id.nostr_relays).setText(p.getString(CS.NOSTR_RELAYS, ""))
        edit(view, R.id.stun_servers).setText(p.getString(CS.STUN_SERVERS, ""))
        edit(view, R.id.udp_bind).setText(p.getString(CS.UDP_BIND, ""))
        edit(view, R.id.tcp_bind).setText(p.getString(CS.TCP_BIND, ""))
        sw(view, R.id.enable_fips_dns).isChecked = p.getBoolean(CS.ENABLE_FIPS_DNS, true)
        edit(view, R.id.dns_upstreams).setText(p.getString(CS.DNS_UPSTREAMS, ""))
        sw(view, R.id.battery_saver).isChecked = p.getBoolean(CS.BATTERY_SAVER, true)
        sw(view, R.id.forward_clearnet).isChecked = p.getBoolean(CS.FORWARD_CLEARNET, true)
        edit(view, R.id.worker_threads).setText(p.getInt(CS.WORKER_THREADS, 1).toString())
        edit(view, R.id.log_level).setText(p.getString(CS.LOG_LEVEL, "info"))
        edit(view, R.id.fips_yaml).setText(p.getString(CS.FIPS_YAML, ""))
    }

    private fun save(view: View) {
        val workers = edit(view, R.id.worker_threads).text.toString().trim().toIntOrNull() ?: 1
        CS.prefs(requireContext()).edit()
            .putString(CS.PEER_NPUB, edit(view, R.id.peer_npub).text.toString().trim())
            .putString(CS.PEER_ENDPOINT, edit(view, R.id.peer_endpoint).text.toString().trim())
            .putString(
                CS.PEER_TRANSPORT,
                edit(view, R.id.peer_transport).text.toString().trim().ifEmpty { "udp" }
            )
            .putBoolean(CS.NOSTR, sw(view, R.id.nostr).isChecked)
            .putString(CS.NOSTR_RELAYS, edit(view, R.id.nostr_relays).text.toString().trim())
            .putString(CS.STUN_SERVERS, edit(view, R.id.stun_servers).text.toString().trim())
            .putString(CS.UDP_BIND, edit(view, R.id.udp_bind).text.toString().trim())
            .putString(CS.TCP_BIND, edit(view, R.id.tcp_bind).text.toString().trim())
            .putBoolean(CS.ENABLE_FIPS_DNS, sw(view, R.id.enable_fips_dns).isChecked)
            .putString(CS.DNS_UPSTREAMS, edit(view, R.id.dns_upstreams).text.toString().trim())
            .putBoolean(CS.BATTERY_SAVER, sw(view, R.id.battery_saver).isChecked)
            .putBoolean(CS.FORWARD_CLEARNET, sw(view, R.id.forward_clearnet).isChecked)
            .putInt(CS.WORKER_THREADS, workers.coerceIn(0, 16))
            .putString(
                CS.LOG_LEVEL,
                edit(view, R.id.log_level).text.toString().trim().ifEmpty { "info" }
            )
            .putString(CS.FIPS_YAML, edit(view, R.id.fips_yaml).text.toString().trim())
            .apply()
    }
}
