package org.fips.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import org.json.JSONObject

/** Diagnostics page: resolve/ping an npub, and view the node's logs. */
class TroubleshootFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_troubleshoot, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        logView = view.findViewById(R.id.log_view)
        logScroll = view.findViewById(R.id.log_scroll)
        val result = view.findViewById<TextView>(R.id.probe_result)
        val npubField = view.findViewById<EditText>(R.id.probe_npub)

        view.findViewById<MaterialButton>(R.id.resolve).setOnClickListener {
            val npub = npubField.text.toString().trim()
            val info = JSONObject(FipsNative.resolveNpub(npub))
            result.text = if (info.has("error")) {
                "✗ ${info.getString("error")}"
            } else {
                "npub:  ${info.getString("npub")}\naddr:  ${info.getString("address")}"
            }
        }

        view.findViewById<MaterialButton>(R.id.reachability).setOnClickListener {
            result.text = checkReachability(npubField.text.toString().trim())
        }

        view.findViewById<MaterialButton>(R.id.refresh_logs).setOnClickListener {
            refreshLogs(force = true)
        }
        view.findViewById<MaterialButton>(R.id.copy_logs).setOnClickListener {
            val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("fips logs", logView.text))
        }
    }

    /**
     * Resolve the npub, then check whether the running node currently has an
     * active link or a cached route/coordinate to that address. This reflects
     * the node's live view (not an end-to-end ICMP ping).
     */
    private fun checkReachability(npub: String): String {
        val info = JSONObject(FipsNative.resolveNpub(npub))
        if (info.has("error")) return "✗ ${info.getString("error")}"
        val address = info.getString("address")
        if (!FipsNative.isRunning()) return "addr:  $address\n(node not running — connect first)"

        val hay = buildString {
            append(FipsNative.query("show_peers", ""))
            append(FipsNative.query("show_routing", ""))
            append(FipsNative.query("show_cache", ""))
        }
        val known = hay.contains(address) || hay.contains(info.getString("npub"))
        return "addr:  $address\n" +
            if (known) "✓ known to the node (active link or cached route)"
            else "• not currently known (no active link / cached route)"
    }

    override fun onResume() {
        super.onResume()
        poller.post(logPoller)
    }

    override fun onPause() {
        poller.removeCallbacks(logPoller)
        super.onPause()
    }

    private val logPoller = object : Runnable {
        override fun run() {
            refreshLogs()
            poller.postDelayed(this, 2000)
        }
    }

    /**
     * Update the log view, keeping it readable while the user scrolls:
     * replacing the text resets the ScrollView position, so while the user is
     * scrolled up reading, leave the view frozen — it catches up as soon as
     * they return to the bottom, or immediately on the Refresh button
     * (`force`). Unchanged text is never re-set (no relayout, no jump), and
     * sticking to the bottom uses `scrollTo` rather than `fullScroll`, which
     * would also move focus.
     */
    private fun refreshLogs(force: Boolean = false) {
        val atBottom = !logScroll.canScrollVertically(1)
        if (!force && !atBottom) return
        val logs = FipsNative.recentLogs(500)
        if (logs != logView.text.toString()) {
            logView.text = logs
            logScroll.post { logScroll.scrollTo(0, logView.bottom) }
        } else if (force && !atBottom) {
            logScroll.post { logScroll.scrollTo(0, logView.bottom) }
        }
    }
}
