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
import org.json.JSONArray
import org.json.JSONObject

/** Diagnostics page: resolve/ping an npub, and view the node's logs. */
class TroubleshootFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var sessionsView: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_troubleshoot, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        logView = view.findViewById(R.id.log_view)
        logScroll = view.findViewById(R.id.log_scroll)
        sessionsView = view.findViewById(R.id.sessions_view)
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
            refreshSessions()
            poller.postDelayed(this, 2000)
        }
    }

    /**
     * Live FMP (network/routing links to direct peers) and FSP (end-to-end
     * encrypted sessions) view, from the node's lock-free `show_*` snapshots.
     * FMP byte counters come from `show_links`, joined via `link_id`.
     */
    private fun refreshSessions() {
        val text = if (!FipsNative.isRunning()) {
            "(node not running)"
        } else {
            try {
                renderSessions()
            } catch (e: Exception) {
                "(sessions unavailable: ${e.message})"
            }
        }
        // Only touch the view on change — keeps text selection alive.
        if (sessionsView.text.toString() != text) sessionsView.text = text
    }

    private fun queryData(cmd: String): JSONObject {
        val root = JSONObject(FipsNative.query(cmd, ""))
        return root.optJSONObject("data") ?: root
    }

    private fun renderSessions(): String {
        val peers = queryData("show_peers").optJSONArray("peers") ?: JSONArray()
        val sessions = queryData("show_sessions").optJSONArray("sessions") ?: JSONArray()
        val links = queryData("show_links").optJSONArray("links") ?: JSONArray()

        // link_id → (bytes_sent, bytes_recv) for the FMP traffic columns.
        val linkStats = HashMap<Long, Pair<Long, Long>>()
        for (i in 0 until links.length()) {
            val l = links.getJSONObject(i)
            val s = l.optJSONObject("stats") ?: continue
            linkStats[l.optLong("link_id")] =
                Pair(s.optLong("bytes_sent"), s.optLong("bytes_recv"))
        }

        val out = StringBuilder()
        out.append("FMP peers (${peers.length()}) — routing layer\n")
        if (peers.length() == 0) out.append("  (none)\n")
        for (i in 0 until peers.length()) {
            val p = peers.getJSONObject(i)
            val role = when {
                p.optBoolean("is_parent") -> "▲"
                p.optBoolean("is_child") -> "▼"
                else -> "•"
            }
            val transport = listOfNotNull(
                p.optString("transport_type").ifEmpty { null },
                p.optString("transport_addr").ifEmpty { null },
            ).joinToString(" ")
            val traffic = linkStats[p.optLong("link_id")]
                ?.let { "↑${fmtBytes(it.first)} ↓${fmtBytes(it.second)}" } ?: ""
            out.append(
                "$role ${peerName(p)}  ${p.optString("connectivity")}" +
                    (if (transport.isEmpty()) "" else "  $transport") +
                    (if (traffic.isEmpty()) "" else "  $traffic") +
                    age(p.optLong("last_seen_ms")) + "\n"
            )
        }

        out.append("\nFSP sessions (${sessions.length()}) — end-to-end\n")
        if (sessions.length() == 0) out.append("  (none)\n")
        for (i in 0 until sessions.length()) {
            val s = sessions.getJSONObject(i)
            val state = s.optString("state")
            val mark = if (state == "established") "●" else "◐"
            val st = s.optJSONObject("stats")
            val traffic = st?.let {
                "↑${fmtBytes(it.optLong("bytes_sent"))}/${it.optLong("packets_sent")}p" +
                    " ↓${fmtBytes(it.optLong("bytes_recv"))}/${it.optLong("packets_recv")}p"
            } ?: ""
            out.append(
                "$mark ${peerName(s)}  $state" +
                    (if (traffic.isEmpty()) "" else "  $traffic") +
                    age(s.optLong("last_activity_ms")) + "\n"
            )
        }
        return out.toString().trimEnd()
    }

    /** display_name when set, else a shortened npub. */
    private fun peerName(o: JSONObject): String {
        val dn = o.optString("display_name")
        if (dn.isNotEmpty() && dn != "null") return dn
        val npub = o.optString("npub")
        return if (npub.length > 20) "${npub.take(10)}…${npub.takeLast(6)}" else npub
    }

    private fun fmtBytes(b: Long): String = when {
        b >= 1_048_576 -> "%.1fMB".format(b / 1_048_576.0)
        b >= 1024 -> "%.1fKB".format(b / 1024.0)
        else -> "${b}B"
    }

    /** "  Ns ago" when the timestamp is plausibly epoch-ms and recent. */
    private fun age(ms: Long): String {
        val d = System.currentTimeMillis() - ms
        if (ms <= 0 || d < 0 || d > 7 * 24 * 3600_000L) return ""
        return "  ${if (d < 60_000) "${d / 1000}s" else "${d / 60_000}m"} ago"
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
