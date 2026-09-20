package org.fips.android

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.button.MaterialButton
import org.json.JSONArray
import org.json.JSONObject
import kotlin.concurrent.thread
import org.fips.android.ConfigStore as CS

/** Diagnostics page: resolve/ping an npub, and view the node's logs. */
class TroubleshootFragment : Fragment() {

    private val poller = Handler(Looper.getMainLooper())
    private lateinit var logView: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var sessionsView: TextView
    private lateinit var lanList: LinearLayout
    private lateinit var lanEmpty: TextView
    private lateinit var hotspotStatus: TextView

    /** Structural fingerprint of the rendered LAN rows (see [refreshLanPeers]). */
    private var lastLanKey = ""

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_troubleshoot, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        logView = view.findViewById(R.id.log_view)
        logScroll = view.findViewById(R.id.log_scroll)
        sessionsView = view.findViewById(R.id.sessions_view)
        lanList = view.findViewById(R.id.lan_list)
        lanEmpty = view.findViewById(R.id.lan_empty)
        hotspotStatus = view.findViewById(R.id.hotspot_status)
        val result = view.findViewById<TextView>(R.id.probe_result)
        val npubField = view.findViewById<EditText>(R.id.probe_npub)

        // The result well stays out of the layout until it has something in it.
        val show = { text: String ->
            result.text = text
            result.visibility = View.VISIBLE
        }
        view.findViewById<MaterialButton>(R.id.resolve).setOnClickListener {
            val npub = npubField.text.toString().trim()
            val info = JSONObject(FipsNative.resolveNpub(npub))
            show(
                if (info.has("error")) {
                    "✗ ${info.getString("error")}"
                } else {
                    "npub:  ${info.getString("npub")}\naddr:  ${info.getString("address")}"
                }
            )
        }

        view.findViewById<MaterialButton>(R.id.reachability).setOnClickListener {
            show(checkReachability(npubField.text.toString().trim()))
        }

        view.findViewById<MaterialButton>(R.id.refresh_logs).setOnClickListener {
            refreshLogs(force = true)
        }
        view.findViewById<MaterialButton>(R.id.copy_logs).setOnClickListener {
            Ui.copy(view, "fips logs", logView.text, "Logs copied")
        }
        view.findViewById<MaterialButton>(R.id.expand_logs).setOnClickListener {
            showLogDialog()
        }

        val ctx = requireContext()
        val pkg = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        @Suppress("DEPRECATION")
        val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkg.longVersionCode
        } else {
            pkg.versionCode.toLong()
        }
        view.findViewById<TextView>(R.id.app_version).text =
            "fips2go ${pkg.versionName} (build $code, ${Build.SUPPORTED_ABIS.firstOrNull()})"
        view.findViewById<MaterialButton>(R.id.check_update).setOnClickListener {
            checkForUpdate(view, pkg.versionName ?: "0")
        }
    }

    /**
     * Manual update check against GitHub Releases; the offer/download/install
     * UI is shared with the automatic startup check ([UpdateUi]).
     */
    private fun checkForUpdate(root: View, current: String) {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: return
        Ui.snack(root, "Checking for updates…")
        thread {
            val result = runCatching { Updater.check(current, abi) }
            activity?.runOnUiThread {
                result.fold(
                    onSuccess = { update ->
                        if (update == null) {
                            Ui.snack(root, "Up to date (v$current)")
                        } else {
                            offerUpdate(root, update)
                        }
                    },
                    onFailure = {
                        Ui.snack(root, "Update check failed: ${it.message}", long = true)
                    },
                )
            }
        }
    }

    private fun offerUpdate(root: View, update: Updater.Update) {
        UpdateUi.offer(requireActivity() as AppCompatActivity, root, update)
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
            refreshLanPeers()
            poller.postDelayed(this, 2000)
        }
    }

    private data class LanPeer(
        val npub: String,
        val addr: String,
        val lastSeenMs: Long,
        val connected: Boolean,
    )

    /**
     * "Nearby (mDNS)" card: peers whose LAN advert the node has seen since it
     * started (`show_lan_peers`), joined against `show_peers` for connection
     * state. The node auto-dials discoveries, so most rows show connected; the
     * Connect button is the manual retry for the ones that aren't. Rows are
     * rebuilt only when the structural fingerprint changes — the per-row age
     * line is updated in place so an in-flight tap isn't cancelled by a
     * removeAllViews under the finger.
     */
    private fun refreshLanPeers() {
        val running = FipsNative.isRunning()
        val rows = ArrayList<LanPeer>()
        if (running) {
            try {
                val connected = HashSet<String>()
                val peers = queryData("show_peers").optJSONArray("peers") ?: JSONArray()
                for (i in 0 until peers.length()) {
                    connected.add(peers.getJSONObject(i).optString("npub"))
                }
                val lan = queryData("show_lan_peers").optJSONArray("lan_peers") ?: JSONArray()
                for (i in 0 until lan.length()) {
                    val o = lan.getJSONObject(i)
                    val npub = o.optString("npub")
                    rows.add(
                        LanPeer(npub, o.optString("addr"), o.optLong("last_seen_ms"), npub in connected)
                    )
                }
            } catch (_: Exception) {
                // Engine mid-restart (network change) — keep the last render.
                return
            }
        }

        // FIPS Hotspot line: joined state while the service reports one,
        // otherwise a hint that the armed toggle is waiting for the SSID.
        val hotspotJoined = FipsVpnService.hotspotStatus
        val hotspotArmed = CS.hotspotEnabled(requireContext())
        hotspotStatus.visibility =
            if (running && (hotspotJoined != null || hotspotArmed)) View.VISIBLE else View.GONE
        hotspotStatus.text = when {
            hotspotJoined != null -> "FIPS Hotspot: connected ($hotspotJoined)"
            else -> "FIPS Hotspot: waiting for \"!FIPS\" to come in range"
        }

        lanEmpty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
        if (rows.isEmpty()) {
            lanEmpty.text = when {
                !running -> "(node not running)"
                !CS.lanMdns(requireContext()) && hotspotJoined == null ->
                    "LAN discovery is off — enable \"LAN discovery (mDNS)\" in Settings " +
                        "and reconnect."
                else -> "Nothing discovered yet — fips peers on this Wi-Fi appear here " +
                    "(can take a minute or two)."
            }
        }

        val key = rows.joinToString("|") { "${it.npub},${it.addr},${it.connected}" }
        if (key != lastLanKey) {
            lastLanKey = key
            lanList.removeAllViews()
            for (peer in rows) {
                val row = layoutInflater.inflate(R.layout.item_lan_peer, lanList, false)
                row.findViewById<TextView>(R.id.lan_npub).text = shortNpub(peer.npub)
                row.findViewById<TextView>(R.id.lan_status).visibility =
                    if (peer.connected) View.VISIBLE else View.GONE
                val connect = row.findViewById<MaterialButton>(R.id.lan_connect)
                connect.visibility = if (peer.connected) View.GONE else View.VISIBLE
                connect.setOnClickListener { connectLanPeer(peer) }
                // Tapping the row drops the full npub into the probe field
                // (resolve / reachability) and the clipboard.
                row.setOnClickListener {
                    view?.findViewById<EditText>(R.id.probe_npub)?.setText(peer.npub)
                    Ui.copy(requireView(), "npub", peer.npub, "npub copied")
                }
                lanList.addView(row)
            }
            capLanListHeight(rows.size)
        }
        for (i in 0 until lanList.childCount) {
            val peer = rows.getOrNull(i) ?: break
            lanList.getChildAt(i).findViewById<TextView>(R.id.lan_detail).text =
                "${peer.addr} · seen ${age(peer.lastSeenMs).trim().ifEmpty { "just now" }}"
        }
    }

    /**
     * Let the peer list grow freely while it is short, then cap it and let it
     * scroll internally. A busy LAN can advertise dozens of peers, and an
     * uncapped list turns the rest of the page — Logs especially — into a long
     * scroll to reach.
     */
    private fun capLanListHeight(count: Int) {
        val scroll = view?.findViewById<View>(R.id.lan_scroll) ?: return
        val capped = count > MAX_UNCAPPED_LAN_ROWS
        val want = if (capped) {
            (LAN_LIST_CAP_DP * resources.displayMetrics.density).toInt()
        } else {
            ViewGroup.LayoutParams.WRAP_CONTENT
        }
        if (scroll.layoutParams.height != want) {
            scroll.layoutParams = scroll.layoutParams.apply { height = want }
            scroll.requestLayout()
        }
    }

    private fun connectLanPeer(peer: LanPeer) {
        val root = requireView()
        Ui.snack(root, "Connecting to ${shortNpub(peer.npub)}…")
        thread {
            val resp = runCatching { JSONObject(FipsNative.connectPeer(peer.npub, peer.addr)) }
                .getOrNull()
            activity?.runOnUiThread {
                val msg = when {
                    resp == null -> "Connect failed (engine not responding)"
                    resp.optString("status") == "ok" ->
                        "Handshake initiated — watch Sessions above"
                    else -> "Connect failed: ${resp.optString("message", "unknown error")}"
                }
                Ui.snack(root, msg, long = true)
            }
        }
    }

    private fun shortNpub(npub: String): String =
        if (npub.length > 20) "${npub.take(10)}…${npub.takeLast(6)}" else npub

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
        return shortNpub(o.optString("npub"))
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
    /**
     * Fullscreen live log viewer — the inline window shares the page with
     * three cards and gets squeezed; this one gets the whole screen, live
     * 2 s refresh, and sticks to the bottom unless scrolled up to read.
     */
    private fun showLogDialog() {
        val ctx = requireContext()
        val text = TextView(ctx).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
            setPadding(24, 16, 24, 16)
        }
        val scroll = ScrollView(ctx).apply { addView(text) }
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(ctx)
            .setTitle("Node log")
            .setView(scroll)
            .setPositiveButton("Close", null)
            .setNeutralButton("Copy") { _, _ ->
                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("fips logs", text.text))
            }
            .create()
        val updater = object : Runnable {
            override fun run() {
                if (!dialog.isShowing) return
                val atBottom = !scroll.canScrollVertically(1)
                val logs = FipsNative.recentLogs(1000)
                if (logs != text.text.toString()) {
                    text.text = logs
                    if (atBottom) scroll.post { scroll.scrollTo(0, text.bottom) }
                }
                poller.postDelayed(this, 2000)
            }
        }
        dialog.setOnShowListener {
            dialog.window?.setLayout(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
            text.text = FipsNative.recentLogs(1000)
            scroll.post { scroll.scrollTo(0, text.bottom) }
            poller.postDelayed(updater, 2000)
        }
        dialog.setOnDismissListener { poller.removeCallbacks(updater) }
        dialog.show()
    }

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

    private companion object {
        /** Peer counts up to this render at full height. */
        const val MAX_UNCAPPED_LAN_ROWS = 6

        /** Height the peer list is pinned to beyond that, in dp. */
        const val LAN_LIST_CAP_DP = 300
    }
}
