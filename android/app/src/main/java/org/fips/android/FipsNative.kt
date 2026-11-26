package org.fips.android

/**
 * JNI bridge to the Rust shim (libfips_android.so). Signatures mirror the
 * exports in `shim/src/jni_api.rs` — keep both sides in sync.
 */
object FipsNative {
    init {
        System.loadLibrary("fips_android")
    }

    /**
     * Derive (or generate, when [nsec] is empty) the node identity.
     * Returns JSON `{nsec, npub, address}` or `{"error": "..."}`.
     */
    external fun deriveIdentity(nsec: String): String

    /**
     * Start the embedded node. [callback] receives `protectFd(int)` for each
     * UDP socket the node binds and every socket the shim dials itself. Returns "" on success, an error message otherwise.
     * Blocks until the node is up (worst case ~60s) — call off the main thread.
     */
    external fun start(configJson: String, tunFd: Int, callback: FipsVpnService): String

    /** Stop the node and the fd pump. Idempotent, blocking (graceful drain). */
    external fun stop()

    /**
     * The in-tunnel DNS server address for `VpnService.Builder.addDnsServer`.
     * This is a `fd00::/8` sentinel the pump intercepts — deliberately NOT the
     * node's own tun address (that would be delivered locally by the kernel and
     * never reach the pump).
     */
    external fun dnsServer(): String

    external fun isRunning(): Boolean

    /**
     * Rebuild the node on the given TUN fd after the underlying network
     * changed (Wi-Fi ↔ cellular) or the FIPS Hotspot came/went. Usually the
     * fd from `start`; pass the new fd instead when the tunnel was
     * re-established with different routes. [configJson] is the freshly
     * regenerated shim config for the rebuilt node (empty keeps the previous
     * one). Blocking — call off the main thread. No-op if the engine isn't
     * running.
     */
    external fun onNetworkChanged(tunFd: Int, configJson: String)

    /**
     * Tell the running node the underlying network moved when nothing needs
     * a rebind: wakes its medium-change detector so it re-probes every peer
     * now instead of at its next 5 s poll (the kernel event source it would
     * use is denied to apps). Non-blocking; fine on the main thread. No-op if
     * the engine isn't running.
     */
    external fun networkHint()

    /**
     * Tell the public-names resolver whether a validated Internet network
     * exists. Without one its legacy DNS lookup gets a short wait, so a
     * first offline lookup fails into the mesh path within the budget; the
     * lookup is not skipped, so a network that works but was never
     * validated still verifies online. Sent at start and whenever the
     * answer changes; the shim remembers it across rebinds. No-op if the
     * engine isn't running.
     */
    external fun namesOnline(online: Boolean)

    /**
     * Compact status JSON: `{running, npub, address, status: {...}, relays:
     * [{url, status, connected}]}` — `relays` is the Nostr relay pool with
     * live per-relay state (empty until the node has started it).
     */
    external fun status(): String

    /** Any snapshot-served `show_*` query, e.g. `query("show_peers", "")`. */
    external fun query(command: String, paramsJson: String): String

    /**
     * Manually dial a peer over UDP (Diagnostics "Connect" on an mDNS-seen
     * peer). Returns the node's command response
     * (`{"status":"ok"|"error", ...}`). Blocking — call off the main thread.
     */
    external fun connectPeer(npub: String, address: String): String

    /** Resolve an npub to its `.fips` address. JSON `{npub,address}` or `{error}`. */
    external fun resolveNpub(npub: String): String

    /**
     * `GET http://[<npub's mesh address>]:<port><path>` over the mesh, made
     * inside the shim (this app's own sockets are outside its tunnel).
     * [headersJson] is an object of extra request headers. Returns
     * `{"status": <code>, "body": "<text>"}` or `{"error": "...",
     * "unreachable": <bool>, "restarted": <bool>}` (`restarted`: the engine
     * stopped or was rebuilt under the request). Blocking (up to [timeoutMs]) — call off the
     * main thread. Used by [HostsSync].
     */
    external fun meshHttpGet(
        npub: String, port: Int, path: String, headersJson: String, timeoutMs: Int,
    ): String

    /**
     * Can the selected exit be used right now? Two pings to it through the
     * node: a small one, and one that is a full-size mesh packet (1280
     * bytes). Returns `{"exit": npub | null, "reachable": bool, "full_size":
     * bool}` or `{"error": "..."}`. `reachable` without `full_size` means the
     * exit answers but large packets are lost on the way, so names resolve
     * and no page loads. Blocking (up to twice [timeoutMs]) — call off the
     * main thread.
     */
    external fun exitProbe(timeoutMs: Int): String

    /**
     * Look for exits that advertise themselves on Nostr (`exitfind.rs`): the
     * mesh relays from Settings and, while online, the public relays.
     * Returns `{"exits": [{npub, name, about, access, created_at, expires}],
     * "mesh_relays": n, "public_relays": n}` or `{"error": "..."}`. `access`
     * is `open` or `allow-list`; `name` and `about` are the operator's own
     * words, already reduced to one printable line each. Blocking (up to
     * about [timeoutMs]) — call off the main thread.
     */
    external fun findExits(timeoutMs: Int): String

    /** The most recent node log lines (newline-joined). */
    external fun recentLogs(maxLines: Int): String

    // ---- Bluetooth: the app's radio (shim/src/ble.rs) ----------------------
    //
    // fips links to nodes in radio range over BLE, but cannot open a radio on
    // Android: scanning, advertising and the L2CAP sockets are Java APIs. So
    // the app runs the radio and fips commands it through [BleRadio], while
    // the app reports what happens with the functions below.
    //
    // Channel and dial ids are opaque: pass back exactly what was given. An
    // id from before a node restart or a radio replacement reads as closed.

    /**
     * What fips asks of the radio. Every method is called from the node's
     * own thread and must return at once: start the work on another thread
     * and report the outcome with the matching `ble…` function.
     */
    interface BleRadio {
        /** Open the L2CAP listener; return its PSM, or 0 if it failed. */
        fun bleListen(): Int

        /**
         * Dial [addr] (6 bytes) on [psm]. Answer with [bleConnectResult],
         * passing [connectId] back.
         */
        fun bleConnect(connectId: Long, addr: ByteArray, psm: Int)

        /** Advertise the FIPS service with [psm] in its service data. */
        fun bleStartAdvertising(psm: Int)
        fun bleStopAdvertising()

        /**
         * Scanning is wanted. When the chip actually scans is the radio's
         * decision; an advert it does not report is a link fips never makes.
         */
        fun bleStartScanning()
        fun bleStopScanning()

        /** fips dropped the channel: close its socket. */
        fun bleCloseChannel(chId: Long)
    }

    /**
     * The radio is up; fips may command it. Call again with a new object to
     * replace it. Allowed before the node starts and kept across restarts.
     */
    external fun bleInstall(radio: BleRadio)

    /** The radio is gone (Bluetooth off, a permission withdrawn, setting off). */
    external fun bleClear()

    /**
     * A peer connected to our listener. Returns the channel id, or 0: close
     * the socket.
     */
    external fun bleInbound(addr: ByteArray, sendMtu: Int, recvMtu: Int): Long

    /**
     * The outcome of a [BleRadio.bleConnect]. Returns the channel id when
     * [ok], or 0 (it failed, or fips stopped waiting): close the socket.
     */
    external fun bleConnectResult(
        connectId: Long, ok: Boolean, addr: ByteArray, sendMtu: Int, recvMtu: Int,
    ): Long

    /**
     * One FIPS advert seen. [psm] is 0 when it carried none; [rssi] is
     * `Int.MIN_VALUE` when unknown.
     */
    external fun bleScan(addr: ByteArray, psm: Int, rssi: Int)

    /**
     * The first [len] bytes of [data], read from channel [chId]. False: the
     * channel is gone — stop reading and close the socket. Blocks while fips
     * is behind, so call it from the channel's own reader thread.
     */
    external fun bleRecv(chId: Long, data: ByteArray, len: Int): Boolean

    /**
     * The next packet to write to channel [chId], or null: nothing within
     * [timeoutMs], or the channel is gone ([bleChannelOpen] tells which).
     * Blocks up to the timeout — call it from the channel's writer thread.
     */
    external fun bleNextSend(chId: Long, timeoutMs: Int): ByteArray?

    /** Whether fips still holds channel [chId]. */
    external fun bleChannelOpen(chId: Long): Boolean

    /** The socket of channel [chId] closed (the peer left, or an error). */
    external fun bleChannelClosed(chId: Long)
}
