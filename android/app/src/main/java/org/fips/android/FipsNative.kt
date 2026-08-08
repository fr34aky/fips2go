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
     * Start the embedded node. [callback] receives `protectFd(int)` for every
     * underlay socket. Returns "" on success, an error message otherwise.
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
     * Rebuild the node on the same TUN fd after the underlying network changed
     * (Wi-Fi ↔ cellular). Blocking — call off the main thread. No-op if the
     * engine isn't running.
     */
    external fun onNetworkChanged(tunFd: Int)

    /** Compact status JSON: `{running, npub, address, status: {...}}`. */
    external fun status(): String

    /** Any snapshot-served `show_*` query, e.g. `query("show_peers", "")`. */
    external fun query(command: String, paramsJson: String): String

    /** Resolve an npub to its `.fips` address. JSON `{npub,address}` or `{error}`. */
    external fun resolveNpub(npub: String): String

    /** The most recent node log lines (newline-joined). */
    external fun recentLogs(maxLines: Int): String
}
