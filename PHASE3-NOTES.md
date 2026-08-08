# Phase 3 — JNI shim + Kotlin VpnService app

Date: 2026-08-08. All local. Depends on the `android-hooks` worktree
(`fips-android/fips/`, commits `a1c796d` + `bda3997` — the second adds the
public `ControlReadHandle::query` status surface).

## Components

### Rust shim (`shim/` → `libfips_android.so`, JNI class `org.fips.android.FipsNative`)

| Module | Role |
|---|---|
| `engine.rs` | Singleton lifecycle: build in-memory `fips::Config`, `Node::new` → `enable_app_owned_tun` → `set_socket_protect` → node on a dedicated current-thread tokio runtime; `stop()` drains, joins, closes the dup'd fd. Status/query served from `ControlReadHandle` snapshots. |
| `pump.rs` | Three threads over the dup'd TUN fd: reader (`poll()` + `read()`, DNS intercept, then the node's `TunPacketProcessor` → forward/hairpin/respond/drop), writer (single fd writer), bridge (mesh→app channel into the writer). All stop via one flag; nothing blocks indefinitely. |
| `dns.rs` | DNS proxy: queries to `<node-addr>:53` from the tunnel are split — `*.fips` → in-process FIPS responder `[::1]:5354`, everything else → configured upstreams over **protected** sockets (default 1.1.1.1/9.9.9.9), SERVFAIL when all fail, transaction-id-checked responses, per-query short-lived thread. |
| `packet.rs` | IPv6/UDP build+parse with RFC-correct UDP checksum. |
| `config.rs` | `ShimConfig` JSON (nsec, peers, dns_upstreams, enable_nostr, enable_fips_dns, log_level) → validated `fips::Config`; `derive_identity` (nsec/npub/fd-address triple). |
| `jni_api.rs` | Six `Java_org_fips_android_FipsNative_*` exports (deriveIdentity, start, stop, isRunning, status, query); protect hook = JavaVM + GlobalRef calling `protectFd(int)` from any thread; panics caught at the boundary. |
| `lib.rs` | tracing → logcat via `__android_log_write` (tag "fips") on Android, stderr elsewhere. |

**Tests (host): 10/10 pass** — packet codec roundtrip + independent checksum
verification, qname parsing, SERVFAIL shaping, a full DNS proxy exchange
against a fake upstream, and a **complete engine lifecycle test** (pipe as
TUN fd, loopback UDP node, protect-hook assertion, status + query, double
start rejected, stop idempotent, restartable ×2).

### Kotlin app (`android/`)

- `FipsVpnService` — Builder: address `<node fd-addr>/128`, route `fd00::/8`,
  DNS `<node fd-addr>`, MTU 1280; `protectFd()` bridged to
  `VpnService.protect`; foreground notification (specialUse FGS type);
  `onRevoke` handled.
- `MainActivity` — identity generated in Rust and persisted in prefs, peer
  npub/endpoint entry, Nostr toggle, VPN consent flow, 2s status poller
  rendering the `show_status` snapshot.
- `FipsNative` — the `external fun` mirror of the JNI exports.

## Build — **APK built successfully on this machine**

- `./build-native.sh` → shim cross-compiled, `.so` copied to jniLibs
  (11.7 MB arm64, all six JNI symbols verified with `llvm-nm`).
- APK: `cd android && JAVA_HOME=~/.local/jdk-17 ~/.local/gradle-8.7/bin/gradle assembleDebug`
  — **BUILD SUCCESSFUL**; a copy of the installable artifact is at
  `dist/fips-android-debug.apk` (26.7 MB, contains
  `lib/arm64-v8a/libfips_android.so`). Install: `adb install dist/fips-android-debug.apk`.
- Toolchain installed in userspace this session: Temurin JDK 17
  (`~/.local/jdk-17`), Android SDK platform-34 + build-tools 34.0.0
  (`~/android-sdk`), Gradle 8.7 (`~/.local/gradle-8.7`).
- `fips-android/` is now a local git repo (branch `main`, no remote).

## Design decisions

- **Hand-written JNI over UniFFI**: 6 methods didn't justify codegen + the
  JNA runtime dependency; everything crosses as JSON strings.
- **DNS server = the node's own fips address**: Android requires the VPN DNS
  server to be reachable through the tunnel; using our address means queries
  arrive in the pump as ordinary TUN packets, no extra listener.
- **All-DNS capture handled**: Android sends *all* covered-app DNS to the VPN
  resolver, so upstream forwarding is part of the MVP (protected sockets).
- **fd ownership**: the shim dups the fd; Kotlin's ParcelFileDescriptor and
  the shim close independently — no double-close, no leak on either side's
  failure path.
- **nsec in SharedPreferences** for MVP — move to Android Keystore /
  EncryptedSharedPreferences before any real-world use.

## On-device findings (Pixel 9 Pro, Android 17, arm64)

Tested on real hardware. **The mesh works end to end:** the app-owned TUN
seam, socket-protect hook, embedded node, and FMP handshake all run on the
phone. With a direct peer (`194.191.252.108:2121`) the phone joined a live
**1308-node mesh** — `link_count: 1`, `is_leaf_only: false`, spanning-tree
depth 4, `effective_ipv6_mtu: 1203`. Status JSON renders live from
`ControlReadHandle` over JNI.

Two issues found and fixed on-device:

1. **16 KB page alignment.** Android 15+ on Pixel-9-class hardware runs 16 KB
   pages; the `.so` was 4 KB-aligned → a "not 16 KB compatible" warning dialog.
   Fixed with `shim/.cargo/config.toml`
   (`-Wl,-z,max-page-size=16384`); LOAD segments now `0x4000`.

2. **DNS server address bug (the important one).** The VpnService advertised
   the node's *own* tun address as the DNS server. A packet to the interface's
   own `/128` is delivered locally by the kernel and **never written to the TUN
   fd**, so the pump/DNS-proxy never saw a single query — `.fips` and Nostr
   relay resolution both failed. Fixed by advertising a **sentinel address in
   `fd00::/8` that is not the node's** (`fd00::53`, `engine::DNS_SENTINEL`,
   shared with Kotlin via the new `FipsNative.dnsServer()` JNI accessor). The
   kernel routes the sentinel out the fd; the pump peels off `:53` to the
   proxy. (Re-test pending on-device.)

Note: `avc: denied ... cgroup` SELinux lines are benign — Rust's
`available_parallelism()` cgroup probe; the worker pool still spawns. Worth
capping `FIPS_ENCRYPT/DECRYPT_WORKERS` for mobile later (it chose 8+8).

## Not done / next

- On-device testing (no adb on this machine): install `app-debug.apk`, check
  logcat tag `fips`, verify peer handshake to a desktop node, `.fips`
  browsing, and normal-DNS passthrough.
- Network-change handling (Wi-Fi↔cellular): the node's sockets survive but
  NAT bindings change; needs a rebind/re-STUN nudge on
  `ConnectivityManager` callbacks.
- Always-on VPN, battery profile (1s tick vs Doze), Keystore, runtime peer
  connect/disconnect UI, QR config exchange, x86_64 ABI for emulator.
