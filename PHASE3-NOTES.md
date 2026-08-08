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
   proxy. **Verified on-device after the fix:** `<npub>.fips` resolves to the
   correct mesh address (ping 0.44 ms via hairpin), and upstream forwarding
   works — a Nostr relay (`relay.damus.io`) connected, which required
   resolving its hostname through the proxy. Nostr rendezvous is fully live
   (`nostr notify loop received first event`).

Note: `avc: denied ... cgroup` SELinux lines are benign — Rust's
`available_parallelism()` cgroup probe; the worker pool still spawns. Worth
capping `FIPS_ENCRYPT/DECRYPT_WORKERS` for mobile later (it chose 8+8).

## Network-change handling (Wi-Fi ↔ cellular) — done, verified on-device

The node's UDP socket keeps a stale source/NAT binding across an
underlying-network switch and the mesh **silently black-holes** — confirmed
on-device: after forcing Wi-Fi off, 50s+ passed with zero fips activity, no
self-heal. The node has no runtime socket-rebind hook, so:

- **Kotlin** (`FipsVpnService`): a `ConnectivityManager` callback tracks
  non-VPN internet networks and picks a preferred one (Wi-Fi > Ethernet >
  cellular). `registerSystemDefaultNetworkCallback` would be ideal but is a
  `@SystemApi` gated on `NETWORK_SETTINGS` (verified absent from the
  platform-34 jar), so we track the available set ourselves. On a change:
  `setUnderlyingNetworks()` + `FipsNative.onNetworkChanged(fd)`, on a worker
  thread, debounced by an `AtomicBoolean`. Needs `ACCESS_NETWORK_STATE`.
- **Shim** (`engine::network_changed`): restarts the node on the **same TUN
  fd** — the Kotlin `ParcelFileDescriptor` keeps the tunnel up, so only the
  node cycles: fresh, re-protected UDP socket on the new network, then it
  re-dials static peers / re-STUNs. Guarded by a `REBINDING` flag against
  overlapping rebuilds. New JNI export `onNetworkChanged`.

**Verified on Pixel 9 Pro**: `underlying network changed 156 -> 129` (Wi-Fi→
LTE) and `129 -> 164` (LTE→Wi-Fi) each tore down and re-formed the mesh
(`Peer promoted to active`) in ~1–2 s. `setUnderlyingNetworks` confirmed via
`dumpsys connectivity` (`UnderlyingNetworks: [164]`). Trade-off: a network
switch causes a ~1–2 s mesh blip (full node restart) rather than a seamless
socket rebind — acceptable, and far better than the indefinite black-hole; a
seamless version would need a runtime rebind API added to fips.

## Split tunnel (per-app) — done, verified on-device

Android's `VpnService` confines every covered app to the tunnel's routes, so
routing only `fd00::/8` cut all other apps off from the internet (verified:
IPv4 → "No route to host" / ENETUNREACH, public IPv6 → EACCES via the
`prohibit` rule). There is no `VpnService` config that leaves un-routed
traffic on the underlay for unmodified apps — the standard fix is a userspace
forwarder (tun2socks-style). Implemented, scoped per-app:

- **Kotlin**: `AppPickerActivity` (a multi-choice list of launchable apps)
  persists the selected package set. `FipsVpnService` captures **only** those
  via `addAllowedApplication` (every other app is left untouched), adds an
  IPv4 tun address (`10.111.222.1/32`) alongside the mesh IPv6, and routes
  `fd00::/8` + `::/0` + `0.0.0.0/0` so captured apps' non-mesh traffic reaches
  us. Empty selection captures only our own app (a no-op).
- **Shim** (`forward.rs`, `ipstack` crate): the pump classifier sends
  `fd00::/8` to the mesh and everything else into a userspace TCP/IP stack;
  each accepted TCP/UDP flow is dialed out on a VPN-**protected** socket and
  copied through (`copy_bidirectional` for TCP, a datagram pump for UDP). DNS
  stays on the existing proxy. Runs on its own thread/runtime; torn down with
  the pump. Gated by `forward_clearnet` (default on; host tests off).

**Verified on Pixel 9 Pro** with only `com.android.shell` (the adb shell,
uid 2000) selected: from the captured shell, IPv4 clearnet TCP (`1.1.1.1:443`),
public IPv6 TCP (`2606:4700:4700::1111:443`), and hostname connects
(`one.one.one.one:443`, DNS-proxy + forwarded TCP) all succeed — while the
same app still reaches the mesh (`.fips` resolves, 0.5 ms). `dumpsys` confirms
the VPN captures `Uid: 2000` only; every other app is on the normal network.
Caveat: ICMP to clearnet isn't forwarded (only TCP/UDP), and all captured-app
traffic flows through the app's userspace stack (battery/latency cost — the
reason it's per-app).

## Not done / next

- On-device testing (no adb on this machine): install `app-debug.apk`, check
  logcat tag `fips`, verify peer handshake to a desktop node, `.fips`
  browsing, and normal-DNS passthrough.
- Network-change handling (Wi-Fi↔cellular): the node's sockets survive but
  NAT bindings change; needs a rebind/re-STUN nudge on
  `ConnectivityManager` callbacks.
- Always-on VPN, battery profile (1s tick vs Doze), Keystore, runtime peer
  connect/disconnect UI, QR config exchange, x86_64 ABI for emulator.
