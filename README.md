# fips-android

Android port of [FIPS](../fips): the daemon embedded in a `VpnService` app.
Unmodified phone apps reach the mesh over `fd00::/8` with `.fips` DNS, while
their ordinary traffic bypasses the tunnel.

## Layout

| Path | What |
|---|---|
| `fips/` | git worktree of `~/fips`, branch **`android-hooks`** — the embedder hooks (socket-protect, `TunPacketProcessor`, public `ControlReadHandle::query`). Local only, not pushed. |
| `shim/` | Rust cdylib `libfips_android.so`: engine (node lifecycle), TUN fd pump, DNS proxy, JNI surface (`org.fips.android.FipsNative`). |
| `android/` | The Kotlin app: `MainActivity` (identity, peer config, status), `FipsVpnService` (TUN fd, protect callback, foreground notification). |
| `smoke/` | Two-node host smoke test of the embedding seam (Phases 1–2). |
| `android-env.sh` | Cross-build env: NDK r27c paths + the `LIBCLANG_PATH` fix for host builds. |
| `build-native.sh` | Builds the shim for `aarch64-linux-android` and copies it into `android/app/src/main/jniLibs/`. |

## Build

```bash
./build-native.sh                          # Rust shim → jniLibs
cd android
JAVA_HOME=~/.local/jdk-17 ~/.local/gradle-8.7/bin/gradle assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
adb install app/build/outputs/apk/debug/app-debug.apk
```

(SDK at `~/android-sdk` via `local.properties`; adjust for your machine.)

## How it works

- **Identity**: generated in Rust (`deriveIdentity`), nsec persisted in app
  prefs (TODO: Android Keystore). The node's fips address doubles as the
  tunnel address and the in-tunnel DNS server address.
- **Tunnel**: routes only `fd00::/8`, MTU 1280. The TUN fd is dup'd by the
  shim; a reader thread runs each outbound packet through the node's own
  `TunPacketProcessor` (destination filter, MSS clamp, hairpin, ICMPv6) —
  byte-identical to the daemon's system-TUN path.
- **DNS**: all covered-app DNS arrives at `<node-address>:53` in the pump.
  `.fips` names go to the in-process FIPS responder (`[::1]:5354`); everything
  else is forwarded to upstream resolvers over protected sockets (SERVFAIL on
  total failure). Configurable via `dns_upstreams`.
- **Socket protection**: the node announces every underlay socket fd to the
  shim's hook, which crosses JNI to `VpnService.protect()`. Covered: UDP
  listen/adopted/connected-peer, TCP listener/accepted/dialed (pre-SYN),
  Nostr STUN/hole-punch. Not covered (no fd in those libraries): nostr-sdk
  relay websockets, mDNS — benign while only `fd00::/8` is routed.
- **Status**: `FipsNative.status()`/`query()` are served lock-free from the
  node's `ControlReadHandle` snapshots — same data as `fipsctl show_*`.

## Status / caveats

- Built and unit-tested on the host (engine lifecycle, DNS proxy, packet
  codecs) and cross-compiled for arm64; **not yet exercised on a device**
  (no adb on this machine).
- mDNS (`lan-mdns`) is compiled out; Android needs `MulticastLock` handling
  first. BLE/Ethernet transports are not available on Android.
- Battery: the node ticks at 1s and keeps transports warm; expect Doze to
  fight long-lived sessions until timers get a mobile profile.
- Runtime peer add/remove (control `connect`/`disconnect`) not exposed yet —
  peers come from config at connect time; toggling the VPN re-reads them.
