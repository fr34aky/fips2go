# fips-android

Android port of [FIPS](https://github.com/jmcorgan/fips): the mesh daemon
embedded in a `VpnService` app. Selected phone apps reach the mesh over
`fd00::/8` with `.fips` DNS while keeping normal internet (per-app split
tunnel with a userspace forwarder).

Standalone repo — it depends on fips as a pinned **git dependency**
(`fr34aky/fips` @ `android-hooks`, which carries the small embedder hooks:
socket-protect, `TunPacketProcessor`, public `ControlReadHandle::query`), so
it clones and builds without a sibling fips checkout.

## Layout

| Path | What |
|---|---|
| `shim/` | Rust cdylib `libfips_android.so`: engine (node lifecycle), TUN fd pump, DNS proxy, clearnet forwarder, JNI surface (`org.fips.android.FipsNative`). |
| `android/` | The Kotlin app (Material 3, bottom-nav): Overview / Settings / Diagnostics, `FipsVpnService` (per-app split tunnel, protect callback, foreground service). |
| `smoke/` | Two-node host smoke test of the embedding seam. |
| `android-env.sh` | Cross-build env: NDK r27c paths + the `LIBCLANG_PATH` fix for host builds. |
| `build-native.sh` | Builds the shim for every supported ABI and copies the `.so`s into `android/app/src/main/jniLibs/<abi>/`. |

## Supported platforms

| ABI | Rust target | Devices |
|---|---|---|
| `arm64-v8a` | `aarch64-linux-android` | Every 64-bit ARM phone/tablet (~2016+); the primary, on-device-verified target. |
| `armeabi-v7a` | `armv7-linux-androideabi` | Old 32-bit phones. Compiles and packages; not exercised on real 32-bit hardware. |
| `x86_64` | `x86_64-linux-android` | Android emulator, Chromebooks. Emulator-verified: connect, VPN establish, and a live mesh link + npub resolve against a host-side fips daemon reached via `10.0.2.2`. |

All three are packaged into one APK. min SDK 26 (Android 8.0).

## Prerequisites

- Rust 1.94.1 with the Android targets (all pinned in `rust-toolchain.toml`;
  `rustup target add aarch64-linux-android armv7-linux-androideabi
  x86_64-linux-android` if rustup doesn't auto-install them).
- Android NDK r27c (paths in `android-env.sh`).
- JDK 17, Android SDK (platform-34, build-tools 34) + Gradle 8.7.

## Build

```bash
./build-native.sh                          # Rust shim, all ABIs → jniLibs
cd android
JAVA_HOME=~/.local/jdk-17 ~/.local/gradle-8.7/bin/gradle assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk (universal, all three ABIs)
adb install app/build/outputs/apk/debug/app-debug.apk
```

(SDK path in `android/local.properties`; adjust for your machine.)

To iterate on a single platform, pass the ABI(s) to the native build —
Gradle repackages whatever is in `jniLibs/`:

```bash
./build-native.sh arm64-v8a                # physical phone only
./build-native.sh x86_64                   # emulator only
./build-native.sh arm64-v8a x86_64         # both
```

Per-ABI notes:

- **arm64-v8a / x86_64**: `shim/.cargo/config.toml` forces 16 KB
  page-aligned LOAD segments (required on Android 15+ devices and by
  Google's 16 KB-page policy); don't remove those rustflags.
- **armeabi-v7a**: stays 4 KB-aligned (32-bit Android never uses 16 KB
  pages). This is the ABI most likely to surface pointer-width issues in
  the fips dependency — build it before bumping the fips pin.
- **Emulator (x86_64)**: create an AVD on the "Google APIs" x86_64 image
  (API 26+), `adb install` the same APK; the emulator picks the x86_64
  `.so` automatically. To exercise the mesh, run a peer daemon on the host
  (`fips --config <yaml>` with a UDP bind, `tun.enabled: false`) and set
  the app's peer endpoint to `10.0.2.2:<port>` — the emulator's alias for
  the host loopback.

## Release build

```bash
./release-build.sh                # all ABIs
./release-build.sh arm64-v8a      # subset
# → dist/v<versionName>/: one signed APK per ABI + sha256 + unstripped .so
```

Releases ship **one APK per ABI** (users install the one matching their
device; `arm64-v8a` is the device-verified one — see Supported platforms).
Signing needs `android/keystore.properties` (gitignored):

```properties
storeFile=/path/to/release.keystore
storePassword=...
keyAlias=fips-android
keyPassword=...
```

Without it the release APK comes out unsigned. The script archives an
unstripped copy of the shim next to the APK for symbolizing native crash
dumps — keep it (and the keystore!) with the release, not in the repo.
`THIRD-PARTY-NOTICES.md` lists everything statically linked into the
binary and is attached to each GitHub release. Bump `versionCode` and
`versionName` together in `android/app/build.gradle.kts` for every release.

## Local fips development

To hack on the fips hooks against a local checkout instead of the pinned
fork, add a patch to `shim/Cargo.toml` (and `smoke/Cargo.toml`):

```toml
[patch."https://github.com/fr34aky/fips"]
fips = { path = "../fips" }   # your local fips checkout on android-hooks
```

## How it works

- **Identity**: generated in Rust (`deriveIdentity`); the nsec is encrypted
  with a non-exportable Android Keystore key (`SecureStore`/`IdentityStore`).
  The node's fips address is the tunnel address.
- **Tunnel**: routes `fd00::/8` plus full clearnet (`0.0.0.0/0`, and `::/0`
  only while the underlay has IPv6 internet; on v4-only underlays two probe
  host-routes — `2000::/128` for netd, `2001:4860:4860::8888/128` for
  Chromium's 60 s-cached reachability probe — keep AAAA queries and thus
  `.fips` names resolving) for the captured apps only, MTU 1280. The TUN fd is dup'd by the shim; a reader
  thread classifies each outbound packet — `fd00::/8` goes through the node's
  own `TunPacketProcessor` (destination filter, MSS clamp, hairpin, ICMPv6;
  byte-identical to the daemon's system-TUN path), everything else to the
  userspace forwarder.
- **DNS**: covered-app DNS is sent to the `fd00::53` sentinel and intercepted
  in the pump. `.fips` names go to the in-process FIPS responder
  (`[::1]:5354`); everything else is forwarded to upstream resolvers over
  protected sockets (SERVFAIL on total failure). Configurable via
  `dns_upstreams`.
- **Socket protection**: the node announces every underlay socket fd to the
  shim's hook, which crosses JNI to `VpnService.protect()`. Covered: UDP
  listen/adopted/connected-peer, TCP listener/accepted/dialed (pre-SYN),
  Nostr STUN/hole-punch. Not covered (no fd in those libraries): nostr-sdk
  relay websockets, mDNS — benign because the fips app itself is not
  captured by the per-app tunnel.
- **Status**: `FipsNative.status()`/`query()` are served lock-free from the
  node's `ControlReadHandle` snapshots — same data as `fipsctl show_*`.

## Status / caveats

- **Exercised on a device** (Pixel 9 Pro, GrapheneOS / Android). Verified:
  connect/disconnect and joining a live ~1300-node mesh; `.fips` resolution
  and upstream DNS; per-app split tunnel (selected apps get mesh **and**
  clearnet, other apps untouched); automatic Wi-Fi↔cellular hand-over in both
  directions — the callback burst is coalesced into one node restart and the
  mesh recovers in ~20 s with no manual reconnect, including on a roaming
  IPv4-only CGNAT 5G network, with `.fips` resolution surviving past
  Chromium's 60 s IPv6-probe window; Keystore identity
  + regenerate; the Material 3 UI (Overview / Settings / Diagnostics), npub
  resolve, and the log viewer; the battery profile (relaxed timers). Also
  unit-tested on the host (engine lifecycle, DNS proxy, packet codecs) and
  cross-compiled for arm64.
- **Battery profile measured** (Pixel 9 Pro, 10-min screen-off idle windows,
  per-thread `/proc` deltas): `battery_saver` cuts the shim's idle CPU ~40%
  (5.5 vs 9.2 ms CPU/s) and process wakeups ~19% (19.3 vs 23.9 wake/s) —
  mostly via the relaxed maintenance tick and halved heartbeats (encrypt
  wakeups 0.6 vs 2.0/s). The pump's former 250 ms stop-flag tick (12 wake/s
  across 3 threads, ~62% of process wakeups) has since been eliminated
  (eventfd in the reader's poll, stop sentinel / channel-close instead of
  recv timeouts): re-measured, the pump now contributes ~0 idle wakeups and
  the process idles at 7.5 wake/s / 3.7 ms CPU per s (was 19.3 / 5.5 before
  the fix, same saver-on conditions). Not yet measured: a full multi-hour
  Doze cycle. The forwarder was validated on a few flows, not under broad
  real-app load.
- mDNS LAN discovery is available behind a default-off Settings toggle,
  and is live-verified against a fips daemon on the same Wi-Fi: the phone
  discovered the host via `_fips._udp` within ~1.5 min, dialed its LAN
  address directly (no relay/mesh hop), and the advert carried only the
  Wi-Fi address — the tunnel ULA stays off the LAN. The toggle
  acquires a `MulticastLock` (held only while the underlay is Wi-Fi;
  the lock disables the chip's multicast filtering, so chatty LANs cost
  battery) and excludes the tunnel's own addresses from the adverts so the
  mesh ULA is not broadcast on the LAN. mDNS sockets cannot be
  socket-protected (no fd access) — fine for the per-app split tunnel,
  non-functional under "Block connections without VPN". BLE/Ethernet
  transports are not available on Android. ICMP to clearnet is not
  forwarded (TCP/UDP are).
- Multi-ABI: `arm64-v8a`, `armeabi-v7a`, and `x86_64` are built and packaged;
  only `arm64-v8a` has been exercised on real hardware. Debug build only; no
  signed release yet.

## License

MIT (see `LICENSE`). The bundled native library statically links
[fips](https://github.com/jmcorgan/fips) (MIT, © Johnathan Corgan) and other
MIT/Apache-2.0 Rust crates — binary releases should ship their notices.
