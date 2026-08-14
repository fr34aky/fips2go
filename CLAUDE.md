# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Android port of the FIPS mesh daemon, embedded in a `VpnService` app. A Rust JNI shim (`shim/`) runs the fips node in-process; the Kotlin app (`android/`) provides the VPN tunnel, per-app split tunnel, and Material 3 UI. Selected apps reach the mesh over `fd00::/8` with `.fips` DNS while keeping normal internet through a userspace forwarder.

## Build & test commands

```bash
# Rust shim → android/app/src/main/jniLibs/<abi>/libfips_android.so
./build-native.sh                # all ABIs: arm64-v8a, armeabi-v7a, x86_64
./build-native.sh arm64-v8a      # single ABI for faster iteration

# Host-side Rust tests (engine lifecycle, DNS proxy, packet codecs — everything but the JNI surface)
source ./android-env.sh && (cd shim && cargo test)
# Single test: (cd shim && cargo test dns::tests::name_of_test)

# Two-node host smoke test of the embedding seam
source ./android-env.sh && (cd smoke && cargo run)

# APK (debug; toolchain paths are machine-specific — see android/local.properties)
cd android && JAVA_HOME=~/.local/jdk-17 ~/.local/gradle-8.7/bin/gradle assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk; install with adb install

# Release: signed arm64-v8a-only APK + sha256 + unstripped .so → dist/v<versionName>/
./release-build.sh
```

`source ./android-env.sh` is required before any cargo command:
- Cross builds: sets the NDK r27c linker/CC/AR (API 24 floor — `getifaddrs` in fips's STUN code).
- **Host builds too**: it pins `LIBCLANG_PATH=/usr/lib/llvm-18/lib`, overriding a machine-wide ESP32/Xtensa libclang that breaks bindgen (`rustables`) with an `assertion failed 4 != 8` panic.

Toolchain: Rust 1.94.1 (pinned in `rust-toolchain.toml`), NDK r27c at `/home/andre/android-ndk-r27c`, JDK 17 at `~/.local/jdk-17`, Gradle 8.7 at `~/.local/gradle-8.7`, Android SDK platform-34.

There is no Kotlin test suite; the app was verified on-device (Pixel 9 Pro). Rust tests live as `#[cfg(test)]` modules inside `shim/src/*.rs`.

## The fips dependency

`shim/` and `smoke/` depend on fips as a **pinned git dependency**: `fr34aky/fips` @ branch `android-hooks` (rev in both `Cargo.toml`s must stay in sync). That fork carries the embedder hooks the shim needs: `Node::enable_app_owned_tun()`, `Node::set_socket_protect()`, `Node::tun_packet_processor()`, public `ControlReadHandle::query`, and `LanRendezvousConfig.exclude_addrs` (keeps tunnel addresses out of mDNS adverts). mDNS is compiled in unconditionally and gated at runtime by `node.rendezvous.lan.enabled` (shim knob `enable_lan_mdns`, default off; the Kotlin side pairs it with a `MulticastLock` held only on Wi-Fi).

The local `fips/` directory is a **git worktree of `~/fips` on `android-hooks`**, ignored by this repo — it is NOT what builds use. To develop against it, add to `shim/Cargo.toml` (and `smoke/Cargo.toml`):

```toml
[patch."https://github.com/fr34aky/fips"]
fips = { path = "../fips" }
```

When bumping the pin: change the `rev` in both `Cargo.toml`s and update both `Cargo.lock`s. `smoke/Cargo.lock` deliberately pins `rustables` 0.8.7 (known-good against the host libclang).

## Architecture

Everything crosses the JNI boundary as JSON strings — hand-written JNI (`jni_api.rs`, ten `Java_org_fips_android_FipsNative_*` exports: start/stop/status/isRunning, deriveIdentity, dnsServer, onNetworkChanged, query, resolveNpub, recentLogs), no UniFFI. `FipsNative.kt` is the Kotlin `external fun` mirror. Panics are caught at the boundary.

Data path (the core seam): Kotlin's `VpnService` establishes the TUN (addresses = the node's fips /128 + an IPv4 source for clearnet, routes `fd00::/8` + `0.0.0.0/0`, plus `::/0` only while the underlying network has IPv6 internet — advertising it unconditionally black-holes IPv6 because the forwarder's userspace stack SYN-ACKs before dialing, defeating Happy Eyeballs; without `::/0`, two host routes keep AAAA queries — and thus AAAA-only `.fips` names — resolving: `2000::/128` satisfies netd's AI_ADDRCONFIG probe (UDP connect to `2000::`) and `2001:4860:4860::8888/128` satisfies Chromium/WebView's own IPv6-reachability probe (UDP connect to Google DNS, cached 60 s — without it `.fips` browsing dies exactly one minute after landing on a v4-only underlay); MTU 1280) and hands the fd to the shim, which dups it. When the IPv6 decision flips (network switch or link-properties change), the service re-establishes the tunnel and passes the NEW fd to `onNetworkChanged`. Network callbacks are coalesced, never dropped: a hand-over emits a burst of them over seconds while a rebind (full node restart) takes seconds itself, so requests queue on a flag served by a single worker that re-checks after every pass — the burst always ends with a rebind against final network state. Validated networks are preferred over unvalidated ones (a dying Wi-Fi keeps its transport for 10–30 s; follow the OS default to cellular instead). `pump.rs` runs reader/writer/bridge threads over the dup'd fd; each outbound packet goes through DNS intercept, then a mesh/clearnet classifier: `fd00::/8` goes through the node's own `TunPacketProcessor` (forward with MSS clamp / hairpin / ICMPv6 respond / drop — byte-identical to the daemon's system-TUN path), everything else to the userspace forwarder.

- `engine.rs` — singleton node lifecycle on a dedicated current-thread tokio runtime: in-memory `fips::Config` → `Node::new` → `enable_app_owned_tun` → `set_socket_protect` → `start`. Status/query served lock-free from `ControlReadHandle` snapshots. `network_changed` restarts the node on the SAME tun fd (tunnel stays up; fips has no runtime socket-rebind API).
- `dns.rs` — covered-app DNS is sent to the `fd00::53` sentinel (`engine::DNS_SENTINEL`, exposed as `FipsNative.dnsServer()`), NOT the node's own tun /128 — the kernel would deliver packets addressed to the interface's own address locally, so they'd never reach the TUN fd. The pump intercepts port 53 to that sentinel: `.fips` names → in-process responder at `[::1]:5354`; everything else → configured upstreams over protected sockets; SERVFAIL on total failure.
- `forward.rs` — userspace clearnet forwarder (`ipstack`-based tun2socks; TCP/UDP, not ICMP) dialing protected sockets per flow, so covered apps keep normal internet.
- Socket protection: the node announces every underlay socket fd to the shim's hook, which crosses JNI (JavaVM + GlobalRef, callable from any thread) to `VpnService.protect()`. Not covered (no fd access): nostr-sdk relay websockets, mDNS — benign because the fips app itself is not captured by the per-app tunnel.
- `config.rs` — `ShimConfig` JSON → validated `fips::Config` (knobs incl. `worker_threads`, `battery_saver`, and `fips_yaml` — a raw fips.yaml base config parsed by fips's serde); `derive_identity` produces the nsec/npub/fd-address triple. Identity is generated in Rust and persisted via Android Keystore (`SecureStore.kt`/`IdentityStore.kt`).

The shim crate is both `cdylib` (the .so Kotlin loads) and `lib` (so host tests can exercise everything except the JNI surface itself).

Kotlin side: `MainActivity` hosts bottom-nav fragments (Overview / Settings / Diagnostics), `FipsVpnService` owns the tunnel + foreground notification + network-change handling (ConnectivityManager callback → `setUnderlyingNetworks` + `onNetworkChanged`), `AppPickerActivity` selects the captured apps (with no selection the tunnel captures only the fips app itself, a no-op), `ConfigStore` holds structured settings (relays, STUN, DNS upstreams, binds).

## Constraints & gotchas

- `shim/.cargo/config.toml` forces 16 KB page alignment (`max-page-size=16384`) on `aarch64` and `x86_64` — required on Android 15+/Pixel 9-class devices; don't remove it. `armeabi-v7a` stays 4 KB (32-bit Android never uses 16 KB pages).
- Three ABIs are built and packaged in the **debug** APK (`arm64-v8a`, `armeabi-v7a`, `x86_64`); only `arm64-v8a` is device-verified, and **release builds ship arm64-v8a only** (per-buildType `abiFilters`). The ABI list lives in three places that must stay in sync: `build-native.sh`, `rust-toolchain.toml`, and the debug `abiFilters` in `android/app/build.gradle.kts`. 32-bit `armeabi-v7a` is the build most likely to break on a fips pin bump (pointer-width casts — e.g. bionic's 32-bit `msghdr.msg_namelen` is `i32`); build it before bumping the pin.
- Releases: `./release-build.sh` (signs via gitignored `android/keystore.properties` → keystore at `~/.android-keys/fips-android-release.keystore`; unsigned fallback when absent). It archives an unstripped `.so` per release for symbolication and verifies ABI contents, 16 KB alignment, and the signature. Bump `versionCode` + `versionName` together. `THIRD-PARTY-NOTICES.md` is generated from the arm64 `cargo tree` (no GPL links into the Android build — `rustables` is host-only) and must be regenerated on a fips pin bump. Installing a release over the debug build requires an uninstall (different signing key), which **irrecoverably destroys the device's mesh identity** (nsec is sealed by a non-exportable Keystore key).
- min SDK 26, target/compile SDK 34.
- Don't reinstall or force-kill the app while the VPN is connected — it can leak netd routing rules that block other apps' connectivity until reboot. Disconnect first.
- Launcher icon assets (`android/.../res/mipmap-*`) are generated from the fips repo's `docs/logos/fips_logo.png` (mesh graphic cropped, luminance→alpha, adaptive icon + monochrome layer).
- `PHASE1-NOTES.md` / `PHASE2-NOTES.md` / `PHASE3-NOTES.md` document the porting history, the full socket-protect coverage table, and verification status — consult them before changing the embedding seam.
