# Phase 1 — prove the fips core builds and runs for Android

Date: 2026-08-08. All local; nothing committed to the fips repo.

## Results

| Check | Result |
|---|---|
| Host two-node smoke test through the app-owned TUN seam | **PASS** (`smoke/`, see below) |
| `cargo build --lib --no-default-features --target aarch64-linux-android` (fips repo) | **PASS** |
| `cargo build --lib --target aarch64-linux-android` (default features, incl. `lan-mdns`) | **PASS** — `mdns-sd`/`socket-pktinfo` compile against bionic |
| Full binary link for Android (`smoke` release build) | **PASS** — ELF aarch64 PIE, `/system/bin/linker64` interpreter |
| `tun` crate on the Android target | Compiles as-is; no `cfg` gating needed (it's in the tree via `cfg(unix)` but never called on the app-owned path) |
| On-device run | **Not done** — no adb/emulator on this machine; `smoke/target/aarch64-linux-android/release/fips-smoke` is ready to push to a device (`adb push` + `adb shell` under `/data/local/tmp`) |

## The smoke test (`smoke/`)

Exercises the exact embedding shape the Android `VpnService` shim will use:

- `Config` built entirely in memory (no config files, no key files) —
  identity injected via `config.node.identity.nsec`.
- `Node::enable_app_owned_tun()` called between `Node::new()` and
  `start()` — no system TUN device, no root.
- DNS responder and control socket disabled.
- Shutdown via a plain oneshot future (no signal handlers).

Two nodes on one current-thread runtime, linked over loopback UDP (B dials A
as a static peer). Node A pushes a hand-crafted IPv6/UDP packet (valid UDP
checksum) into its app-owned TUN sender; the test passes when the packet
arrives on node B's app-owned receiver — which requires the FMP handshake,
coordinate lookup, FSP session establishment, header compression, and routing
to all succeed. Passes in ~1 s.

```bash
source ../android-env.sh          # only needed for LIBCLANG_PATH on host
cargo run                          # host run
cargo build --release --target aarch64-linux-android   # device binary
```

## Environment notes

- **NDK r27c** installed at `/home/andre/android-ndk-r27c` (API 24 clang —
  API 24 is the floor because `src/nostr/stun.rs` uses `getifaddrs`).
  Cross-build env vars: `android-env.sh`.
- **Host builds of fips were broken machine-wide** before this work: the
  ESP32 toolchain (espup) exports
  `LIBCLANG_PATH=~/.rustup/toolchains/esp/xtensa-esp32-elf-clang/...` in the
  shell profile. That libclang targets 32-bit Xtensa, so bindgen (pulled in
  by `rustables` on Linux hosts) panics with
  `assertion failed ... left: 4 right: 8`. Fix (already in `android-env.sh`):
  `export LIBCLANG_PATH=/usr/lib/llvm-18/lib`. Android-target builds don't
  need libclang at all (`rustables` drops out of the dep tree).
- `smoke/Cargo.lock` pins `rustables` 0.8.7 to match the fips repo's
  lockfile (0.8.8 was untested against this host once LIBCLANG_PATH was
  fixed; 0.8.7 is the known-good version).
- Rust target installed: `aarch64-linux-android` (toolchain 1.94.1, matching
  the fips pin). Other ABIs (`armeabi-v7a`, `x86_64` for the emulator) not
  yet added — one `rustup target add` each when needed.

## What Phase 1 confirmed for the plan

- No fips code changes were needed to build for Android — the
  `enable_app_owned_tun` seam, the Android platform stubs in
  `src/upper/tun.rs`, and the target-gated dependencies all hold up.
- The library-only embedding (no signals, no files, no root, oneshot
  shutdown) works end to end.

## Next (Phase 2 — small changes inside the fips repo)

1. Socket-protect callback hook (`VpnService.protect`) at UDP/TCP socket
   creation — the one genuinely missing capability.
2. Widen `per_flow_max_mss` / MSS-clamp helpers to `pub` so the embedder's
   fd pump can clamp TCP MSS (the app-owned path bypasses
   `handle_tun_packet`).
3. Optional: config knobs for `/etc/fips/{hosts,peers.allow,peers.deny}`,
   upstream-DNS forwarding, `any(linux, android)` for the sendmmsg/GSO fast
   paths.
