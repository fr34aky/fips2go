# Phase 2 — embedder hooks inside the fips codebase

Date: 2026-08-08. All local: the changes live on the **`android-hooks` branch
in the worktree at `fips-android/fips/`** (commit `a1c796d`), never pushed;
your main checkout at `~/fips` is untouched.

## What was added

### 1. `Node::set_socket_protect(hook)` — the VpnService.protect seam

`SocketProtect = Arc<dyn Fn(RawSocketHandle) + Send + Sync>` (re-exported from
the crate root). Installed before `start()`; the node announces the raw fd of
every underlay socket it creates, after creation and before any traffic:

| Socket | Where it's applied |
|---|---|
| UDP listen socket | `UdpTransport::start_async` |
| UDP adopted socket (NAT-traversal handoff) | `UdpTransport::adopt_socket_async` (re-announce; hook is documented idempotent) |
| Per-peer connected-UDP fast path | `node/dataplane/connected_udp.rs` activation |
| TCP listener | `TcpTransport::start_async` |
| TCP accepted sockets | accept loop, before the connection's read task |
| TCP dialed sockets | new `TcpTransport::dial` built on `tokio::net::TcpSocket` so the hook runs **before the SYN leaves** (both foreground and background connect paths) |
| Nostr STUN observation + hole-punch sockets | the three binds in `nostr/runtime.rs` (`NostrRendezvous::start` takes the hook as a new parameter) |

Documented as **not** covered (no fd access in the libraries): `nostr-sdk`
relay websockets, `mdns-sd`, the Tor/Nym SOCKS5 dialer (local proxy protects
itself). Benign while the VPN routes only `fd00::/8`; revisit for
block-connections-without-VPN setups.

Internals: `src/transport/protect.rs` — platform-neutral `RawSocketHandle`
(RawFd on unix / RawSocket on windows) plus a blanket `AsRawSocketHandle`
trait, so no call site needs `cfg`.

### 2. `Node::tun_packet_processor()` — outbound pipeline parity

The per-packet decision logic was extracted out of `handle_tun_packet`
(`src/upper/tun.rs`) into pure `process_outbound_packet` → both the system-TUN
reader and the new embedder-facing `TunPacketProcessor` (cheap clone; call
after `start()`) share it byte-for-byte. `process(&mut packet)` returns
`TunPacketAction`: `Forward` (MSS clamped in place using the node's live
per-destination path-MTU map), `Hairpin` / `Respond(icmpv6)` (write back to
the fd), `Drop`. This replaces the earlier plan of just widening
`per_flow_max_mss` to `pub` — embedders get the whole pipeline, not one
helper.

Docs updated: `docs/design/fips-ipv6-adapter.md` App-Owned TUN section.

## Verification

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`: clean.
- Full test suite: **1712 pass, 0 fail** (1653 lib + bins), including 8 new
  tests: UDP hook on open/adopt, TCP hook on listener/dialed/accepted,
  node-level hook + processor, and 4 `TunPacketProcessor` behavior tests
  (drop non-IPv6, forward+MSS-clamp, hairpin self, ICMPv6 for off-mesh).
- Android cross-compile (`aarch64-linux-android`, `--no-default-features`):
  clean; smoke binary links.
- Smoke test (host, two nodes, app-owned TUN + both new hooks): **PASS** —
  protect hook fired for the listen socket at start *and* for the
  runtime-created connected-UDP peer socket; every outbound packet went
  through `TunPacketProcessor` and forwarded.
- FreeBSD `cargo check`: fails on `socket-pktinfo` — **pre-existing on
  unmodified master** (verified via stash), unrelated to these changes.
- Windows: not compile-checked (no mingw toolchain on this host, no sudo to
  install one). Windows-specific additions are ~6 lines (two `AsRawSocket`
  impls); all touched types implement `AsRawSocket` on Windows. Flag for CI
  when this becomes a PR.

## PR readiness (when you decide to upstream)

Target branch: `master` (compatible feature, no wire change). One logical
change; includes unit tests + design-doc update. Per PR-REVIEW.md you'd still
want: an integration-test angle under `testing/` (the hook is
embedder-triggered, so a unit-level story may be acceptable — maintainer's
call) and a changelog entry at release time.

## Next (Phase 3)

JNI/UniFFI shim crate + Kotlin app in this repo (`fips-android`):
config-from-Keystore, fd pump threads using `TunPacketProcessor`, DNS
proxy (intercept UDP :53 to the node's own address → in-process responder
+ upstream forwarding), `android_logger` tracing layer, VpnService +
foreground service UI.
