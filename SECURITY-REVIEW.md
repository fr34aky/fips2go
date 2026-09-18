# Security review context for fips2go

Security review here is done by hand, as part of the PR review in
`PR-REVIEW.md` (there is no automated scanner in CI any more). This file is
the context that review needs: where this codebase's trust boundaries
actually are, so findings can be weighted accordingly, and which deliberate
design choices are not findings.

## What this is

An Android `VpnService` app embedding the FIPS mesh daemon. A Rust shim
(`shim/`) runs the node in-process and owns the TUN file descriptor; the Kotlin
app (`android/`) owns the tunnel, the per-app split tunnel and the UI.
Everything crosses JNI as JSON strings.

## Untrusted input, in rough order of exposure

1. **Packets from the mesh.** Any authorized node on a ~1000-node public mesh
   can send arbitrary IPv6 traffic at this device. `shim/src/filter.rs`
   (stateful inbound firewall), `shim/src/packet.rs` (hand-rolled IPv6/UDP
   parsing and checksums) and `shim/src/pump.rs` (the mesh/clearnet classifier)
   all parse it. Parser bugs here are remotely reachable.
2. **Packets from covered apps** heading out through the TUN, including
   intercepted DNS to the `fd00::53` sentinel (`shim/src/dns.rs`).
3. **DNS responses** from configured upstreams, parsed in `shim/src/dns.rs`.
4. **GitHub release metadata and the downloaded APK** in
   `android/.../Updater.kt`.
5. **Nostr relay traffic**, handled inside the fips dependency rather than here.
6. **DNS-SD relay adverts on the LAN** (`android/.../RelayDiscovery.kt`):
   anyone on the same Wi-Fi can announce `_nostr._tcp` and choose the URL the
   phone dials. The shim validates the URL (`ws`/`wss` only, capped at 8) and
   adds it to the *advert* relay set only — never the DM set, which fips
   publishes under the npub as the identity's inbox-relay list (kind 10050)
   and fans every traversal signal to. A LAN relay therefore sees adverts
   (public, self-signed documents also on the public relays) and nothing
   that isn't already public. The one relay that does reach the DM set is
   the hand-typed "relay on this phone" Settings field (`trusted_nostr_relays`):
   the user vouched for it, and DM membership is what makes an offline
   handshake possible — deliberate, not a finding.

## Things that would be serious in this codebase

- **Inbound firewall bypass.** `filter.rs` default-denies new inbound flows and
  permits only replies to outbound-initiated flows, ICMPv6, and an explicit
  port allowlist. Any path that lets an unsolicited packet reach a covered app
  re-exposes every listening port on the phone to the whole mesh.
- **Flow-table abuse.** The 4-tuple table is bounded and idle-expiring; look
  for unbounded growth, or a remote party being able to forge a state entry.
- **Packet parsing.** Out-of-bounds reads, integer overflow in length or offset
  arithmetic, extension-header/fragment handling, and checksum logic. Note the
  design intent that non-TCP/UDP/ICMPv6 next-headers are dropped *unparsed*.
- **Identity handling.** The node secret (nsec) is sealed by a non-exportable
  Android Keystore key (`SecureStore.kt`, `IdentityStore.kt`). Flag anything
  that writes it in plaintext, logs it, puts it in an Intent, or widens where
  it can be read. The backup/restore feature in `OverviewFragment.kt`
  deliberately reveals it on screen and to the clipboard — that is intended,
  but check the clipboard is flagged sensitive and that `deriveIdentity` is
  never handed an empty string (which means "generate", and would silently mint
  a new identity while claiming to restore one).
- **Tunnel leaks.** Every underlay socket must be passed to
  `VpnService.protect()`, or its traffic routes back into the tunnel. Missing
  protection, or a socket created on a path that skips the hook, is a real
  finding.
- **Updater integrity.** `Updater.kt` must verify the downloaded APK against
  the release `.sha256` before handing it to the package installer, and must
  not fall back to installing an unverified file.
- **JNI boundary.** `shim/src/jni_api.rs` must not let a panic unwind across
  the boundary, and must handle malformed JSON and non-UTF-8 strings.

## Deliberate design choices — not findings

- The inbound firewall's default allowlist is empty and fips needs no inbound
  TUN ports; that is intentional, not a misconfiguration.
- `enable_nostr` and the in-app `.fips` resolver are hardcoded on.
- The nsec is shown in cleartext by the Back up dialog by design.
- `android-env.sh` pins `LIBCLANG_PATH` to override a bad machine-wide value;
  that is a build-environment workaround, not a hardcoded secret.
- Release signing happens on a workstation, never in CI. There is deliberately
  no signing key in GitHub secrets.
