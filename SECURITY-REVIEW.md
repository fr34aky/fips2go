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
   (`answer_as_asked` there also parses a reply, but only the in-process
   responder's on `[::1]`, for a name out of the user's own hosts file.)
4. **GitHub release metadata and the downloaded APK** in
   `android/.../Updater.kt`.
5. **Nostr relay traffic**, handled inside the fips dependency rather than here.
6. **The Mesh names sync answer** (opt-in, off by default): the upstream
   node's `/api/hosts` JSON, fetched over the mesh by the in-process TCP client
   in `shim/src/meshhttp.rs` and parsed in `android/.../HostsSync.kt`. Only the
   npub the user named can answer from its address, so the source is
   authentic — but it is still a remote party writing names into this
   device's `.fips` resolution (a synced name overrides a local one by design,
   as in fips-ui). The HTTP parsing is bounded (4 MiB body, chunked decoding
   checked), entries are validated like hand-typed ones and capped at 2000.
   The reply tap (`Divert`) sits in front of the inbound firewall, but only
   claims packets matching an open in-process flow's exact (remote address,
   remote port, local port) — it cannot admit anything to a covered app.
7. **Packets from an exit node** (only while the user has selected one):
   IPv4-in-IPv6 (next header 4) from the exit's fips address, unwrapped in
   `shim/src/exit.rs` and written to the TUN ahead of `filter.rs`. The exit's
   operator controls everything inside: any inner source, port and flag.
   `ExitSwitch` therefore keeps its own flow table (the same bounded,
   idle-expiring `FlowTable` as `filter.rs`, cleared when the exit changes)
   and delivers only replies to flows a covered app opened through that exit:
   TCP/UDP by the reversed 4-tuple, ICMP echo replies by identifier, ICMP
   errors (types 3, 11, 12) only when the header they quote is a packet this
   phone sent on a recorded flow. Later fragments, IHL < 5 and every other
   ICMP type are dropped. Only packets the apps send refresh a flow; the
   exit cannot keep one alive by sending on it. There is no port allowlist
   and no off switch on this path, and any IPv4-in-IPv6 it does not deliver
   is dropped, whatever `inbound_filter` says. Also from the exit: the
   answers of its DNS resolver
   (`dns.rs` via `meshudp.rs`), which carry every non-`.fips` name while it
   is selected.
8. **Anyone in Bluetooth range** (only with Settings → Bluetooth on, off by
   default, and only while connected): BLE adverts and L2CAP connections,
   from strangers, with no pairing and no link-layer encryption. The radio
   is the app's (`FipsBle.kt`); what it hears goes through the JNI exports in
   `jni_api.rs` (`bleScan`, `bleInbound`, `bleRecv`: a 6-byte address or the
   call is dropped, lengths clamped, only the bytes read are copied) into
   fips's own BLE transport, which does the pubkey exchange, the handshake
   and the framing. A peer that completes them is a link like any other: its
   traffic for covered apps still meets `filter.rs`. Nothing in the shim or
   the app parses what arrives on a channel. The app holds at most
   `BLE_MAX_CONNECTIONS` links; an accepted socket costs two threads until
   fips drops it.

## Things that would be serious in this codebase

- **Inbound firewall bypass.** `filter.rs` default-denies new inbound flows and
  permits only replies to outbound-initiated flows, ICMPv6, and an explicit
  port allowlist. Any path that lets an unsolicited packet reach a covered app
  re-exposes every listening port on the phone to the whole mesh.
- **Flow-table abuse.** The 4-tuple table is bounded and idle-expiring; look
  for unbounded growth, or a remote party being able to forge a state entry.
  The same applies to the exit's table in `exit.rs`: only outbound packets
  from covered apps may add to it.
- **Exit-node leaks.** With an exit selected, nothing a covered app sends may
  leave through the phone's own connection: IPv4 goes to the exit or nowhere,
  IPv6 internet traffic is refused, every non-`.fips` DNS query goes to the
  exit's resolver only (no upstream fallback, no TCP retry upstream), and the
  public-names resolver is offline and asked about pinned domains only, so it
  sends no TXT query and asks no relay. A path that sends a packet or a name
  around the exit is a finding.
- **Stale Bluetooth channels.** A node restart or a radio restart builds a
  new fips bridge that numbers channels from 1 again, while the app may still
  hold sockets from the one before. Every id that crosses to Kotlin carries
  the bridge's generation (`ble::tag`); anything that lets an old id reach
  the new bridge would splice one peer's bytes into another peer's channel.
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
- Mesh names (`files/hosts`) are stored in plaintext in the app's private
  dir: they hold npubs — public keys — and labels, and the shim has to read
  the file. Only `.fips` queries from covered apps consult it; nothing
  arriving from the mesh can probe the name space.
- `android-env.sh` pins `LIBCLANG_PATH` to override a bad machine-wide value;
  that is a build-environment workaround, not a hardcoded secret.
- Release signing happens on a workstation, never in CI. There is deliberately
  no signing key in GitHub secrets.
- An exit node can read, tamper with and inject into the flows a covered app
  opens through it, as any VPN server can (the app's own TLS is what protects
  their content). What it cannot do is open a flow to the phone. Choosing an
  exit is the user's statement of trust in its operator; the Internet route
  screen says so.
- An unreachable exit blocks internet traffic rather than falling back to the
  phone's connection. That is the point of selecting one.
- With Bluetooth on, the phone links to any fips node in range
  (`auto_connect`), as LAN discovery does on a Wi-Fi. That is the feature.
  It also means anyone in range who runs fips can tell that this phone does,
  and learn its npub by connecting, so a known npub can be noticed at a
  place. Android rotates the Bluetooth address; the npub does not rotate.
  The setting is off by default and its summary says so.
- The Bluetooth channels are "insecure" L2CAP (no pairing, no BLE
  encryption) on purpose: strangers must be able to link, and fips encrypts
  and authenticates above it.
