# fips2go

Android port of [FIPS](https://github.com/jmcorgan/fips): the mesh daemon
embedded in a `VpnService` app. Selected phone apps reach the mesh over
`fd00::/8` with `.fips` DNS while keeping normal internet (per-app split
tunnel with a userspace forwarder).

## Screenshots

| Overview | Settings | Diagnostics | Mesh apps |
|---|---|---|---|
| ![Overview: connected to the mesh](docs/screenshots/overview.png) | ![Settings](docs/screenshots/settings.png) | ![Diagnostics](docs/screenshots/diagnostics.png) | ![Per-app split tunnel](docs/screenshots/app-picker.png) |

| Light theme | Nostr relays |
|---|---|
| ![Overview in the light theme](docs/screenshots/overview-light.png) | ![Add and remove Nostr relays](docs/screenshots/relays.png) |

<sub>Captured on a Pixel 9 Pro joined to the live public mesh, with the
maintainer's own names, peers and app list blanked. The app is dark by
default; Settings → Appearance switches to light or to following the
system.</sub>

## Features

Beyond running a fips node on the phone, the app is what makes that node
usable on a device you also use for everything else.

- **Per-app split tunnel.** You pick which apps reach the mesh. Those apps get
  the mesh **and** normal internet — clearnet traffic rides a userspace
  forwarder on sockets protected from the tunnel — and every other app on the
  phone is untouched. With nothing selected the tunnel captures only fips2go
  itself, so it does nothing. Change the selection while connected and the
  mesh reconnects for a moment to apply it — no manual reconnect.
- **`.fips` names just resolve.** Covered apps' DNS is intercepted in-process:
  `.fips` names are answered by the built-in resolver, everything else goes to
  your normal upstreams. A `.fips` hostname works in the browser with nothing
  to configure.
- **Public domain names over fips.** A site owner who binds `www.example.org`
  to a mesh node (a `_fips-dns` TXT record plus a signed claim on Nostr —
  [fips-pub-domains](https://github.com/fr34aky/fips-pub-domains)) is reached
  over the mesh by name, in any covered app, with the ordinary Internet
  address as the fallback. The binding is verified before it is used (DNSSEC
  where the zone is signed, two resolvers otherwise) and then pinned; a domain
  already verified, or one whose claim carries a DNSSEC proof, keeps resolving
  with no Internet at all through a relay on the mesh, and nodes you trust
  can vouch for others (Settings → *Public domain names over fips*).
  Everything else resolves exactly as before, and the first lookup of an
  ordinary name does not wait for the decision.
- **Mesh names.** An address book on Overview maps readable names to npubs —
  `home.fips` instead of `npub1k3ae….fips` — for every mesh app, like a hosts
  file (it *is* one: fips's `name npub` format). Names are local to the
  device, and adding or re-pointing one applies to the next lookup; the mesh
  does not reconnect. Optionally they can also be pulled from a node you run
  with [fips-ui](https://github.com/fr34aky/fips-ui) — the same sync its own
  nodes use: hourly and on demand, over the mesh, with that node admitting
  this device by its npub as a viewer.
- **Default-deny inbound firewall.** Any authorized node on the mesh can
  otherwise reach any port your selected apps listen on, as if you had joined
  a shared LAN. Only replies to connections the phone opened, ICMPv6, and an
  explicit port allowlist get through; blocked ports show up in the log.
- **Identity sealed by the Android Keystore, with backup and restore.** The
  node's secret key is encrypted with a non-exportable Keystore key. Overview
  can reveal it for backup (clipboard flagged sensitive) and take it back
  afterwards — the only way an identity survives an uninstall, since the
  Keystore key dies with the app.
- **FIPS Hotspot.** While connected, the app auto-joins any open Wi-Fi named
  `!FIPS`, anywhere, to reach fips peers on it — your internet stays on your
  normal network. On dual-Wi-Fi phones it joins as a *second*, local-only
  connection without giving up the Wi-Fi you are already on.
- **Three links into the mesh, not one.** Besides the bootstrap server you
  picked, the node peers with two more public servers in other regions
  (Settings → *Fallback bootstrap peers*, on by default), so one server
  going down does not take the mesh with it. Every configured peer is also
  re-found through its Nostr advert if it moves to a new address.
- **Peer discovery via Nostr** (Settings, off by default). The node also links
  to a few nodes that announce themselves on the relays — capped at three, so
  the mesh survives every bootstrap server being down without the phone
  collecting links the way a server would.
- **LAN discovery (mDNS).** Finds fips peers on your Wi-Fi and dials them
  directly, with no relay or mesh hop. The tunnel's own addresses are kept out
  of the adverts, so the mesh ULA is never broadcast on the LAN. It also works
  the other way round: a device **tethered to this phone's own hotspot** that
  runs fips is found and linked over the hotspot LAN, with nothing to set up —
  which is how tethered devices get the mesh. (Android gives an app no way to
  route a tethered client's traffic into the tunnel: the kernel forwards it,
  no app owns it, and tethering never uses a VPN as its upstream.)
- **Survives network changes.** A Wi-Fi↔cellular hand-over keeps the node
  running: sessions, tree position and routes are all kept, and the peers
  whose path moved are re-pinned within about half a second of Android
  reporting the new network (the service pokes fips's medium-change detector
  the moment the callback fires). No restart, no manual reconnect — including
  on IPv4-only CGNAT mobile networks, where extra probe routes keep AAAA
  lookups (and so `.fips` names) resolving. Only two network events still
  restart the node: an underlay whose IPv6 status differs from the last one,
  and a FIPS Hotspot joining or leaving. (Changing the mesh apps or the relay
  list while connected restarts it too, once, because you asked.)
- **Your choice of Nostr relays.** The node publishes its address to, and looks
  peers up on, fips's three default relays out of the box. Add your own or
  remove any of them from Overview; addresses are validated before they are
  saved, because one the relay client rejects would take the whole rendezvous
  down with it.
- **Diagnostics that answer the real questions.** Resolve or ping an npub,
  live peer sessions with byte counts, nearby mDNS sightings, which Nostr
  relays the node is actually connected to, and a log viewer you can expand
  and copy.
- **In-app updates.** Checks GitHub Releases, downloads the APK matching your
  device's ABI, verifies it against the release's sha256, and hands it to the
  system installer — which enforces the release signing key and refuses while
  the VPN is up. Identity and settings survive.
- **Zero-config first run.** A fresh install connects without opening
  Settings: a bootstrap peer and working defaults are seeded on first launch.
  (Android's *Always-on VPN* is deliberately not supported: the app declares
  so, and the toggle is greyed out in system settings. Connect from the app.)
- **Battery-aware.** A saver profile relaxes the maintenance tick and halves
  heartbeats, measured at ~40% less idle CPU; the packet pump idles at
  essentially zero wakeups.
- **Dark by default.** The whole app uses a dark Material 3 scheme unless
  Settings → Appearance says light, or to follow the phone.

Standalone repo — it depends on fips as a pinned **git dependency**
(`fr34aky/fips` @ `android-hooks`, upstream v0.5.1+ plus the small embedder
hooks: socket-protect, `TunPacketProcessor`, public `ControlReadHandle::query`,
`ControlCommandHandle` for socket-less connect/disconnect, the `show_lan_peers`
mDNS-sightings query, dial-scoped UDP instances for the hotspot, and a
`NetmonTrigger` to wake the medium-change detector), so it clones and builds
without a sibling fips checkout.

## Ecosystem: fips2go, fips-ui and fips-pub-domains

fips2go is the phone end of three projects built around the same fips mesh.
The other two run on nodes you (or a site owner) operate — a home server, a
VPS, a router — and offer services that the phone uses over the mesh. None of
them is required: a fresh fips2go install joins the public mesh on its own,
and each service below is an addition.

```
  phone                                    nodes on the mesh
 ┌─────────────────────┐  names sync,      ┌─────────────────────────────────┐
 │ fips2go             │  dashboard :8321  │ your node (Linux, FreeBSD)      │
 │                     │ ────────────────► │ fips-ui                         │
 │ DNS proxy with      │                   │   │ manages, on this node only  │
 │ pubdom-core +       │                   │   ▼                             │
 │ pubdom-resolve      │                   │ fips-pubdom-server (optional)   │
 │                     │                   └─────────────────────────────────┘
 │                     │  DNS over the     ┌─────────────────────────────────┐
 │                     │  mesh (port from  │ a site's node                   │
 │                     │ ────────────────► │ fips-pubdom-server              │
 │                     │  its TXT record)  └─────────────────────────────────┘
 │                     │  Nostr, offline   ┌─────────────────────────────────┐
 │                     │ ────────────────► │ a relay on a fips node          │
 └─────────────────────┘                   └─────────────────────────────────┘
        every arrow runs over the fips mesh: fd00::/8, end-to-end encrypted
```

| Project | Runs on | What it gives fips2go |
|---|---|---|
| **fips2go** (this repo) | Android | The mesh node, per-app tunnel and DNS proxy. Consumes the two services below; links the `pubdom-*` crates directly. |
| **[fips-ui](https://github.com/fr34aky/fips-ui)** | a fips node; the features the phone uses need Linux, NixOS or FreeBSD (macOS experimental) | A web dashboard for a fips node. Serves the phone its **Mesh names** and its **dashboard** over the mesh, and is where an operator **manages fips-pub-domains** on that same node. |
| **[fips-pub-domains](https://github.com/fr34aky/fips-pub-domains)** | the node serving a domain (`fips-pubdom-server`); desktops (`fips-pubdomd`); fips2go (the library crates) | **Public domain names over fips**: `www.example.org` reached over the mesh by its ordinary name, verified and pinned, also with no Internet. |

### fips-ui → fips2go: names and a dashboard

Both uses go through fips-ui's *Web UI over the mesh*, which exists only
where fips-ui can load its kernel guard — Linux and NixOS (nftables) and
FreeBSD (pf); macOS is experimental, pfSense and Windows have none. On the
node, Access → **Web UI over the mesh** must be switched on (it needs helper
v5 or later; without the guard nobody is admitted from the mesh) and the
phone's npub added as a **viewer**. Viewer is enough for everything below;
do not make the phone an admin: fips-ui grants a role to everything that
leaves the listed node under its npub, which on a phone means every mesh
app you selected, a browser running arbitrary web pages included — and
admin is root on that node ([fips-ui
docs/mesh-access.md](https://github.com/fr34aky/fips-ui/blob/main/docs/mesh-access.md)).

- **Mesh names sync.** Overview → *Mesh names* can pull the name → npub
  address book from that node (off by default): fips2go sends
  `GET /api/hosts` to its mesh address through the shim's in-process HTTP
  client (`meshhttp.rs` — the app's own sockets cannot reach `fd00::/8`),
  hourly and on *Sync now*, only while connected. The names land in fips-ui's
  own marked block at the end of the phone's hosts file, so a synced name
  wins over a local one, and turning sync off removes the block. It is the
  same protocol fips-ui nodes use among themselves ([fips-ui
  docs/hosts-sync.md](https://github.com/fr34aky/fips-ui/blob/main/docs/hosts-sync.md)),
  so the phone sits in that tree as a follower of whichever node you name.
  fips-ui's guard drops TCP it does not admit, so a missing viewer entry,
  mesh access switched off, or no guard loaded all show up on the phone as
  a timeout, not a 403.
- **The dashboard itself.** With a browser selected as a mesh app, the phone
  opens the node's fips-ui at `http://<name>.fips:8321` (or `<npub>.fips`;
  8321 is fips-ui's default). There is no login: the mesh authenticates the
  source address. The same viewer entry serves both uses.

### fips-pub-domains → fips2go: public names over the mesh

- **On the phone, built in.** The resolver is not a separate app: the
  shim links fips-pub-domains' `pubdom-core` (policy, no I/O) and
  `pubdom-resolve` (relays, TXT verification, pin file) as pinned git
  dependencies and runs them inside the VPN's DNS proxy (`names.rs`). Every
  non-`.fips` name a mesh app asks for is offered to it first; a domain bound
  to a mesh node answers with that node's `fd…` address, anything else
  resolves as before. Settings → *Public domain names over fips* (on by
  default).
- **On the site's node.** The service the phone uses is
  `fips-pubdom-server`: it publishes the domain's signed claim to Nostr and
  answers the per-name lookups (`www` → `CNAME <npub>.fips.`) as DNS over the
  mesh, on the port named in the domain's TXT record and claim (5355 by
  default), which fips2go reaches through its in-process smoltcp stack
  (`meshudp.rs`). When the CNAME names another node, the phone pings that
  node over the mesh before answering. The site owner adds one `_fips-dns`
  TXT record at their DNS hoster; that record, DNSSEC-validated where the
  zone is signed, is what makes the phone trust the claim before it pins it.
- **Direct links.** With Settings → *Link directly to the servers of domains
  you use* (on by default), fips2go peers with the servers of up to two of
  its most recently verified domains — those verified by DNSSEC or by
  several resolvers, read when the node starts, so a domain verified while
  connected becomes a peer at the next connect. Their first lookup after a
  connect then does not wait for mesh discovery.
- **Offline.** A pinned domain keeps resolving with no Internet. For a domain
  never seen before, a Nostr relay running *on a fips node* — a separate
  service from `fips-pubdom-server`, listed in Settings → *Mesh relays for
  public names* and carried over the mesh by `meshtcp.rs` — lets the phone
  fetch claims and verify their DNSSEC proof, or — with witness npubs
  configured — accept attestations from nodes you trust. *Trust my Mesh
  names as witnesses* (off by default) counts the fips-ui node the names
  sync from, and every named node, among them.

Spec and phone-specific details: [fips-pub-domains
docs/spec.md](https://github.com/fr34aky/fips-pub-domains/blob/main/docs/spec.md)
and
[docs/android.md](https://github.com/fr34aky/fips-pub-domains/blob/main/docs/android.md).

### Where they meet: fips-ui manages fips-pub-domains

On a node that serves a domain or resolves for a desktop, fips-ui's *Public
domains* page manages the fips-pub-domains installed **on that same node**,
read from its local control sockets: it installs and updates
`fips-pubdom-server` and `fips-pubdomd` (Linux with systemd), edits their
zone files and configuration, shows the TXT record to add, and lists which
domains are served, attested and pinned ([fips-ui
docs/public-domains.md](https://github.com/fr34aky/fips-ui/blob/main/docs/public-domains.md)).
So a typical setup is one home or VPS node running fips, fips-ui and —
optionally — `fips-pubdom-server`, with fips2go on the phone syncing names
from it and reaching its services by name.

## Layout

| Path | What |
|---|---|
| `shim/` | Rust cdylib `libfips_android.so`: engine (node lifecycle), TUN fd pump, DNS proxy, clearnet forwarder, the public-names resolver and its mesh transports (`names.rs`, `meshudp.rs`, `meshtcp.rs`, on the `pubdom-*` crates), JNI surface (`org.fips.android.FipsNative`). |
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

The debug APK packages all three. Releases ship **one APK per ABI**, plus a
universal APK containing all three for anyone who would rather not work out
which one they need (see [Release build](#release-build)). min SDK 26
(Android 8.0).

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
./release-build.sh                # all ABIs + the universal APK
./release-build.sh arm64-v8a      # subset; no universal APK
# → dist/v<versionName>/: one signed APK per ABI + sha256 + unstripped .so,
#   plus fips-android-v<version>-universal.apk + sha256
```

The full release process — version decision, build, GitHub release, Zapstore
publish and credential handling — is in [`RELEASING.md`](RELEASING.md).

Releases ship **one APK per ABI** — `arm64-v8a` is the device-verified one
(see Supported platforms) — **plus one universal APK** carrying all three.
Point first-time installers at the universal APK: it is ~40 MB against ~18 MB
for arm64, but it always installs, whereas picking the wrong per-ABI APK
fails with `INSTALL_FAILED_NO_MATCHING_ABIS`.

The per-ABI APKs are not redundant: the in-app updater selects assets by the
`-<abi>.apk` suffix, so an installed app keeps taking the ~18 MB APK matching
its own device on every update, universal-installed or not (same package, same
signing key, higher `versionCode` — it updates in place). The universal APK's
`-universal` suffix matches no ABI, so the updater never picks it. **Publish
all of them**: dropping the per-ABI assets silently breaks in-app updates for
every already-installed user, since the updater would find no matching asset
and just report "no update".

A partial run (`./release-build.sh arm64-v8a`) skips the universal APK rather
than building one from whatever `jniLibs/` happens to hold, which could be a
stale `.so` from an earlier version.

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
  (`[::1]:5354`) — a name from the app's hosts file (`hosts_path`) is first
  re-asked as `<npub>.fips`, and the answer re-issued under the name the app
  used; every other name is first offered to the public-names resolver
  (a domain bound to a mesh node answers with that node's `fd…` address,
  verified and pinned — see
  [fips-pub-domains' android.md](https://github.com/fr34aky/fips-pub-domains/blob/main/docs/android.md))
  and otherwise forwarded to upstream resolvers over protected sockets
  (SERVFAIL on total failure). Configurable via `dns_upstreams`.
- **Socket protection**: the node announces every underlay socket fd to the
  shim's hook, which crosses JNI to `VpnService.protect()`. Covered: UDP
  listen/adopted/connected-peer, TCP listener/accepted/dialed (pre-SYN),
  Nostr STUN/hole-punch. Not covered (no fd in those libraries): nostr-sdk
  relay websockets, mDNS — benign because the fips app itself is not
  captured by the per-app tunnel.
- **FIPS Hotspot** (Settings toggle, on by default; API 29+, needs the fine
  location permission — Android hides SSIDs and scan results without it):
  while connected, the app auto-joins the open SSID `!FIPS` by two paths — a
  `WifiNetworkSuggestion` (API 31+) that the platform auto-joins and roams
  city-wide whenever the primary Wi-Fi slot is free, and a
  `WifiNetworkSpecifier` local-only secondary connection for the dual-Wi-Fi
  case, filed only once a scan actually shows `!FIPS` in range with the
  strongest beacon's BSSID pinned (approval is stored per BSSID, so a known
  AP rejoins with no prompt). The hotspot is never an underlay candidate: on
  join the node is rebound with a *second* UDP transport bound to the hotspot
  address on the main instance's port, dial-scoped to the link subnet, and
  LAN mDNS is forced on for that link.
- **Status**: `FipsNative.status()`/`query()` are served lock-free from the
  node's `ControlReadHandle` snapshots — same data as `fipsctl show_*`.

## Status / caveats

- **Exercised on a device** (Pixel 9 Pro, GrapheneOS / Android). Verified:
  connect/disconnect and joining a live ~1300-node mesh; `.fips` resolution
  and upstream DNS; per-app split tunnel (selected apps get mesh **and**
  clearnet, other apps untouched); automatic Wi-Fi↔cellular hand-over in both
  directions — the node stays up and both peers were re-pinned 0.5 s (to
  LTE) and 0.3 s (back to Wi-Fi) after the network callback, with no link
  lost through the liveness window, including on a roaming IPv4-only CGNAT
  5G network, with `.fips` resolution surviving past Chromium's 60 s
  IPv6-probe window; Keystore identity
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
- mDNS LAN discovery sits behind a Settings toggle, **on by default since
  0.3**, and is live-verified against a fips daemon on the same Wi-Fi: the
  phone discovered the host via `_fips._udp` within ~1.5 min, dialed its LAN
  address directly (no relay/mesh hop), and the advert carried only the
  Wi-Fi address — the tunnel ULA stays off the LAN. The app holds a
  `MulticastLock` while discovery can actually work — the toggle is on and
  the underlay is Wi-Fi, or a FIPS Hotspot is joined (which forces LAN
  discovery on for that link) — and never on cellular: the lock disables the
  chip's hardware multicast filtering, so every LAN multicast frame wakes the
  CPU and chatty LANs cost battery. Discovery over the phone's **own**
  hotspot needs no lock: with the phone as the access point (underlay
  cellular, lock not held) a laptop running fips on the hotspot was
  discovered and the link came up (Pixel, 0.6.0) — so do not widen the lock
  to cover tethering, it would only cost battery. The tunnel's own addresses are excluded
  from the adverts so the mesh ULA is not broadcast on the LAN. mDNS sockets
  cannot be socket-protected (no fd access) — fine for the per-app split
  tunnel, non-functional under "Block connections without VPN". BLE/Ethernet
  transports are not available on Android. ICMP to clearnet is not
  forwarded (TCP/UDP are).
- Public domain names are device-verified with a real bound domain: online
  (first-visit discovery and pinning), offline from a pin, offline from the
  claim's DNSSEC proof through a mesh relay, and offline through witnesses'
  attestations (fips-pub-domains' `docs/testing.md`, levels 5, 5b and 5c).
- Signed per-ABI releases are published on GitHub Releases and on
  [Zapstore](https://zapstore.dev), and the app can update itself: *Check for updates* (Diagnostics) downloads the ABI-matching
  APK, verifies it against the release's sha256, and hands it to the system
  installer — which only proceeds with the VPN disconnected and enforces the
  release signing key (identity and settings survive; verified live by
  updating v0.1.2 → v0.1.3 from within the app). Only `arm64-v8a` has been
  exercised on real hardware.

## License

MIT (see `LICENSE`). The bundled native library statically links
[fips](https://github.com/jmcorgan/fips) (MIT, © Johnathan Corgan) and other
MIT/Apache-2.0 Rust crates — binary releases should ship their notices.
