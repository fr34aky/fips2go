# Releasing

The full sequence for cutting a release, as actually performed for v0.3.3.
Every step here has been run; the gotchas are ones that bit, not ones that
might.

Two distribution channels, in order: **GitHub Releases** (which the in-app
updater reads) and **Zapstore** (Nostr-based). GitHub first — Zapstore's
manifest pulls the APK from the GitHub release.

## 0. Decide whether to release at all

Check what actually changed:

```bash
git diff <last-tag>..main -- android/app/src/ shim/src/
```

If that is **empty**, the binary is functionally identical to the last
release. `DEF_AUTO_UPDATE` is on, so every installed user gets prompted to
download ~18 MB for no behavioural change. That is sometimes still the right
call — v0.3.3 was cut precisely that way, because v0.3.2's artifacts had been
built by a verification script that turned out never to work — but it should
be a decision, not an accident, and the release notes should say so plainly.

Versioning (pre-1.0 semver, adopted after 0.1.6):

- **minor** (0.2 → 0.3) for new user-visible features
- **patch** (0.3.2 → 0.3.3) for bug fixes and polish
- **1.0** is reserved for the native npub-addressed API milestone
- `versionCode` is a plain +1 counter, independent of the name

The updater compares dotted numerics, so differing segment counts (`0.2` vs
`0.1.6`) are fine.

## 1. Prerequisites

| Need | Where |
|---|---|
| Signing keystore | `~/.android-keys/fips-android-release.keystore`, referenced by gitignored `android/keystore.properties` |
| Toolchain | Rust 1.94.1, NDK r27c, JDK 17, Gradle 8.7, SDK platform-34 |
| GitHub CLI | `gh auth status` — needs `repo` scope |
| Zapstore CLI | `zsp` (`~/go/bin/zsp`; on PATH via `~/.profile`). Prebuilt: `gh release download -R zapstore/zsp -p 'zsp-*-linux-amd64' -O ~/go/bin/zsp` |
| Nostr signer | The publisher nsec in `~/.zsp-nsec` (mode 600) — see step 5. `nak` (`~/go/bin/nak`, prebuilt from `fiatjaf/nak`) for the identity link and relay checks |

Without `keystore.properties` the APKs come out **unsigned**, which the script
does not treat as fatal. Check the signature output in step 2.

## 2. Bump the version and build

```bash
# android/app/build.gradle.kts — bump BOTH together
#   versionCode = <n+1>
#   versionName = "<x.y.z>"

./release-build.sh          # all ABIs + the universal APK
```

Land the bump through a PR like any other change; CI cross-compiles all three
ABIs, which is the check that matters.

`release-build.sh` produces, into `dist/v<versionName>/`:

- one signed APK per ABI + `.sha256`
- one signed **universal** APK (all three ABIs) + `.sha256`
- an unstripped `.so` per ABI, for symbolicating native crashes

and verifies, per APK: exactly the expected ABI(s) present, 16 KB LOAD
alignment on 64-bit (4 KB on `armeabi-v7a`), and the signing certificate.

> The universal APK is built **only when one run produces every ABI**.
> `./release-build.sh arm64-v8a` skips it, deliberately: `jniLibs/` persists
> between runs and may hold a stale `.so` from an earlier version.

Confirm before going further:

```bash
cd dist/v<version> && sha256sum -c *.sha256

# aapt2 is not on PATH; it lives in the SDK build-tools
BT=$(ls -d "$(sed -n 's/^sdk.dir=//p' android/local.properties)"/build-tools/* | sort -V | tail -1)
"$BT/aapt2" dump badging fips-android-v<version>-universal.apk \
  | grep -E "versionCode|native-code"
```

Expect the new `versionCode`/`versionName` and all three ABIs in the universal
APK. The signature line in the build output must read `CN=fr34aky`.

Regenerate `THIRD-PARTY-NOTICES.md` only when the **fips pin** moved (from the
arm64 `cargo tree`); otherwise attach the existing one.

## 3. Publish the GitHub release

```bash
gh release create v<version> --target main --title "v<version>" \
  --notes "$(cat notes.md)" \
  dist/v<version>/fips-android-v<version>-arm64-v8a.apk{,.sha256} \
  dist/v<version>/fips-android-v<version>-armeabi-v7a.apk{,.sha256} \
  dist/v<version>/fips-android-v<version>-x86_64.apk{,.sha256} \
  dist/v<version>/fips-android-v<version>-universal.apk{,.sha256} \
  THIRD-PARTY-NOTICES.md
```

**Asset names are load-bearing.** `Updater.kt` selects assets by the suffixes
`-<abi>.apk` and `-<abi>.apk.sha256`. Renaming or omitting either silently
breaks in-app updates for every installed user — the check just returns "no
update", and no later release repairs it because the same mismatch recurs.

- Publish **all four** APKs. The per-ABI ones are what the updater consumes;
  the universal one is a first-install convenience for the release page.
- `-universal.apk` deliberately matches no ABI suffix, so the updater never
  selects it. `release-build.sh` asserts that non-collision.
- Never re-upload per-ABI assets over an existing release: an APK rebuild is
  **not** byte-reproducible, so the published `.sha256` would stop matching.

Verify the updater contract:

```bash
curl -s https://api.github.com/repos/fr34aky/fips2go/releases/latest \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['tag_name']); [print(' ',a['name']) for a in d['assets']]"
```

`/releases/latest` must resolve to the new tag, and each ABI must have both its
`.apk` and `.apk.sha256`.

## 4. Release notes

Cover: what changed, which APK to pick, and the signing fingerprint.

```
aa905e32bd0058874d252990abba26c78ddd8fca018195ebd1cd232a99a7a8e1
```

The fingerprint matters most on a **first** install — there is no previously
installed signature for Android to compare against, so the checksum and this
fingerprint are the only things identifying a genuine build. Updates are
enforced against the key automatically.

If the binary is unchanged (step 0), say so in the first line so anyone
reading the update prompt knows it is optional.

## 5. Zapstore: prepare the credential

`zapstore.yaml` at the repo root already tracks this repo's latest GitHub
release and pins the universal APK via `match: '.*-universal\.apk$'`. It needs
no edit per release.

Signing needs a Nostr key: the publisher nsec, kept in `~/.zsp-nsec` (mode
600, one line, no newline needed). **That file is the identity, not a
session token** — `relay.zapstore.dev` accepts events only from the pubkey
declared in this repo's `zapstore.yaml`, and every published release and the
certificate proof below hang off it. Back it up; do not shred it after a
release. **Never paste it into a shared session or a shell command** — it
would land in shell history and `ps`. `$(cat ~/.zsp-nsec)` in the commands
below keeps it out of `argv`. (A `bunker://` URI in the same file works too,
if you run a remote signer.)

If the key is ever lost (it was, 2026-09-10): generate a new one, commit its
npub as `pubkey:` in `zapstore.yaml` — the relay fetches that file from the
repo to allowlist the key, so until it is on `main` every publish fails with
`event pubkey is not allowed` — then redo the one-time certificate link at the
bottom of this document. Earlier releases stay under the old pubkey; Zapstore
users see the app as a new publisher.

The allowlist is only the first gate. The relay also enforces **one publisher
per app id**: a kind-32267 app event whose `d` tag (`org.fips.android`) is
already held by a different pubkey is refused with `another pubkey has already
published an app with the same 'd' tag identifier`, and nothing on our side
can clear that — the relay's own code only lets a developer reclaim an app
from Zapstore's *indexer* key, not from another developer key. The old app
event has to be deleted or transferred by the Zapstore team (open an issue on
`zapstore/relay`, naming the app id, the old npub and the new one). Until
then `zsp publish` fails on `software_application` and publishes nothing.

```bash
umask 077
hex=$(nak key generate)
printf '%s' "$(nak encode nsec "$hex")" > ~/.zsp-nsec
nak key public "$hex" | nak encode npub        # → the pubkey: line
```

`/.env` and `/signing-crt_*.txt` are gitignored because zsp's own flows leave
credentials there.

## 6. Publish to Zapstore

```bash
cd ~/fips2go
SIGN_WITH=$(cat ~/.zsp-nsec) zsp publish -q --skip-preview zapstore.yaml
```

`-q` auto-confirms; without it, `zsp publish` opens an interactive selector
that needs a real TTY.

> **`zsp publish -q` prints nothing on success**, and zsp documents "nothing to
> do: silent exit 0". **Exit 0 does not mean it published.** Always verify
> against the relay.

Optional pre-flight (no signing, no publishing):

```bash
zsp publish --check zapstore.yaml     # → {"package_id":"org.fips.android"}
```

## 7. Verify the Zapstore release

The relay is the source of truth — zapstore.dev renders its Releases panel
client-side, so `curl`/fetch tools show "No releases found." even for
long-published apps. Do not read anything into that.

Quickest check, with `nak` (the release event is kind 30063, addressed by the
package id; the file event it references is kind 1063):

```bash
nak req -k 30063 -i org.fips.android --limit 3 wss://relay.zapstore.dev \
  | python3 -c "import json,sys; [print([t for t in json.loads(l)['tags'] if t[0] in ('d','e')]) for l in sys.stdin]"
nak req --id <e-tag> wss://relay.zapstore.dev    # → filename, x (sha256), size, version_code
```

Or the longer script below, which walks the same events:

```python
# python3 - <<'PY'   (needs the `websockets` package)
import asyncio, json, websockets
async def q(f):
    out=[]
    async with websockets.connect("wss://relay.zapstore.dev", open_timeout=20) as ws:
        await ws.send(json.dumps(["REQ","v",f]))
        while True:
            try:
                m=json.loads(await asyncio.wait_for(ws.recv(), timeout=8))
            except asyncio.TimeoutError:
                break
            if m[0]=="EVENT": out.append(m[2])
            elif m[0]=="EOSE": break
    return out
async def main():
    rels=await q({"kinds":[30063],"#i":["org.fips.android"],"limit":10})
    for r in sorted(rels, key=lambda x:-x["created_at"]):
        tags={}
        for t in r["tags"]: tags.setdefault(t[0],[]).append(t[1])
        print(tags["d"][0])
        for eid in tags.get("e",[]):
            fe=await q({"ids":[eid]})
            ft={}
            for t in fe[0]["tags"]: ft.setdefault(t[0],[]).append(t[1])
            print("  ", ft["filename"][0], ft["x"][0], ft["size"][0], "vc="+ft["version_code"][0])
asyncio.run(main())
# PY
```

Check the newest `d` tag is `org.fips.android@<version>` and that the file
event's `x` (sha256) and `size` match `dist/v<version>/` exactly.

## 8. Clean up

Nothing to shred: `~/.zsp-nsec` is the publisher identity and stays (step 5).
`zsp`'s own flows can leave `/.env` and `/signing-crt_*.txt` in the repo; both
are gitignored, but check `git status` before the next commit. Rotate the key
if it was ever exposed — an ignore rule does not undo exposure.

## One-time: link the signing certificate

Only needed when the **signing key changes** or the proof expires. The current
proof (kind 30509, from npub `…xpaz6gsyrxvrw`, 2026-09-10) covers cert
`aa905e32…a7a8e1` until **2028-09-09**; every release signed with that key is
covered, so this is not a per-release step.

```bash
KEYSTORE_PASSWORD=$(sed -n 's/^storePassword=//p' android/keystore.properties) \
SIGN_WITH=$(cat ~/.zsp-nsec) \
  zsp identity --link-key ~/.android-keys/fips-android-release.p12 \
               --key-alias fips-android --link-key-expiry 2y --offline \
  | nak event wss://relay.primal.net wss://relay.damus.io wss://relay.zapstore.dev
```

`--offline` prints the signed kind-30509 event instead of publishing it, and
`nak event` publishes an already-signed event unchanged — which is what makes
this runnable from a script or an agent session (see the second trap below).
Two of the three relays accepting is enough; `relay.damus.io` rate-limits
freely.

Two traps:

- **The keystore is PKCS#12 despite its `.keystore` name** (modern `keytool`
  defaults to PKCS12). zsp picks its loader from the file *extension*, so
  `.keystore` makes it try JKS and fail with `got invalid magic`. Point it at
  a `.p12` name — a symlink is enough, and avoids a second copy of the key.
  One already exists: `~/.android-keys/fips-android-release.p12`.
- **`zsp identity` has no `--yes`.** Its final confirmation is a TUI selector
  needing a real TTY; `--json` and `-q` do not suppress it, and neither a
  background shell nor Claude Code's `!` prefix can drive it. The `--offline |
  nak event` form above sidesteps the prompt entirely; if you drop `--offline`,
  run it in a real terminal and press Enter on "Publish now".

Verify (prompts for the npub; pipe it in for a non-interactive run):

```bash
printf '%s\n' npub1q697zgclkyz9dztp9zt3mzctwgxvxnqj69u52sqrjvzmyxpaz6gsyrxvrw \
  | zsp identity --verify dist/v<version>/fips-android-v<version>-universal.apk
```

Expect `Cert hash match: YES`, `Status: ACTIVE`, `Signature: VALID`.

## Gotchas worth remembering

- **Do not reinstall or force-stop the app while the VPN is connected** — it
  can leak netd routing rules that block other apps' connectivity until
  reboot. Disconnect first.
- **Installing a release over a debug build (or vice versa) needs an
  uninstall** — different signing keys — which **wipes the mesh identity**,
  since the nsec is sealed by a non-exportable Keystore key. Since 0.3 this is
  survivable if planned: Overview → **Back up** reveals the nsec, **Restore**
  takes it back. There is no recovery from a build already uninstalled. Check
  what is installed (`adb shell dumpsys package org.fips.android`) and compare
  signers (`apksigner verify --print-certs`) first.
- **`armeabi-v7a` is the build most likely to break on a fips pin bump**
  (32-bit pointer-width casts). CI covers it; look at the result.
- Only `arm64-v8a` is device-verified. `x86_64` is emulator-verified,
  `armeabi-v7a` has never run on real 32-bit hardware.
