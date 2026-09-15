# PR Review Checklist

The criteria maintainers apply to incoming PRs on `fips2go`. Written to
be executable by a human or a coding agent, in that order: read the context,
apply the criteria, then write prose — not a filled-in form.

This repo is an Android `VpnService` embedding a mesh daemon. A change here can
expose every port on someone's phone to a public mesh, silently destroy an
unrecoverable identity key, or brick connectivity until reboot. The criteria
below are weighted accordingly, and several exist because the failure already
happened once.

## Step 1 — Should this even be reviewed?

Skip and say so briefly:

- Closed, merged, or draft PRs.
- Dependabot PRs, unless the bump crosses a major version or moves an
  action that handles the checked-out tree or the cache (`actions/checkout`,
  `Swatinem/rust-cache`) — those run with the repo's contents in hand and
  were pinned for exactly that reason.
- Pure version bumps (`versionCode` / `versionName`) that accompany a release.
- Changes confined to `dist/`, generated notices, or screenshots.

Everything touching `shim/src/`, `android/app/src/`, the build scripts, or
`.github/workflows/` gets a real review.

## Step 2 — Gather context

Do this before reading a single diff hunk.

1. **PR metadata.** `gh pr view <n>` and `gh pr diff <n>`. Read the body: does
   it say what the change does and why, or only what it touches?
2. **CI state.** `gh pr checks <n>`. `android` is the meaningful one — it is
   the only job that cross-compiles all three ABIs. Do not treat a red check
   as authoritative without reading why: on 2026-09-15 every `android` run
   was red for an hour because a third-party setup action broke, with no
   change on our side. There is no automated security scan: the security
   review is part of this checklist (section B, plus criterion 14 for the
   updater), done by a person reading the diff with `SECURITY-REVIEW.md`
   open — it maps the trust boundaries and lists the deliberate design
   choices that are not findings.
3. **Base freshness.** Is the branch behind `main`? Workflow and pin changes in
   particular go stale within hours.
4. **Project guidance.** `CLAUDE.md` is the architecture and constraints
   document, and it is specific. `PHASE1-NOTES.md` / `PHASE2-NOTES.md` /
   `PHASE3-NOTES.md` document the porting history and the socket-protect
   coverage table — consult them before accepting a change to the embedding
   seam.
5. **Prior art.** Search closed PRs and commits for the same file. Much of this
   codebase's behaviour is the result of a specific device-observed bug, and
   the commit message usually explains it.

## Step 3 — The criteria

### A. Structure and hygiene

1. **The body explains the why.** A diff shows what changed. The body should
   say what was broken or missing, and what observable behaviour differs now.
   "Refactor pump.rs" is not a description.

2. **Scope matches the stated intent.** Unrelated reformatting, drive-by
   renames, or a second feature smuggled into a bugfix all make the change
   harder to revert when it turns out to be wrong.

3. **Commit messages carry the reasoning.** This repo's history is unusually
   good at explaining *why*; a PR that degrades that is a real cost. The
   message, not the PR body, is what survives.

4. **The fips pin stays in sync.** If `shim/Cargo.toml`'s `rev` moved, then
   `smoke/Cargo.toml`, `shim/Cargo.lock` and `smoke/Cargo.lock` must all move
   with it, and `THIRD-PARTY-NOTICES.md` must be regenerated. CI guards the
   first two; the notices are on the author. A bumped manifest with a stale
   lock quietly builds the *old* fips.

### B. The change itself

5. **Untrusted input is treated as hostile.** Anything parsing packets off the
   mesh (`filter.rs`, `packet.rs`, `pump.rs`), DNS responses (`dns.rs`), or
   GitHub release metadata (`Updater.kt`) is handling attacker-controlled
   bytes. Check bounds, length arithmetic, and what happens on a truncated or
   malformed input. Any authorized node on a ~1000-node public mesh can reach
   this device.

6. **The inbound firewall still default-denies.** `filter.rs` permits only
   replies to outbound-initiated flows, ICMPv6, and an explicit port
   allowlist. A change that lets an unsolicited packet reach a covered app
   re-exposes every listening port on the phone. The flow table must stay
   bounded and idle-expiring.

7. **The identity is not widened.** The nsec is sealed by a non-exportable
   Keystore key. Flag anything that logs it, writes it in plaintext, puts it in
   an Intent, or broadens where it is readable. Two specific traps:
   `deriveIdentity("")` means *generate*, so an empty string silently mints a
   new identity while claiming to restore one; and clipboard copies of it must
   set `EXTRA_IS_SENSITIVE`.

8. **Every underlay socket is still protected.** The node announces socket fds
   to the shim's hook, which calls `VpnService.protect()`. A new socket on a
   path that skips the hook routes its traffic back into the tunnel. Check
   `PHASE3-NOTES.md`'s coverage table rather than assuming.

9. **Settings migrations preserve existing choices.** `ConfigStore.applyDefaults()`
   seeds only keys the user has never saved, guarded by `contains()`, because
   `SettingsFragment.save()` writes every key. A new default that skips that
   guard will overwrite a deliberate user choice — including a deliberately
   blanked field — on upgrade. Retiring a key means deleting it, or a stale
   value keeps taking effect with no UI left to clear it.

10. **The JNI boundary holds.** No panic may unwind across it, and malformed
    JSON or non-UTF-8 strings must be handled. Every export is mirrored in
    `FipsNative.kt`; the two must stay in step.

11. **Kotlin changes state how they were verified.** There is no Kotlin test
    suite. Every Kotlin path is verified by a human looking at a screen, so a
    PR touching the UI or the service should say what was exercised and on
    what — a wiped emulator (`fips-firstrun` AVD) for first-run and migration
    paths, a real device for anything involving Wi-Fi, Doze, or the hotspot,
    which the emulator cannot test.

### C. Consequences

12. **All three ABIs still build.** `armeabi-v7a` is 32-bit and breaks on
    pointer-width casts the 64-bit targets accept; it is the build most likely
    to fail on a fips pin bump. CI covers this, so the criterion is really:
    did CI actually run, and did the author look?

13. **Page alignment is intact.** 16 KB LOAD alignment on `aarch64` and
    `x86_64` (required on Android 15+), 4 KB on `armeabi-v7a`. Do not let
    `shim/.cargo/config.toml`'s rustflags be "cleaned up".

14. **The updater contract is intact.** `Updater.kt` matches release assets by
    the suffixes `-<abi>.apk` and `-<abi>.apk.sha256`. Renaming an artifact
    breaks in-app updates for every installed user *silently* — the updater
    just reports "no update". Any change to `release-build.sh` naming needs
    checking against that.

15. **Versioning follows the policy.** Pre-1.0 semver: **minor** for new
    user-visible features, **patch** for fixes and polish, `versionCode` a
    plain +1 counter. `1.0` is reserved for the native npub-addressed API
    milestone.

16. **Destructive device behaviour is called out.** Anything that changes
    install, uninstall, identity, or the VPN lifecycle should say so plainly.
    Reinstalling across a signing-key change destroys the identity; reinstalling
    or force-stopping while the VPN is connected can leak netd routing rules
    that block other apps until reboot.

## Step 4 — Compose the review

Write prose, not a checklist with the boxes filled in. The criteria are a
thinking aid; the reader wants an argument.

- **Open** with what the PR does and whether it should land, in two or three
  sentences. Lead with the disposition, not suspense.
- **Body**: the findings that matter, most serious first, each with the
  concrete failure it causes — inputs, state, resulting behaviour. "This could
  overflow" is not a finding; "a 3-byte extension header makes this read past
  the buffer" is.
- **Close** with the disposition and what would change it: approve, approve
  with nits, or request changes plus the specific thing that must happen.

## Step 5 — Filter aggressively

Do not flag:

- Style the codebase does not enforce. There is no linter here; do not become one.
- Hypotheticals with no reachable path. Name the caller or drop it.
- Deliberate design choices — the list lives in `SECURITY-REVIEW.md` (empty
  default inbound allowlist, nsec shown in cleartext by the backup dialog,
  no signing key in CI, the in-app `.fips` resolver, and so on) with the
  reasoning in `CLAUDE.md`. Add new ones there, not here.
- Missing tests for Kotlin. There is no suite; asking for one per PR is noise.
  Ask how it was verified instead.

Three real findings beat fifteen observations. Every false positive spends the
author's attention and teaches them to skim the next review.

## Step 6 — Citation discipline

Cite with full-SHA permalinks so they survive a rebase:

```
https://github.com/fr34aky/fips2go/blob/<full-40-char-sha>/shim/src/filter.rs#L42-L58
```

Not branch links, and not bare line numbers — a reviewer reading the thread in
a month needs the code as it was.

## Notes

State confidence honestly. "This is wrong" and "I think this is wrong, but I
have not traced the caller" are different claims, and conflating them costs
you the reader's trust the first time you are wrong.

On re-review, read the fixes rather than re-running the whole checklist, and
say explicitly what is now resolved. A PR whose findings were addressed should
not have to re-litigate them.

Green CI means the change built on three ABIs and the host tests passed,
nothing more; reading it for security is this review's job.
