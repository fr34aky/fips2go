#!/usr/bin/env bash
# Release build (GitHub Releases flow): one signed APK per ABI, each with an
# unstripped copy of the shim archived for symbolizing native crash dumps,
# plus one universal APK carrying all three ABIs.
#
#   ./release-build.sh                # all supported ABIs + universal
#   ./release-build.sh arm64-v8a      # subset (any of: arm64-v8a,
#                                     #   armeabi-v7a, x86_64); no universal
#
# The per-ABI APKs are what the in-app updater consumes: Updater.kt matches
# release assets by the suffixes -<abi>.apk and -<abi>.apk.sha256, so those
# names are load-bearing and must not change. The universal APK exists only
# for the GitHub release page, so a human installing for the first time does
# not have to identify their own ABI (a wrong pick fails with
# INSTALL_FAILED_NO_MATCHING_ABIS). Its "-universal" suffix deliberately
# matches no ABI, so the updater never selects it and installed users keep
# taking the ~18 MB arm64 APK instead of the ~40 MB universal one.
#
# Needs android/keystore.properties (gitignored; see README "Release") for
# signing — without it the APKs come out unsigned. Artifacts land in
# dist/v<versionName>/: per-ABI APK + sha256 + unstripped .so, and the
# universal APK + sha256.
set -euo pipefail
cd "$(dirname "$0")"
source ./android-env.sh
export JAVA_HOME=$HOME/.local/jdk-17
SDK_DIR=$(sed -n 's/^sdk.dir=//p' android/local.properties)
BUILD_TOOLS=$(ls -d "$SDK_DIR"/build-tools/* | sort -V | tail -1)

VERSION=$(sed -n 's/.*versionName = "\(.*\)".*/\1/p' android/app/build.gradle.kts)
DIST=dist/v$VERSION
mkdir -p "$DIST"

ALL_ABIS=(arm64-v8a armeabi-v7a x86_64)
ABIS=("$@")
[ ${#ABIS[@]} -gt 0 ] || ABIS=("${ALL_ABIS[@]}")

for abi in "${ABIS[@]}"; do
    echo "=== $abi"
    # 1. Shim for this ABI only. Override the release profile's strip=true
    #    so the build keeps symbols; archive that copy, then strip the one
    #    Gradle packages (llvm-strip ≈ cargo's strip="symbols").
    CARGO_PROFILE_RELEASE_STRIP=false ./build-native.sh "$abi"
    SO=android/app/src/main/jniLibs/$abi/libfips_android.so
    cp "$SO" "$DIST/libfips_android-v$VERSION-$abi-unstripped.so"
    "$NDK_BIN/llvm-strip" "$SO"

    # 2. APK (release build type: this ABI only + release signing).
    (cd android && "$HOME/.local/gradle-8.7/bin/gradle" assembleRelease "-PreleaseAbi=$abi")
    APK=$DIST/fips-android-v$VERSION-$abi.apk
    cp android/app/build/outputs/apk/release/app-release.apk "$APK"

    # 3. Verify before publishing anything.
    echo "--- packaged ABIs (must be $abi only):"
    # Derive the set of ABI directories present and compare it to what was
    # asked for. Deliberately not `... | grep -qv "lib/$abi/"`: grep -qv exits
    # at the first foreign line, SIGPIPEs the upstream grep, and pipefail
    # turns that into a non-zero pipeline which the leading `!` flips into a
    # PASS — so a foreign ABI shipped silently. Every command below reads its
    # input to the end, so nothing can exit early and break the pipe.
    listing=$(unzip -l "$APK")
    grep 'lib/' <<< "$listing" || { echo "no native libs in APK!"; exit 1; }
    found=$(grep -oE 'lib/[^/]+/' <<< "$listing" | sed 's#^lib/##; s#/$##' | sort -u)
    if [ "$found" != "$abi" ]; then
        echo "::error:: expected only $abi, found: $(echo $found)"
        exit 1
    fi
    # 16 KB LOAD alignment on 64-bit; 32-bit Android stays on 4 KB pages.
    want=0x4000; [ "$abi" = armeabi-v7a ] && want=0x1000
    echo "--- ELF LOAD alignment (must be $want):"
    got=$("$NDK_BIN/llvm-readelf" -l "$SO" | awk '/LOAD/ {print $NF}' | sort -u)
    echo "$got"
    [ "$got" = "$want" ]
    echo "--- signature:"
    "$BUILD_TOOLS/apksigner" verify --print-certs "$APK"
    (cd "$DIST" && sha256sum "$(basename "$APK")" > "$(basename "$APK").sha256")
done

# Universal APK — every ABI in one file, for the release page's "not sure
# which one?" download. Reuses the stripped .so the loop above just built and
# verified, so it packages byte-identical libraries to the per-ABI APKs and
# costs one extra Gradle run rather than another cargo build.
#
# Built only when this run produced every ABI: jniLibs is a build output that
# persists between runs, so after `./release-build.sh arm64-v8a` it can still
# hold stale .so files from an earlier version, and packaging those would ship
# a universal APK that is a different build for two of its three ABIs.
built=$(printf '%s\n' "${ABIS[@]}" | sort -u)
wanted=$(printf '%s\n' "${ALL_ABIS[@]}" | sort -u)
if [ "$built" = "$wanted" ]; then
    echo "=== universal"
    (cd android && "$HOME/.local/gradle-8.7/bin/gradle" assembleRelease \
        "-PreleaseAbi=$(IFS=,; echo "${ALL_ABIS[*]}")")
    UAPK=$DIST/fips-android-v$VERSION-universal.apk
    cp android/app/build/outputs/apk/release/app-release.apk "$UAPK"

    echo "--- packaged ABIs (must be all ${#ALL_ABIS[@]}):"
    # Capture the listing once and match against it, rather than piping into
    # `grep -q` per ABI: grep -q exits at the first match (line 9 of ~900),
    # unzip then dies writing to the closed pipe, and `set -o pipefail` turns
    # that into a failed check even though every ABI is present.
    listing=$(unzip -l "$UAPK")
    grep 'lib/' <<< "$listing"
    for abi in "${ALL_ABIS[@]}"; do
        grep -q "lib/$abi/libfips_android.so" <<< "$listing" \
            || { echo "$abi missing from the universal APK!"; exit 1; }
    done
    # The updater matches assets by "-<abi>.apk"; this name must match none of
    # them, or clients would download 40 MB instead of their own 18 MB APK.
    for abi in "${ALL_ABIS[@]}"; do
        case "$(basename "$UAPK")" in
            *-"$abi".apk) echo "universal APK name collides with the updater's $abi asset!"; exit 1 ;;
        esac
    done
    echo "--- signature:"
    "$BUILD_TOOLS/apksigner" verify --print-certs "$UAPK"
    (cd "$DIST" && sha256sum "$(basename "$UAPK")" > "$(basename "$UAPK").sha256")
else
    echo
    echo "note: partial ABI set ($(echo $built)) — skipping the universal APK."
fi

echo
echo "Release artifacts:"
ls -la "$DIST"
