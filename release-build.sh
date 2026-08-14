#!/usr/bin/env bash
# Release build (GitHub Releases flow): one signed APK per ABI, each with an
# unstripped copy of the shim archived for symbolizing native crash dumps.
#
#   ./release-build.sh                # all supported ABIs
#   ./release-build.sh arm64-v8a      # subset (any of: arm64-v8a,
#                                     #   armeabi-v7a, x86_64)
#
# Needs android/keystore.properties (gitignored; see README "Release") for
# signing — without it the APKs come out unsigned. Artifacts land in
# dist/v<versionName>/: per-ABI APK + sha256 + unstripped .so.
set -euo pipefail
cd "$(dirname "$0")"
source ./android-env.sh
export JAVA_HOME=$HOME/.local/jdk-17
SDK_DIR=$(sed -n 's/^sdk.dir=//p' android/local.properties)
BUILD_TOOLS=$(ls -d "$SDK_DIR"/build-tools/* | sort -V | tail -1)

VERSION=$(sed -n 's/.*versionName = "\(.*\)".*/\1/p' android/app/build.gradle.kts)
DIST=dist/v$VERSION
mkdir -p "$DIST"

ABIS=("$@")
[ ${#ABIS[@]} -gt 0 ] || ABIS=(arm64-v8a armeabi-v7a x86_64)

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
    unzip -l "$APK" | grep 'lib/' || { echo "no native libs in APK!"; exit 1; }
    ! unzip -l "$APK" | grep 'lib/' | grep -qv "lib/$abi/"
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

echo
echo "Release artifacts:"
ls -la "$DIST"
