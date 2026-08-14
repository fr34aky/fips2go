#!/usr/bin/env bash
# Release build (GitHub Releases flow): arm64-v8a only, signed, with an
# unstripped copy of the shim archived for symbolizing native crash dumps.
#
#   ./release-build.sh
#
# Needs android/keystore.properties (gitignored; see README "Release") for
# signing — without it the APK comes out unsigned. Artifacts land in
# dist/v<versionName>/: the APK, its sha256, and the unstripped .so.
set -euo pipefail
cd "$(dirname "$0")"
source ./android-env.sh
export JAVA_HOME=$HOME/.local/jdk-17
SDK_DIR=$(sed -n 's/^sdk.dir=//p' android/local.properties)

VERSION=$(sed -n 's/.*versionName = "\(.*\)".*/\1/p' android/app/build.gradle.kts)
DIST=dist/v$VERSION
mkdir -p "$DIST"

# 1. Shim, arm64 only. Override the release profile's strip=true so the
#    build keeps symbols; archive that copy, then strip the one Gradle
#    packages (llvm-strip ≈ cargo's strip="symbols").
CARGO_PROFILE_RELEASE_STRIP=false ./build-native.sh arm64-v8a
cp android/app/src/main/jniLibs/arm64-v8a/libfips_android.so \
   "$DIST/libfips_android-v$VERSION-unstripped.so"
"$NDK_BIN/llvm-strip" android/app/src/main/jniLibs/arm64-v8a/libfips_android.so

# 2. APK (release build type: arm64-only abiFilters + release signing).
(cd android && "$HOME/.local/gradle-8.7/bin/gradle" assembleRelease)
APK=$DIST/fips-android-v$VERSION-arm64-v8a.apk
cp android/app/build/outputs/apk/release/app-release.apk "$APK"

# 3. Verify before publishing anything.
BUILD_TOOLS=$(ls -d "$SDK_DIR"/build-tools/* | sort -V | tail -1)
echo "--- packaged ABIs (must be arm64-v8a only):"
unzip -l "$APK" | grep 'lib/' || { echo "no native libs in APK!"; exit 1; }
! unzip -l "$APK" | grep 'lib/' | grep -qv 'lib/arm64-v8a/'
echo "--- ELF LOAD alignment (must be 0x4000 for 16 KB pages):"
"$NDK_BIN/llvm-readelf" -l android/app/src/main/jniLibs/arm64-v8a/libfips_android.so \
    | awk '/LOAD/ {print $NF}' | sort -u
echo "--- signature:"
"$BUILD_TOOLS/apksigner" verify --print-certs "$APK"

(cd "$DIST" && sha256sum "$(basename "$APK")" > "$(basename "$APK").sha256")
echo
echo "Release artifacts:"
ls -la "$DIST"
