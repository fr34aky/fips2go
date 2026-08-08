#!/usr/bin/env bash
# Build the Rust shim for Android and drop the .so files where Gradle
# packages them (android/app/src/main/jniLibs/<abi>/).
#
#   ./build-native.sh                 # all supported ABIs
#   ./build-native.sh arm64-v8a       # just one (any of: arm64-v8a,
#                                     #   armeabi-v7a, x86_64)
set -euo pipefail
cd "$(dirname "$0")"
source ./android-env.sh

# rust-target:jniLibs-abi pairs. Keep in sync with rust-toolchain.toml and
# the abiFilters list in android/app/build.gradle.kts.
ALL_TARGETS=(
    aarch64-linux-android:arm64-v8a
    armv7-linux-androideabi:armeabi-v7a
    x86_64-linux-android:x86_64
)

TARGETS=()
if [ $# -eq 0 ]; then
    TARGETS=("${ALL_TARGETS[@]}")
else
    for abi in "$@"; do
        found=
        for pair in "${ALL_TARGETS[@]}"; do
            [ "${pair##*:}" = "$abi" ] && TARGETS+=("$pair") && found=1
        done
        [ -n "$found" ] || { echo "unknown ABI: $abi" >&2; exit 1; }
    done
fi

for pair in "${TARGETS[@]}"; do
    target=${pair%%:*}
    abi=${pair##*:}
    (cd shim && cargo build --release --target "$target")
    mkdir -p "android/app/src/main/jniLibs/$abi"
    cp "shim/target/$target/release/libfips_android.so" \
       "android/app/src/main/jniLibs/$abi/"
done

echo "jniLibs updated:"
ls -la android/app/src/main/jniLibs/*/libfips_android.so
