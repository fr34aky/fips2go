#!/usr/bin/env bash
# Build the Rust shim for Android and drop it where Gradle packages it.
set -euo pipefail
cd "$(dirname "$0")"
source ./android-env.sh
(cd shim && cargo build --release --target aarch64-linux-android)
mkdir -p android/app/src/main/jniLibs/arm64-v8a
cp shim/target/aarch64-linux-android/release/libfips_android.so \
   android/app/src/main/jniLibs/arm64-v8a/
echo "jniLibs updated: $(ls -la android/app/src/main/jniLibs/arm64-v8a/libfips_android.so)"
