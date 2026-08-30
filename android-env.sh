# Source this before cross-building for Android.
# NDK r27c, API level 24 (minimum for getifaddrs, used by src/nostr/stun.rs).
# NDK location. Defaults to this machine's checkout; CI (and anyone whose NDK
# lives elsewhere) overrides FIPS_NDK_HOME instead of editing this file.
NDK_HOME=${FIPS_NDK_HOME:-/home/andre/android-ndk-r27c}
NDK_BIN=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
if [ ! -x "$NDK_BIN/clang" ]; then
    echo "android-env.sh: no NDK at $NDK_HOME (set FIPS_NDK_HOME)" >&2
fi

# arm64-v8a
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK_BIN/aarch64-linux-android24-clang
export CC_aarch64_linux_android=$NDK_BIN/aarch64-linux-android24-clang
export AR_aarch64_linux_android=$NDK_BIN/llvm-ar
export RANLIB_aarch64_linux_android=$NDK_BIN/llvm-ranlib

# armeabi-v7a (Rust target armv7-linux-androideabi)
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$NDK_BIN/armv7a-linux-androideabi24-clang
export CC_armv7_linux_androideabi=$NDK_BIN/armv7a-linux-androideabi24-clang
export AR_armv7_linux_androideabi=$NDK_BIN/llvm-ar
export RANLIB_armv7_linux_androideabi=$NDK_BIN/llvm-ranlib

# x86_64 (emulator, Chromebooks)
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$NDK_BIN/x86_64-linux-android24-clang
export CC_x86_64_linux_android=$NDK_BIN/x86_64-linux-android24-clang
export AR_x86_64_linux_android=$NDK_BIN/llvm-ar
export RANLIB_x86_64_linux_android=$NDK_BIN/llvm-ranlib

# The ESP32 toolchain exports a 32-bit Xtensa libclang globally, which breaks
# bindgen (rustables) on HOST builds; pin the system libclang for those.
# Deliberately NOT ${LIBCLANG_PATH:-...}: the whole point is to override a bad
# machine-wide value, so an already-set LIBCLANG_PATH must lose. Use the
# dedicated override to point somewhere else (CI has its own llvm).
export LIBCLANG_PATH=${FIPS_LIBCLANG_PATH:-/usr/lib/llvm-18/lib}
