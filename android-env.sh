# Source this before cross-building for Android.
# NDK r27c, API level 24 (minimum for getifaddrs, used by src/nostr/stun.rs).
NDK_BIN=/home/andre/android-ndk-r27c/toolchains/llvm/prebuilt/linux-x86_64/bin

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
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
