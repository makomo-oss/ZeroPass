#!/usr/bin/env bash
# Builds the Rust core for Android and generates its Kotlin bindings.
#
# Needs the Android NDK (ANDROID_NDK_HOME), the Rust target
# aarch64-linux-android and cargo-ndk. Run it before the Gradle build and again
# whenever crates/zp-ffi or anything below it changes. Its outputs are not
# committed:
#   app/src/main/jniLibs/arm64-v8a/libzp_ffi.so
#   app/src/main/java/uniffi/zp_ffi/zp_ffi.kt
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$root"

cargo ndk -t arm64-v8a -o "$here/app/src/main/jniLibs" build -p zp-ffi --release

# The bindings are read from a host build: the release library for Android is
# stripped of the symbols that describe the interface.
cargo build -q -p zp-ffi
host_lib=""
for candidate in target/debug/zp_ffi.dll target/debug/libzp_ffi.so target/debug/libzp_ffi.dylib; do
    if [ -f "$candidate" ]; then host_lib="$candidate"; fi
done
[ -n "$host_lib" ] || { echo "no host build of zp-ffi found" >&2; exit 1; }
cargo run -q -p zp-ffi --features cli --bin uniffi-bindgen -- generate \
    --library "$host_lib" --language kotlin --no-format \
    --out-dir "$here/app/src/main/java"

echo "core built: $(wc -c < "$here/app/src/main/jniLibs/arm64-v8a/libzp_ffi.so") bytes"
