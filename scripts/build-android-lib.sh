#!/usr/bin/env bash
# Builds libphonetpm_mobile.so for Android ABIs and regenerates the Kotlin
# UniFFI bindings. Run inside `nix develop`.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE=${PROFILE:-release}
ABIS=${ABIS:-"arm64-v8a x86_64"}
JNI_DIR=android/app/src/main/jniLibs
KT_DIR=android/app/src/main/java

# host dev build of the cdylib is used by bindgen to extract metadata
# (release strips symbols, which removes the metadata section)
cargo build -p phonetpm-mobile --lib

# shellcheck disable=SC2086
cargo ndk -o "$JNI_DIR" $(for a in $ABIS; do printf -- '-t %s ' "$a"; done) \
    build -p phonetpm-mobile --lib --${PROFILE}
# iroh ships extra crate-types; only our cdylib is needed at runtime
find "$JNI_DIR" -name 'libiroh*.so' -delete

cargo run -p phonetpm-mobile --bin uniffi-bindgen -- generate \
    --library target/debug/libphonetpm_mobile.so \
    --language kotlin \
    --out-dir "$KT_DIR"

echo "native libs: $JNI_DIR"
echo "bindings:    $KT_DIR/uniffi/phonetpm_mobile/phonetpm_mobile.kt"
