#!/usr/bin/env bash
# Build SbrCore.xcframework (static) for iOS, iOS Simulator and macOS.
# Run on macOS with Xcode and rustup installed.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin)
rustup target add "${TARGETS[@]}"
export IPHONEOS_DEPLOYMENT_TARGET=15.0 MACOSX_DEPLOYMENT_TARGET=12.0
for t in "${TARGETS[@]}"; do
  cargo build --release -p sbr-apple --target "$t"
done

OUT=apple/build
rm -rf "$OUT" apple/SbrCore.xcframework
mkdir -p "$OUT/ios-sim" "$OUT/macos" "$OUT/headers"
cp crates/sbr-apple/include/sbr.h "$OUT/headers/"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module SbrCore {
    header "sbr.h"
    export *
}
MAP
lib=libsbr_apple.a
lipo -create target/aarch64-apple-ios-sim/release/$lib target/x86_64-apple-ios/release/$lib -output "$OUT/ios-sim/$lib"
lipo -create target/aarch64-apple-darwin/release/$lib target/x86_64-apple-darwin/release/$lib -output "$OUT/macos/$lib"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$lib -headers "$OUT/headers" \
  -library "$OUT/ios-sim/$lib" -headers "$OUT/headers" \
  -library "$OUT/macos/$lib" -headers "$OUT/headers" \
  -output apple/SbrCore.xcframework
echo "built apple/SbrCore.xcframework"
