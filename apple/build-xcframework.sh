#!/usr/bin/env bash
# Build apple/SbrCore.xcframework (static library + sbr.h module) for:
#   iOS, iOS Simulator (arm64), macOS (arm64 + x86_64),
#   Mac Catalyst (arm64 + x86_64), tvOS and tvOS Simulator (arm64).
#
# Run on macOS with Xcode and rustup. SBR_SKIP_TVOS=1 skips tvOS and
# SBR_SKIP_CATALYST=1 skips Catalyst. The simulators are arm64 only: Intel
# simulators would need an Intel Mac, and x86_64 tvOS has no prebuilt std.
#
# Every target builds in one cargo invocation, so their final LTO passes,
# each single-threaded, run side by side rather than one after another.
#
# Release profile: fat LTO, one codegen unit (workspace Cargo.toml), no debug
# info. The archives are deliberately not run through strip(1): it corrupts
# aws-lc's assembly objects (even -S), and the app then fails to link with
# "address not in any section". Xcode strips the final binary.
set -euo pipefail
cd "$(dirname "$0")/.."

export IPHONEOS_DEPLOYMENT_TARGET=15.0 MACOSX_DEPLOYMENT_TARGET=12.0 TVOS_DEPLOYMENT_TARGET=17.0
export CARGO_PROFILE_RELEASE_DEBUG=0

IOS=(aarch64-apple-ios)
IOS_SIM=(aarch64-apple-ios-sim)
MACOS=(aarch64-apple-darwin x86_64-apple-darwin)
CATALYST=(aarch64-apple-ios-macabi x86_64-apple-ios-macabi)
TVOS=(aarch64-apple-tvos)
TVOS_SIM=(aarch64-apple-tvos-sim)

TARGETS=("${IOS[@]}" "${IOS_SIM[@]}" "${MACOS[@]}")
[ "${SBR_SKIP_CATALYST:-0}" = 1 ] || TARGETS+=("${CATALYST[@]}")
[ "${SBR_SKIP_TVOS:-0}" = 1 ] || TARGETS+=("${TVOS[@]}" "${TVOS_SIM[@]}")

rustup target add "${TARGETS[@]}"
cargo build --release -p sbr-apple "${TARGETS[@]/#/--target=}"

lib=libsbr_apple.a
OUT=apple/build
rm -rf "$OUT" apple/SbrCore.xcframework
mkdir -p "$OUT/headers"
cp crates/sbr-apple/include/sbr.h "$OUT/headers/"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module SbrCore {
    header "sbr.h"
    export *
}
MAP

# One (fat) archive per xcframework slice.
slice() {
  local name=$1; shift
  mkdir -p "$OUT/$name"
  local inputs=()
  for t in "$@"; do inputs+=("target/$t/release/$lib"); done
  if [ $# -gt 1 ]; then
    lipo -create "${inputs[@]}" -output "$OUT/$name/$lib"
  else
    cp "${inputs[0]}" "$OUT/$name/$lib"
  fi
  XCF_ARGS+=(-library "$OUT/$name/$lib" -headers "$OUT/headers")
}

XCF_ARGS=()
slice ios "${IOS[@]}"
slice ios-simulator "${IOS_SIM[@]}"
slice macos "${MACOS[@]}"
[ "${SBR_SKIP_CATALYST:-0}" = 1 ] || slice maccatalyst "${CATALYST[@]}"
if [ "${SBR_SKIP_TVOS:-0}" != 1 ]; then
  slice tvos "${TVOS[@]}"
  slice tvos-simulator "${TVOS_SIM[@]}"
fi

xcodebuild -create-xcframework "${XCF_ARGS[@]}" -output apple/SbrCore.xcframework

echo
echo "slice sizes (static archives; the linked app adds far less after dead-stripping):"
for d in "$OUT"/*/; do
  [ -f "$d$lib" ] && printf '  %-16s %s\n' "$(basename "$d")" "$(du -h "$d$lib" | cut -f1)"
done
printf '  %-16s %s\n' xcframework "$(du -sh apple/SbrCore.xcframework | cut -f1)"
echo "built apple/SbrCore.xcframework"
