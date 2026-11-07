#!/usr/bin/env bash
# Build two xcframeworks of static libraries:
#
#   apple/SbrCore.xcframework    sbr-apple (C ABI + sbr.h module) for SbrKit:
#                                iOS, iOS Simulator (arm64), macOS (arm64 +
#                                x86_64), Mac Catalyst (arm64 + x86_64), tvOS
#                                and tvOS Simulator (arm64).
#   apple/SbrTunnel.xcframework  sbr-tunnel-ext, the packet tunnel provider
#                                the tunnel extensions link: the same slices
#                                without Mac Catalyst.
#   apple/SbrGui.xcframework     sbr-gui, the iOS and macOS app, which the app
#                                targets' `main` calls: iOS, iOS Simulator
#                                (arm64) and macOS (arm64 + x86_64).
#
# Run on macOS with Xcode and rustup. SBR_SKIP_TVOS=1 skips tvOS and
# SBR_SKIP_CATALYST=1 skips Catalyst. The simulators are arm64 only: Intel
# simulators would need an Intel Mac, and x86_64 tvOS has no prebuilt std.
#
# Every target and both libraries build in one cargo invocation, so their
# final LTO passes, each single-threaded, run side by side rather than one
# after another.
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
# sbr-tunnel-ext has nothing to offer Catalyst, but building it there too
# keeps this one invocation.
cargo build --release -p sbr-apple -p sbr-tunnel-ext "${TARGETS[@]/#/--target=}"
# The app has no tvOS or Catalyst build, and targets the iOS GPUI runs on.
GUI_TARGETS=("${IOS[@]}" "${IOS_SIM[@]}" "${MACOS[@]}")
IPHONEOS_DEPLOYMENT_TARGET=26.0 MACOSX_DEPLOYMENT_TARGET=26.0 \
  cargo build --release -p sbr-gui --lib "${GUI_TARGETS[@]/#/--target=}"

OUT=apple/build
rm -rf "$OUT" apple/SbrCore.xcframework apple/SbrTunnel.xcframework apple/SbrGui.xcframework
mkdir -p "$OUT/headers"
cp crates/sbr-apple/include/sbr.h "$OUT/headers/"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module SbrCore {
    header "sbr.h"
    export *
}
MAP

# One (fat) archive of $lib per xcframework slice, under $OUT/$dir.
slice() {
  local name=$1; shift
  mkdir -p "$OUT/$dir/$name"
  local inputs=()
  for t in "$@"; do inputs+=("target/$t/release/$lib"); done
  if [ $# -gt 1 ]; then
    lipo -create "${inputs[@]}" -output "$OUT/$dir/$name/$lib"
  else
    cp "${inputs[0]}" "$OUT/$dir/$name/$lib"
  fi
  XCF_ARGS+=(-library "$OUT/$dir/$name/$lib")
  [ -z "$headers" ] || XCF_ARGS+=(-headers "$headers")
}

lib=libsbr_apple.a dir=core headers=$OUT/headers
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

# The provider has no header: the extension refers to one symbol, declared
# where it is used (apple/App/Tunnel/Provider.c).
lib=libsbr_tunnel_ext.a dir=tunnel headers=
XCF_ARGS=()
slice ios "${IOS[@]}"
slice ios-simulator "${IOS_SIM[@]}"
slice macos "${MACOS[@]}"
if [ "${SBR_SKIP_TVOS:-0}" != 1 ]; then
  slice tvos "${TVOS[@]}"
  slice tvos-simulator "${TVOS_SIM[@]}"
fi
xcodebuild -create-xcframework "${XCF_ARGS[@]}" -output apple/SbrTunnel.xcframework

# The app's entry point is declared where it is called (apple/App/Gui/main.c).
lib=libsbr_gui.a dir=gui headers=
XCF_ARGS=()
slice ios "${IOS[@]}"
slice ios-simulator "${IOS_SIM[@]}"
slice macos "${MACOS[@]}"
xcodebuild -create-xcframework "${XCF_ARGS[@]}" -output apple/SbrGui.xcframework

echo
echo "slice sizes (static archives; the linked app adds far less after dead-stripping):"
for a in "$OUT"/*/*/*.a; do
  printf '  %-34s %s\n' "${a#"$OUT"/}" "$(du -h "$a" | cut -f1)"
done
for x in SbrCore SbrTunnel SbrGui; do
  printf '  %-34s %s\n' "$x.xcframework" "$(du -sh "apple/$x.xcframework" | cut -f1)"
done
echo "built apple/SbrCore.xcframework, apple/SbrTunnel.xcframework and apple/SbrGui.xcframework"
