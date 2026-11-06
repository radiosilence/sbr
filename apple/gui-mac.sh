#!/usr/bin/env bash
# Builds the macOS app for development with sbr-gui as its executable.
#
# Xcode builds the Sbr app as before, which gives the bundle its tunnel
# extension, entitlements and provisioning profile; the executable is then
# replaced with sbr-gui and the app signed again with the same identity and
# entitlements. The extension keeps its own signature. This stands in until
# the bundle is assembled without Xcode.
#
#   apple/gui-mac.sh           build, and print the app's path
#   apple/gui-mac.sh --open    build and open it
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
derived="$root/target/xcode"

SBR_SKIP_TVOS=1 SBR_SKIP_CATALYST=1 "$here/build-xcframework.sh"
(cd "$here/App" && mise exec -- xcodegen generate --quiet)
xcodebuild -project "$here/App/Sbr.xcodeproj" -scheme Sbr \
    -destination 'platform=macOS' -configuration Debug \
    -derivedDataPath "$derived" -allowProvisioningUpdates -quiet build
app="$derived/Build/Products/Debug/Sbr.app"

(cd "$root" && cargo build -p sbr-gui --profile gui-dev --features runtime-shaders)

exe=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$app/Contents/Info.plist")
identity=$(codesign -dvv "$app" 2>&1 | sed -n 's/^Authority=//p' | head -1)
entitlements=$(mktemp "${TMPDIR:-/tmp}/sbr-gui-entitlements.XXXXXX")
trap 'rm -f "$entitlements"' EXIT
codesign -d --entitlements - --xml "$app" > "$entitlements"
cp "$root/target/gui-dev/sbr-gui" "$app/Contents/MacOS/$exe"
codesign --force --sign "$identity" --entitlements "$entitlements" "$app"
codesign --verify --strict "$app"

echo "$app"
if [ "${1:-}" = --open ]; then
    open "$app"
fi
