#!/usr/bin/env bash
# Archive the Developer ID macOS app (SbrMac, with its system extension),
# export it signed and package it as a disk image. With --notarise, notarise
# and staple both the app and the image, so Gatekeeper opens them without
# going online.
#
#   apple/macos-release.sh [--notarise] [build-number]
#
# Needs apple/SbrCore.xcframework (build-xcframework.sh), a Developer ID
# Application identity in a keychain, and the "sbr mac Developer ID" and
# "sbr mac tunnel Developer ID" profiles installed (tools/fetch-profiles.py).
# --notarise also needs APPLE_API_KEY_PATH, APPLE_API_KEY_ID and
# APPLE_API_ISSUER_ID. Writes apple/build/macos/sbr-<version>.dmg.
set -euo pipefail
cd "$(dirname "$0")/App"

notarise=0
build=""
for arg in "$@"; do
  case "$arg" in
    --notarise) notarise=1 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) build=$arg ;;
  esac
done
[ -d ../SbrCore.xcframework ] || { echo "apple/SbrCore.xcframework is missing: run apple/build-xcframework.sh" >&2; exit 1; }
if [ "$notarise" = 1 ]; then
  : "${APPLE_API_KEY_PATH:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER_ID:?}"
fi

# macOS replaces an active system extension only when the new one's version
# differs, so a build that kept the last one's number would leave the old
# tunnel running. UTC YYYYMMDDHHMM, as TestFlight builds are numbered.
build=${build:-$(date -u +%Y%m%d%H%M)}
version=$(sed -n 's/^ *MARKETING_VERSION: "\(.*\)"/\1/p' project.yml | head -1)
team=$(sed -n 's/^ *DEVELOPMENT_TEAM: *//p' project.yml | head -1)
bundle=$(sed -n 's/^ *SBR_BUNDLE_ID: *//p' project.yml | head -1)
identity=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/ { print $2; exit }')
[ -n "$identity" ] || { echo "no Developer ID Application identity in the keychain" >&2; exit 1; }
out=../build/macos
rm -rf "$out" && mkdir -p "$out"

mise exec -- xcodegen generate --quiet

if ! xcodebuild archive \
  -project Sbr.xcodeproj -scheme SbrMac -configuration Release \
  -destination 'generic/platform=macOS' \
  -archivePath "$out/sbr.xcarchive" \
  CURRENT_PROJECT_VERSION="$build" > "$out/archive.log" 2>&1; then
  grep -E 'error:|warning: .*(sign|provision)' "$out/archive.log" || tail -n 60 "$out/archive.log"
  exit 1
fi

cat > "$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>developer-id</string>
    <key>signingStyle</key><string>manual</string>
    <key>signingCertificate</key><string>Developer ID Application</string>
    <key>teamID</key><string>$team</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>$bundle.mac</key><string>sbr mac Developer ID</string>
        <key>$bundle.mac.tunnel</key><string>sbr mac tunnel Developer ID</string>
    </dict>
</dict>
</plist>
PLIST

if ! xcodebuild -exportArchive \
  -archivePath "$out/sbr.xcarchive" \
  -exportPath "$out/export" \
  -exportOptionsPlist "$out/ExportOptions.plist" > "$out/export.log" 2>&1; then
  grep -E 'error:' "$out/export.log" || tail -n 60 "$out/export.log"
  exit 1
fi

# The target builds SbrMac.app; it ships as sbr.app. A signature does not
# cover the bundle's own name.
exported=$(find "$out/export" -maxdepth 1 -name '*.app' | head -1)
app="$out/sbr.app"
ditto "$exported" "$app"
sysext="$app/Contents/Library/SystemExtensions/$bundle.mac.tunnel.systemextension"

codesign --verify --deep --strict --verbose=2 "$app"
codesign -d --entitlements - --xml "$sysext" 2>/dev/null | grep -q packet-tunnel-provider-systemextension \
  || { echo "the system extension is not signed with packet-tunnel-provider-systemextension" >&2; exit 1; }
app_build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$app/Contents/Info.plist")
ext_build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$sysext/Contents/Info.plist")
[ "$app_build" = "$build" ] && [ "$ext_build" = "$build" ] \
  || { echo "build numbers differ: wanted $build, app $app_build, system extension $ext_build" >&2; exit 1; }

# Each submission is named for its contents' hash: notarise.sh takes up a
# submission of the same name rather than submitting again, so a rebuilt file
# must not share a name with the last one.
if [ "$notarise" = 1 ]; then
  zip="$out/payload.zip"
  ditto -c -k --keepParent "$app" "$zip"
  named="$out/sbr-$version-$(shasum -a 256 "$zip" | cut -c1-12).zip"
  mv "$zip" "$named"
  ../tools/notarise.sh "$named"
  rm "$named"
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  spctl --assess --type exec -vv "$app"
fi

stage="$out/dmg"
mkdir -p "$stage"
ditto "$app" "$stage/sbr.app"
ln -s /Applications "$stage/Applications"
dmg="$out/sbr-$version.dmg"
hdiutil create -quiet -volname sbr -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
codesign --force --timestamp --sign "$identity" "$dmg"

if [ "$notarise" = 1 ]; then
  named="$out/sbr-$version-$(shasum -a 256 "$dmg" | cut -c1-12).dmg"
  cp "$dmg" "$named"
  ../tools/notarise.sh "$named"
  rm "$named"
  xcrun stapler staple "$dmg"
  xcrun stapler validate "$dmg"
  spctl --assess --type open --context context:primary-signature -vv "$dmg"
fi

echo "built $dmg (version $version, build $build)"
