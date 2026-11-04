#!/usr/bin/env bash
# Build, package and notarise the Developer ID macOS app (SbrMac, with its
# system extension), in three steps:
#
#   apple/macos-release.sh build [build-number]  archive, export, verify:
#                                                apple/build/macos/sbr.app.zip
#   apple/macos-release.sh package               make and sign the disk image
#                                                from that zip:
#                                                apple/build/macos/sbr-<version>.dmg
#   apple/macos-release.sh notarise-dmg          notarise the image, staple the
#                                                app, then remake, notarise and
#                                                staple the image
#
# CI runs build and package before the release is published and notarise-dmg
# after it, so Apple's queue holds up nothing. Notarising the image covers the
# app inside it, but its ticket stays with the image. The app needs its own
# stapled: sysextd will not activate the system extension without one, and it
# does not look a ticket up online for an app Gatekeeper already passed, such
# as one put back from the Bin. So the image is notarised, the app taken out
# and stapled, and the image made again around it and notarised in turn.
# Re-running a failed notarisation submits nothing new for the first image:
# notarise.sh takes up the submission of the same name, and a name is the
# file's content hash. The remade image hashes differently each time.
#
# build needs apple/SbrCore.xcframework (build-xcframework.sh) and the
# "sbr mac Developer ID" and "sbr mac tunnel Developer ID" profiles installed
# (tools/fetch-profiles.py); build and package need a Developer ID Application
# identity in a keychain; notarise-dmg needs that too, and APPLE_API_KEY_PATH,
# APPLE_API_KEY_ID and APPLE_API_ISSUER_ID.
set -euo pipefail
cd "$(dirname "$0")/App"

step=${1:-}
shift || true
version=$(sed -n 's/^ *MARKETING_VERSION: "\(.*\)"/\1/p' project.yml | head -1)
team=$(sed -n 's/^ *DEVELOPMENT_TEAM: *//p' project.yml | head -1)
bundle=$(sed -n 's/^ *SBR_BUNDLE_ID: *//p' project.yml | head -1)
out=../build/macos
zip="$out/sbr.app.zip"
dmg="$out/sbr-$version.dmg"

identity() {
  local id
  id=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/ { print $2; exit }')
  [ -n "$id" ] || { echo "no Developer ID Application identity in the keychain" >&2; exit 1; }
  printf '%s' "$id"
}

# Notarise a file under a name holding its content hash.
notarise() {
  : "${APPLE_API_KEY_PATH:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER_ID:?}"
  local file=$1 ext=${1##*.} named
  named="$out/sbr-$version-$(shasum -a 256 "$file" | cut -c1-12).$ext"
  cp "$file" "$named"
  ../tools/notarise.sh "$named"
  rm "$named"
}

# The signed disk image, from $out/sbr.app.
make_dmg() {
  rm -rf "$out/dmg"
  # The window's background at 1x and 2x, paired into one TIFF, and the
  # volume icon from the app icon's macOS sizes, named as an .iconset's are.
  mkdir -p "$out/dmg/AppIcon.iconset"
  swift ../tools/make-icon.swift --dmg-background App/Resources/geist-mono.woff2 "$out/dmg"
  tiffutil -cathidpicheck "$out/dmg/background.png" "$out/dmg/background@2x.png" -out "$out/dmg/background.tiff" >/dev/null
  cp App/Assets.xcassets/AppIcon.appiconset/icon_*.png "$out/dmg/AppIcon.iconset/"
  iconutil -c icns "$out/dmg/AppIcon.iconset" -o "$out/dmg/AppIcon.icns"
  rm -f "$dmg"
  uvx --from dmgbuild==1.6.7 dmgbuild -s ../dmg/settings.py \
    -D app="$out/sbr.app" -D background="$out/dmg/background.tiff" -D volume_icon="$out/dmg/AppIcon.icns" \
    sbr "$dmg"
  codesign --force --timestamp --sign "$(identity)" "$dmg"
}

case "$step" in
build)
  [ -d ../SbrCore.xcframework ] || { echo "apple/SbrCore.xcframework is missing: run apple/build-xcframework.sh" >&2; exit 1; }
  # macOS replaces an active system extension only when the new one's version
  # differs, so a build that kept the last one's number would leave the old
  # tunnel running. UTC YYYYMMDDHHMM, as TestFlight builds are numbered.
  build=${1:-$(date -u +%Y%m%d%H%M)}
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
  [ "$(/usr/libexec/PlistBuddy -c 'Print CFBundlePackageType' "$sysext/Contents/Info.plist" 2>/dev/null)" = SYSX ] \
    || { echo "the system extension's CFBundlePackageType is not SYSX, so macOS will not activate it" >&2; exit 1; }
  app_build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$app/Contents/Info.plist")
  ext_build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$sysext/Contents/Info.plist")
  [ "$app_build" = "$build" ] && [ "$ext_build" = "$build" ] \
    || { echo "build numbers differ: wanted $build, app $app_build, system extension $ext_build" >&2; exit 1; }

  ditto -c -k --keepParent "$app" "$zip"
  echo "built $zip (version $version, build $build)"
  ;;

package)
  [ -f "$zip" ] || { echo "$zip is missing: run the build step" >&2; exit 1; }
  rm -rf "$out/sbr.app"
  ditto -x -k "$zip" "$out"
  make_dmg
  echo "packaged $dmg"
  ;;

notarise-dmg)
  [ -f "$dmg" ] || { echo "$dmg is missing: run the package step" >&2; exit 1; }
  notarise "$dmg"
  # The app's ticket exists once the image holding it is accepted. Stapling
  # adds a file the app's signature leaves out, so the signature still holds;
  # the system extension inside cannot take one of its own without breaking
  # the app's seal, and is covered by the app's.
  mount=$(mktemp -d)
  hdiutil attach -nobrowse -readonly -mountpoint "$mount" "$dmg" >/dev/null
  rm -rf "$out/sbr.app"
  ditto "$mount/sbr.app" "$out/sbr.app"
  hdiutil detach "$mount" >/dev/null
  xcrun stapler staple "$out/sbr.app"
  xcrun stapler validate "$out/sbr.app"
  codesign --verify --deep --strict "$out/sbr.app"
  make_dmg
  notarise "$dmg"
  xcrun stapler staple "$dmg"
  xcrun stapler validate "$dmg"
  spctl --assess --type open --context context:primary-signature -vv "$dmg"
  echo "notarised $dmg"
  ;;

*)
  echo "usage: apple/macos-release.sh build [build-number] | package | notarise-dmg" >&2
  exit 2
  ;;
esac
