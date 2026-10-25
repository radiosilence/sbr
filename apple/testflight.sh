#!/usr/bin/env bash
# Archive the iOS app, sign it for the App Store and upload it to TestFlight.
#
#   APPLE_API_KEY_PATH=AuthKey.p8 APPLE_API_KEY_ID=... APPLE_API_ISSUER_ID=... \
#     apple/testflight.sh [build-number]
#
# Needs apple/SbrCore.xcframework (build-xcframework.sh), the Apple
# Distribution identity in a keychain, and the "sbr App Store", "sbr tunnel
# App Store" and "sbr widgets App Store" profiles installed
# (tools/fetch-profiles.py). The build number defaults to the UTC time as YYYYMMDDHHMM: App Store Connect
# takes each build number of a version once, and only rising ones.
set -euo pipefail
cd "$(dirname "$0")/App"
: "${APPLE_API_KEY_PATH:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER_ID:?}"
[ -d ../SbrCore.xcframework ] || { echo "apple/SbrCore.xcframework is missing: run apple/build-xcframework.sh" >&2; exit 1; }

build=${1:-$(date -u +%Y%m%d%H%M)}
team=$(sed -n 's/^ *DEVELOPMENT_TEAM: *//p' project.yml | head -1)
bundle=$(sed -n 's/^ *SBR_BUNDLE_ID: *//p' project.yml | head -1)
out=../build/ios-archive
rm -rf "$out" && mkdir -p "$out"
auth=(
  -authenticationKeyPath "$APPLE_API_KEY_PATH"
  -authenticationKeyID "$APPLE_API_KEY_ID"
  -authenticationKeyIssuerID "$APPLE_API_ISSUER_ID"
)

mise exec -- xcodegen generate --quiet

# Release signs iOS manually with the distribution profiles (project.yml).
if ! xcodebuild archive \
  -project Sbr.xcodeproj -scheme Sbr -configuration Release \
  -destination 'generic/platform=iOS' \
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
    <key>method</key><string>app-store-connect</string>
    <key>destination</key><string>upload</string>
    <key>signingStyle</key><string>manual</string>
    <key>signingCertificate</key><string>Apple Distribution</string>
    <key>teamID</key><string>$team</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>$bundle</key><string>sbr App Store</string>
        <key>$bundle.tunnel</key><string>sbr tunnel App Store</string>
        <key>$bundle.widgets</key><string>sbr widgets App Store</string>
    </dict>
    <key>uploadSymbols</key><true/>
    <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST

# The system PATH: Homebrew's rsync, found first, makes the export's copy
# step fail ("Copy failed").
PATH=/usr/bin:/bin:/usr/sbin:/sbin xcodebuild -exportArchive \
  -archivePath "$out/sbr.xcarchive" \
  -exportOptionsPlist "$out/ExportOptions.plist" \
  -exportPath "$out/export" \
  -allowProvisioningUpdates "${auth[@]}"
echo "uploaded build $build to App Store Connect"
