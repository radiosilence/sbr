# Open the release pull request (patch|minor|major|X.Y.Z); merging it releases
release version *args:
    scripts/release.sh {{version}} {{args}}

# Write CHANGELOG.md from changelog.d/ (--check, --lint, --stdout)
changelog *args:
    python3 scripts/changelog.py {{args}}

# Frame App Store screenshots with their captions (apple/store/captions.toml,
# or captions-tv for the Apple TV): `just app-store-shots DIR target/shots`
app-store-shots src out captions="captions":
    uv run apple/store/frame.py apple/store/{{captions}}.toml {{src}} {{out}}

# Push the App Store listing (apple/store/listing.toml): text, review details,
# the newest processed build of the version, and screenshots given as
# `iphone=DIR ipad=DIR` (or `--platform tvos tv=DIR`). `--attachment FILE`
# gives App Review a recording; `--submit` submits, as store.yml does.
app-store *args:
    uv run apple/store/push.py {{args}}
