# Open the release pull request (patch|minor|major|X.Y.Z); merging it releases
release version *args:
    scripts/release.sh {{version}} {{args}}

# Write CHANGELOG.md from changelog.d/ (--check, --lint, --stdout)
changelog *args:
    python3 scripts/changelog.py {{args}}

# The macOS app with sbr-gui as its executable, signed for development (--open to run it)
gui-mac *args:
    apple/gui-mac.sh {{args}}
