# Open the release pull request (patch|minor|major|X.Y.Z); merging it releases
release version *args:
    scripts/release.sh {{version}} {{args}}

# Write CHANGELOG.md from changelog.d/ (--check, --lint, --stdout)
changelog *args:
    python3 scripts/changelog.py {{args}}
