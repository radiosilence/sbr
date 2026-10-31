# Changelog

## 0.2.0

### Added

- **macOS menu bar app.** sbr runs from the menu bar on macOS: connect, switch profiles and launch at login without opening a window. macOS 15 or later is required.
- **Signed macOS releases.** Each release publishes a notarised disk image of the Developer ID build, with its system extension, on GitHub.

### Fixed

- **Connecting the Developer ID macOS build no longer hangs while its system extension awaits approval.** It reports that approval is needed and links to the settings pane.
- **A failed VPN configuration save no longer leaves the previous profile in place.** The next connect saves it again, and a running tunnel takes the new profile and rules either way.

### Internal

- **`just release` and `just changelog`.** The release and changelog commands run through just, as in kōan.
