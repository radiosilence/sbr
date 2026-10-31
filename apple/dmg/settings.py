# dmgbuild settings for sbr-<version>.dmg. `apple/macos-release.sh package`
# passes the paths in with -D.
#
# dmgbuild writes the window layout into .DS_Store itself rather than scripting
# Finder, so it works on a runner with no logged-in session. The window size and
# icon centres must match those `make-icon.swift --dmg-background` draws around.

import os.path

app = defines["app"]  # noqa: F821 - supplied by dmgbuild

format = "UDZO"
filesystem = "HFS+"
files = [app]
symlinks = {"Applications": "/Applications"}
icon = defines["volume_icon"]  # noqa: F821

background = defines["background"]  # noqa: F821
window_rect = ((200, 120), (660, 400))
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False

default_view = "icon-view"
icon_size = 128
text_size = 13
arrange_by = None
icon_locations = {
    os.path.basename(app): (170, 190),
    "Applications": (490, 190),
}
