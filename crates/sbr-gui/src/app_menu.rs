//! The application's menus in the system menu bar, shown while the window is
//! open and sbr is in the Dock: About sbr, hiding, and Quit with ⌘Q.

use koan_kit::app::platform::{Menu, MenuItem};
use koan_kit::app::*;
use objc2::MainThreadMarker;
use objc2_app_kit::NSApplication;

actions!(sbr, [About, Hide, HideOthers, ShowAll, Quit, Minimize]);

pub fn install(cx: &mut App) {
    cx.on_action(|_: &About, _| {
        // AppKit's panel takes the name, version, build and icon from the bundle.
        if let Some(mtm) = MainThreadMarker::new() {
            let app = NSApplication::sharedApplication(mtm);
            unsafe { app.orderFrontStandardAboutPanel(None) };
            #[allow(deprecated)]
            app.activateIgnoringOtherApps(true);
        }
    });
    cx.on_action(|_: &Hide, cx| cx.hide());
    cx.on_action(|_: &HideOthers, cx| cx.hide_other_apps());
    cx.on_action(|_: &ShowAll, cx| cx.unhide_other_apps());
    cx.on_action(|_: &Quit, cx| cx.quit());
    cx.on_action(|_: &Minimize, cx| {
        if let Some(window) = cx.active_window() {
            let _ = window.update(cx, |_, window, _| window.minimize_window());
        }
    });
    cx.bind_keys([
        KeyBinding::new("cmd-h", Hide, None),
        KeyBinding::new("cmd-alt-h", HideOthers, None),
        KeyBinding::new("cmd-q", Quit, None),
        KeyBinding::new("cmd-m", Minimize, None),
    ]);
    cx.set_menus(vec![
        Menu::new("sbr").items([
            MenuItem::action("About sbr", About),
            MenuItem::separator(),
            MenuItem::action("Hide sbr", Hide),
            MenuItem::action("Hide Others", HideOthers),
            MenuItem::action("Show All", ShowAll),
            MenuItem::separator(),
            MenuItem::action("Quit sbr", Quit),
        ]),
        Menu::new("Window").items([MenuItem::action("Minimize", Minimize)]),
    ]);
}
