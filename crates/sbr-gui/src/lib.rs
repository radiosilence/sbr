//! The sbr app on macOS and iOS. `SBR_GUI_DEMO=1` runs it on made-up
//! figures, without a tunnel.

pub mod profile;
/// The app's side of the tunnel messages; the tunnel extension shares them.
pub use sbr_message as proto;
pub mod rules;
pub mod swift;

#[cfg(target_vendor = "apple")]
pub mod connections;
#[cfg(target_vendor = "apple")]
pub mod connections_view;
#[cfg(target_vendor = "apple")]
pub mod demo;
#[cfg(target_vendor = "apple")]
pub mod diagnose;
#[cfg(target_vendor = "apple")]
pub mod graph;
#[cfg(target_vendor = "apple")]
pub mod install;
#[cfg(target_vendor = "apple")]
pub mod keychain;
#[cfg(target_vendor = "apple")]
pub mod logs;
#[cfg(target_vendor = "apple")]
pub mod logs_view;
#[cfg(target_os = "macos")]
pub mod menubar;
#[cfg(target_vendor = "apple")]
pub mod ne;
#[cfg(target_vendor = "apple")]
pub mod profiles;
#[cfg(target_vendor = "apple")]
pub mod profiles_view;
#[cfg(target_vendor = "apple")]
pub mod settings_view;
#[cfg(target_vendor = "apple")]
pub mod shell;
#[cfg(target_os = "macos")]
pub mod status_item;
#[cfg(target_vendor = "apple")]
pub mod tunnel;
#[cfg(target_vendor = "apple")]
pub mod ui;
#[cfg(target_vendor = "apple")]
pub mod view;

/// What the app holds whether or not its window is open: the tunnel, the
/// profiles and the VPN configuration that joins them. On macOS the menu bar
/// works on them with the window closed.
#[cfg(target_vendor = "apple")]
#[derive(Clone)]
pub struct Models {
    pub tunnel: koan_kit::app::Entity<tunnel::Tunnel>,
    pub profiles: koan_kit::app::Entity<profiles::Profiles>,
    pub vpn: koan_kit::app::Entity<install::Vpn>,
}

#[cfg(target_vendor = "apple")]
impl Models {
    pub fn new(cx: &mut koan_kit::app::App) -> Self {
        use koan_kit::app::AppContext as _;
        let tunnel = cx.new(tunnel::Tunnel::new);
        let profiles = cx.new(profiles::Profiles::new);
        let vpn = cx.new(|cx| install::Vpn::new(tunnel.clone(), profiles.clone(), cx));
        vpn.update(cx, |v, cx| v.refresh_profiles(cx));
        Models { tunnel, profiles, vpn }
    }
}

/// The app's models, and its window while one is open.
#[cfg(target_vendor = "apple")]
pub struct AppModels(pub Models, Option<koan_kit::app::AnyWindowHandle>);

#[cfg(target_vendor = "apple")]
impl koan_kit::app::Global for AppModels {}

/// Brings the window to the front, opening it if it is closed. While it is
/// open the tunnel is polled four times a second for its graphs, and on
/// macOS the app shows in the Dock and the app switcher.
#[cfg(target_vendor = "apple")]
pub fn open_window(models: &Models, cx: &mut koan_kit::app::App) {
    use koan_kit::app::*;
    use koan_kit::components::{MainWindow, ToolbarMetrics};

    if let Some(handle) = cx.try_global::<AppModels>().and_then(|m| m.1) {
        let shown = handle.update(cx, |_, window, _| window.activate_window());
        if shown.is_ok() {
            #[cfg(target_os = "macos")]
            dock::show(true);
            cx.activate(true);
            return;
        }
    }
    #[cfg(target_os = "macos")]
    dock::show(true);
    models.tunnel.update(cx, |t, cx| t.watch(true, cx));
    let opening = models.clone();
    let opened = MainWindow::new("sbr", "cc.blit.sbr")
        .size(880.0, 720.0)
        .buttons_at(ToolbarMetrics::WINDOW_BUTTONS_ORIGIN)
        .open(cx, move |window, cx| {
            let closing = opening.clone();
            window.on_window_should_close(cx, move |_, cx| {
                closing.tunnel.update(cx, |t, cx| t.watch(false, cx));
                cx.update_global::<AppModels, _>(|m, _| m.1 = None);
                #[cfg(target_os = "macos")]
                dock::show(false);
                true
            });
            cx.new(|cx| shell::Shell::new(opening, shell::Tab::Tunnel, window, cx))
        });
    match opened {
        Ok(handle) => {
            cx.update_global::<AppModels, _>(|m, _| m.1 = Some(handle));
            cx.activate(true);
        }
        Err(e) => eprintln!("sbr's window did not open: {e}"),
    }
}

/// Whether sbr shows in the Dock and the app switcher: while its window is
/// open. With it closed, sbr is in the menu bar alone.
#[cfg(target_os = "macos")]
mod dock {
    use objc2::MainThreadMarker;
    use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};

    pub fn show(shown: bool) {
        let Some(mtm) = MainThreadMarker::new() else { return };
        let policy = if shown {
            NSApplicationActivationPolicy::Regular
        } else {
            NSApplicationActivationPolicy::Accessory
        };
        NSApplication::sharedApplication(mtm).setActivationPolicy(policy);
    }
}

#[cfg(target_vendor = "apple")]
pub fn run() {
    use koan_kit::app::*;
    use koan_kit::theme;

    let application = koan_kit::raw::application().with_assets(theme::icons::Assets);
    // Opening sbr again while it runs brings its window back.
    application.on_reopen(|cx| {
        if let Some(models) = cx.try_global::<AppModels>().map(|m| m.0.clone()) {
            open_window(&models, cx);
        }
    });
    application.run(|cx: &mut App| {
        theme::init(cx);
        let models = Models::new(cx);
        cx.set_global(AppModels(models.clone(), None));
        #[cfg(target_os = "macos")]
        {
            // In the menu bar with the window closed, until it quits.
            cx.set_quit_mode(QuitMode::Explicit);
            dock::show(false);
            menubar::install(&models, cx);
            // Opened at launch only when there is nothing to connect yet,
            // or for the demo; otherwise from the menu bar, or by opening
            // sbr again.
            let first_run = models.profiles.read(cx).profiles.is_empty();
            if first_run || std::env::var_os("SBR_GUI_DEMO").is_some() {
                open_window(&models, cx);
            }
        }
        #[cfg(not(target_os = "macos"))]
        open_window(&models, cx);
    });
}
