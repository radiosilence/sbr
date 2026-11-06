//! The sbr app on macOS and iOS. `SBR_GUI_DEMO=1` runs it on made-up
//! figures, without a tunnel.

pub mod profile;
#[allow(dead_code)]
pub mod proto;
pub mod rules;
pub mod swift;

#[cfg(target_vendor = "apple")]
pub mod demo;
#[cfg(target_vendor = "apple")]
pub mod graph;
#[cfg(target_vendor = "apple")]
pub mod install;
#[cfg(target_vendor = "apple")]
pub mod keychain;
#[cfg(target_vendor = "apple")]
pub mod ne;
#[cfg(target_vendor = "apple")]
pub mod profiles;
#[cfg(target_vendor = "apple")]
pub mod profiles_view;
#[cfg(target_vendor = "apple")]
pub mod shell;
#[cfg(target_vendor = "apple")]
pub mod tunnel;
#[cfg(target_vendor = "apple")]
pub mod view;

#[cfg(target_vendor = "apple")]
pub fn run() {
    use koan_kit::app::*;
    use koan_kit::components::{MainWindow, ToolbarMetrics};
    use koan_kit::theme;

    koan_kit::raw::application()
        .with_assets(theme::icons::Assets)
        .run(|cx: &mut App| {
            theme::init(cx);
            let tunnel = cx.new(tunnel::Tunnel::new);
            let opened = MainWindow::new("sbr", "cc.blit.sbr")
                .size(880.0, 720.0)
                .buttons_at(ToolbarMetrics::WINDOW_BUTTONS_ORIGIN)
                .open(cx, |window, cx| {
                    window.on_window_should_close(cx, |_, cx| {
                        cx.quit();
                        true
                    });
                    cx.new(|cx| shell::Shell::new(tunnel, shell::Tab::Tunnel, window, cx))
                });
            if let Err(e) = opened {
                eprintln!("sbr's window did not open: {e}");
                cx.quit();
            }
        });
}
