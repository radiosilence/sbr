//! Draws the tunnel page offscreen on the demo figures, dark and light side
//! by side, into a PNG. No window is shown; GPUI's headless renderer draws it.
//!
//! cargo run -p sbr-gui --features runtime-shaders --example shot -- target/shot.png [tunnel|profiles]

#[cfg(target_vendor = "apple")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use gpui::{AppContext, HeadlessAppContext, px, size};
    use koan_kit::theme;

    let out = std::env::args().nth(1).unwrap_or_else(|| "target/shot.png".into());
    let profiles = std::env::args().nth(2).as_deref() == Some("profiles");
    // SAFETY: set before any thread that reads the environment starts.
    unsafe { std::env::set_var("SBR_GUI_DEMO", "1") };
    let text_system = gpui_platform::current_platform(true).text_system();
    let mut cx = HeadlessAppContext::with_platform(
        text_system,
        Arc::new(theme::icons::Assets),
        gpui_platform::current_headless_renderer,
    );
    cx.update(theme::init);
    let models = cx.update(sbr_gui::Models::new);

    let mut shots = Vec::new();
    for dark in [true, false] {
        let models = models.clone();
        let window = cx.open_window(size(px(880.0), px(900.0)), |window, cx| {
            if profiles {
                let tab = sbr_gui::shell::Tab::Profiles;
                let page = cx.new(|cx| sbr_gui::shell::Shell::new(models, tab, window, cx));
                return koan_kit::components::host(page, window, cx);
            }
            let page = cx.new(|cx| sbr_gui::view::TunnelPage::new(models.tunnel, cx));
            koan_kit::components::host(page, window, cx)
        })?;
        cx.update_window(window.into(), |_, window, cx| {
            theme::pin_appearance(Some(dark), window, cx)
        })?;
        cx.update_window(window.into(), |_, window, _| window.refresh())?;
        cx.run_until_parked();
        shots.push(cx.capture_screenshot(window.into())?);
    }
    let (w, h) = (shots[0].width(), shots[0].height());
    let mut page = image::RgbaImage::new(w * 2, h);
    for (i, shot) in shots.iter().enumerate() {
        image::imageops::replace(&mut page, shot, (i as u32 * w) as i64, 0);
    }
    page.save(&out)?;
    println!("{out}");
    Ok(())
}

#[cfg(not(target_vendor = "apple"))]
fn main() {}
