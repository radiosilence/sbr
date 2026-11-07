//! Draws the tunnel page offscreen on the demo figures, dark and light side
//! by side, into a PNG. No window is shown; GPUI's headless renderer draws it.
//!
//! cargo run -p sbr-gui --features runtime-shaders --example shot -- target/shot.png [tunnel|profiles|connections|logs|settings] [--phone]
//!
//! `--phone` draws the window's shell at an iPhone's 390 x 844 points, with
//! touch on and the phone's layout (`SBR_GUI_PHONE`). `--click x,y` clicks
//! there, and `--scroll x,y,dy` scrolls there, in order, before the capture.

#[cfg(target_vendor = "apple")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use gpui::{AppContext, HeadlessAppContext, px, size};
    use koan_kit::theme;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let phone = args.iter().any(|a| a == "--phone");
    let mut inputs = Vec::new();
    let mut rest = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--phone" => {}
            "--click" | "--scroll" => {
                let at: Vec<f32> = it
                    .next()
                    .unwrap_or_default()
                    .split(',')
                    .filter_map(|n| n.parse().ok())
                    .collect();
                inputs.push((a == "--click", at));
            }
            _ => rest.push(a),
        }
    }
    let mut args = rest.into_iter();
    let out = args.next().unwrap_or_else(|| "target/shot.png".into());
    let named = args.next().and_then(|name| sbr_gui::shell::Tab::named(&name));
    // The tunnel page alone, or another page in the window's shell; on a
    // phone, every page in the shell.
    let tab = match (named, phone) {
        (None, true) => Some(sbr_gui::shell::Tab::Tunnel),
        (Some(sbr_gui::shell::Tab::Tunnel), false) => None,
        (named, _) => named,
    };
    let (width, height) = if phone { (390.0, 844.0) } else { (880.0, 900.0) };
    // SAFETY: set before any thread that reads the environment starts.
    unsafe {
        std::env::set_var("SBR_GUI_DEMO", "1");
        if phone {
            std::env::set_var("SBR_GUI_PHONE", "1");
        }
    }
    let text_system = gpui_platform::current_platform(true).text_system();
    let mut cx = HeadlessAppContext::with_platform(
        text_system,
        Arc::new(theme::icons::Assets),
        gpui_platform::current_headless_renderer,
    );
    cx.update(|cx| {
        theme::init(cx);
        if phone {
            theme::KoanTheme::set_touch(true, cx);
        }
    });
    let models = cx.update(sbr_gui::Models::new);

    let mut shots = Vec::new();
    for dark in [true, false] {
        let models = models.clone();
        let window = cx.open_window(size(px(width), px(height)), |window, cx| {
            if let Some(tab) = tab {
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
        for (click, at) in &inputs {
            let [x, y, rest @ ..] = at.as_slice() else { continue };
            let position = gpui::point(px(*x), px(*y));
            let events = if *click {
                vec![
                    gpui::PlatformInput::MouseDown(gpui::MouseDownEvent {
                        position,
                        button: gpui::MouseButton::Left,
                        modifiers: Default::default(),
                        click_count: 1,
                        first_mouse: false,
                    }),
                    gpui::PlatformInput::MouseUp(gpui::MouseUpEvent {
                        position,
                        button: gpui::MouseButton::Left,
                        modifiers: Default::default(),
                        click_count: 1,
                    }),
                ]
            } else {
                vec![
                    gpui::PlatformInput::MouseMove(gpui::MouseMoveEvent {
                        position,
                        pressed_button: None,
                        modifiers: Default::default(),
                    }),
                    gpui::PlatformInput::Scroll(gpui::ScrollEvent {
                        position,
                        delta: gpui::ScrollDelta::Pixels(gpui::point(
                            px(0.0),
                            px(-rest.first().copied().unwrap_or(400.0)),
                        )),
                        ..Default::default()
                    }),
                ]
            };
            for event in events {
                cx.update_window(window.into(), |_, window, cx| {
                    window.dispatch_event(event, cx);
                })?;
                cx.run_until_parked();
            }
            cx.advance_clock(std::time::Duration::from_secs(1));
            cx.update_window(window.into(), |_, window, _| window.refresh())?;
            cx.run_until_parked();
        }
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
