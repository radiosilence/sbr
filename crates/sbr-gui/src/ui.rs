//! Pieces the app's pages share: a line of text in a role and tone, a
//! dismissable problem, a page's chrome and column, how pages fold on a
//! phone, and how long ago something was.

use koan_kit::app::*;
use koan_kit::components::{ButtonKind, PageHeader, Toolbar, ToolbarTitle, moves_window};
use koan_kit::raw::{Pixels, px};
use koan_kit::theme::{HIT, KoanStyled, Look, Space, Tone, TypeRole};

/// Whether the app takes a phone's layout: on iOS, and on a desktop with
/// `SBR_GUI_PHONE` set, so it can be looked at at a phone's size. As
/// koan-gui's `mobile::phone`.
pub fn phone() -> bool {
    static PHONE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PHONE.get_or_init(|| cfg!(target_os = "ios") || std::env::var_os("SBR_GUI_PHONE").is_some())
}

/// Below this width a page folds to one column: gauges stack, columns
/// that only label drop, and rows wrap.
const NARROW: Pixels = px(600.0);

pub fn narrow(window: &Window) -> bool {
    window.viewport_size().width < NARROW
}

/// The least height of a row a finger taps: `HIT` under touch.
pub fn row_height(look: &Look) -> Pixels {
    if look.touch { HIT } else { px(0.0) }
}

pub fn text(s: impl Into<SharedString>, role: TypeRole, tone: Tone, look: &Look) -> Div {
    div()
        .text_role(role, look)
        .text_color(look.text_color(tone))
        .child(s.into())
}

/// A message in the bad tone that a click puts away.
pub fn problem(id: &'static str, message: String, look: &Look, dismiss: impl Fn(&mut App) + 'static) -> Stateful<Div> {
    div()
        .id(id)
        .p(look.space(Space::M))
        .border_1()
        .border_color(look.color(Tone::Bad))
        .cursor_pointer()
        .on_click(move |_, _, cx| dismiss(cx))
        .child(text(message, TypeRole::Body, Tone::Bad, look))
}

/// A page's title and verbs, laid out as kōan lays out its own: on a phone
/// the title in the flush toolbar and the verbs at its trailing edge; on a
/// desktop a bare toolbar under the window buttons, which moves the window,
/// with the title and verbs opening the page as its `PageHeader`, on the
/// page's margin rather than past the window buttons.
pub struct Chrome {
    pub toolbar: Toolbar,
    pub header: Option<AnyElement>,
}

/// The kind of button a page's verb takes: a toolbar's text button on a
/// phone, a header's compact button on a desktop.
pub fn verb() -> ButtonKind {
    if phone() { ButtonKind::Text } else { ButtonKind::Compact }
}

pub fn chrome(title: &str, verbs: Vec<AnyElement>, window: &mut Window, cx: &mut App) -> Chrome {
    if phone() {
        let title = div().size_full().flex().items_center().child(ToolbarTitle::new(title));
        let toolbar = verbs
            .into_iter()
            .fold(Toolbar::new().flush().principal(title), Toolbar::trailing);
        return Chrome { toolbar, header: None };
    }
    let strip = moves_window(div().id("title").size_full(), window, cx);
    let header = verbs.into_iter().fold(PageHeader::new(title), PageHeader::action);
    Chrome {
        toolbar: Toolbar::new().flush().under_window_buttons(true).principal(strip),
        header: Some(header.into_any_element()),
    }
}

/// A page under its toolbar, scrolling.
pub fn page(toolbar: Toolbar, id: &'static str, content: Div, look: &Look) -> Div {
    div()
        .size_full()
        .flex()
        .flex_col()
        .bg(look.palette.bg.hsla())
        .child(toolbar)
        // The rest of the height under the toolbar, not the whole of it,
        // which would run its foot under what stands below the page.
        .child(koan_kit::components::ScrollArea::new(id, content).shrinks())
}

/// A page's column of sections, closer to the edges on a narrow screen.
pub fn column(look: &Look, window: &Window) -> Div {
    let edge = if narrow(window) { Space::L } else { Space::Xl };
    div().flex().flex_col().gap(look.space(Space::Xl)).p(look.space(edge))
}

/// Seconds as the fewest words: `42s`, `5m`, `3h 12m`, `2d 4h`.
pub fn age(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        s => format!("{}d {}h", s / 86_400, s % 86_400 / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        assert_eq!(age(42), "42s");
        assert_eq!(age(300), "5m");
        assert_eq!(age(3600 * 3 + 60 * 12), "3h 12m");
        assert_eq!(age(86_400 * 2 + 3600 * 4), "2d 4h");
    }
}
