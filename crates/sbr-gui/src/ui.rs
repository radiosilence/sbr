//! Pieces the app's pages share: a line of text in a role and tone, a
//! dismissable problem, a page's toolbar, and how long ago something was.

use koan_kit::app::*;
use koan_kit::components::{Toolbar, ToolbarTitle, moves_window};
use koan_kit::theme::{KoanStyled, Look, Space, Tone, TypeRole};

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

/// A page's toolbar under the window buttons, its title moving the window.
pub fn toolbar(title: &str, window: &mut Window, cx: &mut App) -> Toolbar {
    let title = moves_window(
        div()
            .id("title")
            .size_full()
            .flex()
            .items_center()
            .child(ToolbarTitle::new(title)),
        window,
        cx,
    );
    Toolbar::new().under_window_buttons(true).principal(title)
}

/// A page under its toolbar, scrolling.
pub fn page(toolbar: Toolbar, id: &'static str, content: impl IntoElement, look: &Look) -> Div {
    div()
        .size_full()
        .flex()
        .flex_col()
        .bg(look.palette.bg.hsla())
        .child(toolbar)
        .child(koan_kit::components::ScrollArea::new(id, content))
}

/// A page's column of sections.
pub fn column(look: &Look) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(look.space(Space::Xl))
        .p(look.space(Space::Xl))
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
