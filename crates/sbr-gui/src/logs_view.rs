//! The logs page: the tunnel's recent log lines, newest first, errors in
//! the bad tone and warnings in ink; the last session's lines while the
//! tunnel is down. They come from the extension's memory and stay on this
//! device unless copied.

use koan_kit::app::*;
use koan_kit::components::{Button, ButtonKind, Toggle};
use koan_kit::theme::{Look, Space, Tone, TypeRole, label};

use crate::install::Vpn;
use crate::logs::{Level, Logs, level};
use crate::ui::{column, page, text, toolbar};

pub struct LogsPage {
    logs: Entity<Logs>,
    vpn: Entity<Vpn>,
    _subscriptions: Vec<Subscription>,
}

impl LogsPage {
    pub fn new(logs: Entity<Logs>, vpn: Entity<Vpn>, cx: &mut Context<Self>) -> Self {
        let _subscriptions = vec![
            cx.observe(&logs, |_, _, cx| cx.notify()),
            cx.observe(&vpn, |_, _, cx| cx.notify()),
        ];
        Self {
            logs,
            vpn,
            _subscriptions,
        }
    }
}

impl Render for LogsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let toolbar = toolbar("logs", window, cx);
        let logs = self.logs.read(cx);
        let connected = logs.connected(cx);
        let all = logs.lines.join("\n");
        let copy = Button::new("copy-logs", ButtonKind::Bordered)
            .label("copy")
            .disabled(logs.lines.is_empty())
            .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(all.clone())));
        let toolbar = toolbar.trailing(copy);

        let vpn = self.vpn.clone();
        let verbose =
            Toggle::new("verbose", "verbose", self.vpn.read(cx).settings.verbose).on_change(move |on, _, cx| {
                let on = *on;
                vpn.update(cx, |v, cx| v.set_verbose(on, cx))
            });
        let mut content = column(&look, window).child(verbose);

        let note = match (connected, logs.lines.is_empty()) {
            (true, true) => Some("nothing yet."),
            (false, true) => Some("connect to see the tunnel's logs."),
            (false, false) => Some("from the last session."),
            (true, false) => None,
        };
        if let Some(note) = note {
            content = content.child(text(label(note), TypeRole::Meta, Tone::Muted, &look));
        }
        let mut lines = div().flex().flex_col().gap(look.space(Space::Xs));
        for line in logs.lines.iter().rev() {
            let tone = match level(line) {
                Level::Error => Tone::Bad,
                Level::Warn => Tone::Ink,
                Level::Other => Tone::Muted,
            };
            lines = lines.child(text(line.clone(), TypeRole::Meta, tone, &look));
        }
        content = content.child(lines);
        page(toolbar, "logs", content, &look)
    }
}
