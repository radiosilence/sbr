//! The tunnel page: whether it is up and where traffic goes, throughput
//! over the last two minutes, the extension's memory, CPU and connections,
//! and each selector group with its members' latency.

use koan_kit::app::*;
use koan_kit::components::{Button, ButtonKind, ScrollArea, SectionHeading, Sparkline, Toolbar, ToolbarTitle};
use koan_kit::raw::{Hsla, px, size};
use koan_kit::theme::{KoanStyled, Look, Space, Tone, TypeRole, label};

use crate::graph;
use crate::proto::{Group, Member};
use crate::tunnel::{Sample, Tunnel};

pub struct TunnelPage {
    tunnel: Entity<Tunnel>,
    _observe: Subscription,
}

impl TunnelPage {
    pub fn new(tunnel: Entity<Tunnel>, cx: &mut Context<Self>) -> Self {
        let _observe = cx.observe(&tunnel, |_, _, cx| cx.notify());
        Self { tunnel, _observe }
    }
}

fn text(s: impl Into<SharedString>, role: TypeRole, tone: Tone, look: &Look) -> Div {
    div()
        .text_role(role, look)
        .text_color(look.text_color(tone))
        .child(s.into())
}

impl Render for TunnelPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let t = self.tunnel.read(cx);
        let on = t.status.is_on();
        let samples: Vec<Sample> = t.history.iter().copied().collect();
        let latest = samples.last().copied().unwrap_or_default();

        let tunnel = self.tunnel.clone();
        let connect = Button::new("connect", ButtonKind::Prominent)
            .label(if on { "disconnect" } else { "connect" })
            .on_click(move |_, _, cx| tunnel.update(cx, |t, cx| t.set_on(!on, cx)));

        let toolbar = Toolbar::new().leading(ToolbarTitle::new("sbr")).trailing(connect);

        let route = t
            .groups
            .first()
            .map(|g| match g.delay {
                Some(ms) => format!("via {} · {ms} ms", g.now),
                None => format!("via {}", g.now),
            })
            .unwrap_or_default();
        let status = div()
            .flex()
            .items_center()
            .gap(look.space(Space::S))
            .child(div().size(px(10.0)).rounded_full().bg(if on {
                look.color(Tone::Accent)
            } else {
                look.color(Tone::Muted)
            }))
            .child(text(label(t.status.label()), TypeRole::Title, Tone::Strong, &look))
            .child(text(route, TypeRole::Body, Tone::Muted, &look));

        let figures = div()
            .flex()
            .gap(look.space(Space::Xxl))
            .child(figure("down", graph::rate(latest.down), Tone::Accent, &look))
            .child(figure("up", graph::rate(latest.up), Tone::Ink, &look));

        let gauges = div()
            .flex()
            .gap(look.space(Space::M))
            .child(gauge(
                "memory",
                graph::bytes(latest.memory as f64),
                samples.iter().map(|s| s.memory as f64).collect(),
                &look,
            ))
            .child(gauge(
                "cpu",
                format!("{:.0} %", latest.cpu * 100.0),
                samples.iter().map(|s| s.cpu).collect(),
                &look,
            ))
            .child(gauge(
                "connections",
                latest.connections.to_string(),
                samples.iter().map(|s| s.connections as f64).collect(),
                &look,
            ));

        let mut content = div()
            .flex()
            .flex_col()
            .gap(look.space(Space::Xl))
            .p(look.space(Space::Xl))
            .child(status);
        if let Some(error) = t.error.clone() {
            let tunnel = self.tunnel.clone();
            content = content.child(
                div()
                    .id("error")
                    .p(look.space(Space::M))
                    .border_1()
                    .border_color(look.color(Tone::Bad))
                    .cursor_pointer()
                    .on_click(move |_, _, cx| tunnel.update(cx, |t, cx| t.dismiss_error(cx)))
                    .child(text(error, TypeRole::Body, Tone::Bad, &look)),
            );
        }
        content = content
            .child(figures)
            .child(graph::throughput(samples.clone(), look, 180.0))
            .child(gauges);

        // One-member selectors are aliases.
        for g in t.groups.iter().filter(|g| g.members.len() > 1) {
            let testing = t.testing.contains(&g.tag);
            content = content.child(self.group(g, testing, &look));
        }

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(look.palette.bg.hsla())
            .child(toolbar)
            .child(ScrollArea::new("tunnel", content))
    }
}

fn figure(name: &str, value: String, tone: Tone, look: &Look) -> Div {
    div()
        .flex()
        .flex_col()
        .child(text(label(name), TypeRole::Meta, Tone::Muted, look))
        .child(text(value, TypeRole::Display, tone, look))
}

/// A figure with its last two minutes as a line beneath.
fn gauge(name: &str, value: String, values: Vec<f64>, look: &Look) -> Div {
    let peak = values.iter().copied().fold(0.0, f64::max).max(f64::EPSILON);
    let centred: Vec<f64> = values.iter().map(|v| v / peak * 2.0 - 1.0).collect();
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap(look.space(Space::S))
        .p(look.space(Space::M))
        .border(look.hairline)
        .border_color(look.palette.rule.hsla())
        .child(text(label(name), TypeRole::Meta, Tone::Muted, look))
        .child(text(value, TypeRole::TitleSmall, Tone::Strong, look))
        .child(Sparkline::new(centred, 1.0, look.color(Tone::Accent)).size(size(px(160.0), px(28.0))))
}

impl TunnelPage {
    fn group(&self, g: &Group, testing: bool, look: &Look) -> Div {
        let tunnel = self.tunnel.clone();
        let tag = g.tag.clone();
        let test = Button::new(SharedString::from(format!("test-{}", g.tag)), ButtonKind::Compact)
            .label(if testing { "testing" } else { "test" })
            .disabled(testing)
            .on_click(move |_, _, cx| {
                let tag = tag.clone();
                tunnel.update(cx, |t, cx| t.url_test(tag, cx))
            });
        let fastest = g.members.iter().filter_map(|m| m.delay).min();
        let slowest = g.members.iter().filter_map(|m| m.delay).max().unwrap_or(1).max(1);
        let mut rows = div().flex().flex_col();
        for m in g.members.iter().cloned() {
            rows = rows.child(self.member(g, m, fastest, slowest, look));
        }
        div()
            .flex()
            .flex_col()
            .child(SectionHeading::new(&g.tag).trailing(test))
            .child(rows)
    }

    fn member(&self, g: &Group, m: Member, fastest: Option<u32>, slowest: u32, look: &Look) -> Stateful<Div> {
        let picked = g.selected == m.tag;
        let degraded = m.degraded == Some(true);
        let bar_color: Hsla = if degraded {
            look.color(Tone::Bad)
        } else if m.delay.is_some() && m.delay == fastest {
            look.color(Tone::Accent)
        } else {
            look.color(Tone::Muted)
        };
        let share = m.delay.map(|d| d as f32 / slowest as f32).unwrap_or(0.0);
        let delay = match (m.delay, degraded, m.retry_in) {
            (_, true, Some(s)) => format!("down · retry {s}s"),
            (_, true, None) => "down".into(),
            (Some(ms), _, _) => format!("{ms} ms"),
            (None, _, _) => "—".into(),
        };
        let selectable = g.selectable();
        let tunnel = self.tunnel.clone();
        let (group, member) = (g.tag.clone(), m.tag.clone());
        div()
            .id(SharedString::from(format!("{}/{}", g.tag, m.tag)))
            .flex()
            .items_center()
            .gap(look.space(Space::M))
            .py(look.space(Space::S))
            .border_b(look.hairline)
            .border_color(look.palette.rule.hsla())
            .when(selectable, |row| {
                row.cursor_pointer().on_click(move |_, _, cx| {
                    let (group, member) = (group.clone(), member.clone());
                    tunnel.update(cx, |t, cx| t.select(group, member, cx))
                })
            })
            .child(
                div()
                    .w(px(10.0))
                    .child(text(if picked { "●" } else { "" }, TypeRole::Body, Tone::Accent, look)),
            )
            .child(div().w(look.sized(140.0)).child(text(
                m.tag.clone(),
                TypeRole::Body,
                if picked { Tone::Strong } else { Tone::Ink },
                look,
            )))
            .child(
                div()
                    .w(look.sized(110.0))
                    .child(text(m.kind.clone(), TypeRole::Meta, Tone::Muted, look)),
            )
            .child(
                div()
                    .flex_1()
                    .h(px(4.0))
                    .bg(look.palette.rule.hsla())
                    .child(div().h_full().w(relative(share.clamp(0.0, 1.0))).bg(bar_color)),
            )
            .child(div().w(look.sized(120.0)).flex().justify_end().child(text(
                delay,
                TypeRole::Meta,
                if degraded { Tone::Bad } else { Tone::Ink },
                look,
            )))
    }
}
