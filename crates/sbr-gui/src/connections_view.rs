//! The connections page: the tunnel's open connections, most recently
//! active first, each with its route, its rates against the busiest one,
//! and a close button. A row opens a sheet with everything known about the
//! connection, where it can be closed, every connection to its domain
//! closed, or the domain always routed through a chosen exit.

use std::time::{SystemTime, UNIX_EPOCH};

use koan_kit::app::*;
use koan_kit::components::sheet;
use koan_kit::components::{Badge, Button, ButtonKind, Chip, FieldState, InputEvent, SectionHeading, TextField};
use koan_kit::raw::px;
use koan_kit::theme::{Look, Space, Tone, TypeRole, label};

use crate::connections::{Connections, Live};
use crate::graph;
use crate::install::Vpn;
use crate::proto::Connection;
use crate::ui::{age, column, page, problem, text, toolbar};

pub struct ConnectionsPage {
    connections: Entity<Connections>,
    vpn: Entity<Vpn>,
    filter: Entity<FieldState>,
    _subscriptions: Vec<Subscription>,
}

impl ConnectionsPage {
    pub fn new(connections: Entity<Connections>, vpn: Entity<Vpn>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let filter = cx.new(|cx| FieldState::new(window, cx).placeholder("filter"));
        let _subscriptions = vec![
            cx.observe(&connections, |_, _, cx| cx.notify()),
            cx.subscribe(&filter, |_, _, e: &InputEvent, cx| {
                if *e == InputEvent::Change {
                    cx.notify();
                }
            }),
        ];
        Self {
            connections,
            vpn,
            filter,
            _subscriptions,
        }
    }
}

/// The route as it reads: the outbound the rule chose, through to the leaf.
fn route(c: &Connection) -> String {
    if c.chain.is_empty() {
        "—".into()
    } else {
        c.chain.iter().rev().cloned().collect::<Vec<_>>().join(" → ")
    }
}

fn started_secs_ago(c: &Connection) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    ((now - c.start).max(0) / 1000) as u64
}

/// Every word of `filter` appears in the host, destination, route, rule,
/// inbound, network or protocol.
fn matches(c: &Connection, filter: &str) -> bool {
    let mut hay = [
        c.host(),
        &c.destination,
        c.ip.as_deref().unwrap_or(""),
        &c.rule,
        &c.inbound,
        &c.network,
        c.sniffed.as_deref().unwrap_or(""),
    ]
    .join(" ");
    hay.push(' ');
    hay.push_str(&c.chain.join(" "));
    let hay = hay.to_lowercase();
    filter.to_lowercase().split_whitespace().all(|w| hay.contains(w))
}

impl Render for ConnectionsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let toolbar = toolbar("connections", window, cx);
        let c = self.connections.read(cx);
        let connected = c.connected(cx);
        let filter = self.filter.read(cx).value().to_string();
        let shown: Vec<&Live> = c.rows.iter().filter(|l| matches(&l.connection, &filter)).collect();

        let up: f64 = c.rows.iter().map(|l| l.up).sum();
        let down: f64 = c.rows.iter().map(|l| l.down).sum();
        let listed = c.rows.len() as u64;
        let count = if c.total > listed {
            format!("newest {listed} of {}", c.total)
        } else {
            format!("{listed} open")
        };
        let summary = if connected {
            format!("{count} · ↑ {} ↓ {}", graph::rate(up), graph::rate(down))
        } else {
            "off".into()
        };

        let mut content = column(&look);
        if let Some(e) = c.error.clone() {
            let connections = self.connections.clone();
            content = content.child(problem("connections-problem", e, &look, move |cx| {
                connections.update(cx, |c, cx| c.dismiss_error(cx))
            }));
        }
        content = content.child(
            div()
                .flex()
                .flex_col()
                .gap(look.space(Space::S))
                .child(text(summary, TypeRole::Meta, Tone::Muted, &look))
                .child(TextField::new(&self.filter).label("filter connections")),
        );

        let mut list = div().flex().flex_col();
        let empty = if !connected {
            Some("connect to see the tunnel's connections.")
        } else if shown.is_empty() {
            Some(if filter.trim().is_empty() { "nothing open." } else { "nothing matches." })
        } else {
            None
        };
        if let Some(empty) = empty {
            list = list.child(text(label(empty), TypeRole::Body, Tone::Muted, &look));
        }
        // Rates are drawn against the busiest connection listed.
        let peak = shown.iter().map(|l| l.up.max(l.down)).fold(1.0, f64::max);
        for live in shown {
            list = list.child(self.row(live, peak, &look));
        }
        content = content.child(list);
        page(toolbar, "connections", content, &look)
    }
}

/// A bar `share` of the way across, in `tone`.
fn bar(share: f64, tone: Tone, look: &Look) -> Div {
    div()
        .w_full()
        .h(px(3.0))
        .bg(look.palette.rule.hsla())
        .child(div().h_full().w(relative(share.clamp(0.0, 1.0) as f32)).bg(look.color(tone)))
}

impl ConnectionsPage {
    fn row(&self, live: &Live, peak: f64, look: &Look) -> Stateful<Div> {
        let c = &live.connection;
        let active = live.active();
        let mut chips = div().flex().flex_wrap().gap(look.space(Space::Xs));
        chips = chips.child(Badge::new(c.network.clone()));
        if let Some(p) = &c.sniffed {
            chips = chips.child(Badge::new(p.clone()).accent(true));
        }
        for hop in c.chain.iter().rev() {
            chips = chips.child(Badge::new(hop.clone()));
        }
        let rates = div()
            .w(look.sized(180.0))
            .flex()
            .flex_col()
            .gap(px(3.0))
            .child(bar(live.down / peak, Tone::Accent, look))
            .child(bar(live.up / peak, Tone::Ink, look))
            .child(text(
                format!("↓ {}  ↑ {}", graph::rate(live.down), graph::rate(live.up)),
                TypeRole::Meta,
                if active { Tone::Accent } else { Tone::Muted },
                look,
            ));
        let totals = format!(
            "↓ {} ↑ {} · {}",
            graph::bytes(c.download as f64),
            graph::bytes(c.upload as f64),
            age(started_secs_ago(c))
        );
        let id = c.id.clone();
        let close_id = c.id.clone();
        let (connections, vpn) = (self.connections.clone(), self.vpn.clone());
        let closer = self.connections.clone();
        div()
            .id(SharedString::from(format!("conn-{id}")))
            .flex()
            .items_center()
            .gap(look.space(Space::M))
            .py(look.space(Space::M))
            .border_b(look.hairline)
            .border_color(look.palette.rule.hsla())
            .cursor_pointer()
            .on_click(move |_, window, cx| {
                let detail = cx.new(|cx| Detail::new(id.clone(), connections.clone(), vpn.clone(), cx));
                sheet::present(detail, window, cx);
            })
            .child(div().w(px(2.0)).h(px(40.0)).when(active, |b| b.bg(look.color(Tone::Accent))))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(look.space(Space::Xs))
                    .child(text(c.host().to_owned(), TypeRole::Body, Tone::Strong, look).truncate())
                    .child(chips)
                    .child(text(totals, TypeRole::Meta, Tone::Muted, look)),
            )
            .child(rates)
            .child(
                Button::new(SharedString::from(format!("close-{close_id}")), ButtonKind::Compact)
                    .label("close")
                    .on_click(move |_, _, cx| {
                        let id = close_id.clone();
                        closer.update(cx, |c, cx| c.close(id, cx));
                        cx.stop_propagation();
                    }),
            )
    }
}

/// Everything known about one connection, kept live by the list's polling
/// and still readable once it closes.
struct Detail {
    id: String,
    last: Option<Live>,
    connections: Entity<Connections>,
    vpn: Entity<Vpn>,
    _observe: Subscription,
}

impl Detail {
    fn new(id: String, connections: Entity<Connections>, vpn: Entity<Vpn>, cx: &mut Context<Self>) -> Self {
        let _observe = cx.observe(&connections, |d: &mut Detail, c, cx| {
            if let Some(live) = c.read(cx).rows.iter().find(|l| l.connection.id == d.id) {
                d.last = Some(live.clone());
            }
            cx.notify();
        });
        let last = connections.read(cx).rows.iter().find(|l| l.connection.id == id).cloned();
        Detail {
            id,
            last,
            connections,
            vpn,
            _observe,
        }
    }
}

fn field(name: &str, value: String, look: &Look) -> Div {
    div()
        .flex()
        .items_baseline()
        .gap(look.space(Space::M))
        .py(look.space(Space::S))
        .border_b(look.hairline)
        .border_color(look.palette.rule.hsla())
        .child(div().w(look.sized(96.0)).child(text(label(name), TypeRole::Meta, Tone::Muted, look)))
        .child(div().flex_1().min_w_0().child(text(value, TypeRole::Meta, Tone::Ink, look)))
}

fn figure(name: &str, rate: String, total: String, look: &Look) -> Div {
    div()
        .flex()
        .flex_col()
        .child(text(label(name), TypeRole::Meta, Tone::Muted, look))
        .child(text(rate, TypeRole::Title, Tone::Strong, look))
        .child(text(total, TypeRole::Meta, Tone::Muted, look))
}

impl Render for Detail {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let open = self
            .connections
            .read(cx)
            .rows
            .iter()
            .any(|l| l.connection.id == self.id);
        let done = Button::new("detail-done", ButtonKind::Text)
            .label("done")
            .on_click(|_, _, cx| sheet::close(cx));
        let Some(live) = self.last.clone() else {
            return sheet::panel("connection", &look)
                .child(sheet::head("connection", vec![done.into_any_element()], &look))
                .child(sheet::note(label("closed."), Tone::Muted, &look));
        };
        let c = &live.connection;
        let mut body = sheet::body("detail-body", &look)
            .child(text(
                label(if open { "open" } else { "closed" }),
                TypeRole::Meta,
                if open { Tone::Accent } else { Tone::Muted },
                &look,
            ))
            .child(text(route(c), TypeRole::Body, Tone::Ink, &look))
            .child(SectionHeading::new("traffic"))
            .child(
                div()
                    .flex()
                    .gap(look.space(Space::Xl))
                    .child(figure("up", graph::rate(live.up), graph::bytes(c.upload as f64), &look))
                    .child(figure("down", graph::rate(live.down), graph::bytes(c.download as f64), &look)),
            )
            .child(SectionHeading::new("connection"))
            .child(field("destination", c.destination.clone(), &look));
        if let Some(ip) = &c.ip {
            body = body.child(field("address", ip.clone(), &look));
        }
        if let Some(d) = &c.domain {
            body = body.child(field("domain", d.clone(), &look));
        }
        body = body.child(field("network", c.network.clone(), &look));
        if let Some(p) = &c.sniffed {
            body = body.child(field("protocol", p.clone(), &look));
        }
        body = body
            .child(field("inbound", c.inbound.clone(), &look))
            .child(field("source", c.source.clone(), &look))
            .child(field("rule", c.rule.clone(), &look))
            .child(field("started", format!("{} ago", age(started_secs_ago(c))), &look))
            .child(field("id", c.id.clone(), &look));

        if let Some(domain) = c.domain.clone() {
            let choices = self.vpn.read(cx).route_choices();
            let ruled = self
                .vpn
                .read(cx)
                .settings
                .rules
                .iter()
                .find(|r| r.domains == [domain.clone()])
                .map(|r| r.outbound.clone());
            if !choices.is_empty() {
                let mut row = div().flex().flex_wrap().gap(look.space(Space::S));
                for tag in choices {
                    let vpn = self.vpn.clone();
                    let (d, t) = (domain.clone(), tag.clone());
                    let picked = ruled.as_deref() == Some(tag.as_str());
                    row = row.child(
                        Chip::new(SharedString::from(format!("via-{tag}")), if picked { format!("● {tag}") } else { tag.clone() })
                            .on_click(move |_, _, cx| {
                                let (d, t) = (d.clone(), t.clone());
                                vpn.update(cx, |v, cx| v.add_rule(&d, t, cx))
                            }),
                    );
                }
                body = body
                    .child(SectionHeading::new(format!("always route {domain} via")))
                    .child(row);
            }
        }

        let mut actions = div().flex().gap(look.space(Space::M)).pt(look.space(Space::L));
        if open {
            let connections = self.connections.clone();
            let id = self.id.clone();
            actions = actions.child(
                Button::new("detail-close", ButtonKind::Bordered)
                    .label("close connection")
                    .on_click(move |_, _, cx| {
                        let id = id.clone();
                        connections.update(cx, |c, cx| c.close(id, cx));
                        sheet::close(cx);
                    }),
            );
        }
        if let Some(domain) = c.domain.clone() {
            let connections = self.connections.clone();
            actions = actions.child(
                Button::new("detail-close-domain", ButtonKind::Bordered)
                    .label(format!("close all to {domain}"))
                    .on_click(move |_, _, cx| {
                        connections.update(cx, |c, cx| c.close_domain(&domain, cx));
                        sheet::close(cx);
                    }),
            );
        }
        body = body.child(actions);

        sheet::panel("connection", &look)
            .child(sheet::head_data(c.host().to_owned(), vec![done.into_any_element()], &look))
            .child(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_and_route() {
        let c = Connection {
            id: "1".into(),
            network: "tcp".into(),
            inbound: "tun-in".into(),
            source: "172.19.0.1:5000".into(),
            destination: "www.example.com:443".into(),
            domain: Some("www.example.com".into()),
            ip: None,
            sniffed: Some("tls".into()),
            chain: vec!["hk-01".into(), "auto".into()],
            rule: "final".into(),
            upload: 0,
            download: 0,
            start: 0,
        };
        assert!(matches(&c, ""));
        assert!(matches(&c, "EXAMPLE hk-01"));
        assert!(matches(&c, "tls tcp"));
        assert!(!matches(&c, "example udp"));
        assert_eq!(route(&c), "auto → hk-01");
    }
}
