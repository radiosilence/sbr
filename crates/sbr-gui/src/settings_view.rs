//! The settings page: when the tunnel connects on its own and where it
//! stays off, leak protection, the engine's TCP stack and log level, the
//! end-to-end checks, and erasing everything sbr keeps on the device.

use koan_kit::app::*;
use koan_kit::components::sheet::{self, Confirm};
use koan_kit::components::{Button, ButtonKind, FieldState, InputEvent, SectionHeading, TextField, Toggle};
use koan_kit::theme::{Look, Space, Tone, TypeRole, label};

use crate::diagnose::Diagnose;
use crate::install::Vpn;
use crate::logs::Logs;
use crate::profiles::Profiles;
use crate::ui::{column, page, problem, text, toolbar};

pub struct SettingsPage {
    vpn: Entity<Vpn>,
    profiles: Entity<Profiles>,
    logs: Entity<Logs>,
    diagnose: Entity<Diagnose>,
    network: Entity<FieldState>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsPage {
    pub fn new(
        vpn: Entity<Vpn>,
        profiles: Entity<Profiles>,
        logs: Entity<Logs>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let network = cx.new(|cx| FieldState::new(window, cx).placeholder("wi-fi name"));
        let diagnose = cx.new(|_| Diagnose::default());
        let _subscriptions = vec![
            cx.observe(&vpn, |_, _, cx| cx.notify()),
            cx.observe(&diagnose, |_, _, cx| cx.notify()),
            cx.subscribe_in(&network, window, |page, _, e: &InputEvent, window, cx| {
                if matches!(e, InputEvent::PressEnter { .. }) {
                    page.add_network(window, cx);
                }
            }),
        ];
        Self {
            vpn,
            profiles,
            logs,
            diagnose,
            network,
            _subscriptions,
        }
    }

    fn add_network(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ssid = self.network.read(cx).value().trim().to_owned();
        if ssid.is_empty() {
            return;
        }
        self.vpn.update(cx, |v, cx| {
            v.update_settings(None, cx, |s| {
                if !s.trusted_networks.contains(&ssid) {
                    s.trusted_networks.push(ssid);
                }
            })
        });
        self.network.update(cx, |f, cx| f.set_value("", window, cx));
    }
}

fn note(s: &str, look: &Look) -> Div {
    text(label(s), TypeRole::Meta, Tone::Muted, look)
}

fn section(title: &str, look: &Look) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(look.space(Space::S))
        .child(SectionHeading::new(title))
}

impl Render for SettingsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let toolbar = toolbar("settings", window, cx);
        let mut content = column(&look);
        if let Some(e) = self.vpn.read(cx).error.clone() {
            let vpn = self.vpn.clone();
            content = content.child(problem("settings-problem", e, &look, move |cx| {
                vpn.update(cx, |v, cx| v.dismiss_error(cx))
            }));
        }
        let content = content
            .child(self.auto_connect(&look, cx))
            .child(self.protection(&look, cx))
            .child(self.engine(&look, cx))
            .child(self.diagnose(&look, cx))
            .child(self.erase(&look));
        page(toolbar, "settings", content, &look)
    }
}

impl SettingsPage {
    fn auto_connect(&self, look: &Look, cx: &App) -> Div {
        let s = &self.vpn.read(cx).settings;
        let vpn = self.vpn.clone();
        let mut out = section("auto-connect", look)
            .child(
                Toggle::new("auto-connect", "auto-connect", s.auto_connect).on_change(move |on, _, cx| {
                    let on = *on;
                    vpn.update(cx, |v, cx| v.update_settings(Some(on), cx, |s| s.auto_connect = on))
                }),
            )
            .child(note(
                "connects on cellular and on wi-fi not listed below; disconnects on listed networks. disconnecting by hand keeps it off until you connect again.",
                look,
            ));
        if !s.auto_connect {
            return out;
        }
        out = out.child(SectionHeading::new("trusted networks"));
        for ssid in &s.trusted_networks {
            let vpn = self.vpn.clone();
            let gone = ssid.clone();
            out = out.child(
                div()
                    .flex()
                    .items_center()
                    .py(look.space(Space::S))
                    .border_b(look.hairline)
                    .border_color(look.palette.rule.hsla())
                    .child(
                        div()
                            .flex_1()
                            .child(text(ssid.clone(), TypeRole::Body, Tone::Ink, look)),
                    )
                    .child(
                        Button::new(SharedString::from(format!("forget-{ssid}")), ButtonKind::Text)
                            .label("remove")
                            .on_click(move |_, _, cx| {
                                let gone = gone.clone();
                                vpn.update(cx, |v, cx| {
                                    v.update_settings(None, cx, |s| s.trusted_networks.retain(|n| *n != gone))
                                })
                            }),
                    ),
            );
        }
        out.child(TextField::new(&self.network).label("trusted wi-fi name"))
            .child(note("names are matched exactly, including case.", look))
    }

    fn protection(&self, look: &Look, cx: &App) -> Div {
        let v = self.vpn.read(cx);
        let strict = v.strict();
        let vpn = self.vpn.clone();
        let mut out = section("protection", look)
            .child(
                Toggle::new("strict", "block traffic outside the tunnel", strict).on_change(move |on, _, cx| {
                    let on = *on;
                    vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.strict = Some(on)))
                }),
            )
            .child(note(
                "sends everything through the tunnel, connections opened before it included, and blocks traffic while it is down. follows the profile's strict_route until set. breaks airdrop and other local traffic.",
                look,
            ));
        if strict {
            let vpn = self.vpn.clone();
            out = out
                .child(
                    Toggle::new("local", "allow the local network", v.settings.allow_local_network).on_change(
                        move |on, _, cx| {
                            let on = *on;
                            vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.allow_local_network = on))
                        },
                    ),
                )
                .child(note(
                    "for airplay, printers and media servers. exempts whatever the current network calls local.",
                    look,
                ));
        }
        out.child(note("applied the next time the tunnel connects.", look))
    }

    fn engine(&self, look: &Look, cx: &App) -> Div {
        let s = &self.vpn.read(cx).settings;
        let (tcp, verbose) = (self.vpn.clone(), self.vpn.clone());
        section("engine", look)
            .child(
                Toggle::new("userspace-tcp", "userspace tcp", s.userspace_tcp).on_change(move |on, _, cx| {
                    let on = *on;
                    tcp.update(cx, |v, cx| v.set_userspace_tcp(on, cx))
                }),
            )
            .child(note(
                "sbr's own tcp stack. off uses the kernel's, which ios stops under heavy load. reconnects.",
                look,
            ))
            .child(
                Toggle::new("verbose-settings", "verbose logs", s.verbose).on_change(move |on, _, cx| {
                    let on = *on;
                    verbose.update(cx, |v, cx| v.set_verbose(on, cx))
                }),
            )
    }

    fn diagnose(&self, look: &Look, cx: &App) -> Div {
        let d = self.diagnose.read(cx);
        let diagnose = self.diagnose.clone();
        let logs = self.logs.clone();
        let profiles = self.profiles.clone();
        let run = Button::new("diagnose-run", ButtonKind::Bordered)
            .label(if d.running { "running" } else { "run" })
            .disabled(d.running)
            .on_click(move |_, _, cx| {
                let connected = logs.read(cx).connected(cx);
                let config = profiles.read(cx).active_text.clone();
                diagnose.update(cx, |d, cx| d.run(connected, config, cx))
            });
        let mut out = div()
            .flex()
            .flex_col()
            .gap(look.space(Space::S))
            .child(SectionHeading::new("diagnose").trailing(run))
            .child(note(
                "checks run from the app, so their traffic takes the same path as any other app's.",
                look,
            ));
        if !d.checks.is_empty() && !d.checks.iter().any(|c| c.name == "webrtc") {
            out = out.child(note("connect to also test for address and ipv6 leaks.", look));
        }
        for c in &d.checks {
            let (mark, tone) = match (c.done, c.ok) {
                (false, _) => ("·", Tone::Muted),
                (true, Some(true)) => ("ok", Tone::Accent),
                (true, Some(false)) => ("fail", Tone::Bad),
                (true, None) => ("note", Tone::Muted),
            };
            out = out.child(
                div()
                    .flex()
                    .items_baseline()
                    .gap(look.space(Space::M))
                    .py(look.space(Space::Xs))
                    .child(div().w(look.sized(40.0)).child(text(mark, TypeRole::Meta, tone, look)))
                    .child(
                        div()
                            .w(look.sized(110.0))
                            .child(text(c.name, TypeRole::Meta, Tone::Ink, look)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(text(c.detail.clone(), TypeRole::Meta, Tone::Muted, look)),
                    ),
            );
        }
        out
    }

    fn erase(&self, look: &Look) -> Div {
        let (vpn, logs) = (self.vpn.clone(), self.logs.clone());
        section("erase", look)
            .child(note(
                "removes every profile and its credentials, the vpn configuration, settings and logs from this device. the app stays installed, and the system keeps its own record of vpn connections.",
                look,
            ))
            .child(
                div().flex().child(
                    Button::new("erase", ButtonKind::Bordered)
                        .label("erase everything")
                        .destructive(true)
                        .on_click(move |_, window, cx| {
                            let (vpn, logs) = (vpn.clone(), logs.clone());
                            sheet::confirm(
                                Confirm {
                                    title: "erase everything?".into(),
                                    verb: "erase".into(),
                                    destructive: true,
                                    lines: vec![
                                        "every profile and its credentials".into(),
                                        "the vpn configuration and the tunnel's files".into(),
                                        "settings, personal rules, trusted networks and logs".into(),
                                    ],
                                    note: Some(
                                        "profiles can't be recovered. you'll need their links or files to add them again."
                                            .into(),
                                    ),
                                },
                                window,
                                cx,
                                move |cx| {
                                    vpn.update(cx, |v, cx| v.erase(cx));
                                    logs.update(cx, |l, cx| l.clear(cx));
                                },
                            );
                        }),
                ),
            )
    }
}
