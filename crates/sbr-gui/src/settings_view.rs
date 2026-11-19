//! The settings page: when the tunnel connects on its own and where it
//! stays off, leak protection, the engine's TCP stack and log level, the
//! end-to-end checks, and erasing everything sbr keeps on the device.

use koan_kit::app::*;
use koan_kit::components::sheet::{self, Confirm};
use koan_kit::components::{
    Button, ButtonKind, FieldState, Form, FormSection, InputEvent, TextField, Toggle, form_buttons, form_item,
    form_text,
};
use koan_kit::theme::{Look, Tone, TypeRole, label};

use crate::diagnose::Diagnose;
use crate::install::Vpn;
use crate::logs::Logs;
use crate::profiles::Profiles;
use crate::ui::{Chrome, chrome, problem};

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

/// An explanation under a setting, as a form's footer reads.
fn note(s: &str, look: &Look) -> AnyElement {
    form_text(label(s), TypeRole::Fine, Tone::Muted, look).into_any_element()
}

impl Render for SettingsPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let Chrome { toolbar, header } = chrome("settings", Vec::new(), window, cx);
        let mut sections: Vec<AnyElement> = header.into_iter().collect();
        if let Some(e) = self.vpn.read(cx).error.clone() {
            let vpn = self.vpn.clone();
            sections.push(
                problem("settings-problem", e, &look, move |cx| {
                    vpn.update(cx, |v, cx| v.dismiss_error(cx))
                })
                .into_any_element(),
            );
        }
        sections.extend(self.auto_connect(&look, cx));
        sections.extend([
            self.protection(&look, cx),
            self.engine(&look, cx),
            self.diagnose(&look, cx),
            self.erase(&look),
        ]);
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(look.palette.bg.hsla())
            .child(toolbar)
            .child(Form::new("settings").sections(sections).build(&look).shrinks())
    }
}

impl SettingsPage {
    /// The toggle, and while it is on the networks it stays off on.
    fn auto_connect(&self, look: &Look, cx: &App) -> Vec<AnyElement> {
        let s = &self.vpn.read(cx).settings;
        let vpn = self.vpn.clone();
        // The toggle names the setting; a header over it would repeat it.
        let toggle = FormSection::new()
            .row(
                Toggle::new("auto-connect", "auto-connect", s.auto_connect).on_change(move |on, _, cx| {
                    let on = *on;
                    vpn.update(cx, |v, cx| v.update_settings(Some(on), cx, |s| s.auto_connect = on))
                }),
            )
            .footer(label(
                "connects on cellular and on wi-fi not listed below; disconnects on listed networks. disconnecting by hand keeps it off until you connect again.",
            ));
        if !s.auto_connect {
            return vec![toggle.into_any_element()];
        }
        let networks = s.trusted_networks.iter().map(|ssid| {
            let vpn = self.vpn.clone();
            let gone = ssid.clone();
            let remove = Button::new(SharedString::from(format!("forget-{ssid}")), ButtonKind::Text)
                .label("remove")
                .on_click(move |_, _, cx| {
                    let gone = gone.clone();
                    vpn.update(cx, |v, cx| {
                        v.update_settings(None, cx, |s| s.trusted_networks.retain(|n| *n != gone))
                    })
                });
            form_item(ssid.clone(), None, vec![remove.into_any_element()], look)
        });
        let trusted = FormSection::titled("trusted networks")
            .rows(networks)
            .row(TextField::new(&self.network).label("trusted wi-fi name"))
            .footer(label("names are matched exactly, including case."));
        vec![toggle.into_any_element(), trusted.into_any_element()]
    }

    fn protection(&self, look: &Look, cx: &App) -> AnyElement {
        let v = self.vpn.read(cx);
        let strict = v.strict();
        let vpn = self.vpn.clone();
        let mut section = FormSection::titled("protection")
            .row(
                Toggle::new("strict", "block traffic outside the tunnel", strict).on_change(move |on, _, cx| {
                    let on = *on;
                    vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.strict = Some(on)))
                }),
            )
            .row(note(
                "sends everything through the tunnel, connections opened before it included, and blocks traffic while it is down. follows the profile's strict_route until set. breaks airdrop and other local traffic.",
                look,
            ));
        if strict {
            let vpn = self.vpn.clone();
            section = section
                .row(
                    Toggle::new("local", "allow the local network", v.settings.allow_local_network).on_change(
                        move |on, _, cx| {
                            let on = *on;
                            vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.allow_local_network = on))
                        },
                    ),
                )
                .row(note(
                    "for airplay, printers and media servers. exempts whatever the current network calls local.",
                    look,
                ));
        }
        section
            .footer(label("applied the next time the tunnel connects."))
            .into_any_element()
    }

    fn engine(&self, look: &Look, cx: &App) -> AnyElement {
        let s = &self.vpn.read(cx).settings;
        let (tcp, verbose) = (self.vpn.clone(), self.vpn.clone());
        FormSection::titled("engine")
            .row(
                Toggle::new("userspace-tcp", "userspace tcp", s.userspace_tcp).on_change(move |on, _, cx| {
                    let on = *on;
                    tcp.update(cx, |v, cx| v.set_userspace_tcp(on, cx))
                }),
            )
            .row(note(
                "sbr's own tcp stack. off uses the kernel's, which ios stops under heavy load. reconnects.",
                look,
            ))
            .row(
                Toggle::new("verbose-settings", "verbose logs", s.verbose).on_change(move |on, _, cx| {
                    let on = *on;
                    verbose.update(cx, |v, cx| v.set_verbose(on, cx))
                }),
            )
            .into_any_element()
    }

    fn diagnose(&self, look: &Look, cx: &App) -> AnyElement {
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
        let mut section = FormSection::titled("diagnose")
            .row(note(
                "checks run from the app, so their traffic takes the same path as any other app's.",
                look,
            ))
            .row(form_buttons(vec![run.into_any_element()], look));
        if !d.checks.is_empty() && !d.checks.iter().any(|c| c.name == "webrtc") {
            section = section.row(note("connect to also test for address and ipv6 leaks.", look));
        }
        let checks = d.checks.iter().map(|c| {
            let (mark, tone) = match (c.done, c.ok) {
                (false, _) => ("·", Tone::Muted),
                (true, Some(true)) => ("ok", Tone::Accent),
                (true, Some(false)) => ("fail", Tone::Bad),
                (true, None) => ("note", Tone::Muted),
            };
            let detail = (!c.detail.is_empty()).then(|| SharedString::from(c.detail.clone()));
            form_item(
                c.name,
                detail,
                vec![form_text(mark, TypeRole::Meta, tone, look).into_any_element()],
                look,
            )
        });
        section.rows(checks).into_any_element()
    }

    fn erase(&self, look: &Look) -> AnyElement {
        let vpn = self.vpn.clone();
        let erase = Button::new("erase", ButtonKind::Bordered)
            .label("erase everything")
            .destructive(true)
            .on_click(move |_, window, cx| {
                let vpn = vpn.clone();
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
                            "profiles can't be recovered. you'll need their links or files to add them again.".into(),
                        ),
                    },
                    window,
                    cx,
                    move |cx| vpn.update(cx, |v, cx| v.erase(cx)),
                );
            });
        FormSection::titled("erase")
            .row(note(
                "removes every profile and its credentials, the vpn configuration, settings and logs from this device. the app stays installed, and the system keeps its own record of vpn connections.",
                look,
            ))
            .row(form_buttons(vec![erase.into_any_element()], look))
            .into_any_element()
    }
}
