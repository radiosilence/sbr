//! The profiles page: the profiles with the active one marked, adding one
//! from a link, pasted JSON or a file, and how the tunnel connects (on
//! demand, trusted Wi-Fi, leak protection), the personal rules and erasing
//! everything.

use koan_kit::app::*;
use koan_kit::components::{
    Button, ButtonKind, FieldState, InputEvent, ScrollArea, SectionHeading, TextField, Toggle, Toolbar, ToolbarTitle,
    moves_window,
};
use koan_kit::raw::px;
use koan_kit::theme::{KoanStyled, Look, Space, Tone, TypeRole, label};

use crate::install::Vpn;
use crate::profile::Profile;
use crate::profiles::Profiles;
use crate::swift::{Date, Uuid};

/// What waits for a second click.
#[derive(Clone, Copy, PartialEq)]
enum Confirm {
    Delete(Uuid),
    Erase,
}

pub struct ProfilesPage {
    profiles: Entity<Profiles>,
    vpn: Entity<Vpn>,
    link: Entity<FieldState>,
    network: Entity<FieldState>,
    renaming: Option<(Uuid, Entity<FieldState>)>,
    confirm: Option<Confirm>,
    _subscriptions: Vec<Subscription>,
}

impl ProfilesPage {
    pub fn new(profiles: Entity<Profiles>, vpn: Entity<Vpn>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let link = cx.new(|cx| {
            FieldState::new(window, cx).placeholder("https://… or sing-box://import-remote-profile… or pasted JSON")
        });
        let network = cx.new(|cx| FieldState::new(window, cx).placeholder("wi-fi name"));
        let _subscriptions = vec![
            cx.observe(&profiles, |_, _, cx| cx.notify()),
            cx.observe(&vpn, |_, _, cx| cx.notify()),
            cx.subscribe_in(&link, window, |page, _, e: &InputEvent, window, cx| {
                if matches!(e, InputEvent::PressEnter { .. }) {
                    page.add_link(window, cx);
                }
            }),
            cx.subscribe_in(&network, window, |page, _, e: &InputEvent, window, cx| {
                if matches!(e, InputEvent::PressEnter { .. }) {
                    page.add_network(window, cx);
                }
            }),
        ];
        Self {
            profiles,
            vpn,
            link,
            network,
            renaming: None,
            confirm: None,
            _subscriptions,
        }
    }

    fn add_link(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = self.link.read(cx).value().to_string();
        if input.trim().is_empty() {
            return;
        }
        self.profiles.update(cx, |p, cx| p.add_input(&input, cx));
        self.link.update(cx, |f, cx| f.set_value("", window, cx));
    }

    fn paste(&mut self, cx: &mut Context<Self>) {
        let Some(text) = cx.read_from_clipboard().and_then(|c| c.text()) else {
            return;
        };
        self.profiles.update(cx, |p, cx| p.add_input(&text, cx));
    }

    fn pick_file(&mut self, cx: &mut Context<Self>) {
        let picked = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("add profile".into()),
        });
        let profiles = self.profiles.clone();
        cx.spawn(async move |_, cx| {
            if let Ok(Ok(Some(paths))) = picked.await
                && let Some(path) = paths.into_iter().next()
            {
                profiles.update(cx, |p, cx| p.add_file(path, cx));
            }
        })
        .detach();
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

    fn start_rename(&mut self, p: &Profile, window: &mut Window, cx: &mut Context<Self>) {
        let field = cx.new(|cx| FieldState::new(window, cx).default_value(p.name.clone()));
        let id = p.id;
        self._subscriptions.push(
            cx.subscribe_in(&field, window, move |page, field, e: &InputEvent, _, cx| match e {
                InputEvent::PressEnter { .. } | InputEvent::Blur => {
                    let name = field.read(cx).value().to_string();
                    page.profiles.update(cx, |p, cx| p.rename(id, &name, cx));
                    page.renaming = None;
                    cx.notify();
                }
                _ => {}
            }),
        );
        field.update(cx, |f, cx| f.focus(window, cx));
        self.renaming = Some((id, field));
        cx.notify();
    }

    fn confirm(&mut self, what: Confirm, cx: &mut Context<Self>) -> bool {
        if self.confirm == Some(what) {
            self.confirm = None;
            return true;
        }
        self.confirm = Some(what);
        cx.notify();
        false
    }
}

fn text(s: impl Into<SharedString>, role: TypeRole, tone: Tone, look: &Look) -> Div {
    div()
        .text_role(role, look)
        .text_color(look.text_color(tone))
        .child(s.into())
}

/// How long ago, in the fewest words.
fn ago(d: Date) -> String {
    let s = d.age().max(0.0);
    match s {
        s if s < 60.0 => "just now".into(),
        s if s < 3600.0 => format!("{} min ago", (s / 60.0) as u64),
        s if s < 86_400.0 => format!("{} h ago", (s / 3600.0) as u64),
        s => format!("{} d ago", (s / 86_400.0) as u64),
    }
}

/// A dismissable message in the bad tone.
fn problem(id: &'static str, message: String, look: &Look, dismiss: impl Fn(&mut App) + 'static) -> Stateful<Div> {
    div()
        .id(id)
        .p(look.space(Space::M))
        .border_1()
        .border_color(look.color(Tone::Bad))
        .cursor_pointer()
        .on_click(move |_, _, cx| dismiss(cx))
        .child(text(message, TypeRole::Body, Tone::Bad, look))
}

impl Render for ProfilesPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let title = moves_window(
            div()
                .id("title")
                .size_full()
                .flex()
                .items_center()
                .child(ToolbarTitle::new("profiles")),
            window,
            cx,
        );
        let page = cx.entity();
        let refresh = Button::new("refresh-all", ButtonKind::Bordered)
            .label("update")
            .on_click({
                let vpn = self.vpn.clone();
                move |_, _, cx| vpn.update(cx, |v, cx| v.refresh_profiles(cx))
            });
        let toolbar = Toolbar::new()
            .under_window_buttons(true)
            .principal(title)
            .trailing(refresh);

        let mut content = div()
            .flex()
            .flex_col()
            .gap(look.space(Space::Xl))
            .p(look.space(Space::Xl));

        let store = self.profiles.read(cx);
        if let Some(e) = store.problem.clone() {
            let profiles = self.profiles.clone();
            content = content.child(problem("profiles-problem", e, &look, move |cx| {
                profiles.update(cx, |p, cx| p.dismiss_problem(cx))
            }));
        }
        if let Some(e) = self.vpn.read(cx).error.clone() {
            let vpn = self.vpn.clone();
            content = content.child(problem("vpn-problem", e, &look, move |cx| {
                vpn.update(cx, |v, cx| v.dismiss_error(cx))
            }));
        }

        let mut list = div().flex().flex_col();
        if store.profiles.is_empty() {
            list = list.child(text(
                label("add a sing-box profile link or file to begin."),
                TypeRole::Body,
                Tone::Muted,
                &look,
            ));
        }
        for p in &store.profiles {
            let active = store.active_id == Some(p.id);
            let refreshing = store.refreshing.contains(&p.id);
            list = list.child(self.row(p, active, refreshing, &look, page.clone()));
            if active {
                for w in &store.active_warnings {
                    list = list.child(div().pl(look.space(Space::L)).pb(look.space(Space::S)).child(text(
                        w.clone(),
                        TypeRole::Meta,
                        Tone::Muted,
                        &look,
                    )));
                }
            }
        }
        content = content
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(SectionHeading::new("profiles"))
                    .child(list),
            )
            .child(self.add_section(store.adding, &look, page.clone()))
            .child(self.connection_section(&look, cx))
            .child(self.rules_section(&look, cx))
            .child(self.erase_section(&look, page));

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(look.palette.bg.hsla())
            .child(toolbar)
            .child(ScrollArea::new("profiles", content))
    }
}

impl ProfilesPage {
    fn row(&self, p: &Profile, active: bool, refreshing: bool, look: &Look, page: Entity<Self>) -> AnyElement {
        let id = p.id;
        let key = |what: &str| SharedString::from(format!("{what}-{id}"));
        let subtitle = match (p.host(), p.updated) {
            _ if refreshing => "updating".to_owned(),
            (None, _) => "local".to_owned(),
            (Some(host), Some(u)) => format!("{host} · updated {}", ago(u)),
            (Some(host), None) => host,
        };
        let name: AnyElement = match &self.renaming {
            Some((rid, field)) if *rid == id => TextField::new(field).label("name").into_any_element(),
            _ => text(
                p.name.clone(),
                TypeRole::Body,
                if active { Tone::Strong } else { Tone::Ink },
                look,
            )
            .into_any_element(),
        };
        let mut actions = div().flex().items_center().gap(look.space(Space::S));
        if p.remote_url.is_some() {
            let profiles = self.profiles.clone();
            actions = actions.child(
                Button::new(key("update"), ButtonKind::Compact)
                    .label("update")
                    .disabled(refreshing)
                    .on_click(move |_, _, cx| profiles.update(cx, |s, cx| s.refresh(id, cx))),
            );
        }
        let profile = p.clone();
        let renamer = page.clone();
        actions = actions.child(
            Button::new(key("rename"), ButtonKind::Compact)
                .label("rename")
                .on_click(move |_, window, cx| renamer.update(cx, |pg, cx| pg.start_rename(&profile, window, cx))),
        );
        let confirming = self.confirm == Some(Confirm::Delete(id));
        let vpn = self.vpn.clone();
        actions = actions.child(
            Button::new(key("delete"), ButtonKind::Compact)
                .label(if confirming { "really delete" } else { "delete" })
                .destructive(confirming)
                .on_click(move |_, _, cx| {
                    if page.update(cx, |pg, cx| pg.confirm(Confirm::Delete(id), cx)) {
                        vpn.update(cx, |v, cx| v.delete_profile(id, cx));
                    }
                }),
        );
        let profiles = self.profiles.clone();
        div()
            .id(key("row"))
            .flex()
            .items_center()
            .gap(look.space(Space::M))
            .py(look.space(Space::M))
            .border_b(look.hairline)
            .border_color(look.palette.rule.hsla())
            .cursor_pointer()
            .on_click(move |_, _, cx| profiles.update(cx, |s, cx| s.activate(id, cx)))
            .child(
                div()
                    .w(px(2.0))
                    .h(px(32.0))
                    .when(active, |bar| bar.bg(look.color(Tone::Accent))),
            )
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap(look.space(Space::Xs))
                    .child(name)
                    .child(text(subtitle, TypeRole::Meta, Tone::Muted, look)),
            )
            .child(actions)
            .into_any_element()
    }

    fn add_section(&self, adding: bool, look: &Look, page: Entity<Self>) -> Div {
        let (add, paste, file) = (page.clone(), page.clone(), page);
        let buttons = div()
            .flex()
            .gap(look.space(Space::M))
            .child(
                Button::new("add", ButtonKind::Prominent)
                    .label(if adding { "adding" } else { "add" })
                    .disabled(adding)
                    .on_click(move |_, window, cx| add.update(cx, |pg, cx| pg.add_link(window, cx))),
            )
            .child(
                Button::new("paste", ButtonKind::Bordered)
                    .label("paste")
                    .on_click(move |_, _, cx| paste.update(cx, |pg, cx| pg.paste(cx))),
            )
            .child(
                Button::new("file", ButtonKind::Bordered)
                    .label("file")
                    .on_click(move |_, _, cx| file.update(cx, |pg, cx| pg.pick_file(cx))),
            );
        div()
            .flex()
            .flex_col()
            .gap(look.space(Space::S))
            .child(SectionHeading::new("add"))
            .child(TextField::new(&self.link).label("profile link"))
            .child(buttons)
    }

    fn connection_section(&self, look: &Look, cx: &App) -> Div {
        let v = self.vpn.read(cx);
        let s = &v.settings;
        let strict = v.strict();
        let vpn = self.vpn.clone();
        let auto = Toggle::new("auto-connect", "auto-connect", s.auto_connect).on_change(move |on, _, cx| {
            let on = *on;
            vpn.update(cx, |v, cx| v.update_settings(Some(on), cx, |s| s.auto_connect = on))
        });
        let mut section = div()
            .flex()
            .flex_col()
            .gap(look.space(Space::S))
            .child(SectionHeading::new("connection"))
            .child(auto)
            .child(text(
                label("connects on cellular and on wi-fi not listed below; disconnects on listed networks. disconnecting by hand keeps it off until you connect again."),
                TypeRole::Meta,
                Tone::Muted,
                look,
            ));
        if s.auto_connect {
            for ssid in &s.trusted_networks {
                let vpn = self.vpn.clone();
                let gone = ssid.clone();
                section = section.child(
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
            section = section
                .child(TextField::new(&self.network).label("trusted wi-fi name"))
                .child(text(
                    label("names are matched exactly, including case."),
                    TypeRole::Meta,
                    Tone::Muted,
                    look,
                ));
        }
        let vpn = self.vpn.clone();
        section = section.child(
            Toggle::new("strict", "block traffic outside the tunnel", strict).on_change(move |on, _, cx| {
                let on = *on;
                vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.strict = Some(on)))
            }),
        );
        if strict {
            let vpn = self.vpn.clone();
            section = section.child(
                Toggle::new("local", "allow the local network", s.allow_local_network).on_change(move |on, _, cx| {
                    let on = *on;
                    vpn.update(cx, |v, cx| v.update_settings(None, cx, |s| s.allow_local_network = on))
                }),
            );
        }
        section.child(text(
            label("applied the next time the tunnel connects."),
            TypeRole::Meta,
            Tone::Muted,
            look,
        ))
    }

    fn rules_section(&self, look: &Look, cx: &App) -> Div {
        let rules = &self.vpn.read(cx).settings.rules;
        let mut section = div().flex().flex_col().child(SectionHeading::new("rules"));
        if rules.is_empty() {
            section = section.child(text(
                label("domains routed through a chosen exit whatever the profile says appear here."),
                TypeRole::Meta,
                Tone::Muted,
                look,
            ));
        }
        for r in rules {
            let vpn = self.vpn.clone();
            let id = r.id;
            section = section.child(
                div()
                    .flex()
                    .items_center()
                    .gap(look.space(Space::M))
                    .py(look.space(Space::S))
                    .border_b(look.hairline)
                    .border_color(look.palette.rule.hsla())
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .child(text(r.domains.join(" "), TypeRole::Body, Tone::Ink, look))
                            .child(text(format!("via {}", r.outbound), TypeRole::Meta, Tone::Muted, look)),
                    )
                    .child(
                        Button::new(SharedString::from(format!("rule-{id}")), ButtonKind::Text)
                            .label("delete")
                            .on_click(move |_, _, cx| vpn.update(cx, |v, cx| v.remove_rule(id, cx))),
                    ),
            );
        }
        section
    }

    fn erase_section(&self, look: &Look, page: Entity<Self>) -> Div {
        let confirming = self.confirm == Some(Confirm::Erase);
        let vpn = self.vpn.clone();
        div()
            .flex()
            .flex_col()
            .gap(look.space(Space::S))
            .child(SectionHeading::new("erase"))
            .child(text(
                label("removes every profile, the vpn configuration, the tunnel's files and these settings from this device."),
                TypeRole::Meta,
                Tone::Muted,
                look,
            ))
            .child(
                div().child(
                    Button::new("erase", ButtonKind::Bordered)
                        .label(if confirming { "really erase everything" } else { "erase everything" })
                        .destructive(true)
                        .on_click(move |_, _, cx| {
                            if page.update(cx, |pg, cx| pg.confirm(Confirm::Erase, cx)) {
                                vpn.update(cx, |v, cx| v.erase(cx));
                            }
                        }),
                ),
            )
    }
}
