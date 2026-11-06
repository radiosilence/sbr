//! The profiles page: the profiles with the active one marked, adding one
//! from a link, pasted JSON or a file, and the personal rules that apply
//! whichever runs.

use koan_kit::app::*;
use koan_kit::components::sheet::{self, Confirm};
use koan_kit::components::{Button, ButtonKind, FieldState, InputEvent, SectionHeading, TextField};
use koan_kit::raw::px;
use koan_kit::theme::{Look, Space, Tone, TypeRole, label};

use crate::install::Vpn;
use crate::profile::Profile;
use crate::profiles::Profiles;
use crate::swift::Date;
use crate::ui::{column, page, problem, text, toolbar};

pub struct ProfilesPage {
    profiles: Entity<Profiles>,
    vpn: Entity<Vpn>,
    link: Entity<FieldState>,
    _subscriptions: Vec<Subscription>,
}

impl ProfilesPage {
    pub fn new(profiles: Entity<Profiles>, vpn: Entity<Vpn>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let link = cx.new(|cx| {
            FieldState::new(window, cx).placeholder("https://… or sing-box://import-remote-profile… or pasted JSON")
        });
        let _subscriptions = vec![
            cx.observe(&profiles, |_, _, cx| cx.notify()),
            cx.observe(&vpn, |_, _, cx| cx.notify()),
            cx.subscribe_in(&link, window, |page, _, e: &InputEvent, window, cx| {
                if matches!(e, InputEvent::PressEnter { .. }) {
                    page.add_link(window, cx);
                }
            }),
        ];
        Self {
            profiles,
            vpn,
            link,
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
}

/// How long ago, in the fewest words.
fn ago(d: Date) -> String {
    match d.age().max(0.0) {
        s if s < 60.0 => "just now".into(),
        s if s < 3600.0 => format!("{} min ago", (s / 60.0) as u64),
        s if s < 86_400.0 => format!("{} h ago", (s / 3600.0) as u64),
        s => format!("{} d ago", (s / 86_400.0) as u64),
    }
}

impl Render for ProfilesPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let vpn = self.vpn.clone();
        let refresh = Button::new("refresh-all", ButtonKind::Bordered)
            .label("update")
            .on_click(move |_, _, cx| vpn.update(cx, |v, cx| v.refresh_profiles(cx)));
        let toolbar = toolbar("profiles", window, cx).trailing(refresh);

        let mut content = column(&look);
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
                label("a vpn client for sing-box profiles. add the profile your server's operator gave you to begin."),
                TypeRole::Body,
                Tone::Muted,
                &look,
            ));
        }
        for p in &store.profiles {
            let active = store.active_id == Some(p.id);
            let refreshing = store.refreshing.contains(&p.id);
            list = list.child(self.row(p, active, refreshing, &look));
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
        let content = content
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(SectionHeading::new("profiles"))
                    .child(list),
            )
            .child(self.add_section(store.adding, &look, cx.entity()))
            .child(self.rules_section(&look, cx));
        page(toolbar, "profiles", content, &look)
    }
}

impl ProfilesPage {
    fn row(&self, p: &Profile, active: bool, refreshing: bool, look: &Look) -> AnyElement {
        let id = p.id;
        let key = |what: &str| SharedString::from(format!("{what}-{id}"));
        let subtitle = match (p.host(), p.updated) {
            _ if refreshing => "updating".to_owned(),
            (None, _) => "local".to_owned(),
            (Some(host), Some(u)) => format!("{host} · updated {}", ago(u)),
            (Some(host), None) => host,
        };
        let mut actions = div().flex().items_center().gap(look.space(Space::S));
        if p.remote_url.is_some() {
            let profiles = self.profiles.clone();
            actions = actions.child(
                Button::new(key("update"), ButtonKind::Compact)
                    .label("update")
                    .disabled(refreshing)
                    .on_click(move |_, _, cx| {
                        profiles.update(cx, |s, cx| s.refresh(id, cx));
                        cx.stop_propagation();
                    }),
            );
        }
        let (profiles, name) = (self.profiles.clone(), p.name.clone());
        actions = actions.child(
            Button::new(key("rename"), ButtonKind::Compact)
                .label("rename")
                .on_click(move |_, window, cx| {
                    cx.stop_propagation();
                    let profiles = profiles.clone();
                    sheet::name(
                        "rename profile",
                        "rename",
                        &name,
                        |typed| vec![SharedString::from(format!("the profile is called {typed}"))],
                        window,
                        cx,
                        move |typed, cx| profiles.update(cx, |s, cx| s.rename(id, &typed, cx)),
                    );
                }),
        );
        let (vpn, name) = (self.vpn.clone(), p.name.clone());
        actions = actions.child(
            Button::new(key("delete"), ButtonKind::Compact)
                .label("delete")
                .on_click(move |_, window, cx| {
                    cx.stop_propagation();
                    let vpn = vpn.clone();
                    let mut lines = vec![SharedString::from(format!("{name} and its credentials"))];
                    if active {
                        lines.push("the tunnel stops: this profile is the active one".into());
                    }
                    sheet::confirm(
                        Confirm {
                            title: "delete profile?".into(),
                            verb: "delete".into(),
                            destructive: true,
                            lines,
                            note: Some("adding it again needs its link or file.".into()),
                        },
                        window,
                        cx,
                        move |cx| vpn.update(cx, |v, cx| v.delete_profile(id, cx)),
                    );
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
                    .child(text(
                        p.name.clone(),
                        TypeRole::Body,
                        if active { Tone::Strong } else { Tone::Ink },
                        look,
                    ))
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

    fn rules_section(&self, look: &Look, cx: &App) -> Div {
        let rules = &self.vpn.read(cx).settings.rules;
        let mut section = div().flex().flex_col().child(SectionHeading::new("rules"));
        if rules.is_empty() {
            section = section.child(text(
                label("open a connection to always route its domain via an exit."),
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
}
