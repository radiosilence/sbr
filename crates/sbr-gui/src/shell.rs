//! The window's pages, the tab bar between them, the sheet and question
//! drawn over them, and koan-kit's wash beneath them: mint while the tunnel
//! is on, the bare ground while it is off.

use koan_kit::app::*;
use koan_kit::components::sheet::{self, Layer};
use koan_kit::components::{Clear, TabStrip, system_insets};
use koan_kit::theme::wash::{Sleeve, Wash, WindowWash};
use koan_kit::theme::{Icon, KoanTheme, Look};

use crate::Models;
use crate::connections::Connections;
use crate::connections_view::ConnectionsPage;
use crate::install::Vpn;
use crate::logs::Logs;
use crate::logs_view::LogsPage;
use crate::profiles_view::ProfilesPage;
use crate::settings_view::SettingsPage;
use crate::view::TunnelPage;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tab {
    Tunnel,
    Profiles,
    Connections,
    Logs,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Tunnel, Tab::Profiles, Tab::Connections, Tab::Logs, Tab::Settings];

    fn title(self) -> &'static str {
        match self {
            Tab::Tunnel => "tunnel",
            Tab::Profiles => "profiles",
            Tab::Connections => "connections",
            Tab::Logs => "logs",
            Tab::Settings => "settings",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Tab::Tunnel => Icon::Server,
            Tab::Profiles => Icon::Library,
            Tab::Connections => Icon::Devices,
            Tab::Logs => Icon::History,
            Tab::Settings => Icon::Settings,
        }
    }

    /// The tab a name, such as one given on the command line, asks for.
    pub fn named(name: &str) -> Option<Tab> {
        Tab::ALL.into_iter().find(|t| t.title() == name)
    }
}

pub struct Shell {
    tab: Tab,
    vpn: Entity<Vpn>,
    connections: Entity<Connections>,
    logs: Entity<Logs>,
    tunnel_page: Entity<TunnelPage>,
    profiles_page: Entity<ProfilesPage>,
    connections_page: Entity<ConnectionsPage>,
    logs_page: Entity<LogsPage>,
    settings_page: Entity<SettingsPage>,
    /// Under every page; the pages draw no ground of their own.
    wash: Entity<Wash>,
    /// Whether the wash shows mint: the tunnel was on when last looked at.
    washed: bool,
    _asking: Subscription,
    _tunnel: Subscription,
}

/// The wash's sleeve while connected: a small field of mints, which the kit
/// blurs, holds to the appearance's contrast and drifts.
fn mint() -> Option<Sleeve> {
    const SIDE: u32 = 8;
    let corners = [
        [168.0, 232.0, 200.0],
        [52.0, 160.0, 120.0],
        [96.0, 200.0, 190.0],
        [140.0, 220.0, 150.0],
    ];
    let mut rgba = Vec::with_capacity((SIDE * SIDE * 4) as usize);
    for y in 0..SIDE {
        for x in 0..SIDE {
            let (u, v) = (x as f32 / (SIDE - 1) as f32, y as f32 / (SIDE - 1) as f32);
            let w = [(1.0 - u) * (1.0 - v), u * (1.0 - v), (1.0 - u) * v, u * v];
            for c in 0..3 {
                let value: f32 = corners.iter().zip(w).map(|(k, w)| k[c] * w).sum();
                rgba.push(value.round() as u8);
            }
            rgba.push(255);
        }
    }
    Sleeve::new(rgba.into(), SIDE, SIDE)
}

impl Shell {
    pub fn new(models: Models, tab: Tab, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let Models { tunnel, profiles, vpn } = models;
        let connections = cx.new(|cx| Connections::new(tunnel.clone(), cx));
        let logs = cx.new(|cx| Logs::new(tunnel.clone(), &vpn, cx));
        let washed = tunnel.read(cx).status.is_on();
        let wash = cx.new(|cx| {
            let mut wash = Wash::new();
            if washed {
                wash.set_sleeve(mint(), cx);
                wash.drift(true, cx);
            }
            wash
        });
        WindowWash::set(window, (!KoanTheme::opaque(cx)).then_some(&wash), cx);
        let _tunnel = cx.observe(&tunnel, |shell: &mut Shell, tunnel, cx| {
            let on = tunnel.read(cx).status.is_on();
            if on != shell.washed {
                shell.washed = on;
                shell.wash.update(cx, |wash, cx| {
                    wash.set_sleeve(if on { mint() } else { None }, cx);
                    wash.drift(on, cx);
                });
            }
        });
        let tunnel_page = cx.new(|cx| TunnelPage::new(tunnel, cx));
        let profiles_page = cx.new(|cx| ProfilesPage::new(profiles.clone(), vpn.clone(), window, cx));
        let connections_page = cx.new(|cx| ConnectionsPage::new(connections.clone(), vpn.clone(), window, cx));
        let logs_page = cx.new(|cx| LogsPage::new(logs.clone(), vpn.clone(), cx));
        let settings_page = cx.new(|cx| SettingsPage::new(vpn.clone(), profiles, logs.clone(), window, cx));
        // The sheet and the question are drawn here, over the page.
        let asking = sheet::asking(cx);
        let _asking = cx.observe(&asking, |_, _, cx| cx.notify());
        let mut shell = Self {
            tab: Tab::Tunnel,
            vpn,
            connections,
            logs,
            tunnel_page,
            profiles_page,
            connections_page,
            logs_page,
            settings_page,
            wash,
            washed,
            _asking,
            _tunnel,
        };
        shell.show(tab, cx);
        shell
    }

    fn show(&mut self, tab: Tab, cx: &mut Context<Self>) {
        self.tab = tab;
        if tab == Tab::Profiles {
            self.vpn.update(cx, |v, cx| v.refresh_profiles(cx));
        }
        // Polled only while their page shows.
        self.connections
            .update(cx, |c, cx| c.set_shown(tab == Tab::Connections, cx));
        self.logs.update(cx, |l, cx| l.set_shown(tab == Tab::Logs, cx));
        cx.notify();
    }
}

impl Render for Shell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let page: AnyView = match self.tab {
            Tab::Tunnel => self.tunnel_page.clone().into(),
            Tab::Profiles => self.profiles_page.clone().into(),
            Tab::Connections => self.connections_page.clone().into(),
            Tab::Logs => self.logs_page.clone().into(),
            Tab::Settings => self.settings_page.clone().into(),
        };
        let mut tabs = TabStrip::new().bar();
        for tab in Tab::ALL {
            let shell = cx.entity();
            tabs = tabs.tab(tab.icon(), tab.title(), self.tab == tab, move |_, _, cx| {
                shell.update(cx, |s, cx| {
                    if s.tab != tab {
                        s.show(tab, cx)
                    }
                })
            });
        }
        // On a phone, as koan-gui's shell: the page clears the status bar
        // and the notch, and the tab bar's surface runs on under the home
        // indicator. A desktop window has no insets.
        let insets = system_insets(Clear::System, window);
        let foot = if crate::ui::phone() {
            look.palette.surface.hsla()
        } else {
            look.palette.bg.hsla()
        };
        let ground = div().absolute().size_full().map(|d| {
            if KoanTheme::opaque(cx) {
                d.bg(look.palette.bg.hsla())
            } else {
                d.child(self.wash.clone().cached(StyleRefinement::default().size_full()))
            }
        });
        let shell = div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .pt(insets.top)
            .pl(insets.left)
            .pr(insets.right)
            .child(div().flex_1().min_h_0().overflow_hidden().child(page))
            .child(
                div()
                    .flex_shrink_0()
                    .bg(foot)
                    .pb(insets.bottom)
                    .border_t(look.hairline)
                    .border_color(look.palette.rule.hsla())
                    .child(tabs),
            )
            .children(sheet::presented(window, cx).map(|s| sheet::layered(Layer::Sheet, s)))
            .children(sheet::overlay(window, cx).map(|q| sheet::layered(Layer::Question, q)));
        div().relative().size_full().child(ground).child(shell)
    }
}
