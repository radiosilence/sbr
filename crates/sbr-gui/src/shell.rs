//! The window's pages, the tab bar between them, and the sheet and question
//! drawn over them.

use koan_kit::app::*;
use koan_kit::components::{TabStrip, sheet};
use koan_kit::theme::{Icon, Look};

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
    _asking: Subscription,
}

impl Shell {
    pub fn new(models: Models, tab: Tab, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let Models { tunnel, profiles, vpn } = models;
        let connections = cx.new(|cx| Connections::new(tunnel.clone(), cx));
        let logs = cx.new(|cx| Logs::new(tunnel.clone(), &vpn, cx));
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
            _asking,
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
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(look.palette.bg.hsla())
            .child(div().flex_1().min_h_0().overflow_hidden().child(page))
            .child(
                div()
                    .bg(look.palette.bg.hsla())
                    .border_t(look.hairline)
                    .border_color(look.palette.rule.hsla())
                    .child(tabs),
            )
            .children(sheet::presented(window, cx))
            .children(sheet::overlay(window, cx))
    }
}
