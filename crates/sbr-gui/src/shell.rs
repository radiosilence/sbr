//! The window's pages and the tab bar between them.

use koan_kit::app::*;
use koan_kit::components::TabStrip;
use koan_kit::theme::{Icon, Look};

use crate::Models;
use crate::install::Vpn;
use crate::profiles_view::ProfilesPage;
use crate::view::TunnelPage;

#[derive(Clone, Copy, PartialEq)]
pub enum Tab {
    Tunnel,
    Profiles,
}

pub struct Shell {
    tab: Tab,
    vpn: Entity<Vpn>,
    tunnel_page: Entity<TunnelPage>,
    profiles_page: Entity<ProfilesPage>,
}

impl Shell {
    pub fn new(models: Models, tab: Tab, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let Models { tunnel, profiles, vpn } = models;
        let tunnel_page = cx.new(|cx| TunnelPage::new(tunnel, cx));
        let profiles_page = cx.new(|cx| ProfilesPage::new(profiles, vpn.clone(), window, cx));
        Self {
            tab,
            vpn,
            tunnel_page,
            profiles_page,
        }
    }

    fn show(&mut self, tab: Tab, cx: &mut Context<Self>) {
        if tab == self.tab {
            return;
        }
        self.tab = tab;
        if tab == Tab::Profiles {
            self.vpn.update(cx, |v, cx| v.refresh_profiles(cx));
        }
        cx.notify();
    }
}

impl Render for Shell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let look = Look::of(window, cx);
        let page: AnyView = match self.tab {
            Tab::Tunnel => self.tunnel_page.clone().into(),
            Tab::Profiles => self.profiles_page.clone().into(),
        };
        let (to_tunnel, to_profiles) = (cx.entity(), cx.entity());
        let tabs = TabStrip::new()
            .bar()
            .tab(Icon::Server, "tunnel", self.tab == Tab::Tunnel, move |_, _, cx| {
                to_tunnel.update(cx, |s, cx| s.show(Tab::Tunnel, cx))
            })
            .tab(Icon::Library, "profiles", self.tab == Tab::Profiles, move |_, _, cx| {
                to_profiles.update(cx, |s, cx| s.show(Tab::Profiles, cx))
            });
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
    }
}
