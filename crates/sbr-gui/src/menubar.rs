//! sbr on macOS lives in the menu bar: the arch, lit while the tunnel is up,
//! and a menu to connect and disconnect, switch profiles, open the window,
//! launch at login and quit. The menu is rebuilt only when what it shows
//! changes. Its commands use macOS title case, as system chrome beside other
//! apps' menus; the status line is the app's own label and stays lowercase.

use koan_kit::app::*;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use crate::Models;
use crate::status_item::{Entry, StatusItem};
use crate::swift::Uuid;

const ON: &[u8] = include_bytes!("../../../apple/App/App/Assets.xcassets/MenuBarOn.imageset/MenuBarOn.pdf");
const OFF: &[u8] = include_bytes!("../../../apple/App/App/Assets.xcassets/MenuBarOff.imageset/MenuBarOff.pdf");

/// What the menu shows, compared to decide whether to rebuild it.
#[derive(Clone, PartialEq)]
struct Shown {
    lit: bool,
    error: Option<String>,
    status: String,
    on: bool,
    can_connect: bool,
    profiles: Vec<(Uuid, String)>,
    active: Option<Uuid>,
    login: Login,
}

#[derive(Clone, Copy, PartialEq)]
enum Login {
    Off,
    On,
    NeedsApproval,
}

fn login() -> Login {
    match unsafe { SMAppService::mainAppService().status() } {
        SMAppServiceStatus::Enabled => Login::On,
        SMAppServiceStatus::RequiresApproval => Login::NeedsApproval,
        _ => Login::Off,
    }
}

pub struct MenuBar {
    item: StatusItem,
    shown: Option<Shown>,
    _observe: [Subscription; 3],
}

impl Global for MenuBar {}

/// Puts sbr in the menu bar, following `models` from then on.
pub fn install(models: &Models, cx: &mut App) {
    let Some(item) = StatusItem::install("sbr", cx) else {
        return;
    };
    let refresh = |cx: &mut App| {
        if cx.has_global::<MenuBar>() {
            let models = cx.global::<crate::AppModels>().0.clone();
            let shown = shown(&models, cx);
            cx.update_global::<MenuBar, _>(|bar, _| bar.show(shown, &models));
        }
    };
    let _observe = [
        cx.observe(&models.tunnel, move |_, cx| refresh(cx)),
        cx.observe(&models.profiles, move |_, cx| refresh(cx)),
        cx.observe(&models.vpn, move |_, cx| refresh(cx)),
    ];
    let shown = shown(models, cx);
    let mut bar = MenuBar {
        item,
        shown: None,
        _observe,
    };
    bar.show(shown, models);
    cx.set_global(bar);
}

fn shown(models: &Models, cx: &App) -> Shown {
    let tunnel = models.tunnel.read(cx);
    let profiles = models.profiles.read(cx);
    let vpn = models.vpn.read(cx);
    let state = tunnel.status.label();
    let status = match profiles.active() {
        Some(p) => format!("{state} · {}", p.name),
        None => state.to_string(),
    };
    Shown {
        lit: tunnel.status == crate::ne::Status::On,
        error: tunnel.error.clone().or_else(|| vpn.error.clone()).map(|e| brief(&e)),
        status,
        on: tunnel.status.is_on(),
        can_connect: profiles.active().is_some(),
        profiles: profiles.profiles.iter().map(|p| (p.id, p.name.clone())).collect(),
        active: profiles.active_id,
        login: login(),
    }
}

/// The menu is as wide as its widest item; the window has the rest.
fn brief(message: &str) -> String {
    let line = message.lines().next().unwrap_or_default();
    if line.chars().count() > 60 {
        format!("{}…", line.chars().take(59).collect::<String>())
    } else {
        line.to_string()
    }
}

impl MenuBar {
    fn show(&mut self, shown: Shown, models: &Models) {
        if self.shown.as_ref() == Some(&shown) {
            return;
        }
        if self.shown.as_ref().map(|s| s.lit) != Some(shown.lit) {
            let (image, name) = if shown.lit {
                (ON, "sbr, connected")
            } else {
                (OFF, "sbr, disconnected")
            };
            self.item.set_image(image, name);
        }

        let mut entries = Vec::new();
        if let Some(error) = &shown.error {
            entries.push(Entry::Label(format!("Error: {error}")));
        }
        entries.push(Entry::Label(shown.status.clone()));
        let on = shown.on;
        let tunnel = models.tunnel.clone();
        entries.push(
            Entry::action(if on { "Disconnect" } else { "Connect" }, move |cx| {
                tunnel.update(cx, |t, cx| t.set_on(!on, cx));
            })
            .enabled(on || shown.can_connect),
        );
        if !shown.profiles.is_empty() {
            let choices = shown
                .profiles
                .iter()
                .map(|(id, name)| {
                    let (id, profiles) = (*id, models.profiles.clone());
                    Entry::action(name.clone(), move |cx| {
                        profiles.update(cx, |p, cx| p.activate(id, cx));
                    })
                    .checked(shown.active == Some(id))
                })
                .collect();
            entries.push(Entry::Submenu {
                title: "Profile".into(),
                entries: choices,
            });
        }
        entries.push(Entry::Separator);
        let opening = models.clone();
        entries.push(Entry::action("Open sbr", move |cx| crate::open_window(&opening, cx)).key("o"));
        entries.push(match shown.login {
            Login::NeedsApproval => Entry::action("Launch at Login: Allow in System Settings…", |_| unsafe {
                SMAppService::openSystemSettingsLoginItems();
            }),
            login => Entry::action("Launch at Login", move |cx| {
                let service = unsafe { SMAppService::mainAppService() };
                let done = if login == Login::On {
                    unsafe { service.unregisterAndReturnError() }
                } else {
                    unsafe { service.registerAndReturnError() }
                };
                if let Err(e) = done {
                    let message = e.localizedDescription().to_string();
                    let tunnel = cx.global::<crate::AppModels>().0.tunnel.clone();
                    tunnel.update(cx, |t, cx| {
                        t.error = Some(message);
                        cx.notify();
                    });
                } else {
                    // The status is not observable: read it again now.
                    let tunnel = cx.global::<crate::AppModels>().0.tunnel.clone();
                    tunnel.update(cx, |_, cx| cx.notify());
                }
            })
            .checked(login == Login::On),
        });
        entries.push(Entry::Separator);
        entries.push(Entry::action("Quit sbr", |cx| cx.quit()).key("q"));
        self.item.set_menu(entries);
        self.shown = Some(shown);
    }
}
