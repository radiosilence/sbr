//! sbr on macOS lives in the menu bar: the arch, lit while the tunnel is up,
//! and a menu to connect and disconnect, switch profiles, pick each group's
//! route, open the window, launch at login and quit. While the menu is open
//! the tunnel is polled, so the rates and latencies in it are live; the
//! menu is rebuilt only when what it shows changes. Its commands use macOS
//! title case, as system chrome beside other apps' menus; the status line
//! is the app's own label and stays lowercase.

use std::collections::BTreeSet;

use koan_kit::app::*;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use crate::Models;
use crate::graph::{bytes, rate};
use crate::proto::Group;
use crate::status_item::{Entry, StatusItem};
use crate::swift::Uuid;
use crate::view::failure;

const ON: &[u8] = include_bytes!("../../../apple/App/App/Assets.xcassets/MenuBarOn.imageset/MenuBarOn.pdf");
const OFF: &[u8] = include_bytes!("../../../apple/App/App/Assets.xcassets/MenuBarOff.imageset/MenuBarOff.pdf");

/// What the menu shows, compared to decide whether to rebuild it.
#[derive(Clone, PartialEq)]
struct Shown {
    lit: bool,
    error: Option<String>,
    status: String,
    /// Throughput and connections while the tunnel is up and polled.
    live: String,
    on: bool,
    can_connect: bool,
    /// Each profile's id, name and where it downloads from.
    profiles: Vec<(Uuid, String, Option<String>)>,
    active: Option<Uuid>,
    groups: Vec<Group>,
    testing: BTreeSet<String>,
    login: Login,
    /// The system extension waits for the user to allow it.
    needs_approval: bool,
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
    let tunnel = models.tunnel.clone();
    let opened = move |open: bool, cx: &mut App| tunnel.update(cx, |t, cx| t.peek(open, cx));
    let Some(item) = StatusItem::install("sbr", opened, cx) else {
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
    let on = tunnel.status.is_on();
    // Over the last second, as the window's header reads them.
    let recent: Vec<_> = tunnel.history.iter().rev().take(4).collect();
    let live = match (on, recent.is_empty(), &tunnel.stats) {
        (true, false, Some(stats)) => {
            let mean =
                |f: fn(&crate::tunnel::Sample) -> f64| recent.iter().map(|s| f(s)).sum::<f64>() / recent.len() as f64;
            format!(
                "↓ {}  ↑ {} · {} {}",
                rate(mean(|s| s.down)),
                rate(mean(|s| s.up)),
                stats.active_connections,
                if stats.active_connections == 1 {
                    "connection"
                } else {
                    "connections"
                },
            )
        }
        (true, _, Some(stats)) => format!(
            "↓ {}  ↑ {} in all",
            bytes(stats.downlink_bytes as f64),
            bytes(stats.uplink_bytes as f64)
        ),
        _ => String::new(),
    };
    Shown {
        lit: tunnel.status == crate::ne::Status::On,
        error: tunnel.error.clone().or_else(|| vpn.error.clone()).map(|e| brief(&e)),
        status,
        live,
        on,
        can_connect: profiles.active().is_some(),
        profiles: profiles
            .profiles
            .iter()
            .map(|p| (p.id, p.name.clone(), p.host()))
            .collect(),
        active: profiles.active_id,
        groups: if on { tunnel.groups.clone() } else { Vec::new() },
        testing: tunnel.testing.clone(),
        login: login(),
        needs_approval: vpn.needs_approval,
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

fn ms(delay: Option<u32>) -> Option<String> {
    delay.map(|d| format!("{d} ms"))
}

/// A group's line: where it sends traffic now, and a submenu of its members
/// to choose from (a selector) or to read (a urltest, which chooses itself).
fn group_entry(g: &Group, all: &[Group], testing: bool, models: &Models) -> Entry {
    let selectable = g.selectable();
    let fastest = g
        .members
        .iter()
        .filter(|m| m.degraded != Some(true))
        .filter_map(|m| m.delay)
        .min();
    let mut members: Vec<Entry> = g
        .members
        .iter()
        .map(|m| {
            let degraded = m.degraded == Some(true);
            // A member that is itself a group: where it leads.
            let inner = all
                .iter()
                .find(|o| o.tag == m.tag)
                .map(|o| format!("{} → {}", m.kind, o.now));
            let subtitle = match (degraded, m.retry_in) {
                (true, Some(s)) => format!("{} · retry in {s}s", failure(m.reason.as_deref().unwrap_or("down"))),
                (true, None) => failure(m.reason.as_deref().unwrap_or("down")).to_string(),
                (false, _) => inner.unwrap_or_else(|| m.kind.clone()),
            };
            let picked = if selectable {
                g.selected == m.tag
            } else {
                g.now == m.tag
            };
            let (tunnel, group, member) = (models.tunnel.clone(), g.tag.clone(), m.tag.clone());
            let entry = Entry::action(m.tag.clone(), move |cx| {
                let (group, member) = (group.clone(), member.clone());
                tunnel.update(cx, |t, cx| t.select(group, member, cx));
            })
            .subtitle(subtitle)
            .badge(if degraded { None } else { ms(m.delay) })
            .checked(picked)
            .enabled(selectable);
            if degraded {
                entry.symbol("exclamationmark.triangle.fill")
            } else if m.delay.is_some() && m.delay == fastest {
                entry.symbol("bolt.fill")
            } else {
                entry
            }
        })
        .collect();
    // Latency is tested on urltest groups: this one, or those it holds.
    let testable = g.kind == "urltest" || g.members.iter().any(|m| m.kind == "urltest");
    if testable {
        let (tunnel, tag) = (models.tunnel.clone(), g.tag.clone());
        members.push(Entry::Separator);
        members.push(
            Entry::action(if testing { "Testing Latency…" } else { "Test Latency" }, move |cx| {
                let tag = tag.clone();
                tunnel.update(cx, |t, cx| t.url_test(tag, cx));
            })
            .symbol("gauge.with.needle")
            .enabled(!testing),
        );
    }
    let route = if g.selected == g.now || !selectable {
        g.now.clone()
    } else {
        format!("{} → {}", g.selected, g.now)
    };
    let down = g.members.iter().any(|m| m.tag == g.now && m.degraded == Some(true));
    Entry::submenu(g.tag.clone(), members)
        .subtitle(route)
        .badge(ms(g.delay))
        .symbol(if down {
            "exclamationmark.triangle.fill"
        } else if selectable {
            "arrow.triangle.branch"
        } else {
            "bolt.horizontal"
        })
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
            entries.push(Entry::label(error.clone()).symbol("exclamationmark.triangle.fill"));
        }
        entries.push(Entry::label(shown.status.clone()).subtitle(shown.live.clone()));
        if shown.needs_approval {
            let vpn = models.vpn.clone();
            entries.push(
                Entry::action("Allow sbr in System Settings…", move |cx| {
                    vpn.read(cx).open_approval_settings()
                })
                .symbol("lock.shield"),
            );
        }
        let on = shown.on;
        let tunnel = models.tunnel.clone();
        entries.push(
            Entry::action(if on { "Disconnect" } else { "Connect" }, move |cx| {
                tunnel.update(cx, |t, cx| t.set_on(!on, cx));
            })
            .symbol(if on { "stop.circle" } else { "play.circle" })
            .enabled(on || shown.can_connect),
        );

        if !shown.profiles.is_empty() {
            entries.push(Entry::Separator);
            entries.push(Entry::Header("Profiles".into()));
            for (id, name, host) in &shown.profiles {
                let (id, profiles) = (*id, models.profiles.clone());
                entries.push(
                    Entry::action(name.clone(), move |cx| {
                        profiles.update(cx, |p, cx| p.activate(id, cx));
                    })
                    .subtitle(host.clone().unwrap_or_default())
                    .checked(shown.active == Some(id)),
                );
            }
        }

        if !shown.groups.is_empty() {
            entries.push(Entry::Separator);
            entries.push(Entry::Header("Routes".into()));
            for g in &shown.groups {
                entries.push(group_entry(g, &shown.groups, shown.testing.contains(&g.tag), models));
            }
        }

        entries.push(Entry::Separator);
        let opening = models.clone();
        entries.push(
            Entry::action("Open sbr", move |cx| crate::open_window(&opening, cx))
                .symbol("macwindow")
                .key("o"),
        );
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
