//! A menu bar item: a template image and a menu of entries, each chosen
//! entry answered by a closure on GPUI's side. GPUI has no status item, so
//! this is AppKit's `NSStatusItem`. It knows nothing of sbr, so it can move
//! into koan-kit as it stands.
//!
//! A new menu with the same shape as the one shown (the same kinds of entry
//! in the same places) updates the items in place, so live figures can
//! change while the menu is open without closing a submenu under the
//! pointer.

use std::cell::RefCell;
use std::rc::Rc;

use futures::StreamExt as _;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use koan_kit::app::*;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSControlStateValueOff, NSControlStateValueOn, NSEventModifierFlags, NSImage, NSMenu, NSMenuDelegate, NSMenuItem,
    NSMenuItemBadge, NSStatusBar, NSStatusItem, NSVariableStatusItemLength,
};
use objc2_foundation::{NSData, NSSize, NSString};

/// What an entry does when chosen.
pub type Run = Rc<dyn Fn(&mut App)>;

/// One line of the menu.
pub enum Entry {
    Item(Item),
    /// A section's title, in the small type macOS gives section headers.
    Header(String),
    Separator,
}

pub struct Item {
    title: String,
    /// A second line in smaller type.
    subtitle: Option<String>,
    /// A short figure in a capsule at the trailing edge.
    badge: Option<String>,
    /// An SF Symbol shown before the title.
    symbol: Option<&'static str>,
    enabled: bool,
    /// Shown with a check mark: a toggle that is on, the chosen option.
    checked: bool,
    /// A key that chooses it with Command held while the menu is open.
    key: &'static str,
    /// None for a line that cannot be chosen.
    run: Option<Run>,
    submenu: Option<Vec<Entry>>,
}

impl Entry {
    fn item(title: impl Into<String>, run: Option<Run>, submenu: Option<Vec<Entry>>) -> Entry {
        Entry::Item(Item {
            title: title.into(),
            subtitle: None,
            badge: None,
            symbol: None,
            enabled: true,
            checked: false,
            key: "",
            run,
            submenu,
        })
    }

    pub fn action(title: impl Into<String>, run: impl Fn(&mut App) + 'static) -> Entry {
        Entry::item(title, Some(Rc::new(run)), None)
    }

    /// Text that cannot be chosen: a status line.
    pub fn label(title: impl Into<String>) -> Entry {
        Entry::item(title, None, None).enabled(false)
    }

    pub fn submenu(title: impl Into<String>, entries: Vec<Entry>) -> Entry {
        Entry::item(title, None, Some(entries))
    }

    fn with(mut self, f: impl FnOnce(&mut Item)) -> Entry {
        if let Entry::Item(item) = &mut self {
            f(item);
        }
        self
    }

    pub fn enabled(self, on: bool) -> Entry {
        self.with(|i| i.enabled = on)
    }

    pub fn checked(self, on: bool) -> Entry {
        self.with(|i| i.checked = on)
    }

    pub fn key(self, k: &'static str) -> Entry {
        self.with(|i| i.key = k)
    }

    pub fn subtitle(self, s: impl Into<String>) -> Entry {
        let s = s.into();
        self.with(|i| i.subtitle = (!s.is_empty()).then_some(s))
    }

    pub fn badge(self, b: Option<String>) -> Entry {
        self.with(|i| i.badge = b)
    }

    pub fn symbol(self, s: &'static str) -> Entry {
        self.with(|i| i.symbol = Some(s))
    }
}

enum Event {
    Chosen(Run),
    Opened(bool),
}

thread_local! {
    /// The current menu's closures, by the tag of their item, and where
    /// a chosen closure or the menu opening goes: the task on GPUI's side.
    static RUNS: RefCell<Vec<Run>> = const { RefCell::new(Vec::new()) };
    static EVENTS: RefCell<Option<UnboundedSender<Event>>> = const { RefCell::new(None) };
}

fn send(event: Event) {
    EVENTS.with(|events| {
        if let Some(events) = &*events.borrow() {
            events.unbounded_send(event).ok();
        }
    });
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and the class keeps
    // no state of its own.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SbrStatusTarget"]
    struct Target;

    impl Target {
        #[unsafe(method(chosen:))]
        fn chosen(&self, sender: Option<&NSMenuItem>) {
            let Some(item) = sender else { return };
            // Looked up now: a refresh before the event is handled may
            // number the items differently.
            let Ok(tag) = usize::try_from(item.tag()) else { return };
            if let Some(run) = RUNS.with(|runs| runs.borrow().get(tag).cloned()) {
                send(Event::Chosen(run));
            }
        }
    }

    unsafe impl NSObjectProtocol for Target {}

    unsafe impl NSMenuDelegate for Target {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            send(Event::Opened(true));
        }

        #[unsafe(method(menuDidClose:))]
        fn menu_did_close(&self, _menu: &NSMenu) {
            send(Event::Opened(false));
        }
    }
);

/// The item, while it is in the menu bar; dropped, it leaves it.
pub struct StatusItem {
    item: Retained<NSStatusItem>,
    menu: Retained<NSMenu>,
    target: Retained<Target>,
    _events: Task<()>,
}

impl Drop for StatusItem {
    fn drop(&mut self) {
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
        EVENTS.with(|events| events.borrow_mut().take());
        RUNS.with(|runs| runs.borrow_mut().clear());
    }
}

impl StatusItem {
    /// Puts an item in the menu bar, calling `opened` as its menu opens
    /// (true) and closes (false). `None` off the main thread.
    pub fn install(tooltip: &str, opened: impl Fn(bool, &mut App) + 'static, cx: &mut App) -> Option<StatusItem> {
        let mtm = MainThreadMarker::new()?;
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        if let Some(button) = item.button(mtm) {
            button.setToolTip(Some(&NSString::from_str(tooltip)));
        }
        let menu = NSMenu::new(mtm);
        menu.setAutoenablesItems(false);
        // SAFETY: `init` on a fresh instance of a class with no fields.
        let target: Retained<Target> = unsafe { msg_send![Target::alloc(mtm), init] };
        // The menu holds its delegate weakly; `target` lives as long.
        menu.setDelegate(Some(ProtocolObject::from_ref(&*target)));
        item.setMenu(Some(&menu));

        let (events, mut received) = unbounded::<Event>();
        EVENTS.with(|slot| *slot.borrow_mut() = Some(events));
        let events = cx.spawn(async move |cx| {
            while let Some(event) = received.next().await {
                match event {
                    Event::Chosen(run) => cx.update(|cx| run(cx)),
                    Event::Opened(open) => cx.update(|cx| opened(open, cx)),
                }
            }
        });
        Some(StatusItem {
            item,
            menu,
            target,
            _events: events,
        })
    }

    /// Shows `pdf` (or any image AppKit reads) as a template image, which
    /// the menu bar tints for its appearance, and `accessible` as its name.
    pub fn set_image(&self, image: &[u8], accessible: &str) {
        let Some(mtm) = MainThreadMarker::new() else { return };
        let Some(button) = self.item.button(mtm) else { return };
        let data = NSData::with_bytes(image);
        if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
            image.setSize(NSSize::new(18.0, 18.0));
            image.setTemplate(true);
            image.setAccessibilityDescription(Some(&NSString::from_str(accessible)));
            button.setImage(Some(&image));
        }
    }

    /// Replaces the menu with `entries`, in place when the shape matches.
    pub fn set_menu(&self, entries: Vec<Entry>) {
        let Some(mtm) = MainThreadMarker::new() else { return };
        let mut runs = Vec::new();
        if same_shape(&self.menu, &entries) {
            self.update(&self.menu, entries, &mut runs);
        } else {
            self.menu.removeAllItems();
            self.fill(&self.menu, entries, &mut runs, mtm);
        }
        RUNS.with(|slot| *slot.borrow_mut() = runs);
    }

    fn fill(&self, menu: &NSMenu, entries: Vec<Entry>, runs: &mut Vec<Run>, mtm: MainThreadMarker) {
        for entry in entries {
            let item = match entry {
                Entry::Separator => NSMenuItem::separatorItem(mtm),
                Entry::Header(title) => NSMenuItem::sectionHeaderWithTitle(&NSString::from_str(&title), mtm),
                Entry::Item(mut entry) => {
                    // SAFETY: a menu item with no action yet; `apply` sets
                    // the one this item's target answers.
                    let item = unsafe {
                        NSMenuItem::initWithTitle_action_keyEquivalent(
                            NSMenuItem::alloc(mtm),
                            &NSString::from_str(&entry.title),
                            None,
                            &NSString::from_str(entry.key),
                        )
                    };
                    if let Some(entries) = entry.submenu.take() {
                        let sub = NSMenu::new(mtm);
                        sub.setAutoenablesItems(false);
                        self.fill(&sub, entries, runs, mtm);
                        item.setSubmenu(Some(&sub));
                    }
                    self.apply(&item, entry, runs);
                    item
                }
            };
            menu.addItem(&item);
        }
    }

    fn update(&self, menu: &NSMenu, entries: Vec<Entry>, runs: &mut Vec<Run>) {
        for (item, entry) in menu.itemArray().iter().zip(entries) {
            match entry {
                Entry::Separator => {}
                Entry::Header(title) => item.setTitle(&NSString::from_str(&title)),
                Entry::Item(mut entry) => {
                    if let (Some(entries), Some(sub)) = (entry.submenu.take(), item.submenu()) {
                        self.update(&sub, entries, runs);
                    }
                    self.apply(&item, entry, runs);
                }
            }
        }
    }

    fn apply(&self, item: &NSMenuItem, entry: Item, runs: &mut Vec<Run>) {
        item.setTitle(&NSString::from_str(&entry.title));
        item.setSubtitle(entry.subtitle.as_deref().map(NSString::from_str).as_deref());
        item.setBadge(
            entry
                .badge
                .as_deref()
                .map(|b| NSMenuItemBadge::initWithString(NSMenuItemBadge::alloc(), &NSString::from_str(b)))
                .as_deref(),
        );
        item.setImage(
            entry
                .symbol
                .and_then(|s| NSImage::imageWithSystemSymbolName_accessibilityDescription(&NSString::from_str(s), None))
                .as_deref(),
        );
        item.setEnabled(entry.enabled);
        item.setState(if entry.checked {
            NSControlStateValueOn
        } else {
            NSControlStateValueOff
        });
        if !entry.key.is_empty() {
            item.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
        }
        match entry.run {
            Some(run) => {
                item.setTag(runs.len() as isize);
                runs.push(run);
                let target: &AnyObject = self.target.as_ref();
                // SAFETY: the target answers `chosen:` and outlives the menu.
                unsafe {
                    item.setTarget(Some(target));
                    item.setAction(Some(sel!(chosen:)));
                }
            }
            None => {
                item.setTag(-1);
                // SAFETY: clearing the action leaves nothing to call.
                unsafe {
                    item.setTarget(None);
                    item.setAction(None);
                }
            }
        }
    }
}

/// Whether `entries` would lay out as `menu` does: the same kinds of entry
/// in the same places, submenus included.
fn same_shape(menu: &NSMenu, entries: &[Entry]) -> bool {
    let items = menu.itemArray();
    items.len() == entries.len()
        && items.iter().zip(entries).all(|(item, entry)| match entry {
            Entry::Separator => item.isSeparatorItem(),
            Entry::Header(_) => item.isSectionHeader(),
            Entry::Item(entry) => {
                !item.isSeparatorItem()
                    && !item.isSectionHeader()
                    && item.keyEquivalent().to_string() == entry.key
                    && match (&entry.submenu, item.submenu()) {
                        (None, None) => true,
                        (Some(entries), Some(sub)) => same_shape(&sub, entries),
                        _ => false,
                    }
            }
        })
}
