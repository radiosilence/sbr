//! A menu bar item: a template image and a menu of entries, each chosen
//! entry answered by a closure on GPUI's side. GPUI has no status item, so
//! this is AppKit's `NSStatusItem`. It knows nothing of sbr, so it can move
//! into koan-kit as it stands.

use std::cell::RefCell;
use std::rc::Rc;

use futures::StreamExt as _;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use koan_kit::app::*;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{AnyThread, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSControlStateValueOff, NSControlStateValueOn, NSEventModifierFlags, NSImage, NSMenu, NSMenuItem, NSStatusBar,
    NSStatusItem, NSVariableStatusItemLength,
};
use objc2_foundation::{NSData, NSSize, NSString};

/// What an entry does when chosen.
pub type Run = Rc<dyn Fn(&mut App)>;

/// One line of the menu.
pub enum Entry {
    /// Text that cannot be chosen: a status line.
    Label(String),
    Action {
        title: String,
        enabled: bool,
        /// Shown with a check mark: a toggle that is on, the chosen option.
        checked: bool,
        /// A key that chooses it with Command held while the menu is open.
        key: &'static str,
        run: Run,
    },
    Submenu {
        title: String,
        entries: Vec<Entry>,
    },
    Separator,
}

impl Entry {
    pub fn action(title: impl Into<String>, run: impl Fn(&mut App) + 'static) -> Entry {
        Entry::Action {
            title: title.into(),
            enabled: true,
            checked: false,
            key: "",
            run: Rc::new(run),
        }
    }

    pub fn enabled(mut self, on: bool) -> Entry {
        if let Entry::Action { enabled, .. } = &mut self {
            *enabled = on;
        }
        self
    }

    pub fn checked(mut self, on: bool) -> Entry {
        if let Entry::Action { checked, .. } = &mut self {
            *checked = on;
        }
        self
    }

    pub fn key(mut self, k: &'static str) -> Entry {
        if let Entry::Action { key, .. } = &mut self {
            *key = k;
        }
        self
    }
}

thread_local! {
    /// The current menu's closures, by the tag of their item, and where
    /// a chosen tag goes: the task that runs it on GPUI's side.
    static RUNS: RefCell<Vec<Run>> = const { RefCell::new(Vec::new()) };
    static CHOSEN: RefCell<Option<UnboundedSender<usize>>> = const { RefCell::new(None) };
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
            let tag = item.tag();
            if tag < 0 {
                return;
            }
            CHOSEN.with(|chosen| {
                if let Some(chosen) = &*chosen.borrow() {
                    chosen.unbounded_send(tag as usize).ok();
                }
            });
        }
    }
);

/// The item, while it is in the menu bar; dropped, it leaves it.
pub struct StatusItem {
    item: Retained<NSStatusItem>,
    menu: Retained<NSMenu>,
    target: Retained<Target>,
    _answers: Task<()>,
}

impl Drop for StatusItem {
    fn drop(&mut self) {
        NSStatusBar::systemStatusBar().removeStatusItem(&self.item);
        CHOSEN.with(|chosen| chosen.borrow_mut().take());
        RUNS.with(|runs| runs.borrow_mut().clear());
    }
}

impl StatusItem {
    /// Puts an item in the menu bar. `None` off the main thread.
    pub fn install(tooltip: &str, cx: &mut App) -> Option<StatusItem> {
        let mtm = MainThreadMarker::new()?;
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        if let Some(button) = item.button(mtm) {
            button.setToolTip(Some(&NSString::from_str(tooltip)));
        }
        let menu = NSMenu::new(mtm);
        menu.setAutoenablesItems(false);
        item.setMenu(Some(&menu));
        // SAFETY: `init` on a fresh instance of a class with no fields.
        let target: Retained<Target> = unsafe { msg_send![Target::alloc(mtm), init] };

        let (chosen, mut choices) = unbounded::<usize>();
        CHOSEN.with(|slot| *slot.borrow_mut() = Some(chosen));
        let answers = cx.spawn(async move |cx| {
            while let Some(tag) = choices.next().await {
                let run = RUNS.with(|runs| runs.borrow().get(tag).cloned());
                if let Some(run) = run {
                    cx.update(|cx| run(cx));
                }
            }
        });
        Some(StatusItem {
            item,
            menu,
            target,
            _answers: answers,
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

    /// Replaces the menu with `entries`.
    pub fn set_menu(&self, entries: Vec<Entry>) {
        let Some(mtm) = MainThreadMarker::new() else { return };
        let mut runs = Vec::new();
        self.menu.removeAllItems();
        self.fill(&self.menu, entries, &mut runs, mtm);
        RUNS.with(|slot| *slot.borrow_mut() = runs);
    }

    fn fill(&self, menu: &NSMenu, entries: Vec<Entry>, runs: &mut Vec<Run>, mtm: MainThreadMarker) {
        for entry in entries {
            match entry {
                Entry::Separator => menu.addItem(&NSMenuItem::separatorItem(mtm)),
                Entry::Label(text) => {
                    let item = self.item_for(&text, None, "", mtm);
                    item.setEnabled(false);
                    menu.addItem(&item);
                }
                Entry::Action {
                    title,
                    enabled,
                    checked,
                    key,
                    run,
                } => {
                    let item = self.item_for(&title, Some(sel!(chosen:)), key, mtm);
                    item.setTag(runs.len() as isize);
                    item.setEnabled(enabled);
                    item.setState(if checked {
                        NSControlStateValueOn
                    } else {
                        NSControlStateValueOff
                    });
                    if !key.is_empty() {
                        item.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
                    }
                    runs.push(run);
                    menu.addItem(&item);
                }
                Entry::Submenu { title, entries } => {
                    let item = self.item_for(&title, None, "", mtm);
                    let sub = NSMenu::new(mtm);
                    sub.setAutoenablesItems(false);
                    self.fill(&sub, entries, runs, mtm);
                    item.setSubmenu(Some(&sub));
                    menu.addItem(&item);
                }
            }
        }
    }

    fn item_for(
        &self,
        title: &str,
        action: Option<objc2::runtime::Sel>,
        key: &str,
        mtm: MainThreadMarker,
    ) -> Retained<NSMenuItem> {
        // SAFETY: a menu item with a title, an action this item's target
        // answers, and a key equivalent; the target outlives the menu.
        unsafe {
            let item = NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                action,
                &NSString::from_str(key),
            );
            if action.is_some() {
                let target: &AnyObject = self.target.as_ref();
                item.setTarget(Some(target));
            }
            item
        }
    }
}
