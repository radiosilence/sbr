use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_core::{BoxFuture, Destination, Stream};

use super::Outbound;

pub struct Selector {
    tag: String,
    kind: &'static str,
    members: Vec<Arc<dyn Outbound>>,
    selected: AtomicUsize,
}

impl Selector {
    pub fn new(
        tag: String,
        kind: &'static str,
        members: Vec<Arc<dyn Outbound>>,
        default: Option<&str>,
    ) -> Self {
        let selected = default
            .and_then(|d| members.iter().position(|m| m.tag() == d))
            .unwrap_or(0);
        Self {
            tag,
            kind,
            members,
            selected: AtomicUsize::new(selected),
        }
    }

    pub fn members(&self) -> impl Iterator<Item = &str> {
        self.members.iter().map(|m| m.tag())
    }

    pub fn selected(&self) -> &str {
        self.members[self.selected.load(Ordering::Relaxed)].tag()
    }

    /// Switch the active member. Existing connections are left alone.
    pub fn select(&self, tag: &str) -> bool {
        match self.members.iter().position(|m| m.tag() == tag) {
            Some(i) => {
                self.selected.store(i, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}

impl Outbound for Selector {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn connect<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<Stream>> {
        let member = self.members[self.selected.load(Ordering::Relaxed)].clone();
        Box::pin(async move { member.connect(dest).await })
    }
    fn as_selector(&self) -> Option<&Selector> {
        Some(self)
    }
}
