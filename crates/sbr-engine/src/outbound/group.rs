use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sbr_core::{BoxFuture, BoxPacketConn, Destination, Group, Outbound, Stream};

pub struct Selector {
    tag: String,
    kind: &'static str,
    members: Vec<Arc<dyn Outbound>>,
    selected: AtomicUsize,
}

impl Selector {
    pub fn new(tag: String, kind: &'static str, members: Vec<Arc<dyn Outbound>>, default: Option<&str>) -> Self {
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

    fn current(&self) -> Arc<dyn Outbound> {
        self.members[self.selected.load(Ordering::Relaxed)].clone()
    }
}

impl Group for Selector {
    fn members(&self) -> Vec<Arc<dyn Outbound>> {
        self.members.clone()
    }
    fn selected(&self) -> Arc<dyn Outbound> {
        self.current()
    }
    /// Switch the active member. Existing connections are left alone.
    fn select(&self, tag: &str) -> bool {
        if self.kind != "selector" {
            return false;
        }
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
        let member = self.current();
        Box::pin(async move { member.connect(dest).await })
    }
    fn connect_udp<'a>(&'a self, dest: &'a Destination) -> BoxFuture<'a, io::Result<BoxPacketConn>> {
        let member = self.current();
        Box::pin(async move { member.connect_udp(dest).await })
    }
    fn as_group(&self) -> Option<&dyn Group> {
        Some(self)
    }
}
