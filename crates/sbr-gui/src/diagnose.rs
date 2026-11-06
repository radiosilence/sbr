//! End-to-end checks run from the app, so their traffic takes the same path
//! as any other app's: system, tunnel, sbr, server. A port of Diagnose.swift
//! for what Rust reaches without URLSession: DNS, an HTTPS request, the
//! exit address and an IPv6 leak check. QUIC, the bulk download and the
//! system-resolver check need URLSession's metrics or libresolv and are
//! not run here.

use std::net::ToSocketAddrs;
use std::time::Instant;

use koan_kit::app::*;

const PROBE: &str = "https://www.gstatic.com/generate_204";
/// Cloudflare's plain-text trace: the address and country a request
/// arrived from.
const TRACE: &str = "https://speed.cloudflare.com/cdn-cgi/trace";
/// The same trace on an IPv6 literal, so the request has no IPv4 path to
/// fall back to.
const TRACE6: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";

#[derive(Clone, Debug, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub detail: String,
    /// None while running, or for a note rather than a verdict.
    pub ok: Option<bool>,
    pub done: bool,
}

#[derive(Default)]
pub struct Diagnose {
    pub checks: Vec<Check>,
    pub running: bool,
}

type Outcome = (Option<bool>, String);

impl Diagnose {
    /// `config` is the active profile, whose tun inbound says where IPv6
    /// should go. The leak checks run only while connected.
    pub fn run(&mut self, connected: bool, config: Option<String>, cx: &mut Context<Self>) {
        if self.running {
            return;
        }
        self.running = true;
        let mut names = vec!["dns", "https"];
        if connected {
            names.extend(["exit address", "ipv6", "webrtc"]);
        }
        self.checks = names
            .iter()
            .map(|name| Check {
                name,
                detail: "…".into(),
                ok: None,
                done: false,
            })
            .collect();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let plan = config.as_deref().and_then(sbr_apple::app::tun_plan);
            for (i, name) in names.into_iter().enumerate() {
                let plan = plan.clone();
                let outcome = cx
                    .background_spawn(async move { run_check(name, plan.as_ref()) })
                    .await;
                let alive = this.update(cx, |d, cx| {
                    if let Some(c) = d.checks.get_mut(i) {
                        (c.ok, c.detail) = outcome;
                        c.done = true;
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    return;
                }
            }
            let _ = this.update(cx, |d, cx| {
                d.running = false;
                cx.notify();
            });
        })
        .detach();
    }
}

fn ms(start: Instant) -> String {
    format!("{} ms", start.elapsed().as_millis())
}

fn run_check(name: &str, plan: Option<&sbr_apple::app::TunPlan>) -> Outcome {
    let start = Instant::now();
    match name {
        "dns" => match ("www.google.com", 443).to_socket_addrs() {
            Ok(addrs) => {
                let n = addrs.count();
                let s = if n == 1 { "" } else { "es" };
                (Some(true), format!("{n} address{s} · {}", ms(start)))
            }
            Err(e) => (Some(false), format!("{} · {}", e.to_string().to_lowercase(), ms(start))),
        },
        "https" => match sbr_apple::app::get(PROBE, 64 * 1024) {
            Ok(_) => (Some(true), format!("http/1.1 · {}", ms(start))),
            Err(e) => (Some(false), format!("{} · {}", e.to_lowercase(), ms(start))),
        },
        "exit address" => match trace(TRACE) {
            Ok((ip, loc)) => (Some(true), format!("{ip} · {}", loc.to_lowercase())),
            Err(e) => (Some(false), e),
        },
        "ipv6" => {
            // Without a real IPv6 address on the tun, the tunnel claims ::/0
            // only to refuse it, so any IPv6 answer came by another route.
            let carried = plan.is_some_and(|p| !p.ipv6_addresses.is_empty());
            match trace(TRACE6) {
                Err(_) => (Some(true), "no ipv6 route, so none leaves outside the tunnel".into()),
                Ok((ip, _)) if carried => (Some(true), format!("via the tunnel as {ip}")),
                Ok((ip, _)) => (Some(false), format!("reached the internet outside the tunnel as {ip}")),
            }
        }
        "webrtc" => (
            None,
            if plan.is_some_and(|p| p.routes_all_ipv4) {
                "not testable in the app. all traffic is routed through the tunnel, so browsers' webrtc is too".into()
            } else {
                "the profile routes only some addresses through the tunnel, so webrtc may bypass it".into()
            },
        ),
        _ => (None, String::new()),
    }
}

fn trace(url: &str) -> Result<(String, String), String> {
    let body = sbr_apple::app::get(url, 64 * 1024).map_err(|e| e.to_lowercase())?;
    parse_trace(&body).ok_or_else(|| "unexpected reply".into())
}

/// `ip` and `loc` from a `key=value` trace.
fn parse_trace(body: &str) -> Option<(String, String)> {
    let field = |k: &str| {
        body.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('=').map(str::to_owned))
    };
    Some((field("ip")?, field("loc").unwrap_or_else(|| "?".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traces_parse() {
        let body = "fl=1\nh=speed.cloudflare.com\nip=203.0.113.9\nts=1\nloc=GB\n";
        assert_eq!(parse_trace(body), Some(("203.0.113.9".into(), "GB".into())));
        assert_eq!(parse_trace("nothing"), None);
    }
}
