//! The tunnel's figures as koan-kit charts: throughput over the last two
//! minutes on a scale that rounds up to a readable step, and the gauges'
//! trends, each scrolling a sample in at every poll.

use std::collections::VecDeque;
use std::sync::Arc;

use koan_kit::app::*;
use koan_kit::components::{Axis, Base, Chart, DataMotion, Series, Ticks};
use koan_kit::raw::{Hsla, Pixels};
use koan_kit::theme::{KoanStyled, Look, Space, Tone, TypeRole};

use crate::tunnel::{HISTORY, POLL, Sample};

/// Bytes a second the scale never goes below, so an idle tunnel draws flat.
const FLOOR: f64 = 64.0 * 1024.0;

/// The scale's top for `peak`: the next of 1, 1.5, 2, 3, 4, 5, 6 or 8 times
/// a power of ten, so the tallest peak fills most of the height.
pub fn scale_for(peak: f64) -> f64 {
    let peak = peak.max(FLOOR);
    let decade = 10f64.powf(peak.log10().floor());
    [1.0, 1.5, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0]
        .into_iter()
        .map(|m| m * decade)
        .find(|top| *top >= peak)
        .unwrap_or(decade * 10.0)
}

/// A rate as people read it, in bytes.
pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec))
}

pub fn bytes(b: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b.max(0.0);
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 || v >= 100.0 {
        format!("{v:.0} {}", UNITS[u])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// The x of each of the last `n` samples: slots on a fixed axis of
/// `HISTORY`, the newest at the right edge, so a fresh tunnel's short
/// history starts partway across.
fn slots(n: usize) -> Arc<[f64]> {
    let n = n.min(HISTORY);
    ((HISTORY - n)..HISTORY).map(|i| i as f64).collect()
}

fn last(values: impl Iterator<Item = f64>) -> Arc<[f64]> {
    let values: Vec<f64> = values.collect();
    values[values.len().saturating_sub(HISTORY)..].into()
}

/// A line and the area under it down to `floor`, scrolling at the poll.
fn trace(id: &str, xs: &Arc<[f64]>, ys: &Arc<[f64]>, floor: f64, colour: Hsla, fill: f32, width: f32) -> [Series; 2] {
    [
        Series::area(format!("{id}-fill"), xs.clone(), ys.clone())
            .base(Base::Level(floor))
            .color(colour.opacity(fill))
            .motion(DataMotion::Scroll(POLL)),
        Series::line(id.to_owned(), xs.clone(), ys.clone())
            .width(width)
            .color(colour)
            .motion(DataMotion::Scroll(POLL)),
    ]
}

/// Throughput: download in the accent, upload in `ink` in front of it, under
/// quarter rules, its scale named above and its span below.
pub fn throughput(samples: &VecDeque<Sample>, look: Look, height: Pixels) -> impl IntoElement {
    let peak = samples.iter().map(|s| s.down.max(s.up)).fold(0.0, f64::max);
    let top = scale_for(peak);
    let xs = slots(samples.len());
    let down = last(samples.iter().map(|s| s.down));
    let up = last(samples.iter().map(|s| s.up));
    let chart = Chart::new(
        "throughput",
        Axis::linear(0.0, (HISTORY - 1) as f64).no_labels().no_grid(),
        Axis::linear(0.0, top).ticks(Ticks::Every(top / 4.0)).no_labels(),
    )
    .height(height)
    .series(trace("down", &xs, &down, 0.0, look.color(Tone::Accent), 0.18, 1.75))
    .series(trace(
        "up",
        &xs,
        &up,
        0.0,
        look.color(Tone::Ink).opacity(0.8),
        0.10,
        1.4,
    ));
    let muted = look.text_color(Tone::Muted);
    let note = |s: String| div().text_role(TypeRole::Fine, &look).text_color(muted).child(s);
    div()
        .flex()
        .flex_col()
        .gap(look.space(Space::Xs))
        .child(note(rate(top)))
        .child(chart)
        .child(
            div()
                .flex()
                .justify_between()
                .child(note("2 min".into()))
                .child(note("now".into())),
        )
}

/// A gauge's line, scaled between its own least and greatest values so a
/// figure that moves little still shows its shape.
pub fn trend(id: &str, values: Vec<f64>, look: &Look, height: Pixels) -> impl IntoElement {
    let lo = values.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = values.iter().copied().fold(0.0, f64::max);
    let base = if lo.is_finite() {
        (lo - (hi - lo) * 0.4).max(0.0)
    } else {
        0.0
    };
    let top = (base + (hi - base) * 1.1).max(base + f64::EPSILON);
    let ys = last(values.into_iter());
    Chart::new(
        SharedString::from(format!("trend-{id}")),
        Axis::linear(0.0, (HISTORY - 1) as f64).no_labels().no_grid(),
        Axis::linear(base, top).no_labels().no_grid(),
    )
    .height(height)
    .series(trace(
        id,
        &slots(ys.len()),
        &ys,
        base,
        look.color(Tone::Accent),
        0.14,
        1.2,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_rounds_up_to_a_readable_step() {
        assert_eq!(scale_for(0.0), 80_000.0);
        assert_eq!(scale_for(140_000.0), 150_000.0);
        assert_eq!(scale_for(2_500_000.0), 3_000_000.0);
        assert_eq!(scale_for(9_000_000.0), 10_000_000.0);
    }

    #[test]
    fn bytes_read_as_people_do() {
        assert_eq!(bytes(512.0), "512 B");
        assert_eq!(bytes(12_400_000.0), "12.4 MB");
        assert_eq!(bytes(250_000.0), "250 KB");
    }
}
