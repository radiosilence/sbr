//! Plots drawn on the GPU: throughput over the last two minutes on a scale
//! that rounds up to a readable step, and the gauges' trends.

use koan_kit::app::*;
use koan_kit::raw::{Hsla, PathBuilder, canvas, point, px};
use koan_kit::theme::{KoanStyled, Look, Space, Tone, TypeRole};

use crate::tunnel::{HISTORY, Sample};

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

/// A series on a plot: its values, oldest first, and how it is drawn.
pub struct Series {
    pub values: Vec<f64>,
    pub fill: Hsla,
    pub stroke: Hsla,
    pub width: f32,
}

/// Series over one baseline, newest at the right edge, `slots` wide: a
/// shorter series starts partway across, as a fresh tunnel's history does.
/// Values at `scale` reach the top; `rules` draws quarter rules under them.
pub fn plot(
    series: Vec<Series>,
    scale: f64,
    slots: usize,
    rules: bool,
    rule: Hsla,
    height: Pixels,
) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let (w, h) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
            let span = slots.max(2) - 1;
            if rules {
                for q in 1..=4 {
                    let y = h - h * q as f32 / 4.0 + 0.5;
                    let mut b = PathBuilder::stroke(px(1.0)).dash_array(&[px(2.0), px(4.0)]);
                    b.move_to(bounds.origin + point(px(0.0), px(y)));
                    b.line_to(bounds.origin + point(px(w), px(y)));
                    if let Ok(p) = b.build() {
                        window.paint_path(p, rule);
                    }
                }
            }
            let mut b = PathBuilder::stroke(px(1.0));
            b.move_to(bounds.origin + point(px(0.0), px(h - 0.5)));
            b.line_to(bounds.origin + point(px(w), px(h - 0.5)));
            if let Ok(p) = b.build() {
                window.paint_path(p, rule);
            }
            for s in &series {
                let n = s.values.len();
                if n < 2 {
                    continue;
                }
                let at = |i: usize, v: f64| {
                    let x = w * (i + span + 1 - n.min(span + 1)) as f32 / span as f32;
                    let y = h - (v / scale).clamp(0.0, 1.0) as f32 * h;
                    bounds.origin + point(px(x), px(y))
                };
                let skip = n.saturating_sub(span + 1);
                let values = &s.values[skip..];
                let mut fill = PathBuilder::fill();
                fill.move_to(at(0, 0.0));
                for (i, v) in values.iter().enumerate() {
                    fill.line_to(at(i, *v));
                }
                fill.line_to(at(values.len() - 1, 0.0));
                fill.close();
                if let Ok(p) = fill.build() {
                    window.paint_path(p, s.fill);
                }
                let mut line = PathBuilder::stroke(px(s.width));
                for (i, v) in values.iter().enumerate() {
                    if i == 0 {
                        line.move_to(at(i, *v));
                    } else {
                        line.line_to(at(i, *v));
                    }
                }
                if let Ok(p) = line.build() {
                    window.paint_path(p, s.stroke);
                }
            }
        },
    )
    .w_full()
    .h(height)
}

/// Throughput over the last two minutes: download in the accent, upload in
/// `ink` in front of it, on a scale named at its top left.
pub fn throughput(samples: &[Sample], look: Look, height: Pixels) -> impl IntoElement {
    let peak = samples.iter().map(|s| s.down.max(s.up)).fold(0.0, f64::max);
    let scale = scale_for(peak);
    let accent = look.color(Tone::Accent);
    let ink = look.color(Tone::Ink);
    let muted = look.text_color(Tone::Muted);
    let note = |s: String| div().text_role(TypeRole::Fine, &look).text_color(muted).child(s);
    div()
        .flex()
        .flex_col()
        .gap(look.space(Space::Xs))
        .child(note(rate(scale)))
        .child(plot(
            vec![
                Series {
                    values: samples.iter().map(|s| s.down).collect(),
                    fill: accent.opacity(0.18),
                    stroke: accent,
                    width: 1.6,
                },
                Series {
                    values: samples.iter().map(|s| s.up).collect(),
                    fill: ink.opacity(0.10),
                    stroke: ink.opacity(0.8),
                    width: 1.2,
                },
            ],
            scale,
            HISTORY,
            true,
            look.palette.rule.hsla(),
            height,
        ))
        .child(
            div()
                .flex()
                .justify_between()
                .child(note("2 min".into()))
                .child(note("now".into())),
        )
}

/// A gauge's trend: one series filling its box, scaled between its own
/// least and greatest values so a figure that moves little still shows its
/// shape.
pub fn trend(values: Vec<f64>, look: Look, height: Pixels) -> impl IntoElement {
    let lo = values.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = values.iter().copied().fold(0.0, f64::max);
    let base = if lo.is_finite() {
        (lo - (hi - lo) * 0.4).max(0.0)
    } else {
        0.0
    };
    let values: Vec<f64> = values.iter().map(|v| v - base).collect();
    let peak = ((hi - base) * 1.1).max(f64::EPSILON);
    let accent = look.color(Tone::Accent);
    plot(
        vec![Series {
            values,
            fill: accent.opacity(0.14),
            stroke: accent,
            width: 1.2,
        }],
        peak,
        HISTORY,
        false,
        look.palette.rule.hsla(),
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_rounds_up_to_a_readable_step() {
        assert_eq!(scale_for(0.0), 100_000.0);
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
