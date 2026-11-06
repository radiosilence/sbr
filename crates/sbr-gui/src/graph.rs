//! Throughput over the last two minutes, drawn on the GPU: download as a
//! filled area in the accent under its line, upload as a line in `ink`
//! mirrored below the axis, on a scale that rounds up to a readable step.

use koan_kit::app::*;
use koan_kit::raw::{Hsla, PathBuilder, canvas, point, px};
use koan_kit::theme::Look;

use crate::tunnel::{HISTORY, Sample};

/// Bytes a second the scale never goes below, so an idle tunnel draws flat.
const FLOOR: f64 = 64.0 * 1024.0;

/// The scale's top for `peak`: 1, 2 or 5 times a power of ten.
pub fn scale_for(peak: f64) -> f64 {
    let peak = peak.max(FLOOR);
    let mut step = 10f64.powf(peak.log10().floor());
    for m in [1.0, 2.0, 5.0, 10.0] {
        if step * m >= peak {
            step *= m;
            break;
        }
    }
    step
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

/// The throughput graph: download above the axis, upload below it, each on
/// the same scale, newest at the right.
pub fn throughput(samples: Vec<Sample>, look: Look, height: f32) -> impl IntoElement {
    let down_peak = samples.iter().map(|s| s.down).fold(0.0, f64::max);
    let up_peak = samples.iter().map(|s| s.up).fold(0.0, f64::max);
    let scale = scale_for(down_peak.max(up_peak));
    let accent = look.color(koan_kit::theme::Tone::Accent);
    let ink = look.color(koan_kit::theme::Tone::Ink);
    let rule = look.palette.rule.hsla();
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let (w, h) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
            let axis = h * 0.62;
            let at = |i: usize, v: f64, below: bool| {
                let x = w * (i + HISTORY - samples.len()) as f32 / (HISTORY - 1) as f32;
                let reach = if below { h - axis } else { axis };
                let y = (v / scale).min(1.0) as f32 * reach * 0.94;
                bounds.origin + point(px(x), px(if below { axis + y } else { axis - y }))
            };

            // Quarter rules above the axis, and the axis itself.
            for q in 1..=4 {
                let y = axis - axis * 0.94 * q as f32 / 4.0;
                let mut b = PathBuilder::stroke(px(1.0)).dash_array(&[px(2.0), px(4.0)]);
                b.move_to(bounds.origin + point(px(0.0), px(y)));
                b.line_to(bounds.origin + point(px(w), px(y)));
                if let Ok(p) = b.build() {
                    window.paint_path(p, rule);
                }
            }
            let mut b = PathBuilder::stroke(look.hairline);
            b.move_to(bounds.origin + point(px(0.0), px(axis)));
            b.line_to(bounds.origin + point(px(w), px(axis)));
            if let Ok(p) = b.build() {
                window.paint_path(p, rule);
            }

            if samples.len() < 2 {
                return;
            }
            area(window, &samples, |s| s.down, false, &at, accent.opacity(0.22));
            line(window, &samples, |s| s.down, false, &at, accent, 1.6);
            area(window, &samples, |s| s.up, true, &at, ink.opacity(0.12));
            line(window, &samples, |s| s.up, true, &at, ink, 1.2);
        },
    )
    .w_full()
    .h(px(height))
}

type At<'a> = &'a dyn Fn(usize, f64, bool) -> koan_kit::app::Point<koan_kit::app::Pixels>;

fn area(window: &mut Window, samples: &[Sample], value: impl Fn(&Sample) -> f64, below: bool, at: At, color: Hsla) {
    let mut b = PathBuilder::fill();
    let first = at(0, 0.0, below);
    b.move_to(first);
    for (i, s) in samples.iter().enumerate() {
        b.line_to(at(i, value(s), below));
    }
    b.line_to(at(samples.len() - 1, 0.0, below));
    b.close();
    if let Ok(p) = b.build() {
        window.paint_path(p, color);
    }
}

fn line(
    window: &mut Window,
    samples: &[Sample],
    value: impl Fn(&Sample) -> f64,
    below: bool,
    at: At,
    color: Hsla,
    width: f32,
) {
    let mut b = PathBuilder::stroke(px(width));
    for (i, s) in samples.iter().enumerate() {
        let p = at(i, value(s), below);
        if i == 0 {
            b.move_to(p);
        } else {
            b.line_to(p);
        }
    }
    if let Ok(p) = b.build() {
        window.paint_path(p, color);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_rounds_up_to_one_two_five() {
        assert_eq!(scale_for(0.0), 100_000.0);
        assert_eq!(scale_for(150_000.0), 200_000.0);
        assert_eq!(scale_for(3_000_000.0), 5_000_000.0);
        assert_eq!(scale_for(7_000_000.0), 10_000_000.0);
    }

    #[test]
    fn bytes_read_as_people_do() {
        assert_eq!(bytes(512.0), "512 B");
        assert_eq!(bytes(12_400_000.0), "12.4 MB");
        assert_eq!(bytes(250_000.0), "250 KB");
    }
}
