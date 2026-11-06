//! Plots drawn on the GPU: throughput over the last two minutes on a scale
//! that rounds up to a readable step, and the gauges' trends.

use koan_kit::app::*;
use koan_kit::raw::{Hsla, PathBuilder, canvas, point, px};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use koan_kit::app::image::RenderImage;
use koan_kit::components::{Animated, AnimatedQuad, Ease, Repeat, ShaderProgram};
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

/// The throughput curves, drawn by the GPU from a texture of samples: row 0
/// download, row 1 upload, each sample 16 bits as a fraction of `u[2]`, its
/// high byte in red and blue (so either channel order reads alike) and its
/// low byte in green. Texels are read at their centres, so the linear
/// sampler returns them exactly; the program interpolates between them.
///
/// Uniforms: 0 samples in the texture, 1 samples across the plot, 2 the
/// bytes a second a texel's full value stands for, 3 device pixels a point,
/// 4..8 and 8..12 the two curves' colours, 12..14 their fills' opacity,
/// 14..16 their strokes' width in points. Track 0 scrolls the newest sample
/// in from the right edge, 0 to 1 over one poll; track 1 is the scale's top.
static CURVES: ShaderProgram = ShaderProgram {
    name: "sbr-throughput",
    msl: r#"
float sbr_value(texture2d<float> image, float4 tile, float i, float row, float n) {
    float4 c = koan_sample(image, tile, float2((i + 0.5) / n, (row + 0.5) / 2.0));
    return (round(c.r * 255.0) * 256.0 + round(c.g * 255.0)) / 65535.0;
}

float4 shade(float2 position, float2 size, float time, constant float *u, texture2d<float> image, float4 tile) {
    float n = u[0];
    float slots = u[1];
    if (n < 2.0) {
        return float4(0.0);
    }
    float phase = clamp(koan_track(u, 0, time), 0.0, 1.0);
    float k = u[2] / max(koan_track(u, 1, time), 1.0);
    float step = size.x / (slots - 1.0);
    float f = position.x / step + (n - 1.0) - (slots - 1.0) - (1.0 - phase);
    if (f < 0.0) {
        return float4(0.0);
    }
    f = min(f, n - 1.0);
    float i0 = floor(f);
    float i1 = min(i0 + 1.0, n - 1.0);
    float t = f - i0;
    float4 out = float4(0.0);
    for (int row = 0; row < 2; row++) {
        float a = sbr_value(image, tile, i0, float(row), n) * k;
        float b = sbr_value(image, tile, i1, float(row), n) * k;
        float y = size.y * (1.0 - clamp(mix(a, b, t), 0.0, 1.0));
        float slope = (b - a) * size.y / step;
        float dist = abs(position.y - y) / sqrt(1.0 + slope * slope);
        float4 colour = row == 0 ? float4(u[4], u[5], u[6], u[7]) : float4(u[8], u[9], u[10], u[11]);
        float fill = clamp(position.y - y + 0.5, 0.0, 1.0) * u[12 + row];
        float line = clamp(u[14 + row] * u[3] * 0.5 - dist + 0.5, 0.0, 1.0);
        float alpha = colour.a * max(fill, line);
        float over = alpha + out.a * (1.0 - alpha);
        if (over > 0.0) {
            out.rgb = (colour.rgb * alpha + out.rgb * out.a * (1.0 - alpha)) / over;
        }
        out.a = over;
    }
    return out;
}
"#,
    // sbr-gui runs on Metal alone; wgpu never compiles this.
    wgsl: r#"
fn shade(position: vec2<f32>, size: vec2<f32>, time: f32, u: array<vec4<f32>, 20>, tile: vec4<f32>) -> vec4<f32> {
    return vec4<f32>(0.0);
}
"#,
    prepare: None,
};

/// Throughput over the last two minutes, which moves at the display's rate
/// while the page itself is drawn only as samples arrive: each sample is
/// written into a small texture and the GPU scrolls it in over one poll, and
/// eases the scale when it changes. Kept by the page that shows it.
#[derive(Default)]
pub struct LiveChart {
    animated: Animated,
    image: Option<Arc<RenderImage>>,
    taken: u64,
    scale: Option<f64>,
    look: Option<Look>,
}

impl LiveChart {
    /// Takes the samples if they changed since the last call.
    pub fn update(&mut self, samples: &VecDeque<Sample>, taken: u64, look: &Look, window: &mut Window, cx: &mut App) {
        if self.look != Some(*look) {
            self.look = Some(*look);
            self.animated.set(3, window.scale_factor());
            self.animated.set_color(4, look.color(Tone::Accent));
            self.animated.set_color(8, look.color(Tone::Ink).opacity(0.8));
        }
        if taken == self.taken {
            return;
        }
        let first = self.taken == 0;
        self.taken = taken;
        let full = samples.iter().map(|s| s.down.max(s.up)).fold(1.0, f64::max);
        let n = samples.len();
        let mut bytes = Vec::with_capacity(n.max(1) * 2 * 4);
        for row in 0..2 {
            for s in samples {
                let v = if row == 0 { s.down } else { s.up };
                let q = (v / full * 65535.0).round().clamp(0.0, 65535.0) as u16;
                let (hi, lo) = ((q >> 8) as u8, q as u8);
                bytes.extend_from_slice(&[hi, lo, hi, 255]);
            }
        }
        let next = (n > 0)
            .then(|| ::image::RgbaImage::from_raw(n as u32, 2, bytes))
            .flatten()
            .map(|pixels| Arc::new(RenderImage::new(vec![::image::Frame::new(pixels)])));
        if let Some(old) = std::mem::replace(&mut self.image, next) {
            cx.drop_image(old, Some(window));
        }

        let a = &self.animated;
        a.set(0, n as f32);
        a.set(1, HISTORY as f32);
        a.set(2, full as f32);
        a.set(12, 0.18);
        a.set(13, 0.10);
        a.set(14, 1.6);
        a.set(15, 1.2);
        if first {
            a.hold(0, 1.0);
        } else {
            a.segment(0, 0.0, 1.0, Animated::now(), POLL, Ease::Linear, Repeat::Once);
        }
        let peak = samples.iter().map(|s| s.down.max(s.up)).fold(0.0, f64::max);
        let scale = scale_for(peak);
        if self.scale.is_none() {
            a.hold(1, scale as f32);
        } else if self.scale != Some(scale) {
            a.to(1, scale as f32, Duration::from_millis(400), Ease::QuickOut);
        }
        self.scale = Some(scale);
    }

    /// The chart with its scale named above and its span below.
    pub fn element(&self, look: Look, height: Pixels) -> impl IntoElement {
        let muted = look.text_color(Tone::Muted);
        let note = |s: String| div().text_role(TypeRole::Fine, &look).text_color(muted).child(s);
        let mut plot_area = div().relative().w_full().h(height).child(plot(
            Vec::new(),
            1.0,
            HISTORY,
            true,
            look.palette.rule.hsla(),
            height,
        ));
        if let Some(image) = self.image.clone() {
            plot_area = plot_area.child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .child(AnimatedQuad::new(&CURVES, &self.animated).image(image).size_full()),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(look.space(Space::Xs))
            .child(note(rate(self.scale.unwrap_or(FLOOR))))
            .child(plot_area)
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(note("2 min".into()))
                    .child(note("now".into())),
            )
    }
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
