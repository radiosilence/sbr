//! Plots drawn on the GPU: throughput over the last two minutes on a scale
//! that rounds up to a readable step, and the gauges' trends.

use koan_kit::app::*;
use koan_kit::raw::{Hsla, PathBuilder, canvas, point, px};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
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
/// sampler returns them exactly. The program draws a monotone cubic through
/// them, which rounds peaks off without overshooting, and strokes it by each
/// pixel's distance to the curve, so the line keeps its width at any slope
/// and does not shimmer as it scrolls.
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
    i = clamp(i, 0.0, n - 1.0);
    float4 c = koan_sample(image, tile, float2((i + 0.5) / n, (row + 0.5) / 2.0));
    return (round(c.r * 255.0) * 256.0 + round(c.g * 255.0)) / 65535.0;
}

// A monotone cubic's tangent at b (Fritsch and Butland): flat at a peak or
// a trough, so the curve rounds them off without passing beyond them.
float sbr_tangent(float a, float b, float c) {
    float d0 = b - a;
    float d1 = c - b;
    return d0 * d1 <= 0.0 ? 0.0 : 2.0 * d0 * d1 / (d0 + d1);
}

float sbr_curve(float p1, float p2, float m1, float m2, float t) {
    float t2 = t * t;
    float t3 = t2 * t;
    return (2.0 * t3 - 3.0 * t2 + 1.0) * p1 + (t3 - 2.0 * t2 + t) * m1
        + (3.0 * t2 - 2.0 * t3) * p2 + (t3 - t2) * m2;
}

float sbr_segment(float2 p, float2 a, float2 b) {
    float2 ab = b - a;
    float h = clamp(dot(p - a, ab) / max(dot(ab, ab), 1e-6), 0.0, 1.0);
    return length(p - a - ab * h);
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
    // Sample i stands at x = (i - shift) * step.
    float shift = (n - 1.0) - (slots - 1.0) - (1.0 - phase);
    float f = position.x / step + shift;
    if (f < -1.0) {
        return float4(0.0);
    }
    float i0 = floor(clamp(f, 0.0, n - 1.0));
    float t = clamp(f - i0, 0.0, 1.0);
    float4 out = float4(0.0);
    for (int row = 0; row < 2; row++) {
        float4 colour = row == 0 ? float4(u[4], u[5], u[6], u[7]) : float4(u[8], u[9], u[10], u[11]);
        if (colour.a <= 0.0) {
            continue;
        }
        // Samples i0 - 2 to i0 + 3, and the tangents at i0 - 1 to i0 + 2.
        float v[6];
        for (int q = 0; q < 6; q++) {
            v[q] = sbr_value(image, tile, i0 - 2.0 + float(q), float(row), n) * k;
        }
        float m[6];
        for (int q = 1; q < 5; q++) {
            m[q] = sbr_tangent(v[q - 1], v[q], v[q + 1]);
        }
        float y = size.y * (1.0 - clamp(sbr_curve(v[2], v[3], m[2], m[3], t), 0.0, 1.0));
        float fill = f >= 0.0 ? clamp(position.y - y + 0.5, 0.0, 1.0) * u[12 + row] : 0.0;

        // The stroke: the distance to the curve over this interval and its
        // neighbours, each followed in four straight pieces.
        float d = 1e9;
        for (int q = 1; q < 4; q++) {
            float j = i0 - 2.0 + float(q);
            if (j < 0.0 || j + 1.0 > n - 1.0) {
                continue;
            }
            float2 prev = float2((j - shift) * step, size.y * (1.0 - clamp(v[q], 0.0, 1.0)));
            for (int s = 1; s <= 4; s++) {
                float tt = float(s) / 4.0;
                float value = sbr_curve(v[q], v[q + 1], m[q], m[q + 1], tt);
                float2 at = float2((j + tt - shift) * step, size.y * (1.0 - clamp(value, 0.0, 1.0)));
                d = min(d, sbr_segment(position, prev, at));
                prev = at;
            }
        }
        float half_width = u[14 + row] * u[3] * 0.5;
        float line = 1.0 - smoothstep(half_width - 0.6, half_width + 0.6, d);

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

/// A line on a `LiveChart`: its values, oldest first, and how it is drawn.
pub struct Line {
    pub values: Vec<f64>,
    pub colour: Hsla,
    /// The fill's opacity under the line.
    pub fill: f32,
    /// The stroke's width, in points.
    pub width: f32,
}

/// A chart of one or two lines that moves at the display's rate while the
/// page around it is drawn only as samples arrive: each sample is written
/// into a small texture the GPU draws from, scrolled in over one poll, and
/// the scale eases when it changes. Nothing is tessellated on the CPU, so
/// scrolling the page costs the chart nothing. Kept by the page that shows
/// it.
#[derive(Default)]
pub struct LiveChart {
    animated: Animated,
    image: Option<Arc<RenderImage>>,
    taken: u64,
    top: Option<f64>,
    look: Option<Look>,
}

impl LiveChart {
    /// Takes new lines when a sample was `taken` or the look changed since
    /// the last call; `build` gives the value that reaches the top and at
    /// most two lines.
    pub fn update(
        &mut self,
        taken: u64,
        look: &Look,
        window: &mut Window,
        cx: &mut App,
        build: impl FnOnce(&Look) -> (f64, Vec<Line>),
    ) {
        let fresh = taken != self.taken;
        if !fresh && self.look == Some(*look) {
            return;
        }
        let first = self.taken == 0;
        self.taken = taken;
        self.look = Some(*look);
        let (top, lines) = build(look);
        let n = lines.iter().map(|l| l.values.len()).max().unwrap_or(0);
        let full = lines
            .iter()
            .flat_map(|l| l.values.iter().copied())
            .fold(f64::EPSILON, f64::max);
        let mut bytes = Vec::with_capacity(n.max(1) * 2 * 4);
        for row in 0..2 {
            let values = lines.get(row).map(|l| l.values.as_slice()).unwrap_or(&[]);
            for i in 0..n {
                let v = values.get(i).copied().unwrap_or(0.0);
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
        a.set(3, window.scale_factor());
        for row in 0..2 {
            match lines.get(row) {
                Some(line) => {
                    a.set_color(4 + row * 4, line.colour);
                    a.set(12 + row, line.fill);
                    a.set(14 + row, line.width);
                }
                None => {
                    a.set_color(4 + row * 4, Hsla::transparent_black());
                    a.set(12 + row, 0.0);
                    a.set(14 + row, 0.0);
                }
            }
        }
        if first {
            a.hold(0, 1.0);
        } else if fresh {
            a.segment(0, 0.0, 1.0, Animated::now(), POLL, Ease::Linear, Repeat::Once);
        }
        if self.top.is_none() {
            a.hold(1, top as f32);
        } else if self.top != Some(top) {
            a.to(1, top as f32, Duration::from_millis(400), Ease::QuickOut);
        }
        self.top = Some(top);
    }

    /// The value at the top of the chart.
    pub fn top(&self) -> Option<f64> {
        self.top
    }

    /// The lines, filling a box `height` tall.
    pub fn quad(&self, height: Pixels) -> Div {
        let mut area = div().relative().w_full().h(height);
        if let Some(image) = self.image.clone() {
            area = area.child(
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .child(AnimatedQuad::new(&CURVES, &self.animated).image(image).size_full()),
            );
        }
        area
    }
}

/// Throughput's lines: download in the accent, upload in `ink` in front of
/// it, on a scale that rounds up to a readable step.
pub fn throughput_lines(samples: &VecDeque<Sample>, look: &Look) -> (f64, Vec<Line>) {
    let peak = samples.iter().map(|s| s.down.max(s.up)).fold(0.0, f64::max);
    (
        scale_for(peak),
        vec![
            Line {
                values: samples.iter().map(|s| s.down).collect(),
                colour: look.color(Tone::Accent),
                fill: 0.18,
                width: 1.75,
            },
            Line {
                values: samples.iter().map(|s| s.up).collect(),
                colour: look.color(Tone::Ink).opacity(0.8),
                fill: 0.10,
                width: 1.4,
            },
        ],
    )
}

/// The throughput chart with quarter rules, its scale named above and its
/// span below.
pub fn throughput(chart: &LiveChart, look: Look, height: Pixels) -> impl IntoElement {
    let muted = look.text_color(Tone::Muted);
    let note = |s: String| div().text_role(TypeRole::Fine, &look).text_color(muted).child(s);
    let rules = div().absolute().top_0().left_0().size_full().child(plot(
        Vec::new(),
        1.0,
        HISTORY,
        true,
        look.palette.rule.hsla(),
        height,
    ));
    div()
        .flex()
        .flex_col()
        .gap(look.space(Space::Xs))
        .child(note(rate(chart.top().unwrap_or(FLOOR))))
        .child(div().relative().child(rules).child(chart.quad(height)))
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
pub fn trend_lines(values: Vec<f64>, look: &Look) -> (f64, Vec<Line>) {
    let lo = values.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = values.iter().copied().fold(0.0, f64::max);
    let base = if lo.is_finite() {
        (lo - (hi - lo) * 0.4).max(0.0)
    } else {
        0.0
    };
    let values: Vec<f64> = values.iter().map(|v| v - base).collect();
    (
        ((hi - base) * 1.1).max(f64::EPSILON),
        vec![Line {
            values,
            colour: look.color(Tone::Accent),
            fill: 0.14,
            width: 1.2,
        }],
    )
}

/// A bar's fill, drawn by the GPU: from the left edge to track 0's
/// fraction of the width, in the colour at uniform 4, its edge smoothed.
static BAR: ShaderProgram = ShaderProgram {
    name: "sbr-bar",
    msl: r#"
float4 shade(float2 position, float2 size, float time, constant float *u, texture2d<float> image, float4 tile) {
    float w = clamp(koan_track(u, 0, time), 0.0, 1.0) * size.x;
    float cover = clamp(w - position.x + 0.5, 0.0, 1.0);
    return float4(u[4], u[5], u[6], u[7] * cover);
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

/// Bars whose fills the GPU eases to each new value: speeds, latencies,
/// shares. Each is kept by its key from one render to the next, so it moves
/// from where it stands; the page is not drawn while it moves. Kept by the
/// page that shows them.
pub struct Bars {
    shown: RefCell<HashMap<SharedString, (Animated, f32)>>,
    drawn: RefCell<HashSet<SharedString>>,
    ease: Duration,
}

/// Bars fed at the tunnel's poll, four times a second.
impl Default for Bars {
    fn default() -> Self {
        Self::easing(POLL)
    }
}

impl Bars {
    /// Bars that take `ease` to reach a new value: the time between the
    /// values that feed them, so they move without stopping.
    pub fn easing(ease: Duration) -> Self {
        Self {
            shown: RefCell::default(),
            drawn: RefCell::default(),
            ease,
        }
    }

    /// Forgets the bars the last render did not draw. Called once at the
    /// start of each render.
    pub fn sweep(&self) {
        let drawn = std::mem::take(&mut *self.drawn.borrow_mut());
        self.shown.borrow_mut().retain(|key, _| drawn.contains(key));
    }

    /// The bar `key`, filled to `fraction` in `colour` over `track`.
    pub fn bar(&self, key: impl Into<SharedString>, fraction: f32, colour: Hsla, track: Hsla, height: Pixels) -> Div {
        let key = key.into();
        let fraction = if fraction.is_finite() {
            fraction.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let mut shown = self.shown.borrow_mut();
        let (animated, at) = shown.entry(key.clone()).or_insert_with(|| {
            let animated = Animated::new();
            animated.hold(0, fraction);
            (animated, fraction)
        });
        if *at != fraction {
            animated.to(0, fraction, self.ease, Ease::QuickOut);
            *at = fraction;
        }
        animated.set_color(4, colour);
        self.drawn.borrow_mut().insert(key);
        div().w_full().h(height).bg(track).relative().child(
            AnimatedQuad::new(&BAR, animated)
                .absolute()
                .top_0()
                .left_0()
                .size_full(),
        )
    }
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
