#!/usr/bin/env python3
"""Render the charts in benchmarks.json as inline SVG into the site's pages.

Each page marks a chart's place with `<!-- chart <id> -->` ... `<!-- /chart -->`;
everything between the markers is replaced, so the pages stay plain HTML that is
committed and served as-is. The SVG takes its colours from the page's CSS
variables, so it follows the light and dark themes.

Bars are drawn solid to the lowest round and faint from there to the highest, so
the spread between rounds stays visible.
"""

import html
import json
import math
import re
import sys
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent
PAGES = [SITE / "public" / "benchmarks" / "index.html"]

WIDTH = 440
VALUE_GUTTER = 92
PLOT = WIDTH - VALUE_GUTTER
LEGEND = 26
ROW = 48
BAR = 10
AXIS = 26


def fmt(v, places=None):
    return f"{v:g}" if places is None else f"{v:.{places}f}"


def places(row):
    """Decimal places for a row, so 0.27–0.30 keeps the precision it was measured to."""
    return max(len(f"{v:g}".partition(".")[2]) for pair in row["values"] for v in pair)


def span(lo, hi, p=None):
    return fmt(lo, p) if lo == hi else f"{fmt(lo, p)}–{fmt(hi, p)}"


def nice_ticks(top):
    """A step from 1, 2, 2.5 or 5 times a power of ten, giving at most five intervals."""
    raw = top / 5
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    count = math.ceil(top / step - 1e-9)
    return step, step * count


def svg(chart):
    rows = chart["rows"]
    top = max(v[1] for row in rows for v in row["values"])
    step, scale = nice_ticks(top)
    height = LEGEND + ROW * len(rows) + AXIS
    x = lambda v: v / scale * PLOT
    cid = chart["id"]
    a, b = chart["series"]
    out = [
        f'<svg class="chart" viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="{cid}-t">',
        f'<title id="{cid}-t">{html.escape(chart["title"])}, {chart["unit"]}, {chart["better"]} is better</title>',
    ]
    # Legend.
    out.append(f'<rect class="s0" x="0" y="4" width="10" height="10"/>')
    out.append(f'<text class="lg" x="16" y="13">{html.escape(a)}</text>')
    bx = 16 + 7.4 * len(a) + 22
    out.append(f'<rect class="s1" x="{bx:.1f}" y="4" width="10" height="10"/>')
    out.append(f'<text class="lg" x="{bx + 16:.1f}" y="13">{html.escape(b)}</text>')
    out.append(f'<text class="lg dim" x="{WIDTH}" y="13" text-anchor="end">{chart["unit"]}, {chart["better"]} is better</text>')
    plot_bottom = LEGEND + ROW * len(rows)
    # Gridlines and tick labels.
    ticks = round(scale / step)
    for i in range(ticks + 1):
        tx = x(i * step)
        out.append(f'<line class="grid" x1="{tx:.1f}" y1="{LEGEND}" x2="{tx:.1f}" y2="{plot_bottom}"/>')
        anchor = "start" if i == 0 else "middle"
        out.append(f'<text class="tick" x="{tx:.1f}" y="{plot_bottom + 16}" text-anchor="{anchor}">{fmt(round(i * step, 6))}</text>')
    for n, row in enumerate(rows):
        y = LEGEND + n * ROW
        out.append(f'<text class="lb" x="0" y="{y + 15}">{html.escape(row["label"])}</text>')
        for s, (lo, hi) in enumerate(row["values"]):
            by = y + 21 + s * (BAR + 3)
            out.append(f'<rect class="s{s}" x="0" y="{by}" width="{x(lo):.1f}" height="{BAR}"/>')
            if hi > lo:
                out.append(f'<rect class="s{s} range" x="{x(lo):.1f}" y="{by}" width="{x(hi) - x(lo):.1f}" height="{BAR}"/>')
            out.append(f'<text class="val{"" if s == 0 else " dim"}" x="{x(hi) + 5:.1f}" y="{by + 9}">{span(lo, hi, places(row))}</text>')
    out.append("</svg>")
    return "\n".join(out)


def table(chart):
    a, b = chart["series"]
    head = f"<tr><th>path</th><th>{html.escape(a)}</th><th>{html.escape(b)}</th></tr>"
    body = "".join(
        f"<tr><td>{html.escape(r['label'])}</td><td>{span(*r['values'][0], places(r))}</td><td>{span(*r['values'][1], places(r))}</td></tr>"
        for r in chart["rows"]
    )
    return f"<details><summary>numbers</summary><table>{head}{body}</table></details>"


def figure(chart):
    return f'<figure id="{chart["id"]}">\n<figcaption>{html.escape(chart["title"])}</figcaption>\n{svg(chart)}\n{table(chart)}\n</figure>'


def main():
    charts = {c["id"]: c for c in json.loads((SITE / "src" / "benchmarks.json").read_text())["charts"]}
    pattern = re.compile(r"(<!-- chart ([\w-]+) -->).*?(<!-- /chart -->)", re.S)
    for page in PAGES:
        text = page.read_text()

        def render(m):
            if m.group(2) not in charts:
                sys.exit(f"{page}: no chart {m.group(2)!r} in benchmarks.json")
            return f"{m.group(1)}\n{figure(charts[m.group(2)])}\n{m.group(3)}"

        page.write_text(pattern.sub(render, text))


if __name__ == "__main__":
    main()
