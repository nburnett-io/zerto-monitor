"""Small server-side SVG charts: the same markup renders on the pages and in PDF reports
(no JavaScript, no external library). Colours are explicit hex values chosen to read on
both the light and the dark theme, because CSS variables don't reach SVG attributes in
every renderer."""
from __future__ import annotations

from datetime import datetime, timedelta
from html import escape

from markupsafe import Markup

BLUE, RED, AMBER, GREEN, GREY = "#2F7FD0", "#D0524C", "#C98A1E", "#3C9A6A", "#8791A1"


def _nice(top: float) -> tuple[float, float]:
    """A round axis maximum and step for 4-5 ticks."""
    if top <= 0:
        return 1, 0.25
    import math
    raw = top / 4
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    return step * math.ceil(top / step), step


def fmt_secs(v: float) -> str:
    v = float(v)
    if v < 90:
        return f"{v:.0f}s"
    if v < 5400:
        return f"{v / 60:.0f}m"
    return f"{v / 3600:.1f}h"


def fmt_num(v: float) -> str:
    return f"{v:,.0f}" if abs(v) >= 10 else f"{v:.1f}".rstrip("0").rstrip(".")


def line_chart(series: list[dict], start: datetime, end: datetime, *, width: int = 760, height: int = 180,
               y_fmt=fmt_num, y_max: float | None = None, gap: timedelta = timedelta(hours=3),
               title: str = "") -> Markup:
    """series: [{"name", "color", "points": [(datetime, value|None)], "dash": bool, "area": bool}].
    A gap longer than `gap` between points breaks the line (no data, no invented line)."""
    L, R, T, B = 46, 10, 12, 22
    w, h = width - L - R, height - T - B
    vals = [v for s in series for _, v in s["points"] if v is not None]
    top, step = _nice(y_max if y_max is not None else (max(vals) if vals else 1) * 1.08)
    span = max((end - start).total_seconds(), 1)

    def X(t):
        return L + w * min(max((t - start).total_seconds() / span, 0), 1)

    def Y(v):
        return T + h - h * min(max(v / top, 0), 1)

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" '
         f'role="img" aria-label="{escape(title)}" style="max-width:{width}px;font:10px sans-serif">']
    tick = 0.0
    while tick <= top + 1e-9:
        y = Y(tick)
        o.append(f'<line x1="{L}" x2="{L + w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GREY}" stroke-opacity=".25"/>')
        o.append(f'<text x="{L - 4}" y="{y + 3:.1f}" text-anchor="end" fill="{GREY}">{escape(y_fmt(tick))}</text>')
        tick += step
    days = (end - start).days or 1
    every = 1 if days <= 10 else (2 if days <= 20 else 4)
    d = datetime(start.year, start.month, start.day, tzinfo=start.tzinfo)
    i = 0
    while d <= end:
        if d >= start and i % every == 0:
            x = X(d)
            o.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{T}" y2="{T + h}" stroke="{GREY}" stroke-opacity=".12"/>')
            o.append(f'<text x="{x:.1f}" y="{height - 6}" text-anchor="middle" fill="{GREY}">{d:%m-%d}</text>')
        d += timedelta(days=1)
        i += 1
    for s in series:
        pts = sorted((t, v) for t, v in s["points"] if v is not None)
        if not pts:
            continue
        runs, cur, prev = [], [], None
        brk = None if s.get("dash") else gap          # reference lines (targets) never break
        for t, v in pts:
            if brk is not None and prev is not None and t - prev > brk:
                runs.append(cur)
                cur = []
            cur.append((X(t), Y(v)))
            prev = t
        runs.append(cur)
        dash = ' stroke-dasharray="5 4"' if s.get("dash") else ""
        for run in runs:
            if len(run) == 1:
                x, y = run[0]
                o.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2" fill="{s["color"]}"/>')
                continue
            path = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in run)
            if s.get("area"):
                o.append(f'<path d="{path} L{run[-1][0]:.1f},{T + h} L{run[0][0]:.1f},{T + h} Z" '
                         f'fill="{s["color"]}" fill-opacity=".15" stroke="none"/>')
            o.append(f'<path d="{path}" fill="none" stroke="{s["color"]}" stroke-width="1.6"{dash}/>')
    lx = L
    for s in series:
        o.append(f'<rect x="{lx}" y="1" width="10" height="3" fill="{s["color"]}"/>'
                 f'<text x="{lx + 14}" y="7" fill="{GREY}">{escape(s["name"])}</text>')
        lx += 22 + 6 * len(s["name"])
    o.append("</svg>")
    return Markup("".join(o))


def bar_chart(bars: list[tuple[str, float, str]], *, width: int = 760, height: int = 160, y_fmt=fmt_num,
              y_max: float | None = None, title: str = "") -> Markup:
    """bars: [(label, value or None, colour)] - e.g. % healthy per day; None = no data (a gap)."""
    L, R, T, B = 46, 10, 10, 22
    w, h = width - L - R, height - T - B
    top, step = _nice(y_max if y_max is not None else max([v for _, v, _ in bars if v is not None] or [1]) * 1.05)
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" role="img" '
         f'aria-label="{escape(title)}" style="max-width:{width}px;font:10px sans-serif">']
    tick = 0.0
    while tick <= top + 1e-9:
        y = T + h - h * tick / top
        o.append(f'<line x1="{L}" x2="{L + w}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GREY}" stroke-opacity=".25"/>'
                 f'<text x="{L - 4}" y="{y + 3:.1f}" text-anchor="end" fill="{GREY}">{escape(y_fmt(tick))}</text>')
        tick += step
    n = max(len(bars), 1)
    bw = w / n
    for i, (label, v, color) in enumerate(bars):
        x = L + i * bw
        if v is not None:
            bh = h * min(max(v / top, 0), 1)
            rw = min(bw * .7, 36)
            o.append(f'<rect x="{x + (bw - rw) / 2:.1f}" y="{T + h - bh:.1f}" width="{rw:.1f}" height="{bh:.1f}" '
                     f'fill="{color}"><title>{escape(label)}: {escape(y_fmt(v))}</title></rect>')
        if n <= 16 or i % max(1, n // 10) == 0:
            o.append(f'<text x="{x + bw / 2:.1f}" y="{height - 6}" text-anchor="middle" fill="{GREY}">{escape(label)}</text>')
    o.append("</svg>")
    return Markup("".join(o))
