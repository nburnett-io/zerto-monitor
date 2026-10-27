"""Monthly DR report per zORG - on screen and as a branded PDF.

Built from what the monitor keeps: the daily RPO / journal / health buckets (trends.py),
Zerto's failover-test reports and events (events.py), the alert log, recovery plans and
VPG backups. The PDF is rendered from the same HTML by WeasyPrint (pango is installed on
the appliance); if it isn't available the page still prints to PDF from the browser.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import charts
import db
import events as zevents
import plans
import trends
from zerto import fmt_age

ROOT = Path(__file__).resolve().parent.parent


class ReportError(Exception):
    pass


def month_bounds(month: str) -> tuple[datetime, datetime]:
    try:
        start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ReportError("month must look like 2026-10") from e
    end = (start + timedelta(days=32)).replace(day=1)
    return start, end


def months(n: int = 13) -> list[str]:
    now = datetime.now(timezone.utc).replace(day=1)
    out = []
    for _ in range(n):
        out.append(now.strftime("%Y-%m"))
        now = (now - timedelta(days=1)).replace(day=1)
    return out


def logo_data_uri(name: str = "favicon") -> str:
    """The glyph only: the white-lettered logo.svg is for the navy nav, not white paper."""
    p = ROOT / "static" / "img" / f"{name}.svg"
    try:
        return "data:image/svg+xml;base64," + base64.b64encode(p.read_bytes()).decode()
    except OSError:
        return ""


def build(zorg: str, month: str) -> dict:
    import views
    start, end = month_bounds(month)
    now = datetime.now(timezone.utc)
    d0, d1 = start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")
    t0, t1 = start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")
    detail = views.zorg_detail(zorg)
    vpgs_now = detail["vpgs"]
    daily = db.trend_rows("vpg_daily", org=zorg, since=d0, until=d1)
    by_vpg: dict[str, list] = {}
    for r in daily:
        by_vpg.setdefault(r["vpg_key"], []).append(r)
    names = {v["key"]: v for v in vpgs_now}
    rows = []
    for k, lst in by_vpg.items():
        s = trends.summarise(lst)
        v = names.get(k) or {}
        rows.append({"key": k, "name": lst[-1]["name"] or v.get("name") or k, **s,
                     "rpo_cfg": lst[-1]["rpo_cfg"], "hist_cfg": lst[-1]["hist_cfg"],
                     "still_protected": k in names, "last_test": (v.get("last_test") or "")[:10]})
    rows.sort(key=lambda r: (r.get("rpo_ok_pct", 100), r["name"].lower()))
    total = trends.summarise(daily)
    days = sorted({r["period"] for r in daily})
    coverage = {"first": days[0] if days else None, "last": days[-1] if days else None, "days": len(days),
                "month_days": (end - start).days, "partial": len(days) < (min(end, now) - start).days}
    # charts: worst RPO across the zORG each day, and % of samples healthy each day
    per_day: dict[str, list] = {}
    for r in daily:
        per_day.setdefault(r["period"], []).append(r)
    rpo_pts = [(datetime.fromisoformat(d).replace(tzinfo=timezone.utc) + timedelta(hours=12),
                max((x["rpo_max"] or 0) for x in per_day[d])) for d in days]
    avg_pts = [(datetime.fromisoformat(d).replace(tzinfo=timezone.utc) + timedelta(hours=12),
                sum(x["rpo_sum"] or 0 for x in per_day[d]) / max(1, sum(x["samples"] or 0 for x in per_day[d])))
               for d in days]
    cfgs = sorted({r["rpo_cfg"] for r in daily if r["rpo_cfg"]})
    series = [{"name": "worst RPO", "color": charts.RED, "points": rpo_pts},
              {"name": "average RPO", "color": charts.BLUE, "points": avg_pts, "area": True}]
    if len(cfgs) == 1:
        series.append({"name": f"target {fmt_age(cfgs[0])}", "color": charts.GREY, "dash": True,
                       "points": [(start, cfgs[0]), (end, cfgs[0])]})
    rpo_chart = charts.line_chart(series, start, end, y_fmt=charts.fmt_secs, gap=timedelta(days=1, hours=1),
                                  title="RPO by day") if days else None
    health_bars = []                                   # every day of the month (so far) gets a slot
    d = start
    while d < min(end, now + timedelta(days=1)):
        k = d.strftime("%Y-%m-%d")
        v = (round(100 * sum(x["healthy"] or 0 for x in per_day[k]) / max(1, sum(x["samples"] or 0 for x in per_day[k])), 1)
             if k in per_day else None)
        health_bars.append((k[8:], v, charts.GREEN if v is None or v >= 99 else (charts.AMBER if v >= 90 else charts.RED)))
        d += timedelta(days=1)
    health_chart = charts.bar_chart(health_bars, y_max=100, y_fmt=lambda v: f"{v:.0f}%",
                                    title="healthy share by day") if days else None
    tests = db.test_reports(zorg=zorg, since=t0, until=t1)
    for t in tests:
        t["ok"] = zevents.test_ok(t["status"])
        t["rto_h"] = fmt_age(int(t["rto_s"])) if t["rto_s"] is not None else "-"
    # limit -1 is no limit in SQLite: the counts must cover the whole month (the table shows 60)
    evs = db.events(zorg=zorg, since=t0, until=t1, kinds=("change", "pause", "test", "failover"), limit=-1)
    ev_counts: dict[str, int] = {}
    for e in evs:
        ev_counts[e["kind"]] = ev_counts.get(e["kind"], 0) + 1
    alerts = [a for a in db.alerts_between(zorg, t0, t1) if a["event"] in ("raised", "escalated", "cleared", "updated")]
    open_issues = [v for v in vpgs_now if v["health"] != "healthy"]
    pl = plans.zorg_plans(zorg, vpgs_now)
    bk = db.list_backups(zorg=zorg)
    never = [v["name"] for v in vpgs_now if not v.get("last_test")]
    stale = [v["name"] for v in vpgs_now if v.get("last_test") and
             (now - views._parse_iso(v["last_test"])).days > 90] if vpgs_now else []
    return {
        "zorg": zorg, "month": month, "start": start, "end": end, "generated": now,
        "summary": detail["summary"], "vpgs_now": vpgs_now, "rows": rows, "total": total,
        "coverage": coverage, "rpo_chart": rpo_chart, "health_chart": health_chart,
        "tests": tests, "tests_ok": sum(1 for t in tests if t["ok"] and t.get("rtype") == "FailoverTest"),
        "tests_failed": sum(1 for t in tests if t["ok"] is False), "never_tested": never, "stale_tested": stale,
        "events": evs, "event_counts": ev_counts, "alerts": alerts, "open_issues": open_issues,
        "plans": pl, "backups": {"count": len({b["export_ts"][:10] for b in bk}), "latest": bk[0]["export_ts"] if bk else None,
                                 "vpgs": len({b["vpg_name"] for b in bk}), "days": db.get_setting("backup_days", "7")},
        "logo": logo_data_uri(),"kind_label": zevents.KIND_LABEL,
    }


def pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML
    except Exception as e:  # noqa: BLE001 - missing python package or system libraries (pango)
        raise ReportError("the PDF engine (WeasyPrint) isn't available on this appliance - run the appliance "
                          "upgrade, or use the browser's Print → Save as PDF on the report page") from e
    return HTML(string=html, base_url=str(ROOT / "static")).write_pdf()
