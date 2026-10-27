"""RPO and journal trends per VPG.

After every full poll each VPG's state is folded into an hourly bucket (kept 35 days) and
a daily one (kept 400 days, for monthly reports): worst and average RPO, how many samples
breached the configured RPO, the shortest journal history against the configured one,
journal size, and how many samples were healthy / warning / failure. Only LIVE sources
count - a ZVM that stopped answering must not keep replaying its last good poll as data.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import db


def history_short(hist: int | None, cfg: int | None) -> bool:
    """Journal history meaningfully below what's configured (an hour or 5% of slack:
    the oldest checkpoint ages out in steps, so a few minutes short is normal)."""
    return bool(hist is not None and cfg and hist < cfg - max(60, cfg * 0.05))


def samples_from(merged: dict) -> list[dict]:
    out = []
    for k, v in merged.items():
        rpo, cfg = v.get("rpo"), v.get("rpo_cfg") or 0
        out.append({
            "key": k, "org": v.get("org") or "(no zORG)", "name": v.get("name"),
            "rpo": max(int(rpo), 0) if rpo is not None else 0, "rpo_cfg": cfg,
            "rpo_breach": int(rpo is None or rpo < 0 or bool(cfg and rpo > cfg)),
            "hist_min": v.get("history_min"), "hist_cfg": v.get("history_cfg_min"),
            "hist_short": int(history_short(v.get("history_min"), v.get("history_cfg_min"))),
            "journal_gb": round(sum((m.get("journal_gb") or 0) for m in v.get("members") or []), 1),
            "used_gb": v.get("used_gb") or 0, "health": v.get("health") or "warning",
        })
    return out


def record(now: datetime | None = None) -> int:
    import views
    now = now or datetime.now(timezone.utc)
    rows = [r for r in views._sources_with_snapshots() if r["payload"]]       # live polls only
    if not rows:
        return 0
    samples = samples_from(views.merged_vpgs(rows))
    db.record_trend_samples(samples, now.strftime("%Y-%m-%dT%H"), now.strftime("%Y-%m-%d"))
    return len(samples)


def _when(period: str) -> datetime:
    return datetime.fromisoformat(period + (":00:00" if "T" in period else "T00:00:00")).replace(tzinfo=timezone.utc)


def vpg_series(key: str, hours: int = 168) -> dict:
    """Hourly points for one VPG's charts."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")
    rows = db.trend_rows("vpg_hourly", vpg_key=key, since=since)
    pts = [{"t": _when(r["period"]), "rpo_max": r["rpo_max"], "rpo_avg": (r["rpo_sum"] or 0) / max(1, r["samples"]),
            "rpo_cfg": r["rpo_cfg"], "hist_min": r["hist_min"], "hist_cfg": r["hist_cfg"],
            "journal_gb": r["journal_gb"], "breach": r["rpo_breach"], "samples": r["samples"],
            "healthy": r["healthy"]} for r in rows]
    n = sum(p["samples"] for p in pts)
    return {"points": pts, "hours": hours,
            "rpo_ok_pct": round(100 * (1 - sum(p["breach"] for p in pts) / n), 1) if n else None,
            "healthy_pct": round(100 * sum(p["healthy"] for p in pts) / n, 1) if n else None,
            "since": pts[0]["t"] if pts else None}


def summarise(rows: list[dict]) -> dict:
    """Totals over a set of hourly/daily rows (one VPG or many)."""
    n = sum(r["samples"] or 0 for r in rows)
    if not n:
        return {"samples": 0}
    return {"samples": n,
            "rpo_ok_pct": round(100 * (1 - sum(r["rpo_breach"] or 0 for r in rows) / n), 2),
            "hist_ok_pct": round(100 * (1 - sum(r["hist_short"] or 0 for r in rows) / n), 2),
            "healthy_pct": round(100 * sum(r["healthy"] or 0 for r in rows) / n, 2),
            "failure_pct": round(100 * sum(r["failure"] or 0 for r in rows) / n, 2),
            "rpo_avg": round(sum(r["rpo_sum"] or 0 for r in rows) / n),
            "rpo_max": max((r["rpo_max"] or 0) for r in rows),
            "journal_gb_max": max((r["journal_gb"] or 0) for r in rows)}
