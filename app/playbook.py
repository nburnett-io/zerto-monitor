"""Suggested fixes: a playbook keyed by Zerto alert code and replication state.

Two kinds of entry, shown together:

  * researched - playbook.json beside this file, written from Zerto's alert reference
    and adversarially reviewed for safety (anything that can cause a resync, lose
    checkpoints or fail over carries a caution). Read-only; ships with the app.
  * team - written by engineers from the dashboards when they find what actually
    fixes an error here. Stored in the database (so upgrades keep them), shown FIRST
    because they carry local knowledge, and labelled with who wrote them and when.

This module only matches a VPG's condition to entries and fills in the specifics
from the alert text. It never invents advice: no entry means "no playbook entry yet".
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import db

PLAYBOOK_FILE = Path(__file__).with_name("playbook.json")
_cache: dict = {"mtime": None, "entries": {}}
_team: dict = {"at": 0.0, "entries": None}
TEAM_TTL = 30                    # seconds; writes in this process invalidate at once

SYNCING = {"InitialSync", "VolumeInitialSync", "Sync", "DeltaSync", "VolumeDeltaSync", "BitmapSync"}

# what a {placeholder} becomes when the alert text doesn't supply it
DEFAULTS = {"vm": "the VM", "vpg": "the VPG", "host": "the host", "zorg": "the zORG",
            "datastore": "the datastore", "peer": "the peer site", "ip": "the VRA",
            "cluster": "the cluster", "percent": "the threshold"}

_PATTERNS = {
    "vm": re.compile(r"\bfor VM\s+(\S+?)(?=\s+in\s+VPG|\s|$)"),
    "host": re.compile(r"\bhost\s+([A-Za-z0-9][\w.-]*[A-Za-z0-9])"),
    "datastore": re.compile(r"\bdatastore\s+([\w.-]+[\w])"),
    "peer": re.compile(r"\bpeer site\s+(.+?)\s*\("),
    "ip": re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"),
    "zorg": re.compile(r"\bZORG\s+([^\s.]+)"),
    "percent": re.compile(r"\b(\d{1,3})\s*percent"),
    "cluster": re.compile(r"\bcluster\s+(.+?)\s+(?:that|in|contains|which)\b"),
}
_PLACEHOLDER = re.compile(r"\{(\w+)\}")

# What a team entry may be keyed on: a Zerto alert code, or a replication condition
ALERT_CODE = re.compile(r"^[A-Z]{2,6}\d{3,5}$")
STATE_KEY = re.compile(r"^(?:cond:[a-z][a-z-]{2,40}|sub:[A-Za-z]{3,40}|status:[A-Za-z]{3,40})$")
CONDITIONS = {
    "cond:on-disconnected-vra": "VM on a host whose VRA is disconnected",
    "cond:sync-stalled": "sync running but making no progress",
    "cond:no-recovery-point": "no checkpoint at all",
    "cond:rpo-over-target": "RPO above the VPG's target",
}
LIMITS = {"title": 120, "fix": 2000, "caution": 500}


def entries() -> dict:
    """The researched playbook, reloaded whenever the file changes (no restart needed)."""
    try:
        m = PLAYBOOK_FILE.stat().st_mtime
    except OSError:
        return {}
    if _cache["mtime"] != m:
        try:
            data = json.loads(PLAYBOOK_FILE.read_text(encoding="utf-8"))
            _cache["entries"] = data.get("entries") or {}
        except (OSError, ValueError):
            _cache["entries"] = {}
        _cache["mtime"] = m
    return _cache["entries"]


def team_entries() -> dict[str, list[dict]]:
    """Engineers' entries by key, newest first. Cached briefly: pages ask per VPG."""
    if _team["entries"] is None or time.monotonic() - _team["at"] > TEAM_TTL:
        _team["entries"] = db.team_fixes()
        _team["at"] = time.monotonic()
    return _team["entries"]


def invalidate() -> None:
    _team["entries"] = None


def entries_for(key: str) -> list[dict]:
    """Every entry for one key: team entries first, then the researched one."""
    out = [dict(e, team=True) for e in team_entries().get(key, [])]
    shipped = entries().get(key)
    if shipped:
        out.append(dict(shipped, team=False))
    return out


def _values(text: str, ctx: dict) -> dict:
    vals = {k: v for k, v in ctx.items() if v}
    for k, pat in _PATTERNS.items():
        if k not in vals:
            m = pat.search(text or "")
            if m:
                vals[k] = m.group(1).rstrip(".")
    return vals


def _fill(template: str, vals: dict) -> str:
    return _PLACEHOLDER.sub(lambda m: str(vals.get(m.group(1)) or DEFAULTS.get(m.group(1), m.group(0))),
                            template or "")


def _render(key: str, e: dict, text: str, ctx: dict) -> dict:
    vals = _values(text, ctx)
    return {"key": key, "title": e.get("title", ""), "fix": _fill(e.get("fix", ""), vals),
            "caution": _fill(e.get("caution", ""), vals), "self_clears": e.get("self_clears"),
            "source": e.get("source", ""), "team": bool(e.get("team")),
            "id": e.get("id"), "by": e.get("updated_by") or e.get("created_by") or "",
            "at": (e.get("updated_at") or e.get("created_at") or "")[:10]}


def for_alert(a: dict, ctx: dict | None = None) -> list[dict]:
    """Suggested fixes for one alert (zORG and VRA pages), team entries first."""
    key = a.get("id") or ""
    return [_render(key, e, a.get("text") or "", ctx or {}) for e in entries_for(key)]


def state_keys(v: dict) -> list[str]:
    """Playbook keys for a VPG's replication state, most specific first."""
    st, sub, rpo = v.get("status"), v.get("sub") or "None", v.get("rpo")
    keys = []
    if v.get("on_disconnected_vra"):
        keys.append("cond:on-disconnected-vra")
    if sub in SYNCING and (v.get("thru") or 0) < 0.5 and (v.get("progress") or 0) == 0:
        keys.append("cond:sync-stalled")
    if sub != "None":
        keys.append(f"sub:{sub}")
    if rpo is not None and rpo < 0 and st not in ("Initializing", "Moving", "FailingOver", "Deleting"):
        keys.append("cond:no-recovery-point")
    elif rpo is not None and v.get("rpo_cfg") and rpo > v["rpo_cfg"]:
        keys.append("cond:rpo-over-target")
    if st and st != "MeetingSLA":
        keys.append(f"status:{st}")
    return keys


def _live_alerts(v: dict) -> list[dict]:
    return sorted((a for a in v.get("alerts") or [] if a.get("level") in ("Error", "Warning")),
                  key=lambda a: (a.get("level") != "Error", a.get("id") or ""))


def keys_for(v: dict) -> list[str]:
    """Every key a fix for this VPG could be filed under, most specific first - what
    the "add a team fix" form offers."""
    out = []
    for k in [a.get("id") for a in _live_alerts(v)] + state_keys(v):
        if k and k not in out:
            out.append(k)
    return out


def suggest(v: dict, limit: int = 3) -> list[dict]:
    """Ordered suggestions for one unhealthy VPG: its live alerts (errors first), then
    what its replication state calls for; per key, team entries before the
    researched one. Deduplicated; at most `limit`."""
    ctx = {"vpg": v.get("name"), "zorg": v.get("org")}
    out, seen = [], set()
    texts = {a.get("id"): a.get("text") or "" for a in _live_alerts(v)}
    for k in keys_for(v):
        if k in seen:
            continue
        seen.add(k)
        for e in entries_for(k):
            out.append(_render(k, e, texts.get(k, ""), ctx))
            if len(out) >= limit:
                return out
    return out


def validate(key: str, title: str, fix: str, caution: str) -> tuple[str, str | None]:
    """(normalised key, error or None) for an engineer's entry."""
    key = (key or "").strip()
    if ALERT_CODE.match(key.upper()):
        key = key.upper()
    elif not STATE_KEY.match(key):
        return key, ("file it under a Zerto alert code (e.g. VPG0035) or a condition "
                     "(cond:..., sub:..., status:...)")
    if not (fix or "").strip():
        return key, "describe the fix"
    for name, val in (("title", title), ("fix", fix), ("caution", caution)):
        if len(val or "") > LIMITS[name]:
            return key, f"the {name} is longer than {LIMITS[name]} characters"
    unknown = sorted({p for p in _PLACEHOLDER.findall((fix or "") + (caution or "") + (title or ""))
                      if p not in DEFAULTS})
    if unknown:
        return key, ("unknown placeholder " + ", ".join("{" + u + "}" for u in unknown)
                     + " - available: " + ", ".join("{" + p + "}" for p in sorted(DEFAULTS)))
    return key, None


def catalogue() -> list[dict]:
    """Every key with an entry of either kind, for the Playbook page."""
    shipped, team = entries(), team_entries()
    out = []
    for k in sorted(set(shipped) | set(team), key=lambda k: (":" in k, k)):
        e = shipped.get(k) or {}
        out.append({"key": k, "title": e.get("title") or (team.get(k) or [{}])[0].get("title") or "",
                    "researched": dict(e) if e else None, "team": team.get(k, []),
                    "condition": CONDITIONS.get(k, "")})
    return out
