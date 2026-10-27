"""zORG alerting: dwell-time thresholds, delivered by email and SNMP trap.

Evaluated after every full poll. A zORG's health is the worst of its VPGs. Two
clocks run per zORG:

    fail_since  continuously in FAILURE since
    bad_since   continuously NOT HEALTHY (warning or failure) since

A rule raises FAILURE once fail_since is older than its error_minutes, and WARNING
once bad_since is older than its warning_minutes. Using a not-healthy clock for
warnings means a zORG flapping between warning and failure cannot keep resetting
its own timer and dodge the alert.

Notifications go out when the alert level RISES (none->warning, none->failure,
warning->failure), as a reminder every N hours while it holds, and once when the
zORG is healthy again. Easing from failure back to warning is not announced: it is
not an all-clear.

Email is per VPG: "[Zerto Monitor] <zORG> - <VPG> - Failure|Warning|Recovered", with the
details and links to the VPG and zORG pages. Each VPG has its own clock against its zORG
rule's thresholds, and is emailed when it crosses one, when it gets worse, as a reminder
while it holds, and once when it recovers (_vpg_notices). More than alert_vpg_email_cap
(25) in one evaluation - a site-wide event - and the rest go out as one roll-up. SNMP traps
stay one per zORG event, which is what trap receivers expect.

A source (ZVM/ZCM) that cannot be polled is also tracked, as "[source] <name>", under
the '*' rule's error threshold - otherwise a dead ZVM would silence every alert for
the zORGs behind it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import smtplib
import ssl
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from email.message import EmailMessage
from html import escape
from pathlib import Path

import crypto
import db
import playbook
import views
from zerto import fmt_age, reason

log = logging.getLogger("alerts")
RANK = {"": 0, "warning": 1, "failure": 2}
SOURCE_PREFIX = "[source] "

# NET-SNMP-MIB::netSnmpPlaypen - the arc net-snmp reserves for experimentation.
# Swap for your own Private Enterprise Number in Admin -> Alerting.
DEFAULT_TRAP_OID = "1.3.6.1.4.1.8072.9999.9999.7"
COMMUNITY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

# What the SNMP agent exposes. Must match the 'extend' lines the privileged helper
# writes into snmpd.conf (deploy/appliance/zerto-monitor-admin).
SNMP_EXTENDS = [
    ("zmVpgTotal", "vpgs", "VPGs, total"),
    ("zmVpgFailure", "failure", "VPGs in failure"),
    ("zmVpgWarning", "warning", "VPGs in warning"),
    ("zmVpgHealthy", "healthy", "VPGs healthy"),
    ("zmVpgIgnored", "ignored", "Unhealthy VPGs an admin has ignored"),
    ("zmVraTotal", "vras", "VRAs, total"),
    ("zmVraDown", "vras_disconnected", "VRAs disconnected"),
    ("zmVraMaskBad", "vras_mask_mismatch", "VRAs with subnet-mask drift"),
    ("zmSourcesDown", "sources_down", "ZVM/ZCM sources not answering"),
    ("zmOrgsFailure", "orgs_failure", "zORGs with a failing VPG"),
    ("zmOrgsWarning", "orgs_warning", "zORGs with warnings only"),
    ("zmOrgsAlerting", "orgs_alerting", "zORGs past their alert threshold"),
    ("zmWorstRpoSec", "worst_rpo", "Worst RPO, seconds"),
]
_EXTEND_OUT = "1.3.6.1.4.1.8072.1.3.2.3.1.1"   # NET-SNMP-EXTEND-MIB::nsExtendOutput1Line


def snmp_oids() -> list[dict]:
    """Numeric OIDs for nsExtendOutput1Line."<name>" - index is length then ASCII."""
    return [{"name": n, "metric": m, "desc": d,
             "oid": f"{_EXTEND_OUT}.{len(n)}." + ".".join(str(ord(c)) for c in n)}
            for n, m, d in SNMP_EXTENDS]


class AlertError(RuntimeError):
    pass


# ── settings ────────────────────────────────────────────────────────────────
def _s(key: str, default: str = "") -> str:
    return db.get_setting(key, default) or default


def _flag(key: str, default: bool = False) -> bool:
    return _s(key, "true" if default else "false") == "true"


def config() -> dict:
    """Everything the admin page shows. Secrets are reported as present/absent only."""
    return {
        "alerts_enabled": _flag("alerts_enabled"),
        "alert_repeat_hours": int(_s("alert_repeat_hours", "24") or 24),
        "alert_notify_clear": _flag("alert_notify_clear", True),
        "alert_default_recipients": _s("alert_default_recipients"),
        "public_url": _s("public_url"),
        "smtp_host": _s("smtp_host"), "smtp_port": _s("smtp_port", "587"),
        "smtp_security": _s("smtp_security", "starttls"), "smtp_user": crypto.decrypt(_s("smtp_user")),
        "smtp_from": _s("smtp_from"), "smtp_verify": _flag("smtp_verify", True),
        "smtp_has_password": bool(_s("smtp_password")),
        "snmp_trap_enabled": _flag("snmp_trap_enabled"),
        "snmp_trap_targets": _s("snmp_trap_targets"),
        "snmp_trap_oid": _s("snmp_trap_oid", DEFAULT_TRAP_OID),
        "snmp_trap_has_community": bool(_s("snmp_trap_community")),
        "snmp_agent_enabled": _flag("snmp_agent_enabled"),
        "snmp_agent_source": _s("snmp_agent_source", "default"),
        "snmp_agent_has_community": bool(_s("snmp_agent_community")),
    }


def _recipients(text: str) -> list[str]:
    return [r.strip() for r in (text or "").replace(";", ",").split(",") if "@" in r]


def base_url() -> str:
    u = _s("public_url").strip().rstrip("/")
    if u:
        return u
    try:
        import tlsmgr
        return f"https://{tlsmgr.hostname()['fqdn']}"
    except Exception:                                       # noqa: BLE001
        return ""


# ── time helpers ────────────────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") if dt else None


_dt = views._parse_iso


def _mins(since: datetime | None, now: datetime) -> int:
    return int((now - since).total_seconds() // 60) if since else 0


def _fmt_mins(m: int) -> str:
    if m < 60:
        return f"{m} min"
    h, mm = divmod(m, 60)
    if h < 48:
        return f"{h}h {mm:02d}m"
    return f"{h // 24}d {h % 24}h"


# ── rule matching ───────────────────────────────────────────────────────────
def rule_for(name: str, rules: list[dict]) -> dict | None:
    """Exact zORG rule first, then '*'. Source pseudo-zORGs only ever use '*'."""
    if not name.startswith(SOURCE_PREFIX):
        for r in rules:
            if r["zorg"] == name:
                return r
    return next((r for r in rules if r["zorg"] == "*"), None)


# ── evaluation ──────────────────────────────────────────────────────────────
def _observations() -> list[dict]:
    """Current health per zORG, plus one pseudo-entry per unreachable source."""
    obs = []
    for o in views.zorg_list():
        health = "failure" if o["failure"] else "warning" if o["warning"] else "healthy"
        # failure/warning here already exclude ignored VPGs (views.zorg_list)
        obs.append({"name": o["name"], "health": health, "failure": o["failure"],
                    "warning": o["warning"], "healthy": o["healthy"], "vpgs": o["vpg_count"],
                    "worst_rpo": o["worst_rpo"], "sites": o["sites"], "bad": o["bad"],
                    "ignored": o.get("ignored", 0), "ignored_keys": o.get("ignored_keys") or [],
                    "keys": o.get("keys") or []})
    snaps = db.get_snapshots()
    for s in db.list_sources(enabled_only=True):
        sn = snaps.get(s["id"])
        if sn is None:
            continue                                        # never polled yet: no verdict
        down = not views.source_ok(sn)                      # a hung poller counts as down too
        obs.append({"name": SOURCE_PREFIX + s["name"], "health": "failure" if down else "healthy",
                    "failure": 1 if down else 0, "warning": 0, "healthy": 0 if down else 1,
                    "vpgs": 0, "worst_rpo": "-", "sites": [s["host"]],
                    "error": (sn.get("error") or f"no poll since {sn.get('taken_at')}" if down else "")[:300]})
    return obs


def evaluate(now: datetime | None = None, send: bool = True) -> list[dict]:
    """Advance every zORG's clocks and work out what to announce. Returns the events."""
    now = now or _now()
    obs = _observations()
    if not obs:
        return []                                           # no data yet: change nothing

    rules = db.alert_rules()
    states = db.zorg_states()
    enabled = _flag("alerts_enabled")
    repeat_h = int(_s("alert_repeat_hours", "24") or 24)
    notify_clear = _flag("alert_notify_clear", True)

    rows, events, seen, notes, told_of = [], [], set(), [], {}
    for o in obs:
        name, health = o["name"], o["health"]
        seen.add(name)
        st = states.get(name) or {}
        fail_since = _dt(st.get("fail_since")) if health == "failure" else None
        bad_since = _dt(st.get("bad_since")) if health != "healthy" else None
        if health == "failure" and not fail_since:
            fail_since = now
        if health != "healthy" and not bad_since:
            bad_since = now

        rule = rule_for(name, rules)
        level = ""
        if rule and rule["enabled"]:
            if fail_since and _mins(fail_since, now) >= int(rule["error_minutes"]):
                level = "failure"
            elif bad_since and _mins(bad_since, now) >= int(rule["warning_minutes"]):
                level = "warning"

        prev = st.get("alerted") or ""
        alerted, alerted_at = prev, _dt(st.get("alerted_at"))
        event = None
        # per-VPG clocks: a zORG already alerted at its level still announces a VPG that
        # goes bad later (a standing VPG0035 warning must not hide a new RPO breach)
        try:
            det = json.loads(st.get("detail") or "{}")
        except ValueError:
            det = {}
        bad = o.get("bad") or {}
        vpg_since = {k: (det.get("vpg_since") or {}).get(k) or _iso(now) for k in bad}
        # continuously in FAILURE since, like the zORG's fail_since: one failing poll after
        # hours of warning is not hours of failure
        vpg_fail = {k: (det.get("vpg_fail") or {}).get(k) or _iso(now) for k, (h, _n) in bad.items() if h == "failure"}
        told = [k for k in det.get("told") or [] if k in bad]
        new = [k for k, (h, _n) in bad.items() if rule and k not in told
               and _mins(_dt((vpg_fail if h == "failure" else vpg_since)[k]), now)
               >= int(rule["error_minutes"] if h == "failure" else rule["warning_minutes"])]
        if level and RANK[level] > RANK[prev]:
            event = "raised" if not prev else "escalated"
            alerted, alerted_at = level, now
        elif level and level == prev and repeat_h > 0 and alerted_at \
                and (now - alerted_at).total_seconds() >= repeat_h * 3600:
            event, alerted_at = "reminder", now
        elif health == "healthy" and prev:
            # healthy only because what's left is ignored? then it ISN'T healthy - stand
            # down quietly rather than send a false "all VPGs healthy again"
            event = "cleared" if (notify_clear and not o.get("ignored")) else None
            alerted, alerted_at = "", None
        elif level and RANK[level] < RANK[prev]:
            alerted = level                                 # eased, still bad: remember, don't announce
        elif level and prev and new:
            event = "updated"                               # same level, but another VPG went bad

        # with alerting switched off the clocks still run, but nothing new is marked
        # as announced - so switching it on later reports what is genuinely wrong.
        # A recovery while off is forgotten quietly rather than queued for later.
        if event and not enabled:
            if event == "cleared":
                alerted, alerted_at = "", None
            else:
                alerted, alerted_at = prev, _dt(st.get("alerted_at"))
            event = None
        if event == "cleared" or not alerted:
            told = []
        elif event:
            told = list(bad)                                # the digest lists every unhealthy VPG

        if event == "cleared":
            minutes = _mins(_dt(st.get("bad_since")), now)  # how long the outage lasted
        elif (level or prev) == "failure":
            minutes = _mins(fail_since, now)
        else:
            minutes = _mins(bad_since, now)
        if event:
            events.append({**o, "event": event, "level": level or "healthy", "minutes": minutes,
                           "rule": rule, "new": [bad[k][1] for k in new] if event == "updated" else []})
        # email is per VPG: each VPG's own clock, threshold and last notice
        vpg_told = det.get("vpg_told") or {}
        if not name.startswith(SOURCE_PREFIX):
            vpg_told, vn = _vpg_notices(o, rule, vpg_told, vpg_since, vpg_fail, det.get("vpg_since") or {}, now,
                                        enabled, repeat_h, notify_clear)
            notes += vn
        told_of[name] = vpg_told
        rows.append({"zorg": name, "health": health, "fail_since": _iso(fail_since),
                     "bad_since": _iso(bad_since), "alerted": alerted,
                     "alerted_at": _iso(alerted_at), "last_seen": _iso(now),
                     "detail": {**{k: o.get(k) for k in ("failure", "warning", "healthy", "vpgs", "worst_rpo")},
                                "vpg_since": vpg_since, "vpg_fail": vpg_fail, "told": told, "vpg_told": vpg_told}})

    failed = []
    if (events or notes) and send:
        try:
            failed = deliver(events, notes)
        except Exception:                                   # noqa: BLE001 - the clocks must still be saved
            log.exception("alert delivery failed")
    for n in failed:
        # an email that didn't go out isn't 'told': put back what was, so the next poll retries
        if n["prev"]:
            told_of[n["org"]][n["key"]] = n["prev"]
        else:
            told_of[n["org"]].pop(n["key"], None)
    # a zORG that disappeared (deleted, or its ZVM removed) leaves quietly
    gone = [z for z in states if z not in seen]
    db.save_zorg_states([{**r, "detail": json.dumps(r["detail"])} for r in rows], gone)
    return events


def _vpg_notices(o: dict, rule: dict | None, told: dict, since: dict, fail: dict, prev_since: dict, now: datetime,
                 enabled: bool, repeat_h: int, notify_clear: bool) -> tuple[dict, list[dict]]:
    """Which VPGs of one zORG get an email now, and what each VPG was last told.

    told: {vpg key: {"level", "name", "at"}}. A VPG is emailed when it has been unhealthy
    (for failure: continuously failing) longer than its zORG rule's threshold for its level
    (raised), when it gets worse (escalated), every repeat_h hours while it stays at that
    level (reminder), and once when it is healthy again (cleared). Easing from failure to
    warning is remembered, not announced. With alerting off nothing is marked as told, so
    switching it on reports what is wrong then. A VPG that became ignored, or vanished, is
    dropped without a 'recovered'. Each note carries the told entry it replaces ('prev')."""
    bad = o.get("bad") or {}
    ignored = set(o.get("ignored_keys") or [])
    present = set(o.get("keys") or [])
    active = bool(enabled and rule and rule.get("enabled"))
    keep, out = {}, []

    def note(kind, k, level, vname, minutes):
        return {"kind": kind, "key": k, "level": level, "name": vname, "org": o["name"], "minutes": minutes,
                "rule": rule, "sites": o.get("sites") or [], "prev": told.get(k)}

    for k, (h, vname) in bad.items():
        prev = told.get(k)
        mins = _mins(_dt(since.get(k)), now)
        if not active:
            if prev:
                keep[k] = prev
            continue
        threshold = int(rule["error_minutes"] if h == "failure" else rule["warning_minutes"])
        clock = _mins(_dt(fail.get(k)), now) if h == "failure" else mins
        if prev and RANK[h] <= RANK.get(prev.get("level") or "", 0):
            entry = dict(prev)
            if RANK[h] < RANK.get(prev.get("level") or "", 0):
                entry["level"] = h                          # eased: remember, don't announce
            elif repeat_h > 0 and _dt(prev.get("at")) and (now - _dt(prev["at"])).total_seconds() >= repeat_h * 3600:
                out.append(note("reminder", k, h, vname, mins))
                entry["at"] = _iso(now)
            keep[k] = entry
        elif clock >= threshold:
            out.append(note("escalated" if prev else "raised", k, h, vname, mins))
            keep[k] = {"level": h, "name": vname, "at": _iso(now)}
        elif prev:
            keep[k] = prev                                  # worse, but not yet past its threshold
    for k, prev in told.items():
        if k in bad or k not in present:
            continue                                        # still bad, or gone from Zerto: no 'recovered'
        if active and notify_clear and k not in ignored:
            out.append(note("cleared", k, "healthy", prev.get("name"), _mins(_dt(prev_since.get(k)), now)))
    return keep, out


# ── delivery ────────────────────────────────────────────────────────────────
def _summary(e: dict) -> str:
    after = f" after {_fmt_mins(e['minutes'])}" if e.get("minutes") else ""
    if e["name"].startswith(SOURCE_PREFIX):
        if e["event"] == "cleared":
            return f"{e['name'][len(SOURCE_PREFIX):]} is reachable again{after}"
        return (f"{e['name'][len(SOURCE_PREFIX):]} has not answered for "
                f"{_fmt_mins(e['minutes'])}: {e.get('error') or 'poll failed'}")
    if e["event"] == "cleared":
        return f"all {e['vpgs']} VPGs healthy again{after}"
    parts = []
    if e["failure"]:
        parts.append(f"{e['failure']} failing")
    if e["warning"]:
        parts.append(f"{e['warning']} warning")
    where = f" ({', '.join(e['sites'])})" if e.get("sites") else ""
    lead = ""
    if e["event"] == "updated" and e.get("new"):
        more = f" +{len(e['new']) - 3} more" if len(e["new"]) > 3 else ""
        lead = f"newly unhealthy: {', '.join(e['new'][:3])}{more}; now "
    return (f"{lead}{' and '.join(parts)} of {e['vpgs']} VPGs for {_fmt_mins(e['minutes'])}"
            f"{where}; worst RPO {e['worst_rpo']}")


def deliver(events: list[dict], notes: list[dict] = ()) -> list[dict]:
    """Send what evaluate() decided. VPGs: one email per VPG (deliver_vpg_notes). zORG
    events: one SNMP trap each (what trap receivers expect). A source that stopped
    answering: its own email as well, since it has no VPG to be about. Returns the VPG
    notes whose email failed."""
    cfg = config()
    default_to = _recipients(cfg["alert_default_recipients"])
    by_recipient: dict[str, list[dict]] = defaultdict(list)
    results: dict[int, list[str]] = defaultdict(list)

    for i, e in enumerate(events):
        rule = e.get("rule") or {}
        if e["name"].startswith(SOURCE_PREFIX) and rule.get("email", 1) and cfg["smtp_host"]:
            for r in (_recipients(rule.get("recipients") or "") or default_to):
                by_recipient[r].append(e)
                e.setdefault("_to", []).append(r)
        elif not e["name"].startswith(SOURCE_PREFIX) and rule.get("email", 1) and cfg["smtp_host"]:
            results[i].append("email:per-VPG")
        if rule.get("snmp", 1) and cfg["snmp_trap_enabled"]:
            try:
                send_trap(e)
                results[i].append("snmp:ok")
            except Exception as ex:                         # noqa: BLE001
                results[i].append(f"snmp:fail({str(ex)[:60]})")

    sent_ok: dict[str, bool] = {}
    for rcpt, evs in by_recipient.items():
        try:
            subject, text, html = _digest(evs)
            send_email([rcpt], subject, text, html)
            sent_ok[rcpt] = True
        except Exception as ex:                             # noqa: BLE001
            log.warning("email to %s failed: %s", rcpt, ex)
            sent_ok[rcpt] = False

    for i, e in enumerate(events):
        for r in e.get("_to", []):
            results[i].append(f"email:{r}:{'ok' if sent_ok.get(r) else 'fail'}")
        chans = " ".join(results[i]) or "no channel configured"
        ok = bool(results[i]) and not any(":fail" in c for c in results[i])
        db.log_alert(e["name"], e["event"], e["level"], e["minutes"], _summary(e), chans, ok)
    return deliver_vpg_notes(list(notes), cfg, default_to) if notes else []


VPG_EMAIL_CAP = 25          # per evaluation; beyond it one roll-up (a site outage must not send 500 emails)
_KIND_ORDER = {"raised": 0, "escalated": 0, "reminder": 2, "cleared": 3}


def deliver_vpg_notes(notes: list[dict], cfg: dict, default_to: list[str]) -> list[dict]:
    """One email per VPG to its zORG rule's recipients (or the defaults); each one logged.
    Returns the notes whose email failed to send, so the caller doesn't count them as told."""
    cap = max(1, int(_s("alert_vpg_email_cap", str(VPG_EMAIL_CAP)) or VPG_EMAIL_CAP))
    notes.sort(key=lambda n: (_KIND_ORDER.get(n["kind"], 1), -RANK.get(n["level"], 0), n["org"].lower(),
                              (n["name"] or "").lower()))
    try:
        merged = views.merged_vpgs()                        # once per delivery, not once per zORG
    except Exception:                                       # noqa: BLE001
        merged = {}

    url = base_url()
    emailable = [n for n in notes if cfg["smtp_host"] and (n.get("rule") or {}).get("email", 1)]
    sent_n = 0
    overflow, failed = defaultdict(list), []
    for n in notes:
        v = merged.get(n["key"])
        why = reason(v) if v and v["health"] != "healthy" else ""
        summary = f"{n['name']}: {'recovered' if n['kind'] == 'cleared' else n['level']}" + (f" - {why}" if why else "")
        if n not in emailable:
            db.log_alert(n["org"], n["kind"], n["level"], n["minutes"], summary[:600], "no channel configured", False)
            continue
        rcpts = _recipients((n.get("rule") or {}).get("recipients") or "") or default_to
        if not rcpts:
            db.log_alert(n["org"], n["kind"], n["level"], n["minutes"], summary[:600], "email: no recipients", False)
            continue
        if sent_n >= cap:
            overflow[tuple(sorted(rcpts))].append((n, summary))   # one roll-up per recipient set
            continue
        try:
            if v:
                v = dict(v, why=why, rpo_h=fmt_age(v["rpo"]),
                         fixes=playbook.suggest(v) if v["health"] != "healthy" else [])
            subject, text, html = vpg_email(n, v, url)
            send_email(rcpts, subject, text, html)
            chans, ok = "email:" + ",".join(rcpts) + ":ok", True
        except Exception as ex:                             # noqa: BLE001
            log.warning("VPG email for %s failed: %s", n["name"], ex)
            chans, ok = "email:" + ",".join(rcpts) + ":fail", False
            failed.append(n)
        sent_n += 1
        db.log_alert(n["org"], n["kind"], n["level"], n["minutes"], summary[:600], chans, ok)
    for rcpts, items in overflow.items():
        lines = [f"{'RECOVERED' if n['kind'] == 'cleared' else n['level'].upper():9} {n['org']} - {n['name']}"
                 + (f"  {url}/vpgs/{_q(n['key'])}" if url else "") for n, _ in items]
        try:
            send_email(list(rcpts), f"[Zerto Monitor] {len(items)} more VPG alerts (over {cap} in one poll)",
                       f"More than {cap} VPGs changed state in one poll - likely a site-wide event. "
                       f"Individual emails went out for the first {cap}; the rest are listed here.\n\n"
                       + "\n".join(lines) + (f"\n\n{url}/" if url else ""))
            chans, ok = "email:rollup:ok", True
        except Exception as ex:                             # noqa: BLE001
            log.warning("roll-up email failed: %s", ex)
            chans, ok = "email:rollup:fail", False
            failed += [n for n, _ in items]
        for n, summary in items:
            db.log_alert(n["org"], n["kind"], n["level"], n["minutes"], summary[:600], chans, ok)
    return failed


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "", safe="")


def vpg_email(n: dict, v: dict | None, url: str) -> tuple[str, str, str]:
    """[Zerto Monitor] <zORG> - <VPG> - Failure|Warning|Recovered, with the details and links."""
    cleared = n["kind"] == "cleared"
    label = "Recovered" if cleared else n["level"].capitalize()
    subject = f"[Zerto Monitor] {n['org']} - {n['name']} - {label}"
    lead = {"raised": f"{label}: unhealthy for {_fmt_mins(n['minutes'])}",
            "escalated": f"Now FAILURE (was warning) - unhealthy for {_fmt_mins(n['minutes'])}",
            "reminder": f"Still {n['level']} after {_fmt_mins(n['minutes'])} (reminder)",
            "cleared": f"Healthy again after {_fmt_mins(n['minutes'])}"}.get(n["kind"], label)
    vlink = f"{url}/vpgs/{_q(n['key'])}" if url else ""
    zlink = f"{url}/zorgs/{_q(n['org'])}" if url else ""
    facts: list[tuple[str, str]] = []
    alerts_, fixes = [], []
    if v:
        if v.get("why") and not cleared:
            facts.append(("What's wrong", v["why"]))
        facts.append(("Status", f"{v.get('status')} / {v.get('sub')}"))
        rpo = v.get("rpo")
        facts.append(("RPO", f"{v.get('rpo_h') or '-'} (target {_secs(v.get('rpo_cfg'))})" if rpo is not None else "-"))
        if v.get("history_cfg_min"):
            facts.append(("Journal history", f"{_secs((v.get('history_min') or 0) * 60)} of "
                                             f"{_secs(v['history_cfg_min'] * 60)} configured"))
        facts.append(("Path", f"{v.get('protected_site') or '?'} → {v.get('recovery_site') or '?'}"))
        facts.append(("VMs", f"{v.get('vms')}  ·  priority {v.get('priority') or '-'}  ·  last test "
                             f"{(v.get('last_test') or 'never')[:10]}"))
        facts.append(("Seen on", ", ".join(v.get("seen_on") or [])))
        if not cleared:
            alerts_ = [a for a in v.get("alerts") or [] if a.get("level") in ("Error", "Warning")][:6]
            fixes = (v.get("fixes") or [])[:2]
    colour = {"Failure": "#c62828", "Warning": "#b26a00", "Recovered": "#2e7d32"}.get(label, "#555")

    text = [f"{label.upper()}  {n['org']} - {n['name']}", lead, ""]
    text += [f"{k + ':':17}{val}" for k, val in facts]
    if alerts_:
        text += ["", "Zerto alerts:"] + [f"  {a.get('id')} ({a.get('level')}): {a.get('text')}" for a in alerts_]
    if fixes:
        text += ["", "Suggested fix:"] + [f"  - {(f.get('title') + ': ') if f.get('title') else ''}{f.get('fix')}"
                                          + (f"  [caution: {f['caution']}]" if f.get("caution") else "") for f in fixes]
    if vlink:
        text += ["", f"Open in Zerto Monitor: {vlink}", f"zORG {n['org']}: {zlink}"]

    h = ["<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2328;max-width:760px\">",
         "<div style=\"background:#0d1b2a;color:#fff;padding:10px 14px;border-left:4px solid #1b75bc\">"
         "<span style=\"font-weight:700;letter-spacing:.04em\">Zerto Monitor</span></div>",
         f"<p style=\"margin:14px 0 2px\"><span style=\"background:{colour};color:#fff;padding:2px 7px;"
         f"border-radius:3px;font-weight:600\">{label.upper()}</span> <b>{escape(n['org'])}</b> - "
         f"<b>{escape(n['name'] or '')}</b></p>",
         f"<p style=\"margin:2px 0 12px;color:#555\">{escape(lead)}</p>",
         "<table style=\"border-collapse:collapse;font-size:13px\">"]
    for k, val in facts:
        h.append(f"<tr><td style=\"padding:3px 14px 3px 0;color:#666;vertical-align:top;white-space:nowrap\">{escape(k)}</td>"
                 f"<td style=\"padding:3px 0\">{escape(str(val))}</td></tr>")
    h.append("</table>")
    if alerts_:
        h.append("<p style=\"margin:14px 0 4px;font-weight:600\">Zerto alerts</p><ul style=\"margin:0;padding-left:18px\">")
        h += [f"<li><b>{escape(a.get('id') or '')}</b> ({escape(a.get('level') or '')}): {escape(a.get('text') or '')}</li>"
              for a in alerts_]
        h.append("</ul>")
    if fixes:
        h.append("<p style=\"margin:14px 0 4px;font-weight:600\">Suggested fix</p><ul style=\"margin:0;padding-left:18px\">")
        for f in fixes:
            h.append("<li>" + (f"<b>{escape(f.get('title'))}:</b> " if f.get("title") else "")
                     + escape(f.get("fix") or "").replace("\n", "<br>")
                     + (f"<br><span style=\"color:#b26a00\">⚠ {escape(f['caution'])}</span>" if f.get("caution") else "")
                     + "</li>")
        h.append("</ul>")
    if vlink:
        h.append(f"<p style=\"margin:18px 0 6px\"><a href=\"{escape(vlink)}\" style=\"background:#1b75bc;color:#fff;"
                 f"padding:7px 14px;border-radius:3px;text-decoration:none\">Open {escape(n['name'] or 'the VPG')} in Zerto "
                 f"Monitor</a> &nbsp; <a href=\"{escape(zlink)}\">zORG {escape(n['org'])}</a></p>")
    h.append("<p style=\"color:#888;font-size:12px;margin-top:18px\">Sent by Zerto Monitor</p></div>")
    return subject[:240], "\n".join(text), "".join(h)


def _secs(s) -> str:
    return fmt_age(s) if s is not None else "-"


def _digest(evs: list[dict]) -> tuple[str, str, str]:
    """The email for sources that stopped (or resumed) answering - the only zORG-level events
    still emailed; VPGs get their own (vpg_email)."""
    url = base_url()
    if len(evs) == 1:
        e = evs[0]
        tag = "CLEARED" if e["event"] == "cleared" else e["level"].upper()
        subject = f"[Zerto Monitor] {tag}: {e['name']} - {_summary(e)}"
    else:
        counts = defaultdict(int)
        for e in evs:
            counts["cleared" if e["event"] == "cleared" else e["level"]] += 1
        bits = [f"{counts[k]} {k}" for k in ("failure", "warning", "cleared") if counts[k]]
        subject = f"[Zerto Monitor] {', '.join(bits)} ({len(evs)} zORGs)"

    order = {"failure": 0, "warning": 1, "healthy": 2}
    evs = sorted(evs, key=lambda e: (order.get(e["level"], 3), e["name"].lower()))
    text, html = [], []
    html.append("<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2328\">")
    # branded header as text: mail clients block remote images and many strip inline ones
    html.append("<div style=\"background:#0d1b2a;color:#fff;padding:10px 14px;border-left:4px solid #1b75bc\">"
                "<span style=\"font-weight:700;letter-spacing:.04em\">Zerto Monitor</span></div>")
    for e in evs:
        tag = "CLEARED" if e["event"] == "cleared" else e["level"].upper()
        colour = {"FAILURE": "#c62828", "WARNING": "#b26a00", "CLEARED": "#2e7d32"}.get(tag, "#555")
        text.append(f"{tag:8} {e['name']}  [{e['event']}]")
        text.append(f"         {_summary(e)}")
        html.append(f"<p style=\"margin:14px 0 4px\"><span style=\"background:{colour};color:#fff;"
                    f"padding:2px 7px;border-radius:3px;font-weight:600\">{tag}</span> "
                    f"<b>{escape(e['name'])}</b> <span style=\"color:#666\">({e['event']})</span><br>"
                    f"{escape(_summary(e))}</p>")
        text.append("")
    html.append(f"<p style=\"color:#888;font-size:12px;margin-top:20px\">Sent by Zerto Monitor"
                + (f" &middot; <a href=\"{escape(url)}\">{escape(url)}</a>" if url else "")
                + "</p></div>")
    return subject[:240], "\n".join(text), "".join(html)


def send_email(to: list[str], subject: str, text: str, html: str | None = None) -> None:
    host = _s("smtp_host").strip()
    if not host:
        raise AlertError("SMTP server is not configured")
    port = int(_s("smtp_port", "587") or 587)
    security = _s("smtp_security", "starttls")
    user = crypto.decrypt(_s("smtp_user")).strip()
    password = crypto.decrypt(_s("smtp_password"))
    sender = _s("smtp_from").strip() or (user if "@" in user else f"zerto-monitor@{host}")
    if not to:
        raise AlertError("no recipients")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    ctx = ssl.create_default_context()
    if not _flag("smtp_verify", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(host, port, timeout=30)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
        if user:
            if security not in ("starttls", "ssl"):
                raise AlertError("refusing to send the SMTP password over an unencrypted "
                                 "connection - choose STARTTLS or SSL")
            server.login(user, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:                                   # noqa: BLE001
            pass


def send_trap(e: dict) -> None:
    """One SNMPv2c trap via net-snmp's snmptrap. Varbinds under <base>.1.x."""
    targets = [t.strip() for t in _s("snmp_trap_targets").split(",") if t.strip()]
    community = crypto.decrypt(_s("snmp_trap_community"))
    base = _s("snmp_trap_oid", DEFAULT_TRAP_OID).strip().strip(".")
    if not targets:
        raise AlertError("no trap receivers configured")
    if not community:
        raise AlertError("no trap community configured")
    if not COMMUNITY_RE.match(community):         # it is written into a config file below
        raise AlertError("the trap community may only contain letters, digits, _ . -")
    exe = "/usr/bin/snmptrap"
    if not Path(exe).exists():
        raise AlertError("snmptrap is not installed (apt install snmp)")

    trap_oid = f"{base}.0.{2 if e['event'] == 'cleared' else 3 if e['event'] == 'test' else 1}"
    url = base_url()
    vb = [
        f"{base}.1.1", "s", e["name"][:200],
        f"{base}.1.2", "s", e["level"],
        f"{base}.1.3", "s", e["event"],
        f"{base}.1.4", "i", str(int(e.get("minutes") or 0)),
        f"{base}.1.5", "i", str(int(e.get("failure") or 0)),
        f"{base}.1.6", "i", str(int(e.get("warning") or 0)),
        f"{base}.1.7", "i", str(int(e.get("vpgs") or 0)),
        f"{base}.1.8", "s", _summary(e)[:250] if e["event"] != "test" else "Zerto Monitor test trap",
        f"{base}.1.9", "s", url,
    ]
    (db.DATA_DIR / "snmp").mkdir(parents=True, exist_ok=True)
    # The community goes in a private snmp.conf (defCommunity), never on the command
    # line, where every local account could read it from the process list. The file
    # lives for the length of the send in a 0700 directory in the service's private /tmp.
    import shutil
    import tempfile
    conf = tempfile.mkdtemp(prefix="zm-trap-")
    try:
        with open(os.open(os.path.join(conf, "snmp.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                  "w") as f:
            f.write(f"defVersion 2c\ndefCommunity {community}\n")
        env = dict(os.environ, MIBS="", SNMPCONFPATH=conf,
                   SNMP_PERSISTENT_DIR=str(db.DATA_DIR / "snmp"))
        errors = []
        for t in targets:
            target = t if ":" in t else f"{t}:162"
            p = subprocess.run([exe, "-On", target, "", trap_oid, *vb],
                               capture_output=True, text=True, timeout=20, env=env)
            if p.returncode != 0:
                errors.append(f"{t}: {(p.stderr or '').strip().splitlines()[-1:] or ['failed']}")
    finally:
        shutil.rmtree(conf, ignore_errors=True)
    if errors:
        raise AlertError("; ".join(errors))


# ── tests from the admin page ───────────────────────────────────────────────
def test_email(to: str = "") -> str:
    rcpts = _recipients(to) or _recipients(_s("alert_default_recipients"))
    if not rcpts:
        raise AlertError("add a default recipient (or a recipient on a rule) first")
    url = base_url()
    send_email(rcpts, "[Zerto Monitor] test message",
               "This is a test from Zerto Monitor. If you can read it, email alerting works.\n"
               + (f"\n{url}\n" if url else ""),
               "<p style=\"font-family:Segoe UI,Arial,sans-serif\">This is a test from "
               "<b>Zerto Monitor</b>. If you can read it, email alerting works.</p>"
               + (f"<p><a href=\"{escape(url)}\">{escape(url)}</a></p>" if url else ""))
    db.log_alert("(test)", "test", "", 0, "test email", "email:" + ",".join(rcpts) + ":ok", True)
    return ", ".join(rcpts)


def test_trap() -> str:
    send_trap({"name": "(test)", "level": "", "event": "test", "minutes": 0,
               "failure": 0, "warning": 0, "vpgs": 0})
    db.log_alert("(test)", "test", "", 0, "test trap", "snmp:ok", True)
    return _s("snmp_trap_targets")


def preview(now: datetime | None = None) -> list[dict]:
    """What switching alerting on right now would announce - without sending or saving."""
    states = db.zorg_states()
    now = now or _now()
    rules = db.alert_rules()
    out = []
    for o in _observations():
        st = states.get(o["name"]) or {}
        rule = rule_for(o["name"], rules)
        if not rule or not rule["enabled"] or o["health"] == "healthy":
            continue
        fs = _dt(st.get("fail_since")) if o["health"] == "failure" else None
        bs = _dt(st.get("bad_since"))
        if fs and _mins(fs, now) >= int(rule["error_minutes"]):
            out.append({**o, "level": "failure", "minutes": _mins(fs, now)})
        elif bs and _mins(bs, now) >= int(rule["warning_minutes"]):
            out.append({**o, "level": "warning", "minutes": _mins(bs, now)})
    return out


def state_rows() -> list[dict]:
    """Per-zORG clocks for the admin page, worst first."""
    now = _now()
    rows = []
    for z, st in db.zorg_states().items():
        if st["health"] == "healthy" and not st.get("alerted"):
            continue
        fs, bs = _dt(st.get("fail_since")), _dt(st.get("bad_since"))
        rows.append({"zorg": z, "health": st["health"], "alerted": st.get("alerted") or "",
                     "fail_for": _fmt_mins(_mins(fs, now)) if fs else "",
                     "bad_for": _fmt_mins(_mins(bs, now)) if bs else "",
                     "bad_mins": _mins(bs, now) if bs else 0})
    rows.sort(key=lambda r: (-RANK.get(r["health"] if r["health"] != "healthy" else "", 0),
                             -r["bad_mins"], r["zorg"].lower()))
    return rows
