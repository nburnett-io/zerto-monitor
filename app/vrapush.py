"""Resize a VRA to its sizing standard through the ZVM API - deliberately, one at a time.

A resize is a PLANNED REPLICATION OUTAGE, not a settings change. Zerto applies a
memory/vCPU change by powering the VRA off: every VPG with a VM or a recovery volume on
it stops replicating (VRA0028), VPGs recovering to it can't fail over until it's back,
and a Bitmap or (protected side) Delta Sync follows. Design and sources: the research
of 2026-10-05 (vra_push_design.md). In short:

  armed     global switch + the site armed + its OWN ManageVRA credential + a pinned TLS
            certificate + the host connection method attested as public-key (VIB)
  previewed every check, the exact request and the blast radius before anything is sent
  admin     engineers preview; only an admin starts a resize, with a ticket + attestations
  gated     re-checked on a fresh poll just before the write: health, version, identity,
            blast radius, VPG states, Zerto tasks in flight, site errors
  one-shot  one PUT, never retried, never queued; one resize in flight estate-wide,
            30 min cooldown, 24 h apart until five have succeeded, at most 4 a day a site
  watched   task -> VRA back (size, status, alerts) -> nothing else changed -> every
            affected VPG healthy again; holds keep those VPGs out of alerting meanwhile
  halted    any outcome but 'done' stops all resizes until an admin acknowledges it
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import requests

import crypto
import db
import views
from zerto import (WRITE_ALLOWED, WRITES_RESIZE, ZvmClient, ZvmError, build_resize_body, ci, parse_task_id,
                   pinned_session)

log = logging.getLogger("vrapush")

TASK_TIMEOUT = 30 * 60
VRA_BACK = 20 * 60                 # KB 3077: involve Support if VRA0028 persists 10-15 min
VPG_RECOVER = 90 * 60
HOLD_MINUTES = 30 + 20 + 90 + 15   # the runner's own limits, plus slack for poll/sleep overshoot
QUEUE_EXPIRY = 10 * 60             # an admin's go is for now, not for whenever the worker gets to it
CONFLICT_STATES = (1, 2, 3, 7)     # in progress, waiting for user input, paused, cancelling
COOLDOWN = 30 * 60
BURNIN_COUNT, BURNIN_GAP = 5, 24 * 3600
DAILY_CAP = 4
LOST_RESPONSE_WATCH = 5 * 60
POLL_TASK, POLL_VRA, POLL_VPG = 10, 15, 60
MIN_HISTORY_MIN = 280              # 2 x the longest window
TASK_DONE, TASK_FAILED, TASK_RUNNING = {6}, {4, 5}, {1}
CONFLICT_TYPES = re.compile(r"vra|host|failover|move|clone|test|evacuat|upgrade|install|recover|backup|"
                            r"retention|copy", re.I)
BAD_STATUS = {"FailingOver", "Moving", "Deleting"}
BAD_SUBS = {"InitialSync", "VolumeInitialSync", "Sync", "NeedsConfiguration", "RecoveryStorageError",
            "ReplicationPausedForMissingVolume"}
TERMINAL = {"done", "failed", "unknown", "refused"}


class PushError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# ── switches and the halt latch ─────────────────────────────────────────────
def enabled() -> bool:
    return db.get_setting("vra_push_enabled") == "true"


def halted() -> dict | None:
    try:
        h = json.loads(db.get_setting("vra_push_halted") or "null")
    except ValueError:
        h = {"reason": "unreadable halt record"}
    return h or None


def _halt(push_id: int, reason: str) -> None:
    db.set_setting("vra_push_halted", json.dumps({"push_id": push_id, "reason": reason[:300], "at": _iso(_now())}))


def acknowledge_halt(user: str, note: str) -> None:
    h = halted()
    if h and h.get("push_id"):
        db.update_vra_push(int(h["push_id"]), acked_by=user, acked_note=note[:500])
    db.set_setting("vra_push_halted", "")
    db.log_alert("[vra-push]", "settings", "", None, f"{user} cleared the resize halt: {note[:200]}", "-", True)


def zvm_versions() -> list[str]:
    return [v.strip() for v in (db.get_setting("vra_push_zvm_versions") or "10.9").split(",") if v.strip()]


# ── where things are ────────────────────────────────────────────────────────
def _site_source(site: str, source_id: int | None = None) -> tuple[dict | None, dict | None, dict | None]:
    """(source, its latest payload, the snapshot row) for the enabled ZVM that reports a
    site. With source_id, only that source will do (a running resize must keep reading the
    ZVM it is changing); otherwise a live source wins over one whose last poll failed."""
    snaps = db.get_snapshots()
    found = []
    for s in db.list_sources(enabled_only=True):
        if s["kind"] != "zvm" or (source_id is not None and s["id"] != source_id):
            continue
        sn = snaps.get(s["id"]) or {}
        p = sn.get("payload") or {}
        if p.get("site") == site:
            found.append((not sn.get("ok"), s["id"], s, p, sn))
    if not found:
        return None, None, None
    _, _, s, p, sn = min(found, key=lambda x: (x[0], x[1]))
    return s, p, sn


def push_pin(src: dict) -> str | None:
    """The certificate a change to this ZVM is sent over: one pinned for it explicitly,
    else the pin the polling connection has trusted since the source was added."""
    return src.get("push_cert_fp") or db.source_pins(src).get(443)


def site_problems(src: dict) -> list[str]:
    """What every kind of change needs from the site: armed, and reached over a pinned (or
    CA-verified) certificate. The source's own credential makes the change."""
    out = []
    if not src.get("allow_changes"):
        out.append(f"{src['name']} isn't armed for changes")
    if not (src.get("verify_tls") or push_pin(src)):
        out.append(f"{src['name']}'s certificate isn't pinned")
    return out


def arming_problems(src: dict | None) -> list[str]:
    if not src:
        return ["no ZVM source reports this site"]
    out = []
    if not enabled():
        out.append("VRA resizing is switched off for this appliance (Admin → Sources → VRA resizing)")
    out += site_problems(src)
    if (src.get("push_host_auth") or "unknown") != "vib":
        out.append(f"{src['name']}'s host connection method isn't attested as public-key (VIB); "
                   "password-mode hosts are out of scope")
    h = halted()
    if h:
        out.append(f"resizes are halted after #{h.get('push_id')}: {h.get('reason')} - an admin must acknowledge it")
    return out


def pacing_problems(site: str, ignore_push: int | None = None) -> list[str]:
    out = []
    active = [p for p in db.active_vra_pushes() if p["id"] != ignore_push]
    if active:
        out.append(f"resize #{active[0]['id']} ({active[0].get('host')}) is {active[0]['state']} - one at a time")
    last = db.last_done_push()
    if last and last.get("finished_at"):
        until = datetime.fromisoformat(last["finished_at"]) + timedelta(seconds=COOLDOWN)
        if _now() < until:
            out.append(f"cooling down after #{last['id']} until {until:%H:%M} UTC")
    recent = [p for p in db.vra_pushes_since(_iso(_now() - timedelta(seconds=BURNIN_GAP)))
              if p["state"] != "refused" and p["id"] != ignore_push]
    if db.vra_push_done_count() < BURNIN_COUNT and recent:
        nxt = datetime.fromisoformat(recent[-1]["at"]) + timedelta(seconds=BURNIN_GAP)
        out.append(f"until {BURNIN_COUNT} resizes have succeeded they run 24 h apart - next from {nxt:%Y-%m-%d %H:%M} UTC")
    if len([p for p in recent if p.get("site") == site]) >= DAILY_CAP:
        out.append(f"{site} has had {DAILY_CAP} resizes in the last 24 h")
    return out


def _names_host(text: str, label: str) -> bool:
    return bool(label) and re.search(rf"(?<![\w.-]){re.escape(label)}(?![\w-])", (text or "").lower()) is not None


def affected(site: str, vra: dict, source_id: int | None = None) -> dict:
    """Every VPG with a VM protected on, or recovering to, this VRA's host - matched by
    host identifier, never by name - with each one's state and alert codes now."""
    src, p, _ = _site_source(site, source_id)
    hid, label = vra.get("host_id"), views.host_label(vra.get("host"))
    merged = views.merged_vpgs()
    sites = {(x.get("payload") or {}).get("site") for x in db.get_snapshots().values()}
    rows = []
    for v in (p or {}).get("vpgs") or []:
        roles = set()
        for m in v.get("members") or []:
            ph, rh = m.get("protected_host_id"), m.get("recovery_host_id")
            if hid and (ph or rh):
                if ph == hid:
                    roles.add("protected")
                if rh == hid:
                    roles.add("recovery")
            else:                                   # data from before host ids were collected
                if views.host_label(m.get("protected_host")) == label:
                    roles.add("protected")
                if views.host_label(m.get("recovery_host")) == label:
                    roles.add("recovery")
        if not roles:
            continue
        mv = merged.get(v.get("id")) or v
        peer = v.get("recovery_site") if v.get("protected_site") == site else v.get("protected_site")
        rows.append({"key": v.get("id"), "name": v.get("name"), "org": v.get("org"), "roles": sorted(roles),
                     "status": v.get("status"), "sub": v.get("sub"), "rpo": v.get("rpo"), "rpo_cfg": v.get("rpo_cfg"),
                     "history_cfg_min": v.get("history_cfg_min"), "testing": bool(v.get("testing")),
                     "health": mv.get("health"), "priority": v.get("priority"), "last_test": v.get("last_test"),
                     "codes": sorted({a.get("id") for a in v.get("alerts") or []
                                      if a.get("id") and a.get("level") in ("Error", "Warning")}),
                     "peer": peer, "peer_monitored": peer in sites})
    rows.sort(key=lambda r: (r["org"] or "", r["name"] or ""))
    prot = sum("protected" in r["roles"] for r in rows)
    rec = sum("recovery" in r["roles"] for r in rows)
    return {"vpgs": rows, "protected": prot, "recovery": rec,
            "counts_match": (prot, rec) == (vra.get("protected_vpgs") or 0, vra.get("recovery_vpgs") or 0),
            "customer_peers": sorted({r["peer"] for r in rows if r["peer"] and not r["peer_monitored"]})}


def _vpg_ok(r: dict) -> list[str]:
    why = []
    if r["status"] != "MeetingSLA":
        why.append(f"status {r['status']}")
    if (r["sub"] or "None") != "None":
        why.append(f"sub-status {r['sub']}")
    rpo, cfg = r.get("rpo"), r.get("rpo_cfg")
    if rpo is None or rpo < 0 or (cfg and rpo > cfg):
        why.append(f"RPO {rpo}s against a {cfg}s target")
    if r.get("testing"):
        why.append("a failover test is running")
    if r.get("history_cfg_min") is not None and r["history_cfg_min"] < MIN_HISTORY_MIN:
        why.append(f"only {r['history_cfg_min']} min of journal history configured")
    return why


# ── the preview ─────────────────────────────────────────────────────────────
def plan(site: str, key: str, lower: bool = False, ignore_push: int | None = None,
         source_id: int | None = None) -> dict:
    """Everything an admin needs to decide, computed from the latest poll. Writes nothing.
    ignore_push: the resize being run right now, so it doesn't count against itself."""
    vs = views.vras_site(site)
    row = next((r for r in vs["vras"] if r["key"] == key), None)
    if not row:
        return {"error": "that VRA isn't in the current data", "site": site, "key": key}
    src, payload, snap = _site_source(site, source_id)
    z = row["sizing"]
    m, c = int(row.get("mem_gb") or 0), int(row.get("cpus") or 0)
    if lower and z["can_lower"]:
        tm, tc = int(z["target_mem"]), int(z["target_cpus"])
    else:
        lower = False
        tm, tc = int(z["push_mem"]), int(z["push_cpus"])
    flags = views.vra_flags(row, tm, tc)
    aff = affected(site, row, (src or {}).get("id"))
    label = views.host_label(row.get("host"))
    alerts = (payload or {}).get("alerts") or []
    live = [a for a in alerts if not a.get("dismissed")]
    host_alerts = [a for a in live if (a.get("id") or "").startswith(("VRA", "ZVM0002", "ZVM0024"))
                   and _names_host(a.get("text"), label)]
    site_errors = [a for a in live if a.get("level") == "Error" and (a.get("entity") or "").lower() == "vra"
                   and a not in host_alerts]
    peers_down = [a for a in live if a.get("id") == "ZVM0003" and any(
        p and p.lower() in (a.get("text") or "").lower() for p in {r["peer"] for r in aff["vpgs"]})]
    vpg_codes = sorted({c for r in aff["vpgs"] for c in r["codes"]})
    gates = []

    def gate(gid, name, problems, blocking=True):
        gates.append({"id": gid, "name": name, "ok": not problems, "blocking": blocking, "detail": problems})

    gate("G1", "Armed", arming_problems(src))
    gate("G2", "Pacing", pacing_problems(site, ignore_push))
    zvm_problems = []
    ver = (payload or {}).get("version") or ""
    if not any(ver.startswith(v) for v in zvm_versions()):
        zvm_problems.append(f"ZVM version {ver or '?'} isn't one this has been validated against ({', '.join(zvm_versions())})")
    if (payload or {}).get("flavour") != "appliance":
        zvm_problems.append("only Zerto 10 appliances (Keycloak) are supported")
    interval = int(db.get_setting("poll_interval", "120") or 120)
    taken = views._parse_iso((snap or {}).get("taken_at"))
    if not (snap or {}).get("ok") or not taken or _now() - taken > timedelta(seconds=max(300, 2 * interval)):
        zvm_problems.append("the last good poll is too old - poll the source first")
    gate("G3", "ZVM", zvm_problems)
    health = []
    if "unhealthy" in flags:
        health.append(f"VRA status {row.get('status')}, alert status {row.get('alert_status')}"
                      + (", ghost" if row.get("is_ghost") else "") + (", disconnected" if row.get("disconnected") else ""))
    if "maintenance" in flags:
        health.append("VRA is in a maintenance state")
    health += [f"{a.get('id')}: {(a.get('text') or '')[:120]}" for a in host_alerts]
    gate("G5", "VRA health", health)
    version = []
    if "version_lag" in flags:
        version.append(f"VRA runs {row.get('version')} but the ZVM runs {row.get('zvm_version')} - upgrade the VRA first")
    gate("G6", "VRA version", version)
    size = []
    if (tm, tc) == (m, c):
        size.append("already at its target - a no-op edit would still power-cycle it")
    if not (1 <= tm <= views.VRA_MEM_MAX and 1 <= tc <= views.VRA_CPU_MAX):
        size.append(f"{tm} GB / {tc} vCPU is outside 1-{views.VRA_MEM_MAX} GB, 1-{views.VRA_CPU_MAX} vCPU")
    if "beyond_guidance" in flags and not z.get("support_ref"):
        size.append(f"beyond Zerto's {views.GUIDE_MEM} GB / {views.GUIDE_CPU} vCPU guidance: the rule needs a Zerto case reference")
    if "no_id" in flags:
        size.append("Zerto reported no identifier for this VRA")
    gate("G7", "Size", size)
    gate("G9", "Blast radius", [] if aff["counts_match"] else [
        f"found {aff['protected']} protected / {aff['recovery']} recovery VPGs on this host, but Zerto counts "
        f"{row.get('protected_vpgs')} / {row.get('recovery_vpgs')} - the data disagrees, so the blast radius is unknown"])
    gate("G10", "Affected VPGs", [f"{r['name']} ({r['org']}): {', '.join(_vpg_ok(r))}" for r in aff["vpgs"] if _vpg_ok(r)])
    gate("G11", "Zerto tasks in flight", [], blocking=False)    # checked live just before sending
    gate("G12", "Site state", [f"{a.get('id')}: {(a.get('text') or '')[:120]}" for a in site_errors + peers_down],
         blocking=False)

    needs = {"headroom_gb": tm - m if tm > m else 0, "tier_cross": "tier_cross" in flags,
             "typed_host": lower, "site_alerts": [f"{a.get('id')}" for a in site_errors + peers_down],
             "vpg_codes": vpg_codes}
    preview_body = {"memoryInGb": tm, "numOfCpus": tc, "groupName": row.get("group"),
                    "vraNetworkDataApi": {"vraIPConfigurationTypeApi": row.get("ip_config"),
                                          "vraIPAddress": row.get("ip"), "vraIPAddressRangeEnd": None,
                                          "subnetMask": row.get("mask"), "defaultGateway": row.get("gw")},
                    "usePublicKeyInsteadOfCredentials": True}
    fingerprint = {"site": site, "key": key, "vra": row.get("id"), "host_id": row.get("host_id"),
                   "from": [m, c], "to": [tm, tc], "lower": lower,
                   "affected": sorted(r["key"] for r in aff["vpgs"] if r["key"]),
                   "site_alerts": needs["site_alerts"], "vpg_codes": vpg_codes}
    return {"site": site, "key": key, "vra": row, "source": src, "zvm_version": ver,
            "rule": {"source": z["source"], "support_ref": z.get("support_ref"), "target": [z["target_mem"], z["target_cpus"]]},
            "current": [m, c], "target": [tm, tc], "lower": lower, "can_lower": z["can_lower"],
            "flags": flags, "affected": aff, "gates": gates, "needs": needs,
            "blocking": [g for g in gates if g["blocking"] and not g["ok"]],
            "request": {"method": "PUT", "url": f"https://{(src or {}).get('host')}/v1/vras/{row.get('id')}",
                        "body": preview_body},
            "plan_hash": hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()[:16],
            "hold_minutes": HOLD_MINUTES, "as_of": (snap or {}).get("taken_at")}


def start(site: str, key: str, lower: bool, user: dict, form: dict) -> int:
    """Admin's go: re-plan, check every gate and attestation, record the push. The
    worker sends it within seconds - after re-checking everything on a fresh poll."""
    if user.get("role") != "admin":
        raise PushError("only an admin can start a resize")
    pl = plan(site, key, lower)
    if pl.get("error"):
        raise PushError(pl["error"])
    if pl["blocking"]:
        raise PushError("; ".join(f"{g['id']} {g['name']}: {g['detail'][0]}" for g in pl["blocking"]))
    if form.get("plan_hash") != pl["plan_hash"]:
        raise PushError("something changed since the preview was opened - review it again")
    n, r = pl["needs"], pl["vra"]
    missing = []
    if not (form.get("ticket") or "").strip():
        missing.append("a ticket / change number")
    for box, needed, what in (("ack_outage", True, "the planned-outage acknowledgement"),
                              ("ack_vib", True, "the connection-method check for this VRA"),
                              ("ack_headroom", n["headroom_gb"] > 0, f"the +{n['headroom_gb']} GB host headroom check"),
                              ("ack_tier", n["tier_cross"], "the driver-reload (maintenance window) acknowledgement"),
                              ("ack_site", bool(n["site_alerts"]), "the site-alert acknowledgement"),
                              ("ack_codes", bool(n["vpg_codes"]), "the acknowledgement of the VPGs' current alerts")):
        if needed and form.get(box) != "yes":
            missing.append(what)
    if n["typed_host"] and views.host_label(form.get("typed_host")) != views.host_label(r.get("host")):
        missing.append("the host name typed in full (lowering)")
    if missing:
        raise PushError("missing: " + "; ".join(missing))
    attest = {k: form.get(k) for k in ("ack_outage", "ack_vib", "ack_headroom", "ack_tier", "ack_site", "ack_codes")}
    attest["typed_host"] = form.get("typed_host") if n["typed_host"] else None
    return db.log_vra_push(
        by_user=user["username"], site=site, source_id=pl["source"]["id"], vra_id=r["id"], vra_key=key,
        cluster=r.get("cluster"), host=r.get("host"), host_id=r.get("host_id"),
        from_mem=pl["current"][0], from_cpus=pl["current"][1], to_mem=pl["target"][0], to_cpus=pl["target"][1],
        state="queued", detail=f"started by {user['username']}; checks run again on a fresh poll before sending",
        ticket=(form.get("ticket") or "").strip()[:100], attest=json.dumps(attest), plan_hash=pl["plan_hash"],
        affected=json.dumps(pl["affected"]["vpgs"]), preflight=json.dumps(pl["gates"]),
        lowers="1" if pl["lower"] else "0", rule=json.dumps(pl["rule"]), zvm=pl["source"]["host"],
        zvm_version=pl["zvm_version"])


# ── the runner ──────────────────────────────────────────────────────────────
def _refresh(source_id: int) -> None:
    """A fresh, synchronous poll of one source - gates must see live data. Raises if the
    poll failed: the last GOOD payload stays in the snapshot, and judging anything from
    it would mean judging pre-outage data."""
    import collector
    src = db.get_source(source_id)
    if not src:
        raise RuntimeError("the source is gone")
    ok, err, payload, ms = collector.collect_source(src)
    collector.store(src, ok, err, ms, payload)
    if not ok:
        raise RuntimeError(err or "poll failed")


def change_client(src: dict, writes: tuple) -> ZvmClient:
    """A client on the source's own (read/write) credential, over the pinned certificate,
    able to make exactly the writes given. The polling client is built with no writes."""
    session = None if src.get("verify_tls") else pinned_session(src["host"], push_pin(src))
    c = ZvmClient(src["host"], src["auth_type"], src.get("identity") or "",
                  crypto.decrypt(src.get("secret_enc") or ""), bool(src.get("verify_tls")), session=session,
                  writes=writes)
    c.login()
    return c


def _push_client(src: dict) -> ZvmClient:
    return change_client(src, WRITES_RESIZE)


def _notify(p: dict, level: str, text: str) -> None:
    """Sent/done/failed go out at once - no dwell - and always into the alert log."""
    db.log_alert(f"[vra-push] {p.get('site')}", "vra-resize", level, None, f"#{p['id']} {p.get('host')}: {text}"[:600],
                 "-", level in ("", "info"))
    if level in ("", "info") and db.get_setting("vra_push_notify_info", "false") != "true":
        return
    try:
        import alerts
        cfg = alerts.config()
        rcpts = alerts._recipients(cfg["alert_default_recipients"])
        if cfg["smtp_host"] and rcpts:
            alerts.send_email(rcpts, f"[Zerto Monitor] VRA resize #{p['id']} {p.get('host')}: {level or 'info'}",
                              f"{text}\n\nSite {p.get('site')}, ticket {p.get('ticket')}, by {p.get('by_user')}.\n")
        if cfg["snmp_trap_enabled"]:
            alerts.send_trap({"name": f"[vra-push] {p.get('site')}", "level": level or "warning",
                              "event": "raised" if level else "cleared", "minutes": 0, "failure": 0,
                              "warning": 0, "vpgs": 0, "worst_rpo": "-", "sites": [p.get("site")]})
    except Exception:  # noqa: BLE001 - notification must never break the runner
        log.exception("resize notification failed")


def _end(p: dict, state: str, detail: str, keep_holds: bool = False) -> None:
    if state not in ("done", "refused"):
        _halt(p["id"], f"{state}: {detail[:200]}")       # first: if anything below fails, resizing stays halted
    db.update_vra_push(p["id"], state=state, detail=detail[:900], finished_at=_iso(_now()))
    if not keep_holds:
        db.release_holds(p["id"], state)
    if state != "done":
        _notify(p, "failure" if state in ("failed", "unknown") else "warning", f"{state} - {detail}")
    else:
        _notify(p, "info", detail)


def _host_alerts(alerts: list, label: str) -> list:
    return [a for a in alerts or [] if not ci(a, "IsDismissed")
            and (ci(a, "HelpIdentifier") or "").startswith(views.VRA_ALERT_PREFIXES)
            and _names_host(ci(a, "Description"), label)]


def run_one(p: dict, *, sleep=time.sleep, clock=time.monotonic, refresh=_refresh, client_factory=_push_client) -> None:
    """Carry out one started resize from the last checks to the end (blocking). Whatever
    goes wrong, it ENDS: an unexpected error before the PUT refuses it (nothing was sent);
    after it, the outcome is unknown, resizing halts and the holds are kept."""
    try:
        _run(p, sleep, clock, refresh, client_factory)
    except Exception as e:  # noqa: BLE001 - a resize must never be left in flight
        log.exception("resize #%s: unexpected error", p["id"])
        cur = db.get_vra_push(p["id"]) or p
        why = f"{type(e).__name__}: {str(e)[:160]}"
        if cur.get("state") == "queued" or (cur.get("state") == "sending" and not p.get("_put_started")):
            _end(cur, "refused", f"nothing was sent - the monitor hit an error before sending ({why})")
        elif cur.get("state") not in TERMINAL:
            _end(cur, "unknown", f"the monitor hit an error after the resize was sent ({why}) - check the VRA "
                                 "and its VPGs in Zerto/vCenter", keep_holds=True)


def _relogin(cl, logged_in: float, clock) -> float:
    """Tokens last ~5 min: refresh every 4. A failed refresh is just a failed read - the
    next call fails and is counted like any other unreadable answer."""
    if clock() - logged_in <= 240:
        return logged_in
    try:
        cl.login()
        return clock()
    except (ZvmError, requests.RequestException):
        return logged_in


def _run(p: dict, sleep, clock, refresh, client_factory) -> None:
    site, key, lower = p["site"], p["vra_key"], p.get("lowers") == "1"
    try:
        refresh(p["source_id"])
    except Exception as e:  # noqa: BLE001
        return _end(p, "refused", f"couldn't take a fresh poll before sending: {e}")
    pl = plan(site, key, lower, ignore_push=p["id"], source_id=p["source_id"])
    if pl.get("error"):
        return _end(p, "refused", pl["error"])
    blocking = pl["blocking"]
    if blocking:
        return _end(p, "refused", "checks failed on a fresh poll: " +
                    "; ".join(f"{g['id']} {g['name']}: {g['detail'][0]}" for g in blocking))
    if pl["plan_hash"] != p.get("plan_hash"):
        return _end(p, "refused", "the VRA, its target, its VPGs or their alerts changed since the preview - "
                                  "nothing was sent; preview it again")
    src, row, (tm, tc) = pl["source"], pl["vra"], pl["target"]
    label = views.host_label(row.get("host"))
    try:
        cl = client_factory(src)
        logged_in = clock()
        cur = cl.get(f"/v1/vras/{row['id']}")
        drift = [f"{name} {have!r} (expected {want!r})" for name, have, want in (
            ("host", views.host_label(ci(cur, "HostDisplayName")), label),
            ("host id", ci(cur, "HostIdentifier"), row.get("host_id")),
            ("memory", ci(cur, "MemoryInGB"), row.get("mem_gb")),
            ("vCPUs", ci(cur, "NumOfCpus"), row.get("cpus")),
            ("group", ci(cur, "VraGroup"), row.get("group"))) if have != want]
        if (ci(cur, "Status") or 0) != 0 or (ci(ci(cur, "VraAlerts") or {}, "VraAlertsStatus") or 0) != 0 \
                or ci(cur, "IsGhost"):
            drift.append("the VRA isn't healthy right now")
        if drift:
            return _end(p, "refused", "the live VRA doesn't match the preview: " + "; ".join(drift))
        aff_keys = {v["key"] for v in pl["affected"]["vpgs"] if v["key"]}
        conflicts = []
        for status in CONFLICT_STATES:
            for t in cl.get(f"/v1/tasks?status={status}") or []:
                rel = ci(t, "RelatedEntities") or {}
                hosts = {ci(x, "identifier") for x in ci(rel, "Hosts") or []}
                vpgs = {ci(x, "identifier") for x in ci(rel, "Vpgs") or []}
                typ = ci(t, "Type") or ""
                if row.get("host_id") in hosts or aff_keys & vpgs or CONFLICT_TYPES.search(typ):
                    conflicts.append(f"{typ or 'task'} (state {status})")
        if conflicts:
            return _end(p, "refused", "Zerto has work in flight that a VRA restart would disturb: " + ", ".join(conflicts[:5]))
        body = build_resize_body(cur, tm, tc)
        if not WRITE_ALLOWED.fullmatch(f"/v1/vras/{row['id']}"):
            raise ZvmError(f"the VRA id {row['id']!r} isn't one the resize may send to")
    except ZvmError as e:
        return _end(p, "refused", f"nothing was sent: {e}")
    except requests.RequestException as e:
        return _end(p, "refused", f"nothing was sent - the ZVM didn't answer: {type(e).__name__}")

    # ── point of no return: record everything, hold the affected VPGs, send ONCE ──
    sent = _now()
    hold_until = sent + timedelta(minutes=HOLD_MINUTES)
    db.update_vra_push(p["id"], state="sending", sent_at=_iso(sent), before_json=json.dumps(cur)[:20000],
                       request_json=json.dumps(body), hold_until=_iso(hold_until),
                       detail="sending the resize to the ZVM")
    db.add_holds(p["id"], pl["affected"]["vpgs"], _iso(hold_until))
    p["_put_started"] = True                 # from here on the PUT may have reached the ZVM
    try:
        status, resp = cl.put(f"/v1/vras/{row['id']}", body)
    except requests.RequestException as e:
        return _lost(p, cl, row, label, f"no answer to the PUT ({type(e).__name__})", sleep, clock)
    except ZvmError as e:
        db.update_vra_push(p["id"], response_json=json.dumps({"error": str(e)}))
        return _lost(p, cl, row, label, str(e), sleep, clock)
    _notify(p, "info", f"resize sent: {row.get('mem_gb')}G/{row.get('cpus')} -> {tm}G/{tc} vCPU; "
                       f"{len(aff_keys)} VPG(s) held until {hold_until:%H:%M} UTC")
    db.update_vra_push(p["id"], response_json=json.dumps({"status": status, "body": resp})[:5000])
    task_id = parse_task_id(resp) if status == 200 else None
    if not task_id:
        return _lost(p, cl, row, label, f"unexpected answer {status}: {str(resp)[:150]}", sleep, clock)

    # ── the ZVM task ──
    db.update_vra_push(p["id"], state="task_running", task_id=task_id, detail=f"ZVM task {task_id} running")
    deadline, state, t, errors = clock() + TASK_TIMEOUT, None, {}, 0
    while clock() < deadline:
        sleep(POLL_TASK)
        logged_in = _relogin(cl, logged_in, clock)
        try:
            t = cl.task(task_id)
            errors = 0
        except (ZvmError, requests.RequestException):
            errors += 1
            if errors >= 6:                 # a finished task can become unreadable: watch the VRA instead
                break
            continue
        st = ci(t, "Status") or {}
        state = ci(st, "State")
        db.update_vra_push(p["id"], task_json=json.dumps(t)[:5000],
                           detail=f"ZVM task {task_id}: state {state}, {ci(st, 'Progress', 0)}%")
        if state in TASK_DONE or state in TASK_FAILED or state not in TASK_RUNNING:
            break
    if state in TASK_FAILED:
        return _end(p, "failed", f"the ZVM task failed: {ci(t, 'CompleteReason') or 'no reason given'} - "
                                 "the VRA may be powered off; check it in vCenter/Zerto", keep_holds=True)
    if state is not None and state not in TASK_DONE and state not in TASK_RUNNING:
        return _end(p, "unknown", f"the ZVM task is in state {state} - check it in Zerto", keep_holds=True)
    if state in TASK_RUNNING:
        return _end(p, "unknown", f"the ZVM task didn't finish in {TASK_TIMEOUT // 60} min", keep_holds=True)
    db.update_vra_push(p["id"], task_done_at=_iso(_now()), state="vra_returning",
                       detail="task done - waiting for the VRA to come back at its new size")

    # ── the VRA comes back ──
    deadline, after, why = clock() + VRA_BACK, {}, "never read"
    while clock() < deadline:
        logged_in = _relogin(cl, logged_in, clock)
        try:
            after = cl.get(f"/v1/vras/{row['id']}") or {}
            alerts = cl.get("/v1/alerts") or []
        except (ZvmError, requests.RequestException) as e:
            why = f"couldn't read it: {e}"
            sleep(POLL_VRA)
            continue
        ha = _host_alerts(alerts, label)
        if any((ci(a, "HelpIdentifier") or "") == "VRA0029" for a in ha):
            return _end(p, "failed", "VRA0029: the VRA's memory isn't reserved - check it in vCenter", keep_holds=True)
        why = (f"{ci(after, 'MemoryInGB')} GB / {ci(after, 'NumOfCpus')} vCPU, status {ci(after, 'Status')}, "
               f"alert status {ci(ci(after, 'VraAlerts') or {}, 'VraAlertsStatus')}"
               + (f", {', '.join(ci(a, 'HelpIdentifier') for a in ha)}" if ha else ""))
        if (ci(after, "MemoryInGB") == tm and ci(after, "NumOfCpus") == tc and (ci(after, "Status") or 0) == 0
                and (ci(ci(after, "VraAlerts") or {}, "VraAlertsStatus") or 0) == 0 and not ci(after, "IsGhost")
                and not ha):
            break
        sleep(POLL_VRA)
    else:
        return _end(p, "unknown", f"the VRA isn't back after {VRA_BACK // 60} min ({why}) - "
                                  "power it on / check it in vCenter (Zerto KB 4137)", keep_holds=True)
    back_iso = _iso(_now())
    db.update_vra_push(p["id"], vra_back_at=back_iso, after_json=json.dumps(after)[:20000])

    # ── nothing else changed ──
    drift = [f for f in ("VraGroup", "HostIdentifier", "DatastoreIdentifier", "NetworkIdentifier", "VraVersion")
             if ci(cur, f) != ci(after, f)]
    nb, na = ci(cur, "VraNetworkDataApi") or {}, ci(after, "VraNetworkDataApi") or {}
    drift += [f"network {k}" for k in ("VraIPConfigurationTypeApi", "VraIPAddress", "SubnetMask", "DefaultGateway")
              if ci(nb, k) != ci(na, k)]
    if drift:
        return _end(p, "failed", f"the VRA came back but these changed too: {', '.join(drift)}", keep_holds=True)

    # ── its VPGs recover ──
    db.update_vra_push(p["id"], state="vpgs_recovering",
                       detail=f"VRA back at {tm} GB / {tc} vCPU - waiting for its VPGs to recover")
    pending = {v["key"]: v for v in pl["affected"]["vpgs"] if v["key"]}
    healthy_once: set = set()
    back_at, deadline = clock(), clock() + VPG_RECOVER
    observed: dict = {}
    while pending and clock() < deadline:
        sleep(POLL_VPG)
        try:
            refresh(p["source_id"])
        except Exception:  # noqa: BLE001
            continue
        # judge recovery only on a good poll taken after the VRA came back - never on the
        # last good payload from before the outage, which would say "all healthy"
        sn = db.get_snapshots().get(p["source_id"]) or {}
        if not sn.get("ok") or (sn.get("taken_at") or "") < back_iso:
            continue
        now_aff = {v["key"]: v for v in affected(site, pl["vra"], p["source_id"])["vpgs"]}
        # host fields can be blank for a poll right after a VRA power cycle: a VPG that
        # merely stops matching the host is still judged on its own state, by id
        now_all = {v.get("id"): v for v in (sn.get("payload") or {}).get("vpgs") or []}
        for k in list(pending):
            v = now_aff.get(k) or ({**now_all[k], "health": now_all[k].get("health")} if k in now_all else None)
            if not v:                      # the VPG no longer exists on this ZVM - nothing to wait for
                pending.pop(k)
                db.release_holds(p["id"], "no longer reported", k)
                continue
            observed.setdefault(k, []).append(f"{v['status']}/{v['sub']}/{v['rpo']}")
            bad = (v["status"] in BAD_STATUS or v["sub"] in BAD_SUBS or
                   (v.get("history_cfg_min") and v.get("rpo") and v["rpo"] > v["history_cfg_min"] * 30) or
                   (v["health"] == "failure" and clock() - back_at > 15 * 60))
            if bad:
                db.release_holds(p["id"], "escalated", k)
                db.update_vra_push(p["id"], observed=json.dumps(observed)[:20000])
                return _end(p, "unknown", f"{v['name']} ({v['org']}) is {v['status']}/{v['sub']}, RPO {v['rpo']}s "
                                          "after the VRA came back - check it in Zerto", keep_holds=True)
            if not _vpg_ok(v):
                if k in healthy_once:
                    pending.pop(k)
                    db.release_holds(p["id"], "recovered", k)
                else:
                    healthy_once.add(k)
            else:
                healthy_once.discard(k)
        db.update_vra_push(p["id"], observed=json.dumps(observed)[:20000],
                           detail=f"VRA back; {len(pending)} VPG(s) still recovering")
    if pending:
        return _end(p, "unknown", f"{len(pending)} VPG(s) not healthy {VPG_RECOVER // 60} min after the VRA came "
                                  "back: " + ", ".join(v["name"] for v in list(pending.values())[:5]), keep_holds=True)
    db.update_vra_push(p["id"], vpgs_ok_at=_iso(_now()))
    _end(p, "done", f"{row.get('host')} is {tm} GB / {tc} vCPU and every affected VPG has recovered")


def _lost(p, cl, row, label, why, sleep, clock) -> None:
    """No clean answer to the PUT: never re-send. Watch for 5 minutes to learn whether
    it started; either way a person has to look."""
    deadline, changed = clock() + LOST_RESPONSE_WATCH, False
    while clock() < deadline:
        try:
            v = cl.get(f"/v1/vras/{row['id']}") or {}
            if (ci(v, "MemoryInGB"), ci(v, "NumOfCpus")) != (row.get("mem_gb"), row.get("cpus")) or \
                    (ci(ci(v, "VraAlerts") or {}, "VraAlertsStatus") or 0) != 0 or \
                    _host_alerts(cl.get("/v1/alerts") or [], label):
                changed = True
                break
        except (ZvmError, requests.RequestException):
            pass
        sleep(POLL_VRA)
    if changed:
        _end(p, "unknown", f"{why}; the VRA has started changing - follow it in Zerto/vCenter", keep_holds=True)
    else:
        _end(p, "failed", f"{why}; the VRA shows no change after {LOST_RESPONSE_WATCH // 60} min, so it was "
                          "probably not applied - confirm in Zerto before trying again")


async def worker(idle_seconds: float = 5):
    """The one place resizes run. Started with the app; strictly one at a time."""
    import asyncio
    for p in db.active_vra_pushes():
        if p["state"] != "queued":     # mid-flight when the monitor stopped: never re-send
            _end(p, "unknown", f"the monitor restarted while this was {p['state']} - check the VRA and its VPGs "
                               "in Zerto; the affected VPGs' holds expire on their own", keep_holds=True)
    while True:
        try:
            todo = [p for p in db.active_vra_pushes() if p["state"] == "queued"]
            if not todo:
                await asyncio.sleep(idle_seconds)
                continue
            started = datetime.fromisoformat(todo[0]["at"])
            if _now() - started > timedelta(seconds=QUEUE_EXPIRY):
                _end(todo[0], "refused", f"not sent: it waited more than {QUEUE_EXPIRY // 60} minutes after the "
                                         "go (the monitor was busy or restarting) - preview it again")
                continue
            await asyncio.to_thread(run_one, todo[0])
            try:
                import collector
                await collector.poll_once(todo[0]["source_id"])
            except Exception:  # noqa: BLE001
                log.exception("post-resize poll failed")
        except Exception:  # noqa: BLE001
            log.exception("resize worker error")
            await asyncio.sleep(idle_seconds)
