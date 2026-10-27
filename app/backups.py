"""VPG settings backups, kept 7 days, and restoring a VPG from one.

BACKUP. Every Zerto 10 ZVM already writes a full export of its VPGs' settings once a
day and keeps about 30 of them (GET /v1/vpgSettings/exportedSettings; verified on all
three ZVMs 2026-10-06). Reading one back is a POST with read semantics
(/v1/vpgSettings/exportedSettings/{timeStamp}) that the read-only polling client may make.
So backups need no write access: each hour the monitor checks every ZVM for an export it
hasn't stored yet and keeps each VPG's settings - compressed and Fernet-encrypted, because
pre/post-recovery script parameters can carry credentials - for `backup_days` (7). The
copy lives off the ZVM, so it survives the ZVM. "Back up now" asks the ZVM for a fresh
export first when the site is armed; otherwise it stores the newest daily export.

RESTORE re-creates a VPG that no longer exists, from a backup, with Zerto's own import
(POST /v1/vpgSettings/import) on the ZVM the backup came from. It is a write: admin only,
the site armed for changes and the restore switch on, the source's credential over the
pinned certificate, a ticket, the VPG's name typed in full, checked again on a fresh poll,
sent once and never retried, its Zerto task followed to the end. A VPG that still exists
is never imported over: compare the backup with it instead and fix the difference in Zerto.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import requests

import crypto
import db
from zerto import WRITES_EXPORT, WRITES_RESTORE, ZvmError, ci

log = logging.getLogger("backups")

RESTORE_TASK_TIMEOUT = 60 * 60
SECRET_KEYS = {"parameters"}           # scripting parameters may hold credentials: never shown


class RestoreError(Exception):
    pass


def enabled_restore() -> bool:
    return db.get_setting("vpg_restore_enabled") == "true"


def retention_days() -> int:
    return max(1, min(int(db.get_setting("backup_days", "7") or 7), 90))


def _zorg_names(payload: dict) -> dict[str, str]:
    return {z.get("id"): z.get("name") for z in (payload or {}).get("zorgs") or [] if z.get("id")}


def store_export(src: dict, site: str, export_ts: str, items: list, zorgs: dict[str, str],
                 origin: str = "daily") -> int:
    rows, now = [], db.now_iso()
    for it in items or []:
        basic = ci(it, "Basic") or {}
        name = ci(basic, "Name")
        if not name:
            continue
        blob = json.dumps(it, sort_keys=True, separators=(",", ":")).encode()
        rows.append({"site": site, "source_id": src["id"], "export_ts": export_ts, "captured_at": now,
                     "vpg_id": ci(it, "VpgIdentifier"), "vpg_name": name,
                     "zorg": zorgs.get(ci(basic, "ZorgIdentifier")),
                     "protected_site": ci(it, "SourceSiteName"), "recovery_site": ci(it, "TargetSiteName"),
                     "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob),
                     "data_enc": crypto.encrypt_blob(blob), "origin": origin})
    return db.save_backups(rows)


def collect(src: dict, client, payload: dict, force: bool = False) -> str:
    """Store the newest export this ZVM has, unless it is already stored."""
    site = (payload or {}).get("site") or src["name"]
    exports = sorted(ci(x, "TimeStamp") for x in client.get("/v1/vpgSettings/exportedSettings") or []
                     if ci(x, "TimeStamp"))
    if not exports:
        return f"{site}: the ZVM has no exports yet"
    ts = exports[-1]
    if not force and db.backup_exists(site, ts):
        return f"{site}: export {ts} already stored"
    data = client.post_read(f"/v1/vpgSettings/exportedSettings/{ts}", {"VpgNames": []}) or {}
    items = ci(data, "ExportedVpgSettingsApi") or []
    # Zerto reports VPGs it couldn't convert ("Failed to convert export VPG settings for the
    # following VPGs: ...") alongside everything it did export: keep those, flag the rest
    warn = (ci(data, "ErrorMessage") or "").strip()
    db.set_setting(f"backup_warn_{src['id']}", f"{site}: {warn}"[:1000] if warn else "")
    if not items:
        return f"{site}: nothing exported" + (f" - Zerto said {warn}" if warn else "")
    n = store_export(src, site, ts, items, _zorg_names(payload))
    db.set_setting(f"backup_last_{src['id']}", db.now_iso())
    log.info("%s: stored %d VPG settings from export %s%s", site, n, ts, f" (Zerto: {warn[:200]})" if warn else "")
    return (f"{site}: stored {n} VPGs from Zerto's export of {ts[:16].replace('T', ' ')} UTC"
            + (f"; Zerto couldn't export some: {warn[:300]}" if warn else ""))


def backup_now(src: dict, payload: dict, vpg_names: list[str] | None, user: str) -> str:
    """On demand. On an armed site, a FRESH export (of just these VPGs, or all); otherwise the
    newest daily export."""
    import collector
    import vrapush
    site = (payload or {}).get("site") or src["name"]
    if not vrapush.site_problems(src):
        cl = vrapush.change_client(src, WRITES_EXPORT)
        status, r = cl.write("POST", "/v1/vpgSettings/exportSettings", {"VpgNames": vpg_names or []},
                             "Exporting VPG settings needs Zerto's VPG management privilege.")
        res = ci(r, "ExportResult") or {} if isinstance(r, dict) else {}
        ts = ci(r, "TimeStamp") if isinstance(r, dict) else None
        if status != 200 or not ts or (ci(res, "Result") or "").lower() not in ("", "success", "succeeded"):
            raise ZvmError(f"the ZVM didn't export ({status}): {ci(res, 'Message') or str(r)[:150]}")
        data = cl.post_read(f"/v1/vpgSettings/exportedSettings/{ts}", {"VpgNames": vpg_names or []}) or {}
        n = store_export(src, site, ts, ci(data, "ExportedVpgSettingsApi") or [], _zorg_names(payload), "manual")
        if ci(data, "ErrorMessage"):
            return f"Fresh export stored: {n} VPG(s) at {site}; Zerto couldn't export some: {ci(data, 'ErrorMessage')[:300]}"
        db.log_alert(f"[backup] {site}", "backup", "", None,
                     f"{user} took a fresh backup of {n} VPG(s) at {site}", "-", True)
        return f"Fresh export taken and stored: {n} VPG(s) at {site}"
    cl = collector.polling_client(src)
    msg = collect(src, cl, payload, force=False)
    return msg + " (a fresh export needs the site armed - Admin → Changes to Zerto)"


# ── reading, comparing ──────────────────────────────────────────────────────
def load(backup_id: int) -> tuple[dict | None, dict | None]:
    b = db.get_backup(backup_id)
    if not b:
        return None, None
    return b, json.loads(crypto.decrypt_blob(b["data_enc"]))


ID_KEYS = ("VmIdentifier", "VolumeIdentifier", "NicIdentifier", "BootGroupIdentifier")


def flatten(obj, prefix: str = "") -> dict[str, object]:
    """Settings as path -> value. Lists of VMs, volumes, NICs and boot groups are keyed by
    their identifier, so a reordered list isn't reported as a change."""
    out: dict[str, object] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = next((str(v[k]) for k in ID_KEYS if isinstance(v, dict) and v.get(k)), str(i))
            out.update(flatten(v, f"{prefix}[{key}]"))
    else:
        out[prefix] = obj
    return out


def shown(path: str, value) -> object:
    """What a page may show of one setting: script parameters only as set / empty."""
    leaf = path.rsplit(".", 1)[-1].lower()
    if leaf in SECRET_KEYS:
        return "(set - hidden)" if value else "(empty)"
    return value


def diff(a: dict, b: dict) -> list[dict]:
    fa, fb = flatten(a), flatten(b)
    out = []
    for k in sorted(set(fa) | set(fb)):
        if k in ("Generation", "VpgSettingsIdentifier"):
            continue
        va, vb = fa.get(k, "(absent)"), fb.get(k, "(absent)")
        if va != vb:
            out.append({"path": k, "old": shown(k, va), "new": shown(k, vb)})
    return out


def summary(item: dict) -> dict:
    basic = ci(item, "Basic") or {}
    rec = ci(item, "Recovery") or {}
    vcd = ci(rec, "VCD") or ci(rec, "Vcd") or {}
    journal = ci(item, "Journal") or {}
    lim = ci(journal, "Limitation") or {}
    script = ci(item, "Scripting") or {}
    return {"name": ci(basic, "Name"), "type": ci(basic, "VpgType"), "rpo_s": ci(basic, "RpoInSeconds"),
            "journal_h": ci(basic, "JournalHistoryInHours"), "test_interval_min": ci(basic, "TestIntervalInMinutes"),
            "priority": ci(basic, "Priority"), "wan_compression": ci(basic, "UseWanCompression"),
            "vms": len(ci(item, "Vms") or []),
            "volumes": sum(len(ci(v, "Volumes") or []) for v in ci(item, "Vms") or []),
            "target": ("vCD org vDC " + str(ci(vcd, "OrgVdcIdentifier"))) if ci(vcd, "OrgVdcIdentifier") else
                      ("vSphere " + ", ".join(str(x) for x in (ci(rec, "DefaultHostClusterIdentifier"),
                                                               ci(rec, "DefaultHostIdentifier"),
                                                               ci(rec, "DefaultDatastoreIdentifier")) if x)),
            "journal_limit": f"{ci(lim, 'HardLimitInPercent') or ci(lim, 'HardLimitInMB')}"
                             f"{'%' if ci(lim, 'HardLimitInPercent') else ' MB'} hard / "
                             f"{ci(lim, 'WarningThresholdInPercent') or ci(lim, 'WarningThresholdInMB')}"
                             f"{'%' if ci(lim, 'WarningThresholdInPercent') else ' MB'} warning",
            "pre_script": bool(ci(ci(script, "PreRecovery") or {}, "Command")),
            "post_script": bool(ci(ci(script, "PostRecovery") or {}, "Command")),
            "protected_site": ci(item, "SourceSiteName"), "recovery_site": ci(item, "TargetSiteName")}


def previous_of(b: dict) -> dict | None:
    """The same VPG's backup just before this one (same site), to compare against."""
    rows = [r for r in db.list_backups(vpg_name=b["vpg_name"], site=b["site"]) if r["export_ts"] < b["export_ts"]]
    return rows[0] if rows else None


# ── restore ─────────────────────────────────────────────────────────────────
def _exists(name: str, vpg_id: str | None) -> list[str]:
    import views
    hits = []
    for k, v in views.merged_vpgs().items():
        if (vpg_id and v.get("id") == vpg_id) or (v.get("name") or "").lower() == (name or "").lower():
            hits.append(f"{v.get('name')} ({v.get('org') or 'no zORG'}, {v.get('protected_site')} → {v.get('recovery_site')})")
    return hits


def restore_plan(backup_id: int) -> dict:
    import views
    import vrapush
    b, item = load(backup_id)
    if not b:
        return {"error": "that backup no longer exists (backups are kept "
                         f"{retention_days()} days)"}
    src = db.get_source(b["source_id"]) if b.get("source_id") else None
    snap = (db.get_snapshots().get(src["id"]) or {}) if src else {}
    payload = snap.get("payload") or {}
    problems = []
    if not enabled_restore():
        problems.append("VPG restores are switched off (Admin → Changes to Zerto)")
    if not src or not src.get("enabled"):
        problems.append(f"the ZVM this backup came from ({b['site']}) isn't an enabled source")
    else:
        problems += vrapush.site_problems(src)
        if payload.get("flavour") != "appliance":
            problems.append("only Zerto 10 appliances (Keycloak) are supported")
        if not views.source_ok(snap):
            problems.append(f"{src['name']}'s last poll failed or is stale - poll it first")
    exists = _exists(b["vpg_name"], b.get("vpg_id"))
    if exists:
        problems.append("a VPG with this name or identifier exists right now: " + "; ".join(exists[:3]) +
                        ". Import never overwrites one - compare the settings and correct them in Zerto, or delete it first")
    body = {"exportedVpgSettingsApi": [item], "vpgNames": [b["vpg_name"]]}
    h = hashlib.sha256(json.dumps({"b": backup_id, "sha": b["sha256"], "exists": exists,
                                   "src": (src or {}).get("id")}, sort_keys=True).encode()).hexdigest()[:16]
    return {"backup": b, "summary": summary(item), "source": src, "problems": problems, "exists": exists,
            "request": {"method": "POST", "url": f"https://{(src or {}).get('host')}/v1/vpgSettings/import",
                        "vpgNames": body["vpgNames"]},
            "plan_hash": h}


def start_restore(backup_id: int, user: dict, form: dict) -> int:
    if user.get("role") != "admin":
        raise RestoreError("only an admin can restore a VPG")
    pl = restore_plan(backup_id)
    if pl.get("error"):
        raise RestoreError(pl["error"])
    if pl["problems"]:
        raise RestoreError(pl["problems"][0])
    if form.get("plan_hash") != pl["plan_hash"]:
        raise RestoreError("something changed since the preview was opened - review it again")
    if not (form.get("ticket") or "").strip():
        raise RestoreError("a ticket / change number is required")
    if (form.get("typed_name") or "").strip() != pl["backup"]["vpg_name"]:
        raise RestoreError("type the VPG's name exactly as shown to confirm")
    if form.get("ack_sync") != "yes":
        raise RestoreError("acknowledge that a restored VPG starts with an initial sync and no journal history")
    b = pl["backup"]
    cid = db.log_change(kind="restore", by_user=user["username"], site=b["site"], source_id=b["source_id"],
                        target=b["vpg_name"], zorg=b.get("zorg"), ticket=form["ticket"].strip()[:100],
                        state="queued", detail="queued; checked again on a fresh poll before sending",
                        request_json=json.dumps({"vpgNames": [b["vpg_name"]], "backup": b["id"],
                                                 "export_ts": b["export_ts"], "plan_hash": pl["plan_hash"]}),
                        backup_id=b["id"])
    db.log_alert(f"[restore] {b.get('zorg') or b['site']}", "restore", "", None,
                 f"{user['username']} started restoring VPG {b['vpg_name']} from the {b['export_ts'][:10]} "
                 f"backup ({form['ticket'].strip()[:40]})", "-", True)
    return cid


def _end(ch: dict, state: str, detail: str) -> None:
    db.update_change(ch["id"], state=state, detail=detail[:900], finished_at=db.now_iso())
    db.log_alert(f"[restore] {ch.get('zorg') or ch.get('site')}", "restore",
                 "" if state == "done" else "failure", None, f"restore of {ch['target']}: {state} - {detail}"[:600],
                 "-", state == "done")


def run_restore(ch: dict, *, refresh=None, client_factory=None, sleep=time.sleep, clock=time.monotonic) -> None:
    """Carry one queued restore to the end. Never retried, never re-sent."""
    import vrapush
    refresh = refresh or vrapush._refresh
    client_factory = client_factory or (lambda s: vrapush.change_client(s, WRITES_RESTORE))
    try:
        req = json.loads(ch.get("request_json") or "{}")
        try:
            refresh(ch["source_id"])
        except Exception as e:  # noqa: BLE001
            return _end(ch, "refused", f"nothing was sent - couldn't take a fresh poll: {e}")
        pl = restore_plan(ch["backup_id"])
        if pl.get("error") or pl["problems"]:
            return _end(ch, "refused", "nothing was sent: " + (pl.get("error") or pl["problems"][0]))
        if pl["plan_hash"] != req.get("plan_hash"):
            return _end(ch, "refused", "nothing was sent: something changed since the preview - review it again")
        _, item = load(ch["backup_id"])
        cl = client_factory(pl["source"])
        live = [v for v in cl.get("/v1/vpgs") or [] if (ci(v, "VpgName") or "").lower() == ch["target"].lower()]
        if live:
            return _end(ch, "refused", "nothing was sent: the ZVM reports a VPG with that name now")
        db.update_change(ch["id"], state="sending", detail="sending the import to the ZVM")
    except Exception as e:  # noqa: BLE001
        log.exception("restore #%s before sending", ch["id"])
        return _end(ch, "refused", f"nothing was sent - error before sending: {type(e).__name__}: {str(e)[:150]}")
    try:
        status, r = cl.write("POST", "/v1/vpgSettings/import",
                             {"exportedVpgSettingsApi": [item], "vpgNames": [ch["target"]]},
                             "Importing VPGs needs Zerto's VPG management privilege.")
        db.update_change(ch["id"], response_json=json.dumps({"status": status, "body": r})[:20000])
        if status >= 500:                   # e.g. a 502/504 while Zerto is creating the VPG
            return _end(ch, "unknown", f"the ZVM answered {status} - the import may still have run; check Zerto")
        if status != 200 or not isinstance(r, dict):
            return _end(ch, "failed", f"the ZVM answered {status}: {str(r)[:200]}")
        vfail = ci(r, "ValidationFailedResults") or []
        ifail = ci(r, "ImportFailedResults") or []
        tasks = [ci(t, "TaskIdentifier") for t in ci(r, "ImportTaskIdentifiers") or [] if ci(t, "TaskIdentifier")]
        if vfail or ifail:
            msgs = [m for x in vfail for m in (ci(x, "ErrorMessages") or [])] + [ci(x, "ErrorMessage") for x in ifail]
            return _end(ch, "failed", "Zerto refused the import: " + "; ".join(str(m) for m in msgs if m)[:600])
        if not tasks:
            return _end(ch, "unknown", "Zerto accepted the import but returned no task - check the VPG in Zerto")
        db.update_change(ch["id"], state="task_running", task_id=",".join(tasks), detail=f"Zerto task {tasks[0]} running")
        deadline, state, t = clock() + RESTORE_TASK_TIMEOUT, None, {}
        logged = clock()
        while clock() < deadline:
            sleep(15)
            if clock() - logged > 240:
                try:
                    cl.login()
                    logged = clock()
                except (ZvmError, requests.RequestException):
                    pass
            try:
                t = cl.task(tasks[0])
            except (ZvmError, requests.RequestException):
                continue
            state = ci(ci(t, "Status") or {}, "State")
            db.update_change(ch["id"], detail=f"Zerto task: state {state}, {ci(ci(t, 'Status') or {}, 'Progress', 0)}%")
            if state not in (1, 2, 3, 7):
                break
        if state == 6:
            return _end(ch, "done", f"VPG {ch['target']} re-created from the {req.get('export_ts', '')[:10]} backup; "
                                    "it starts with an initial sync")
        if state in (4, 5):
            return _end(ch, "failed", f"Zerto's task ended in state {state}: {ci(t, 'CompleteReason') or 'no reason given'}")
        return _end(ch, "unknown", f"Zerto's task hadn't finished after {RESTORE_TASK_TIMEOUT // 60} min (state {state}) "
                                   "- check it in Zerto")
    except Exception as e:  # noqa: BLE001 - after sending: never retry, say it plainly
        log.exception("restore #%s after sending", ch["id"])
        return _end(ch, "unknown", f"error after the import was sent ({type(e).__name__}: {str(e)[:150]}) "
                                   "- check the VPG in Zerto before trying again")


async def worker(idle_seconds: float = 5):
    """Restores run here, one at a time. A restore mid-flight when the monitor stopped is
    marked unknown, never re-sent."""
    import asyncio
    for ch in db.changes(kind="restore"):
        if ch["state"] in ("sending", "task_running"):
            _end(ch, "unknown", "the monitor restarted while this was running - check the VPG in Zerto")
    for kind in ("plan_create", "plan_update", "plan_delete"):          # sent inline; a restart leaves them hanging
        for ch in db.changes(kind=kind, state="sending"):
            db.update_change(ch["id"], state="unknown", finished_at=db.now_iso(),
                             detail="the monitor restarted while this was being sent - check the plan in Zerto")
    while True:
        try:
            todo = [c for c in db.changes(kind="restore", state="queued", limit=10)]
            if not todo:
                await asyncio.sleep(idle_seconds)
                continue
            ch = todo[-1]                                       # oldest first
            if datetime.now(timezone.utc) - datetime.fromisoformat(ch["at"]) > timedelta(minutes=10):
                _end(ch, "refused", "not sent: it waited more than 10 minutes after the go - preview it again")
                continue
            await asyncio.to_thread(run_restore, ch)
        except Exception:  # noqa: BLE001
            log.exception("restore worker error")
            await asyncio.sleep(idle_seconds)
