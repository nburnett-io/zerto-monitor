"""Zerto events for the timeline: who changed, paused, tested or failed over what.

Two limits of Zerto's /v1/events (verified on 10.9, 2026-10-06):
  - per query it returns the LATEST 1000 events in the window and applies the category
    filter AFTER that cap - a 6-hour window holding 1000 alert on/off events returned zero
    real ones;
  - a busy ZVM keeps only a few days of events at all (about 3 days on one busy site).
So events are collected every poll, for the minutes since the last one (category=Events),
and the monitor's own copy (400 days) is the history. A one-time backfill reads back what
the ZVM still holds, in 1-hour windows to stay under the cap. Both ZVMs of a pair report the
same event with the same identifier, so it is stored once.

Failover-test results come from Zerto's recovery reports (RTO, result, who, notes).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import db
from zerto import ci

log = logging.getLogger("events")

KINDS = {
    "change": {"CreateProtectionGroup", "RemoveProtectionGroup", "UpdateProtectionGroup", "ProtectVM",
               "UnprotectVM", "ForceReconfigurationOfNewVM", "ForceRemoveProtectionGroup",
               "ForceUpdateProtectionGroup", "ForceKillProtectionGroup", "InitFullSync", "KeepDisk",
               "ChangeRecoveryHost", "InsertTaggedCP", "Clone", "BackupProtectionGroup", "RestoreProtectionGroup",
               "PrePostScript", "PreScript", "PostScript", "ScriptExecutionFailure", "ProtectedVmRemovedFromHypervisor",
               "ProtectedVmAddedToHypervisor", "RemoveVmFromVc", "VmRestoredToSnapshot", "StartVMsWithOrder"},
    "pause": {"PauseProtectionGroup", "ResumeProtectionGroup", "PauseProtectionGroupForMissingVm",
              "ResumeProtectionGroupAfterUserRemovedMissingVm", "MoveProtectionGroupToManualOperationNeeded"},
    "test": {"FailOverTest", "StopFailOverTest"},
    "failover": {"FailOver", "Move", "FailoverBeforeCommit", "FailoverCommit", "FailoverRollback",
                 "MoveBeforeCommit", "MoveRollback", "MoveCommit"},
    "vra": {"InstallVra", "UninstallVra", "UpgradeVra", "ChangeVraIpSettings", "ChangeVraPassword",
            "ChangeVraPasswordIpSettings", "BulkUpgradeVras", "BulkUninstallVras", "MaintainHost",
            "HostEnteringMaintenanceMode", "HostExitingMaintenanceMode"},
    "site": {"Pair", "Unpair", "UpgradeZVM", "SetAdvancedSiteSettings", "InstallCloudConnector",
             "UninstallCloudConnector", "RedeployCloudConnector", "ClearSite"},
}
# noise for a DR timeline: sign-ins, log bundles, alert flapping (shown elsewhere), housekeeping
SKIP = {"Login", "LogCollection", "AlertTurnedOn", "AlertTurnedOff", "CleanupProtectionGroupVipDiskbox",
        "HandleMirrorPromotion", "ActivateAllMirrors", "Unknown"}
KIND_LABEL = {"change": "change", "pause": "pause/resume", "test": "test", "failover": "failover/move",
              "vra": "VRA/host", "site": "site", "other": "other"}
NULL_ID = "00000000-0000-0000-0000-000000000000"
BACKFILL_DAYS, WINDOW_H, BACKFILL_WINDOW_H = 7, 6, 1
_TAG = re.compile(r"<[^>]+>")


def kind_of(type_name: str) -> str:
    return next((k for k, names in KINDS.items() if type_name in names), "other")


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _at(s: str | None) -> str:
    """Zerto's '2026-10-06T11:03:51.840Z' -> '2026-10-06T11:03:51Z' (sorts and compares as text)."""
    return (s or "")[:19] + "Z" if s else ""


def normalise(raw: list, types: list | None, source: str, site: str | None) -> list[dict]:
    out = []
    for e in raw or []:
        t = ci(e, "EventType")
        name = (types[t] if isinstance(t, int) and types and 0 <= t < len(types) else
                (str(t) if t is not None else "Unknown"))
        if name in SKIP or not ci(e, "EventIdentifier"):
            continue
        vpgs = [x for x in ci(e, "Vpgs") or [] if isinstance(x, dict) and ci(x, "VpgIdentifier")
                and ci(x, "VpgIdentifier") != NULL_ID]
        out.append({
            "id": ci(e, "EventIdentifier"), "at": _at(ci(e, "OccurredOn")), "site": ci(e, "SiteName") or site,
            "source": source, "type": name, "kind": kind_of(name),
            "text": _TAG.sub(" ", ci(e, "Description") or "").replace("  ", " ").strip()[:1000],
            "user": ci(e, "UserName"), "ok": ci(e, "EventCompletedSuccessfully"),
            "vpg_ids": [ci(x, "VpgIdentifier") for x in vpgs], "vpg_names": [ci(x, "VpgName") or "" for x in vpgs],
            "zorg_id": ci(e, "ZorgIdentifier") if ci(e, "ZorgIdentifier") != NULL_ID else None,
            "zorg": ci(e, "ZorgName") or None,
        })
    return out


def _since_key(sid: int) -> str:
    return f"events_since_{sid}"


def since(src: dict) -> str:
    """Start of the next poll's window: the newest event seen, less a little overlap."""
    s = db.get_setting(_since_key(src["id"]))
    if s:
        return s
    return _iso(datetime.now(timezone.utc) - timedelta(hours=WINDOW_H))


def ingest(src: dict, site: str | None, raw: list | None, types: list | None) -> int:
    if raw is None:
        return 0
    rows = normalise(raw, types, src["name"], site)
    n = db.save_events(rows)
    # from everything Zerto returned, skipped types too: a window of only sign-ins must still move on
    newest = max((_at(ci(e, "OccurredOn")) for e in raw if ci(e, "OccurredOn")), default="")
    if newest:
        # a generous overlap: an event can land late, and save_events skips ones already stored
        dt = datetime.fromisoformat(newest.replace("Z", "+00:00")) - timedelta(minutes=30)
        db.set_setting(_since_key(src["id"]), _iso(max(dt, datetime.now(timezone.utc) - timedelta(days=1))))
    elif not db.get_setting(_since_key(src["id"])):
        db.set_setting(_since_key(src["id"]), _iso(datetime.now(timezone.utc) - timedelta(minutes=10)))
    if types:
        db.set_setting("event_types", ",".join(types))
    return n


def backfill(src: dict, client, days: int = BACKFILL_DAYS) -> int:
    """Once per source: whatever the ZVM still holds of the last `days` days, in 1-hour windows."""
    key = f"events_backfilled_v2_{src['id']}"
    if db.get_setting(key):
        return 0
    types = client.get("/v1/events/types") or []
    end = datetime.now(timezone.utc)
    t, n = end - timedelta(days=days), 0
    while t < end:
        w = min(t + timedelta(hours=BACKFILL_WINDOW_H), end)
        raw = client.get(f"/v1/events?startDate={_iso(t)}&endDate={_iso(w)}&eventCategory=Events") or []
        n += db.save_events(normalise(raw, types, src["name"], None))
        t = w
    db.set_setting(key, db.now_iso())
    log.info("%s: backfilled %d events over %d days", src["name"], n, days)
    return n


# ── failover-test (recovery) reports ────────────────────────────────────────
def collect_tests(src: dict, client, days: int, org_of: dict[str, str]) -> int:
    """Zerto's recovery reports for the last `days` days (tests, failovers, moves)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    rows, page = [], 1
    while page <= 50:
        got = client.get(f"/v1/reports/recovery?startTime={_iso(start)}&endTime={_iso(end)}"
                         f"&pageNumber={page}&pageSize=100") or []
        for r in got:
            g = ci(r, "General") or {}
            steps = [{"what": ci(s, "Description"), "result": ci(s, "Result"), "took": ci(s, "ExecutionTime")}
                     for s in (ci(ci(r, "RecoverySettings") or {}, "Steps") or [])]
            try:
                rto = float(ci(g, "RTOInSeconds")) if ci(g, "RTOInSeconds") not in (None, "") else None
            except (TypeError, ValueError):
                rto = None
            vid = ci(g, "VpgIdentifier")
            rows.append({"id": ci(r, "RecoveryOperationIdentifier"), "vpg_id": vid, "vpg_name": ci(g, "VpgName"),
                         "zorg": org_of.get(vid), "protected_site": ci(g, "ProtectedSiteName"),
                         "recovery_site": ci(g, "RecoverySiteName"), "started": _at(ci(g, "StartTime")),
                         "ended": _at(ci(g, "EndTime")), "rto_s": rto, "status": ci(g, "Status"),
                         "by_user": ci(g, "InitiatedBy"), "notes": (ci(g, "Notes") or "")[:500],
                         "rtype": ci(g, "RecoveryType"), "steps": steps})
        if len(got) < 100:
            break
        page += 1
    return db.save_test_reports([r for r in rows if r["id"]])


TEST_OK = {"Success", "PassedByUser", "Passed"}


def test_ok(status: str | None) -> bool | None:
    """Zerto reports a stopped test as PassedByUser / FailedByUser (the engineer's verdict)."""
    if not status:
        return None
    if status in TEST_OK:
        return True
    return False if ("Fail" in status or "Abort" in status) else None
