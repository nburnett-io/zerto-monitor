"""Replication hot spots: which VMs carry a VRA's - or a whole site's - replication load.

Zerto's /v1/statistics/vms counters are cumulative per VM. Every poll stores the latest
sample and adds the difference to that VM's traffic for the hour (db.record_vm_counters).
A VM's WRITE volume is the work its VRAs do: the protected-side VRA splits those writes
and ships them, the recovery-side VRA writes them into the journal. One VM carrying a large
share of a VRA's or a site's writes explains lag that looks like a platform problem
(in one real case, one VM was 42% of all inbound replication, on a saturated array).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import db
import views
from zerto import ci

WINDOW_H = 24
VRA_SHARE, VRA_MIN_GB, VRA_MIN_VMS = 0.30, 20, 3        # one VM >= 30% of a busy VRA with 3+ VMs
SITE_SHARE, SITE_MIN_GB = 0.20, 100                    # one VM >= 20% of a site's inbound or outbound
MIN_COVERAGE_H = 1.0                                   # no verdicts from a few minutes of data


def ingest(source_id: int, stats: list | None, now: datetime | None = None) -> None:
    if not stats:
        return
    now = now or datetime.now(timezone.utc)
    rows = []
    for s in stats:
        vm, t = ci(s, "VmIdentifier"), ci(s, "SampleTime")
        if vm and t:
            rows.append({"vm_id": vm, "sample": t, "write_mb": int(ci(s, "WriteCounterInMBs") or 0),
                         "net_mb": int(ci(s, "NetworkTrafficCounterInMBs") or 0)})
    db.record_vm_counters(source_id, rows, now.strftime("%Y-%m-%dT%H"))


def hotspots(site: str, vra_rows: list | None = None, hours: int = WINDOW_H) -> dict | None:
    """Per-VRA and per-site write shares over the last `hours`, from the live source."""
    snaps = db.get_snapshots()
    src = next((s for s in db.list_sources(enabled_only=True) if s["kind"] == "zvm"
                and ((snaps.get(s["id"]) or {}).get("payload") or {}).get("site") == site), None)
    if not src:
        return None
    p = snaps[src["id"]]["payload"] or {}
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")
    traffic = db.vm_traffic(src["id"], since)
    out = {"hours": hours, "ready": bool(traffic), "by_vra": {}, "inbound": None, "outbound": None,
           "flags": [], "coverage_h": 0}
    if not traffic:
        return out
    out["coverage_h"] = round(max((t["seconds"] or 0) for t in traffic.values()) / 3600, 1)
    enough = out["coverage_h"] >= MIN_COVERAGE_H
    span = f"the last {min(hours, out['coverage_h']):g} h"
    vms = []
    for v in p.get("vpgs") or []:
        outbound = v.get("direction") == "outbound"
        for m in v.get("members") or []:
            t = traffic.get(m.get("id") or "")
            if not t:
                continue
            vra = views.host_label(m.get("protected_host") if outbound else m.get("recovery_host"))
            secs = t["seconds"] or 0
            vms.append({"name": m.get("name"), "vpg": v.get("name"), "vpg_key": v.get("id"), "org": v.get("org"),
                        "direction": "outbound" if outbound else "inbound", "vra": vra,
                        "write_gb": round((t["write_mb"] or 0) / 1024, 1), "net_gb": round((t["net_mb"] or 0) / 1024, 1),
                        "mbps": round((t["write_mb"] or 0) / secs, 2) if secs else None})
    by_vra: dict[str, list] = {}
    for x in vms:
        if x["vra"]:
            by_vra.setdefault(x["vra"], []).append(x)
    for vra, lst in by_vra.items():
        total = sum(x["write_gb"] for x in lst)
        lst.sort(key=lambda x: -x["write_gb"])
        top = [{**x, "share": round(x["write_gb"] / total, 3) if total else 0} for x in lst[:3]]
        hog = None
        if top and enough and total >= VRA_MIN_GB and len(lst) >= VRA_MIN_VMS and top[0]["share"] >= VRA_SHARE:
            hog = top[0]
            out["flags"].append(f"{hog['name']} ({hog['org']}) is {hog['share']:.0%} of VRA {vra}'s replication "
                                f"({hog['write_gb']} of {total:.0f} GB in {span})")
        out["by_vra"][vra] = {"write_gb": round(total, 1), "vms": len(lst), "top": top, "hog": hog}
    for direction in ("inbound", "outbound"):
        lst = sorted((x for x in vms if x["direction"] == direction), key=lambda x: -x["write_gb"])
        total = sum(x["write_gb"] for x in lst)
        top = [{**x, "share": round(x["write_gb"] / total, 3) if total else 0} for x in lst[:10]]
        out[direction] = {"total_gb": round(total, 1), "vms": len(lst), "top": top}
        if top and enough and total >= SITE_MIN_GB and top[0]["share"] >= SITE_SHARE:
            out["flags"].insert(0, f"{top[0]['name']} ({top[0]['org']}) is {top[0]['share']:.0%} of all {direction} "
                                   f"replication at {site} ({top[0]['write_gb']} of {total:.0f} GB in {span})")
    return out
