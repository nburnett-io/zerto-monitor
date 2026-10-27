"""Turn per-source snapshots into what the pages render."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

import db
import hogs
import playbook
from zerto import alert_key, classify, fmt_age, reason, worst

HEALTH_RANK = {"failure": 0, "warning": 1, "healthy": 2}


def source_ok(snap: dict | None) -> bool:
    """The last poll succeeded AND is recent: one older than 3 poll intervals means the
    poller is stuck, and its data is as stale as a failed poll's."""
    taken = _parse_iso((snap or {}).get("taken_at"))
    interval = max(30, int(db.get_setting("poll_interval", "120") or 120))
    return bool(snap and snap.get("ok") and taken
                and (datetime.now(timezone.utc) - taken).total_seconds() <= 3 * interval)


def _sources_with_snapshots():
    snaps = db.get_snapshots()
    out = []
    for s in db.list_sources():
        snap = snaps.get(s["id"])
        # a disabled source is never polled again; don't merge its last poll as live data
        p = (snap or {}).get("payload") if s["enabled"] else None
        ok = source_ok(snap)
        out.append({"source": s, "snap": snap, "ok": ok,
                    "payload": p if ok else None,
                    "stale_payload": p if snap and not ok else None})
    return out


def _vpg_key(v: dict) -> str:
    # VpgIdentifier is the same on both ZVMs of a VPG (all 891 dual-reported VPGs
    # checked 2026-10-05), and unlike the name it can't collide across customers
    return v.get("id") or f"name:{v.get('name')}:{v.get('protected_site')}:{v.get('recovery_site')}"


def _union_alerts(*lists) -> list:
    out, seen = [], set()
    for x in (a for lst in lists for a in (lst or [])):
        k = alert_key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _base_rank(v: dict) -> tuple:
    # which ZVM's record a merged VPG is shown from (lowest first): worse health, then a
    # live poll over a stale one, then the worse replication-only state (so an RPO breach
    # beats an alert-only warning), then a specific substatus over "None"
    return (HEALTH_RANK[v["health"]], v["_stale"],
            HEALTH_RANK[classify(v["status"], v["sub"], v["rpo"])], v["sub"] == "None")


def merged_vpgs(rows: list | None = None) -> dict[str, dict]:
    """ONE record per VPG across every ZVM that reports it - the single source every
    page, the SNMP metrics and the alert engine read, so they cannot disagree.

    A VPG between two monitored sites is reported by both ZVMs, and they don't always
    agree: alerts in particular are raised by whichever side sees the problem
    (journal alerts on the recovery side, "errors from protected side" on the other).
    So keep the WORSE side's record, the union of both sides' alerts, the higher
    AlertStatus, and every source it was seen on.
    """
    groups: dict[str, list] = {}
    for r in rows if rows is not None else _sources_with_snapshots():
        p = r["payload"] or r["stale_payload"]
        if not p or r["source"]["kind"] != "zvm":
            continue
        for v in p["vpgs"]:
            v = dict(v, source=r["source"]["name"], _site=p.get("site"), _stale=r["payload"] is None)
            try:
                v["alert_status"] = int(v.get("alert_status") or 0)
            except (TypeError, ValueError):
                v["alert_status"] = 0
            if v.get("health") not in HEALTH_RANK:
                v["health"] = "warning"                     # unknown value: fail closed
            groups.setdefault(_vpg_key(v), []).append(v)
    merged: dict[str, dict] = {}
    for k, recs in groups.items():
        base = dict(min(recs, key=_base_rank))              # min() is stable: full tie -> first source
        base["key"] = k                                     # what an ignore targets
        base["health"] = worst(*(x["health"] for x in recs))
        base["seen_on"] = sorted({x["source"] for x in recs})
        base["seen_sites"] = sorted({x["_site"] for x in recs if x["_site"]})
        base["alerts"] = _union_alerts(*(x.get("alerts") for x in recs))
        base["alert_status"] = max(x["alert_status"] for x in recs)
        base["on_disconnected_vra"] = sorted({h for x in recs for h in x.get("on_disconnected_vra") or []})
        base["org"] = next((x["org"] for x in (base, *recs) if x.get("org")), "")
        base["zorg_id"] = next((x["zorg_id"] for x in (base, *recs) if x.get("zorg_id")), None)
        # per-VM detail only the protected side knows (the recovery ZVM leaves hosts blank)
        out = next((x for x in recs if x.get("direction") == "outbound" and x.get("protected_hosts")), None)
        if out is not None:
            base["members"], base["protected_hosts"] = out["members"], out["protected_hosts"]
        # name the stale source(s) when only their last good poll makes the VPG this bad
        live = [x["health"] for x in recs if not x["_stale"]]
        base["stale_from"] = ([] if live and worst(*live) == base["health"]
                              else sorted({x["source"] for x in recs if x["_stale"]}))
        del base["_site"], base["_stale"]
        merged[k] = base
    _apply_ignores(merged)
    return merged


# ── ignores ─────────────────────────────────────────────────────────────────
# An ignore never changes a VPG's health - that stays Zerto's truth on every page.
# It only takes the VPG out of the counts that demand attention, out of SNMP's
# failure/warning figures and out of alerting, and only while it still describes
# what is wrong. In 'ack' mode it remembers the alert codes, Zerto's AlertStatus and
# the replication state at the moment it was set; anything new or worse - another
# alert code, an RPO breach, a higher AlertStatus - lifts it automatically.
def ignore_snapshot(v: dict) -> dict:
    return {"codes": sorted(live_codes(v)),
            "state": classify(v["status"], v["sub"], v["rpo"]),
            "alert_status": int(v.get("alert_status") or 0)}


def _covers(ig: dict, key: str, v: dict) -> tuple[bool, str]:
    """(covered?, why not) for one ignore against one unhealthy VPG."""
    if ig["mode"] == "all":
        return True, ""
    snap = (ig.get("snapshot") or {}).get(key)
    if not snap:
        return False, "it was healthy when this was acknowledged"
    now = ignore_snapshot(v)
    new_codes = sorted(set(now["codes"]) - set(snap.get("codes") or []))
    if new_codes:
        return False, "new alert " + ", ".join(new_codes)
    if HEALTH_RANK[now["state"]] < HEALTH_RANK.get(snap.get("state"), 2):
        return False, f"replication now {now['state']} (was {snap.get('state')})"
    if now["alert_status"] > int(snap.get("alert_status") or 0):
        return False, "Zerto raised its alert level"
    return True, ""


def _brief(ig: dict) -> dict:
    return {"id": ig["id"], "scope": ig["scope"], "mode": ig["mode"], "label": ig.get("label"),
            "note": ig.get("note") or "", "by": ig.get("created_by") or "",
            "at": (ig.get("created_at") or "")[:16].replace("T", " "),
            "until": (ig.get("expires_at") or "")[:16].replace("T", " ")}


def live_codes(v: dict) -> set[str]:
    """The Zerto alert codes behind a VPG's problems right now (Warning/Error, not dismissed)."""
    return {a.get("id") for a in v.get("alerts") or [] if a.get("level") in ("Warning", "Error") and a.get("id")}


def _code_cover(v: dict, codes: dict[str, dict]) -> dict | None:
    """A global code ignore covers a VPG only when EVERY live alert on it has an ignored code
    and its replication is otherwise healthy - so an RPO breach, a sync problem or any other
    alert still counts. Nor does it cover Zerto's error level (AlertStatus 2) with an alert
    that is only a Warning."""
    have = live_codes(v)
    if not have or not have <= set(codes) or classify(v["status"], v["sub"], v["rpo"]) != "healthy":
        return None
    if v.get("alert_status") == 2 and not any(a.get("level") == "Error" for a in v.get("alerts") or []):
        return None
    rows = [codes[c] for c in sorted(have)]
    until = min((r["expires_at"] for r in rows if r.get("expires_at")), default="")
    return {"id": None, "scope": "code", "mode": "code", "label": ", ".join(sorted(have)),
            "note": "; ".join(f"{r['code']}: {r['note']}" for r in rows if r.get("note")),
            "by": ", ".join(sorted({r.get("created_by") or "" for r in rows})), "at": "",
            "until": (until or "")[:16].replace("T", " ")}


def _apply_ignores(merged: dict[str, dict]) -> None:
    igs = db.list_ignores(active_only=True)
    by_vpg = {i["target"]: i for i in igs if i["scope"] == "vpg"}
    by_zorg = {i["target"]: i for i in igs if i["scope"] == "zorg"}
    codes = {c["code"]: c for c in db.list_code_ignores(active_only=True)}
    holds = db.active_holds()
    for k, v in merged.items():
        v["ignored"] = v["ignore_lapsed"] = None
        h = holds.get(k)
        if h and v["health"] != "healthy":
            # a planned outage: this VPG rides on a VRA being resized right now. Never
            # stored as an ignore, and it expires on its own.
            v["ignored"] = {"id": None, "scope": "push", "mode": "all", "label": f"VRA resize #{h['push_id']}",
                            "note": "planned: its VRA is being resized", "by": "resize",
                            "at": "", "until": (h.get("expires_at") or "")[:16].replace("T", " ")}
            continue
        candidates = [i for i in (by_vpg.get(k), by_zorg.get(v["org"] or "(no zORG)")) if i]
        if not candidates:
            if v["health"] != "healthy" and codes:
                v["ignored"] = _code_cover(v, codes)
            continue
        v["ignore_set"] = _brief(candidates[0])          # shown even while healthy
        if v["health"] == "healthy":
            continue
        reasons = []
        for ig in candidates:                            # the VPG's own ignore first
            ok, why = _covers(ig, k, v)
            if ok:
                v["ignored"] = _brief(ig)
                break
            reasons.append(why)
        if not v["ignored"] and codes:
            v["ignored"] = _code_cover(v, codes)        # an admin's global code ignore still applies
        if not v["ignored"]:
            # it IS ignored, but something new or worse has happened: say exactly what
            v["ignore_lapsed"] = {**_brief(candidates[0]), "why": "; ".join(reasons)}


def _age(iso: str | None) -> str:
    if not iso:
        return "never"
    try:
        dt = datetime.fromisoformat(iso)
        return fmt_age(int((datetime.now(timezone.utc) - dt).total_seconds())) + " ago"
    except ValueError:
        return "?"


def overview(rows: list | None = None, merged: dict | None = None) -> dict:
    """Dashboard: only failure/warning VPGs, deduplicated across ZVMs, with reasons."""
    rows = rows if rows is not None else _sources_with_snapshots()
    sites = []
    all_vras = []
    for r in rows:
        s, snap, p = r["source"], r["snap"], r["payload"] or r["stale_payload"]
        entry = {"id": s["id"], "name": s["name"], "kind": s["kind"], "host": s["host"],
                 "enabled": bool(s["enabled"]), "ok": r["ok"],
                 "error": (snap or {}).get("error"), "age": _age((snap or {}).get("taken_at")),
                 "stale": bool(r["stale_payload"]),
                 "counts": (p or {}).get("counts"), "site": (p or {}).get("site"),
                 "version": (p or {}).get("version"), "flavour": (p or {}).get("flavour")}
        sites.append(entry)
        if not p or s["kind"] != "zvm":
            continue
        for vr in p["vras"]:
            all_vras.append({**vr, "source": s["name"], "site": p["site"]})
    merged = merged if merged is not None else merged_vpgs(rows)

    unhealthy = [v for v in merged.values() if v["health"] != "healthy"]
    for v in unhealthy:
        v["why"] = reason(v)
        v["rpo_h"] = fmt_age(v["rpo"])
        v["fixes"] = playbook.suggest(v)
        v["fix_keys"] = playbook.keys_for(v)
    unhealthy.sort(key=lambda v: (HEALTH_RANK[v["health"]], -(v["rpo"] if v["rpo"] and v["rpo"] > 0 else 0)))
    bad = [v for v in unhealthy if not v.get("ignored")]           # what needs attention
    ignored = [v for v in unhealthy if v.get("ignored")]

    totals = {"vpgs": len(merged),
              "failure": sum(1 for v in bad if v["health"] == "failure"),
              "warning": sum(1 for v in bad if v["health"] == "warning"),
              "healthy": sum(1 for v in merged.values() if v["health"] == "healthy"),
              "ignored": len(ignored),
              "vras": len(all_vras),
              "vras_disconnected": sum(1 for r in all_vras if r["disconnected"]),
              "vras_mask_mismatch": sum(1 for r in all_vras if r["mask_mismatch"]),
              "sources_down": sum(1 for s in sites if s["enabled"] and not s["ok"])}
    # trend vs ~24h ago from the history table (per-source sums; not deduped across
    # ZVMs, so compare direction rather than exact numbers)
    now_ids = {s["id"] for s in sites if s["ok"] and s["enabled"]}       # like with like
    base = {k: b for k, b in db.history_baseline(24).items() if k in now_ids}
    if base:
        totals["trend"] = {
            "hours": 24,
            "failure_then": sum((b.get("failure") or 0) for b in base.values()),
            "warning_then": sum((b.get("warning") or 0) for b in base.values()),
            "failure_now": sum(((s["counts"] or {}).get("failure") or 0) for s in sites if s["ok"]),
            "warning_now": sum(((s["counts"] or {}).get("warning") or 0) for s in sites if s["ok"]),
            "since": min(b["taken_at"] for b in base.values()),
        }
        t = totals["trend"]
        t["failure_delta"] = t["failure_now"] - t["failure_then"]
        t["warning_delta"] = t["warning_now"] - t["warning_then"]
    else:
        totals["trend"] = None
    by_org = defaultdict(lambda: {"failure": 0, "warning": 0})
    for v in bad:
        by_org[v["org"] or "(no zORG)"][v["health"]] += 1
    top_orgs = sorted(by_org.items(), key=lambda kv: (-kv[1]["failure"], -kv[1]["warning"]))[:12]
    return {"sites": sites, "vpgs": bad, "ignored_vpgs": ignored, "totals": totals,
            "top_orgs": top_orgs}


def _all_vras() -> list[dict]:
    out = []
    for r in _sources_with_snapshots():
        p = r["payload"] or r["stale_payload"]
        if not p or r["source"]["kind"] != "zvm":
            continue
        for vr in p["vras"]:
            out.append({**vr, "source": r["source"]["name"], "site": p["site"], "zvm_version": p.get("version"),
                        "site_stale": bool(r["stale_payload"] and not r["payload"])})
    out.sort(key=lambda x: (not x["disconnected"], not x["mask_mismatch"], x["status"] != 0,
                            x["site"] or "", x["host"] or ""))
    return out


def _vra_counts(rows: list[dict]) -> dict:
    c = {"total": len(rows),
         "disconnected": sum(1 for x in rows if x["disconnected"]),
         "mask_mismatch": sum(1 for x in rows if x["mask_mismatch"]),
         "not_ok": sum(1 for x in rows if x["status"] != 0),
         "recovery_vols": sum(x["recovery_vols"] for x in rows),
         "protected_vols": sum(x["protected_vols"] for x in rows)}
    c["healthy"] = sum(1 for x in rows if not x["disconnected"] and not x["mask_mismatch"] and x["status"] == 0)
    c["health"] = ("failure" if c["disconnected"] else
                   "warning" if (c["mask_mismatch"] or c["not_ok"]) else "healthy")
    return c


def host_label(h: str | None) -> str:
    """A host's first DNS label, lower-case - how VRAs, pins and gates match hosts."""
    return (h or "").split(".")[0].strip().lower()


def vra_key(site: str, r: dict) -> str:
    # by HOST, not VraIdentifier: the identifier changes when a VRA is reinstalled
    return f"{site}|{host_label(r.get('host'))}"


# Bounds. Zerto 10.9 sets no maximum; its guides and KBs disagree (16 GB / 4 vCPU in KB
# 4466/4468, "up to 8 CPUs and 32 GB" in 10.0 U5) and production sites already run 48 and 64 GB.
# The hard ceiling is the largest size in use; beyond the 16/4 guidance a rule needs a
# Zerto case reference. More than 2 vCPU is "only per Zerto Support recommendation".
VRA_MEM_MAX, VRA_CPU_MAX = 64, 8
GUIDE_MEM, GUIDE_CPU = 16, 4
NO_CLUSTER = "(cluster unknown)"


def _ver3(v: str | None) -> str:
    return ".".join((v or "").split(".")[:3])


def vra_flags(r: dict, tm: int | None = None, tc: int | None = None) -> list[str]:
    """Why a VRA must not be resized by default, plus warnings (sec. 3 of the design)."""
    f = []
    if r.get("zvm_version") and r.get("version") and _ver3(r["version"]) != _ver3(r["zvm_version"]):
        f.append("version_lag")
    if (r.get("status") or 0) != 0 or (r.get("alert_status") or 0) != 0 or r.get("is_ghost") or r.get("disconnected"):
        f.append("unhealthy")
    if r.get("status") in (9, 10):
        f.append("maintenance")
    if not r.get("id"):
        f.append("no_id")
    m, c = int(r.get("mem_gb") or 0), int(r.get("cpus") or 0)
    if tm is not None and tm != m and min(m, tm) <= 8:
        f.append("tier_cross")              # host Zerto driver restarts with a new I/O cache size
    if tm is not None and (tm > GUIDE_MEM or (tc or 0) > GUIDE_CPU):
        f.append("beyond_guidance")
    if tc is not None and tc > 2:
        f.append("cpu_gt2")
    return f


BLOCKING_FLAGS = {"version_lag", "unhealthy", "maintenance", "no_id"}


def vra_compliance(r: dict, std: dict | None, pin: dict | None, cstd: dict | None = None) -> dict:
    """Judge one VRA against the most specific size that applies to it:
    its pin, else its cluster's override, else the site standard.

    Raise-only, per dimension, always: a VRA is never lowered by a rule. Lowering is
    something an admin chooses for ONE resize, on its preview. A raise power-cycles the
    VRA just like a lower does, so "pushable" also requires a healthy, current VRA.
    """
    rule, source = ((pin, "pin") if pin else (cstd, "cluster") if cstd else (std, "site") if std
                    else (None, None))
    m, c = int(r.get("mem_gb") or 0), int(r.get("cpus") or 0)
    if not rule:
        return {"state": "unset", "target_mem": None, "target_cpus": None, "source": None,
                "push": False, "push_mem": m, "push_cpus": c, "pinned": False, "lowers": False,
                "can_lower": False, "flags": vra_flags(r), "support_ref": ""}
    tm, tc = int(rule["memory_gb"]), int(rule["cpus"])
    under = m < tm or c < tc
    over = m > tm or c > tc
    state = ("ok" if not (under or over) else "mixed" if (under and over)
             else "under" if under else "over")
    pm, pc = max(m, tm), max(c, tc)
    flags = vra_flags(r, pm, pc)
    blocked = bool(BLOCKING_FLAGS & set(flags)) or \
        ("beyond_guidance" in flags and not (rule.get("support_ref") or "").strip())
    return {"state": state, "target_mem": tm, "target_cpus": tc, "pinned": source == "pin",
            "source": source, "support_ref": rule.get("support_ref") or "",
            "push": (pm, pc) != (m, c) and not blocked,
            "push_mem": pm, "push_cpus": pc, "lowers": False,
            "can_lower": over and not (BLOCKING_FLAGS & set(flags)) and bool(r.get("id")),
            "flags": flags, "blocked": blocked}


def _with_compliance(site: str, rows: list[dict], std: dict | None, pins: dict,
                     cstds: dict | None = None) -> dict:
    counts = {"ok": 0, "under": 0, "over": 0, "mixed": 0, "unset": 0, "pinned": 0, "pushable": 0}
    cstds = cstds or {}
    for r in rows:
        key = vra_key(site, r)
        r["key"] = key
        r["sizing"] = vra_compliance(r, std, pins.get(key), cstds.get((site, r.get("cluster") or NO_CLUSTER)))
        counts[r["sizing"]["state"]] += 1
        counts["pinned"] += r["sizing"]["pinned"]
        counts["pushable"] += r["sizing"]["push"]
    return counts


def _common_size(rows: list[dict]) -> dict | None:
    """The most common size already in use - the obvious standard to offer."""
    if not rows:
        return None
    sizes = defaultdict(int)
    for r in rows:
        sizes[(r.get("mem_gb") or 0, r.get("cpus") or 0)] += 1
    (cm, cc), n = max(sizes.items(), key=lambda kv: kv[1])
    return {"memory_gb": cm, "cpus": cc, "count": n}


def vras() -> dict:
    """Overall health plus a per-site rollup; the full list is behind /vras/{site}."""
    rows = _all_vras()
    stds, pins, cstds = db.vra_standards(), db.vra_pins(), db.vra_cluster_standards()
    by_site: dict[str, list] = defaultdict(list)
    for x in rows:
        by_site[x["site"] or x["source"]].append(x)
    sites = []
    for site, lst in by_site.items():
        c = _vra_counts(lst)
        versions = sorted({x["version"] for x in lst if x["version"]})
        sizing = _with_compliance(site, lst, stds.get(site), pins, cstds)
        sites.append({"site": site, "source": lst[0]["source"], "stale": lst[0]["site_stale"],
                      "versions": versions, "min_mem": min((x["mem_gb"] or 0) for x in lst),
                      "max_mem": max((x["mem_gb"] or 0) for x in lst),
                      "standard": stds.get(site), "sizing": sizing, **c})
    sites.sort(key=lambda s: (HEALTH_RANK[s["health"]], -s["disconnected"], -s["mask_mismatch"], s["site"]))
    return {"sites": sites, "counts": _vra_counts(rows), "vras": rows}


VRA_ALERT_PREFIXES = ("VRA", "ZVM0002", "ZVM0024")


def _site_vra_alerts(site: str, hosts: set[str]) -> list[dict]:
    """VRA-level alerts the site's ZVM reports, matched to this site's VRAs by host
    name where the text names one, with the playbook's suggested fix."""
    out, seen = [], set()
    for r in _sources_with_snapshots():
        p = r["payload"] or r["stale_payload"]
        if not p or r["source"]["kind"] != "zvm" or p.get("site") != site:
            continue
        for a in p.get("alerts") or []:
            if a.get("dismissed") or not (a.get("id") or "").startswith(VRA_ALERT_PREFIXES):
                continue
            k = alert_key(a)
            if k in seen:
                continue
            seen.add(k)
            text = a.get("text") or ""
            host = next((h for h in hosts if h and h.lower() in text.lower()), None)
            out.append({**a, "host": host, "fixes": playbook.for_alert(a, {"host": host})})
    out.sort(key=lambda a: (a.get("level") != "Error", a.get("host") is None, a.get("id") or ""))
    return out


def vras_site(site: str) -> dict:
    rows = [x for x in _all_vras() if (x["site"] or x["source"]) == site]
    std = db.vra_standards().get(site)
    cstds = db.vra_cluster_standards()
    sizing = _with_compliance(site, rows, std, db.vra_pins(), cstds)
    # sorted and grouped by vSphere cluster, then host
    rows.sort(key=lambda r: ((r.get("cluster") or "~").lower(), (r.get("host") or "").lower()))
    clusters = []
    for r in rows:
        name = r.get("cluster") or NO_CLUSTER
        if not clusters or clusters[-1]["name"] != name:
            clusters.append({"name": name, "id": r.get("cluster_id"), "vras": [],
                             "override": cstds.get((site, name))})
        clusters[-1]["vras"].append(r)
    for cl in clusters:
        z = [r["sizing"] for r in cl["vras"]]
        cl["counts"] = {"total": len(z), "ok": sum(s["state"] == "ok" for s in z),
                        "below": sum(s["state"] in ("under", "mixed") for s in z),
                        "pushable": sum(bool(s["push"]) for s in z)}
        cl["common"] = _common_size(cl["vras"])
    src = next((s for s in db.list_sources() if s["kind"] == "zvm" and
                any(r["source"] == s["name"] for r in rows)), None)
    return {"site": site, "vras": rows, "clusters": clusters, "counts": _vra_counts(rows),
            "standard": std, "sizing": sizing, "common": _common_size(rows),
            "versions": sorted({r["version"] for r in rows if r.get("version")}),
            "alerts": _site_vra_alerts(site, {r.get("host") for r in rows}),
            "pushes": db.recent_vra_pushes(site, 25),         # public columns only
            "hotspots": hogs.hotspots(site, rows),
            "source_id": src["id"] if src else None,
            "allow_changes": bool(src and src.get("allow_changes")),
            "mem_max": VRA_MEM_MAX, "cpu_max": VRA_CPU_MAX}


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _test_summary(vpgs: list[dict]) -> dict:
    """Failover-test recency across a set of VPGs (Zerto's LastTest field)."""
    now = datetime.now(timezone.utc)
    dates = [_parse_iso(v.get("last_test")) for v in vpgs]
    tested = [d for d in dates if d]
    never = sum(1 for d in dates if not d)
    newest = max(tested) if tested else None
    oldest = min(tested) if tested else None
    stale90 = sum(1 for d in tested if (now - d).days > 90)
    return {
        "last_test": newest.strftime("%Y-%m-%d") if newest else "never",
        "last_test_age": fmt_age(int((now - newest).total_seconds())) if newest else "never",
        "oldest_test": oldest.strftime("%Y-%m-%d") if oldest else "never",
        "never_tested": never, "stale_90d": stale90,
        "test_health": ("failure" if never == len(dates) and dates else
                        "warning" if (never or stale90) else "healthy"),
    }


def zorg_list(rows: list | None = None, merged: dict | None = None) -> list[dict]:
    if merged is None:
        merged = merged_vpgs(rows if rows is not None else _sources_with_snapshots())
    zorg_igs = {i["target"]: _brief(i) for i in db.list_ignores() if i["scope"] == "zorg"}
    orgs: dict[str, dict] = {}
    for k, v in merged.items():
        o = v["org"] or "(no zORG)"
        e = orgs.setdefault(o, {"name": o, "vpgs": {}, "failure": 0, "warning": 0,
                                "healthy": 0, "ignored": 0, "sites": set(), "worst_rpo": 0})
        e["vpgs"][k] = v
        # ignored VPGs are counted apart: they don't make the zORG need attention
        e["ignored" if v.get("ignored") else v["health"]] += 1
        e["sites"].update(v["seen_sites"])
        if v["rpo"] and v["rpo"] > e["worst_rpo"]:
            e["worst_rpo"] = v["rpo"]
    out = []
    for e in orgs.values():
        n = len(e["vpgs"])
        out.append({"name": e["name"], "vpg_count": n, "failure": e["failure"],
                    "warning": e["warning"], "healthy": e["healthy"], "ignored": e["ignored"],
                    "zorg_ignore": zorg_igs.get(e["name"]),
                    # unhealthy, non-ignored VPGs, for the alert engine's per-VPG clocks
                    "bad": {k: [v["health"], v["name"]] for k, v in e["vpgs"].items()
                            if v["health"] != "healthy" and not v.get("ignored")},
                    # unhealthy but ignored: no "recovered" email when one is ignored mid-alert
                    "ignored_keys": [k for k, v in e["vpgs"].items() if v.get("ignored")],
                    # every VPG it has now: one that's gone from Zerto gets no "recovered" email
                    "keys": list(e["vpgs"]),
                    "sites": sorted(s for s in e["sites"] if s),
                    "worst_rpo": fmt_age(e["worst_rpo"]) if e["worst_rpo"] else "-",
                    "pct": round(e["healthy"] / max(1, n) * 100),
                    **_test_summary(list(e["vpgs"].values()))})
    out.sort(key=lambda x: (-x["failure"], -x["warning"], x["name"].lower()))
    return out


def metrics() -> dict:
    """Flat integers for SNMP / RMM polling (/api/metrics, snmpd extend)."""
    rows = _sources_with_snapshots()             # ONE read: every figure from the same polls
    merged = merged_vpgs(rows)
    t = overview(rows, merged)["totals"]
    orgs = zorg_list(rows, merged)
    # every ZVM's own figure, as before the merge existed: a tie in the merge must not hide it
    worst_rpo = max((v["rpo"] for r in rows if r["source"]["kind"] == "zvm"
                     for v in (r["payload"] or r["stale_payload"] or {}).get("vpgs", [])
                     if (v.get("rpo") or 0) > 0), default=0)
    states = {z: s for z, s in db.zorg_states().items() if not z.startswith("[source] ")}
    return {
        "vpgs": t["vpgs"], "failure": t["failure"], "warning": t["warning"],
        "healthy": t["healthy"], "ignored": t["ignored"], "vras": t["vras"],
        "vras_disconnected": t["vras_disconnected"],
        "vras_mask_mismatch": t["vras_mask_mismatch"],
        "sources_down": t["sources_down"],
        "orgs_failure": sum(1 for o in orgs if o["failure"]),
        "orgs_warning": sum(1 for o in orgs if not o["failure"] and o["warning"]),
        "orgs_alerting": sum(1 for s in states.values() if s.get("alerted")),
        "worst_rpo": int(worst_rpo),
    }


# ── 1.3: VPG page, timeline, backups, plans ─────────────────────────────────
def _events_view(rows: list[dict]) -> list[dict]:
    import events as zevents
    out = []
    for e in rows:
        out.append({**e, "label": zevents.KIND_LABEL.get(e["kind"], e["kind"]),
                    "when": e["at"][:16].replace("T", " "),
                    "vpgs": list(zip(e["vpg_ids"], e["vpg_names"]))})
    return out


def vpg_detail(key: str, hours: int = 168) -> dict:
    import charts
    import trends
    from datetime import timedelta
    merged = merged_vpgs()
    v = merged.get(key)
    if v:
        v = dict(v)
        v["why"] = reason(v) if v["health"] != "healthy" else ""
        v["fixes"] = playbook.suggest(v) if v["health"] != "healthy" else []
        v["fix_keys"] = playbook.keys_for(v) if v["health"] != "healthy" else []
        v["rpo_h"] = fmt_age(v["rpo"])
    ser = trends.vpg_series(key, hours)
    pts = ser["points"]
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    rpo_chart = hist_chart = jrnl_chart = None
    if pts:
        cfg = next((p["rpo_cfg"] for p in reversed(pts) if p["rpo_cfg"]), None)
        s = [{"name": "worst in hour", "color": charts.RED, "points": [(p["t"], p["rpo_max"]) for p in pts]},
             {"name": "average", "color": charts.BLUE, "area": True, "points": [(p["t"], p["rpo_avg"]) for p in pts]}]
        if cfg:
            s.append({"name": f"target {fmt_age(cfg)}", "color": charts.GREY, "dash": True,
                      "points": [(start, cfg), (end, cfg)]})
        rpo_chart = charts.line_chart(s, start, end, y_fmt=charts.fmt_secs, title="RPO")
        hcfg = next((p["hist_cfg"] for p in reversed(pts) if p["hist_cfg"]), None)
        s = [{"name": "journal history (shortest in hour)", "color": charts.GREEN,
              "points": [(p["t"], (p["hist_min"] or 0) * 60) for p in pts if p["hist_min"] is not None]}]
        if hcfg:
            s.append({"name": f"configured {fmt_age(hcfg * 60)}", "color": charts.GREY, "dash": True,
                      "points": [(start, hcfg * 60), (end, hcfg * 60)]})
        hist_chart = charts.line_chart(s, start, end, y_fmt=charts.fmt_secs, title="Journal history")
        jrnl_chart = charts.line_chart([{"name": "journal used (GB)", "color": charts.AMBER, "area": True,
                                         "points": [(p["t"], p["journal_gb"]) for p in pts]}],
                                       start, end, title="Journal size")
    vid = (v or {}).get("id") or (key if "-" in key and ":" not in key else None)
    name = (v or {}).get("name")
    evs = _events_view(db.events(vpg_id=vid, limit=200)) if vid else []
    tests = db.test_reports(vpg_id=vid, limit=50) if vid else []
    bk = db.list_backups(vpg_id=vid) if vid else []
    if not bk and name:
        bk = db.list_backups(vpg_name=name)
    import events as zevents
    for t in tests:
        t["ok"] = zevents.test_ok(t["status"])
    return {"key": key, "v": v, "series": ser, "hours": hours, "rpo_chart": rpo_chart, "hist_chart": hist_chart,
            "jrnl_chart": jrnl_chart, "events": evs, "tests": tests, "backups": bk}


def timeline(zorg: str | None, kind: str | None, days: int) -> list[dict]:
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    kinds = (kind,) if kind else None
    return _events_view(db.events(zorg=zorg, since=since, kinds=kinds, limit=1000))


def backups_overview(zorg: str | None, q: str | None) -> dict:
    rows = db.latest_backups(zorg=zorg)                # newest per (site, VPG), with its copy count
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["vpg_name"] or "").lower()]
    merged = merged_vpgs()
    live_names = {(v.get("name") or "").lower() for v in merged.values()}
    vpgs = sorted(({**r, "exists": (r["vpg_name"] or "").lower() in live_names} for r in rows),
                  key=lambda r: ((r["zorg"] or "~").lower(), r["vpg_name"].lower()))
    snaps = db.get_snapshots()
    sites = sorted({(p.get("site"), s["id"]) for s in db.list_sources(enabled_only=True) if s["kind"] == "zvm"
                    for p in [((snaps.get(s["id"]) or {}).get("payload") or {})] if p.get("site")})
    warnings = [w for w in (db.get_setting(f"backup_warn_{s['id']}") for s in db.list_sources(enabled_only=True)) if w]
    return {"vpgs": vpgs[:3000], "summary": db.backup_summary()[:30], "sites": [s for s, _ in sites], "warnings": warnings,
            "days": db.get_setting("backup_days", "7"), "restores": db.changes(kind="restore", limit=15),
            "deleted": sum(1 for r in vpgs if not r["exists"])}


def backup_detail(backup_id: int, against: int | None = None) -> dict | None:
    import backups
    b, item = backups.load(backup_id)
    if not b:
        return None
    other = db.get_backup(against) if against else backups.previous_of(b)
    changes = None
    if other:
        _, oitem = backups.load(other["id"])
        changes = backups.diff(oitem, item) if other["export_ts"] < b["export_ts"] else backups.diff(item, oitem)
    copies = db.list_backups(vpg_name=b["vpg_name"], site=b["site"])
    flat = [{"path": k, "value": backups.shown(k, val)} for k, val in sorted(backups.flatten(item).items())]
    return {"b": b, "summary": backups.summary(item), "other": other, "changes": changes, "copies": copies,
            "flat": flat, "exists": bool(backups._exists(b["vpg_name"], b.get("vpg_id")))}


def plan_editor(name: str, site: str, plan_id: str | None, form: dict | None) -> dict:
    import plans
    import vrapush
    d = zorg_detail(name)
    vpgs = d["vpgs"]
    zp = plans.zorg_plans(name, vpgs)
    sites = [s["site"] for s in zp["sites"]]
    site = site if site in sites else (sites[0] if sites else "")
    here = [v for v in vpgs if v.get("recovery_site") == site]
    existing = next((p for p in zp["plans"] if p["id"] == plan_id and p["site"] == site), None) if plan_id else None
    if form is None:                                    # prefill: existing plan's tiers, else one tier
        form = {"name": existing["name"] if existing else f"{name} DR ({site})",
                "type": existing["type"] if existing else "Standard"}
        if existing:
            n = 0
            for b in existing["blocks"]:
                if b.get("type") == "VPG":
                    n += 1
                    for i in b.get("vpg_ids") or []:
                        form[f"tier_{i}"] = str(n)
                elif n and b.get("type") == "WaitRecoveryOperationCompletion":
                    form[f"wait_{n}"] = "1"
                elif n and b.get("type") == "Delay":
                    form[f"delay_{n}"] = str(b.get("delay") or 0)
                elif n and b.get("type") == "Script":
                    form[f"script_{n}"], form[f"params_{n}"] = b.get("script") or "", " ".join(b.get("params") or [])
        else:
            for i in range(1, plans.MAX_TIERS + 1):
                form[f"wait_{i}"] = "1"
    pname, ptype, tiers, problems = plans.parse_form(form, vpgs, site) if site else ("", "Standard", [], ["no recovery site"])
    body = plans.build_body(pname, ptype, tiers) if tiers else None
    src = vrapush._site_source(site)[0] if site else None
    return {"name": name, "site": site, "sites": zp["sites"], "vpgs": here, "existing": existing,
            "plan_id": plan_id if existing else None, "form": form, "tiers": tiers, "problems": problems
            if form.get("action") else [], "body": body, "arming": plans.arming(src), "max_tiers": plans.MAX_TIERS,
            "submitted": bool(form.get("action"))}


def zorg_extras(name: str, d: dict) -> dict:
    import plans
    from datetime import timedelta
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bk = db.list_backups(zorg=name, limit=5000)
    import events as zevents
    tests = db.test_reports(zorg=name, limit=10)
    for t in tests:
        t["ok"] = zevents.test_ok(t["status"])
    return {"plans": plans.zorg_plans(name, d["vpgs"]),
            "recent_events": _events_view(db.events(zorg=name, since=since, limit=25)),
            "recent_tests": tests,
            "backups": {"vpgs": len({b["vpg_name"] for b in bk}), "latest": bk[0]["export_ts"] if bk else None}}


def zorg_detail(name: str) -> dict:
    rows = _sources_with_snapshots()
    vpgs: dict[str, dict] = {}
    alerts, ccs, zcm_zorg = [], [], None
    zcc_alerts: list[dict] = []
    # first pass: this org's VPGs (from the shared merge, so this page can never
    # disagree with the dashboard) and the zORG identifiers they carry
    zorg_ids: set[str] = set()
    for k, v in merged_vpgs(rows).items():
        if (v["org"] or "(no zORG)") != name:
            continue
        v = dict(v)
        v["why"] = reason(v) if v["health"] != "healthy" else ""
        v["fixes"] = playbook.suggest(v) if v["health"] != "healthy" else []
        v["fix_keys"] = playbook.keys_for(v) if v["health"] != "healthy" else []
        v["rpo_h"] = fmt_age(v["rpo"])
        if v.get("zorg_id"):
            zorg_ids.add(v["zorg_id"])
        vpgs[k] = v
    key = name.lower().replace(" ", "")
    vpg_ids = {v.get("id") for v in vpgs.values() if v.get("id")}
    seen_alerts: dict[tuple, dict] = {}
    for r in rows:
        p = r["payload"] or r["stale_payload"]
        if not p:
            continue
        if r["source"]["kind"] == "zvm":
            for a in p.get("alerts") or []:
                if a.get("dismissed"):
                    continue                    # acknowledged in Zerto
                by_id = bool(set(a.get("zorgs") or []) & zorg_ids) or bool(set(a.get("vpgs") or []) & vpg_ids)
                by_text = key in (a.get("text") or "").lower().replace(" ", "")
                is_zcc = (a.get("id") or "").startswith("ZCC") or a.get("entity") == "CloudConnector"
                if by_id or by_text:
                    k = alert_key(a)
                    if k in seen_alerts:        # the paired ZVM reports the same alert
                        seen_alerts[k]["source"] += ", " + r["source"]["name"]
                        continue
                    rec = seen_alerts[k] = {**a, "source": r["source"]["name"],
                                            "fixes": playbook.for_alert(a, {"zorg": name})}
                    alerts.append(rec)
                    if is_zcc:
                        zcc_alerts.append(rec)
        else:
            for z in p.get("zorgs", []):
                if str(z.get("_name") or "").lower() == name.lower():
                    zcm_zorg = z
            for c in p.get("cloud_connectors", []):
                if (str(c.get("_zorg") or "").lower() == name.lower()
                        or (c.get("_zorg_id") and c["_zorg_id"] in zorg_ids)):
                    ccs.append(c)

    lst = sorted(vpgs.values(), key=lambda v: (HEALTH_RANK[v["health"]], (v["name"] or "").lower()))
    rpos = [v["rpo"] for v in lst if v["rpo"] is not None and v["rpo"] >= 0]
    sites = sorted({v["protected_site"] for v in lst if v["protected_site"]} |
                   {v["recovery_site"] for v in lst if v["recovery_site"]})
    vms = sum(len(v["members"]) for v in lst)
    zorg_ig = next((_brief(i) for i in db.list_ignores() if i["scope"] == "zorg" and i["target"] == name), None)
    return {
        "name": name, "vpgs": lst, "alerts": alerts, "cloud_connectors": ccs, "zcm": zcm_zorg,
        "zcc_alerts": zcc_alerts, "zorg_ids": sorted(zorg_ids), "zorg_ignore": zorg_ig,
        "tests": _test_summary(lst),
        "summary": {
            "vpgs": len(lst), "vms": vms,
            "failure": sum(1 for v in lst if v["health"] == "failure" and not v.get("ignored")),
            "warning": sum(1 for v in lst if v["health"] == "warning" and not v.get("ignored")),
            "healthy": sum(1 for v in lst if v["health"] == "healthy"),
            "ignored": sum(1 for v in lst if v.get("ignored")),
            "prov_tb": round(sum(v["prov_gb"] for v in lst) / 1024, 2),
            "used_tb": round(sum(v["used_gb"] for v in lst) / 1024, 2),
            "journal_gb": round(sum(m["journal_gb"] for v in lst for m in v["members"]), 1),
            "thru": round(sum(v["thru"] for v in lst), 1),
            "worst_rpo": fmt_age(max(rpos)) if rpos else "-",
            "median_rpo": fmt_age(sorted(rpos)[len(rpos) // 2]) if rpos else "-",
            "sites": sites,
            "no_recovery_point": sum(1 for v in lst if v["rpo"] is not None and v["rpo"] < 0),
        },
    }
