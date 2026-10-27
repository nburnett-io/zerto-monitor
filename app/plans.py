"""DR failover plans per zORG - Zerto 10.9 recovery plans.

A recovery plan is an ordered list of blocks that a failover (or test) runs top to
bottom: VPG (a set of VPGs started together), WaitRecoveryOperationCompletion (finish
before going on), Delay (minutes) and Script (from the ZVM's script repository). The
monitor shows every plan that covers a zORG's VPGs with its status and last runs, flags
the zORG's VPGs that no plan covers (a VPG added after the plan was built is silently left
out of a real failover), and builds plans from the zORG page: VPGs dropped into numbered
tiers, each tier optionally followed by a wait, a script and a delay.

A plan lives on the ZVM of the site the VPGs recover TO, where a failover is started when
the protected site is gone. Creating or editing one is a write: the site armed, the plan
switch on, the source's credential over the pinned certificate; engineers may create
and edit, only admins delete. Nothing here RUNS a plan.
"""
from __future__ import annotations

import json
import re

import db
from zerto import WRITES_PLAN_DELETE, WRITES_PLANS, ZvmError, ci

MAX_TIERS = 10
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_./\\ \-]{1,200}$")


class PlanError(Exception):
    pass


def enabled() -> bool:
    return db.get_setting("plans_enabled") == "true"


def _sources_by_site() -> dict[str, tuple[dict, dict]]:
    snaps, out = db.get_snapshots(), {}
    for s in db.list_sources(enabled_only=True):
        p = (snaps.get(s["id"]) or {}).get("payload") or {}
        if s["kind"] == "zvm" and p.get("site") and p["site"] not in out:
            out[p["site"]] = (s, p)
    return out


def zorg_plans(name: str, vpgs: list[dict]) -> dict:
    """Plans touching this zORG's VPGs, per site; and the zORG's VPGs no plan covers."""
    ids = {v.get("id"): v for v in vpgs if v.get("id")}
    by_site = _sources_by_site()
    plans, readable = [], {}
    for site, (src, p) in by_site.items():
        readable[site] = p.get("plans") is not None
        for pl in p.get("plans") or []:
            vids = [i for b in pl["blocks"] for i in b.get("vpg_ids") or []]
            if not set(vids) & set(ids):
                continue
            tiers, n = [], 0
            for b in pl["blocks"]:
                if b.get("type") == "VPG":
                    n += 1
                    tiers.append({"n": n, "vpgs": [ids[i]["name"] if i in ids else f"(other zORG / unknown {i[:8]})"
                                                   for i in b.get("vpg_ids") or []], "after": []})
                elif tiers:
                    tiers[-1]["after"].append(
                        "wait for completion" if b.get("type") == "WaitRecoveryOperationCompletion" else
                        f"delay {b.get('delay')} min" if b.get("type") == "Delay" else
                        f"script {b.get('script')}" if b.get("type") == "Script" else str(b.get("type")))
            plans.append({**pl, "site": site, "source_id": src["id"], "tiers": tiers, "vpg_ids": vids})
    covered = {i for pl in plans for i in pl["vpg_ids"]}
    sites = sorted({v.get("recovery_site") for v in vpgs if v.get("recovery_site")})
    missing = {}
    for site in sites:
        here = [v for v in vpgs if v.get("recovery_site") == site]
        site_plans = [pl for pl in plans if pl["site"] == site]
        if site_plans:
            gaps = [v["name"] for v in here if v.get("id") not in covered]
            if gaps:
                missing[site] = gaps
    return {"plans": plans, "sites": [{"site": s, "monitored": s in by_site, "readable": readable.get(s, False),
                                       "has_plan": any(pl["site"] == s for pl in plans),
                                       "vpgs": sum(1 for v in vpgs if v.get("recovery_site") == s)} for s in sites],
            "missing": missing, "enabled": enabled()}


def _zorg_vpgs_and_plans(zorg: str) -> tuple[list[dict], list[dict]]:
    import views
    vpgs = views.zorg_detail(zorg)["vpgs"]
    return vpgs, zorg_plans(zorg, vpgs)["plans"]


def zorg_plans_for(zorg: str) -> list[dict]:
    return _zorg_vpgs_and_plans(zorg)[1]


def build_body(name: str, ptype: str, tiers: list[dict]) -> dict:
    """tiers: in order, [{"vpg_ids": [...], "wait": bool, "script": str, "params": str, "delay": int}]."""
    blocks = []
    for t in tiers:
        blocks.append({"blockType": "VPG", "vpgIds": list(t["vpg_ids"])})
        if t.get("wait"):
            blocks.append({"blockType": "WaitRecoveryOperationCompletion"})
        if t.get("script"):
            blocks.append({"blockType": "Script", "scriptPath": t["script"],
                           "scriptParameters": [p for p in (t.get("params") or "").split() if p]})
        if t.get("delay"):
            blocks.append({"blockType": "Delay", "delayInMinutes": int(t["delay"])})
    while blocks and blocks[-1]["blockType"] in ("WaitRecoveryOperationCompletion", "Delay"):
        blocks.pop()                                    # nothing left to wait for after the last tier
    return {"name": name, "type": ptype, "blocks": blocks}


def not_editable(plan: dict, vpgs: list[dict], site: str) -> str | None:
    """Why the builder can't edit this plan without losing something, else None. Saving
    replaces the whole plan, so it must round-trip exactly: only this zORG's VPGs at this
    site, and after each VPG tier at most one wait, script and delay, in that order."""
    allowed = {v["id"] for v in vpgs if v.get("id") and v.get("recovery_site") == site}
    order = ("WaitRecoveryOperationCompletion", "Script", "Delay")
    last = None
    for b in plan.get("blocks") or []:
        t = b.get("type")
        if t == "VPG":
            foreign = [i for i in b.get("vpg_ids") or [] if i not in allowed]
            if foreign:
                return (f"it also holds {len(foreign)} VPG(s) of another zORG or site; saving from here would "
                        "drop them from the plan. Edit it in Zerto.")
            last = -1
        elif t in order and last is not None and order.index(t) > last and \
                not (t == "Script" and any(" " in p for p in b.get("params") or [])):
            last = order.index(t)
        else:
            return "it has steps this builder can't reproduce exactly. Edit it in Zerto."
    return None


def parse_form(form: dict, vpgs: list[dict], site: str) -> tuple[str, str, list[dict], list[str]]:
    """The builder form -> (name, type, tiers, problems). Only this zORG's VPGs that
    recover to `site` may go in."""
    allowed = {v["id"]: v for v in vpgs if v.get("id") and v.get("recovery_site") == site}
    problems = []
    name = (form.get("name") or "").strip()
    if not (1 <= len(name) <= 100):
        problems.append("give the plan a name (up to 100 characters)")
    ptype = form.get("type") or "Standard"
    if ptype not in ("Standard", "Cyber"):
        problems.append("type must be Standard or Cyber")
    tiers: dict[int, dict] = {}
    for vid, v in allowed.items():
        raw = (form.get(f"tier_{vid}") or "").strip()
        if not raw:
            continue
        if not raw.isdigit() or not (1 <= int(raw) <= MAX_TIERS):
            problems.append(f"{v['name']}: tier must be 1-{MAX_TIERS}")
            continue
        tiers.setdefault(int(raw), {"vpg_ids": []})["vpg_ids"].append(vid)
    for k in [x for x in form if x.startswith("tier_") and x[5:] not in allowed and form[x]]:
        problems.append(f"{k[5:]} isn't one of this zORG's VPGs recovering to {site}")
    ordered = []
    for n in sorted(tiers):
        t = tiers[n]
        t["wait"] = form.get(f"wait_{n}") == "1"
        script = (form.get(f"script_{n}") or "").strip()
        if script and not SCRIPT_RE.match(script):
            problems.append(f"tier {n}: the script path has characters a path shouldn't")
        t["script"], t["params"] = script, (form.get(f"params_{n}") or "").strip()[:500]
        try:
            t["delay"] = int(form.get(f"delay_{n}") or 0)
        except ValueError:
            t["delay"] = -1
        if not (0 <= t["delay"] <= 240):
            problems.append(f"tier {n}: delay must be 0-240 minutes")
        ordered.append({**t, "n": n})
    if not ordered:
        problems.append("put at least one VPG in a tier")
    return name, ptype, ordered, problems


def arming(src: dict | None) -> list[str]:
    import vrapush
    if not src:
        return ["the recovery site isn't a monitored ZVM"]
    out = []
    if not enabled():
        out.append("recovery-plan changes are switched off (Admin → Changes to Zerto)")
    return out + vrapush.site_problems(src)


def save(zorg: str, site: str, plan_id: str | None, body: dict, user: dict, client_factory=None) -> str:
    """Create (POST) or update (PUT) the plan on the recovery site's ZVM. Returns the plan id."""
    import vrapush
    src = (_sources_by_site().get(site) or (None, None))[0]
    problems = arming(src)
    if problems:
        raise PlanError(problems[0])
    if plan_id and not re.fullmatch(r"[0-9A-Fa-f-]{36}", plan_id):
        raise PlanError("bad plan id")
    if plan_id:                     # only a plan of this zORG at this site, and only one that round-trips
        vpgs, zps = _zorg_vpgs_and_plans(zorg)
        pl = next((p for p in zps if p["id"] == plan_id and p["site"] == site), None)
        if not pl:
            raise PlanError(f"that plan doesn't cover {zorg}'s VPGs at {site} (any more)")
        why = not_editable(pl, vpgs, site)
        if why:
            raise PlanError(f"this plan can't be edited here: {why}")
    if not plan_id and any(pl.get("name") == body["name"] for pl in _sources_by_site()[site][1].get("plans") or []):
        raise PlanError(f"{site} already has a plan named '{body['name']}' - edit that one, or pick another name")
    cid = db.log_change(kind="plan_update" if plan_id else "plan_create", by_user=user["username"], site=site,
                        source_id=src["id"], target=body["name"], zorg=zorg, state="sending",
                        request_json=json.dumps(body))
    try:
        cl = (client_factory or (lambda s: vrapush.change_client(s, WRITES_PLANS)))(src)
    except Exception as e:  # noqa: BLE001 - nothing was sent
        db.update_change(cid, state="failed", detail=str(e)[:600], finished_at=db.now_iso())
        raise PlanError(str(e)[:300]) from e
    try:
        if plan_id:
            status, r = cl.write("PUT", f"/v1/recoveryPlans/{plan_id}", body,
                                 "Managing recovery plans needs Zerto's recovery-plan privilege.")
        else:
            status, r = cl.write("POST", "/v1/recoveryPlans", body,
                                 "Managing recovery plans needs Zerto's recovery-plan privilege.")
    except ZvmError as e:                       # refused before or by Zerto (403): not applied
        db.update_change(cid, state="failed", detail=str(e)[:600], finished_at=db.now_iso())
        raise PlanError(str(e)[:300]) from e
    except Exception as e:  # noqa: BLE001 - e.g. a timeout after the request went out
        db.update_change(cid, state="unknown", detail=f"no clear answer: {e}"[:600], finished_at=db.now_iso())
        raise PlanError(f"no clear answer from {site} ({type(e).__name__}): check the plan in Zerto before "
                        "trying again") from e
    db.update_change(cid, response_json=json.dumps({"status": status, "body": r})[:5000], finished_at=db.now_iso())
    if status >= 500:
        db.update_change(cid, state="unknown", detail=f"{status}: Zerto may have applied it")
        raise PlanError(f"{site} answered {status}: check the plan in Zerto before trying again")
    if status not in (200, 201, 204):
        msg = (ci(r, "Message") or ci(r, "Error") or str(r)) if isinstance(r, dict) else str(r)
        db.update_change(cid, state="failed", detail=f"{status}: {msg}"[:600])
        raise PlanError(f"Zerto refused the plan ({status}): {msg[:300]}")
    new_id = plan_id or (r.strip('"') if isinstance(r, str) else ci(r, "Id") if isinstance(r, dict) else None)
    db.update_change(cid, state="done", detail=f"{'updated' if plan_id else 'created'} plan {new_id}")
    db.log_alert(zorg, "plan", "", None, f"{user['username']} {'updated' if plan_id else 'created'} recovery plan "
                 f"'{body['name']}' at {site} ({sum(b['blockType'] == 'VPG' for b in body['blocks'])} tier(s))", "-", True)
    return new_id or ""


def delete(zorg: str, site: str, plan_id: str, user: dict, client_factory=None) -> None:
    import vrapush
    if user.get("role") != "admin":
        raise PlanError("only an admin can delete a recovery plan")
    src = (_sources_by_site().get(site) or (None, None))[0]
    problems = arming(src)
    if problems:
        raise PlanError(problems[0])
    if not re.fullmatch(r"[0-9A-Fa-f-]{36}", plan_id or ""):
        raise PlanError("bad plan id")
    if plan_id not in {pl["id"] for pl in zorg_plans_for(zorg) if pl["site"] == site}:
        raise PlanError(f"that plan doesn't cover {zorg}'s VPGs at {site}")
    cid = db.log_change(kind="plan_delete", by_user=user["username"], site=site, source_id=src["id"],
                        target=plan_id, zorg=zorg, state="sending")
    try:
        cl = (client_factory or (lambda s: vrapush.change_client(s, WRITES_PLAN_DELETE)))(src)
        status, r = cl.write("DELETE", f"/v1/recoveryPlans/{plan_id}", None,
                             "Managing recovery plans needs Zerto's recovery-plan privilege.")
    except Exception as e:  # noqa: BLE001
        db.update_change(cid, state="failed", detail=str(e)[:600], finished_at=db.now_iso())
        raise PlanError(str(e)[:300]) from e
    ok = status in (200, 202, 204)
    db.update_change(cid, state="done" if ok else "failed", detail=f"{status}: {str(r)[:300]}", finished_at=db.now_iso())
    if not ok:
        raise PlanError(f"Zerto refused ({status}): {str(r)[:200]}")
    db.log_alert(zorg, "plan", "", None, f"{user['username']} deleted recovery plan {plan_id} at {site}", "-", True)
