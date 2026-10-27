"""Zerto Monitor — FastAPI app.

Pages:  /            failure + warning VPGs across every source, with reasons
        /vras        VRA status (disconnects, subnet-mask drift, sizing)
        /zorgs       zORG list  ->  /zorgs/{name} drill-down (+ ZCC health from ZCM)
        /admin       sources, users, poll interval          (admin only)
JSON:   /api/overview /api/vras /api/zorgs /api/zorgs/{name} /api/sources
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.templating import Jinja2Templates  # noqa: E402

import alerts  # noqa: E402
import auth  # noqa: E402
import backups  # noqa: E402
import collector  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import events as zevents  # noqa: E402
import plans  # noqa: E402
import playbook  # noqa: E402
import reports  # noqa: E402
import tlsmgr  # noqa: E402
import updates  # noqa: E402
import views  # noqa: E402
import vrapush  # noqa: E402
import zerto  # noqa: E402
from zerto import fmt_age  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
# a crash dump of this process would carry decrypted credentials: never write one
if sys.platform.startswith("linux"):
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)        # PR_SET_DUMPABLE = 0
    except (OSError, AttributeError):
        pass
ROOT = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(ROOT / "templates"))
templates.env.filters["age"] = fmt_age
templates.env.globals["app_version"] = updates.current_version()   # an update restarts the service


def linkify(text):
    """Engineer-written text, escaped, with bare http(s) links made clickable. Each
    piece is escaped on its own, so nothing typed can become markup."""
    from markupsafe import Markup, escape
    text = str(text or "")
    out, pos = [], 0
    for m in re.finditer(r"https?://[^\s<>\"']+", text):
        url = m.group(0).rstrip(".,;:)]}!?")
        out.append(escape(text[pos:m.start()]))
        u = escape(url)
        out.append(Markup(f'<a href="{u}" rel="noopener noreferrer" target="_blank">{u}</a>'))
        pos = m.start() + len(url)
    out.append(escape(text[pos:]))
    return Markup("").join(out)


templates.env.filters["linkify"] = linkify


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    task = asyncio.create_task(collector.loop_forever())
    pusher = asyncio.create_task(vrapush.worker())      # VRA resizes, strictly one at a time
    restorer = asyncio.create_task(backups.worker())    # VPG restores, one at a time
    yield
    task.cancel()
    pusher.cancel()
    restorer.cancel()


app = FastAPI(title="Zerto Monitor", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")


def render(request: Request, template: str, **ctx):
    # parameter is `template`, not `name`: view dicts (zorg_detail) carry a `name` key
    ctx.setdefault("user", auth.optional_user(request))
    ctx["request"] = request
    return templates.TemplateResponse(request, template, ctx)


def _secure(request: Request) -> bool:
    """Mark cookies Secure whenever the browser is on HTTPS. Behind nginx, uvicorn
    takes the scheme from X-Forwarded-Proto (it trusts 127.0.0.1 by default), so
    this is true on the appliance and false for local plain-HTTP development."""
    return request.url.scheme == "https" or os.environ.get("COOKIE_SECURE") == "1"


def _set_session(resp, request: Request, username: str, role: str):
    resp.set_cookie(auth.COOKIE, auth.create_token(username, role), httponly=True,
                    samesite="lax", secure=_secure(request), max_age=auth.EXPIRE_HOURS * 3600)


def _local(path: str, default: str = "/") -> str:
    """Only ever redirect to a path on this site: '//evil.example' and
    'https://...' would otherwise make the login form an open redirect."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return default
    return path


# ── sign-in requirement ─────────────────────────────────────────────────────
# Off by default: dashboards are read-only for anyone who can reach them until an
# admin turns this on (Admin -> Access). On, every page and API needs a session.
# /api/update/* authenticates itself (deploy token or an admin session)
OPEN_PATHS = ("/login", "/logout", "/setup", "/auth/", "/static/", "/healthz", "/api/update/")
_login_cache = {"at": 0.0, "on": False}


def login_required() -> bool:
    import time
    if time.monotonic() - _login_cache["at"] > 5:
        _login_cache.update(at=time.monotonic(), on=db.get_setting("require_login") == "true")
    return _login_cache["on"]


def _login_redirect(request: Request) -> RedirectResponse:
    nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"/login?next={quote(nxt, safe='/')}", status_code=303)


def _cross_site(request: Request) -> bool:
    """A browser POST from another site (CSRF). Browsers send Origin (or at least Referer)
    on cross-site POSTs; every *.example.com host counts as the same *site* to SameSite=Lax,
    so the cookie alone proves nothing. Scripts that send neither carry no ambient cookie
    from another site, and Bearer-token calls don't use the cookie at all."""
    if request.method in ("GET", "HEAD", "OPTIONS") or request.headers.get("authorization", "").startswith("Bearer "):
        return False
    src = request.headers.get("origin") or request.headers.get("referer")
    if not src:
        return False
    from urllib.parse import urlsplit
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    return (urlsplit(src).hostname or "") != host


@app.middleware("http")
async def _require_login(request: Request, call_next):
    path = request.url.path
    if _cross_site(request):
        return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
    if login_required() and not path.startswith(OPEN_PATHS) and auth.optional_user(request) is None:
        # the appliance's own SNMP hook reads /api/metrics over loopback; uvicorn takes
        # the client address from nginx's X-Forwarded-For, which nginx sets itself
        local = request.client is not None and request.client.host in ("127.0.0.1", "::1")
        if not (path == "/api/metrics" and local):
            if path.startswith("/api/"):
                return JSONResponse({"detail": "not authenticated"}, status_code=401)
            return _login_redirect(request)
    return await call_next(request)


def _back(msg: str = "", err: str = "", anchor: str = "") -> RedirectResponse:
    q = f"msg={quote(msg[:300])}" if msg else f"err={quote(err[:300])}"
    return RedirectResponse(f"/admin?{q}{('#' + anchor) if anchor else ''}", status_code=303)


def _to(back: str, msg: str = "", err: str = "") -> RedirectResponse:
    """Redirect to a LOCAL page with a flash message. Anything that isn't a plain
    local path (//evil.example, https://...) falls back to the dashboard, so the
    form's 'back' field can't be turned into an open redirect."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    u = urlsplit(_local(back))
    q = [(k, v) for k, v in parse_qsl(u.query) if k not in ("msg", "err")]
    q.append(("msg", msg[:300]) if msg else ("err", err[:300]))
    return RedirectResponse(urlunsplit(("", "", u.path, urlencode(q), u.fragment)), status_code=303)


@app.exception_handler(auth.NotAuthenticated)
async def _redirect_login(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "not authenticated"}, status_code=401)
    return _login_redirect(request)


# ── first run / login ───────────────────────────────────────────────────────
@app.get("/setup", response_class=HTMLResponse)
async def setup_form(request: Request):
    if db.user_count():
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html")


@app.post("/setup")
async def setup_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    if db.user_count():
        raise HTTPException(403)
    problem = auth.username_problem(username.strip()) or auth.password_problem(password)
    if problem:
        return render(request, "setup.html", error=problem)
    db.create_user(username.strip(), auth.hash_password(password), "admin")
    return RedirectResponse("/login", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/", error: str = ""):
    if not db.user_count():
        return RedirectResponse("/setup", status_code=303)
    return render(request, "login.html", next=next, error=error,
                  entra_enabled=auth.entra_config() is not None,
                  entra_label=db.get_setting("entra_button_label") or auth.ENTRA_BUTTON_DEFAULT)


# ── Entra ID SSO ────────────────────────────────────────────────────────────
@app.get("/login/entra")
async def login_entra(request: Request, next: str = "/admin"):
    cfg = auth.entra_config()
    if not cfg:
        return RedirectResponse("/login?error=Entra+ID+SSO+is+not+configured", status_code=303)
    state = secrets.token_urlsafe(24)
    redirect_uri = cfg["entra_redirect_uri"] or str(request.base_url).rstrip("/") + "/auth/callback"
    try:
        url = await asyncio.to_thread(
            lambda: auth.entra_app(cfg).get_authorization_request_url(
                scopes=auth.SCOPES, state=state, redirect_uri=redirect_uri))
    except Exception as e:  # noqa: BLE001 - bad tenant id, discovery unreachable, etc.
        logging.getLogger("sso").warning("entra authorize-url failed: %s", e)
        return RedirectResponse(f"/login?error={quote('Entra ID: ' + str(e)[:160])}", status_code=303)
    resp = RedirectResponse(url, status_code=303)
    resp.set_cookie("oidc_state", state, httponly=True, samesite="lax",
                    secure=_secure(request), max_age=600)
    resp.set_cookie("oidc_next", _local(next, "/admin"),
                    httponly=True, samesite="lax", secure=_secure(request), max_age=600)
    return resp


@app.get("/auth/callback")
async def entra_callback(request: Request, code: str = "", state: str = "",
                         error: str = "", error_description: str = ""):
    cfg = auth.entra_config()
    if not cfg:
        return RedirectResponse("/login?error=Entra+ID+SSO+is+not+configured", status_code=303)
    if error:
        return RedirectResponse(f"/login?error={quote(error_description or error)}", status_code=303)
    if not state or state != request.cookies.get("oidc_state"):
        return RedirectResponse("/login?error=SSO+state+mismatch", status_code=303)
    redirect_uri = cfg["entra_redirect_uri"] or str(request.base_url).rstrip("/") + "/auth/callback"
    try:
        result = await asyncio.to_thread(
            lambda: auth.entra_app(cfg).acquire_token_by_authorization_code(
                code, scopes=auth.SCOPES, redirect_uri=redirect_uri))
    except Exception as e:  # noqa: BLE001
        logging.getLogger("sso").warning("entra token exchange failed: %s", e)
        return RedirectResponse(f"/login?error={quote('Entra ID: ' + str(e)[:160])}", status_code=303)
    if "id_token_claims" not in result:
        msg = result.get("error_description") or result.get("error") or "token exchange failed"
        return RedirectResponse(f"/login?error={quote(str(msg)[:200])}", status_code=303)
    claims = result["id_token_claims"]
    upn = (claims.get("preferred_username") or claims.get("upn") or claims.get("email") or "").lower()
    if not upn:
        return RedirectResponse("/login?error=no+username+in+token", status_code=303)
    role = auth.entra_role(cfg, claims)
    if not db.upsert_sso_user(upn, role):
        return RedirectResponse(f"/login?error={quote(f'{upn} is a local account here: sign in with its password')}",
                                status_code=303)
    resp = RedirectResponse(_local(request.cookies.get("oidc_next") or "", "/admin"), status_code=303)
    _set_session(resp, request, upn, role)
    resp.delete_cookie("oidc_state")
    resp.delete_cookie("oidc_next")
    return resp


@app.post("/login")
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                       next: str = Form("/")):
    u = await asyncio.to_thread(auth.authenticate, username.strip(), password)   # bcrypt: ~0.2 s
    if not u:
        return render(request, "login.html", error="Invalid credentials", next=next)
    resp = RedirectResponse(_local(next), status_code=303)
    _set_session(resp, request, u["username"], u["role"])
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.COOKIE)
    return resp


# ── pages (public - no login required; only /admin is protected) ────────────
# view builders read SQLite and shape thousands of records; keep them off the
# event loop so a poll landing mid-request can't stall the server.
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, msg: str = "", err: str = "", zorg: str = "", q: str = "",
                    health: str = "", zvm: str = ""):
    ov = await asyncio.to_thread(views.overview)
    # filters narrow the two lists only; the counts above them stay estate-wide
    f = {"zorg": zorg.strip(), "q": q.strip(), "health": health if health in ("failure", "warning") else "",
         "zvm": zvm.strip()}

    def keep(v):
        return ((not f["zorg"] or (v.get("org") or "(no zORG)") == f["zorg"])
                and (not f["q"] or f["q"].lower() in (v.get("name") or "").lower())
                and (not f["health"] or v.get("health") == f["health"])
                and (not f["zvm"] or f["zvm"] in (v.get("seen_on") or [])))
    every = ov["vpgs"] + ov["ignored_vpgs"]
    options = {"zorgs": sorted({v.get("org") or "(no zORG)" for v in every}, key=str.lower),
               "zvms": sorted({s["name"] for s in ov["sites"] if s["kind"] == "zvm"}, key=str.lower)}
    shown = {"vpgs_all": len(ov["vpgs"]), "ignored_all": len(ov["ignored_vpgs"])}
    if any(f.values()):
        ov = {**ov, "vpgs": [v for v in ov["vpgs"] if keep(v)],
              "ignored_vpgs": [v for v in ov["ignored_vpgs"] if keep(v)]}
    # where an ignore / team-fix form returns to: this filtered view (_to drops old msg/err)
    here = _local(request.url.path + (f"?{request.url.query}" if request.url.query else ""))
    return render(request, "dashboard.html", msg=msg, err=err, f=f, options=options, shown=shown,
                  here=here, **ov)


@app.get("/vras", response_class=HTMLResponse)
async def vras_page(request: Request, msg: str = "", err: str = ""):
    return render(request, "vras.html", msg=msg, err=err, **(await asyncio.to_thread(views.vras)))


@app.get("/vras/{site}", response_class=HTMLResponse)
async def vras_site_page(request: Request, site: str, msg: str = "", err: str = ""):
    return render(request, "vras_site.html", msg=msg, err=err, halted=vrapush.halted(),
                  **(await asyncio.to_thread(views.vras_site, site)))


@app.get("/zorgs", response_class=HTMLResponse)
async def zorgs_page(request: Request):
    return render(request, "zorgs.html", zorgs=await asyncio.to_thread(views.zorg_list))


@app.get("/zorgs/{name}", response_class=HTMLResponse)
async def zorg_page(request: Request, name: str, msg: str = "", err: str = ""):
    def build():
        d = views.zorg_detail(name)
        return {**d, **views.zorg_extras(name, d)}
    return render(request, "zorg.html", msg=msg, err=err, months=reports.months(3),
                  **(await asyncio.to_thread(build)))


# ── VPG page: trends, timeline, backups ─────────────────────────────────────
@app.get("/vpgs/{key:path}", response_class=HTMLResponse)
async def vpg_page(request: Request, key: str, hours: int = 168, msg: str = "", err: str = ""):
    return render(request, "vpg.html", msg=msg, err=err,
                  **(await asyncio.to_thread(views.vpg_detail, key, max(24, min(hours, 24 * 35)))))


@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request, zorg: str = "", kind: str = "", days: int = 30):
    days = max(1, min(days, 400))
    rows = await asyncio.to_thread(views.timeline, zorg or None, kind or None, days)
    orgs = await asyncio.to_thread(views.zorg_list)
    return render(request, "timeline.html", rows=rows, zorg=zorg, kind=kind, days=days,
                  kinds=zevents.KIND_LABEL, zorg_names=sorted({o["name"] for o in orgs}, key=str.lower))


# ── VPG settings backups + restore ──────────────────────────────────────────
@app.get("/backups", response_class=HTMLResponse)
async def backups_page(request: Request, zorg: str = "", q: str = "", msg: str = "", err: str = ""):
    return render(request, "backups.html", msg=msg, err=err, zorg=zorg, q=q,
                  **(await asyncio.to_thread(views.backups_overview, zorg or None, q.strip() or None)))


@app.post("/backups/now")
async def backup_now(user=Depends(auth.engineer_user), site: str = Form(...), vpg: str = Form(""),
                     back: str = Form("/backups")):
    src, payload, _ = await asyncio.to_thread(vrapush._site_source, site)
    if not src:
        return _to(back, err=f"No live ZVM source reports {site}")
    try:
        msg = await asyncio.to_thread(backups.backup_now, src, payload, [vpg] if vpg else None, user["username"])
    except Exception as e:  # noqa: BLE001 - shown to the engineer as-is (credentials are never in these errors)
        return _to(back, err=f"Backup failed: {e}"[:300])
    return _to(back, msg=msg)


@app.get("/backups/{backup_id}", response_class=HTMLResponse)
async def backup_page(request: Request, backup_id: int, against: int | None = None,
                      user=Depends(auth.engineer_user)):
    ctx = await asyncio.to_thread(views.backup_detail, backup_id, against)
    if not ctx:
        raise HTTPException(404, "that backup no longer exists")
    return render(request, "backup.html", user=user, **ctx)


@app.get("/backups/{backup_id}/restore", response_class=HTMLResponse)
async def restore_preview(request: Request, backup_id: int, user=Depends(auth.engineer_user),
                          msg: str = "", err: str = ""):
    pl = await asyncio.to_thread(backups.restore_plan, backup_id)
    return render(request, "restore.html", pl=pl, user=user, msg=msg, err=err,
                  restores=db.changes(kind="restore", limit=20))


@app.post("/admin/backups/{backup_id}/restore")
async def restore_start(request: Request, backup_id: int, user=Depends(auth.admin_user)):
    form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
    try:
        cid = await asyncio.to_thread(backups.start_restore, backup_id, user, form)
    except backups.RestoreError as e:
        return _to(f"/backups/{backup_id}/restore", err=f"Not started: {e}")
    return _to(f"/backups/{backup_id}/restore", msg=f"Restore #{cid} started: checked again on a fresh poll, "
                                                     "then sent once. Progress shows below.")


# ── DR failover (recovery) plans per zORG ───────────────────────────────────
@app.get("/zorgs/{name}/plan", response_class=HTMLResponse)
async def plan_editor(request: Request, name: str, site: str = "", id: str = "",
                      user=Depends(auth.engineer_user), msg: str = "", err: str = ""):
    ctx = await asyncio.to_thread(views.plan_editor, name, site, id or None, None)
    why = ctx["existing"] and plans.not_editable(ctx["existing"], ctx["vpgs"], ctx["site"])
    return render(request, "plan_edit.html", user=user, msg=msg,
                  err=err or (f"This plan can't be edited here: {why}" if why else ""), **ctx)


@app.post("/zorgs/{name}/plan", response_class=HTMLResponse)
async def plan_submit(request: Request, name: str, user=Depends(auth.engineer_user)):
    form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
    ctx = await asyncio.to_thread(views.plan_editor, name, form.get("site", ""), form.get("plan_id") or None, form)
    site, plan_id = ctx["site"], ctx["plan_id"]          # the checked values, never the raw form's
    if form.get("plan_id") and not plan_id:
        return render(request, "plan_edit.html", user=user, err="Not saved: that plan no longer covers this "
                      "zORG's VPGs at this site - reload the zORG page", **ctx)
    if form.get("action") == "save" and not ctx["problems"] and not ctx["arming"]:
        try:
            pid = await asyncio.to_thread(plans.save, name, site, plan_id, ctx["body"], user)
        except plans.PlanError as e:
            return render(request, "plan_edit.html", user=user, err=f"Not saved: {e}", **ctx)
        sid = (await asyncio.to_thread(vrapush._site_source, site))[0]
        sid = (sid or {}).get("id")
        if sid:
            asyncio.create_task(collector.poll_once(sid))
        return _to(f"/zorgs/{quote(name)}#plans", msg=f"Recovery plan '{ctx['body']['name']}' "
                                                      f"{'updated' if plan_id else 'created'} at {site} ({pid[:8]}…). "
                                                      "It shows here after the next poll.")
    return render(request, "plan_edit.html", user=user, **ctx)


@app.post("/admin/plans/delete")
async def plan_delete(user=Depends(auth.admin_user), zorg: str = Form(...), site: str = Form(...),
                      plan_id: str = Form(...), typed: str = Form("")):
    if typed.strip().lower() != "delete":
        return _to(f"/zorgs/{quote(zorg)}#plans", err="Type DELETE to confirm removing the plan")
    try:
        await asyncio.to_thread(plans.delete, zorg, site, plan_id, user)
    except plans.PlanError as e:
        return _to(f"/zorgs/{quote(zorg)}#plans", err=f"Not deleted: {e}")
    sid = ((await asyncio.to_thread(vrapush._site_source, site))[0] or {}).get("id")
    if sid:
        asyncio.create_task(collector.poll_once(sid))
    return _to(f"/zorgs/{quote(zorg)}#plans", msg="Recovery plan deleted")


# ── monthly reports ─────────────────────────────────────────────────────────
@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, msg: str = "", err: str = ""):
    return render(request, "reports.html", msg=msg, err=err, months=reports.months(),
                  zorgs=await asyncio.to_thread(views.zorg_list))


async def _report_html(request: Request, zorg: str, month: str, pdf: bool, err: str = "") -> str:
    try:
        r = await asyncio.to_thread(reports.build, zorg, month)
    except reports.ReportError as e:
        raise HTTPException(400, str(e))
    return templates.get_template("report.html").render(r=r, pdf=pdf, err=err, request=request,
                                                        user=auth.optional_user(request))


@app.get("/reports/{zorg}/{month}", response_class=HTMLResponse)
async def report_page(request: Request, zorg: str, month: str, err: str = ""):
    return HTMLResponse(await _report_html(request, zorg, month, False, err))


@app.get("/reports/{zorg}/{month}/pdf")
async def report_pdf(request: Request, zorg: str, month: str):
    from fastapi.responses import Response
    html = await _report_html(request, zorg, month, True)
    try:
        data = await asyncio.to_thread(reports.pdf, html)
    except reports.ReportError as e:
        return _to(f"/reports/{quote(zorg)}/{quote(month)}", err=str(e))
    fname = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in zorg)
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="DR-report-{fname}-{month}.pdf"'})


# ── ignores: an engineer takes a VPG or a whole zORG out of alerting ────────
IGNORE_SPANS = {0: "until removed", 1: "1 day", 7: "7 days", 30: "30 days", 90: "90 days"}


@app.post("/admin/ignores")
async def add_ignore(user=Depends(auth.engineer_user), scope: str = Form(...), target: str = Form(...),
                     mode: str = Form("ack"), days: int = Form(7), note: str = Form(""),
                     back: str = Form("/")):
    if scope not in ("vpg", "zorg") or mode not in ("ack", "all") or days not in IGNORE_SPANS:
        return _to(back, err="That ignore request wasn't valid")
    merged = await asyncio.to_thread(views.merged_vpgs)
    if scope == "vpg":
        v = merged.get(target)
        if not v:
            return _to(back, err="That VPG isn't in the current data any more")
        members, label, org = {target: v}, v["name"], v["org"] or "(no zORG)"
    else:
        members = {k: v for k, v in merged.items() if (v["org"] or "(no zORG)") == target}
        if not members:
            return _to(back, err=f"No VPGs found for zORG {target}")
        label = org = target
    # what is wrong RIGHT NOW is what an acknowledgement covers - built server-side
    # from current data, never from anything the browser sends
    snapshot = {k: views.ignore_snapshot(v) for k, v in members.items() if v["health"] != "healthy"}
    if mode == "ack" and not snapshot:
        return _to(back, err=f"Nothing is wrong with {label} right now, so there's nothing to "
                             "acknowledge. Choose 'everything' to ignore it ahead of time.")
    from datetime import datetime, timedelta, timezone
    expires = ((datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
               if days else None)
    note = note.strip()[:300]
    db.save_ignore(scope, target, label, mode, snapshot if mode == "ack" else {}, note,
                   user["username"], expires)
    what = ("its current problems" if mode == "ack" else "everything")
    db.log_alert(org, "ignored", "", None,
                 f"{user['username']} ignored {'VPG' if scope == 'vpg' else 'zORG'} {label}: {what}, "
                 f"{IGNORE_SPANS[days]}" + (f" - {note}" if note else ""), "-", True)
    tail = ("; anything new or worse will still alert" if mode == "ack" else "")
    return _to(back, msg=f"Ignoring {label} ({what}, {IGNORE_SPANS[days]}){tail}")


@app.post("/admin/ignores/{ignore_id}/delete")
async def remove_ignore(ignore_id: int, user=Depends(auth.engineer_user), back: str = Form("/admin#ignores")):
    ig = db.get_ignore(ignore_id)
    if ig:
        db.delete_ignore(ignore_id)
        org = ig["label"] if ig["scope"] == "zorg" else \
            ((await asyncio.to_thread(views.merged_vpgs)).get(ig["target"]) or {}).get("org") or ig.get("label") or "?"
        db.log_alert(org, "unignored", "", None,
                     f"{user['username']} removed the ignore on {ig['scope']} {ig.get('label')}", "-", True)
    return _to(back, msg="Ignore removed - it alerts normally again")


# ── signed self-update: admin page + token API ──────────────────────────────
def _updates_ctx(**extra) -> dict:
    try:
        rel, rel_err = updates.releases(), ""
    except updates.UpdateError as e:
        rel, rel_err = [], str(e)
    return {"installed": updates.current_version(), "status": updates.status(), "staged": updates.staged(),
            "key_id": updates.key_id(), "releases": rel, "releases_err": rel_err, "source": updates.source(),
            "tokens": db.list_deploy_tokens(), "now_iso": db.now_iso(), **extra}


@app.get("/admin/updates", response_class=HTMLResponse)
async def updates_page(request: Request, user=Depends(auth.admin_user), msg: str = "", err: str = ""):
    ctx = await asyncio.to_thread(_updates_ctx)
    return render(request, "admin_updates.html", user=user, msg=msg, err=err, **ctx)


def _upd_back(msg: str = "", err: str = "") -> RedirectResponse:
    return _to("/admin/updates", msg=msg, err=err)


@app.post("/admin/updates/fetch")
async def updates_fetch(user=Depends(auth.admin_user), version: str = Form(...)):
    try:
        info = await asyncio.to_thread(updates.fetch, version.strip())
    except updates.UpdateError as e:
        return _upd_back(err=str(e))
    return _upd_back(msg=f"{info['version']} downloaded and its signature checks out - review and apply below")


@app.post("/admin/updates/upload")
async def updates_upload(user=Depends(auth.admin_user), bundle: UploadFile = File(...)):
    data = await bundle.read(updates.MAX_BUNDLE + 1)
    try:
        info = await asyncio.to_thread(updates.stage, data)
    except updates.UpdateError as e:
        return _upd_back(err=str(e))
    return _upd_back(msg=f"{info['version']} uploaded and its signature checks out - review and apply below")


@app.post("/admin/updates/discard")
async def updates_discard(user=Depends(auth.admin_user)):
    updates.discard_staged()
    return _upd_back(msg="Staged bundle discarded")


@app.post("/admin/updates/apply")
async def updates_apply(user=Depends(auth.admin_user), typed: str = Form(""), allow_downgrade: str = Form("")):
    info = updates.staged() or {}
    if not info or info.get("error"):
        return _upd_back(err=info.get("error") or "nothing is staged")
    if typed.strip() != info["version"]:
        return _upd_back(err=f"type the version ({info['version']}) to confirm")
    try:
        await asyncio.to_thread(updates.start, user["username"], bool(allow_downgrade))
    except (updates.UpdateError, tlsmgr.TlsError) as e:
        return _upd_back(err=f"Not started: {e}")
    return _upd_back(msg=f"Update to {info['version']} started. The service restarts in about a minute; "
                         "this page shows its progress (refresh).")


@app.post("/admin/updates/source")
async def updates_source(user=Depends(auth.admin_user), url: str = Form("")):
    url = url.strip().rstrip("/")
    if url and not re.match(r"^https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?$", url):
        return _upd_back(err="the release source must be an https:// URL")
    db.set_setting("update_source", url)
    return _upd_back(msg=f"Release source: {url or updates.DEFAULT_SOURCE or 'none (upload .zmupdate bundles)'}")


@app.post("/admin/updates/tokens", response_class=HTMLResponse)
async def updates_token_new(request: Request, user=Depends(auth.admin_user), name: str = Form(...),
                            days: int = Form(30)):
    name = re.sub(r"[^A-Za-z0-9 ._@-]", "", name).strip()[:60]
    if not name or days not in (1, 7, 30, 90, 365):
        return _upd_back(err="give the token a name and a lifetime")
    token = updates.create_token(name, days, user["username"])
    ctx = await asyncio.to_thread(_updates_ctx, new_token=token, new_token_name=name)
    return render(request, "admin_updates.html", user=user, msg="", err="", **ctx)   # shown ONCE, never in a URL


@app.post("/admin/updates/tokens/{token_id}/revoke")
async def updates_token_revoke(token_id: int, user=Depends(auth.admin_user)):
    db.revoke_deploy_token(token_id)
    db.log_alert("[update]", "settings", "", None, f"{user['username']} revoked deploy token #{token_id}", "-", True)
    return _upd_back(msg="Token revoked")


def _update_caller(request: Request) -> str:
    """A deploy token (Authorization: Bearer zmd_...) or a signed-in admin."""
    tok = updates.check_token(request.headers.get("authorization"))
    if tok:
        return f"token-{tok['name']}"
    u = auth.optional_user(request)
    if u and u["role"] == "admin":
        return u["username"]
    raise HTTPException(401, "a deploy token (Authorization: Bearer zmd_...) or an admin session is required")


@app.get("/api/update/status")
async def api_update_status(request: Request):
    _update_caller(request)
    st = await asyncio.to_thread(updates.staged)            # untars + verifies up to 64 MB
    return {"installed": updates.current_version(), "status": updates.status(), "key_id": updates.key_id(),
            "staged": {k: st.get(k) for k in ("version", "relation", "error")} if st else None}


@app.get("/api/update/available")
async def api_update_available(request: Request):
    _update_caller(request)
    try:
        return {"installed": updates.current_version(), "releases": await asyncio.to_thread(updates.releases)}
    except updates.UpdateError as e:
        raise HTTPException(502, str(e))


@app.post("/api/update/apply")
async def api_update_apply(request: Request):
    """{"version": "1.4.1"} - fetch that published, signed release and install it. Newer
    versions only: a reinstall or downgrade needs an admin in the portal."""
    who = _update_caller(request)
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, 'send JSON: {"version": "x.y.z"}')     # a text/plain form can't pose as one
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, 'send JSON: {"version": "x.y.z"}')
    version = str((body or {}).get("version") or "")
    try:
        info = await asyncio.to_thread(updates.fetch, version)
        if info["relation"] != "newer":
            updates.discard_staged()
            raise HTTPException(409, f"{version} is not newer than the installed {info['installed']}")
        await asyncio.to_thread(updates.start, who, False)
    except (updates.UpdateError, tlsmgr.TlsError) as e:
        raise HTTPException(400, str(e))
    return JSONResponse({"started": True, "from": info["installed"], "to": version,
                         "follow": "/api/update/status"}, status_code=202)


# ── global alert-code ignores: admins only ──────────────────────────────────
CODE_RE = re.compile(r"^[A-Z]{2,6}[0-9]{3,5}$")


@app.post("/admin/code-ignores")
async def add_code_ignore(user=Depends(auth.admin_user), code: str = Form(...), days: int = Form(0),
                          note: str = Form("")):
    code = code.strip().upper()
    if not CODE_RE.match(code):
        return _back(err="That isn't a Zerto alert code (e.g. VPG0035)", anchor="code-ignores")
    if days not in IGNORE_SPANS:
        return _back(err="That ignore period isn't valid", anchor="code-ignores")
    if len(note.strip()) < 5:
        return _back(err="Say why (5+ characters) - everyone sees it next to every VPG it hides", anchor="code-ignores")
    from datetime import datetime, timedelta, timezone
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds") if days else None
    db.save_code_ignore(code, note.strip()[:300], user["username"], expires)
    db.log_alert("[code ignore]", "ignored", "", None,
                 f"{user['username']} ignored alert code {code} on every VPG, {IGNORE_SPANS[days]}: {note.strip()[:200]}",
                 "-", True)
    n = sum(1 for v in (await asyncio.to_thread(views.merged_vpgs)).values()
            if (v.get("ignored") or {}).get("scope") == "code" and code in v["ignored"]["label"])
    return _back(f"{code} is ignored on every VPG ({IGNORE_SPANS[days]}). It covers {n} VPG(s) right now; any VPG "
                 "with another alert or a replication problem still alerts.", anchor="code-ignores")


@app.post("/admin/code-ignores/{code}/delete")
async def remove_code_ignore(code: str, user=Depends(auth.admin_user)):
    db.delete_code_ignore(code)
    db.log_alert("[code ignore]", "unignored", "", None, f"{user['username']} stopped ignoring alert code {code}", "-", True)
    return _back(f"{code} alerts normally again", anchor="code-ignores")


# ── VRA sizing standards, set per site on the VRA page ──────────────────────
async def _known_vra_sites() -> set[str]:
    return {s["site"] for s in (await asyncio.to_thread(views.vras))["sites"]}


@app.post("/admin/vras/standard")
async def save_vra_standard(user=Depends(auth.engineer_user), site: str = Form(...),
                            memory_gb: int = Form(...), cpus: int = Form(...),
                            support_ref: str = Form(""), note: str = Form(""),
                            back: str = Form("/vras")):
    if site not in await _known_vra_sites():
        return _to(back, err=f"No VRAs are reported for site {site}")
    if not (1 <= memory_gb <= views.VRA_MEM_MAX) or not (1 <= cpus <= views.VRA_CPU_MAX):
        return _to(back, err=f"Memory must be 1-{views.VRA_MEM_MAX} GB and vCPUs 1-{views.VRA_CPU_MAX}")
    db.save_vra_standard(site, memory_gb, cpus, False, note.strip()[:300], user["username"],
                         support_ref.strip()[:60])
    beyond = memory_gb > views.GUIDE_MEM or cpus > views.GUIDE_CPU
    return _to(back, msg=f"{site} VRA standard set to {memory_gb} GB / {cpus} vCPU (raise-only)"
                         + (" - beyond Zerto's 16 GB / 4 vCPU guidance, so resizes to it need the Zerto "
                            "case reference" + ("" if support_ref.strip() else ", which isn't set")
                            if beyond else ""))


@app.post("/admin/vras/standard/delete")
async def delete_vra_standard(user=Depends(auth.engineer_user), site: str = Form(...),
                              back: str = Form("/vras")):
    db.delete_vra_standard(site)
    return _to(back, msg=f"{site} has no VRA standard now")


@app.post("/admin/vras/pin")
async def pin_vra(user=Depends(auth.engineer_user), site: str = Form(...), key: str = Form(...),
                  host: str = Form(""), memory_gb: int = Form(...), cpus: int = Form(...),
                  note: str = Form(""), back: str = Form("/vras")):
    rows = (await asyncio.to_thread(views.vras_site, site))["vras"]
    if not any(r["key"] == key for r in rows):
        return _to(back, err="That VRA isn't in the current data")
    if not (1 <= memory_gb <= views.VRA_MEM_MAX) or not (1 <= cpus <= views.VRA_CPU_MAX):
        return _to(back, err=f"Memory must be 1-{views.VRA_MEM_MAX} GB and vCPUs 1-{views.VRA_CPU_MAX}")
    db.save_vra_pin(key, site, host, memory_gb, cpus, note.strip()[:300], user["username"])
    return _to(back, msg=f"{host or key} pinned at {memory_gb} GB / {cpus} vCPU")


@app.post("/admin/vras/pin/delete")
async def unpin_vra(user=Depends(auth.engineer_user), key: str = Form(...), back: str = Form("/vras")):
    db.delete_vra_pin(key)
    return _to(back, msg="Pin removed - the VRA follows its cluster or site standard again")


@app.post("/admin/vras/cluster-standard")
async def save_cluster_standard(user=Depends(auth.engineer_user), site: str = Form(...),
                                cluster: str = Form(...), memory_gb: int = Form(...), cpus: int = Form(...),
                                support_ref: str = Form(""), note: str = Form(""), back: str = Form("/vras")):
    vs = await asyncio.to_thread(views.vras_site, site)
    if not any(c["name"] == cluster for c in vs["clusters"]):
        return _to(back, err=f"No cluster {cluster} at {site}")
    if not (1 <= memory_gb <= views.VRA_MEM_MAX) or not (1 <= cpus <= views.VRA_CPU_MAX):
        return _to(back, err=f"Memory must be 1-{views.VRA_MEM_MAX} GB and vCPUs 1-{views.VRA_CPU_MAX}")
    db.save_vra_cluster_standard(site, cluster, memory_gb, cpus, False, note.strip()[:300],
                                 user["username"], support_ref.strip()[:60])
    return _to(back, msg=f"{cluster} overrides the site standard: {memory_gb} GB / {cpus} vCPU (raise-only)")


@app.post("/admin/vras/cluster-standard/delete")
async def delete_cluster_standard(user=Depends(auth.engineer_user), site: str = Form(...),
                                  cluster: str = Form(...), back: str = Form("/vras")):
    db.delete_vra_cluster_standard(site, cluster)
    return _to(back, msg=f"{cluster} follows the site standard again")


# ── VRA resize: a planned outage, previewed by engineers, started by an admin ─
@app.get("/vras/{site}/resize", response_class=HTMLResponse)
async def resize_preview(request: Request, site: str, key: str = "", lower: str = "",
                         user=Depends(auth.engineer_user), msg: str = "", err: str = ""):
    pl = await asyncio.to_thread(vrapush.plan, site, key, lower == "1")
    return render(request, "vra_resize.html", pl=pl, site=site, user=user, msg=msg, err=err,
                  halted=vrapush.halted())


@app.post("/admin/vras/resize")
async def resize_start(request: Request, user=Depends(auth.admin_user)):
    form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
    site, key, lower = form.get("site", ""), form.get("key", ""), form.get("lower") == "1"
    back = f"/vras/{quote(site)}/resize?key={quote(key)}" + ("&lower=1" if lower else "")
    try:
        pid = await asyncio.to_thread(vrapush.start, site, key, lower, user, form)
    except vrapush.PushError as e:
        return _to(back, err=f"Not started: {e}")
    return _to(f"/vras/{quote(site)}#resizes",
               msg=f"Resize #{pid} started - every check runs again on a fresh poll, then it is sent once. "
                   "Progress shows below.")


@app.post("/admin/vras/resize/acknowledge")
async def resize_acknowledge(user=Depends(auth.admin_user), note: str = Form(""), back: str = Form("/vras")):
    if len(note.strip()) < 10:
        return _to(back, err="Say what was checked and what was found (10+ characters) before clearing the halt")
    await asyncio.to_thread(vrapush.acknowledge_halt, user["username"], note.strip())
    return _to(back, msg="Halt cleared - resizes may be started again")


@app.post("/admin/vras/resize/{push_id}/release-holds")
async def resize_release_holds(push_id: int, user=Depends(auth.admin_user), back: str = Form("/vras")):
    db.release_holds(push_id, f"released by {user['username']}")
    return _to(back, msg=f"Alert holds for resize #{push_id} released - its VPGs alert normally again")


@app.post("/admin/vra-push")
async def vra_push_switch(user=Depends(auth.admin_user), enabled: str = Form(""), notify_info: str = Form("")):
    db.set_setting("vra_push_enabled", "true" if enabled else "false")
    db.set_setting("vra_push_notify_info", "true" if notify_info else "false")
    db.log_alert("[vra-push]", "settings", "", None,
                 f"{user['username']} switched VRA resizing {'ON' if enabled else 'off'}", "-", True)
    return _back(f"VRA resizing switched {'on' if enabled else 'off'}", anchor="vra-push")


@app.post("/admin/changes")
async def changes_switches(user=Depends(auth.admin_user), restores: str = Form(""), plans_on: str = Form(""),
                           backup_days: int = Form(7)):
    days = max(1, min(backup_days, 90))
    db.set_setting("vpg_restore_enabled", "true" if restores else "false")
    db.set_setting("plans_enabled", "true" if plans_on else "false")
    db.set_setting("backup_days", str(days))
    db.log_alert("[changes]", "settings", "", None,
                 f"{user['username']}: VPG restores {'ON' if restores else 'off'}, recovery-plan changes "
                 f"{'ON' if plans_on else 'off'}, backups kept {days} days", "-", True)
    return _back(f"Saved: restores {'on' if restores else 'off'}, plan changes {'on' if plans_on else 'off'}, "
                 f"backups kept {days} days", anchor="vra-push")


@app.post("/admin/sources/{sid}/push")
async def source_push_settings(sid: int, user=Depends(auth.admin_user), allow: str = Form(""),
                               host_auth: str = Form("unknown"), pin: str = Form("")):
    src = db.get_source(sid)
    if not src or src["kind"] != "zvm":
        return _back(err="unknown ZVM source", anchor="vra-push")
    if host_auth not in ("vib", "password", "unknown"):
        return _back(err="bad connection method", anchor="vra-push")
    notes = []
    if host_auth != (src.get("push_host_auth") or "unknown"):
        db.set_source_push(sid, push_host_auth=host_auth, push_host_auth_by=user["username"],
                           push_host_auth_at=db.now_iso())
        notes.append(f"host connection method recorded as {host_auth}")
    if pin:
        try:
            fp = await asyncio.to_thread(zerto.cert_fingerprint, src["host"])
        except OSError as e:
            return _back(err=f"Couldn't read {src['host']}'s certificate: {e}", anchor="vra-push")
        # a capture at click time proves nothing on its own: it must be the certificate
        # polling has trusted since the source was added
        known = db.source_pins(src).get(443)
        if known and fp != known:
            return _back(err=f"{src['host']} now presents a different certificate (SHA-256 {fp[:23]}…) from the "
                             f"one polling has trusted since the source was added ({known[:23]}…). Nothing was "
                             "pinned. If the change is expected, re-pin the source under Sources first.",
                         anchor="vra-push")
        db.set_source_push(sid, push_cert_fp=fp)
        notes.append(f"certificate pinned (SHA-256 {fp[:23]}…)")
    if bool(allow) != bool(src.get("allow_changes")):
        db.set_source_allow_changes(sid, bool(allow))
        notes.append("armed for changes" if allow else "disarmed - read-only again")
    db.log_alert("[source] " + src["name"], "settings", "", None,
                 f"{user['username']} changed change settings on {src['name']}: {'; '.join(notes) or 'no change'}",
                 "-", True)
    return _back(f"{src['name']}: " + ("; ".join(notes) or "nothing changed"), anchor="vra-push")


# ── playbook: researched entries + engineers' own team fixes ────────────────
@app.get("/playbook", response_class=HTMLResponse)
async def playbook_page(request: Request, msg: str = "", err: str = "", key: str = ""):
    return render(request, "playbook.html", msg=msg, err=err, entries=await asyncio.to_thread(playbook.catalogue),
                  prefill=key, placeholders=sorted(playbook.DEFAULTS), conditions=playbook.CONDITIONS,
                  limits=playbook.LIMITS)


@app.post("/admin/playbook")
async def playbook_add(user=Depends(auth.engineer_user), key: str = Form(...), title: str = Form(""),
                       fix: str = Form(...), caution: str = Form(""), back: str = Form("/playbook")):
    key, problem = playbook.validate(key, title, fix, caution)
    if problem:
        return _to(back, err=f"Team fix not saved: {problem}")
    db.save_team_fix(None, key, title.strip(), fix.strip(), caution.strip(), user["username"])
    playbook.invalidate()
    return _to(back, msg=f"Team fix saved for {key} - it shows first wherever {key} appears")


@app.post("/admin/playbook/{fix_id}")
async def playbook_edit(fix_id: int, user=Depends(auth.engineer_user), key: str = Form(...),
                        title: str = Form(""), fix: str = Form(...), caution: str = Form(""),
                        back: str = Form("/playbook")):
    if not db.get_team_fix(fix_id):
        return _to(back, err="That team fix no longer exists")
    key, problem = playbook.validate(key, title, fix, caution)
    if problem:
        return _to(back, err=f"Not saved: {problem}")
    db.save_team_fix(fix_id, key, title.strip(), fix.strip(), caution.strip(), user["username"])
    playbook.invalidate()
    return _to(back, msg=f"Team fix for {key} updated")


@app.post("/admin/playbook/{fix_id}/delete")
async def playbook_delete(fix_id: int, user=Depends(auth.engineer_user), back: str = Form("/playbook")):
    f = db.get_team_fix(fix_id)
    if f:
        db.delete_team_fix(fix_id)
        playbook.invalidate()
    return _to(back, msg=f"Team fix for {f['key']} deleted" if f else "Already gone")


# ── admin ───────────────────────────────────────────────────────────────────
def _posture(acfg: dict, ovf: dict) -> list[dict]:
    """The Security card: what is protected, and - plainly - what isn't yet.
    state: ok | warn | bad."""
    plain = db.unencrypted_count()
    rows = [
        {"area": "Stored credentials", "state": "bad" if plain else "ok",
         "what": (f"{plain} stored credential value(s) are NOT encrypted - restart the service to "
                  "re-encrypt them, then Scrub the DB. " if plain else "Counted just now: none unencrypted. ")
                 + "ZVM/ZCM usernames, passwords and client secrets, Keycloak registration tokens and "
                   "URIs, resize credentials, the SMTP username and password, SNMP communities and the "
                   f"Entra client secret are Fernet-encrypted (AES-128 + HMAC-SHA256). Key: "
                   f"{crypto.key_source()}, root-owned 0600."},
        {"area": "Web passwords", "state": "ok",
         "what": "bcrypt hashes. Entra ID users have no local password."},
    ]
    sk = auth.session_key_source()
    rows.append({"area": "Session signing key", "state": "ok" if sk.startswith("systemd") else "warn",
                 "what": f"{sk}" + ("" if sk.startswith("systemd") else
                                    " - in the app's data directory; the next upgrade moves it to "
                                    "/etc/zerto-monitor/session.key")})
    rows.append({"area": "Browser ↔ appliance", "state": "ok",
                 "what": "HTTPS only (TLS 1.2/1.3); port 80 only redirects; session cookie is "
                         "Secure + HttpOnly + SameSite."})
    srcs = [s for s in db.list_sources() if s.get("enabled")]
    unpinned = [s["name"] for s in srcs if not s.get("verify_tls") and not db.source_pins(s)]
    pinned = [s["name"] for s in srcs if not s.get("verify_tls") and db.source_pins(s)]
    rows.append({"area": "Appliance ↔ ZVM/ZCM", "state": "warn" if unpinned else "ok",
                 "what": "HTTPS, redirects refused on every call that carries a credential. "
                         + (f"Pinned certificate (trust on first use): {', '.join(pinned)}. " if pinned else "")
                         + (f"Not yet pinned - pinned on the next successful connection: {', '.join(unpinned)}."
                            if unpinned else "Every source is CA-verified or pinned.")})
    if not acfg["smtp_host"]:
        rows.append({"area": "Email", "state": "ok", "what": "not configured"})
    elif acfg["smtp_security"] == "none":
        rows.append({"area": "Email", "state": "warn",
                     "what": "no TLS to the relay: alert emails cross the network unencrypted "
                             "(no password is ever sent this way)"})
    else:
        rows.append({"area": "Email", "state": "ok" if acfg["smtp_verify"] else "warn",
                     "what": f"{acfg['smtp_security'].upper()}"
                             + ("" if acfg["smtp_verify"] else ", certificate checking off")})
    snmp_on = [n for n, on in (("traps", acfg["snmp_trap_enabled"]),
                               ("polling agent", acfg["snmp_agent_enabled"])) if on]
    rows.append({"area": "SNMP", "state": "warn" if snmp_on else "ok",
                 "what": (f"{' and '.join(snmp_on)} on: SNMP v2c sends its community string "
                          "unencrypted - keep it on the management network")
                 if snmp_on else "off"})
    armed = [s["name"] for s in db.list_sources() if s.get("allow_changes")]
    kinds = [k for k, on in (("VRA resizes", vrapush.enabled()), ("VPG restores", backups.enabled_restore()),
                             ("recovery-plan changes", plans.enabled())) if on]
    rows.append({"area": "Changes to Zerto", "state": "warn" if (kinds and armed) else "ok",
                 "what": (f"{', '.join(kinds)} allowed on {', '.join(armed)}, each through the site's own change "
                          "credential over its pinned certificate, with a client that can send only that change")
                 if (kinds and armed) else
                         "none: the monitor is read-only on every ZVM (it reads Zerto's own daily VPG-settings "
                         "exports for backups, which changes nothing)"})
    if ovf.get("held"):
        rows.append({"area": "vCenter vApp properties", "state": "bad",
                     "what": f"vCenter still holds the deploy-time {', '.join(ovf['labels'])} for this "
                             "VM. Anyone who can read its settings in vCenter can read them."
                             + (" This VM won't let the guest blank its copy, so local accounts can "
                                "read them too." if ovf.get("guest") == "unsupported" else
                                " The appliance blanks its own copy at every boot.")})
    elif ovf.get("guest") == "unknown":
        rows.append({"area": "vCenter vApp properties", "state": "warn",
                     "what": "this boot's vApp environment couldn't be read, so it can't be confirmed that "
                             "vCenter holds no deploy-time passwords - check Edit Settings > vApp Options"})
    elif ovf.get("known"):
        rows.append({"area": "vCenter vApp properties", "state": "ok",
                     "what": "no deploy-time passwords in this VM's vApp environment"})
    rows.append({"area": "Sign-in", "state": "ok" if login_required() else "warn",
                 "what": "required for every page" if login_required() else
                         "dashboards are readable without signing in (read-only)"})
    return rows


def _admin_ctx():
    snaps = db.get_snapshots()
    sources = []
    for s in db.list_sources():
        sn = snaps.get(s["id"]) or {}
        sources.append({**s, "ok": views.source_ok(sn), "error": sn.get("error"),
                        "taken_at": sn.get("taken_at"), "duration_ms": sn.get("duration_ms"),
                        "site": ((sn.get("payload") or {}).get("site")),
                        "roles": (sn.get("payload") or {}).get("token_roles"),
                        "has_secret": bool(s.get("secret_enc"))})
    sso = {k: (db.get_setting(k) or "") for k in auth.ENTRA_KEYS}
    sso["has_secret"] = bool(sso.pop("entra_client_secret"))
    zorg_names = sorted({o["name"] for o in views.zorg_list()}, key=str.lower)
    acfg, ovf = alerts.config(), tlsmgr.ovfenv_state()
    return {"sources": sources, "users": db.list_users(),
            "require_login": login_required(), "ovfenv": ovf, "posture": _posture(acfg, ovf),
            "vra_push": {"enabled": vrapush.enabled(), "halted": vrapush.halted(),
                         "notify_info": db.get_setting("vra_push_notify_info") == "true"},
            "changes": {"restores": backups.enabled_restore(), "plans": plans.enabled(),
                        "backup_days": backups.retention_days(), "backups": db.backup_summary()[:9],
                        "recent": db.changes(limit=15)},
            "session_hours": auth.EXPIRE_HOURS,
            "poll_interval": db.get_setting("poll_interval", "120"),
            "history_days": db.get_setting("history_days", "30"),
            "key_source": crypto.key_source(), "sso": sso,
            "tls": tlsmgr.state(), "host": tlsmgr.hostname(),
            "helper": tlsmgr.helper_available(),
            "acfg": acfg, "rules": db.alert_rules(),
            "alert_states": alerts.state_rows()[:40], "alert_log": db.recent_alerts(30),
            "would_fire": alerts.preview(), "zorg_names": zorg_names,
            "viewer_role": zerto.VIEWER_ROLE, "snmp_oids": alerts.snmp_oids(),
            "default_trap_oid": alerts.DEFAULT_TRAP_OID,
            "ignores": db.list_ignores(active_only=False), "now_iso": db.now_iso(),
            "code_ignores": _code_ignore_ctx()}


def _code_ignore_ctx() -> dict:
    """Global code ignores with how many VPGs each hides now, and the codes on unhealthy VPGs
    right now (to pick from), with counts."""
    merged = views.merged_vpgs()
    rows = db.list_code_ignores(active_only=False)
    covered: dict[str, int] = {}
    seen: dict[str, int] = {}
    for v in merged.values():
        if v["health"] == "healthy":
            continue
        for c in views.live_codes(v):
            seen[c] = seen.get(c, 0) + 1
        ig = v.get("ignored") or {}
        if ig.get("scope") == "code":
            for c in ig["label"].split(", "):
                covered[c] = covered.get(c, 0) + 1
    now = db.now_iso()
    for r in rows:
        r["covers"] = covered.get(r["code"], 0)
        r["expired"] = bool(r.get("expires_at") and r["expires_at"] <= now)
    return {"rows": rows, "seen": sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))}


# ── admin: hostname + TLS ───────────────────────────────────────────────────
@app.post("/admin/hostname")
async def admin_hostname(user=Depends(auth.admin_user), hostname: str = Form(...),
                         regen: str = Form("")):
    try:
        h = await asyncio.to_thread(tlsmgr.set_hostname, hostname)
        note = f"Hostname is now {h['short']}"
        if regen:
            fqdn = h["fqdn"] if "." in h["fqdn"] else h["short"]
            await asyncio.to_thread(tlsmgr.self_signed, fqdn)
            note += f"; new self-signed certificate issued for {fqdn}"
        return _back(note, anchor="tls")
    except tlsmgr.TlsError as e:
        return _back(err=f"Hostname: {e}", anchor="tls")


@app.post("/admin/tls/selfsigned")
async def admin_tls_selfsigned(user=Depends(auth.admin_user), fqdn: str = Form(...),
                               days: int = Form(3650)):
    try:
        st = await asyncio.to_thread(tlsmgr.self_signed, fqdn, days)
        return _back(f"Self-signed certificate installed for {fqdn} "
                     f"(valid to {st['not_after']}; names: {', '.join(st['sans'])})", anchor="tls")
    except tlsmgr.TlsError as e:
        return _back(err=f"Certificate: {e}", anchor="tls")


async def _read_upload(f: UploadFile | None, limit: int = 65536) -> bytes:
    if f is None or not f.filename:
        return b""
    data = await f.read(limit + 1)
    if len(data) > limit:
        raise tlsmgr.TlsError(f"{f.filename} is larger than {limit // 1024} KB")
    return data


@app.post("/admin/tls/upload")
async def admin_tls_upload(user=Depends(auth.admin_user),
                           cert: UploadFile | None = File(None), key: UploadFile | None = File(None),
                           chain: UploadFile | None = File(None), pfx: UploadFile | None = File(None),
                           pfx_password: str = Form("")):
    try:
        pfx_bytes = await _read_upload(pfx)
        if pfx_bytes:
            st = await asyncio.to_thread(tlsmgr.install_pfx, pfx_bytes, pfx_password)
        else:
            c, k, ch = await _read_upload(cert), await _read_upload(key), await _read_upload(chain)
            if not c or not k:
                raise tlsmgr.TlsError("choose a certificate and its private key, or a .pfx")
            full = c.rstrip() + b"\n" + (ch.strip() + b"\n" if ch.strip() else b"")
            st = await asyncio.to_thread(tlsmgr.install, full, k)
        return _back(f"Certificate installed: {st['subject']} (valid to {st['not_after']})", anchor="tls")
    except tlsmgr.TlsError as e:
        return _back(err=f"Certificate: {e}", anchor="tls")


# ── admin: alerting + SNMP ──────────────────────────────────────────────────
@app.post("/admin/alerts/settings")
async def admin_alert_settings(user=Depends(auth.admin_user), enabled: str = Form(""),
                               repeat_hours: int = Form(24), notify_clear: str = Form(""),
                               recipients: str = Form(""), public_url: str = Form("")):
    db.set_setting("alerts_enabled", "true" if enabled else "false")
    db.set_setting("alert_repeat_hours", str(max(0, min(repeat_hours, 720))))
    db.set_setting("alert_notify_clear", "true" if notify_clear else "false")
    db.set_setting("alert_default_recipients", recipients.strip())
    db.set_setting("public_url", public_url.strip().rstrip("/"))
    return _back("Alert settings saved", anchor="alerts")


@app.post("/admin/alerts/smtp")
async def admin_alert_smtp(user=Depends(auth.admin_user), host: str = Form(""),
                           port: int = Form(587), security: str = Form("starttls"),
                           username: str = Form(""), password: str = Form(""),
                           sender: str = Form(""), verify: str = Form(""),
                           clear_password: str = Form("")):
    if security not in ("starttls", "ssl", "none"):
        return _back(err="bad SMTP security mode", anchor="alerts")
    if security == "none" and username.strip():
        return _back(err="SMTP: a username/password is only sent over STARTTLS or SSL - "
                         "'none' is for an unauthenticated internal relay", anchor="alerts")
    # a stored password is never carried to a different server: re-enter it there
    old, note = alerts.config(), ""
    moved = (host.strip(), str(port), security, bool(verify)) != \
        (old["smtp_host"], str(old["smtp_port"]), old["smtp_security"], bool(old["smtp_verify"]))
    if moved and old["smtp_has_password"] and not password and not clear_password:
        clear_password, note = "1", " - the stored password was cleared because the server changed; enter it again"
    db.set_setting("smtp_host", host.strip())
    db.set_setting("smtp_port", str(port))
    db.set_setting("smtp_security", security)
    db.set_setting("smtp_user", crypto.encrypt(username.strip()) if username.strip() else "")
    db.set_setting("smtp_from", sender.strip())
    db.set_setting("smtp_verify", "true" if verify else "false")
    if clear_password:
        db.set_setting("smtp_password", "")
    elif password:
        db.set_setting("smtp_password", crypto.encrypt(password))
    return _back("SMTP settings saved" + note, anchor="alerts")


@app.post("/admin/alerts/snmp-trap")
async def admin_snmp_trap(user=Depends(auth.admin_user), enabled: str = Form(""),
                          targets: str = Form(""), community: str = Form(""),
                          oid: str = Form("")):
    oid = oid.strip().strip(".") or alerts.DEFAULT_TRAP_OID
    if not all(p.isdigit() for p in oid.split(".")):
        return _back(err="trap OID must be numeric, e.g. 1.3.6.1.4.1.8072.9999.9999.7", anchor="alerts")
    if community and not alerts.COMMUNITY_RE.match(community):
        return _back(err="trap community: letters, digits, _ . - only (up to 64)", anchor="alerts")
    note = ""
    if targets.strip() != (db.get_setting("snmp_trap_targets") or "").strip() and not community \
            and db.get_setting("snmp_trap_community"):
        # never send the stored community to receivers it wasn't entered for
        db.set_setting("snmp_trap_community", "")
        note = " - the stored community was cleared because the receivers changed; enter it again"
    db.set_setting("snmp_trap_enabled", "true" if enabled else "false")
    db.set_setting("snmp_trap_targets", targets.strip())
    db.set_setting("snmp_trap_oid", oid)
    if community:
        db.set_setting("snmp_trap_community", crypto.encrypt(community))
    return _back("SNMP trap settings saved" + note, anchor="alerts")


@app.post("/admin/alerts/snmp-agent")
async def admin_snmp_agent(user=Depends(auth.admin_user), enabled: str = Form(""),
                           community: str = Form(""), source: str = Form("")):
    source = (source or "").strip()
    if enabled and (not source or source == "default"):
        return _back(err="SNMP agent: give the network allowed to poll it, e.g. 192.0.2.0/24 - never 'default', "
                         "which would answer anyone who knows the community", anchor="alerts")
    if community and not (alerts.COMMUNITY_RE.match(community) and 6 <= len(community) <= 64):
        # checked BEFORE saving: a rejected value must not replace the working one
        return _back(err="SNMP agent: community must be 6-64 letters, digits, _ . - only", anchor="alerts")
    try:
        if enabled:
            if community:
                db.set_setting("snmp_agent_community", crypto.encrypt(community))
            comm = crypto.decrypt(db.get_setting("snmp_agent_community") or "")
            if not comm:
                raise tlsmgr.TlsError("set a community string first")
            out = await asyncio.to_thread(tlsmgr.helper, "snmp-agent-on", comm, source)
        else:
            out = await asyncio.to_thread(tlsmgr.helper, "snmp-agent-off")
        db.set_setting("snmp_agent_enabled", "true" if enabled else "false")
        db.set_setting("snmp_agent_source", source)
        return _back(f"SNMP agent: {out.splitlines()[-1] if out else 'done'}", anchor="alerts")
    except tlsmgr.TlsError as e:
        return _back(err=f"SNMP agent: {e}", anchor="alerts")


@app.post("/admin/alerts/rules")
async def admin_alert_rule(user=Depends(auth.admin_user), zorg: str = Form(...),
                           error_minutes: int = Form(15), warning_minutes: int = Form(60),
                           recipients: str = Form(""), email: str = Form(""),
                           snmp: str = Form(""), enabled: str = Form("")):
    zorg = zorg.strip()
    if not zorg:
        return _back(err="choose a zORG (or * for all)", anchor="alerts")
    db.save_alert_rule(zorg, max(1, min(error_minutes, 10080)), max(1, min(warning_minutes, 10080)),
                       recipients.strip(), bool(email), bool(snmp), bool(enabled))
    return _back(f"Alert rule saved for {zorg}", anchor="alerts")


@app.post("/admin/alerts/rules/{rule_id}/delete")
async def admin_alert_rule_delete(rule_id: int, user=Depends(auth.admin_user)):
    db.delete_alert_rule(rule_id)
    return _back("Alert rule removed", anchor="alerts")


@app.post("/admin/alerts/test-email")
async def admin_test_email(user=Depends(auth.admin_user), to: str = Form("")):
    try:
        sent = await asyncio.to_thread(alerts.test_email, to)
        return _back(f"Test email sent to {sent}", anchor="alerts")
    except Exception as e:  # noqa: BLE001 - surface SMTP errors verbatim
        return _back(err=f"Test email failed: {type(e).__name__}: {e}", anchor="alerts")


@app.post("/admin/alerts/test-trap")
async def admin_test_trap(user=Depends(auth.admin_user)):
    try:
        sent = await asyncio.to_thread(alerts.test_trap)
        return _back(f"Test trap sent to {sent}", anchor="alerts")
    except Exception as e:  # noqa: BLE001
        return _back(err=f"Test trap failed: {e}", anchor="alerts")


@app.post("/admin/sso")
async def save_sso(user=Depends(auth.admin_user), entra_enabled: str = Form(""),
                   entra_tenant_id: str = Form(""), entra_client_id: str = Form(""),
                   entra_client_secret: str = Form(""), entra_redirect_uri: str = Form(""),
                   entra_admin_group: str = Form(""), entra_engineer_group: str = Form(""),
                   entra_button_label: str = Form("")):
    db.set_setting("entra_enabled", "true" if entra_enabled else "false")
    db.set_setting("entra_tenant_id", entra_tenant_id.strip())
    db.set_setting("entra_client_id", entra_client_id.strip())
    db.set_setting("entra_redirect_uri", entra_redirect_uri.strip())
    db.set_setting("entra_admin_group", entra_admin_group.strip())
    db.set_setting("entra_engineer_group", entra_engineer_group.strip())
    db.set_setting("entra_button_label", " ".join(entra_button_label.split())[:80])
    if entra_client_secret.strip():
        db.set_setting("entra_client_secret", crypto.encrypt(entra_client_secret.strip()))
    return RedirectResponse("/admin?msg=SSO+settings+saved", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user=Depends(auth.admin_user), msg: str = "", err: str = ""):
    return render(request, "admin.html", user=user, msg=msg, err=err,
                  **(await asyncio.to_thread(_admin_ctx)))


@app.post("/admin/sources")
async def add_source(user=Depends(auth.admin_user), name: str = Form(...), kind: str = Form(...),
                     host: str = Form(...), auth_type: str = Form(...), identity: str = Form(""),
                     secret: str = Form(""), verify_tls: str = Form("")):
    if kind not in ("zvm", "zcm") or auth_type not in ("password", "client_credentials", "basic",
                                                       "initial_access_token"):
        return _back(err="bad values")
    host = host.strip()
    if auth_type == "initial_access_token":
        # Spend the token on a confidential client of our own, then store that
        # client's id + secret like any other API client. The token itself is never kept.
        if kind != "zvm":
            return _back(err="Initial access tokens apply to Zerto 10 ZVM appliances only")
        if not secret.strip():
            return _back(err="Paste the Keycloak initial access token into the Secret field")
        label = f"zerto-monitor@{tlsmgr.hostname()['short'] or 'appliance'}"
        try:
            reg_host = zerto.inspect_iat(host, secret.strip())
            session = None
            if not verify_tls:              # the client secret comes back over this connection: pin it
                fp = await asyncio.to_thread(zerto.cert_fingerprint, reg_host)
                session = zerto.pinned_session(reg_host, {443: fp})
            reg = await asyncio.to_thread(zerto.register_client, host, secret,
                                          bool(verify_tls), label, session)
        except zerto.ZvmError as e:
            return _back(err=f"Registration on {host} failed: {e}")
        except OSError as e:
            return _back(err=f"Couldn't read {host}'s certificate to pin it: {e}")
        sid = db.add_source(name.strip(), kind, host, "client_credentials", reg["client_id"],
                            crypto.encrypt(reg["client_secret"]), bool(verify_tls))
        db.set_registration(sid, reg["registration_client_uri"], reg["registration_access_token"])
        pin_note = await _pin_new_source(sid, host, kind, bool(verify_tls))
        asyncio.create_task(collector.poll_once(sid))
        via = (f" (the token came from the console at {reg['registered_via']}, the same server, "
               f"so it was registered there)") if reg["registered_via"] != host else ""
        return _back(f"Registered an API client on {host}{via} - no password is stored{pin_note}. "
                     f"Polling now; if it reports 'refused', the card shows the one role to grant.")
    sid = db.add_source(name.strip(), kind, host, auth_type, identity.strip(),
                        crypto.encrypt(secret) if secret else "", bool(verify_tls))
    pin_note = await _pin_new_source(sid, host, kind, bool(verify_tls))
    asyncio.create_task(collector.poll_once(sid))
    return _back(f"source added{pin_note} - polling")


async def _pin_new_source(sid: int, host: str, kind: str, verified: bool) -> str:
    """Trust on first use: record the certificate(s) the source presents now, so no
    credential is ever sent to a server that later presents a different one."""
    if verified:
        return ""
    pins = await asyncio.to_thread(collector.capture_pins, host, kind)
    db.set_source_pins(sid, pins)
    return (f"; certificate pinned (SHA-256 {next(iter(pins.values()))[:23]}…)" if pins else
            "; its certificate couldn't be read yet - it will be pinned on the first successful connection")


@app.post("/admin/sources/{sid}")
async def edit_source(sid: int, user=Depends(auth.admin_user), name: str = Form(...),
                      host: str = Form(...), auth_type: str = Form(...), identity: str = Form(""),
                      secret: str = Form(""), verify_tls: str = Form(""), enabled: str = Form("")):
    cur = db.get_source(sid)
    if not cur:
        raise HTTPException(404)
    moved = host.strip().lower() != cur["host"].lower() or auth_type != cur["auth_type"]
    if moved and cur.get("reg_uri"):
        return _back(err="This source uses a registered API client: remove it and add it again to "
                         "move it", anchor="sources")
    if moved and not secret:
        # a stored secret is never carried to a different server
        return _back(err="Re-enter the secret when you change the host or the auth type", anchor="sources")
    db.update_source(sid, name.strip(), host.strip(), auth_type, identity.strip(),
                     crypto.encrypt(secret) if secret else None, bool(verify_tls), bool(enabled))
    note = ""
    if moved:
        db.set_source_push(sid, push_identity=None, push_secret_enc=None, push_cert_fp=None)
        db.set_source_allow_changes(sid, False)
        db.set_source_pins(sid, None)
        note = await _pin_new_source(sid, host.strip(), cur["kind"], bool(verify_tls))
    asyncio.create_task(collector.poll_once(sid))
    return _back("source updated" + note, anchor="sources")


@app.post("/admin/sources/{sid}/repin")
async def repin_source(sid: int, user=Depends(auth.admin_user)):
    """After an expected certificate change on the ZVM/ZCM (renewal), trust the new one."""
    src = db.get_source(sid)
    if not src:
        raise HTTPException(404)
    pins = await asyncio.to_thread(collector.capture_pins, src["host"], src["kind"])
    if not pins:
        return _back(err=f"Couldn't read {src['host']}'s certificate", anchor="sources")
    db.set_source_pins(sid, pins)
    db.log_alert("[source] " + src["name"], "settings", "", None,
                 f"{user['username']} re-pinned {src['host']}'s certificate: "
                 + ", ".join(f"{p}={fp[:23]}…" for p, fp in pins.items()), "-", True)
    asyncio.create_task(collector.poll_once(sid))
    return _back(f"{src['name']}: certificate re-pinned (SHA-256 {next(iter(pins.values()))[:23]}…)", anchor="sources")


@app.post("/admin/sources/{sid}/delete")
async def delete_source(sid: int, user=Depends(auth.admin_user), force: str = Form("")):
    from urllib.parse import urlparse
    src = db.get_source(sid)
    note = ""
    if src and src.get("reg_uri") and not force:
        # we created this client in the ZVM's Keycloak; don't leave it behind. Same machine,
        # same certificate - even when it was registered via another name (inspect_iat) -
        # and never unpinned: with no pin the session refuses to send at all
        reg_uri = crypto.decrypt(src["reg_uri"])
        session = None if src.get("verify_tls") else \
            zerto.pinned_session(urlparse(reg_uri).hostname or src["host"], db.source_pins(src))
        note = await asyncio.to_thread(
            zerto.deregister_client, src["host"], reg_uri,
            crypto.decrypt(src.get("reg_token_enc") or ""), bool(src.get("verify_tls")), session)
        if note not in ("client removed from Keycloak", "client was already gone", "nothing to remove"):
            return _back(err=f"{src['name']} was NOT removed: its Keycloak client couldn't be deleted ({note}). "
                             "Delete the client in the ZVM's Keycloak by hand, then use 'remove anyway'.",
                         anchor="sources")
        note = f" ({note})"
    db.delete_source(sid)
    return _back(f"source removed{note}")


@app.post("/admin/sources/{sid}/poll")
async def poll_source(sid: int, user=Depends(auth.admin_user)):
    await collector.poll_once(sid)
    sn = db.get_snapshots().get(sid) or {}
    if sn.get("ok"):
        return RedirectResponse(f"/admin?msg=polled+ok+in+{sn.get('duration_ms')}ms", status_code=303)
    return _back(err=(sn.get("error") or "failed")[:200], anchor="sources")


@app.post("/admin/poll-all")
async def poll_all(user=Depends(auth.admin_user)):
    asyncio.create_task(collector.cycle())
    return RedirectResponse("/admin?msg=poll+started", status_code=303)


@app.post("/admin/scrub")
async def scrub_db(user=Depends(auth.admin_user)):
    r = await asyncio.to_thread(db.scrub)
    return RedirectResponse(
        f"/admin?msg=DB+scrubbed:+{r['bytes_before']:,}+->+{r['bytes_after']:,}+bytes", status_code=303)


@app.post("/admin/settings")
async def save_settings(user=Depends(auth.admin_user), poll_interval: int = Form(120),
                        history_days: int = Form(30)):
    db.set_setting("poll_interval", str(max(30, poll_interval)))
    db.set_setting("history_days", str(max(1, min(history_days, 365))))
    return RedirectResponse("/admin?msg=saved", status_code=303)


@app.post("/admin/users")
async def add_user(user=Depends(auth.admin_user), username: str = Form(...),
                   password: str = Form(...), role: str = Form("viewer")):
    if role not in auth.ROLES:
        return _back(err="unknown role", anchor="users")
    if db.get_user(username.strip()):
        return _back(err="user exists", anchor="users")
    problem = auth.username_problem(username.strip()) or auth.password_problem(password)
    if problem:
        return _back(err=problem, anchor="users")
    db.create_user(username.strip(), auth.hash_password(password), role)
    return _back(f"{username.strip()} added as {role}", anchor="users")


@app.post("/admin/users/{username}/role")
async def change_role(username: str, user=Depends(auth.admin_user), role: str = Form(...)):
    u = db.get_user(username)
    if not u or role not in auth.ROLES:
        return _back(err="unknown user or role", anchor="users")
    if u.get("auth_source") == "entra":
        return _back(err=f"{username} signs in with Entra ID: their role follows the "
                         "admin/engineer groups at every sign-in", anchor="users")
    if auth.role_of(u) == "admin" and role != "admin" and db.admin_count() <= 1:
        return _back(err="that would leave no admin", anchor="users")
    db.set_role(username, role)
    return _back(f"{username} is now {role} (effective immediately)", anchor="users")


@app.post("/admin/access")
async def admin_access(user=Depends(auth.admin_user), require_login: str = Form("")):
    db.set_setting("require_login", "true" if require_login else "false")
    _login_cache["at"] = 0.0
    return _back("Sign-in is now required for every page" if require_login else
                 "Dashboards are readable without signing in again", anchor="users")


@app.post("/admin/users/{username}/password")
async def reset_password(username: str, user=Depends(auth.admin_user), password: str = Form(...)):
    problem = auth.password_problem(password)
    if problem:
        return _back(err=problem, anchor="users")
    db.set_password(username, auth.hash_password(password))
    return RedirectResponse("/admin?msg=password+reset", status_code=303)


@app.post("/admin/users/{username}/delete")
async def remove_user(username: str, user=Depends(auth.admin_user)):
    if username == user["username"]:
        return _back(err="cannot delete yourself", anchor="users")
    u = db.get_user(username)
    if u and auth.role_of(u) == "admin" and db.admin_count() <= 1:
        return _back(err="that would leave no admin", anchor="users")
    db.delete_user(username)
    return _back(f"{username} removed", anchor="users")


# ── JSON API ────────────────────────────────────────────────────────────────
# ── JSON API (read-only endpoints are public, like the pages) ───────────────
@app.get("/api/overview")
async def api_overview():
    return await asyncio.to_thread(views.overview)


@app.get("/api/vras")
async def api_vras():
    return await asyncio.to_thread(views.vras)


@app.get("/api/vras/{site}")
async def api_vras_site(site: str):
    return await asyncio.to_thread(views.vras_site, site)


@app.get("/api/zorgs")
async def api_zorgs():
    return await asyncio.to_thread(views.zorg_list)


@app.get("/api/zorgs/{name}")
async def api_zorg(name: str):
    return await asyncio.to_thread(views.zorg_detail, name)


@app.get("/api/sources")
async def api_sources(user=Depends(auth.admin_user)):
    hidden = ("identity", "secret_enc", "reg_token_enc", "reg_uri", "push_identity", "push_secret_enc")
    return [{k: v for k, v in s.items() if k not in hidden} for s in db.list_sources()]


@app.get("/api/metrics")
async def api_metrics():
    """Flat integers for your RMM / network monitoring system (or SNMP). Public, like the dashboards."""
    return await asyncio.to_thread(views.metrics)


@app.get("/api/history")
async def api_history(source: int | None = None, hours: int = 24):
    """Per-poll counts from the history table (retained `history_days`, default 30)."""
    return await asyncio.to_thread(db.history, source, max(1, min(hours, 24 * 90)))


@app.get("/healthz")
async def healthz():
    # version = the code THIS process runs (read at start): the updater checks it, so a
    # still-running old process can't pass the new version's health check
    return {"ok": True, "key_source": crypto.key_source(), "version": templates.env.globals["app_version"]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), reload=False)
