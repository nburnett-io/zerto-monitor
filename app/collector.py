"""Background poller. Each enabled source is collected in a worker thread
(requests is synchronous); the latest good payload is kept per source."""
from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

import crypto
import db
from zcm import ZcmClient
from zerto import ZvmClient, pinned_session

log = logging.getLogger("collector")
_pool = ThreadPoolExecutor(max_workers=8)
# source id -> the asyncio Task currently collecting it. A second request for the
# same source while one is in flight AWAITS it rather than skipping, so "Poll now"
# right after "Save" reports the fresh result instead of the stale snapshot.
_inflight: dict[int, asyncio.Task] = {}


PIN_PORTS = {"zvm": (443, 9669), "zcm": (9989,)}       # appliance/Keycloak, legacy Windows ZVM, ZCM


def capture_pins(host: str, kind: str) -> dict:
    """The certificate each of a source's ports presents right now (trust on first use)."""
    from zerto import cert_fingerprint
    pins = {}
    for port in PIN_PORTS.get(kind, (443,)):
        try:
            pins[port] = cert_fingerprint(host, port)
        except OSError:
            continue
    return pins


def _redact(text: str, *values: str) -> str:
    """Errors are shown on pages and in alerts: never with a credential in them."""
    for v in values:
        if v and len(v) >= 4:
            text = text.replace(v, "<redacted>")
    return text


def _session(src: dict):
    """None for a CA-verified source; otherwise a session that talks only to the
    certificate pinned on first use, and refuses any port that isn't pinned rather than
    send credentials blind."""
    if src.get("verify_tls"):
        return None
    pins = db.source_pins(src)
    if not pins:
        pins = capture_pins(src["host"], src["kind"])
        if pins:
            db.set_source_pins(src["id"], pins)
            log.info("%s %s: certificate pinned on first use (%s)", src["kind"], src["name"],
                     ", ".join(f"{p}={fp[:23]}…" for p, fp in pins.items()))
    if not pins:
        raise ConnectionError(f"couldn't read {src['host']}'s certificate to pin it - nothing was sent")
    return pinned_session(src["host"], pins)


def polling_client(src: dict) -> ZvmClient:
    """A logged-in, read-only client on the source's polling credential."""
    c = ZvmClient(src["host"], src["auth_type"], src.get("identity") or "",
                  crypto.decrypt(src.get("secret_enc") or ""), bool(src.get("verify_tls")), session=_session(src))
    c.login()
    return c


def collect_source(src: dict) -> tuple[bool, str | None, dict | None, int]:
    t0 = time.time()
    secret = crypto.decrypt(src.get("secret_enc") or "")
    identity = src.get("identity") or ""
    try:
        session = _session(src)
        if src["kind"] == "zvm":
            import events
            c = ZvmClient(src["host"], src["auth_type"], identity, secret, bool(src.get("verify_tls")),
                          session=session)
            payload = c.collect(events_since=events.since(src))
        elif src["kind"] == "zcm":
            c = ZcmClient(src["host"], identity, secret, bool(src.get("verify_tls")), session=session)
            payload = c.collect()
        else:
            raise ValueError(f"unknown kind {src['kind']}")
        return True, None, payload, int((time.time() - t0) * 1000)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "Fingerprints did not match" in msg or "fingerprint" in msg.lower() and "match" in msg.lower():
            msg = ("its certificate changed since it was pinned - nothing was sent. If the change is "
                   "expected (a renewed certificate), re-pin it in Admin → Sources")
        return False, _redact(f"{type(e).__name__}: {msg[:300]}", identity, secret), None, \
            int((time.time() - t0) * 1000)


def store(src: dict, ok: bool, err: str | None, ms: int, payload: dict | None) -> None:
    """Save a poll. The bulky side data (per-VM statistics, new events: keys starting with
    '_') never goes into the snapshot - it is handed to its own store here."""
    side = {k: payload.pop(k) for k in [k for k in (payload or {}) if k.startswith("_")]} if payload else {}
    db.save_snapshot(src["id"], ok, err, ms, payload)
    if not (ok and payload and src["kind"] == "zvm"):
        return
    import events
    import hogs
    for what, fn in (("statistics", lambda: hogs.ingest(src["id"], side.get("_stats"))),
                     ("events", lambda: events.ingest(src, payload.get("site"), side.get("_events"),
                                                      side.get("_event_types")))):
        try:
            fn()
        except Exception:  # noqa: BLE001 - side data must never cost the poll
            log.exception("%s: storing %s failed", src["name"], what)


async def poll_once(source_id: int | None = None):
    sources = db.list_sources(enabled_only=True)
    if source_id is not None:
        sources = [s for s in sources if s["id"] == source_id]
    loop = asyncio.get_running_loop()

    async def _collect(src):
        try:
            ok, err, payload, ms = await loop.run_in_executor(_pool, collect_source, src)
            await asyncio.to_thread(store, src, ok, err, ms, payload)
            log.info("%s %s ok=%s %dms %s", src["kind"], src["name"], ok, ms, err or "")
        finally:
            _inflight.pop(src["id"], None)

    async def one(src):
        task = _inflight.get(src["id"])
        if task is None or task.done():
            task = asyncio.create_task(_collect(src))
            _inflight[src["id"]] = task
        await task

    await asyncio.gather(*(one(s) for s in sources))


async def cycle():
    """One full poll, then alert evaluation on the fresh data. Evaluation runs after
    full polls only, so a single-source 'Poll now' can't half-advance the clocks. One
    cycle at a time: a second caller ("poll all" during the loop's own) waits, then runs
    its own fresh one - never two evaluations at once (double emails, double trend samples)."""
    async with _cycle_lock:
        await poll_once()
        try:
            import alerts
            events = await asyncio.to_thread(alerts.evaluate)
            if events:
                log.info("alerts: %s", ", ".join(f"{e['name']}:{e['event']}" for e in events))
        except Exception:  # noqa: BLE001 - alerting must never stop polling
            log.exception("alert evaluation failed")
        try:
            import trends
            await asyncio.to_thread(trends.record)
        except Exception:  # noqa: BLE001
            log.exception("trend recording failed")
        global _maint_task
        if _maint_task is None or _maint_task.done():
            _maint_task = asyncio.create_task(asyncio.to_thread(maintenance))


_cycle_lock = asyncio.Lock()
_maint_task: asyncio.Task | None = None
MAINT_EVERY = 3600


def maintenance(force: bool = False) -> dict:
    """Hourly, off the poll path: retention, the one-time event backfill, Zerto's test
    reports, and storing any new daily VPG-settings export. Each ZVM gets its own read-only
    client; one failing ZVM doesn't stop the others."""
    from datetime import datetime, timezone
    last = db.get_setting("maint_last")
    now = datetime.now(timezone.utc)
    if not force and last and (now - datetime.fromisoformat(last)).total_seconds() < MAINT_EVERY:
        return {}
    db.set_setting("maint_last", now.isoformat(timespec="seconds"))
    import backups
    import events
    import views
    out = {"purged": db.purge()}
    snaps = db.get_snapshots()
    org_of = {v.get("id"): v.get("org") for v in views.merged_vpgs().values() if v.get("id")}
    for src in db.list_sources(enabled_only=True):
        p = (snaps.get(src["id"]) or {}).get("payload") or {}
        if src["kind"] != "zvm" or p.get("flavour") != "appliance":
            continue
        try:
            cl = polling_client(src)
            events.backfill(src, cl)
            first = not db.get_setting(f"tests_collected_{src['id']}")
            out[f"tests {src['name']}"] = events.collect_tests(src, cl, 60 if first else 3, org_of)
            db.set_setting(f"tests_collected_{src['id']}", db.now_iso())
            out[f"backup {src['name']}"] = backups.collect(src, cl, p)
        except Exception as e:  # noqa: BLE001
            log.warning("maintenance for %s failed: %s", src["name"], _redact(str(e)[:200]))
            out[f"error {src['name']}"] = str(e)[:200]
    log.info("maintenance: %s", out)
    return out


async def loop_forever():
    while True:
        try:
            await cycle()
        except Exception:  # noqa: BLE001
            log.exception("poll failed")
        interval = int(db.get_setting("poll_interval", "120") or 120)
        await asyncio.sleep(max(30, interval))
