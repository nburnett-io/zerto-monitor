"""Local verification for the 1.5 data/alerting fixes: per-VPG failure clock, no false
'Recovered' for a vanished VPG, failed sends retried, per-customer roll-ups, one poll cycle
at a time, a hung poller counts as down, report retention, backups overview, events window,
code ignores vs Zerto's error level.

EMPTY temporary data dir, synthetic snapshots, a fake clock and a fake mailer: nothing here
can reach a real ZVM or SMTP server (hosts are .invalid, the poller is stubbed)."""
import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(__file__).resolve().parent / "fixtures"
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke15-"))
os.environ.update(DATA_DIR=str(TMP), TLS_DIR=str(TMP / "tls"), ADMIN_SOCKET=str(TMP / "no.sock"),
                  OVFENV_STATE=str(TMP / "ovfenv.state"))
from cryptography.fernet import Fernet  # noqa: E402
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
sys.path.insert(0, str(ROOT / "app"))
FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)[:200]) if detail and not ok else ''}")
    if not ok:
        FAILED.append(desc)


import alerts  # noqa: E402
import collector  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import events  # noqa: E402
import reports  # noqa: E402
import views  # noqa: E402

db.init()
NOW = datetime.now(timezone.utc)

# ═══════════════════════════════════════════ alert engine, fake clock + fake mailer
OBS = {"v": []}
_real_obs = alerts._observations
alerts._observations = lambda: OBS["v"]
OUTBOX, SMTP = [], {"down": False}


def fake_send(to, subject, text, html=None):
    if SMTP["down"]:
        raise OSError("smtp.example.invalid: connection refused")
    OUTBOX.append({"to": tuple(to), "subject": subject, "text": text})


alerts.send_email = fake_send
for k, v in (("alerts_enabled", "true"), ("smtp_host", "smtp.example.invalid"),
             ("alert_default_recipients", "noc@example.invalid"), ("public_url", "https://zm.example.invalid"),
             ("alert_notify_clear", "true"), ("alert_repeat_hours", "24"), ("snmp_trap_enabled", "false")):
    db.set_setting(k, v)
db.save_alert_rule("*", 15, 60, "", True, False, True)
T0 = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def org(name, bad, keys=None):
    """bad: {key: [health, VPG name]}; keys: every VPG the zORG has now (default: the bad ones)."""
    f = sum(1 for h, _ in bad.values() if h == "failure")
    w = len(bad) - f
    return {"name": name, "health": "failure" if f else "warning" if w else "healthy", "failure": f, "warning": w,
            "healthy": 1, "bad": bad, "vpgs": len(bad) + 1, "worst_rpo": "-", "sites": [], "ignored": 0,
            "ignored_keys": [], "keys": list(keys if keys is not None else bad)}


def run(m, *orgs):
    OBS["v"] = list(orgs)
    OUTBOX.clear()
    alerts.evaluate(now=T0 + timedelta(minutes=m))
    return [x["subject"] for x in OUTBOX]


print("=== 1. per-VPG failure clock ===")
W, F = ["warning", "A-VPG"], ["failure", "A-VPG"]
run(0, org("Acme", {"a1": W}))
s = run(60, org("Acme", {"a1": W}))
step("warning for 60 min: one Warning email", s == ["[Zerto Monitor] Acme - A-VPG - Warning"], s)
s = run(70, org("Acme", {"a1": F}))
step("hours of warning, then ONE failing poll: no Failure email yet", s == [], s)
run(72, org("Acme", {"a1": W}))
s = run(80, org("Acme", {"a1": F}))
step("flapping back into failure restarts its failure clock", s == [], s)
s = run(94, org("Acme", {"a1": F}))
step("14 min of continuous failure: still nothing", s == [], s)
s = run(95, org("Acme", {"a1": F}))
step("15 min of continuous failure: Failure email", s == ["[Zerto Monitor] Acme - A-VPG - Failure"], s)
run(200, org("Bravo", {"b1": ["warning", "B-VPG"]}))
s = run(230, org("Bravo", {"b1": ["failure", "B-VPG"]}))
step("30 min warning (not yet told) then failure: not raised at once", s == [], s)
s = run(245, org("Bravo", {"b1": ["failure", "B-VPG"]}))
step("...raised after 15 min of failure", s == ["[Zerto Monitor] Bravo - B-VPG - Failure"], s)

print("\n=== 2. a VPG that vanished gets no 'Recovered' ===")
C = {"c1": ["failure", "C-VPG-1"], "c2": ["failure", "C-VPG-2"]}
run(1000, org("Cobalt", C))
s = run(1015, org("Cobalt", C))
step("both VPGs raised", sorted(s) == ["[Zerto Monitor] Cobalt - C-VPG-1 - Failure", "[Zerto Monitor] Cobalt - C-VPG-2 - Failure"], s)
s = run(1020, org("Cobalt", {}, keys=["c1"]))                  # c1 healthy, c2 deleted in Zerto
step("only the VPG still present and healthy is 'Recovered'", s == ["[Zerto Monitor] Cobalt - C-VPG-1 - Recovered"], s)
s = run(1021, org("Cobalt", {}, keys=["c1"]))
step("...and the vanished one is dropped, not announced later", s == [], s)

print("\n=== 3. a failed send is retried next poll ===")
D = {"d1": ["failure", "D-VPG"]}
run(2000, org("Delta", D))
SMTP["down"] = True
s = run(2015, org("Delta", D))
step("SMTP down: nothing delivered", s == [], s)
SMTP["down"] = False
s = run(2016, org("Delta", D))
step("next poll retries it", s == ["[Zerto Monitor] Delta - D-VPG - Failure"], s)
s = run(2017, org("Delta", D))
step("once delivered it counts as told: no repeat", s == [], s)
log = [r for r in db.recent_alerts(10) if "D-VPG" in (r["summary"] or "")]
step("the failure and the retry are both in the alert log", [r["ok"] for r in log][:2] == [1, 0], [r["ok"] for r in log])

print("\n=== 4. storm roll-up stays per customer ===")
db.save_alert_rule("Echo", 15, 60, "echo@example.invalid", True, False, True)
db.save_alert_rule("Fox", 15, 60, "fox@example.invalid", True, False, True)
db.set_setting("alert_vpg_email_cap", "1")
E = {"ev1": ["failure", "E-VPG-1"], "ev2": ["failure", "E-VPG-2"]}
FX = {"f1": ["failure", "F-VPG-1"], "f2": ["failure", "F-VPG-2"]}
run(3000, org("Echo", E), org("Fox", FX))
_zd, ZD = views.zorg_detail, []
views.zorg_detail = lambda name: ZD.append(name) or _zd(name)
run(3015, org("Echo", E), org("Fox", FX))
views.zorg_detail = _zd
rolls = [m for m in OUTBOX if "more VPG alerts" in m["subject"]]
by_to = {m["to"]: m["text"] for m in rolls}
step("one roll-up per recipient set", sorted(by_to) == [("echo@example.invalid",), ("fox@example.invalid",)], sorted(by_to))
step("...each lists only its own customer's VPGs",
     "F-VPG" not in by_to.get(("echo@example.invalid",), "F-VPG") and "E-VPG" not in by_to.get(("fox@example.invalid",), "E-VPG")
     and "F-VPG-1" in by_to.get(("fox@example.invalid",), "") and "F-VPG-2" in by_to.get(("fox@example.invalid",), ""))
step("delivery doesn't rebuild a zORG page per zORG", ZD == [], ZD)
db.set_setting("alert_vpg_email_cap", "25")
alerts._observations = _real_obs

print("\n=== 5. one poll cycle at a time ===")
LIVE, PEAK, EVALS = {"n": 0}, {"n": 0}, []


async def fake_poll(source_id=None):
    LIVE["n"] += 1
    PEAK["n"] = max(PEAK["n"], LIVE["n"])
    await asyncio.sleep(0.05)
    LIVE["n"] -= 1


_saved = (collector.poll_once, alerts.evaluate, collector.maintenance)
collector.poll_once = fake_poll
alerts.evaluate = lambda: EVALS.append(1) or []
collector.maintenance = lambda force=False: {}


async def two():
    await asyncio.gather(collector.cycle(), collector.cycle())

asyncio.run(two())
step("'poll all' during the loop's own cycle waits for it", PEAK["n"] == 1, PEAK)
step("...then runs its own (fresh) evaluation", len(EVALS) == 2, EVALS)
collector.poll_once, alerts.evaluate, collector.maintenance = _saved

print("\n=== 6. a hung poller counts as down ===")
snap = json.loads((SCRATCH / "snapshot.json").read_text(encoding="utf-8"))
real = next(s for s in snap["snapshots"] if s["payload"])["payload"]
SID = db.add_source("Site-A", "zvm", "zvm.invalid", "client_credentials", "poll-id", crypto.encrypt("poll-secret"), False)
db.save_snapshot(SID, True, None, 10, real)
step("a fresh good poll: no source down", views.overview()["totals"]["sources_down"] == 0)
old = (NOW - timedelta(hours=1)).isoformat(timespec="seconds")          # 30x the 120 s interval
with db._conn() as c:
    c.execute("UPDATE snapshots SET taken_at=? WHERE source_id=?", (old, SID))
ov = views.overview()
step("a good poll an hour old: the source counts as down", ov["totals"]["sources_down"] == 1, ov["totals"])
step("...the RMM's sources_down sees it", views.metrics()["sources_down"] == 1)
step("...its VPGs are shown as stale, not live", ov["sites"][0]["stale"] and not ov["sites"][0]["ok"])
src = [o for o in alerts._observations() if o["name"] == alerts.SOURCE_PREFIX + "Site-A"]
step("...and the alert engine sees the source failing", src and src[0]["health"] == "failure"
     and "no poll since" in src[0]["error"], src)

print("\n=== 7. reports: 13 months of alerts, every event counted ===")
with db._conn() as c:
    c.execute("INSERT INTO alert_log(at,zorg,event,level,minutes,summary,channels,ok) VALUES(?,?,?,?,?,?,?,?)",
              ((NOW - timedelta(days=200)).isoformat(timespec="seconds"), "Acme", "raised", "failure", 20, "x", "email", 1))
db.log_alert("Acme", "raised", "failure", 20, "now", "email", True)               # runs the purge
step("an alert 200 days old is kept", len(db.alerts_between("Acme", (NOW - timedelta(days=201)).isoformat(),
                                                                (NOW - timedelta(days=199)).isoformat())) == 1)
month0 = NOW.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
db.save_events([{"id": f"ev-{i}", "at": (month0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "kind": "change", "type": "UpdateProtectionGroup", "zorg": "Acme"} for i in range(350)])
rep = reports.build("Acme", NOW.strftime("%Y-%m"))
step("report counts all 350 changes, not the first 300", rep["event_counts"].get("change") == 350, rep["event_counts"])

print("\n=== 8. backups overview: newest per VPG, from SQL ===")
day = lambda d: (NOW - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
db.save_backups([{"site": "Site-A", "export_ts": day(d), "vpg_name": "Gone-VPG", "zorg": "Acme", "data_enc": "x"}
                 for d in (5, 6, 7)] +
                [{"site": "Site-A", "export_ts": day(d), "vpg_name": "Live-VPG", "zorg": "Acme", "data_enc": "x"}
                 for d in (0, 1)])
bo = {r["vpg_name"]: r for r in views.backups_overview(None, None)["vpgs"]}
step("every VPG listed, with its copies", bo.get("Gone-VPG", {}).get("copies") == 3 and bo.get("Live-VPG", {}).get("copies") == 2, bo)
step("...and its NEWEST backup", bo.get("Gone-VPG", {}).get("export_ts") == day(5) and bo.get("Live-VPG", {}).get("export_ts") == day(0))
step("zORG filter still applies", views.backups_overview("Nobody", None)["vpgs"] == [])

print("\n=== 10. events window ===")
ESRC = {"id": 77, "name": "Site-E"}
at = (NOW - timedelta(minutes=5)).replace(microsecond=0)
events.ingest(ESRC, "Site-E", [{"EventIdentifier": "l-1", "EventType": "Login", "OccurredOn": at.strftime("%Y-%m-%dT%H:%M:%S.000Z")}], None)
step("a window of only skipped types still moves the window on (30 min overlap)",
     db.get_setting("events_since_77") == events._iso(at - timedelta(minutes=30)), db.get_setting("events_since_77"))
ev = [{"EventIdentifier": "p-1", "EventType": "PauseProtectionGroup", "OccurredOn": at.strftime("%Y-%m-%dT%H:%M:%S.000Z")}]
step("overlap is safe: the same event is stored once", events.ingest(ESRC, "Site-E", ev, None) == 1
     and events.ingest(ESRC, "Site-E", ev, None) == 0)

print("\n=== 11. a code ignore doesn't hide Zerto's error level ===")
CODES = {"VPG0035": {"code": "VPG0035", "note": "", "created_by": "eng", "expires_at": None}}
cv = {"status": "MeetingSLA", "sub": "None", "rpo": 10, "alerts": [{"id": "VPG0035", "level": "Warning"}]}
step("AlertStatus 1 with only the ignored warning: covered", views._code_cover({**cv, "alert_status": 1}, CODES) is not None)
step("AlertStatus 2 with only the ignored warning: NOT covered", views._code_cover({**cv, "alert_status": 2}, CODES) is None)
step("AlertStatus 2 whose ignored alert is an Error: covered", views._code_cover(
    {**cv, "alert_status": 2, "alerts": [{"id": "VPG0035", "level": "Error"}]}, CODES) is not None)

print("\nALL GOOD" if not FAILED else f"\nFAILED {len(FAILED)}:\n   - " + "\n   - ".join(FAILED))
sys.exit(1 if FAILED else 0)
