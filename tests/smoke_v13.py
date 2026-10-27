"""Local verification for Zerto Monitor 1.3: resize hardening, write allowlists, events/
timeline, trends, hot spots, VPG backups + restore, recovery plans, monthly reports, pages.

EMPTY temporary data dir, synthetic snapshots, fake ZVMs and a fake clock: nothing here can
reach a real ZVM (hosts are .invalid, the poller and workers are stubbed)."""
import asyncio
import copy
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(__file__).resolve().parent / "fixtures"
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke13-"))
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


import backups  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import events  # noqa: E402
import hogs  # noqa: E402
import plans  # noqa: E402
import reports  # noqa: E402
import requests  # noqa: E402
import trends  # noqa: E402
import views  # noqa: E402
import vrapush  # noqa: E402
import zerto  # noqa: E402
from zerto import classify  # noqa: E402

db.init()
NOW = datetime.now(timezone.utc)

# ═══════════════════════════════════════════ synthetic site
snap = json.loads((SCRATCH / "snapshot.json").read_text(encoding="utf-8"))
real = next(s for s in snap["snapshots"] if s["payload"] and s["payload"]["site"] == "Site-A")["payload"]
TV = next(v for v in real["vpgs"] if v["health"] == "healthy")
TR = real["vras"][0]
SITE = "Site-A"


def vpg(i, org, rpo=10, rpo_cfg=300, status="MeetingSLA", sub="None", rec_host="esx01.site-a.example.invalid",
        direction="inbound", hist=1440):
    v = copy.deepcopy(TV)
    v.update(id=f"0000000{i}-aaaa-bbbb-cccc-00000000000{i}", name=f"{org}-VPG-{i}", org=org, zorg_id=f"z-{org}",
             status=status, sub=sub, rpo=rpo, rpo_cfg=rpo_cfg, alert_status=0, direction=direction, alerts=[],
             on_disconnected_vra=[], protected_site="Site-B" if direction == "inbound" else SITE,
             recovery_site=SITE if direction == "inbound" else "Site-B", history_min=hist,
             history_cfg_min=1440, last_test=None, vms=2,
             members=[{"id": f"vm-{i}-{k}", "name": f"VM{i}{k}", "protected_host": "esx01.site-b.example.invalid",
                       "recovery_host": rec_host, "protected_host_id": None, "recovery_host_id": None,
                       "journal_gb": 5.0, "prov_gb": 100} for k in "ab"])
    v["health"] = classify(status, sub, rpo, 0)
    return v


def vra(i, host):
    r = copy.deepcopy(TR)
    r.update(id=str(1000 + i), host=host, mem_gb=16, cpus=4, disconnected=False, mask_mismatch=False, status=0,
             version="10.9.0", cluster="C1", cluster_id="domain-c1", is_ghost=False, alert_status=0)
    return r


VPGS = [vpg(1, "Acme"), vpg(2, "Acme", rpo=900), vpg(3, "Acme", rec_host="esx02.site-a.example.invalid"), vpg(4, "Beta")]


def payload(vpgs=None, plans_=None):
    p = copy.deepcopy(real)
    p.update(vpgs=vpgs or VPGS, vras=[vra(1, "esx01.site-a.example.invalid"), vra(2, "esx02.site-a.example.invalid")], alerts=[],
             version="10.9.0.155", flavour="appliance", site=SITE,
             zorgs=[{"name": "Acme", "id": "z-Acme"}, {"name": "Beta", "id": "z-Beta"}], plans=plans_ or [])
    p["counts"] = {"vpgs": len(p["vpgs"])}
    return p


SID = db.add_source(SITE, "zvm", "zvm.invalid", "client_credentials", "poll-id", crypto.encrypt("poll-secret"), False)
db.set_source_pins(SID, {443: "aa:" * 31 + "aa"})
db.save_snapshot(SID, True, None, 10, payload())

# ═══════════════════════════════════════════ write allowlists
print("=== write allowlists ===")


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.is_redirect, self.text = status, body, False, json.dumps(body)

    def json(self):
        return self._b


class _Http:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json")))
        return _Resp(201, "11111111-2222-3333-4444-555555555555")

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw.get("json")))
        return _Resp(200, {"ExportedVpgSettingsApi": []})


def client_with(writes):
    h = _Http()
    c = zerto.ZvmClient("zvm.invalid", "client_credentials", "c", "s", session=None, writes=writes)
    c._http, c.base, c.headers = h, "https://zvm.invalid", {}
    return c, h


poll, h = client_with(())
for m, p in (("POST", "/v1/recoveryPlans"), ("POST", "/v1/vpgSettings/import"), ("PUT", "/v1/vras/1")):
    try:
        poll.write(m, p, {})
        step(f"polling client refuses {m} {p}", False)
    except zerto.ZvmError:
        step(f"polling client refuses {m} {p}", not h.calls)
pc, h = client_with(zerto.WRITES_PLANS)
st, r = pc.write("POST", "/v1/recoveryPlans", {"name": "x"})
step("plan client: POST /v1/recoveryPlans allowed", st == 201 and h.calls[0][0] == "POST")
for m, p in (("DELETE", "/v1/recoveryPlans/11111111-2222-3333-4444-555555555555"), ("POST", "/v1/vpgSettings/import"),
             ("PUT", "/v1/recoveryPlans/../vras/1")):
    try:
        pc.write(m, p, {})
        step(f"plan client refuses {m} {p}", False)
    except zerto.ZvmError:
        step(f"plan client refuses {m} {p}", True)
try:
    poll.post_read("/v1/vpgSettings/exportSettings", {})
    step("post_read refuses a POST that changes something", False)
except zerto.ZvmError:
    step("post_read refuses a POST that changes something", True)
poll.post_read("/v1/vpgSettings/exportedSettings/2026-10-05T19:51:32.000Z", {"VpgNames": []})
step("post_read allows reading an export", True)
s = zerto.pinned_session("zvm.invalid", {443: "aa:" * 31 + "aa"})
step("pinned sessions ignore proxy environment variables", s.trust_env is False and s.proxies == {})

# ═══════════════════════════════════════════ events
print("\n=== events / timeline ===")
TYPES = ["Unknown", "CreateProtectionGroup", "RemoveProtectionGroup", "FailOver", "FailOverTest", "StopFailOverTest",
         "Move", "ProtectVM", "UnprotectVM", "InstallVra", "UninstallVra", "UpdateProtectionGroup"] + \
        [f"T{i}" for i in range(12, 42)] + ["PauseProtectionGroup", "ResumeProtectionGroup"] + \
        [f"T{i}" for i in range(44, 47)] + ["AlertTurnedOn", "AlertTurnedOff"] + [f"T{i}" for i in range(49, 60)] + ["Login"]
V1 = VPGS[0]


def ev(i, t, desc, vid=V1["id"], ok=True, at="2026-10-06T10:00:00.123Z"):
    return {"EventIdentifier": f"ev-{i}", "OccurredOn": at, "EventType": t, "EventCategory": "Events",
            "Description": desc, "UserName": "corp.example.invalid\\eng", "EventCompletedSuccessfully": ok,
            "Vpgs": [{"VpgIdentifier": "00000000-0000-0000-0000-000000000000", "VpgName": ""},
                     {"VpgIdentifier": vid, "VpgName": V1["name"]}], "ZorgName": "Acme", "ZorgIdentifier": "z-Acme",
            "SiteName": SITE}


RAW = [ev(1, 11, "Update protection group. Completed successfully.<br>RPO changed"), ev(2, 42, "Pause"),
       ev(3, 4, "Protection group failover test. <br>RTO : 6 minutes"), ev(4, 60, "ZVM Login. Success."),
       ev(5, 47, "Alert turned on"), ev(6, 43, "Resume", ok=False, at="2026-10-06T11:00:00.000Z")]
rows = events.normalise(RAW, TYPES, SITE, SITE)
step("logins and alert flapping are left out", [r["type"] for r in rows] ==
     ["UpdateProtectionGroup", "PauseProtectionGroup", "FailOverTest", "ResumeProtectionGroup"])
step("kinds: change / pause / test", [r["kind"] for r in rows] == ["change", "pause", "test", "pause"])
step("the all-zero VPG placeholder is dropped; HTML stripped", rows[0]["vpg_ids"] == [V1["id"]] and "<br>" not in rows[0]["text"])
n1 = events.ingest({"id": SID, "name": SITE}, SITE, RAW, TYPES)
n2 = events.ingest({"id": SID + 99, "name": "paired ZVM"}, SITE, RAW, TYPES)
step("the paired ZVM's copy of the same events is stored once", n1 == 4 and n2 == 0)
_want = max(datetime(2026, 10, 6, 10, 58, tzinfo=timezone.utc), datetime.now(timezone.utc) - timedelta(days=1))
_got = datetime.fromisoformat(events.since({"id": SID}).replace("Z", "+00:00"))
step("next window starts at the newest event (minus overlap), never more than a day back",
     abs(_got - _want) < timedelta(minutes=2), (_got, _want))
step("filter by zORG + kind", [e["type"] for e in db.events(zorg="Acme", kinds=("pause",))] ==
     ["ResumeProtectionGroup", "PauseProtectionGroup"])
step("filter by VPG", len(db.events(vpg_id=V1["id"])) == 4 and not db.events(vpg_id=VPGS[1]["id"]))
step("Zerto's test verdicts", events.test_ok("PassedByUser") and events.test_ok("FailedByUser") is False
     and events.test_ok(None) is None)

# ═══════════════════════════════════════════ trends
print("\n=== RPO / journal trends ===")
merged = views.merged_vpgs()
samples = trends.samples_from(merged)
s2 = next(s for s in samples if s["key"] == VPGS[1]["id"])
step("an RPO over its target is a breach", s2["rpo_breach"] == 1 and next(s for s in samples if s["key"] == V1["id"])["rpo_breach"] == 0)
step("journal history short only beyond the slack", not trends.history_short(1436, 1440) and trends.history_short(1200, 1440))
for k in range(3):
    trends.record(NOW - timedelta(hours=2 - k))
h1 = db.trend_rows("vpg_hourly", vpg_key=V1["id"])
d1 = db.trend_rows("vpg_daily", vpg_key=V1["id"])
step("hourly buckets: one per hour; daily bucket accumulates", len(h1) == 3 and sum(r["samples"] for r in d1) == 3, (len(h1), d1))
sm = trends.summarise(db.trend_rows("vpg_daily", vpg_key=VPGS[1]["id"]))
step("summary: 0% RPO met for the breaching VPG", sm["rpo_ok_pct"] == 0 and sm["rpo_max"] == 900, sm)
ser = trends.vpg_series(V1["id"], 24)
step("series for charts", len(ser["points"]) == 3 and ser["rpo_ok_pct"] == 100)
db.save_snapshot(SID, False, "down", 10, None)
before = sum(r["samples"] for r in db.trend_rows("vpg_daily", vpg_key=V1["id"]))
trends.record(NOW)
step("a down source adds no samples (its last good poll is not replayed)",
     sum(r["samples"] for r in db.trend_rows("vpg_daily", vpg_key=V1["id"])) == before)
db.save_snapshot(SID, True, None, 10, payload())

# ═══════════════════════════════════════════ hot spots
print("\n=== VRA hot spots ===")


def stats(t, mb):
    return [{"VmIdentifier": vid, "WriteCounterInMBs": w, "NetworkTrafficCounterInMBs": w // 3,
             "SampleTime": t.strftime("%Y-%m-%dT%H:%M:%S.000Z")} for vid, w in mb.items()]


t0 = NOW - timedelta(hours=2)
base = {"vm-1-a": 1000, "vm-1-b": 1000, "vm-2-a": 1000, "vm-2-b": 1000, "vm-4-a": 1000, "vm-4-b": 1000, "vm-3-a": 1000}
hogs.ingest(SID, stats(t0, base), t0)
grow = {"vm-1-a": 1000 + 150000, "vm-1-b": 1000 + 2000, "vm-2-a": 1000 + 2000, "vm-2-b": 1000 + 1000,
        "vm-4-a": 1000 + 1000, "vm-4-b": 1000 + 1000, "vm-3-a": 1000 + 500}
half = {k: (v + base[k]) // 2 for k, v in grow.items()}
hogs.ingest(SID, stats(t0 + timedelta(minutes=30), half), t0 + timedelta(minutes=30))
step("no hot-spot verdict from under an hour of data", not hogs.hotspots(SITE)["flags"])
hogs.ingest(SID, stats(t0 + timedelta(minutes=90), grow), t0 + timedelta(minutes=90))
hs = hogs.hotspots(SITE)
v1 = hs["by_vra"].get("esx01")
step("traffic attributed to the recovery VRA (inbound VPGs)", v1 and v1["vms"] == 6, hs["by_vra"].keys())
step("one VM dominating its VRA is a hot spot", v1["hog"] and v1["hog"]["name"] == "VM1a" and v1["hog"]["share"] > .8, v1)
step("...and the site-level flag names it", any("VM1a" in f and "inbound" in f for f in hs["flags"]), hs["flags"])
hogs.ingest(SID, stats(t0 + timedelta(minutes=110), {**grow, "vm-1-a": 5}), t0 + timedelta(minutes=110))
hs2 = hogs.hotspots(SITE)
step("a counter that went backwards (VRA restart) adds nothing", hs2["by_vra"]["esx01"]["write_gb"] == v1["write_gb"])

# ═══════════════════════════════════════════ backups
print("\n=== VPG settings backups ===")
SECRET_PARAM = "s3cr3t-Script-Param-998"


def item(name, vid, rpo=1800, vm_order=("vm-a", "vm-b"), param=SECRET_PARAM):
    return {"VpgIdentifier": vid, "VpgSettingsIdentifier": "x", "Generation": 3, "SourceSiteName": "Site-B",
            "TargetSiteName": SITE,
            "Basic": {"Name": name, "VpgType": "Remote", "RpoInSeconds": rpo, "JournalHistoryInHours": 24,
                      "ZorgIdentifier": "z-Acme", "Priority": "Medium", "UseWanCompression": True,
                      "TestIntervalInMinutes": 0},
            "Recovery": {"VCD": {"OrgVdcIdentifier": "urn:vcloud:vdc:1"}},
            "Journal": {"Limitation": {"HardLimitInPercent": 80, "WarningThresholdInPercent": 70}},
            "Scripting": {"PreRecovery": {"Command": "/scripts/pre.sh", "Parameters": param, "TimeoutInSeconds": 300}},
            "Vms": [{"VmIdentifier": v, "Volumes": [{"VolumeIdentifier": "d1"}]} for v in vm_order]}


src = db.get_source(SID)
n = backups.store_export(src, SITE, "2026-10-04T19:00:00.000Z",
                         [item(V1["name"], V1["id"]), item("Gone-VPG", "dead-0000")], {"z-Acme": "Acme"})
n += backups.store_export(src, SITE, "2026-10-05T19:00:00.000Z",
                          [item(V1["name"], V1["id"], rpo=600, vm_order=("vm-b", "vm-a"))], {"z-Acme": "Acme"})
step("exports stored per VPG, tagged with the zORG", n == 3 and {b["zorg"] for b in db.list_backups()} == {"Acme"})
raw = (TMP / "monitor.db").read_bytes() + ((TMP / "monitor.db-wal").read_bytes() if (TMP / "monitor.db-wal").exists() else b"")
step("stored encrypted: the script parameter isn't in the DB or WAL bytes", SECRET_PARAM.encode() not in raw)
newest = db.list_backups(vpg_name=V1["name"])[0]
older = backups.previous_of(newest)
b, it = backups.load(newest["id"])
step("decrypts back to the export", it["Basic"]["RpoInSeconds"] == 600)
_, oit = backups.load(older["id"])
df = backups.diff(oit, it)
step("diff finds the RPO change only (a reordered VM list isn't a change)",
     [d["path"] for d in df] == ["Basic.RpoInSeconds"], df)
df2 = backups.diff(oit, item(V1["name"], V1["id"], param="other-value"))
step("script parameters are diffed but never shown", any(d["path"].endswith("Parameters") and d["old"] == "(set - hidden)"
                                                        for d in df2), df2)
db.set_setting("backup_days", "7")
old_cap = (NOW - timedelta(days=8)).isoformat(timespec="seconds")
with db._conn() as c:
    c.execute("UPDATE vpg_backups SET captured_at=? WHERE export_ts LIKE '2026-10-04%'", (old_cap,))
db.purge()
step("backups older than 7 days are purged", not any(b["export_ts"].startswith("2026-10-04") for b in db.list_backups()))
backups.store_export(src, SITE, "2026-10-04T19:00:00.000Z", [item(V1["name"], V1["id"]), item("Gone-VPG", "dead-0000")],
                     {"z-Acme": "Acme"})

class _ExportZvm:
    def get(self, path):
        return [{"TimeStamp": "2026-10-06T07:00:00.000Z"}]

    def post_read(self, path, body):
        return {"ErrorMessage": "Failed to convert export VPG settings for the following VPGs: Broken-1",
                "ExportedVpgSettingsApi": [item("Partial-OK", "partial-1")]}


msg = backups.collect(src, _ExportZvm(), payload())
step("a partial Zerto export: the VPGs it did export are stored, the failure is flagged",
     db.list_backups(vpg_name="Partial-OK") and "Broken-1" in (db.get_setting(f"backup_warn_{SID}") or ""), msg)

print("\n=== restore ===")
gone = db.list_backups(vpg_name="Gone-VPG")[0]
exists = db.list_backups(vpg_name=V1["name"])[0]
pl = backups.restore_plan(exists["id"])
step("a VPG that exists is never imported over", any("exists right now" in p for p in pl["problems"]), pl["problems"])
pl = backups.restore_plan(gone["id"])
step("disarmed by default (switch, armed site)", len(pl["problems"]) >= 2, pl["problems"])
db.set_setting("vpg_restore_enabled", "true")
db.set_source_allow_changes(SID, True)
db.set_source_push(SID, push_identity=crypto.encrypt("chg-id"), push_secret_enc=crypto.encrypt("chg-secret"))
pl = backups.restore_plan(gone["id"])
step("armed + pinned (polling pin reused) + deleted VPG -> no problems", pl["problems"] == [], pl["problems"])
ADMIN, ENG = {"username": "admin", "role": "admin"}, {"username": "eng", "role": "engineer"}
F = {"plan_hash": pl["plan_hash"], "ticket": "CHG-9", "typed_name": "Gone-VPG", "ack_sync": "yes"}
for who, f, why in ((ENG, F, "an engineer"), (ADMIN, {**F, "ticket": ""}, "no ticket"),
                    (ADMIN, {**F, "typed_name": "gone-vpg"}, "name not typed exactly"),
                    (ADMIN, {**F, "ack_sync": ""}, "no initial-sync acknowledgement"),
                    (ADMIN, {**F, "plan_hash": "stale"}, "stale preview")):
    try:
        backups.start_restore(gone["id"], who, f)
        step(f"restore refused: {why}", False)
    except backups.RestoreError:
        step(f"restore refused: {why}", True)


class FakeRestoreZvm:
    def __init__(self, result=None, task_states=(1, 6), live=(), boom_after=False):
        self.result, self.states, self.live, self.boom = result, list(task_states), list(live), boom_after
        self.writes = []

    def get(self, path):
        if path == "/v1/vpgs":
            return [{"VpgName": n} for n in self.live]
        raise zerto.ZvmError(path)

    def write(self, method, path, body, denied=""):
        self.writes.append((method, path, body))
        return 200, self.result

    def task(self, t):
        if self.boom:
            raise ValueError("boom")
        s = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"Status": {"State": s, "Progress": 50}, "CompleteReason": "x"}

    def login(self):
        pass


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def restore(fake):
    cid = backups.start_restore(gone["id"], ADMIN, {**F, "plan_hash": backups.restore_plan(gone["id"])["plan_hash"]})
    clk = Clock()
    backups.run_restore(db.get_change(cid), refresh=lambda sid: None, client_factory=lambda s: fake,
                        sleep=clk.sleep, clock=clk.now)
    return db.get_change(cid), fake


ch, fk = restore(FakeRestoreZvm(result={"ImportTaskIdentifiers": [{"VpgName": "Gone-VPG", "TaskIdentifier": "t-1"}]}))
step("restore: one import, task followed -> done", ch["state"] == "done" and len(fk.writes) == 1
     and fk.writes[0][1] == "/v1/vpgSettings/import" and fk.writes[0][2]["vpgNames"] == ["Gone-VPG"], (ch["state"], ch["detail"]))
step("  ...the backed-up settings are what's sent", fk.writes[0][2]["exportedVpgSettingsApi"][0]["Basic"]["Name"] == "Gone-VPG")
ch, fk = restore(FakeRestoreZvm(result={"ValidationFailedResults": [{"VpgName": "Gone-VPG", "ErrorMessages": ["VM not found"]}]}))
step("restore: Zerto's validation errors -> failed, with the reason", ch["state"] == "failed" and "VM not found" in ch["detail"])
ch, fk = restore(FakeRestoreZvm(live=["gone-vpg"]))
step("restore: the ZVM reports the VPG now -> refused, nothing sent", ch["state"] == "refused" and not fk.writes)
ch, fk = restore(FakeRestoreZvm(result={"ImportTaskIdentifiers": [{"TaskIdentifier": "t-2"}]}, boom_after=True))
step("restore: an unexpected error after sending -> unknown (never re-sent)", ch["state"] == "unknown" and len(fk.writes) == 1)

# ═══════════════════════════════════════════ recovery plans
print("\n=== recovery plans ===")
body = plans.build_body("Acme DR new", "Standard", [{"vpg_ids": ["a"], "wait": True, "delay": 5, "script": "", "params": ""},
                                                 {"vpg_ids": ["b", "c"], "wait": True, "delay": 0}])
step("blocks in order: VPG, wait, delay, VPG (trailing wait dropped)",
     [b["blockType"] for b in body["blocks"]] == ["VPG", "WaitRecoveryOperationCompletion", "Delay", "VPG"], body)
vp = views.zorg_detail("Acme")["vpgs"]
form = {"name": "Acme DR", "type": "Standard", f"tier_{VPGS[0]['id']}": "1", f"tier_{VPGS[1]['id']}": "2", "wait_1": "1",
        f"tier_{VPGS[3]['id']}": "1"}
_, _, tiers, probs = plans.parse_form(form, vp, SITE)
step("a VPG from another zORG can't be put in the plan", any(VPGS[3]["id"] in p for p in probs), probs)
form.pop(f"tier_{VPGS[3]['id']}")
_, _, tiers, probs = plans.parse_form(form, vp, SITE)
step("tiers parsed in order", not probs and [t["vpg_ids"] for t in tiers] == [[VPGS[0]["id"]], [VPGS[1]["id"]]], probs)
PLAN = {"id": "11111111-2222-3333-4444-555555555555", "name": "Acme DR", "type": "Standard", "status": "Ready",
        "last_run": None, "last_ok": None,
        "blocks": [{"type": "VPG", "vpg_ids": [VPGS[0]["id"]]}, {"type": "WaitRecoveryOperationCompletion", "vpg_ids": []},
                   {"type": "VPG", "vpg_ids": [VPGS[1]["id"]]}]}
db.save_snapshot(SID, True, None, 10, payload(plans_=[PLAN]))
zp = plans.zorg_plans("Acme", views.zorg_detail("Acme")["vpgs"])
step("plan shown with its tiers", zp["plans"] and [t["vpgs"] for t in zp["plans"][0]["tiers"]] ==
     [[VPGS[0]["name"]], [VPGS[1]["name"]]], zp["plans"][:1])
step("a zORG VPG left out of the plan is flagged", zp["missing"].get(SITE) == [VPGS[2]["name"]], zp["missing"])
try:
    plans.save("Acme", SITE, None, body, ENG)
    step("plan save refused while plan changes are off", False)
except plans.PlanError:
    step("plan save refused while plan changes are off", True)
db.set_setting("plans_enabled", "true")
fc, fh = client_with(zerto.WRITES_PLANS)
pid = plans.save("Acme", SITE, None, body, ENG, client_factory=lambda s: fc)
step("engineer creates a plan: one POST with the built body, logged", pid.startswith("11111111") and fh.calls[0][2] == body
     and db.changes(kind="plan_create")[0]["state"] == "done")
try:
    plans.delete("Acme", SITE, PLAN["id"], ENG)
    step("only an admin deletes a plan", False)
except plans.PlanError:
    step("only an admin deletes a plan", True)


def _refused(fn, *a, **k):
    try:
        fn(*a, **k)
        return None
    except plans.PlanError as e:
        return str(e)


ADM = {"username": "admin", "role": "admin"}
n = len(fh.calls)
step("a second plan with an existing name is refused, nothing sent",
     "already has a plan named" in (_refused(plans.save, "Acme", SITE, None, dict(body, name="Acme DR"), ENG,
                                             client_factory=lambda s: fc) or "") and len(fh.calls) == n)
step("an update to a plan that isn't this zORG's is refused, nothing sent",
     "doesn't cover" in (_refused(plans.save, "Beta", SITE, PLAN["id"], body, ENG, client_factory=lambda s: fc) or "")
     and len(fh.calls) == n)
step("a delete of a plan that isn't this zORG's is refused",
     "doesn't cover" in (_refused(plans.delete, "Beta", SITE, PLAN["id"], ADM, client_factory=lambda s: fc) or ""))
mixed = dict(PLAN, blocks=PLAN["blocks"] + [{"type": "VPG", "vpg_ids": [VPGS[3]["id"]]}])
step("a plan holding another zORG's VPG can't be edited (saving would drop it)",
     "another zORG" in (plans.not_editable(mixed, vp, SITE) or "") and plans.not_editable(PLAN, vp, SITE) is None)
step("two scripts after one tier can't round-trip -> not editable",
     plans.not_editable(dict(PLAN, blocks=[PLAN["blocks"][0], {"type": "Script", "script": "a"},
                                           {"type": "Script", "script": "b"}]), vp, SITE) is not None)


class _Timeout:
    def write(self, *a, **k):
        raise requests.ReadTimeout("slow")


step("a timeout after the POST went out is 'unknown', not 'failed'",
     "no clear answer" in (_refused(plans.save, "Acme", SITE, None, dict(body, name="Acme DR 3"), ENG,
                                    client_factory=lambda s: _Timeout()) or "")
     and db.changes(kind="plan_create")[0]["state"] == "unknown")

# ═══════════════════════════════════════════ resize hardening
print("\n=== resize hardening ===")
step("the polling pin is reused for changes", vrapush.push_pin(db.get_source(SID)) == "aa:" * 31 + "aa")
SID2 = db.add_source("disabled copy", "zvm", "zvm2.invalid", "password", "u", crypto.encrypt("p"), False)
db.save_snapshot(SID2, True, None, 10, payload())
db.update_source(SID2, "disabled copy", "zvm2.invalid", "password", "u", None, False, False)
step("a disabled source never stands in for a site", vrapush._site_source(SITE)[0]["id"] == SID)
step("conflicting Zerto tasks include 'waiting for user input' (2)", 2 in vrapush.CONFLICT_STATES)
step("holds outlast the runner's own limits", vrapush.HOLD_MINUTES * 60 > vrapush.TASK_TIMEOUT + vrapush.VRA_BACK + vrapush.VPG_RECOVER)
db.add_holds(999, [{"key": None, "name": "x"}, {"key": "k1", "name": "y"}], (NOW + timedelta(hours=1)).isoformat())
step("a VPG without an identifier is skipped when holding (no crash)", "k1" in db.active_holds())
db.release_holds(999, "test")

# a queued push that crashes before sending, and one after
db.set_setting("vra_push_enabled", "true")
db.set_source_push(SID, push_host_auth="vib")
pid = db.log_vra_push(by_user="admin", site=SITE, source_id=SID, vra_id="1001", vra_key=f"{SITE}|esx01", host="esx01",
                      from_mem=16, from_cpus=4, to_mem=16, to_cpus=4, state="queued", plan_hash="x")


def boom(src):
    raise KeyError("unexpected")


vrapush.run_one(db.get_vra_push(pid), refresh=lambda sid: None, client_factory=boom)
step("an unexpected error before sending ends it 'refused' - never left queued",
     db.get_vra_push(pid)["state"] == "refused", db.get_vra_push(pid)["detail"])
pid = db.log_vra_push(by_user="admin", site=SITE, source_id=SID, vra_id="1001", vra_key=f"{SITE}|esx01", host="esx01",
                      state="task_running")
orig_run = vrapush._run


def crash_mid(p, *a):
    raise RuntimeError("database is locked")


vrapush._run = crash_mid
vrapush.run_one(db.get_vra_push(pid))
vrapush._run = orig_run
st = db.get_vra_push(pid)
step("an unexpected error after sending ends it 'unknown' and halts resizing", st["state"] == "unknown" and vrapush.halted())
vrapush.acknowledge_halt("admin", "test cleanup of the halt")
old = (NOW - timedelta(minutes=11)).isoformat(timespec="seconds")
pid = db.log_vra_push(by_user="admin", site=SITE, source_id=SID, vra_key="x", host="h", state="queued")
with db._conn() as c:
    c.execute("UPDATE vra_pushes SET at=? WHERE id=?", (old, pid))


async def one_tick():
    try:
        await asyncio.wait_for(vrapush.worker(idle_seconds=0.01), timeout=0.5)
    except asyncio.TimeoutError:
        pass


asyncio.run(one_tick())
step("a go that waited over 10 minutes is refused, not sent late", db.get_vra_push(pid)["state"] == "refused",
     db.get_vra_push(pid)["detail"])
step("the public resize history carries no request/response bodies",
     all("request_json" not in p and "attest" not in p for p in db.recent_vra_pushes(SITE)))

# ═══════════════════════════════════════════ reports
print("\n=== monthly report ===")
db.save_test_reports([{"id": "t-1", "vpg_id": V1["id"], "vpg_name": V1["name"], "zorg": "Acme",
                       "started": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "rto_s": 390.0, "status": "PassedByUser",
                       "by_user": "eng", "notes": "quarterly test", "rtype": "FailoverTest", "steps": []}])
month = NOW.strftime("%Y-%m")
rep = reports.build("Acme", month)
step("report: compliance from the daily samples", rep["total"]["samples"] > 0 and rep["total"]["rpo_ok_pct"] < 100)
step("report: the month's failover test with its RTO", rep["tests"] and rep["tests"][0]["rto_h"] == "6m" and rep["tests_ok"] == 1)
step("report: the plan and its gap", rep["plans"]["plans"] and rep["plans"]["missing"])
step("report: charts rendered as SVG", "<svg" in str(rep["rpo_chart"]) and "<svg" in str(rep["health_chart"]))
step("report: logo embedded (self-contained PDF)", rep["logo"].startswith("data:image/svg+xml;base64,"))

# ═══════════════════════════════════════════ ZCM cloud connectors
print("\n=== ZCM cloud connectors ===")
import zcm  # noqa: E402
REAL = {"CloudConnectorIdentifier": "23fb21d9", "SiteName": "Site-A", "CustomerName": "SiteA_Initech",
        "VmName": "ZertoZCCInitech1", "Progress": 0, "Status": "Installed", "GhostStatus": "False", "SitePaired": True}
f1 = zcm._flat(REAL)
step("GhostStatus 'False' (text, as the ZCM sends it) is NOT a ghost", f1["_ghost"] is False and f1["_healthy"] is True, f1)
step("GhostStatus 'True' is a ghost and unhealthy", zcm._flat({**REAL, "GhostStatus": "True"})["_ghost"] is True
     and zcm._flat({**REAL, "GhostStatus": "True"})["_healthy"] is False)
step("an unknown GhostStatus fails closed", zcm._flat({**REAL, "GhostStatus": "Weird"})["_ghost"] is True)
step("progress is hidden on an installed connector", f1["_progress"] is None)
step("progress shown while installing", zcm._flat({**REAL, "Status": "Installing", "Progress": 40})["_progress"] == 40)
step("not paired -> unhealthy", zcm._flat({**REAL, "SitePaired": False})["_healthy"] is False)
from jinja2 import Environment  # noqa: E402
cell = Environment().from_string("{% if c._ghost is sameas true %}GHOST{% elif c._ghost is sameas false %}no{% else %}?{% endif %}")
step("the page shows 'no' for it (a non-empty string no longer reads as ghost)", cell.render(c=f1) == "no"
     and cell.render(c={"_ghost": "False"}) == "?")
# ═══════════════════════════════════════════ per-VPG alert emails
print("\n=== per-VPG alert emails ===")
import alerts as _al  # noqa: E402
OUTBOX = []
_real_send = _al.send_email
_al.send_email = lambda to, s, t, h=None: OUTBOX.append({"to": tuple(to), "subject": s, "text": t, "html": h})
for k, v in (("alerts_enabled", "true"), ("smtp_host", "smtp.example.invalid"), ("alert_default_recipients", "noc@example.invalid"),
             ("public_url", "https://zm.example.invalid"), ("alert_notify_clear", "true"), ("alert_repeat_hours", "24")):
    db.set_setting(k, v)
db.save_alert_rule("*", 15, 60, "", True, False, True)
FAILV = [vpg(1, "Acme", status="NotMeetingSLA", rpo=2400), vpg(2, "Acme", rpo=900), vpg(3, "Acme", rec_host="esx02.site-a.example.invalid"), vpg(4, "Beta")]
db.save_snapshot(SID, True, None, 10, payload(FAILV))
T = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
_al.evaluate(now=T)
step("under the 15-min threshold: no email yet", not OUTBOX)
_al.evaluate(now=T + timedelta(minutes=16))
subj = [m["subject"] for m in OUTBOX]
step("one email for the failing VPG, subject '[Zerto Monitor] Org - VPG - Failure'",
     subj == [f"[Zerto Monitor] Acme - {FAILV[0]['name']} - Failure"], subj)
m = OUTBOX[0] if OUTBOX else {"text": "", "html": ""}
step("body: what's wrong, status, RPO vs target, path", "What's wrong:" in m["text"] and "NotMeetingSLA" in m["text"]
     and "RPO:" in m["text"] and "target 5m" in m["text"] and "Site-B → Site-A" in m["text"], m["text"][:400])
step("body: links to the VPG and the zORG in Zerto Monitor",
     f"https://zm.example.invalid/vpgs/{FAILV[0]['id']}" in m["text"] and "https://zm.example.invalid/zorgs/Acme" in m["text"]
     and f'href="https://zm.example.invalid/vpgs/{FAILV[0]["id"]}"' in (m["html"] or ""))
step("each VPG email is in the alert log", any(r["event"] == "raised" and FAILV[0]["name"] in (r["summary"] or "")
                                                for r in db.recent_alerts(20)))
OUTBOX.clear()
_al.evaluate(now=T + timedelta(minutes=17))
step("no repeat before the reminder interval", not OUTBOX)
_al.evaluate(now=T + timedelta(hours=25))
step("reminder after 24 h, same subject", [x["subject"] for x in OUTBOX] == [f"[Zerto Monitor] Acme - {FAILV[0]['name']} - Failure"]
     and "(reminder)" in OUTBOX[0]["text"])
OUTBOX.clear()
db.save_snapshot(SID, True, None, 10, payload([vpg(1, "Acme")] + FAILV[1:]))
_al.evaluate(now=T + timedelta(hours=26))
step("recovery: one '... - Recovered' email", [x["subject"] for x in OUTBOX] == [f"[Zerto Monitor] Acme - {FAILV[0]['name']} - Recovered"],
     [x["subject"] for x in OUTBOX])
OUTBOX.clear()
db.save_snapshot(SID, True, None, 10, payload(FAILV))
_al.evaluate(now=T + timedelta(hours=27))
_al.evaluate(now=T + timedelta(hours=27, minutes=16))
OUTBOX.clear()
merged_now = views.merged_vpgs()
db.save_ignore("vpg", FAILV[0]["id"], FAILV[0]["name"], "all", {}, "", "eng", None)
_al.evaluate(now=T + timedelta(hours=27, minutes=20))
step("ignoring a VPG mid-alert sends no false 'Recovered'", not OUTBOX, [x["subject"] for x in OUTBOX])
for i in [x["id"] for x in db.list_ignores(False)]:
    db.delete_ignore(i)
OUTBOX.clear()
db.set_setting("alert_vpg_email_cap", "1")
STORM = [vpg(1, "Acme", status="NotMeetingSLA", rpo=2400), vpg(2, "Acme", status="NotMeetingSLA", rpo=2400),
         vpg(3, "Acme", status="NotMeetingSLA", rpo=2400, rec_host="esx02.site-a.example.invalid"), vpg(4, "Beta")]
db.save_snapshot(SID, True, None, 10, payload(STORM))
_al.evaluate(now=T + timedelta(hours=28))
_al.evaluate(now=T + timedelta(hours=28, minutes=16))
subj = [x["subject"] for x in OUTBOX]
step("storm guard: emails up to the cap, then ONE roll-up listing the rest",
     len(subj) == 2 and subj[0].startswith("[Zerto Monitor] Acme - ") and "more VPG alerts" in subj[1], subj)
db.set_setting("alert_vpg_email_cap", "25")
_al.send_email = _real_send
db.set_setting("alerts_enabled", "false")
db.save_snapshot(SID, True, None, 10, payload(plans_=[PLAN]))
# ═══════════════════════════════════════════ pages
print("\n=== pages ===")
from fastapi.testclient import TestClient  # noqa: E402
import alerts  # noqa: E402
import collector  # noqa: E402
import main  # noqa: E402


async def _idle():
    return None


collector.loop_forever = _idle
vrapush.worker = _idle
backups.worker = _idle
alerts._observations = lambda: []


def client(user=None, pw=None):
    c = TestClient(main.app, client=("203.0.113.9", 50000))
    c.__enter__()
    if user:
        r = c.post("/login", data={"username": user, "password": pw, "next": "/"}, follow_redirects=False)
        assert r.status_code == 303, r.text[:200]
    return c


boot = client()
boot.post("/setup", data={"username": "admin", "password": "admin-pw-123"}, follow_redirects=False)
adm = client("admin", "admin-pw-123")
adm.post("/admin/users", data={"username": "eng", "password": "eng-pw-12345", "role": "engineer"})
eng, anon = client("eng", "eng-pw-12345"), client()
r = anon.get("/")
step("nav: logo and the new sections", 'logo.svg' in r.text and 'href="/timeline"' in r.text
     and 'href="/backups"' in r.text and 'href="/reports"' in r.text)
r = anon.get(f"/vpgs/{V1['id']}")
step("VPG page: trends charts, timeline, tests", r.status_code == 200 and "<svg" in r.text and "PauseProtectionGroup" in r.text
     and "quarterly test" in r.text, r.status_code)
r = anon.get("/timeline?zorg=Acme&days=400")
step("timeline page filters by zORG", r.status_code == 200 and "UpdateProtectionGroup" in r.text)
r = anon.get("/backups")
step("backups page lists VPGs, shows the deleted one as restorable", r.status_code == 200 and "Gone-VPG" in r.text and "deleted" in r.text)
step("anonymous can't open a backup's contents", anon.get(f"/backups/{gone['id']}", follow_redirects=False).status_code in (303, 401, 403))
r = eng.get(f"/backups/{newest['id']}")
step("engineer opens a backup: diff shown, script parameter never", r.status_code == 200 and "Basic.RpoInSeconds" in r.text
     and SECRET_PARAM not in r.text and "(set - hidden)" in r.text, r.status_code)
r = eng.get(f"/backups/{gone['id']}/restore")
step("restore preview: engineer sees it, no start button", r.status_code == 200 and "Restore the VPG</button>" not in r.text)
r = adm.get(f"/backups/{gone['id']}/restore")
step("restore preview: admin gets the start form", "Restore the VPG</button>" in r.text)
r = anon.get("/zorgs/Acme")
step("zORG page: plans section with the gap, report links, recent activity", r.status_code == 200 and "Acme DR" in r.text
     and "Not in any plan" in r.text and f"/reports/Acme/{month}" in r.text and "Failover tests" in r.text)
r = eng.get(f"/zorgs/Acme/plan?site={SITE}&id={PLAN['id']}")
step("plan editor prefilled from the existing plan", r.status_code == 200 and f'name="tier_{VPGS[1]["id"]}" min="1" max="10" value="2"' in r.text, r.status_code)
r = eng.post("/zorgs/Acme/plan", data={"site": SITE, "name": "Acme DR", "type": "Standard", "action": "preview",
                                       f"tier_{VPGS[0]['id']}": "1", "wait_1": "1"})
step("plan preview shows the order and what's left out", r.status_code == 200 and "Tier 1" in r.text and "Not in the plan" in r.text)
step("plan editor is engineer-only", anon.get("/zorgs/Acme/plan", follow_redirects=False).status_code in (303, 401, 403))
import re as _re  # noqa: E402
nested = [p.name for p in (ROOT / "templates").glob("*.html")
          if _re.search(r"<label[^>]*>(?:(?!</label>).)*<select", p.read_text(encoding="utf-8"), _re.S)]
step("no <select> sits inside a <label> (Chromium closes the picker)", not nested, nested)
r = anon.get("/timeline")
step("timeline filters render as captioned selects", r.status_code == 200 and r.text.count('class="fld"') == 3
     and 'aria-label="zORG"' in r.text)
r = anon.get("/reports")
step("reports index", r.status_code == 200 and "Monthly DR reports" in r.text)
r = anon.get(f"/reports/Acme/{month}")
step("report page renders: branded, KPIs, test, plan", r.status_code == 200 and "Disaster recovery report" in r.text
     and "data:image/svg+xml;base64," in r.text and "quarterly test" in r.text and "Acme DR" in r.text)
r = anon.get(f"/reports/Acme/{month}/pdf", follow_redirects=False)
step("PDF: a file, or (no WeasyPrint here) a clear way back", r.status_code == 200 and r.content[:4] == b"%PDF"
     or (r.status_code == 303 and "WeasyPrint" in r.headers.get("location", "").replace("+", " ").replace("%20", " ")),
     (r.status_code, r.headers.get("location", "")[:160]))
r = anon.get(f"/vras/{SITE}")
step("VRA page: hot spot tag and section", r.status_code == 200 and "hot spot: VM1a" in r.text and "Replication hot spots" in r.text)
step("API: resize history without bodies", all("request_json" not in p for p in anon.get(f"/api/vras/{SITE}").json()["pushes"]))
r = adm.get("/admin")
step("admin: changes section with restore/plan switches and the log", "Changes to Zerto" in r.text and 'name="restores"' in r.text
     and "plan_create" in r.text)
r = adm.post("/admin/changes", data={"restores": "", "plans_on": "1", "backup_days": "200"}, follow_redirects=False)
step("switches saved; retention capped at 90 days", db.get_setting("backup_days") == "90" and not backups.enabled_restore()
     and plans.enabled())


print("\n=== dashboard filters ===")
FV = [vpg(1, "Acme", status="NotMeetingSLA", rpo=2400), vpg(2, "Acme", status="RpoNotMeetingSLA", rpo=900),
      vpg(4, "Beta", status="NotMeetingSLA", rpo=2400)]
db.save_snapshot(SID, True, None, 10, payload(FV))
names = lambda r: sorted(n for n in (v["name"] for v in FV) if f'>{n}</a>' in r.text)  # noqa: E731
r = anon.get("/")
step("unfiltered: all three unhealthy VPGs, filter bar shown", names(r) == sorted(v["name"] for v in FV) and 'name="zvm"' in r.text, names(r))
r = anon.get("/?health=failure")
step("state=failure: only failures", names(r) == sorted([FV[0]["name"], FV[2]["name"]]) and "2 of 3 VPGs" in r.text, names(r))
r = anon.get("/?zorg=Beta")
step("zORG filter", names(r) == [FV[2]["name"]], names(r))
r = anon.get("/?q=vpg-2")
step("VPG name filter (case-insensitive, contains)", names(r) == [FV[1]["name"]], names(r))
r = anon.get(f"/?zvm={SITE}")
step("ZVM filter: VPGs that ZVM reports", names(r) == sorted(v["name"] for v in FV), names(r))
r = anon.get("/?zvm=NoSuchZVM")
step("no match says so", names(r) == [] and "matches this filter" in r.text)
r = eng.get("/?zorg=Acme")
step("ignore/team-fix forms return to the filtered view", 'name="back" value="/?zorg=Acme"' in r.text)
step("the counts at the top stay estate-wide", '<div class="v fail">2</div>' in anon.get("/?zorg=Beta").text)
print("\n=== global alert-code ignores ===")
def warn_vpg(i, org, codes, status="MeetingSLA", rpo=10):
    v = vpg(i, org, status=status, rpo=rpo)
    v["alerts"] = [{"id": c, "level": "Warning", "text": f"{c} on VPG {v['name']}", "since": "2026-10-06T10:00:00"} for c in codes]
    v["alert_status"] = 1
    v["health"] = classify(v["status"], v["sub"], v["rpo"], 1)
    return v
CV = [warn_vpg(1, "Acme", ["VPG0035"]), warn_vpg(2, "Acme", ["VPG0035", "VRA0040"]),
      warn_vpg(3, "Acme", ["VPG0035"], status="NotMeetingSLA", rpo=4000), warn_vpg(4, "Beta", ["VPG0036"])]
db.save_snapshot(SID, True, None, 10, payload(CV))
r = eng.post("/admin/code-ignores", data={"code": "VPG0035", "days": "0", "note": "accepted zORG mapping"}, follow_redirects=False)
step("an engineer can't ignore a code globally", r.status_code == 403 and not db.list_code_ignores())
r = adm.post("/admin/code-ignores", data={"code": "vpg 0035", "days": "0", "note": "accepted zORG mapping"}, follow_redirects=False)
step("a malformed code is refused", not db.list_code_ignores())
r = adm.post("/admin/code-ignores", data={"code": "vpg0035", "days": "0", "note": "accepted zORG mapping"}, follow_redirects=False)
step("an admin ignores VPG0035 (normalised to upper case)", [c["code"] for c in db.list_code_ignores()] == ["VPG0035"])
mv = views.merged_vpgs()
step("a VPG whose only alert is VPG0035 is ignored (global)", (mv[CV[0]["id"]].get("ignored") or {}).get("scope") == "code")
step("...one with VPG0035 AND another alert still counts", not mv[CV[1]["id"]].get("ignored"))
step("...one with VPG0035 and an RPO failure still counts", not mv[CV[2]["id"]].get("ignored"))
step("...other codes are untouched", not mv[CV[3]["id"]].get("ignored"))
ov = views.overview()
step("counts drop it; it's listed under ignored", ov["totals"]["ignored"] == 1 and CV[0]["id"] not in {v["key"] for v in ov["vpgs"]})
step("alerting never sees it (not in the zORG's bad VPGs)",
     CV[0]["id"] not in next(o for o in views.zorg_list() if o["name"] == "Acme")["bad"])
r = anon.get("/")
step("dashboard badge names the code and says global", "ignored: VPG0035 (global)" in r.text)
r = adm.get("/admin")
step("admin page lists it, with how many VPGs it hides now", "Ignored Zerto alert codes" in r.text and "1 VPG<" in r.text, r.status_code)
adm.post("/admin/code-ignores/VPG0035/delete", follow_redirects=False)
step("removed: it alerts normally again", not db.list_code_ignores() and not views.merged_vpgs()[CV[0]["id"]].get("ignored"))
if os.environ.get("ZM_DUMP"):
    out = Path(os.environ["ZM_DUMP"])
    out.mkdir(exist_ok=True)
    static = (ROOT / "static").as_uri() + "/"
    for fname, cl, url in (("report.html", anon, f"/reports/Acme/{month}"), ("vpg.html", anon, f"/vpgs/{V1['id']}"),
                           ("zorg.html", eng, "/zorgs/Acme"), ("vras.html", anon, f"/vras/{SITE}"),
                           ("backup.html", eng, f"/backups/{newest['id']}"), ("plan.html", eng, f"/zorgs/Acme/plan?site={SITE}&id={PLAN['id']}"),
                           ("admin.html", adm, "/admin"), ("dash.html", eng, "/?health=failure")):
        (out / fname).write_text(cl.get(url).text.replace('"/static/', '"' + static), encoding="utf-8")
print("\nALL GOOD" if not FAILED else f"\nFAILED {len(FAILED)}:\n   - " + "\n   - ".join(FAILED))
sys.exit(1 if FAILED else 0)
