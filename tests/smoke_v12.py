"""Local verification for Zerto Monitor 1.2: ignores, VRA sizing, suggested fixes,
roles + require-login, responsive tables, and the plaintext-secret fixes.

Runs against an EMPTY temporary data dir with synthetic snapshots (shaped from a
real appliance export), so nothing polls a real ZVM.
"""
import copy
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(__file__).resolve().parent / "fixtures"
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke12-"))
os.environ["DATA_DIR"] = str(TMP)
os.environ["TLS_DIR"] = str(TMP / "tls")
os.environ["ADMIN_SOCKET"] = str(TMP / "no-such.sock")
os.environ["OVFENV_STATE"] = str(TMP / "ovfenv.state")
from cryptography.fernet import Fernet  # noqa: E402
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
sys.path.insert(0, str(ROOT / "app"))

FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)) if detail else ''}")
    if not ok:
        FAILED.append(desc)


import alerts  # noqa: E402
import auth  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import playbook  # noqa: E402
import tlsmgr  # noqa: E402
import views  # noqa: E402
from zerto import classify  # noqa: E402

db.init()

# ═════════════════════════════════════════════════════════ ovfscrub (pure)
print("=== zerto-monitor-ovfscrub ===")
loader = importlib.machinery.SourceFileLoader("ovfscrub", str(ROOT / "deploy/appliance/zerto-monitor-ovfscrub"))
spec = importlib.util.spec_from_loader("ovfscrub", loader)
ovf = importlib.util.module_from_spec(spec)
loader.exec_module(ovf)

ENV = """<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1"
     xmlns:ve="http://www.vmware.com/schema/ovfenv" oe:id="" ve:vCenterId="vm-1234">
   <PlatformSection><Kind>VMware ESXi</Kind></PlatformSection>
   <PropertySection>
         <Property oe:key="instance-id" oe:value="zerto-monitor-1"/>
         <Property oe:key="user-data" oe:value="I2Nsb3VkLWNvbmZpZw=="/>
         <Property oe:key="zm-admin-password" oe:value="Adm&quot;in&gt;pw&lt;1"/>
         <Property oe:key="zm-admin-user" oe:value="zmops"/>
         <Property oe:key="zm-hostname" oe:value="ZERTOMON01"/>
         <Property oe:value="ro>ot'pw2" oe:key="zm-root-password"/>
         <Property oe:key="zm-ssh-key" oe:value="ssh-ed25519 AAAAC3Nza zmops@ws"/>
         <Property oe:key="zm-payload0" oe:value="QUJDREVGR0g="/>
         <Property oe:key="zm-payload1" oe:value="SUpLTE1OT1A="/>
         <Property oe:key="zm-web-password" oe:value=""/>
         <Property oe:key="zm-zvm-password" oe:value='single&apos;quoted'/>
   </PropertySection>
</Environment>"""
props = ovf.properties(ENV)
step("parses every property (incl. value-before-key and single quotes)", props is not None and len(props) == 11, props and sorted(props))
step("held_secrets names the populated secrets only",
     ovf.held_secrets(props) == ["zm-admin-password", "zm-root-password", "zm-zvm-password"], ovf.held_secrets(props))
clean = ovf.scrub(ENV)
after = ovf.properties(clean)
step("scrub(): no secret survives (checked by a real XML parse)", after is not None and ovf.held_secrets(after) == [])
step("scrub(): '>' and quotes inside a value don't defeat it", "ro>ot" not in clean and "Adm&quot;in" not in clean)
step("scrub(): install payload and user-data blanked", after["zm-payload0"] == "" and after["user-data"] == "")
step("scrub(): everything else byte-for-byte", after["zm-hostname"] == "ZERTOMON01" and after["zm-ssh-key"].startswith("ssh-ed25519")
     and after["instance-id"] == "zerto-monitor-1" and set(after) == set(props))
step("scrub() is idempotent", ovf.scrub(clean) == clean)
step("a blanked copy is recognisably not fresh from vCenter",
     not any(v for k, v in after.items() if ovf.BULK.match(k)))
step("unparseable environment -> None (never 'clean')", ovf.properties("<Environment><Property oe:key='a'") is None)

# ═════════════════════════════════════════════════════════ session key
print("\n=== session key ===")
cred = TMP / "creds"
cred.mkdir()
(cred / "session.key").write_text("from-systemd-credential\n")
os.environ["CREDENTIALS_DIRECTORY"] = str(cred)
step("LoadCredential session.key wins over the data dir", auth._secret() == "from-systemd-credential")
step("  ...and is reported as such", auth.session_key_source().startswith("systemd:"))
del os.environ["CREDENTIALS_DIRECTORY"]
step("importing auth created no key file", not (TMP / "secret.key").exists() or auth._KEY is not None)
fb = (ROOT / "deploy/appliance/firstboot.py").read_text(encoding="utf-8")
step("service unit loads session.key as a credential", "LoadCredential=session.key:" in fb)
step("upgrade + first boot move/create the session key", fb.count("make_session_key()") >= 3)
step("first boot + upgrade lock down the OVF environment", fb.count("lock_down_ovf_environment()") >= 3)
step("cloud-init is disabled after configuration", "/etc/cloud/cloud-init.disabled" in fb)
step("seeding passes secrets on stdin, not the environment", "ZM_WEB_PW" not in fb and "ZM_ZVM_PW" not in fb and "input=payload" in fb)
step("nginx sets X-Forwarded-For itself (not client-appendable)", "X-Forwarded-For $remote_addr" in fb
     and "$proxy_add_x_forwarded_for" not in fb)

# ═════════════════════════════════════════════════════════ synthetic data
print("\n=== synthetic snapshot ===")
snap = json.loads((SCRATCH / "snapshot.json").read_text(encoding="utf-8"))
real = next(s for s in snap["snapshots"] if s["payload"] and s["payload"]["site"] == "Site-A")["payload"]
tmpl_vpg = next(v for v in real["vpgs"] if v["health"] == "healthy")
tmpl_vra = real["vras"][0]


def vpg(i, org, status="MeetingSLA", sub="None", rpo=10, rpo_cfg=300, alerts_=(), astat=0):
    v = copy.deepcopy(tmpl_vpg)
    v.update(id=f"vpg-{i}", name=f"VPG-{i}", org=org, zorg_id=f"z-{org}", status=status, sub=sub, rpo=rpo,
             rpo_cfg=rpo_cfg, alert_status=astat, direction="inbound", on_disconnected_vra=[],
             alerts=[{"id": c, "level": lvl, "text": f"{c} for VM vm{i}-01 in VPG VPG-{i}", "since": "2026-10-05T10:00:00"}
                     for c, lvl in alerts_])
    v["health"] = classify(status, sub, rpo, astat)
    return v


def vra(i, mem, cpus, host=None, cluster=None):
    r = copy.deepcopy(tmpl_vra)
    r.update(id=str(1000 + i), host=host or f"esx{i:02d}.site-a.example.invalid", mem_gb=mem, cpus=cpus,
             disconnected=False, mask_mismatch=False, status=0, version="10.9.0",
             cluster=cluster, cluster_id=f"domain-c{len(cluster)}" if cluster else None, progress=0, is_ghost=False)
    return r


def payload(vpgs, vras):
    p = copy.deepcopy(real)
    p["vpgs"], p["vras"], p["alerts"] = vpgs, vras, []
    p["counts"] = {"vpgs": len(vpgs), "failure": sum(v["health"] == "failure" for v in vpgs),
                   "warning": sum(v["health"] == "warning" for v in vpgs),
                   "healthy": sum(v["health"] == "healthy" for v in vpgs), "vras": len(vras)}
    return p


# .invalid is reserved (RFC 2606): even if a poll slipped through, it can't reach a real ZVM
SID = db.add_source("Site-A", "zvm", "zvm.invalid", "password", "u", crypto.encrypt("p"), False)
STATE = {}


def load(*vpgs):
    STATE["vpgs"] = list(vpgs)
    db.save_snapshot(SID, True, None, 10, payload(list(vpgs), STATE.get("vras") or []))


STATE["vras"] = [vra(1, 16, 4, cluster="Prod-B"), vra(2, 16, 4, cluster="Prod-A"),
                 vra(3, 8, 2, cluster="Prod-A"), vra(4, 32, 8)]
V1 = vpg(1, "Globex", alerts_=[("VPG0035", "Warning")], astat=1)
V2 = vpg(2, "Globex", status="NotMeetingSLA", rpo=9000)
V3 = vpg(3, "OtherCo")
V4 = vpg(4, "OtherCo", alerts_=[("VPG0040", "Warning")], astat=1)
load(V1, V2, V3, V4)
step("fixture: V1 warning, V2 failure, V3 healthy, V4 warning",
     [V1["health"], V2["health"], V3["health"], V4["health"]] == ["warning", "failure", "healthy", "warning"])
ov = views.overview()
step("no ignores: 1 failure + 2 warnings need attention", (ov["totals"]["failure"], ov["totals"]["warning"], ov["totals"]["ignored"]) == (1, 2, 0), ov["totals"])

# ═════════════════════════════════════════════════════════ ignores
print("\n=== ignores ===")
merged = views.merged_vpgs()
db.save_ignore("vpg", "vpg-1", "VPG-1", "ack", {"vpg-1": views.ignore_snapshot(merged["vpg-1"])}, "known", "eng", None)
ov = views.overview()
step("ack on V1: warning count drops, ignored = 1", (ov["totals"]["warning"], ov["totals"]["ignored"]) == (1, 1), ov["totals"])
step("  ...V1 listed under ignored, health unchanged", [v["key"] for v in ov["ignored_vpgs"]] == ["vpg-1"]
     and ov["ignored_vpgs"][0]["health"] == "warning")
m = views.metrics()
step("  ...SNMP metrics agree (warning excludes it, ignored counts it)", m["warning"] == 1 and m["ignored"] == 1, m)

V1b = vpg(1, "Globex", alerts_=[("VPG0035", "Warning"), ("VPG0040", "Warning")], astat=1)
load(V1b, V2, V3, V4)
v1 = views.merged_vpgs()["vpg-1"]
step("new alert code lifts the ack", not v1["ignored"] and "new alert VPG0040" in (v1["ignore_lapsed"] or {}).get("why", ""), v1.get("ignore_lapsed"))
V1c = vpg(1, "Globex", alerts_=[("VPG0035", "Warning")], astat=2)
load(V1c, V2, V3, V4)
v1 = views.merged_vpgs()["vpg-1"]
step("higher Zerto AlertStatus lifts the ack", not v1["ignored"] and "alert level" in v1["ignore_lapsed"]["why"], v1["ignore_lapsed"])
V1d = vpg(1, "Globex", status="NotMeetingSLA", rpo=9000, alerts_=[("VPG0035", "Warning")], astat=1)
load(V1d, V2, V3, V4)
v1 = views.merged_vpgs()["vpg-1"]
step("worse replication lifts the ack", not v1["ignored"] and "replication now failure" in v1["ignore_lapsed"]["why"], v1["ignore_lapsed"])
load(V1, V2, V3, V4)
step("back to what was acknowledged: ignored again", views.merged_vpgs()["vpg-1"]["ignored"] is not None)

db.save_ignore("zorg", "OtherCo", "OtherCo", "all", {}, "", "eng", None)
mv = views.merged_vpgs()
step("zORG 'everything' ignore covers its warning VPG", mv["vpg-4"]["ignored"] is not None)
step("  ...and is shown on its healthy VPG too", (mv["vpg-3"].get("ignore_set") or {}).get("scope") == "zorg")
past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds")
db.save_ignore("zorg", "OtherCo", "OtherCo", "all", {}, "", "eng", past)
step("an expired ignore no longer applies", views.merged_vpgs()["vpg-4"]["ignored"] is None)
db.save_ignore("zorg", "OtherCo", "OtherCo", "all", {}, "", "eng", None)

zl = {o["name"]: o for o in views.zorg_list()}
step("zORG list: OtherCo has nothing needing attention, 1 ignored",
     zl["OtherCo"]["warning"] == 0 and zl["OtherCo"].get("ignored") == 1, {k: zl["OtherCo"].get(k) for k in ("failure", "warning", "ignored")})

print("\n=== ignores x alert engine ===")
for k in ("alerts_enabled",):
    db.set_setting(k, "true")
db.set_setting("alert_default_recipients", "noc@example.invalid")
db.set_setting("smtp_host", "smtp.example.com")
db.save_alert_rule("*", 15, 60, "", True, False, True)
sent = []
REAL_SEND_EMAIL = alerts.send_email
alerts.send_email = lambda to, s, t, h=None: sent.append(s)
T0 = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
for igid in [i["id"] for i in db.list_ignores(False)]:
    db.delete_ignore(igid)
alerts.evaluate(now=T0)
ev = alerts.evaluate(now=T0 + timedelta(minutes=16))
step("Globex failing 16 min -> raised", any(e["name"] == "Globex" and e["event"] == "raised" for e in ev), [(e["name"], e["event"]) for e in ev])
db.save_ignore("zorg", "Globex", "Globex", "all", {}, "", "eng", None)
ev = alerts.evaluate(now=T0 + timedelta(minutes=17))
step("ignoring the whole zORG: no false 'cleared' email", not any(e["name"] == "Globex" for e in ev), [(e["name"], e["event"]) for e in ev])
step("  ...but the alert stands down", db.zorg_states()["Globex"]["alerted"] == "")
for igid in [i["id"] for i in db.list_ignores(False)]:
    db.delete_ignore(igid)

# ═════════════════════════════════════════════════════════ VRA sizing
print("\n=== VRA sizing (raise-only, flags) ===")
std = {"memory_gb": 16, "cpus": 4, "allow_lower": 0}
c = views.vra_compliance
OKV = {"id": "1", "status": 0, "alert_status": 0, "version": "10.9.0", "zvm_version": "10.9.0.155"}
r = c({**OKV, "mem_gb": 8, "cpus": 2}, std, None)
step("below standard -> resize up to it", (r["state"], r["push"], r["push_mem"], r["push_cpus"]) == ("under", True, 16, 4), r)
step("  ...crossing the 8 GB boundary is flagged (host driver reload)", "tier_cross" in r["flags"], r["flags"])
r = c({**OKV, "mem_gb": 32, "cpus": 8}, std, None)
step("above -> never resized down by a rule; lowering is offered instead", (r["state"], r["push"], r["can_lower"]) == ("over", False, True), r)
r = c({**OKV, "mem_gb": 32, "cpus": 8}, {**std, "allow_lower": 1}, None)
step("the old allow_lower flag no longer lowers anything", r["push"] is False, r)
r = c({**OKV, "mem_gb": 32, "cpus": 2}, std, None)
step("mixed -> only the low dimension rises (32/2 -> 32/4)", (r["state"], r["push_mem"], r["push_cpus"]) == ("mixed", 32, 4), r)
r = c({**OKV, "mem_gb": 16, "cpus": 4}, std, {"memory_gb": 24, "cpus": 6})
step("a pin beyond 16/4 without a Zerto reference isn't resizable", r["pinned"] and "beyond_guidance" in r["flags"] and not r["push"], r)
r = c({**OKV, "mem_gb": 16, "cpus": 4}, std, {"memory_gb": 24, "cpus": 6, "support_ref": "ZTO-1234"})
step("  ...with a reference it is (16/4 -> 24/6)", r["push"] and (r["push_mem"], r["push_cpus"]) == (24, 6), r)
r = c({**OKV, "version": "10.8.0", "mem_gb": 8, "cpus": 2}, std, None)
step("a VRA behind its ZVM's version is blocked (upgrade it first)", "version_lag" in r["flags"] and not r["push"], r["flags"])
r = c({**OKV, "alert_status": 1, "mem_gb": 8, "cpus": 2}, std, None)
step("a VRA with an alert status is blocked (Status 0 alone proves nothing)", "unhealthy" in r["flags"] and not r["push"])
r = c({**OKV, "id": None, "mem_gb": 8, "cpus": 2}, std, None)
step("no VRA identifier -> nothing to resize", r["push"] is False and "no_id" in r["flags"])
step("no standard -> unset", c({**OKV, "mem_gb": 8, "cpus": 2}, None, None)["state"] == "unset")
step("pins are keyed by host, not VRA id", views.vra_key("S", {"id": "77", "host": "ESX03.site-a.example.invalid"}) == "S|esx03")
db.save_vra_standard("Site-A", 16, 4, False, "", "eng")
vs = views.vras_site("Site-A")
step("site view: 2 at target, 1 below, 1 above; 1 resizable", (vs["sizing"]["ok"], vs["sizing"]["under"], vs["sizing"]["over"], vs["sizing"]["pushable"]) == (2, 1, 1, 1), vs["sizing"])
step("  ...most common size offered", vs["common"] == {"memory_gb": 16, "cpus": 4, "count": 2}, vs["common"])

print("\n=== VRAs by cluster ===")
step("grouped by cluster, sorted by name, unknown last",
     [c["name"] for c in vs["clusters"]] == ["Prod-A", "Prod-B", views.NO_CLUSTER], [c["name"] for c in vs["clusters"]])
step("  ...hosts sorted inside each cluster", [r["host"] for r in vs["clusters"][0]["vras"]] == ["esx02.site-a.example.invalid", "esx03.site-a.example.invalid"])
db.save_vra_cluster_standard("Site-A", "Prod-A", 12, 4, False, "bigger hosts", "eng")
vs = views.vras_site("Site-A")
a = {r["host"]: r["sizing"] for r in vs["vras"]}
step("cluster override beats the site standard (Prod-A -> 12G/4)",
     a["esx03.site-a.example.invalid"]["source"] == "cluster" and (a["esx03.site-a.example.invalid"]["push_mem"], a["esx03.site-a.example.invalid"]["push_cpus"]) == (12, 4), a["esx03.site-a.example.invalid"])
step("  ...and a bigger VRA in that cluster is left alone", a["esx02.site-a.example.invalid"]["state"] == "over" and not a["esx02.site-a.example.invalid"]["push"])
step("  ...other clusters still follow the site standard", a["esx01.site-a.example.invalid"]["source"] == "site")
db.save_vra_pin("Site-A|esx03", "Site-A", "esx03.site-a.example.invalid", 10, 2, "", "eng")
step("a pin beats the cluster override", {r["host"]: r for r in views.vras_site("Site-A")["vras"]}["esx03.site-a.example.invalid"]["sizing"]["source"] == "pin")
db.delete_vra_pin("Site-A|esx03")
cl_a = next(c for c in views.vras_site("Site-A")["clusters"] if c["name"] == "Prod-A")
step("cluster header counts", cl_a["counts"] == {"total": 2, "ok": 0, "below": 1, "pushable": 1} and cl_a["override"]["memory_gb"] == 12, cl_a["counts"])

# ═════════════════════════════════════════════════════════ VRA resize engine
print("\n=== VRA resize: request body + API guards ===")
import requests  # noqa: E402
import zerto  # noqa: E402
import vrapush  # noqa: E402
CUR = {"VraIdentifier": 1003, "HostDisplayName": "esx03.site-a.example.invalid", "HostIdentifier": "host-3", "MemoryInGB": 8,
       "NumOfCpus": 2, "VraGroup": "default_group", "Status": 0, "VraAlerts": {"VraAlertsStatus": 0}, "IsGhost": False,
       "DatastoreIdentifier": "ds-1", "NetworkIdentifier": "net-1", "VraVersion": "10.9.0",
       "VraNetworkDataApi": {"VraIPConfigurationTypeApi": "Static", "VraIPAddress": "192.0.2.13",
                             "VraIPAddressRangeEnd": None, "SubnetMask": "255.255.254.0", "DefaultGateway": "192.0.2.1"}}
b = zerto.build_resize_body(CUR, 12, 4)
step("body: both sizes, camelCase, group + network echoed exactly, public-key mode explicit",
     b == {"memoryInGb": 12, "numOfCpus": 4, "groupName": "default_group",
           "vraNetworkDataApi": {"vraIPConfigurationTypeApi": "Static", "vraIPAddress": "192.0.2.13", "vraIPAddressRangeEnd": None,
                                 "subnetMask": "255.255.254.0", "defaultGateway": "192.0.2.1"},
           "usePublicKeyInsteadOfCredentials": True}, b)
for bad, why in (({**CUR, "VraGroup": ""}, "empty group"), ({**CUR, "VraNetworkDataApi": None}, "no network"),
                 ({**CUR, "VraNetworkDataApi": {**CUR["VraNetworkDataApi"], "Extra": 1}}, "unknown network field"),
                 ({**CUR, "VraNetworkDataApi": {**CUR["VraNetworkDataApi"], "VraIPConfigurationTypeApi": None}}, "no IP config type")):
    try:
        zerto.build_resize_body(bad, 12, 4)
        step(f"  refuses to build a body from a VRA with {why}", False)
    except zerto.ZvmError:
        step(f"  refuses to build a body from a VRA with {why}", True)
step("task id from a bare string or a legacy object", zerto.parse_task_id('"abc-1"') == "abc-1"
     and zerto.parse_task_id({"TaskIdentifier": "t-2"}) == "t-2" and zerto.parse_task_id({"x": 1}) is None)
zc = zerto.ZvmClient("zvm.invalid", "client_credentials", "c", "s")
zc.base, zc.headers = "https://zvm.invalid", {}
for path in ("/v1/vras/1003/upgrade", "/v1/vras", "/v1/vras/clusters/c1/settings", "/v1/vpgs/x"):
    try:
        zc.put(path, {})
        step(f"  the client refuses any write but PUT /v1/vras/{{id}}: {path}", False)
    except zerto.ZvmError:
        step(f"  the client refuses any write but PUT /v1/vras/{{id}}: {path}", True)

# a site that reports its VPGs on each VRA by host id
def vpg_on(i, org, prot=None, rec=None, **kw):
    v = vpg(i, org, **kw)
    v["members"] = [{"name": f"vm{i}", "protected_host": "x", "recovery_host": "y",
                     "protected_host_id": prot, "recovery_host_id": rec}]
    v.update(history_cfg_min=1440, testing=False, protected_site="Site-A", recovery_site="Site-B")
    return v


def resize_fixture(**vra3):
    r3 = vra(3, 8, 2, cluster="Prod-A")
    r3.update(host_id="host-3", group="default_group", ip_config="Static", ip="192.0.2.13", mask="255.255.254.0",
              gw="192.0.2.1", version="10.9.0", alert_status=0, protected_vpgs=1, recovery_vpgs=1)
    r3.update(vra3)
    STATE["vras"] = [vra(1, 16, 4, cluster="Prod-B"), vra(2, 16, 4, cluster="Prod-A"), r3, vra(4, 32, 8)]
    vp = [vpg_on(11, "Acme", prot="host-3"), vpg_on(12, "Beta", rec="host-3"), vpg_on(13, "Gamma", prot="host-9")]
    STATE["vpgs"] = vp
    p = payload(vp, STATE["vras"])
    p.update(version="10.9.0.155", flavour="appliance")
    db.save_snapshot(SID, True, None, 10, p)


resize_fixture()
db.delete_vra_cluster_standard("Site-A", "Prod-A")
KEY3 = "Site-A|esx03"
pl = vrapush.plan("Site-A", KEY3)
step("blast radius found by host id: 1 protected + 1 recovering, and it matches Zerto's counts",
     (pl["affected"]["protected"], pl["affected"]["recovery"], pl["affected"]["counts_match"]) == (1, 1, True),
     [(v["name"], v["roles"]) for v in pl["affected"]["vpgs"]])
step("disarmed by default: G1 blocks with every missing piece", any(g["id"] == "G1" for g in pl["blocking"])
     and len(next(g for g in pl["gates"] if g["id"] == "G1")["detail"]) >= 4)
step("preview shows the exact request", pl["request"]["body"]["memoryInGb"] == 16 and pl["request"]["body"]["usePublicKeyInsteadOfCredentials"] is True)

print("\n=== VRA resize: arming + gates ===")
db.set_setting("vra_push_enabled", "true")
db.set_source_allow_changes(SID, True)
db.set_source_push(SID, push_identity=crypto.encrypt("zm-resize"), push_secret_enc=crypto.encrypt("resize-secret-1"),
                   push_cert_fp="ab:" * 31 + "ab", push_host_auth="vib")
pl = vrapush.plan("Site-A", KEY3)
step("armed, healthy, current, in step with Zerto -> no blocking gate", pl["blocking"] == [], [(g["id"], g["detail"]) for g in pl["blocking"]])
step("  ...memory raise asks for host headroom; 8->16 asks for a maintenance window",
     pl["needs"]["headroom_gb"] == 8 and pl["needs"]["tier_cross"] is True)
STATE["vpgs"][1]["sub"] = "BitmapSync"
db.save_snapshot(SID, True, None, 10, {**payload(STATE["vpgs"], STATE["vras"]), "version": "10.9.0.155", "flavour": "appliance"})
step("G10: an affected VPG mid-sync blocks it (Status alone would let it through)",
     any(g["id"] == "G10" for g in vrapush.plan("Site-A", KEY3)["blocking"]))
resize_fixture(version="10.8.0")
step("G6: VRA behind the ZVM version blocks it", any(g["id"] == "G6" for g in vrapush.plan("Site-A", KEY3)["blocking"]))
resize_fixture(recovery_vpgs=5)
step("G9: our blast radius disagreeing with Zerto's counts blocks it", any(g["id"] == "G9" for g in vrapush.plan("Site-A", KEY3)["blocking"]))
resize_fixture()
pl = vrapush.plan("Site-A", KEY3)
ADMIN, ENG = {"username": "admin", "role": "admin"}, {"username": "eng", "role": "engineer"}
FORM = {"plan_hash": pl["plan_hash"], "ticket": "CHG-1", "ack_outage": "yes", "ack_vib": "yes", "ack_headroom": "yes", "ack_tier": "yes"}
for who, form, why in ((ENG, FORM, "an engineer"), (ADMIN, {**FORM, "ticket": ""}, "no ticket"),
                       (ADMIN, {**FORM, "ack_headroom": ""}, "no headroom check"), (ADMIN, {**FORM, "plan_hash": "stale"}, "a stale preview")):
    try:
        vrapush.start("Site-A", KEY3, False, who, form)
        step(f"start refused: {why}", False)
    except vrapush.PushError as e:
        step(f"start refused: {why}", True, str(e)[:70])


class Clock:
    def __init__(self): self.t = 0.0
    def now(self): return self.t
    def sleep(self, s): self.t += s


class FakeZvm:
    """A ZVM that resizes: GET before/after, a task, alerts. Behaviour per scenario."""
    def __init__(self, tasks=(1, 6), after=None, conflicts=(), put_raises=None, cur=None, alerts=()):
        self.tasks, self.after, self.conflicts = list(tasks), after, list(conflicts)
        self.put_raises, self.cur, self.alerts = put_raises, cur or copy.deepcopy(CUR), list(alerts)
        self.puts, self.sent = [], False

    def login(self): pass

    def get(self, path):
        if path.startswith("/v1/vras/"):
            return copy.deepcopy(self.after if (self.sent and self.after is not None) else self.cur)
        if path.startswith("/v1/tasks?status="):
            return self.conflicts if path.endswith("=1") else []
        if path == "/v1/alerts":
            return self.alerts
        raise zerto.ZvmError(f"unexpected GET {path}")

    def task(self, t):
        s = self.tasks.pop(0) if len(self.tasks) > 1 else self.tasks[0]
        return {"Status": {"State": s, "Progress": 100 if s == 6 else 40}, "CompleteReason": "VRA did not power on", "Type": "EditVra"}

    def put(self, path, body):
        self.puts.append((path, body))
        if self.put_raises:
            raise self.put_raises
        self.sent = True
        return 200, "task-77"


AFTER = {**copy.deepcopy(CUR), "MemoryInGB": 16, "NumOfCpus": 4}


def go(fake, **kw):
    pl = vrapush.plan("Site-A", KEY3)
    pid = vrapush.start("Site-A", KEY3, False, ADMIN, {**FORM, "plan_hash": pl["plan_hash"]})
    seen = {}

    def refresh(sid):                      # VPGs stay healthy; note what's held mid-run
        seen["holds"] = seen.get("holds", set()) | set(db.active_holds())
        db.save_snapshot(SID, True, None, 10, {**payload(STATE["vpgs"], STATE["vras"]), "version": "10.9.0.155", "flavour": "appliance"})

    clk = Clock()
    vrapush.run_one(db.get_vra_push(pid), sleep=clk.sleep, clock=clk.now, refresh=kw.get("refresh", refresh),
                    client_factory=lambda src: fake)
    return db.get_vra_push(pid), seen


vrapush.pacing_problems = lambda site, ignore_push=None: []        # pacing is tested on its own below
print("\n=== VRA resize: runs (fake ZVM, fake clock) ===")
fz = FakeZvm(after=AFTER)
p, seen = go(fz)
step("success: one PUT, task followed, VRA back at 16/4, VPGs recovered -> done",
     len(fz.puts) == 1 and p["state"] == "done" and p["task_id"] == "task-77", (p["state"], p["detail"]))
step("  ...the affected VPGs were held while it ran, and released after",
     seen.get("holds") == {"vpg-11", "vpg-12"} and not db.active_holds(), seen)
step("  ...before/after, the exact request and the ticket are on record",
     json.loads(p["request_json"])["memoryInGb"] == 16 and p["before_json"] and p["after_json"] and p["ticket"] == "CHG-1")
step("  ...and no halt", vrapush.halted() is None)

resize_fixture()
fz = FakeZvm(after=AFTER, conflicts=[{"Type": "FailoverTest", "RelatedEntities": {"Vpgs": [{"identifier": "vpg-12"}]}}])
p, _ = go(fz)
step("a Zerto task touching an affected VPG -> refused, nothing sent", p["state"] == "refused" and not fz.puts, p["detail"][:90])
resize_fixture()
fz = FakeZvm(after=AFTER, cur={**copy.deepcopy(CUR), "MemoryInGB": 12})
p, _ = go(fz)
step("the live VRA differs from the preview -> refused, nothing sent", p["state"] == "refused" and not fz.puts, p["detail"][:90])

resize_fixture()
fz = FakeZvm(after=AFTER, tasks=(1, 4))
p, _ = go(fz)
step("a failed task -> failed with Zerto's reason, and resizing halts",
     p["state"] == "failed" and "VRA did not power on" in p["detail"] and vrapush.halted()["push_id"] == p["id"])
step("  ...the halt blocks the next one (G1) until acknowledged",
     any("halted" in d for g in vrapush.plan("Site-A", KEY3)["blocking"] for d in g["detail"]))
vrapush.acknowledge_halt("admin", "checked the VRA in vCenter, powered on")
step("  ...acknowledged with a note -> cleared and recorded", vrapush.halted() is None and db.get_vra_push(p["id"])["acked_by"] == "admin")

resize_fixture()
fz = FakeZvm(after=None)               # the VRA never comes back at the new size
p, _ = go(fz)
step("the VRA doesn't come back -> unknown, halted, holds kept until they expire",
     p["state"] == "unknown" and vrapush.halted() and db.active_holds(), p["detail"][:80])
vrapush.acknowledge_halt("admin", "powered the VRA on by hand per KB 4137")

resize_fixture()
fz = FakeZvm(after=AFTER, put_raises=requests.Timeout("lost"))
p, _ = go(fz)
step("no answer to the PUT -> never re-sent; VRA unchanged -> failed (probably not applied)",
     len(fz.puts) == 1 and p["state"] == "failed" and "probably not applied" in p["detail"], p["detail"][:90])
vrapush.acknowledge_halt("admin", "confirmed in Zerto nothing changed")

resize_fixture()
fz = FakeZvm(after={**copy.deepcopy(AFTER), "VraGroup": "other_group"})
p, _ = go(fz)
step("the VRA came back with a different group -> failed (drift)", p["state"] == "failed" and "VraGroup" in p["detail"], p["detail"][:90])
vrapush.acknowledge_halt("admin", "restored the bandwidth group in the Zerto UI")
for h in list(db.active_holds().values()):
    db.release_holds(h["push_id"], "test cleanup")

import importlib  # noqa: E402
importlib.reload(vrapush)              # real pacing again
vrapush.ZvmClient = FakeZvm
print("\n=== VRA resize: pacing ===")
db.update_vra_push(next(x["id"] for x in db.recent_vra_pushes("Site-A") if x["state"] == "done"),
                   finished_at=db.now_iso())
pp = vrapush.pacing_problems("Site-A")
step("30-minute cooldown after a clean resize", any("cooling down" in x for x in pp), pp)
step("24 h between resizes until five have succeeded", any("24 h apart" in x for x in pp), pp)
db.set_setting("vra_push_enabled", "false")
db.set_source_allow_changes(SID, False)

# ═════════════════════════════════════════════════════════ playbook
print("\n=== suggested fixes (playbook) ===")
load(V1, V2, V3, V4)                    # the resize tests replaced the fixture
pb_file = TMP / "playbook.json"
pb_file.write_text(json.dumps({"entries": {
    "VPG0035": {"title": "Journal", "fix": "Check {vm} in {vpg}", "caution": "", "source": "doc"},
    "cond:rpo-over-target": {"title": "RPO", "fix": "Look at {zorg}'s link", "caution": "may resync"},
    "status:NotMeetingSLA": {"title": "SLA", "fix": "generic"}}}), encoding="utf-8")
playbook.PLAYBOOK_FILE = pb_file
s = playbook.suggest(views.merged_vpgs()["vpg-1"])
step("alert entry filled from the alert text", s and s[0]["key"] == "VPG0035" and s[0]["fix"] == "Check vm1-01 in VPG-1", s)
s = playbook.suggest(views.merged_vpgs()["vpg-2"])
step("state entries, most specific first", [x["key"] for x in s] == ["cond:rpo-over-target", "status:NotMeetingSLA"], [x["key"] for x in s])
step("  ...with the zORG filled in", s[0]["fix"] == "Look at Globex's link")
step("no entry -> no advice invented", playbook.suggest(vpg(9, "X", alerts_=[("ZZZ9999", "Warning")], astat=1)) == [])
time.sleep(0.05)
pb_file.write_text(json.dumps({"entries": {"VPG0035": {"title": "J", "fix": "changed"}}}), encoding="utf-8")
os.utime(pb_file, (time.time() + 5, time.time() + 5))
step("edits to playbook.json are picked up without a restart", playbook.suggest(views.merged_vpgs()["vpg-1"])[0]["fix"] == "changed")
real_pb = ROOT / "app" / "playbook.json"
if real_pb.exists():
    data = json.loads(real_pb.read_text(encoding="utf-8"))
    bad = [k for k, e in data.get("entries", {}).items() if not e.get("fix")]
    unknown = sorted({p for e in data.get("entries", {}).values() for p in
                      playbook._PLACEHOLDER.findall(e.get("fix", "") + e.get("caution", "")) if p not in playbook.DEFAULTS})
    step(f"shipped playbook.json: {len(data.get('entries', {}))} entries, all with a fix", not bad, bad[:5])
    step("  ...only known placeholders", not unknown, unknown)
else:
    print("  (app/playbook.json not present yet - shipped-playbook checks skipped)")
playbook.PLAYBOOK_FILE = real_pb
playbook._cache.update(mtime=None, entries={})

# ═════════════════════════════════════════════════════════ secrets in motion
print("\n=== secrets in motion ===")
captured = {}


def fake_run(argv, **kw):
    conf = Path(kw["env"]["SNMPCONFPATH"]) / "snmp.conf"
    captured.update(argv=argv, env=kw["env"], conf=conf.read_text(), mode=oct(conf.stat().st_mode & 0o777))
    return type("P", (), {"returncode": 0, "stderr": "", "stdout": ""})()


orig_run = alerts.subprocess.run
alerts.subprocess.run = fake_run
orig_exists = alerts.Path.exists
alerts.Path.exists = lambda self: True if str(self).endswith("snmptrap") else orig_exists(self)
db.set_setting("snmp_trap_targets", "203.0.113.5")
db.set_setting("snmp_trap_community", crypto.encrypt("trap-secret-77"))
try:
    alerts.send_trap({"name": "X", "level": "warning", "event": "raised", "minutes": 1, "failure": 0, "warning": 1, "vpgs": 1,
                      "worst_rpo": "1m", "sites": []})
finally:
    alerts.subprocess.run = orig_run
    alerts.Path.exists = orig_exists
step("trap community is NOT on the command line", "trap-secret-77" not in " ".join(captured["argv"]) and "-c" not in captured["argv"], captured.get("argv", [])[:4])
step("  ...it's in a private snmp.conf instead", "defCommunity trap-secret-77" in captured["conf"] and "defVersion 2c" in captured["conf"])
step("  ...and that file is gone after the send", not Path(captured["env"]["SNMPCONFPATH"]).exists())
db.set_setting("snmp_trap_community", crypto.encrypt("bad comm\ndefVersion 1"))
try:
    alerts.send_trap({"name": "X", "level": "warning", "event": "raised", "minutes": 1, "failure": 0, "warning": 1, "vpgs": 1,
                      "worst_rpo": "1m", "sites": []})
    step("a community that could inject config is refused", False)
except alerts.AlertError as e:
    step("a community that could inject config is refused", "only contain" in str(e), e)


class FakeSMTP:
    calls = []

    def __init__(self, *a, **k): FakeSMTP.calls.append("connect")
    def ehlo(self): pass
    def starttls(self, **k): FakeSMTP.calls.append("starttls")
    def login(self, u, p): FakeSMTP.calls.append("LOGIN")
    def send_message(self, m): FakeSMTP.calls.append("send")
    def quit(self): pass


alerts.smtplib.SMTP = FakeSMTP
alerts.send_email = REAL_SEND_EMAIL
db.set_setting("smtp_security", "none")
db.set_setting("smtp_user", "relay-user")
db.set_setting("smtp_password", crypto.encrypt("smtp-pw-1"))
try:
    alerts.send_email(["a@b.c"], "s", "t")
    step("SMTP password never sent without TLS", False)
except alerts.AlertError:
    step("SMTP password never sent without TLS", "LOGIN" not in FakeSMTP.calls, FakeSMTP.calls)
FakeSMTP.calls.clear()
db.set_setting("smtp_security", "starttls")
alerts.send_email(["a@b.c"], "s", "t")
step("  ...and is sent after STARTTLS", FakeSMTP.calls == ["connect", "starttls", "LOGIN", "send"], FakeSMTP.calls)
db.set_setting("smtp_user", "")

# ═════════════════════════════════════════════════════════ roles + access
print("\n=== roles, access, redirects ===")
alerts._observations = lambda: []
from fastapi.testclient import TestClient  # noqa: E402
import collector  # noqa: E402
import main  # noqa: E402


async def _no_polling():                 # the app's lifespan must never poll from a test
    return None


collector.loop_forever = _no_polling
vrapush.worker = _no_polling             # ...nor resize anything

(TMP / "ovfenv.state").write_text("checked=2026-10-05T20:00:00Z\nguest=scrubbed\nsource=vcenter\n"
                                  "held=zm-admin-password,zm-root-password,zm-web-password\ncache_removed=1\n")


def client(user=None, pw=None, ip="203.0.113.9"):
    c = TestClient(main.app, client=(ip, 50000))
    c.__enter__()
    if user:
        r = c.post("/login", data={"username": user, "password": pw, "next": "/"}, follow_redirects=False)
        assert r.status_code == 303, (user, r.status_code, r.text[:200])
    return c


boot = client()
r = boot.post("/setup", data={"username": "admin", "password": "admin-pw-123"}, follow_redirects=False)
step("setup makes the first user an admin", db.get_user("admin")["role"] == "admin")
adm = client("admin", "admin-pw-123")
for name, role in (("eng", "engineer"), ("view", "viewer")):
    r = adm.post("/admin/users", data={"username": name, "password": f"{name}-pw-12345", "role": role}, follow_redirects=False)
    step(f"admin adds a {role}", db.get_user(name)["role"] == role, r.headers.get("location"))
eng, view, anon = client("eng", "eng-pw-12345"), client("view", "view-pw-12345"), client()

h = adm.get("/admin").text
step("admin page: Security card with the vApp warning", 'id="security"' in h and "Deploy-time passwords are still stored in vCenter" in h
     and "root password" in h and "web admin password" in h)
step("admin page: users table has role selects + engineer group field", 'name="role"' in h and 'name="entra_engineer_group"' in h)
step("admin page: require-sign-in switch", 'name="require_login"' in h)
step("engineer can't open /admin", eng.get("/admin", follow_redirects=False).status_code == 403)
step("viewer can't open /admin", view.get("/admin", follow_redirects=False).status_code == 403)

load(V1, V2, V3, V4)
d_eng, d_view, d_anon = eng.get("/").text, view.get("/").text, anon.get("/").text
step("dashboard: engineer gets the ignore form", 'action="/admin/ignores"' in d_eng)
step("dashboard: viewer and anonymous don't", 'action="/admin/ignores"' not in d_view and 'action="/admin/ignores"' not in d_anon)
step("nav shows the signed-in role", ">engineer</span>" in d_eng)
r = view.post("/admin/ignores", data={"scope": "vpg", "target": "vpg-1", "mode": "ack", "days": "7"}, follow_redirects=False)
step("viewer can't ignore (403)", r.status_code == 403)
r = eng.post("/admin/ignores", data={"scope": "vpg", "target": "vpg-3", "mode": "ack", "days": "7", "back": "/"}, follow_redirects=False)
step("engineer: 'ack' on a healthy VPG refused with a reason", "err=" in r.headers["location"])
r = eng.post("/admin/ignores", data={"scope": "vpg", "target": "vpg-1", "mode": "ack", "days": "7", "note": "known", "back": "/zorgs/Globex"}, follow_redirects=False)
step("engineer: ack V1 works, returns to the page it came from", r.headers["location"].startswith("/zorgs/Globex?msg="), r.headers["location"])
step("  ...snapshot built server-side from current data", db.list_ignores()[0]["snapshot"].get("vpg-1", {}).get("codes") == ["VPG0035"])
r = eng.post("/admin/ignores", data={"scope": "vpg", "target": "vpg-1", "mode": "ack", "days": "3"}, follow_redirects=False)
step("unknown span refused", "err=" in r.headers["location"])
igid = db.list_ignores()[0]["id"]
r = eng.post(f"/admin/ignores/{igid}/delete", data={"back": "//evil.example/x"}, follow_redirects=False)
step("engineer removes it; a hostile 'back' can't redirect off-site", r.headers["location"].startswith("/?msg=") and not db.list_ignores(), r.headers["location"])

vs_eng, vs_view = eng.get("/vras/Site-A").text, view.get("/vras/Site-A").text
step("VRA page: engineer gets the sizing editor + pin buttons", 'action="/admin/vras/standard"' in vs_eng and "pin as is" in vs_eng)
step("VRA page: viewer doesn't", 'action="/admin/vras/standard"' not in vs_view)
r = eng.post("/admin/vras/standard", data={"site": "Site-A", "memory_gb": "12", "cpus": "4", "back": "/vras/Site-A"}, follow_redirects=False)
step("engineer sets a site standard (raise-only)", "msg=" in r.headers["location"] and db.vra_standards()["Site-A"]["memory_gb"] == 12)
r = eng.post("/admin/vras/standard", data={"site": "Nowhere", "memory_gb": "12", "cpus": "4"}, follow_redirects=False)
step("  ...unknown site refused", "err=" in r.headers["location"])
r = eng.post("/admin/vras/standard", data={"site": "Site-A", "memory_gb": "80", "cpus": "4"}, follow_redirects=False)
step("  ...beyond the 64 GB / 8 vCPU ceiling refused", "err=" in r.headers["location"])
r = eng.post("/admin/vras/standard", data={"site": "Site-A", "memory_gb": "24", "cpus": "6"}, follow_redirects=False)
step("  ...beyond the 16/4 guidance accepted, with a warning about the Zerto reference",
     "msg=" in r.headers["location"] and "beyond" in r.headers["location"].replace("+", " ").replace("%20", " "))
eng.post("/admin/vras/standard", data={"site": "Site-A", "memory_gb": "12", "cpus": "4"}, follow_redirects=False)
r = eng.post("/admin/vras/cluster-standard", data={"site": "Site-A", "cluster": "Prod-B", "memory_gb": "8", "cpus": "2",
                                                    "support_ref": "", "back": "/vras/Site-A"}, follow_redirects=False)
step("engineer sets a cluster override", "msg=" in r.headers["location"] and ("Site-A", "Prod-B") in db.vra_cluster_standards())
r = eng.post("/admin/vras/cluster-standard", data={"site": "Site-A", "cluster": "Nope", "memory_gb": "8", "cpus": "2"}, follow_redirects=False)
step("  ...unknown cluster refused", "err=" in r.headers["location"])
t = eng.get("/vras/Site-A").text
step("VRA page: one block per cluster with its override", t.count('class="cluster"') == 3 and "override 8G / 2 vCPU" in t)
step("  ...Resize… previews offered even while disarmed, which the page says", "/resize?key=Site-A%7Cesx03" in t
     and "Resizing is <b>off</b>" in t, t.count("/resize?key="))
r = view.get("/vras/Site-A/resize?key=Site-A%7Cesx03", follow_redirects=False)
step("viewer can't open a resize preview", r.status_code == 403)
t = eng.get("/vras/Site-A/resize?key=Site-A%7Cesx03").text
step("engineer's preview: outage warning, checks, exact request, blast radius - and no start button",
     "planned replication outage" in t and "G1 Armed" in t and "usePublicKeyInsteadOfCredentials" in t
     and "Blast radius" in t and 'action="/admin/vras/resize"' not in t and "An admin starts resizes" in t)
r = eng.post("/admin/vras/resize", data={"site": "Site-A", "key": "Site-A|esx03"}, follow_redirects=False)
step("an engineer can't start a resize (admin only)", r.status_code == 403)
t = adm.get("/vras/Site-A/resize?key=Site-A%7Cesx03").text
step("admin's preview carries the form, the plan hash and the required acknowledgements",
     'action="/admin/vras/resize"' in t and 'name="plan_hash"' in t and 'name="ack_vib"' in t and 'name="ack_headroom"' in t)
r = adm.post("/admin/vra-push", data={"enabled": "1"}, follow_redirects=False)
zerto.cert_fingerprint = lambda host, port=443: "12:" * 31 + "34"
r = adm.post(f"/admin/sources/{SID}/push", data={"allow": "1", "push_identity": "zm-resize", "push_secret": "resize-pw-9",
                                                 "host_auth": "vib", "pin": "1"}, follow_redirects=False)
s = db.get_source(SID)
step("admin arms a site: method recorded, certificate pinned; no separate credential is taken (1.4.2)",
     s["allow_changes"] == 1 and not s.get("push_secret_enc") and not s.get("push_identity")
     and s["push_host_auth"] == "vib" and s["push_cert_fp"].startswith("12:12"), r.headers["location"][:120])
step("  ...and /api/sources never shows a credential or identity", all(
    not ({"push_secret_enc", "push_identity", "identity", "secret_enc"} & set(x)) for x in adm.get("/api/sources").json()))
t = adm.get("/admin").text
step("admin page: changes section, armed, with the pin", 'id="vra-push"' in t and "armed for changes" in t and "12:12:12" in t)
pl = vrapush.plan("Site-A", "Site-A|esx03")
form = {"site": "Site-A", "key": "Site-A|esx03", "plan_hash": pl["plan_hash"], "ticket": "CHG-9",
        "ack_outage": "yes", "ack_vib": "yes", "ack_headroom": "yes", "ack_tier": "yes"}
r = adm.post("/admin/vras/resize", data=form, follow_redirects=False)
step("admin start inside the first 24 h is refused by pacing (G2), with the reason",
     "err=" in r.headers["location"] and "G2+Pacing" in r.headers["location"], r.headers["location"][:160])
vrapush._halt(999, "test halt")
r = adm.post("/admin/vras/resize/acknowledge", data={"note": "short", "back": "/vras"}, follow_redirects=False)
step("clearing a halt needs a real note", "err=" in r.headers["location"] and vrapush.halted())
r = adm.post("/admin/vras/resize/acknowledge", data={"note": "checked VRA and VPGs in Zerto, all healthy", "back": "/vras"}, follow_redirects=False)
step("  ...with one, it clears", "msg=" in r.headers["location"] and vrapush.halted() is None)
t = eng.get("/vras/Site-A").text
step("resize history shows every outcome", 'id="resizes"' in t and all(f">{s}<" in t for s in ("done", "failed", "unknown", "refused")))
adm.post("/admin/vra-push", data={}, follow_redirects=False)
adm.post(f"/admin/sources/{SID}/push", data={"allow": "", "host_auth": "vib"}, follow_redirects=False)
step("switched off and disarmed again", not vrapush.enabled() and db.get_source(SID)["allow_changes"] == 0)

print("\n=== team playbook entries ===")
r = view.post("/admin/playbook", data={"key": "VPG0035", "fix": "x"}, follow_redirects=False)
step("viewer can't add a team fix", r.status_code == 403)
r = eng.post("/admin/playbook", data={"key": "vpg0035", "title": "Journal", "back": "/",
                                      "fix": "Expand {datastore}; see https://kb.example/x?a=1&b=2.\nThen re-check {vm}.",
                                      "caution": ""}, follow_redirects=False)
step("engineer adds a team fix (code normalised to VPG0035)", "msg=" in r.headers["location"] and "VPG0035" in db.team_fixes(), r.headers["location"])
for bad, why in (({"key": "hello", "fix": "x"}, "key"), ({"key": "VPG0035", "fix": "  "}, "empty"),
                 ({"key": "VPG0035", "fix": "use {secret}"}, "placeholder"), ({"key": "VPG0035", "fix": "x" * 2001}, "length")):
    r = eng.post("/admin/playbook", data={**bad, "back": "/playbook"}, follow_redirects=False)
    step(f"  ...refused: bad {why}", "err=" in r.headers["location"], r.headers["location"][:90])
r = eng.post("/admin/playbook", data={"key": "VPG0035", "fix": "<script>alert(1)</script> javascript:alert(2)", "back": "/"}, follow_redirects=False)
load(V1, V2, V3, V4)
d = eng.get("/").text
step("dashboard: team fix shown first, labelled, author named", d.find(">team</span>") != -1 and "eng," in d)
step("  ...placeholders filled from the alert", "Then re-check vm1-01." in d)
step("  ...links are clickable, the rest stays text", 'href="https://kb.example/x?a=1&amp;b=2"' in d and "<script>alert(1)" not in d
     and "&lt;script&gt;" in d and 'href="javascript' not in d)
step("  ...and the '+ team fix' form offers the row's codes", 'action="/admin/playbook"' in d and '<option value="VPG0035">' in d)
fx_id = db.team_fixes()["VPG0035"][-1]["id"]
r = eng.post(f"/admin/playbook/{fx_id}", data={"key": "VPG0035", "title": "J2", "fix": "edited fix", "caution": "may resync", "back": "/playbook"}, follow_redirects=False)
step("edit a team fix", "msg=" in r.headers["location"] and db.get_team_fix(fx_id)["fix"] == "edited fix" and db.get_team_fix(fx_id)["updated_by"] == "eng")
pb = eng.get("/playbook").text
step("Playbook page lists it with edit/delete for engineers", "edited fix" in pb and f'action="/admin/playbook/{fx_id}/delete"' in pb)
step("  ...and read-only for viewers", 'action="/admin/playbook"' not in anon.get("/playbook").text)
r = eng.post(f"/admin/playbook/{fx_id}/delete", data={"back": "/playbook"}, follow_redirects=False)
step("delete a team fix", db.get_team_fix(fx_id) is None)

for path in ("/", "/zorgs", "/zorgs/Globex", "/vras", "/vras/Site-A"):
    t = eng.get(path).text
    step(f"{path}: responsive column classes present", ' class="c' in t or 'c1"' in t or "c2" in t)
css = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
step("CSS hides .c3/.c2/.c1 progressively as the window narrows", all(f".c{i}" in css for i in (1, 2, 3)) and "@media" in css)

r = adm.post("/admin/users/eng/role", data={"role": "viewer"}, follow_redirects=False)
step("demotion is immediate (engineer -> viewer, next request 403)",
     eng.post("/admin/vras/standard/delete", data={"site": "Site-A"}, follow_redirects=False).status_code == 403)
r = adm.post("/admin/users/admin/role", data={"role": "engineer"}, follow_redirects=False)
step("can't demote the last admin", "err=" in r.headers["location"] and db.get_user("admin")["role"] == "admin")
r = adm.post("/admin/users/view/delete", follow_redirects=False)
step("deleting a user ends their session at once", view.get("/admin/../", follow_redirects=False).status_code in (200, 303)
     and auth.optional_user(type("R", (), {"cookies": view.cookies})()) is None)
db.upsert_sso_user("someone@example.invalid", "engineer")
r = adm.post("/admin/users/someone%40example.invalid/role", data={"role": "admin"}, follow_redirects=False)
step("an Entra user's role can't be overridden locally", "err=" in r.headers["location"] and db.get_user("someone@example.invalid")["role"] == "engineer")
cfg = {"entra_admin_group": "G-ADM", "entra_engineer_group": "G-ENG"}
step("Entra: admin group wins, engineer next, else viewer",
     (auth.entra_role(cfg, {"groups": ["g-eng", "G-ADM"]}), auth.entra_role(cfg, {"groups": ["G-ENG"]}),
      auth.entra_role(cfg, {"groups": []}), auth.entra_role({"entra_admin_group": "", "entra_engineer_group": ""}, {"groups": [""]}))
     == ("admin", "engineer", "viewer", "viewer"))

for nxt, want in (("//evil.example/a", "/"), ("https://evil.example", "/"), ("/\\evil.example", "/"), ("/vras", "/vras")):
    r = client().post("/login", data={"username": "admin", "password": "admin-pw-123", "next": nxt}, follow_redirects=False)
    step(f"login next={nxt!r} -> {want}", r.headers["location"] == want, r.headers["location"])

r = adm.post("/admin/alerts/smtp", data={"host": "smtp.x", "port": "25", "security": "none", "username": "u", "password": "p"}, follow_redirects=False)
step("admin: SMTP 'none' with a username is refused", "err=" in r.headers["location"])
r = adm.post("/admin/alerts/snmp-trap", data={"enabled": "1", "targets": "203.0.113.5", "community": "has space"}, follow_redirects=False)
step("admin: trap community with whitespace refused", "err=" in r.headers["location"])

print("\n=== require sign-in ===")
step("off by default: anonymous can read the dashboard", anon.get("/").status_code == 200)
adm.post("/admin/access", data={"require_login": "1"}, follow_redirects=False)
main._login_cache["at"] = 0.0
r = anon.get("/", follow_redirects=False)
step("on: anonymous dashboard -> sign-in page", r.status_code == 303 and r.headers["location"].startswith("/login?next=/"))
step("on: anonymous API -> 401", anon.get("/api/overview").status_code == 401)
step("on: /login, /static and /healthz stay open", anon.get("/login").status_code == 200
     and anon.get("/static/style.css").status_code == 200 and anon.get("/healthz").status_code == 200)
step("on: /api/metrics from a remote address -> 401", anon.get("/api/metrics").status_code == 401)
step("on: /api/metrics from loopback (the SNMP hook) -> 200", client(ip="127.0.0.1").get("/api/metrics").status_code == 200)
step("on: a signed-in viewer reads pages", client("eng", "eng-pw-12345").get("/").status_code == 200)
adm.post("/admin/access", data={}, follow_redirects=False)
main._login_cache["at"] = 0.0
step("off again: anonymous reads", anon.get("/").status_code == 200)

# ═════════════════════════════════════════════════════════ secrets-audit fixes
print("\n=== secrets audit fixes ===")
import collector  # noqa: E402,F811
# C1: no key file is ever created inside a synced folder
os.environ["OneDrive"] = str(TMP / "od")
(TMP / "od").mkdir(exist_ok=True)
try:
    crypto.refuse_synced(TMP / "od" / "data" / "fernet.key")
    step("C1: a key file inside a synced folder is refused", False)
except RuntimeError:
    step("C1: a key file inside a synced folder is refused", True)
step("  ...and allowed elsewhere", crypto.refuse_synced(TMP / "elsewhere" / "fernet.key") is None)
del os.environ["OneDrive"]

# C3: redirects are never followed with credentials; unpinned origins are refused
class _R:
    def __init__(self, code): self.status_code, self.is_redirect = code, code in (301, 302, 303, 307, 308)
for code in (302, 307, 308):
    try:
        zerto.refuse_redirect(_R(code), "the token endpoint")
        step(f"C3: a {code} redirect is refused", False)
    except zerto.ZvmError:
        step(f"C3: a {code} redirect is refused", True)
sess = zerto.pinned_session("zvm.invalid", {443: "aa:" * 31 + "aa"})
try:
    sess.get("https://other.invalid/x", timeout=2)
    step("C3: a pinned session refuses an origin it has no pin for", False)
except requests.exceptions.SSLError as e:
    step("C3: a pinned session refuses an origin it has no pin for", "no certificate pin" in str(e))
try:
    sess.get("https://zvm.invalid:9669/x", timeout=2)
    step("  ...including another port on the same host", False)
except requests.exceptions.SSLError:
    step("  ...including another port on the same host", True)
src_id = db.add_source("PinTest", "zvm", "pin.invalid", "password", "svc-user-77", crypto.encrypt("Pw-Secret-77!"), False)
captured = {}
orig_cp = collector.capture_pins
collector.capture_pins = lambda host, kind: captured.setdefault("pins", {443: "bb:" * 31 + "bb"})
orig_zc = collector.ZvmClient


class _Boom:
    def __init__(self, *a, **k): captured["session"] = k.get("session")
    def collect(self, **kw): raise zerto.ZvmError("auth failed for svc-user-77 with Pw-Secret-77! at pin.invalid")


collector.ZvmClient = _Boom
ok, err, payload_, ms = collector.collect_source(db.get_source(src_id))
step("C3: first contact pins the certificate (trust on first use) and uses a pinned session",
     db.source_pins(db.get_source(src_id)) == {443: "bb:" * 31 + "bb"} and captured.get("session") is not None)
step("C6: errors never carry the username or the secret", "svc-user-77" not in err and "Pw-Secret-77!" not in err and "<redacted>" in err, err)


class _Mismatch:
    def __init__(self, *a, **k): pass
    def collect(self, **kw): raise requests.exceptions.SSLError("Fingerprints did not match. Expected bb.., got cc..")


collector.ZvmClient = _Mismatch
ok, err, payload_, ms = collector.collect_source(db.get_source(src_id))
step("C3: a changed certificate stops the poll with a clear message", not ok and "re-pin" in err, err)
collector.ZvmClient, collector.capture_pins = orig_zc, orig_cp

# C5: no stored secret follows a changed destination
r = adm.post(f"/admin/sources/{src_id}", data={"name": "PinTest", "host": "elsewhere.invalid", "auth_type": "password",
                                               "identity": "svc-user-77", "secret": "", "enabled": "1"}, follow_redirects=False)
step("C5: changing a source's host without re-entering the secret is refused",
     "err=" in r.headers["location"] and db.get_source(src_id)["host"] == "pin.invalid")
db.set_setting("smtp_host", "smtp.a.invalid")
db.set_setting("smtp_port", "587")
db.set_setting("smtp_security", "starttls")
db.set_setting("smtp_verify", "true")
db.set_setting("smtp_password", crypto.encrypt("smtp-pw-zz"))
r = adm.post("/admin/alerts/smtp", data={"host": "smtp.b.invalid", "port": "587", "security": "starttls", "username": "u@x",
                                          "password": "", "verify": "1"}, follow_redirects=False)
step("C5: a new SMTP server doesn't inherit the stored password", db.get_setting("smtp_password") == ""
     and "cleared" in r.headers["location"].replace("+", " ").replace("%20", " "))
step("C6: the SMTP username is stored encrypted", crypto.is_token(db.get_setting("smtp_user"))
     and crypto.decrypt(db.get_setting("smtp_user")) == "u@x")
db.set_setting("snmp_trap_targets", "203.0.113.5")
db.set_setting("snmp_trap_community", crypto.encrypt("trapcomm1"))
r = adm.post("/admin/alerts/snmp-trap", data={"enabled": "1", "targets": "203.0.113.9", "community": "", "oid": ""}, follow_redirects=False)
step("C5: new trap receivers don't inherit the stored community", db.get_setting("snmp_trap_community") == "")

# C14: anything stored unencrypted is encrypted at the next start
db.set_setting("snmp_agent_community", "plain-comm-1")
with db._conn() as cx:
    cx.execute("UPDATE sources SET reg_uri=? WHERE id=?", ("https://pin.invalid/auth/realms/zerto/clients-registrations/default/abc", src_id))
step("C14: the Security card counts unencrypted values", db.unencrypted_count() == 2, db.unencrypted_count())
db.init()
step("  ...and db.init() encrypts them (reg_uri, community)", db.unencrypted_count() == 0
     and crypto.decrypt(db.get_source(src_id)["reg_uri"]).endswith("/abc"))
step("  ...the API never shows reg_uri", all("reg_uri" not in x for x in adm.get("/api/sources").json()))

# C4, C7, C9, C10, C12, C13, C15, R3: build- and deploy-time guarantees
fb = (ROOT / "deploy/appliance/firstboot.py").read_text(encoding="utf-8")
main_pos = fb.index("def main()")
step("C4: OVF lock-down runs right after credentials, before packages", fb.index("lock_down_ovf_environment()", main_pos)
     < fb.index("install_packages()", main_pos) and "install_ovfscrub()" in fb)
step("C4: a web password over bcrypt's 72 bytes is skipped, and the wizard caps it at 72",
     "> 72" in fb and "MaxLen(72)" in (ROOT / "deploy/appliance/build_ova.py").read_text(encoding="utf-8"))
step("C7: only allow-listed OVF values are logged; the log is private", "LOGGABLE" in fb and "0o600" in fb.split("def log(")[1][:600])
step("C7: the scrub treats the ZVM username as sensitive", "zm-zvm-user" in (ROOT / "deploy/appliance/zerto-monitor-ovfscrub").read_text())
step("C9: uploads stay in memory/tmpfs (body buffer, RuntimeDirectory)", "client_body_buffer_size 2m" in fb and "RuntimeDirectory=zerto-monitor" in fb
     and "/run/zerto-monitor/staging" in (ROOT / "deploy/appliance/zerto-monitor-admin").read_text())
step("C10: no query strings in access logs", "--no-access-log" in fb and "zm_noargs" in fb)
step("C12: the session key is regenerated, never carried over", "retired, not copied" in fb and "old.read_text" not in fb)
step("C13: keys are written private from the first byte", "O_EXCL" in fb and "write_secret(KEY_FILE" in fb and "write_secret(SESSION_KEY" in fb)
step("C15: crash dumps off (apport, LimitCORE, non-dumpable process)", "disable_crash_dumps()" in fb and "LimitCORE=0" in fb
     and "PR_SET_DUMPABLE" in (ROOT / "app/main.py").read_text(encoding="utf-8"))
helper = (ROOT / "deploy/appliance/zerto-monitor-admin").read_text()
step("R3: the SNMP agent answers only for system + the monitor's metrics, from a named network",
     "-V zmview" in helper and "default) ;;" not in helper)
sys.path.insert(0, str(ROOT / "deploy/appliance"))
import build_ova  # noqa: E402
leaks = build_ova.secret_scan([("app/x.py", b"-----BEGIN PRIVATE KEY-----\nMII"), ("app/y.json", b'{"t":"gAAAAA' + b"A" * 90 + b'"}'),
                               ("app/z.py", b"print('fine')")])
step("C16: the payload builder refuses private keys and Fernet tokens", len(leaks) == 2 and all("z.py" not in l for l in leaks), leaks)
step("C16: only allow-listed file types are packed", not build_ova.packable(ROOT / "app" / "monitor.db") and build_ova.packable(ROOT / "app" / "main.py"))

print()
if FAILED:
    print(f"FAILED {len(FAILED)}:")
    for f in FAILED:
        print("   - " + f)
    sys.exit(1)
print("ALL GOOD")
