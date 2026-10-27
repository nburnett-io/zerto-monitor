"""Local verification for Zerto Monitor 1.1: TLS manager, alert engine, routes, theme.

Runs against an EMPTY temporary data dir, so nothing polls a real ZVM.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke-"))
os.environ["DATA_DIR"] = str(TMP)
os.environ["TLS_DIR"] = str(TMP / "tls")
os.environ["ADMIN_SOCKET"] = str(TMP / "no-such.sock")
from cryptography.fernet import Fernet  # noqa: E402
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
sys.path.insert(0, str(ROOT / "app"))

FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)) if detail else ''}")
    if not ok:
        FAILED.append(desc)


import alerts  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import tlsmgr  # noqa: E402
import zerto  # noqa: E402

db.init()

# ───────────────────────────────────────────────────────── TLS validation
print("=== TLS manager ===")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402


def mkcert(cn, days=365, key=None, past=False):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    nb, na = (now - timedelta(days=400), now - timedelta(days=1)) if past else (now - timedelta(minutes=5), now + timedelta(days=days))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.IPAddress(__import__('ipaddress').ip_address('192.0.2.16'))]), False)
         .sign(key, hashes.SHA256()))
    kp = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return c.public_bytes(serialization.Encoding.PEM), kp, key, c


cert, keyp, k, cobj = mkcert("zertomon.example.invalid")
other_cert, _, _, _ = mkcert("other.example.invalid")
old_cert, old_key, _, _ = mkcert("old.example.invalid", past=True)

step("matching pair validates, returns CN", tlsmgr._validate_pair(cert, keyp) == "zertomon.example.invalid")
try:
    tlsmgr._validate_pair(other_cert, keyp)
    step("mismatched pair rejected", False)
except tlsmgr.TlsError as e:
    step("mismatched pair rejected", "does not match" in str(e), e)
try:
    tlsmgr._validate_pair(old_cert, old_key)
    step("expired certificate rejected", False)
except tlsmgr.TlsError as e:
    step("expired certificate rejected", "expired" in str(e), e)
enc_key = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.BestAvailableEncryption(b"pw"))
try:
    tlsmgr._validate_pair(cert, enc_key)
    step("encrypted key rejected with guidance", False)
except tlsmgr.TlsError as e:
    step("encrypted key rejected with guidance", "encrypted" in str(e), e)
try:
    tlsmgr._validate_pair(b"garbage", keyp)
    step("non-PEM certificate rejected", False)
except tlsmgr.TlsError as e:
    step("non-PEM certificate rejected", "not valid PEM" in str(e))

# install() must validate BEFORE needing the helper, and must not leave a key behind
try:
    tlsmgr.install(other_cert, keyp)
    step("install refuses mismatch before touching the helper", False)
except tlsmgr.TlsError as e:
    step("install refuses mismatch before touching the helper", "does not match" in str(e))
try:
    tlsmgr.install(cert, keyp)
    step("install with no helper fails cleanly", False)
except tlsmgr.TlsError as e:
    step("install with no helper fails cleanly", "helper" in str(e), e)
staged = list((TMP / "staging").glob("*")) if (TMP / "staging").exists() else []
step("no private key left in the staging dir", not staged, staged)

pfx = pkcs12.serialize_key_and_certificates(b"zm", k, cobj, None, serialization.BestAvailableEncryption(b"s3cret"))
try:
    tlsmgr.install_pfx(pfx, "wrong")
    step("pfx with wrong password rejected", False)
except tlsmgr.TlsError as e:
    step("pfx with wrong password rejected", "wrong password" in str(e))
try:
    tlsmgr.install_pfx(pfx, "s3cret")
    step("pfx with right password gets as far as the helper", False)
except tlsmgr.TlsError as e:
    step("pfx with right password gets as far as the helper", "helper" in str(e), e)

for bad in ("a b", "x\nstatus", "", "rm -rf /", "a;b"):
    try:
        tlsmgr.helper("tls-selfsigned", bad)
        step(f"helper refuses word {bad!r}", False)
    except tlsmgr.TlsError as e:
        step(f"helper refuses word {bad!r}", "malformed" in str(e) or "not installed" in str(e) and bad.strip() == "", e)
for good in ("zertomon.example.invalid", "ZERTOMON01", "a-b.c-d.example"):
    step(f"fqdn pattern accepts {good!r}", bool(tlsmgr.FQDN_RE.match(good)))
for bad in ("-x", "a..b-", "a..b", "a.-b", "has space", "x" * 300, "x" * 64 + ".com"):
    try:
        tlsmgr.self_signed(bad)
        step(f"self_signed refuses fqdn {bad[:20]!r}", False)
    except tlsmgr.TlsError:
        step(f"self_signed refuses fqdn {bad[:20]!r}", True)
for bad in ("-lead", "trail-", "under_score", "x" * 64):
    try:
        tlsmgr.set_hostname(bad)
        step(f"set_hostname refuses {bad[:20]!r}", False)
    except tlsmgr.TlsError:
        step(f"set_hostname refuses {bad[:20]!r}", True)

# state() parses the public half
(TMP / "tls").mkdir(exist_ok=True)
(TMP / "tls" / "fullchain.pem").write_bytes(cert + other_cert)
st = tlsmgr.state()
step("state(): certificate parsed", st["present"] and st["self_signed"] and "zertomon.example.invalid" in st["sans"], st["sans"])
step("state(): IP SAN and chain length reported", "192.0.2.16" in st["sans"] and st["chain_len"] == 2)
step("state(): days_left sensible", 360 <= st["days_left"] <= 366, st["days_left"])

# ───────────────────────────────────────────────────────── Keycloak registration
print("\n=== Keycloak registration guard ===")
r = zerto.deregister_client("zvm-a.example.invalid",
                            "https://evil.example.com/auth/realms/zerto/clients-registrations/default/x", "tok")
step("deregister refuses a URI on another host", r.startswith("refused"), r)
r = zerto.deregister_client("zvm-a.example.invalid", "", "")
step("deregister with nothing stored is a no-op", r == "nothing to remove")
step("role hint names the exact role", "ZertoPrivilege_Viewer" in zerto.role_hint("abc") and "zerto-client" in zerto.role_hint("abc"))

# ───────────────────────────────────────────────────────── alert engine (simulated time)
print("\n=== alert engine: dwell clocks ===")
obs_box = {"v": []}
alerts._observations = lambda: obs_box["v"]                  # control the inputs
sent = {"email": [], "trap": []}
alerts.send_email = lambda to, s, t, h=None: sent["email"].append((tuple(to), s, t))
alerts.send_trap = lambda e: sent["trap"].append((e["name"], e["event"], e["level"]))


def org(name, health, f=0, w=0, h=5):
    # per-VPG emails need the unhealthy VPGs themselves (key -> [health, name])
    bad = {f"{name}-f{i}": ["failure", f"{name}-VPG-F{i}"] for i in range(f)}
    bad.update({f"{name}-w{i}": ["warning", f"{name}-VPG-W{i}"] for i in range(w)})
    return {"name": name, "health": health, "failure": f, "warning": w, "healthy": h, "bad": bad,
            "vpgs": f + w + h, "worst_rpo": "2h", "sites": ["Site-A"]}


db.set_setting("alerts_enabled", "true")
db.set_setting("alert_default_recipients", "noc@example.invalid")
db.set_setting("smtp_host", "smtp.example.com")
db.set_setting("snmp_trap_enabled", "true")
db.set_setting("alert_repeat_hours", "4")
db.save_alert_rule("*", 15, 60, "", True, True, True)
db.save_alert_rule("Muted Corp", 15, 60, "", True, True, False)
db.save_alert_rule("VIP Corp", 5, 20, "vip@example.invalid", True, False, True)

T0 = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def at(m):
    return T0 + timedelta(minutes=m)


def run(m, *orgs):
    obs_box["v"] = list(orgs)
    sent["email"].clear()
    sent["trap"].clear()
    return alerts.evaluate(now=at(m))


ev = run(0, org("Acme", "warning", w=2))
step("t=0 warning: nothing yet (clock starts)", ev == [])
ev = run(59, org("Acme", "warning", w=2))
step("t=59 still under 60-min warning threshold", ev == [])
ev = run(60, org("Acme", "warning", w=2))
step("t=60 warning RAISED", [(e["name"], e["event"], e["level"]) for e in ev] == [("Acme", "raised", "warning")])
step("  ...one email PER VPG (2) to the default recipient", len(sent["email"]) == 2 and all(e[0] == ("noc@example.invalid",) for e in sent["email"]),
     [e[1] for e in sent["email"]])
step("  ...subject: [Zerto Monitor] Org - VPG - Warning", sorted(e[1] for e in sent["email"]) ==
     ["[Zerto Monitor] Acme - Acme-VPG-W0 - Warning", "[Zerto Monitor] Acme - Acme-VPG-W1 - Warning"], [e[1] for e in sent["email"]])
step("  ...one trap", sent["trap"] == [("Acme", "raised", "warning")])
ev = run(61, org("Acme", "warning", w=2))
step("t=61 no repeat inside the reminder window", ev == [])
ev = run(70, org("Acme", "failure", f=1, w=1))
step("t=70 failure begins: not yet 15 min", ev == [])
ev = run(85, org("Acme", "failure", f=1, w=1))
step("t=85 ESCALATED to failure after 15 min of failure", [(e["event"], e["level"]) for e in ev] == [("escalated", "failure")])
ev = run(90, org("Acme", "warning", w=2))
step("t=90 eased to warning: not announced (not an all-clear)", ev == [])
ev = run(95, org("Acme", "failure", f=1))
step("t=95 failure again: fail clock restarted, so silent", ev == [])
ev = run(110, org("Acme", "failure", f=1))
step("t=110 15 min of renewed failure: escalated again", [(e["event"], e["level"]) for e in ev] == [("escalated", "failure")])
ev = run(110 + 4 * 60, org("Acme", "failure", f=1))
step("4h later: REMINDER", [(e["event"], e["level"]) for e in ev] == [("reminder", "failure")])
ev = run(400, org("Acme", "healthy"))
step("healthy: CLEARED once", [(e["event"]) for e in ev] == ["cleared"])
step("  ...cleared summary says how long it lasted", "after" in alerts._summary(ev[0]), alerts._summary(ev[0]))
ev = run(401, org("Acme", "healthy"))
step("still healthy: silent", ev == [])

print("\n=== alert engine: flapping, rules, mute, digest ===")
# flapping between warning and failure must NOT reset the warning clock
for m, h in ((1000, "warning"), (1010, "failure"), (1013, "warning"), (1020, "failure"), (1023, "warning")):
    run(m, org("Flappy", h, f=1 if h == "failure" else 0, w=1))
ev = run(1060, org("Flappy", "warning", w=1))
step("flapping zORG still warns at 60 min of not-healthy", [(e["name"], e["level"]) for e in ev] == [("Flappy", "warning")])

run(2000, org("Muted Corp", "failure", f=3))
ev = run(2100, org("Muted Corp", "failure", f=3))
step("muted zORG never alerts", ev == [])

run(3000, org("VIP Corp", "failure", f=1))
ev = run(3005, org("VIP Corp", "failure", f=1))
step("per-zORG rule: 5-min failure threshold honoured", [(e["name"], e["level"]) for e in ev] == [("VIP Corp", "failure")])
step("  ...to that rule's recipient, not the default", sent["email"] and sent["email"][0][0] == ("vip@example.invalid",))
step("  ...and no trap (rule has traps off)", sent["trap"] == [])

run(4000, org("A1", "failure", f=1), org("A2", "failure", f=2), org("A3", "warning", w=1))
ev = run(4100, org("A1", "failure", f=1), org("A2", "failure", f=2), org("A3", "warning", w=1))
step("three zORGs at once -> three events", len(ev) == 3)
step("  ...one email per unhealthy VPG (4), each with its own subject", len(sent["email"]) == 4
     and {e[1] for e in sent["email"]} == {"[Zerto Monitor] A1 - A1-VPG-F0 - Failure", "[Zerto Monitor] A2 - A2-VPG-F0 - Failure",
                                           "[Zerto Monitor] A2 - A2-VPG-F1 - Failure", "[Zerto Monitor] A3 - A3-VPG-W0 - Warning"},
     [e[1] for e in sent["email"]])
step("  ...and three traps (traps stay per zORG)", len(sent["trap"]) == 3)

print("\n=== alert engine: switched off ===")
db.set_setting("alerts_enabled", "false")
run(5000, org("Quiet", "failure", f=1))
ev = run(5100, org("Quiet", "failure", f=1))
step("alerting off: no events", ev == [] and not sent["email"])
step("  ...but preview() shows it would fire", any(p["name"] == "Quiet" for p in alerts.preview(now=at(5100))))
db.set_setting("alerts_enabled", "true")
ev = run(5101, org("Quiet", "failure", f=1))
step("switched on: the existing failure is announced", [(e["name"], e["event"]) for e in ev] == [("Quiet", "raised")])
db.set_setting("alerts_enabled", "false")
ev = run(5102, org("Quiet", "healthy"))
step("recovery while off: no stale 'cleared' queued", ev == [])
db.set_setting("alerts_enabled", "true")
ev = run(5103, org("Quiet", "healthy"))
step("  ...and nothing fires when switched back on", ev == [])

print("\n=== alert engine: source down + disappearing zORG ===")
run(6000, {**org(alerts.SOURCE_PREFIX + "Site-A", "failure", f=1), "error": "ConnectionError"})
ev = run(6016, {**org(alerts.SOURCE_PREFIX + "Site-A", "failure", f=1), "error": "ConnectionError"})
step("unreachable ZVM alerts under the * rule", ev and "has not answered" in alerts._summary(ev[0]), ev and alerts._summary(ev[0]))
run(6017, org("Other", "healthy"))
step("a zORG that vanished is dropped from state", alerts.SOURCE_PREFIX + "Site-A" not in db.zorg_states())
step("log rows written for delivered events", len(db.recent_alerts(200)) > 5)

# ───────────────────────────────────────────────────────── SNMP OIDs
print("\n=== SNMP ===")
oids = {o["name"]: o["oid"] for o in alerts.snmp_oids()}
step("extend OID encodes length + ASCII", oids["zmVpgFailure"] ==
     "1.3.6.1.4.1.8072.1.3.2.3.1.1.12." + ".".join(str(ord(c)) for c in "zmVpgFailure"))
helper_src = (ROOT / "deploy" / "appliance" / "zerto-monitor-admin").read_text()
missing = [n for n in oids if f"extend {n} " not in helper_src]
step("every documented OID has an extend line in the helper", not missing, missing)
step("helper script has LF line endings", b"\r\n" not in (ROOT / "deploy" / "appliance" / "zerto-monitor-admin").read_bytes())

# ───────────────────────────────────────────────────────── routes + pages
print("\n=== routes ===")
alerts._observations = lambda: []
from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402

with TestClient(main.app) as c:
    r = c.post("/setup", data={"username": "admin", "password": "smoke-test-pw-1"}, follow_redirects=False)
    step("setup creates the first admin", r.status_code == 303)
    r = c.post("/login", data={"username": "admin", "password": "smoke-test-pw-1", "next": "/admin"}, follow_redirects=False)
    sc = r.headers.get("set-cookie", "")
    step("login over plain HTTP: cookie NOT marked Secure (dev)", r.status_code == 303 and "secure" not in sc.lower(), sc[:80])
    r = c.get("/admin")
    html = r.text
    step("admin renders", r.status_code == 200, r.status_code)
    for needle in ("Hostname &amp; TLS", "Self-signed certificate", "Install a CA-issued certificate",
                   ".pfx", "Alerting", "Failure after (min)", "Email (SMTP)", "SNMP traps",
                   "SNMP polling", "zmVpgFailure", "initial_access_token", "ZertoPrivilege_Viewer",
                   "privileged helper isn", 'id="themeToggle"'):
        step(f"admin page contains {needle!r}", needle in html)
    step("rule rows use form= (no <form> wrapped round cells)", 'form="rule' in html)
    r = c.post("/admin/alerts/rules", data={"zorg": "Smoke Org", "error_minutes": "10", "warning_minutes": "30",
                                             "recipients": "a@b.c", "email": "1", "enabled": "1"}, follow_redirects=False)
    step("add alert rule", r.status_code == 303 and "msg=" in r.headers["location"])
    step("  ...stored with trap off (unticked)", any(x["zorg"] == "Smoke Org" and not x["snmp"] and x["error_minutes"] == 10 for x in db.alert_rules()))
    r = c.post("/admin/alerts/smtp", data={"host": "smtp.example.com", "port": "587", "security": "starttls",
                                            "username": "u@x", "password": "smtp-secret-123", "sender": "zm@x"}, follow_redirects=False)
    step("save SMTP", r.status_code == 303)
    raw = db.get_setting("smtp_password")
    step("SMTP password stored encrypted", crypto.is_token(raw) and crypto.decrypt(raw) == "smtp-secret-123")
    r = c.post("/admin/alerts/snmp-trap", data={"enabled": "1", "targets": "203.0.113.5", "community": "trap-comm-1",
                                                 "oid": "1.3.6.1.4.1.99999.1"}, follow_redirects=False)
    step("save SNMP trap", r.status_code == 303 and crypto.is_token(db.get_setting("snmp_trap_community")))
    r = c.post("/admin/alerts/snmp-trap", data={"oid": "1.3.bad"}, follow_redirects=False)
    step("non-numeric trap OID refused", "err=" in r.headers["location"])
    r = c.post("/admin/alerts/snmp-agent", data={"enabled": "1", "community": "agent-comm-1", "source": "192.0.2.0/24"}, follow_redirects=False)
    step("SNMP agent without helper: clean error, not a 500", r.status_code == 303 and "err=" in r.headers["location"])
    r = c.post("/admin/tls/selfsigned", data={"fqdn": "zertomon.example.invalid"}, follow_redirects=False)
    step("self-signed without helper: clean error", r.status_code == 303 and "err=" in r.headers["location"])
    r = c.post("/admin/tls/upload", files={"cert": ("c.pem", other_cert), "key": ("k.pem", keyp)}, follow_redirects=False)
    step("upload mismatched pair: refused with reason", "does%20not%20match" in r.headers["location"] or "does+not+match" in r.headers["location"])
    r = c.post("/admin/sources", data={"name": "X", "kind": "zcm", "host": "h", "auth_type": "initial_access_token", "secret": "t"}, follow_redirects=False)
    step("IAT on a ZCM refused", "err=" in r.headers["location"])
    r = c.post("/admin/sources", data={"name": "X", "kind": "zvm", "host": "h", "auth_type": "initial_access_token", "secret": ""}, follow_redirects=False)
    step("IAT with no token refused", "err=" in r.headers["location"])
    r = c.get("/api/metrics")
    j = r.json()
    step("/api/metrics public and complete", r.status_code == 200 and {o["metric"] for o in alerts.snmp_oids()} <= set(j), sorted(j))
    r = c.get("/api/sources")
    step("/api/sources never exposes reg_token_enc", all("reg_token_enc" not in s for s in r.json()))
    r = c.get("/")
    step("public dashboard carries the theme toggle", 'id="themeToggle"' in r.text and "zm-theme" in r.text)
    r = c.get("/login")
    step("login page carries the theme toggle", 'id="themeToggle"' in r.text)

# Secure cookie when the request arrives as HTTPS (what nginx forwards)
with TestClient(main.app, base_url="https://testserver") as c:
    r = c.post("/login", data={"username": "admin", "password": "smoke-test-pw-1", "next": "/admin"}, follow_redirects=False)
    sc = r.headers.get("set-cookie", "")
    step("login over HTTPS: cookie IS Secure + HttpOnly", "secure" in sc.lower() and "httponly" in sc.lower(), sc[:120])

css = (ROOT / "static" / "style.css").read_text()
step("CSS: pinned dark theme block", ':root[data-theme="dark"]' in css)
step("CSS: OS dark preference unless pinned light", ':root:not([data-theme="light"])' in css)
step("CSS: color-scheme set for native controls", "color-scheme:dark" in css)

print()
if FAILED:
    print(f"FAILED {len(FAILED)}:")
    for f in FAILED:
        print("   - " + f)
    sys.exit(1)
print("ALL GOOD")
