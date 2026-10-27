"""1.4.2 web-layer audit fixes: CSRF, sign-in, Entra, version, credentials, Zerto write paths.
Offline: temporary data, .invalid hosts, pollers and workers stubbed."""
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke15w-"))
os.environ.update(DATA_DIR=str(TMP), TLS_DIR=str(TMP / "tls"), ADMIN_SOCKET=str(TMP / "no.sock"),
                  OVFENV_STATE=str(TMP / "ovfenv.state"), UPDATE_STATUS=str(TMP / "update-status.json"),
                  RUNTIME_DIRECTORY=str(TMP / "run"))
from cryptography.fernet import Fernet  # noqa: E402
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
sys.path.insert(0, str(ROOT / "app"))
FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)[:200]) if detail and not ok else ''}")
    if not ok:
        FAILED.append(desc)


import backups  # noqa: E402
import collector  # noqa: E402
import crypto  # noqa: E402
import db  # noqa: E402
import vrapush  # noqa: E402
import zerto  # noqa: E402


async def _idle():
    return None


collector.loop_forever = _idle
vrapush.worker = _idle
backups.worker = _idle
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

H = "zm.example.invalid"


def client(user=None, pw=None):
    c = TestClient(main.app, base_url=f"https://{H}", client=("203.0.113.9", 50000))
    c.__enter__()
    if user:
        r = c.post("/login", data={"username": user, "password": pw, "next": "/"}, follow_redirects=False)
        assert r.status_code == 303, r.text[:200]
    return c


boot = client()
boot.post("/setup", data={"username": "admin", "password": "admin-pw-123"}, follow_redirects=False)
adm, anon = client("admin", "admin-pw-123"), client()

print("=== CSRF ===")
r = adm.post("/admin/access", data={"require_login": "1"}, headers={"Origin": "https://evil.example.invalid"},
             follow_redirects=False)
step("a POST from another site is refused (403), even with the admin's cookie", r.status_code == 403, r.status_code)
step("  ...and changed nothing", db.get_setting("require_login") != "true")
r = adm.post("/admin/access", data={}, headers={"Referer": "https://evil.example.invalid/x"}, follow_redirects=False)
step("a Referer from another site is refused too", r.status_code == 403, r.status_code)
r = adm.post("/admin/access", data={}, headers={"Origin": f"https://{H}"}, follow_redirects=False)
step("a POST from this site goes through", r.status_code == 303, r.status_code)
r = adm.post("/admin/access", data={}, follow_redirects=False)
step("a script with no Origin/Referer goes through (no ambient cross-site cookie)", r.status_code == 303)
r = adm.post("/api/update/apply", content='{"version":"9.9.9","x":"="}', headers={"Content-Type": "text/plain"})
step("the update API refuses a text/plain body (the form trick)", r.status_code == 415, r.status_code)

print("=== sign-in ===")
long_pw = "é" * 40                     # 80 bytes
r = anon.post("/login", data={"username": "admin", "password": long_pw, "next": "/"}, follow_redirects=False)
step("a >72-byte password is a failed login, not a 500", r.status_code == 200 and "Invalid credentials" in r.text,
     r.status_code)
r = adm.post("/admin/users", data={"username": "ops/alice", "password": "a-long-password", "role": "viewer"},
             follow_redirects=False)
step("a username with '/' is refused", "err=" in r.headers["location"] and not db.get_user("ops/alice"))
r = adm.post("/admin/users", data={"username": "eve", "password": long_pw, "role": "viewer"}, follow_redirects=False)
step("a >72-byte password can't be set (refused, not a 500)", r.status_code == 303 and not db.get_user("eve"))
step("Entra never takes over a LOCAL account of the same name", db.upsert_sso_user("admin", "viewer") is None
     and db.get_user("admin")["role"] == "admin" and (db.get_user("admin").get("auth_source") or "local") != "entra")
step("Entra users are still created and refreshed", db.upsert_sso_user("o'neil@x.invalid", "viewer") is not None)
t = adm.get("/admin").text
step("confirm() prompts are JS-safe for a name with an apostrophe",
     "confirm(\"Delete o\\u0027neil@x.invalid?\")" in t and "confirm('Delete o" not in t)

print("=== version ===")
step("/healthz reports the running version", anon.get("/healthz").json().get("version") == main.updates.current_version())
step("every page has the version footer", f"Zerto Monitor v{main.updates.current_version()}" in anon.get("/login").text)

print("=== one read/write credential per ZVM ===")
SID = db.add_source("Site-A", "zvm", "zvm.invalid", "client_credentials", "zm-client", crypto.encrypt("poll-secret-1"), False)
db.set_source_pins(SID, {443: "aa:" * 31 + "aa"})
seen = {}


class FakeClient:
    def __init__(self, host, auth_type, identity, secret, verify, session=None, writes=()):
        seen.update(host=host, auth=auth_type, identity=identity, secret=secret, writes=writes, session=session)

    def login(self):
        pass


real = vrapush.ZvmClient
vrapush.ZvmClient = FakeClient
vrapush.change_client(db.get_source(SID), zerto.WRITES_PLANS)
vrapush.ZvmClient = real
step("changes use the source's own credential, pinned, with only that feature's writes",
     seen["identity"] == "zm-client" and seen["secret"] == "poll-secret-1" and seen["auth"] == "client_credentials"
     and seen["writes"] == zerto.WRITES_PLANS and seen["session"] is not None)
src = db.get_source(SID)
step("a site needs only arming + a pin now (no second credential)",
     vrapush.site_problems(src) == ["Site-A isn't armed for changes"], vrapush.site_problems(src))
db.set_source_push(SID, push_identity=crypto.encrypt("old"), push_secret_enc=crypto.encrypt("old-secret"))
db.init()
s = db.get_source(SID)
step("an old separate change credential is wiped at start", not s.get("push_identity") and not s.get("push_secret_enc"))
step("/api/sources hides the identity", all("identity" not in x for x in adm.get("/api/sources").json()))
claims = {"realm_access": {"roles": ["default-roles-zerto", "viewer", "offline_access"]},
          "resource_access": {"zerto-client": {"roles": ["ZertoPrivilege_ManageVRA"]}}}
tok = "x." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".y"
step("the token's Zerto roles are read for display", zerto.token_roles(tok) == ["ZertoPrivilege_ManageVRA", "viewer"],
     zerto.token_roles(tok))
step("a garbage token gives no roles, no crash", zerto.token_roles("nope") == [])

print("=== write allowlists ===")
c = zerto.ZvmClient("zvm.invalid", "client_credentials", "i", "s", writes=zerto.WRITES_RESIZE)
c.base, c.headers = "https://zvm.invalid", {}
for bad in ("/v1/vras/..", "/v1/vras/.", "/v1/vras/1\n", "/v1/vras/1/../../vpgs"):
    try:
        c.write("PUT", bad, {})
        step(f"refuses PUT {bad!r}", False)
    except zerto.ZvmError:
        step(f"refuses PUT {bad!r}", True)
for bad in ("/v1/vpgSettings/exportedSettings/..", "/v1/vpgSettings/exportedSettings/1\n"):
    try:
        c.post_read(bad, {})
        step(f"post_read refuses {bad!r}", False)
    except zerto.ZvmError:
        step(f"post_read refuses {bad!r}", True)
step("a normal VRA id still passes", bool(zerto.WRITE_ALLOWED.fullmatch("/v1/vras/1234-abcd.5")))

print("=== sources and SNMP ===")
db.set_setting("snmp_agent_community", crypto.encrypt("goodcomm"))
r = adm.post("/admin/alerts/snmp-agent", data={"enabled": "1", "community": "my comm", "source": "203.0.113.0/24"},
             follow_redirects=False)
step("a bad SNMP community is refused before it replaces the good one",
     "err=" in r.headers["location"] and crypto.decrypt(db.get_setting("snmp_agent_community")) == "goodcomm")
db.set_registration(SID, "https://zvm.invalid/auth/realms/zerto/clients-registrations/openid-connect/x", "registration-token-1")
sent = {}


def fake_dereg(host, uri, tok, verify, session):
    sent["session"] = session
    return "could not reach zvm.invalid: ConnectionError"


zerto.deregister_client = fake_dereg
r = adm.post(f"/admin/sources/{SID}/delete", follow_redirects=False)
step("a source whose Keycloak client couldn't be removed is KEPT", db.get_source(SID) is not None
     and "NOT removed" in __import__("urllib.parse").parse.unquote(r.headers["location"]), r.headers["location"][:120])
step("  ...and the deregistration went over a pinned session", sent.get("session") is not None)
adm.post(f"/admin/sources/{SID}/delete", data={"force": "1"}, follow_redirects=False)
step("  ...'remove anyway' removes it", db.get_source(SID) is None)

print("\nALL GOOD" if not FAILED else f"\nFAILED {len(FAILED)}:\n   - " + "\n   - ".join(FAILED))
sys.exit(1 if FAILED else 0)
