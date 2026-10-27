"""Signed self-update (1.4): signing, bundle checks (web side and root updater), portal and
token API. Offline: a throwaway key, .invalid hosts, the root helper stubbed."""
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke14-"))
os.environ.update(DATA_DIR=str(TMP), TLS_DIR=str(TMP / "tls"), ADMIN_SOCKET=str(TMP / "no.sock"),
                  OVFENV_STATE=str(TMP / "ovfenv.state"), UPDATE_STATUS=str(TMP / "update-status.json"),
                  RUNTIME_DIRECTORY=str(TMP / "run"))
from cryptography.fernet import Fernet  # noqa: E402
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "deploy"))
FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)[:200]) if detail and not ok else ''}")
    if not ok:
        FAILED.append(desc)


from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import release_signing as rs  # noqa: E402


def payload(version, extra=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as t:
        for name, data in (("VERSION", f"{version}\n".encode()), ("firstboot.py", b"print('x')\n"),
                           ("app/main.py", b"# app\n"), *extra):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


KEY, OTHER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
PUBPEM = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
(TMP / "release-signing.pub").write_bytes(PUBPEM)

print("=== signing (workstation) ===")
b, m = rs.make_bundle(KEY, payload("9.9.9"), "9.9.9")
step("a bundle verifies with its key", rs.verify_bundle(b, KEY.public_key())["version"] == "9.9.9")
try:
    rs.verify_bundle(b, OTHER.public_key())
    step("a different key rejects it", False)
except Exception:  # noqa: BLE001
    step("a different key rejects it", True)
try:
    rs.make_bundle(KEY, payload("9.9.8"), "9.9.9")
    step("signing refuses a payload of another version", False)
except SystemExit:
    step("signing refuses a payload of another version", True)


def tamper(bundle, new_payload):
    out = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as src, tarfile.open(fileobj=out, mode="w:") as dst:
        for mem in src.getmembers():
            data = new_payload if mem.name == "payload.tar.xz" else src.extractfile(mem).read()
            mem.size = len(data)
            dst.addfile(mem, io.BytesIO(data))
    return out.getvalue()


BAD = tamper(b, payload("9.9.9", extra=(("app/evil.py", b"import os\n"),)))

print("\n=== web-side check (updates.inspect) ===")
import updates  # noqa: E402
updates.PUBKEY_PATHS = (TMP / "release-signing.pub",)
updates.current_version = lambda: "1.4.0"
info = updates.inspect(b)
step("signed bundle: accepted, 'newer' than 1.4.0", info["relation"] == "newer" and info["version"] == "9.9.9")
for name, data in (("payload swapped after signing", BAD), ("signed with another key", rs.make_bundle(OTHER, payload("9.9.9"), "9.9.9")[0]),
                   ("not a bundle at all", b"hello")):
    try:
        updates.inspect(data)
        step(f"refused: {name}", False)
    except updates.UpdateError as e:
        step(f"refused: {name}", True, str(e))
old, _ = rs.make_bundle(KEY, payload("1.3.0"), "1.3.0")
step("an older signed release is recognised as older", updates.inspect(old)["relation"] == "older")

print("\n=== root updater (zerto-monitor-update) ===")
loader = importlib.machinery.SourceFileLoader("zmupd", str(ROOT / "deploy/appliance/zerto-monitor-update"))
spec = importlib.util.spec_from_loader("zmupd", loader)
up = importlib.util.module_from_spec(spec)
loader.exec_module(up)
APPDIR = TMP / "opt"
APPDIR.mkdir()
(APPDIR / "VERSION").write_text("1.4.0\n")
up.APP, up.WORK, up.PUBKEY = APPDIR, TMP / "work", TMP / "release-signing.pub"
up.WORK.mkdir()


def verify_with_cryptography(manifest, sig):          # the box uses openssl; same check here
    try:
        KEY.public_key().verify(sig, manifest) if False else \
            serialization.load_pem_public_key(up.PUBKEY.read_bytes()).verify(sig, manifest)
    except Exception:  # noqa: BLE001
        raise up.Refused("SIGNATURE INVALID") from None


up.verify_signature = verify_with_cryptography
f = TMP / "b.zmupdate"
f.write_bytes(b)
m2, _ = up.verify(f, False)
step("updater accepts the genuine newer bundle", m2["version"] == "9.9.9")
for name, data, dg in (("tampered payload", BAD, False), ("older without permission", old, False)):
    f.write_bytes(data)
    try:
        up.verify(f, dg)
        step(f"updater refuses: {name}", False)
    except up.Refused as e:
        step(f"updater refuses: {name}", True, str(e))
f.write_bytes(old)
step("older is allowed only when explicitly requested", up.verify(f, True)[0]["version"] == "1.3.0")
for evil in (("../etc/cron.d/x", b"x"), ("/etc/passwd", b"x"), ("bin/sh", b"x")):
    eb, _ = rs.make_bundle(KEY, payload("9.9.9", extra=(evil,)), "9.9.9")
    f.write_bytes(eb)
    try:
        up.verify(f, False)
        step(f"updater refuses a payload path {evil[0]!r}", False)
    except up.Refused:
        step(f"updater refuses a payload path {evil[0]!r}", True)
extra = io.BytesIO()
with tarfile.open(fileobj=io.BytesIO(b), mode="r:") as src, tarfile.open(fileobj=extra, mode="w:") as dst:
    for mem in src.getmembers():
        dst.addfile(mem, src.extractfile(mem))
    ti = tarfile.TarInfo("run-me.sh")
    ti.size = 2
    dst.addfile(ti, io.BytesIO(b"x\n"))
f.write_bytes(extra.getvalue())
try:
    up.verify(f, False)
    step("updater refuses a bundle with an extra file", False)
except up.Refused:
    step("updater refuses a bundle with an extra file", True)

print("\n=== portal + token API ===")
import db  # noqa: E402
db.init()
db.set_setting("update_source", "https://releases.invalid/api/packages/x/generic")
import requests  # noqa: E402
GETS = []


def _offline(url, **kw):                              # never touch the network: every host is "unreachable"
    GETS.append((url, kw))
    raise requests.ConnectionError("offline test")


requests.get = _offline
import auth  # noqa: E402
import collector  # noqa: E402
import tlsmgr  # noqa: E402
import vrapush  # noqa: E402
import backups  # noqa: E402
CALLS = []
tlsmgr.helper = lambda *a, **k: CALLS.append(a) or "update started"


async def _idle():
    return None


collector.loop_forever = _idle
vrapush.worker = _idle
backups.worker = _idle
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def client(user=None, pw=None):
    c = TestClient(main.app, client=("203.0.113.9", 50000))
    c.__enter__()
    if user:
        assert c.post("/login", data={"username": user, "password": pw, "next": "/"}, follow_redirects=False).status_code == 303
    return c


boot = client()
boot.post("/setup", data={"username": "admin", "password": "admin-pw-123"}, follow_redirects=False)
adm = client("admin", "admin-pw-123")
adm.post("/admin/users", data={"username": "eng", "password": "eng-pw-12345", "role": "engineer"})
eng, anon = client("eng", "eng-pw-12345"), client()
r = adm.get("/admin/updates")
step("Updates page renders for an admin (index unreachable is reported, not fatal)", r.status_code == 200
     and "Installed" in r.text and "release index" in r.text, r.status_code)
step("engineers can't open it", eng.get("/admin/updates", follow_redirects=False).status_code == 403)
r = adm.post("/admin/updates/upload", files={"bundle": ("x.zmupdate", BAD)}, follow_redirects=False)
step("uploading a tampered bundle is refused", "SIGNATURE" in r.headers.get("location", "").replace("+", " ").replace("%20", " ")
     or "match" in r.headers.get("location", ""), r.headers.get("location"))
r = adm.post("/admin/updates/upload", files={"bundle": ("x.zmupdate", b)}, follow_redirects=False)
step("a signed bundle uploads and is staged", (updates.staged() or {}).get("version") == "9.9.9")
r = adm.post("/admin/updates/apply", data={"typed": "9.9.8"}, follow_redirects=False)
step("apply needs the version typed exactly", not CALLS)
r = adm.post("/admin/updates/apply", data={"typed": "9.9.9"}, follow_redirects=False)
step("apply hands it to the root helper (normal mode, by admin)", CALLS == [("update-start", "normal", "admin")], CALLS)
r = adm.post("/admin/updates/tokens", data={"name": "deploy bot", "days": "7"})
tok = next((ln.split("<code")[1].split(">")[1].split("<")[0] for ln in r.text.splitlines() if "zmd_" in ln and "<code" in ln), "")
step("token created and shown once", tok.startswith("zmd_") and len(tok) > 40)
with db._conn() as _c:
    _rows = [tuple(r) for r in _c.execute("SELECT * FROM deploy_tokens")]
step("only its hash is stored", tok not in json.dumps(db.list_deploy_tokens()) and not any(tok in str(v) for row in _rows for v in row))
step("token reads status", anon.get("/api/update/status", headers={"Authorization": f"Bearer {tok}"}).status_code == 200)
step("no token -> 401", anon.get("/api/update/status").status_code == 401)
step("a wrong token -> 401", anon.get("/api/update/status", headers={"Authorization": "Bearer zmd_nope"}).status_code == 401)
real_fetch = updates.fetch
updates.fetch = lambda v: updates.stage(old)
r = anon.post("/api/update/apply", json={"version": "1.3.0"}, headers={"Authorization": f"Bearer {tok}"})
step("a token can't downgrade (409) and nothing is started", r.status_code == 409 and len(CALLS) == 1, (r.status_code, r.text[:120]))
updates.fetch = lambda v: updates.stage(b)
r = anon.post("/api/update/apply", json={"version": "9.9.9"}, headers={"Authorization": f"Bearer {tok}"})
step("a token applies a newer signed release (202), recorded as the token", r.status_code == 202
     and CALLS[-1] == ("update-start", "normal", "token-deploy-bot"), (r.status_code, CALLS[-1:]))
tid = db.list_deploy_tokens()[0]["id"]
adm.post(f"/admin/updates/tokens/{tid}/revoke", follow_redirects=False)
step("a revoked token stops working", anon.get("/api/update/status", headers={"Authorization": f"Bearer {tok}"}).status_code == 401)

print("\n=== release sources (requests.get stubbed) ===")
import hashlib  # noqa: E402


class FakeResp:
    def __init__(self, status=200, body=b""):
        self.status_code, self.body, self.raw = status, body, io.BytesIO(body)
        self.raw.read = lambda n=-1, decode_content=False, _r=self.raw.read: _r(n)

    def json(self):
        return json.loads(self.body)


def serve(pages):
    def get(url, **kw):
        GETS.append((url, kw))
        return FakeResp(*pages[url]) if url in pages else FakeResp(404)
    requests.get = get


IDX = {"releases": [{"version": "9.9.9", "bundle": "zerto-monitor-9.9.9.zmupdate", "sha256": hashlib.sha256(b).hexdigest()},
                    {"version": "1.3.0", "bundle": "zerto-monitor-1.3.0.zmupdate"}]}
db.set_setting("update_source", "")
GETS.clear()
try:
    updates.releases()
    step("empty default: releases() says no index is configured", False)
except updates.UpdateError as e:
    step("empty default: releases() says no index is configured", "no release index configured" in str(e) and not GETS, str(e))
step("  ...the shipped default is empty", updates.DEFAULT_SOURCE == "" and updates.source() == "")
step("  ...and the Updates page says so instead of an error", "No release index configured" in adm.get("/admin/updates").text)

BASE = "https://git.example.invalid/api/packages/OWNER/generic"
db.set_setting("update_source", BASE + "/")
serve({f"{BASE}/zerto-monitor-index/current/releases.json": (200, json.dumps(IDX).encode()),
       f"{BASE}/zerto-monitor/9.9.9/zerto-monitor-9.9.9.zmupdate": (200, b)})
GETS.clear()
rel = updates.releases()
step("package-registry base: index read from {base}/zerto-monitor-index/current/releases.json",
     GETS and GETS[0][0] == f"{BASE}/zerto-monitor-index/current/releases.json", GETS[:1])
step("  ...bundle URL is {base}/zerto-monitor/{ver}/{bundle}, newest first",
     [x["version"] for x in rel] == ["9.9.9", "1.3.0"] and rel[0]["url"] == f"{BASE}/zerto-monitor/9.9.9/zerto-monitor-9.9.9.zmupdate", rel)
updates.discard_staged()
step("  ...fetch() downloads, checks and stages it", real_fetch("9.9.9")["version"] == "9.9.9")

IDXURL = "https://github.example.invalid/OWNER/REPO/releases/latest/download/releases.json"
ASSET = "https://objects.example.invalid/OWNER/REPO/zerto-monitor-9.9.9.zmupdate"
db.set_setting("update_source", IDXURL)
IDX["releases"][0]["url"] = ASSET
serve({IDXURL: (200, json.dumps(IDX).encode()), ASSET: (200, b)})
GETS.clear()
rel = updates.releases()
step("index URL ending in .json: used as-is", GETS[0][0] == IDXURL, GETS[:1])
step("  ...each entry's url gives the bundle (a missing one resolves next to the index)",
     rel[0]["url"] == ASSET and rel[1]["url"] == IDXURL.rsplit("/", 1)[0] + "/zerto-monitor-1.3.0.zmupdate", rel)
updates.discard_staged()
step("  ...fetch() downloads that url and stages it", real_fetch("9.9.9")["version"] == "9.9.9" and GETS[-1][0] == ASSET)
step("index and bundle downloads follow redirects and send no credentials",
     all(kw.get("allow_redirects") is True and not kw.get("auth") and not kw.get("headers") for _, kw in GETS), GETS)
step("the Admin form saves a .json index URL", "msg=" in adm.post("/admin/updates/source", data={"url": IDXURL},
                                                                    follow_redirects=False).headers["location"]
     and db.get_setting("update_source") == IDXURL)
requests.get = _offline
updates.discard_staged()
sso = {"entra_enabled": "1", "entra_tenant_id": "00000000-0000-0000-0000-000000000001",
       "entra_client_id": "00000000-0000-0000-0000-000000000002", "entra_client_secret": "not-a-real-secret",
       "entra_admin_group": "ZertoMonitor.Admin", "entra_engineer_group": "ZertoMonitor.Engineer"}
adm.post("/admin/sso", data={**sso, "entra_button_label": "  Sign in with Entra ID (ad.example.invalid) "}, follow_redirects=False)
h = anon.get("/login").text
step("SSO button shows the configured label (trimmed)", ">Sign in with Entra ID (ad.example.invalid)<" in h)
step("admin form labels the role fields as app-role values, not group names",
     "Admin app-role value" in adm.get("/admin").text)
adm.post("/admin/sso", data={**sso, "entra_button_label": ""}, follow_redirects=False)
step("blank label falls back to the default", ">Sign in with Entra ID<" in anon.get("/login").text)
adm.post("/admin/sso", data={**sso, "entra_button_label": "<b>x</b>"}, follow_redirects=False)
step("the label is escaped", "&lt;b&gt;x&lt;/b&gt;" in anon.get("/login").text)
db.set_setting("require_login", "true")
main._login_cache["at"] = 0
step("with sign-in required, the token API still works for a valid admin session",
     adm.get("/api/update/status").status_code == 200)

print("\nALL GOOD" if not FAILED else f"\nFAILED {len(FAILED)}:\n   - " + "\n   - ".join(FAILED))
sys.exit(1 if FAILED else 0)
