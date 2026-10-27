"""Appliance hardening (1.5): updater rollback on any error + version-aware health check,
the root helper's set -e, console network safety (rollback apply, one adapter, MAC only,
UTC snapshots, no empty restore), signed console upgrade, and the build's base-image pick.
Offline: temp dirs only; every command, URL and service is stubbed."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path(tempfile.mkdtemp(prefix="zm-smoke15-"))
FAILED = []


def step(desc, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + str(detail)[:200]) if detail and not ok else ''}")
    if not ok:
        FAILED.append(desc)


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(mod)
    return mod


# ═════════════════════════════════════════════════════════ root updater
print("=== zerto-monitor-update: rollback + health check ===")
up = load("zmupd15", ROOT / "deploy/appliance/zerto-monitor-update")
up.APP, up.WORK, up.STATUS, up.LOG, up.BACKUPS = (TMP / "opt", TMP / "work", TMP / "status.json",
                                                   TMP / "update.log", TMP / "backups")
for d in (up.APP, up.WORK):
    d.mkdir()
(up.APP / "VERSION").write_text("1.4.0\n")
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:xz") as t:
    for name, data in (("VERSION", b"9.9.9\n"), ("firstboot.py", b"print('x')\n")):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
PAYLOAD = TMP / "payload.tar.xz"
PAYLOAD.write_bytes(buf.getvalue())
BK = TMP / "backups" / "pre-update-x"
up.verify = lambda path, dg: ({"version": "9.9.9", "sha256": "0" * 64}, PAYLOAD)


def scenario(backup, run_results, healthy_ok=True):
    """Run apply() with stubs; -> (rc, status, install_code calls, healthy expectations)."""
    calls, expects, runs = [], [], list(run_results)
    up.STATUS.unlink(missing_ok=True)
    up.backup = backup
    up.install_code = lambda src: calls.append(Path(src))

    def run_upgrade():
        r = runs.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r
    up.run_upgrade = run_upgrade
    up.healthy = lambda expected, timeout=150: expects.append(expected) or healthy_ok
    rc = up.apply(TMP / "x.zmupdate", False, "test")
    return rc, json.loads(up.STATUS.read_text()), calls, expects


rc, st, calls, _ = scenario(lambda: BK, [subprocess.TimeoutExpired("firstboot.py", 1200), True])
step("U1: run_upgrade timing out (apt/pip hang) rolls back to the backup",
     rc == 1 and calls and calls[-1] == BK and st["state"] == "rolled_back", (rc, st.get("state"), calls))
step("U1: ...and the error is logged", "ERROR installing 9.9.9" in up.LOG.read_text())
rc, st, calls, _ = scenario(lambda: BK, [OSError(28, "No space left on device"), OSError(28, "still full")])
step("U1: a failing rollback ends as failed (not a traceback), naming the backup",
     rc == 1 and st["state"] == "failed" and str(BK) in st["detail"], (rc, st))


def no_space():
    raise OSError(28, "No space left on device")


rc, st, calls, _ = scenario(no_space, [True])
step("U1: a backup failure installs nothing and says the old version is untouched",
     rc == 2 and not calls and st["state"] == "refused" and "untouched" in st["detail"], (rc, st, calls))
real_open = up.tarfile.open
up.tarfile.open = lambda *a, **k: (_ for _ in ()).throw(tarfile.ReadError("truncated"))
rc, st, calls, _ = scenario(lambda: BK, [True])
up.tarfile.open = real_open
step("U1: an unpack error after the backup still restores the backup",
     calls == [BK] and st["state"] == "rolled_back", (calls, st.get("state")))
rc, st, calls, expects = scenario(lambda: BK, [True, True], healthy_ok=False)
step("U3: install checks for the new version, rollback for the old one", expects == ["9.9.9", "1.4.0"], expects)

# healthy() itself, against a stubbed /healthz
up2 = load("zmupd15b", ROOT / "deploy/appliance/zerto-monitor-update")


class Resp:
    def __init__(self, body):
        self.status, self._b = 200, json.dumps(body).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def health(body, expected):
    up2.urllib.request.urlopen = lambda *a, **k: Resp(body)
    real_sleep, up2.time.sleep = up2.time.sleep, (lambda s: None)
    try:
        return up2.healthy(expected, timeout=0.2)
    finally:
        up2.time.sleep = real_sleep


real_urlopen = up2.urllib.request.urlopen
step("U3: healthy() accepts the expected version", health({"ok": True, "version": "9.9.9"}, "9.9.9"))
step("U3: healthy() rejects a still-running old version", not health({"ok": True, "version": "1.4.0"}, "9.9.9"))
step("U3: healthy() accepts an app that doesn't report a version yet", health({"ok": True}, "9.9.9"))
step("U3: healthy() rejects ok=false", not health({"ok": False, "version": "9.9.9"}, "9.9.9"))
up2.urllib.request.urlopen = real_urlopen

# ═════════════════════════════════════════════════════════ root helper (POSIX sh)
print("\n=== zerto-monitor-admin: errors propagate in socket mode ===")
admin = (ROOT / "deploy/appliance/zerto-monitor-admin").read_text()
step("U2: no `( dispatch ) || rc=$?` (it disables set -e)", "( dispatch \"$@\" ) || rc" not in admin)
shell = shutil.which("sh") or shutil.which("bash")
if shell:
    block = admin.split('if [ "${1:-}" = "--socket" ]; then', 1)[1].split("\nfi\n", 1)[0]
    block = block.replace("IFS= read -r line || die \"empty request\"", "line=x")
    script = ("set -eu\ndie() { echo \"ERROR: $1\"; exit 1; }\n"
              "dispatch() { false; echo SHOULD-NOT-PRINT; }\n" + block + "\n")
    f = TMP / "sock.sh"
    f.write_bytes(script.encode())
    r = subprocess.run([shell, str(f)], capture_output=True, text=True, timeout=30)
    step("U2: a failing command inside a verb stops it and reports __RC__=1",
         "SHOULD-NOT-PRINT" not in r.stdout and "__RC__=1" in r.stdout, r.stdout + r.stderr)
else:
    print("  [SKIP] U2 socket-mode run: no sh/bash on this host (checked textually above)")

# ═════════════════════════════════════════════════════════ console-ops network
print("\n=== zerto-monitor-console-ops: network safety ===")
z = load("zmops15", ROOT / "deploy/appliance/zerto-monitor-console-ops")
z.NETPLAN_DIR, z.BACKUP_ROOT, z.RUN_DIR, z.LOG = TMP / "netplan", TMP / "nbk", TMP / "run", TMP / "console.log"
z.PENDING = z.RUN_DIR / "pending.json"
z.signal = types.SimpleNamespace(signal=lambda *a: None, SIGHUP=1, SIG_IGN=None)   # no SIGHUP on Windows
z.refresh_motd = lambda: None
CMDS = []
z.sh = lambda cmd, **k: CMDS.append([str(c) for c in cmd]) or subprocess.CompletedProcess(cmd, 0, "", "")
z.NETPLAN_DIR.mkdir()
ORIG = "network: {version: 2}  # the old config\n"
(z.NETPLAN_DIR / "50-cloud-init.yaml").write_text(ORIG)


def stage_new():
    z.set_aside_others()
    z.write_ours("network: {version: 2}  # NEW\n")


for outcome, want_apply, want_rc in (("reverted", True, 3), ("unknown", True, 3), ("accepted", False, 0)):
    CMDS.clear()
    z.netplan_try = lambda o=outcome: o
    rc = z.change_network(stage_new, f"test {outcome}")
    applied = ["netplan", "apply"] in CMDS
    if outcome != "accepted":
        live = sorted(p.name for p in z.NETPLAN_DIR.iterdir())
        step(f"C1: '{outcome}' restores the old files AND runs netplan apply",
             rc == want_rc and applied and live == ["50-cloud-init.yaml"]
             and (z.NETPLAN_DIR / "50-cloud-init.yaml").read_text() == ORIG, (rc, applied, live))
    else:
        step("C1: 'accepted' keeps the new config without an extra apply", rc == 0 and not applied, (rc, CMDS))

snaps = sorted(p.name for p in z.BACKUP_ROOT.iterdir())
t0 = time.strftime("%Y%m%d-%H%M", time.gmtime())
step("C4: snapshot names are UTC", any(s.startswith((t0, time.strftime("%Y%m%d-%H%M", time.gmtime(time.time() - 60))))
                                       for s in snaps), (snaps, t0))
before = sorted(p.name for p in z.NETPLAN_DIR.iterdir())
for desc, snap in (("an empty", z.BACKUP_ROOT / "20000101-000000"), ("a missing", z.BACKUP_ROOT / "nope")):
    if desc == "an empty":
        snap.mkdir()
    try:
        z.restore_netplan(snap)
        step(f"C4: restoring {desc} snapshot is refused", False)
    except RuntimeError:
        step(f"C4: restoring {desc} snapshot is refused, /etc/netplan untouched",
             sorted(p.name for p in z.NETPLAN_DIR.iterdir()) == before)

# C2 + C3: one adapter, matched by MAC only
A = {"name": "ens192", "mac": "00:50:56:00:00:0a", "driver": "vmxnet3", "state": "up", "mtu": "1500",
     "ipv4": [{"cidr": "192.0.2.5/24", "dynamic": False}]}
B = {"name": "ens224", "mac": "00:50:56:00:00:0b", "driver": "vmxnet3", "state": "up", "mtu": "1500", "ipv4": []}
z.list_nics = lambda: [A, B]
z.precheck = lambda files: None
APPLIED = []
z.change_network = lambda stage, label: APPLIED.append(label) or 0


def net_apply(mac):
    a = z.parser().parse_args(["net-apply", "--mode", "static", "--mac", mac, "--address", "198.51.100.5/24"])
    try:
        return z.cmd_net_apply(a)
    except z.Invalid as e:
        return str(e)


z.write_ours(z.render_netplan(z.build_network("static", mac=A["mac"], address="192.0.2.5/24")))
r = net_apply(B["mac"])
step("C2: configuring a second adapter is refused while the first holds the config",
     isinstance(r, str) and "ens192" in r and not APPLIED, r)
step("C2: reconfiguring the same adapter is allowed", net_apply(A["mac"]) == 0 and len(APPLIED) == 1)
z.write_ours(z.render_netplan(z.build_network("dhcp", mac="00:50:56:00:00:99")))
step("C2: a config for a vNIC that is gone doesn't block the new one", net_apply(B["mac"]) == 0)
z.write_ours('network:\n  ethernets:\n    zm-nic0:\n      match:\n        driver: "e1000"\n      dhcp4: true\n')
A2 = dict(A, driver="e1000")
z.list_nics = lambda: [A2, B]
step("C2: a pre-1.5 driver-matched config counts as its adapter's",
     isinstance(net_apply(B["mac"]), str) and net_apply(A2["mac"]) == 0)
try:
    with contextlib.redirect_stderr(io.StringIO()):     # argparse's usage message
        z.parser().parse_args(["net-apply", "--mode", "dhcp", "--driver", "vmxnet3"])
    step("C3: --driver is gone from net-apply", False)
except SystemExit:
    step("C3: --driver is gone from net-apply", True)
try:
    z.build_network("dhcp", driver="vmxnet3")
    step("C3: build_network has no driver match", False)
except TypeError:
    step("C3: build_network has no driver match", True)
step("C3: rendered netplan matches by MAC only",
     "driver" not in z.render_netplan(z.build_network("dhcp", mac=A["mac"])))
fb = (ROOT / "deploy/appliance/firstboot.py").read_text(encoding="utf-8")
step("C3: first boot no longer picks a driver match", '{"driver"' not in fb)

# ═════════════════════════════════════════════════════════ console upgrade = signed updater
print("\n=== console Upgrade -> Apply goes through the signed updater ===")
step("C5: the unsigned payload staging is gone",
     not any(hasattr(z, n) for n in ("stage_payload", "ALLOWED_TOP", "PAYLOAD")))
a = z.parser().parse_args(["upgrade", "--allow-downgrade"])
step("C5: upgrade takes --allow-downgrade (default off)", a.allow_downgrade and not
     z.parser().parse_args(["upgrade"]).allow_downgrade)
if hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid"):
    z.BUNDLE, z.UPDATE_WORK, z.UPDATE_STATUS = TMP / "zm-update.zmupdate", TMP / "upd", TMP / "upd-status.json"
    z.SUDO_UID = os.geteuid()
    z.BUNDLE.write_bytes(b"bundle-bytes")
    os.chmod(z.BUNDLE, 0o600)

    def fake_sh(cmd, **k):
        CMDS.append(cmd)
        if cmd[:2] == ["systemctl", "start"]:
            z.UPDATE_STATUS.write_text(json.dumps({"state": "done", "from_version": "1", "to_version": "2"}))
        return subprocess.CompletedProcess(cmd, 3 if "is-active" in cmd else 0, "", "")
    z.sh = fake_sh
    rc = z.cmd_upgrade(z.parser().parse_args(["upgrade"]))
    req = json.loads((z.UPDATE_WORK / "request.json").read_text())
    step("C5: the bundle is handed over root-private with a request, and the updater unit runs",
         rc == 0 and (z.UPDATE_WORK / "incoming.zmupdate").read_bytes() == b"bundle-bytes"
         and req == {"allow_downgrade": False, "by": "console"}
         and ["systemctl", "start", "zerto-monitor-update.service"] in CMDS, (rc, req))
    os.chmod(z.BUNDLE, 0o666)
    try:
        z.cmd_upgrade(z.parser().parse_args(["upgrade"]))
        step("C5: a world-writable bundle is refused", False)
    except z.Invalid:
        step("C5: a world-writable bundle is refused", True)
else:
    print("  [SKIP] C5 bundle hand-over: needs O_NOFOLLOW/geteuid (Linux); structure checked above")
console = (ROOT / "deploy/appliance/zerto-monitor-console").read_text(encoding="utf-8")
step("C5: the menu no longer offers the unsigned payload", "zm-payload" not in console and "--allow-downgrade" in console)

# ═════════════════════════════════════════════════════════ build: exactly one base image
print("\n=== build_ova: base image pick ===")
os.environ["ZM_BUILD_DIR"] = str(TMP / "build")
sys.path.insert(0, str(ROOT / "deploy/appliance"))
import build_ova  # noqa: E402
build_ova.SRC = TMP / "build" / "src"
build_ova.SRC.mkdir(parents=True)
(build_ova.SRC / "ubuntu-a.ovf").write_text("x")
step("T5: one base image is used", build_ova._one("*.ovf").name == "ubuntu-a.ovf")
(build_ova.SRC / "ubuntu-b.ovf").write_text("x")
try:
    build_ova._one("*.ovf")
    step("T5: two base images are refused, not sorted()[0]", False)
except SystemExit as e:
    step("T5: two base images are refused, not sorted()[0]", "more than one" in str(e))

# ═════════════════════════════════════════════════════════ release tooling (text checks)
print("\n=== release tooling ===")
key = (ROOT / "deploy/new_release_key.ps1").read_text(encoding="utf-8")
step("T1: -Rotate refuses to overwrite a waiting key", "a rotated key is already waiting" in key)
step("T1: the key file is -KeyFile / $env:ZM_SIGNING_KEY / ~\\.zerto-monitor",
     "[string]$KeyFile" in key and "$env:ZM_SIGNING_KEY" in key and "\\.zerto-monitor\\release-signing.xml" in key)
step("T7: stale deploy files are gone", not any((ROOT / p).exists() for p in
     ("deploy/install.ps1", "deploy/cloud-init.yaml", "deploy/appliance/peek_ova.py")))

shutil.rmtree(TMP, ignore_errors=True)
print("\nALL GOOD" if not FAILED else f"\nFAILED {len(FAILED)}:\n   - " + "\n   - ".join(FAILED))
sys.exit(1 if FAILED else 0)
