"""Validate the built appliance OVA without ovftool.

Checks structure, manifest integrity, that Canonical's disk is untouched, that the
descriptor is well-formed and carries the expected properties, and - the important
one - that the application payload survives the whole round trip: descriptor ->
synthetic ovf-env.xml -> the guest's own parser -> tar.xz -> original files.

    python validate_ova.py                  # the full OVA
    python validate_ova.py --payload-only   # just payload.tar.xz (build_ova.py --payload-only)

Both modes also check every guest script (present, LF endings, compiles) and unit-test
the console's network validation and netplan rendering.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent              # deploy/appliance
APP_SRC = HERE.parent.parent                        # the ZertoMonitor project
sys.path.insert(0, str(HERE))
import build_ova  # noqa: E402  - single source of truth for version, paths, file list

WORK = build_ova.WORK
OVA = build_ova.OUT_OVA
APPLIANCE_FILES = build_ova.APPLIANCE_FILES
PAYLOAD_ONLY = "--payload-only" in sys.argv[1:]

OVF_NS = "{http://schemas.dmtf.org/ovf/envelope/1}"
RASD = "{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData}"
FAILED: list[str] = []


def step(desc: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'OK ' if ok else 'FAIL'}] {desc}{('  ' + detail) if detail else ''}")
    if not ok:
        FAILED.append(desc)
    return ok


def skip(desc: str, why: str) -> None:
    print(f"  [SKIP] {desc}  {why}")


def load(name: str, path: Path):
    loader = SourceFileLoader(name, str(path))      # works for extension-less scripts too
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(mod)
    return mod


# Canonical's disk hash, read from the manifest inside the base OVA we built from
# (whose own SHA-256 was checked against Canonical's published SHA256SUMS).
def _canonical_disk_hash() -> str:
    for line in build_ova.SRC_MF.read_text().splitlines():
        if line.startswith("SHA256(") and line.split(")")[0].endswith(".vmdk"):
            return line.split("= ", 1)[1].strip().lower()
    raise SystemExit(f"no disk hash in {build_ova.SRC_MF}")


def validate_ova() -> tuple[dict[str, bytes], dict[str, str]]:
    """Every OVA-level check; returns the payload files and the OVF properties."""
    print("=== structure ===")
    if not OVA.exists():
        sys.exit(f"missing {OVA}  (or run with --payload-only)")
    ubuntu_vmdk_sha256 = _canonical_disk_hash()

    with tarfile.open(OVA, "r") as t:
        members = t.getmembers()
        names = [m.name for m in members]
        blobs = {}
        for m in members:
            if m.name.endswith((".ovf", ".mf")):
                blobs[m.name] = t.extractfile(m).read()

    step("three members", len(names) == 3, str(names))
    step("descriptor is first", names[0].endswith(".ovf"), names[0])
    step("manifest is second", names[1].endswith(".mf"), names[1])
    step("disk is last", names[2].endswith(".vmdk"), names[2])
    step("no path separators in member names", all("/" not in n for n in names))
    step("ustar format, no pax/GNU extension entries",
         all(m.type in (tarfile.REGTYPE, tarfile.AREGTYPE) for m in members),
         ",".join(sorted({m.type.decode() if isinstance(m.type, bytes) else str(m.type)
                          for m in members})))

    ovf_name, mf_name, vmdk_name = names
    ovf_bytes = blobs[ovf_name]
    mf_text = blobs[mf_name].decode()

    print("\n=== manifest ===")
    listed = dict(ln.split(")= ")[0].replace("SHA256(", "").strip() and
                  (ln.split(")= ")[0].replace("SHA256(", "").strip(), ln.split(")= ")[1].strip())
                  for ln in mf_text.strip().splitlines())
    step("manifest lists the descriptor", ovf_name in listed)
    step("manifest lists the disk", vmdk_name in listed)
    step("manifest does not list itself", mf_name not in listed)
    step("descriptor hash matches", listed.get(ovf_name) == hashlib.sha256(ovf_bytes).hexdigest())

    # stream the disk once: verify both the manifest hash and that it is Canonical's
    h = hashlib.sha256()
    size = 0
    with tarfile.open(OVA, "r") as t:
        f = t.extractfile(vmdk_name)
        for blk in iter(lambda: f.read(8 << 20), b""):
            h.update(blk)
            size += len(blk)
    disk_sha = h.hexdigest()
    step("disk hash matches the manifest", listed.get(vmdk_name) == disk_sha)
    step("disk is Canonical's, byte-for-byte", disk_sha == ubuntu_vmdk_sha256, disk_sha[:16] + "...")

    print("\n=== descriptor ===")
    try:
        root = ET.fromstring(ovf_bytes)
        step("descriptor is well-formed XML", True)
    except ET.ParseError as e:
        step("descriptor is well-formed XML", False, str(e))
        sys.exit(1)

    file_el = root.find(f".//{OVF_NS}References/{OVF_NS}File")
    declared = int(file_el.get(f"{OVF_NS}size"))
    step("File ovf:size equals the disk member size", declared == size, f"{declared:,} vs {size:,}")
    step("File href matches the disk member", file_el.get(f"{OVF_NS}href") == vmdk_name)

    disk_el = root.find(f".//{OVF_NS}DiskSection/{OVF_NS}Disk")
    step("disk capacity untouched (10 GiB)",
         disk_el.get(f"{OVF_NS}capacity") == "10737418240", disk_el.get(f"{OVF_NS}capacity"))
    step("disk format still streamOptimized",
         "streamOptimized" in disk_el.get(f"{OVF_NS}format"))

    vhs = root.find(f".//{OVF_NS}VirtualHardwareSection")
    transport = vhs.get(f"{OVF_NS}transport")
    step("transport declared", bool(transport), transport)
    step("iso transport present (cloud-init reads it)", "iso" in (transport or ""))

    mem = [i for i in vhs.findall(f"{OVF_NS}Item") if i.findtext(f"{RASD}ResourceType") == "4"]
    memqty = mem[0].findtext(f"{RASD}VirtualQuantity")
    step("memory raised to 4096 MB", memqty == "4096", memqty)

    # vSphere 7+ silently DROPS a CD-ROM parented to a SCSI controller. No CD-ROM means
    # no ISO transport, which means the wizard values never reach the guest and the
    # appliance boots unconfigured with no error anywhere.
    items = vhs.findall(f"{OVF_NS}Item")
    ide = {i.findtext(f"{RASD}InstanceID") for i in items if i.findtext(f"{RASD}ResourceType") == "5"}
    cds = [i for i in items if i.findtext(f"{RASD}ResourceType") == "15"]
    step("a CD-ROM device exists for the ISO transport", bool(cds))
    step("CD-ROM is parented to an IDE controller",
         all(c.findtext(f"{RASD}Parent") in ide for c in cds),
         f"parent={cds[0].findtext(f'{RASD}Parent') if cds else None} ide={sorted(ide)}")
    step("original InstanceIDs 1-12 untouched",
         {str(n) for n in range(1, 13)} <= {i.findtext(f"{RASD}InstanceID") for i in items})

    print("\n=== properties ===")
    props = {}
    meta = {}
    for pel in root.iter(f"{OVF_NS}Property"):
        k = pel.get(f"{OVF_NS}key")
        props[k] = pel.get(f"{OVF_NS}value") or ""
        meta[k] = (pel.get(f"{OVF_NS}userConfigurable"), pel.get(f"{OVF_NS}password"))

    expected_visible = ["zm-hostname", "zm-net-dhcp", "zm-net-address", "zm-net-prefix",
                        "zm-net-gateway", "zm-net-dns1", "zm-net-dns2", "zm-net-search",
                        "zm-root-password", "zm-admin-user", "zm-admin-password", "zm-ssh-key",
                        "zm-web-user", "zm-web-password", "zm-timezone", "zm-ntp-server",
                        "zm-zvm-name", "zm-zvm-host", "zm-zvm-user", "zm-zvm-password"]
    missing = [k for k in expected_visible if k not in props]
    step("every wizard property present", not missing, f"missing={missing}")
    step("wizard properties are user-configurable",
         all(meta[k][0] == "true" for k in expected_visible if k in meta))
    for secret in ("zm-root-password", "zm-admin-password", "zm-web-password", "zm-zvm-password"):
        step(f"{secret} is masked", meta.get(secret, (None, None))[1] == "true")
    step("payload properties hidden from the operator",
         all(meta[k][0] == "false" for k in props if k.startswith("zm-payload")))

    # DSP0243 9.5: ovf:key shall not contain '.' or ':' - dots also collide with the
    # [class '.'] key ['.' instance] grammar that composes the guest-visible key.
    bad_keys = [k for k in props if "." in k or ":" in k]
    step("no ovf:key contains '.' or ':' (DSP0243 9.5)", not bad_keys, f"bad={bad_keys}")
    reserved = {"hostname", "password", "public-keys", "seedfrom"}
    step("no cloud-init reserved key is reused for appliance settings",
         not (reserved & set(props)), f"clash={sorted(reserved & set(props))}")
    step("instance-id is present and non-empty",
         bool(props.get("instance-id")), repr(props.get("instance-id")))
    step("user-data hidden from the operator", meta.get("user-data", (None,))[0] == "false")

    sizes = {k: len(v) for k, v in props.items() if v}
    biggest = max(sizes.values())
    total = sum(sizes.values())
    # The verified limit is per property: vSphere caps a vApp property value at 65,535
    # characters. The environment as a whole is bounded by the guestInfo transport
    # (~1 MB), far above anything this appliance needs.
    step("every property under vSphere's 65,535-char limit", biggest <= 65535, f"largest {biggest:,} chars")
    step("whole OVF environment well inside the guestInfo transport", total < 512 * 1024, f"{total:,} chars")

    print("\n=== guest-side round trip ===")
    # Rebuild the ovf-env.xml exactly as vCenter would present it, then feed it to the
    # guest's own parser. This is the real test of the delivery mechanism.
    env = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1"',
           '  xmlns:oe="http://schemas.dmtf.org/ovf/environment/1"',
           '  xmlns:ve="http://www.vmware.com/schema/ovfenv"',
           '  oe:id="" ve:esxId="vm-42">',
           '  <PlatformSection><Kind>VMware ESXi</Kind><Version>8.0.3</Version></PlatformSection>',
           '  <PropertySection>']
    for k, v in props.items():
        env.append(f'    <Property oe:key="{k}" oe:value="{v}"/>')
    env += ['  </PropertySection>', '</Environment>']
    env_xml = "\n".join(env)

    bootstrap = load("zm_bootstrap", HERE / "bootstrap.py")
    firstboot = load("zm_firstboot", HERE / "firstboot.py")
    step("bootstrap.py imports cleanly", True)
    step("firstboot.py imports cleanly", True)

    parsed_b = bootstrap.parse_props(env_xml)
    parsed_f = firstboot.parse_props(env_xml)
    step("bootstrap parser recovers every property", parsed_b == props,
         f"{len(parsed_b)}/{len(props)}")
    step("firstboot parser recovers every property", parsed_f == props)

    chunks = []
    i = 0
    while f"zm-payload{i}" in parsed_b:
        chunks.append(parsed_b[f"zm-payload{i}"])
        i += 1
    step("payload chunks contiguous from 0", len(chunks) > 0, f"{len(chunks)} chunks")
    blob = base64.b64decode("".join(chunks))
    if build_ova.OUT_PAYLOAD.exists():
        step("OVA payload equals payload.tar.xz", blob == build_ova.OUT_PAYLOAD.read_bytes())
    return unpack(blob), props


def unpack(blob: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:xz") as t:
        got = {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
    step("payload is a readable tar.xz", bool(got), f"{len(got)} files, {len(blob):,} bytes")
    return got


def check_payload(got: dict[str, bytes]) -> None:
    step("firstboot.py travels in the payload", "firstboot.py" in got)
    step("requirements.txt travels in the payload", "requirements.txt" in got)
    step(f"VERSION travels in the payload and says {build_ova.VERSION}",
         got.get("VERSION") == f"{build_ova.VERSION}\n".encode())

    mismatch = []
    for name, data in got.items():
        if name == "VERSION":
            continue
        if name == "firstboot.py":
            src, want = HERE / "firstboot.py", None
        elif name.startswith("appliance/"):
            # shell scripts are normalised to LF on the way in
            src = HERE / name.split("/", 1)[1]
            want = src.read_bytes().replace(b"\r\n", b"\n") if src.is_file() else None
        else:
            src, want = APP_SRC / name, None
        if not src.is_file() or (want if want is not None else src.read_bytes()) != data:
            mismatch.append(name)
    for name in APPLIANCE_FILES:
        key = f"appliance/{name}"
        step(f"{key} travels in the payload", key in got)
        if key in got:
            step(f"{key} has LF line endings", b"\r\n" not in got[key])
            step(f"{key} has a shebang", got[key].startswith(b"#!/"),
                 got[key].split(b"\n", 1)[0].decode(errors="replace"))
    for name in build_ova.APPLIANCE_DATA:
        step(f"appliance/{name} travels in the payload", f"appliance/{name}" in got)
    pub = got.get("appliance/release-signing.pub", b"")
    step("the release key in the payload is a PUBLIC key only", pub.startswith(b"-----BEGIN PUBLIC KEY-----")
         and b"PRIVATE" not in pub)
    step("every payload file is byte-identical to source", not mismatch, f"bad={mismatch[:4]}")

    expect_app = {p.relative_to(APP_SRC).as_posix()
                  for d in ("app", "templates", "static")
                  for p in (APP_SRC / d).rglob("*")
                  if build_ova.packable(p)}
    step("no application file left behind", expect_app <= set(got),
         f"absent={sorted(expect_app - set(got))[:4]}")

    print("\n=== syntax (as shipped) ===")
    for name, data in sorted(got.items()):
        first = data.split(b"\n", 1)[0]
        # the installer and every guest script (app/ is checked by its own tests)
        if name == "firstboot.py" or (name.startswith("appliance/") and b"python" in first):
            try:
                compile(data, name, "exec")
                step(f"{name} compiles", True)
            except SyntaxError as e:
                step(f"{name} compiles", False, f"line {e.lineno}: {e.msg}")
        elif name.startswith("appliance/") and first.endswith((b"/sh", b"/bash")):
            shell = shutil.which("sh") or shutil.which("bash")
            if not shell:
                skip(f"{name} 'sh -n'", "(no POSIX shell on this host; firstboot.py runs "
                     "'sh -n' on the appliance before installing it)")
                continue
            tmp = WORK / "shcheck.tmp"
            tmp.write_bytes(data)
            r = subprocess.run([shell, "-n", str(tmp)], capture_output=True, text=True)
            tmp.unlink()
            step(f"{name} passes 'sh -n'", r.returncode == 0, (r.stderr or "").strip()[:120])
    try:
        compile((HERE / "bootstrap.py").read_bytes(), "bootstrap.py", "exec")
        step("bootstrap.py compiles", True)
    except SyntaxError as e:
        step("bootstrap.py compiles", False, str(e))


def check_console() -> None:
    """Unit-test the shared network rules and the install wiring, from source."""
    print("\n=== console menu ===")
    z = load("zm_console_ops", HERE / "zerto-monitor-console-ops")
    fb = load("zm_firstboot_c", HERE / "firstboot.py")

    def rejects(desc, **kw):
        mode = kw.pop("mode", "static")
        try:
            z.build_network(mode, **kw)
            step(f"rejects {desc}", False)
        except z.Invalid:
            step(f"rejects {desc}", True)

    s = z.build_network("static", mac="00:50:56:AA:BB:CC", address="192.0.2.5/24",
                        prefix="16", gateway="192.0.2.1", dns="192.0.2.10, 192.0.2.11",
                        search="example.com", mtu="9000")
    step("address with its own /prefix wins over the prefix field", s["address"] == "192.0.2.5/24")
    s2 = z.build_network("static", mac="00:50:56:aa:bb:cd", address="198.51.100.16",
                         prefix="255.255.255.128", gateway="198.51.100.126")
    step("dotted mask accepted as a prefix", s2["address"] == "198.51.100.16/25")
    rejects("an address that isn't one", mac="00:50:56:aa:bb:cc", address="192.0.2.300/24")
    rejects("a gateway outside the subnet", mac="00:50:56:aa:bb:cc", address="192.0.2.5/24",
            gateway="198.51.100.1")
    rejects("the network address as host", mac="00:50:56:aa:bb:cc", address="192.0.2.0/24")
    rejects("a non-contiguous mask", mac="00:50:56:aa:bb:cc", address="192.0.2.5",
            prefix="255.0.255.0")
    rejects("YAML injection in DNS", mac="00:50:56:aa:bb:cc", address="192.0.2.5/24",
            dns="192.0.2.1]\n  evil: [x")
    rejects("a bad search domain", mac="00:50:56:aa:bb:cc", address="192.0.2.5/24",
            search="example..com")
    rejects("an out-of-range MTU", mac="00:50:56:aa:bb:cc", address="192.0.2.5/24", mtu="70000")
    rejects("an address in DHCP mode", mode="dhcp", mac="00:50:56:aa:bb:cc", address="192.0.2.5/24")
    rejects("no adapter match", address="192.0.2.5/24")

    y = z.render_netplan(s)
    import re
    step("netplan matches by MAC, not interface name",
         'macaddress: "00:50:56:aa:bb:cc"' in y and "    zm-nic0:" in y and "set-name" not in y
         and not re.search(r"\b(ens|enp|eth)\d", y))
    step("netplan carries address, route, DNS, search, MTU",
         all(t in y for t in ('"192.0.2.5/24"', 'via: "192.0.2.1"', '"192.0.2.10", "192.0.2.11"',
                              '"example.com"', "mtu: 9000")))
    step("netplan never matches by driver (a hot-added vNIC would share the address)",
         "driver" not in z.render_netplan(s2) and not hasattr(z, "v_driver"))
    yd = z.render_netplan(z.build_network("dhcp", mac="00:50:56:aa:bb:cc"))
    step("DHCP netplan has no static address", "dhcp4: true" in yd and "addresses" not in yd)
    try:
        import yaml  # noqa: F401  (only if the dev venv happens to have PyYAML)
        doc = yaml.safe_load(y)
        step("rendered netplan parses as YAML",
             doc["network"]["ethernets"]["zm-nic0"]["addresses"] == ["192.0.2.5/24"])
    except ImportError:
        skip("rendered netplan parses as YAML", "(PyYAML not installed here)")

    step("ops verbs are a fixed list", set(z.VERBS) == {
        "net-apply", "net-restore", "net-show", "net-confirm", "net-rollback-now", "hostname",
        "tls-selfsigned", "time-ntp", "time-tz", "time-sync", "disk-info", "disk-grow",
        "svc-restart", "logs", "upgrade", "web-users", "web-password", "os-password",
        "ssh-password", "posture", "power"}, ",".join(sorted(z.VERBS)))
    step("web password reset runs as the service user",
         '"runuser", "-u", SVC_USER' in (HERE / "zerto-monitor-console-ops").read_text())
    admin = (HERE / "zerto-monitor-admin").read_text()
    step("no console verb was added to the web app's helper",
         not any(v in admin for v in ("net-apply", "disk-grow", "netplan", "growpart")))

    hook = fb.PROFILE_HOOK_TEXT
    step("login hook skips TERM=dumb", "dumb|unknown) return 0" in hook)
    step("login hook skips non-interactive shells", 'case "$-" in *i*) ;; *) return 0' in hook)
    step("login hook skips non-login shells (ssh host command, bash -l)",
         'case "$0" in -*) ;; *) return 0' in hook)
    step("login hook needs a TTY on stdin and stdout", "[ -t 0 ] && [ -t 1 ] || return 0" in hook)
    step("login hook has no CR", "\r" not in hook)
    step("sudoers grants exactly the ops script",
         fb.SUDOERS_TEXT.strip().splitlines()[-1] ==
         "%zmconsole ALL=(root) NOPASSWD: /usr/local/sbin/zerto-monitor-console-ops")
    step("/etc/issue shows the URL via agetty's \\4", "https://\\4/" in fb.ISSUE_TEXT)
    for pkg in ("whiptail", "cloud-guest-utils", "chrony", "libpango-1.0-0",
                "libpangoft2-1.0-0", "libharfbuzz-subset0", "fonts-dejavu-core"):
        step(f"apt installs {pkg}", pkg in fb.PACKAGES)
    up = (HERE / "firstboot.py").read_text().split("def upgrade()", 1)[1].split("\nif __name__", 1)[0]
    for call in ("install_packages()", "build_venv()", "install_console()"):
        step(f"--upgrade runs {call}", call in up)
    step("build_venv pip-installs requirements.txt",
         '"-r", str(req)' in (HERE / "firstboot.py").read_text())


# ── run ─────────────────────────────────────────────────────────────────────
if PAYLOAD_ONLY:
    print(f"=== payload only: {build_ova.OUT_PAYLOAD} ===")
    if not build_ova.OUT_PAYLOAD.exists():
        sys.exit(f"missing {build_ova.OUT_PAYLOAD}; run build_ova.py --payload-only first")
    pl = build_ova.OUT_PAYLOAD.read_bytes()
    got = unpack(pl)
    b64 = len(base64.b64encode(pl))
    step("payload well inside the guestInfo transport", b64 < 400 * 1024,
         f"{b64:,} base64 chars -> {-(-b64 // build_ova.CHUNK)} properties of {build_ova.CHUNK:,}")
    props = None
else:
    got, props = validate_ova()
check_payload(got)
check_console()

if props is not None:
    print("\n=== user-data ===")
    cc = base64.b64decode(props["user-data"]).decode()
    step("user-data decodes to a cloud-config", cc.startswith("#cloud-config"))
    step("cloud-config runs the bootstrap", "/opt/zerto-monitor/bootstrap.py" in cc)
    emb = cc.split("content: ")[1].split("\n")[0].strip()
    step("embedded bootstrap.py matches source",
         base64.b64decode(emb) == (HERE / "bootstrap.py").read_bytes())

print()
if FAILED:
    print(f"FAILED {len(FAILED)}:")
    for f in FAILED:
        print("   - " + f)
    sys.exit(1)
print(f"ALL GOOD - {build_ova.OUT_PAYLOAD.name if PAYLOAD_ONLY else OVA.name}"
      + ("" if PAYLOAD_ONLY else f", {OVA.stat().st_size:,} bytes"))
