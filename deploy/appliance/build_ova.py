"""Build the Zerto Monitor appliance OVA from Canonical's Ubuntu 26.04 cloud OVA.

Pure Python: no ovftool, no qemu-img. The Canonical VMDK is reused byte-for-byte;
only the descriptor is rewritten, so the disk needs no conversion and its hash
stays verifiable.

    python build_ova.py                # also writes payload.tar.xz for live upgrades

Big files (the 828 MB base image, the output OVA) live in a work directory OUTSIDE
any synced folder: $ZM_BUILD_DIR, default ~/ZertoMonitor-build. Put Canonical's OVA there,
unpacked into src/ (see README.md).
"""
from __future__ import annotations

import base64
import hashlib
import io
import lzma
import os
import re
import shutil
import tarfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

HERE = Path(__file__).resolve().parent              # deploy/appliance
APP_SRC = HERE.parent.parent                        # the ZertoMonitor project
WORK = Path(os.environ.get("ZM_BUILD_DIR") or (Path.home() / "ZertoMonitor-build"))
SRC = WORK / "src"

def _one(pattern: str) -> Path:
    hits = sorted(SRC.glob(pattern))
    if len(hits) > 1:               # never guess which base image (or which build date) to use
        raise SystemExit(f"more than one {pattern} in {SRC} ({', '.join(h.name for h in hits)}); "
                         "keep exactly one unpacked base image there")
    return hits[0] if hits else SRC / pattern.replace("*", "MISSING")


SRC_OVF = _one("*.ovf")          # Canonical's descriptor, whatever the build date
SRC_VMDK = _one("*.vmdk")
SRC_MF = _one("*.mf")

PRODUCT = "Zerto Monitor"
VERSION = "1.5.0"
VMNAME = f"ZertoMonitor-{VERSION}"
DISK_NAME = f"{VMNAME}-disk1.vmdk"
OUT_OVA = WORK / f"{VMNAME}.ova"
OUT_PAYLOAD = WORK / "payload.tar.xz"

# Guest-side scripts that travel in the payload under appliance/ (always with LF endings)
APPLIANCE_FILES = ("zerto-monitor-admin", "zerto-monitor-snmp", "zerto-monitor-ovfscrub",
                   "zerto-monitor-console", "zerto-monitor-console-ops", "zerto-monitor-update")
# Non-script files under appliance/: the PUBLIC release key appliances pin for self-update
APPLIANCE_DATA = ("release-signing.pub",)

MEMORY_MB = 4096
CHUNK = 24000               # base64 chars per payload property

# Both transports, space-separated (DSP0243 11.2). The spec lets a platform use
# "any of them", so the guest must try both rather than assume either: guestInfo
# first (cheap, no mount), CD-ROM second.
TRANSPORT = "com.vmware.guestInfo iso"


# ── payload ────────────────────────────────────────────────────────────────
PACKABLE = {".py", ".html", ".css", ".js", ".svg", ".png", ".ico", ".json"}   # never keys, DBs, logs


def packable(p: Path) -> bool:
    return p.is_file() and "__pycache__" not in p.parts and p.suffix.lower() in PACKABLE


_SECRET_SHAPES = [
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a PEM private key"),
    (re.compile(rb"\bgAAAAA[A-Za-z0-9_\-]{80,}={0,2}"), "a Fernet token"),
]


def secret_scan(members: list[tuple[str, bytes]]) -> list[str]:
    """Nothing secret-shaped ever ships: private keys, Fernet tokens, or the bytes of
    any key file found in a local dev data folder."""
    local_keys = []
    for d in (APP_SRC / "data", Path(os.environ.get("LOCALAPPDATA", "")) / "ZertoMonitor" / "data"):
        for name in ("fernet.key", "secret.key"):
            try:
                k = (d / name).read_bytes().strip()
                if len(k) >= 16:
                    local_keys.append(k)
            except OSError:
                pass
    found = []
    for name, data in members:
        for rx, what in _SECRET_SHAPES:
            if rx.search(data):
                found.append(f"{name}: {what}")
        if any(k in data for k in local_keys):
            found.append(f"{name}: a local dev key")
    return found
def build_payload() -> bytes:
    """Deterministic tar.xz of everything the appliance runs, incl. firstboot.py.

    A solid xz archive beats a per-entry zip by about 25% here, which matters:
    this whole blob has to fit in OVF property values.
    """
    members: list[tuple[str, bytes]] = []
    for d in ("app", "templates", "static"):
        for p in sorted((APP_SRC / d).rglob("*")):
            if packable(p):
                members.append((p.relative_to(APP_SRC).as_posix(), p.read_bytes()))
    members.append(("requirements.txt", (APP_SRC / "requirements.txt").read_bytes()))
    members.append(("firstboot.py", (HERE / "firstboot.py").read_bytes()))
    # lands as /opt/zerto-monitor/VERSION; the console menu shows it
    members.append(("VERSION", f"{VERSION}\n".encode()))
    for name in APPLIANCE_FILES + APPLIANCE_DATA:
        # shell scripts must reach Linux with LF endings whatever git/Windows did
        if not (HERE / name).is_file():
            raise SystemExit(f"refusing to build: appliance/{name} is missing"
                             + (" - run deploy/new_release_key.ps1 once" if name.endswith(".pub") else ""))
        members.append((f"appliance/{name}", (HERE / name).read_bytes().replace(b"\r\n", b"\n")))
    members.sort()
    leaks = secret_scan(members)
    if leaks:
        raise SystemExit("refusing to build: secret-shaped content in the payload: " + "; ".join(leaks))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz", format=tarfile.USTAR_FORMAT,
                      preset=9 | lzma.PRESET_EXTREME) as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.uid, ti.gid = len(data), 0, 0, 0
            ti.uname = ti.gname = ""
            ti.mode = 0o755 if (name.endswith(".py") or name.startswith("appliance/")) else 0o644
            t.addfile(ti, io.BytesIO(data))
    blob = buf.getvalue()
    print(f"  payload.tar.xz   {len(blob):,} bytes  ({len(members)} files)")
    return blob


def build_userdata() -> str:
    """cloud-config carrying only the stage-1 bootstrap."""
    boot = (HERE / "bootstrap.py").read_bytes()
    cc = f"""#cloud-config
# Zerto Monitor appliance. Stage 1 only: unpack the payload from the OVF
# properties and hand over to firstboot.py. Log: /var/log/zerto-monitor-firstboot.log
write_files:
  - path: /opt/zerto-monitor/bootstrap.py
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: {base64.b64encode(boot).decode()}
runcmd:
  - [/usr/bin/python3, /opt/zerto-monitor/bootstrap.py]
final_message: "Zerto Monitor appliance: cloud-init finished after $UPTIME s. Configuration continues in /var/log/zerto-monitor-firstboot.log"
"""
    print(f"  user-data        {len(cc):,} bytes raw")
    return base64.b64encode(cc.encode()).decode()


# ── descriptor ─────────────────────────────────────────────────────────────
def prop(key, label, desc, *, value="", ptype="string", user=True,
         password=False, qualifiers=None) -> str:
    a = [f'ovf:key={quoteattr(key)}', f'ovf:type={quoteattr(ptype)}']
    if qualifiers:
        a.append(f'ovf:qualifiers={quoteattr(qualifiers)}')
    a.append(f'ovf:userConfigurable={quoteattr("true" if user else "false")}')
    if password:
        a.append('ovf:password="true"')
    a.append(f'ovf:value={quoteattr(value)}')
    out = [f'      <Property {" ".join(a)}>']
    if label:
        out.append(f"        <Label>{label}</Label>")
    if desc:
        out.append(f"        <Description>{desc}</Description>")
    out.append("      </Property>")
    return "\n".join(out)


def product_section(userdata_b64: str, chunks: list[str]) -> str:
    p: list[str] = [
        '    <ProductSection ovf:required="false">',
        "      <Info>Zerto Monitor appliance configuration</Info>",
        f"      <Product>{PRODUCT}</Product>",
        "      <Vendor>Zerto Monitor contributors</Vendor>",
        f"      <Version>{VERSION}</Version>",
        f"      <FullVersion>{VERSION} on Ubuntu 26.04 LTS</FullVersion>",

        # NOTE: ovf:key must not contain '.' or ':' (DSP0243 9.5) - dots also collide
        # with the [class '.'] key ['.' instance] grammar used to compose the key the
        # guest sees. Hyphenated, 'zm-' prefixed so nothing collides with the cloud-init
        # reserved names (hostname, password, public-keys, seedfrom).
        "      <Category>1. Networking</Category>",
        prop("zm-hostname", "Hostname", "Short hostname for this appliance.",
             value="zertomon"),
        prop("zm-net-dhcp", "Use DHCP",
             "Tick to obtain the address automatically. Leave unticked to use the static settings below.",
             ptype="boolean", value="false"),
        prop("zm-net-address", "IPv4 address",
             "Static IPv4 address, e.g. 192.0.2.10. Ignored when DHCP is ticked."),
        prop("zm-net-prefix", "Subnet prefix or mask",
             "Prefix length (e.g. 23) or dotted mask (e.g. 255.255.254.0).", value="24"),
        prop("zm-net-gateway", "Default gateway", "IPv4 address of the default gateway."),
        prop("zm-net-dns1", "DNS server 1", "Primary DNS resolver."),
        prop("zm-net-dns2", "DNS server 2", "Secondary DNS resolver. Optional."),
        prop("zm-net-search", "DNS search domain", "Search domain, e.g. example.com. Optional."),

        # vCenter keeps every value below in the VM's vApp properties after deployment.
        # The appliance blanks its own copy at each boot, but vCenter's must be cleared
        # by hand (the admin page says so until it is).
        "      <Category>2. Appliance credentials</Category>",
        prop("zm-root-password", "Root password",
             "Password for the root console account. Blank leaves root locked, which is safer. "
             "Root SSH stays key-only regardless. After deployment, clear every password field "
             "here (Edit Settings > vApp Options) - vCenter otherwise keeps them.",
             password=True, qualifiers="MinLen(8),MaxLen(128)"),
        prop("zm-admin-user", "Admin username",
             "Linux account created with sudo rights for console and SSH access.",
             value="zmadmin"),
        prop("zm-admin-password", "Admin password", "Password for the admin account above.",
             password=True, qualifiers="MinLen(8),MaxLen(128)"),
        prop("zm-ssh-key", "SSH public key",
             "Optional. One OpenSSH public key added to the admin account's authorized_keys."),

        "      <Category>3. Web console</Category>",
        prop("zm-web-user", "Web admin username",
             "Login for the /admin area. The dashboards themselves are public.",
             value="admin"),
        prop("zm-web-password", "Web admin password",
             "At least 10 characters. Stored as a bcrypt hash. Leave blank to be prompted at first visit.",
             password=True, qualifiers="MinLen(10),MaxLen(72)"),     # bcrypt's limit

        "      <Category>4. Regional</Category>",
        prop("zm-timezone", "Timezone", "IANA timezone, e.g. America/New_York.",
             value="America/New_York"),
        prop("zm-ntp-server", "NTP server",
             "Hostname or address of an NTP server. Replaces Ubuntu's default NTS pools, "
             "which need outbound 4460/tcp to Canonical.",
             value="pool.ntp.org"),

        "      <Category>5. First Zerto site (optional)</Category>",
        prop("zm-zvm-name", "Site display name",
             "Friendly name shown in the dashboard, e.g. Primary-DC."),
        prop("zm-zvm-host", "ZVM hostname", "Leave blank to add sites later from the admin page."),
        prop("zm-zvm-user", "ZVM username", "Account used to poll this Zerto Virtual Manager."),
        prop("zm-zvm-password", "ZVM password",
             "Stored Fernet-encrypted in the appliance. Clear it here after deployment - "
             "vCenter otherwise keeps it in the VM's vApp properties.", password=True),

        "      <Category>6. Do not modify</Category>",
        prop("instance-id", "Instance ID",
             "cloud-init instance identity. Read once, at first boot; cloud-init is switched "
             "off once the appliance has configured itself.",
             value="zerto-monitor-1", user=False),
        prop("user-data", "Encoded user-data",
             "Base64 cloud-config that bootstraps the appliance.",
             value=userdata_b64, user=False),
    ]
    for i, c in enumerate(chunks):
        p.append(prop(f"zm-payload{i}", f"Application payload {i + 1}/{len(chunks)}",
                      "Base64 fragment of the application archive.", value=c, user=False))
    p.append("    </ProductSection>")
    return "\n".join(p)


def _sub1(pattern: str, repl: str, text: str, what: str) -> str:
    """Replace exactly one match, or fail loudly - a silent miss ships a broken OVA."""
    out, n = re.subn(pattern, repl, text, count=1, flags=re.S)
    assert n == 1, f"could not find {what} in Canonical's descriptor (has its format changed?)"
    return out


def build_ovf(userdata_b64: str, chunks: list[str], vmdk_size: int) -> str:
    x = SRC_OVF.read_text(encoding="utf-8")
    # Canonical stamps each image with its build date (…-cloudimg-20260823), so read
    # the identifiers out of THIS descriptor rather than assuming a particular build.
    src_vmdk_name = SRC_VMDK.name
    vs_id = re.search(r'<VirtualSystem ovf:id="([^"]+)"', x).group(1)

    # disk file: rename only (contents and byte size unchanged)
    x = _sub1(rf'ovf:href="{re.escape(src_vmdk_name)}"', f'ovf:href="{DISK_NAME}"', x, "the disk href")
    assert f'ovf:size="{vmdk_size}"' in x, "File ovf:size does not match the VMDK on disk"

    # identity
    x = _sub1(rf'<VirtualSystem ovf:id="{re.escape(vs_id)}"', f'<VirtualSystem ovf:id="{VMNAME}"', x,
              "the VirtualSystem id")
    x = _sub1(rf"<Name>{re.escape(vs_id)}</Name>", f"<Name>{VMNAME}</Name>", x, "the VM name")
    x = _sub1(rf"<vssd:VirtualSystemIdentifier>{re.escape(vs_id)}</vssd:VirtualSystemIdentifier>",
              f"<vssd:VirtualSystemIdentifier>{VMNAME}</vssd:VirtualSystemIdentifier>", x,
              "the VirtualSystemIdentifier")

    # memory: the one Item whose ResourceType is 4
    x = _sub1(r"(<rasd:ElementName>)\d+MB of memory(</rasd:ElementName>)",
              rf"\g<1>{MEMORY_MB}MB of memory\g<2>", x, "the memory label")
    x = _sub1(r"(<rasd:ResourceType>4</rasd:ResourceType>\s*<rasd:VirtualQuantity>)\d+(</rasd:VirtualQuantity>)",
              rf"\g<1>{MEMORY_MB}\g<2>", x, "the memory quantity")

    # transport
    x = _sub1(r'<VirtualHardwareSection ovf:transport="[^"]*">',
              f'<VirtualHardwareSection ovf:transport="{TRANSPORT}">', x, "the hardware transport")

    # swap Canonical's ProductSection for ours
    new_ps = product_section(userdata_b64, chunks)
    x, n = re.subn(r"[ \t]*<ProductSection\b.*?</ProductSection>", new_ps, x, flags=re.S)
    assert n == 1, f"expected exactly one ProductSection, replaced {n}"

    # a description in the vSphere summary
    ann = ("    <AnnotationSection ovf:required=\"false\">\n"
           "      <Info>Description</Info>\n"
           "      <Annotation>Zerto Monitor " + VERSION + ": aggregates every Zerto Virtual Manager "
           "and the Zerto Cloud Manager into one dashboard, with zORG alerting by email and "
           "SNMP. HTTPS only (self-signed until you install a certificate in Admin). Public "
           "read-only dashboards; the admin area requires a login. Configure it on the "
           "Customize template page. First boot needs outbound access to archive.ubuntu.com "
           "and pypi.org.</Annotation>\n"
           "    </AnnotationSection>\n")
    x = x.replace("    <ProductSection", ann + "    <ProductSection", 1)

    for must in (f'ovf:href="{DISK_NAME}"', f"<Name>{VMNAME}</Name>", "zm-payload0",
                 f'ovf:transport="{TRANSPORT}"'):
        assert must in x, f"descriptor is missing {must!r}"
    # keep the descriptor pure ASCII so no parser can disagree about encoding
    non_ascii = {c for c in x if ord(c) > 127}
    assert not non_ascii, f"descriptor has non-ASCII characters: {non_ascii}"
    check_hardware(x)
    return x


OVF_NS = "{http://schemas.dmtf.org/ovf/envelope/1}"
RASD = "{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData}"


def check_hardware(x: str) -> None:
    """Guard the invariants that fail silently rather than loudly.

    vSphere 7+ quietly DROPS a CD-ROM parented to a SCSI controller. With no CD-ROM
    there is no ISO transport, so ovf-env.xml never reaches the guest, the deploy
    still succeeds, and the appliance boots completely unconfigured. Assert the
    CD-ROM is still on an IDE controller, and that no InstanceID was disturbed.
    """
    import xml.etree.ElementTree as ET
    root = ET.fromstring(x)
    items = root.findall(f".//{OVF_NS}VirtualHardwareSection/{OVF_NS}Item")
    by_id, ide, cdrom = {}, set(), []
    for it in items:
        iid = it.findtext(f"{RASD}InstanceID")
        rt = it.findtext(f"{RASD}ResourceType")
        by_id[iid] = rt
        if rt == "5":
            ide.add(iid)
        if rt == "15":
            cdrom.append(it)
    assert cdrom, "no CD-ROM device: the ISO transport would have nothing to attach to"
    for cd in cdrom:
        parent = cd.findtext(f"{RASD}Parent")
        assert parent in ide, (
            f"CD-ROM parent {parent!r} is not an IDE controller (IDE ids: {sorted(ide)}). "
            "vSphere would silently drop the device and the appliance would boot unconfigured.")
    expected = {str(i) for i in range(1, 13)}
    assert expected <= set(by_id), f"InstanceIDs were renumbered: {sorted(by_id)}"
    # the ISO transport requires a disconnected CD-ROM to be present
    auto = cdrom[0].findtext(f"{RASD}AutomaticAllocation")
    assert (auto or "false").lower() == "false", "CD-ROM must start disconnected"
    print(f"  hardware check   CD-ROM {cdrom[0].findtext(f'{RASD}InstanceID')} "
          f"-> IDE {cdrom[0].findtext(f'{RASD}Parent')}, {len(items)} items intact")


# ── packing ────────────────────────────────────────────────────────────────
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for blk in iter(lambda: f.read(4 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def write_ova(ovf_text: str) -> None:
    stage = WORK / "stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()

    ovf_path = stage / f"{VMNAME}.ovf"
    ovf_path.write_text(ovf_text, encoding="utf-8", newline="\n")
    disk_path = stage / DISK_NAME
    print("  copying the Canonical VMDK (unmodified)...")
    shutil.copyfile(SRC_VMDK, disk_path)

    mf = (f"SHA256({ovf_path.name})= {sha256_file(ovf_path)}\n"
          f"SHA256({DISK_NAME})= {sha256_file(disk_path)}\n")
    mf_path = stage / f"{VMNAME}.mf"
    mf_path.write_text(mf, encoding="utf-8", newline="\n")

    if OUT_OVA.exists():
        OUT_OVA.unlink()
    # OVA order is mandatory: descriptor, manifest, then disks.
    with tarfile.open(OUT_OVA, "w", format=tarfile.USTAR_FORMAT) as t:
        for p in (ovf_path, mf_path, disk_path):
            ti = t.gettarinfo(str(p), arcname=p.name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = 0, 0, 0, "", "", 0o644
            with p.open("rb") as f:
                t.addfile(ti, f)
    shutil.rmtree(stage)


def main() -> None:
    import sys
    print(f"Zerto Monitor {VERSION} appliance builder  (work dir {WORK})")
    WORK.mkdir(parents=True, exist_ok=True)

    blob = build_payload()
    # the same archive a running appliance takes for an in-place upgrade:
    #   tar -xJf payload.tar.xz -C /opt/zerto-monitor && python3 firstboot.py --upgrade
    OUT_PAYLOAD.write_bytes(blob)
    print(f"  -> {OUT_PAYLOAD}  (sha256 {hashlib.sha256(blob).hexdigest()[:16]}...)")
    if "--payload-only" in sys.argv[1:]:
        return

    vmdk_size = SRC_VMDK.stat().st_size
    print(f"  base disk        {vmdk_size:,} bytes (reused unmodified)")
    b64 = base64.b64encode(blob).decode()
    chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
    print(f"  payload base64   {len(b64):,} chars in {len(chunks)} propert"
          f"{'y' if len(chunks) == 1 else 'ies'}")

    userdata = build_userdata()
    ovf = build_ovf(userdata, chunks, vmdk_size)

    env_bytes = len(userdata) + sum(len(c) for c in chunks)
    print(f"  descriptor       {len(ovf):,} bytes")
    print(f"  OVF env payload  {env_bytes:,} chars across {len(chunks) + 1} properties")
    print(f"  largest property {max([len(userdata)] + [len(c) for c in chunks]):,} chars")

    write_ova(ovf)
    print(f"\n  -> {OUT_OVA.name}  {OUT_OVA.stat().st_size:,} bytes")
    print(f"     sha256 {sha256_file(OUT_OVA)}")


if __name__ == "__main__":
    main()
