#!/usr/bin/env python3
"""Zerto Monitor appliance — cloud-init bootstrap (stage 1 of 2).

Small on purpose: this is the only code carried in the OVF user-data property.
It finds the OVF environment, reassembles the application archive from the
zm.payload* properties, unpacks it, and hands over to firstboot.py, which does
the real configuration work and ships inside that archive.
"""
import base64
import io
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

APP_DIR = Path("/opt/zerto-monitor")
LOG = Path("/var/log/zerto-monitor-firstboot.log")


def log(msg):
    import os
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [bootstrap] {msg}"
    print(line, flush=True)
    try:
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)     # private from byte one
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _rpctool():
    for tool in ("/usr/bin/vmware-rpctool", "/usr/sbin/vmware-rpctool", "vmware-rpctool"):
        try:
            p = subprocess.run([tool, "info-get guestinfo.ovfEnv"],
                               capture_output=True, text=True, timeout=15)
            if p.returncode == 0 and "<Environment" in p.stdout:
                return p.stdout
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _cdrom():
    for base in ("/media", "/mnt", "/run/media", "/cdrom"):
        b = Path(base)
        if b.is_dir():
            for c in list(b.glob("**/ovf-env.xml"))[:12]:
                try:
                    t = c.read_text(errors="replace")
                    if "<Environment" in t:
                        return t
                except OSError:
                    pass
    tmp = Path("/run/zm-ovfenv")
    tmp.mkdir(parents=True, exist_ok=True)
    devs = sorted(str(p) for p in Path("/dev").glob("sr*")) + ["/dev/cdrom"]
    for dev in devs:
        if not Path(dev).exists():
            continue
        ok = False
        try:
            ok = subprocess.run(["mount", "-o", "ro", dev, str(tmp)],
                                capture_output=True, timeout=30).returncode == 0
            if ok:
                for c in tmp.glob("**/ovf-env.xml"):
                    t = c.read_text(errors="replace")
                    if "<Environment" in t:
                        return t
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            if ok:
                subprocess.run(["umount", str(tmp)], capture_output=True)
    return None


def _cached():
    for p in (Path("/var/lib/cloud/instance/ovf-env.xml"),
              Path("/var/lib/cloud/seed/ovf/ovf-env.xml"),
              Path("/run/cloud-init/ovf-env.xml")):
        try:
            if p.is_file():
                t = p.read_text(errors="replace")
                if "<Environment" in t:
                    return t
        except OSError:
            pass
    return None


def parse_props(xml):
    """Pull every oe:key/oe:value pair out of an ovf-env.xml document.

    Namespace-agnostic on purpose: the environment vCenter hands over uses the
    oe: prefix, but other platforms bind the same names differently.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    out = {}
    for el in root.iter():
        if not (el.tag.endswith("}Property") or el.tag == "Property"):
            continue
        k = v = None
        for an, av in el.attrib.items():
            if an.endswith("}key") or an == "key":
                k = av
            elif an.endswith("}value") or an == "value":
                v = av
        if k is not None:
            out[k] = v or ""
    return out


def properties():
    for name, fn in (("guestinfo", _rpctool), ("cdrom", _cdrom), ("cloud-init", _cached)):
        try:
            xml = fn()
        except Exception:
            xml = None
        if not xml:
            continue
        out = parse_props(xml)
        if out:
            log(f"{len(out)} properties via {name}")
            return out
    return {}


def main():
    log("stage 1 starting")
    props = properties()

    chunks = []
    i = 0
    while f"zm-payload{i}" in props:
        chunks.append(props[f"zm-payload{i}"].strip())
        i += 1
    if not chunks:
        log("FATAL: no zm-payload* properties in the OVF environment; cannot install")
        return 2

    blob = base64.b64decode("".join(chunks))
    APP_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:xz") as t:
        unsafe = [m.name for m in t.getmembers()
                  if m.name.startswith("/") or ".." in Path(m.name).parts
                  or not (m.isfile() or m.isdir())]
        if unsafe:
            log(f"FATAL: unsafe entries in payload: {unsafe[:3]}")
            return 2
        t.extractall(APP_DIR)
    log(f"unpacked {len(blob):,} bytes from {len(chunks)} propert"
        f"{'y' if len(chunks) == 1 else 'ies'} into {APP_DIR}")

    installer = APP_DIR / "firstboot.py"
    if not installer.is_file():
        log("FATAL: firstboot.py missing from the payload")
        return 2
    installer.chmod(0o700)
    log("handing over to firstboot.py")
    return subprocess.run([sys.executable or "python3", str(installer)]).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        log(f"FATAL: {exc}")
        import traceback
        for ln in traceback.format_exc().splitlines():
            log("    " + ln)
        sys.exit(1)
