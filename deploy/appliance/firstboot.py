#!/usr/bin/env python3
"""Zerto Monitor appliance — first-boot configurator.

Runs once, from cloud-init runcmd. Reads the vApp / OVF properties the operator
filled in on the vSphere "Customize template" page, then:

    network -> identity -> credentials -> packages -> app -> services

Everything is logged to /var/log/zerto-monitor-firstboot.log. Secrets are never
logged and never passed on a command line (chpasswd reads them on stdin).

Idempotent: a completion stamp short-circuits later boots.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

try:                          # absent on the Windows build host, which only imports
    import grp                # this module to syntax-check and exercise the parser
    import pwd
except ImportError:           # pragma: no cover
    grp = pwd = None

APP_DIR = Path("/opt/zerto-monitor")
DATA_DIR = APP_DIR / "data"
ETC_DIR = Path("/etc/zerto-monitor")
KEY_FILE = ETC_DIR / "fernet.key"
VENV = APP_DIR / "venv"
STAMP = APP_DIR / ".firstboot-done"
LOG = Path("/var/log/zerto-monitor-firstboot.log")
SVC = "zerto-monitor"

SECRET_KEYS = {"zm-root-password", "zm-admin-password", "zm-web-password",
               "zm-zvm-password", "password"}
# the only OVF properties whose VALUES may be logged; everything else shows as set/blank
LOGGABLE = {"zm-hostname", "zm-net-dhcp", "zm-net-address", "zm-net-prefix", "zm-net-gateway",
            "zm-net-dns1", "zm-net-dns2", "zm-net-search", "zm-timezone", "zm-ntp-server",
            "zm-zvm-host", "zm-zvm-name", "zm-admin-user", "zm-web-user", "instance-id"}


# ── logging ─────────────────────────────────────────────────────────────────
def log(msg: str = "") -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        # private from the first byte: the log names hosts and accounts
        fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def write_secret(path: Path, text: str) -> None:
    """Create a root-only secret file 0600 from its first byte (no write-then-chmod gap)."""
    tmp = path.with_name(path.name + ".new")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chown(tmp, 0, 0)
    os.replace(tmp, path)


def run(cmd, *, stdin: str | None = None, check: bool = True, quiet: bool = False):
    """Run a command. stdin is used for secrets so they never hit the process list."""
    if not quiet:
        log("  $ " + " ".join(cmd))
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()[-6:]
        for t in tail:
            log("    ! " + t)
        if check:
            raise RuntimeError(" ".join(cmd) + f" exited {p.returncode}")
    return p


# ── OVF environment ─────────────────────────────────────────────────────────
def _from_rpctool() -> str | None:
    for tool in ("/usr/bin/vmware-rpctool", "/usr/sbin/vmware-rpctool", "vmware-rpctool"):
        try:
            p = subprocess.run([tool, "info-get guestinfo.ovfEnv"],
                               capture_output=True, text=True, timeout=15)
            if p.returncode == 0 and "<Environment" in p.stdout:
                return p.stdout
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _from_cdrom() -> str | None:
    """vCenter attaches the OVF environment as a tiny ISO holding ovf-env.xml."""
    # already-mounted copies first (cloud-init may have got there first)
    for base in ("/media", "/mnt", "/run/media", "/media/cdrom", "/cdrom"):
        b = Path(base)
        if b.is_dir():
            for cand in list(b.glob("**/ovf-env.xml"))[:12]:
                try:
                    t = cand.read_text(errors="replace")
                    if "<Environment" in t:
                        return t
                except OSError:
                    pass
    tmp = Path("/run/zm-ovfenv")
    tmp.mkdir(parents=True, exist_ok=True)
    # scan, don't hardcode: this OVA declares a CD-ROM and a floppy, and the spec
    # warns the environment may land on any of several disconnected CD-ROMs
    devs = sorted(str(p) for p in Path("/dev").glob("sr*"))
    for extra in ("/dev/cdrom", "/dev/dvd"):
        if extra not in devs:
            devs.append(extra)
    for dev in devs:
        if not Path(dev).exists():
            continue
        mounted = False
        try:
            p = subprocess.run(["mount", "-o", "ro", dev, str(tmp)],
                               capture_output=True, text=True, timeout=30)
            mounted = p.returncode == 0
            if mounted:
                for cand in tmp.glob("**/ovf-env.xml"):
                    t = cand.read_text(errors="replace")
                    if "<Environment" in t:
                        return t
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            if mounted:
                subprocess.run(["umount", str(tmp)], capture_output=True)
    return None


def _from_cloudinit() -> str | None:
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


def parse_props(xml: str) -> dict[str, str]:
    """Every oe:key/oe:value pair in an ovf-env.xml document, namespace-agnostic."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    out: dict[str, str] = {}
    for el in root.iter():
        if not el.tag.endswith("}Property") and el.tag != "Property":
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


def ovf_properties() -> dict[str, str]:
    """Every OVF property, by key. Tries all transports; empty dict if none."""
    for name, fn in (("guestinfo", _from_rpctool),
                     ("cdrom", _from_cdrom),
                     ("cloud-init cache", _from_cloudinit)):
        try:
            xml = fn()
        except Exception as e:                              # never fail the boot on this
            log(f"  transport {name} errored: {e}")
            xml = None
        if not xml:
            continue
        out = parse_props(xml)
        if out:
            log(f"read {len(out)} OVF properties via {name}")
            return out
    log("WARNING: no OVF environment found on any transport; using defaults")
    return {}


# ── helpers ─────────────────────────────────────────────────────────────────
def truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in ("true", "1", "yes", "on")


def console_ops():
    """The console's root-operations script, loaded as a module: it holds the one
    implementation of network validation, netplan rendering and the netplan backups."""
    import importlib.util
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("zm_console_ops", str(APP_DIR / "appliance" / "zerto-monitor-console-ops"))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def primary_nic() -> str:
    """The real NIC, preferring predictable VMware names (ens192, eth0...)."""
    net = Path("/sys/class/net")
    cands = []
    for p in sorted(net.iterdir()):
        n = p.name
        if n == "lo" or not (p / "device").exists():
            continue
        cands.append(n)
    if not cands:                                           # fall back to any non-loopback
        cands = [p.name for p in sorted(net.iterdir()) if p.name != "lo"]
    for pref in ("en", "eth"):
        for n in cands:
            if n.startswith(pref):
                return n
    return cands[0] if cands else "ens192"


def online(timeout: float = 4.0) -> bool:
    for host, port in (("archive.ubuntu.com", 80), ("pypi.org", 443)):     # what first boot needs anyway
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return True
        except OSError:
            continue
    return False


# ── steps ───────────────────────────────────────────────────────────────────
def network_spec(z, p: dict, nic: dict) -> dict:
    """The OVF network properties as a validated spec. Every value goes through
    ipaddress first: a bad static address falls back to DHCP, a bad gateway, DNS
    server or search domain is dropped - each loudly - so nothing invalid ever
    reaches netplan."""
    # by MAC, never by interface name or driver (a driver match would also catch a
    # hot-added second vNIC and give it the same address and default route)
    m = {"mac": nic["mac"]}
    dhcp = truthy(p.get("zm-net-dhcp"))
    ip = (p.get("zm-net-address") or "").strip()
    if dhcp or not ip:
        if not dhcp:
            log("no static address supplied -> DHCP")
        return z.build_network("dhcp", **m)

    def keep(check, values, what):
        good = []
        for v in values:
            try:
                good += check([v])
            except z.Invalid as e:
                log(f"  ! {what} ignored: {e}")
        return good
    dns = keep(z.v_dns, [d for d in ((p.get("zm-net-dns1") or "").strip(),
                                     (p.get("zm-net-dns2") or "").strip()) if d], "DNS server")
    search = keep(z.v_search, z.split_list(p.get("zm-net-search")), "search domain")
    prefix = (p.get("zm-net-prefix") or "").strip() or "24"
    try:
        base = z.build_network("static", **m, address=ip, prefix=prefix, dns=dns, search=search)
    except z.Invalid as e:
        log(f"! static address rejected: {e}")
        log("! falling back to DHCP; fix it from the console menu (Network) once signed in")
        return z.build_network("dhcp", **m)
    if "/" in ip:
        log(f"  address field carried its own prefix; using {base['address']}")
    gw = (p.get("zm-net-gateway") or "").strip()
    if gw:
        try:
            return z.build_network("static", **m, address=base["address"], gateway=gw,
                                   dns=dns, search=search)
        except z.Invalid as e:
            log(f"! gateway ignored: {e} - the appliance is reachable only on its own subnet")
    return base


def configure_network(p: dict) -> None:
    try:
        z = console_ops()
    except Exception as e:                                  # noqa: BLE001
        log(f"! network helpers unavailable ({e}); leaving the image's DHCP configuration")
        return
    nics = z.list_nics()
    name = primary_nic()
    nic = next((n for n in nics if n["name"] == name), nics[0] if nics else None)
    if not nic or not nic["mac"]:
        log("! no network adapter found; leaving the network configuration as it is")
        return
    spec = network_spec(z, p, nic)
    body = z.render_netplan(spec)
    # check it in a scratch root BEFORE anything in /etc/netplan moves
    err = z.precheck({z.NETPLAN_NAME: body})
    if err:
        log("! netplan rejected the generated configuration; keeping the image's own:")
        for line in err.splitlines()[-6:]:
            log("    ! " + line)
        return

    # stop cloud-init re-writing the network on later boots
    Path("/etc/cloud/cloud.cfg.d").mkdir(parents=True, exist_ok=True)
    Path("/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg").write_text(
        "network: {config: disabled}\n")

    # netplan CONCATENATES sequences across files, so leaving cloud-init's file in
    # place would merge into two default routes and a DHCP/static hybrid. Renaming
    # takes it out of the *.yaml glob without destroying it; a full copy of the
    # directory is kept in /var/lib/zerto-monitor/netplan-backup as well.
    snap = z.snapshot_netplan()
    try:
        z.set_aside_others()
        z.write_ours(body)
        if run(["netplan", "generate"], check=False).returncode != 0:
            raise RuntimeError("netplan generate failed")
    except Exception as e:                                  # noqa: BLE001
        log(f"! {e}; putting the previous netplan files back")
        z.restore_netplan(snap)
        run(["netplan", "generate"], check=False)
        return
    log(f"netplan written: {z.summary(spec)} (adapter {nic['name']}; backup {snap.name})")
    run(["netplan", "apply"], check=False)
    time.sleep(6)                                           # let the link settle


def configure_identity(p: dict) -> str:
    host = (p.get("zm-hostname") or "").strip() or "zerto-monitor"
    host = host.split(".")[0]
    run(["hostnamectl", "set-hostname", host], check=False)
    hosts = Path("/etc/hosts")
    try:
        lines = [ln for ln in hosts.read_text().splitlines()
                 if not ln.startswith("127.0.1.1")]
        lines.append(f"127.0.1.1\t{host}")
        hosts.write_text("\n".join(lines) + "\n")
    except OSError:
        pass

    tz = (p.get("zm-timezone") or "").strip()
    if tz:
        known = subprocess.run(["timedatectl", "list-timezones"],
                               capture_output=True, text=True)
        if known.returncode == 0 and tz not in known.stdout.split():
            log(f"  ! '{tz}' is not a known timezone; leaving the clock on UTC")
            tz = ""
        else:
            run(["timedatectl", "set-timezone", tz], check=False)

    # This image ships chrony, NOT systemd-timesyncd. Writing timesyncd config here
    # would silently discard the operator's NTP server.
    ntp = (p.get("zm-ntp-server") or "").strip()
    if ntp:
        d = Path("/etc/chrony/sources.d")
        if d.is_dir():
            # Ubuntu's stock sources are all NTS to *.ntp.ubuntu.com and need
            # outbound 4460/tcp; on a closed network they leave the clock unset.
            stock = d / "ubuntu-ntp-pools.sources"
            if stock.exists():
                stock.rename(stock.with_suffix(".sources.disabled"))
            # the .sources suffix is mandatory, and each line needs a trailing newline
            (d / "zerto-monitor.sources").write_text(f"server {ntp} iburst\n")
            if subprocess.run(["chronyc", "reload", "sources"],
                              capture_output=True).returncode != 0:
                run(["systemctl", "restart", "chrony"], check=False)
        else:
            log("  ! /etc/chrony/sources.d missing; NTP server not applied")
            ntp = ""
    log(f"hostname={host} timezone={tz or 'unchanged'} ntp={ntp or 'unchanged'}")
    return host


def configure_credentials(p: dict) -> None:
    rootpw = p.get("zm-root-password") or ""
    user = (p.get("zm-admin-user") or "").strip()
    userpw = p.get("zm-admin-password") or ""
    sshkey = (p.get("zm-ssh-key") or "").strip()

    if rootpw:
        run(["chpasswd"], stdin=f"root:{rootpw}\n", quiet=True)
        run(["chage", "-M", "99999", "-d", "today", "root"], check=False, quiet=True)
        log("root password set (console; SSH stays key-only)")

    if user:
        try:
            pwd.getpwnam(user)
        except KeyError:
            run(["useradd", "--create-home", "--shell", "/bin/bash", user], check=False)
        for group in ("sudo", "adm"):
            try:
                grp.getgrnam(group)
                run(["usermod", "-aG", group, user], check=False, quiet=True)
            except KeyError:
                pass
        if userpw:
            run(["chpasswd"], stdin=f"{user}:{userpw}\n", quiet=True)
            # don't expire: this account is used for scp/Ansible as well as console
            run(["chage", "-M", "99999", "-d", "today", user], check=False, quiet=True)
        log(f"admin user '{user}' ready (sudo)")

        if sshkey:
            try:
                home = Path(pwd.getpwnam(user).pw_dir)
                sd = home / ".ssh"
                sd.mkdir(mode=0o700, exist_ok=True)
                ak = sd / "authorized_keys"
                cur = ak.read_text() if ak.exists() else ""
                if sshkey not in cur:
                    ak.write_text((cur + "\n" if cur.strip() else "") + sshkey + "\n")
                ak.chmod(0o600)
                rec = pwd.getpwnam(user)
                os.chown(sd, rec.pw_uid, rec.pw_gid)
                os.chown(ak, rec.pw_uid, rec.pw_gid)
                log("ssh public key installed")
            except (OSError, KeyError) as e:
                log(f"  ! could not install ssh key: {e}")

    if userpw:
        # sshd applies the FIRST value it sees and Include sits at the top of
        # sshd_config, so a drop-in must sort BEFORE cloud-init's 50-cloud-init.conf
        # and the image's own 60-cloudimg-settings.conf (which sets
        # PasswordAuthentication no) to have any effect.
        d = Path("/etc/ssh/sshd_config.d")
        d.mkdir(parents=True, exist_ok=True)
        (d / "10-zerto-monitor.conf").write_text(
            "PasswordAuthentication yes\nPermitRootLogin prohibit-password\n")
        (d / "10-zerto-monitor.conf").chmod(0o600)
        # 26.04 uses socket activation for ssh
        run(["systemctl", "daemon-reload"], check=False, quiet=True)
        for unit in ("ssh.socket", "ssh.service"):
            subprocess.run(["systemctl", "restart", unit], capture_output=True)
        log("ssh password authentication enabled for the admin account")


CORE_PACKAGES = ["python3-venv", "python3-pip", "nginx", "ca-certificates", "openssl",
                 "snmp",       # snmptrap, for alert traps
                 "snmpd"]      # the agent, for RMM / network-monitoring polling (off until enabled in Admin)
EXTRA_PACKAGES = [
    "chrony",                  # NTP; the image ships it, the console's Time menu configures it
    "whiptail",                # the console menu's dialogs
    "cloud-guest-utils",       # growpart, for the console's disk expansion
    # WeasyPrint's runtime (PDF reports): Pango, HarfBuzz subsetting and one font
    "libpango-1.0-0", "libpangoft2-1.0-0", "libharfbuzz-subset0", "fonts-dejavu-core",
]
PACKAGES = CORE_PACKAGES + EXTRA_PACKAGES


def _missing_packages(pkgs: list[str]) -> list[str]:
    missing = []
    for pkg in pkgs:
        r = subprocess.run(["dpkg-query", "-W", "--showformat=${Status}", pkg],
                           capture_output=True, text=True)
        if r.returncode != 0 or "install ok installed" not in r.stdout:
            missing.append(pkg)
    return missing


def install_packages() -> None:
    """Install whatever is missing - on first boot nearly everything, on --upgrade
    only what a newer payload added (so an upgrade with nothing new needs no mirror).
    If the batch fails, retry one by one so a single renamed library can't cost the
    rest; only a missing CORE package is fatal."""
    missing = _missing_packages(PACKAGES)
    if not missing:
        log("system packages already present: " + ", ".join(PACKAGES))
        return
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    def apt_install(pkgs):
        return subprocess.run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", *pkgs],
                              env=env, capture_output=True, text=True)
    subprocess.run(["apt-get", "update", "-qq"], env=env, capture_output=True, text=True)
    p = apt_install(missing)
    if p.returncode == 0:
        log("system packages installed: " + ", ".join(missing))
        return
    for t in (p.stderr or "").strip().splitlines()[-8:]:
        log("    ! " + t)
    failed = [pkg for pkg in missing if apt_install([pkg]).returncode != 0]
    if failed:
        log("! could not install: " + ", ".join(failed))
    core = [pkg for pkg in failed if pkg in CORE_PACKAGES]
    if core:
        raise RuntimeError("apt-get install failed for " + ", ".join(core))
    log("system packages installed: " + ", ".join(pkg for pkg in missing if pkg not in failed))


def ensure_service_user() -> None:
    try:
        pwd.getpwnam("zertomon")
    except KeyError:
        run(["useradd", "--system", "--home-dir", str(APP_DIR),
             "--shell", "/usr/sbin/nologin", "zertomon"], check=False)


HELPER = Path("/usr/local/sbin/zerto-monitor-admin")
SNMP_HOOK = Path("/usr/local/bin/zerto-monitor-snmp")
OVFSCRUB = Path("/usr/local/sbin/zerto-monitor-ovfscrub")
CONSOLE = Path("/usr/local/bin/zerto-monitor-console")
CONSOLE_OPS = Path("/usr/local/sbin/zerto-monitor-console-ops")
CONSOLE_GROUP = "zmconsole"
SUDOERS = Path("/etc/sudoers.d/zerto-monitor-console")
PROFILE_HOOK = Path("/etc/profile.d/zz-zerto-monitor-console.sh")


def install_script(name: str, dest: Path, mode: int) -> None:
    """Install one script from the payload: LF endings, root-owned, swapped in
    atomically - and only after it passes a syntax check, so a broken file never
    replaces a working one."""
    data = (APP_DIR / "appliance" / name).read_bytes().replace(b"\r\n", b"\n")
    first = data.split(b"\n", 1)[0]
    if b"python" in first:
        compile(data, name, "exec")                     # SyntaxError -> nothing replaced
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".new")
    tmp.write_bytes(data)
    os.chown(tmp, 0, 0)
    tmp.chmod(mode)
    if first.endswith((b"/sh", b"/bash")):
        shell = first[2:].decode().strip()
        chk = subprocess.run([shell, "-n", str(tmp)], capture_output=True, text=True)
        if chk.returncode != 0:
            tmp.unlink()
            raise RuntimeError(f"{name} failed '{shell} -n': {(chk.stderr or '').strip()[:200]}")
    tmp.replace(dest)


def install_privileged_helper() -> None:
    """The narrow root door the sandboxed web app knocks on.

    The app runs with NoNewPrivileges + ProtectSystem=strict, so sudo is blocked
    and even a root child of it would see /etc read-only. Instead systemd listens on
    a root:zertomon 0660 socket and starts one helper per connection, outside the
    app's sandbox. The helper whitelists every verb and argument and takes no paths.
    """
    for name, dest, mode in (("zerto-monitor-admin", HELPER, 0o750),
                             ("zerto-monitor-snmp", SNMP_HOOK, 0o755),
                             ("zerto-monitor-ovfscrub", OVFSCRUB, 0o700)):
        install_script(name, dest, mode)
    Path("/etc/systemd/system/zerto-monitor-admin.socket").write_text("""[Unit]
Description=Zerto Monitor privileged helper socket

[Socket]
ListenStream=/run/zerto-monitor-admin.sock
SocketUser=root
SocketGroup=zertomon
SocketMode=0660
Accept=yes
MaxConnections=4

[Install]
WantedBy=sockets.target
""")
    Path("/etc/systemd/system/zerto-monitor-admin@.service").write_text(f"""[Unit]
Description=Zerto Monitor privileged helper (request %i)
CollectMode=inactive-or-failed

[Service]
ExecStart={HELPER} --socket
StandardInput=socket
StandardOutput=socket
StandardError=journal
RuntimeMaxSec=300
# Runs as root, deliberately outside the web app's sandbox: it exists to write the
# few root-owned paths the app can't (TLS pair, hostname, snmpd.conf).
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
""")
    install_updater()
    run(["systemctl", "daemon-reload"], check=False, quiet=True)
    run(["systemctl", "enable", "--now", "zerto-monitor-admin.socket"], check=False)
    log(f"privileged helper installed at {HELPER} (socket-activated)")


UPDATER = Path("/usr/local/sbin/zerto-monitor-update")
RELEASE_KEY = Path("/etc/zerto-monitor/release-signing.pub")


def install_updater() -> None:
    """The signed self-update: the updater script, its oneshot unit (started by the
    helper's update-start verb) and the PINNED release public key it verifies every
    bundle against. A new key can only arrive inside a payload, i.e. signed by the old
    key or installed by root by hand - which is how a key is rotated."""
    install_script("zerto-monitor-update", UPDATER, 0o700)
    src = APP_DIR / "appliance" / "release-signing.pub"
    if src.is_file():
        RELEASE_KEY.parent.mkdir(parents=True, exist_ok=True)
        tmp = RELEASE_KEY.with_name(RELEASE_KEY.name + ".new")
        tmp.write_bytes(src.read_bytes().replace(b"\r\n", b"\n"))
        os.chown(tmp, 0, 0)
        tmp.chmod(0o644)                    # public: the web app reads it for its pre-check
        tmp.replace(RELEASE_KEY)
    Path("/var/lib/zerto-monitor-update").mkdir(mode=0o700, parents=True, exist_ok=True)
    Path("/etc/systemd/system/zerto-monitor-update.service").write_text(f"""[Unit]
Description=Zerto Monitor signed self-update
After=network-online.target

[Service]
Type=oneshot
ExecStart={UPDATER} run
TimeoutStartSec=3600
# runs as root on purpose: it replaces root-owned code - but only code whose signature
# verifies against {RELEASE_KEY}
""")
    log(f"self-update installed: {UPDATER}, release key {RELEASE_KEY}")


def system_fqdn(p: dict | None = None) -> str:
    """hostname + search domain, e.g. zertomon.example.com."""
    short = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip() or "zerto-monitor"
    dom = ((p or {}).get("zm-net-search") or "").strip().split(",")[0].strip()
    if not dom:
        dom = subprocess.run(["hostname", "-d"], capture_output=True, text=True).stdout.strip()
    if not dom:
        try:
            for ln in Path("/etc/resolv.conf").read_text().splitlines():
                if ln.startswith("search "):
                    dom = ln.split()[1]
                    break
        except (OSError, IndexError):
            pass
    return f"{short}.{dom}" if dom and "." not in short else short


def ensure_certificate(fqdn: str) -> None:
    """A self-signed pair if none exists yet, so HTTPS works from the first boot."""
    p = run([str(HELPER), "tls-ensure", fqdn], check=False)
    for line in (p.stdout or "").strip().splitlines():
        log("  " + line)
    if p.returncode != 0:
        raise RuntimeError("could not create the TLS certificate")


def app_setting(key: str) -> str | None:
    """Read one app setting straight from SQLite (read-only), without the venv."""
    import sqlite3
    dbf = DATA_DIR / "monitor.db"
    if not dbf.exists():
        return None
    try:
        c = sqlite3.connect(f"file:{dbf}?mode=ro", uri=True, timeout=10)
        try:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        finally:
            c.close()
        return r[0] if r else None
    except sqlite3.Error:
        return None


def snmp_default_off() -> None:
    """Installing snmpd starts it with the distro config (community 'public' on
    localhost). Keep the agent off until someone enables it from the admin page -
    and on an upgrade, leave an agent the admin turned on exactly as it is."""
    if not Path("/usr/sbin/snmpd").exists():
        return
    if app_setting("snmp_agent_enabled") == "true":
        log("SNMP agent is enabled in Admin; leaving it running")
        return
    run([str(HELPER), "snmp-agent-off"], check=False, quiet=True)
    log("SNMP agent installed but disabled (enable it in Admin -> SNMP)")


def build_venv() -> None:
    if not (VENV / "bin" / "python").exists():
        run([sys.executable or "python3", "-m", "venv", str(VENV)])
    pip = str(VENV / "bin" / "pip")
    run([pip, "install", "-q", "--upgrade", "pip"], check=False)
    req = APP_DIR / "requirements.txt"
    wheels = APP_DIR / "wheels"

    if wheels.is_dir() and any(wheels.iterdir()):
        log("installing dependencies from the bundled wheelhouse")
        run([pip, "install", "-q", "--no-index", "--find-links", str(wheels), "-r", str(req)])
    else:
        p = subprocess.run([pip, "install", "-q", "-r", str(req)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            # uvicorn[standard] drags in four compiled extensions (uvloop, httptools,
            # watchfiles, websockets). If no wheel matches this interpreter they need a
            # compiler the appliance doesn't have - so retry without the extras, which
            # costs a little throughput and nothing else.
            for line in (p.stderr or "").strip().splitlines()[-4:]:
                log("    ! " + line)
            log("  full dependency set failed; retrying without uvicorn's optional extras")
            relaxed = [ln for ln in req.read_text().splitlines()
                       if ln.strip() and not ln.strip().startswith("#")]
            relaxed = [ln.replace("uvicorn[standard]", "uvicorn") for ln in relaxed]
            run([pip, "install", "-q", *relaxed])
    # prove it actually imports before we promise a working service. WeasyPrint is
    # checked whenever requirements.txt asks for it: its import loads Pango through
    # cffi, so this also proves the apt runtime libraries are there.
    mods = "fastapi, uvicorn, jinja2, bcrypt, cryptography, requests, jose, msal"
    if re.search(r"(?im)^\s*weasyprint\b", req.read_text()):
        mods += ", weasyprint"
    run([str(VENV / "bin" / "python"), "-c", f"import {mods}"])
    log("python dependencies installed and verified: " + mods)


def make_key() -> str:
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    # 0711, not 0700: the service must be able to traverse into tls/ to read the
    # PUBLIC certificate for the admin page. Nobody can list the directory, and
    # fernet.key and tls/privkey.pem are each root-only 0600 in their own right.
    ETC_DIR.chmod(0o711)
    if not (KEY_FILE.exists() and KEY_FILE.stat().st_size > 0):
        p = run([str(VENV / "bin" / "python"), "-c",
                 "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"],
                quiet=True)
        write_secret(KEY_FILE, p.stdout.strip() + "\n")
    KEY_FILE.chmod(0o600)
    os.chown(KEY_FILE, 0, 0)
    log("Fernet key present at " + str(KEY_FILE) + " (root-owned, 0600)")
    return KEY_FILE.read_text().strip()


SESSION_KEY = ETC_DIR / "session.key"


def make_session_key() -> None:
    """The key that signs login sessions, kept like the Fernet key: root-owned 0600
    in /etc/zerto-monitor and handed to the service by systemd (LoadCredential), so
    it never sits in the service's writable data directory. Earlier builds kept it
    at data/secret.key; that one is NOT carried over - copies of it may sit in
    backups and replicas - so a fresh key is made (everyone signs in once more)."""
    import secrets as _secrets
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    old = DATA_DIR / "secret.key"
    if not (SESSION_KEY.exists() and SESSION_KEY.stat().st_size > 0):
        write_secret(SESSION_KEY, _secrets.token_urlsafe(48) + "\n")
        log(f"session key created -> {SESSION_KEY} (root-owned, 0600)"
            + ("; the old data/secret.key was retired, not copied" if old.exists() else ""))
    SESSION_KEY.chmod(0o600)
    os.chown(SESSION_KEY, 0, 0)
    if old.exists():
        old.unlink()


def seed_database(p: dict, key: str) -> None:
    """Create the web admin and, if supplied, the first ZVM source — both encrypted."""
    web_user = (p.get("zm-web-user") or "admin").strip() or "admin"
    web_pw = p.get("zm-web-password") or ""
    zvm_host = (p.get("zm-zvm-host") or "").strip()
    zvm_user = (p.get("zm-zvm-user") or "").strip()
    zvm_pw = p.get("zm-zvm-password") or ""
    if len(web_pw.encode()) > 72:
        log("! the web console password is longer than 72 bytes, which bcrypt can't take - not applied; "
            "/setup will prompt on first visit")
        web_pw = ""
    if not web_pw:
        log("no web console password supplied — /setup will prompt on first visit")
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)          # private before anything lands in it

    # Everything goes over stdin: an environment variable is readable from
    # /proc/<pid>/environ for as long as the child runs.
    script = r'''
import json, os, sys
cfg = json.loads(sys.stdin.read())
sys.path.insert(0, "/opt/zerto-monitor/app")
import db, auth, crypto
from cryptography.fernet import Fernet
crypto._fernet = Fernet(cfg.pop("fernet_key").encode())   # the key never touches env or disk here
db.init()
if cfg["web_pw"] and not db.get_user(cfg["web_user"]):
    db.create_user(cfg["web_user"], auth.hash_password(cfg["web_pw"]), "admin")
    print("created web admin:", cfg["web_user"])
host = cfg["zvm_host"]
if host and not any(s["host"] == host for s in db.list_sources()):
    db.add_source(cfg["zvm_name"] or host.split(".")[0], "zvm", host, "password",
                  cfg["zvm_user"], crypto.encrypt(cfg["zvm_pw"]), 0)
    print("seeded ZVM source:", host)
'''
    import json
    payload = json.dumps({"fernet_key": key, "web_user": web_user, "web_pw": web_pw,
                          "zvm_host": zvm_host, "zvm_user": zvm_user, "zvm_pw": zvm_pw,
                          "zvm_name": (p.get("zm-zvm-name") or "").strip()})
    p2 = subprocess.run([str(VENV / "bin" / "python"), "-c", script], input=payload,
                        env=dict(os.environ, DATA_DIR=str(DATA_DIR)),
                        capture_output=True, text=True)
    for line in (p2.stdout or "").strip().splitlines():
        log("  " + line)
    if p2.returncode != 0:
        for t in (p2.stderr or "").strip().splitlines()[-8:]:
            log("    ! " + t)
        raise RuntimeError("database seeding failed")


NGINX_SITE = """# Zerto Monitor - HTTPS only. Port 80 exists solely to redirect.
# Access log WITHOUT query strings ($uri, not $request): they can carry text that
# shouldn't sit in a log file (flash messages, the Entra sign-in code).
log_format zm_noargs '$remote_addr - [$time_local] "$request_method $uri $server_protocol" $status $body_bytes_sent';

server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    access_log /var/log/nginx/access.log zm_noargs;
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;

    ssl_certificate     {tls}/fullchain.pem;
    ssl_certificate_key {tls}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:ZM:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Browsers ignore HSTS sent over an untrusted certificate, so a self-signed
    # cert stays click-through; once a trusted one is installed, HSTS takes hold.
    # Never set add_header inside a location block below: it would silently drop these.
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "same-origin" always;

    client_max_body_size 2m;
    client_body_buffer_size 2m;            # uploads (certificates, keys) stay in memory, never in temp files

    # access log without query strings: msg/err text and the Entra sign-in code ride in them
    access_log /var/log/nginx/access.log zm_noargs;
    location /static/ {{ alias {app}/static/; expires 1h; }}
    location / {{
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        # the client address nginx saw - never a value the client sent
        proxy_set_header   X-Forwarded-For $remote_addr;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 120s;
        proxy_max_temp_file_size 0;
    }}
}}
"""


def install_services() -> None:
    Path("/etc/systemd/system/zerto-monitor.service").write_text(f"""[Unit]
Description=Zerto Monitor (FastAPI)
After=network-online.target zerto-monitor-admin.socket
Wants=network-online.target zerto-monitor-admin.socket

[Service]
User=zertomon
Group=zertomon
UMask=0077
WorkingDirectory={APP_DIR}/app
Environment=DATA_DIR={DATA_DIR}
Environment=PORT=8000
LoadCredential=fernet.key:{KEY_FILE}
LoadCredential=session.key:{SESSION_KEY}
ExecStart={VENV}/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
# uploaded key material is staged here: tmpfs, private, gone when the service stops
RuntimeDirectory=zerto-monitor
RuntimeDirectoryMode=0700
LimitCORE=0
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={DATA_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
""")
    site = Path("/etc/nginx/sites-available/zerto-monitor")
    previous = site.read_text() if site.exists() else None
    site.write_text(NGINX_SITE.format(tls="/etc/zerto-monitor/tls", app=APP_DIR))
    default_site = Path("/etc/nginx/sites-enabled/default")
    if default_site.exists() or default_site.is_symlink():
        default_site.unlink()
    link = Path("/etc/nginx/sites-enabled/zerto-monitor")
    if not link.exists():
        link.symlink_to("/etc/nginx/sites-available/zerto-monitor")
    # never leave nginx on a config it rejects: put the old one back and stop
    if subprocess.run(["nginx", "-t"], capture_output=True).returncode != 0:
        if previous is not None:
            site.write_text(previous)
        raise RuntimeError("nginx rejected the HTTPS site; previous config restored")

    ensure_service_user()
    # Code is root-owned and only readable by the service; ONLY data/ is its to
    # write. Root later runs firstboot.py --upgrade from here, so a service-writable
    # tree would be a path to root.
    run(["chown", "-R", "root:root", str(APP_DIR)], check=False, quiet=True)
    for d in (APP_DIR / "app", APP_DIR / "templates", APP_DIR / "static", APP_DIR / "appliance"):
        if d.is_dir():
            run(["chmod", "-R", "u=rwX,go=rX", str(d)], check=False, quiet=True)
    for f in (APP_DIR / "firstboot.py", APP_DIR / "bootstrap.py"):
        if f.exists():
            f.chmod(0o700)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    run(["chown", "-R", "zertomon:zertomon", str(DATA_DIR)], check=False, quiet=True)
    DATA_DIR.chmod(0o700)
    # the directory already keeps others out; the files say so too, so a copy made
    # with modes preserved (backup tools, cp -a) stays private
    for f in DATA_DIR.glob("monitor.db*"):
        f.chmod(0o600)

    run(["systemctl", "daemon-reload"], check=False)
    run(["systemctl", "enable", "--now", "nginx"], check=False)
    run(["systemctl", "restart", "nginx"], check=False)
    run(["systemctl", "enable", SVC], check=False, quiet=True)
    run(["systemctl", "restart", SVC], check=False)


def secure_transport() -> None:
    """Close the plaintext hole the OVF ISO transport leaves behind.

    vSphere leaves the generated ovf-env ISO in the virtual CD-ROM. udev gives
    /dev/sr0 to root:cdrom 0660, and the cloud image puts its default user in the
    cdrom group - so any local account could 'dd if=/dev/sr0' and read the root,
    admin, web and Zerto passwords in clear. Take the group away and eject the disc.

    This is best-effort mitigation, not a cure: the values also live in the VM's
    vApp configuration in vCenter. The README tells the operator to clear them.
    """
    for name in ("ubuntu", "zertomon"):
        try:
            if pwd and pwd.getpwnam(name):
                subprocess.run(["gpasswd", "-d", name, "cdrom"], capture_output=True)
        except KeyError:
            continue
    try:
        groups = grp.getgrnam("cdrom").gr_mem if grp else []
        for m in groups:
            subprocess.run(["gpasswd", "-d", m, "cdrom"], capture_output=True)
    except KeyError:
        pass
    for dev in sorted(str(p) for p in Path("/dev").glob("sr*")):
        subprocess.run(["eject", dev], capture_output=True)
    # nothing of ours should be holding a copy
    for leftover in (Path("/run/zm-ovfenv"), Path("/run/zm-props.json")):
        try:
            if leftover.is_dir():
                leftover.rmdir()
            elif leftover.exists():
                leftover.unlink()
        except OSError:
            pass
    log("OVF transport secured: cdrom group emptied, media ejected")


def install_ovfscrub() -> None:
    """Install the scrub tool on its own, early - it must not depend on later steps."""
    install_script("zerto-monitor-ovfscrub", OVFSCRUB, 0o700)


# ── console menu ────────────────────────────────────────────────────────────
# Sourced by every login shell. POSIX sh (dash reads /etc/profile.d too). The menu
# opens only for a real interactive login - console or `ssh host` - by a zmconsole
# member. Never for `ssh host command` (a non-login, non-interactive `bash -c`), never
# without a TTY, never with TERM=dumb (automation relies on that), never for a
# login shell started by hand (`bash -l`, whose $0 has no leading '-').
PROFILE_HOOK_TEXT = f"""# Zerto Monitor: open the appliance menu at login. Installed by firstboot.py.
# Plain prompt instead: TERM=dumb, ZM_NO_MENU=1 (or LC_ZM_NO_MENU=1 over SSH),
# a ~/.zm-no-menu file, or the menu's "Shell" item. Reopen: zerto-monitor-console
zm_console_hook() {{
  case "$-" in *i*) ;; *) return 0 ;; esac
  case "$0" in -*) ;; *) return 0 ;; esac
  [ -t 0 ] && [ -t 1 ] || return 0
  case "${{TERM:-dumb}}" in dumb|unknown) return 0 ;; esac
  [ -z "${{ZM_NO_MENU:-}}${{LC_ZM_NO_MENU:-}}${{ZM_CONSOLE_SHOWN:-}}" ] || return 0
  [ ! -e "$HOME/.zm-no-menu" ] || return 0
  [ -x {CONSOLE.as_posix()} ] || return 0
  case " $(id -Gn 2>/dev/null) " in *" {CONSOLE_GROUP} "*) ;; *) return 0 ;; esac
  ZM_CONSOLE_SHOWN=1
  export ZM_CONSOLE_SHOWN
  {CONSOLE.as_posix()} --login
  [ "$?" -ne 10 ] || exit 0
  return 0
}}
zm_console_hook
unset -f zm_console_hook
"""

SUDOERS_TEXT = f"""# Zerto Monitor console menu. Installed by firstboot.py; checked with visudo -c.
# Members of {CONSOLE_GROUP} may run the menu's root operations - that one script, and
# nothing else - without a password, so an admin who signs in with only an SSH key
# can still use the menu. The script allow-lists its verbs and validates every
# argument. The web app's account (zertomon) is not a member, and its unit sets
# NoNewPrivileges, which blocks sudo altogether. Full sudo still needs a password.
%{CONSOLE_GROUP} ALL=(root) NOPASSWD: {CONSOLE_OPS.as_posix()}
"""

# agetty expands \\n (hostname) and \\4 (first IPv4 address) each time it prints this
ISSUE_TEXT = ("Zerto Monitor appliance  \\n\n"
              "\n"
              "  Web console : https://\\4/\n"
              "  Address     : \\4\n"
              "\n"
              "  Sign in as the appliance admin account for the configuration menu.\n"
              "\n")


def install_sudoers() -> None:
    visudo = shutil.which("visudo")
    if not visudo:
        log("! visudo not found; the console's sudo rule was NOT installed")
        return
    # a name containing '.' is ignored by sudo, so the staged copy is inert until checked
    stage = SUDOERS.with_name(SUDOERS.name + ".new")
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o440)
    with os.fdopen(fd, "w") as f:
        f.write(SUDOERS_TEXT)
    os.chown(stage, 0, 0)
    stage.chmod(0o440)
    chk = subprocess.run([visudo, "-c", "-f", str(stage)], capture_output=True, text=True)
    if chk.returncode != 0:
        stage.unlink()
        log("! visudo rejected the console's sudo rule; NOT installed: "
            + (chk.stderr or chk.stdout).strip()[:200])
        return
    previous = SUDOERS.read_text() if SUDOERS.exists() else None
    stage.replace(SUDOERS)
    whole = subprocess.run([visudo, "-c"], capture_output=True, text=True)
    if whole.returncode != 0:                   # never leave sudo itself broken
        if previous is None:
            SUDOERS.unlink()
        else:
            SUDOERS.write_text(previous)
        log("! the full sudoers check failed with the console rule in place; rule removed")
        return
    log(f"sudo rule installed: %{CONSOLE_GROUP} may run {CONSOLE_OPS} without a password")


def console_admins(admin_user: str) -> list[str]:
    """The account(s) the menu is for. First boot names it; on --upgrade from 1.2 it is
    found as the human members of 'sudo' (not the image's own 'ubuntu' user)."""
    if admin_user:
        return [admin_user]
    try:
        members = grp.getgrnam("sudo").gr_mem
    except KeyError:
        return []
    out = []
    for u in members:
        try:
            pw = pwd.getpwnam(u)
        except KeyError:
            continue
        if 1000 <= pw.pw_uid < 60000 and u != "ubuntu" and not pw.pw_shell.endswith("nologin"):
            out.append(u)
    return out


def install_console(admin_user: str = "") -> None:
    """The login menu: scripts, group, sudo rule, profile hook and the /etc/issue banner.
    Touches no network, account password or data; safe on every --upgrade."""
    install_script("zerto-monitor-console-ops", CONSOLE_OPS, 0o755)
    install_script("zerto-monitor-console", CONSOLE, 0o755)
    try:
        members = set(grp.getgrnam(CONSOLE_GROUP).gr_mem)
    except KeyError:
        run(["groupadd", "--system", CONSOLE_GROUP], check=False)
        members = set()
    if admin_user or not members:          # an upgrade never re-adds someone removed later
        for u in console_admins(admin_user):
            if u not in members:
                run(["usermod", "-aG", CONSOLE_GROUP, u], check=False)
                log(f"  {u} added to {CONSOLE_GROUP} (the console menu opens at its login)")
    install_sudoers()
    PROFILE_HOOK.write_text(PROFILE_HOOK_TEXT)
    PROFILE_HOOK.chmod(0o644)
    issue, orig = Path("/etc/issue"), Path("/etc/issue.zm-orig")
    if issue.exists() and not orig.exists():
        shutil.copy2(issue, orig)
    issue.write_text(ISSUE_TEXT)
    backups = Path("/var/lib/zerto-monitor/netplan-backup")
    backups.mkdir(parents=True, exist_ok=True)
    backups.chmod(0o700)
    log(f"console menu installed: {CONSOLE} (opens at login for {CONSOLE_GROUP}), "
        f"root operations {CONSOLE_OPS}")


def disable_crash_dumps() -> None:
    """A crash report of the web app would carry decrypted credentials. The app also
    marks itself non-dumpable, and its unit sets LimitCORE=0; apport receives dumps
    through a pipe, which neither stops - so switch apport off."""
    subprocess.run(["systemctl", "disable", "--now", "apport.service"], capture_output=True)
    conf = Path("/etc/default/apport")
    try:
        if conf.exists():
            body = conf.read_text()
            if "enabled=0" not in body:
                conf.write_text(re.sub(r"(?m)^enabled=.*$", "enabled=0", body) if "enabled=" in body
                                else body + "\nenabled=0\n")
    except OSError:
        pass


def tidy_firstboot_log() -> None:
    """Earlier builds logged the ZVM username among the OVF properties, in a 0644 log."""
    try:
        if LOG.exists():
            lines = LOG.read_text(errors="replace").splitlines()
            kept = [ln for ln in lines if " properties: " not in ln]
            if len(kept) != len(lines):
                LOG.write_text("\n".join(kept) + "\n")
            LOG.chmod(0o600)
    except OSError:
        pass


def lock_down_ovf_environment() -> None:
    """Keep the deploy wizard's passwords out of the running guest from now on.

    vCenter re-sends every vApp property as guestinfo.ovfEnv at each power-on, and any
    local account (even 'nobody') can read that with vmware-rpctool; cloud-init also
    pickles a copy under /var/lib/cloud. Nothing needs them after first boot, so:
    cloud-init is switched off (everything it did is now owned by this appliance's own
    config, and left on it would re-cache the values every boot), then
    zerto-monitor-ovfscrub blanks the runtime copy and removes the caches - now, at
    every boot before anyone can log in, and every 30 minutes.

    vCenter's own copy is out of reach from inside the guest. The scrub records which
    properties vCenter still fills in, and the admin page asks for them to be cleared.
    """
    off = Path("/etc/cloud/cloud-init.disabled")
    if not off.exists():
        off.parent.mkdir(parents=True, exist_ok=True)
        off.write_text("Disabled by Zerto Monitor once first-boot configuration finished:\n"
                       "the appliance owns its network, hostname and accounts from here on,\n"
                       "and cloud-init would otherwise re-cache the deploy-time passwords.\n")
        log("cloud-init disabled for later boots (/etc/cloud/cloud-init.disabled)")
    Path("/etc/systemd/system/zerto-monitor-ovfscrub.service").write_text(f"""[Unit]
Description=Zerto Monitor: keep deploy-time passwords out of the guest
# before any non-root login, the web app or the SNMP agent can run
Before=systemd-user-sessions.service zerto-monitor.service snmpd.service
After=local-fs.target

[Service]
Type=oneshot
ExecStart={OVFSCRUB}
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
""")
    Path("/etc/systemd/system/zerto-monitor-ovfscrub.timer").write_text("""[Unit]
Description=Zerto Monitor: re-check the vApp environment for deploy-time passwords

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
""")
    run(["systemctl", "daemon-reload"], check=False, quiet=True)
    run(["systemctl", "enable", "zerto-monitor-ovfscrub.service"], check=False, quiet=True)
    run(["systemctl", "enable", "--now", "zerto-monitor-ovfscrub.timer"], check=False, quiet=True)
    out = run([str(OVFSCRUB)], check=False, quiet=True).stdout or ""
    for line in out.strip().splitlines():
        log("  " + line)
    if "vcenter_still_holds=" in out and "vcenter_still_holds=nothing" not in out:
        log("  ! vCenter still holds deploy-time passwords in this VM's vApp properties:")
        log("  ! clear them (Edit Settings > vApp Options > Properties), then change them")


def verify(host: str) -> bool:
    """HTTPS answers, and plain HTTP does nothing but redirect to it."""
    import http.client
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE                     # our own self-signed, on loopback
    for attempt in range(20):
        time.sleep(3)
        try:
            c = http.client.HTTPSConnection("127.0.0.1", 443, timeout=5, context=ctx)
            c.request("GET", "/healthz")
            ok = c.getresponse().status == 200
            c.close()
            if not ok:
                continue
            h = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            h.request("GET", "/")
            r = h.getresponse()
            loc = r.getheader("Location") or ""
            h.close()
            if r.status not in (301, 308) or not loc.startswith("https://"):
                log(f"! port 80 answered {r.status} instead of redirecting to HTTPS")
                return False
            log(f"health check OK after {(attempt + 1) * 3}s: HTTPS serving, HTTP redirects")
            return True
        except Exception:                                   # noqa: BLE001
            continue
    log("! health check did not pass; see: journalctl -u " + SVC)
    return False


def live_ipv4() -> str:
    for a in subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split():
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", a):
            return a
    return ""


def banner(host: str, ok: bool) -> None:
    # the address actually in use - the OVF field may have been rejected, or carry a prefix
    url = f"https://{live_ipv4() or host}/"
    # plain ASCII: this goes to /dev/console and /etc/motd, which may be a
    # serial console with no UTF-8
    msg = [
        "",
        "  +-----------------------------------------------------------+",
        "  |  Zerto Monitor appliance                                   |",
        "  +-----------------------------------------------------------+",
        f"  Console : {url}   (HTTPS only; port 80 redirects)",
        f"  Status  : {'running' if ok else 'NOT healthy - check the log'}",
        f"  Log     : {LOG}",
        "  Service : systemctl status zerto-monitor",
        "  Menu    : opens at login for the admin account; zerto-monitor-console",
        "",
        "  Dashboards are read-only without sign-in until Admin > Users",
        "  & access requires it. The certificate is self-signed until you",
        "  install one in Admin. Then clear the passwords from this VM's",
        "  vApp properties in vCenter - Admin > Security shows if any remain.",
        "",
    ]
    text = "\n".join(msg)
    try:
        Path("/etc/motd").write_text(text)
    except OSError:
        pass
    for line in msg:
        log(line)
    try:
        with open("/dev/console", "w") as c:
            c.write(text)
    except OSError:
        pass


# ── main ────────────────────────────────────────────────────────────────────
def main() -> int:
    if STAMP.exists():
        log("first boot already completed; nothing to do "
            "(use --upgrade to apply a newer payload)")
        return 0
    log("=" * 62)
    log("Zerto Monitor first-boot configuration starting")

    props = ovf_properties()
    shown = {k: (v if k in LOGGABLE else ("<set>" if v else "<blank>"))
             for k, v in sorted(props.items())
             if not k.startswith("zm-payload") and k != "user-data"}
    log("properties: " + (", ".join(f"{k}={v}" for k, v in shown.items()) or "(none)"))

    configure_network(props)
    host = configure_identity(props)
    configure_credentials(props)
    # Take the deploy-time secrets out of reach NOW, not at the end: if anything later
    # fails (no outbound network, a bad package mirror...) they must not stay readable
    # in guestinfo or be re-cached by cloud-init at every boot.
    try:
        install_ovfscrub()
        secure_transport()
        lock_down_ovf_environment()
    except Exception as e:  # noqa: BLE001
        log(f"! OVF lock-down failed: {e} - clear the vApp passwords in vCenter")
    disable_crash_dumps()
    # Early, and needing no download: if a later step fails (typically no outbound
    # network), the admin can still sign in on the console, fix the network from the
    # menu and finish the install with Upgrade > Repair.
    admin = (props.get("zm-admin-user") or "").strip()
    try:
        install_console(admin if admin and _user_exists(admin) else "")
    except Exception as e:  # noqa: BLE001
        log(f"! console menu not installed: {e}")

    if not online():
        log("! no outbound network detected. Package installation needs access to")
        log("! archive.ubuntu.com and pypi.org (or a bundled wheelhouse).")
    install_packages()
    ensure_service_user()
    build_venv()
    key = make_key()
    make_session_key()
    seed_database(props, key)
    install_privileged_helper()
    ensure_certificate(system_fqdn(props))     # HTTPS from the very first boot
    install_services()
    snmp_default_off()
    ok = verify(host)
    lock_down_ovf_environment()          # again, now that the helper is installed too

    STAMP.write_text(time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
    banner(host, ok)
    log("first-boot configuration finished")
    return 0 if ok else 1


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def upgrade() -> int:
    """Apply a newer payload to a running appliance, idempotently.

    Touches packages (installs any the payload newly needs), the venv (pip-installs
    requirements.txt), the helper, the console menu, TLS, nginx and the service -
    never the network, accounts or anything read from the OVF environment. An
    existing certificate, Fernet key, database and SNMP choice are all kept.
    """
    log("=" * 62)
    log("Zerto Monitor upgrade starting")
    ensure_service_user()
    install_packages()
    build_venv()
    make_key()
    make_session_key()
    install_privileged_helper()
    try:
        install_console()
    except Exception as e:  # noqa: BLE001
        log(f"! console menu not installed: {e}")
    ensure_certificate(system_fqdn())
    install_services()
    snmp_default_off()
    lock_down_ovf_environment()
    disable_crash_dumps()
    tidy_firstboot_log()
    host = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    ok = verify(host)
    banner(host, ok)
    log("upgrade finished" if ok else "upgrade finished WITH ERRORS")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            sys.exit("run as root")
        sys.exit(upgrade() if "--upgrade" in sys.argv[1:] else main())
    except Exception as exc:                                # noqa: BLE001
        log(f"FATAL: {exc}")
        import traceback
        for ln in traceback.format_exc().splitlines():
            log("    " + ln)
        sys.exit(1)
